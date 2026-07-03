#!/usr/bin/env python3
"""
Purpose:
  Check TLS posture for authorized targets using Python's ssl module and cryptography.

Usage examples:
  python3 tls_check.py -u https://example.com
  python3 tls_check.py -f targets.txt -T 5 -o tls_check_output

What it checks:
  - Certificate expiry (<30 days = HIGH, expired = CRITICAL)
  - Weak protocols and ciphers
  - Self-signed certificates
  - SAN/CN mismatch with hostname
  - Missing OCSP stapling

Output structure:
  tls_check_output/
    summary.txt
    <host>/
      report_<timestamp>.txt

Limitations / false-positive-prone checks:
  - OCSP stapling availability can vary by load balancer/CDN and may not reflect backend TLS.
  - Self-signed detection is a heuristic based on subject/issuer equality.
  - SAN/CN mismatch only checks the hostname supplied to the tool.
  - Cipher/protocol results reflect the negotiated settings on the tested endpoint only.

WARNING:
  Only run on targets you are authorized to test.
  Do not scan assets outside your approved scope.
"""

import argparse
import concurrent.futures
import os
import socket
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    x509 = None
    default_backend = None
    NameOID = None
    print("[!] cryptography not found, TLS parsing will be disabled")
    print("    pip install cryptography --break-system-packages\n")


#  helpers

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def clean_target(value):
    value = value.strip()
    if not value:
        return None
    if "://" not in value:
        value = "https://" + value
    return value.rstrip("/")


def load_targets(filepath):
    targets = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                target = clean_target(line)
                if target:
                    targets.append(target)
    return list(dict.fromkeys(targets))


def get_host_port(url):
    parsed = urlsplit(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or 443
    return host, port


def safe_name(value):
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)


def utc_now():
    return datetime.now(timezone.utc)


def parse_cert_time(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def get_leaf_certificate(url):
    host, port = get_host_port(url)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            meta = {
                "version": tls_sock.version(),
                "cipher": tls_sock.cipher(),
                "ocsp_response": getattr(tls_sock, "ocsp_response", None),
            }
    cert = x509.load_der_x509_certificate(der, default_backend()) if CRYPTO_OK else None
    return cert, meta


def cert_subject(cert):
    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return ""


def cert_issuer(cert):
    try:
        return cert.issuer.rfc4514_string()
    except Exception:
        return ""


def cert_cn(cert):
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def cert_sans(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [x.lower() for x in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


def match_hostname(host, san_list, cn_value):
    host_l = host.lower()
    for san in san_list:
        if san == host_l:
            return True
        if san.startswith("*.") and host_l.endswith(san[1:]):
            return True
    if cn_value:
        cn_l = cn_value.lower()
        if cn_l == host_l:
            return True
        if cn_l.startswith("*.") and host_l.endswith(cn_l[1:]):
            return True
    return False


#  checks

def check_certificate_expiry(url, findings):
    try:
        cert, _ = get_leaf_certificate(url)
        if not cert:
            findings.append(("INFO", "Certificate parsing unavailable", "install cryptography"))
            return
        now = utc_now()
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if now > not_after:
            findings.append(("CRITICAL", "Certificate expired", f"expired at {not_after.isoformat()}"))
        else:
            days_left = (not_after - now).days
            if days_left < 30:
                findings.append(("HIGH", "Certificate expiring soon", f"{days_left} days remaining"))
    except Exception as e:
        findings.append(("INFO", "Certificate expiry check failed", str(e)))


def check_protocol_and_cipher(url, findings):
    try:
        _, meta = get_leaf_certificate(url)
        version = meta.get("version") or ""
        cipher = meta.get("cipher") or ("", "", 0)
        cipher_name = cipher[0] if cipher else ""
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(("HIGH", "Weak protocol negotiated", version))
        elif version:
            findings.append(("INFO", "Negotiated protocol", version))

        weak_tokens = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")
        if any(tok in cipher_name.upper() for tok in weak_tokens):
            findings.append(("HIGH", "Weak cipher negotiated", cipher_name))
        elif cipher_name:
            findings.append(("INFO", "Negotiated cipher", cipher_name))
    except Exception as e:
        findings.append(("INFO", "Protocol/cipher check failed", str(e)))


def check_self_signed(url, findings):
    try:
        cert, _ = get_leaf_certificate(url)
        if not cert:
            return
        if cert_subject(cert) and cert_issuer(cert) and cert_subject(cert) == cert_issuer(cert):
            findings.append(("MEDIUM", "Self-signed certificate", cert_subject(cert)))
    except Exception as e:
        findings.append(("INFO", "Self-signed check failed", str(e)))


def check_san_cn_mismatch(url, findings):
    try:
        host, _ = get_host_port(url)
        cert, _ = get_leaf_certificate(url)
        if not cert:
            return
        sans = cert_sans(cert)
        cn_value = cert_cn(cert)
        if not match_hostname(host, sans, cn_value):
            detail = f"host={host} cn={cn_value or 'n/a'} san_count={len(sans)}"
            findings.append(("HIGH", "SAN/CN mismatch", detail))
    except Exception as e:
        findings.append(("INFO", "SAN/CN check failed", str(e)))


def check_ocsp_stapling(url, findings):
    try:
        cert, meta = get_leaf_certificate(url)
        if not cert:
            return
        ocsp = meta.get("ocsp_response")
        if ocsp:
            findings.append(("INFO", "OCSP stapling present", f"{len(ocsp)} bytes"))
        else:
            findings.append(("LOW", "Missing OCSP stapling", "server did not staple an OCSP response"))
    except Exception as e:
        findings.append(("INFO", "OCSP stapling check failed", str(e)))


def run_target(url, output_dir):
    findings = []
    host, _ = get_host_port(url)
    target_dir = Path(output_dir) / safe_name(host or "unknown")
    target_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] {url}")
    checks = [
        ("expiry", lambda: check_certificate_expiry(url, findings)),
        ("protocol/cipher", lambda: check_protocol_and_cipher(url, findings)),
        ("self-signed", lambda: check_self_signed(url, findings)),
        ("san/cn", lambda: check_san_cn_mismatch(url, findings)),
        ("ocsp", lambda: check_ocsp_stapling(url, findings)),
    ]

    for name, fn in checks:
        try:
            fn()
            print(f"  [+] {name} done")
        except Exception as e:
            print(f"  [!] {name} error: {e}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = target_dir / f"report_{ts}.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"target: {url}\n")
        f.write(f"date: {datetime.now().isoformat()}\n")
        f.write("-" * 60 + "\n\n")
        if not findings:
            f.write("no findings\n")
        else:
            for i, (sev, title, detail) in enumerate(findings, 1):
                f.write(f"[{i}] [{sev}] {title}\n")
                f.write(f"     {detail}\n\n")

    if findings:
        print(f"  findings for {host}:")
        for sev, title, detail in findings:
            print(f"    [{sev}] {title} - {detail}")
    else:
        print("  no findings")

    print(f"  report saved: {report_path}")
    return url, findings


def write_summary(results, output_dir):
    path = Path(output_dir) / "summary.txt"
    severity_rank = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}
    sorted_results = sorted(results, key=lambda item: (len(item[1]), sum(severity_rank.get(f[0], 999) for f in item[1])), reverse=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"tls check summary - {datetime.now().isoformat()}\n")
        f.write(f"total targets: {len(results)}\n")
        f.write("=" * 60 + "\n\n")
        for url, findings in sorted_results:
            counts = Counter(sev for sev, _, _ in findings)
            summary = " | ".join(f"{sev}:{counts[sev]}" for sev in SEVERITY_ORDER if counts.get(sev))
            f.write(f"{url}\n")
            f.write(f"  {summary or 'no findings'}\n")
            for sev, title, detail in sorted(findings, key=lambda x: severity_rank.get(x[0], 999)):
                f.write(f"  [{sev}] {title}\n")
                f.write(f"     {detail}\n")
            f.write("\n")

    print(f"\n[*] summary saved: {path}")


#  main

def main():
    parser = argparse.ArgumentParser(description="tls checker for authorized targets")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="single target url")
    group.add_argument("-f", "--file", help="file with list of targets")
    parser.add_argument("-o", "--output", default="./tls_check_output", help="output folder")
    parser.add_argument("-T", "--threads", type=int, default=5, help="number of threads")
    args = parser.parse_args()

    if args.url:
        targets = [clean_target(args.url)]
    else:
        if not os.path.exists(args.file):
            print(f"[!] file not found: {args.file}")
            sys.exit(1)
        targets = load_targets(args.file)
        print(f"[*] loaded {len(targets)} targets from {args.file}")

    targets = [t for t in targets if t]
    if not targets:
        print("[!] no valid targets provided")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    results = []

    if args.threads > 1 and len(targets) > 1:
        print(f"[*] running {args.threads} threads")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_target, target, args.output): target for target in targets}
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    print(f"[!] error on {target}: {e}")
    else:
        for target in targets:
            results.append(run_target(target, args.output))

    write_summary(results, args.output)


if __name__ == "__main__":
    main()
