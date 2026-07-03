#!/usr/bin/env python3
"""
Purpose:
  Audit TLS posture for one HTTPS target or a file of targets.

Usage examples:
  python3 tls_recon.py -u https://example.com
  python3 tls_recon.py -f targets.txt -t 10 -o tls_recon_output

What it checks:
  - Certificate expiry and validity window
  - Hostname / SAN mismatch
  - Basic certificate metadata disclosures
  - OCSP stapling availability
  - Certificate chain depth / issuer trust heuristics
  - Negotiated TLS protocol and cipher
  - Optional weak-cipher probe using nmap if installed

Output structure:
  output/
    summary.txt
    <host>/
      report_<timestamp>.txt

Limitations / manual verification:
  - SAN / hostname mismatch depends on the supplied target host and redirects are not followed.
  - Cipher weakness checks are heuristic; confirm with a dedicated TLS scanner before reporting.
  - Expiry is assessed from the leaf certificate only; intermediates are not fully validated.
  - OCSP stapling and trust checks are best-effort and may be unavailable behind load balancers or CDNs.
  - Optional nmap-based cipher probing requires local nmap installation and may be blocked by rate limits.

WARNING:
  Only run on targets you are authorized to test.
  Do not scan assets outside your approved scope, even if they appear interesting.
"""

import argparse
import concurrent.futures
import os
import socket
import ssl
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    requests = None
    print("[!] requests not found, falling back to stdlib only")
    print("    pip install requests --break-system-packages\n")


#  helpers

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def clean_target(target):
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = "https://" + target
    return target.rstrip("/")


def load_targets(filepath):
    targets = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            target = clean_target(line)
            if target:
                targets.append(target)
    return list(dict.fromkeys(targets))


def get_host_port(url):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    if not host:
        return None, None
    port = parsed.port or 443
    return host, port


def safe_name(value):
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)


def open_tls_connection(host, port, sni=None, timeout=8, ciphers=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if ciphers:
        context.set_ciphers(ciphers)

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return context.wrap_socket(sock, server_hostname=sni or host)
    except Exception:
        sock.close()
        raise


def get_leaf_certificate(url):
    host, port = get_host_port(url)
    if not host:
        raise ValueError("could not parse host")

    with open_tls_connection(host, port, sni=host) as tls_sock:
        cert = tls_sock.getpeercert()
        negotiated = {
            "version": tls_sock.version(),
            "cipher": tls_sock.cipher(),
        }
    return cert, negotiated


def normalize_cert_name(name_parts):
    return ", ".join("=".join(item) for part in name_parts for item in part)


def cert_time_to_utc(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def fetch_https_head(url):
    if not REQUESTS_OK:
        return None
    try:
        return requests.get(url, timeout=10, verify=False, allow_redirects=False)
    except Exception:
        return None


def nmap_probe_ciphers(host, port):
    try:
        proc = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except FileNotFoundError:
        return None, "nmap not installed"
    except Exception as e:
        return None, str(e)
    return proc.stdout + proc.stderr, None


def get_cert_chain_info(url):
    host, port = get_host_port(url)
    if not host:
        raise ValueError("could not parse host")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert(binary_form=False)
            chain = []
            get_chain = getattr(tls_sock, "get_verified_chain", None)
            if callable(get_chain):
                try:
                    chain = get_chain() or []
                except Exception:
                    chain = []
            return cert, chain


#  checks

def check_certificate_expiry(url, findings):
    try:
        cert, _ = get_leaf_certificate(url)
        not_before = cert_time_to_utc(cert["notBefore"])
        not_after = cert_time_to_utc(cert["notAfter"])
        now = datetime.now(timezone.utc)

        if now < not_before:
            findings.append(("HIGH", "Certificate not yet valid", f"valid from {not_before.isoformat()}"))
        elif now > not_after:
            findings.append(("CRITICAL", "Certificate expired", f"expired at {not_after.isoformat()}"))
        else:
            days_left = (not_after - now).days
            if days_left <= 7:
                findings.append(("HIGH", "Certificate expiring soon", f"{days_left} days remaining"))
            elif days_left <= 30:
                findings.append(("MEDIUM", "Certificate nearing expiry", f"{days_left} days remaining"))
    except Exception as e:
        findings.append(("INFO", "Certificate expiry check failed", str(e)))


def check_hostname_san(url, findings):
    try:
        host, _ = get_host_port(url)
        cert, _ = get_leaf_certificate(url)
        san = []
        for entry in cert.get("subjectAltName", []):
            if entry[0].lower() == "dns":
                san.append(entry[1].lower())

        if san:
            matched = False
            host_l = host.lower()
            for name in san:
                if name == host_l:
                    matched = True
                    break
                if name.startswith("*.") and host_l.endswith(name[1:]):
                    matched = True
                    break
            if not matched:
                findings.append(("HIGH", "Hostname does not match SAN", f"host={host} san={', '.join(san[:10])}"))
        else:
            findings.append(("MEDIUM", "No SAN entries found", "manual verification recommended"))
    except Exception as e:
        findings.append(("INFO", "Hostname/SAN check failed", str(e)))


def check_certificate_metadata(url, findings):
    try:
        cert, _ = get_leaf_certificate(url)
        subject = cert.get("subject", [])
        issuer = cert.get("issuer", [])
        subject_text = normalize_cert_name(subject)
        issuer_text = normalize_cert_name(issuer)

        if subject_text:
            findings.append(("INFO", "Certificate subject", subject_text))
        if issuer_text:
            findings.append(("INFO", "Certificate issuer", issuer_text))

        if "Let's Encrypt" in issuer_text and "R3" in issuer_text:
            findings.append(("INFO", "Public AC issuer", "Let's Encrypt R3 chain detected"))
    except Exception as e:
        findings.append(("INFO", "Certificate metadata check failed", str(e)))


def check_ocsp_stapling(url, findings):
    try:
        host, port = get_host_port(url)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                ocsp = getattr(tls_sock, "ocsp_response", None)
                if ocsp:
                    findings.append(("INFO", "OCSP stapling present", f"{len(ocsp)} bytes"))
                else:
                    findings.append(("LOW", "OCSP stapling absent", "server did not staple an OCSP response"))
    except Exception as e:
        findings.append(("INFO", "OCSP stapling check failed", str(e)))


def check_chain_depth_and_trust(url, findings):
    try:
        cert, chain = get_cert_chain_info(url)
        subject = normalize_cert_name(cert.get("subject", []))
        issuer = normalize_cert_name(cert.get("issuer", []))

        if chain:
            findings.append(("INFO", "Certificate chain depth", f"{len(chain)} certificate(s) observed"))
        else:
            findings.append(("INFO", "Certificate chain depth", "chain inspection unavailable on this Python/OpenSSL build"))

        if subject and issuer and subject == issuer:
            findings.append(("LOW", "Possible self-signed leaf certificate", subject))

        if issuer:
            trusted_indicators = (
                "Let's Encrypt",
                "DigiCert",
                "GlobalSign",
                "Sectigo",
                "Comodo",
                "Entrust",
                "Amazon",
                "Google Trust Services",
                "Go Daddy",
                "Cloudflare",
                "Buypass",
            )
            if not any(marker.lower() in issuer.lower() for marker in trusted_indicators):
                findings.append(("MEDIUM", "Issuer trust requires manual verification", issuer))
    except Exception as e:
        findings.append(("INFO", "Chain depth / trust check failed", str(e)))


def check_tls_negotiation(url, findings):
    try:
        cert, negotiated = get_leaf_certificate(url)
        version = negotiated.get("version") or ""
        cipher = negotiated.get("cipher") or ("", "", 0)
        cipher_name = cipher[0] if len(cipher) > 0 else ""
        cipher_bits = cipher[2] if len(cipher) > 2 else 0

        if version in ("TLSv1", "TLSv1.1"):
            findings.append(("HIGH", "Weak TLS version negotiated", version))
        elif version == "TLSv1.2":
            findings.append(("INFO", "TLS 1.2 negotiated", "consider TLS 1.3 where possible"))
        elif version == "TLSv1.3":
            findings.append(("INFO", "TLS 1.3 negotiated", cipher_name))
        else:
            findings.append(("LOW", "Unknown TLS version", str(version)))

        weak_names = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "DES-CBC3")
        if any(name in cipher_name.upper() for name in weak_names):
            findings.append(("HIGH", "Weak cipher negotiated", f"{cipher_name} ({cipher_bits} bits)"))
        elif cipher_bits and cipher_bits < 128:
            findings.append(("MEDIUM", "Short cipher key length", f"{cipher_name} ({cipher_bits} bits)"))
        else:
            findings.append(("INFO", "Negotiated cipher", f"{cipher_name} ({cipher_bits} bits)"))
    except Exception as e:
        findings.append(("INFO", "TLS negotiation check failed", str(e)))


def check_https_redirect(url, findings):
    try:
        r = fetch_https_head(url)
        if not r:
            return
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc and loc.startswith("http://"):
                findings.append(("HIGH", "HTTPS redirects to HTTP", loc))
        elif r.status_code >= 400:
            findings.append(("LOW", "HTTPS request returned error", f"HTTP {r.status_code}"))
    except Exception as e:
        findings.append(("INFO", "HTTPS redirect check failed", str(e)))


def check_optional_weak_ciphers(url, findings):
    host, port = get_host_port(url)
    try:
        output, err = nmap_probe_ciphers(host, port)
        if err:
            findings.append(("INFO", "Optional cipher probe unavailable", err))
            return
        if not output:
            return
        weak_hits = []
        for name in ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"):
            if name.lower() in output.lower():
                weak_hits.append(name)
        if weak_hits:
            findings.append(("HIGH", "Optional weak cipher probe hit", ", ".join(sorted(set(weak_hits)))))
    except Exception as e:
        findings.append(("INFO", "Optional weak cipher probe failed", str(e)))


#  main

def run_target(url, output_dir, output_mode="both"):
    findings = []
    host, _ = get_host_port(url)
    target_dir = Path(output_dir) / safe_name(host or "unknown")
    target_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] {url}")

    checks = [
        ("certificate expiry", lambda: check_certificate_expiry(url, findings)),
        ("hostname/san", lambda: check_hostname_san(url, findings)),
        ("certificate metadata", lambda: check_certificate_metadata(url, findings)),
        ("ocsp stapling", lambda: check_ocsp_stapling(url, findings)),
        ("chain trust", lambda: check_chain_depth_and_trust(url, findings)),
        ("tls negotiation", lambda: check_tls_negotiation(url, findings)),
        ("https redirect", lambda: check_https_redirect(url, findings)),
        ("optional weak ciphers", lambda: check_optional_weak_ciphers(url, findings)),
    ]

    for name, fn in checks:
        try:
            fn()
            print(f"  [+] {name} done")
        except Exception as e:
            print(f"  [!] {name} error: {e}")

    if findings:
        print(f"  findings for {host}:")
        for sev, title, detail in findings:
            print(f"    [{sev}] {title} - {detail}")
    else:
        print("  no findings")

    if output_mode in ("both", "text"):
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
        print(f"  report saved: {report_path}")

    return url, findings


def write_target_json(url, findings, output_dir):
    host, _ = get_host_port(url)
    target_dir = Path(output_dir) / safe_name(host or "unknown")
    payload = {
        "target": url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [
            {"severity": sev, "title": title, "detail": detail}
            for sev, title, detail in findings
        ],
    }
    path = target_dir / "report.json"
    try:
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        print(f"  json saved: {path}")
    except Exception as e:
        print(f"  [!] json report write failed: {e}")


def write_target_text_only(url, findings, output_dir):
    host, _ = get_host_port(url)
    target_dir = Path(output_dir) / safe_name(host or "unknown")
    target_dir.mkdir(parents=True, exist_ok=True)

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
    print(f"  text report saved: {report_path}")


def write_summary(all_results, output_dir):
    path = Path(output_dir) / "summary.txt"
    severity_rank = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}

    def score(findings):
        counts = Counter(sev for sev, _, _ in findings)
        weighted = 0
        for sev, count in counts.items():
            weighted += (len(SEVERITY_ORDER) - severity_rank.get(sev, len(SEVERITY_ORDER))) * count
        return len(findings), weighted

    sorted_results = sorted(all_results, key=lambda item: score(item[1]), reverse=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"TLS recon summary - {datetime.now().isoformat()}\n")
        f.write(f"total targets: {len(all_results)}\n")
        f.write("=" * 72 + "\n\n")

        for url, findings in sorted_results:
            counts = Counter(sev for sev, _, _ in findings)
            summary_bits = [f"{sev}:{counts[sev]}" for sev in SEVERITY_ORDER if counts.get(sev)]
            f.write(f"{url}\n")
            f.write(f"  findings: {len(findings)} | {' | '.join(summary_bits) if summary_bits else 'no findings'}\n")
            for sev, title, detail in sorted(findings, key=lambda item: severity_rank.get(item[0], 999)):
                f.write(f"  [{sev}] {title} - {detail}\n")
            f.write("\n")

    return sorted_results


def write_summary_json(all_results, output_dir):
    path = Path(output_dir) / "summary.json"
    try:
        import json
        json_payload = []
        for url, findings in all_results:
            counts = Counter(sev for sev, _, _ in findings)
            json_payload.append({
                "target": url,
                "finding_count": len(findings),
                "severity_counts": {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER if counts.get(sev)},
                "findings": [
                    {"severity": sev, "title": title, "detail": detail}
                    for sev, title, detail in findings
                ],
            })
        with open(path, "w", encoding="utf-8") as jf:
            json.dump(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "total_targets": len(all_results),
                    "results": json_payload,
                },
                jf,
                indent=2,
                sort_keys=True,
            )
        print(f"[*] summary json saved: {path}")
    except Exception as e:
        print(f"[!] summary json write failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="TLS recon script for authorized targets")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="single target url")
    group.add_argument("-f", "--file", help="file with list of targets")
    parser.add_argument("-t", "--threads", type=int, default=5, help="number of threads")
    parser.add_argument("-o", "--output", default="./tls_recon_output", help="output folder")
    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument("--text-only", action="store_true", help="write only text reports and summary")
    out_group.add_argument("--json-only", action="store_true", help="write only json reports and summary")
    args = parser.parse_args()
    output_mode = "both"
    if args.text_only:
        output_mode = "text"
    elif args.json_only:
        output_mode = "json"

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
    all_results = []

    if args.threads > 1 and len(targets) > 1:
        print(f"[*] running {args.threads} threads")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_target, target, args.output, output_mode): target for target in targets}
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    all_results.append(future.result())
                except Exception as e:
                    print(f"[!] error on {target}: {e}")
    else:
        for target in targets:
            all_results.append(run_target(target, args.output, output_mode))

    sorted_results = write_summary(all_results, args.output)
    print(f"\n[*] summary saved: {Path(args.output) / 'summary.txt'}")
    if output_mode in ("both", "json"):
        write_summary_json(sorted_results, args.output)


if __name__ == "__main__":
    main()
