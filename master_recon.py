#!/usr/bin/env python3
"""
master_recon.py — All-in-one recon orchestrator

PURPOSE:
    Chains multiple recon steps into a single run against a domain/host:
      1. Subdomain enumeration (crt.sh certificate transparency + optional
         wordlist brute force)
      2. DNS resolution / alive-host check
      3. Port scan (uses system `nmap` if installed, else a light socket
         connect scan on a small common-port list)
      4. TLS/certificate check (expiry, weak protocol versions, SAN/CN
         mismatch)
      5. HTTP header / security header audit
      6. Sensitive path check (basic fixed list, extend via -w)
      7. Basic tech fingerprinting (server header, common JS/CMS signatures)

    Findings from every stage feed into the same (severity, title, detail)
    format and get written to per-target reports plus a ranked summary.txt.

USAGE:
    python3 master_recon.py -d example.com
    python3 master_recon.py -d example.com -w subdomains_wordlist.txt
    python3 master_recon.py -f domains.txt -o results/ -T 10
    python3 master_recon.py -d example.com --skip-portscan --skip-subenum

    -d / --domain         single domain to run against
    -f / --file           file of domains, one per line
    -w / --wordlist       wordlist for subdomain brute force (optional)
    -o / --output         output folder (default ./master_recon_output)
    -T / --threads        thread pool size (default 5)
    --skip-subenum        skip subdomain enumeration stage
    --skip-portscan       skip port scanning stage
    --skip-tls            skip TLS/cert checks
    --skip-paths          skip sensitive path checks
    --dry-run             print what would run without making requests

OUTPUT STRUCTURE:
    <output>/<domain>/subdomains.txt      alive subdomains found
    <output>/<domain>/report.txt          full findings for this domain
    <output>/summary.txt                  ranked summary across all targets

LIMITATIONS / FALSE-POSITIVE-PRONE CHECKS:
    - crt.sh can be slow or rate-limit; script backs off but won't retry
      forever.
    - Port scan without nmap installed only checks a small common-port
      list via raw socket connect — not a substitute for a real nmap scan.
    - Sensitive path checks are presence/status-code based; a 200 response
      does not always mean the file is truly exposed (some apps return
      200 for a custom 404 page) — verify manually before reporting.
    - TLS checks use Python's ssl module; very old/misconfigured servers
      may cause connection errors that get logged as INFO rather than a
      real finding.
    - Tech fingerprinting here is header/string based only, not a full
      Wappalyzer-equivalent — treat matches as hints, not certainty.

WARNING:
    Only run this against targets you own or are explicitly authorized to
    test (CTF scope, signed pentest agreement, your own infrastructure).
    Unauthorized scanning of systems you don't have permission to test is
    illegal in most jurisdictions.
"""

import argparse
import concurrent.futures
import os
import socket
import ssl
import sys
import time
import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

import subprocess
import shutil

# ------------------------------------------------------------------ helpers

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                3306, 3389, 5432, 8080, 8443]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/backup.zip", "/config.php.bak", "/.aws/credentials",
    "/server-status", "/.DS_Store", "/admin/", "/phpinfo.php",
    "/debug", "/actuator/health", "/.htaccess", "/id_rsa",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Drupal": ["drupal.js", "/sites/default/"],
    "Laravel": ["laravel_session"],
    "React": ["__NEXT_DATA__", "react-root", "id=\"root\""],
    "nginx": [],   # detected via Server header instead
    "Apache": [],
}

DEFAULT_TIMEOUT = 6


def clean_domain(raw):
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urlparse(raw).netloc
    return raw.strip("/").lower()


def load_targets(domain_arg, file_arg):
    targets = []
    if domain_arg:
        d = clean_domain(domain_arg)
        if d:
            targets.append(d)
    if file_arg:
        with open(file_arg) as f:
            for line in f:
                d = clean_domain(line)
                if d:
                    targets.append(d)
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def add_finding(findings, severity, title, detail):
    findings.append((severity.upper(), title, detail))


def safe_get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True):
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=allow_redirects,
            headers={"User-Agent": "master-recon/1.0 (authorized-testing)"},
            verify=False,
        )
    except requests.exceptions.RequestException:
        return None


# ------------------------------------------------------------------ checks

def check_subdomains(domain, wordlist, findings, dry_run=False):
    print(f"[*] Subdomain enumeration for {domain}")
    found = set()

    if dry_run:
        print("    [dry-run] would query crt.sh and optionally brute force")
        return found

    # crt.sh certificate transparency lookup
    try:
        resp = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lstrip("*.").lower()
                        if sub.endswith(domain):
                            found.add(sub)
            except ValueError:
                pass
        else:
            add_finding(findings, "INFO", "crt.sh lookup incomplete",
                        "crt.sh did not return usable data (rate limit or timeout).")
    except Exception as e:
        add_finding(findings, "INFO", "crt.sh lookup failed", str(e))

    # optional wordlist brute force
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist) as f:
            words = [w.strip() for w in f if w.strip()]
        print(f"    brute forcing {len(words)} candidates via DNS")
        for w in words:
            candidate = f"{w}.{domain}"
            if resolves(candidate):
                found.add(candidate)
            time.sleep(0.02)  # gentle rate limit

    alive = set()
    for sub in found:
        if resolves(sub):
            alive.add(sub)

    if alive:
        add_finding(findings, "INFO", "Subdomains discovered",
                    f"{len(alive)} alive subdomain(s) found out of {len(found)} total discovered.")
    return alive


def resolves(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False


def check_ports(domain, findings, dry_run=False):
    print(f"[*] Port scan for {domain}")
    if dry_run:
        print("    [dry-run] would scan ports")
        return

    if shutil.which("nmap"):
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-T3", "--top-ports", "50", domain],
                capture_output=True, text=True, timeout=120,
            )
            open_lines = [l for l in result.stdout.splitlines() if "/tcp" in l and "open" in l]
            if open_lines:
                add_finding(findings, "INFO", "Open ports (nmap)",
                            "; ".join(open_lines))
        except Exception as e:
            add_finding(findings, "INFO", "nmap scan failed", str(e))
    else:
        open_ports = []
        for port in COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    if s.connect_ex((domain, port)) == 0:
                        open_ports.append(port)
            except socket.error:
                continue
        if open_ports:
            add_finding(findings, "INFO", "Open ports (socket scan)",
                        f"Ports open: {', '.join(map(str, open_ports))}. "
                        f"Install nmap for a fuller scan.")


def check_tls(domain, findings, dry_run=False):
    print(f"[*] TLS/certificate check for {domain}")
    if dry_run:
        print("    [dry-run] would inspect TLS cert")
        return

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()

                if proto in ("SSLv3", "TLSv1", "TLSv1.1"):
                    add_finding(findings, "HIGH", "Weak TLS protocol in use",
                                f"Server negotiated {proto}, which is deprecated.")

                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        if days_left < 0:
                            add_finding(findings, "CRITICAL", "Expired TLS certificate",
                                        f"Certificate expired {abs(days_left)} day(s) ago.")
                        elif days_left < 30:
                            add_finding(findings, "HIGH", "TLS certificate expiring soon",
                                        f"Certificate expires in {days_left} day(s).")
    except ssl.SSLError as e:
        add_finding(findings, "INFO", "TLS handshake issue", str(e))
    except (socket.error, socket.timeout):
        add_finding(findings, "INFO", "No TLS/443 response",
                    "Could not establish a TLS connection on port 443.")


def check_headers(domain, findings, dry_run=False):
    print(f"[*] Header audit for {domain}")
    if dry_run:
        print("    [dry-run] would fetch and inspect HTTP headers")
        return

    resp = safe_get(f"https://{domain}/") or safe_get(f"http://{domain}/")
    if resp is None:
        add_finding(findings, "INFO", "No HTTP response", "Target did not respond over HTTP(S).")
        return

    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if missing:
        add_finding(findings, "LOW", "Missing security headers",
                    f"Missing: {', '.join(missing)}")

    server = resp.headers.get("Server")
    if server:
        add_finding(findings, "INFO", "Server header disclosed", server)

    powered_by = resp.headers.get("X-Powered-By")
    if powered_by:
        add_finding(findings, "LOW", "X-Powered-By header disclosed",
                    f"{powered_by} — consider suppressing this header.")

    body = resp.text[:20000] if resp.text else ""
    detected = []
    for tech, signatures in TECH_SIGNATURES.items():
        if any(sig in body for sig in signatures):
            detected.append(tech)
    if server:
        for tech in ("nginx", "Apache"):
            if tech.lower() in server.lower():
                detected.append(tech)
    if detected:
        add_finding(findings, "INFO", "Technology fingerprint",
                    f"Detected: {', '.join(sorted(set(detected)))}")


def check_sensitive_paths(domain, extra_wordlist, findings, dry_run=False):
    print(f"[*] Sensitive path check for {domain}")
    if dry_run:
        print("    [dry-run] would probe sensitive paths")
        return

    paths = list(SENSITIVE_PATHS)
    if extra_wordlist and os.path.isfile(extra_wordlist):
        with open(extra_wordlist) as f:
            paths += [p.strip() for p in f if p.strip().startswith("/")]

    for path in paths:
        resp = safe_get(f"https://{domain}{path}") or safe_get(f"http://{domain}{path}")
        if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
            add_finding(findings, "MEDIUM", "Sensitive path accessible",
                        f"{path} returned HTTP 200 — verify manually, may be a custom 404.")
        time.sleep(0.05)


# ------------------------------------------------------------------ runner

def run_target(domain, args):
    findings = []
    target_dir = os.path.join(args.output, domain)
    os.makedirs(target_dir, exist_ok=True)

    try:
        if not args.skip_subenum:
            alive = check_subdomains(domain, args.wordlist, findings, args.dry_run)
            if alive:
                with open(os.path.join(target_dir, "subdomains.txt"), "w") as f:
                    f.write("\n".join(sorted(alive)) + "\n")
    except Exception as e:
        add_finding(findings, "INFO", "Subdomain stage error", str(e))

    try:
        if not args.skip_portscan:
            check_ports(domain, findings, args.dry_run)
    except Exception as e:
        add_finding(findings, "INFO", "Port scan stage error", str(e))

    try:
        if not args.skip_tls:
            check_tls(domain, findings, args.dry_run)
    except Exception as e:
        add_finding(findings, "INFO", "TLS stage error", str(e))

    try:
        check_headers(domain, findings, args.dry_run)
    except Exception as e:
        add_finding(findings, "INFO", "Header stage error", str(e))

    try:
        if not args.skip_paths:
            check_sensitive_paths(domain, args.wordlist, findings, args.dry_run)
    except Exception as e:
        add_finding(findings, "INFO", "Sensitive path stage error", str(e))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 5))

    report_path = os.path.join(target_dir, "report.txt")
    with open(report_path, "w") as f:
        f.write(f"Recon report for {domain}\n")
        f.write(f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n")
        f.write("=" * 60 + "\n\n")
        for sev, title, detail in findings:
            f.write(f"[{sev}] {title}\n    {detail}\n\n")
        if not findings:
            f.write("No findings recorded.\n")

    print(f"[+] {domain}: {len(findings)} finding(s) — report at {report_path}")
    return domain, findings


def write_summary(results, output_dir):
    summary_path = os.path.join(output_dir, "summary.txt")
    ranked = sorted(
        results,
        key=lambda r: (
            sum(1 for f in r[1] if f[0] in ("CRITICAL", "HIGH")),
        ),
        reverse=True,
    )
    with open(summary_path, "w") as f:
        f.write("Master Recon Summary\n")
        f.write(f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n")
        f.write("=" * 60 + "\n\n")
        for domain, findings in ranked:
            counts = {}
            for sev, _, _ in findings:
                counts[sev] = counts.get(sev, 0) + 1
            count_str = ", ".join(f"{k}: {v}" for k, v in sorted(
                counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 5)))
            f.write(f"{domain} — {count_str or 'no findings'}\n")
    print(f"[+] Summary written to {summary_path}")


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(
        description="All-in-one recon orchestrator (subdomains, ports, TLS, headers, sensitive paths).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-d", "--domain", help="single domain to scan")
    parser.add_argument("-f", "--file", help="file of domains, one per line")
    parser.add_argument("-w", "--wordlist", help="wordlist for subdomain brute force / path checks")
    parser.add_argument("-o", "--output", default="./master_recon_output", help="output folder")
    parser.add_argument("-T", "--threads", type=int, default=5, help="thread pool size")
    parser.add_argument("--skip-subenum", action="store_true")
    parser.add_argument("--skip-portscan", action="store_true")
    parser.add_argument("--skip-tls", action="store_true")
    parser.add_argument("--skip-paths", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="print actions without making requests")
    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.error("provide -d/--domain or -f/--file")

    targets = load_targets(args.domain, args.file)
    if not targets:
        print("[!] No valid targets found.")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    print(f"[*] Running master recon against {len(targets)} target(s)")
    print("[!] Only run this against targets you own or are authorized to test.\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(run_target, t, args): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                print(f"[!] {domain} failed: {e}")

    write_summary(results, args.output)


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()
