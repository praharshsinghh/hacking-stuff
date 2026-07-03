# recon_auto.py
#
# runs automated recon on a single url or list of urls (targets.txt)
#
# usage:
#   python3 recon_auto.py -u https://target.com
#   python3 recon_auto.py -f targets.txt -t 10 -o recon_output
#
# checks (9 total):
#   headers, cors, email security (spf/dmarc), cookie flags,
#   js secrets (api keys/tokens), sensitive paths (.git/.env/etc),
#   open redirect, subdomain takeover hints, info disclosure
#
# severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
#
# output:
#   recon_output/summary.txt          - all targets ranked by findings
#   recon_output/<domain>/report_*.txt - per-target findings
#   recon_output/<domain>/js_files/    - saved js where secrets found
#
# WARNING - only run on authorized targets
# do not run on anything outside agreed scope, even if found by accident
#
# limitations:
#   - low/info findings need manual verification before reporting
#   - open redirect + cors checks can false positive, confirm in burp
#   - no auth testing, IDOR, XSS, or SQLi - do that part manually
import argparse
import concurrent.futures
import os
import re
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests
requests.packages.urllib3.disable_warnings()

try:
    import dns.resolver
    dns_ok = True
except ImportError:
    dns_ok = False
    print("[!] dnspython not found, skipping email checks")
    print("    pip install dnspython --break-system-packages\n")


#  helpers

def clean_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")

def get_domain(url):
    return urllib.parse.urlparse(url).netloc

def load_targets(filepath):
    targets = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                u = clean_url(line)
                if u:
                    targets.append(u)
    return list(dict.fromkeys(targets))

def req(url, timeout=10, redirects=True, extra_headers=None):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=redirects, headers=headers)
    except Exception:
        return None


#  checks

def check_headers(url, findings):
    r = req(url)
    if not r:
        return

    h = {k.lower(): v for k, v in r.headers.items()}

    missing = [
        ("strict-transport-security", "MEDIUM", "Missing HSTS header"),
        ("x-frame-options",           "MEDIUM", "Missing X-Frame-Options (clickjacking)"),
        ("x-content-type-options",    "LOW",    "Missing X-Content-Type-Options"),
        ("content-security-policy",   "MEDIUM", "Missing Content-Security-Policy"),
        ("referrer-policy",           "LOW",    "Missing Referrer-Policy"),
        ("permissions-policy",        "LOW",    "Missing Permissions-Policy"),
    ]

    for header, sev, title in missing:
        if header not in h:
            findings.append((sev, title, f"not present on {url}"))

    server = h.get("server", "")
    if re.search(r"\d", server):
        findings.append(("LOW", "Server version disclosure", f"Server: {server}"))

    xpb = h.get("x-powered-by", "")
    if xpb:
        findings.append(("LOW", "X-Powered-By disclosure", f"X-Powered-By: {xpb}"))


def check_cors(url, findings):
    test_origins = ["https://evil.com", "null", "https://notreal.com"]

    for origin in test_origins:
        r = req(url, extra_headers={"Origin": origin})
        if not r:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao in (origin, "*"):
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            findings.append((sev, "CORS misconfiguration", f"ACAO: {acao} | ACAC: {acac} | tested origin: {origin}"))
            break


def check_email_security(url, findings):
    if not dns_ok:
        return

    domain = get_domain(url)

    # SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [str(r) for r in answers if "v=spf1" in str(r).lower()]
        if not spf_records:
            findings.append(("HIGH", "Missing SPF record", domain))
        else:
            spf = spf_records[0]
            if "+all" in spf:
                findings.append(("CRITICAL", "SPF uses +all (anyone can send)", spf))
            elif "~all" in spf or "?all" in spf:
                findings.append(("MEDIUM", "SPF soft-fail (~all or ?all)", spf))
    except Exception:
        pass

    # DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in answers if "v=dmarc1" in str(r).lower()]
        if not dmarc_records:
            findings.append(("HIGH", "Missing DMARC record", f"_dmarc.{domain}"))
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc.lower():
                findings.append(("MEDIUM", "DMARC policy is none (no enforcement)", dmarc))
            elif "p=quarantine" in dmarc.lower():
                findings.append(("LOW", "DMARC quarantine (not reject)", dmarc))
    except Exception:
        pass


def check_cookies(url, findings):
    r = req(url)
    if not r:
        return

    for cookie in r.cookies:
        issues = []
        if not cookie.secure:
            issues.append("no Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("no HttpOnly flag")
        if not cookie.get_nonstandard_attr("SameSite", ""):
            issues.append("no SameSite")
        if issues:
            sev = "HIGH" if "no Secure flag" in issues or "no HttpOnly flag" in issues else "LOW"
            findings.append((sev, f"Insecure cookie: {cookie.name}", ", ".join(issues)))


def check_js_secrets(url, findings, output_dir):
    r = req(url)
    if not r:
        return

    js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text, re.I)
    full_js_urls = []
    for js in js_urls:
        if js.startswith("http"):
            full_js_urls.append(js)
        elif js.startswith("//"):
            full_js_urls.append("https:" + js)
        elif js.startswith("/"):
            full_js_urls.append(url + js)
        else:
            full_js_urls.append(url + "/" + js)

    patterns = {
        "AWS access key":       r'AKIA[0-9A-Z]{16}',
        "AWS secret key":       r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?[A-Za-z0-9/+]{40}',
        "Generic API key":      r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
        "Bearer token":         r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}',
        "Private key":          r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        "Slack token":          r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        "Stripe key":           r'sk_(live|test)_[0-9a-zA-Z]{24,}',
        "Google API key":       r'AIza[0-9A-Za-z\-_]{35}',
        "Sentry DSN":           r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io',
        "SendGrid key":         r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        "Hardcoded password":   r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
        "Firebase URL":         r'https://[a-z0-9\-]+\.firebaseio\.com',
    }

    js_save_dir = Path(output_dir) / get_domain(url) / "js_files"
    js_save_dir.mkdir(parents=True, exist_ok=True)

    for js_url in full_js_urls[:20]:
        jr = req(js_url, timeout=8)
        if not jr or not jr.text:
            continue
        content = jr.text
        for name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                safe_name = re.sub(r'[^\w\-]', '_', js_url.split("/")[-1])[:60]
                with open(js_save_dir / safe_name, "w") as f:
                    f.write(content[:50000])
                match_preview = str(matches[0] if isinstance(matches[0], str) else matches[0][0])[:80]
                findings.append(("CRITICAL", f"Secret in JS: {name}", f"{js_url} -> {match_preview}"))


def check_sensitive_paths(url, findings):
    paths = [
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.backup",
        "/config.json", "/config.yaml", "/config.yml", "/wp-config.php.bak",
        "/backup.sql", "/dump.sql", "/phpinfo.php", "/info.php",
        "/server-status", "/server-info", "/actuator", "/actuator/env",
        "/actuator/health", "/api/v1/users", "/api/users",
        "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
        "/robots.txt", "/sitemap.xml", "/.htaccess",
    ]

    for path in paths:
        r = req(url + path, redirects=False, timeout=6)
        if not r:
            continue
        if r.status_code in (200, 206):
            if ".git/HEAD" in path and "ref:" not in r.text[:50]:
                continue
            if any(x in path for x in [".git", ".env", "config", "backup", "dump"]):
                sev = "CRITICAL"
            elif any(x in path for x in ["actuator", "phpinfo", "swagger", "api-docs", "api/users"]):
                sev = "MEDIUM"
            else:
                sev = "INFO"
            findings.append((sev, f"Exposed path: {path}", f"HTTP {r.status_code}, {len(r.text)} bytes"))


def check_open_redirect(url, findings):
    paths = [
        "/redirect?url=https://evil.com",
        "/redirect?next=https://evil.com",
        "/logout?redirect=https://evil.com",
        "/login?next=https://evil.com",
        "/?url=https://evil.com",
        "/?next=https://evil.com",
        "/?redirect=https://evil.com",
        "/?return=https://evil.com",
        "/?returnUrl=https://evil.com",
        "/?goto=https://evil.com",
    ]
    for path in paths:
        r = req(url + path, redirects=False, timeout=6)
        if not r:
            continue
        location = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
            findings.append(("HIGH", "Open redirect", f"{path} -> {location}"))


def check_takeover(url, findings):
    fingerprints = {
        "GitHub Pages":  "There isn't a GitHub Pages site here",
        "Heroku":        "No such app",
        "Shopify":       "Sorry, this shop is currently unavailable",
        "Fastly":        "Fastly error: unknown domain",
        "Netlify":       "Not Found - Request ID",
        "AWS S3":        "NoSuchBucket",
        "Azure":         "404 Web Site not found",
        "SendGrid":      "The provided host name is not valid",
        "Ghost":         "The thing you were looking for is no longer here",
    }
    r = req(url)
    if not r:
        return
    for platform, sig in fingerprints.items():
        if sig.lower() in r.text.lower():
            findings.append(("HIGH", f"Possible subdomain takeover ({platform})", sig))


def check_info_disclosure(url, findings):
    r = req(url)
    if not r:
        return

    patterns = {
        "Internal IP":        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "AWS EC2 instance ID": r'i-[0-9a-f]{8,17}',
        "AWS ARN":            r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\'<>]+',
        "Stack trace":        r'(Traceback \(most recent call last\)|Exception in thread)',
        "SQL error":          r'(SQL syntax|mysql_fetch|ORA-[0-9]{5}|PostgreSQL.*ERROR)',
        "PHP error":          r'(Fatal error:|Warning:|Notice:).{0,200}\.php',
        "Private key":        r'-----BEGIN (RSA |EC )?PRIVATE KEY',
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, r.text)
        if matches:
            if name in ("SQL error", "Stack trace", "Private key", "AWS ARN"):
                sev = "HIGH"
            elif name in ("Internal IP", "AWS EC2 instance ID", "PHP error"):
                sev = "MEDIUM"
            else:
                sev = "LOW"
            preview = str(matches[0])[:100]
            findings.append((sev, f"Info disclosure: {name}", preview))


# ---- run all checks on one target ----

def run_target(url, output_dir):
    domain = get_domain(url)
    target_dir = Path(output_dir) / domain
    target_dir.mkdir(parents=True, exist_ok=True)

    findings = []

    print(f"\n[*] {url}")

    checks = [
        ("headers",        lambda: check_headers(url, findings)),
        ("cors",           lambda: check_cors(url, findings)),
        ("email security", lambda: check_email_security(url, findings)),
        ("cookies",        lambda: check_cookies(url, findings)),
        ("js secrets",     lambda: check_js_secrets(url, findings, output_dir)),
        ("paths",          lambda: check_sensitive_paths(url, findings)),
        ("open redirect",  lambda: check_open_redirect(url, findings)),
        ("takeover",       lambda: check_takeover(url, findings)),
        ("info disclosure",lambda: check_info_disclosure(url, findings)),
    ]

    for name, fn in checks:
        try:
            fn()
            print(f"  [+] {name} done")
        except Exception as e:
            print(f"  [!] {name} error: {e}")

    # print findings
    if findings:
        print(f"\n  findings for {domain}:")
        for sev, title, detail in findings:
            print(f"    [{sev}] {title} — {detail}")
    else:
        print(f"  no findings for {domain}")

    # save to file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = target_dir / f"report_{ts}.txt"
    with open(report_path, "w") as f:
        f.write(f"target: {url}\n")
        f.write(f"date: {datetime.now()}\n")
        f.write("-" * 50 + "\n\n")
        if not findings:
            f.write("no findings\n")
        else:
            for i, (sev, title, detail) in enumerate(findings, 1):
                f.write(f"[{i}] [{sev}] {title}\n")
                f.write(f"     {detail}\n\n")

    print(f"  report saved: {report_path}")
    return (url, findings)


#  master summary

def write_summary(all_results, output_dir):
    path = Path(output_dir) / "summary.txt"
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    with open(path, "w") as f:
        f.write(f"recon summary — {datetime.now()}\n")
        f.write(f"total targets: {len(all_results)}\n")
        f.write("=" * 60 + "\n\n")

        # sort by number of findings
        sorted_results = sorted(all_results, key=lambda x: len(x[1]), reverse=True)

        for url, findings in sorted_results:
            counts = {s: sum(1 for f in findings if f[0] == s) for s in sev_order}
            summary = " | ".join(f"{s}:{counts[s]}" for s in sev_order if counts[s])
            f.write(f"{url}\n")
            f.write(f"  {summary or 'no findings'}\n")
            for sev, title, detail in sorted(findings, key=lambda x: sev_order.index(x[0])):
                f.write(f"  [{sev}] {title}\n")
            f.write("\n")

    print(f"\n[*] summary saved: {path}")


#  main

def main():
    parser = argparse.ArgumentParser(description="recon script for farchase targets")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="single target url")
    group.add_argument("-f", "--file", help="file with list of urls")
    parser.add_argument("-o", "--output", default="./recon_output", help="output folder")
    parser.add_argument("-t", "--threads", type=int, default=5, help="number of threads")
    args = parser.parse_args()

    if args.url:
        targets = [clean_url(args.url)]
    else:
        if not os.path.exists(args.file):
            print(f"[!] file not found: {args.file}")
            sys.exit(1)
        targets = load_targets(args.file)
        print(f"[*] loaded {len(targets)} targets from {args.file}")

    os.makedirs(args.output, exist_ok=True)
    all_results = []

    if args.threads > 1 and len(targets) > 1:
        print(f"[*] running {args.threads} threads\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(run_target, t, args.output): t for t in targets}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    all_results.append(fut.result())
                except Exception as e:
                    print(f"[!] error on {futures[fut]}: {e}")
    else:
        for t in targets:
            all_results.append(run_target(t, args.output))

    write_summary(all_results, args.output)


if __name__ == "__main__":
    main()
