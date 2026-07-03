#!/usr/bin/env python3
"""
Purpose:
  Enumerate subdomains for authorized domains using crt.sh, optional DNS brute force,
  and a few common name permutations, then resolve what is alive.

Usage examples:
  python3 subdomain_enum.py -d example.com
  python3 subdomain_enum.py -f domains.txt -w wordlist.txt -T 5 -o subdomains_output

What it checks:
  - crt.sh certificate transparency JSON results
  - Optional DNS brute force from a wordlist
  - Common permutations: dev-, staging-, api-, test- + base domain
  - DNS resolution for A / AAAA / CNAME records
  - Alive vs dead status based on successful resolution

Output structure:
  subdomains_output/
    summary.txt
    <domain>/
      all_subdomains.txt
      subdomains.txt

Limitations / false-positive-prone checks:
  - crt.sh can return stale or historical names that no longer resolve.
  - DNS brute force can miss wildcard records and is rate-limited by design.
  - Alive/dead is based on current DNS resolution, not HTTP reachability.
  - CNAME chains may point to externally hosted services and still be valid.

WARNING:
  Only run on targets you are authorized to test.
  Do not enumerate domains outside your approved scope.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    requests = None
    print("[!] requests not found, crt.sh lookups will be disabled")
    print("    pip install requests --break-system-packages\n")

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False
    dns = None
    print("[!] dnspython not found, DNS resolution and brute force will be disabled")
    print("    pip install dnspython --break-system-packages\n")


#  helpers

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DEFAULT_PERMUTATIONS = ["dev", "staging", "api", "test"]


def clean_domain(value):
    value = value.strip().lower()
    if not value or value.startswith("#"):
        return None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.strip(".")
    return value or None


def load_domains(filepath):
    domains = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            domain = clean_domain(line)
            if domain:
                domains.append(domain)
    return list(dict.fromkeys(domains))


def load_wordlist(filepath):
    words = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                words.append(word)
    return list(dict.fromkeys(words))


def safe_name(value):
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)


def make_session():
    if not REQUESTS_OK:
        return None
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        }
    )
    return s


def http_probe(name, timeout=8):
    if not REQUESTS_OK:
        return None
    session = make_session()
    for scheme in ("https", "http"):
        url = f"{scheme}://{name}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return {"alive": True, "url": url, "status": r.status_code}
        except Exception:
            continue
    return {"alive": False, "url": "", "status": 0}


def wildcard_answers(domain):
    if not DNS_OK:
        return set()
    bogus = f"{int(time.time())}-does-not-exist.{domain}"
    answers = set()
    for qtype in ("A", "AAAA", "CNAME"):
        for item in dns_query(bogus, qtype):
            answers.add(f"{qtype}:{item}")
    return answers


def crtsh_lookup(domain, session=None):
    if not REQUESTS_OK:
        return set()

    session = session or make_session()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = session.get(url, timeout=20)
        if r.status_code != 200:
            print(f"[!] crt.sh returned HTTP {r.status_code} for {domain}")
            return set()
        data = r.json()
    except json.JSONDecodeError:
        print(f"[!] crt.sh returned non-JSON for {domain}")
        return set()
    except Exception as e:
        print(f"[!] crt.sh lookup failed for {domain}: {e}")
        return set()

    names = set()
    for item in data:
        name_value = item.get("name_value", "")
        for raw_name in str(name_value).splitlines():
            raw_name = raw_name.strip().lower().lstrip("*.")
            if raw_name.endswith("." + domain) and raw_name != domain:
                names.add(raw_name)
    return names


def dns_query(name, qtype):
    if not DNS_OK:
        return []
    try:
        answers = dns.resolver.resolve(name, qtype, lifetime=4)
        return [str(a).strip() for a in answers]
    except Exception:
        return []


def resolve_subdomain(name):
    if not DNS_OK:
        return {"alive": False, "records": []}

    records = []
    a_records = dns_query(name, "A")
    aaaa_records = dns_query(name, "AAAA")
    cname_records = dns_query(name, "CNAME")

    if a_records:
        records.extend([f"A:{r}" for r in a_records])
    if aaaa_records:
        records.extend([f"AAAA:{r}" for r in aaaa_records])
    if cname_records:
        records.extend([f"CNAME:{r}" for r in cname_records])

    return {"alive": bool(records), "records": records}


def build_permutations(domain):
    return [f"{prefix}.{domain}" for prefix in DEFAULT_PERMUTATIONS]


def brute_force_candidates(domain, wordlist, delay=0.15):
    found = set()
    if not DNS_OK:
        return found

    for word in wordlist:
        candidate = f"{word}.{domain}"
        result = resolve_subdomain(candidate)
        if result["alive"]:
            found.add(candidate)
            print(f"  [+] {candidate} -> alive")
        else:
            print(f"  [*] {candidate} -> dead")
        time.sleep(delay)
    return found


def collect_findings(domain, wordlist=None, delay=0.15):
    findings = []
    seen = set()

    def add(name, source):
        if name and name not in seen and name.endswith("." + domain):
            seen.add(name)
            findings.append((name, source))

    session = make_session()
    print(f"[*] querying crt.sh for {domain}")
    for name in sorted(crtsh_lookup(domain, session=session)):
        add(name, "crt.sh")

    for name in build_permutations(domain):
        add(name, "permutation")

    if wordlist:
        print(f"[*] brute forcing {domain} with {len(wordlist)} words")
        brute_found = brute_force_candidates(domain, wordlist, delay=delay)
        for name in brute_found:
            add(name, "bruteforce")

    return findings


def write_domain_outputs(domain, findings, output_dir, json_data=None):
    domain_dir = Path(output_dir) / safe_name(domain)
    domain_dir.mkdir(parents=True, exist_ok=True)

    all_path = domain_dir / "all_subdomains.txt"
    alive_path = domain_dir / "subdomains.txt"

    all_names = sorted({name for name, _ in findings})
    alive_names = []

    if DNS_OK:
        for name in all_names:
            res = resolve_subdomain(name)
            if res["alive"]:
                alive_names.append(name)
    else:
        alive_names = all_names[:]

    with open(all_path, "w", encoding="utf-8") as f:
        for name in all_names:
            f.write(name + "\n")

    with open(alive_path, "w", encoding="utf-8") as f:
        for name in alive_names:
            f.write(name + "\n")

    if json_data is not None:
        json_path = domain_dir / "subdomains.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, sort_keys=True)
        print(f"  [+] wrote {json_path}")

    print(f"  [+] wrote {all_path}")
    print(f"  [+] wrote {alive_path}")

    return {
        "domain": domain,
        "all_count": len(all_names),
        "alive_count": len(alive_names),
        "all_path": str(all_path),
        "alive_path": str(alive_path),
    }


#  checks

def run_target(domain, output_dir, wordlist=None, delay=0.15, dry_run=False):
    print(f"\n[*] {domain}")
    if dry_run:
        preview = build_permutations(domain)
        print(f"  [+] dry-run permutations: {', '.join(preview)}")
        if wordlist:
            print(f"  [+] dry-run wordlist entries: {len(wordlist)}")
        return {
            "domain": domain,
            "all_count": 0,
            "alive_count": 0,
            "all_path": "",
            "alive_path": "",
        }

    findings = []
    try:
        wildcard = wildcard_answers(domain)
        if wildcard:
            print(f"  [!] wildcard DNS detected for {domain}: {', '.join(sorted(wildcard))}")
        findings = collect_findings(domain, wordlist=wordlist, delay=delay)
        print(f"  [+] collected {len(findings)} unique candidates")
    except Exception as e:
        print(f"  [!] collection error: {e}")

    try:
        for name, source in findings:
            print(f"  [+] {source}: {name}")
    except Exception as e:
        print(f"  [!] printing error: {e}")

    try:
        json_payload = {
            "domain": domain,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "subdomains": [],
        }
        seen_names = sorted({name for name, _ in findings})
        for name in seen_names:
            dns_result = resolve_subdomain(name)
            http_result = http_probe(name)
            json_payload["subdomains"].append(
                {
                    "name": name,
                    "alive_dns": dns_result["alive"],
                    "records": dns_result["records"],
                    "alive_http": bool(http_result and http_result.get("alive")),
                    "http": http_result or {},
                }
            )
        return write_domain_outputs(domain, findings, output_dir, json_data=json_payload)
    except Exception as e:
        print(f"  [!] output write error: {e}")
        return {
            "domain": domain,
            "all_count": len(findings),
            "alive_count": 0,
            "all_path": "",
            "alive_path": "",
        }


def write_summary(results, output_dir):
    path = Path(output_dir) / "summary.txt"
    sorted_results = sorted(
        results,
        key=lambda item: (item.get("alive_count", 0), item.get("all_count", 0)),
        reverse=True,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write("subdomain enumeration summary\n")
        f.write(f"total domains: {len(results)}\n")
        f.write("=" * 72 + "\n\n")
        for item in sorted_results:
            f.write(f"{item['domain']}\n")
            f.write(f"  alive: {item.get('alive_count', 0)} | all: {item.get('all_count', 0)}\n")
            if item.get("alive_path"):
                f.write(f"  alive file: {item['alive_path']}\n")
            if item.get("all_path"):
                f.write(f"  all file: {item['all_path']}\n")
            f.write("\n")

    print(f"\n[*] summary saved: {path}")


#  main

def main():
    parser = argparse.ArgumentParser(description="subdomain enumerator for authorized domains")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="single domain")
    group.add_argument("-f", "--file", help="file with list of domains")
    parser.add_argument("-w", "--wordlist", help="wordlist for optional DNS brute force")
    parser.add_argument("-o", "--output", default="./subdomains_output", help="output folder")
    parser.add_argument("-T", "--threads", type=int, default=5, help="number of threads")
    parser.add_argument("--dry-run", action="store_true", help="preview candidate names without querying DNS")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="delay in seconds between brute-force DNS queries",
    )
    args = parser.parse_args()

    if args.domain:
        domains = [clean_domain(args.domain)]
    else:
        if not os.path.exists(args.file):
            print(f"[!] file not found: {args.file}")
            sys.exit(1)
        domains = load_domains(args.file)
        print(f"[*] loaded {len(domains)} domains from {args.file}")

    domains = [d for d in domains if d]
    if not domains:
        print("[!] no valid domains provided")
        sys.exit(1)

    wordlist = None
    if args.wordlist:
        if not os.path.exists(args.wordlist):
            print(f"[!] wordlist not found: {args.wordlist}")
            sys.exit(1)
        wordlist = load_wordlist(args.wordlist)
        print(f"[*] loaded {len(wordlist)} brute-force words from {args.wordlist}")

    os.makedirs(args.output, exist_ok=True)
    results = []

    if args.threads > 1 and len(domains) > 1:
        print(f"[*] running {args.threads} threads")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(run_target, domain, args.output, wordlist, args.delay, args.dry_run): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(futures):
                domain = futures[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    print(f"[!] error on {domain}: {e}")
    else:
        for domain in domains:
            results.append(run_target(domain, args.output, wordlist, args.delay, args.dry_run))

    write_summary(results, args.output)


if __name__ == "__main__":
    main()
