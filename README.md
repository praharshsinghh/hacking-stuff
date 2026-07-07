# hacking-stuff

Personal security toolkit for CTFs, authorized penetration testing, and personal infrastructure management. The repo is convention-first: `recon_auto_webs.py` is the style reference for safety headers, argparse CLIs, severity-tuple findings, graceful degradation, and per-target plus summary report output.

## ⚠️ Scope & Authorization

Only run these tools against targets you own or are explicitly authorized to test, such as CTF scope, a signed pentest agreement, or your own infrastructure. Do not scan, enumerate, brute force, or generate target-specific attack material for systems outside approved scope, even if they appear interesting or are discovered by accident. Unauthorized testing is illegal in most jurisdictions.

## Repository Structure

Current layout is flat:

```text
.
├── master_recon.py
├── recon_auto_webs.py
├── report_gen.py
├── subdomain_enum.py
├── tls_check.py
├── tls_recon.py
├── wordlist_gen.py
├── requirements.txt
└── docs/
```

Expected folder conventions for growth:

- `wordlists/`: input wordlists, generated lists that are safe to keep, and non-sensitive fixtures.
- `scripts/`: standalone tooling once the root becomes crowded.
- `cheatsheets/`: CTF and assessment reference notes.
- `writeups/`: sanitized CTF writeups and authorized engagement notes.
- `templates/`: report templates, convention prompts, and review prompts.
- `configs/`: non-secret configuration examples.
- `docs/`: deeper usage notes for tools with multiple modes or many flags.

## Tools

**Orchestrators**

### `master_recon.py`

**Purpose:** Chains domain reconnaissance into one workflow: subdomain discovery, DNS alive checks, port scanning, TLS review, HTTP header audit, sensitive path checks, and basic technology fingerprinting.

**Category:** Orchestrator

**Key features:**

- Uses `(severity, title, detail)` findings with `CRITICAL/HIGH/MEDIUM/LOW/INFO`.
- Uses `nmap` when available, with socket-connect fallback over a small common port list.
- Supports crt.sh lookup, optional DNS brute force, threaded multi-target runs, skip flags, and dry-run mode.
- Produces per-target reports and a ranked summary.

**Usage:**

```bash
python3 master_recon.py [-d DOMAIN | -f FILE] [-w WORDLIST] [-o OUTPUT] [-T THREADS] [--skip-subenum] [--skip-portscan] [--skip-tls] [--skip-paths] [--dry-run]
```

Defaults: `--output ./master_recon_output`, `--threads 5`; all skip flags and `--dry-run` default to false.

Example:

```bash
python3 master_recon.py -d example.com -w wordlists/subdomains.txt -o results/master -T 10
```

**Inputs:** A single domain or a file of domains; optional wordlist for DNS brute force and sensitive path checks.

**Output:** `<output>/<domain>/subdomains.txt`, `<output>/<domain>/report.txt`, and `<output>/summary.txt`.

**Dependencies:** Python packages `requests` and optional `dnspython`; external binary `nmap` is optional and has a socket fallback.

**Safety/scope notes:** Has a detailed authorized-scope warning, user-agent marker, fixed timeouts, and small sleeps during brute force and path checks.

**Convention compliance:** Closely follows `recon_auto_webs.py`: severity tuples, consistent short/long argparse flags, per-target report plus summary. Report filename is fixed as `report.txt` instead of timestamped `report_*.txt`.

**Deep usage:** See [`docs/master_recon.md`](docs/master_recon.md).

**Recon / Enumeration**

### `recon_auto_webs.py`

**Purpose:** Runs a web reconnaissance and light vulnerability audit against one URL or a list of URLs.

**Category:** Recon/Enumeration

**Key features:**

- Checks security headers, CORS, SPF/DMARC, cookies, JavaScript secrets, sensitive paths, open redirect probes, takeover fingerprints, and information disclosure.
- Uses threaded execution for multi-target files.
- Saves JavaScript files only when a secret pattern is found.
- Writes timestamped per-target reports and a global summary.

**Usage:**

```bash
python3 recon_auto_webs.py (-u URL | -f FILE) [-o OUTPUT] [-t THREADS]
```

Defaults: `--output ./recon_output`, `--threads 5`.

Example:

```bash
python3 recon_auto_webs.py -f targets.txt -t 10 -o recon_output
```

**Inputs:** A single URL or a file of URLs. Bare hostnames are normalized to `https://`.

**Output:** `recon_output/summary.txt`, `recon_output/<domain>/report_<timestamp>.txt`, and `recon_output/<domain>/js_files/<saved-js>` when JavaScript secrets are detected.

**Dependencies:** Python packages `requests` and optional `dnspython`; no external binaries.

**Safety/scope notes:** Has an authorized-target warning and notes that low/info findings, CORS, and open redirect checks require manual verification. No explicit rate-limit flag; request volume is bounded by fixed probe lists.

**Convention compliance:** This is the style reference. It uses severity tuples, the standard severity vocabulary, argparse flags, per-target reports, and a summary.

### `subdomain_enum.py`

**Purpose:** Enumerates subdomains using crt.sh, common permutations, optional DNS brute force, and DNS/HTTP liveness checks.

**Category:** Recon/Enumeration

**Key features:**

- Accepts one domain or a domain file.
- Performs crt.sh certificate transparency lookup when `requests` is installed.
- Performs DNS A/AAAA/CNAME resolution and basic wildcard-DNS detection when `dnspython` is installed.
- Optional DNS brute force with a configurable delay.
- Emits text and JSON subdomain data.

**Usage:**

```bash
python3 subdomain_enum.py (-d DOMAIN | -f FILE) [-w WORDLIST] [-o OUTPUT] [-T THREADS] [--dry-run] [--delay DELAY]
```

Defaults: `--output ./subdomains_output`, `--threads 5`, `--delay 0.15`; `--dry-run` defaults to false.

Example:

```bash
python3 subdomain_enum.py -d example.com -w wordlists/subdomains.txt -T 5 --delay 0.2 -o subdomains_output
```

**Inputs:** A single domain or file of domains; optional brute-force wordlist.

**Output:** `subdomains_output/summary.txt`, `subdomains_output/<domain>/all_subdomains.txt`, `subdomains_output/<domain>/subdomains.txt`, and `subdomains_output/<domain>/subdomains.json`.

**Dependencies:** Optional Python packages `requests` and `dnspython`; no external binaries. If missing, crt.sh or DNS-dependent checks are disabled.

**Safety/scope notes:** Has an authorized-scope warning, a brute-force delay default, and dry-run mode.

**Convention compliance:** Partially follows the conventions. CLI and output layout match the style, but findings are internal `(name, source)` subdomain records rather than severity tuples because it is an enumerator, not a vulnerability reporter.

**Deep usage:** See [`docs/subdomain_enum.md`](docs/subdomain_enum.md).

**Vulnerability Testing**

### `tls_check.py`

**Purpose:** Checks TLS certificate and negotiation posture for one target or a list of targets using Python SSL plus `cryptography`.

**Category:** Vulnerability Testing

**Key features:**

- Checks expiry, weak protocol/cipher negotiation, self-signed certificates, SAN/CN mismatch, and OCSP stapling.
- Supports threaded scans for target files.
- Gracefully degrades when `cryptography` is missing by recording parsing-unavailable findings.
- Writes timestamped per-target text reports and a severity summary.

**Usage:**

```bash
python3 tls_check.py (-u URL | -f FILE) [-o OUTPUT] [-T THREADS]
```

Defaults: `--output ./tls_check_output`, `--threads 5`.

Example:

```bash
python3 tls_check.py -f targets.txt -T 5 -o tls_check_output
```

**Inputs:** A single URL/host or a file of targets. Bare hosts are normalized to `https://`; default port is 443 unless present in the URL.

**Output:** `tls_check_output/summary.txt` and `tls_check_output/<host>/report_<timestamp>.txt`.

**Dependencies:** Python package `cryptography`; no external binaries.

**Safety/scope notes:** Has an authorized-scope warning. Uses socket timeouts; no explicit rate-limit delay.

**Convention compliance:** Follows severity tuple findings, argparse flag style, per-target reports, and summary structure.

### `tls_recon.py`

**Purpose:** Performs a broader TLS audit for one HTTPS target or a file of targets, including certificate metadata, trust heuristics, negotiation checks, redirect checks, and optional nmap cipher probing.

**Category:** Vulnerability Testing

**Key features:**

- Checks certificate validity, SAN matching, metadata disclosure, OCSP stapling, chain/trust heuristics, TLS version/cipher, HTTPS-to-HTTP redirects, and optional weak cipher hits.
- Supports threaded target files.
- Supports text, JSON, or both output modes.
- Uses `nmap --script ssl-enum-ciphers` when available; records an INFO finding when unavailable.

**Usage:**

```bash
python3 tls_recon.py (-u URL | -f FILE) [-t THREADS] [-o OUTPUT] [--text-only | --json-only]
```

Defaults: `--threads 5`, `--output ./tls_recon_output`; default output mode is both text and JSON.

Example:

```bash
python3 tls_recon.py -u https://example.com -o tls_recon_output --json-only
```

**Inputs:** A single HTTPS URL/host or a file of targets. Bare hosts are normalized to `https://`; default port is 443 unless present in the URL.

**Output:** Always writes `tls_recon_output/summary.txt`; in default/both mode also writes `tls_recon_output/summary.json`, `<host>/report_<timestamp>.txt`, and `<host>/report.json`. `--text-only` suppresses JSON. `--json-only` suppresses per-target text reports but still writes text summary.

**Dependencies:** Optional Python package `requests` for HTTPS redirect checks; external binary `nmap` is optional for cipher enumeration and has an INFO fallback.

**Safety/scope notes:** Has an authorized-scope warning and network timeouts. No explicit rate-limit delay.

**Convention compliance:** Follows severity tuple findings, standard severity vocabulary, argparse flag style, per-target reports, and summary. It extends the convention with JSON output.

**Deep usage:** See [`docs/tls_recon.md`](docs/tls_recon.md).

**Password / Wordlist Tooling**

### `wordlist_gen.py`

**Purpose:** Generates offline username/password candidates from company/person CSV data or mutates an existing wordlist.

**Category:** Password/Wordlist Tooling

**Key features:**

- Two mutually exclusive modes: `--from-info` CSV generation and `--mutate` wordlist expansion.
- Generates username permutations from first/last names.
- Generates company/year/special-character password variants for years 2020 through 2026.
- Writes a Hashcat-compatible rule file in mutate mode.

**Usage:**

```bash
python3 wordlist_gen.py (--from-info CSV | --mutate WORDLIST) [-o OUTPUT]
```

Default: `--output ./wordlist_gen_output`.

Example:

```bash
python3 wordlist_gen.py --from-info company.csv -o wordlists_out
```

**Inputs:** CSV with `company`, `first`, and `last` columns or recognized variants (`Company`, `first_name`, `firstname`, `last_name`, `lastname`); or a plain-text base wordlist.

**Output:** From-info mode writes `generated_usernames.txt`, `generated_passwords.txt`, and `summary.txt`. Mutate mode writes `mutated_wordlist.txt`, `wordlist.rules`, and `summary.txt`.

**Dependencies:** Standard library only; no external binaries.

**Safety/scope notes:** Has an authorized-scope warning. It is offline and does not perform login attempts or network activity.

**Convention compliance:** CLI style and safety header are consistent. Severity tuple findings and per-target report structure do not apply because this is an offline generator.

**Deep usage:** See [`docs/wordlist_gen.md`](docs/wordlist_gen.md).

**Reporting / Workflow**

### `report_gen.py`

**Purpose:** Converts `recon_auto_webs.py`-style output folders into self-contained HTML or Markdown reports.

**Category:** Reporting/Workflow

**Key features:**

- Parses `summary.txt` and latest `report_*.txt` under each target directory.
- Aggregates severity counts.
- Supports HTML and Markdown output.
- Uses `jinja2` when installed; falls back to built-in string templates, although the current fallback path renders Markdown when `jinja2` is missing.

**Usage:**

```bash
python3 report_gen.py -i INPUT -o OUTPUT [--format {html,markdown}]
```

Default: `--format html`.

Example:

```bash
python3 report_gen.py -i recon_output -o report.html
```

**Inputs:** A recon output directory containing `summary.txt` and per-target `report_*.txt` files, or a parent directory with one child that contains `summary.txt`.

**Output:** One HTML or Markdown file at the requested output path.

**Dependencies:** Optional Python package `jinja2`; no external binaries.

**Safety/scope notes:** Has a report-only authorized-assessment warning. It performs local file parsing only.

**Convention compliance:** Depends on the `recon_auto_webs.py` text report convention and parses severity labels. It does not generate tuple findings itself.

## Conventions

No master conventions prompt was found under `/templates` or `/docs` at the time this README was generated.

- Use argparse with clear short/long flags, mutually exclusive input groups where applicable, and documented defaults.
- Use `(severity, title, detail)` findings for tools that report security observations.
- Use only `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO` severities.
- Write per-target reports plus a summary file for multi-target tools.
- Include an authorized-scope warning header in every executable security tool.
- Prefer graceful degradation: if an optional Python package or external binary is missing, skip or downgrade that feature with a clear message/finding.
- Keep generated secrets, credentials, customer data, and sensitive assessment output out of version control.
- Use fixed timeouts and bounded probe lists; add explicit delay/rate-limit controls to brute-force or enumeration paths.

## Setup

Python observed locally: `Python 3.14.4`.

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

External tools:

- `nmap`: optional for `master_recon.py` port scanning and `tls_recon.py` cipher enumeration. Without it, `master_recon.py` uses a small socket scan and `tls_recon.py` records the optional probe as unavailable.
- `git-lfs`: not used by the current Python scripts.

Example Debian/Ubuntu install:

```bash
sudo apt-get update
sudo apt-get install -y nmap
```

## Contributing / Adding New Tools

New tools should be specced and reviewed against the conventions above before they are considered complete. No code review prompt was found in the repo; add one under `templates/` or `docs/` before relying on a shared review workflow.
