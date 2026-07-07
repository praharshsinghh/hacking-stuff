# master_recon.py

`master_recon.py` chains several lightweight recon steps into one domain-oriented run. It is intended for authorized domains where a quick first-pass report is more useful than a deep specialist scan.

## Modes

- Single target: `python3 master_recon.py -d example.com`
- Target file: `python3 master_recon.py -f domains.txt`
- Dry run: `python3 master_recon.py -d example.com --dry-run`
- Skip stages: combine `--skip-subenum`, `--skip-portscan`, `--skip-tls`, and `--skip-paths`.

## Pipeline

1. Subdomain enumeration through crt.sh plus optional DNS brute force.
2. DNS resolution of discovered names.
3. Port scan using `nmap -Pn -T3 --top-ports 50 <domain>` when available, otherwise socket checks for common ports.
4. TLS certificate/protocol check on port 443.
5. HTTP header audit and simple technology fingerprinting.
6. Sensitive path probes from a built-in list plus optional `/`-prefixed entries in the wordlist.
7. Per-domain report and global summary.

## Output

```text
master_recon_output/
├── summary.txt
└── example.com/
    ├── report.txt
    └── subdomains.txt
```

`report.txt` stores sorted severity findings as `[SEVERITY] title` followed by detail. `summary.txt` ranks domains by critical/high finding count.

## Notes

- `--wordlist` is used for both subdomain brute force and extra sensitive paths.
- Extra sensitive paths must start with `/`.
- Path findings are presence/status-code based and should be manually verified.
- TLS checks are best-effort with Python `ssl`; handshake errors are recorded as `INFO`.
