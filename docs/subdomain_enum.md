# subdomain_enum.py

`subdomain_enum.py` enumerates candidate subdomains and writes both text and JSON output. It separates discovery from liveness: `all_subdomains.txt` contains all candidates, while `subdomains.txt` contains names with DNS records when DNS support is available.

## Modes

- Single domain: `python3 subdomain_enum.py -d example.com`
- Domain file: `python3 subdomain_enum.py -f domains.txt`
- Optional DNS brute force: add `-w wordlist.txt`
- Preview only: add `--dry-run`

## Discovery Sources

- crt.sh JSON lookup when `requests` is installed.
- Built-in permutations: `dev`, `staging`, `api`, and `test`.
- Optional wordlist brute force when `dnspython` is installed.

## Output

```text
subdomains_output/
├── summary.txt
└── example.com/
    ├── all_subdomains.txt
    ├── subdomains.txt
    └── subdomains.json
```

The JSON output records the subdomain name, DNS liveness, DNS records, HTTP liveness, and HTTP status where available.

## Rate Controls

`--delay` controls the sleep between brute-force DNS candidates. The default is `0.15` seconds.

## Dependency Behavior

- Without `requests`, crt.sh lookup and HTTP probes are disabled.
- Without `dnspython`, DNS resolution, wildcard detection, and brute force are disabled.
