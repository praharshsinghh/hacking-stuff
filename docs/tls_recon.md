# tls_recon.py

`tls_recon.py` is the broader TLS audit script. It uses Python `ssl` for direct negotiation, optional `requests` for redirect checks, and optional `nmap` for cipher enumeration.

## Modes

- Single target: `python3 tls_recon.py -u https://example.com`
- Target file: `python3 tls_recon.py -f targets.txt -t 10`
- Text-only output: add `--text-only`
- JSON-only output: add `--json-only`

Default mode writes both text and JSON target reports.

## Checks

- Certificate validity window and expiry severity.
- Hostname/SAN match.
- Certificate subject and issuer metadata.
- OCSP stapling availability.
- Chain-depth availability and basic issuer trust heuristics.
- Negotiated TLS version and cipher.
- HTTPS redirect to HTTP.
- Optional weak cipher hits from `nmap --script ssl-enum-ciphers`.

## Output

```text
tls_recon_output/
├── summary.txt
├── summary.json
└── example.com/
    ├── report_<timestamp>.txt
    └── report.json
```

`--text-only` suppresses JSON files. `--json-only` suppresses per-target text reports but still writes `summary.txt`.

## Notes

- Bare hosts are normalized to `https://`.
- Default port is 443 unless a port is included in the URL.
- Trust checks are heuristics and should be verified with a dedicated TLS scanner before reporting.
