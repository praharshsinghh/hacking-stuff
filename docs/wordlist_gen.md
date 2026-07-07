# wordlist_gen.py

`wordlist_gen.py` is an offline generator. It does not attempt authentication, make network requests, or validate generated candidates.

## CSV Generation

```bash
python3 wordlist_gen.py --from-info company.csv -o wordlists_out
```

Accepted CSV columns:

- Company: `company` or `Company`
- First name: `first`, `first_name`, or `firstname`
- Last name: `last`, `last_name`, or `lastname`

Outputs:

- `generated_usernames.txt`
- `generated_passwords.txt`
- `summary.txt`

## Mutation

```bash
python3 wordlist_gen.py --mutate base_words.txt -o mutated_out
```

Mutation includes case variants, simple leetspeak substitutions, years 2020 through 2026, and common suffixes. The mode also writes `wordlist.rules` for Hashcat-style mutation workflows.

Outputs:

- `mutated_wordlist.txt`
- `wordlist.rules`
- `summary.txt`
