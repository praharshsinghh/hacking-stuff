#!/usr/bin/env python3
"""
Purpose:
  Generate offline username and password wordlists for authorized assessments.

Usage examples:
  python3 wordlist_gen.py --from-info company.csv -o wordlists_out
  python3 wordlist_gen.py --mutate base_words.txt -o mutated_out

What it checks:
  - Mode 1: builds username permutations from company name and employee names
  - Mode 1: builds common password patterns from company name and year variants
  - Mode 2: mutates an existing wordlist with leetspeak, years, case variants, and suffixes
  - Mode 2: writes a Hashcat-compatible .rule file alongside the expanded wordlist

Output structure:
  output/
    generated_usernames.txt
    generated_passwords.txt
    mutated_wordlist.txt
    wordlist.rules
    summary.txt

Limitations / false-positive-prone checks:
  - Generated material is heuristic and may include many weak or redundant candidates.
  - Username permutations are generic and should be trimmed to the target's naming style.
  - Password patterns are intentionally broad and require manual review before use.

WARNING:
  Only run on targets you are authorized to test.
  Do not use generated material outside approved scope.
"""

import argparse
import csv
import os
from pathlib import Path


#  helpers

YEARS = [str(y) for y in range(2020, 2027)]
SPECIALS = ["!", "@", "#", "$", "1"]
LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def clean_token(value):
    return "".join(ch for ch in value.strip() if ch.isalnum())


def title_token(value):
    token = clean_token(value)
    return token.capitalize() if token else ""


def lower_token(value):
    return clean_token(value).lower()


def dedupe(items):
    return sorted(dict.fromkeys(item for item in items if item))


def load_csv_info(filepath):
    rows = []
    with open(filepath, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            company = row.get("company") or row.get("Company") or ""
            first = row.get("first") or row.get("first_name") or row.get("firstname") or ""
            last = row.get("last") or row.get("last_name") or row.get("lastname") or ""
            rows.append(
                {
                    "company": company.strip(),
                    "first": first.strip(),
                    "last": last.strip(),
                }
            )
    return rows


def username_variants(first, last):
    first_l = lower_token(first)
    last_l = lower_token(last)
    if not first_l or not last_l:
        return []
    first_i = first_l[0]
    last_i = last_l[0]
    return [
        f"{first_l}.{last_l}",
        f"{first_l}{last_l}",
        f"{first_i}{last_l}",
        f"{first_l}{last_i}",
        f"{first_l}_{last_l}",
        f"{first_l}-{last_l}",
        f"{last_l}.{first_l}",
        f"{last_l}{first_l}",
        f"{first_l}{last_i}{last_i}",
        f"{first_i}.{last_l}",
    ]


def company_password_variants(company):
    base = clean_token(company)
    title = title_token(company)
    lower = lower_token(company)
    if not base:
        return []

    variants = set()
    for form in {base, title, lower}:
        for year in YEARS:
            variants.update(
                {
                    f"{form}{year}",
                    f"{form}{year}!",
                    f"{form}@{year}",
                    f"{form}#{year}",
                    f"{form}{year}#",
                    f"{form}{year}$",
                }
            )
        variants.update(
            {
                f"{form}!",
                f"{form}123",
                f"{form}123!",
                f"{form}2024!",
                f"{form}2025!",
                f"{form}2026!",
            }
        )
    return sorted(variants)


def write_lines(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(item + "\n")


def build_from_info(csv_path, output_dir):
    rows = load_csv_info(csv_path)
    usernames = []
    passwords = []

    for row in rows:
        company = row["company"]
        first = row["first"]
        last = row["last"]
        usernames.extend(username_variants(first, last))
        passwords.extend(company_password_variants(company))
        if first and last:
            passwords.extend(
                [
                    f"{title_token(first)}{title_token(last)}2024!",
                    f"{lower_token(first)}{lower_token(last)}2024!",
                    f"{lower_token(first)}.{lower_token(last)}2024!",
                ]
            )

    usernames = dedupe(usernames)
    passwords = dedupe(passwords)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_lines(out / "generated_usernames.txt", usernames)
    write_lines(out / "generated_passwords.txt", passwords)

    summary = out / "summary.txt"
    with open(summary, "w", encoding="utf-8") as f:
        f.write("wordlist generation summary\n")
        f.write(f"source rows: {len(rows)}\n")
        f.write(f"usernames generated: {len(usernames)}\n")
        f.write(f"passwords generated: {len(passwords)}\n")

    print(f"[*] usernames: {len(usernames)}")
    print(f"[*] passwords: {len(passwords)}")
    print(f"[*] wrote {out / 'generated_usernames.txt'}")
    print(f"[*] wrote {out / 'generated_passwords.txt'}")
    print(f"[*] wrote {summary}")


def mutate_word(word):
    variants = {word}
    variants.add(word.lower())
    variants.add(word.upper())
    variants.add(word.capitalize())
    variants.add(word.translate(LEET_MAP))
    variants.add(word.lower().translate(LEET_MAP))
    variants.add(word.capitalize().translate(LEET_MAP))

    expanded = set()
    for base in variants:
        expanded.add(base)
        for year in YEARS:
            expanded.add(f"{base}{year}")
            expanded.add(f"{base}{year}!")
            expanded.add(f"{base}{year}@")
        for special in SPECIALS:
            expanded.add(f"{base}{special}")
    return expanded


def build_rules(words):
    rules = []
    rules.extend([":", "l", "u", "c"])
    for year in YEARS:
        rules.append("".join(f"${ch}" for ch in year))
        rules.append("".join(f"${ch}" for ch in year) + "!")
    rules.append("$!")
    rules.extend([f"$1", f"$@", f"$#"])
    for word in words[:200]:
        if len(word) >= 4:
            rules.append("c$1")
    return dedupe(rules)


def build_mutate(wordlist_path, output_dir):
    with open(wordlist_path, "r", encoding="utf-8") as f:
        base_words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    mutated = set()
    for word in base_words:
        mutated.update(mutate_word(word))

    mutated = dedupe(mutated)
    rules = build_rules(base_words)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    wordlist_out = out / "mutated_wordlist.txt"
    rule_out = out / "wordlist.rules"
    write_lines(wordlist_out, mutated)
    write_lines(rule_out, rules)

    summary = out / "summary.txt"
    with open(summary, "w", encoding="utf-8") as f:
        f.write("wordlist mutation summary\n")
        f.write(f"base words: {len(base_words)}\n")
        f.write(f"mutated entries: {len(mutated)}\n")
        f.write(f"rules generated: {len(rules)}\n")

    print(f"[*] mutated entries: {len(mutated)}")
    print(f"[*] rules: {len(rules)}")
    print(f"[*] wrote {wordlist_out}")
    print(f"[*] wrote {rule_out}")
    print(f"[*] wrote {summary}")


#  checks

def run():
    parser = argparse.ArgumentParser(description="offline wordlist generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--from-info", help="CSV input with company, first, and last columns")
    group.add_argument("--mutate", help="existing wordlist to mutate")
    parser.add_argument("-o", "--output", default="./wordlist_gen_output", help="output folder")
    args = parser.parse_args()

    if args.from_info:
        if not os.path.exists(args.from_info):
            print(f"[!] file not found: {args.from_info}")
            raise SystemExit(1)
        build_from_info(args.from_info, args.output)
    else:
        if not os.path.exists(args.mutate):
            print(f"[!] file not found: {args.mutate}")
            raise SystemExit(1)
        build_mutate(args.mutate, args.output)


#  main

def main():
    run()


if __name__ == "__main__":
    main()
