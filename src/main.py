#!/usr/bin/python3
"""
Reads messy raw text, pulls out emails, credit card numbers, phone
numbers, and URLs, and screens every line for attack patterns first
so nothing malicious gets treated as trustworthy data.
"""

import json
import re
import sys
from pathlib import Path
""" Project root folder, so paths work no matter where you run the script from. """
BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "input" / "raw-text.txt"
OUTPUT_FILE = BASE_DIR / "output" / "sample-output.json"

""" Matches standard email addresses: name@domain.tld. """
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

""" Matches 13-19 digit runs (spaces/dashes allowed) that could be a card number.
    Lookbehind/lookahead stop it from grabbing part of a longer digit string. """
CARD_CANDIDATE_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

""" Matches http/https links, stops at whitespace or a quote character. """ 
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

""" Matches common phone formats: +country code, parentheses, dashes, dots, or none at all. """"
PHONE_PATTERN = re.compile(r"(?<!\w)\+?\(?\d{2,4}\)?[\d\-.\s]{5,15}\d(?!\w)")
"""" Attack patterns to reject: script tags, JS links, event handlers, and SQL injection. """"
SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"(--|;)\s*(drop|delete|update|insert)\b", re.IGNORECASE),
    re.compile(r"'\s*(or|and)\s*'?\d*'?\s*=\s*'?\d*", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
]
""" The three real ALU domains, and their category they belong to. """
ALU_DOMAINS = {
    "alueducation.com": "official",
    "alumni.alueducation.com": "alumni",
    "si.alueducation.com": "si",
}


def read_input(path):
    """Loads the raw text file. Exits with a clear message if it's missing."""
    if not path.exists():
        sys.exit(f"Could not find input file at {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def is_suspicious(line):
    """True if the line matches a known attack shape (script tag, handler, SQLi)."""
    return any(pattern.search(line) for pattern in SUSPICIOUS_PATTERNS)


def split_clean_and_flagged(text):
    """
    Separates safe lines from flagged ones. Flagged lines are counted but
    never kept, so an attack payload never ends up sitting in the output.
    """
    clean_lines = []
    flagged_count = 0
    for line in text.splitlines():
        if is_suspicious(line):
            flagged_count += 1
        else:
            clean_lines.append(line)
    return "\n".join(clean_lines), flagged_count


def mask_email(email):
    """Shows the first letter of the address and the full domain, hides the rest."""
    local, _, domain = email.partition("@")
    visible = local[0] if local else ""
    return f"{visible}***@{domain}"


def classify_email(email):
    """
    Compares the domain after the last @ exactly against ALU's real domains.
    Exact match, not a \\b regex, so lookalikes like ...alueducation.com.evil.net
    can't sneak through as official.
    """
    domain = email.rsplit("@", 1)[-1].lower()
    if domain in ALU_DOMAINS:
        return ALU_DOMAINS[domain]
    if "alueducation" in domain:
        return "spoofed"
    return "external"


def extract_emails(text):
    """Finds every email, dedupes it, and sorts it into official/alumni/si/external/spoofed."""
    seen = []
    result = {"official": [], "alumni": [], "si": [], "external": [], "spoofed": []}
    for match in EMAIL_PATTERN.findall(text):
        if match in seen:
            continue
        seen.append(match)
        category = classify_email(match)
        result[category].append(mask_email(match))
    return result


def luhn_is_valid(digits):
    """Standard Luhn checksum, the same math real card issuers use to validate a number."""
    total = 0
    should_double = False
    for char in reversed(digits):
        value = int(char)
        if should_double:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        should_double = not should_double
    return total % 10 == 0


def extract_card_numbers(text):
    """
    Finds 13-19 digit runs (spaces or dashes allowed), keeps only the ones
    that pass Luhn, and masks each to its last 4 digits.
    """
    found = []
    for candidate in CARD_CANDIDATE_PATTERN.findall(text):
        digits_only = re.sub(r"[ -]", "", candidate)
        if 13 <= len(digits_only) <= 19 and luhn_is_valid(digits_only):
            masked = "**** **** **** " + digits_only[-4:]
            if masked not in found:
                found.append(masked)
    return found


def extract_phone_numbers(text):
    """Matches common phone formats, keeping only ones with 7-13 actual digits."""
    results = []
    for match in PHONE_PATTERN.finditer(text):
        raw = match.group().strip()
        digits_only = re.sub(r"\D", "", raw)
        if 7 <= len(digits_only) <= 13 and raw not in results:
            results.append(raw)
    return results


def extract_urls(text):
    """Grabs http(s) links and trims trailing punctuation that isn't really part of the URL."""
    seen = []
    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,);:!?")
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def build_report(raw_text):
    """Filters unsafe lines, extracts from what's left, and packages it all into one dict."""
    clean_text, flagged_count = split_clean_and_flagged(raw_text)
    return {
        "emails": extract_emails(clean_text),
        "credit_cards_found": extract_card_numbers(clean_text),
        "phone_numbers": extract_phone_numbers(clean_text),
        "urls": extract_urls(clean_text),
        "security_summary": {
            "lines_flagged_and_ignored": flagged_count,
            "note": "Flagged lines matched known attack patterns "
            "(script tags, event handlers, or SQL injection strings) "
            "and were excluded before extraction ran.",
        },
    }


def main():
    """Reads the input, builds the report, prints a summary, and saves the JSON."""
    raw_text = read_input(INPUT_FILE)
    report = build_report(raw_text)

    print("=== Extraction Summary ===")
    print(f"Official ALU emails found: {len(report['emails']['official'])}")
    print(f"Alumni ALU emails found:   {len(report['emails']['alumni'])}")
    print(f"SI ALU emails found:       {len(report['emails']['si'])}")
    print(f"External emails found:     {len(report['emails']['external'])}")
    print(f"Spoofed/lookalike emails:  {len(report['emails']['spoofed'])}")
    print(f"Valid credit card numbers: {len(report['credit_cards_found'])}")
    print(f"Phone numbers found:       {len(report['phone_numbers'])}")
    print(f"URLs found:                {len(report['urls'])}")
    print(f"Lines ignored as unsafe:   {report['security_summary']['lines_flagged_and_ignored']}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFull report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
