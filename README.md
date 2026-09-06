# ALU Regex Data Extraction & Secure Validation

A Python program that extracts structured data (emails, credit card
numbers, phone numbers, and URLs) from raw, unstructured text, and treats
that text as untrusted until it proves otherwise.

## What it does

Given a block of raw text, the program:

1. Screens every line for known attack patterns before touching it.
2. Extracts emails, credit card numbers, phone numbers, and URLs from
   whatever lines survive that screening.
3. Classifies emails by domain, validates card numbers with a real
   checksum, and masks anything sensitive before it's written anywhere.
4. Prints a short summary to the console and saves the full result as
   JSON.

## Data extracted

| Type | Details |
|---|---|
| Emails | Classified as `official` (`@alueducation.com`), `alumni` (`@alumni.alueducation.com`), `si` (`@si.alueducation.com`), `external`, or `spoofed` (a lookalike domain that isn't an exact match) |
| Credit card numbers | Matched as 13 to 19 digit sequences, validated with the Luhn checksum, masked to the last 4 digits |
| Phone numbers | Matched across common formats: international codes, parentheses, dashes, dots, and no separators at all |
| URLs | `http://` and `https://` links, with trailing punctuation stripped |

## Security approach

Nothing gets extracted until the line it came from has been checked
against a short list of known attack shapes: script tags, `javascript:`
links, inline event handlers such as `onerror=`, and common SQL
injection strings. Any line that matches is dropped from extraction
entirely and its content is never written to the console or the output
file. Logging an attack payload back out doesn't make it safer, it just
gives it a second home.

Email validation deserves a specific note. It would be easy to write a
check like `email.endswith("alueducation.com")` or a regex ending in
`\b`, and both would be wrong. `\b` only checks for a boundary between a
word character and a non-word character, and a dot counts as a
non-word character, so an address like
`fake@alueducation.com.phish-domain.net` would still pass that check
even though the real domain is `phish-domain.net`. This program instead
splits each email on the last `@`, lowercases the result, and compares
the entire domain string exactly against ALU's three known domains.
Anything that contains "alueducation" without matching exactly is
flagged as `spoofed` rather than silently discarded, so it still shows
up in the report as something worth a second look.

Anything sensitive that does make it into the output is masked. Credit
card numbers show only their last four digits. Email addresses show
only the first character of the local part plus the full domain.

## Project structure

```
alu-regex-data-extraction_Quentin712/
├── input/
│   └── raw-text.txt        Sample input, written to resemble a real support ticket export
├── src/
│   └── main.py              All extraction, classification, and validation logic
├── output/
│   └── sample-output.json   Result of the last run, regenerated each time the script runs
└── README.md
```

## Requirements

Python 3.8 or later. No external libraries, everything used is part of
the standard library (`re`, `json`, `pathlib`).

## Cloning the repository

```bash
git clone https://github.com/Quentin712/alu-regex-data-extraction_Quentin712.git
cd alu-regex-data-extraction_Quentin712
```

Replace the URL above with the actual repo URL once it's pushed to GitHub.

## Running it

```bash
python3 src/main.py
```

This reads `input/raw-text.txt`, prints a short summary to the console,
and writes the full structured result to `output/sample-output.json`,
overwriting whatever was there before.

## Sample output

Running the script against the included `raw-text.txt` produces
something like:

```
=== Extraction Summary ===
Official ALU emails found: 2
Alumni ALU emails found:   2
SI ALU emails found:       1
External emails found:     2
Spoofed/lookalike emails:  2
Valid credit card numbers: 2
Phone numbers found:       7
URLs found:                4
Lines ignored as unsafe:   3
```

The full breakdown, with every value masked appropriately, is saved to
`output/sample-output.json`.

## Known limitations

- Phone number matching is tuned to the formats present in the sample
  input (mainly US and Rwandan formats). A general solution for
  arbitrary international formats would need a dedicated library such
  as `phonenumbers`, not a single regular expression.
- URL matching stops at the first whitespace or quote character, so a
  URL with no separator between it and adjacent text could be captured
  incorrectly.
- The suspicious input check covers a handful of common attack
  patterns for demonstration purposes. It is not a substitute for a
  real security scanning tool, and isn't meant to be one.

## Author

Built by Quentin712 as part of the Data Extraction & Secure Validation
assignment.
