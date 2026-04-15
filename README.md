# PassAudit

**Password Strength Analyzer with Interactive TUI**

PassAudit is a hardened, security-audited Python tool that evaluates password strength through mathematical entropy, deep pattern recognition, privacy-preserving breach intelligence, and forensic memory sanitisation — all wrapped in a Rich-powered terminal interface.

```
    ____                 ___             ___  __
   / __ \____ ___  _____/   | __  ______/ (_)/ /_
  / /_/ / __ `/ / / / __  / / / / / __  / / __/
 / ____/ /_/ / /_/ / /_/ / /_/ / /_/ / / / /_
/_/    \__,_/\__,_/\__,_/\__,_/\__,_/_/\__/    v2.1.0
```

---

## Features

### Entropy Engine

Calculates password entropy using `E = L × log₂(R)` where L is the password length and R is the character-set size, detected automatically across five classes (lowercase, uppercase, digits, symbols, unicode). Results are classified into five bands: Critical (<40 bits), Weak (40–60), Good (60–80), Strong (80–100), and Excellent (100+).

### Pattern Recognition

Integrates the zxcvbn library to detect keyboard walks, dictionary words, common names, dates, l33t substitutions, repeated characters, and sequential patterns. Each password receives a 0–4 strength score, crack-time estimates across four attack scenarios, and specific warnings and suggestions.

### Breach Check (HIBP k-Anonymity)

Queries the Have I Been Pwned API using the k-Anonymity protocol. The password is SHA-1 hashed locally, only the first 5 hex characters are sent to the API, and the returned suffix list is searched on-device. The plaintext password never leaves the machine. The full SHA-1 hash and suffix are wiped from memory after the lookup completes.

### Crack-Time Estimation

Estimates brute-force time across two scenarios: offline GPU (100 billion hashes/second) and online throttled (100 attempts/second). All arithmetic is performed in log₂ space to safely handle arbitrarily large keyspaces without integer overflow.

### Memory Sanitisation

After analysis, the password's character buffer is zeroed via `ctypes.memset`, targeting only the inline data region past the CPython PyObject header. The wipe detects UCS-1/2/4 encoding width for correct byte counts and skips strings ≤3 characters to avoid corrupting Python's interned string table. Pattern tokens captured by zxcvbn are also wiped. This is a best-effort forensic mitigation.

### Secure Input

Uses `getpass` for terminal input so the password is never echoed to screen or saved in shell history. Non-TTY environments are detected and rejected to prevent accidental leakage through piped input.

### Interactive TUI

Rich-powered terminal interface with ASCII art banner, interactive menu, progress spinner during analysis, visual strength meter, colour-coded severity indicators, and structured report tables.

---

## Installation

**Requirements:** Python 3.10+, Linux, CPython interpreter.

```bash
git clone https://github.com/C7aWL3R/passaudit.git
cd passaudit
pip install -r requirements.txt
chmod 0700 passaudit.py
```

### Dependencies

| Package        | Purpose                          |
|----------------|----------------------------------|
| zxcvbn-python  | Pattern recognition engine       |
| requests       | HIBP API communication           |
| rich           | Terminal UI rendering            |

---

## Usage

```bash
./passaudit.py
```

The interactive menu offers five options:

| Option | Action                                              |
|--------|-----------------------------------------------------|
| 1      | Full analysis (entropy + zxcvbn + HIBP + crack time) |
| 2      | Offline analysis (skip breach check)                 |
| 3      | Display analysis methodology                         |
| 4      | About / version info                                 |
| 0      | Exit                                                 |

Password input is always hidden. The tool loops so you can analyse multiple passwords without restarting.

---

## Report Output

Each analysis produces a structured report with five sections:

**Strength Bar** — Visual gauge combining entropy (60% weight) and zxcvbn score (40% weight), capped at 10% if the password appears in breach databases. Overall verdict: PASS, MARGINAL, FAIL, or COMPROMISED.

**Summary Table** — Password length, character-set size, entropy (bits and rating), zxcvbn score, HIBP breach status, and overall verdict with colour-coded status emojis.

**Crack-Time Table** — Estimated brute-force duration across five scenarios: offline GPU (100B H/s), online throttled (100 att/s), and three zxcvbn-computed scenarios (offline slow, offline fast, online throttled).

**Detected Patterns** — Each pattern recognised by zxcvbn (dictionary, spatial, sequence, repeat, etc.) with the matched token partially masked and the source dictionary identified.

**Feedback** — Specific warnings and actionable suggestions from zxcvbn, with all text sanitised against Rich markup injection.

---

## Security Hardening

PassAudit has been through two full security audit passes with 20 findings identified and resolved. The hardening measures include:

**Input validation** — 512-character maximum length to prevent DoS via entropy computation. Non-TTY stdin is rejected. Empty and oversized inputs are handled gracefully.

**Memory sanitisation** — Password data is zeroed at the C level via `ctypes.memset` with correct UCS-1/2/4 byte width detection. Interned string corruption is prevented by skipping strings ≤3 characters. zxcvbn's internal password reference is removed from the result dict, and pattern tokens are wiped independently. Signal handlers (SIGINT/SIGTERM) wipe any in-flight password before exit.

**Network safety** — HIBP requests use TLS verification (`verify=True`), a 10-second timeout, and granular exception handling (ConnectionError, Timeout, HTTPError with None-response guard). The SHA-1 digest and suffix are wiped from memory after use.

**Output safety** — All zxcvbn-generated text (warnings, suggestions) is escaped via `rich.markup.escape()` before rendering. Exception messages use `type(exc).__name__` only, never the full message, to prevent password fragment leakage.

**Arithmetic safety** — Crack-time estimation works entirely in log₂ space, preventing integer overflow on large keyspaces. `format_seconds()` handles `inf`, `nan`, and values exceeding 10¹⁸ seconds.

---

## License

MIT — see [LICENSE](LICENSE) for full text.

---

## Author

**C7aWL3R**
