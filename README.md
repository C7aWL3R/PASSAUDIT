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

**Important caveat:** Shannon entropy represents the theoretical maximum for a perfectly random string of the given length and character set. A password like `Password123!` yields \~79 bits of entropy but has virtually zero practical strength because it follows highly predictable patterns. When PassAudit detects this divergence (high entropy but low zxcvbn score), it displays an explicit "Entropy ≠ Strength" warning panel in the report. The entropy row in the summary table is labelled "theoretical" and the zxcvbn row is labelled "practical" to prevent misreading.

### Pattern Recognition (zxcvbn with timeout)

Integrates the zxcvbn library to detect keyboard walks, dictionary words, common names, dates, l33t substitutions, repeated characters, and sequential patterns. Each password receives a 0–4 strength score, crack-time estimates across four attack scenarios, and specific warnings and suggestions.

The zxcvbn call is wrapped in a 5-second `SIGALRM` timeout. The zxcvbn-python library is a pure-Python port of an older JavaScript engine that uses recursive logic and regex matching. A specifically crafted input (e.g., a repetitive sequence mixed with partial dictionary words) could trigger catastrophic backtracking. The alarm ensures the TUI never freezes; if zxcvbn exceeds the deadline, the tool reports "Analysis timed out" and continues with the remaining engines. The original SIGALRM handler is always restored in a `finally` block.

### Breach Check — HIBP k-Anonymity (streamed)

Queries the Have I Been Pwned API using the k-Anonymity protocol. The password is SHA-1 hashed locally, only the first 5 hex characters are sent to the API, and the returned suffix list is consumed line-by-line via `resp.iter\_lines()` with `stream=True`. This avoids loading the full response body (several megabytes, hundreds of thousands of hash suffixes) into memory as a single string, minimising GC pressure and reducing the RAM footprint of sensitive hash material. The connection is explicitly closed in a `finally` block. The full SHA-1 hash and suffix are wiped from memory after the lookup completes.

### Crack-Time Estimation

Estimates brute-force time across two scenarios: offline GPU (100 billion hashes/second) and online throttled (100 attempts/second). All arithmetic is performed in log₂ space to safely handle arbitrarily large keyspaces without integer overflow.

### Memory Sanitisation (best-effort)

After analysis, the password's character buffer is zeroed via `ctypes.memset`, targeting only the inline data region past the CPython PyObject header. The wipe detects UCS-1/2/4 encoding width for correct byte counts and skips strings ≤3 characters to avoid corrupting Python's interned string table. Pattern tokens captured by zxcvbn are also wiped.

**Honest limitation:** Python strings are immutable. When a password is passed to `getpass`, `hashlib`, `zxcvbn`, or `len()`, CPython may create hidden copies, references, or caches. Additionally, the `getpass` module relies on OS libraries (`termios`) that buffer the input before Python ever sees it. Even if the primary buffer is successfully zeroed, copies may persist in the OS terminal buffer, CPython's internal memory allocator arenas, and garbage collector generations. The `ctypes.memset` wipe reduces the window of exposure but cannot guarantee complete removal from process memory.

**For a hard guarantee:** Input collection and hashing must be implemented in C or Rust using mutable byte buffers with `mlock()` to prevent swapping to disk. This is documented in the methodology screen and the source code.

### Secure Context Manager

All in-flight password state is managed through a `\_SecureContext` context manager that guarantees cleanup on normal exit, exception, or signal. This replaces the brittle global-variable approach from earlier versions and ensures deterministic cleanup even if an error occurs deep inside `requests` or `zxcvbn`.

### Secure Input

Uses `getpass` for terminal input so the password is never echoed to screen or saved in shell history. Non-TTY environments are detected and rejected. Passwords are capped at 128 characters (reduced from 512 in v2.1.0 to better match realistic human input and limit zxcvbn's evaluation surface).

\---

## Installation

**Requirements:** Python 3.10+, Linux, CPython interpreter.

```bash
git clone https://github.com/C7aWL3R/passaudit.git
cd passaudit
pip install -r requirements.txt
chmod 0700 passaudit.py
```

### Dependencies

|Package|Purpose|
|-|-|
|zxcvbn-python|Pattern recognition engine|
|requests|HIBP API communication|
|rich|Terminal UI rendering|

\---

## Usage

```bash
./passaudit.py
```

The interactive menu offers five options:

|Option|Action|
|-|-|
|1|Full analysis (entropy + zxcvbn + HIBP + crack time)|
|2|Offline analysis (skip breach check)|
|3|Display analysis methodology (with caveats)|
|4|About / version info|
|0|Exit|

Password input is always hidden. The tool loops so you can analyse multiple passwords without restarting.

\---

## Report Output

Each analysis produces a structured report with up to six sections:

**Strength Bar** — Visual gauge combining entropy (60% weight) and zxcvbn score (40% weight), capped at 10% if the password appears in breach databases. Overall verdict: PASS, MARGINAL, FAIL, or COMPROMISED.

**Summary Table** — Password length, character-set size, entropy (labelled "theoretical"), zxcvbn score (labelled "practical"), HIBP breach status, and overall verdict.

**Entropy ≠ Strength Warning** — Displayed only when entropy is ≥60 bits but zxcvbn scores ≤2, explaining the difference between theoretical randomness and practical crack resistance.

**Crack-Time Table** — Estimated brute-force duration across five scenarios: offline GPU (100B H/s), online throttled (100 att/s), and three zxcvbn-computed scenarios.

**Detected Patterns** — Each pattern recognised by zxcvbn with the matched token partially masked and the source dictionary identified.

**Feedback** — Specific warnings and actionable suggestions from zxcvbn, with all text sanitised against Rich markup injection.

\---

## Known Limitations

**Memory wipe is best-effort.** Python strings are immutable. Copies may persist in OS terminal buffers, CPython allocator arenas, GC generations, and any library that held a reference. The `ctypes.memset` wipe reduces exposure but cannot guarantee the password is fully removed from process memory. For a hard guarantee, input collection and hashing must be implemented in C or Rust using `mlock`'d mutable buffers.

**SHA-1 for HIBP only.** SHA-1 is used exclusively because the HIBP API requires it. It is not used for any security-critical purpose within the tool.

**CPython-specific.** The memory wipe relies on CPython's `id()` returning the object's memory address and `sys.getsizeof()` reflecting the true allocation size. On PyPy, GraalPy, or other implementations the wipe will silently no-op.

**zxcvbn-python is unmaintained.** The library is a pure-Python port of an older JavaScript engine. Consider migrating to a maintained alternative (e.g., `nbvcxz` or `zxcvbn-c` via CFFI) if performance and long-term support are critical.

**SIGALRM is Linux-only.** The zxcvbn timeout mechanism uses `signal.alarm()` which is not available on Windows. Since PassAudit targets Linux, this is acceptable, but cross-platform portability would require a threading-based timeout.

\---

## License

MIT — see [LICENSE](LICENSE) for full text.

\---

## Author

**C7aWL3R**
