#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  PassAudit — Password Strength Analyzer  v2.2.0                ║
║  Author : C7aWL3R                                              ║
║  License: MIT                                                  ║
║                                                                ║
║  Interactive TUI for password strength evaluation via:         ║
║    • Mathematical entropy  (E = L × log₂R)                    ║
║    • Deep pattern recognition  (zxcvbn)                        ║
║    • Privacy-preserving breach lookup  (HIBP k-Anonymity)      ║
║    • Forensic memory sanitisation  (ctypes, best-effort)       ║
╚══════════════════════════════════════════════════════════════════╝

v2.2.0 changelog (third-party review):
  • HIBP response streamed via iter_lines() — no bulk allocation
  • zxcvbn wrapped in SIGALRM timeout (5 s) to cap runaway regex
  • Brittle global inflight state replaced with _SecureContext CM
  • Entropy caveat added to report and methodology screen
  • MAX_PASSWORD_LENGTH reduced 512 → 128
  • Memory wipe documented as best-effort with known CPython limits
"""

# ─── Standard Library ────────────────────────────────────────────
import ctypes
import gc
import hashlib
import math
import signal
import sys
from getpass import getpass

# ─── Third-Party ─────────────────────────────────────────────────
import requests
import zxcvbn as zxcvbn_lib
from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ─── Constants ───────────────────────────────────────────────────
VERSION = "2.2.0"
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
HIBP_USER_AGENT = f"PassAudit/{VERSION}"
REQUEST_TIMEOUT = 10
MAX_PASSWORD_LENGTH = 128
ZXCVBN_TIMEOUT = 5  # seconds — caps runaway pattern matching

OFFLINE_GPU_SPEED = 100_000_000_000
ONLINE_THROTTLED_SPEED = 100

console = Console()

# ─── TUI Assets ──────────────────────────────────────────────────
BANNER = r"""[bright_cyan]
    ____                 ___             ___  __
   / __ \____ ___  _____/   | __  ______/ (_)/ /_
  / /_/ / __ `/ / / / __  / / / / / __  / / __/
 / ____/ /_/ / /_/ / /_/ / /_/ / /_/ / / / /_
/_/    \__,_/\__,_/\__,_/\__,_/\__,_/_/\__/    v{ver}
[/bright_cyan]
[dim]  Entropy · zxcvbn · HIBP k-Anonymity · Memory Wipe[/dim]"""

MENU = """
[bold bright_cyan]  ┌─────────────────────────────────────┐
  │[/bold bright_cyan]        [bold]MAIN MENU[/bold]                   [bold bright_cyan]│
  ├─────────────────────────────────────┤
  │[/bold bright_cyan]  [bold green]1[/bold green]  Analyse Password             [bold bright_cyan]│
  │[/bold bright_cyan]  [bold green]2[/bold green]  Analyse (skip breach check)   [bold bright_cyan]│
  │[/bold bright_cyan]  [bold green]3[/bold green]  Security Methodology          [bold bright_cyan]│
  │[/bold bright_cyan]  [bold green]4[/bold green]  About                         [bold bright_cyan]│
  │[/bold bright_cyan]  [bold red]0[/bold red]  Exit                          [bold bright_cyan]│
  └─────────────────────────────────────┘[/bold bright_cyan]
"""

# ─── Character Pools ─────────────────────────────────────────────
_LOWER = set("abcdefghijklmnopqrstuvwxyz")
_UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT = set("0123456789")
_SYMBOL = set(" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


# ═══════════════════════════════════════════════════════════════════
#  Memory Sanitisation
# ═══════════════════════════════════════════════════════════════════

def _str_char_width(s: str) -> int:
    """Per-character byte width for CPython's internal encoding."""
    m = max((ord(c) for c in s), default=0)
    if m <= 0xFF:
        return 1
    if m <= 0xFFFF:
        return 2
    return 4


def _secure_wipe_str(secret: str) -> None:
    """Zero the character-data region of a CPython str object.

    IMPORTANT — BEST-EFFORT ONLY.  Python strings are immutable.
    Copies may persist in: getpass/termios OS buffers, CPython's
    internal memory allocator arenas, GC generations, and any
    library (hashlib, zxcvbn) that held a reference.  This wipe
    reduces the window of exposure but cannot guarantee the password
    is fully removed from process memory.  For a hard guarantee,
    input collection and hashing must be implemented in C/Rust
    using mlock'd mutable buffers.

    Guards:
        Skips strings <= 3 chars (auto-interned by CPython).
        Detects UCS-1/2/4 width to compute correct byte count.
        Targets only the inline data buffer, not the PyObject header.
    """
    if not secret or len(secret) <= 3:
        return
    try:
        char_width = _str_char_width(secret)
        total_size = sys.getsizeof(secret)
        data_bytes = len(secret) * char_width + char_width
        offset = max(total_size - data_bytes, 0)
        ctypes.memset(id(secret) + offset, 0, data_bytes)
    except Exception:
        pass


def _secure_cleanup(password: str, zxcvbn_result: dict) -> None:
    """Wipe the password and any token copies retained by zxcvbn."""
    for pat in zxcvbn_result.get("patterns", []):
        token = pat.get("token", "")
        if token:
            _secure_wipe_str(token)
    _secure_wipe_str(password)
    gc.collect()


# ═══════════════════════════════════════════════════════════════════
#  Secure Context Manager
# ═══════════════════════════════════════════════════════════════════

class _SecureContext:
    """Deterministic cleanup for in-flight password state.

    Replaces the brittle global-variable approach.  Ensures the
    password is wiped on normal exit, exception, or signal, even
    if an error occurs deep inside requests or zxcvbn.
    """
    _active = None  # class-level reference for the signal handler

    def __init__(self, password: str):
        self.password = password
        self.zxcvbn_result = None

    def __enter__(self):
        _SecureContext._active = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()
        _SecureContext._active = None
        return False  # do not suppress exceptions

    def _cleanup(self):
        if self.zxcvbn_result is not None:
            _secure_cleanup(self.password, self.zxcvbn_result)
        else:
            _secure_wipe_str(self.password)
        gc.collect()

    @classmethod
    def signal_cleanup(cls):
        """Called from the signal handler to wipe in-flight data."""
        if cls._active is not None:
            try:
                cls._active._cleanup()
            except Exception:
                pass
            cls._active = None


# ═══════════════════════════════════════════════════════════════════
#  Signal Handling
# ═══════════════════════════════════════════════════════════════════

def _handle_signal(signum, frame):
    """Wipe any in-flight password via the context manager, then exit."""
    _SecureContext.signal_cleanup()
    console.print("\n[dim]Signal received — exiting cleanly.[/dim]")
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ═══════════════════════════════════════════════════════════════════
#  1. Entropy Engine
# ═══════════════════════════════════════════════════════════════════

def _calculate_charset_size(password: str) -> int:
    """Effective character-set size (R) based on character classes."""
    chars = set(password)
    size = 0
    if chars & _LOWER:
        size += 26
    if chars & _UPPER:
        size += 26
    if chars & _DIGIT:
        size += 10
    if chars & _SYMBOL:
        size += 33
    if any(ord(c) > 127 for c in chars):
        size += 128
    return max(size, 1)


def _compute_entropy(password: str) -> float:
    """Entropy in bits: E = L × log₂(R).

    NOTE: This is the theoretical maximum for a perfectly random
    string of this length and character set.  It does not account
    for dictionary words, patterns, or predictable structure.
    The zxcvbn score provides the practical strength estimate.
    """
    length = len(password)
    if length == 0:
        return 0.0
    return length * math.log2(_calculate_charset_size(password))


def _classify_entropy(bits: float) -> tuple:
    """Map entropy → (label, emoji, rich_style)."""
    if bits < 40:
        return ("Critical", "🔴", "bold red")
    if bits < 60:
        return ("Weak", "🟠", "bold yellow")
    if bits < 80:
        return ("Good", "🟡", "yellow")
    if bits < 100:
        return ("Strong", "🟢", "bold green")
    return ("Excellent", "🟣", "bold bright_magenta")


# ═══════════════════════════════════════════════════════════════════
#  2. Pattern Recognition (zxcvbn) — with SIGALRM timeout
# ═══════════════════════════════════════════════════════════════════

class _ZxcvbnTimeout(Exception):
    """Raised when zxcvbn exceeds the analysis deadline."""


def _zxcvbn_alarm_handler(signum, frame):
    raise _ZxcvbnTimeout()


def _analyse_patterns(password: str) -> dict:
    """Run zxcvbn with a SIGALRM timeout.

    On Linux, signal.alarm() fires SIGALRM after ZXCVBN_TIMEOUT
    seconds, interrupting any catastrophic backtracking in the
    pure-Python zxcvbn port.
    """
    error_template = {
        "score": -1, "guesses": 0, "guesses_log10": 0,
        "crack_offline": "N/A", "crack_online_throttled": "N/A",
        "crack_online_unthrottled": "N/A", "crack_offline_fast": "N/A",
        "warning": "", "suggestions": [], "patterns": [], "error": True,
    }

    old_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, _zxcvbn_alarm_handler)
        signal.alarm(ZXCVBN_TIMEOUT)
        result = zxcvbn_lib.zxcvbn(password)
        signal.alarm(0)  # cancel timer on success
    except _ZxcvbnTimeout:
        error_template["warning"] = (
            f"Pattern analysis timed out ({ZXCVBN_TIMEOUT}s)")
        return error_template
    except Exception as exc:
        signal.alarm(0)
        error_template["warning"] = (
            f"zxcvbn analysis failed: {type(exc).__name__}")
        return error_template
    finally:
        signal.signal(signal.SIGALRM, old_handler)

    result.pop("password", None)

    return {
        "score":    result["score"],
        "guesses":  result["guesses"],
        "guesses_log10": result["guesses_log10"],
        "crack_offline":
            result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "crack_online_throttled":
            result["crack_times_display"]["online_throttling_100_per_hour"],
        "crack_online_unthrottled":
            result["crack_times_display"]["online_no_throttling_10_per_second"],
        "crack_offline_fast":
            result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
        "warning":     result["feedback"].get("warning", ""),
        "suggestions": result["feedback"].get("suggestions", []),
        "patterns": [
            {"pattern": m.get("pattern", "unknown"),
             "token":   m.get("token", ""),
             "dictionary_name": m.get("dictionary_name", "")}
            for m in result.get("sequence", [])
        ],
        "error": False,
    }


def _zxcvbn_score_label(score: int) -> tuple:
    """zxcvbn 0-4 score → (label, emoji, style)."""
    return {
        0: ("Very Weak",   "🔴", "bold red"),
        1: ("Weak",        "🟠", "bold yellow"),
        2: ("Fair",        "🟡", "yellow"),
        3: ("Strong",      "🟢", "bold green"),
        4: ("Very Strong", "🟣", "bold bright_magenta"),
    }.get(score, ("Error", "⚠️", "bold red"))


# ═══════════════════════════════════════════════════════════════════
#  3. Breach Check — HIBP k-Anonymity (streamed)
# ═══════════════════════════════════════════════════════════════════

def _check_hibp(password: str) -> tuple:
    """Query Have I Been Pwned using k-Anonymity with streamed response.

    The response is consumed line-by-line via iter_lines() to avoid
    loading the full suffix list (several MB, hundreds of thousands
    of hashes) into memory as a single string.

    Returns ``(breached, count, error_msg | None)``.
    """
    sha1_hash = None
    try:
        sha1_hash = hashlib.sha1(
            password.encode("utf-8")).hexdigest().upper()
    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        return False, -1, f"Hash encoding failed: {type(exc).__name__}"

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    _secure_wipe_str(sha1_hash)
    del sha1_hash

    resp = None
    try:
        resp = requests.get(
            f"{HIBP_API_URL}{prefix}",
            headers={"User-Agent": HIBP_USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            verify=True,
            stream=True,
        )
        resp.raise_for_status()

        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            parts = line.strip().split(":")
            if len(parts) != 2:
                continue
            if parts[0].strip() == suffix:
                try:
                    count = int(parts[1].strip())
                except (ValueError, OverflowError):
                    return True, 1, "Breach count unparseable"
                return True, count, None
    except requests.ConnectionError:
        return False, -1, "Connection lost"
    except requests.Timeout:
        return False, -1, f"Request timed out ({REQUEST_TIMEOUT}s)"
    except requests.HTTPError as exc:
        code = getattr(exc.response, "status_code", "?") \
            if exc.response else "?"
        return False, -1, f"HTTP {code}"
    except requests.RequestException as exc:
        return False, -1, type(exc).__name__
    finally:
        if resp is not None:
            resp.close()
        _secure_wipe_str(suffix)
        del suffix

    return False, 0, None


# ═══════════════════════════════════════════════════════════════════
#  4. Crack-Time Estimation (log-space)
# ═══════════════════════════════════════════════════════════════════

def _format_seconds(seconds: float) -> str:
    """Human-readable duration.  Safe for inf, nan, and astronomic values."""
    if not math.isfinite(seconds) or seconds > 1e18:
        return "centuries (effectively infinite)"
    if seconds < 1:
        return "< 1 second"
    units = [
        ("year",   31_536_000), ("month",  2_592_000),
        ("week",      604_800), ("day",       86_400),
        ("hour",        3_600), ("minute",        60),
        ("second",          1),
    ]
    parts = []
    remaining = seconds
    for name, divisor in units:
        if remaining >= divisor:
            count = int(remaining // divisor)
            remaining %= divisor
            parts.append(f"{count:,} {name}{'s' if count != 1 else ''}")
        if len(parts) == 2:
            break
    return ", ".join(parts) if parts else "< 1 second"


def _estimate_crack_times(password: str) -> dict:
    """Crack time via log₂ arithmetic — safe for any password length."""
    length = len(password)
    log2_ks = length * math.log2(_calculate_charset_size(password)) \
        if length else 0.0

    def _seconds(speed: float) -> float:
        try:
            exp = log2_ks - math.log2(speed)
            return math.pow(2, exp) if exp < 1024 else float("inf")
        except (OverflowError, ValueError):
            return float("inf")

    return {
        "offline_gpu":      _format_seconds(_seconds(OFFLINE_GPU_SPEED)),
        "online_throttled": _format_seconds(_seconds(ONLINE_THROTTLED_SPEED)),
        "log2_keyspace":    log2_ks,
    }


# ═══════════════════════════════════════════════════════════════════
#  5. Strength Meter
# ═══════════════════════════════════════════════════════════════════

def _strength_bar(score_pct: float, width: int = 36) -> str:
    """Rich-markup strength bar from a 0.0–1.0 percentage."""
    filled = max(0, min(int(score_pct * width), width))
    empty = width - filled
    if score_pct < 0.25:
        color = "red"
    elif score_pct < 0.50:
        color = "yellow"
    elif score_pct < 0.75:
        color = "bright_green"
    else:
        color = "bright_magenta"
    return (f"[{color}]{'█' * filled}[/{color}]"
            f"[dim]{'░' * empty}[/dim]"
            f" {score_pct * 100:.0f}%")


# ═══════════════════════════════════════════════════════════════════
#  6. Report Renderer
# ═══════════════════════════════════════════════════════════════════

def _render_report(
    pw_len: int,
    entropy_bits: float,
    entropy_label: str,
    entropy_emoji: str,
    entropy_style: str,
    zxcvbn_result: dict,
    breached: bool,
    breach_count: int,
    breach_error: str,
    crack_times: dict,
    charset_size: int,
) -> None:
    """Print the full analysis report to the terminal."""
    zx_label, zx_emoji, zx_style = _zxcvbn_score_label(
        zxcvbn_result["score"])

    # Verdict
    if breached and breach_count > 0:
        verdict, v_style, v_emoji = "COMPROMISED", "bold red", "🔴"
    elif entropy_bits < 40 or zxcvbn_result["score"] <= 1:
        verdict, v_style, v_emoji = "FAIL", "bold red", "🔴"
    elif entropy_bits < 60 or zxcvbn_result["score"] == 2:
        verdict, v_style, v_emoji = "MARGINAL", "bold yellow", "🟠"
    else:
        verdict, v_style, v_emoji = "PASS", "bold green", "🟢"

    # Strength bar
    ent_pct = min(entropy_bits / 128.0, 1.0)
    zx_pct = zxcvbn_result["score"] / 4.0 \
        if zxcvbn_result["score"] >= 0 else 0.0
    combined = (ent_pct * 0.6) + (zx_pct * 0.4)
    if breached and breach_count > 0:
        combined = min(combined, 0.10)

    console.print()
    console.print(Rule(
        "[bold bright_cyan]  ANALYSIS REPORT  [/bold bright_cyan]",
        style="bright_cyan"))
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"  Overall Strength:  {_strength_bar(combined)}"),
        border_style=v_style.replace("bold ", ""),
        box=box.HEAVY,
        title=f" {v_emoji} {verdict} ",
        title_align="center",
    ))

    # ── Summary ──
    tbl = Table(box=box.ROUNDED,
                title="[bold bright_cyan]Summary[/bold bright_cyan]",
                header_style="bold", show_lines=True, padding=(0, 1))
    tbl.add_column("Metric", style="cyan", min_width=28)
    tbl.add_column("Value", min_width=24)
    tbl.add_column("Status", justify="center", min_width=8)

    tbl.add_row("Password Length", str(pw_len), "🔵")
    tbl.add_row("Character-Set Size (R)", str(charset_size), "🔵")
    tbl.add_row("Entropy (bits) [dim]theoretical[/dim]",
                f"{entropy_bits:.2f}", entropy_emoji)
    tbl.add_row("Entropy Rating [dim]if random[/dim]",
                f"[{entropy_style}]{entropy_label}[/{entropy_style}]",
                entropy_emoji)
    if zxcvbn_result.get("error"):
        tbl.add_row("zxcvbn Score [dim]practical[/dim]",
                     "[red]Analysis failed[/red]", "⚠️")
    else:
        tbl.add_row(
            "zxcvbn Score [dim]practical[/dim]",
            f"[{zx_style}]{zxcvbn_result['score']}/4 "
            f"— {zx_label}[/{zx_style}]", zx_emoji)
    if breach_count == -1:
        tbl.add_row("HIBP Breach Status",
                     f"[yellow]Unavailable[/yellow] "
                     f"({rich_escape(breach_error)})", "⚠️")
    elif breached:
        tbl.add_row("HIBP Breach Status",
                     f"[bold red]YES — seen {breach_count:,} "
                     f"times[/bold red]", "🔴")
    else:
        tbl.add_row("HIBP Breach Status",
                     "[green]Not found in known breaches[/green]", "🟢")
    tbl.add_row("Overall Verdict",
                f"[{v_style}]{verdict}[/{v_style}]", v_emoji)
    console.print(tbl)

    # Entropy caveat
    if (entropy_bits >= 60
            and not zxcvbn_result.get("error")
            and zxcvbn_result["score"] <= 2):
        console.print(Panel(
            "[yellow]⚠[/yellow]  Entropy is high but zxcvbn detected "
            "predictable patterns.  Shannon entropy\n"
            "   measures the [bold]theoretical maximum[/bold] for a "
            "random string of this length and charset.\n"
            "   The zxcvbn score reflects [bold]practical strength[/bold]"
            " against modern cracking dictionaries.",
            border_style="yellow", box=box.ROUNDED,
            title="[bold yellow] Entropy ≠ Strength [/bold yellow]",
        ))

    # ── Crack times ──
    ct = Table(box=box.ROUNDED,
               title="[bold bright_cyan]Estimated Crack Time"
                     "[/bold bright_cyan]",
               header_style="bold", show_lines=True, padding=(0, 1))
    ct.add_column("Scenario", style="cyan", min_width=35)
    ct.add_column("Time to Exhaust Keyspace", min_width=30)
    ct.add_row(
        f"Offline GPU ({OFFLINE_GPU_SPEED / 1e9:.0f}B H/s)",
        crack_times["offline_gpu"])
    ct.add_row(
        f"Online Throttled ({ONLINE_THROTTLED_SPEED} att/s)",
        crack_times["online_throttled"])
    if not zxcvbn_result.get("error"):
        ct.add_row("zxcvbn — Offline slow (10k H/s)",
                    str(zxcvbn_result["crack_offline"]))
        ct.add_row("zxcvbn — Offline fast (10B H/s)",
                    str(zxcvbn_result["crack_offline_fast"]))
        ct.add_row("zxcvbn — Online throttled (100/hr)",
                    str(zxcvbn_result["crack_online_throttled"]))
    console.print(ct)

    # ── Patterns ──
    patterns = zxcvbn_result.get("patterns", [])
    if patterns:
        pt = Table(box=box.ROUNDED,
                   title="[bold bright_cyan]Detected Patterns"
                         "[/bold bright_cyan]",
                   header_style="bold", show_lines=True)
        pt.add_column("Pattern Type", style="cyan")
        pt.add_column("Matched Token (masked)")
        pt.add_column("Dictionary")
        for p in patterns:
            tok = p.get("token", "")
            if len(tok) > 3:
                masked = tok[:2] + "·" * (len(tok) - 2)
            else:
                masked = "·" * len(tok) if tok else "—"
            pt.add_row(p.get("pattern", "unknown"), masked,
                       p.get("dictionary_name") or "—")
        console.print(pt)

    # ── Feedback ──
    warning = zxcvbn_result.get("warning", "")
    suggestions = zxcvbn_result.get("suggestions", [])
    if warning or suggestions:
        parts = []
        if warning:
            parts.append(
                f"  [bold red]⚠  Warning:[/bold red]  "
                f"{rich_escape(str(warning))}")
        for s in suggestions:
            parts.append(
                f"  [yellow]→[/yellow]  {rich_escape(str(s))}")
        console.print(Panel(
            "\n".join(parts),
            title="[bold yellow] Feedback [/bold yellow]",
            border_style="yellow", box=box.ROUNDED))
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  7. Analysis Pipeline
# ═══════════════════════════════════════════════════════════════════

def _run_analysis(skip_breach: bool = False) -> None:
    """Prompt for a password and run the full analysis pipeline."""
    console.print()

    if not sys.stdin.isatty():
        console.print("[red]Error: stdin is not a terminal. "
                      "Cannot read password securely.[/red]")
        return

    try:
        password = getpass(
            "  🔑  Enter password to analyse (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]  Cancelled.[/dim]")
        return

    if not password:
        console.print("[red]  No password provided.[/red]")
        return
    if len(password) > MAX_PASSWORD_LENGTH:
        console.print(
            f"[red]  Password exceeds {MAX_PASSWORD_LENGTH} "
            f"character limit.[/red]")
        _secure_wipe_str(password)
        del password
        return

    pw_len = len(password)

    with _SecureContext(password) as ctx:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bright_cyan]{task.description}[/bright_cyan]"),
            console=console, transient=True,
        ) as progress:

            task = progress.add_task("Computing entropy…", total=None)
            charset_size = _calculate_charset_size(password)
            entropy_bits = _compute_entropy(password)
            entropy_label, entropy_emoji, entropy_style = \
                _classify_entropy(entropy_bits)
            progress.update(task, description="Entropy ✓")

            progress.update(
                task, description="Running pattern analysis (zxcvbn)…")
            zxcvbn_result = _analyse_patterns(password)
            ctx.zxcvbn_result = zxcvbn_result
            progress.update(task, description="Patterns ✓")

            if skip_breach:
                breached, breach_count, breach_error = \
                    False, -1, "Skipped by user"
            else:
                progress.update(
                    task, description="Querying HIBP (k-Anonymity)…")
                breached, breach_count, breach_error = \
                    _check_hibp(password)
            progress.update(task, description="Breach check ✓")

            progress.update(
                task, description="Estimating crack times…")
            crack_times = _estimate_crack_times(password)
            progress.update(task, description="Complete ✓")

        _render_report(
            pw_len=pw_len, entropy_bits=entropy_bits,
            entropy_label=entropy_label, entropy_emoji=entropy_emoji,
            entropy_style=entropy_style, zxcvbn_result=zxcvbn_result,
            breached=breached, breach_count=breach_count,
            breach_error=breach_error or "", crack_times=crack_times,
            charset_size=charset_size,
        )

    # _SecureContext.__exit__ already called _secure_cleanup + gc
    del password, zxcvbn_result
    console.print("[dim]  🧹  Password wiped from memory.[/dim]\n")


# ═══════════════════════════════════════════════════════════════════
#  8. Info Screens
# ═══════════════════════════════════════════════════════════════════

def _show_methodology() -> None:
    console.print(Panel(
        "[bold bright_cyan]Analysis Methodology[/bold bright_cyan]\n\n"

        "[bold]1. Entropy Calculation[/bold]\n"
        "   Formula: E = L × log₂(R)\n"
        "   L = password length, R = character-set size.\n"
        "   Bands: <40 Critical │ 40-60 Weak │ 60-80 Good │ "
        "80-100 Strong │ 100+ Excellent\n\n"
        "   [yellow]Caveat:[/yellow] Shannon entropy represents the "
        "theoretical maximum for a\n"
        "   perfectly random string of that length.  A password like\n"
        "   'Password123!' has high entropy (78 bits) but near-zero\n"
        "   practical strength.  The zxcvbn score (below) measures\n"
        "   practical resistance to modern cracking dictionaries.\n\n"

        "[bold]2. Pattern Recognition (zxcvbn)[/bold]\n"
        "   Detects keyboard walks, dictionary words, names, dates,\n"
        "   l33t substitutions, repeats, and sequences.  Produces a\n"
        "   0-4 strength score and crack-time estimates across four\n"
        "   attack scenarios.  Subject to a 5-second SIGALRM timeout\n"
        "   to prevent CPU exhaustion on adversarial inputs.\n\n"

        "[bold]3. Breach Lookup (HIBP k-Anonymity)[/bold]\n"
        "   SHA-1 hashes the password locally.  Only the first 5 hex\n"
        "   characters are sent to the API.  The response is streamed\n"
        "   line-by-line (iter_lines) so the full suffix list is never\n"
        "   materialised in memory.  The plaintext never leaves your\n"
        "   machine.\n\n"

        "[bold]4. Crack-Time Estimation[/bold]\n"
        "   Offline GPU: 100 billion hashes/second.\n"
        "   Online throttled: 100 attempts/second.\n"
        "   Computed in log-space for arbitrary keyspace sizes.\n\n"

        "[bold]5. Memory Sanitisation (best-effort)[/bold]\n"
        "   After analysis the password's character buffer is zeroed\n"
        "   via ctypes.memset (offset past the PyObject header).\n"
        "   zxcvbn's internal copies and pattern tokens are also\n"
        "   wiped.  A context manager ensures cleanup even on\n"
        "   exceptions or signals.\n\n"
        "   [yellow]Limitation:[/yellow] Python strings are immutable."
        "  Copies may persist\n"
        "   in OS terminal buffers, CPython allocator arenas, and GC\n"
        "   generations.  This wipe reduces exposure but cannot fully\n"
        "   guarantee removal.  For a hard guarantee, input collection\n"
        "   and hashing must use C/Rust with mlock'd mutable buffers.",
        border_style="bright_cyan", box=box.ROUNDED, padding=(1, 2),
    ))


def _show_about() -> None:
    console.print(Panel(
        f"[bold bright_cyan]PassAudit[/bold bright_cyan] v{VERSION}\n\n"
        "Author:  C7aWL3R\n"
        "License: MIT\n\n"
        "A password strength analyser built for security professionals.\n"
        "Combines mathematical entropy, deep pattern recognition, and\n"
        "privacy-preserving breach intelligence into a single TUI.\n\n"
        "[dim]Dependencies: zxcvbn-python, requests, rich[/dim]\n"
        "[dim]Platform:     Linux (CPython 3.10+)[/dim]",
        border_style="bright_cyan", box=box.ROUNDED, padding=(1, 2),
    ))


# ═══════════════════════════════════════════════════════════════════
#  9. Main
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    """Interactive TUI main loop."""
    console.clear()
    console.print(BANNER.format(ver=VERSION))

    while True:
        console.print(MENU)
        try:
            choice = console.input(
                "[bold bright_cyan]  ❯ [/bold bright_cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]  Goodbye.[/dim]\n")
            break

        if choice == "1":
            _run_analysis(skip_breach=False)
        elif choice == "2":
            _run_analysis(skip_breach=True)
        elif choice == "3":
            _show_methodology()
        elif choice == "4":
            _show_about()
        elif choice == "0":
            console.print("\n[dim]  Goodbye.[/dim]\n")
            break
        else:
            console.print("[red]  Invalid option. "
                          "Enter 1-4 or 0 to exit.[/red]")


if __name__ == "__main__":
    main()
