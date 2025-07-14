#!/usr/bin/env python3
"""
fast_scanner.py ── Two-phase Nmap wrapper
============================================================

► Phase 0  : ICMP ping + TTL → quick OS fingerprint
► Phase 1  : All-ports sweep  (-p-)  → discover every open TCP port
► Phase 2  : Targeted scan    (-sCV) → service + version detection on found ports

Key options
-----------

--flat                 Write every file in the current directory (skip Content/ and <outdir>/).
--phase {all|ping|ports|versions}
                       • all       ─ complete workflow  (default)
                       • ping      ─ only the ping check
                       • ports     ─ only the all-ports sweep
                       • versions  ─ only the -sCV scan (needs --ports OR --gnmap-file)
--force                Keep going even if ping fails (ICMP filtered).
--format-all {…}       Output format(s) for Phase 1   [gnmap]
--format-target {…}    Output format(s) for Phase 2   [gnmap]
--min-rate N           --min-rate for the all-ports sweep (pps).    [5000]
--extra "flags"        Extra Nmap flags applied to BOTH phases.
--ports 22,80,443      Ports for Phase 2 when you already know them.
--gnmap-file file.gnmap
                       .gnmap to parse ports from, for --phase versions. [AllPorts.gnmap]
-o / --outdir DIR      Output directory when not using --flat.      [Scanner]

Optional eye-candy
------------------
pip install colorama pyfiglet pyperclip
(colours, ASCII banner, clipboard copy; script works fine without them)
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# ─────────────────────────── Colours (graceful fallback) ───────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init  # type: ignore

    colorama_init(autoreset=True)

    def c(text: str, colour: str) -> str:  # type: ignore
        return f"{colour}{text}{Style.RESET_ALL}"

except ModuleNotFoundError:  # plain text
    class _N:
        RED = GREEN = CYAN = MAGENTA = YELLOW = ""

    Fore = _N()  # type: ignore

    def c(text: str, _colour: str) -> str:  # type: ignore
        return text


# ─────────────────────────── ASCII banner ───────────────────────────
def banner() -> None:
    title = "FAST SCANNER"
    try:
        from pyfiglet import figlet_format  # type: ignore

        art = figlet_format(title, font="slant")
        print(c(art, Fore.GREEN))
        width = max(len(line) for line in art.splitlines())
        print(c("by levi4tan".rjust(width), Fore.YELLOW) + "\n")
    except ModuleNotFoundError:
        line = "=" * len(title)
        print(c(f"{line}\n{title}\n{line}\nby levi4tan\n", Fore.GREEN))


# ─────────────────────────── Helper utilities ───────────────────────────
def run(cmd: str) -> None:
    """Run a shell command, streaming its output."""
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    if proc.stdout is None:
        raise RuntimeError("No stdout from subprocess")
    for line in proc.stdout:
        sys.stdout.write(line)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"[!] Command failed: {cmd} (exit {proc.returncode})")


def ping_host(host: str) -> Tuple[int, float]:
    """Return (ttl, rtt_ms). Raise RuntimeError if unreachable."""
    p = subprocess.run(["ping", "-c", "1", "-W", "2", host],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("[X] Host unreachable (ICMP filtered or down).")
    ttl_match = re.search(r"ttl[= ](\d+)", p.stdout, re.I)
    time_match = re.search(r"time[= ]([\d.]+)\s*ms", p.stdout)
    if not ttl_match:
        raise RuntimeError("[X] Unable to parse TTL from ping.")
    ttl = int(ttl_match.group(1))
    rtt = float(time_match.group(1)) if time_match else -1.0
    return ttl, rtt


def os_from_ttl(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Solaris/AIX/Other"


def extract_ports(gnmap: Path) -> str:
    """Parse .gnmap and return comma-separated open ports (copies to clipboard if available)."""
    if not gnmap.exists():
        raise FileNotFoundError(gnmap)
    data = gnmap.read_text(errors="ignore")
    ports = sorted({int(p) for p in re.findall(r"(\d{1,5})/open", data)})
    if not ports:
        raise ValueError("No open ports found in gnmap.")
    csv = ",".join(map(str, ports))
    try:
        import pyperclip  # type: ignore

        pyperclip.copy(csv)
        print(c("[+] Ports copied to clipboard\n", Fore.YELLOW))
    except ModuleNotFoundError:
        pass
    return csv


def output_flags(base: Path, fmt: str) -> str:
    """Return -o* flags for the selected format."""
    flags: List[str] = []
    root = str(base)
    if fmt in ("gnmap", "all"):
        flags.append(f"-oG {root}.gnmap")
    if fmt in ("normal", "all"):
        flags.append(f"-oN {root}.nmap")
    if fmt in ("xml", "all"):
        flags.append(f"-oX {root}.xml")
    if fmt in ("json", "all"):
        flags.append(f"-oJ {root}.json")  # Nmap ≥ 7.94
    return " ".join(flags)


# ─────────────────────────── Main routine ───────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Two-phase Nmap wrapper with ping pre-check and flexible options.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Target IP / hostname")

    # Layout
    parser.add_argument("-o", "--outdir", default="Scanner",
                        help="Output directory when not using --flat [Scanner]")
    parser.add_argument("--flat", action="store_true",
                        help="Write everything in the current directory (skip folders)")

    # Flow control
    parser.add_argument("--phase", choices=["all", "ping", "ports", "versions"],
                        default="all", help="Run only a part of the workflow [all]")
    parser.add_argument("--force", action="store_true",
                        help="Continue even if ping fails")

    # Output formats
    parser.add_argument("--format-all",
                        choices=["gnmap", "normal", "xml", "json", "all"],
                        default="gnmap", help="Output format for Phase 1 [gnmap]")
    parser.add_argument("--format-target",
                        choices=["gnmap", "normal", "xml", "json", "all"],
                        default="gnmap", help="Output format for Phase 2 [gnmap]")

    # Nmap tuning
    parser.add_argument("--min-rate", type=int, default=5000,
                        help="--min-rate for Phase 1 sweep [5000]")
    parser.add_argument("--extra", default="",
                        help='Extra Nmap flags for both phases (e.g. "--reason -T4")')

    # Phase 2 helpers
    parser.add_argument("--ports",
                        help="Comma-separated ports for --phase versions")
    parser.add_argument("--gnmap-file", default="AllPorts.gnmap",
                        help="Path to .gnmap for --phase versions [AllPorts.gnmap]")

    args = parser.parse_args()

    # ── Banner
    banner()

    # ── Directory setup
    if args.flat:
        outdir = Path(".")
    else:
        Path("Content").mkdir(exist_ok=True)
        outdir = Path(args.outdir).expanduser().absolute()
        outdir.mkdir(parents=True, exist_ok=True)
    all_base = outdir / "AllPorts"
    tgt_base = outdir / "Targeted"

    # ── Phase 0 – Ping
    if args.phase in ("all", "ping"):
        print(c("[+] Phase 0 – ping & TTL\n", Fore.CYAN))
        try:
            ttl, rtt = ping_host(args.target)
            print(c(f"[+] Host up → RTT ≈ {rtt:.0f} ms, TTL {ttl} → {os_from_ttl(ttl)}\n",
                    Fore.GREEN))
        except RuntimeError as e:
            print(c(str(e) + "\n", Fore.RED))
            if not args.force:
                sys.exit(1)
    if args.phase == "ping":
        return

    # ── Phase 1 – AllPorts sweep
    if args.phase in ("all", "ports"):
        print(c("[+] Phase 1 – AllPorts sweep\n", Fore.CYAN))
        cmd_all = (
            f"nmap -p- --open -sS -n -Pn --min-rate {args.min_rate} -vvv "
            f"{args.extra} {args.target} {output_flags(all_base, args.format_all)}"
        )
        run(cmd_all)
        if args.phase == "ports":
            return

    # ── Build port list for Phase 2
    if args.phase in ("all", "versions"):
        if args.ports:
            ports_csv = args.ports
        elif args.phase == "all":  # we just generated AllPorts.gnmap
            ports_csv = extract_ports(all_base.with_suffix(".gnmap"))
        else:  # versions-only run: use provided file
            ports_csv = extract_ports(Path(args.gnmap_file))
        print(c(f"[+] Ports: {ports_csv}\n", Fore.GREEN))

    # ── Phase 2 – Targeted -sCV
    if args.phase in ("all", "versions"):
        print(c("[+] Phase 2 – Targeted -sCV\n", Fore.CYAN))
        cmd_tgt = (
            f"nmap -p{ports_csv} -sCV {args.extra} {args.target} "
            f"{output_flags(tgt_base, args.format_target)}"
        )
        run(cmd_tgt)

    print(c("\n[✓] Selected phase(s) completed.\n", Fore.GREEN))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.\n")
                                                                                                                   
