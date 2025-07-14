# Fast Scanner 🚀

**Fast Scanner** is a two-phase wrapper around Nmap that helps you move fast while keeping results tidy.

* **Phase 0&nbsp;· Ping** – checks reachability and guesses the OS from the TTL.  
* **Phase 1&nbsp;· AllPorts sweep** – scans **all TCP ports** (`-p-`) with a configurable `--min-rate`.  
* **Phase 2&nbsp;· Targeted** – runs `-sCV` **only** against ports discovered in Phase 1.  

Extra sugar: flat mode, per-phase output formats (`gnmap`, XML, JSON…), a `--phase` switch to run just *ping*, *ports* or *versions*, colourised output (`colorama`), an ASCII banner (`pyfiglet`) and auto-clipboard copy (`pyperclip`) – all optional.

---

## Quick Start

sudo python3 fast_scanner.py X.X.X.X

Common flags:

Flag	Purpose
--flat	Drop output in current dir (skip folders)
--phase ports	Only the wide port sweep
--phase versions --ports 22,80,443	Only -sCV against given ports
--format-all all --format-target xml	Mixed output formats
--force	Continue even if ping fails (ICMP filtered)

Installation / Download

# 1. Clone the repository
git clone https://github.com/levi4tan-cL/fast_scanner.git

cd fast_scanner

# 2. (optional) install eye-candy dependencies
pip install colorama pyfiglet pyperclip

# 3. Run
sudo python3 fast_scanner.py --help

Tip
To make it globally available:
sudo install -m 755 fast_scanner.py /usr/local/bin/fast_scanner

Clone via SSH

git clone git@github.com:levi4tan-cL/fast_scanner.git
