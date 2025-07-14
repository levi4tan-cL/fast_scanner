# Fast Scanner 🚀

**Fast Scanner** is a two-phase wrapper around Nmap that:

* Pings the host and guesses the OS from TTL.  
* Sweeps **all TCP ports** quickly with a configurable `--min-rate`.  
* Runs `-sCV` only against the open ports found, saving your time.  
* Supports flat mode, per-phase output formats (gnmap, XML, JSON…), and a
  `--phase` switch to run just *ping*, *ports* or *versions*.  
* Copies the port list to your clipboard (via `pyperclip`) and colours the
  output (`colorama`, `pyfiglet`) – all optional.

## Quick start

```bash
pip install colorama pyfiglet pyperclip   # optional eye-candy
sudo python3 fast_scanner.py x.x.x.x
