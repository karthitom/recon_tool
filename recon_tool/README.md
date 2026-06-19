# Automated Network Recon & Asset Monitoring Tool

A modular, terminal-based network reconnaissance tool for authorized asset visibility
and defensive posture assessment.

## Requirements

- Python 3.x
- nmap (system-level installation)
- rich (`pip install rich`)

## Usage

```bash
python main.py -t 192.168.1.1
python main.py -t 192.168.1.1 --output json
python main.py -t 192.168.1.1 --output csv --scan-type service
```

## Modules

| Module        | File           | Responsibility                          |
|---------------|----------------|-----------------------------------------|
| Input Handler | cli.py         | Argument parsing and IP validation      |
| Core Scanner  | scanner.py     | Nmap execution via subprocess           |
| Data Parser   | parser.py      | Raw output → structured data            |
| Reporter      | reporter.py    | Rich terminal UI + file export          |
| Entry Point   | main.py        | Orchestrates the full scan workflow     |

## Disclaimer

This tool is strictly for authorized network reconnaissance and defensive asset
monitoring. Do not use on networks or systems you do not own or have explicit
written permission to scan.
