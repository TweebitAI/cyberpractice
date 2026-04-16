# SOC Home Lab — Cybersecurity Detection Practice

Hands-on SOC detection lab built on Apple Silicon (VMware Fusion, M2 MacBook).
Simulating real-world attack scenarios and detecting them using Splunk SIEM.

## Current Stack
- **SIEM:** Splunk Enterprise (macOS host)
- **Endpoint:** Windows 11 ARM VM + Sysmon (ARM64)
- **Attacker:** Kali Linux ARM VM
- **Linux target:** Debian 12 ARM VM (planned: Docker, Suricata, Squid proxy)

## Completed Lab Exercises
| # | Exercise | Technique | MITRE |
|---|----------|-----------|-------|
| 001 | Brute Force Detection | PowerShell credential stuffing → EventCode 4625 → Splunk Alert | T1110.004 |
| 002 | Nmap Port Scan Detection | Kali TCP connect scan → Sysmon EventID 3 → Splunk SPL | T1046 |

## Detection Pipeline

    Attack simulation (Kali / PowerShell)
            ↓
    Windows logs (Security + Sysmon)
            ↓
    Splunk Universal Forwarder
            ↓
    Splunk Enterprise (SIEM)
            ↓
    SPL detection queries + scheduled alerts

## Planned Extensions
- AWS CloudTrail + GuardDuty → Splunk (cloud security layer)
- Hetzner VPS honeypot (Cowrie) → real internet attack data
- Suricata IDS on Debian VM → network detection
- Docker + DVWA → web attack simulation
- Python + Anthropic API → AI-assisted alert triage with MITRE mapping

## Key Technical Notes
- All VMs running ARM64 on Apple Silicon — required ARM-specific
  binaries (Sysmon64a.exe, Windows 11 ARM ISO)
- VMware NAT routing means Kali traffic appears as Mac host IP
  in Windows logs — documented as real-world NAT attribution challenge
- Splunk minFreeSpace tuned for home lab disk constraints

## Lab Reports
- [001 — Brute Force Detection](incidents/incident-001-bruteforce/incident-001-bruteforce.md)
- [002 — Nmap Port Scan Detection](incidents/incident-002-nmap-scan/incident-002-nmap-scan.md)
