# SOC Home Lab — Cybersecurity Detection Practice

Hands-on SOC detection lab built on Apple Silicon (VMware Fusion, M2 MacBook).  
Simulating real-world attack scenarios and detecting them using Splunk SIEM.

## Current Stack

- SIEM: Splunk Enterprise (macOS host)
- Endpoint: Windows 11 ARM VM + Sysmon (ARM64)
- Attacker: Kali Linux ARM VM
- Linux target: Debian 12 ARM VM (planned: Docker, Suricata, Squid proxy)
- Cloud: Microsoft Azure SOC Lab foundation

## Completed Lab Exercises

| # | Exercise | Technique | MITRE |
|---|----------|-----------|-------|
| 001 | Brute Force Detection | PowerShell credential stuffing → EventCode 4625 → Splunk Alert | T1110.004 |
| 002 | Nmap Port Scan Detection | Kali TCP connect scan → Sysmon EventID 3 → Splunk SPL | T1046 |
| 003 | Wireshark Packet Capture | Slow nmap -T1 scan → tcpdump on attacker NIC → Wireshark analysis | T1046 |

## Cloud Security Labs

| # | Lab | Focus | Status |
|---|-----|-------|--------|
| 001 | Azure SOC Lab Foundation | Budget, resource group, virtual network, subnet | Completed |
| 002 | Windows Server DC01 Deployment | VM deployment, private IP, secure access | Planned |
| 003 | Active Directory Domain Services | Domain controller, lab.local domain | Planned |
| 004 | Windows Logging + SIEM Integration | Event logs, Sysmon, Sentinel/Splunk integration | Planned |

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

## Cloud Lab Pipeline

    Azure cost control
            ↓
    Dedicated resource group
            ↓
    Virtual network and subnet
            ↓
    Windows Server / Active Directory
            ↓
    Windows logging and telemetry collection
            ↓
    SIEM integration and detection engineering

## Planned Extensions

- Azure Windows Server DC01 deployment
- Active Directory Domain Services lab domain
- Windows Event Forwarding / Sysmon telemetry collection
- Microsoft Sentinel or Splunk integration for Azure lab telemetry
- Hetzner VPS honeypot (Cowrie) → real internet attack data
- Suricata IDS on Debian VM → network detection
- Docker + DVWA → web attack simulation
- Python + AI-assisted alert triage with MITRE mapping

## Key Technical Notes

- All local VMs run ARM64 on Apple Silicon and require ARM-specific binaries such as Sysmon64a.exe and Windows 11 ARM ISO.
- VMware NAT routing means Kali traffic appears as Mac host IP in Windows logs — documented as real-world NAT attribution challenge.
- VMware Fusion on Apple Silicon uses Apple's vmnet.framework, which hides VM-to-VM traffic from BPF, the kernel facility tcpdump and Wireshark use.
- Packet capture must be done on the source VM, such as Kali eth0 — documented in incident 003.
- Splunk minFreeSpace tuned for home lab disk constraints.
- Azure lab resources are isolated inside a dedicated resource group.
- No credentials, keys, tokens, or connection strings are stored in this repository.

## Lab Reports

### Detection / Incident Reports

- 001 — Brute Force Detection
- 002 — Nmap Port Scan Detection
- 003 — Wireshark Packet Capture

### Cloud Security Lab Reports

- 001 — Azure SOC Lab Foundation
