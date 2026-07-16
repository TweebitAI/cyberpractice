# SOC Home Lab - Detection and Investigation Practice

Hands-on SOC detection lab built on Apple Silicon (VMware Fusion, M2 MacBook).  
The repository documents controlled attack simulations, evidence collection,
SIEM analysis, detection limitations, and incident-style reporting.

## What This Repository Demonstrates

- Alert investigation and evidence correlation in Splunk Enterprise
- Windows Security and Sysmon telemetry analysis
- SPL query development and scheduled alert validation
- Packet-level investigation with tcpdump and Wireshark
- MITRE ATT&CK mapping with documented analytical limitations
- Clear triage notes, verdicts, escalation criteria, and response recommendations

All exercises were performed in a controlled lab. Findings describe the lab
evidence and should not be interpreted as production incident experience.

## Current Stack

- **SIEM:** Splunk Enterprise (macOS host)
- **Endpoint:** Windows 11 ARM VM + Sysmon (ARM64)
- **Attacker:** Kali Linux ARM VM
- **Linux target:** Debian 12 ARM VM (planned: Docker, Suricata, Squid proxy)
- **Cloud:** Microsoft Azure SOC Lab foundation

## Completed Lab Exercises

| # | Exercise | Technique | MITRE |
|---|----------|-----------|-------|
| 001 | [Password Spray Simulation](incidents/incident-001-bruteforce/incident-001-bruteforce.md) | Same password across multiple accounts -> Event ID 4625 -> Splunk alert review | T1110.003 |
| 002 | [Nmap TCP Connect Scan](incidents/incident-002-nmap-scan/incident-002-nmap-scan.md) | Kali `-sT` scan -> Sysmon Event ID 3 -> SPL investigation | T1046 |
| 003 | [Slow Scan Packet Analysis](incidents/incident-003-wireshark/incident-003.md) | Nmap `-T1` scan -> source-side tcpdump -> Wireshark analysis | T1046 |

## Cloud Security Labs

| # | Lab | Focus | Status |
|---|-----|-------|--------|
| 001 | [Azure SOC Lab Foundation](labs/azure-soc-lab/lab-001-azure-foundation/lab-001-azure-foundation.md) | Budget, resource group, virtual network, subnet | Completed |
| 002 | Windows Server DC01 Deployment | VM deployment, private IP, secure access | Planned |
| 003 | Active Directory Domain Services | Domain controller, `lab.local` domain | Planned |
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
- Python-based alert enrichment with evidence validation and MITRE mapping

## Key Technical Notes

- All local VMs run ARM64 on Apple Silicon and require ARM-specific binaries such as Sysmon64a.exe and Windows 11 ARM ISO.
- In the NAT-based Incident 002 setup, Windows telemetry recorded the translated host IP rather than the Kali guest IP. This is documented as an attribution limitation.
- In the bridged Incident 003 setup, host-side capture attempts returned no VM-to-VM packets on the tested interfaces. The report records this as an environment-specific observation, not a universal VMware Fusion limitation.
- Source-side capture on Kali `eth0` provided the evidence used for Incident 003.
- Splunk minFreeSpace tuned for home lab disk constraints.
- Azure lab resources are grouped in a dedicated resource group; network isolation controls are planned for later phases.
- No credentials, keys, tokens, or connection strings are stored in this repository.

## Lab Reports

### Detection / Incident Reports

- [001 - Password Spray Simulation and Failed Logon Detection](incidents/incident-001-bruteforce/incident-001-bruteforce.md)
- [002 - Nmap TCP Connect Scan Detection](incidents/incident-002-nmap-scan/incident-002-nmap-scan.md)
- [003 - Slow Scan Packet Analysis](incidents/incident-003-wireshark/incident-003.md)

### Cloud Security Lab Reports

- [001 — Azure SOC Lab Foundation](labs/azure-soc-lab/lab-001-azure-foundation/lab-001-azure-foundation.md)
