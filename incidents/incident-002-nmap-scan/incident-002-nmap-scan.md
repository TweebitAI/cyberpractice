# Lab Exercise 002 - Nmap TCP Connect Scan Detection with Sysmon and Splunk

**Date:** 2026-04-16

**Analyst:** Artur B.

**Environment:** SOC Home Lab (VMware Fusion, Apple Silicon M2)

## Executive Summary

Simulated network service discovery from a Kali Linux VM against a Windows 11
VM using an Nmap TCP connect scan. Sysmon Event ID 3 network-connection events
were forwarded to Splunk Enterprise and investigated with SPL.

The selected five-minute evidence window contained connections to TCP ports
135, 139, and 445. The timing and port combination were consistent with the
known lab scan. In production, the same telemetry would require source ownership,
change context, and allow-list validation before classifying the activity as
malicious.

## Scenario

- **Tool:** Nmap 7.95
- **Command:** `nmap -sT -p 135,139,445 192.168.178.27`
- **Source:** Kali Linux VM behind VMware NAT
- **Target:** Windows 11 ARM VM (`192.168.178.27`)
- **Scan type:** TCP connect (`-sT`), which completes the TCP handshake
- **Log source:** Sysmon Event ID 3 (network connection)
- **SIEM:** Splunk Enterprise

## Detection and Analysis

Sysmon Event ID 3 recorded the connections observed by the Windows target. The
SPL query extracted source IP, destination IP, destination port, and process
from the raw XML event data:

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?P<EventID>\d+)</EventID>"
| where EventID="3"
| rex field=_raw "<Data Name='DestinationIp'>(?P<DstIP>[^<]+)"
| rex field=_raw "<Data Name='SourceIp'>(?P<SrcIP>[^<]+)"
| rex field=_raw "<Data Name='DestinationPort'>(?P<DstPort>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?P<Process>[^<]+)"
| where SrcIP="192.168.178.24" AND DstIP="192.168.178.27"
| table _time, SrcIP, DstIP, DstPort, Process
| sort -_time
```

### NAT Attribution Limitation

The Kali guest address (`192.168.161.130`) did not appear in the Windows
telemetry. VMware NAT translated the connection, so the Windows events recorded
the Mac host address (`192.168.178.24`) as the source. This demonstrates why an
analyst should not assume that a logged source IP always identifies the original
endpoint; NAT, proxies, and other intermediaries may require additional evidence.

### Evidence

![Nmap scan output from Kali Linux](screenshots/01-kali-nmap-output.png)

![Splunk investigation of Sysmon Event ID 3](screenshots/02-splunk-sysmon-eventid3.png)

### Findings

The published Splunk evidence shows three matching connections in the selected
five-minute window:

- TCP 135 (`msrpc`) associated with `C:\Windows\System32\svchost.exe`
- TCP 139 (`netbios-ssn`) associated with `System`
- TCP 445 (`microsoft-ds`/SMB) associated with `System`

Three connections to related Windows service ports within the same second are
consistent with automated discovery in this controlled scenario. The pattern is
not independently proof of compromise; authorized inventory, vulnerability
scanning, and administrative tools can generate similar telemetry.

## MITRE ATT&CK Mapping

- **Tactic:** Discovery (TA0007)
- **Technique:** [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

## Triage and Response Considerations

In this controlled lab, no containment was required. In a production case:

1. Identify the originating asset and user, accounting for NAT or proxy layers.
2. Check whether the source is an approved scanner, management server, or
   administrator workstation.
3. Expand the search across destination hosts, ports, and a longer time window
   to determine scan scope.
4. Review authentication, process-creation, firewall, and EDR telemetry for
   follow-on activity.
5. If the activity is unauthorized, contain the source host and block traffic
   according to incident-response policy.
6. Escalate when discovery is broad, targets sensitive services, or is followed
   by authentication, exploitation, or lateral-movement indicators.

## Outcome

The exercise validated Sysmon network telemetry ingestion, raw XML field
extraction in SPL, NAT-aware source attribution, and contextual analysis of a
network-service discovery pattern.
