# Incident 003 — Network Service Discovery via TCP Connect Scan

- **Detection method:** Packet capture (tcpdump on attacker NIC, analyzed in Wireshark)
- **Date:** 2026-05-14
- **Lab environment:** VMware Fusion on Apple Silicon (M2 MacBook), bridged Wi-Fi networking
- **Analyst:** Artur B.

---

## Triage

### Alert
Network service discovery activity was observed against host `192.168.178.27`
(DESKTOP-H4578B8). Three TCP SYN probes from `192.168.178.29` targeted
RPC/SMB-related ports (135, 139, 445) over a 30-second window. Lab inventory
mapped the source IP and MAC `00:0c:29:b4:63:49` to the Kali VM. The VMware OUI
is consistent with a VMware virtual NIC but does not independently identify the
guest operating system or asset owner.

### Hypothesis
Active service discovery against Windows file/RPC services. Inter-probe spacing of approximately 15 seconds is consistent with nmap's `-T1` ("sneaky") timing template and may evade short-window or volume-only detection rules.

### Evidence For
- The pcap shows three successful TCP connection establishments from `.29` to
  `.27` on ports 135, 139, and 445 (SYN -> SYN-ACK -> ACK), each immediately
  followed by a client-initiated RST.
- The connect-then-RST pattern is consistent with an `nmap -sT` TCP connect
  scan, but it is not unique to Nmap
- Wireshark reports `Conversation completeness: Complete, NO_DATA`: the handshake completed with no application payload. This supports a probe hypothesis when combined with the immediate reset and port sequence, but it is not conclusive by itself because legitimate health checks can also complete without payload.
- Inter-probe spacing: packets 3 -> 9 -> 13 at 15.45s -> 30.45s -> 45.45s. The approximately 15-second interval supports automated timing; regularity alone does not establish malicious intent.
- Target ports (135 msrpc, 139 netbios-ssn, 445 microsoft-ds) form a known Windows reconnaissance set, mapping to MITRE T1046 (Network Service Discovery)

### Evidence Against
In production, an approved vulnerability scanner, inventory tool, or administrator connectivity check could create a similar pattern. In this lab, those alternatives were excluded because the source system and executed Nmap command were known.

### Verdict
**True Positive - confirmed simulated network service discovery.** Confidence: high because the source, command, target, timing, and packet capture were controlled and documented.

### Response (real-world equivalent)
1. Identify the source asset and confirm whether it is an approved scanner or administrator system.
2. Pivot in Splunk: search Sysmon Event ID 3 from `.29` across internal hosts and a wider time window to establish scope.
3. Check firewall, authentication, and endpoint telemetry on `.27` for follow-on activity around the scan window.
4. If unauthorized, contain the source according to policy and document the timeline.
5. Escalate to L2 if the scan is broad, targets sensitive services, or is followed by exploitation, authentication, or lateral-movement indicators.

### MITRE ATT&CK
- **Tactic:** TA0007 Discovery
- **Technique:** T1046 Network Service Discovery

---

## Packet Walkthrough

The capture contains 16 packets total. Reading top-to-bottom:

**Packets 1-2 (t=0.000s) — ARP discovery.** Kali broadcasts "who has 192.168.178.27?"; Windows replies with its MAC. Required Layer 2 lookup before any TCP can flow.

**Packets 3-6 (t=15.4s) — Probe of port 139 (netbios-ssn):**
- SYN (Kali -> Win): "open connection to 139?"
- SYN-ACK (Win -> Kali): "yes, port open"
- ACK (Kali -> Win): handshake complete
- RST-ACK (Kali -> Win): immediate teardown -- nmap has its answer

**Packets 7-8 (t=20.3s) — ARP refresh.** Windows verifying Kali's MAC; routine.

**Packets 9-12 (t=30.4s) — Same handshake-then-RST pattern for port 445 (microsoft-ds / SMB).**

**Packets 13-16 (t=45.4s) — Same pattern for port 135 (msrpc).**

---

## Detection Engineering Notes

The `-T1` timing template used here is operationally significant for SOC alert tuning:

- A hypothetical volume rule requiring more than five connections in five minutes would not fire on this scan. The capture contains only three probes across approximately 30 seconds.
- Threshold-based detection is necessary but not sufficient. Complement with:
  - **Sequence-based detection:** same source -> multiple distinct destination ports within an extended window (e.g. 1 hour)
  - **Conversation-completeness enrichment:** TCP streams ending with `Complete, NO_DATA` can support a probe hypothesis when correlated with port diversity and rapid reset behavior
  - **Periodicity enrichment:** consistent inter-event spacing can support an automation hypothesis
- Slow and regular probes can reduce the effectiveness of volume thresholds. Detection should combine timing with source role, destination scope, port diversity, allow lists, and follow-on behavior.

---

## Capture Methodology

**This section documents an architectural finding and the resulting analytical decision.** It is included because the capture method affected the evidence chain.

### Initial approach (failed)
Standard host-side packet capture from the analyst workstation (macOS host) targeting the bridged subnet `192.168.178.0/24` on which both the attacker and victim VMs reside. Tested across all candidate interfaces:

| Interface | Description | Result |
|-----------|------------|--------|
| `en0` | Mac Wi-Fi (physical bridged uplink) | 0 packets captured |
| `bridge100` | vmnet1 / Host-only (192.168.30.0/24) | 0 packets captured |
| `bridge101` | vmnet8 / NAT (192.168.161.0/24) | 0 packets captured |
| `bridge102` | vmnet2 / Bridged (mapped to en0) | 0 packets captured |

In each test, ICMP connectivity between the VMs was confirmed working
(sub-millisecond round-trip times). This established network reachability while
the zero-packet results indicated a host-side capture visibility, forwarding
path, interface-selection, or capture-configuration issue; ICMP success alone
did not prove one specific root cause.

### Observed limitation and working hypothesis

On this host and network configuration, the tested macOS interfaces did not expose the VM-to-VM frames to the host-side `tcpdump` capture. This is an environment-specific observation. The available evidence does not justify a universal claim that VMware Fusion on Apple Silicon can never expose VM traffic to host capture tools.

VMware Fusion provides bridged, NAT, and host-only networking modes, while Apple's `vmnet` framework provides packet I/O for virtual-machine interfaces. The exact forwarding and capture path can vary by configuration. For this exercise, the practical conclusion was limited to the tested setup: host-side capture did not produce the required evidence.

### VMware tooling result
VMware ships a bundled utility, `vmnet-sniffer`, located at `/Applications/VMware Fusion.app/Contents/Library/vmnet-sniffer`.

On Intel Macs this tool was the documented workaround for the BPF limitation, accessing VMware's vmnet driver directly. On Apple Silicon, invoking it returns the error: *"is not supported when using MacOS network virtualization API. Use tcpdump instead."*

The message confirmed that `vmnet-sniffer` was unavailable in this configuration. It did not establish that host-side `tcpdump` would capture the VM-to-VM traffic; the interface tests above remained the direct evidence for the limitation observed in the lab.

### Chosen alternative
Capture on the attacker's NIC inside the source VM (Kali `eth0`), which is a normal Linux interface with full BPF support. Commands used:

- On Kali: `sudo tcpdump -i eth0 -w /tmp/exercise003.pcap host 192.168.178.27`
- Then from second Kali terminal: `sudo nmap -sT -T1 -p 135,139,445 192.168.178.27`
- After scan completes, stop tcpdump with Ctrl+C
- Transfer to analyst workstation: `scp adm1@192.168.178.29:/tmp/exercise003.pcap ~/Desktop/`
- Open in Wireshark: `open ~/Desktop/exercise003.pcap`

Capturing on the source NIC preserved the packet sequence, flags, ports, timing, and payload information required for this investigation. It should not be described as byte-identical to a capture taken at a different point, because link-layer details, timestamps, offload behavior, and visibility can vary by capture location.

### Lessons
- Packet visibility depends on the capture interface and virtualization
  forwarding path. The presence of BPF and `tcpdump` does not guarantee that a
  particular VM-to-VM frame will be observable on every host interface.
- Source-side capture was a practical fallback for this lab because it provided the evidence needed to analyze the simulated scan.
- Tool guidance should be validated against the interfaces and network mode actually in use rather than assumed to apply to every virtualized topology.

### Platform References

- [Apple vmnet framework documentation](https://developer.apple.com/documentation/vmnet)
- [Broadcom: Understanding networking types in VMware Fusion](https://knowledge.broadcom.com/external/article/303393)

---

## Artifacts

- `screenshots/01-overview-all-packets.png` -- Full 16-packet capture, no filter applied. ARP, three TCP handshakes (gray), three RST teardowns (red), ARP refresh.
- `screenshots/02-syn-only-filter.png` -- Display filter `tcp.flags.syn == 1 and tcp.flags.ack == 0` applied. List narrows to three SYN probes (one per target port).
- `screenshots/03-syn-packet-drilldown.png` -- Packet 3 expanded showing TCP header: src port 45082, dst port 139, sequence 0, Flags 0x002 (SYN), conversation completeness `Complete, NO_DATA (39)`.
- `exercise003.pcap` -- Raw packet capture file (16 packets).

---

## Reproduction

Lab setup at the time of capture:

| Host | Role | IP | NIC mode |
|------|------|-----|----------|
| Mac (M2) | Analyst workstation, Splunk indexer | 192.168.178.24 | Physical Wi-Fi |
| Kali | Attacker VM | 192.168.178.29 | Bridged Wi-Fi |
| Windows 11 ARM64 | Target VM (DESKTOP-H4578B8) | 192.168.178.27 | Bridged Wi-Fi |

Reproduction steps documented in *Capture Methodology* above.

---

## Related Incidents
- Incident 001 — Password spraying detection (Splunk + Windows Security log, EID 4625)
- Incident 002 — Nmap port scan detection (Splunk + Sysmon EID 3)

Incident 003 complements Incident 002 by adding packet-level evidence to the same ATT&CK technique. Incident 002 demonstrates investigation with Sysmon and Splunk; Incident 003 shows the packet sequence and explains why volume-only thresholds may miss a slow, low-count scan.
