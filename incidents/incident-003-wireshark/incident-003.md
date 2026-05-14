# Incident 003 — Network Reconnaissance via TCP Connect Scan

**Detection method:** Packet capture (tcpdump on attacker NIC, analyzed in Wireshark)
**Date:** 2026-05-14
**Lab environment:** VMware Fusion on Apple Silicon (M2 MacBook), bridged Wi-Fi networking
**Analyst:** Artur B.

---

## Triage

### Alert
Network reconnaissance detected against host `192.168.178.27` (DESKTOP-H4578B8). Three TCP SYN probes from `192.168.178.29` targeting RPC/SMB-related ports (135, 139, 445) over a 30-second window. Source MAC `00:0c:29:b4:63:49` (VMware-assigned) confirms originating host as the lab Kali VM.

### Hypothesis
Active port scan against Windows file/RPC services. Inter-probe spacing of approximately 15 seconds suggests slow-scan evasion, consistent with nmap's `-T1` ("sneaky") timing template — designed to defeat threshold-based detection.

### Evidence For
- pcap shows three complete TCP three-way handshakes (SYN -> SYN-ACK -> ACK -> RST) initiated from `.29` to `.27` on ports 135, 139, 445
- Connect-then-RST pattern is the signature of `nmap -sT` (TCP connect scan)
- Wireshark TCP dissector reports `Conversation completeness: Complete, NO_DATA` -- handshake completed but zero application bytes exchanged. Real connections always carry payload; probe traffic does not.
- Inter-probe spacing: packets 3 -> 9 -> 13 at 15.45s -> 30.45s -> 45.45s. Difference of ~15.0s, accurate to the millisecond. Human-driven traffic is not this regular; this fingerprint is automation.
- Target ports (135 msrpc, 139 netbios-ssn, 445 microsoft-ds) form a known Windows reconnaissance set, mapping to MITRE T1046 (Network Service Discovery)

### Evidence Against
None. Pattern is unambiguous; ports targeted are a known reconnaissance set; source IP is the documented attacker host in this controlled lab environment.

### Verdict
**True Positive — confirmed reconnaissance.** Confidence: 100% (lab-controlled simulation).

### Response (real-world equivalent)
1. Isolate source host pending investigation
2. Pivot in Splunk: search Sysmon EID 3 from `.29` across all internal hosts in the past 24 hours -- port scans rarely target a single victim
3. Check `WinEventLog:Security` on `.27` for any successful authentication events from `.29` around the scan window
4. Document timeline; escalate to L2 if scan was followed by exploitation attempts (e.g. Sysmon EID 1 process creation tied to inbound SMB session)

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

- The Splunk alert from Incident 002 ("more than 5 connections in 5 minutes") **would not fire on this scan**. Three connections across 30 seconds remains far below threshold.
- Threshold-based detection is necessary but not sufficient. Complement with:
  - **Sequence-based detection:** same source -> multiple distinct destination ports within an extended window (e.g. 1 hour)
  - **Conversation-completeness detection:** TCP streams ending with `Complete, NO_DATA` indicate probe traffic
  - **Periodicity detection:** inter-event spacing with sub-second standard deviation indicates automation
- An attacker tuning their timing to evade your alert window is itself a signal of intent. Statistical regularity of the connections is suspicious in a way that volume alone is not.

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

In each test, ICMP connectivity between the VMs was confirmed working (sub-millisecond round-trip times), proving the failure was capture-side, not connectivity-side.

### Root cause
VMware Fusion on Apple Silicon does not provide kernel-level packet visibility for VM-to-VM traffic.

Apple's M-series Macs do not permit the legacy VMware kernel extension that previously implemented `vmnet` driver hooks. VMware Fusion 13+ on Apple Silicon is forced to use Apple's `vmnet.framework` (the "MacOS network virtualization API"). This framework manages VM-to-VM forwarding via internal mechanisms not exposed to BPF (Berkeley Packet Filter), which is the kernel facility that `libpcap` -- and therefore both `tcpdump` and Wireshark -- depend on. With no BPF hook into the forwarding path, no userspace capture tool on the host can observe the traffic.

### Confirmation via VMware's own tooling
VMware ships a bundled utility, `vmnet-sniffer`, located at `/Applications/VMware Fusion.app/Contents/Library/vmnet-sniffer`.

On Intel Macs this tool was the documented workaround for the BPF limitation, accessing VMware's vmnet driver directly. On Apple Silicon, invoking it returns the error: *"is not supported when using MacOS network virtualization API. Use tcpdump instead."*

This is VMware acknowledging the architectural change. The error does not mean tcpdump works on the bridge interfaces (it does not, as documented above); it reflects that VMware's private hook into their old driver no longer exists, and they have no replacement.

### Chosen alternative
Capture on the attacker's NIC inside the source VM (Kali `eth0`), which is a normal Linux interface with full BPF support. Commands used:

- On Kali: `sudo tcpdump -i eth0 -w /tmp/exercise003.pcap host 192.168.178.27`
- Then from second Kali terminal: `sudo nmap -sT -T1 -p 135,139,445 192.168.178.27`
- After scan completes, stop tcpdump with Ctrl+C
- Transfer to analyst workstation: `scp adm1@192.168.178.29:/tmp/exercise003.pcap ~/Desktop/`
- Open in Wireshark: `open ~/Desktop/exercise003.pcap`

Capturing on the source NIC yields the same TCP frames a host-side capture would -- every packet a VM emits must transit its own virtual interface, and that interface is fully BPF-visible inside Linux. The pcap is byte-equivalent to the unattainable host-side capture.

### Lessons
- BPF availability is a property of the network stack, not the operating system. The same Mac that fails to capture VM-to-VM traffic captures Wi-Fi traffic on en0 without issue.
- "Capture on the attacker" is the architecturally correct fallback in any virtualized lab where the host hypervisor manages internal forwarding outside BPF (also applies to: VirtualBox internal networks, Hyper-V private switches, container CNI drivers without host bridge).
- VMware's vendor messaging ("Use tcpdump instead") is misleading on Apple Silicon and should not be trusted at face value -- the error message describes the tool's surrender, not a working alternative.

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
- Incident 001 — Brute force detection (Splunk + Windows Security log, EID 4625)
- Incident 002 — Nmap port scan detection (Splunk + Sysmon EID 3)

Incident 003 complements 002 by adding packet-level evidence to the same attack technique. 002 demonstrates that the scan can be detected from logs alone; 003 demonstrates how the scan looks on the wire and surfaces a slow-scan timing pattern that 002's threshold alert would miss.
