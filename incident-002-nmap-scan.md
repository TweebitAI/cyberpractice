# Lab Exercise 002 — Nmap Port Scan Detection
Date: 2026-04-16
Analyst: Artur B.

## Scenario
Simulated reconnaissance attack from Kali Linux against 
Windows 11 VM using Nmap TCP connect scan.

## Attack
Tool: Nmap 7.95
Command: nmap -sT -p 135,139,445 192.168.178.27
From: Kali Linux VM (routed via 192.168.178.24)

## Detection Method
Sysmon EventID 3 (Network Connection) captured inbound 
connections to Windows VM.
Splunk SPL query extracted SourceIP, DestinationIP, 
DestinationPort, and Process fields from raw XML.

## Evidence
Multiple scans detected at 14:41, 14:48, 14:53, 14:55.
Each scan generated 3 connections in the same second:
- Port 135 (msrpc) → C:\Windows\System32\svchost.exe
- Port 139 (netbios-ssn) → System
- Port 445 (microsoft-ds) → System

## MITRE ATT&CK Mapping
Tactic: Reconnaissance
Technique: T1046 — Network Service Discovery

## Key Observation
Simultaneous connections to ports 135/139/445 within 
the same second is a strong indicator of automated 
port scanning activity.
