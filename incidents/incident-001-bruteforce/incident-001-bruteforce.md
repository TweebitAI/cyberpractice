# Lab Exercise 001 - Password Spraying Simulation and Failed Logon Detection

**Date:** 2026-04-16

**Analyst:** Artur B.

**Environment:** SOC Home Lab (VMware Fusion, Apple Silicon M2)

## Executive Summary

Simulated a password spraying pattern against a Windows 11 VM by using the
same incorrect password across five accounts. Windows Security Event ID 4625
events were forwarded to Splunk Enterprise. A scheduled per-account failed
logon alert triggered after each target account exceeded five failures.

The alert confirmed repeated authentication failures, while correlation across
the five accounts and knowledge of the lab command established the password
spraying scenario. The exercise also identified a detection gap: a per-account
threshold alone can miss a low-and-slow spray that stays below the threshold for
each user.

## Scenario

- **Technique simulated:** One password attempted against multiple accounts
- **Tool:** PowerShell using `PSCredential`
- **Target accounts:** `Administrator`, `admin`, `root`, `testuser`, `service`
- **Target:** Windows 11 ARM VM (`DESKTOP-H4578B8`)
- **Log source:** Windows Security log, Event ID 4625 (failed logon)
- **SIEM:** Splunk Enterprise

The loop was executed repeatedly during testing, producing seven failed logon
events for each target account.

## Attack Simulation

```powershell
$users = @("Administrator", "admin", "root", "testuser", "service")

foreach ($user in $users) {
    $secpasswd = ConvertTo-SecureString "WrongPass!" -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ($user, $secpasswd)
    Start-Job -ScriptBlock { whoami } -Credential $creds 2>$null
}
```

## Detection and Analysis

The scheduled search ran every five minutes and returned accounts with more
than five failed logons. The query below matches the published evidence:

```spl
index=* source="WinEventLog:Security" EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen by Account_Name
| where count > 5
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort -count
```

### Evidence

![Splunk showing failed logons by account](screenshots/01-splunk-4625-events.png)

![Splunk scheduled alert triggered](screenshots/02-triggered-alert.png)

### Findings

- Each of the five target accounts recorded seven failed logons.
- The search also returned 35 events associated with `winvm-1`; these were
  treated as unrelated test/background activity rather than part of the five
  targeted user accounts.
- The scheduled alert fired at 17:10 CEST and appeared in Splunk's Triggered
  Alerts view.
- Event ID 4625 does not expose the attempted password. In production, the
  password-spray classification must be supported by source, timing, account
  distribution, and other authentication context.

## Detection Limitation and Improvement

The demonstrated alert groups failures by account. It detects repeated failures
against individual accounts but does not reliably identify low-volume spraying
across many accounts. A stronger analytic would correlate distinct target
accounts by source and time window, for example:

```spl
index=* source="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count dc(Account_Name) as targeted_accounts
        values(Account_Name) as accounts
        by Source_Network_Address _time
| where targeted_accounts >= 5
```

Field names depend on the Windows event parsing configuration and should be
validated before production use.

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** T1110 - Brute Force
- **Sub-technique:** [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

The scenario is password spraying because one password was attempted across
multiple accounts. Credential stuffing (`T1110.004`) instead uses previously
compromised username/password pairs.

## Triage and Response Considerations

In this controlled lab, no containment was required. In a production case:

1. Validate the source system, authentication service, time window, and whether
   the activity matches an approved scanner or test.
2. Search for successful logons, especially Event ID 4624, from the same source
   before and after the failures.
3. Identify privileged, service, or high-impact accounts among the targets.
4. Apply account lock, password reset, source blocking, or conditional-access
   controls according to policy and verified scope.
5. Escalate when privileged accounts, successful authentication, distributed
   sources, or continuing attempts increase the potential impact.

## Outcome

The exercise validated Windows failed-logon ingestion, SPL aggregation, and
scheduled alert execution. It also demonstrated why technique-specific analysis
requires correlation across accounts rather than reliance on a single
per-account threshold.
