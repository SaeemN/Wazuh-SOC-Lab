# Scheduled Task Persistence Detection (MITRE T1053.005)

## Objective

Simulate persistence using Windows Scheduled Tasks and detect the activity using Sysmon and a custom Wazuh detection rule.

## MITRE ATT&CK

* Technique: T1053.005
* Name: Scheduled Task/Job

## Attack Execution

The following command was executed on the Windows 10 endpoint:

```powershell
schtasks /create /tn "EvilTask" /tr "calc.exe" /sc onlogon /f
```

This creates a scheduled task that launches calc.exe whenever a user logs on.

## Sysmon Evidence

Sysmon Event ID 1 captured process creation:

* Image: schtasks.exe
* Parent Process: powershell.exe
* Command Line: schtasks /create /tn EvilTask /tr calc.exe /sc onlogon /f

## Wazuh Custom Detection Rule

Custom Rule ID: 100101

Description:

Scheduled Task Persistence Detected

## Detection Result

Wazuh successfully generated an alert:

* Rule ID: 100101
* Level: 12
* MITRE Technique: T1053.005

## Skills Demonstrated

* Threat Detection
* Detection Engineering
* Sysmon Log Analysis
* Wazuh Custom Rules
* MITRE ATT&CK Mapping
* Incident Investigation

