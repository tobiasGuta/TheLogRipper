# TheLogRipper

**TheLogRipper** is an interactive PowerShell tool for parsing and analyzing Windows Event Log (`.evtx`) files. It extracts key fields, flags suspicious behavior, and offers export to JSON or CSV. Built for threat hunters, SOC analysts, and DFIR workflows.

---

## Why Use TheLogRipper?

Because Event Viewer sucks.

Manual `.evtx` analysis is slow, clunky, and frustrating. TheLogRipper gives you:
- CLI-based interaction
- Highlighted suspicious strings
- Fast extraction of useful metadata
- Optional export for offline analysis or reporting

Whether you're triaging a system post-breach or trying to track a specific type of event this is your drop-in forensic blade.

---

## Features

- Interactive prompt-based interface
- Supports multiple Event IDs at once
- Detects suspicious strings (`.exe`, `powershell`, `shutdown`, `Invoke-*`, `bypass`, etc.)
- Outputs full parsed event data in readable format
- Optional export to:
  - JSON (`TheLogRipper_output.json`)
  - CSV (`TheLogRipper_output.csv`)
- Compatible with PowerShell 5.1+ (no PowerShell 7 required)
- Infinite loop mode for multiple log investigations

---

## Usage

### 1. Clone the repo:
```bash
git clone https://github.com/tobiasGuta/TheLogRipper.git
cd TheLogRipper
```
### 2. Run the script:
```bash
.\TheLogRipper.ps1
```

### 3. Follow prompts:
- Enter path to .evtx file
- Enter Event ID(s) to search (comma-separated)
- Choose to export or not
- Type exit when done

### Suspicious Value Detection
TheLogRipper flags fields containing known suspicious keywords like:

- .exe, cmd.exe, powershell, base64
- shutdown, curl, wget
- Invoke-*, bypass, wscript
- Base64 strings and encoded payloads
- These are highlighted in red for fast visual triage.

## Example Session

https://github.com/user-attachments/assets/2a4708f7-54cd-49dd-955d-f3f4cbce252b

## TheLogRipper Versions Explained

### TheLogRipper.ps1 (Stable)
This is the original version of the tool. It performs event log analysis based on specified Event IDs and highlights suspicious values in common fields like `DataValues`. It’s reliable and simple — ideal for general log inspection or incident triage.

- ✅ Takes `.evtx` file input
- ✅ Filters by Event ID
- ✅ Highlights suspicious terms (e.g., PowerShell, base64, etc.)
- ✅ Optional export to JSON/CSV

> Use this if you want a solid base log parser without too much complexity.

---

### TheLogRipper2.0.ps1 (Advanced, In Progress)
This version builds on the original by introducing **conditional smart filtering** for authentication events like `4624` and `4625`. It prompts the user for more specific filtering **only when** those event types are present.

#### Features added in 2.0:

- Detection of authentication-related events
- Optional filter prompts:
  - Logon Type(s) (e.g., 3, 10)
  - TargetUserName (e.g., Administrator)
  - IpAddress (e.g., 10.10.53.248)
-  More fine-tuned triage for brute force, lateral movement, and failed logon attempts
-  Future plans: coming soon

> This version is actively being enhanced. Expect rapid updates and experimental logic.

## Example Session

https://github.com/user-attachments/assets/f83b2018-d994-4b2a-929f-c856fd18620c

### This video demonstrates how TheLogRipper2.0.ps1 improves over the original version:

- First half: Running **without filters** shows **all matching logs** (4624, 4625)
- Second half: Running **with advanced filters** shows **only logs** matching:
  - LogonType: 10 or 3
  - TargetUserName: Administrator
  - IpAddress: 10.10.53.248

These filters are optional and only appear **when authentication events (e.g., 4624/4625)** are detected.  
Perfect for narrowing down brute force attempts, RDP logons, or lateral movement.

> Still under development more features coming.

## Malicious Activity Detection & Analysis with TheLogRipper2.0

My PowerShell script doesn't just parse logs it actively detects potential malicious activity and assigns a **risk score** based on suspicious behaviors. For example, it can flag when a user downloads and executes a suspicious file.

### Real-World Example: Sarah.Miller's Download & Execution

In one analyzed Sysmon log(Sysmon is an external tool not installed by default.), a user named **sarah.miller** downloads a file (`ckjg.exe`) and then executes it. The script flags this as suspicious and assigns a risk score to help prioritize investigations.

-   We can see the executable file appear in **Event ID 1** (process creation). [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)

<img width="1498" height="711" alt="image" src="https://github.com/user-attachments/assets/e7398ef5-61aa-4ecd-bd9d-59529ef352f3" />

-   But to find **where the file was downloaded from**, we dig into **Event ID 15** (File Create Stream Hash), which logs Alternate Data Streams.

### Why Event ID 15 Matters

Event ID 15 captures metadata attached to downloaded files, like the **Zone.Identifier** stream in Windows. This stream stores the original URL the file was downloaded from. [Sysmon Event ID 15 - FileCreateStreamHash](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015)

For Sarah's case, Event ID 15 reveals:

`HostUrl=http://gettsveriff.com/bgj3/ckjg.exe`

<img width="1420" height="523" alt="image" src="https://github.com/user-attachments/assets/172d7ab7-10c7-41fd-8eb9-9f53166485c9" />

This tells us exactly which URL the suspicious executable was fetched from.

We can also investigate Event ID 11 and 13, which correspond to File Create and Registry Value Set events, respectively. [Sysmon Event ID 11 - FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)

<img width="1141" height="474" alt="image" src="https://github.com/user-attachments/assets/f5cc8e14-c9ab-40c3-ae97-d1335eff6099" />

If we want to investigate Event IDs 3 and 22 (Network Connection and DNS Query), the script will show you everything you need to know. [Sysmon Event ID 3 - Network connection detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?source=Sysmon&eventID=3) and [Sysmon Event ID 22 - DNSEvent](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022)

<img width="1124" height="649" alt="image" src="https://github.com/user-attachments/assets/7b1fcc2c-f00e-4f7e-9d01-ad9d03c2a0e3" />

<img width="1062" height="486" alt="image" src="https://github.com/user-attachments/assets/084dcd08-be82-4844-8187-9b638bf85ec0" />

## TheLogRipper2.0.ps1 Last Update: User Management Correlation (Event IDs 4720 & 4732)(07/12/2025)
We added a new automatic correlation feature for User Account Creation (4720) and Security Group Membership Changes (4732).

### When both event IDs are selected, the script now prompts:

"Want to run a User Creation + Group Membership Summary automatically?"

If you choose yes, it will:

- Detect new users created (Event ID 4720)

- Check which groups (e.g., Administrators, Remote Desktop Users) the user was added to shortly after (Event ID 4732)

### Correlate using the SID and Logon ID to show:

- Who created the user

- What groups the user was added to

## Example

<img width="956" height="243" alt="Screenshot 2025-07-12 182931" src="https://github.com/user-attachments/assets/e056a81c-d294-4855-b290-014ee3736713" />

## TheLogRipper2.0.ps1 — Last Update(07/13/2025):

- Added support to check all Event IDs (type "all" to select every event)

- Introduced two new filters: WorkstationName and External IPs filtering

## Example 

<img width="1892" height="777" alt="image" src="https://github.com/user-attachments/assets/426da6ee-cac3-40b9-938d-003323be050e" />

## TheLogRipper2.0.ps1 Last Update: DNSEvent (Event IDs 22)(07/12/2025) 

When the user inputs Event ID 22, the script now asks if they want to apply extra filters specifically for Image path and ProcessID. If the user says yes, it prompts for the filter values to narrow down the event log results accordingly. If not, it continues normally without those filters.

In this scenerario we are going to use EventId 1 [Sysmon Event ID 1 - Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001) and EventId 22 [Sysmon Event ID 22 - DNSEvent](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022), 

The process creation event provides extended information about a newly created process.
<img width="1521" height="748" alt="image" src="https://github.com/user-attachments/assets/b6db1d25-2864-43ff-bd52-d4184d1d0d82" />

Why Event ID 22 Matters in Malware Analysis:
Event ID 22 (DNS query from Sysmon) is valuable for detecting malware that uses DNS to reach out to attacker infrastructure like command and control (C2) servers. Malware often blends into normal traffic, but each DNS query is tied to the process that made it.

By analyzing this event, we can correlate suspicious domain lookups with specific processes either by Process ID (e.g., 5484) or Image path (e.g., C:\Users\Administrator\Pictures\best-cat.jpg.exe). This helps us isolate which binary initiated the connection, even in a noisy log environment.

<img width="1889" height="785" alt="image" src="https://github.com/user-attachments/assets/76a8f92b-4446-42f2-a7f1-abdb0b7fd93a" />

<img width="1891" height="774" alt="image" src="https://github.com/user-attachments/assets/a63ce398-eea3-4672-9f5f-ff2306542ec7" />

## TheLogRipper2.0.ps1 Last Update: extra filters (Event ID 1)(07/16/2025)

When the user inputs Event ID 1, the script now asks if they want to apply extra filters specifically for .

<img width="1043" height="171" alt="image" src="https://github.com/user-attachments/assets/71f6ccb2-67c4-4add-a00f-591f2faa9013" />

Example: 

Image:

<img width="1871" height="767" alt="image" src="https://github.com/user-attachments/assets/808f5dad-b621-4e80-aae2-a9a7f6b521d7" />

<img width="1648" height="303" alt="image" src="https://github.com/user-attachments/assets/b12ac650-65db-4048-8e57-0e9585cd3fdb" />

Parent Process Id:

<img width="1889" height="782" alt="image" src="https://github.com/user-attachments/assets/cdfda0a0-33d5-4ecf-ae10-19bad9118485" />

Parent Image:

<img width="1883" height="768" alt="image" src="https://github.com/user-attachments/assets/10889255-25b6-4c28-9c3c-641d4b4a32d7" />


## log_UIviewer.py

After ripping apart logs with my custom-built tool https://github.com/tobiasGuta/TheLogRipper built to recompile and enrich EVTX logs I realized I needed something more visual to hunt threats efficiently.

So I built a web-based threat hunting UI using Streamlit!

Why? Because across dozens of logs, you need speed, clarity, and context.

https://github.com/user-attachments/assets/7d28dae9-0966-4999-b632-bc6c74a6bbca

# log_UIviewer_plusYARA.py

Current Limitation:
Right now, when you load a new log in log_UIviewer_plusYARA.py, the YARA rules applied to the previous log don’t reset properly. This means tags, MITRE IDs, and YARA detection results from the old log bleed over and apply incorrectly to the new logs, even if they don’t actually match.

https://github.com/user-attachments/assets/d2bfa527-b580-406d-bc57-cbfa5cc36d4a




