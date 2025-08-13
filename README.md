# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jacobvasquez92/threat-hunting-scenario-tor/tree/main)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

An initial search of the DeviceFileEvents table for files containing the string "tor" was performed, revealing a series of file-related events associated with user "kodoghouse". These events began at 2025-08-12T02:13:03.861808Z and included the download and subsequent silent installation of a Tor installer. This process resulted in the creation of multiple Tor-related files on the user's desktop, and culminated with the creation of a file named "tor-shopping-list.txt" on the desktop at 2025-08-12T02:23:52.5166321Z.

**Query used to locate events:**

```kql
// Detect the installer being downloaded
DeviceFileEvents
| where DeviceName =="jv-win10-disa-s"
| where InitiatingProcessAccountName == "kodoghouse"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-12T02:13:03.861808Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1611" height="587" alt="image" src="https://github.com/user-attachments/assets/49590a15-ebf2-4a0c-8038-775a3c11015f" />

---

### 2. Searched the `DeviceProcessEvents` Table

An investigation of the DeviceProcessEvents table for processes with the command line string tor-browser-windows-x86_64-portable-14.5.5.exe confirmed a suspicious event. At 2025-08-12T02:15:45.1270531Z, an employee on the jv-win10-disa-s device executed the file tor-browser-windows-x86_64-portable-14.5.5.exe from their Downloads folder. The command line included a switch that initiated a silent installation of the software.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1515" height="555" alt="image" src="https://github.com/user-attachments/assets/9ec88ce9-bebc-45bd-bdd3-2009b2169d2e" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Based on a search of the DeviceProcessEvents table for processes initiated by the user kodoghouse, evidence of Tor Browser usage was identified. The initial launch was detected at 2025-08-12T02:16:12.6258334Z, with the process being identified as firefox.exe. This initial event was followed by several subsequent instances of both firefox.exe and tor.exe being spawned, confirming the activation of the Tor Browser.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1467" height="638" alt="image" src="https://github.com/user-attachments/assets/171f0fd5-cacd-4f96-9b37-c8b5ab214ff5" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

An investigation of the DeviceNetworkEvents table for connections on known Tor ports confirmed unauthorized usage. At 2025-08-12T02:16:53.9930483Z, a connection was established from the jv-win10-disa-s device to the remote IP address 96.20.102.87 on port 9001. This connection was initiated by tor.exe. The process was located at c:\users\kodoghouse\desktop\tor browser\browser\torbrowser\tor\tor.exe. The investigation also found a few other connections, including several to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1433" height="725" alt="image" src="https://github.com/user-attachments/assets/c668410a-7a3c-43f5-a03e-5c06dafbef24" />



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
