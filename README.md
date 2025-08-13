# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="869" height="515" alt="image" src="https://github.com/user-attachments/assets/8c59f805-b866-40a3-93c9-c0f6620cc37f" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](threat-hunting-scenario-tor-event-creation.md)

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

### **1. File Download – TOR Installer**

| Timestamp           | Event                 | Action                                     | File Path                                                                      |
| ------------------- | --------------------- | ------------------------------------------ | ------------------------------------------------------------------------------ |
| 2025-08-11 19:13:03 | TOR installer renamed | User renamed file to prepare for execution | `C:\Users\kodoghouse\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe` |

---

### **2. Process Execution – TOR Browser Installation**

| Timestamp           | Event                                    | Action                                       | File Path                                                                      |
| ------------------- | ---------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------ |
| 2025-08-11 19:15:45 | TOR installer executed                   | Silent installation initiated by user        | `C:\Users\kodoghouse\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe` |
| 2025-08-11 19:16:00 | TOR-related license/config files created | Installer wrote default license/config files | `C:\Users\kodoghouse\Desktop\Tor Browser\Browser\TorBrowser\Docs\`             |
| 2025-08-11 19:16:01 | Core TOR executable created              | Installer deployed core executable           | `C:\Users\kodoghouse\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`       |
| 2025-08-11 19:16:08 | TOR Browser shortcut created             | Installer created desktop shortcut           | `C:\Users\kodoghouse\Desktop\Tor Browser.lnk`                                  |

---

### **3. Process Execution – TOR Browser Launch**

| Timestamp           | Event                              | Action                        | File Path                                                     |
| ------------------- | ---------------------------------- | ----------------------------- | ------------------------------------------------------------- |
| 2025-08-11 19:16:12 | TOR Browser launched (firefox.exe) | User initiated browser launch | `C:\Users\kodoghouse\Desktop\Tor Browser\Browser\firefox.exe` |

---

### **4. Network Connection – TOR Network**

| Timestamp           | Event                                           | Action                                 | File Path                                                                |
| ------------------- | ----------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------ |
| 2025-08-11 19:16:48 | SOCKS proxy connection established              | `firefox.exe` connected to local proxy | N/A                                                                      |
| 2025-08-11 19:16:51 | TOR process started                             | `tor.exe` initiated                    | `C:\Users\kodoghouse\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` |
| 2025-08-11 19:16:53 | Connected to TOR entry node (96.20.102.87:9001) | Outbound TOR network connection        | `tor.exe`                                                                |

---

### **5. Additional Network Connections – TOR Browser Activity**

| Timestamp           | Event                                           | Action                 | File Path     |
| ------------------- | ----------------------------------------------- | ---------------------- | ------------- |
| 2025-08-11 19:17:57 | Reconnected to local proxy (127.0.0.1:9150)     | Maintained TOR circuit | `firefox.exe` |
| 2025-08-11 19:18:02 | Connected to TOR relay node (78.138.98.42:9001) | TOR routing            | `tor.exe`     |
| 2025-08-11 19:18:03 | Accessed .onion service                         | Hidden service access  | `tor.exe`     |

---

### **6. File Creation – TOR Shopping List**

| Timestamp           | Event                           | Action                                 | File Path                                                       |
| ------------------- | ------------------------------- | -------------------------------------- | --------------------------------------------------------------- |
| 2025-08-11 19:23:52 | Shopping list shortcut created  | Link file generated in roaming profile | `C:\Users\kodoghouse\AppData\Roaming\tor-shopping-list.txt.lnk` |
| 2025-08-11 19:23:52 | Shopping list text file created | Document saved on desktop              | `C:\Users\kodoghouse\Desktop\tor-shopping-list.txt`             |

---

## Summary

The investigation confirmed that an employee, identified by the account kodoghouse, installed and used the Tor Browser on the workstation jv-win10-disa-s. The user downloaded a portable version of the Tor installer, and ran it using a silent installation command. The presence of tor.exe and firefox.exe and subsequent network connections to known Tor ports (9001 and 9150) provided clear evidence of its usage. The user also accessed an onion service site and created a shortcut to a file named tor-shopping-list.txt. These findings confirm the unauthorized use of Tor on the corporate network. As a response, the device was isolated and the user's direct manager was notified.

---

## Response Taken

TOR usage was confirmed on endpoint jv-win10-disa-s. The device was isolated and the user's direct manager was notified.

---
