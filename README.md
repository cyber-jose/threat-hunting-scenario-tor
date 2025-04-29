<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cyber-jose/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-21T15:41:23.5029969Z`. These events began at `2025-04-21T15:28:13.3682112Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jj-vm-to-mde"
| where InitiatingProcessAccountName == "vvvjlab"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/6346deaf-ed43-4928-b474-262cde6f65a3)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.exe". Based on the logs returned, at `2025-04-21T15:30:50.0863834Z`, an employee on the "jj-vm-to-mde" device ran the file `tor-browser-windows-x86_64-portable-14.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "jj-vm-to-mde"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/5a17ca3e-486a-4bd6-8471-d575abdc7b32)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-04-21T15:32:06.8923123Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jj-vm-to-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/012ae1f6-1ff9-406d-be25-381e9abdfef3)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-21T15:33:33.1356727Z`, an employee on the "jj-vm-to-mde" device successfully established a connection to the remote IP address `77.174.62.158` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\vvvjlab\desktop\tor browser\browser\torbrowser\tor\tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jj-vm-to-mde"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessParentFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/87bacaeb-ee14-4b6e-b42c-1bd0f6ba4536)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-21T15:28:13.3682112Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\vvvjlab\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-21T15:30:50.0863834Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.exe  /S`
- **File Path:** `C:\Users\vvvjlab\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-21T15:32:06.8923123Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\vvvjlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-21T15:33:33.1356727Z`
- **Event:** A network connection to IP `77.174.62.158` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\vvvjlab\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-21T15:41:23.350011Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\vvvjlab\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "jj-vm-to-mde" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jj-vm-to-mde` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
