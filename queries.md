# SPL Queries: BOTS v1 Investigation

Every search I ran during the investigation, in order, with why I ran it and what it showed.

- **Dataset:** Splunk Boss of the SOC v1 (`index=botsv1`)
- **Splunk version:** Splunk Enterprise 10.6 on Ubuntu (WSL2)
- **Time zone:** UTC (set under Administrator → Preferences)
- **Note:** `earliest=0` means "search all time" (the data is from August 2016)

Each query lists: **Why I ran it** · **SPL** · **What it showed** · **Screenshot** (in `screenshots/evidence/`)

---

## 0. Setup and data reconnaissance

### Q1: Confirm the dataset loaded
**Why I ran it:** verify the pre-indexed BOTS v1 app was picked up after extracting it into `$SPLUNK_HOME/etc/apps/`.
```spl
index=botsv1 earliest=0 | stats count by sourcetype
```
**What it showed:** 33,413,777 events across 26 sourcetypes.
**Screenshot:** [`01-data-loaded.png`](screenshots/01-data-loaded.png)

### Q2: Check field extraction per log source
**Why I ran it:** make sure the add-ons were parsing fields before relying on them.
```spl
index=botsv1 earliest=0 sourcetype=stream:http | head 5 | table _time src_ip dest_ip http_method site uri status
index=botsv1 earliest=0 sourcetype=stream:dns | head 5 | table _time src_ip dest_ip query
index=botsv1 earliest=0 sourcetype=suricata event_type=alert | head 5 | table _time src_ip dest_ip alert.signature
```
**What it showed:** web, DNS and IDS fields extracted correctly. Searches for `sourcetype=fgt_utm`, the original Sysmon sourcetype and `WinEventLog:Security` returned **0 events**.

### Q3: Troubleshoot missing sourcetypes
**Why I ran it:** after installing modern add-ons, some sourcetype searches returned nothing. `tstats` reads index metadata, so it shows the original index-time names.
```spl
| tstats count where index=botsv1 by sourcetype source
```
**What it showed:** the data was there. The add-ons **rename sourcetypes at search time** (`fgt_traffic` → `fortigate_traffic`, Sysmon → `XmlWinEventLog`, `WinEventLog:Security` → `WinEventLog`). The Sysmon source is `WinEventLog:Microsoft-Windows-Sysmon/Operational`. Fix: search by `source=` instead.
**Screenshot:** [`e01-tstats-sourcetypes.png`](screenshots/evidence/e01-tstats-sourcetypes.png)

### Q4: Re-test with the correct names
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | head 5 | table _time sourcetype host EventCode Image CommandLine ParentImage
index=botsv1 earliest=0 source="udp:514" | head 5 | table _time sourcetype srcip dstip action
```
**What it showed:** Sysmon and FortiGate fields extract correctly. Empty CommandLine on EventCode 3 is expected (network events carry no command line).

### Q5: Host inventory
**Why I ran it:** identify every machine and its likely role before hunting.
```spl
| tstats count where index=botsv1 by host | sort -count
```
**What it showed:** 192.168.250.1 (firewall), splunk-02 (Stream sensor), suricata-ids (IDS), **we8105desk** (the only workstation), and many `we####srv` servers.
**Screenshot:** [`e02-host-inventory.png`](screenshots/evidence/e02-host-inventory.png)

### Q6: Top web traffic sources
**Why I ran it:** find who generates the most HTTP traffic.
```spl
index=botsv1 earliest=0 sourcetype=stream:http | stats count by src_ip | sort -count | head 20
```
**What it showed:** two public IPs stand out: **40.80.148.42 (20,997 requests)** and **23.22.63.114 (1,430)**. Everything else is internal or under 1,000.
**Screenshot:** [`e03-top-http-sources.png`](screenshots/evidence/e03-top-http-sources.png)

---

## 1. Scenario 1: Web defacement

### 1.1 Reconnaissance / scanning

### Q7: What were the suspicious IPs targeting?
**Why I ran it:** link the two external IPs to an internal target and website.
```spl
index=botsv1 earliest=0 sourcetype=stream:http (src_ip=40.80.148.42 OR src_ip=23.22.63.114) | stats count by src_ip dest_ip site
```
**What it showed:** target site **imreallynotbatman.com** on **192.168.250.70**. 40.80.148.42 sent attack payloads in the Host header (SQL injection, command injection, template injection), including `acunetix_wvs_security_test`.
**Screenshot:** [`e04-scanner-payloads.png`](screenshots/evidence/e04-scanner-payloads.png)

### Q8: Confirm the scanner with the IDS (second log source)
**Why I ran it:** confirm the scanner from an independent source.
```spl
index=botsv1 earliest=0 sourcetype=suricata event_type=alert src_ip=40.80.148.42 | stats count by alert.signature | sort -count
```
**What it showed:** 538 alerts, including **"ET SCAN Acunetix Version 6 (Free Edition) Scan Detected"** (45), XSS, SQLi, XXE and Shellshock (CVE-2014-6271) attempts.
**Screenshot:** [`e05-suricata-acunetix.png`](screenshots/evidence/e05-suricata-acunetix.png)

### 1.2 Brute force against the admin login

### Q9: What was 23.22.63.114 doing?
**Why I ran it:** it behaved differently from the scanner.
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=23.22.63.114 | stats count by http_method uri | sort -count
```
**What it showed:** the site runs **Joomla**. 412 POSTs to `/joomla/administrator/index.php` (login brute force), plus 194 GETs to `/joomla/agent.php`.
**Screenshot:** [`e06-bruteforce-uris.png`](screenshots/evidence/e06-bruteforce-uris.png)

### Q10: Extract the attempted credentials
**Why I ran it:** see which passwords were tried and whether one worked. `rex` replaces the URL Toolbox add-on, which is not compatible with Splunk 10.
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST uri="/joomla/administrator/index.php"
| rex field=form_data "username=(?<username>[^&]+)"
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count values(src_ip) as src_ips by username password
| sort -count
```
**What it showed:** 412 unique passwords for `admin`. Only **`batman`** was used twice, by **both** 23.22.63.114 and 40.80.148.42, which links the two IPs to one attacker.
**Screenshot:** [`02-bruteforce-batman.png`](screenshots/02-bruteforce-batman.png)

### Q11: Attack start and end times
**Why I ran it:** build the timeline.
```spl
index=botsv1 earliest=0 sourcetype=stream:http (src_ip=40.80.148.42 OR src_ip=23.22.63.114)
| stats min(_time) as first_seen max(_time) as last_seen count by src_ip
| convert ctime(first_seen) ctime(last_seen)
```
**What it showed:** scan 21:36:45 – 22:22:27; brute force 21:45:09 – 22:21:34 (UTC).
**Screenshot:** [`e07-first-last-seen.png`](screenshots/evidence/e07-first-last-seen.png)

### 1.3 Successful login and file upload

### Q12: The successful login
**Why I ran it:** find when and how `batman` was used.
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST uri="/joomla/administrator/index.php" form_data="*passwd=batman*"
| table _time src_ip http_user_agent
```
**What it showed:** 21:46:33 from 23.22.63.114 using `Python-urllib/2.7` (the script found it); 21:48:05 from 40.80.148.42 using **Internet Explorer 11** (a human logged in).
**Screenshot:** [`e08-login-user-agents.png`](screenshots/evidence/e08-login-user-agents.png)

### Q13: Uploaded files
**Why I ran it:** check what the attacker uploaded after logging in. The first version failed in `stats` because of the `{}` in the field name; `rename` fixed it.
```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST part_filename{}=*
| rename "part_filename{}" as filename
| table _time src_ip uri filename
```
**What it showed:** **`3791.exe`** and **`agent.php`** uploaded at 21:52:47.
**Screenshot:** [`e09-uploaded-files.png`](screenshots/evidence/e09-uploaded-files.png)

### Q14: Did 3791.exe run? Get its hash.
**Why I ran it:** an uploaded file only matters if it executed.
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 "3791.exe"
| table _time host Image ParentImage CommandLine Hashes
```
**What it showed:** on **we1149srv**, `php-cgi.exe` → `cmd.exe /c "3791.exe"` → `3791.exe` at 21:56:18. It then spawned `cmd.exe` at 21:58:23 and 22:08:13 (remote shell). MD5 `AAE3F5A29935E6ABCC2C2754D12A9AF0`. Only the 3791.exe hash is an IOC; cmd.exe and conhost.exe are legitimate Windows binaries.
**Screenshot:** [`e10-3791-process-chain.png`](screenshots/evidence/e10-3791-process-chain.png)

**VirusTotal:** 63/68, `trojan.swrort/cryptz`, Microsoft: `Trojan:Win32/Meterpreter.O`, a trojanized ApacheBench (`ab.exe`), consistent with an msfvenom-built payload.
**Screenshots:** [`e11-vt-3791.png`](screenshots/evidence/e11-vt-3791.png), [`e12a-vt-ip-40-80-148-42.png`](screenshots/evidence/e12a-vt-ip-40-80-148-42.png) (1/92, Microsoft), [`e12b-vt-ip-23-22-63-114.png`](screenshots/evidence/e12b-vt-ip-23-22-63-114.png) (0/92, Amazon)

### Q15: Where did the backdoor connect?
**Why I ran it:** find the C2 server.
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 Image="*3791.exe"
| table _time DestinationIp DestinationPort
```
**What it showed:** **23.22.63.114:3791** at 21:56:19, one second after execution.
**Screenshot:** [`e13-c2-connection.png`](screenshots/evidence/e13-c2-connection.png)

### 1.4 Defacement

### Q16: Outbound requests from the web server
**Why I ran it:** a defacement usually means the server fetched attacker content, so I flipped the direction and looked at where the web server itself connected.
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=192.168.250.70 | stats count by dest_ip site uri | sort -count
```
**What it showed:** `update.joomla.org` is normal update checking (ruled out). **`prankglassinebracket.jumpingcrab.com:1337/poisonivy-is-coming-for-you-batman.jpeg`** served from 23.22.63.114.

### Q17: Time of the defacement
```spl
index=botsv1 earliest=0 sourcetype=stream:http src_ip=192.168.250.70 site="prankglassinebracket*"
| table _time src_ip dest_ip site uri
```
**What it showed:** downloaded at 22:06:21 and again at 22:13:46.
**Screenshot:** [`03-defacement-download.png`](screenshots/03-defacement-download.png)

### 1.5 Cross-source confirmation

### Q18: Search the IOC across every log source
**Why I ran it:** see how far one IOC reaches and confirm it from independent sources.
```spl
index=botsv1 earliest=0 "prankglassinebracket.jumpingcrab.com" | stats count by sourcetype
```
**What it showed:** 20 events across 6 sourcetypes: suricata (7), stream:dns (3), stream:http (3), fortigate_utm (3), WinEventLog (2), XmlWinEventLog (2). VirusTotal: 3/92.
**Screenshots:** [`e14-ioc-across-sources.png`](screenshots/evidence/e14-ioc-across-sources.png), [`e15-vt-defacement-domain.png`](screenshots/evidence/e15-vt-defacement-domain.png)

---

## 2. Scenario 2: Ransomware

### 2.1 Identifying the infected host

### Q19: Ransomware alerts from the IDS
**Why I ran it:** start from what the IDS flagged as Cerber.
```spl
index=botsv1 earliest=0 sourcetype=suricata event_type=alert alert.signature="*Cerber*"
| stats count min(_time) as first_seen by src_ip dest_ip alert.signature
| convert ctime(first_seen)
```
**What it showed:** 192.168.250.100 sent a **Cerber check-in** to 85.93.0.0 at 16:49:24 and an **onion domain lookup** to 192.168.250.20 at 17:15:12.
**Screenshot:** [`e16-suricata-cerber.png`](screenshots/evidence/e16-suricata-cerber.png)

### Q20: Hostname of 192.168.250.100
**Why I ran it:** a report needs hostnames, not just IPs. My first attempt (without sorting) listed 1,758 hosts, because servers that **receive** connections from .100 also log `SourceIp=192.168.250.100`. Sorting by count shows the machine itself.
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" SourceIp=192.168.250.100
| stats count by host | sort -count | head 5
```
**What it showed:** **we8105desk** (53,106 events), the workstation I had noted during reconnaissance.
**Screenshot:** [`e17-infected-host.png`](screenshots/evidence/e17-infected-host.png)

### Q21: Logged-in user
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk
| stats count by User | sort -count
```
**What it showed:** **WAYNECORPINC\bob.smith** (other accounts are Windows system accounts).
**Screenshot:** [`e18-infected-user.png`](screenshots/evidence/e18-infected-user.png)

### 2.2 Initial access

### Q22: Processes before the first check-in
**Why I ran it:** the first check-in was 16:49:24, so whatever started the infection ran shortly before.
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 earliest="08/24/2016:16:30:00" latest="08/24/2016:16:50:00"
| table _time ParentImage Image CommandLine | sort _time
```
**What it showed:** 85 events, mostly **authorised Nessus scanning** (WMI-launched netstat, tasklist, netsh writing `nessus_*.TMP`). Benign.

### Q23: Filter out known-good
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 earliest="08/24/2016:16:30:00" latest="08/24/2016:16:50:00"
NOT ParentImage="*WmiPrvSE.exe" NOT CommandLine="*nessus*" NOT Image="*conhost.exe" NOT Image="*SearchFilterHost.exe" NOT Image="*SearchProtocolHost.exe"
| table _time ParentImage Image CommandLine | sort _time
```
**What it showed:** at 16:43:12, `explorer.exe` → `WINWORD.EXE /n /f "D:\Miranda_Tate_unveiled.dotm"`. A macro-enabled template opened by the user from **D:\ (removable drive)**.
**Screenshot:** [`e19-winword-dotm.png`](screenshots/evidence/e19-winword-dotm.png)

### 2.3 Execution / process chain

### Q24: What did Word launch?
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 ParentImage="*WINWORD.EXE"
| table _time ParentImage Image CommandLine | sort _time
```
**What it showed:** at 16:43:21 Word launched `cmd.exe`, which wrote an **obfuscated VBScript** to `%APPDATA%\%RANDOM%.vbs` line by line and started it. The script uses encoded strings, mixed case, junk arithmetic and sleep loops, and downloads, XOR-decodes and runs a payload. (`splwow64.exe` is a normal Word print helper.)
**Screenshot:** [`e20-macro-cmd-vbs.png`](screenshots/evidence/e20-macro-cmd-vbs.png)

### Q25: Follow the chain
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 earliest="08/24/2016:16:43:00" latest="08/24/2016:17:30:00"
(Image="*wscript.exe" OR ParentImage="*wscript.exe" OR Image="*AppData*" OR ParentImage="*AppData*")
| table _time ParentImage Image CommandLine | sort _time
```
**What it showed:** `wscript 20429.vbs` → `121214.tmp` (16:48:21) → copied to `{35ACA89F...}\osk.exe` and the original deleted → `osk.exe` launches explorer.exe → **shadow copies deleted** (wmic, vssadmin) and **recovery disabled** (bcdedit) at 16:49:23–24 → **ransom note** opened 17:15:11 → **self-delete** 17:15:29.
**Screenshot:** [`04-ransomware-process-chain.png`](screenshots/04-ransomware-process-chain.png)

### 2.4 Download, C2 and DNS

### Q26: What did the script download?
```spl
index=botsv1 sourcetype=stream:http src_ip=192.168.250.100 earliest="08/24/2016:16:43:00" latest="08/24/2016:16:50:00"
| table _time dest_ip site uri http_method
```
**What it showed:** `/mhtr.jpg` from **solidaritedeproximite.org** (37.187.37.150) at 16:48:13, fallback from 92.222.104.182, then `ipinfo.io/json` at 16:49:24 (external IP lookup).
**Screenshot:** [`05-payload-download.png`](screenshots/05-payload-download.png)

### Q27: Ransomware hashes
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=1 Image="*osk.exe"
| rex field=Hashes "SHA256=(?<sha256>[A-F0-9]{64})"
| rex field=Hashes "MD5=(?<md5>[A-F0-9]{32})"
| stats values(md5) values(sha256)
```
**What it showed:** `121214.tmp` and `osk.exe` share one hash (same file). MD5 `EE0828A4E4C195D97313BFC7D4B531F1`, SHA256 `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`. VirusTotal: **55/71, `trojan.cerber/fimal`**, seen as `chkdsk.exe`, tagged self-delete / long-sleeps / persistence. Payload domain: 0/92 (likely compromised legitimate site).
**Screenshots:** [`e22-ransomware-hashes.png`](screenshots/evidence/e22-ransomware-hashes.png), [`e23-vt-cerber.png`](screenshots/evidence/e23-vt-cerber.png), [`e24-vt-payload-domain.png`](screenshots/evidence/e24-vt-payload-domain.png)

### 2.5 Encryption and lateral impact

### Q28: Did it spread to 192.168.250.20?
**Why I ran it:** the onion lookup went to this internal host, so I checked its traffic from the infected PC during the encryption window.
```spl
index=botsv1 earliest="08/24/2016:16:49:00" latest="08/24/2016:17:16:00" src_ip=192.168.250.100 dest_ip=192.168.250.20
| stats count by sourcetype dest_port
```
**What it showed:** **38,398 SMB events on port 445** in 27 minutes, consistent with mass file encryption on a network share. Also DNS (53) and LDAP (389), so the host is likely a domain controller / file server.
**Screenshot:** [`e21-smb-spread.png`](screenshots/evidence/e21-smb-spread.png)

### Q29: File server hostname
```spl
index=botsv1 earliest=0 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" host=we8105desk EventCode=3 DestinationIp=192.168.250.20
| stats count by DestinationHostname
```
**What it showed:** **we9041srv**.
**Screenshot:** [`e25-file-server-hostname.png`](screenshots/evidence/e25-file-server-hostname.png)

### Q30: Files accessed on the share
```spl
index=botsv1 earliest="08/24/2016:16:49:00" latest="08/24/2016:17:16:00" source="WinEventLog:Security" EventCode=5145 Source_Address=192.168.250.100
| stats dc(Relative_Target_Name) as unique_files count by host
```
**What it showed:** **5,193 unique files** (16,869 accesses) on we9041srv. Other hosts with 1 access each are normal background noise.
**Screenshot:** [`e26-files-accessed-5145.png`](screenshots/evidence/e26-files-accessed-5145.png)

### Q31: Which files were encrypted?
```spl
index=botsv1 earliest="08/24/2016:16:49:00" latest="08/24/2016:17:16:00" source="WinEventLog:Security" EventCode=5145 Source_Address=192.168.250.100 host=we9041srv
| rex field=Relative_Target_Name "\.(?<ext>[A-Za-z0-9]+)$"
| stats dc(Relative_Target_Name) as files by ext | sort -files
```
**What it showed:** **970 files with the `.cerber` extension** (encrypted). html/txt/url/vbs each ~641: the four ransom-note formats dropped into **641 folders**. The rest (pdf, doc, xls, ppt, jpg…) are the original documents read before encryption.
**Screenshot:** [`06-encrypted-files.png`](screenshots/06-encrypted-files.png)

---

## 3. Dead ends and lessons

- **Sourcetype searches returned 0 events** after installing modern add-ons. Cause: search-time sourcetype renaming. Fixed with `tstats` and `source=` (Q3).
- **`stats ... by part_filename{}` returned no rows** even though an event matched. Cause: `{}` in the field name. Fixed with `rename` (Q13).
- **Hostname lookup returned 1,758 hosts.** Cause: `SourceIp` also appears in logs from machines receiving connections. Fixed by sorting by count (Q20).
- **Times initially showed 2016-08-11.** Cause: Splunk displayed my local time zone (UTC+7). Switched to UTC before building timelines.

---

## 4. Detection ideas (searches that could become alerts)

### D1: Brute force against CMS admin logins
```spl
index=botsv1 sourcetype=stream:http http_method=POST uri="*/administrator/index.php"
| bin _time span=5m
| stats count by _time src_ip
| where count > 20
```
**Suggested schedule:** every 5 minutes; alert on any result.

### D2: Web server process spawning a shell
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(ParentImage="*php-cgi.exe" OR ParentImage="*w3wp.exe" OR ParentImage="*httpd.exe")
(Image="*cmd.exe" OR Image="*powershell.exe")
| table _time host ParentImage Image CommandLine
```
**Suggested schedule:** real-time or every 5 minutes; high severity.

### D3: Office application spawning a script engine
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*POWERPNT.EXE")
(Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*powershell.exe")
| table _time host User ParentImage Image CommandLine
```
**Suggested schedule:** real-time; high severity.

### D4: Shadow copy deletion / recovery disabled
```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*delete shadows*" OR CommandLine="*shadowcopy delete*" OR CommandLine="*recoveryenabled no*")
| table _time host User ParentImage Image CommandLine
```
**Suggested schedule:** real-time; critical (strong ransomware indicator).

### D5: Mass file access on a share
```spl
index=botsv1 source="WinEventLog:Security" EventCode=5145
| bin _time span=5m
| stats dc(Relative_Target_Name) as unique_files by _time Source_Address host
| where unique_files > 200
```
**Suggested schedule:** every 5 minutes; tune the threshold to normal activity.
