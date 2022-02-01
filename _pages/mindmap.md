---
title: "OSCP Mindmap"
permalink: /mindmap/
date: 2022-01-31
---

WIP

<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="ie=edge">
<title>Markmap</title>
<style>
* {
  margin: 0;
  padding: 0;
}
#mindmap {
  display: block;
  width: 100vw;
  height: 100vh;
}
</style>

</head>
<body>
<svg id="mindmap"></svg>
<script src="https://cdn.jsdelivr.net/npm/d3@6.7.0"></script><script src="https://cdn.jsdelivr.net/npm/markmap-view@0.2.7"></script><script>((c,d,p)=>{const{Markmap:g}=c();window.mm=g.create("svg#mindmap",d==null?void 0:d(),p)})(()=>window.markmap,c=>(c=c||window.d3,{color:(N=>E=>N(E.p.i))(c.scaleOrdinal(c.schemeCategory10))}),{"t":"root","d":0,"v":"","c":[{"t":"heading","d":1,"p":{"lines":[0,1]},"v":"Meta Ideas","c":[{"t":"list_item","d":3,"p":{"lines":[1,2]},"v":"Reset box"},{"t":"list_item","d":3,"p":{"lines":[2,3]},"v":"google","c":[{"t":"list_item","d":5,"p":{"lines":[3,4]},"v":"errors"},{"t":"list_item","d":5,"p":{"lines":[4,5]},"v":"any urls"},{"t":"list_item","d":5,"p":{"lines":[5,6]},"v":"every version"},{"t":"list_item","d":5,"p":{"lines":[6,7]},"v":"every parameter"}]},{"t":"list_item","d":3,"p":{"lines":[7,8]},"v":"take a break!"}]},{"t":"heading","d":1,"p":{"lines":[9,10]},"v":"Recon"},{"t":"heading","d":1,"p":{"lines":[11,12]},"v":"Services"},{"t":"heading","d":1,"p":{"lines":[13,14]},"v":"SMB"},{"t":"heading","d":1,"p":{"lines":[16,17]},"v":"Password cracking","c":[{"t":"list_item","d":3,"p":{"lines":[17,18]},"v":"hashtype identification","c":[{"t":"list_item","d":5,"p":{"lines":[18,19]},"v":"links"}]},{"t":"list_item","d":3,"p":{"lines":[19,20]},"v":"john"},{"t":"list_item","d":3,"p":{"lines":[20,21]},"v":"hashcat"}]},{"t":"heading","d":1,"p":{"lines":[22,23]},"v":"Web","c":[{"t":"list_item","d":3,"p":{"lines":[23,24]},"v":"nikto","c":[{"t":"list_item","d":5,"p":{"lines":[24,25]},"v":"<code>nikto -h http://$target-hostname:80</code>"}]},{"t":"list_item","d":3,"p":{"lines":[25,26]},"v":"directory brute force","c":[{"t":"list_item","d":5,"p":{"lines":[26,27]},"v":"feroxbuster","c":[{"t":"list_item","d":7,"p":{"lines":[27,28]},"v":"<code>feroxbuster -u http://$target-hostname/ -x txt php js</code>"},{"t":"list_item","d":7,"p":{"lines":[28,29]},"v":"no hits?","c":[{"t":"list_item","d":9,"p":{"lines":[29,30]},"v":"try bigger wordlists"},{"t":"list_item","d":9,"p":{"lines":[30,31]},"v":"specific wordlists (i.e. iis servers)"},{"t":"list_item","d":9,"p":{"lines":[31,32]},"v":"do the directories have a pattern?"},{"t":"list_item","d":9,"p":{"lines":[32,33]},"v":"expand scope of <code>-x</code> file extension parameter"}]}]}]},{"t":"list_item","d":3,"p":{"lines":[33,34]},"v":"subdomain brute force","c":[{"t":"list_item","d":5,"p":{"lines":[34,35]},"v":"ffuf","c":[{"t":"list_item","d":7,"p":{"lines":[35,36]},"v":"<code>ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://$target-ip-H &quot;Host: FUZZ.$target-hostname&quot;</code>"},{"t":"list_item","d":7,"p":{"lines":[36,37]},"v":"<code>-fc</code> to filter HTTP status codes from response. i.e. <code>-fc 200</code>"},{"t":"list_item","d":7,"p":{"lines":[37,38]},"v":"<code>-fs</code> to filter HTTP response sie. i.e. <code>-fc 4242</code>"}]}]},{"t":"list_item","d":3,"p":{"lines":[38,39]},"v":"login page","c":[{"t":"list_item","d":5,"p":{"lines":[39,40]},"v":"brute force","c":[{"t":"list_item","d":7,"p":{"lines":[40,41]},"v":"<a href=\"https://book.hacktricks.xyz/brute-force#http-basic-auth\">HTTP basic auth</a>"},{"t":"list_item","d":7,"p":{"lines":[41,42]},"v":"<a href=\"https://book.hacktricks.xyz/brute-force#http-post-form\">POST auth</a>"},{"t":"list_item","d":7,"p":{"lines":[42,43]},"v":"ffuf brute forcing","c":[{"t":"list_item","d":9,"p":{"lines":[43,44]},"v":"Burp suite intercept -&gt; save request -&gt; update pass to FUZZ"},{"t":"list_item","d":9,"p":{"lines":[44,45]},"v":"<code>ffuf -request saved-request.txt -w /opt/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt</code>"}]}]},{"t":"list_item","d":5,"p":{"lines":[45,46]},"v":"<a href=\"https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/\">sql injection bypass</a>"}]},{"t":"list_item","d":3,"p":{"lines":[46,47]},"v":"php fields?","c":[{"t":"list_item","d":5,"p":{"lines":[47,48]},"v":"sql injection? try to crash with ' &quot; and other commons","c":[{"t":"list_item","d":7,"p":{"lines":[48,49]},"v":"union based"},{"t":"list_item","d":7,"p":{"lines":[49,50]},"v":"login bypass"}]}]},{"t":"list_item","d":3,"p":{"lines":[50,51]},"v":"burpsuite","c":[{"t":"list_item","d":5,"p":{"lines":[51,52]},"v":"request tampering?"},{"t":"list_item","d":5,"p":{"lines":[52,53]},"v":"intercept"},{"t":"list_item","d":5,"p":{"lines":[53,54]},"v":"30X redirect attacks"}]},{"t":"list_item","d":3,"p":{"lines":[54,55]},"v":"tech stack (list more info like login page, default creds, hacktricks)","c":[{"t":"list_item","d":5,"p":{"lines":[55,56]},"v":"servers","c":[{"t":"list_item","d":7,"p":{"lines":[56,57]},"v":"nginx"},{"t":"list_item","d":7,"p":{"lines":[57,58]},"v":"tomcat"},{"t":"list_item","d":7,"p":{"lines":[58,59]},"v":"apache"}]},{"t":"list_item","d":5,"p":{"lines":[59,60]},"v":"software","c":[{"t":"list_item","d":7,"p":{"lines":[60,61]},"v":"drupal","c":[{"t":"list_item","d":9,"p":{"lines":[61,62]},"v":"drupalgeddon"}]},{"t":"list_item","d":7,"p":{"lines":[62,63]},"v":"wordpress","c":[{"t":"list_item","d":9,"p":{"lines":[63,64]},"v":"wpscan"}]}]}]},{"t":"list_item","d":3,"p":{"lines":[65,66]},"v":"iis","c":[{"t":"list_item","d":5,"p":{"lines":[66,67]},"v":"<a href=\"https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services\">HackTricks Pentesting IIS</a>"}]}]},{"t":"heading","d":1,"p":{"lines":[68,69]},"v":"Windows Privesc"},{"t":"heading","d":1,"p":{"lines":[71,72]},"v":"Linux Privesc"}],"p":{}})</script>
</body>
</html>
