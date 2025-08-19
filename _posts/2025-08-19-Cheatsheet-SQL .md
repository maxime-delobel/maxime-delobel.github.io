---
layout: post
title: "Cheatsheet-SQL"
description: Cheatsheet of basic SQL queries.
---

<p>These cheatsheets serve as my personal quick reference. Therefore, they’re less organized than the box walkthroughs, but I’ve shared them in case others find them useful.</p>

<h2>General MYSQL command line</h2>

<h3>login command</h3>
<pre>
mysql -u &lt;username&gt; -p -h &lt;remote_host&gt; -P &lt;port&gt;
</pre>

<h3>List databases and switch to database</h3>
<pre>
show databases;use &lt;database_name&gt;
</pre>

<h3>List fields of database</h3>
<pre>
describe &lt;database_name&gt;
</pre>

<h3>INSERT statement</h3>
<pre>
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
</pre>

<h3>DROP statement</h3>
<pre>
DROP TABLE &lt;table_name&gt;;
</pre>

<h3>ALTER statement</h3>
<pre>
ALTER TABLE &lt;table_name&gt; ADD newColumn &lt;datatype&gt;;
</pre>

<h3>UPDATE statement</h3>
<pre>
UPDATE &lt;table_name&gt; SET column1=newvalue1, column2=newvalue2, ... WHERE &lt;condition&gt;;
</pre>


