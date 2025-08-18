---
layout: post
title: "HTB-Planning"
description: Walkthrough writeup of HTB-Planning
---

<p>In Code, we  exploited a Python sandbox to execute code, got a reverse shell, dumped SSH creds from the database, and bypassed a backup filter to grab root.</p>

<h2>Introduction</h2>

<p>In this post, I will demonstrate the exploitation of an easy machine called "Cap" on hack the box. Overall, it was quite a hard box for me as I have little experience with python. It was a good learning experience.</p>

<h2> Step 1: running an Nmap scan on the target</h2>
