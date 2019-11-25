---
title: Vulnserver
layout: home
permalink: /vulnserver/
collection: vulnserver
sidebar:
  nav: "main"
entries_layout: grid
classes: wide
---

Vulnserver is a multithreaded Windows based TCP server that listens for client connections on port 9999 (by default) and allows the user to run a number of different commands that are vulnerable to various types of exploitable buffer overflows.

The software is developed by Stephen Bradshaw and is intended mainly as a tool for learning how to find and exploit buffer overflow bugs, and each of the bugs it contains is subtly different from the others, requiring a slightly different approach to be taken when writing the exploit.

Though it does make an attempt to mimic a (simple) legitimate server program this software has no functional use beyond that of acting as an exploit target, and this software should not generally be run by anyone who is not using it as a learning tool.

More information on Vulnserver can be found at the following GitHub page.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Vulnserver GitHub](https://github.com/stephenbradshaw/vulnserver)

The following write ups were performed while testing Vulnserver in the following test environment.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Hypervisor: VMware Workstation 15 Pro  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Attack Machine: Kali Linux 2019 (32-bit)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Victim Machine: Windows 7 SP1 (32-bit)  


The following write-ups assume that the reader is familiar with application fuzzing using the SPIKE platform.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[SPIKE Presentation](https://www.blackhat.com/presentations/bh-usa-02/bh-us-02-aitel-spike.ppt)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[SPIKE Basics](https://resources.infosecinstitute.com/intro-to-fuzzing/)  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[SPIKE Automation](https://resources.infosecinstitute.com/fuzzer-automation-with-spike/)
