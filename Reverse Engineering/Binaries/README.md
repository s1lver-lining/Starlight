Reversing binaries can be used to solve keygen (or crackme) challenges, or just to understand how a program works to [exploit it](../../Binary%20Exploitation/README.md).


* `strace` - [Website](https://strace.io)

	Report library, system calls and signals.

* `ltrace` - [Manual](http://man7.org/linux/man-pages/man1/ltrace.1.html)

* `gdb` :heart: - [Wikipedia](https://en.wikipedia.org/wiki/GNU_Debugger) [CheatSheet](https://raw.githubusercontent.com/zxgio/gdb_gef-cheatsheet/master/gdb_gef-cheatsheet.pdf)

	Most used debugger, can be improved with [GEF](https://hugsy.github.io/gef/) :heart: or [PEDA](https://github.com/longld/peda). Here are the most common commands:


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

* `Ghidra` :heart: - [Website](https://ghidra-sre.org/)

	Decompiler for binary files, useful for **static** analysis.

	Automatically create a ghidra project from a binary file using [this script](./Tools/ghidra.py):
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


* `IDA` :heart: - [Website](https://www.hex-rays.com/products/ida/support/download.shtml)

	Proprietary reverse engineering software, known to have the best disassembler. The free version can only disassemble 64-bit binaries.

* `radare2` - [GitHub](https://github.com/radareorg/radare2)

	Binary analysis, disassembler, debugger. Identified as `r2`.