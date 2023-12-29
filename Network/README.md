
* `Wireshark` :heart: - [Website](https://www.wireshark.org/)
	The go-to tool for examining [`.pcap`](https://en.wikipedia.org/wiki/Pcap) files.


* `PCAPNG` - [GitHub](https://github.com/pcapng/pcapng) 
	Not all tools like the [PCAPNG](https://github.com/pcapng/pcapng) file format... so you can convert them with an online tool [http://pcapng.com/](http://pcapng.com/) or from the command-line with the `editcap` command that comes with installing [Wireshark]:

	```
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
	

