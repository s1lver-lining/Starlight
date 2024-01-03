This section present some tools to analyse networks and network traffic. The `Services and Ports` section and the `Pentest` section can also be useful for network related tasks.

* `Wireshark` :heart: - [Website](https://www.wireshark.org/)
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
	

