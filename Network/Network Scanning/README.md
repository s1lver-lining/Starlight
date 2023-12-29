* `Private IPs`

    Some ip ranges are reserved for private networks. They are not routable on the internet. They are:

    | Network | Range | Count |
    | --- | --- | --- |
    | `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | 16,777,214 |
    | `172.16.0.0/16` | `172.16.0.0` - `172.31.255.255` | 1,048,574 |
    | `192.168.0.0/16` | `192.168.0.0` - `192.168.255.255` | 65,534 |


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

* `traceroute` - [Wikipedia](https://en.wikipedia.org/wiki/Traceroute)

    See the machines that a packet goes through to reach its destination.

* `netdiscover`

    `netdiscover` is a utility for network discovery.

    ```bash
    # Passive scan
    netdiscover -p
    ```