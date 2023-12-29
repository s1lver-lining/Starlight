* `sudo`

    First thing to check. See what the current user is allowed to do.
    ```bash
    sudo -l # List available commands
    ```


* `PEAS` :heart: - [GitHub](https://github\.com/carlospolop/PEASS-ng)

    Find common misconfigurations and vulnerabilities in Linux and Windows.

    Some payload can be found in the [Tools](./Tools/PEAS/) section.

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

    Some payload can be found in the [Tools](./Tools/CVE-2021-3156/) section.

