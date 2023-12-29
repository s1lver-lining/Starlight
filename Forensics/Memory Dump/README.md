Memory dumps are captures of the state of the memory at a given time. It contains all the loaded files, processes and data that was used at this moment.

Memory dumps can be analyzed using the [Volatility Framework](https://www.volatilityfoundation.org/) :heart: .

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



* `bulk_extractor` - [GitHub](https://github.com/simsong/bulk_extractor)

    Find some information in a large binary dump.
    
    ```bash
    mkdir out_bulk
    bulk_extractor ./dump.bin -o ./out_bulk
    ```

* Browser profile

    It is often a good idea to look at the browser profile to find interesting information, such as bookmarks, history, cookies, stored passwords, etc... 
    
    See [Browser Forensics](../Browser%20Forensics/README.md) for more information.



