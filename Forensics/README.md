
* `File scanning`

	Use [this section](../Files/File%20Scanning/README.md) to find information about files.

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