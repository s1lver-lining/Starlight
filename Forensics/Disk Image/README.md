## Tools

* `Autopsy` :heart: - [Website](https://www.autopsy.com/download/)

    GUI for analyzing disk images with Sleuthkit. It can be used to extract files, search for keywords, etc...

* `mount`

    Mount a disk image to a filesystem.
    
    I recommend to use a virtual machine to mount the disk image. This way you can browse the filesystem and extract files without risking to damage your system.

* `TestDisk` - [Website](https://www.cgsecurity.org/Download_and_donate.php/testdisk-7.1-WIP.linux26.tar.bz2) 
	
    CLI tool to recover lost partitions and/or make non-booting disks bootable again.

* `photorec` - [Website](https://www.cgsecurity.org/wiki/PhotoRec) 
	
    CLI tool to recover deleted files. Works with raw data, so the disk do not need to have a partition system working.

## Techniques

* Extract windows hashes from filesystem (SAM file).

    This can be done with `samdump2`. See this [GitHub repository](https://github.com/noraj/the-hacking-trove/blob/master/docs/Tools/extract_windows_hashes.md) for more information.


## Data formats

* `WIM` : Windows Imaging Format - [Wikipedia](https://en.wikipedia.org/wiki/Windows_Imaging_Format)

    WIM is a file format used for windows disk images. Data can be extracted on linux using `wimlib`.

	```bash
	wiminfo <file.wim> # List all images in the wim file
	wimapply <file.wim> <image_index> <output_directory> # Extract an image from the wim file
	``` 


