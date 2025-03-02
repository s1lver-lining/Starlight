File scanning is the process of analyzing a, potentially large, file to find information about it. This can be useful to find hidden data, or to simply find the data type and structure of a file.

## Tools

* `file`

    Deduce the file type from the headers.

* `binwalk` :heart:

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

## File signatures

* `file signatures` - [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

    File signatures are bytes at the beginning of a file that identify the file type. This header is also called magic numbers.

    Most files can be [found here](https://en.wikipedia.org/wiki/List_of_file_signatures), but the most common ones are :

    | Hex signature | File type | Description |
    | --- | --- | --- |
    | `FF D8 FF` (???) | JPEG | [JPEG](https://en.wikipedia.org/wiki/JPEG) image |
    | `89 50 4E 47 0D 0A 1A 0A` (?PNG) | PNG | [PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) image |
    | `50 4B` (PK) | ZIP | [ZIP](https://en.wikipedia.org/wiki/Zip_(file_format)) archive |

    For exemple, the first 16 bytes of PNG are usually b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'

    This data can be outputed to a file with 
    ```bash
    echo -n -e "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" > png.sig
    ```