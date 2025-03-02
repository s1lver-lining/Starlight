* `zip2john` :heart:

    Brute force password protected zip files.

    ``` bash
    zip2john protected.zip > protected.john
    john --wordlist=/usr/share/wordlists/rockyou.txt protected.john
    ```

* `bkcrack` - [GitHub](https://github.com/kimci86/bkcrack)

    Crack ZipCrypto Store files. Need some plaintext (~9bytes) to work.

    Usage:
    ``` bash
    bkcrack -L encrypted.zip # List all files in the zip
    bkcrack -C encrypted.zip -c zipped_file.png -p plain.png # Crack the zip when "store" method is used
    bkcrcak -C encrypted.zip -c zipped_file.png -k key -D out.zip # Decipher the zip with the key
    ```

    See [File signatures](../File%20Scanning/README.md) to generate the first 9 bytes of the file.  
    You can use `echo -n -e "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" > plain.png` to generate the signature of a PNG file.


* `Reading the specifications`

	Reading the specification of image format are sometimes the only way to fix a corrupted ZIP. A summary of this specification can be found on [GitHub](https://github.com/corkami/formats/blob/master/archive/ZIP.md)

