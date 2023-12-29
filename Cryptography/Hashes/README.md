* `Hash types` - [Website](https://hashcat.net/wiki/doku.php?id=example_hashes)

    Different hash types exists, and they are used in different contexts. This page lists the most common hash types and their respective hashcat modes.

| Hash type | Byte Length | Hashcat mode | Example hash  |
|-----------|--------------|--------------|--------------|
| MD5      | 32  | 0    | `8743b52063cd84097a65d1633f5c74f5` |
| SHA1     | 40  | 100  | `b89eaac7e61417341b710b727768294d0e6a277b` |
| SHA256   | 64  | 1400 | `127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935` |
| SHA2-512 | 128 | 1700 | too long |



* `Haiti` - [GitHub](https://github.com/noraj/haiti/)

    CLI Hash type identifier

* `Hashcat` - [Website](https://hashcat.net/hashcat/)

    Crack hashes. Can use GPU.


* `John the Ripper` - [Website](https://www.openwall.com/john/)

    Better compatibility and easier to use than hashcat, but lower number of hash types supported.

* `dcipher` - [GitHub](https://github.com/k4m4/dcipher-cli)

    CLI tool to lookup hashes in online databases.