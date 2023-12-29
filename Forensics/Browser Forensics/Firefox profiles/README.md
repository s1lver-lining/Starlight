Firefox based browsers (and Thunderbird) store their profiles in the following files in the profile folder (usually `XXXXXXXX.default`):

| File | Description |
| --- | --- |
| `places.sqlite` | Bookmarks, history, cookies, etc... |
| `keyN.db` with N=3 or 4 | Master password, used to encrypt the stored passwords |
| `signons.sqlite` or `logins.json` | Stored passwords |
| `certN.db` with N=8 or 9 | Certificates |

* `Dumpzilla` :heart: - [GitHub](https://github.com/Busindre/dumpzilla)

    Dumps everything from a Firefox profile. 

    ```bash
    python3 dumpzilla.py /path/to/your-profile/
    ```
    
    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install.


* `Firefox decrypt` - [GitHub](https://github.com/unode/firefox_decrypt)

    Decrypts passwords from Firefox. Better support than dumpzilla but don't handle legacy profiles (key3.db).

    ```bash
    python3 firefox_decrypt.py /path/to/your-profile/
    ```

    Uses [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which can be hard to install. Similar to [nss-password](https://github.com/glondu/nss-passwords) which can be installed with a .deb file.

* `FirePWD` - [GitHub](https://github.com/lclevy/firepwd)

    Decrypt all types of firefox passwords (including legacy).

    ```bash
    python3 firepwd.py -d /path/to/your-profile/
    ```

    It does not use [NSS](https://en.wikipedia.org/wiki/Network_Security_Services) to decrypt passwords, which makes it easier to install. Found this tool [here](https://security.stackexchange.com/questions/152285/command-line-tools-to-decrypt-my-firefox-45-7-0-passwords-using-key3-db-and-logi).