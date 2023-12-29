
* URL Encoding

    URL encoding is a way to encode special characters in a URL. The code is the `%` character followed by the Hex representation of the character in ascii. For example, the `?` character is encoded as `%3F`, space is `%20` etc.
    
    Read [this](https://www.w3schools.com/tags/ref_urlencode.asp) for more details on how to encode characters.


* IP restriction bypass with the `X-Forwarded-For` header

    Some servers use the `X-Forwarded-For` header to check if the request comes from a valid IP address. This is a vulnerability since it can be changed by the client, and used to bypass IP restrictions. 
    
    Use [burp](https://portswigger.net/burp) or python's `requests` library to set the header.


* Authentication bypass with `User-Agent` header

    Some servers use the `User-Agent` header to authenticate the user. Usually this field is used to identify the browser's version and OS, but it can be changed by the client.
    
    Use [burp](https://portswigger.net/burp) or python's `requests` library to set the header.

* Verb tampering

    Servers can have different behaviors depending on the HTTP verb used. For example, a server can return a 404 error when a `GET` request is made, but return a 200 when a `PUT` request is made.

    Read [this](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering) for more details on how to test it.

* JWT tempering

    JWTs are a way to authenticate users. They are encoded strings that contain the user's information. The server can decode the JWT and use the information to authenticate the user. 
    
    [`jwt_tools`](https://github.com/ticarpi/jwt_tool) can help with modifying the JWTs. They also document common vulnerabilities in JWTs [in their wiki page](https://github.com/ticarpi/jwt_tool/wiki)
    ```bash
    python jwt_tool.py <jwt>        # Inspect the JWT
    python jwt_tool.py -T <jwt>     # Modify (temper) the JWT
    python jwt_tool.py -C -d <jwt>  # Crack the JWT's signature
    ```

* AES CBC ciphered cookies

    See [Bit flipping attack](../../Cryptography/AES/AES%20-%20CBC%20Mode/README.md) for more details.