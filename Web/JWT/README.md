[JSON Web Tokens (JWT)](https://wikipedia.org/wiki/JSON_Web_Token) are a way to authenticate users. They are encoded strings that contain the user's information. The server can decode the JWT and use the information to authenticate the user.

They are encoded in base64 in the following format:
```
header.payload.signature
```
Where:
| Name | Description |
| --------- | ----------- |
| Header | a JSON object that contains the algorithm used to encode the JWT and the type of the token |
| Payload | a JSON object that contains the user's information |
| Signature | the encoded `header` and `payload` using the algorithm specified in the `header` |

* JWT tempering

    JWTs are a way to authenticate users. They are encoded strings that contain the user's information. The server can decode the JWT and use the information to authenticate the user. 
    
    [`jwt_tools`](https://github.com/ticarpi/jwt_tool) can help with modifying the JWTs. They also document common vulnerabilities in JWTs [in their wiki page](https://github.com/ticarpi/jwt_tool/wiki)
    ```bash
    python jwt_tool.py <jwt>        # Inspect the JWT
    python jwt_tool.py -T <jwt>     # Modify (temper) the JWT
    python jwt_tool.py -C -d <jwt>  # Crack the JWT's signature
    ```

* Both asymetic and symetric algorithms

    When both an asymetric and a symetric algorithm are allowed by the server and use the same key, the public key might be used as a secret key in the symetric algorithm. Consequently, the public key can be retrived using the symetric algorithm, and then used to sign/decryot the JWT using the asymetric algorithm.

* Public Key recovery - [GitHub](https://github.com/FlorianPicca/JWT-Key-Recovery)

    When a JWT is signed using an asymetric algorithm, the public key can be recovered using the JWT's signature.