[DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) A.K.A. Data Encryption Standard is a **symmetric** cryptographic algorithm. It uses the **same key** for encryption and decryption. It is a block cipher that encrypts data 64 bits at a time using a 56-bit key. The key is sometimes completed with an additional byte for parity check. DES is now considered insecure and has been replaced by AES.

Variations such as [Triple DES](https://en.wikipedia.org/wiki/Triple_DES) (3DES) and [DES-X](https://en.wikipedia.org/wiki/DES-X) have been created to improve the security of DES.



* Weak keys - [Wikipedia](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES) [CryptoHack](https://aes.cryptohack.org/triple_des/)

    DES allows for weak keys which are keys that produce the same ciphertext when used for encryption and decryption.

    Some weak keys with valid parity check are:

    * 0x0101010101010101
    * 0xFEFEFEFEFEFEFEFE
    * 0xE0E0E0E0F1F1F1F1
    * 0x1F1F1F1F0E0E0E0E

    Using multiple of these keys in [2 or 3 keys triple DES](https://en.wikipedia.org/wiki/Triple_DES#Keying_options) can also produce a symmetric 3DES block cipher.