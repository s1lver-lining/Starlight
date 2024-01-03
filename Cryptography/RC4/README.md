[RC4](https://en.wikipedia.org/wiki/RC4) is a fast stream cipher known to be very insecure.

## Attacks

* FMS Attack - [Wikipedia](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack) [CryptoHack](https://aes.cryptohack.org/oh_snap)

    Allows to recover the key from the keystream when RC4's key is in the form (nonce || unknown). Mostly used to recover WEP from WEP SNAP headers. An implementation and description of this attack can be found on [GitHub](https://github.com/jackieden26/FMS-Attack/blob/master/keyRecover.py).

    If you have an encryption (or decryption, it's the same) oracle, I recommend reading the writeups from this [CryptoHack challenge](https://aes.cryptohack.org/oh_snap).

