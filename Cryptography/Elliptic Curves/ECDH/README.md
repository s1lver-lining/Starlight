Elliptic curve Diffie-Hellman ([ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)) is a elliptic curve variant of the [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange protocol. It allows two parties to establish a shared secret over an insecure channel. The shared secret can then be used to encrypt messages between the two parties.

See the [Diffie-Hellman section](../../Diffie-Hellman/README.md) for more information on the key exchange protocol.

## Attacks

### Bad Parameters

* Small secret - [CryptoHack](https://cryptohack.org/challenges/micro/solutions/)

    If one of the secret integers is small and the order of the curve is rather smooth (i.e has very few lage, over $10^{12}$, factors), using Pohlig-Hellman to solve the discrete logarithm problem on the subgrups of the small factors can be enough to recover the secret.