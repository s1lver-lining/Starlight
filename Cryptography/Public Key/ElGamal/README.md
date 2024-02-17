The [ElGamal encryption system](https://en.wikipedia.org/wiki/ElGamal_encryption) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

## Textbook definition

The variables of textbook ElGamal are:

| Variable | Description |
|----------|-------------|
| $p$ | A large prime number |
| $g$ | A generator of the multiplicative group of integers modulo $p$ |
| $h$ | The public key |
| $x$ | The private key |

The public key is $(p, g, h)$ and the private key is $(p, g, x)$.

### Key generation

The key generation is very similar to the one of the [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

1. Choose a large prime $p$.
2. Choose a generator $g$ of the multiplicative group of integers modulo $p$.
3. Choose a random integer $x$ such that $1 < x < p - 1$.
4. Compute the public key:
   $$h = g^x \mod p$$

### Encryption (Textbook ElGamal)

To encrypt a message $m$ with the **public** key $(p, g, h)$, compute the ciphertext $(c_1, c_2)$ with:

1. Choose a random integer $y$ such that $1 < y < p - 1$.
2. Compute the first part of the ciphertext:
   $$c_1 = g^y \mod p$$
3. Compute the second part of the ciphertext:
    $$c_2 = m \cdot h^y \mod p$$

### Decryption (Textbook ElGamal)

To decrypt a ciphertext $(c_1, c_2)$ with the private key $(p, g, x)$, compute $m$ with:
$$m = c_2 \cdot (c_1^x)^{-1} \mod p$$

m is the deciphered message.


## Attacks

* CCA Padding Oracle

    The Textbook ElGamal encryption system is vulnerable to a [Chosen Ciphertext Attack (CCA)](https://en.wikipedia.org/wiki/Padding_oracle_attack) with a padding oracle.

    [FR] [404CTF2022 Writeup](https://remyoudompheng.github.io/ctf/404ctf/collateraux.html)