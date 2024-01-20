[DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) A.K.A Digital Signature Algorithm is a signing algorithm similar to [RSA](../RSA/README.md).


## Textbook definition

The variables of textbook RSA are:

| Variable | Description |
|----------|-------------|
| $q$ | A large prime |
| $p$ | A large prime such that $p -1$ is a multiple of $q$ |
| $g$ | $g = h^{(p-1)/q} \mod p$ where $h$ is a random integer such that $1 < h < p-1$ |

### Key generation

- Chose $x$ such that $1 < x < q$, this is the private key.
- Compute $y = g^x \mod p$, this is the public key.

### Signing

The signature of a message $m$ requires a hashing function $H$.

- Chose $k$ such that $1 < k < q$.
- Compute 
$$r = (g^k \mod p) \mod q$$
$$s = k^{-1} (H(m) + xr) \mod q$$

If $r = 0$ or $s = 0$, do it again with another $k$. The signature is $(r, s)$.

### Verification

- Verify that $0 < r < q$ and $0 < s < q$.
- Compute $w = s^{-1} \mod q$.
- Compute $u_1 = H(m)w \mod q$ and $u_2 = rw \mod q$.
- Compute $v = (g^{u_1} y^{u_2} \mod p) \mod q$.
- Iif $v = r$, the signature is valid.

## Attacks

* No hash function - [StackExchange](https://crypto.stackexchange.com/questions/44862/ecdsa-signature-without-hashing-or-with-offloaded-hash)

    If message is directly signed without hashing, it is possible to forge create messages that have the same signature.