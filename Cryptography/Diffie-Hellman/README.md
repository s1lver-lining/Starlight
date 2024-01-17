[The Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) is a method that generates a shared secret over a public channel. This method is based on the [discrete logarithm problem](https://en.wikipedia.org/wiki/Discrete_logarithm) which is believed to be hard to solve.

## Key generation (Textbook DH)

Suppose a situation where Alice and Bob want to create a shared secret key. They will use a public channel to do so.

1. They chose a standard prime number $p$ and a generator $g$. $g$ is usually 2 or 5 to make computations easier. $p$ and $g$ are public and $GF(p) = {0, 1, ..., p-1} = {g^0 \mod p, g^1 \mod p, ..., g^{p-1} \mod p}$ is a finite field.
2. They create private keys $a$ and $b$ respectively. $a, b \in GF(p)$.
3. They compute the public keys $A$ and $B$ and send them over the public channel.
    $$A = g^a \mod p$$
    $$B = g^b \mod p$$
4. They can now both compute the shared secret key $s$: Alice computes $s = B^a \mod p$ and Bob computes $s = A^b \mod p$.<br> 
    $$s = B^a = A^b = g^{ab} \mod p$$

They can now use the shared secret $s$ to derive a symmetric key for [AES](../AES/README.md) for example, and use it to encrypt their messages.


## Attacks

* DH with weak prime using Pohlig–Hellman - [Wikipedia](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)

    The public prime modulus $p$ must be chosen such that $p = 2*q + 1$ where $q$ is also a prime. If $p-1$ is smooth (i.e have a lot of small, under 1000, factors), the Pohlig–Hellman algorithm can be used to compute the discrete logarithm very quickly. Sagemath's discrete_log function can be used to compute the discrete logarithm for such primes.

    Use [this script](./Tools/smooth_number_generator.py) to generate smooth numbers of selected size.


* DH with small prime 

    The security of Diffie-Hellman is lower than the number of bits in $p$. Consequently, is p is too small (for example 64bits), it is possible to compute the discrete logarithm in a reasonable amount of time.

    ```python
    from sage.all import *
    a = discrete_log(Mod(A, p), Mod(g, p))
    ```