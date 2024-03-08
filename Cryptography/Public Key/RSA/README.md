[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is an **asymetric** cryptographic algorithm. A **public key** is used to encrypt data and a **private key** is used to decrypt data.

## Textbook definition

The variables of textbook RSA are:

| Variable | Description |
|----------|-------------|
| $N$ | The product of two large primes |
| $e$ | The public exponent |
| $d$ | The private exponent |

The public key is (N, e) and the private key is (N, d).

### Key generation

1. Choose two large primes $p$ and $q$. Use a cryptographically secure random number generator.
2. Compute the public modulus:
   $$N = p q$$
3. Compute the "private" modulus:
   $$\Phi(N) = (p - 1) (q - 1)$$
4. Choose an integer $e$ such that 
   $$1 < e < \Phi(N) \text{ and } \gcd(e, \Phi(N)) = 1$$
   <br>
   
   Usually $e = 65537 = 0\text{x}10001$.
5. Compute $d$ such that $de = 1 \mod \Phi(N)$ <br>
   $$d = e^-1 \mod \Phi(N)$$
   
   (for exemple with the [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm))

### Encryption (Textbook RSA)
To encrypt a message $m$ with the **public** key $(N, e)$, compute the ciphertext $c$ with:

$$c = m^e \mod N$$

### Decryption (Textbook RSA)
To decrypt a ciphertext $c$ with the private key $(N, d)$, compute $m = c^d \mod N$.

m is the deciphered message.

## Attacks

Several attacks exist on RSA depending on the circumstances.

* `RSA CTF Tool` :heart: - [GitHub](https://github.com/RsaCtfTool/RsaCtfTool)

    Performs several attacks on RSA keys. Very useful for CTFs.


* Known factors in databases

	Services such as [FactorDB](http://factordb.com) or  [Alpertron's calculator](https://www.alpertron.com.ar/ECM.HTM) provide a database of known factors. If you can find a factor of $N$, you can compute $p$ and $q$ then $d$.

* RSA Fixed Point - [StackExchange](https://crypto.stackexchange.com/questions/81128/fixed-point-in-rsa-encryption)

   These challenges can be spotted when the input is not changed with encrypted/decrypted.

   There are 6 non-trivial fixed points in RSA encryption that are always there, caracterized by $m$ mod $p \in \{0, 1, -1\}$ **and** $m$ mod $q \in \{0, 1, -1\}$.

   It is possible to deduce one of the prime factors of $n$ from the fixed point, since $\text{gcd}(m−1,n),\ \text{gcd}(m,n),\ \text{gcd}(m+1,n)$ are $1, p, q$ in a different order depending on the values of $m$ mod $p$ and $m$ mod $q$.

   However, it is also possible to find other fixed points that are not the 6 non-trivial ones. See [this cryptohack challenge](https://cryptohack.org/challenges/unencryptable/solutions/) for writeups on how to deduce the prime factors of $n$ from these fixed points.
   
* Decipher or signing oracle with blacklist 

   A decipher oracle can not control the message that it decrypts. If it blocks the decryption of cipher $c$, you can pass it $c * r^e \mod n$ where $r$ is any number. It will then return 
   $$(c * r^e)^d = c^d * r = m * r \mod n$$
    
   You can then compute $m = c^d$ by dividing by $r$.

   This also applies to a signing oracle with a blacklist.

* Bleichenbacher's attack on PKCS#1 v1.5

   When the message is padded with **PKCS#1 v1.5** and a **padding oracle** output an error when the decrypted ciphertext is not padded, it is possible to perform a Bleichenbacher attack (BB98). See [this github script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/bleichenbacher.py) for an implementation of the attack.

   This attack is also known as the million message attack, as it require a lot of oracle queries.

* Finding primes $p$ and $q$ from d

   [This algorithm](./Tools/primes_from_d.py) can be used to find $p$ and $q$ from $(N, e)$ and the private key $d$


* Coppersmith's attack - [Wikipedia](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)


### Bad parameters attacks

* Wiener's Attack - [Wikipedia](https://en.wikipedia.org/wiki/Wiener%27s_attack) with continued fractions

   When $e$ is **very large**, that means $d$ is small and the system can be vulnerable to the Wiener's attack. See [this script](./Tools/wiener.py) for an implementation of the attack.

	This type of attack on small private exponents was improved by Boneh and Durfee. See [this repository](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage) for an implementation of the attack.


* Small $e$, usually 3 in textbook RSA - [StackExchange](https://crypto.stackexchange.com/questions/33561/cube-root-attack-rsa-with-low-exponent)

   When $e$ is so small that $c = m^e < N$, you can compute $m$ with a regular root: $m = \sqrt[e]{c}$.

   If $e$ is a bit larger, but still so small that $c = m^e < kN$ for some small $k$, you can compute $m$ with a $k$-th root: $m = \sqrt[e]{c + kN}$.

   See [this script](./Tools/small_e.py) for an implementation of the attack.

* Many primes in the public modulus - [CryptoHack](https://cryptohack.org/courses/public-key/manyprime/)

   When $N$ is the product of many primes (~30), it can be easily factored with the [Elliptic Curve Method](https://en.wikipedia.org/wiki/Lenstra_elliptic_curve_factorization).

   See [this script](./Tools/many_primes.py) for an implementation of the attack.

* Square-free 4p - 1 factorization and it's RSA backdoor viability - [Paper](https://crocs.fi.muni.cz/_media/public/papers/2019-secrypt-sedlacek.pdf)

   > *Definition* Square-free number
   >If we have  
   >
   >$$\begin{cases}
   >N &= p \cdot q \\
   >T &= 4 \cdot p - 1 \\
   >T &= D \cdot s^2 \\
   >D &= 3 \mod 8
   >\end{cases}$$
   >
   >then $D$ is a square-free number and $N$ can be factored.

   See [this GitHub repository](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/complex_multiplication.py) for an implementation of the attack.
  
* Fermat's factorisation method - [Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)

   If the primes $p$ and $q$ are close to each other, it is possible to find them with Fermat's factorisation method. See [this script](./Tools/fermat_factor.py) for an implementation of the attack.

* ROCA vulnerability - [Wikipedia](https://en.wikipedia.org/wiki/ROCA_vulnerability)

   The "Return of Coppersmith's attack" vulnerability occurs when generated primes are in the form <br>
   $$p = k * M * + (65537^a \mod M)$$
   where $M$ is the product of $n$ successive primes and $n$.

   See this [GitHub gist](https://gist.github.com/zademn/6becc979f65230f70c03e82e4873e3ec) for an explaination of the attack.

   See this [Gitlab repository](https://gitlab.com/jix/neca) for an implementation of the attack.


### Bad implementations attacks


* Chinese Remainder Attack

   When there are **multiple moduli** $N_1, N_2, \dots, N_k$ for multiple $c_1, c_2, \dots, c_k$ of the same message and the **same public exponent** $e$, you can use the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to compute $m$.

* Multiple Recipients of the same message

   When there are **multiple public exponents** $e_1, e_2$ for multiple $c_1, c_2$ and the **same moduli** $N$, you can use Bezout's identity to compute $m$.

   Using Bezout's algorithm, you can find $a$ and $b$ such that $a e_1 + b e_2 = 1$. Then you can compute $m$ with:
   $$c_1^a c_2^b = m^{a e_1} m^{b e_2} = m^{a e_1 + b e_2} = m^1 = m \mod N$$

* Franklin-Reiter related-message attack

   When two messages are encrypted using the same key $(e, N)$ and one is a polynomial function of the other, it is possible to decipher the messages.

   A special case of this is when a message is encrypted two times with linear padding : $c = (a*m +b)^e \mod N$.

   See this [GitHub repository](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Franklin-Reiter/README.md) for an explaination of the attack.

   See [this script](./Tools/franklin_reiter.py) for an implementation of the attack.


* Signature that only check for the last few bytes - [CryptoHack](https://cryptohack.org/challenges/pedro/solutions/)

   When a signature is only checking the last few bytes, you can add $2^{8 * n}$ to the message and the signature will still be valid, where $n$ is the number of bytes checked. Consequently, finding the $e$-th root of the signature will be easier. Check writeups of the cryptohack challenge for more details.

