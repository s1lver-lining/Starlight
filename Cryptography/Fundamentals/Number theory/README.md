This section is currently under construction. Use the search bar to find the topic you are looking for.


## Number theory basics

> *Property* Notations
>
> * $a \mid b$ - $a$ divides $b$
> * $a \Z$ - the set of all integers that are multiples of $a$
>

### Divisibility
<!-- GCD -->
> *Definition* GCD - Greatest Common Divisor
>
> The greatest common divisor of two integers $a$ and $b$ is the largest integer that divides both $a$ and $b$:
>
> $$ a \Z + b \Z = \gcd(a, b) \Z $$
>

This can be extended to more than two integers. When $\gcd(a, b) = 1$, we say that $a$ and $b$ are coprime.

We also have the following properties:  
$\gcd(a, b) = \gcd(b, a)$  
$\gcd(a, b) = \gcd(-a, b) = \gcd(a, -b) = \gcd(-a, -b)$  
$\gcd(a, b) = \gcd(a, b - a)$  
$\gcd(a, b) = \gcd(a, b \mod a)$  
$\gcd(k \cdot a, k \cdot b) = k \cdot \gcd(a, b)$

<!-- bezout -->
> *Theorem* Bezout's identity
>
> For any $a_1, a_2 \cdots a_n \in \Z$, they are coprime if and only if there exist integers $x_1, x_2 \cdots x_n$ such that:
>
> $$ x_1 \cdot a_1 + x_2 \cdot a_2 + \cdots + x_n \cdot a_n = 1 $$
>

<!-- gauss -->
> *Theorem* Gauss's lemma
>
> If $a \mid bc$ and $\gcd(a, b) = 1$, then $a \mid c$.
>

<!-- lcm -->
> *Definition* LCM - Least Common Multiple
>
> The least common multiple of two integers $a$ and $b$ is the smallest integer that is a multiple of both $a$ and $b$:
>
> $$ a \Z \cap b \Z = \text{lcm}(a, b) \Z $$
>

This can be extended to more than two integers. We also have the following properties:
$\text{lcm}(a, b) = \text{lcm}(b, a)$  
$\text{lcm}(a, b) = \text{lcm}(-a, b) = \text{lcm}(a, -b) = \text{lcm}(-a, -b)$  
$\text{lcm}(a, b) = \text{lcm}(a, b - a)$  
$\text{lcm}(a, b) = \text{lcm}(a, b \mod a)$  
$\text{lcm}(k \cdot a, k \cdot b) = k \cdot \text{lcm}(a, b)$  
$\text{lcm}(a, b) \cdot \gcd(a, b) = \mid a \cdot b \mid$  

### Prime numbers

<!-- prime number -->
> *Definition* Prime number
>
> A prime number is a natural number greater than 1 that has no positive divisors other than 1 and itself.
>

<!-- prime factorization -->
> *Theorem* Fundamental theorem of arithmetic
>
> Every integer greater than 1 can be expressed uniquely as a product of prime numbers.
>
> $$ n = p_1^{e_1} \cdot p_2^{e_2} \cdots p_k^{e_k} $$
>

<!-- fermat -->
> *Theorem* Fermat's little theorem
>
> If $p$ is a prime number and $a$ is an integer not divisible by $p$, then:
>
> $$ a^{p-1} \equiv 1 \mod p $$
>

<!-- wilson -->
> *Theorem* Wilson's theorem
>
> A natural number $p$ is a prime number if and only if:
>
> $$ (p-1)! \equiv -1 \mod p $$
>

### Euler's totient function

<!-- euler's totient function -->
> *Definition* Euler's totient function
>
> The Euler's totient function $\phi(n)$ is the number of positive integers less than $n$ that are coprime to $n$.
>
> $$ \phi(n) = \mid \{ k \in \N \mid 1 \leq k < n, \gcd(k, n) = 1 \} \mid $$
>

<!-- euler's totient function properties -->
> *Property* Euler's totient function properties
>
> * If $p$ is a prime number, then $\phi(p) = p - 1$
> * If $a$ and $b$ are coprime, then $\phi(a \cdot b) = \phi(a) \cdot \phi(b)$
> * If $p$ is a prime number and $k \in \N$, then $\phi(p^k) = p^k - p^{k-1}$
>

<!-- euler -->
> *Theorem* Euler's theorem
>
> If $a$ and $n$ are coprime, then:
>
> $$ a^{\phi(n)} \equiv 1 \mod n $$