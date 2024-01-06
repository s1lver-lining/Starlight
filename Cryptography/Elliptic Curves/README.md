[ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) is a set of **public-key** cryptographic algorithms based on **elliptic curves** over finite fields. It is used to create **digital signatures** and **key exchanges**.

## General definition

As ECC relies on unusual mathematical problems and some concepts are very specific to this, the definition part is more detailed than orther sections.


Note: This section was made using the following resources:
- CryptoHack, [Elliptic Curves course](https://cryptohack.org/courses/elliptic/).
- [Elliptic Curve notes by Ben Lynn](https://web.archive.org/web/20220412170936/https://crypto.stanford.edu/pbc/notes/elliptic/)
- An Introduction to Mathematical Cryptography, Jeffrey Hoffstein, Jill Pipher, Joseph H. Silverman.

### Elliptic curve

>An [**elliptic curve**](https://en.wikipedia.org/wiki/Elliptic_curve) is a curve defined by the equation: $$Y^2 = X^3 + aX + b$$ where $a$ and $b$ are constants. By convention, the curve also contains a point at infinity $\mathcal{O}$.


To be a valid elliptic curve, the discriminant $\Delta = -16(4a^3 + 27b^2)$ must be non-zero, i.e $4a^3 + 27b^2 \neq 0$. Otherwise, the curve is called a singular curve.

>Formally, the curve on a [field](https://en.wikipedia.org/wiki/Field_(mathematics)) $F$ is the set of points $(x, y)$, $x, y \in F$ defined by $$E(F) = \{(x, y) \in F^2 : y^2 = x^3 + ax + b\} \cup \{\mathcal{O}\}$$

We can already notice:
* The curve is symmetric about the $x$-axis, because $y^2 = (-y)^2$

### Point adition

We can now define the addition of two points on an elliptic curve.

>The **addition of two points** $P$ and $Q$ can be defined as follows: Take the line through $P$ and $Q$, and find the third point of intersection with this line. Then reflect this point about the $x$-axis. The result is $P + Q$.

* If $P = Q$, then the line is the tangent to the curve at $P$.
* If there is no third point of intersection, then the result is $\mathcal{O}$ which can be seen as [the point at infinity](https://en.wikipedia.org/wiki/Projective_geometry).

This figure represents $P + Q = R$:

![Point addition](./_img/EC_addition.png#gh-light-mode-only)
![Point addition](./_img/EC_addition-dark.png#gh-dark-mode-only)

>The following properties can be observed:
>- If $P$ and $Q$ have rational coordinates, then so does $R$.
>* $P + \mathcal{O} = \mathcal{O} + P = P$ (The point at infinity is the identity element.)
>- $P + (-P) = \mathcal{O}$ (The inverse of a point is its reflection about the $x$-axis.)
>* $P + Q = Q + P$ (Addition is commutative.)
>- $(P + Q) + R = P + (Q + R)$ (Addition is associative.)

These properties makes the set of points on an elliptic curve coupled with the point addition operation an [abelian group](https://en.wikipedia.org/wiki/Abelian_group).

Point addition can be computed using the following formulas:
* If $P \neq Q$:
$$\begin{cases}
x_R = \lambda^2 - x_P - x_Q \\
y_R = \lambda(x_P - x_R) - y_P \\
\end{cases}
\text{ where } \lambda = \frac{y_Q - y_P}{x_Q - x_P}$$

* If $P = Q$:
$$\begin{cases}
x_R = \lambda^2 - 2x_P \\
y_R = \lambda(x_P - x_R) - y_P \\
\end{cases}
\text{ where } \lambda = \frac{3x_P^2 + a}{2y_P}$$


## ECC definition

In ellyptic curve cryptography, the coordinates of points are in a [finite field](https://en.wikipedia.org/wiki/Finite_field) $\mathbb{F}_p$ where $p$ is a prime number.

Because of this, the set of points that verifies the equation of an elliptic curve can no longer be seen as a simple geometric curve. Now, the space can be seen as a **rectangular grid** of points. The left and right **edges of the grid are connected**, as well as the top and bottom edges. This is called a *torus*.

For exemple, here is the set of points of the elliptic curve $Y^2 = X^3 − X$ over $\mathbb{F}_{61}$:

![Elliptic curve over a finite field](./_img/Elliptic_curve_on_Z61.png#gh-light-mode-only)
![Elliptic curve over a finite field](./_img/Elliptic_curve_on_Z61-dark.png#gh-dark-mode-only)

We notice that:
* Point addition as we defined it before still works on this grid. See [this website](https://curves.xargs.org/) for visual examples.
* $\mathcal{O}$ is now (0, 0)
* Because the curve is symmetric about the $x$-axis and the space is finite, there is a new symmetry axis at the center of the grid.


Here is python sagemath code that defines the elliptic curve $Y^2 = X^3 − X$ over $\mathbb{F}_{61}$ and computes $P + Q$:

```python
p = 61
F = GF(p)
E = EllipticCurve(F, [-1, 0])
P = E(8, 4)
Q = E(17, 4)
R = P + Q # = R(36, 57)
```

### Scalar multiplication

We can now define the **scalar multiplication** of a point $P$ by an integer $k$.

>The **scalar multiplication** is defined by iterating addition: $kP = P + P + \cdots + P$ ($k$ times).

This operation is the *trapdoor function* of ECC, as inversing it is considered to be very hard. This problem is called the **elliptic curve discrete logarithm problem** (ECDLP): given $P$ and $Q$, find $k$ such that $Q = kP$.