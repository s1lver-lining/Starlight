[ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) is a set of **public-key** cryptographic algorithms based on **elliptic curves** over finite fields. It is used to create **digital signatures** and **key exchanges**.

## General definition

### Elliptic curve

An elliptic curve is a curve defined by the equation: $y^2 = x^3 + ax + b$ where $a$ and $b$ are constants. By convention, the curve also contains a point at infinity $\mathcal{O}$.

To be a valid elliptic curve, the discriminant $\Delta = -16(4a^3 + 27b^2)$ must be non-zero, i.e $4a^3 + 27b^2 \neq 0$. Otherwise, the curve is called a singular curve.

### Point adition

A point $P$ on an elliptic curve is a pair of coordinates $(x, y)$ that satisfies the equation of the curve.

The addition of two points $P$ and $Q$ is defined as follows: If $R = P + Q$, then $-R$, the reflection of $R$ over the x-axis, is obtained by drawing a line through $P$ and $Q$ and finding the third point of intersection of this line with the curve. The point $R$ is then defined as $R = -(-R)$.

![Point addition](./_img/EC_addition.png#gh-light-mode-only)
![python ./utils/make_dark_mode_png.py -e 50 "Cryptography/Elliptic Curves/_img/EC_addition.png"](./_img/EC_addition-dark.png#gh-dark-mode-only)

## ECC definition

In ellyptic curve cryptography, the coordinates of points are in a [finite field](https://en.wikipedia.org/wiki/Finite_field) $\mathbb{F}_p$ where $p$ is a prime number.