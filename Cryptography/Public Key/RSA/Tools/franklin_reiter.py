from sage.all import *
import argparse
from Crypto.Util.number import *
import random

# Implemented from https://crypto.stackexchange.com/questions/30884/help-understanding-basic-franklin-reiter-related-message-attack

def franklin_reiter(e, n, c1, c2, a1, b1, a2, b2):
    """
    Franklin-Reiter Related Message Attack
    c1 = (a1 * m + b1) ** e mod n
    c2 = (a2 * m + b2) ** e mod n
    """
    Px = PolynomialRing(Zmod(n), "x"); x = Px.gen()
    f1 = (a1*x + b1) ** e - c1
    f2 = (a2*x + b2) ** e - c2

    def polyGCD(f, g):
        return f.monic() if g == 0 else polyGCD(g, f%g)
    
    f = polyGCD(f1, f2)
    return ZZ(-f[0])

def test():

    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q

    phi = (p-1)*(q-1)
    e = 11
    a1 = random.randint(2, phi)
    b1 = random.randint(2, phi)
    a2 = random.randint(2, phi)
    b2 = random.randint(2, phi)

    m = 1337133713371337

    c1 = pow((a1*m + b1)%n, e, n)
    c2 = pow((a2*m + b2)%n, e, n)

    m1 = franklin_reiter(e, n, c1, c2, a1, b1, a2, b2)
    m2 = franklin_reiter(e, n, c2, c1, a2, b2, a1, b1)
    print(m1 == m and m2 == m)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Franklin-Reiter Related Message Attack when c1 = (a1 * m + b1) ** e mod n and c2 = (a2 * m + b2) ** e mod n')
    parser.add_argument('e', type=int, help='public exponent', required=True)
    parser.add_argument('n', type=int, help='modulus', required=True)
    parser.add_argument('c1', type=int, help='ciphertext 1', required=True)
    parser.add_argument('c2', type=int, help='ciphertext 2', required=True)
    parser.add_argument('a1', type=int, help='a1', default=1)
    parser.add_argument('b1', type=int, help='b1', default=0)
    parser.add_argument('a2', type=int, help='a2', default=1)
    parser.add_argument('b2', type=int, help='b2', default=0)
    args = parser.parse_args()

    m = franklin_reiter(args.e, args.n, args.c1, args.c2, args.a1, args.b1, args.a2, args.b2)
    print("m = %d" % m)
