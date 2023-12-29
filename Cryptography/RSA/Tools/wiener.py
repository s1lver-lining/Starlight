from sage.all import *
import argparse

# Implemented from https://en.wikipedia.org/wiki/Wiener's_attack

def wiener(e, n):
    m = 13371337     # Random message
    c = pow(m, e, n) # Encrypted message

    # Compute the convergents of the continued fraction
    lst = continued_fraction(Integer(e)/Integer(n))
    conv = lst.convergents()

    # For each k/d, check if d is correct
    for i in conv:
        k = i.numerator()
        d = int(i.denominator())
        try:
            m1 = pow(c, d, n)
            if m1 == m:
                print("Private key found !")
                print("d =", d)
                return d
        except:
            continue
    return -1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Wiener\'s attack with continued fractions')
    parser.add_argument('-e', dest='e', type=int, help='Public exponent')
    parser.add_argument('-n', dest='n', type=int, help='Modulus')
    args = parser.parse_args()
    wiener(args.e, args.n)