from sage.all import *
import argparse

# Implemented using https://doc.sagemath.org/html/en/reference/interfaces/sage/interfaces/ecm.html

def many_primes(n):

    ecm = ECM()
    factors = ecm.factor(n)
    return factors

def test():

    primes = []
    for i in range(30):
        p = random_prime(2**64)
        primes.append(p)

    # Sort the primes
    primes.sort()
    print("primes =", primes)

    N = 1
    for p in primes:
        N *= p

    print("N =", N)
    factors = many_primes(N)
    factors.sort()
    print("factors =", factors)

    test_correct = True
    for i in range(len(primes)):
        if primes[i] != factors[i]:
            test_correct = False

    print("Test correct:", test_correct)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Factor a known composite number with many primes")
    parser.add_argument("n", type=int, help="The number to factor")
    args = parser.parse_args()

    factors = many_primes(args.number)
    print("factors =", factors)








