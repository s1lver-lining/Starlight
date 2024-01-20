from sage.all import *
import argparse

#Find p, q from https://crypto.stackexchange.com/questions/11509/computing-p-and-q-from-private-key
# Adapted from https://github.com/truongkma/ctf-tools/blob/master/RecoverPrimeFactors.py

def primes_from_d(n, e, d):

    f = d * e - 1
    if f % 2 == 1:
        return 0, 0
    
    else:
        s = 0
        g = f
        while(g % 2 == 0):
            g = int(g // 2)
            s += 1
        while True:
            a = randint(0, n) 
            b = pow(a, g, n)
            if b == 1 or b == n - 1:
                continue
            else:
                for j in range(1, s): 
                    c = pow(b, 2, n)
                    if c == 1:
                        p = gcd(b-1, n)
                        q = int(n / p)
                        return p, q
                    elif c == n - 1:
                        continue
                    b = c
                    c = pow(b, 2, n)
                    if c == 1:
                        p = gcd(b-1, n)
                        q = int(n / p)
                        return p, q
                    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find p, q from n, e, d in RSA')
    parser.add_argument('-n', dest='n', help='Modulus', type=int, required=True)
    parser.add_argument('-e', dest='e', help='Public exponent', type=int, required=True)
    parser.add_argument('-d', dest='d', help='Private exponent', type=int, required=True)
    args = parser.parse_args()

    p, q = primes_from_d(args.n, args.e, args.d)
    print("p = {}".format(p))
    print("q = {}".format(q))
    print("e = {}".format(args.e))
    print("d = {}".format(args.d))
    print("n     = {}".format(args.n))
    print("p * q = {}".format(p * q))