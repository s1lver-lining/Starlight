from sage.all import *
import argparse

def fermat_factor(n): 
    tmin = floor(sqrt(n))+1

    for a in range(tmin,n):
       b = sqrt(a*a - n)
       if floor(b) == b :
            return ([a+b,a-b])
       
    return ([0,0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fermat factorization method')
    parser.add_argument('-n', '--number', help='Number to factorize', required=True)
    args = parser.parse_args()
    n = int(args.number)
    print(fermat_factor(n))