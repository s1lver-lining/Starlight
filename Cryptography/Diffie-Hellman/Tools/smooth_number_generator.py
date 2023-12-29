from sage.all import *
import argparse

def smooth_number_generator(n_bits, max_prime_factor=1000):
    """
    Generates a smooth number of n_bits bits.
    :param n_bits: number of bits of the smooth number to generate
    :return: a smooth number of n_bits bits
    """
    factors = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    n = prod(factors)
    bit_length = n.bit_length()

    while bit_length != n_bits:

        candidate_additions = [random_prime(max_prime_factor) for _ in range(randint(1, 20))]
        candidate_deletions_indexes = list(set([randint(0, len(factors) - 1) for _ in range(randint(1, 20))])) # no duplicates and cant remove more factors than there are
        candidate_deletions = [factors[i] for i in candidate_deletions_indexes]

        candidate = (n * prod(candidate_additions)) // prod(candidate_deletions)
        candidate_bit_length = candidate.nbits()
        if abs(candidate_bit_length - n_bits) < abs(bit_length - n_bits):
            n = candidate
            bit_length = candidate_bit_length
            factors += candidate_additions
            factors = [factors[i] for i in range(len(factors)) if i not in candidate_deletions_indexes]


    return n

def weak_prime_gemerator(nbits, max_prime_factor=1000):
    """
    Generates a weak prime of nbits bits.
    :param nbits: number of bits of the weak prime to generate
    :return: a weak prime of nbits bits
    """

    n = smooth_number_generator(nbits, max_prime_factor)
    # slow but simple, returns in a few seconds, can be faster by just modifying smooth_number_generator
    while not (is_prime(n + 1) and (n+1).nbits() == nbits):
        n = smooth_number_generator(nbits, max_prime_factor)
    return n + 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generates a smooth number of n_bits bits or a weak prime for Diffie-Hellman of n_bits bits.')
    parser.add_argument('n_bits', type=int, help='number of bits of the smooth number to generate')
    parser.add_argument('--max_prime_factor', type=int, default=1000, help='maximum prime factor of the smooth number to generate')
    parser.add_argument('--prime', action='store_true', help='generate a weak prime with p-1 smooth instead', default=False)
    args = parser.parse_args()

    if args.prime:
        n = weak_prime_gemerator(args.n_bits, args.max_prime_factor)
    else:
        n = smooth_number_generator(args.n_bits, args.max_prime_factor)

    print(n)