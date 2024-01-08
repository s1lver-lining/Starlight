from sage.all import *
import argparse

def break_smooth_order(E, P, G) -> int:
    """
    Compute the discrete logarithm of P in base G on E when the order of E is smooth.

    Args:
        E: Elliptic curve
        P: Point on E
        G: Base point on E

    Returns:
        The discrete logarithm of P in base G on E
    """

    order = E.order()
    print("Order:", order)
    print("->", factor(order))
    factors, exps = zip(*factor(order))
    moduli = [factor[0] ** factor[1] for factor in zip(factors, exps)]

    logs = []
    for modulus in moduli:
        c = int(G.order() / modulus)
        l = discrete_log(c * P, c * G, operation="+")
        logs.append(l)
        print("log(P, G) = {} mod {}".format(l, modulus))

    return crt(logs, moduli)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Breaks the discrete logarithm of P in base G on E when the order of E is smooth.')
    parser.add_argument('p', type=int, help='prime number of the finite field')
    parser.add_argument('a', type=int, help='a parameter of the elliptic curve')
    parser.add_argument('b', type=int, help='b parameter of the elliptic curve')
    parser.add_argument('px', type=int, help='x coordinate of the point P')
    parser.add_argument('py', type=int, help='y coordinate of the point P')
    parser.add_argument('gx', type=int, help='x coordinate of the point G')
    parser.add_argument('gy', type=int, help='y coordinate of the point G')
    args = parser.parse_args()

    E = EllipticCurve(GF(args.p), [args.a, args.b])
    P = E(args.px, args.py)
    G = E(args.gx, args.gy)

    print("log(P, G) = {}".format(break_smooth_order(E, P, G)))




