from sage.all import *
import argparse

# https://crypto.stackexchange.com/questions/1871/how-does-the-mov-attack-work
def MOV_attack(E, P, G, max_k=100):
    """
    Performs MOV attack on the elliptic curve E
    with generator G and point P.
    Returns the discrete logarithm of P to the base G.

    Args:
        E: Elliptic curve
        P: Point on E
        G: Generator of E
        max_k: Maximum embedding degree to try

    Returns:
        Discrete logarithm of P to the base G
    """

    order = E.order()
    n = G.order()

    p = E.base_ring().characteristic()
    print("order =", order)
    print("p =", p)

    k = 1 
    while k < max_k:
        if ((p**k)-1)%order == 0:
            break
        k += 1
    print("Found embedding degree k =", k)
    if k == max_k:
        print("embedding degree k not found")
        return None
    
    Fy = GF(p**k,'y')
    Ee = EllipticCurve(Fy, [Fy(a) for a in E.a_invariants()])

    Ge = Ee(G)
    Pe = Ee(P)

    Q1 = Ee.random_point()
    order_Q = Q1.order()
    d = gcd(order_Q, n)
    Q2 = (order_Q//d)*Q1

    assert n/Q2.order() in ZZ
    assert n == Q2.order()

    u = Ge.weil_pairing(Q2, n)
    v = Pe.weil_pairing(Q2, n)

    log = v.log(u)
    return log

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

    print("log(P, G) = {}".format(MOV_attack(E, P, G)))




