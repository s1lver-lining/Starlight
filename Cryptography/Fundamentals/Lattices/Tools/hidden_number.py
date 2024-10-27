# Adapted from: https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/lbc_toolkit/problems/hidden_number_problem.sage
# Article: https://eprint.iacr.org/2023/032.pdf

from sage.all import *

def hnp(p:int, T:list, A:list, B:int, debug:bool=False) -> tuple[int, list]:
    """
    Compute an approximate solution to the hidden number problem (HNP) instance.

    Args:
        - p (int) - The prime modulus
        - T (list) - The list of (t_1, t_2, ... t_m) known integers
        - A (list) - The list of (a_1, a_2, ... a_m) known integers
        - B (int) - The bound on the unknown small integers beta_i

    Returns
        - (int) - alpha the secret integer
        - (list) - The list of beta_i's
    """
    print("WARNING: This program was not extensively tested, use it at your onw risk")
    assert len(T) == len(A), f"The length of T ({len(T)}) is different from the length of A ({len(A)})"

    # Generate the lattice basis
    m = len(T)
    M = p * Matrix.identity(QQ, m)
    M = M.stack(vector(T))
    M = M.stack(vector(A))
    M = M.augment(vector([0] * m + [B / p] + [0]))
    M = M.augment(vector([0] * (m + 1) + [B]))
    M = M.dense_matrix()

    # Run LLL
    M = M.LLL()

    # Find the right row
    for row in M:
        if row[-1] == -B:
            alpha = (row[-2] * p / B) % p
            if all((beta - t * alpha + a) % p == 0 for beta, t, a in zip(row[:m], T, A)):
                return alpha, row[:m]
        if row[-1] == B:
            alpha = (-row[-2] * p / B) % p
            if all((beta - t * alpha + a) % p == 0 for beta, t, a in zip(-row[:m], T, A)):
                return alpha, -row[:m]

    return None