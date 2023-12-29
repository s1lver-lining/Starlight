from sage.all import *

# Chinese Remainder Theorem, you can also use the function crt() in sage
def crt(a_list, m_list):
    M = 1
    for m in m_list:
        M *= m
    x = 0
    for a, m in zip(a_list, m_list):
        M_i = M // m
        M_i_inv = inverse_mod(M_i, m)
        x += a * M_i * M_i_inv
    return x % M