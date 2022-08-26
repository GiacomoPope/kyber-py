"""
TODO: Build structure to allow this to generalise away from n=256.
"""

def br(i, k):
    """
    bit reversal of an unsigned k-bit integer
    """
    bin_i = bin(i & (2**k - 1))[2:].zfill(k)
    return int(bin_i[::-1], 2)

KYBER_Q   = 3329
MONT_R    = 2**16
MONT_RINV = pow(MONT_R, -1, KYBER_Q)
MONT_MASK = MONT_R - 1
Q_INV     = pow(-KYBER_Q, -1, MONT_R)
# NTT_ZETAS = [(MONT_R * pow(17,  br(i,7), KYBER_Q)) % KYBER_Q for i in range(128)]
NTT_ZETAS = [2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 
             573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 
             1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 
             2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 
             2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 
             778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 
             1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 
             1799, 2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628]
    
def montgomery_reduce(a):
    """
    a -> R^(-1) a mod q
    """
    return a * MONT_RINV % KYBER_Q

def barrett_reduce(a):
    """
    return a mod q
    """
    return a % KYBER_Q
    
def __montgomery_reduce_old(a):
    """
    This should be faster, but because
    python, the below function `montgomery_reduce`
    is faster...
    
    a -> R^(-1) a mod q
    """
    u = ((a & MONT_MASK) * Q_INV) & MONT_MASK
    t = a + u*KYBER_Q
    t = t >> 16
    if t >= KYBER_Q:
        t = t - KYBER_Q
    return t
    
def __barrett_reduce_old(a):
    """
    This should be faster, but because
    python, the function `barrett_reduce` is faster...
    
    a mod q \in -(q-1)/2, ... ,(q-1)/2
    """
    v = ((1 << 26) + KYBER_Q // 2) // KYBER_Q
    t = (v * a + (1 << 25)) >> 26
    t = t * KYBER_Q
    return (a - t)
	
def ntt_mul(a, b):
    """
    Multiplication then Montgomery reduction
    
    Ra * Rb -> Rab
    """
    c = a * b
    return montgomery_reduce(c)

def ntt_base_multiplication(a0, a1, b0, b1, zeta):
    r0  = ntt_mul(a1, b1)
    r0  = ntt_mul(r0, zeta)
    r0 += ntt_mul(a0, b0)
    r1  = ntt_mul(a0, b1)
    r1 += ntt_mul(a1, b0)
    return r0, r1
    
def ntt_coefficient_multiplication(f_coeffs, g_coeffs):
    new_coeffs = []
    for i in range(64):
        r0, r1 = ntt_base_multiplication(
                            f_coeffs[4*i+0], f_coeffs[4*i+1],
                            g_coeffs[4*i+0], g_coeffs[4*i+1],
                            NTT_ZETAS[64+i])
        r2, r3 = ntt_base_multiplication(
                            f_coeffs[4*i+2], f_coeffs[4*i+3],
                            g_coeffs[4*i+2], g_coeffs[4*i+3],
                            -NTT_ZETAS[64+i])
        new_coeffs += [r0, r1, r2, r3]
    return new_coeffs
    
if __name__ == '__main__':
    import random
    import time
    
    def test_func(func, name):
        """
        Time normal: 0.10313796997070312
        Time alt: 0.08180785179138184
        """
        t = time.time()
        for _ in range(100_000):
            a = random.randint(0, 2**16)
            func(a)
        print(f"Time {name}: {time.time() - t}")
    
    test_func(montgomery_reduce, "Mont python")
    test_func(__montgomery_reduce_old, "Mont old")
    
    test_func(barrett_reduce, "Barrett python")
    test_func(__barrett_reduce_old, "Barrett old")
    
    """
    Time Mont python: 0.0867300033569336
    Time Mont old: 0.0959770679473877
    Time Barrett python: 0.08015108108520508
    Time Barrett old: 0.10505414009094238
    """
    
    R_inv = pow(2,-16,KYBER_Q)
    for _ in range(1000):
        a = random.randint(0, 2**16)
        assert (R_inv*a) % KYBER_Q == montgomery_reduce(a)
        assert montgomery_reduce(a) == __montgomery_reduce_old(a)
        
    for _ in range(1000):
        a = random.randint(0, 2**32)
        assert (a) % KYBER_Q == barrett_reduce(a) % KYBER_Q
        assert barrett_reduce(a) == __barrett_reduce_old(a) % KYBER_Q
        
        
    
