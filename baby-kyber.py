"""
This is a toy implementation of Kyber which follows
https://cryptopedia.dev/posts/kyber/

As the polynomials are given precisely in the blog post
all calculations are done by calling `polynomials` and
`modules` rather than `Kyber` itself.
"""

from polynomials import *
from modules import *

def keygen():
    # Randomness fixed for example
    # Generate a secret key which
    # is a vector with elements 
    # pulled from a centred
    # binomial distribution
    s0 = R([0,1,-1,-1])
    s1 = R([0,-1,0,-1])
    s = M([s0,s1]).transpose()

    # Randomness fixed for example
    # Generate a 2x2 matrix with 
    # elements taken randomly from
    # R_q
    A00 = R([11,16,16,6])
    A01 = R([3,6,4,9])
    A10 = R([1,10,3,5])
    A11 = R([15,9,1,6])
    A = M([[A00, A01],[A10, A11]])

    # Randomness fixed for example
    # gen random vector `e` from
    # binomial distribution
    e0 = R([0,0,1,0])
    e1 = R([0,-1,1,0])
    e = M([e0,e1]).transpose()

    # Compute `t` from example
    t = A @ s + e
    
    # Check against blogpost
    assert t == M([R([7,0,15,16]),R([6,11,12,10])]).transpose()
    return (A, t), s

def enc(m, public_key):
    # randomness fixed for example
    # gen random vector `r` from
    # binomial distribution
    r0 = R([0,0,1,-1]) 
    r1 = R([-1,0,1,1])
    r = M([r0, r1]).transpose()
    
    # randomness fixed for example
    # gen random vector `e_1` from
    # binomial distribution
    e_10 = R([0,1,1,0])
    e_11 = R([0,0,1,0])
    e_1 = M([e_10, e_11]).transpose()
    
    # randomness fixed for example
    # gen random polynomial `e_2` from
    # binomial distribution
    e_2 = R([0,0,-1,-1])

    A, t = public_key
    poly_m = R.decode(m).decompress(1)
    # Check against blogpost
    assert poly_m == R([9,9,0,9])
    
    u = A.transpose() @ r + e_1
    # Check against blogpost
    assert u == M([R([3,10,11,11]), R([11,13,4,4])]).transpose()
    
    # Typo in blog post, we need to use
    # `- m` rather than `+ m` to make values match
    v = (t.transpose() @ r)[0][0] + e_2 - poly_m  
    assert v == R([15, 8 , 6, 7])
    return u, v

def dec(u, v, s):
    m_n = v - (s.transpose() @ u)[0][0]
    # Check against blogpost
    assert m_n == R([5,7,14,7])
    # Check against blogpost
    m_n_reduced = m_n.compress(1)
    assert m_n_reduced == R([1,1,0,1])
    return m_n_reduced.encode(l=2)
    
if __name__ == '__main__':
    R = PolynomialRing(17, 4)
    M = Module(R)
    # Our polynomial encoding follows Kyber spec
    # So we encode the byte `b'E'` to get the
    # polynomial from the blog post
    # >>> R.decode(bytes([69]))
    # 1 + x + x^3
    m = bytes([69])
    assert R.decode(m) == R([1,1,0,1])
    # Generate keypair
    pub, priv = keygen()
    # Encrypt message
    u, v = enc(m, pub)
    # Decrypt message
    n = dec(u, v, priv)
    assert n == m


