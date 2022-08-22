from polynomials import *
from modules import *

def round_up(x):
    """
    Round x.5 up always
    """
    return int(x + .5)

def closer_to(x, y):
    return abs(x - y) < (y/2)

def poly_from_integer(m):
    m_bin = list(map(int, list(bin(m)[2:][::-1])))
    m_poly = R(m_bin)
    m_scale = round_up(m_poly.parent.q / 2)
    return m_scale * m_poly

def integer_from_poly(p):
    middle = round_up(p.parent.q / 2)
    binary = ["1" if closer_to(x,middle) else "0" for x in p.coeffs]
    return int("".join(binary[::-1]), 2)

def keygen():
    # Randomness fixed for example
    s0 = R([0,1,-1,-1])
    s1 = R([0,-1,0,-1])
    s = M([s0,s1]).transpose()

    # Randomness fixed for example
    A00 = R([11,16,16,6])
    A01 = R([3,6,4,9])
    A10 = R([1,10,3,5])
    A11 = R([15,9,1,6])
    A = M([[A00, A01],[A10, A11]])

    # Randomness fixed for example
    e0 = R([0,0,1,0])
    e1 = R([0,-1,1,0])
    e = M([e0,e1]).transpose()

    t = A @ s + e
    return (A, t), s

def encrypt(m, public_key):
    # randomness fixed for
    # this example...
    # gen r
    r0 = R([0,0,1,-1]) 
    r1 = R([-1,0,1,1])
    r = M([r0, r1]).transpose()
    # gen e1, e2
    e_10 = R([0,1,1,0])
    e_11 = R([0,0,1,0])
    e_1 = M([e_10, e_11]).transpose()
    e_2 = R([0,0,-1,-1])

    A, t = public_key
    encoded_message = poly_from_integer(m)
    u = A.transpose() @ r + e_1
    v = (t.transpose() @ r)[0][0] + e_2 + encoded_message
    return u, v

def decrypt(u, v, private_key):
    s = private_key
    m_n = v - (s.transpose() @ u)[0][0]
    return integer_from_poly(m_n)
    
if __name__ == '__main__':
    # for m in range(3,15):
    #     R = PolynomialRing(17, 4)
    #     M = Module(R)
    #     pub, priv = keygen()
    #     u, v = encrypt(m, pub)
    #     n = decrypt(u, v, priv)
    #     assert n == m, f"{n,m}"
        
    R = PolynomialRing(17, 16)
    M = Module(R)


