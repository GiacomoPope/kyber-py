import random
from utils import *

class PolynomialRing:
    """
    Initialise the polynomial ring:
        
        R = GF(q) / (X^n + 1) 
    """
    def __init__(self, q, n, ntt_helper=None):
        self.q = q
        self.n = n
        self.element = PolynomialRing.Polynomial
        self.ntt_helper = ntt_helper

    def gen(self, is_ntt=False):
        return self([0,1], is_ntt=is_ntt)

    def random_element(self, is_ntt=False):
        coefficients = [random.randint(0, self.q - 1) for _ in range(self.n)]
        return self(coefficients, is_ntt=is_ntt)
        
    def parse(self, input_bytes, is_ntt=False):
        """
        Algorithm 1 (Parse)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Parse: B^* -> R
        """
        i, j = 0, 0
        coefficients = [0 for _ in range(self.n)]
        while j < self.n:
            d1 = input_bytes[i] + 256*(input_bytes[i+1] % 16)
            d2 = (input_bytes[i+1] // 16) + 16*input_bytes[i+2]
            
            if d1 < self.q:
                coefficients[j] = d1
                j = j + 1
            
            if d2 < self.q and j < self.n:
                coefficients[j] = d2
                j = j + 1
                
            i = i + 3
        return self(coefficients, is_ntt=is_ntt)      
        
    def cbd(self, input_bytes, eta, is_ntt=False):
        """
        Algorithm 2 (Centered Binomial Distribution)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Expects a byte array of length (eta * deg / 4)
        For Kyber, this is 64 eta.
        """
        assert (self.n >> 2)*eta == len(input_bytes)
        coefficients = [0 for _ in range(self.n)]
        list_of_bits = bytes_to_bits(input_bytes)
        for i in range(self.n):
            a = sum(list_of_bits[2*i*eta + j]       for j in range(eta))
            b = sum(list_of_bits[2*i*eta + eta + j] for j in range(eta))
            coefficients[i] = a-b
        return self(coefficients, is_ntt=is_ntt)
        
    def decode(self, input_bytes, l=None, is_ntt=False):
        """
        Decode (Algorithm 3)
        
        decode: B^32l -> R_q
        """
        if l is None:
            l, check = divmod(8*len(input_bytes), self.n)
            if check != 0:
                raise ValueError("input bytes must be a multiple of (polynomial degree) / 8")
        else:
            if self.n*l != len(input_bytes)*8:
                raise ValueError("input bytes must be a multiple of (polynomial degree) / 8")
        coefficients = [0 for _ in range(self.n)]
        list_of_bits = bytes_to_bits(input_bytes)
        for i in range(self.n):
            coefficients[i] = sum(list_of_bits[i*l + j] << j for j in range(l))
        return self(coefficients, is_ntt=is_ntt)
            
    def __call__(self, coefficients, is_ntt=False):
        if isinstance(coefficients, int):
            return self.element(self, [coefficients], is_ntt)
        if not isinstance(coefficients, list):
            raise TypeError(f"Polynomials should be constructed from a list of integers, of length at most d = {self.n}")
        return self.element(self, coefficients, is_ntt)

    def __repr__(self):
        return f"Univariate Polynomial Ring in x over Finite Field of size {self.q} with modulus x^{self.n} + 1"

    class Polynomial:
        def __init__(self, parent, coefficients, is_ntt=False):
            self.parent = parent
            self.coeffs = self.parse_coefficients(coefficients)
            self.is_ntt = is_ntt

        def is_zero(self):
            """
            Return if polynomial is zero: f = 0
            """
            return all(c == 0 for c in self.coeffs)

        def is_constant(self):
            """
            Return if polynomial is constant: f = c
            """
            return all(c == 0 for c in self.coeffs[1:])
            
        def parse_coefficients(self, coefficients):
            """
            Helper function which right pads with zeros
            to allow polynomial construction as 
            f = R([1,1,1])
            """
            l = len(coefficients)
            if l > self.parent.n:
                raise ValueError(f"Coefficients describe polynomial of degree greater than maximum degree {self.parent.n}")
            elif l < self.parent.n:
                coefficients = coefficients + [0 for _ in range (self.parent.n - l)]
            return coefficients
            
        def reduce_coefficents(self):
            """
            Reduce all coefficents modulo q
            """
            self.coeffs = [c % self.parent.q for c in self.coeffs]
            return self
 
        def encode(self, l=None):
            """
            Encode (Inverse of Algorithm 3)
            """
            if l is None:
                l = max(x.bit_length() for x in self.coeffs)
            bit_string = ''.join(format(c, f'0{l}b')[::-1] for c in self.coeffs)
            return bitstring_to_bytes(bit_string)
            
        def compress(self, d):
            """
            Compress the polynomial by compressing each coefficent
            NOTE: This is lossy compression
            """
            compress_mod   = 2**d
            compress_float = compress_mod / self.parent.q
            self.coeffs = [round_up(compress_float * c) % compress_mod for c in self.coeffs]
            return self
            
        def decompress(self, d):
            """
            Decompress the polynomial by decompressing each coefficent
            NOTE: This as compression is lossy, we have
            x' = decompress(compress(x)), which x' != x, but is 
            close in magnitude.
            """
            decompress_float = self.parent.q / 2**d
            self.coeffs = [round_up(decompress_float * c) for c in self.coeffs ]
            return self
                
        def add_mod_q(self, x, y):
            """
            add two coefficents modulo q
            """
            tmp = x + y
            if tmp >= self.parent.q:
                tmp -= self.parent.q
            return tmp

        def sub_mod_q(self, x, y):
            """
            sub two coefficents modulo q
            """
            tmp = x - y
            if tmp < 0:
                tmp += self.parent.q
            return tmp
            
        def schoolbook_multiplication(self, other):
            """
            Naive implementation of polynomial multiplication
            suitible for all R_q = F_1[X]/(X^n + 1)
            """
            n = self.parent.n
            a = self.coeffs
            b = other.coeffs
            new_coeffs = [0 for _ in range(n)]
            for i in range(n):
                for j in range(0, n-i):
                    new_coeffs[i+j] += (a[i] * b[j])
            for j in range(1, n):
                for i in range(n-j, n):
                    new_coeffs[i+j-n] -= (a[i] * b[j])
            return [c % self.parent.q for c in new_coeffs]
        
        """
        The next four `Polynomial` methods rely on the parent
        `PolynomialRing` having a  `ntt_helper` from 
        ntt_helper.py and are used for NTT speediness.
        """
        def to_ntt(self):
            if self.parent.ntt_helper is None:
                raise ValueError("Can only perform NTT transform when parent element has an NTT Helper")
            return self.parent.ntt_helper.to_ntt(self)
        
        def from_ntt(self):
            if self.parent.ntt_helper is None:
                raise ValueError("Can only perform NTT transform when parent element has an NTT Helper")
            return self.parent.ntt_helper.from_ntt(self)
            
        def to_montgomery(self):
            """
            Multiply every element by 2^16 mod q
            
            Only implemented (currently) for n = 256
            """
            if self.parent.ntt_helper is None:
                raise ValueError("Can only perform Mont. reduction when parent element has an NTT Helper")
            return self.parent.ntt_helper.to_montgomery(self)
        
        def ntt_multiplication(self, other):
            """
            Number Theoretic Transform multiplication.
            Only implemented (currently) for n = 256
            """
            if self.parent.ntt_helper is None:
                raise ValueError("Can only perform ntt reduction when parent element has an NTT Helper")
            if not (self.is_ntt and other.is_ntt):
                raise ValueError("Can only multiply using NTT if both polynomials are in NTT form")
            # function in ntt_helper.py
            new_coeffs = self.parent.ntt_helper.ntt_coefficient_multiplication(self.coeffs, other.coeffs)
            return self.parent(new_coeffs, is_ntt=True)

        def __neg__(self):
            """
            Returns -f, by negating all coefficients
            """
            neg_coeffs = [(-x % self.parent.q) for x in self.coeffs]
            return self.parent(neg_coeffs, is_ntt=self.is_ntt)

        def __add__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                if self.is_ntt ^ other.is_ntt:                    
                    raise ValueError(f"Both or neither polynomials must be in NTT form before multiplication")
                new_coeffs = [self.add_mod_q(x,y) for x,y in zip(self.coeffs, other.coeffs)]
            elif isinstance(other, int):
                new_coeffs = self.coeffs.copy()
                new_coeffs[0] = self.add_mod_q(new_coeffs[0], other)
            else:
                raise NotImplementedError(f"Polynomials can only be added to each other")
            return self.parent(new_coeffs, is_ntt=self.is_ntt)

        def __radd__(self, other):
            return self.__add__(other)

        def __iadd__(self, other):
            self = self + other
            return self

        def __sub__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                if self.is_ntt ^ other.is_ntt:
                    raise ValueError(f"Both or neither polynomials must be in NTT form before multiplication")
                new_coeffs = [self.sub_mod_q(x,y) for x,y in zip(self.coeffs, other.coeffs)]
            elif isinstance(other, int):
                new_coeffs = self.coeffs.copy()
                new_coeffs[0] = self.sub_mod_q(new_coeffs[0], other)
            else:
                raise NotImplementedError(f"Polynomials can only be subracted from each other")
            return self.parent(new_coeffs, is_ntt=self.is_ntt)

        def __rsub__(self, other):
            return self.__sub__(other)

        def __isub__(self, other):
            self = self - other
            return self

        def __mul__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                if self.is_ntt and other.is_ntt:
                    return self.ntt_multiplication(other)
                elif self.is_ntt ^ other.is_ntt:
                     raise ValueError(f"Both or neither polynomials must be in NTT form before multiplication")
                else:
                    new_coeffs = self.schoolbook_multiplication(other)
            elif isinstance(other, int):
                new_coeffs = [(c * other) % self.parent.q for c in self.coeffs]
            else:
                raise NotImplementedError(f"Polynomials can only be multiplied by each other, or scaled by integers")
            return self.parent(new_coeffs, is_ntt=self.is_ntt)

        def __rmul__(self, other):
            return self.__mul__(other)

        def __imul__(self, other):
            self = self * other
            return self

        def __pow__(self, n):
            if not isinstance(n, int):
                raise TypeError(f"Exponentiation of a polynomial must be done using an integer.")

            # Deal with negative scalar multiplication
            if n < 0:
                raise ValueError(f"Negative powers are not supported for elements of a Polynomial Ring")
            f = self
            g = self.parent(1, is_ntt=self.is_ntt)
            while n > 0:
                if n % 2 == 1:
                    g = g * f
                f = f * f
                n = n // 2
            return g

        def __eq__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                return self.coeffs == other.coeffs and self.is_ntt == other.is_ntt
            elif isinstance(other, int):
                if self.is_constant() and (other % self.parent.q) == self.coeffs[0]:
                    return True
            return False

        def __getitem__(self, idx):
            return self.coeffs[idx]

        def __repr__(self):
            ntt_info = ""
            if self.is_ntt:
                ntt_info = " (NTT form)"
            if self.is_zero():
                return "0" + ntt_info

            info = []
            for i,c in enumerate(self.coeffs):
                if c != 0:
                    if i == 0:
                        info.append(f"{c}")
                    elif i == 1:
                        if c == 1:
                            info.append("x")
                        else:
                            info.append(f"{c}*x")
                    else:
                        if c == 1:
                            info.append(f"x^{i}")
                        else:
                            info.append(f"{c}*x^{i}")
            return " + ".join(info) + ntt_info

        def __str__(self):
            return self.__repr__()