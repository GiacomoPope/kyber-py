from ..utilities.utils import bit_count
from .polynomials_generic import PolynomialRing, Polynomial


class PolynomialRingKyber(PolynomialRing):
    """
    Initialise the polynomial ring:

        R = GF(3329) / (X^256 + 1)
    """

    def __init__(self):
        self.q = 3329
        self.n = 256
        self.element = PolynomialKyber
        self.element_ntt = PolynomialKyberNTT

        root_of_unity = 17
        self.ntt_zetas = [
            pow(root_of_unity, self._br(i, 7), 3329) for i in range(128)
        ]
        self.ntt_f = pow(128, -1, 3329)

    @staticmethod
    def _br(i, k):
        """
        bit reversal of an unsigned k-bit integer
        """
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)

    def ntt_sample(self, input_bytes):
        """
        Algorithm 1 (Parse)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Algorithm 6 (Sample NTT)

        Parse: B^* -> R
        """
        i, j = 0, 0
        coefficients = [0 for _ in range(self.n)]
        while j < self.n:
            d1 = input_bytes[i] + 256 * (input_bytes[i + 1] % 16)
            d2 = (input_bytes[i + 1] // 16) + 16 * input_bytes[i + 2]

            if d1 < 3329:
                coefficients[j] = d1
                j = j + 1

            if d2 < 3329 and j < self.n:
                coefficients[j] = d2
                j = j + 1

            i = i + 3
        return self(coefficients, is_ntt=True)

    def cbd(self, input_bytes, eta, is_ntt=False):
        """
        Algorithm 2 (Centered Binomial Distribution)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Algorithm 6 (Sample Poly CBD)

        Expects a byte array of length (eta * deg / 4)
        For Kyber, this is 64 eta.
        """
        assert 64 * eta == len(input_bytes)
        coefficients = [0 for _ in range(256)]
        b_int = int.from_bytes(input_bytes, "little")
        mask = (1 << eta) - 1
        mask2 = (1 << 2 * eta) - 1
        for i in range(256):
            x = b_int & mask2
            a = bit_count(x & mask)
            b = bit_count((x >> eta) & mask)
            b_int >>= 2 * eta
            coefficients[i] = (a - b) % 3329
        return self(coefficients, is_ntt=is_ntt)

    def decode(self, input_bytes, d, is_ntt=False):
        """
        Decode (Algorithm 3)

        decode: B^32l -> R_q
        """
        # Ensure the value d is set correctly
        if 256 * d != len(input_bytes) * 8:
            raise ValueError(
                f"input bytes must be a multiple of (polynomial degree) / 8, {256*d = }, {len(input_bytes)*8 = }"
            )

        # Set the modulus
        if d == 12:
            m = 3329
        else:
            m = 1 << d

        coeffs = [0 for _ in range(256)]
        b_int = int.from_bytes(input_bytes, "little")
        mask = (1 << d) - 1
        for i in range(256):
            coeffs[i] = (b_int & mask) % m
            b_int >>= d

        return self(coeffs, is_ntt=is_ntt)

    def __call__(self, coefficients, is_ntt=False):
        if not is_ntt:
            element = self.element
        else:
            element = self.element_ntt

        if isinstance(coefficients, int):
            return element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(
                f"Polynomials should be constructed from a list of integers, of length at most n = {256}"
            )
        return element(self, coefficients)


class PolynomialKyber(Polynomial):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    def encode(self, d):
        """
        Encode (Inverse of Algorithm 3)
        """
        t = 0
        for i in range(255):
            t |= self.coeffs[256 - i - 1]
            t <<= d
        t |= self.coeffs[0]
        return t.to_bytes(32 * d, "little")

    def _compress_ele(self, x, d):
        """
        Compute round((2^d / q) * x) % 2^d
        """
        t = 1 << d
        y = (t * x + 1664) // 3329  # 1664 = 3329 // 2
        return y % t

    def _decompress_ele(self, x, d):
        """
        Compute round((q / 2^d) * x)
        """
        t = 1 << (d - 1)
        y = (3329 * x + t) >> d
        return y

    def compress(self, d):
        """
        Compress the polynomial by compressing each coefficient

        NOTE: This is lossy compression
        """
        self.coeffs = [self._compress_ele(c, d) for c in self.coeffs]
        return self

    def decompress(self, d):
        """
        Decompress the polynomial by decompressing each coefficient

        NOTE: This as compression is lossy, we have
        x' = decompress(compress(x)), which x' != x, but is
        close in magnitude.
        """
        self.coeffs = [self._decompress_ele(c, d) for c in self.coeffs]
        return self

    def to_ntt(self):
        """
        Convert a polynomial to number-theoretic transform (NTT) form.
        The input is in standard order, the output is in bit-reversed order.
        """
        k, l = 1, 128
        coeffs = self.coeffs
        zetas = self.parent.ntt_zetas
        while l >= 2:
            start = 0
            while start < 256:
                zeta = zetas[k]
                k = k + 1
                for j in range(start, start + l):
                    t = zeta * coeffs[j + l]
                    coeffs[j + l] = coeffs[j] - t
                    coeffs[j] = coeffs[j] + t
                start = l + (j + 1)
            l = l >> 1

        for j in range(256):
            coeffs[j] = coeffs[j] % 3329

        return self.parent(coeffs, is_ntt=True)

    def from_ntt(self):
        """
        Not supported, raises a ``TypeError``
        """
        raise TypeError(f"Polynomial not in the NTT domain: {type(self) = }")


class PolynomialKyberNTT(PolynomialKyber):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    def to_ntt(self):
        """
        Not supported, raises a ``TypeError``
        """
        raise TypeError(
            f"Polynomial is already in the NTT domain: {type(self) = }"
        )

    def from_ntt(self):
        """
        Convert a polynomial from number-theoretic transform (NTT) form in place
        The input is in bit-reversed order, the output is in standard order.
        """
        l, l_upper = 2, 128
        k = l_upper - 1
        coeffs = self.coeffs
        zetas = self.parent.ntt_zetas
        while l <= 128:
            start = 0
            while start < 256:
                zeta = zetas[k]
                k = k - 1
                for j in range(start, start + l):
                    t = coeffs[j]
                    coeffs[j] = t + coeffs[j + l]
                    coeffs[j + l] = coeffs[j + l] - t
                    coeffs[j + l] = zeta * coeffs[j + l]
                start = j + l + 1
            l = l << 1

        f = self.parent.ntt_f
        for j in range(256):
            coeffs[j] = (coeffs[j] * f) % 3329

        return self.parent(coeffs, is_ntt=False)

    @staticmethod
    def _ntt_base_multiplication(a0, a1, b0, b1, zeta):
        """
        Base case for ntt multiplication
        """
        r0 = (a0 * b0 + zeta * a1 * b1) % 3329
        r1 = (a1 * b0 + a0 * b1) % 3329
        return r0, r1

    def _ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        """
        Given the coefficients of two polynomials compute the coefficients of
        their product
        """
        new_coeffs = []
        zetas = self.parent.ntt_zetas
        for i in range(64):
            r0, r1 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 0],
                f_coeffs[4 * i + 1],
                g_coeffs[4 * i + 0],
                g_coeffs[4 * i + 1],
                zetas[64 + i],
            )
            r2, r3 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 2],
                f_coeffs[4 * i + 3],
                g_coeffs[4 * i + 2],
                g_coeffs[4 * i + 3],
                -zetas[64 + i],
            )
            new_coeffs += [r0, r1, r2, r3]
        return new_coeffs

    def _ntt_multiplication(self, other):
        """
        Number Theoretic Transform multiplication.
        """
        new_coeffs = self._ntt_coefficient_multiplication(
            self.coeffs, other.coeffs
        )
        return new_coeffs

    def __add__(self, other):
        new_coeffs = self._add_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __sub__(self, other):
        new_coeffs = self._sub_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __mul__(self, other):
        if isinstance(other, type(self)):
            new_coeffs = self._ntt_multiplication(other)
        elif isinstance(other, int):
            new_coeffs = [(c * other) % 3329 for c in self.coeffs]
        else:
            raise NotImplementedError(
                f"Polynomials can only be multiplied by each other, or scaled by integers, {type(other) = }, {type(self) = }"
            )
        return self.parent(new_coeffs, is_ntt=True)
