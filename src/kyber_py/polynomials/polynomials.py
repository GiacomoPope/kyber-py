from .polynomials_generic import PolynomialRing, Polynomial
from ..utilities.utils import bytes_to_bits, bitstring_to_bytes


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
            pow(root_of_unity, self.br(i, 7), 3329) for i in range(128)
        ]
        self.ntt_f = pow(128, -1, 3329)

    @staticmethod
    def br(i, k):
        """
        bit reversal of an unsigned k-bit integer
        """
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)

    def parse(self, input_bytes, is_ntt=False):
        """
        Algorithm 1 (Parse)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

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
        return self(coefficients, is_ntt=is_ntt)

    def cbd(self, input_bytes, eta, is_ntt=False):
        """
        Algorithm 2 (Centered Binomial Distribution)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Expects a byte array of length (eta * deg / 4)
        For Kyber, this is 64 eta.
        """
        assert 64 * eta == len(input_bytes)
        coefficients = [0 for _ in range(256)]
        list_of_bits = bytes_to_bits(input_bytes)
        for i in range(256):
            a = sum(list_of_bits[eta * 2 * i : eta * (2 * i + 1)])
            b = sum(list_of_bits[eta * (2 * i + 1) : eta * (2 * i + 2)])
            coefficients[i] = (a - b) % 3329
        return self(coefficients, is_ntt=is_ntt)

    def decode(self, input_bytes, l=None, is_ntt=False):
        """
        Decode (Algorithm 3)

        decode: B^32l -> R_q
        """
        if l is None:
            l, check = divmod(8 * len(input_bytes), 256)
            if check != 0:
                raise ValueError(
                    "input bytes must be a multiple of (polynomial degree) / 8"
                )
        else:
            if 256 * l != len(input_bytes) * 8:
                raise ValueError(
                    f"input bytes must be a multiple of (polynomial degree) / 8, {256*l = }, {len(input_bytes)*8 = }"
                )
        coefficients = [0 for _ in range(256)]
        list_of_bits = bytes_to_bits(input_bytes)
        for i in range(256):
            coefficients[i] = sum(
                list_of_bits[i * l + j] << j for j in range(l)
            )
        return self(coefficients, is_ntt=is_ntt)

    def __call__(self, coefficients, is_ntt=False):
        if not is_ntt:
            element = self.element
        else:
            element = self.element_ntt

        if isinstance(coefficients, int):
            return element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(
                f"Polynomials should be constructed from a list of integers, of length at most d = {256}"
            )
        return element(self, coefficients)


class PolynomialKyber(Polynomial):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self.parse_coefficients(coefficients)

    def encode(self, l=None):
        """
        Encode (Inverse of Algorithm 3)
        """
        if l is None:
            l = max(x.bit_length() for x in self.coeffs)
        bit_string = "".join(format(c, f"0{l}b")[::-1] for c in self.coeffs)
        return bitstring_to_bytes(bit_string)

    def compress_ele(self, x, d):
        """
        Compute round((2^d / q) * x) % 2^d
        """
        t = 1 << d
        y = (t * x + 1664) // 3329  # 1664 = 3329 // 2
        return y % t

    def decompress_ele(self, x, d):
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
        self.coeffs = [self.compress_ele(c, d) for c in self.coeffs]
        return self

    def decompress(self, d):
        """
        Decompress the polynomial by decompressing each coefficient
        NOTE: This as compression is lossy, we have
        x' = decompress(compress(x)), which x' != x, but is
        close in magnitude.
        """
        self.coeffs = [self.decompress_ele(c, d) for c in self.coeffs]
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
        raise TypeError(f"Polynomial is of type: {type(self)}")


class PolynomialKyberNTT(PolynomialKyber):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self.parse_coefficients(coefficients)

    def to_ntt(self):
        raise TypeError(f"Polynomial is of type: {type(self)}")

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
    def ntt_base_multiplication(a0, a1, b0, b1, zeta):
        """
        Base case for ntt multiplication
        """
        r0 = (a0 * b0 + zeta * a1 * b1) % 3329
        r1 = (a1 * b0 + a0 * b1) % 3329
        return r0, r1

    def ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        new_coeffs = []
        zetas = self.parent.ntt_zetas
        for i in range(64):
            r0, r1 = self.ntt_base_multiplication(
                f_coeffs[4 * i + 0],
                f_coeffs[4 * i + 1],
                g_coeffs[4 * i + 0],
                g_coeffs[4 * i + 1],
                zetas[64 + i],
            )
            r2, r3 = self.ntt_base_multiplication(
                f_coeffs[4 * i + 2],
                f_coeffs[4 * i + 3],
                g_coeffs[4 * i + 2],
                g_coeffs[4 * i + 3],
                -zetas[64 + i],
            )
            new_coeffs += [r0, r1, r2, r3]
        return new_coeffs

    def ntt_multiplication(self, other):
        """
        Number Theoretic Transform multiplication.
        Only implemented (currently) for n = 256
        """
        if not isinstance(other, type(self)):
            raise ValueError

        new_coeffs = self.ntt_coefficient_multiplication(
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
            new_coeffs = self.ntt_multiplication(other)
        elif isinstance(other, int):
            new_coeffs = [(c * other) % 3329 for c in self.coeffs]
        else:
            raise NotImplementedError(
                f"Polynomials can only be multiplied by each other, or scaled by integers, {type(other) = }, {type(self) = }"
            )
        return self.parent(new_coeffs, is_ntt=True)
