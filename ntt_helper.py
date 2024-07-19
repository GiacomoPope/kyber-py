NTT_PARAMETERS = {
    "kyber": {"q": 3329, "root_of_unity": 17},
}


class NTTHelper:
    def __init__(self, parameter_set):
        root_of_unity = parameter_set["root_of_unity"]
        self.q = parameter_set["q"]
        self.zetas = [
            pow(root_of_unity, self.br(i, 7), self.q) for i in range(128)
        ]
        self.f = pow(128, -1, self.q)

    @staticmethod
    def br(i, k):
        """
        bit reversal of an unsigned k-bit integer
        """
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)

    def ntt_base_multiplication(self, a0, a1, b0, b1, zeta):
        """
        Base case for ntt multiplication
        """
        r0 = (zeta * a1 * b1 + a0 * b0) % self.q
        r1 = (a1 * b0 + a0 * b1) % self.q
        return r0, r1

    def ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        new_coeffs = []
        for i in range(64):
            r0, r1 = self.ntt_base_multiplication(
                f_coeffs[4 * i + 0],
                f_coeffs[4 * i + 1],
                g_coeffs[4 * i + 0],
                g_coeffs[4 * i + 1],
                self.zetas[64 + i],
            )
            r2, r3 = self.ntt_base_multiplication(
                f_coeffs[4 * i + 2],
                f_coeffs[4 * i + 3],
                g_coeffs[4 * i + 2],
                g_coeffs[4 * i + 3],
                -self.zetas[64 + i],
            )
            new_coeffs += [r0, r1, r2, r3]
        return new_coeffs

    def to_ntt(self, poly):
        """
        Convert a polynomial to number-theoretic transform (NTT) form in place
        The input is in standard order, the output is in bit-reversed order.
        """
        if poly.is_ntt:
            raise ValueError("Cannot convert NTT form polynomial to NTT form")

        k, l = 1, 128
        coeffs = poly.coeffs
        while l >= 2:
            start = 0
            while start < 256:
                zeta = self.zetas[k]
                k = k + 1
                for j in range(start, start + l):
                    t = zeta * coeffs[j + l]
                    coeffs[j + l] = coeffs[j] - t
                    coeffs[j] = coeffs[j] + t
                start = l + (j + 1)
            l = l >> 1

        for j in range(poly.parent.n):
            coeffs[j] = coeffs[j] % self.q

        poly.is_ntt = True
        return poly

    def from_ntt(self, poly):
        """
        Convert a polynomial from number-theoretic transform (NTT) form in place
        The input is in bit-reversed order, the output is in standard order.
        """
        if not poly.is_ntt:
            raise ValueError("Can only convert from a polynomial in NTT form")

        l, l_upper = 2, 128
        k = l_upper - 1
        coeffs = poly.coeffs
        while l <= 128:
            start = 0
            while start < poly.parent.n:
                zeta = self.zetas[k]
                k = k - 1
                for j in range(start, start + l):
                    t = coeffs[j]
                    coeffs[j] = t + coeffs[j + l]
                    coeffs[j + l] = coeffs[j + l] - t
                    coeffs[j + l] = zeta * coeffs[j + l]
                start = j + l + 1
            l = l << 1

        for j in range(poly.parent.n):
            coeffs[j] = coeffs[j] * self.f % self.q

        poly.is_ntt = False
        return poly


NTTHelperKyber = NTTHelper(NTT_PARAMETERS["kyber"])
