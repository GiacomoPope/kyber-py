import random

class PolynomialRing:
    def __init__(self, q, d):
        self.q = q
        self.d = d
        self.element = PolynomialRing.Polynomial

    def gen(self):
        return self([0,1])

    def random_element(self):
        coefficients = [random.randint(0, self.q - 1) for _ in range(self.d)]
        return self(coefficients)

    def __call__(self, coefficients):
        if isinstance(coefficients, int):
            return self.element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(f"Polynomials should be constructed from a list of integers, of length at most d = {self.d}")
        return self.element(self, coefficients)

    def __repr__(self):
        return f"Univariate Polynomial Ring in x over Finite Field of size {self.q} with modulus x^{self.d} + 1"

        
    class Polynomial:
        def __init__(self, parent, coefficients):
            self.parent = parent
            coefficients = self.parse_coefficients(coefficients)
            self.coeffs = coefficients

        def parse_coefficients(self, coefficients):
            l = len(coefficients)
            if l > self.parent.d:
                raise ValueError(f"Coefficients describe polynomial of degree greater than maximum degree {self.parent.d}")
            elif l < self.parent.d:
                coefficients = coefficients + [0]*(self.parent.d - l)
            return [(c % self.parent.q) for c in coefficients]

        def add_mod_q(self, x, y):
            tmp = x + y
            if tmp >= self.parent.q:
                tmp -= self.parent.q
            return tmp

        def sub_mod_q(self, x, y):
            tmp = x - y
            if tmp < 0:
                tmp += self.parent.q
            return tmp

        def schoolbook_multiplication(self, other):
            d = self.parent.d
            a = self.coeffs
            b = other.coeffs
            new_coeffs = [0]*d
            for i in range(d):
                for j in range(0, d-i):
                    new_coeffs[i+j] += (a[i] * b[j])
            for j in range(1, d):
                for i in range(d-j, d):
                    new_coeffs[i+j-d] -= (a[i] * b[j])
            return [c % self.parent.q for c in new_coeffs]

        def is_zero(self):
            return all(c == 0 for c in self.coeffs)

        def is_constant(self):
            return all(c == 0 for c in self.coeffs[1:])

        def __neg__(self):
            neg_coeffs = [(-x % self.parent.q) for x in self.coeffs]
            return self.parent(neg_coeffs)

        def __add__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                new_coeffs = [self.add_mod_q(x,y) for x,y in zip(self.coeffs, other.coeffs)]
            elif isinstance(other, int):
                new_coeffs = self.coeffs.copy()
                new_coeffs[0] = self.add_mod_q(new_coeffs[0], other)
            else:
                raise NotImplementedError(f"Polynomials can only be added to each other")
            return self.parent(new_coeffs)

        def __radd__(self, other):
            return self.__add__(other)

        def __iadd__(self, other):
            self = self + other
            return self

        def __sub__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                new_coeffs = [self.sub_mod_q(x,y) for x,y in zip(self.coeffs, other.coeffs)]
            elif isinstance(other, int):
                new_coeffs = self.coeffs.copy()
                new_coeffs[0] = self.sub_mod_q(new_coeffs[0], other)
            else:
                raise NotImplementedError(f"Polynomials can only be subracted from each other")
            return self.parent(new_coeffs)

        def __rsub__(self, other):
            return self.__sub__(other)

        def __iadd__(self, other):
            self = self - other
            return self

        def __mul__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                new_coeffs = self.schoolbook_multiplication(other)
            elif isinstance(other, int):
                new_coeffs = [(c * other) % self.parent.q for c in self.coeffs]
            else:
                raise NotImplementedError(f"Polynomials can only be multiplied by each other, or scaled by integers")
            return self.parent(new_coeffs)

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
            g = self.parent(1)
            while n > 0:
                if n % 2 == 1:
                    g = g * f
                f = f * f
                n = n // 2
            return g

        def __eq__(self, other):
            if isinstance(other, PolynomialRing.Polynomial):
                return self.coeffs == other.coeffs
            elif isinstance(other, int):
                if self.is_constant() and (other % self.parent.q) == self.coeffs[0]:
                    return True
            return False

        def __repr__(self):
            if self.is_zero():
                return "0"

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
            return " + ".join(info[::-1])

        def __str__(self):
            return self.__repr__()




