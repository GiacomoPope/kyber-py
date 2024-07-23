import unittest
from random import randint
from kyber_py.polynomials.polynomials_generic import PolynomialRing


class TestPolynomialRing(unittest.TestCase):
    R = PolynomialRing(11, 5)

    def test_gen(self):
        self.assertTrue(self.R.gen() == self.R([0, 1]))

    def test_random_element(self):
        for _ in range(100):
            f = self.R.random_element()
            self.assertEqual(type(f), self.R.element)
            self.assertEqual(len(f.coeffs), self.R.n)
            self.assertTrue(all([c < self.R.q for c in f.coeffs]))


class TestPolynomial(unittest.TestCase):
    R = PolynomialRing(11, 5)

    def test_is_zero(self):
        self.assertTrue(self.R(0).is_zero())
        self.assertFalse(self.R(1).is_zero())

    def test_is_constant(self):
        self.assertTrue(self.R(0).is_constant())
        self.assertTrue(self.R(1).is_constant())
        self.assertFalse(self.R.gen().is_constant())

    def test_reduce_coefficents(self):
        for _ in range(100):
            # Create non-canonical coefficients
            coeffs = [
                randint(-2 * self.R.q, 3 * self.R.q) for _ in range(self.R.n)
            ]
            f = self.R(coeffs).reduce_coefficients()
            self.assertTrue(all([c < self.R.q for c in f.coeffs]))

    def test_add_polynomials(self):
        zero = self.R(0)
        for _ in range(100):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 + zero, f1)
            self.assertEqual(f1 + f2, f2 + f1)
            self.assertEqual(f1 + (f2 + f3), (f1 + f2) + f3)

    def test_sub_polynomials(self):
        zero = self.R(0)
        for _ in range(100):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 - zero, f1)
            self.assertEqual(f3 - f3, zero)
            self.assertEqual(f1 - f2, -(f2 - f1))
            self.assertEqual(f1 - (f2 - f3), (f1 - f2) + f3)

    def test_mul_polynomials(self):
        zero = self.R(0)
        one = self.R(1)
        for _ in range(100):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 * zero, zero)
            self.assertEqual(f1 * one, f1)
            self.assertEqual(f1 * f2, f2 * f1)
            self.assertEqual(f1 * (f2 * f3), (f1 * f2) * f3)

    def test_pow_polynomials(self):
        one = self.R(1)
        for _ in range(100):
            f1 = self.R.random_element()

            self.assertEqual(one, f1**0)
            self.assertEqual(f1, f1**1)
            self.assertEqual(f1 * f1, f1**2)
            self.assertEqual(f1 * f1 * f1, f1**3)
            self.assertRaises(ValueError, lambda: f1 ** (-1))


if __name__ == "__main__":
    unittest.main()
