import unittest
from kyber_py.polynomials.polynomials import PolynomialRingKyber


class TestModuleKyber(unittest.TestCase):
    R = PolynomialRingKyber()

    def test_decode(self):
        for _ in range(10):
            f = self.R.random_element()
            f_bytes = f.encode(12)
            self.assertEqual(f, self.R.decode(f_bytes, 12))

    def test_decode_wrong_length(self):
        self.assertRaises(ValueError, lambda: self.R.decode(b"1", 12))

    def test_call(self):
        self.assertEqual(1, self.R(1))
        self.assertRaises(TypeError, lambda: self.R("a"))


class TestPolynomial(unittest.TestCase):
    R = PolynomialRingKyber()

    def test_ntt_transform(self):
        f = self.R.random_element()
        g_hat = self.R.random_element().to_ntt()

        self.assertEqual(f, f.to_ntt().from_ntt())
        self.assertEqual(g_hat, g_hat.from_ntt().to_ntt())

        self.assertRaises(TypeError, lambda: f.from_ntt())
        self.assertRaises(TypeError, lambda: g_hat.to_ntt())

    def test_add_failure(self):
        f1 = self.R.random_element()
        self.assertRaises(NotImplementedError, lambda: f1 + "a")

    def test_sub_failure(self):
        f1 = self.R.random_element()
        self.assertRaises(NotImplementedError, lambda: f1 - "a")

    def test_mul_failure(self):
        f1 = self.R.random_element()
        self.assertRaises(NotImplementedError, lambda: f1 * "a")

    def test_pow_failure(self):
        f1 = self.R.random_element()
        self.assertRaises(TypeError, lambda: f1 ** "a")

    def test_add_polynomials(self):
        zero = self.R(0)
        for _ in range(10):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 + zero, f1)
            self.assertEqual(f1 + f2, f2 + f1)
            self.assertEqual(f1 + (f2 + f3), (f1 + f2) + f3)

            f2 = f1
            f2 += f1
            self.assertEqual(f1 + f1, f2)

    def test_sub_polynomials(self):
        zero = self.R(0)
        for _ in range(10):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 - zero, f1)
            self.assertEqual(f3 - f3, zero)
            self.assertEqual(f3 - 0, f3)
            self.assertEqual(0 - f3, -f3)
            self.assertEqual(f1 - f2, -(f2 - f1))
            self.assertEqual(f1 - (f2 - f3), (f1 - f2) + f3)

            f2 = f1
            f2 -= f1
            self.assertEqual(f2, zero)

    def test_mul_polynomials(self):
        zero = self.R(0)
        one = self.R(1)
        for _ in range(10):
            f1 = self.R.random_element()
            f2 = self.R.random_element()
            f3 = self.R.random_element()

            self.assertEqual(f1 * zero, zero)
            self.assertEqual(f1 * one, f1)
            self.assertEqual(f1 * f2, f2 * f1)
            self.assertEqual(f1 * (f2 * f3), (f1 * f2) * f3)
            self.assertEqual(2 * f1, f1 + f1)
            self.assertEqual(2 * f1, f1 * 2)

            f2 = f1
            f2 *= f2
            self.assertEqual(f1 * f1, f2)

    def test_pow_polynomials(self):
        one = self.R(1)
        for _ in range(10):
            f1 = self.R.random_element()

            self.assertEqual(one, f1**0)
            self.assertEqual(f1, f1**1)
            self.assertEqual(f1 * f1, f1**2)
            self.assertEqual(f1 * f1 * f1, f1**3)
            self.assertRaises(ValueError, lambda: f1 ** (-1))

    def test_add_failure_ntt(self):
        f1 = self.R.random_element().to_ntt()
        self.assertRaises(NotImplementedError, lambda: f1 + "a")

    def test_sub_failure_ntt(self):
        f1 = self.R.random_element().to_ntt()
        self.assertRaises(NotImplementedError, lambda: f1 - "a")

    def test_mul_failure_ntt(self):
        f1 = self.R.random_element().to_ntt()
        self.assertRaises(NotImplementedError, lambda: f1 * "a")

    def test_pow_failure_ntt(self):
        f1 = self.R.random_element().to_ntt()
        self.assertRaises(TypeError, lambda: f1 ** "a")

    def test_add_polynomials_ntt(self):
        zero_hat = self.R(0).to_ntt()
        for _ in range(10):
            f1_hat = self.R.random_element().to_ntt()
            f2_hat = self.R.random_element().to_ntt()
            f3_hat = self.R.random_element().to_ntt()

            self.assertEqual(f1_hat + zero_hat, f1_hat)
            self.assertEqual(f1_hat + f2_hat, f2_hat + f1_hat)
            self.assertEqual(
                f1_hat + (f2_hat + f3_hat), (f1_hat + f2_hat) + f3_hat
            )

            f2_hat = f1_hat
            f2_hat += f1_hat
            self.assertEqual(f1_hat + f1_hat, f2_hat)

    def test_sub_polynomials_ntt(self):
        zero_hat = self.R(0).to_ntt()
        for _ in range(10):
            f1_hat = self.R.random_element().to_ntt()
            f2_hat = self.R.random_element().to_ntt()
            f3_hat = self.R.random_element().to_ntt()

            self.assertEqual(f1_hat - zero_hat, f1_hat)
            self.assertEqual(f3_hat - f3_hat, zero_hat)
            self.assertEqual(f3_hat - 0, f3_hat)
            self.assertEqual(0 - f3_hat, -f3_hat)
            self.assertEqual(
                f1_hat - (f2_hat - f3_hat), (f1_hat - f2_hat) + f3_hat
            )

            f2_hat = f1_hat
            f2_hat -= f1_hat
            self.assertEqual(f2_hat, zero_hat)

    def test_mul_polynomials_ntt(self):
        zero_hat = self.R(0).to_ntt()
        one_hat = self.R(1).to_ntt()
        for _ in range(10):
            f1_hat = self.R.random_element().to_ntt()
            f2_hat = self.R.random_element().to_ntt()
            f3_hat = self.R.random_element().to_ntt()

            self.assertEqual(f1_hat * zero_hat, zero_hat)
            self.assertEqual(f1_hat * one_hat, f1_hat)
            self.assertEqual(f1_hat * f2_hat, f2_hat * f1_hat)
            self.assertEqual(
                f1_hat * (f2_hat * f3_hat), (f1_hat * f2_hat) * f3_hat
            )
            self.assertEqual(2 * f1_hat, f1_hat + f1_hat)
            self.assertEqual(2 * f1_hat, f1_hat * 2)

            f2_hat = f1_hat
            f2_hat *= f2_hat
            self.assertEqual(f1_hat * f1_hat, f2_hat)
