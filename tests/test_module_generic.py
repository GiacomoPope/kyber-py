import unittest
from random import randint
from kyber_py.polynomials.polynomials_generic import PolynomialRing
from kyber_py.modules.modules_generic import Module


class TestModule(unittest.TestCase):
    R = PolynomialRing(11, 5)
    M = Module(R)

    def test_random_element(self):
        for _ in range(100):
            m = randint(1, 5)
            n = randint(1, 5)
            A = self.M.random_element(m, n)
            self.assertEqual(type(A), self.M.matrix)
            self.assertEqual(type(A[0, 0]), self.R.element)
            self.assertEqual(A.dim(), (m, n))


class TestMatrix(unittest.TestCase):
    R = PolynomialRing(11, 5)
    M = Module(R)

    def test_matrix_add(self):
        zero = self.R(0)
        Z = self.M([[zero, zero], [zero, zero]])
        for _ in range(100):
            A = self.M.random_element(2, 2)
            B = self.M.random_element(2, 2)
            C = self.M.random_element(2, 2)

            self.assertEqual(A + Z, A)
            self.assertEqual(A + B, B + A)
            self.assertEqual(A + (B + C), (A + B) + C)

    def test_matrix_sub(self):
        zero = self.R(0)
        Z = self.M([[zero, zero], [zero, zero]])
        for _ in range(100):
            A = self.M.random_element(2, 2)
            B = self.M.random_element(2, 2)
            C = self.M.random_element(2, 2)

            self.assertEqual(A - Z, A)
            self.assertEqual(A - B, -(B - A))
            self.assertEqual(A - (B - C), (A - B) + C)

    def test_matrix_mul_square(self):
        zero = self.R(0)
        one = self.R(1)
        Z = self.M([[zero, zero], [zero, zero]])
        I = self.M([[one, zero], [zero, one]])
        for _ in range(100):
            A = self.M.random_element(2, 2)
            B = self.M.random_element(2, 2)
            C = self.M.random_element(2, 2)
            d = self.R.random_element()
            D = self.M([[d, zero], [zero, d]])

            self.assertEqual(A @ Z, Z)
            self.assertEqual(A @ I, A)
            self.assertEqual(A @ D, D @ A)  # Diagonal matrices commute
            self.assertEqual(A @ (B + C), A @ B + A @ C)

    def test_matrix_mul_rectangle(self):
        for _ in range(100):
            A = self.M.random_element(7, 3)
            B = self.M.random_element(3, 2)
            C = self.M.random_element(3, 2)

            self.assertEqual(A @ (B + C), A @ B + A @ C)

    def test_matrix_transpose_id(self):
        zero = self.R(0)
        one = self.R(1)
        I = self.M([[one, zero], [zero, one]])

        self.assertEqual(I, I.transpose())

    def test_matrix_transpose(self):
        for _ in range(100):
            A = self.M.random_element(7, 3)
            At = A.transpose()
            AAt = A @ At

            self.assertEqual(AAt, AAt.transpose())

    def test_matrix_dot(self):
        for _ in range(100):
            u = [self.R.random_element() for _ in range(5)]
            v = [self.R.random_element() for _ in range(5)]
            dot = sum([ui * vi for ui, vi in zip(u, v)])

            U = self.M.vector(u)
            V = self.M.vector(v)

            self.assertEqual(dot, U.dot(V))


if __name__ == "__main__":
    unittest.main()
