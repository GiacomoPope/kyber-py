import unittest
from ml_kem import ML_KEM128, ML_KEM192, ML_KEM256


class TestML_KEM(unittest.TestCase):
    """
    Test ML_KEM levels for internal
    consistency by generating key pairs
    and shared secrets.
    """

    def generic_test_ML_KEM(self, ML_KEM, count):
        for _ in range(count):
            (ek, dk) = ML_KEM.keygen()
            for _ in range(count):
                (K, c) = ML_KEM.encaps(ek)
                K_prime = ML_KEM.decaps(c, dk)
                self.assertEqual(K, K_prime)

    def test_ML_KEM128(self):
        self.generic_test_ML_KEM(ML_KEM128, 5)

    def test_ML_KEM192(self):
        self.generic_test_ML_KEM(ML_KEM192, 5)

    def test_ML_KEM256(self):
        self.generic_test_ML_KEM(ML_KEM256, 5)


if __name__ == "__main__":
    unittest.main()
