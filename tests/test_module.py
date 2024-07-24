import unittest
from random import randint
from kyber_py.modules.modules import ModuleKyber


class TestModuleKyber(unittest.TestCase):
    M = ModuleKyber()
    R = M.ring

    def test_decode_vector(self):
        for _ in range(100):
            k = randint(1, 5)
            v = self.M.random_element(k, 1)
            v_bytes = v.encode(12)
            self.assertEqual(v, self.M.decode_vector(v_bytes, k, 12))

    def test_recode_vector_wrong_length(self):
        self.assertRaises(
            ValueError, lambda: self.M.decode_vector(b"1", 2, 12)
        )
