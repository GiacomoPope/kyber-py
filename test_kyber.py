import unittest
from kyber import *

class TestKyber(unittest.TestCase):
    """
    Test Kyber levels for internal
    consistency by generating keypairs
    and shared secrets.
    """
    def test_kyber512(self):
        for _ in range(10):
            pk, sk = Kyber512.keygen()
            for _ in range(20):
                c, key = Kyber512.encrypt(pk)
                _key = Kyber512.decrypt(c, sk)
                self.assertEqual(key, _key)
    
    def test_kyber768(self):
        for _ in range(10):
            pk, sk = Kyber768.keygen()
            for _ in range(20):
                c, key = Kyber768.encrypt(pk)
                _key = Kyber768.decrypt(c, sk)
                self.assertEqual(key, _key)
                
    def test_kyber1024(self):
        for _ in range(10):
            pk, sk = Kyber1024.keygen()
            for _ in range(20):
                c, key = Kyber1024.encrypt(pk)
                _key = Kyber1024.decrypt(c, sk)
                self.assertEqual(key, _key)
    
if __name__ == '__main__':
    unittest.main()
    """
    output:
        
    ...
    ----------------------------------------------------------------------
    Ran 3 tests in 134.541s
    
    OK
    """