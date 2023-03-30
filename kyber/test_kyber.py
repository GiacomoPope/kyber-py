import unittest
import os
from kyber import Kyber512, Kyber768, Kyber1024
from aes256_ctr_drbg import AES256_CTR_DRBG

def parse_kat_data(data):
    parsed_data = {}
    count_blocks = data.split('\n\n')
    for block in count_blocks[1:-1]:
        block_data = block.split('\n')
        count, seed, pk, sk, ct, ss = [line.split(" = ")[-1] for line in block_data]
        parsed_data[count] = {
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "ct": bytes.fromhex(ct),
            "ss": bytes.fromhex(ss),   
        }
    return parsed_data
    
class TestKyber(unittest.TestCase):
    """
    Test Kyber levels for internal
    consistency by generating keypairs
    and shared secrets.
    """

    def generic_test_kyber(self, Kyber, count):
        for _ in range(count):
            pk, sk = Kyber.keygen()
            for _ in range(count):
                c, key = Kyber.enc(pk)
                _key = Kyber.dec(c, sk)
                self.assertEqual(key, _key)
    
    def test_kyber512(self):
        self.generic_test_kyber(Kyber512, 5)
        
    def test_kyber768(self):
        self.generic_test_kyber(Kyber768, 5)
        
    def test_kyber1024(self):
        self.generic_test_kyber(Kyber1024, 5)
                
class TestKyberDeterministic(unittest.TestCase):
    """
    Ensure that deterministic DRBG is deterministic!
    
    Uses AES256 CTR DRBG for randomness.
    Note: requires pycryptodome for AES impl.
    (Seemed overkill to code my own AES for Kyber)
    """
    
    def generic_test_kyber_deterministic(self, Kyber, count):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure 
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            pk, sk = Kyber.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Now given a fixed keypair make sure
        that c,key are the same for a fixed seed
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber.keygen()
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            c, key = Kyber.enc(pk)
            _key = Kyber.dec(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), count)
        self.assertEqual(len(set(key_output)), 1)
        
    def test_kyber512_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber512, 5)
    
    def test_kyber768_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber768, 5)
    
    def test_kyber1024_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber1024, 5)
        

class TestKnownTestValuesDRBG(unittest.TestCase):
    """
    We know how the seeds for the KAT are generated, so
    let's check against our own implementation.
    
    We only need to test one file, as the seeds are the 
    same across the three files.
    """
    def test_kyber512_known_answer_seed(self):
        # Set DRBG to generate seeds
        entropy_input = bytes([i for i in range(48)])
        rng = AES256_CTR_DRBG(entropy_input)
        
        with open("assets/PQCkemKAT_1632.rsp") as f:
            # extract data from KAT
            kat_data_512 = f.read()
            parsed_data = parse_kat_data(kat_data_512)
            # Check all seeds match
            for data in parsed_data.values():
                seed = data["seed"]
                self.assertEqual(seed, rng.random_bytes(48))
    
class TestKnownTestValues(unittest.TestCase): 
    def generic_test_kyber_known_answer(self, Kyber, filename):
        with open(filename) as f:
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)
            
            for data in parsed_data.values():
                seed, pk, sk, ct, ss = data.values()
                
                # Seed DRBG with KAT seed
                Kyber.set_drbg_seed(seed)
                
                # Assert keygen matches
                _pk, _sk = Kyber.keygen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)
                
                # Assert encapsulation matches
                _ct, _ss = Kyber.enc(_pk)
                self.assertEqual(ct, _ct)
                self.assertEqual(ss, _ss)
                
                # Assert decapsulation matches
                __ss = Kyber.dec(ct, sk)
                self.assertEqual(ss, __ss)
                
    def test_kyber512_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber512, "assets/PQCkemKAT_1632.rsp")
        
    def test_kyber768_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber768, "assets/PQCkemKAT_2400.rsp")
        
    def test_kyber1024_known_answer(self):
        return self.generic_test_kyber_known_answer(Kyber1024, "assets/PQCkemKAT_3168.rsp")

if __name__ == '__main__':
    unittest.main()