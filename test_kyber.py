import unittest
import os
from kyber import Kyber512, Kyber768, Kyber1024
from aes256_crt_drgb import AES256_CRT_DRGB

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
    
    def test_kyber512(self):
        for _ in range(2):
            pk, sk = Kyber512.keygen()
            for _ in range(2):
                c, key = Kyber512.encrypt(pk)
                _key = Kyber512.decrypt(c, sk)
                self.assertEqual(key, _key)
    
    def test_kyber768(self):
        for _ in range(2):
            pk, sk = Kyber768.keygen()
            for _ in range(2):
                c, key = Kyber768.encrypt(pk)
                _key = Kyber768.decrypt(c, sk)
                self.assertEqual(key, _key)
                
    def test_kyber1024(self):
        for _ in range(2):
            pk, sk = Kyber1024.keygen()
            for _ in range(2):
                c, key = Kyber1024.encrypt(pk)
                _key = Kyber1024.decrypt(c, sk)
                self.assertEqual(key, _key)
                
class TestKyberDeterministic(unittest.TestCase):
    """
    Ensure that deterministic DRGB is deterministic!
    
    Uses AES256 CRT DRGB for randomness.
    Note: requires pycryptodome for AES impl.
    (Seemed overkill to code my own AES for Kyber)
    """
    
    def test_kyber512_deterministic(self):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure 
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(5):
            Kyber512.set_drgb_seed(seed)
            pk, sk = Kyber512.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Now given a fixed keypair make sure
        that c,key are the same for a fixed seed
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber512.keygen()
        for _ in range(5):
            Kyber512.set_drgb_seed(seed)
            c, key = Kyber512.encrypt(pk)
            _key = Kyber512.decrypt(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), 5)
        self.assertEqual(len(set(key_output)), 1)
        
    def test_kyber768_deterministic(self):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure 
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(5):
            Kyber768.set_drgb_seed(seed)
            pk, sk = Kyber768.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Now given a fixed keypair make sure
        that c,key are the same for a fixed seed
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber768.keygen()
        for _ in range(5):
            Kyber768.set_drgb_seed(seed)
            c, key = Kyber768.encrypt(pk)
            _key = Kyber768.decrypt(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), 5)
        self.assertEqual(len(set(key_output)), 1)
        
    def test_kyber1024_deterministic(self):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure 
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(5):
            Kyber1024.set_drgb_seed(seed)
            pk, sk = Kyber1024.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Now given a fixed keypair make sure
        that c,key are the same for a fixed seed
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber1024.keygen()
        for _ in range(5):
            Kyber1024.set_drgb_seed(seed)
            c, key = Kyber1024.encrypt(pk)
            _key = Kyber1024.decrypt(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), 5)
        self.assertEqual(len(set(key_output)), 1)

class TestKnownTestValuesDRGB(unittest.TestCase):
    """
    We know how the seeds for the KAT are generated, so
    let's check against our own implementation.
    
    We only need to test one file, as the seeds are the 
    same across the three files.
    """
    def test_kyber_512_known_answer_seed(self):
        # Set DRGB to generate seeds
        entropy_input = bytes([i for i in range(48)])
        rng = AES256_CRT_DRGB(entropy_input)
        
        with open("assets/PQCkemKAT_1632.rsp") as f:
            # extract data from KAT
            kat_data_512 = f.read()
            parsed_data = parse_kat_data(kat_data_512)
            # Check all seeds match
            for data in parsed_data.values():
                seed = data["seed"]
                self.assertEqual(seed, rng.random_bytes(48))
    
class TestKnownTestValues(unittest.TestCase):    
    def test_kyber_512_known_answer(self):
        with open("assets/PQCkemKAT_1632.rsp") as f:
            kat_data_512 = f.read()
            parsed_data = parse_kat_data(kat_data_512)
            
            for data in parsed_data.values():
                seed, pk, sk, ct, ss = data.values()
                
                # Seed DRGB with KAT seed
                Kyber512.set_drgb_seed(seed)
                
                # Assert keygen matches
                _pk, _sk = Kyber512.keygen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)
                
                # Assert encryption matches
                _ct, _ss = Kyber512.encrypt(_pk)
                self.assertEqual(ct, _ct)
                self.assertEqual(ss, _ss)
                
                __ss = Kyber512.decrypt(ct, sk)
                self.assertEqual(ss, __ss)
                
    def test_kyber_768_known_answer(self):
        with open("assets/PQCkemKAT_2400.rsp") as f:
            kat_data_768 = f.read()
            parsed_data = parse_kat_data(kat_data_768)
            
            for data in parsed_data.values():
                seed, pk, sk, ct, ss = data.values()
                
                # Seed DRGB with KAT seed
                Kyber768.set_drgb_seed(seed)
                
                # Assert keygen matches
                _pk, _sk = Kyber768.keygen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)
                
                # Assert encryption matches
                _ct, _ss = Kyber768.encrypt(_pk)
                self.assertEqual(ct, _ct)
                self.assertEqual(ss, _ss)
                
                __ss = Kyber768.decrypt(ct, sk)
                self.assertEqual(ss, __ss)
                
    def test_kyber_1024_known_answer(self):
        with open("assets/PQCkemKAT_3168.rsp") as f:
            kat_data_1024 = f.read()
            parsed_data = parse_kat_data(kat_data_1024)
            
            for data in parsed_data.values():
                seed, pk, sk, ct, ss = data.values()
                
                # Seed DRGB with KAT seed
                Kyber1024.set_drgb_seed(seed)
                
                # Assert keygen matches
                _pk, _sk = Kyber1024.keygen()
                self.assertEqual(pk, _pk)
                self.assertEqual(sk, _sk)
                
                # Assert encryption matches
                _ct, _ss = Kyber1024.encrypt(_pk)
                self.assertEqual(ct, _ct)
                self.assertEqual(ss, _ss)
                
                __ss = Kyber1024.decrypt(ct, sk)
                self.assertEqual(ss, __ss)

if __name__ == '__main__':
    unittest.main()