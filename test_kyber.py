import unittest
from kyber import Kyber512, Kyber768, Kyber1024

def parse_kat_data(data):
    parsed_data = {}
    count_blocks = data.split('\n\n')
    for block in count_blocks[1:-1]:
        block_data = block.split('\n')
        count, seed, pk, sk, ct, ss = [line.split(" = ")[-1] for line in block_data]
        parsed_data[count] = {
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
        for _ in range(1):
            pk, sk = Kyber512.keygen()
            for _ in range(1):
                c, key = Kyber512.encrypt(pk)
                _key = Kyber512.decrypt(c, sk)
                self.assertEqual(key, _key)
    
    def test_kyber768(self):
        for _ in range(1):
            pk, sk = Kyber768.keygen()
            for _ in range(1):
                c, key = Kyber768.encrypt(pk)
                _key = Kyber768.decrypt(c, sk)
                self.assertEqual(key, _key)
                
    def test_kyber1024(self):
        for _ in range(1):
            pk, sk = Kyber1024.keygen()
            for _ in range(1):
                c, key = Kyber1024.encrypt(pk)
                _key = Kyber1024.decrypt(c, sk)
                self.assertEqual(key, _key)
    
    
class TestKnownTestValues(unittest.TestCase):    
    def test_kyber_512_known_answer(self):
        with open("assets/PQCkemKAT_1632.rsp") as f:
            kat_data_512 = f.read()
            parsed_data = parse_kat_data(kat_data_512)
            
            for data in parsed_data.values():
                sk, ct, ss = data.values()
                _ss = Kyber512.decrypt(ct, sk)
                self.assertEqual(ss, _ss)
                
    def test_kyber_768_known_answer(self):
        with open("assets/PQCkemKAT_2400.rsp") as f:
            kat_data_768 = f.read()
            parsed_data = parse_kat_data(kat_data_768)
            
            for data in parsed_data.values():
                sk, ct, ss = data.values()
                _ss = Kyber768.decrypt(ct, sk)
                self.assertEqual(ss, _ss)
                
    def test_kyber_1024_known_answer(self):
        with open("assets/PQCkemKAT_3168.rsp") as f:
            kat_data_1024 = f.read()
            parsed_data = parse_kat_data(kat_data_1024)
            
            for data in parsed_data.values():
                sk, ct, ss = data.values()
                _ss = Kyber1024.decrypt(ct, sk)
                self.assertEqual(ss, _ss)

if __name__ == '__main__':
    unittest.main()