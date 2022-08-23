from kyber import Kyber1024

"""
Currently all partial tests of 512 and 768
pass

13 of the 100 tests fail for Kyber1024
"""

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
            
def test_kyber_512():
    fails = 0
    with open("assets/PQCkemKAT_1632.rsp") as f:
        kat_data_512 = f.read()
        parsed_data = parse_kat_data(kat_data_512)
        
        for count, data in parsed_data.items():
            sk, ct, ss = data.values()
            _ss = Kyber512.decrypt(ct, sk)
            if ss != _ss:
                print(f"Failed for count: {count}")
                print(ss.hex(), len(ss))
                print(_ss.hex(), len(_ss))
                fails += 1
    print(f"Test for Kyber512 failed {fails} time(s)")
    
def test_kyber_768():
    fails = 0
    with open("assets/PQCkemKAT_2400.rsp") as f:
        kat_data_768 = f.read()
        parsed_data = parse_kat_data(kat_data_768)
        
        for count, data in parsed_data.items():
            sk, ct, ss = data.values()
            _ss = Kyber768.decrypt(ct, sk)
            if ss != _ss:
                print(f"Failed for count: {count}")
                print(ss.hex(), len(ss))
                print(_ss.hex(), len(_ss))
                fails += 1
    print(f"Test for Kyber768 failed {fails} time(s)")

def test_kyber_1024():
    fails = 0
    with open("assets/PQCkemKAT_3168.rsp") as f:
        kat_data_1024 = f.read()
        parsed_data = parse_kat_data(kat_data_1024)
        
        for count, data in parsed_data.items():
            sk, ct, ss = data.values()
            _ss = Kyber1024.decrypt(ct, sk)
            if ss != _ss:
                print(f"Failed for count: {count}")
                print(ss.hex(), len(ss))
                print(_ss.hex(), len(_ss))
                fails += 1
    print(f"Test failed {fails} time(s)")
                
if __name__ == '__main__':
    test_kyber_1024()