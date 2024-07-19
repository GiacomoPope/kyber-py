from kyber import Kyber512, Kyber768, Kyber1024

for _ in range(10):
    pk, sk = Kyber512.keygen()
    for _ in range(10):
        c, key = Kyber512.enc(pk)
        _key = Kyber512.dec(c, sk)
        assert key == _key
