from kyber import Kyber512, Kyber768, Kyber1024
import cProfile
from timeit import timeit

def profile_kyber(Kyber):
    pk, sk = Kyber.keygen()
    c, key = Kyber.encrypt(pk)
    
    gvars = {}
    lvars = {"Kyber": Kyber, "c": c, "pk": pk, "sk": sk}
    
    # cProfile.runctx("Kyber.keygen()", globals=gvars, locals=lvars, sort=1)
    # cProfile.runctx("Kyber.encrypt(pk)", globals=gvars, locals=lvars, sort=1)
    cProfile.runctx("Kyber.decrypt(c, sk)", globals=gvars, locals=lvars, sort=1)
    
def benchmark_kyber(Kyber, name):
    pk, sk = Kyber.keygen()
    c, key = Kyber.encrypt(pk)
    n = 1000
    
    keygen = timeit("Kyber.keygen()", number=n, globals=locals())
    encrypt = timeit("Kyber.encrypt(pk)", number=n, globals=locals())
    decrypt = timeit("Kyber.decrypt(c, sk)", number=n, globals=locals())
    
    print(f"-"*25)
    print(f"  {name} | ({n} calls)")
    print(f"-"*25)
    
    print(f"keygen:  {round(keygen,5)}s")
    print(f"encrypt: {round(encrypt,5)}s")
    print(f"decrypt: {round(decrypt,5)}s\n")
    
if __name__ == '__main__':
    # profile_kyber(Kyber512)
    # profile_kyber(Kyber768)
    # profile_kyber(Kyber1024)

    benchmark_kyber(Kyber512,  "Kyber512")
    benchmark_kyber(Kyber768,  "Kyber768")    
    benchmark_kyber(Kyber1024, "Kyber1024")    