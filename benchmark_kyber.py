from kyber import Kyber512, Kyber768, Kyber1024
import cProfile
from time import time

def profile_kyber(Kyber):
    pk, sk = Kyber.keygen()
    c, key = Kyber.enc(pk)
    
    gvars = {}
    lvars = {"Kyber": Kyber, "c": c, "pk": pk, "sk": sk}
    
    cProfile.runctx("[Kyber.keygen() for _ in range(100)]", globals=gvars, locals=lvars, sort=1)
    cProfile.runctx("[Kyber.enc(pk) for _ in range(100)]", globals=gvars, locals=lvars, sort=1)
    cProfile.runctx("[Kyber.dec(c, sk) for _ in range(100)]", globals=gvars, locals=lvars, sort=1)
    
def benchmark_kyber(Kyber, name, count):
    keygen_times = []
    enc_times = []
    dec_times = []
    
    for _ in range(count):
        t0 = time()
        pk, sk = Kyber.keygen()
        keygen_times.append(time() - t0)
        
        t1 = time()
        c, key = Kyber.enc(pk)
        enc_times.append(time() - t1)
        
        t2 = time()
        dec = Kyber.dec(c, sk)
        dec_times.append(time() - t2)

    avg_keygen = sum(keygen_times)/count
    avg_enc = sum(enc_times)/count
    avg_dec = sum(dec_times)/count
    print(f" {name:11} |"
          f"{avg_keygen*1000:8.2f}ms  {1/avg_keygen:11.2f}"
          f"{avg_enc*1000:8.2f}ms  {1/avg_enc:10.2f}"
          f"{avg_dec*1000:8.2f}ms  {1/avg_dec:8.2f}")


if __name__ == '__main__':
    # profile_kyber(Kyber512)
    # profile_kyber(Kyber768)
    # profile_kyber(Kyber1024)
    
    count = 1000
    # common banner
    print("-" * 80)
    print("   Params    |  keygen  |  keygen/s  |  encap  |  encap/s  "
          "|  decap  |  decap/s")
    print("-" * 80)
    benchmark_kyber(Kyber512, "Kyber512", count)
    benchmark_kyber(Kyber768, "Kyber768", count)    
    benchmark_kyber(Kyber1024, "Kyber1024", count)
