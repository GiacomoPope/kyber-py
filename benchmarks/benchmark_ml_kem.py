from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
import cProfile
from time import time


def profile_ml_kem(ML_KEM):
    (ek, dk) = ML_KEM.keygen()
    (K, c) = ML_KEM.encaps(ek)

    gvars = {}
    lvars = {"ML_KEM": ML_KEM, "c": c, "ek": ek, "dk": dk}

    cProfile.runctx(
        "[ML_KEM.keygen() for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )
    cProfile.runctx(
        "[ML_KEM.encaps(ek) for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )
    cProfile.runctx(
        "[ML_KEM.decaps(dk, c) for _ in range(100)]",
        globals=gvars,
        locals=lvars,
        sort=1,
    )


def benchmark_ml_kem(ML_KEM, name, count):
    keygen_times = []
    enc_times = []
    dec_times = []

    for _ in range(count):
        t0 = time()
        ek, dk = ML_KEM.keygen()
        keygen_times.append(time() - t0)

        t1 = time()
        _, c = ML_KEM.encaps(ek)
        enc_times.append(time() - t1)

        t2 = time()
        _ = ML_KEM.decaps(dk, c)
        dec_times.append(time() - t2)

    avg_keygen = sum(keygen_times) / count
    avg_enc = sum(enc_times) / count
    avg_dec = sum(dec_times) / count
    print(
        f" {name:11} |"
        f"{avg_keygen*1000:7.2f}ms | {1/avg_keygen:10.2f} |"
        f"{avg_enc*1000:6.2f}ms | {1/avg_enc:9.2f} |"
        f"{avg_dec*1000:6.2f}ms | {1/avg_dec:7.2f} |"
    )


if __name__ == "__main__":
    count = 1000
    # common banner
    print("-" * 80)
    print(
        "   Params    |  keygen  |  keygen/s  |  encap  |  encap/s  "
        "|  decap  |  decap/s"
    )
    print("-" * 80)
    benchmark_ml_kem(ML_KEM_512, "ML-KEM-512", count)
    benchmark_ml_kem(ML_KEM_768, "ML-KEM-768", count)
    benchmark_ml_kem(ML_KEM_1024, "ML-KEM-1024", count)
