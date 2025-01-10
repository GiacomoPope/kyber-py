import sys

if len(sys.argv) != 4:
    raise ValueError(f"Usage: {sys.argv[0]} ek.pem secret.bin ciphertext.bin")

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

OIDS = {
    (2, 16, 840, 1, 101, 3, 4, 4, 1): ML_KEM_512,
    (2, 16, 840, 1, 101, 3, 4, 4, 2): ML_KEM_768,
    (2, 16, 840, 1, 101, 3, 4, 4, 3): ML_KEM_1024,
}

import ecdsa.der as der

with open(sys.argv[1], "rt") as ek_file:
    ek_pem = ek_file.read()

ek_der = der.unpem(ek_pem)

s1, empty = der.remove_sequence(ek_der)
if empty != b"":
    raise der.UnexpectedDER("Trailing junk after DER public key")

alg_id, rem = der.remove_sequence(s1)

alg_id, rest = der.remove_object(alg_id)
if alg_id not in OIDS:
    raise der.UnexpectedDER(f"Not recognised algoritm OID: {alg_id}")

if rest != b"":
    raise der.UnexpectedDER("parameters specified for ML-KEM OID")

kem = OIDS[alg_id]

key, empty = der.remove_bitstring(rem, 0)
if empty != b"":
    raise der.UnexpectedDER("Trailing junk after the public key bitstring")

secret, encaps = kem.encaps(key)

with open(sys.argv[2], "wb") as secret_file:
    secret_file.write(secret)

with open(sys.argv[3], "wb") as encaps_file:
    encaps_file.write(encaps)

print("done")
