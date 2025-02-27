import sys

if len(sys.argv) != 4:
    raise ValueError(f"Usage: {sys.argv[0]} dk.pem secret.bin ciphertext.bin")

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

OIDS = {
    (2, 16, 840, 1, 101, 3, 4, 4, 1): ML_KEM_512,
    (2, 16, 840, 1, 101, 3, 4, 4, 2): ML_KEM_768,
    (2, 16, 840, 1, 101, 3, 4, 4, 3): ML_KEM_1024,
}

import ecdsa.der as der

with open(sys.argv[1], "rt") as dk_file:
    dk_pem = dk_file.read()

dk_der = der.unpem(dk_pem)

s1, empty = der.remove_sequence(dk_der)
if empty != b"":
    raise der.UnexpectedDER("Trailing junk after DER public key")

ver, rest = der.remove_integer(s1)

if ver != 0:
    raise der.UnexpectedDER("Unexpected format version")

alg_id, rest = der.remove_sequence(rest)

alg_id, empty = der.remove_object(alg_id)
if alg_id not in OIDS:
    raise der.UnexpectedDER(f"Not recognised algoritm OID: {alg_id}")
if empty != b"":
    raise der.UnexpectedDER("parameters specified for ML-KEM OID")

kem = OIDS[alg_id]

key, empty = der.remove_octet_string(rest)
if empty != b"":
    raise der.UnexpectedDER("Trailing junk after the key")

assert len(key) == 64
_, dk = kem.key_derive(key)

with open(sys.argv[3], "rb") as encaps_file:
    encaps = encaps_file.read()

secret = kem.decaps(dk, encaps)

with open(sys.argv[2], "wb") as secret_file:
    secret_file.write(secret)

print("done")
