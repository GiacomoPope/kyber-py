import sys

if len(sys.argv) != 4:
    raise ValueError(
        f"Usage: {sys.argv[0]} ML-KEM-(512|768|1024) ek.pem dk.pem"
    )

if sys.argv[1] == "ML-KEM-512":
    from kyber_py.ml_kem.default_parameters import ML_KEM_512 as ML_KEM

    oid = (2, 16, 840, 1, 101, 3, 4, 4, 1)
elif sys.argv[1] == "ML-KEM-768":
    from kyber_py.ml_kem.default_parameters import ML_KEM_768 as ML_KEM

    oid = (2, 16, 840, 1, 101, 3, 4, 4, 2)
elif sys.argv[1] == "ML-KEM-1024":
    from kyber_py.ml_kem.default_parameters import ML_KEM_1024 as ML_KEM

    oid = (2, 16, 840, 1, 101, 3, 4, 4, 3)
else:
    raise ValueError(f"Unrecognised algorithm: {sys.argv[1]}")

import ecdsa.der as der

ek, dk = ML_KEM.keygen()

with open(sys.argv[2], "wb") as ek_file:
    encoded = der.encode_sequence(
        der.encode_sequence(der.encode_oid(*oid)),
        der.encode_bitstring(ek, 0),
    )
    ek_file.write(der.topem(encoded, "PUBLIC KEY"))

with open(sys.argv[3], "wb") as dk_file:
    encoded = der.encode_sequence(
        der.encode_integer(0),
        der.encode_sequence(der.encode_oid(*oid)),
        der.encode_octet_string(der.encode_octet_string(dk + ek)),
    )
    dk_file.write(der.topem(encoded, "PRIVATE KEY"))
