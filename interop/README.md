Tools that allow use of the OpenSSL Encapsulation and Decapsulation API.

**Note:** this code expects draft-ietf-lamps-kyber-certificates-06 compatible
behaviour.


OpenSSL setup
-------------

To enable support for PQC algorithms in OpenSSL: install oqsprovider and
modify the `openssl.cnf` file to enable the oqsprovider:
```
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[oqsprovider_sect]
activate = 1
```
If you've done that properly, the `openssl list -kem-algorithms` will list
ML-KEM as valid options.

OpenSSL keygen
--------------

To generate the private (decapsulation) key using OpenSSL:
```
openssl genpkey -out private-key.pem -algorithm mlkem512
```
(See other algorithm names in https://github.com/open-quantum-safe/oqs-provider)

To extract the public (encapsulation) key using OpenSSL:
```
openssl pkey -pubout -in public-key.pem -out pub.pem
```

Compile OpenSSL helper apps:
----------------------------

Compile the encapsulation and decapsulation helper apps:
```
gcc -o openssl-decap -lcrypto openssl-decap.c
gcc -o openssl-encap -lcrypto openssl-encap.c
```

OpenSSL encapsulation
---------------------
To encapsulate a shared secret:
```
./openssl-encap -k public-key.pem -s secret.bin -c ciphertext.bin
```

OpenSSL decapsulation
---------------------
To decapsulate a shared secret:
```
./openssl-decap -k private-key.pem -s secret-dec.bin -c ciphertext.bin
```

kyber-py setup
--------------
As the key formats use ASN.1 and PEM encoding, they require presence
of the `ecdsa` library. Install it using your distribution package manager
or using `pip`:
```
pip install ecdsa
```

Kyber-py key gen
----------------
To generate both private (decapsulation) and public (encapsulation) keys
with kyber-py, run:
```
PYTHONPATH=../src python ml_kem_keygen.py ML-KEM-512 public-key.pem private-key.pem
```

Kyber-py encapsulation
-----------------------
To encapsulate a shared secret:
```
PYTHONPATH=../src python ml_kem_encap.py public-key.pem secret.bin ciphertext.bin
```

Kyber-py decapsulation
----------------------
To decapsulate a shared secret:
```
PYTHONPATH=../src python ml_kem_decap.py private-key.pem secret-dec.bin ciphertext.bin
```
