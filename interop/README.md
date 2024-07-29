Tools that allow use of the OpenSSL Encapsulation and Decapsulation API.

To enable support for PQC algorithms in OpenSSL install oqsprovider and
modify the `openssl.cnf` file to enable the oqsprovider:
```
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[oqsprovider_sect]
activate = 1
```

To generate the private (decapsulation) key using OpenSSL:
```
openssl genpkey -out private-key.pem -algorithm mlkem512
```
(See other algorithm names in https://github.com/open-quantum-safe/oqs-provider)

To extract the public (encapsulation) key using OpenSSL:
```
openssl pkey -pubout -in public-key.pem -out pub.pem
```

Compile the encapsulation and decapsulation helper apps:
```
gcc -o openssl-decap -lcrypto openssl-decap.c
gcc -o openssl-encap -lcrypto openssl-encap.c
```

To encapsulate a shared secret:
```
./openssl-encap -k public-key.pem -s secret.bin -c ciphertext.bin
```

To decapsulate a shared secret:
```
./openssl-decap -k private-key.pem -s secret-dec.bin -c ciphertext.bin
```
