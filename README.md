[![GitHub CI](https://github.com/GiacomoPope/kyber-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GiacomoPope/kyber-py/actions/workflows/ci.yml)
[![Documentation Status](https://readthedocs.org/projects/kyber-py/badge/?version=latest)](https://kyber-py.readthedocs.io/en/latest/?badge=latest)

# ML-KEM / CRYSTALS-Kyber Python Implementation

> [!CAUTION]
> :warning: **Under no circumstances should this be used for cryptographic
applications.** :warning:
> 
> This is an educational resource and has not been designed to be secure
> against any form of side-channel attack. The indended use of this project
> is for learning and experimenting with ML-KEM and Kyber

This repository contains a pure python implementation of both:

1. **CRYSTALS-Kyber**: following (at the time of writing) the most recent
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02)
2. **ML-KEM**: The NIST Module-Lattice-Based Key-Encapsulation Mechanism
Standard following the [FIPS 203 (Initial Public
Draft)](https://csrc.nist.gov/pubs/fips/203/ipd) based off the Kyber submission
to the NIST post-quantum cryptography project.

## Disclaimer

`kyber-py` has been written as an educational tool. The goal of this project was
to learn about how Kyber works, and to try and create a clean, well commented
implementation which people can learn from.

This code is not constant time, or written to be performant. Rather, it was
written so that the python code closely follows Algorithms 1-9 in the original
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf).

## History of this Repository

This work started by simply implementing Kyber for fun, however after NIST
picked Kyber to standardise as ML-KEM, the repository grew and now includes both
implementations of Kyber and ML-KEM. I assume as this repository ages, the Kyber
implementation will get less useful and the ML-KEM one will be the focus, but
for historical reasons we will include both. If only so that people can study
the differences which NIST introduced during the standardisation of the
protocol.

### KATs

This implementation currently passes all KAT tests for `kyber` and `ml_kem` For
more information, see the unit tests in [`test_kyber.py`](tests/test_kyber.py)
and [`test_ml_kem.py`](tests/test_ml_kem.py).

The KAT files were either downloaded or generated:

1. For **Kyber**, the KAT files were generated from the projects [GitHub
   repository](https://github.com/pq-crystals/kyber/) and are included in
   `assets/PQCLkemKAT_*.rsp`
2. For **ML-KEM**, the KAT files were download from the GitHub repository
   [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM) and are included in `assets/kat_MLKEM_*.rsp`

**Note**: for Kyber v3.02, there is a discrepancy between the specification and
reference implementation. To ensure all KATs pass, one has to generate the
public key **before** the random bytes $z = \mathcal{B}^{32}$ in algorithm 7 of
the
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02).

### Dependencies

Originally this project was planned to have zero dependencies, however to make this work
pass the KATs, we needed a deterministic CSRNG. The reference implementation uses
AES256 CTR DRBG. I have implemented this in [`aes256_ctr_drbg.py`](aes256_ctr_drbg.py). 
However, I have not implemented AES itself, instead I import this from `pycryptodome`. If this dependency is too annoying, then please make an issue and we can have a pure-python AES included into the repo.

To install dependencies, run `pip -r install requirements`.

## Using kyber-py

### ML-KEM

There are three functions exposed on the `ML_KEM` class which are intended for
use:

- `ML_KEM.keygen()`: generate a keypair `(ek, dk)`
- `ML_KEM.encaps(ek)`: generate a key and ciphertext pair `(key, ct)`
- `ML_KEM.decaps(ct, dk)`: generate the shared key `key`

#### Example

```python
>>> from ml_kem import ML_KEM128
>>> ek, dk = ML_KEM128.keygen()
>>> key, ct = ML_KEM128.encaps(ek)
>>> _key = ML_KEM128.decaps(ct, dk)
>>> assert key == _key
```

The above example would also work with `ML_KEM192` and `ML_KEM256`.

#### Benchmarks

|  Params    |  keygen  |  keygen/s  |  encap  |  encap/s  |  decap  |  decap/s |
|------------|---------:|-----------:|--------:|----------:|--------:|---------:|
|ML_KEM128    |    3.87ms|      258.47|   6.59ms|     151.79|  10.97ms|    91.15 |
|ML_KEM192    |    5.85ms|      170.84|   9.67ms|     103.43|  15.83ms|    63.15 |
|ML_KEM256   |    8.52ms|       117.38|  13.31ms|      75.12|  21.58ms|    46.34 |

All times recorded using a Intel Core i7-9750H CPU and averaged over 1000 runs.

### Kyber

There are three functions exposed on the `Kyber` class which are intended for
use:

- `Kyber.keygen()`: generate a keypair `(pk, sk)`
- `Kyber.encaps(pk)`: generate shared key and challenge `(key, c)`
- `Kyber.decaps(c, sk)`: generate the shared key `key`

#### Example

```python
>>> from kyber import Kyber512
>>> pk, sk = Kyber512.keygen()
>>> key, c = Kyber512.encaps(pk)
>>> _key = Kyber512.decaps(c, sk)
>>> assert key == _key
```

The above example would also work with `Kyber768` and `Kyber1024`.

We expect users to pick one of the three initalised classes which use the
default parameters of the Kyber specification. The three options are `Kyber512`,
`Kyber768` and `Kyber1024`. However, by following the values in
`DEFAULT_PARAMETERS` one could tweak these values to look at how Kyber behaves
for different default values.

**NOTE**: it is relatively easy to change the parameters $k$, $\eta_1$, $\eta_2$
$d_u$ and $d_v$ from the Kyber specification. However, if you wish to change the
polynomial ring itself, then you will lose access to the NTT transforms which
currently only support $q = 3329$ and $n = 256$.

#### Benchmarks

|  Params    |  keygen  |  keygen/s  |  encap  |  encap/s  |  decap  |  decap/s |
|------------|---------:|-----------:|--------:|----------:|--------:|---------:|
|Kyber512    |    3.97ms|     252.17|    6.11ms|     163.70|  10.55ms|     94.80 |
|Kyber768    |    5.94ms|      168.49|   8.88ms|     112.64|  15.10ms|    66.21 |
|Kyber1024   |    8.52ms|      117.30|  12.17ms|      82.14|  20.48ms|    48.83 |

All times recorded using a Intel Core i7-9750H CPU and averaged over 1000 runs.

## Documentation (under active development)

- https://kyber-py.readthedocs.io/en/latest/

## Polynomials and Modules

There are two main things to worry about when implementing Kyber/ML-KEM. The
first thing to consider is the mathematics, which requires performing linear
algebra in a module with elements in the ring $R_q = \mathbb{F}\_q[X] /(X^n + 1)$
and the second is the sampling, compression and decompression, which links to
the cryptographic assurance of the protocol.

For those who don't know, a module is a generalisation of a vector space, where
elements of a matrix are not selected from a field (such as the rationals, or
element of a finite field $\mathbb{F}\_{p^k}$), but rather in a ring (we do not
require each element in a ring to have a multiplicative inverse). The ring in question for Kyber/ML-KEM is a polynomial ring where polynomials have coefficents in $\mathbb{F}\_{q}$ with $q = 3329$ and the polynomial ring has a modulus $X^n + 1$ with $n = 256$ (and so every element of the polynomial ring has at most 256 coefficients).

### Polynomials

To help with experimenting with these polynomial rings themselves, the file [`polynomials_generic.py`](polynomials/polynomials_generic.py) has an implementation of the univariate polynomial ring

$$
R_q = \mathbb{F}_q[X] /(X^n + 1) 
$$

where the user can select any $q, n$. For example, you can create the
ring $R_{11} = \mathbb{F}_{11}[X] /(X^8 + 1)$ in the following way:

#### Example

```python
>>> from polynomials.polynomials_generic import PolynomialRing
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>> f = 3*x**3 + 4*x**7
>>> g = R.random_element(); g
5 + x^2 + 5*x^3 + 4*x^4 + x^5 + 3*x^6 + 8*x^7
>>> f*g
8 + 9*x + 10*x^3 + 7*x^4 + 2*x^5 + 5*x^6 + 10*x^7
>>> f + f
6*x^3 + 8*x^7
>>> g - g
0
```

We hope that this allows for some hands-on experience at working with these
polynomials before starting to play with the whole of Kyber/ML-KEM.

For the "Kyber-specific" functions, needed to implement the protocol itself, we
have made a child class `PolynomialRingKyber(PolynomialRing)` which has the
following additional methods:

- `PolynomialRingKyber`
  - `parse(bytes)` takes $3n$ bytes and produces a random polynomial in $R_q$
  - `decode(bytes, l)` takes $\ell n$ bits and produces a polynomial in $R_q$
  - `cbd(beta, eta)` takes $\eta \cdot n / 4$ bytes and produces a polynomial in
    $R_q$ with coefficents taken from a centered binomial distribution
- `PolynomialKyber`
  - `encode(l)` takes the polynomial and returns a length $\ell n / 8$ bytearray
  - `to_ntt()` converts the polynomial into the NTT domain for efficient
    polynomial multiplication and returns an element of type
    `PolynomialKyberNTT`
- `PolynomialKyberNTT`
  - `from_ntt()` converts the polynomial back from the NTT domain and returns an
    element of type `PolynomialKyber`
  
This class fixes $q = 3329$ and $n = 256$

Lastly, we define a `self.compress(d)` and `self.decompress(d)` method for
polynomials following page 2 of the
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)

$$ \textsf{compress}_q(x, d) = \lceil (2^d / q) \cdot x \rfloor \textrm{mod}^+
2^d, $$

$$ \textsf{decompress}_q(x, d) = \lceil (q / 2^d) \cdot x \rfloor. $$

The functions `compress` and `decompress` are defined for the coefficients of a
polynomial and a polynomial is (de)compressed by acting the function on every
coefficient. Similarly, an element of a module is (de)compressed by acting the
function on every polynomial.

**Note**: compression is lossy! We do not get the same polynomial back by
computing `f.compress(d).decompress(d)`. They are however *close*. See the
specification for more information.

### Number Theoretic Transform

**TODO**: it would be good to write something more detailed here.

### Modules

Building on `polynomials_generic.py` we also include a file
[`modules_generic.py`](modules/modules_generic.py) which has all of the
functions needed to perform linear algebra given a ring.

Note that `Matrix` allows elements of the module to be of size $m \times n$ but
for Kyber, we only need vectors of length $k$ and square matrices of size $k
\times k$.

As an example of the operations we can perform with out `Module` lets revisit
the ring from the previous example:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>>
>>> M = Module(R)
>>> # We create a matrix by feeding the coefficients to M
>>> A = M([[x + 3*x**2, 4 + 3*x**7], [3*x**3 + 9*x**7, x**4]])
>>> A
[    x + 3*x^2, 4 + 3*x^7]
[3*x^3 + 9*x^7,       x^4]
>>> # We can add and subtract matrices of the same size
>>> A + A
[  2*x + 6*x^2, 8 + 6*x^7]
[6*x^3 + 7*x^7,     2*x^4]
>>> A - A
[0, 0]
[0, 0]
>>> # A vector can be constructed by a list of coefficients
>>> v = M([3*x**5, x])
>>> v
[3*x^5, x]
>>> # We can compute the transpose
>>> v.transpose()
[3*x^5]
[    x]
>>> v + v
[6*x^5, 2*x]
>>> # We can also compute the transpose in place
>>> v.transpose_self()
[3*x^5]
[    x]
>>> v + v
[6*x^5]
[  2*x]
>>> # Matrix multiplication follows python standards and is denoted by @
>>> A @ v
[8 + 4*x + 3*x^6 + 9*x^7]
[        2 + 6*x^4 + x^5]
```

On top of this class, we have the classes `ModuleKyber(Module)` and
`MatrixKyber(Matrix)` which have helper functions which (for example) encode
every element of a matrix, or convert every element to or from the NTT domain.
These are simple functions which call the respective `PolynomialKyber` methods
for every element.
