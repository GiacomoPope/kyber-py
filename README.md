[![GitHub CI](https://github.com/GiacomoPope/kyber-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GiacomoPope/kyber-py/actions/workflows/ci.yml)
[![Documentation Status](https://readthedocs.org/projects/kyber-py/badge/?version=latest)](https://kyber-py.readthedocs.io/en/latest/?badge=latest)

# CRYSTALS-Kyber Python Implementation

This repository contains a pure python implementation of CRYSTALS-Kyber 
following (at the time of writing) the most recent 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02)

## A note on ML-KEM

There is a somewhat working implementation of ML-KEM compliant with the NIST spec in this repo, and it is work in progress to allow both kyber and the NIST variant to be used from this repo with full documentation.

## Disclaimer

:warning: **Under no circumstances should this be used for a cryptographic application.** :warning:

I have written `kyber-py` as a way to learn about the way Kyber works, and to
try and create a clean, well commented implementation which people can learn 
from.

This code is not constant time, or written to be performant. Rather, it was 
written so that reading though Algorithms 1-9 in the 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
closely matches the code which is seen in `kyber.py`.

### KATs

This implementation currently passes all KAT tests from the reference implementation. 
For more information, see the unit tests in [`test_kyber.py`](test_kyber.py).

**Note**: there is a discrepancy between the specification and reference implementation.
To ensure all KATs pass, I have to generate the public key **before** the random
bytes $z = \mathcal{B}^{32}$ in algorithm 7 of the 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02).

### Dependencies

Originally this was planned to have zero dependencies, however to make this work
pass the KATs, I needed a deterministic CSRNG. The reference implementation uses
AES256 CTR DRBG. I have implemented this in [`aes256_ctr_drbg.py`](aes256_ctr_drbg.py). 
However, I have not implemented AES itself, instead I import this from `pycryptodome`.

To install dependencies, run `pip -r install requirements`.

If you're happy to use system randomness (`os.urandom`) then you don't need
this dependency.

## Using kyber-py

There are three functions exposed on the `Kyber` class which are intended
for use:

- `Kyber.keygen()`: generate a keypair `(pk, sk)`
- `Kyber.enc(pk)`: generate a challenge and a shared key `(c, K)`
- `Kyber.dec(c, sk)`: generate the shared key `K`

To use `Kyber()` it must be initialised with a dictionary of the 
protocol parameters. An example can be seen in `DEFAULT_PARAMETERS`.

Additionally, the class has been initialised with these default parameters, 
so you can simply import the NIST level you want to play with:

#### Example

```python
>>> from kyber import Kyber512
>>> pk, sk = Kyber512.keygen()
>>> c, key = Kyber512.enc(pk)
>>> _key = Kyber512.dec(c, sk)
>>> assert key == _key
```

The above example would also work with `Kyber768` and `Kyber1024`.

### Benchmarks

For now, here are some approximate benchmarks, although the purpose of this project is not speed, but rather education!

|  Params    |  keygen  |  keygen/s  |  encap  |  encap/s  |  decap  |  decap/s |
|------------|---------:|-----------:|--------:|----------:|--------:|---------:|
|Kyber512    |    4.82ms|      207.59|   7.10ms|     140.80|  11.65ms|    85.82 |
|Kyber768    |    6.87ms|      145.60|  10.11ms|      98.92|  16.51ms|    60.58 |
|Kyber1024   |    9.72ms|      102.91|  13.71ms|      72.94|  22.20ms|    45.05 |

All times recorded using a Intel Core i7-9750H CPU. 

## Documentation (under active development)

- https://kyber-py.readthedocs.io/en/latest/

## Future Plans

* Add documentation on `NTT` transform for polynomials
* Add documentation for working with DRBG and setting the seed

## Discussion of Implementation

### Kyber

```
TODO:

Add some more information about how working with Kyber works with this
library...
```

### Polynomials

The file [`polynomials.py`](polynomials.py) contains the classes 
`PolynomialRing` and 
`Polynomial`. This implements the univariate polynomial ring

$$
R_q = \mathbb{F}_q[X] /(X^n + 1) 
$$

The implementation is inspired by `SageMath` and you can create the
ring $R_{11} = \mathbb{F}_{11}[X] /(X^8 + 1)$ in the following way:

#### Example

```python
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

We additionally include functions for `PolynomialRingKyber` and `PolynomialKyber`
to move from bytes to polynomials (and back again). 

- `PolynomialRingKyber`
  - `parse(bytes)` takes $3n$ bytes and produces a random polynomial in $R_q$
  - `decode(bytes, l)` takes $\ell n$ bits and produces a polynomial in $R_q$
  - `cbd(beta, eta)` takes $\eta \cdot n / 4$ bytes and produces a polynomial in $R_q$ with coefficents taken from a centered binomial distribution
- `PolynomialKyber`
  - `self.encode(l)` takes the polynomial and returns a length $\ell n / 8$ bytearray
  
#### Example

```python
TODO
```

Lastly, we define a `self.compress(d)` and `self.decompress(d)` method for
polynomials following page 2 of the 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)

$$
\textsf{compress}_q(x, d) = \lceil (2^d / q) \cdot x \rfloor \textrm{mod}^+ 2^d,
$$

$$
\textsf{decompress}_q(x, d) = \lceil (q / 2^d) \cdot x \rfloor.
$$

The functions `compress` and `decompress` are defined for the coefficients 
of a polynomial and a polynomial is (de)compressed by acting the function
on every coefficient. 
Similarly, an element of a module is (de)compressed by acting the
function on every polynomial.

#### Example

```python
TODO
```

**Note**: compression is lossy! We do not get the same polynomial back 
by computing `f.compress(d).decompress(d)`. They are however *close*.
See the specification for more information.

### Number Theoretic Transform

```
TODO:

This is now handled by `NTTHelper` which is passed to `PolynomialRing`
and has functions which are accessed by `Polynomial`.

Talk about what is available, and how they are used.
```

### Modules

The file [`modules.py`](modules.py) contains the classes `Module` and `Matrix`.
A module is a generalisation of a vector space, where the field
of scalars is replaced with a ring. In the case of Kyber, we 
need the module with the ring $R_q$ as described above. 

`Matrix` allows elements of the module to be of size $m \times n$
but for Kyber, we only need vectors of length $k$ and square
matricies of size $k \times k$.

As an example of the operations we can perform with out `Module`
lets revisit the ring from the previous example:

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

### TODO

Explain the extra functions available in `ModuleKyber` and `MatrixKyber`.
