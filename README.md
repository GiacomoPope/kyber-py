# CRYSTALS-Kyber Python Implementation

This repository contains a pure python implementation of CRYSTALS-Kyber 
following (at the time of writing) the most recent 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
(v3.02)

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
- `Kyber.dec(sk, c)`: generate the shared key `K`

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

**TODO**: Better benchmarks? Although this was never about speed haha.

For now, here are some approximate benchmarks:

|  1000 Iterations         | Kyber512 | Kyber768 | Kyber1024 |
|--------------------------|----------|----------|-----------|
| `KeyGen()`               |  6.868s  | 10.820s  | 16.172s   |
| `Enc()`                  | 10.677s  | 16.094s  | 22.341s   |
| `Dec()`                  | 16.822s  | 25.979s  | 33.524s   |

All times recorded using a Intel Core i7-9750H CPU. 

## Future Plans

* Add documentation on `NTT` transform for polynomials
* Add documentation for working with DRBG and setting the seed

### Include Dilithium

Using [`polynomials.py`](polynomials.py) and [`modules.py`](modules.py) 
this work could be extended to
have a pure python implementation of CRYSTALS-Dilithium too.

I suppose then this repo should be called `crystals-py` but I wont
get ahead of myself.

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

We additionally include functions for `PolynomialRing` and `Polynomial`
to move from bytes to polynomials (and back again). 

- `PolynomialRing`
  - `parse(bytes)` takes $3n$ bytes and produces a random polynomial in $R_q$
  - `decode(bytes, l)` takes $\ell n$ bits and produces a polynomial in $R_q$
  - `cbd(beta, eta)` takes $\eta \cdot n / 4$ bytes and produces a polynomial in $R_q$ with coefficents taken from a centered binomial distribution
- `Polynomial`
  - `self.encode(l)` takes the polynomial and returns a length $\ell n / 8$ bytearray
  
#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> f = R.random_element()
>>> # If we do not specify `l` then it is computed for us (minimal value)
>>> f_bytes = f.encode()
>>> f_bytes.hex()
'06258910'
>>> R.decode(f_bytes) == f
True
>>> # We can also set `l` ourselves
>>> f_bytes = f.encode(l=10)
>>> f_bytes.hex()
'00180201408024010000'
>>> R.decode(f_bytes, l=10) == f
True
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
>>> R = PolynomialRing(11, 8)
>>> f = R.random_element()
>>> f
9 + 3*x + 5*x^2 + 2*x^3 + 9*x^4 + 10*x^5 + 6*x^6 + x^7
>>> f.compress(1)
x + x^2 + x^6
>>> f.decompress(1)
6*x + 6*x^2 + 6*x^6
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
>>> # We can add and subtract matricies of the same size
>>> A + A
[  2*x + 6*x^2, 8 + 6*x^7]
[6*x^3 + 7*x^7,     2*x^4]
>>> A - A
[0, 0]
[0, 0]
>>> # A vector can be constructed by a list of coefficents
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

We also carry through `Matrix.encode()` and 
`Module.decode(bytes, n_rows, n_cols)` 
which simply use the above functions defined for polynomials and run for each
element.

#### Example

We can see how encoding / decoding a vector works in the following example.
Note that we can swap the rows/columns to decode bytes into the transpose
when working with a vector.

```python
>>> R = PolynomialRing(11, 8)
>>> M = Module(R)
>>> v = M([R.random_element() for _ in range(2)])
>>> v_bytes = v.encode()
>>> v_bytes.hex()
'd'
>>> M.decode(v_bytes, 1, 2) == v
True
>>> v_bytes = v.encode(l=10)
>>> v_bytes.hex()
'a014020100103004000040240a03009030080200'
>>> M.decode(v_bytes, 1, 2, l=10) == v
True
>>> M.decode(v_bytes, 2, 1, l=10) == v.transpose()
True
>>> # We can also compress and decompress elements of the module
>>> v
[5 + 10*x + 4*x^2 + 2*x^3 + 8*x^4 + 3*x^5 + 2*x^6, 2 + 9*x + 5*x^2 + 3*x^3 + 9*x^4 + 3*x^5 + x^6 + x^7]
>>> v.compress(1)
[1 + x^2 + x^4 + x^5, x^2 + x^3 + x^5]
>>> v.decompress(1)
[6 + 6*x^2 + 6*x^4 + 6*x^5, 6*x^2 + 6*x^3 + 6*x^5]
```

## Baby Kyber

A great resource for learning Kyber is available at
[Approachable Cryptography](https://cryptopedia.dev/posts/kyber/).

We include code corresponding to their example in `baby_kyber.py`.
