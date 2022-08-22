# CRYSTALS-Kyber Python Implementation

This repository contains a pure python implementation of CRYSTALS-Kyber 
following the most recent (v3.02)
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf))

**TODO**: Implement the NTT to speed up polynomial multiplication.

## Disclaimer

:warning: **Under no circumstances should this be used for a cryptographic application.** :warning:

I have written `kyber-py` as a way to learn about the way Kyber works, and to
try and create a clean, well commented implementation which people can learn 
from.

This code is not constant time, or written to be performant. Rather, it was 
written so that reading though Algorithms 1-9 in the 
[specification](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
closely matches the code which is seen in `kyber.py`.

## Example

There are three functions exposed on the `Kyber` class which are intended
for use:

- `Kyber.keygen()`: generate a keypair `(pk, sk)`
- `Kyber.encrypt(pk)`: generate a challenge and a shared key `(c, K)`
- `Kyber.keygen(sk, c)`: generate the shared key `K`

To use `Kyber()` it must be initialised with a dictionary of the 
protocol parameters. An example can be seen in `DEFAULT_PARAMETERS`.

Additionally, the class has been initialised with these default parameters, 
so you can simply import the NIST level you want to play with:

```python
>>> from kyber import Kyber512
>>> pk, sk = Kyber512.keygen()
>>> c, key = Kyber512.encrypt(pk)
>>> _key = Kyber512.decrypt(c, sk)
>>> assert key == _key
```

The above example would also work with `Kyber768` and `Kyber1024`.

## Future Plans

### Faster multiplication by using NTT 

At the moment, the implementation is very slow, as we perform schoolbook
multiplication on the polynomials. This should be updated to instead use
the number theoretic transform as is outlined in the spec.

## Discussion of Implementation
### Polynomials

The file `polynomials.py` contains the classes `PolynomialRing` and 
`Polynomial`. This implements the univariate polynomial ring

$$
R = \mathbb{F}_q[X] /(X^n + 1) 
$$

The implementation is inspired by `SageMath` and you can create the
ring $R = \mathbb{F}_{11}[X] /(X^8 + 1)$ in the following way:

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

### Modules

```
TODO
```