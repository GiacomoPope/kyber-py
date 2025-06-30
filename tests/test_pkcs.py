import unittest
import copy

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

try:
    from ecdsa.der import unpem
    from ecdsa import der
    from kyber_py.ml_kem.pkcs import (
        ek_to_pem,
        ek_from_pem,
        ek_from_der,
        dk_to_pem,
        dk_from_pem,
        dk_from_der,
    )

    ECDSA_PRESENT = True
except ImportError:
    ECDSA_PRESENT = False


class BaseTestSetup(object):
    def test_export_ek_to_pem(self):
        pem = ek_to_pem(self.kem, self.ek)

        self.assertEqual(unpem(pem), unpem(self.ek_pem))

    def test_export_ek_to_pem_with_too_long_value(self):
        with self.assertRaises(ValueError) as e:
            ek_to_pem(self.kem, self.ek + b"X")

        self.assertIn("Provided key size", str(e.exception))

    def test_export_with_oid_missing(self):
        kem = copy.copy(self.kem)
        kem.oid = None

        with self.assertRaises(ValueError) as e:
            ek_to_pem(kem, self.ek)

        self.assertIn("Only KEMs with specified OIDs", str(e.exception))

    def test_import_ek_from_pem(self):
        kem, ek = ek_from_pem(self.ek_pem)

        self.assertIs(kem, self.kem)
        self.assertEqual(ek, self.ek)

    def test_export_dk_to_pem_seed_only(self):
        pem = dk_to_pem(self.kem, self.dk, self.seed, form="seed")

        self.assertEqual(unpem(pem), unpem(self.dk_seed_pem))

    def test_export_dk_to_pem_priv_only(self):
        pem = dk_to_pem(self.kem, self.dk, self.seed, form="expanded")

        self.assertEqual(unpem(pem), unpem(self.dk_priv_pem))

    def test_export_dk_to_pem_both(self):
        pem = dk_to_pem(self.kem, self.dk, self.seed, form="both")

        self.assertEqual(unpem(pem), unpem(self.dk_seed_priv_pem))

    def test_export_dk_to_pem_seed_only_auto(self):
        pem = dk_to_pem(self.kem, seed=self.seed)

        self.assertEqual(unpem(pem), unpem(self.dk_seed_pem))

    def test_export_dk_to_pem_priv_only_auto(self):
        pem = dk_to_pem(self.kem, dk=self.dk)

        self.assertEqual(unpem(pem), unpem(self.dk_priv_pem))

    def test_export_dk_to_pem_both_auto(self):
        pem = dk_to_pem(self.kem, self.dk, self.seed)

        self.assertEqual(unpem(pem), unpem(self.dk_seed_priv_pem))

    def test_export_dk_to_pem_derive_expanded(self):
        pem = dk_to_pem(self.kem, seed=self.seed, form="both")

        self.assertEqual(unpem(pem), unpem(self.dk_seed_priv_pem))

    def test_export_dk_to_seed_with_seed_missing(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, dk=self.dk, form="seed")

        self.assertIn("requires specifing seed", str(e.exception))

    def test_export_dk_to_both_with_seed_missing(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, dk=self.dk, form="both")

        self.assertIn("requires specifing seed", str(e.exception))

    def test_export_with_no_keys_specified(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, form="both")

        self.assertIn("dk or seed must be provided", str(e.exception))

    def test_export_with_wrong_form_specified(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, self.dk, self.seed, form="foobar")

        self.assertIn("Invalid form", str(e.exception))

    def test_export_with_too_long_dk(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, self.dk + b"X", self.seed)

        self.assertIn("Invalid decapsulation key size", str(e.exception))

    def test_export_with_too_short_dk(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, self.dk[:-1], self.seed)

        self.assertIn("Invalid decapsulation key size", str(e.exception))

    def test_export_with_too_long_seed(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, self.dk, self.seed + b"X")

        self.assertIn("Invalid seed size", str(e.exception))

    def test_export_with_too_short_seed(self):
        with self.assertRaises(ValueError) as e:
            dk_to_pem(self.kem, self.dk, self.seed[:-1])

        self.assertIn("Invalid seed size", str(e.exception))

    def test_import_from_seed_only(self):
        kem, dk, seed, ek = dk_from_pem(self.dk_seed_pem)

        self.assertIs(kem, self.kem)
        self.assertEqual(dk, self.dk)
        self.assertEqual(seed, self.seed)
        self.assertEqual(ek, self.ek)

    def test_import_from_both(self):
        kem, dk, seed, ek = dk_from_pem(self.dk_seed_priv_pem)

        self.assertIs(kem, self.kem)
        self.assertEqual(dk, self.dk)
        self.assertEqual(seed, self.seed)
        self.assertEqual(ek, self.ek)

    def test_import_from_expanded(self):
        kem, dk, seed, ek = dk_from_pem(self.dk_priv_pem)

        self.assertIs(kem, self.kem)
        self.assertEqual(dk, self.dk)
        self.assertEqual(seed, None)
        self.assertEqual(ek, self.ek)


@unittest.skipUnless(ECDSA_PRESENT, "requires ecdsa package")
class TestMLKEM512(unittest.TestCase, BaseTestSetup):
    @classmethod
    def setUpClass(cls):
        cls.kem = ML_KEM_512
        cls.seed = bytes(range(64))

        cls.ek, cls.dk = cls.kem.key_derive(cls.seed)

        cls.dk_seed_pem = b"""-----BEGIN PRIVATE KEY-----
MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
-----END PRIVATE KEY-----
"""
        cls.dk_priv_pem = b"""-----BEGIN PRIVATE KEY-----
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
JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
-----END PRIVATE KEY-----
"""
        cls.dk_seed_priv_pem = b"""-----BEGIN PRIVATE KEY-----
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
Pj8=
-----END PRIVATE KEY-----
"""
        cls.ek_pem = b"""-----BEGIN PUBLIC KEY-----
MIIDMjALBglghkgBZQMEBAEDggMhADmVgV5ZfRBDVc8pqlMzyTJRhp1bzb5IcST2
Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHmvG+QsOSb
aTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbWf/mqvJdQ
Pyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lAk0Frg7gS
Tmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8XSCVcuD8
dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoEZM5BqLtE
wtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRrevpsRZMl
JqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5JPSQpaxU
lfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6tnVUAAUH
gVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10zgGocjicy
r5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyekb7U7oR3l
y0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oXthQzzRr4
D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPMFgCQPmUp
NWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGmgx1bVMC3
kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9huqtxp6PT
UZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2NoPwS/eg
nMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3guBw7xZoG
WhttY7Js
-----END PUBLIC KEY-----
"""


@unittest.skipUnless(ECDSA_PRESENT, "requires ecdsa package")
class TestMLKEM768(unittest.TestCase, BaseTestSetup):
    @classmethod
    def setUpClass(cls):
        cls.kem = ML_KEM_768
        cls.seed = bytes(range(64))

        cls.ek, cls.dk = cls.kem.key_derive(cls.seed)

        cls.dk_seed_pem = b"""-----BEGIN PRIVATE KEY-----
MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
-----END PRIVATE KEY-----
"""
        cls.dk_priv_pem = b"""-----BEGIN PRIVATE KEY-----
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
JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
-----END PRIVATE KEY-----
"""
        cls.dk_seed_priv_pem = b"""-----BEGIN PRIVATE KEY-----
MIIJvgIBADALBglghkgBZQMEBAIEggmqMIIJpgRAAAECAwQFBgcICQoLDA0ODxAR
EhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwSC
CWAn0qd/M3VvYSCO8ROr6CWVhz1KvHMOW11nlSm/akzrY4NCcjGoYS9BVQUVrLpS
5I6ti5QoM7vmhl0T0Up50sXD4H8KBW2N56rfyroFjEk8gLN8q4xWJ1O7O6a27IKX
+IXqp1QNUwAVqEQG5VsTZrV34jbOWKJtih61pE1UIyPCFn2b9KR/mFaZygW65DuN
7GF/AjgKOJCv1LjH7H7eJlU6Al885bxdemITAwQjXLGtSDa1ZrW4Y72b20WihEpw
R7bI04PkSFJeBAtNyKK0jGw3yW1i1D8/2I4ogcQKIFyeJI9lK1kngad5+GiA8qFH
tnhj85HMGlqQjACV4HISKR4u+KNuuanAxgcyJbNHA6SvBJOCxHVz2mj96SRa1ETj
Gx+9tSHx9h83vAzvKSBn5nDSih/9kE9vEZCplpGKEwN6bKvzw3O/gpbNN6szundG
gJzD+K3hs2Ob1Xv8xpZQqq8d4Zj8TARjKZ5SxGF4DMQo/F0EpcUYUMumwqUnQ0Bn
V5PdoJvkTCnmOVxl+F0qCnxt9BHmkRsfLLbDUc0uh19Rtji+d2CX6T4vKy+D2gvu
9KqFup52OrZFAqDKUiLp6rWztwiO1SBg6Mgmm5Q6casK4cWxtofS4BnPgDa8+b9u
e6w6qjbkFmD6pFQPJkjNk6GJ7Fwt6nC6yqpP/JBvkIEOobZ78k8seM9rqIGq6mHA
ZSv/lbG65EJtF3O5zCyoLCHjjGNuOxxSMkSYawvoqD9d1c8tVHYvs8Xr9ZuOiFMC
sc5HAz7fdg9OApvkC21WaxnddYrNXHQSh4ExJE+QFyxT8mZjwh2QUwHUi6+RyRfM
d3np2IAswQ2Jo3BQmaKtOjqIlnQ8EURpgJO+JX2stm3HhSKLkSyNll0Uqig0LDrE
qT/vpTKyCUXdwQIBOcFNY4uQjE3d6aBkW5Wy5EFNQLt58EQTgw8VqHPCi7cFnCdB
ACAV8gQI8FjnFbC/mVtTgLfdMloFarl+ZZor4M32wzcxxoOmNLdx6MkqE5ruS7Dk
nHB3Mh1C/BmffB8pjKYl0iOlwmOgPMSBWbeBJmW3hjfk4YcgssKaa5n0J2aky8Tc
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
Pj8=
-----END PRIVATE KEY-----
"""
        cls.ek_pem = b"""-----BEGIN PUBLIC KEY-----
MIIEsjALBglghkgBZQMEBAIDggShACmKoQ1CPI3aBp0CvFnmzfA6CWuLPaTKubgM
pKFJB2cszvHsT68jSgvFt+nUc/KzEzs7JqHRdctnp4BZGWmcAvdlMbmcX4kYBwS7
TKRTXFuJcmecZgoHxeUUuHAJyGLrj1FXaV77P8QKne9rgcHMAqJJrk8JStDZvTSF
wcHGgIBSCnyMYyAyzuc4FU5cUXbAfaVgJHdqQw/nbqz2ZaP3uDIQIhW8gvEJOcg1
VwQzao+sHYHkuwSFql18dNa1m75cXpcqDYusQRtVtdVVfNaAoaj3G064a8SMmgUJ
cxpUvZ1ykLJ5Y+Q3Lcmxmc/crAsBrNKKYjlREuTENkjWIsSMgjTQFEDozDdskn8j
pa/JrAR0xmInTkJFJchVLs47P+JlFt6QG8fVFb3olVjmJslcgLkzQvgBAATznmxs
lIccXjRMqzlmyDX5qWpZr9McQChrOLHBp4RwurlHUYk0RTzoZzapGfH1ptUQqG9U
VPw5gMtcdlvSvV97NrFBDWY1yM60fE3aDXaijqyTnHHDAkgEhmxxYmZYRCFjwsIh
F+UKzvzmN4qYVlIwKk7wws4Mxxa3eW4ray43d9+hrD2iWaMbWptTD4y2OKgaYqww
GEmrr5WnMBvaMAaJCb/bfmfbzLs4pVUaJbGjoPaFdIrVdT2IgPABbGJ0hhZjhMVX
H+I2WQA2TQODEeLYdds2ZoaTK17GAkMKNp6Hpu9cM4eGZXglvUwFes65I+sJNeaQ
XmO0ztf4CFenc91ksVDSZhLqmsEgUtsgF78YQ8y0sygbaQ3HKK36hcACgbjjwJKH
M1+Fa0/CiS9povV5Ia2gGRTECYhmLVd2lmKnhjUbm2ZJPat5WU2YbeIQDWW6D/Tq
WLgVONJKRDWiWPrCVASqf0H2WLE4UGXhWNy2ARVzJyD0BFmqrBXkBpU6kKxSmX0c
zQcAYO/GXbnmUzVEZ/rVbscTyG51QMQjrPJmn1L6b0rGiI2HHvPoR8ApqKr7uS4X
skqgebH0GbphdbRCr7EZCdSla3CgM1soc5IYqnyTSOLDwvPrPRWkHmQXwN2Uv+sh
QZsxGnuxOhgLvoMyGKmmsXRHzIXyJYWVh6cwdwSay8/UTQ8CVDjhXRU4Jw1Ybhv4
MZKpRZz2PA6XL4UpdnmDHs8SFQmFHLg0D28Qew+hoO/Rs2qBibwIXE9ct4TlU/Qb
kY+AOXzhlW94W+43fKmqi+aZitowwmt8PYxrVSVMyWIDsgxCruCsTh67QI5JqeP4
edCrB4XrcCVCXRMFoimcAV4SDRY7DhlJTOVyU9AkbRgnRcuBl6t0OLPBu3lyvsWj
BuujVnhVwBRpn+9lrlTHcKDYXBhADPZCrtxmB3e6SxOFAr1aeBL2IfhKSClrmN1D
IrbxWCi4qPDgCoukSlPDqLFDVxsHQKvVZ9rxzenHnCBLbV4lnRdmoxu7y05qBc9F
AhdrMBwcL0Ekd1AVe87IXoCbMKTWDXdHzdD1uZqoyCaYdRd5OqqAgKCxJKhVjfcr
vje3X07btr6CFtbGM/srIoDiURPYaV5DSBw+6zl+sZJQUim2eiAeqJPD4ssy2ovD
QvpN6gV4
-----END PUBLIC KEY-----
"""


@unittest.skipUnless(ECDSA_PRESENT, "requires ecdsa package")
class TestMLKEM1024(unittest.TestCase, BaseTestSetup):
    @classmethod
    def setUpClass(cls):
        cls.kem = ML_KEM_1024
        cls.seed = bytes(range(64))

        cls.ek, cls.dk = cls.kem.key_derive(cls.seed)

        cls.dk_seed_pem = b"""-----BEGIN PRIVATE KEY-----
MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
-----END PRIVATE KEY-----
"""
        cls.dk_priv_pem = b"""-----BEGIN PRIVATE KEY-----
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
JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
-----END PRIVATE KEY-----
"""
        cls.dk_seed_priv_pem = b"""-----BEGIN PRIVATE KEY-----
MIIMvgIBADALBglghkgBZQMEBAMEggyqMIIMpgRAAAECAwQFBgcICQoLDA0ODxAR
EhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwSC
DGD3e39rFcc/4sxUa2f7d0yhm0LNRj6p+7mEykd6d7bHEIfL8FGr5HNqkHLG6HDI
MRxVlj9QCjx7G48qWFWPScYlJ7bFlLXnrLO89ZcnOldDUX0VEgi9SqYedbpnsL1Z
SplJGWJ6wKgE1InhcTNrwzn0ZmcG5RNEErNmgj1QMYyL8mGrEgoooE/sAcwV8rcZ
Es7lSqju2FRpS2uohrXrdmHm1WqsITzB2BTVkrOVVU+udEdtNDcRYxKb+GRSclBg
bMIaU3RrIJlwd7uhVXM7KKTn+gd2OZUkdj60gc6qETZsNHSgRoX0DD8IsEJPQL/5
SaCsknBMO6DG6zbx9bYh2L8rYye+tXzT+suUGG/j/JqwoUNLspHSybtwcjBX4iVA
WWVvVlkZoyz3RXneiWgc0sWpNaUrSqotJMtdXJ4gcp7FSS7DaWHvuKKMvACsMDUj
KV89gDarwWAzB85w14SKNWV6VofdWJkn6mNzFiarsm7E5DG462s7C8HoJXPuc7Gg
IRgxg1KBCK4urK3blbRkoLmEacMZzCe/oBvDEFSmjAVQKxZiuHn+mKFxHDQm9kNs
sCFM6jeaw6fl+2AYSjfB2h7aYcbDnB3U6EeEWBHyo1ikNzFShTbUoykbBBWMLD3G
QWJIgmeLx4BfWKnZTHEEVnhGogROZa7OKiJTcrYCR5mlR31gI3UEqlwKxXvHCjVY
wIxN5ofvEwK0/LVZRBPSLLlZvDG+QjRQQDxrxX3EEbP++sEFKsS7FixEVFpMqAiS
ZX+hOgssSCztYpzEmZ2WnFk9Sq3wc8w+OkWOeKiqA5QI5lK+k7IMi0LsWw5QI52s
cmBShRptFTEuw57SCLciCaV3xrJ3ARKJV0nVJg591EbAsBGMEAC+aAHSYR/PAHkq
nMT0tJki+aLUucj6Wl0NYFBmMafpcc7oQLCPpjwTcp1+parHA1KphM22aTMcunWP
6H7Dkxs+MWH8x0eqdJQkaJ/q4Uv3yaL/uhMCshK4A3LY6QSdtpo6EmHQooWam01X
iZ4LpBYHobZ6fA4SkjaJ+MY5U3fZcMdJCkEpYRodBcO3gTvtlFQgcj9/lSWod5P6
+7/KmC5mu4BoHIMkionaCEwZiC9I8x5/wJCTpJ6f0JaRsCHt9GOvxRm2KFOBYRg0
YRX7C4gsxkgvPFy8wcGJRpfhI5WYs0sqmnrNFSRNBpDIgZQJepvtpYXofENxJGJM
IQdo5iFdN2SCZT64mUeHfBGNNwxpam/8wQGK5BOgio0P+qgZlF2noWfCKZEykMrR
yAo2klh2JhDqJT5i3CQiajDIksEhNsMm8T9ERmZHErC5C8BjtAKFk8veBs3CIoni
QMfilrWRcsGu2oyZ4FEtGgFjqULqMxSOaTfAJgKUJLgbmWsd8i6gYj7GXGvwk1AM
8781N0rcOSA1ynxYO5loW8pUGggHsWOs0IiL4Dhd6oINpG5Nu0TS5GLHNLg6Rz/t
E2QnMVklfMJZqMVnbBx21B1WuZB+wcNZnJ6JB0A6J6cF42GbBLCtBG6OyBacF7Rg
1EwMDERk0ETJRhhrxyWWUIOokrzElcBUAxH/mz5RksMD2I+LpGqQHHgu8COI8bKt
2ralNQ/DY5cA4xVDNzN+SheNNRzStW7h8L/qNKrPoz0ux5HlB1LU0DTLHJUVcsqq
XE2QlHtrF1pt08Yqd7uPesmuJHGbU8KxIKKHaYbiF7cr187kSnJlsRzuGrImF2Kz
Gjc4OGlpwIJft5RS5lLhFC/HPJ32+6QReVtHF5IrKbotU6vlqMDcwWAbCWyW15OP
1aaKh5fHuUd6hqRy612iUMsv7DGNg8j0O76OEcNeN300k2bIXEOCWX9vwnoAUcD7
ALAsAcog+aQn8XJZlHfKaQzBMn4PAl+A7DOKgKFZ4wjBKifbGn4blgqZ0338Iocu
UZMPKMZRqyIfU6uu4gutmj6ry6uRMlG/E1vrKWF7V1QzPE2q2yI4NBwq2TeBhigP
ZElEC3hLp49drETY9ls7dCGVA5fDkTot0j7G0ctxezal/JWvGR4ngpaUjBJU6oa0
7ABLlMKUUBERkYI7NRTJrB6j2YJcy4Y5Oi37BGVPohktN7+tHEl8ZQLu5cqApzv8
4Lr1pUqIWFpAE5ej0jL0JqevsIK8IaRDFwkOqsdZLC6oimU8RJHqGTkxM19S6Ymj
xMxW2cVTcy1XxHD7Qat1m2XS0ERFOC/NnE40ShEo+p4R4ENY4ZLtAUsjIyp+4rIu
I3F/RBEe4zV1OZw3ZG2pgT7JshKv6U5dxcIzCnKUzB9CNKbT+7TxaFq4iSwErLF8
0cFw17BhG2pxdseUzIxn9V/JI8KtIDEA82WZGILDAkPXeBOEO17HyWQDImNwYJLs
8Ax1Fr5k5FmMpCJsBpu15n5Bdc8ihsjdXEiKbFhh8xuqC9AmlHDotVHdO804yGwS
+c2xdsd9yLbAKnAfR4kCyFU/aUwNgnJ7TEpcLBBBISqhJ0gIuCERs3fsdSFOmxl4
92AE1BOdmGE/S46Y0gr3tTQHOlCalZt6dWT5tAyiGL9hgpMgqFAgF5VNMo16xsdp
7ClwB1bnsGhbNA1eEYBZUEpJqaUKEBmOsQpXhGeOtCfXtLq7lVKTOwYol5c+Exjq
8KDqw3WEplQBsXA+BCrM2DdTFIPyQcrc0cHTeBGeaUQp2xmayJHkxTQ3Vwhbs654
Nmc1DERY2XZy6GHoCx0meVEOo6byNgx3pGlCx6BqVU0igIDIS0eu8U2xdiDLFsBq
swob5M2nCCvp+H6cIRxGkWNJpbqOqlIBxylKPAiFtTtldFIQiCXsZGyQoEYSMk7n
0DGv5TQxMsvvZ7bvsaXsKAm3c1OM53s9iwTrCzwiVgEeTHFsGai6B1K/cUkhF2Sf
BhXDKQ/Cmkb95L1S25KG1gM4gkQlnBWnrCtkCmDMAzdqWEGj+4pHNWj6mxomchXz
TAFpew8OYnF11yEFt3B8KbnmFL3DOm9sgYqVNwtCeILXtHZ5ap7G65kydM2bI5Go
K6ReM5PS6a6XIcqdbBuYi1gncT+Qplhd6UM1KMArA84Qu19yATjQ+7TDDBJmuRjl
KSXf4Xs3+V0ivKVPR1kZrIWQmMDw0IrFh17ym1b9FB5u8V9wCgtm85WVxYgXc3PE
ZpshvAceTDql8LSjG2JY812iSsPNKcfyCSQQxQeDVbE4+1Omua5uC5wIJD57qkXE
c3brjH8T1M9RqnNvoxVAySQfNw2lRL+fnCjZpX4vKnypWk5LRm5kGrO8x2rfETnV
Z6bxK1Lzpl5+wKria8qoxVgzsE5ZmY68mhkw+7bSIzxT0sH4uVGOPC3nOhne5rOA
pbMpcc9k4Sn9bB+m511KI0UB6WbdOlQK9cj080prSiU+4oSSVm1eZ8b1WFX8sFBv
sGwVZ0TZoDoxom+pTK0U8Ve38wPQemnHc3aPy00HnAkFlwOgw6lN5Lmeo6LxZYPQ
+RcKOVDbB7TwvDCAKSf595YbYlmJJjapUConBTA2N3md00TaRRwc979nhAzrMHmr
jGuMGSf2QFPGEkUMRcnmA7wWZm5ZazRx4QO28VRHQk0XAiBIER/7034cZw9k8UuK
ezK5TBpJtF3S/DjNUonZEK1jYCz14TBCxkrGeXuJ+1Ua0I4FqS0gDMy35xLvI8kx
LLNQ8CmrU34oc0f9MHWsEJBqeD8cbAfMuI9BIoxL4cZA95C1w6XV08p5JJXXS8Rh
ViZYwHrGACdrkkq1vJvh8ElMt2+C9GCnSAlyZjOB4WmZYGHXmYWexU1PXKXEEcAd
sVl7Fll3Zp3hOpKKNK+6wlj+qMR2QjnJQh3DEZv1tHaZIGl4MnscU0XvdGp5g4Qf
BW4lNBAKsk1OmrvQsXxqlb1MPA5A9p4WEqzusouZCGyVEW5yBCc4kzkL9GuJmzYo
aw6/GUe7mIT3Mson2oKxm13AzH+IhXFJEIiLIxDE+TGdQQs05kM7kAPiF2u5lSV0
VhBuiVIWO4ulklMMxaoK60OtOY/p6XuqUj16RDFnfD068HGeR124XKla9Qib6r6w
Wy+qtIlrpg+ByIRypXtGqCiCagzftEb4GJGC0r9erE7BzF3q9ZnIoT5II1QG0X/9
3INEtsZphKhoqpL6AiJ6CGlQ6wyHAe1Y3GKHdrmDiC4RdWE0nlwTGn4RagRjhh19
GGY8VifDjHFH3arf1IrNekU1ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9
Pj8=
-----END PRIVATE KEY-----
"""
        cls.ek_pem = b"""-----BEGIN PUBLIC KEY-----
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
uYOILhF1
-----END PUBLIC KEY-----
"""


@unittest.skipUnless(ECDSA_PRESENT, "requires ecdsa package")
class TestMalfomedKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kem = ML_KEM_512
        cls.seed = bytes(64)
        cls.ek, cls.dk = cls.kem.key_derive(cls.seed)

    def test_ek_sanity_check(self):
        enc = der.encode_sequence(
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_bitstring(self.ek, 0),
        )

        kem, key = ek_from_der(enc)

        self.assertEqual(kem, self.kem)
        self.assertEqual(key, self.ek)

    def test_ek_trailing_junk_after_pub_key(self):
        enc = (
            der.encode_sequence(
                der.encode_sequence(
                    der.encode_oid(*self.kem.oid),
                ),
                der.encode_bitstring(self.ek, 0),
            )
            + b"\x00"
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            ek_from_der(enc)

        self.assertIn("Trailing junk after DER public key", str(e.exception))

    def test_ek_wrong_oid(self):
        enc = der.encode_sequence(
            der.encode_sequence(
                der.encode_oid(1, 2, 3, 4),
            ),
            der.encode_bitstring(self.ek, 0),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            ek_from_der(enc)

        self.assertIn(
            "Not recognised algoritm OID: (1, 2, 3, 4)", str(e.exception)
        )

    def test_ek_parameters_in_alg_id(self):
        enc = der.encode_sequence(
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
                der.encode_sequence(),
            ),
            der.encode_bitstring(self.ek, 0),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            ek_from_der(enc)

        self.assertIn("Parameters specified for ML-KEM OID", str(e.exception))

    def test_ek_junk_after_public_key(self):
        enc = der.encode_sequence(
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_bitstring(self.ek, 0),
            der.encode_integer(2),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            ek_from_der(enc)

        self.assertIn(
            "Trailing junk after public key bitsting", str(e.exception)
        )

    def test_ek_unexpected_size_of_key(self):
        enc = der.encode_sequence(
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_bitstring(self.ek + b"\x00", 0),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            ek_from_der(enc)

        self.assertIn(
            "Wrong key size for the OID in structure", str(e.exception)
        )

    def test_dk_sanity_both(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                ),
            ),
        )

        kem, expanded, seed, ek = dk_from_der(enc)

        self.assertEqual(self.kem, kem)
        self.assertEqual(self.dk, expanded)
        self.assertEqual(self.seed, seed)
        self.assertEqual(self.ek, ek)

    def test_dk_sanity_seed(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_implicit(0, self.seed),
            ),
        )

        kem, expanded, seed, ek = dk_from_der(enc)

        self.assertEqual(self.kem, kem)
        self.assertEqual(self.dk, expanded)
        self.assertEqual(self.seed, seed)
        self.assertEqual(self.ek, ek)

    def test_dk_sanity_expanded_only(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_octet_string(self.dk),
            ),
        )

        kem, expanded, seed, ek = dk_from_der(enc)

        self.assertEqual(self.kem, kem)
        self.assertEqual(self.dk, expanded)
        self.assertEqual(None, seed)
        self.assertEqual(self.ek, ek)

    def test_dk_trailing_junk(self):
        enc = (
            der.encode_sequence(
                der.encode_integer(0),
                der.encode_sequence(
                    der.encode_oid(*self.kem.oid),
                ),
                der.encode_octet_string(
                    der.encode_sequence(
                        der.encode_octet_string(self.seed),
                        der.encode_octet_string(self.dk),
                    ),
                ),
            )
            + b"\x00"
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn(
            "Trailing junk after private key structure", str(e.exception)
        )

    def test_dk_wrong_version(self):
        enc = der.encode_sequence(
            der.encode_integer(1),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Unsupported version: 1", str(e.exception))

    def test_dk_wrong_oid(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(1, 3, 2, 1),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn(
            "Not recognised algorithm OID: (1, 3, 2, 1)", str(e.exception)
        )

    def test_dk_junk_after_oid(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
                der.encode_integer(1),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Junk after algorithm OID", str(e.exception))

    def test_dk_junk_after_both_encoding(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                )
                + b"\x00",
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Junk after both encoding", str(e.exception))

    def test_dk_junk_in_both_encoding(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk),
                    der.encode_integer(1),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn(
            "Junk after 'expandedKey' in 'both' value", str(e.exception)
        )

    def test_dk_wrong_expanded_key_size(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed),
                    der.encode_octet_string(self.dk + b"\x00"),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn(
            "Invalid expanded key size in encoding", str(e.exception)
        )

    def test_dk_wrong_seed_size(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_sequence(
                    der.encode_octet_string(self.seed + b"\x00"),
                    der.encode_octet_string(self.dk),
                ),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Invalid length of seed in encoding", str(e.exception))

    def test_dk_wrong_tag_in_seed_encoding(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_implicit(1, self.seed),
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn(
            "Unexpected tag in private key encoding", str(e.exception)
        )

    def test_dk_junk_after_seed_encoding(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_implicit(0, self.seed) + b"\x00",
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Junk after seed encoding", str(e.exception))

    def test_dk_junk_after_expanded_key(self):
        enc = der.encode_sequence(
            der.encode_integer(0),
            der.encode_sequence(
                der.encode_oid(*self.kem.oid),
            ),
            der.encode_octet_string(
                der.encode_octet_string(self.dk) + b"\x00",
            ),
        )

        with self.assertRaises(der.UnexpectedDER) as e:
            dk_from_der(enc)

        self.assertIn("Junk after expandedKey", str(e.exception))
