from .kyber import Kyber

DEFAULT_PARAMETERS = {
    "kyber_512": {
        "k": 2,
        "eta_1": 3,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_768": {
        "k": 3,
        "eta_1": 2,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_1024": {
        "k": 4,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 11,
        "dv": 5,
    },
}
"""
Lattice parameters for the Kyber key exchange.

To be used for initialisation of :py:obj:`.Kyber` objects.
"""

# Initialise with default parameters for easy import
Kyber512 = Kyber(DEFAULT_PARAMETERS["kyber_512"])
"""
Key exchange object that uses Kyber512 parameters internally.

Provides about 128 bit level of security.
"""

Kyber768 = Kyber(DEFAULT_PARAMETERS["kyber_768"])
"""
Key exchange object that uses Kyber768 parameters internally.

Provides about 192 bit level of security.
"""

Kyber1024 = Kyber(DEFAULT_PARAMETERS["kyber_1024"])
"""
Key exchange object that uses Kyber1024 parameters internally.

Provides about 256 bit level of security.
"""
