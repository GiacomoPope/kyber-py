"""
The parameters defined in the FIPS 203 document.

Includes the ML-KEM-512, ML-KEM-768, and ML-KEM-1024 parameters
and initialised objects with them.
"""

from .ml_kem import ML_KEM

# TODO: we can only allow a user to select one of the following three
# we should maybe put these into the class and only allow a user to
# select 128, 192 or 256 bit security.
DEFAULT_PARAMETERS = {
    "ML512": {"k": 2, "eta_1": 3, "eta_2": 2, "du": 10, "dv": 4},
    "ML768": {"k": 3, "eta_1": 2, "eta_2": 2, "du": 10, "dv": 4},
    "ML1024": {"k": 4, "eta_1": 2, "eta_2": 2, "du": 11, "dv": 5},
}
"""Parameters for the :py:obj:`.ML_KEM` objects."""

ML_KEM_512 = ML_KEM(DEFAULT_PARAMETERS["ML512"])
"""
Key exchange object that uses ML-KEM-512 parameters internally.

Provides about 128 bit level of security.

Part of stable API.
"""

ML_KEM_768 = ML_KEM(DEFAULT_PARAMETERS["ML768"])
"""
Key exchange object that uses ML-KEM-768 parameters internally.

Provides about 192 bit level of security.

Part of stable API.
"""

ML_KEM_1024 = ML_KEM(DEFAULT_PARAMETERS["ML1024"])
"""
Key exchange object that uses ML-KEM-1024 parameters internally.

Provides about 256 bit level of security.

Part of stable API.
"""
