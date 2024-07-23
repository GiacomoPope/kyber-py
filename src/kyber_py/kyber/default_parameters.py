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

# Initialise with default parameters for easy import
Kyber512 = Kyber(DEFAULT_PARAMETERS["kyber_512"])
Kyber768 = Kyber(DEFAULT_PARAMETERS["kyber_768"])
Kyber1024 = Kyber(DEFAULT_PARAMETERS["kyber_1024"])
