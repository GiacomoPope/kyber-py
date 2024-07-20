from ml_kem.ml_kem import ML_KEM

# TODO: we can only allow a user to select one of the following three
# we should maybe put these into the class and only allow a user to
# select 128, 192 or 256 bit security.
DEFAULT_PARAMETERS = {
    "ML128": {"k": 2, "eta_1": 3, "eta_2": 2, "du": 10, "dv": 4},
    "ML192": {"k": 3, "eta_1": 2, "eta_2": 2, "du": 10, "dv": 4},
    "ML256": {"k": 4, "eta_1": 3, "eta_2": 2, "du": 11, "dv": 5},
}

ML_KEM128 = ML_KEM(DEFAULT_PARAMETERS["ML128"])
ML_KEM192 = ML_KEM(DEFAULT_PARAMETERS["ML192"])
ML_KEM256 = ML_KEM(DEFAULT_PARAMETERS["ML256"])
