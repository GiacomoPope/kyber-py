from ml_kem import ML_KEM128, ML_KEM192, ML_KEM256


def _test_ml_kem(ml_kem):
    for _ in range(50):
        (ek, dk) = ml_kem.keygen()
        (K, c) = ml_kem.encaps(ek)
        K_prime = ml_kem.decaps(c, dk)

        assert K == K_prime


def test_ml_kem_pke_128():
    _test_ml_kem(ML_KEM128)


def test_ml_kem_pke_192():
    _test_ml_kem(ML_KEM192)


def test_ml_kem_pke_256():
    _test_ml_kem(ML_KEM256)


if __name__ == "__main__":
    test_ml_kem_pke_128()
    test_ml_kem_pke_192()
    test_ml_kem_pke_256()
