import unittest
from itertools import islice
import pytest
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from kyber_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG


def read_kat_data(file_name):
    data_blocks = []
    with open(file_name) as f:
        for _ in range(1000):
            data_blocks.append("".join([next(f) for _ in range(11)]))
    return data_blocks


def parse_kat_data(data_blocks):
    parsed_data = {}
    for block in data_blocks:
        block_data = block.split("\n")[:-1]
        count, z, d, msg, seed, pk, sk, ct_n, ss_n, ct, ss = [
            line.split(" = ")[-1] for line in block_data
        ]
        parsed_data[int(count)] = {
            "z": bytes.fromhex(z),
            "d": bytes.fromhex(d),
            "msg": bytes.fromhex(msg),
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "ct_n": bytes.fromhex(ct_n),
            "ss_n": bytes.fromhex(ss_n),
            "ct": bytes.fromhex(ct),
            "ss": bytes.fromhex(ss),
        }
    return parsed_data


class TestML_KEM(unittest.TestCase):
    """
    Test ML_KEM levels for internal
    consistency by generating key pairs
    and shared secrets.
    """

    def generic_test_ML_KEM(self, ML_KEM, count):
        for _ in range(count):
            (ek, dk) = ML_KEM.keygen()
            for _ in range(count):
                (K, c) = ML_KEM.encaps(ek)
                K_prime = ML_KEM.decaps(c, dk)
                self.assertEqual(K, K_prime)

    def test_ML_KEM_512(self):
        self.generic_test_ML_KEM(ML_KEM_512, 5)

    def test_ML_KEM_768(self):
        self.generic_test_ML_KEM(ML_KEM_768, 5)

    def test_ML_KEM_1024(self):
        self.generic_test_ML_KEM(ML_KEM_1024, 5)

    def test_encaps_type_check_failure(self):
        """
        Send an ecaps key of the wrong length
        """
        self.assertRaises(ValueError, lambda: ML_KEM_512.encaps(b"1"))

    def test_encaps_modulus_check_failure(self):
        """
        We create a vector of polynomials with non-canonical values for
        coefficents to fail the modulus check
        """
        (ek, _) = ML_KEM_512.keygen()
        rho = ek[-32:]

        bad_f_hat = ML_KEM_512.R([3329] * 256)
        bad_t_hat = ML_KEM_512.M.vector([bad_f_hat, bad_f_hat])
        bad_t_hat_bytes = bad_t_hat.encode(12)

        bad_ek = bad_t_hat_bytes + rho

        self.assertEqual(len(bad_ek), len(ek))
        self.assertRaises(ValueError, lambda: ML_KEM_512.encaps(bad_ek))

    def test_xof_failure(self):
        self.assertRaises(
            ValueError, lambda: ML_KEM_512._xof(b"1", b"2", b"3")
        )

    def test_prf_failure(self):
        self.assertRaises(ValueError, lambda: ML_KEM_512._prf(2, b"1", b"2"))


# As there are 1000 KATs in the file, execution of all of them takes
# a lot of time, run just 100
KEM_LIMIT = 100


def data_parse(filename):
    # Set DRBG to generate seeds
    # https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM
    entropy_input = bytes.fromhex(
        "60496cd0a12512800a79161189b055ac3996ad24e578d3c5fc57c1"
        "e60fa2eb4e550d08e51e9db7b67f1a616681d9182d"
    )
    rng = AES256_CTR_DRBG(entropy_input)

    # Parse the KAT file data
    kat_data_blocks = read_kat_data(filename)
    parsed_data = parse_kat_data(kat_data_blocks)
    return [
        (rng.random_bytes(48), i)
        for i in islice(parsed_data.values(), KEM_LIMIT)
    ]


@pytest.mark.parametrize(
    "ML_KEM, seed, kat_vals",
    [
        (kem, seed, param)
        for kem, filename in [
            (ML_KEM_512, "assets/kat_MLKEM_512.rsp"),
            (ML_KEM_768, "assets/kat_MLKEM_768.rsp"),
            (ML_KEM_1024, "assets/kat_MLKEM_1024.rsp"),
        ]
        for seed, param in data_parse(filename)
    ],
    ids=[
        f"{kem}-test-{num}"
        for kem in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        for num in range(KEM_LIMIT)
    ],
)
def test_mlkem_known_answer(ML_KEM, seed, kat_vals):
    data = kat_vals

    # Set the seed and check it matches the KAT
    assert seed == data["seed"]

    # Check that the three chunks of 32 random bytes match
    ML_KEM.set_drbg_seed(seed)

    z = ML_KEM.random_bytes(32)
    d = ML_KEM.random_bytes(32)
    msg = ML_KEM.random_bytes(32)
    assert z == data["z"]
    assert d == data["d"]
    assert msg == data["msg"]

    # Reset the seed
    ML_KEM.set_drbg_seed(seed)

    # Assert keygen matches
    ek, dk = ML_KEM.keygen()
    assert ek == data["pk"]
    assert dk == data["sk"]

    # Assert encapsulation matches
    K, c = ML_KEM.encaps(ek)
    assert K == data["ss"]
    assert c == data["ct"]

    # Assert decapsulation matches
    _K = ML_KEM.decaps(c, dk)
    assert _K == data["ss"]

    # Assert decapsulation with faulty ciphertext
    ss_n = ML_KEM.decaps(data["ct_n"], dk)
    assert ss_n == data["ss_n"]
