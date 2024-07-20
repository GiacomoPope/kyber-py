import unittest
from ml_kem import ML_KEM128, ML_KEM192, ML_KEM256


def read_kat_data(file_name):
    data_blocks = []
    with open(file_name) as f:
        for _ in range(1000):
            data_blocks.append("".join([next(f) for _ in range(11)]))
    return data_blocks


def parse_kat_data(data_blocks):
    parsed_data = {}

    # only test the first 100 for now, running all 1000 is overkill
    # for us as it's pretty slow (~165 seconds)
    for block in data_blocks[:100]:
        block_data = block.split("\n")[:-1]
        count, z, d, msg, seed, pk, sk, ct_n, ss_n, ct, ss = [
            line.split(" = ")[-1] for line in block_data
        ]
        parsed_data[count] = {
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

    def test_ML_KEM128(self):
        self.generic_test_ML_KEM(ML_KEM128, 5)

    def test_ML_KEM192(self):
        self.generic_test_ML_KEM(ML_KEM192, 5)

    def test_ML_KEM256(self):
        self.generic_test_ML_KEM(ML_KEM256, 5)


class TestKnownTestValues(unittest.TestCase):
    def generic_test_mlkem_known_answer(self, ML_KEM, filename):

        kat_data_blocks = read_kat_data(filename)
        parsed_data = parse_kat_data(kat_data_blocks)

        for data in parsed_data.values():
            z, d, msg, seed, pk, sk, ct_n, ss_n, ct, ss = data.values()

            # Check that the three chunks of 32 random bytes match
            ML_KEM.set_drbg_seed(seed)
            _z = ML_KEM.random_bytes(32)
            _d = ML_KEM.random_bytes(32)
            _msg = ML_KEM.random_bytes(32)
            self.assertEqual(z, _z)
            self.assertEqual(d, _d)
            self.assertEqual(msg, _msg)

            # Reset the seed
            ML_KEM.set_drbg_seed(seed)

            # Assert keygen matches
            ek, dk = ML_KEM.keygen()
            self.assertEqual(pk, ek)
            self.assertEqual(sk, dk)

            # Assert encapsulation matches
            K, c = ML_KEM.encaps(ek)
            self.assertEqual(ct, c)
            self.assertEqual(ss, K)

            # Assert decapsulation matches
            _c = ML_KEM.decaps(c, dk)
            self.assertEqual(ss, _c)

            # Assert decapsulation with faulty ciphertext
            _c_n = ML_KEM.decaps(ct_n, dk)
            self.assertEqual(ss_n, _c_n)

    def test_mlkem_512_known_answer(self):
        return self.generic_test_mlkem_known_answer(
            ML_KEM128, "assets/kat_MLKEM_512.rsp"
        )

    def test_mlkem_768_known_answer(self):
        return self.generic_test_mlkem_known_answer(
            ML_KEM192, "assets/kat_MLKEM_768.rsp"
        )

    def test_mlkem_1024_known_answer(self):
        return self.generic_test_mlkem_known_answer(
            ML_KEM256, "assets/kat_MLKEM_1024.rsp"
        )


if __name__ == "__main__":
    unittest.main()
