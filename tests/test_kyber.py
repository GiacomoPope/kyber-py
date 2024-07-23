import unittest
import os
from kyber_py.kyber import Kyber512, Kyber768, Kyber1024
from kyber_py.drbg.aes256_ctr_drbg import AES256_CTR_DRBG


def parse_kat_data(data):
    parsed_data = {}
    count_blocks = data.split("\n\n")
    for block in count_blocks[:-1]:
        block_data = block.split("\n")
        count, seed, pk, sk, ct, ss = [
            line.split(" = ")[-1] for line in block_data
        ]
        parsed_data[int(count)] = {
            "seed": bytes.fromhex(seed),
            "pk": bytes.fromhex(pk),
            "sk": bytes.fromhex(sk),
            "ct": bytes.fromhex(ct),
            "ss": bytes.fromhex(ss),
        }
    return parsed_data


class TestKyber(unittest.TestCase):
    """
    Test Kyber levels for internal consistency by generating keypairs and
    shared secrets.
    """

    def generic_test_kyber(self, Kyber, count):
        for _ in range(count):
            pk, sk = Kyber.keygen()
            for _ in range(count):
                key, c = Kyber.encaps(pk)
                _key = Kyber.decaps(c, sk)
                self.assertEqual(key, _key)

    def test_kyber512(self):
        self.generic_test_kyber(Kyber512, 5)

    def test_kyber768(self):
        self.generic_test_kyber(Kyber768, 5)

    def test_kyber1024(self):
        self.generic_test_kyber(Kyber1024, 5)


class TestKyberDeterministic(unittest.TestCase):
    """
    Ensure that deterministic DRBG is deterministic!

    Uses AES256 CTR DRBG for randomness.
    Note: requires pycryptodome for AES impl.
    (Seemed overkill to code my own AES for Kyber)
    """

    def generic_test_kyber_deterministic(self, Kyber, count):
        """
        First we generate five pk,sk pairs
        from the same seed and make sure
        they're all the same
        """
        seed = os.urandom(48)
        pk_output = []
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            pk, sk = Kyber.keygen()
            pk_output.append(pk + sk)
        self.assertEqual(len(pk_output), 5)
        self.assertEqual(len(set(pk_output)), 1)

        """
        Now given a fixed keypair make sure
        that c,key are the same for a fixed seed
        """
        key_output = []
        seed = os.urandom(48)
        pk, sk = Kyber.keygen()
        for _ in range(count):
            Kyber.set_drbg_seed(seed)
            key, c = Kyber.encaps(pk)
            _key = Kyber.decaps(c, sk)
            # Check key derivation works
            self.assertEqual(key, _key)
            key_output.append(c + key)
        self.assertEqual(len(key_output), count)
        self.assertEqual(len(set(key_output)), 1)

    def test_kyber512_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber512, 5)

    def test_kyber768_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber768, 5)

    def test_kyber1024_deterministic(self):
        self.generic_test_kyber_deterministic(Kyber1024, 5)


class TestKnownTestValues(unittest.TestCase):
    def generic_test_kyber_known_answer(self, Kyber, filename):
        # Set DRBG to generate seeds
        entropy_input = bytes([i for i in range(48)])
        rng = AES256_CTR_DRBG(entropy_input)

        with open(filename) as f:
            kat_data = f.read()
            parsed_data = parse_kat_data(kat_data)

        for count in range(100):
            # Obtain the kat data for the count
            data = parsed_data[count]

            # Set the seed and check it matches the KAT
            seed = rng.random_bytes(48)
            self.assertEqual(seed, data["seed"])

            # Seed DRBG with KAT seed
            Kyber.set_drbg_seed(seed)

            # Assert keygen matches
            pk, sk = Kyber.keygen()
            self.assertEqual(pk, data["pk"])
            self.assertEqual(sk, data["sk"])

            # Assert encapsulation matches
            ss, ct = Kyber.encaps(pk)
            self.assertEqual(ct, data["ct"])
            self.assertEqual(ss, data["ss"])

            # Assert decapsulation matches
            _ss = Kyber.decaps(ct, sk)
            self.assertEqual(ss, data["ss"])

    def test_kyber512_known_answer(self):
        return self.generic_test_kyber_known_answer(
            Kyber512, "assets/PQCkemKAT_1632.rsp"
        )

    def test_kyber768_known_answer(self):
        return self.generic_test_kyber_known_answer(
            Kyber768, "assets/PQCkemKAT_2400.rsp"
        )

    def test_kyber1024_known_answer(self):
        return self.generic_test_kyber_known_answer(
            Kyber1024, "assets/PQCkemKAT_3168.rsp"
        )


if __name__ == "__main__":
    unittest.main()
