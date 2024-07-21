from kyber import Kyber512, Kyber768, Kyber1024
from hashlib import sha256
from aes256_ctr_drbg import AES256_CTR_DRBG


def generate_kat_hash(kyber):
    # Set the seed for the KAT file
    entropy_input = bytes([i for i in range(48)])
    rng = AES256_CTR_DRBG(entropy_input)

    file = ""
    for count in range(100):
        seed = rng.random_bytes(48)
        kyber.set_drbg_seed(seed)
        pk, sk = kyber.keygen()
        ct, ss = kyber.enc(pk)
        ss_check = kyber.dec(ct, sk)

        # may as well check here that kyber works
        assert ss == ss_check

        # Create a KAT file block with the data
        block = f"{count = }\n"
        block += f"seed = {seed.hex().upper()}\n"
        block += f"pk = {pk.hex().upper()}\n"
        block += f"sk = {sk.hex().upper()}\n"
        block += f"ct = {ct.hex().upper()}\n"
        block += f"ss = {ss.hex().upper()}\n\n"

        # Append the block to the file
        file += block

    # Return the sha256 hash of the generated data
    return sha256(file.encode()).digest()


def check_kat_file(kyber, kat_file):
    # Hash the asset file
    with open(kat_file, "rb") as f:
        kat_data = f.read()
        kat_hash_assert = sha256(kat_data).digest()
    # Generate a hash from local Kyber version
    kat_hash_derived = generate_kat_hash(kyber)

    # Ensure that they're equal
    assert kat_hash_assert == kat_hash_derived


def test_kat_files():

    check_kat_file(Kyber512, "assets/PQCkemKAT_1632.rsp")
    check_kat_file(Kyber768, "assets/PQCkemKAT_2400.rsp")
    check_kat_file(Kyber1024, "assets/PQCkemKAT_3168.rsp")
