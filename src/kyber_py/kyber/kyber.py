import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from ..modules.modules import ModuleKyber
from ..utilities.utils import select_bytes


class Kyber:
    def __init__(self, parameter_set):
        """
        Initialise Kyber with specified lattice parameters.

        :param dict params: the lattice parameters
        """
        self.k = parameter_set["k"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]

        self.M = ModuleKyber()
        self.R = self.M.ring

        # Use system randomness by default, for deterministic randomness
        # use the method `set_drbg_seed()`
        self.random_bytes = os.urandom

    def set_drbg_seed(self, seed):
        """
        Change entropy source to a DRBG and seed it with provided value.

        Setting the seed switches the entropy source from :func:`os.urandom()`
        to an AES256 CTR DRBG.

        Used for both deterministic versions of Kyber as well as testing
        alignment with the KAT vectors

        Note:
          currently requires pycryptodome for AES impl.

        :param bytes seed: random bytes to seed the DRBG with
        """
        try:
            from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

            self._drbg = AES256_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_bytes
        except ImportError as e:  # pragma: no cover
            print(f"Error importing AES from pycryptodome: {e = }")
            raise Warning(
                "Cannot set DRBG seed due to missing dependencies, try installing requirements: pip -r install requirements"
            )

    @staticmethod
    def _xof(bytes32, i, j):
        """
        XOF: B^* x B x B -> B*

        NOTE:
          We use hashlib's ``shake_128`` implementation, which does not support
          an easy XOF interface, so we take the "easy" option and request a
          fixed number of 840 bytes (5 invocations of Keccak), rather than
          creating a byte stream.

          If your code crashes because of too few bytes, you can get dinner at:
          Casa de Chá da Boa Nova
          https://cryptojedi.org/papers/terminate-20230516.pdf
        """
        input_bytes = bytes32 + i + j
        if len(input_bytes) != 34:
            raise ValueError(
                "Input bytes should be one 32 byte array and 2 single bytes."
            )
        return shake_128(input_bytes).digest(840)

    @staticmethod
    def _h(input_bytes):
        """
        H: B* -> B^32
        """
        return sha3_256(input_bytes).digest()

    @staticmethod
    def _g(input_bytes):
        """
        G: B* -> B^32 x B^32
        """
        output = sha3_512(input_bytes).digest()
        return output[:32], output[32:]

    @staticmethod
    def _prf(s, b, length):
        """
        PRF: B^32 x B -> B^*
        """
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError(
                "Input bytes should be one 32 byte array and one single byte."
            )
        return shake_256(input_bytes).digest(length)

    @staticmethod
    def _kdf(input_bytes, length):
        """
        KDF: B^* -> B^*
        """
        return shake_256(input_bytes).digest(length)

    def _generate_error_vector(self, sigma, eta, N):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        elements = [0 for _ in range(self.k)]
        for i in range(self.k):
            input_bytes = self._prf(sigma, bytes([N]), 64 * eta)
            elements[i] = self.R.cbd(input_bytes, eta)
            N += 1
        v = self.M.vector(elements)
        return v, N

    def _generate_polynomial(self, sigma, eta, N):
        """
        Helper function which generates a element in the
        polynomial ring from the Centered Binomial Distribution.
        """
        prf_output = self._prf(sigma, bytes([N]), 64 * eta)
        p = self.R.cbd(prf_output, eta)
        return p, N + 1

    def _generate_matrix_from_seed(self, rho, transpose=False):
        """
        Helper function which generates a matrix of size k x k from a seed `rho`
        whose coefficients are polynomials in the NTT domain

        When `transpose` is set to True, the matrix A is built as the transpose.
        """
        A_data = [[0 for _ in range(self.k)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.k):
                input_bytes = self._xof(rho, bytes([j]), bytes([i]))
                A_data[i][j] = self.R.ntt_sample(input_bytes)
        A_hat = self.M(A_data, transpose=transpose)
        return A_hat

    def _cpapke_keygen(self):
        """
        Generate a public key and private key.

        Algorithm 4 (Key Generation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        :return: Tuple with public key and private key.
        :rtype: tuple(bytes, bytes)
        """
        # Generate random value, hash and split
        d = self.random_bytes(32)
        rho, sigma = self._g(d)

        # Generate the matrix A ∈ R^kxk
        A_hat = self._generate_matrix_from_seed(rho)

        # Set counter for PRF
        N = 0

        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)
        s_hat = s.to_ntt()

        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)
        e_hat = e.to_ntt()

        # Construct the public key
        t_hat = (A_hat @ s_hat) + e_hat

        # Reduce vectors mod^+ q
        t_hat.reduce_coefficients()
        s_hat.reduce_coefficients()

        # Encode elements to bytes and return
        pk = t_hat.encode(12) + rho
        sk = s_hat.encode(12)
        return pk, sk

    def _cpapke_enc(self, pk, m, coins):
        """
        Algorithm 5 (Encryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        :param bytes pk: byte-encoded public key
        :param bytes m: a 32-byte message
        :param bytes coins: a 32-byte random value
        :return: the ciphertext c
        :rtype: bytes
        """
        # Unpack the public key
        t_hat_bytes, rho = pk[:-32], pk[-32:]

        # Decode t_hat vector from public key
        t_hat = self.M.decode_vector(t_hat_bytes, self.k, 12, is_ntt=True)

        # Encode message as polynomial
        m_poly = self.R.decode(m, 1).decompress(1)

        # Generate the matrix A^T ∈ R^(kxk)
        A_hat_T = self._generate_matrix_from_seed(rho, transpose=True)

        # Set counter for PRF
        N = 0

        # Generate the error vector r ∈ R^k
        r, N = self._generate_error_vector(coins, self.eta_1, N)
        r_hat = r.to_ntt()

        # Generate the error vector e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, self.eta_2, N)

        # Generate the error polynomial e2 ∈ R
        e2, N = self._generate_polynomial(coins, self.eta_2, N)

        # Module/Polynomial arithmetic
        u = (A_hat_T @ r_hat).from_ntt() + e1
        v = t_hat.dot(r_hat).from_ntt()
        v = v + e2 + m_poly

        # Ciphertext to bytes
        c1 = u.compress(self.du).encode(self.du)
        c2 = v.compress(self.dv).encode(self.dv)

        return c1 + c2

    def _cpapke_dec(self, sk, c):
        """
        Algorithm 6 (Decryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        :param bytes sk: byte-encoded secret key
        :param bytes c: a 32-byte ciphertext
        :return: the message m
        :rtype: bytes
        """
        # Split ciphertext to vectors
        index = self.du * self.k * self.R.n // 8
        c1, c2 = c[:index], c[index:]

        # Recover the vector u and convert to NTT form
        u = self.M.decode_vector(c1, self.k, self.du).decompress(self.du)
        u_hat = u.to_ntt()

        # Recover the polynomial v
        v = self.R.decode(c2, self.dv).decompress(self.dv)

        # s_transpose (already in NTT form)
        s_hat = self.M.decode_vector(sk, self.k, 12, is_ntt=True)

        # Recover message as polynomial
        m = (s_hat.dot(u_hat)).from_ntt()
        m = v - m

        # Return message as bytes
        return m.compress(1).encode(1)

    def keygen(self):
        """
        Generate a public public key and private secret key.

        Algorithm 7 (CCA KEM KeyGen)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        :return: Tuple with public key and secret key.
        :rtype: tuple(bytes, bytes)
        """
        # Note, although the paper gens z then
        # pk, sk, the implementation does it this
        # way around, which matters for deterministic
        # randomness...
        pk, _sk = self._cpapke_keygen()
        z = self.random_bytes(32)

        # sk = sk' || pk || H(pk) || z
        sk = _sk + pk + self._h(pk) + z
        return pk, sk

    def encaps(self, pk, key_length=32):
        """
        Generate a random key, encapsulate it, return both it and ciphertext.

        Algorithm 8 (CCA KEM Encapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        NOTE:
          We switch the order of the output (c, K) as (K, c) to align encaps
          output with FIPS 203.

        :param bytes pk: byte-encoded public key
        :param int key_length: length of secret key, default value 32
        :return: a random key and a ciphertext of it
        :rtype: tuple(bytes, bytes)
        """
        # Compute random message
        m = self.random_bytes(32)

        # The hash of shame
        m_hash = self._h(m)

        # Compute key K and challenge c
        K_bar, r = self._g(m_hash + self._h(pk))

        # Perform the underlying pke encryption
        c = self._cpapke_enc(pk, m_hash, r)

        # Derive a key from the ciphertext
        K = self._kdf(K_bar + self._h(c), key_length)

        return K, c

    def _unpack_secret_key(self, sk):
        """
        Extract values from byte encoded secret key:

        sk = _sk || pk || H(pk) || z
        """
        index = 12 * self.k * self.R.n // 8

        sk_pke = sk[:index]
        pk_pke = sk[index:-64]
        pk_hash = sk[-64:-32]
        z = sk[-32:]

        return sk_pke, pk_pke, pk_hash, z

    def decaps(self, sk, c, key_length=32):
        """
        Decapsulate a key from a ciphertext using a secret key.

        Algorithm 9 (CCA KEM Decapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        NOTE:
          We switch the order of the input (c, sk) as (sk, c) to align with FIPS 203

        :param bytes sk: secret key
        :param bytes c: ciphertext with an encapsulated key
        :param int key_length: length of secret key, default value 32
        :return: shared key
        :rtype: bytes
        """
        sk_pke, pk_pke, pk_hash, z = self._unpack_secret_key(sk)

        # Decrypt the ciphertext
        m = self._cpapke_dec(sk_pke, c)

        # Decapsulation
        K_bar, r = self._g(m + pk_hash)
        c_prime = self._cpapke_enc(pk_pke, m, r)

        # if decapsulation was successful return K
        key = self._kdf(K_bar + self._h(c), key_length)
        garbage = self._kdf(z + self._h(c), key_length)

        # If c != c_prime, return garbage instead of the key
        # WARNING: for proper implementations, it is absolutely
        # vital that the selection between the key and garbage is
        # performed in constant time
        return select_bytes(garbage, key, c == c_prime)
