import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from ..modules.modules import ModuleKyber
from ..utilities.utils import select_bytes


class Kyber:
    def __init__(self, parameter_set, seed=None):
        self.k = parameter_set["k"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]

        self.M = ModuleKyber()
        self.R = self.M.ring

        # Use system randomness by default
        self.random_bytes = os.urandom

        # If a seed is supplied, use deterministic randomness
        if seed is not None:
            self.set_drbg_seed(seed)

    def set_drbg_seed(self, seed):
        """
        Setting the seed switches the entropy source
        from os.urandom to AES256 CTR DRBG

        Note: currently requires pycryptodome for AES impl.
        """
        try:
            from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

            self._drbg = AES256_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_bytes
        except ImportError as e:
            print(f"Error importing AES from pycryptodome: {e = }")
            print(
                "Have you tried installing requirements: pip -r install requirements"
            )

    def reseed_drbg(self, seed):
        """
        Reseeds the DRBG, errors if a DRBG is not set.

        Note: currently requires pycryptodome for AES impl.
        """
        if self._drbg is None:
            raise Warning(
                "Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`"
            )
        else:
            self._drbg.reseed(seed)

    @staticmethod
    def _xof(bytes32, i, j):
        """
        XOF: B^* x B x B -> B*

        NOTE:
          We use hashlib's `shake_128` implementation, which does not support an
          easy XOF interface, so we take the "easy" option and request a fixed
          number of 840 bytes (5 invocations of Keccak), rather than creating a
          byte stream.

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

    def _generate_error_vector(self, sigma, eta, N, is_ntt=False):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        elements = [0 for _ in range(self.k)]
        for i in range(self.k):
            input_bytes = self._prf(sigma, bytes([N]), 64 * eta)
            elements[i] = self.R.cbd(input_bytes, eta, is_ntt=is_ntt)
            N += 1
        v = self.M.vector(elements)
        return v, N

    def _generate_matrix_from_seed(self, rho, transpose=False, is_ntt=False):
        """
        Helper function which generates a element of size
        k x k from a seed `rho`.

        When `transpose` is set to True, the matrix A is
        built as the transpose.
        """
        A_data = [[0 for _ in range(self.k)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.k):
                input_bytes = self._xof(rho, bytes([j]), bytes([i]))
                A_data[i][j] = self.R.parse(input_bytes, is_ntt=is_ntt)
        A_hat = self.M(A_data, transpose=transpose)
        return A_hat

    def _cpapke_keygen(self):
        """
        Algorithm 4 (Key Generation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Input:
            None
        Output:
            Secret Key (12*k*n) / 8      bytes
            Public Key (12*k*n) / 8 + 32 bytes
        """
        # Generate random value, hash and split
        d = self.random_bytes(32)
        rho, sigma = self._g(d)

        # Set counter for PRF
        N = 0

        # Generate the matrix A ∈ R^kxk
        A = self._generate_matrix_from_seed(rho, is_ntt=True)

        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)
        s = s.to_ntt()

        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)
        e = e.to_ntt()

        # Construct the public key
        t = (A @ s) + e

        # Reduce vectors mod^+ q
        t.reduce_coefficients()
        s.reduce_coefficients()

        # Encode elements to bytes and return
        pk = t.encode(l=12) + rho
        sk = s.encode(l=12)
        return pk, sk

    def _cpapke_enc(self, pk, m, coins):
        """
        Algorithm 5 (Encryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Input:
            pk: public key
            m:  message ∈ B^32
            coins:  random coins ∈ B^32
        Output:
            c:  ciphertext
        """
        N = 0
        rho = pk[-32:]
        t = self.M.decode_vector(pk, self.k, l=12, is_ntt=True)

        # Encode message as polynomial
        m_poly = self.R.decode(m, l=1).decompress(1)

        # Generate the matrix A^T ∈ R^(kxk)
        At = self._generate_matrix_from_seed(rho, transpose=True, is_ntt=True)

        # Generate the error vector r ∈ R^k
        r, N = self._generate_error_vector(coins, self.eta_1, N)
        r = r.to_ntt()

        # Generate the error vector e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, self.eta_2, N)

        # Generate the error polynomial e2 ∈ R
        input_bytes = self._prf(coins, bytes([N]), 64 * self.eta_2)
        e2 = self.R.cbd(input_bytes, self.eta_2)

        # Module/Polynomial arithmetic
        u = (At @ r).from_ntt() + e1
        v = t.dot(r).from_ntt()
        v = v + e2 + m_poly

        # Ciphertext to bytes
        c1 = u.compress(self.du).encode(l=self.du)
        c2 = v.compress(self.dv).encode(l=self.dv)

        return c1 + c2

    def _cpapke_dec(self, sk, c):
        """
        Algorithm 6 (Decryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Input:
            sk: public key
            c:  message ∈ B^32
        Output:
            m:  message ∈ B^32
        """
        # Split ciphertext to vectors
        index = self.du * self.k * self.R.n // 8
        c2 = c[index:]

        # Recover the vector u and convert to NTT form
        u = self.M.decode_vector(c, self.k, l=self.du).decompress(self.du)
        u = u.to_ntt()

        # Recover the polynomial v
        v = self.R.decode(c2, l=self.dv).decompress(self.dv)

        # s_transpose (already in NTT form)
        s = self.M.decode_vector(sk, self.k, l=12, is_ntt=True)

        # Recover message as polynomial
        m = s.dot(u).from_ntt()
        m = v - m

        # Return message as bytes
        return m.compress(1).encode(l=1)

    def keygen(self):
        """
        Algorithm 7 (CCA KEM KeyGen)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Output:
            pk: Public key
            sk: Secret key

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
        Algorithm 8 (CCA KEM Encapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Input:
            pk: Public Key
        Output:
            K:  Shared key
            c:  Ciphertext

        NOTE:
          We switch the order of the output (c, K) as (K, c) to align encaps
          output with FIPS 203.
        """
        m = self.random_bytes(32)
        m_hash = self._h(m)
        Kbar, r = self._g(m_hash + self._h(pk))
        c = self._cpapke_enc(pk, m_hash, r)
        K = self._kdf(Kbar + self._h(c), key_length)
        return K, c

    def decaps(self, c, sk, key_length=32):
        """
        Algorithm 9 (CCA KEM Decapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

        Input:
            c:  ciphertext
            sk: Secret Key
        Output:
            K:  Shared key
        """
        # Extract values from `sk`
        # sk = _sk || pk || H(pk) || z
        index = 12 * self.k * self.R.n // 8
        _sk = sk[:index]
        pk = sk[index:-64]
        hpk = sk[-64:-32]
        z = sk[-32:]

        # Decrypt the ciphertext
        _m = self._cpapke_dec(_sk, c)

        # Decapsulation
        _Kbar, _r = self._g(_m + hpk)
        _c = self._cpapke_enc(pk, _m, _r)

        # if decapsulation was successful return K
        key = self._kdf(_Kbar + self._h(c), key_length)
        garbage = self._kdf(z + self._h(c), key_length)

        return select_bytes(garbage, key, c == _c)
