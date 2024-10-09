"""
Implementation of ML-KEM following FIPS 203
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
"""

import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from ..modules.modules import ModuleKyber
from ..utilities.utils import select_bytes


class ML_KEM:
    def __init__(self, params):
        """
        Initialise the ML-KEM with specified lattice parameters.

        :param dict params: the lattice parameters
        """
        # ml-kem params
        self.k = params["k"]
        self.eta_1 = params["eta_1"]
        self.eta_2 = params["eta_2"]
        self.du = params["du"]
        self.dv = params["dv"]

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

        Used for both deterministic versions of ML-KEM as well as testing
        alignment with the KAT vectors

        NOTE:
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
        eXtendable-Output Function (XOF) described in 4.9 of FIPS 203 (page 19)

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
    def _prf(eta, s, b):
        """
        Pseudorandom function described in 4.3 of FIPS 203 (page 18)
        """
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError(
                "Input bytes should be one 32 byte array and one single byte."
            )
        return shake_256(input_bytes).digest(eta * 64)

    @staticmethod
    def _H(s):
        """
        Hash function described in 4.4 of FIPS 203 (page 18)
        """
        return sha3_256(s).digest()

    @staticmethod
    def _J(s):
        """
        Hash function described in 4.4 of FIPS 203 (page 18)
        """
        return shake_256(s).digest(32)

    @staticmethod
    def _G(s):
        """
        Hash function described in 4.5 of FIPS 203 (page 18)
        """
        h = sha3_512(s).digest()
        return h[:32], h[32:]

    def _generate_matrix_from_seed(self, rho, transpose=False):
        """
        Helper function which generates a element of size
        k x k from a seed `rho`.

        When `transpose` is set to True, the matrix A is
        built as the transpose.
        """
        A_data = [[0 for _ in range(self.k)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.k):
                xof_bytes = self._xof(rho, bytes([j]), bytes([i]))
                A_data[i][j] = self.R.ntt_sample(xof_bytes)
        A_hat = self.M(A_data, transpose=transpose)
        return A_hat

    def _generate_error_vector(self, sigma, eta, N):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        elements = [0 for _ in range(self.k)]
        for i in range(self.k):
            prf_output = self._prf(eta, sigma, bytes([N]))
            elements[i] = self.R.cbd(prf_output, eta)
            N += 1
        v = self.M.vector(elements)
        return v, N

    def _generate_polynomial(self, sigma, eta, N):
        """
        Helper function which generates a element in the
        polynomial ring from the Centered Binomial Distribution.
        """
        prf_output = self._prf(eta, sigma, bytes([N]))
        p = self.R.cbd(prf_output, eta)
        return p, N + 1

    def _k_pke_keygen(self, d):
        """
        Use randomness to generate an encryption key and a corresponding
        decryption key following Algorithm 13 (FIPS 203)

        :return: Tuple with encryption key and decryption key.
        :rtype: tuple(bytes, bytes)
        """
        # Expand 32 + 1 bytes to two 32-byte seeds. Note that the
        # inclusion of the lattice parameter here is for domain
        # separation between different parameter sets
        rho, sigma = self._G(d + bytes([self.k]))

        # Generate A_hat from seed rho
        A_hat = self._generate_matrix_from_seed(rho)

        # Set counter for PRF
        N = 0

        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)

        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)

        # Compute public value (in NTT form)
        s_hat = s.to_ntt()
        e_hat = e.to_ntt()
        t_hat = A_hat @ s_hat + e_hat

        # Byte encode
        ek_pke = t_hat.encode(12) + rho
        dk_pke = s_hat.encode(12)

        return (ek_pke, dk_pke)

    def _k_pke_encrypt(self, ek_pke, m, r):
        """
        Uses the encryption key to encrypt a plaintext message using the
        randomness r following Algorithm 14 (FIPS 203)

        As well as performing the usual pke encryption, the FIPS document
        requires two additional checks.

        1. Type Check: The ek_pke is of the expected length
        2. Modulus Check: That t_hat has been canonically encoded

        These are performed in this function and a ``ValueError`` is raised if
        either fails.
        """
        # First check if the encap key has the right length
        if len(ek_pke) != 384 * self.k + 32:
            raise ValueError(
                f"Type check failed, ek_pke has the wrong length, expected {384 * self.k + 32} bytes and received {len(ek_pke)}"
            )

        # Unpack ek
        t_hat_bytes, rho = ek_pke[:-32], ek_pke[-32:]

        # Compute Polynomial from bytes
        t_hat = self.M.decode_vector(t_hat_bytes, self.k, 12, is_ntt=True)

        # Next check that t_hat has been canonically encoded
        if t_hat.encode(12) != t_hat_bytes:
            raise ValueError(
                "Modulus check failed, t_hat does not encode correctly"
            )

        # Generate A_hat^T from seed rho
        A_hat_T = self._generate_matrix_from_seed(rho, transpose=True)

        N = 0
        y, N = self._generate_error_vector(r, self.eta_1, N)
        e1, N = self._generate_error_vector(r, self.eta_2, N)
        e2, N = self._generate_polynomial(r, self.eta_2, N)

        y_hat = y.to_ntt()

        u = (A_hat_T @ y_hat).from_ntt() + e1

        mu = self.R.decode(m, 1).decompress(1)
        v = t_hat.dot(y_hat).from_ntt() + e2 + mu

        c1 = u.compress(self.du).encode(self.du)
        c2 = v.compress(self.dv).encode(self.dv)

        return c1 + c2

    def _k_pke_decrypt(self, dk_pke, c):
        """
        Uses the decryption key to decrypt a ciphertext following
        Algorithm 15 (FIPS 203)
        """
        n = self.k * self.du * 32
        c1, c2 = c[:n], c[n:]

        u = self.M.decode_vector(c1, self.k, self.du).decompress(self.du)
        v = self.R.decode(c2, self.dv).decompress(self.dv)
        s_hat = self.M.decode_vector(dk_pke, self.k, 12, is_ntt=True)

        u_hat = u.to_ntt()
        w = v - (s_hat.dot(u_hat)).from_ntt()
        m = w.compress(1).encode(1)

        return m

    def _keygen_internal(self, d, z):
        """
        Use randomness to generate an encapsulation key and a corresponding
        decapsulation key following Algorithm 16 (FIPS 203)

        :return: Tuple with encapsulation key and decapsulation key.
        :rtype: tuple(bytes, bytes)
        """
        ek_pke, dk_pke = self._k_pke_keygen(d)

        ek = ek_pke
        dk = dk_pke + ek + self._H(ek) + z

        return (ek, dk)

    def keygen(self):
        """
        Generate an encapsulation key and corresponding decapsulation key
        following Algorithm 19 (FIPS 203)

        ``ek`` is encoded as bytes of length 384*k + 32
        ``dk`` is encoded as bytes of length 768*k + 96

        Part of stable API.

        :return: Tuple with encapsulation key and decapsulation key.
        :rtype: tuple(bytes, bytes)
        """
        d = self.random_bytes(32)
        z = self.random_bytes(32)
        (
            ek,
            dk,
        ) = self._keygen_internal(d, z)
        return (ek, dk)

    def _encaps_internal(self, ek, m):
        """
        Uses the encapsulation key and randomness to generate a key and an
        associated ciphertext following Algorithm 17 (FIPS 203)

        :param bytes ek: byte-encoded encapsulation key
        :return: a random key and an encapsulation of it
        :rtype: tuple(bytes, bytes)
        """
        K, r = self._G(m + self._H(ek))

        # NOTE: ML-KEM requires input validation before returning the result of
        # encapsulation. These are performed by the following two checks:
        #
        # 1) Type check: the byte length of ek must be correct: 384*k + 32
        # 2) Modulus check: Encode(Decode(ek[0:384*k])) must be correct
        #
        # As the modulus is decoded within the pke_encrypt, the design choice
        # here is to do both of these checks within the k-pke call.
        try:
            c = self._k_pke_encrypt(ek, m, r)
        except ValueError as e:
            raise ValueError(f"Validation of encapsulation key failed: {e = }")

        return K, c

    def encaps(self, ek):
        """
        Uses the encapsulation key to generate a shared secret key and an
        associated ciphertext following Algorithm 20 (FIPS 203)

        ``K`` is the shared secret key of length 32 bytes
        ``c`` is the ciphertext of length 32(du*k + dv)

        Part of stable API.

        :param bytes ek: byte-encoded encapsulation key
        :return: a random key (``K``) and an encapsulation of it (``c``)
        :rtype: tuple(bytes, bytes)
        """
        # Create random tokens
        m = self.random_bytes(32)
        K, c = self._encaps_internal(ek, m)
        return K, c

    def _decaps_internal(self, dk, c):
        """
        Uses the decapsulation key to produce a shared secret key from a
        ciphertext following Algorithm 18 (FIPS 203)

        :param bytes c: ciphertext with an encapsulated key
        :param bytes dk: decapsulation key
        :return: decapsulated key
        :rtype: bytes
        """
        # NOTE: ML-KEM requires input validation before returning the result of
        # decapsulation. These are performed by the following three checks:
        #
        # 1) Ciphertext type check: the byte length of c must be correct
        # 2) Decapsulation type check: the byte length of dk must be correct
        # 3) Hash check: a hash of the internals of the dk must match

        # Unlike encaps, these are easily performed in the kem decaps
        if len(c) != 32 * (self.du * self.k + self.dv):
            raise ValueError(
                f"ciphertext type check failed. Expected {32 * (self.du * self.k + self.dv)} bytes and obtained {len(c)}"
            )
        if len(dk) != 768 * self.k + 96:
            raise ValueError(
                f"decapsulation type check failed. Expected {768 * self.k + 96} bytes and obtained {len(dk)}"
            )

        # Parse out data from dk
        dk_pke = dk[0 : 384 * self.k]
        ek_pke = dk[384 * self.k : 768 * self.k + 32]
        h = dk[768 * self.k + 32 : 768 * self.k + 64]
        z = dk[768 * self.k + 64 :]

        # Ensure the hash-check passes
        if self._H(ek_pke) != h:
            raise ValueError("hash check failed")

        # Decrypt the ciphertext
        m_prime = self._k_pke_decrypt(dk_pke, c)

        # Re-encrypt the recovered message
        K_prime, r_prime = self._G(m_prime + h)
        K_bar = self._J(z + c)

        # Here the public encapsulation key is read from the private
        # key and so we never expect this to fail the TypeCheck or
        # ModulusCheck
        c_prime = self._k_pke_encrypt(ek_pke, m_prime, r_prime)

        # If c != c_prime, return K_bar as garbage
        # WARNING: for proper implementations, it is absolutely
        # vital that the selection between the key and garbage is
        # performed in constant time
        return select_bytes(K_bar, K_prime, c == c_prime)

    def decaps(self, dk, c):
        """
        Uses the decapsulation key to produce a shared secret key from a
        ciphertext following Algorithm 21 (FIPS 203).

        ``K`` is the shared secret key of length 32 bytes

        Part of stable API.

        :param bytes dk: decapsulation key
        :param bytes c: ciphertext with an encapsulated key
        :return: shared secret key (``K``)
        :rtype: bytes
        """
        try:
            K_prime = self._decaps_internal(dk, c)
        except ValueError as e:
            raise ValueError(
                f"Validation of decapsulation key or ciphertext failed: {e = }"
            )
        return K_prime
