import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from polynomials import *
from modules import *

DEFAULT_PARAMETERS = {
    "kyber_512" : {
        "n" : 256,
        "k" : 2,
        "q" : 3329,
        "eta_1" : 3,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_768" : {
        "n" : 256,
        "k" : 3,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_1024" : {
        "n" : 256,
        "k" : 4,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 11,
        "dv" : 5,
    }
}

class Kyber:
    def __init__(self, parameter_set):
        self.n = parameter_set["n"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]
        
        self.R = PolynomialRing(self.q, self.n)
        self.M = Module(self.R)
    
    @staticmethod
    def _xof(bytes32, a, b, length):
        """
        XOF: B^* x B x B -> B*
        """
        input_bytes = bytes32 + a + b
        if len(input_bytes) != 34:
            raise ValueError(f"Input bytes should be one 32 byte array and 2 single bytes.")
        return shake_128(input_bytes).digest(length)
        
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
            raise ValueError(f"Input bytes should be one 32 byte array and one single byte.")
        return shake_256(input_bytes).digest(length)
    
    @staticmethod
    def _kdf(input_bytes, length):
        """
        KDF: B^* -> B^*
        """
        return shake_256(input_bytes).digest(length)
    
    def _generate_error_vector(self, sigma, N):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        coefficients = []
        for i in range(self.k):
            input_bytes = self._prf(sigma,  bytes([N]), 64*self.eta_1)
            c = self.R.cbd(input_bytes, self.eta_1)
            coefficients.append(c)
            N = N + 1
        v = self.M(coefficients).transpose()
        return v, N
        
    def _generate_matrix_from_seed(self, rho, N, transpose=False):
        """
        Helper function which generates a element of size
        k x k from a seed `rho`.
        
        When `transpose` is set to True, the matrix A is
        built as the transpose.
        """
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                if transpose:
                    aij = self.R.parse(self._xof(rho, bytes([i]), bytes([j]), 3*self.R.d))
                else:
                    aij = self.R.parse(self._xof(rho, bytes([j]), bytes([i]), 3*self.R.d))
                row.append(aij)
            A.append(row)
        return self.M(A), N
    
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
        d = os.urandom(32)
        rho, sigma = self._g(d)
        
        # Set counter for PRF
        N = 0
        
        # Generate the matrix A ∈ R^kxk
        A, N = self._generate_matrix_from_seed(rho, N)
        
        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, N)
        
        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, N)
        
        # Construct the public key
        t = A @ s + e
        
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
        _pk, rho = pk[:-32], pk[-32:]
        t = self.M.decode(_pk, self.k, 1, l=12)
        
        # Generate the matrix A^T ∈ R^(kxk)
        At, N = self._generate_matrix_from_seed(rho, N, transpose=True)
        
        # Generate the error vector r ∈ R^k
        r, N = self._generate_error_vector(coins, N)
        
        # Generate the error vector e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, N)
        
        # Generate the error polynomial e2 ∈ R
        input_bytes = self._prf(coins,  bytes([N]), 64*self.eta_2)
        e2 = self.R.cbd(input_bytes, self.eta_2)
        
        m_poly = self.R.decode(m, l=1).decompress(1)
        u = At @ r + e1
        v = (t.transpose() @ r)[0][0] + e2 + m_poly
        
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
        index = self.du * self.k * self.R.d // 8
        c1, c2 = c[:index], c[index:]
        u = self.M.decode(c1, self.k, 1, l=self.du).decompress(self.du)
        v = self.R.decode(c2, l=self.dv).decompress(self.dv)
        st = self.M.decode(sk, 1, self.k, l=12)
        return (v - (st @ u)[0][0]).compress(1).encode(l=1)
        
    def keygen(self):
        """
        Algorithm 7 (CCA KEM KeyGen)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Output:
            pk: Public key
            sk: Secret key
            
        """
        z = os.urandom(32)
        pk, _sk = self._cpapke_keygen()
        sk = _sk + pk + self._h(pk) + z
        return pk, sk
        
    def encrypt(self, pk, key_length=32):
        """
        Algorithm 8 (CCA KEM Encryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input: 
            pk: Public Key
        Output:
            c:  Ciphertext
            K:  Shared key
        """
        m = os.urandom(32)
        m_hash = self._h(m)
        Kbar, r = self._g(m_hash + self._h(pk))
        c = self._cpapke_enc(pk, m_hash, r)
        K = self._kdf(Kbar + self._h(c), key_length)
        return c, K

    def decrypt(self, c, sk, key_length=32):
        """
        Algorithm 9 (CCA KEM Decryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input: 
            c:  ciphertext
            sk: Secret Key
        Output:
            K:  Shared key
        """
        # Extract values from `sk`
        # sk = _sk || pk || H(pk) || z
        index = 12 * self.k * self.R.d // 8
        _sk =  sk[:index]
        pk = sk[index:-64]
        hpk = sk[-64:-32]
        z = sk[-32:]
        
        # Decrypt the ciphertext
        _m = self._cpapke_dec(_sk, c)
        
        # Decapsulation
        _Kbar, _r = self._g(_m + hpk)
        _c = self._cpapke_enc(pk, _m, _r)
        
        # if decapsulation was successful return K
        if c == _c:
            return self._kdf(_Kbar + self._h(c), key_length)
        # decapsulation failed... return random value
        return self._kdf(z + self._h(c), key_length)

# Initialise with default parameters
Kyber512 = Kyber(DEFAULT_PARAMETERS["kyber_512"])
Kyber768 = Kyber(DEFAULT_PARAMETERS["kyber_768"])
Kyber1024 = Kyber(DEFAULT_PARAMETERS["kyber_1024"])

if __name__ == '__main__':
    # Test kyber_512
    pk, sk = Kyber512.keygen()
    for _ in range(10):
        c, key = Kyber512.encrypt(pk)
        _key = Kyber512.decrypt(c, sk)
        assert key == _key
    
    # Test kyber_768
    pk, sk = Kyber768.keygen()
    for _ in range(10):
        c, key = Kyber768.encrypt(pk)
        _key = Kyber768.decrypt(c, sk)
        assert key == _key
        
    # Test kyber_1024
    pk, sk = Kyber1024.keygen()
    for _ in range(10):
        c, key = Kyber1024.encrypt(pk)
        _key = Kyber1024.decrypt(c, sk)
        assert key == _key




