from ..polynomials.polynomials import PolynomialRingKyber
from .modules_generic import Module, Matrix


class ModuleKyber(Module):
    def __init__(self):
        self.ring = PolynomialRingKyber()
        self.matrix = MatrixKyber

    def decode_vector(self, input_bytes, k, d, is_ntt=False):
        """
        Decode bytes into a a vector of polynomial elements.

        Each element is assumed to be encoded as a polynomial with ``d``-bit
        coefficients (hence a polynomial is encoded into ``256 * d`` bits).

        A vector of length ``k`` then has ``256 * d * k`` bits.
        """
        # Ensure the input bytes are the correct length to create k elements with
        # d bits used for each coefficient
        if self.ring.n * d * k != len(input_bytes) * 8:
            raise ValueError(
                "Byte length is the wrong length for given k, d values"
            )

        # Bytes needed to decode a polynomial
        n = 32 * d

        # Encode each chunk of bytes as a polynomial and create the vector
        elements = [
            self.ring.decode(input_bytes[i : i + n], d, is_ntt=is_ntt)
            for i in range(0, len(input_bytes), n)
        ]

        return self.vector(elements)


class MatrixKyber(Matrix):
    def __init__(self, parent, matrix_data, transpose=False):
        super().__init__(parent, matrix_data, transpose=transpose)

    def encode(self, d):
        """
        Encode every element of a matrix into bytes and concatenate
        """
        output = b""
        for row in self._data:
            for ele in row:
                output += ele.encode(d)
        return output

    def compress(self, d):
        """
        Compress every element of the matrix to have at most ``d`` bits
        """
        for row in self._data:
            for ele in row:
                ele.compress(d)
        return self

    def decompress(self, d):
        """
        Perform (lossy) decompression of the polynomial assuming it has been
        compressed to have at most ``d`` bits.
        """
        for row in self._data:
            for ele in row:
                ele.decompress(d)
        return self

    def to_ntt(self):
        """
        Convert every element of the matrix into NTT form
        """
        data = [[x.to_ntt() for x in row] for row in self._data]
        return self.parent(data, transpose=self._transpose)

    def from_ntt(self):
        """
        Convert every element of the matrix from NTT form
        """
        data = [[x.from_ntt() for x in row] for row in self._data]
        return self.parent(data, transpose=self._transpose)
