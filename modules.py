class Module:
    def __init__(self, ring):
        self.ring = ring

    def decode(self, input_bytes, m, n, l=None, is_ntt=False):
        if l is None:
            # Input length must be 32*l*m*n bytes long
            l, check = divmod(8*len(input_bytes), self.ring.n*m*n)
            if check != 0:
                raise ValueError("input bytes must be a multiple of (polynomial degree) / 8")
        else:
            if self.ring.n*l*m*n > len(input_bytes)*8:
                raise ValueError("Byte length is too short for given l")
        chunk_length = 32*l
        byte_chunks = [input_bytes[i:i+chunk_length] for i in range(0, len(input_bytes), chunk_length)]
        matrix = [[0 for _ in range(n)] for _ in range(m)]
        for i in range(m):
            for j in range(n):
                mij = self.ring.decode(byte_chunks[n*i+j], l=l, is_ntt=is_ntt)
                matrix[i][j] = mij
        return self(matrix)
    
    def decode_vector(self, input_bytes, k, l=None, is_ntt=False):
        if l is None:
            # Input length must be 32*l*k bytes long
            l, check = divmod(8*len(input_bytes), self.ring.n*k)
            if check != 0:
                raise ValueError("input bytes must be a multiple of (polynomial degree) / 8")
        else:
            if self.ring.n*l*k > len(input_bytes)*8:
                raise ValueError("Byte length is too short for given l")
        
        # Bytes needed to decode a polynomial
        chunk_length = 32*l
        
        # Break input_bytes into blocks of length chunk_length
        poly_bytes = [input_bytes[i:i+chunk_length] for i in range(0, len(input_bytes), chunk_length)]

        # Encode each chunk of bytes as a polynomial, we iterate only the first k elements in case we've 
        # been sent too many bytes to decode for the vector
        elements = [self.ring.decode(poly_bytes[i], l=l, is_ntt=is_ntt) for i in range(k)]

        return self.vector(elements)
    
    def __repr__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __str__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __call__(self, matrix_elements, transpose=False):
        if not isinstance(matrix_elements, list):
            raise TypeError("elements of a module are matrices, built from elements of the base ring")

        if isinstance(matrix_elements[0], list):
            for element_list in matrix_elements:
                if not all(isinstance(aij, self.ring.element) for aij in element_list):
                    raise TypeError(f"All elements of the matrix must be elements of the ring: {self.ring}")
            return Module.Matrix(self, matrix_elements, transpose=transpose)
        
        elif isinstance(matrix_elements[0], self.ring.element):
            if not all(isinstance(aij, self.ring.element) for aij in matrix_elements):
                raise TypeError(f"All elements of the matrix must be elements of the ring: {self.ring}")
            return Module.Matrix(self, [matrix_elements], transpose=transpose)
        
        else:
            raise TypeError("elements of a module are matrices, built from elements of the base ring")

    def vector(self, elements):
        """
        Construct a vector with the given elements
        """
        return Module.Matrix(self, [elements], transpose=True)

    class Matrix:
        def __init__(self, parent, matrix_data, transpose=False):
            self.parent = parent
            self._data = matrix_data
            self._transpose = transpose
            if not self.check_dimensions():
                raise ValueError("Inconsistent row lengths in matrix")

        def dim(self):
            """
            Return the dimensions of the matrix with m rows
            and n columns"""
            if not self._transpose:
                return len(self._data), len(self._data[0])
            else:
                return len(self._data[0]), len(self._data)

        def check_dimensions(self):
            """
            Ensure that the matrix is rectangluar
            """
            return len(set(map(len, self._data))) == 1

        def transpose(self):
            """
            Swap rows and columns of self
            """
            return self.parent(self._data, not self._transpose)

        def transpose_self(self):
            """
            Transpose in place
            """
            self._transpose = not self._transpose
            return
    
        T = property(transpose)
            
        def reduce_coefficients(self):
            """
            Reduce every element in the polynomial
            using the modulus of the PolynomialRing
            """
            for row in self._data:
                for ele in row:
                    ele.reduce_coefficients()
            return self

        def encode(self, l=None):
            output = b""
            for row in self._data:
                for ele in row:
                    output += ele.encode(l=l)
            return output
            
        def compress(self, d):
            for row in self._data:
                for ele in row:
                    ele.compress(d)
            return self
        
        def decompress(self, d):
            for row in self._data:
                for ele in row:
                    ele.decompress(d)
            return self    
    
        def to_ntt(self):
            for row in self._data:
                for ele in row:
                    ele.to_ntt()
            return self
    
        def from_ntt(self):
            for row in self._data:
                for ele in row:
                    ele.from_ntt()
            return self        
                    
        def __getitem__(self, idx):
            """
            matrix[i, j] returns the element on row i, column j
            """
            assert isinstance(idx, tuple) and len(idx) == 2, "Can't access individual rows"
            if not self._transpose:
                return self._data[idx[0]][idx[1]]
            else:
                return self._data[idx[1]][idx[0]]

        def __eq__(self, other):
            return other._data == self._data and other._transpose == self._transpose

        def __add__(self, other):
            if not isinstance(other, Module.Matrix):
                raise TypeError("Can only add matrices to other matrices")
            if self.parent != other.parent:
                raise TypeError("Matrices must have the same base ring")
            if self.dim() != other.dim():
                raise ValueError("Matrices are not of the same dimensions")
            
            m, n = self.dim()
            return self.parent([[self[i, j] + other[i, j] for j in range(n)] for i in range(m)], False)

        def __radd__(self, other):
            return self.__add__(other)

        def __iadd__(self, other):
            self = self + other
            return self

        def __sub__(self, other):
            if not isinstance(other, Module.Matrix):
                raise TypeError("Can only add matrices to other matrices")
            if self.parent != other.parent:
                raise TypeError("Matrices must have the same base ring")
            if self.dim() != other.dim():
                raise ValueError("Matrices are not of the same dimensions")

            m, n = self.dim()
            return self.parent([[self[i, j] - other[i, j] for j in range(n)] for i in range(m)], False)

        def __rsub__(self, other):
            return self.__sub__(other)

        def __isub__(self, other):
            self = self - other
            return self

        def __matmul__(self, other):
            """
            Denoted A @ B
            """
            if not isinstance(other, Module.Matrix):
                raise TypeError("Can only multiply matrcies with other matrices")
            if self.parent != other.parent:
                raise TypeError("Matricies must have the same base ring")

            m, n = self.dim()
            n_, l = other.dim()
            if not n == n_:
                raise ValueError("Matrices are of incompatible dimensions")

            return self.parent(
                [
                    [sum(self[i, k] * other[k, j] for k in range(n)) for j in range(l)]
                    for i in range(m)
                ]
            )

        def dot(self, other):
            """
            Inner product
            """
            res = self.T @ other
            assert res.dim() == (1, 1)
            return res[0, 0]

        def __repr__(self):
            n, m = self.dim()

            if n == 1:
                return str(self._data[0])
            max_col_width = []
            for n_col in range(n):
                max_col_width.append(max(len(str(row[n_col])) for row in self._data))
            info = ']\n['.join([', '.join([f'{str(x):>{max_col_width[i]}}' for i,x in enumerate(r)]) for r in self._data])
            return f"[{info}]"
