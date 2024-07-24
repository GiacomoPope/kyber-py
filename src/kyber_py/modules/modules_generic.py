from typing import Self


class Module:
    def __init__(self, ring):
        self.ring = ring
        self.matrix = Matrix

    def random_element(self, m, n):
        elements = [
            [self.ring.random_element() for _ in range(n)] for _ in range(m)
        ]
        return self(elements)

    def __repr__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __str__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __call__(self, matrix_elements, transpose=False) -> 'Matrix':
        if not isinstance(matrix_elements, list):
            raise TypeError(
                "elements of a module are matrices, built from elements of the base ring"
            )

        if isinstance(matrix_elements[0], list):
            for element_list in matrix_elements:
                if not all(
                    isinstance(aij, self.ring.element) for aij in element_list
                ):
                    raise TypeError(
                        f"All elements of the matrix must be elements of the ring: {self.ring}"
                    )
            return self.matrix(self, matrix_elements, transpose=transpose)

        elif isinstance(matrix_elements[0], self.ring.element):
            if not all(
                isinstance(aij, self.ring.element) for aij in matrix_elements
            ):
                raise TypeError(
                    f"All elements of the matrix must be elements of the ring: {self.ring}"
                )
            return self.matrix(self, [matrix_elements], transpose=transpose)

        else:
            raise TypeError(
                "elements of a module are matrices, built from elements of the base ring"
            )

    def vector(self, elements):
        """
        Construct a vector with the given elements
        """
        return self.matrix(self, [elements], transpose=True)


class Matrix:
    def __init__(self, parent, matrix_data, transpose=False):
        self.parent = parent
        self._data = matrix_data
        self._transpose = transpose
        if not self._check_dimensions():
            raise ValueError("Inconsistent row lengths in matrix")

    def dim(self):
        """
        Return the dimensions of the matrix with m rows
        and n columns
        """
        if not self._transpose:
            return len(self._data), len(self._data[0])
        else:
            return len(self._data[0]), len(self._data)

    def _check_dimensions(self):
        """
        Ensure that the matrix is rectangular
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

    def reduce_coefficients(self) -> Self:
        """
        Reduce every element in the polynomial
        using the modulus of the PolynomialRing
        """
        for row in self._data:
            for ele in row:
                ele.reduce_coefficients()
        return self

    def __getitem__(self, idx):
        """
        matrix[i, j] returns the element on row i, column j
        """
        assert (
            isinstance(idx, tuple) and len(idx) == 2
        ), "Can't access individual rows"
        if not self._transpose:
            return self._data[idx[0]][idx[1]]
        else:
            return self._data[idx[1]][idx[0]]

    def __eq__(self, other):
        if self.dim() != other.dim():
            return False
        m, n = self.dim()
        return all(
            [self[i, j] == other[i, j] for i in range(m) for j in range(n)]
        )

    def __neg__(self):
        """
        Returns -self, by negating all elements
        """
        m, n = self.dim()
        return self.parent(
            [[-self[i, j] for j in range(n)] for i in range(m)],
            self._transpose,
        )

    def __add__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError("Can only add matrices to other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")
        if self.dim() != other.dim():
            raise ValueError("Matrices are not of the same dimensions")

        m, n = self.dim()
        return self.parent(
            [[self[i, j] + other[i, j] for j in range(n)] for i in range(m)],
            False,
        )

    def __radd__(self, other):
        return self.__add__(other)

    def __iadd__(self, other):
        self = self + other
        return self

    def __sub__(self, other):
        if not isinstance(other, type(self)):
            raise TypeError("Can only add matrices to other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")
        if self.dim() != other.dim():
            raise ValueError("Matrices are not of the same dimensions")

        m, n = self.dim()
        return self.parent(
            [[self[i, j] - other[i, j] for j in range(n)] for i in range(m)],
            False,
        )

    def __rsub__(self, other):
        return self.__sub__(other)

    def __isub__(self, other):
        self = self - other
        return self

    def __matmul__(self, other):
        """
        Denoted A @ B
        """
        if not isinstance(other, type(self)):
            raise TypeError("Can only multiply matrcies with other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")

        m, n = self.dim()
        n_, l = other.dim()
        if not n == n_:
            raise ValueError("Matrices are of incompatible dimensions")

        return self.parent(
            [
                [
                    sum(self[i, k] * other[k, j] for k in range(n))
                    for j in range(l)
                ]
                for i in range(m)
            ]
        )

    def dot(self, other):
        """
        Inner product
        """
        if not isinstance(other, type(self)):
            raise TypeError("Can only perform dot product with other matrices")
        res = self.T @ other
        assert res.dim() == (1, 1)
        return res[0, 0]

    def __repr__(self):
        m, n = self.dim()

        if m == 1:
            return str(self._data[0])

        max_col_width = [
            max(len(str(self[i, j])) for i in range(m)) for j in range(n)
        ]
        info = "]\n[".join(
            [
                ", ".join(
                    [
                        f"{str(self[i, j]):>{max_col_width[j]}}"
                        for j in range(n)
                    ]
                )
                for i in range(m)
            ]
        )
        return f"[{info}]"
