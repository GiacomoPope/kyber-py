from typing import Union, Self

# Reexport from typing
Union = Union
Self = Self

# "type Element = ..."" would require python 3.12
Coefficients = Union[list[int], int]
