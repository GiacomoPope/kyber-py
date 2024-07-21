from typing import Union, Self, Optional

# Reexport from typing
Union = Union
Self = Self
Optional = Optional

# "type Element = ..."" would require python 3.12
Coefficients = Union[list[int], int]
