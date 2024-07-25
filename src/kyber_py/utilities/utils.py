import sys

# int.bit_count() was only made available in 3.10
if sys.version_info >= (3, 10):

    def bit_count(x: int) -> int:
        """
        Count the number of bits in x
        """
        return x.bit_count()

else:

    def bit_count(x: int) -> int:
        """
        Count the number of bits in x
        """
        return bin(x).count("1")


def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    assert len(a) == len(b)
    return bytes(a ^ b for a, b in zip(a, b))


def select_bytes(a, b, cond):
    """
    Select between the bytes a or b depending
    on whether cond is False or True
    """
    assert len(a) == len(b)
    out = [0] * len(a)
    cw = -cond % 256
    for i in range(len(a)):
        out[i] = a[i] ^ (cw & (a[i] ^ b[i]))
    return bytes(out)
