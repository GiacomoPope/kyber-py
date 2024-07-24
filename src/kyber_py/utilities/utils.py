def bit_count(x):
    """
    Count the number of bits in x

    Method to support old python as `x.bit_count()`
    was released in Python 3.10 and we currently
    support Python 3.9
    """
    try:
        return x.bit_count()
    except AttributeError:
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
