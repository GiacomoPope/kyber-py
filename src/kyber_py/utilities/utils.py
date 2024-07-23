def bytes_to_bits(input_bytes):
    """
    FIPS 203: Algorithm 3

    Convert bytes to an array of bits. Bytes are converted little endianness
    following the paper
    """
    b = [0 for _ in range(8 * len(input_bytes))]
    for i, byte in enumerate(input_bytes):
        for j in range(8):
            b[8 * i + j] = byte % 2
            byte //= 2
    return b


def bitstring_to_bytes(s):
    """
    Convert a string of bits to bytes with bytes stored little endian
    """
    return bytes([int(s[i : i + 8][::-1], 2) for i in range(0, len(s), 8)])


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
