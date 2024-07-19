def bytes_to_bits(input_bytes):
    """
    Convert bytes to an array of bits

    Bytes are converted little endianness following the paper
    """
    bit_string = "".join(format(byte, "08b")[::-1] for byte in input_bytes)
    return list(map(int, list(bit_string)))


def bitstring_to_bytes(s):
    """
    Convert a string of bits to bytes with bytes stored little endian
    """
    return bytes([int(s[i : i + 8][::-1], 2) for i in range(0, len(s), 8)])


def compress(x, d, q):
    """
    Compute round((2^d / q) * x) % 2^d
    """
    t = 1 << d
    q_over_2 = q // 2
    y = (t * x + q_over_2) // q
    return y % t


def decompress(x, d, q):
    """
    Compute round((q / 2^d) * x)
    """
    t = 1 << (d - 1)
    y = (q * x + t) >> d
    return y


def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    return bytes(a ^ b for a, b in zip(a, b))
