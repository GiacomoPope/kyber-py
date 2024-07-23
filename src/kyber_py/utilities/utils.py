class Bits(bytes):
    def __new__(cls, arg):
        if not isinstance(arg, str):
            return bytes.__new__(cls, arg)
        return bytes.__new__(cls, arg, encoding="ascii")

    def bytes(self) -> "Bytes":
        return Bytes([int(self[i : i + 8][::-1], 2) for i in range(0, len(self), 8)])


class Bytes(bytes):
    def __new__(cls, arg):
        if not isinstance(arg, str):
            return bytes.__new__(cls, arg)
        return bytes.__new__(cls, arg, encoding="ascii")

    def __init__(self, data: int | list[int] | bytes) -> None:
        # Pity we can't match on type
        if isinstance(data, bytes):
            bytes.__init__(data)
            return
        elif isinstance(data, int):
            data = [data]
        elif isinstance(data, list):
            pass
        else:
            raise ValueError("Expected int or list[int]")
        if any([i < 0 or i > 255 for i in data]):
            raise ValueError("Something that is not a byte was here")
        bytes.__init__(bytes(data))

    def bits(self) -> Bits:
        """Returns the bits of the Bytes.

        FIPS 203: Algorithm 3

        Convert bytes to an array of bits. Bytes are converted little endianness
        following the paper
        """
        b = [0 for _ in range(8 * len(self))]
        for i, byte in enumerate(self):
            for j in range(8):
                b[8 * i + j] = byte % 2
                byte //= 2
        return Bits(b)


def bytes_to_bits(input_bytes: Bytes) -> Bits:
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
    return Bits(b)


def bitstring_to_bytes(s: Bits) -> Bytes:
    """
    Convert a string of bits to bytes with bytes stored little endian
    """
    return Bytes([int(s[i : i + 8][::-1], 2) for i in range(0, len(s), 8)])


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
