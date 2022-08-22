def bytes_to_bits(input_bytes):
    """
    Convert bytes to an array of bits
    """
    bit_string = ''.join(format(byte, '08b') for byte in input_bytes)
    return list(map(int, list(bit_string)))
    
def bitstring_to_bytes(s):
    """
    Convert a string of bytes to bytes
    """
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
    
def round_up(x):
    """
    Round x.5 up always
    """
    return int(x + .5)
    
def br(i, k):
    """
    bit reversal of an unsigned k-bit integer
    """
    bin_i = bin(i & (2**k - 1))[2:].zfill(k)
    return int(bin_i[::-1], 2)