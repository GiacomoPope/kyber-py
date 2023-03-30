def bytes_to_bits(input_bytes):
    """
    Convert bytes to an array of bits
    
    Bytes are converted little endianness following the paper
    """
    bit_string = ''.join(format(byte, '08b')[::-1] for byte in input_bytes)
    return list(map(int, list(bit_string)))
    
def bitstring_to_bytes(s):
    """
    Convert a string of bits to bytes with bytes stored little endian
    """
    return bytes([int(s[i:i+8][::-1], 2) for i in range(0, len(s), 8)])
    
def round_up(x):
    """
    Round x.5 up always
    """
    return round(x + 0.000001)
    
def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are 
    of the same length
    """
    return bytes(a^b for a,b in zip(a,b))