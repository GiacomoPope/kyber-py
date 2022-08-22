def bytes_to_bits(input_bytes):
    bit_string = ''.join(format(byte, '08b') for byte in input_bytes)
    return list(map(int, list(bit_string)))
    
def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
    
def round_up(x):
    """
    Round x.5 up always
    """
    return int(x + .5)