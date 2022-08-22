"""
TODO: Build structure to allow this to generalise away from n=256.
"""

from utils import br

ntt_zetas = [pow(17,  br(i,7), 3329) for i in range(128)]