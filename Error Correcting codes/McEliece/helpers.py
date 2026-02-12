from sage.all import vector, GF
import random


class Helpers:
    @staticmethod
    def string_to_binary(s):
        return ''.join(format(ord(c), '08b') for c in s)
    
    @staticmethod
    def binary_to_string(bin_str):
        # Pad to multiple of 8
        if len(bin_str) % 8 != 0:
            bin_str = bin_str + '0' * (8 - (len(bin_str) % 8))
        
        chars = []
        for i in range(0, len(bin_str), 8):
            byte = bin_str[i:i+8]
            if len(byte) == 8:
                try:
                    chars.append(chr(int(byte, 2)))
                except:
                    chars.append('?')
        return ''.join(chars)
    
    @staticmethod
    def hex_to_binary(hex_str):
        hex_str = hex_str.strip().lower().replace('0x', '')
        return ''.join(format(int(c, 16), '04b') for c in hex_str)
    
    @staticmethod
    def binary_to_hex(bin_str):
        # Pad to multiple of 4
        if len(bin_str) % 4 != 0:
            bin_str = bin_str + '0' * (4 - (len(bin_str) % 4))
        
        hex_str = ''
        for i in range(0, len(bin_str), 4):
            hex_str += format(int(bin_str[i:i+4], 2), 'x')
        return hex_str
    
    @staticmethod
    def hex_to_vector(hex_str, n=None):
        bin_str = Helpers.hex_to_binary(hex_str)
        if n is not None:
            if len(bin_str) < n:
                bin_str = bin_str + '0' * (n - len(bin_str))
            elif len(bin_str) > n:
                bin_str = bin_str[:n]
        return vector(GF(2), [int(b) for b in bin_str])
    
    @staticmethod
    def vector_to_hex(v):
        bin_str = ''.join(str(int(b)) for b in v.list())
        return Helpers.binary_to_hex(bin_str)
    
    @staticmethod
    def random_error_vector(n, t):
        if t == 0:
            return vector(GF(2), n)
        
        if t > n:
            t = n  # Cap at n
        
        pos = random.sample(range(n), t)
        v = vector(GF(2), n)
        for i in pos:
            v[i] = 1
        return v