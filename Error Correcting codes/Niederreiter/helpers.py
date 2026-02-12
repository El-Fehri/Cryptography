from sage.all import GF, random_matrix, vector
import secrets
import math

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary_str):
    char_list = []
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) == 8:
            char_val = int(byte, 2)
            if 32 <= char_val <= 127:  # Printable ASCII range
                char_list.append(chr(char_val))
    return ''.join(char_list)

def create_random_error_vector(n, weight):
    if weight > n:
        raise ValueError("Weight cannot exceed vector length")
    
    positions = secrets.SystemRandom().sample(range(n), weight)
    e = vector(GF(2), n)
    for pos in positions:
        e[pos] = 1
    return e

def create_message_vector(message_bits, n):
    msg_vec = [GF(2)(bit) for bit in message_bits]
    
    # Pad or truncate to length n
    if len(msg_vec) > n:
        msg_vec = msg_vec[:n]
    else:
        msg_vec.extend([GF(2)(0)] * (n - len(msg_vec)))
    
    return vector(GF(2), msg_vec)

def matrix_inverse_mod2(M):
    return M.inverse()

def is_unimodular(matrix):
    try:
        det = matrix.det()
        return det != 0
    except:
        return False

def validate_parameters(m, t):
    if m <= 0 or t <= 0:
        return False
    
    # Check if 2^m is reasonable (not too large)
    if 2**m > 1024:  # Limit to reasonable field sizes
        return False
    
    # Basic sanity check
    if t > 2**m // 2:  # t shouldn't be too large relative to field size
        return False
        
    return True