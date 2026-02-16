"""
RC4 Stream Cipher Implementation
Used in WEP encryption
"""

class RC4:
    """RC4 implementation for WEP encryption/decryption"""
    
    def __init__(self, key):
        """
        Initialize RC4 with a key
        
        Args:
            key: List or bytes of key material
        """
        self.key = key if isinstance(key, list) else list(key)
        self.S = list(range(256))
        self.reset()
    
    def reset(self):
        """Reset and initialize the RC4 state with the key (KSA - Key Scheduling Algorithm)"""
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0
    
    def keystream_byte(self):
        """
        Generate one keystream byte (PRGA - Pseudo-Random Generation Algorithm)
        
        Returns:
            int: Single byte of keystream
        """
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]
    
    def keystream(self, length):
        """
        Generate keystream of specific length
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            bytes: Keystream bytes
        """
        return bytes([self.keystream_byte() for _ in range(length)])
    
    def encrypt(self, data):
        """
        Encrypt/decrypt data using RC4 (XOR with keystream)
        
        Args:
            data: Data to encrypt/decrypt (bytes)
            
        Returns:
            bytes: Encrypted/decrypted data
        """
        self.reset()
        result = bytearray()
        for byte in data:
            keystream_byte = self.keystream_byte()
            result.append(byte ^ keystream_byte)
        return bytes(result)
    
    def decrypt(self, data):
        """
        Decrypt data (same as encrypt for stream cipher)
        
        Args:
            data: Encrypted data (bytes)
            
        Returns:
            bytes: Decrypted data
        """
        return self.encrypt(data)
    
    def get_state(self):
        """
        Get current internal state (for analysis)
        
        Returns:
            dict: Current state information
        """
        return {
            'S': self.S.copy(),
            'i': self.i,
            'j': self.j,
            'key_length': len(self.key)
        }
