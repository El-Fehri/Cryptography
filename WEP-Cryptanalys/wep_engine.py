"""
WEP Encryption Engine
Handles WEP encryption/decryption and key management
"""

import random
import struct
import binascii
from rc4_cipher import RC4
from wep_packet import WEPPacket


class WEPEngine:
    """Main WEP encryption/decryption engine"""
    
    def __init__(self):
        """Initialize WEP engine"""
        self.key = None
        self.key_bytes = None
        self.key_size = 40  # bits (5 bytes for WEP-40, can be changed to 104 for WEP-104)
        self.packets = []
        self.captured_ivs = {}  # Track IV usage for attack simulation
        self.iv_reuse_count = 0
        
    def set_key(self, key_string):
        """
        Set the WEP key from a string
        
        Args:
            key_string: Key as string
            
        Returns:
            bytes: Key bytes
        """
        # Convert string to key bytes (pad/truncate to key_size/8 bytes)
        key_bytes = key_string.encode('utf-8')
        target_len = self.key_size // 8
        
        if len(key_bytes) < target_len:
            # Pad with zeros
            key_bytes = key_bytes.ljust(target_len, b'\x00')
        else:
            # Truncate
            key_bytes = key_bytes[:target_len]
        
        self.key_bytes = key_bytes
        self.key = key_string
        return key_bytes
    
    def set_key_size(self, bits):
        """
        Set the WEP key size
        
        Args:
            bits: Key size in bits (40 or 104)
        """
        if bits not in [40, 104]:
            raise ValueError("Key size must be 40 or 104 bits")
        self.key_size = bits
        if self.key:
            # Re-apply current key with new size
            self.set_key(self.key)
    
    def generate_iv(self, weak=False, attack_type=None):
        """
        Generate an Initialization Vector (3 bytes)
        
        Args:
            weak: If True, generate a weak IV for demonstration
            attack_type: Type of weak IV to generate ('fms', 'korek', etc.)
            
        Returns:
            bytes: 3-byte IV
        """
        if weak and attack_type == 'fms':
            # Generate FMS weak IV: (A+3, 255, X)
            a = random.randint(0, 252)
            return bytes([a, (a + 3) % 256, random.randint(0, 255)])
        elif weak and attack_type == 'korek':
            # Generate KoreK weak IV patterns
            patterns = [
                lambda: bytes([0, 0, random.randint(0, 255)]),  # (0, 0, X)
                lambda: bytes([1, 255, random.randint(0, 255)]),  # (1, 255, X)
                lambda: bytes([random.randint(0, 255), 0, 0]),  # (X, 0, 0)
            ]
            return random.choice(patterns)()
        else:
            # Generate random IV
            return bytes([random.randint(0, 255) for _ in range(3)])
    
    def encrypt_packet(self, packet, iv=None, weak_iv=False, attack_type=None):
        """
        Encrypt a WEP packet
        
        Args:
            packet: WEPPacket object to encrypt
            iv: Custom IV (optional)
            weak_iv: Generate weak IV if True
            attack_type: Type of weak IV to generate
            
        Returns:
            dict: Encryption result with all components
        """
        if not self.key_bytes:
            raise ValueError("WEP key not set")
        
        # Generate or use provided IV
        if iv is None:
            iv = self.generate_iv(weak=weak_iv, attack_type=attack_type)
        else:
            iv = bytes(iv)
        
        # Track IV usage (for attack simulation)
        iv_key = binascii.hexlify(iv).decode()
        if iv_key in self.captured_ivs:
            self.iv_reuse_count += 1
        self.captured_ivs[iv_key] = self.captured_ivs.get(iv_key, 0) + 1
        
        # Generate plaintext
        plaintext = packet.generate_plaintext()
        packet.plaintext = plaintext
        
        # Calculate ICV (CRC-32)
        icv = packet.calculate_icv(plaintext)
        icv_bytes = struct.pack('<I', icv)
        
        # Prepare data for encryption (plaintext + ICV)
        data_to_encrypt = plaintext + icv_bytes
        
        # Create full key (IV + secret key)
        full_key = iv + self.key_bytes
        
        # Encrypt using RC4
        rc4 = RC4(list(full_key))
        encrypted_data = rc4.encrypt(data_to_encrypt)
        
        # Store encrypted data in packet
        packet.iv = iv
        packet.encrypted_data = encrypted_data
        packet.icv = icv_bytes
        
        return {
            'iv': iv,
            'encrypted_data': encrypted_data,
            'icv': icv_bytes,
            'plaintext': plaintext,
            'packet_type': packet.type,
            'full_key': full_key,
            'is_weak_iv': weak_iv
        }
    
    def decrypt_packet(self, iv, encrypted_data, verify_icv=True):
        """
        Decrypt a WEP packet
        
        Args:
            iv: Initialization Vector
            encrypted_data: Encrypted packet data
            verify_icv: Whether to verify ICV
            
        Returns:
            tuple: (plaintext, icv_valid)
        """
        if not self.key_bytes:
            raise ValueError("WEP key not set")
        
        # Create full key (IV + secret key)
        full_key = iv + self.key_bytes
        
        # Decrypt using RC4
        rc4 = RC4(list(full_key))
        decrypted_data = rc4.encrypt(encrypted_data)
        
        # Separate plaintext and ICV
        if len(decrypted_data) < 4:
            return None, False
        
        plaintext = decrypted_data[:-4]
        received_icv = decrypted_data[-4:]
        
        # Verify ICV if requested
        icv_valid = True
        if verify_icv:
            temp_packet = WEPPacket()
            calculated_icv = struct.pack('<I', temp_packet.calculate_icv(plaintext))
            icv_valid = (received_icv == calculated_icv)
        
        return plaintext, icv_valid
    
    def get_iv_statistics(self):
        """
        Get statistics about captured IVs
        
        Returns:
            dict: IV statistics
        """
        total_ivs = sum(self.captured_ivs.values())
        unique_ivs = len(self.captured_ivs)
        
        # Calculate collision rate
        collision_rate = (total_ivs - unique_ivs) / total_ivs * 100 if total_ivs > 0 else 0
        
        # Find most reused IVs
        most_reused = sorted(self.captured_ivs.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calculate birthday paradox probability for IV collision
        # P(collision) ≈ 1 - e^(-n^2 / (2 * 2^24))
        import math
        iv_space = 2 ** 24  # 24-bit IV space
        collision_probability = 1 - math.exp(-(total_ivs ** 2) / (2 * iv_space)) if total_ivs > 0 else 0
        
        return {
            'total_ivs': total_ivs,
            'unique_ivs': unique_ivs,
            'reused_ivs': total_ivs - unique_ivs,
            'collision_rate': collision_rate,
            'iv_reuse_count': self.iv_reuse_count,
            'most_reused': most_reused,
            'collision_probability': collision_probability * 100,
            'iv_space_usage': (unique_ivs / iv_space) * 100
        }
    
    def reset_statistics(self):
        """Reset IV statistics"""
        self.captured_ivs = {}
        self.iv_reuse_count = 0
        self.packets = []
