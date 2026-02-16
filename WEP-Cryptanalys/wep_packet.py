"""
WEP Packet Structure and Handling
Simulates IEEE 802.11 WEP packet format
"""

import random
import struct


class WEPPacket:
    """WEP Packet structure simulation"""
    
    # Packet types for simulation
    PACKET_TYPES = {
        'ARP Request': b'\x08\x06',
        'ARP Reply': b'\x08\x06',
        'ICMP Echo Request': b'\x08\x00',
        'ICMP Echo Reply': b'\x08\x00',
        'TCP Data': b'\x08\x00',
        'UDP Data': b'\x08\x00',
        'DNS Query': b'\x08\x00',
        'HTTP Request': b'\x08\x00'
    }
    
    def __init__(self, packet_type='ARP Request', data_size=64):
        """
        Initialize a WEP packet
        
        Args:
            packet_type: Type of packet to simulate
            data_size: Size of packet data in bytes
        """
        self.type = packet_type
        self.data_size = data_size
        self.iv = None
        self.encrypted_data = None
        self.icv = None
        self.plaintext = None
        
    def generate_plaintext(self):
        """
        Generate realistic plaintext data for simulation
        
        Returns:
            bytes: Plaintext packet data
        """
        if self.type == 'ARP Request':
            # Simulate ARP request structure
            # Hardware type (Ethernet): 0x0001
            # Protocol type (IPv4): 0x0800
            # Hardware size: 6, Protocol size: 4
            # Opcode (request): 0x0001
            return b'\x00\x01\x08\x00\x06\x04\x00\x01' + \
                   bytes([random.randint(0, 255) for _ in range(6)]) + \
                   bytes([192, 168, 1, random.randint(1, 254)]) + \
                   b'\x00\x00\x00\x00\x00\x00' + \
                   bytes([192, 168, 1, random.randint(1, 254)])
                   
        elif self.type == 'ARP Reply':
            # Simulate ARP reply structure
            return b'\x00\x01\x08\x00\x06\x04\x00\x02' + \
                   bytes([random.randint(0, 255) for _ in range(6)]) + \
                   bytes([192, 168, 1, random.randint(1, 254)]) + \
                   bytes([random.randint(0, 255) for _ in range(6)]) + \
                   bytes([192, 168, 1, random.randint(1, 254)])
                   
        elif self.type == 'ICMP Echo Request':
            # Simulate ICMP echo request (ping)
            # Type: 8 (echo request), Code: 0
            icmp_id = random.randint(0, 65535)
            icmp_seq = random.randint(0, 65535)
            return b'\x08\x00' + struct.pack('>H', 0) + \
                   struct.pack('>H', icmp_id) + struct.pack('>H', icmp_seq) + \
                   bytes([random.randint(0, 255) for _ in range(self.data_size - 8)])
                   
        elif self.type == 'ICMP Echo Reply':
            # Simulate ICMP echo reply
            icmp_id = random.randint(0, 65535)
            icmp_seq = random.randint(0, 65535)
            return b'\x00\x00' + struct.pack('>H', 0) + \
                   struct.pack('>H', icmp_id) + struct.pack('>H', icmp_seq) + \
                   bytes([random.randint(0, 255) for _ in range(self.data_size - 8)])
                   
        elif self.type == 'DNS Query':
            # Simulate DNS query
            return b'\x12\x34' + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                   bytes([random.randint(0, 255) for _ in range(self.data_size - 12)])
                   
        elif self.type == 'HTTP Request':
            # Simulate HTTP GET request fragment
            http_data = b'GET / HTTP/1.1\r\nHost: '
            http_data += bytes([random.randint(97, 122) for _ in range(10)])
            http_data += b'.com\r\n\r\n'
            # Pad to data_size
            if len(http_data) < self.data_size:
                http_data += bytes([0] * (self.data_size - len(http_data)))
            return http_data[:self.data_size]
            
        else:
            # Generic data packet
            return bytes([random.randint(0, 255) for _ in range(self.data_size)])
    
    def calculate_icv(self, data):
        """
        Calculate Integrity Check Value using CRC-32
        
        Args:
            data: Data to calculate CRC for
            
        Returns:
            int: 32-bit CRC value
        """
        # CRC-32 implementation (IEEE 802.3 polynomial)
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        return (~crc) & 0xFFFFFFFF
    
    def verify_icv(self, data, icv):
        """
        Verify Integrity Check Value
        
        Args:
            data: Data to verify
            icv: ICV value to check against
            
        Returns:
            bool: True if ICV matches, False otherwise
        """
        calculated_icv = self.calculate_icv(data)
        if isinstance(icv, bytes):
            icv = struct.unpack('<I', icv)[0]
        return calculated_icv == icv
    
    def to_dict(self):
        """
        Convert packet to dictionary representation
        
        Returns:
            dict: Packet information
        """
        return {
            'type': self.type,
            'data_size': self.data_size,
            'iv': self.iv.hex() if self.iv else None,
            'encrypted': self.encrypted_data is not None,
            'encrypted_size': len(self.encrypted_data) if self.encrypted_data else 0,
            'icv': self.icv.hex() if self.icv else None
        }
    
    def __repr__(self):
        """String representation of packet"""
        return f"WEPPacket(type={self.type}, size={self.data_size}, encrypted={self.encrypted_data is not None})"
