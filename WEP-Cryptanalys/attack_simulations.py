"""
WEP Attack Simulations
Simulates various known attacks on WEP encryption
"""

import random
import time
import binascii
import struct
from collections import defaultdict


class WEPAttacks:
    """Collection of WEP attack simulations"""
    
    def __init__(self, wep_engine):
        """
        Initialize attack simulator
        
        Args:
            wep_engine: WEPEngine instance
        """
        self.wep_engine = wep_engine
        self.attack_progress = 0
        self.attack_running = False
        
    def is_weak_iv_fms(self, iv_bytes):
        """
        Check if IV is weak according to FMS attack
        
        Args:
            iv_bytes: IV as bytes
            
        Returns:
            bool: True if IV is weak
        """
        if len(iv_bytes) < 3:
            return False
        # FMS weak IV: First byte + 3 == Second byte (mod 256), and First byte < 253
        return (iv_bytes[0] + 3) % 256 == iv_bytes[1] and iv_bytes[0] < 253
    
    def is_weak_iv_korek(self, iv_bytes):
        """
        Check if IV is weak according to KoreK attack classes
        
        Args:
            iv_bytes: IV as bytes
            
        Returns:
            tuple: (bool, str) - (is_weak, class_name)
        """
        if len(iv_bytes) < 3:
            return False, None
            
        # KoreK attack defines 16 classes of weak IVs
        # Here we implement a few representative classes
        
        # Class 1: (0, 0, X)
        if iv_bytes[0] == 0 and iv_bytes[1] == 0:
            return True, "Class 1: (0, 0, X)"
        
        # Class 2: (1, 255, X)
        if iv_bytes[0] == 1 and iv_bytes[1] == 255:
            return True, "Class 2: (1, 255, X)"
        
        # Class 3: (X, 0, 0)
        if iv_bytes[1] == 0 and iv_bytes[2] == 0:
            return True, "Class 3: (X, 0, 0)"
        
        # Class 4: (X, 255, Y) where Y != 0
        if iv_bytes[1] == 255 and iv_bytes[2] != 0:
            return True, "Class 4: (X, 255, Y)"
        
        # Class 5: (X, Y, 0) where Y != 0
        if iv_bytes[2] == 0 and iv_bytes[1] != 0:
            return True, "Class 5: (X, Y, 0)"
        
        return False, None
    
    def analyze_weak_ivs(self):
        """
        Analyze captured IVs for weaknesses
        
        Returns:
            dict: Analysis results
        """
        fms_weak = []
        korek_weak = defaultdict(list)
        
        for iv_hex in self.wep_engine.captured_ivs:
            iv_bytes = bytes.fromhex(iv_hex)
            
            # Check FMS weakness
            if self.is_weak_iv_fms(iv_bytes):
                fms_weak.append(iv_hex)
            
            # Check KoreK weakness
            is_weak, class_name = self.is_weak_iv_korek(iv_bytes)
            if is_weak:
                korek_weak[class_name].append(iv_hex)
        
        total_ivs = len(self.wep_engine.captured_ivs)
        
        return {
            'total_ivs': total_ivs,
            'fms_weak_count': len(fms_weak),
            'fms_weak_ivs': fms_weak[:20],  # First 20 for display
            'korek_weak_count': sum(len(v) for v in korek_weak.values()),
            'korek_classes': dict(korek_weak),
            'fms_percentage': (len(fms_weak) / total_ivs * 100) if total_ivs > 0 else 0,
            'korek_percentage': (sum(len(v) for v in korek_weak.values()) / total_ivs * 100) if total_ivs > 0 else 0
        }
    
    def simulate_fms_attack(self, callback=None):
        """
        Simulate FMS (Fluhrer, Mantin, Shamir) attack
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        self.attack_progress = 0
        
        analysis = self.analyze_weak_ivs()
        
        if analysis['total_ivs'] < 10:
            return {
                'success': False,
                'message': 'Insufficient packets. Need at least 10 packets for simulation.',
                'packets_needed': 10 - analysis['total_ivs']
            }
        
        # Simulate attack phases
        phases = [
            (20, "Collecting weak IVs..."),
            (40, "Analyzing first keystream bytes..."),
            (60, "Building key byte probability table..."),
            (80, "Testing key candidates..."),
            (100, "Recovering full key...")
        ]
        
        results = []
        key_bytes_recovered = []
        
        for progress, message in phases:
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            self.attack_progress = progress
            if callback:
                callback(progress, message)
            time.sleep(0.5)
            
            # Simulate recovering key bytes
            if progress >= 60:
                byte_recovered = random.randint(0, 255)
                key_bytes_recovered.append(byte_recovered)
                results.append(f"Key byte {len(key_bytes_recovered)}: 0x{byte_recovered:02X}")
        
        # Simulate final key recovery
        recovered_key = ''.join([f'{b:02X}' for b in key_bytes_recovered])
        
        return {
            'success': True,
            'message': 'FMS attack completed successfully',
            'weak_ivs_used': analysis['fms_weak_count'],
            'total_packets': analysis['total_ivs'],
            'recovered_key': recovered_key,
            'actual_key': binascii.hexlify(self.wep_engine.key_bytes).decode().upper(),
            'key_bytes': results,
            'attack_type': 'FMS'
        }
    
    def simulate_korek_attack(self, callback=None):
        """
        Simulate KoreK attack (improved FMS)
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        self.attack_progress = 0
        
        analysis = self.analyze_weak_ivs()
        
        if analysis['total_ivs'] < 10:
            return {
                'success': False,
                'message': 'Insufficient packets. Need at least 10 packets.',
                'packets_needed': 10 - analysis['total_ivs']
            }
        
        # Simulate attack phases
        phases = [
            (15, "Identifying weak IV classes..."),
            (30, f"Found {len(analysis['korek_classes'])} KoreK classes"),
            (50, "Computing statistical correlations..."),
            (70, "Building enhanced key hypothesis table..."),
            (90, "Applying voting algorithms..."),
            (100, "Key recovery complete!")
        ]
        
        key_bytes_recovered = []
        
        for progress, message in phases:
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            self.attack_progress = progress
            if callback:
                callback(progress, message)
            time.sleep(0.5)
            
            if progress >= 70:
                byte_recovered = random.randint(0, 255)
                key_bytes_recovered.append(byte_recovered)
        
        recovered_key = ''.join([f'{b:02X}' for b in key_bytes_recovered])
        
        return {
            'success': True,
            'message': 'KoreK attack completed (more efficient than FMS)',
            'weak_ivs_used': analysis['korek_weak_count'],
            'korek_classes_found': len(analysis['korek_classes']),
            'total_packets': analysis['total_ivs'],
            'recovered_key': recovered_key,
            'actual_key': binascii.hexlify(self.wep_engine.key_bytes).decode().upper(),
            'attack_type': 'KoreK',
            'efficiency': 'Used fewer packets than FMS would require'
        }
    
    def simulate_ptw_attack(self, callback=None):
        """
        Simulate PTW (Pyshkin, Tews, Weinmann) attack
        Most efficient WEP attack
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        self.attack_progress = 0
        
        if len(self.wep_engine.captured_ivs) < 5:
            return {
                'success': False,
                'message': 'Insufficient packets. Need at least 5 packets.',
                'packets_needed': 5 - len(self.wep_engine.captured_ivs)
            }
        
        phases = [
            (20, "Collecting ARP request packets..."),
            (40, "Extracting keystream information..."),
            (60, "Computing Klein's attack tables..."),
            (80, "Performing statistical analysis..."),
            (100, "Key recovered!")
        ]
        
        key_bytes = []
        
        for progress, message in phases:
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            self.attack_progress = progress
            if callback:
                callback(progress, message)
            time.sleep(0.4)
            
            if progress >= 60:
                key_bytes.append(random.randint(0, 255))
        
        recovered_key = ''.join([f'{b:02X}' for b in key_bytes])
        
        return {
            'success': True,
            'message': 'PTW attack completed (fastest WEP attack)',
            'packets_used': len(self.wep_engine.captured_ivs),
            'recovered_key': recovered_key,
            'actual_key': binascii.hexlify(self.wep_engine.key_bytes).decode().upper(),
            'attack_type': 'PTW',
            'efficiency': 'Most efficient - requires only ~40,000 packets for 104-bit WEP'
        }
    
    def simulate_arp_replay_attack(self, callback=None):
        """
        Simulate ARP replay attack (packet injection)
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        injected_packets = []
        
        # Simulate capturing and replaying ARP packets
        for i in range(10):
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            # Generate new IV for each replayed packet
            iv = self.wep_engine.generate_iv()
            iv_hex = binascii.hexlify(iv).decode()
            
            injected_packets.append({
                'packet_num': i + 1,
                'iv': iv_hex,
                'timestamp': time.time()
            })
            
            # Track the IV
            self.wep_engine.captured_ivs[iv_hex] = self.wep_engine.captured_ivs.get(iv_hex, 0) + 1
            
            if callback:
                callback(i * 10, f"Injected packet {i+1}/10 - IV: {iv_hex}")
            
            time.sleep(0.3)
        
        return {
            'success': True,
            'message': 'ARP replay attack completed',
            'packets_injected': len(injected_packets),
            'new_ivs_captured': len(injected_packets),
            'injected_packets': injected_packets,
            'attack_type': 'ARP Replay',
            'purpose': 'Generate traffic to collect more IVs for statistical attacks'
        }
    
    def simulate_chop_chop_attack(self, callback=None):
        """
        Simulate Chop-Chop attack (decrypt without key)
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        
        # Simulate decrypting packet byte by byte
        packet_length = 16
        decrypted_bytes = []
        
        for i in range(packet_length):
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            # Simulate guessing each byte
            guessed_byte = random.randint(0, 255)
            decrypted_bytes.append(guessed_byte)
            
            if callback:
                progress = (i + 1) / packet_length * 100
                callback(progress, f"Decrypting byte {i+1}/{packet_length}: 0x{guessed_byte:02X}")
            
            time.sleep(0.4)
        
        decrypted_data = ''.join([f'{b:02X}' for b in decrypted_bytes])
        
        return {
            'success': True,
            'message': 'Chop-Chop attack completed',
            'decrypted_bytes': decrypted_data,
            'bytes_decrypted': len(decrypted_bytes),
            'attack_type': 'Chop-Chop',
            'method': 'Iteratively remove and guess bytes using CRC validation'
        }
    
    def simulate_fragmentation_attack(self, callback=None):
        """
        Simulate Fragmentation attack (obtain keystream)
        
        Args:
            callback: Function to call with progress updates
            
        Returns:
            dict: Attack results
        """
        self.attack_running = True
        
        phases = [
            (25, "Capturing packet with known plaintext..."),
            (50, "Extracting 8 bytes of keystream..."),
            (75, "Creating valid packet fragments..."),
            (100, "Injecting forged packets!")
        ]
        
        keystream = bytes([random.randint(0, 255) for _ in range(8)])
        
        for progress, message in phases:
            if not self.attack_running:
                return {'success': False, 'message': 'Attack cancelled'}
            
            if callback:
                callback(progress, message)
            
            time.sleep(0.5)
        
        return {
            'success': True,
            'message': 'Fragmentation attack completed',
            'keystream_obtained': binascii.hexlify(keystream).decode().upper(),
            'keystream_length': len(keystream),
            'attack_type': 'Fragmentation',
            'purpose': 'Obtain keystream to forge arbitrary packets'
        }
    
    def stop_attack(self):
        """Stop the currently running attack"""
        self.attack_running = False
