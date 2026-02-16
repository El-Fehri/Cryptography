# WEP Encryption & Attack Simulation Tool

A comprehensive educational tool for understanding WEP (Wired Equivalent Privacy) encryption and its cryptographic vulnerabilities.

## ⚠️ DISCLAIMER

**This tool is for educational purposes only!** Unauthorized access to computer networks is illegal.

## 📋 Overview

This simulation demonstrates why WEP should never be used in production. Features:
- Complete RC4 stream cipher implementation
- WEP packet encryption/decryption
- Multiple attack simulations (FMS, KoreK, PTW, ARP Replay, Chop-Chop, Fragmentation)
- Real-time IV analysis and visualization

## 🏗️ Project Structure

```
├── main.py                    # Main application
├── rc4_cipher.py             # RC4 implementation
├── wep_packet.py             # Packet structure
├── wep_engine.py             # Encryption engine
├── attack_simulations.py    # Attack implementations
├── encryption_tab.py         # Encryption GUI
└── attack_tab.py             # Attack GUI
```

## 🚀 Installation

```bash
pip install tkinter matplotlib numpy
python main.py
```

## 📚 Features

### Encryption Tab
- Key configuration (40/104-bit)
- Packet generation (ARP, ICMP, TCP, UDP, DNS, HTTP)
- Weak IV generation for testing
- Encryption/decryption
- Real-time statistics

### Attack Simulations
- **FMS**: First practical WEP attack (2001)
- **KoreK**: Improved FMS with 16 IV classes (2004)
- **PTW**: Most efficient attack (2007)
- **ARP Replay**: Packet injection
- **Chop-Chop**: Keyless decryption
- **Fragmentation**: Keystream extraction

### Visualization
- IV distribution histograms
- Weak IV analysis
- Collision rate charts

## 🎓 Usage

1. Set a WEP key in Encryption tab
2. Generate and encrypt packets
3. Optionally enable weak IVs
4. Switch to Attacks tab
5. Run attack simulations
6. View results in Visualization tab

## 🔐 Why WEP Failed

1. **Small IV Space**: Only 2^24 IVs
2. **IV Reuse**: Collisions after ~5,000 packets
3. **RC4 Weaknesses**: Information leakage
4. **No Replay Protection**
5. **Weak CRC-32 integrity**

## 📖 References

- Fluhrer, Mantin, Shamir (2001): FMS attack
- KoreK (2004): Statistical attacks
- Pyshkin, Tews, Weinmann (2007): PTW attack

## 🔒 Modern Alternatives

- ✅ WPA2 (AES-CCMP)
- ✅ WPA3
- ❌ WEP (NEVER USE)

---

**Educational use only. Always use secure protocols in production!**