# Quick Start Guide - WEP Attack Simulator

## Installation

1. Install required packages:
   ```bash
   pip install matplotlib numpy
   ```

2. Run the application:
   ```bash
   python main.py
   ```

## Quick Demo (5 minutes)

### Step 1: Set Up (30 seconds)
- Encryption tab → Enter key "12345" → Click "Set Key"

### Step 2: Generate Packets (1 minute)
- Enable "Generate Weak IVs" ✓
- Set "Number of Packets" to 50
- Click "Generate & Encrypt"

### Step 3: Run Attack (2 minutes)
- Switch to "Attacks" tab
- Click "Run FMS Attack"
- Watch progress and results

### Step 4: Visualize (1 minute)
- Switch to "Visualization" tab
- Click "Update Visualization"
- Try "Weak IV Analysis" chart type

## Key Features

### Encryption Tab
- Set WEP keys (40/104-bit)
- Generate various packet types
- Enable weak IVs for attack testing
- View encrypted packets

### Attacks Tab
- FMS Attack (classic)
- KoreK Attack (improved)
- PTW Attack (fastest)
- ARP Replay (injection)
- Chop-Chop (keyless decrypt)
- Fragmentation (keystream)

### Visualization Tab
- IV Distribution
- Weak IV Analysis
- Collision Rate graphs

## Tips

✓ Generate 50-100 packets for best results
✓ Enable weak IVs for attack demonstrations
✓ Use ARP packets (most realistic)
✓ Check Help menu for detailed docs

## Troubleshooting

**Attack fails?** Generate more packets first
**No visualization?** Click "Update Visualization"
**Can't copy files?** They're in the /outputs directory

---

**Educational use only!**
