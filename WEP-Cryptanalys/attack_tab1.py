"""
Attack Tab - WEP Attack Simulations Interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from attack_simulations import WEPAttacks


class AttackTab:
    """Tab for WEP attack simulations"""
    
    def __init__(self, parent, wep_engine, log_callback):
        """
        Initialize attack tab
        
        Args:
            parent: Parent widget
            wep_engine: WEPEngine instance
            log_callback: Function to call for logging
        """
        self.parent = parent
        self.wep_engine = wep_engine
        self.log = log_callback
        self.attacks = WEPAttacks(wep_engine)
        self.current_attack = None
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create all widgets for the attack tab"""
        # Main container
        main_frame = ttk.Frame(self.parent, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Attack Selection Section
        attack_frame = ttk.LabelFrame(main_frame, text="Attack Selection", padding="10")
        attack_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # FMS Attack
        fms_frame = ttk.Frame(attack_frame)
        fms_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(fms_frame, text="FMS Attack (Fluhrer, Mantin, Shamir):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(fms_frame, text="Run FMS Attack", 
                  command=self.run_fms_attack).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Exploits weak IVs to recover key bytes through statistical analysis.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        ttk.Separator(attack_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # KoreK Attack
        korek_frame = ttk.Frame(attack_frame)
        korek_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(korek_frame, text="KoreK Attack (Improved FMS):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(korek_frame, text="Run KoreK Attack", 
                  command=self.run_korek_attack).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Uses 16 classes of weak IVs for more efficient key recovery.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        ttk.Separator(attack_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # PTW Attack
        ptw_frame = ttk.Frame(attack_frame)
        ptw_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ptw_frame, text="PTW Attack (Pyshkin, Tews, Weinmann):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(ptw_frame, text="Run PTW Attack", 
                  command=self.run_ptw_attack).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Most efficient attack - uses Klein's attack and requires minimal packets.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        ttk.Separator(attack_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # ARP Replay Attack
        arp_frame = ttk.Frame(attack_frame)
        arp_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(arp_frame, text="ARP Replay Attack (Packet Injection):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(arp_frame, text="Run ARP Replay", 
                  command=self.run_arp_replay).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Captures and replays ARP packets to generate traffic and collect IVs.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        ttk.Separator(attack_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Chop-Chop Attack
        chop_frame = ttk.Frame(attack_frame)
        chop_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(chop_frame, text="Chop-Chop Attack (Keyless Decryption):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(chop_frame, text="Run Chop-Chop", 
                  command=self.run_chop_chop).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Decrypts packets byte-by-byte using CRC validation without knowing the key.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        ttk.Separator(attack_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Fragmentation Attack
        frag_frame = ttk.Frame(attack_frame)
        frag_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(frag_frame, text="Fragmentation Attack (Keystream Extraction):", 
                 font=('TkDefaultFont', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(frag_frame, text="Run Fragmentation", 
                  command=self.run_fragmentation).pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(attack_frame, text="Extracts keystream from known plaintext to forge arbitrary packets.", 
                 wraplength=700).pack(anchor=tk.W, padx=20, pady=2)
        
        # Bottom buttons
        button_frame = ttk.Frame(attack_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Analyze IV Weaknesses", 
                  command=self.analyze_ivs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Current Attack", 
                  command=self.stop_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Documentation", 
                  command=self.show_documentation).pack(side=tk.LEFT, padx=5)
        
        # Attack Results Section
        results_frame = ttk.LabelFrame(main_frame, text="Attack Progress & Results", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(results_frame, variable=self.progress_var, 
                                           maximum=100, length=300)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_label = ttk.Label(results_frame, text="No attack running")
        self.progress_label.grid(row=0, column=1, padx=10)
        
        # Results text
        self.results_text = scrolledtext.ScrolledText(results_frame, width=80, height=20, 
                                                      wrap=tk.WORD)
        self.results_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initial message
        self.results_text.insert(tk.END, "=== WEP Attack Simulation Tool ===\n\n")
        self.results_text.insert(tk.END, "This tool simulates various known attacks on WEP encryption.\n\n")
        self.results_text.insert(tk.END, "Before running attacks:\n")
        self.results_text.insert(tk.END, "1. Go to the Encryption tab\n")
        self.results_text.insert(tk.END, "2. Set a WEP key\n")
        self.results_text.insert(tk.END, "3. Generate and encrypt some packets\n\n")
        self.results_text.insert(tk.END, "For better simulation results with weak IV attacks:\n")
        self.results_text.insert(tk.END, "- Enable 'Generate Weak IVs' in the Encryption tab\n")
        self.results_text.insert(tk.END, "- Generate at least 20-50 packets\n\n")
        self.results_text.insert(tk.END, "Select an attack above to begin.\n")
    
    def run_fms_attack(self):
        """Run FMS attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "FMS"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== FMS Attack Started ===\n\n")
        self.log("Starting FMS attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_fms_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def run_korek_attack(self):
        """Run KoreK attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "KoreK"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== KoreK Attack Started ===\n\n")
        self.log("Starting KoreK attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_korek_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def run_ptw_attack(self):
        """Run PTW attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "PTW"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== PTW Attack Started ===\n\n")
        self.log("Starting PTW attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_ptw_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def run_arp_replay(self):
        """Run ARP replay attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "ARP Replay"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== ARP Replay Attack Started ===\n\n")
        self.log("Starting ARP replay attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_arp_replay_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def run_chop_chop(self):
        """Run Chop-Chop attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "Chop-Chop"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== Chop-Chop Attack Started ===\n\n")
        self.log("Starting Chop-Chop attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_chop_chop_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def run_fragmentation(self):
        """Run Fragmentation attack in background thread"""
        if self.current_attack:
            messagebox.showwarning("Warning", "An attack is already running")
            return
        
        self.current_attack = "Fragmentation"
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== Fragmentation Attack Started ===\n\n")
        self.log("Starting Fragmentation attack simulation...")
        
        def attack_thread():
            try:
                result = self.attacks.simulate_fragmentation_attack(callback=self.update_progress)
                self.parent.after(0, lambda: self.display_attack_result(result))
            except Exception as e:
                self.parent.after(0, lambda: messagebox.showerror("Error", f"Attack failed: {str(e)}"))
            finally:
                self.current_attack = None
                self.progress_var.set(0)
                self.progress_label.config(text="Attack completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
    
    def update_progress(self, progress, message):
        """Update progress bar and label"""
        self.progress_var.set(progress)
        self.progress_label.config(text=message)
        self.results_text.insert(tk.END, f"[{progress:.0f}%] {message}\n")
        self.results_text.see(tk.END)
    
    def display_attack_result(self, result):
        """Display attack results"""
        self.results_text.insert(tk.END, "\n" + "="*60 + "\n")
        self.results_text.insert(tk.END, "ATTACK RESULTS\n")
        self.results_text.insert(tk.END, "="*60 + "\n\n")
        
        if result['success']:
            self.results_text.insert(tk.END, f"✓ {result['message']}\n\n")
            
            # Display attack-specific results
            if 'recovered_key' in result:
                self.results_text.insert(tk.END, f"Recovered Key: {result['recovered_key']}\n")
                self.results_text.insert(tk.END, f"Actual Key:    {result['actual_key']}\n\n")
            
            if 'packets_used' in result:
                self.results_text.insert(tk.END, f"Packets Used: {result['packets_used']}\n")
            
            if 'weak_ivs_used' in result:
                self.results_text.insert(tk.END, f"Weak IVs Used: {result['weak_ivs_used']}\n")
            
            if 'korek_classes_found' in result:
                self.results_text.insert(tk.END, f"KoreK Classes Found: {result['korek_classes_found']}\n")
            
            if 'packets_injected' in result:
                self.results_text.insert(tk.END, f"Packets Injected: {result['packets_injected']}\n")
            
            if 'decrypted_bytes' in result:
                self.results_text.insert(tk.END, f"Decrypted Data: {result['decrypted_bytes']}\n")
            
            if 'keystream_obtained' in result:
                self.results_text.insert(tk.END, f"Keystream Obtained: {result['keystream_obtained']}\n")
            
            if 'efficiency' in result:
                self.results_text.insert(tk.END, f"\nEfficiency: {result['efficiency']}\n")
            
            if 'purpose' in result:
                self.results_text.insert(tk.END, f"Purpose: {result['purpose']}\n")
            
            if 'method' in result:
                self.results_text.insert(tk.END, f"Method: {result['method']}\n")
            
            self.log(f"{result.get('attack_type', 'Attack')} completed successfully")
        else:
            self.results_text.insert(tk.END, f"✗ {result['message']}\n")
            if 'packets_needed' in result:
                self.results_text.insert(tk.END, f"\nPlease generate {result['packets_needed']} more packets.\n")
            self.log(f"Attack failed: {result['message']}")
        
        self.results_text.see(tk.END)
    
    def analyze_ivs(self):
        """Analyze captured IVs for weaknesses"""
        if not self.wep_engine.captured_ivs:
            messagebox.showwarning("Warning", "No IVs captured yet. Encrypt some packets first.")
            return
        
        self.log("Analyzing IV weaknesses...")
        analysis = self.attacks.analyze_weak_ivs()
        
        # Display in results window
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=== IV Weakness Analysis ===\n\n")
        self.results_text.insert(tk.END, f"Total IVs Captured: {analysis['total_ivs']}\n")
        self.results_text.insert(tk.END, f"FMS Weak IVs: {analysis['fms_weak_count']} ({analysis['fms_percentage']:.2f}%)\n")
        self.results_text.insert(tk.END, f"KoreK Weak IVs: {analysis['korek_weak_count']} ({analysis['korek_percentage']:.2f}%)\n\n")
        
        if analysis['korek_weak_count'] > 0:
            self.results_text.insert(tk.END, "KoreK Weak IV Classes Found:\n")
            for class_name, ivs in analysis['korek_classes'].items():
                self.results_text.insert(tk.END, f"  {class_name}: {len(ivs)} IVs\n")
            self.results_text.insert(tk.END, "\n")
        
        if analysis['fms_weak_count'] > 0:
            self.results_text.insert(tk.END, "Sample FMS Weak IVs:\n")
            for iv in analysis['fms_weak_ivs'][:10]:
                self.results_text.insert(tk.END, f"  {iv}\n")
            if len(analysis['fms_weak_ivs']) > 10:
                self.results_text.insert(tk.END, f"  ... and {len(analysis['fms_weak_ivs']) - 10} more\n")
            self.results_text.insert(tk.END, "\n")
        
        # Recommendation
        self.results_text.insert(tk.END, "Recommendation:\n")
        if analysis['fms_weak_count'] > 5 or analysis['korek_weak_count'] > 5:
            self.results_text.insert(tk.END, "✗ Network is VULNERABLE to statistical attacks!\n")
            self.results_text.insert(tk.END, "  Sufficient weak IVs detected for key recovery.\n")
        else:
            self.results_text.insert(tk.END, "⚠ Insufficient weak IVs for reliable attack.\n")
            self.results_text.insert(tk.END, "  Generate more packets with weak IVs enabled.\n")
        
        self.log("IV analysis completed")
    
    def stop_attack(self):
        """Stop the currently running attack"""
        if self.current_attack:
            self.attacks.stop_attack()
            self.current_attack = None
            self.progress_label.config(text="Attack stopped")
            self.log("Attack stopped by user")
            messagebox.showinfo("Attack Stopped", "The current attack has been stopped.")
        else:
            messagebox.showinfo("No Attack", "No attack is currently running.")
    
    def show_documentation(self):
        """Show attack documentation"""
        doc_window = tk.Toplevel(self.parent)
        doc_window.title("WEP Attack Documentation")
        doc_window.geometry("700x600")
        
        text_widget = scrolledtext.ScrolledText(doc_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        docs = """WEP ATTACK DOCUMENTATION

1. FMS Attack (Fluhrer, Mantin, Shamir) - 2001
   
   Overview:
   First practical attack on WEP that exploits weak IVs in RC4.
   
   How it works:
   - Identifies weak IVs of the form (A+3, 255, X)
   - Uses these IVs to reveal key bytes through statistical analysis
   - Analyzes the first output byte of RC4 keystream
   
   Requirements:
   - 5-10 million packets for 104-bit WEP
   - Passive sniffing only
   
   Impact: Proved WEP was fundamentally broken

2. KoreK Attack - 2004
   
   Overview:
   Improves on FMS by identifying 16 classes of weak IVs.
   
   How it works:
   - Extends FMS concept to multiple IV patterns
   - Uses more sophisticated statistical analysis
   - Applies voting algorithms for key recovery
   
   Requirements:
   - Fewer packets than FMS (hundreds of thousands)
   - More efficient key recovery
   
   Impact: Made WEP cracking significantly faster

3. PTW Attack (Pyshkin, Tews, Weinmann) - 2007
   
   Overview:
   Most efficient WEP attack to date.
   
   How it works:
   - Based on Klein's attack on RC4
   - Uses ARP packets with known plaintext
   - Applies probability distributions to recover key
   
   Requirements:
   - Only ~40,000 packets needed
   - Can crack WEP in minutes
   
   Impact: Made WEP completely impractical to use

4. ARP Replay Attack
   
   Overview:
   Packet injection technique to generate traffic.
   
   How it works:
   - Captures an ARP packet
   - Replays it to trigger responses
   - Each response uses a new IV
   - Accelerates IV collection for statistical attacks
   
   Requirements:
   - One captured ARP packet
   - Active injection capability
   
   Impact: Enables rapid IV collection even on quiet networks

5. Chop-Chop Attack
   
   Overview:
   Decrypts packets without knowing the key.
   
   How it works:
   - Iteratively removes last byte of packet
   - Guesses the byte and tests with CRC validation
   - Uses access point's error responses
   - Works backwards through entire packet
   
   Requirements:
   - One intercepted packet
   - Access to AP responses
   
   Impact: Allows packet decryption and forging

6. Fragmentation Attack
   
   Overview:
   Obtains keystream to forge packets.
   
   How it works:
   - Exploits packet fragmentation feature
   - Extracts 8 bytes of keystream from known plaintext
   - Uses keystream to create valid encrypted packets
   
   Requirements:
   - One packet with known plaintext
   
   Impact: Enables arbitrary packet injection

WHY WEP IS VULNERABLE:

1. Short IV Space (24 bits)
   - Only 16.7 million possible IVs
   - Birthday paradox: 50% collision after ~5,000 packets
   - IV reuse reveals keystream

2. RC4 Key Scheduling Weaknesses
   - Certain IV+Key combinations produce predictable output
   - First bytes of keystream leak information about key

3. No Replay Protection
   - Packets can be captured and replayed
   - Enables injection attacks

4. CRC-32 for Integrity
   - Linear function - can be manipulated
   - Enables bit-flipping attacks

5. No Key Management
   - Static keys shared across all devices
   - Compromised key affects entire network

RECOMMENDATIONS:

1. NEVER use WEP in production
2. Use WPA2 or WPA3 instead
3. Understand these attacks for educational purposes
4. This tool is for learning only - not for unauthorized access

For more information:
- "Weaknesses in the Key Scheduling Algorithm of RC4" (FMS paper)
- "Breaking WEP in Less Than 60 Seconds" (KoreK)
- "Breaking 104 bit WEP in less than 60 seconds" (PTW paper)
"""
        
        text_widget.insert(tk.END, docs)
        text_widget.config(state='disabled')
        
        self.log("Opened attack documentation")
