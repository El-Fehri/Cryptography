"""
Encryption Tab - WEP Encryption and Decryption Interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
from wep_packet import WEPPacket


class EncryptionTab:
    """Tab for WEP encryption/decryption operations"""
    
    def __init__(self, parent, wep_engine, log_callback):
        """
        Initialize encryption tab
        
        Args:
            parent: Parent widget
            wep_engine: WEPEngine instance
            log_callback: Function to call for logging
        """
        self.parent = parent
        self.wep_engine = wep_engine
        self.log = log_callback
        self.packets = []
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create all widgets for the encryption tab"""
        # Main container
        main_frame = ttk.Frame(self.parent, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Key Configuration Section
        key_frame = ttk.LabelFrame(main_frame, text="WEP Key Configuration", padding="10")
        key_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(key_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W)
        self.key_size_var = tk.StringVar(value="40")
        key_size_combo = ttk.Combobox(key_frame, textvariable=self.key_size_var, 
                                      values=["40", "104"], state="readonly", width=10)
        key_size_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        key_size_combo.bind("<<ComboboxSelected>>", self.on_key_size_changed)
        
        ttk.Label(key_frame, text="bits").grid(row=0, column=2, sticky=tk.W)
        
        ttk.Label(key_frame, text="WEP Key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(key_frame, width=30)
        self.key_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        self.key_entry.insert(0, "12345")
        
        ttk.Button(key_frame, text="Set Key", command=self.set_key).grid(
            row=1, column=3, padx=5)
        
        self.key_status_label = ttk.Label(key_frame, text="No key set", foreground="red")
        self.key_status_label.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=5)
        
        # Packet Generation Section
        packet_frame = ttk.LabelFrame(main_frame, text="Packet Generation", padding="10")
        packet_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=(0, 5))
        
        ttk.Label(packet_frame, text="Packet Type:").grid(row=0, column=0, sticky=tk.W)
        self.packet_type_var = tk.StringVar(value="ARP Request")
        packet_types = list(WEPPacket.PACKET_TYPES.keys())
        packet_type_combo = ttk.Combobox(packet_frame, textvariable=self.packet_type_var,
                                         values=packet_types, state="readonly", width=20)
        packet_type_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(packet_frame, text="Data Size:").grid(row=1, column=0, sticky=tk.W)
        self.data_size_var = tk.StringVar(value="64")
        data_size_spin = ttk.Spinbox(packet_frame, from_=32, to=1500, 
                                     textvariable=self.data_size_var, width=20)
        data_size_spin.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(packet_frame, text="Number of Packets:").grid(row=2, column=0, sticky=tk.W)
        self.num_packets_var = tk.StringVar(value="1")
        num_packets_spin = ttk.Spinbox(packet_frame, from_=1, to=1000,
                                       textvariable=self.num_packets_var, width=20)
        num_packets_spin.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Weak IV options
        self.weak_iv_var = tk.BooleanVar()
        weak_iv_check = ttk.Checkbutton(packet_frame, text="Generate Weak IVs (for testing)",
                                        variable=self.weak_iv_var)
        weak_iv_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(packet_frame, text="Weak IV Type:").grid(row=4, column=0, sticky=tk.W)
        self.weak_iv_type_var = tk.StringVar(value="fms")
        weak_type_combo = ttk.Combobox(packet_frame, textvariable=self.weak_iv_type_var,
                                       values=["fms", "korek"], state="readonly", width=20)
        weak_type_combo.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(packet_frame, text="Generate & Encrypt", 
                  command=self.generate_and_encrypt).grid(
            row=5, column=0, columnspan=2, pady=10)
        
        # Encryption Results Section
        results_frame = ttk.LabelFrame(main_frame, text="Encryption Results", padding="10")
        results_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=50, height=15, 
                                                      wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Packet List Section
        list_frame = ttk.LabelFrame(main_frame, text="Encrypted Packets", padding="10")
        list_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Create Treeview for packet list
        columns = ("ID", "Type", "IV", "Size", "Status")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)
        
        self.packet_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # Packet operations
        ops_frame = ttk.Frame(list_frame)
        ops_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(ops_frame, text="View Selected", command=self.view_selected_packet).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(ops_frame, text="Decrypt Selected", command=self.decrypt_selected_packet).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(ops_frame, text="Clear All", command=self.clear_packets).pack(
            side=tk.LEFT, padx=5)
        
        # Statistics
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="No packets encrypted yet")
        self.stats_label.pack()
    
    def on_key_size_changed(self, event=None):
        """Handle key size change"""
        try:
            key_size = int(self.key_size_var.get())
            self.wep_engine.set_key_size(key_size)
            self.log(f"Key size changed to {key_size} bits")
            # Re-set key if one is already set
            if self.wep_engine.key:
                self.set_key()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change key size: {str(e)}")
    
    def set_key(self):
        """Set the WEP key"""
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Warning", "Please enter a key")
            return
        
        try:
            key_bytes = self.wep_engine.set_key(key)
            key_hex = binascii.hexlify(key_bytes).decode().upper()
            self.key_status_label.config(
                text=f"Key set: {key_hex} ({self.wep_engine.key_size} bits)",
                foreground="green"
            )
            self.log(f"WEP key set: {key_hex} ({self.wep_engine.key_size} bits)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set key: {str(e)}")
    
    def generate_and_encrypt(self):
        """Generate and encrypt packets"""
        if not self.wep_engine.key_bytes:
            messagebox.showwarning("Warning", "Please set a WEP key first")
            return
        
        try:
            packet_type = self.packet_type_var.get()
            data_size = int(self.data_size_var.get())
            num_packets = int(self.num_packets_var.get())
            weak_iv = self.weak_iv_var.get()
            weak_iv_type = self.weak_iv_type_var.get() if weak_iv else None
            
            self.results_text.delete(1.0, tk.END)
            self.log(f"Generating {num_packets} {packet_type} packet(s)...")
            
            for i in range(num_packets):
                # Create packet
                packet = WEPPacket(packet_type=packet_type, data_size=data_size)
                
                # Encrypt
                result = self.wep_engine.encrypt_packet(
                    packet, 
                    weak_iv=weak_iv, 
                    attack_type=weak_iv_type
                )
                
                self.packets.append(packet)
                
                # Display result for first packet or if only one packet
                if i == 0 or num_packets == 1:
                    self.display_encryption_result(result, i + 1)
                
                # Add to tree
                iv_hex = binascii.hexlify(result['iv']).decode().upper()
                self.packet_tree.insert('', tk.END, values=(
                    len(self.packets),
                    packet_type,
                    iv_hex,
                    len(result['encrypted_data']),
                    "Encrypted"
                ))
            
            if num_packets > 1:
                self.results_text.insert(tk.END, f"\n... {num_packets} packets encrypted successfully\n")
            
            self.update_statistics()
            self.log(f"Successfully encrypted {num_packets} packet(s)")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.log(f"ERROR: {str(e)}")
    
    def display_encryption_result(self, result, packet_num):
        """Display encryption result in text widget"""
        self.results_text.insert(tk.END, f"=== Packet #{packet_num} ===\n")
        self.results_text.insert(tk.END, f"Type: {result['packet_type']}\n")
        self.results_text.insert(tk.END, f"IV: {binascii.hexlify(result['iv']).decode().upper()}\n")
        self.results_text.insert(tk.END, f"Plaintext: {binascii.hexlify(result['plaintext'][:16]).decode().upper()}...\n")
        self.results_text.insert(tk.END, f"Encrypted: {binascii.hexlify(result['encrypted_data'][:16]).decode().upper()}...\n")
        self.results_text.insert(tk.END, f"ICV: {binascii.hexlify(result['icv']).decode().upper()}\n")
        self.results_text.insert(tk.END, f"Weak IV: {result.get('is_weak_iv', False)}\n")
        self.results_text.insert(tk.END, "\n")
    
    def view_selected_packet(self):
        """View details of selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a packet")
            return
        
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if packet_id >= len(self.packets):
            return
        
        packet = self.packets[packet_id]
        
        # Create detail window
        detail_window = tk.Toplevel(self.parent)
        detail_window.title(f"Packet #{packet_id + 1} Details")
        detail_window.geometry("600x400")
        
        text_widget = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Display details
        text_widget.insert(tk.END, f"Packet Type: {packet.type}\n")
        text_widget.insert(tk.END, f"Data Size: {packet.data_size} bytes\n\n")
        
        if packet.iv:
            text_widget.insert(tk.END, f"IV: {binascii.hexlify(packet.iv).decode().upper()}\n\n")
        
        if packet.plaintext:
            text_widget.insert(tk.END, "Plaintext (hex):\n")
            text_widget.insert(tk.END, binascii.hexlify(packet.plaintext).decode().upper() + "\n\n")
        
        if packet.encrypted_data:
            text_widget.insert(tk.END, "Encrypted Data (hex):\n")
            text_widget.insert(tk.END, binascii.hexlify(packet.encrypted_data).decode().upper() + "\n\n")
        
        if packet.icv:
            text_widget.insert(tk.END, f"ICV: {binascii.hexlify(packet.icv).decode().upper()}\n")
        
        text_widget.config(state='disabled')
    
    def decrypt_selected_packet(self):
        """Decrypt selected packet"""
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a packet")
            return
        
        item = self.packet_tree.item(selection[0])
        packet_id = int(item['values'][0]) - 1
        
        if packet_id >= len(self.packets):
            return
        
        packet = self.packets[packet_id]
        
        try:
            plaintext, icv_valid = self.wep_engine.decrypt_packet(
                packet.iv, packet.encrypted_data
            )
            
            # Display result
            result_text = f"Decryption Result:\n\n"
            result_text += f"ICV Valid: {icv_valid}\n"
            result_text += f"Plaintext (hex): {binascii.hexlify(plaintext).decode().upper()}\n"
            
            messagebox.showinfo("Decryption Result", result_text)
            self.log(f"Packet #{packet_id + 1} decrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.log(f"ERROR: Decryption failed - {str(e)}")
    
    def clear_packets(self):
        """Clear all packets"""
        if messagebox.askyesno("Confirm", "Clear all packets?"):
            self.packets = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.results_text.delete(1.0, tk.END)
            self.update_statistics()
            self.log("All packets cleared")
    
    def update_statistics(self):
        """Update statistics display"""
        stats = self.wep_engine.get_iv_statistics()
        
        stats_text = f"Total Packets: {len(self.packets)} | "
        stats_text += f"Unique IVs: {stats['unique_ivs']} | "
        stats_text += f"IV Reuse: {stats['reused_ivs']} | "
        stats_text += f"Collision Rate: {stats['collision_rate']:.2f}%"
        
        self.stats_label.config(text=stats_text)
