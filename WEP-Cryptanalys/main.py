"""
WEP Encryption & Attack Simulation Tool
Educational tool for understanding WEP vulnerabilities

Main Application File
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# Import our modules
from wep_engine import WEPEngine
from encryption_tab import EncryptionTab
from attack_tab import AttackTab


class WEPSimulator:
    """Main application class"""
    
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.root.title("WEP Encryption & Attack Simulation Tool")
        self.root.geometry("1400x900")
        
        # Initialize WEP engine
        self.wep_engine = WEPEngine()
        
        # Modern color scheme
        self.colors = {
            'bg': '#1e1e2e',           # Dark background
            'fg': '#cdd6f4',           # Light text
            'accent': '#89b4fa',       # Blue accent
            'accent2': '#f38ba8',      # Pink/red accent
            'success': '#a6e3a1',      # Green
            'warning': '#f9e2af',      # Yellow
            'danger': '#f38ba8',       # Red
            'card': '#2a2a3e',         # Card background
            'border': '#45475a',       # Border color
            'hover': '#3a3a4e',        # Hover state
            'button': '#89b4fa',       # Button color
            'button_hover': '#74a0e8', # Button hover
        }
        
        # Configure modern style
        self.configure_modern_style()
        
        # Create menu
        self.create_menu()
        
        # Create main container
        self.create_main_layout()
        
        # Status bar
        self.create_status_bar()
        
        # Log initial message
        self.log("WEP Simulation Tool initialized")
        self.log("WARNING: This tool is for educational purposes only")
    
    def configure_modern_style(self):
        """Configure modern UI styling"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure root window
        self.root.configure(bg=self.colors['bg'])
        
        # Modern frame style
        style.configure('Modern.TFrame',
                       background=self.colors['bg'])
        
        style.configure('Card.TFrame',
                       background=self.colors['card'],
                       relief='flat',
                       borderwidth=1)
        
        # Label styles
        style.configure('Modern.TLabel',
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       font=('Segoe UI', 10))
        
        style.configure('Title.TLabel',
                       background=self.colors['card'],
                       foreground=self.colors['accent'],
                       font=('Segoe UI', 11, 'bold'))
        
        style.configure('Status.TLabel',
                       background=self.colors['card'],
                       foreground=self.colors['success'],
                       font=('Segoe UI', 9))
        
        style.configure('Error.TLabel',
                       background=self.colors['card'],
                       foreground=self.colors['danger'],
                       font=('Segoe UI', 9))
        
        # Button styles
        style.configure('Accent.TButton',
                       background=self.colors['button'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor=self.colors['accent'],
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        
        style.map('Accent.TButton',
                 background=[('active', self.colors['button_hover']),
                           ('pressed', self.colors['accent'])],
                 foreground=[('active', 'white')])
        
        style.configure('Modern.TButton',
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 10),
                       padding=(12, 6))
        
        style.map('Modern.TButton',
                 background=[('active', self.colors['hover'])],
                 relief=[('pressed', 'flat')])
        
        # Danger button
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        
        # Success button
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground=self.colors['bg'],
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'),
                       padding=(15, 8))
        
        # Entry and Combobox
        style.configure('Modern.TEntry',
                       fieldbackground=self.colors['card'],
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       bordercolor=self.colors['border'],
                       lightcolor=self.colors['border'],
                       darkcolor=self.colors['border'],
                       insertcolor=self.colors['fg'])
        
        style.configure('Modern.TCombobox',
                       fieldbackground=self.colors['card'],
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       arrowcolor=self.colors['accent'],
                       bordercolor=self.colors['border'],
                       lightcolor=self.colors['border'],
                       darkcolor=self.colors['border'])
        
        style.map('Modern.TCombobox',
                 fieldbackground=[('readonly', self.colors['card'])],
                 selectbackground=[('readonly', self.colors['accent'])],
                 selectforeground=[('readonly', 'white')])
        
        # Notebook (tabs)
        style.configure('Modern.TNotebook',
                       background=self.colors['bg'],
                       borderwidth=0,
                       tabmargins=[2, 5, 2, 0])
        
        style.configure('Modern.TNotebook.Tab',
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0)
        
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', self.colors['accent'])],
                 foreground=[('selected', 'white')],
                 expand=[('selected', [1, 1, 1, 0])])
        
        # LabelFrame
        style.configure('Modern.TLabelframe',
                       background=self.colors['card'],
                       foreground=self.colors['accent'],
                       bordercolor=self.colors['border'],
                       relief='flat',
                       borderwidth=1)
        
        style.configure('Modern.TLabelframe.Label',
                       background=self.colors['card'],
                       foreground=self.colors['accent'],
                       font=('Segoe UI', 11, 'bold'))
        
        # Progressbar
        style.configure('Modern.Horizontal.TProgressbar',
                       background=self.colors['accent'],
                       troughcolor=self.colors['card'],
                       bordercolor=self.colors['border'],
                       lightcolor=self.colors['accent'],
                       darkcolor=self.colors['accent'])
        
        # Treeview
        style.configure('Modern.Treeview',
                       background=self.colors['card'],
                       foreground=self.colors['fg'],
                       fieldbackground=self.colors['card'],
                       borderwidth=0,
                       font=('Segoe UI', 9))
        
        style.configure('Modern.Treeview.Heading',
                       background=self.colors['accent'],
                       foreground='white',
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'))
        
        style.map('Modern.Treeview',
                 background=[('selected', self.colors['accent'])],
                 foreground=[('selected', 'white')])
        
        # Scrollbar
        style.configure('Modern.Vertical.TScrollbar',
                       background=self.colors['card'],
                       troughcolor=self.colors['bg'],
                       bordercolor=self.colors['border'],
                       arrowcolor=self.colors['fg'])
        
        # Separator
        style.configure('Modern.TSeparator',
                       background=self.colors['border'])
        
        # PanedWindow
        style.configure('Modern.TPanedwindow',
                       background=self.colors['bg'])
        
        style.configure('Modern.Sash',
                       sashthickness=4,
                       sashrelief='flat',
                       background=self.colors['border'])
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Reset All", command=self.reset_all)
        file_menu.add_command(label="Export Statistics", command=self.export_statistics)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="IV Statistics", command=self.show_iv_statistics)
        tools_menu.add_command(label="Visualization", command=self.show_visualization)
        tools_menu.add_command(label="Clear Log", command=self.clear_log)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="WEP Overview", command=self.show_wep_info)
        help_menu.add_command(label="RC4 Cipher Info", command=self.show_rc4_info)
    
    def create_main_layout(self):
        """Create main application layout"""
        # Main container with PanedWindow for resizable sections
        main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL, style='Modern.TPanedwindow')
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top section: Notebook with tabs
        self.notebook = ttk.Notebook(main_paned, style='Modern.TNotebook')
        main_paned.add(self.notebook, weight=3)
        
        # Create tabs
        encryption_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        attack_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        visualization_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        
        self.notebook.add(encryption_frame, text="🔐 Encryption")
        self.notebook.add(attack_frame, text="⚔️ Attacks")
        self.notebook.add(visualization_frame, text="📊 Visualization")
        
        # Initialize tab content
        self.encryption_tab = EncryptionTab(encryption_frame, self.wep_engine, self.log, self.colors)
        self.attack_tab = AttackTab(attack_frame, self.wep_engine, self.log, self.colors)
        self.create_visualization_tab(visualization_frame)
        
        # Bottom section: Log
        log_frame = ttk.LabelFrame(main_paned, text="📋 Activity Log", padding="10", style='Modern.TLabelframe')
        main_paned.add(log_frame, weight=1)
        
        # Create log text widget with modern styling
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            height=8, 
            wrap=tk.WORD,
            bg=self.colors['card'],
            fg=self.colors['fg'],
            insertbackground=self.colors['accent'],
            selectbackground=self.colors['accent'],
            selectforeground='white',
            font=('Consolas', 9),
            relief='flat',
            borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def create_visualization_tab(self, parent):
        """Create visualization tab"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        # Main frame with modern styling
        viz_frame = ttk.Frame(parent, padding="15", style='Modern.TFrame')
        viz_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        viz_frame.columnconfigure(0, weight=1)
        viz_frame.rowconfigure(1, weight=1)
        
        # Control buttons in card
        control_card = ttk.Frame(viz_frame, style='Card.TFrame', padding="15")
        control_card.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(control_card, text="🔄 Update Visualization", 
                  command=self.update_visualization, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(control_card, text="💾 Export Chart", 
                  command=self.export_chart, style='Modern.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Label(control_card, text="Chart Type:", style='Modern.TLabel').pack(side=tk.LEFT, padx=(20, 5))
        self.chart_type_var = tk.StringVar(value="IV Distribution")
        chart_types = ["IV Distribution", "Weak IV Analysis", "Collision Rate"]
        chart_combo = ttk.Combobox(control_card, textvariable=self.chart_type_var, 
                    values=chart_types, state="readonly", width=20, style='Modern.TCombobox')
        chart_combo.pack(side=tk.LEFT)
        
        # Matplotlib figure with dark theme
        plt.style.use('dark_background')
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(12, 5))
        self.fig.patch.set_facecolor(self.colors['card'])
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor(self.colors['bg'])
            ax.spines['bottom'].set_color(self.colors['border'])
            ax.spines['top'].set_color(self.colors['border'])
            ax.spines['left'].set_color(self.colors['border'])
            ax.spines['right'].set_color(self.colors['border'])
            ax.tick_params(colors=self.colors['fg'])
            ax.xaxis.label.set_color(self.colors['fg'])
            ax.yaxis.label.set_color(self.colors['fg'])
            ax.title.set_color(self.colors['accent'])
        self.fig.tight_layout(pad=3.0)
        
        canvas_frame = ttk.Frame(viz_frame, style='Card.TFrame', padding="10")
        canvas_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        canvas_frame.columnconfigure(0, weight=1)
        canvas_frame.rowconfigure(0, weight=1)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=canvas_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial empty plot
        self.ax1.text(0.5, 0.5, 'No data yet\nEncrypt packets to see visualization', 
                     ha='center', va='center', transform=self.ax1.transAxes,
                     color=self.colors['fg'], fontsize=12)
        self.ax2.text(0.5, 0.5, 'Waiting for IV data...', 
                     ha='center', va='center', transform=self.ax2.transAxes,
                     color=self.colors['fg'], fontsize=12)
        self.ax1.set_title('IV Distribution', fontsize=14, fontweight='bold')
        self.ax2.set_title('IV Statistics', fontsize=14, fontweight='bold')
        self.canvas.draw()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        status_frame = ttk.Frame(self.root, style='Card.TFrame')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(
            status_frame, 
            text="Ready", 
            style='Modern.TLabel',
            padding=(10, 5)
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # IV counter with icon
        self.iv_count_label = ttk.Label(
            status_frame, 
            text="🔑 IVs: 0", 
            style='Modern.TLabel',
            padding=(10, 5),
            width=18
        )
        self.iv_count_label.pack(side=tk.RIGHT, padx=2)
        
        # Packet counter with icon
        self.packet_count_label = ttk.Label(
            status_frame, 
            text="📦 Packets: 0",
            style='Modern.TLabel',
            padding=(10, 5),
            width=18
        )
        self.packet_count_label.pack(side=tk.RIGHT, padx=2)
    
    def update_visualization(self):
        """Update visualization charts"""
        if not self.wep_engine.captured_ivs:
            messagebox.showinfo("No Data", "No IVs captured yet. Encrypt some packets first.")
            return
        
        # Clear previous plots
        self.ax1.clear()
        self.ax2.clear()
        
        chart_type = self.chart_type_var.get()
        
        if chart_type == "IV Distribution":
            self.plot_iv_distribution()
        elif chart_type == "Weak IV Analysis":
            self.plot_weak_iv_analysis()
        elif chart_type == "Collision Rate":
            self.plot_collision_rate()
        
        self.canvas.draw()
        self.log("Visualization updated")
    
    def plot_iv_distribution(self):
        """Plot IV distribution"""
        # Get IV data
        iv_counts = list(self.wep_engine.captured_ivs.values())
        
        # Left plot: IV usage histogram
        self.ax1.hist(iv_counts, bins=20, color='steelblue', edgecolor='black', alpha=0.7)
        self.ax1.set_xlabel('Number of Uses')
        self.ax1.set_ylabel('Frequency')
        self.ax1.set_title('IV Reuse Distribution')
        self.ax1.grid(True, alpha=0.3)
        
        # Right plot: Top 10 most used IVs
        top_ivs = sorted(self.wep_engine.captured_ivs.items(), key=lambda x: x[1], reverse=True)[:10]
        if top_ivs:
            ivs = [iv[:8] + "..." for iv, _ in top_ivs]
            counts = [count for _, count in top_ivs]
            
            y_pos = np.arange(len(ivs))
            self.ax2.barh(y_pos, counts, color='coral', edgecolor='black')
            self.ax2.set_yticks(y_pos)
            self.ax2.set_yticklabels(ivs, fontsize=8)
            self.ax2.set_xlabel('Usage Count')
            self.ax2.set_title('Top 10 Most Reused IVs')
            self.ax2.grid(True, alpha=0.3, axis='x')
    
    def plot_weak_iv_analysis(self):
        """Plot weak IV analysis"""
        from attack_simulations import WEPAttacks
        attacks = WEPAttacks(self.wep_engine)
        analysis = attacks.analyze_weak_ivs()
        
        # Left plot: Weak vs Strong IVs
        weak_total = analysis['fms_weak_count'] + analysis['korek_weak_count']
        strong_total = analysis['total_ivs'] - weak_total
        
        labels = ['Weak IVs', 'Strong IVs']
        sizes = [weak_total, strong_total]
        colors = ['#ff6b6b', '#4ecdc4']
        explode = (0.1, 0)
        
        self.ax1.pie(sizes, explode=explode, labels=labels, colors=colors,
                    autopct='%1.1f%%', shadow=True, startangle=90)
        self.ax1.set_title('Weak vs Strong IVs')
        
        # Right plot: Weak IV breakdown
        categories = ['FMS Weak', 'KoreK Weak', 'Strong']
        values = [analysis['fms_weak_count'], analysis['korek_weak_count'], strong_total]
        colors_bar = ['#ff6b6b', '#ff9999', '#4ecdc4']
        
        self.ax2.bar(categories, values, color=colors_bar, edgecolor='black')
        self.ax2.set_ylabel('Count')
        self.ax2.set_title('IV Classification')
        self.ax2.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for i, v in enumerate(values):
            self.ax2.text(i, v, str(v), ha='center', va='bottom')
    
    def plot_collision_rate(self):
        """Plot IV collision statistics"""
        stats = self.wep_engine.get_iv_statistics()
        
        # Left plot: Unique vs Reused IVs
        labels = ['Unique', 'Reused']
        sizes = [stats['unique_ivs'], stats['reused_ivs']]
        colors = ['#51cf66', '#ff6b6b']
        
        self.ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                    shadow=True, startangle=45)
        self.ax1.set_title(f"IV Collisions\n({stats['collision_rate']:.1f}% collision rate)")
        
        # Right plot: Theoretical vs Actual collision probability
        x_packets = np.linspace(0, max(stats['total_ivs'], 10000), 100)
        iv_space = 2 ** 24
        theoretical_prob = 1 - np.exp(-(x_packets ** 2) / (2 * iv_space))
        
        self.ax2.plot(x_packets, theoretical_prob * 100, 'b-', 
                     label='Theoretical (Birthday Paradox)', linewidth=2)
        self.ax2.axvline(stats['total_ivs'], color='r', linestyle='--', 
                        label=f'Current ({stats["total_ivs"]} packets)')
        self.ax2.axhline(stats['collision_probability'], color='g', linestyle='--',
                        label=f'Current Probability ({stats["collision_probability"]:.1f}%)')
        
        self.ax2.set_xlabel('Number of Packets')
        self.ax2.set_ylabel('Collision Probability (%)')
        self.ax2.set_title('IV Collision Probability Over Time')
        self.ax2.legend(fontsize=8)
        self.ax2.grid(True, alpha=0.3)
    
    def show_iv_statistics(self):
        """Show detailed IV statistics window"""
        stats = self.wep_engine.get_iv_statistics()
        
        stat_window = tk.Toplevel(self.root)
        stat_window.title("IV Statistics")
        stat_window.geometry("500x400")
        
        text_widget = scrolledtext.ScrolledText(stat_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Format statistics
        stat_text = f"""IV STATISTICS

Total Packets: {stats['total_ivs']}
Unique IVs: {stats['unique_ivs']}
Reused IVs: {stats['reused_ivs']}
Collision Rate: {stats['collision_rate']:.2f}%

IV Space Usage: {stats['iv_space_usage']:.6f}%
Collision Probability: {stats['collision_probability']:.2f}%

Most Reused IVs:
"""
        for iv, count in stats['most_reused']:
            stat_text += f"  {iv}: {count} times\n"
        
        stat_text += f"""

ANALYSIS:
- WEP uses a 24-bit IV space (16,777,216 possible IVs)
- Birthday paradox: 50% collision probability after ~5,000 packets
- Current collision probability: {stats['collision_probability']:.2f}%
- IV reuse allows keystream recovery attacks

SECURITY IMPLICATIONS:
{'✗ HIGH RISK: Significant IV reuse detected!' if stats['collision_rate'] > 10 else '⚠ MODERATE RISK: Some IV reuse present' if stats['collision_rate'] > 1 else '✓ LOW RISK: Minimal IV reuse so far'}
"""
        
        text_widget.insert(tk.END, stat_text)
        text_widget.config(state='disabled')
        
        self.log("Opened IV statistics window")
    
    def show_visualization(self):
        """Switch to visualization tab and update"""
        self.notebook.select(2)  # Select visualization tab
        self.update_visualization()
    
    def reset_all(self):
        """Reset all data"""
        if messagebox.askyesno("Confirm Reset", "This will clear all packets and statistics. Continue?"):
            self.wep_engine.reset_statistics()
            self.encryption_tab.clear_packets()
            self.log_text.delete(1.0, tk.END)
            self.update_status()
            self.log("All data reset")
            messagebox.showinfo("Reset Complete", "All data has been cleared.")
    
    def export_statistics(self):
        """Export statistics to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            stats = self.wep_engine.get_iv_statistics()
            with open(filename, 'w') as f:
                f.write("WEP SIMULATION STATISTICS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Total Packets: {stats['total_ivs']}\n")
                f.write(f"Unique IVs: {stats['unique_ivs']}\n")
                f.write(f"Reused IVs: {stats['reused_ivs']}\n")
                f.write(f"Collision Rate: {stats['collision_rate']:.2f}%\n")
                f.write(f"IV Space Usage: {stats['iv_space_usage']:.6f}%\n")
                f.write(f"Collision Probability: {stats['collision_probability']:.2f}%\n")
            self.log(f"Statistics exported to {filename}")
            messagebox.showinfo("Export Complete", f"Statistics saved to:\n{filename}")
    
    def export_chart(self):
        """Export current chart to image file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if filename:
            self.fig.savefig(filename, dpi=300, bbox_inches='tight')
            self.log(f"Chart exported to {filename}")
            messagebox.showinfo("Export Complete", f"Chart saved to:\n{filename}")
    
    def log(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.update_status()
    
    def clear_log(self):
        """Clear the log"""
        if messagebox.askyesno("Clear Log", "Clear all log entries?"):
            self.log_text.delete(1.0, tk.END)
            self.log("Log cleared")
    
    def update_status(self):
        """Update status bar"""
        stats = self.wep_engine.get_iv_statistics()
        self.iv_count_label.config(text=f"IVs: {stats['unique_ivs']}")
        self.packet_count_label.config(text=f"Packets: {stats['total_ivs']}")
        
        if self.wep_engine.key:
            self.status_label.config(text=f"Ready - Key: {self.wep_engine.key} ({self.wep_engine.key_size}-bit)")
        else:
            self.status_label.config(text="Ready - No key set")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """WEP Encryption & Attack Simulation Tool
Version 2.0

A comprehensive educational tool for understanding 
WEP encryption and its vulnerabilities.

Features:
• Complete RC4 stream cipher implementation
• WEP packet encryption/decryption
• Multiple attack simulations (FMS, KoreK, PTW, etc.)
• Real-time IV analysis and visualization
• Statistical analysis tools

Educational Purpose:
This tool demonstrates why WEP should never be used
in production environments and helps students understand
cryptographic weaknesses.

⚠️ WARNING: For educational use only!
Unauthorized access to computer networks is illegal.

Created for cybersecurity education.
"""
        messagebox.showinfo("About", about_text)
    
    def show_wep_info(self):
        """Show WEP information"""
        info_window = tk.Toplevel(self.root)
        info_window.title("WEP Overview")
        info_window.geometry("700x600")
        
        text_widget = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        wep_info = """WEP (WIRED EQUIVALENT PRIVACY) OVERVIEW

Introduction:
WEP was the first security protocol for Wi-Fi, introduced in 1997.

How WEP Works:
1. Key Setup: Shared secret key (40 or 104 bits) + 24-bit IV
2. Encryption: RC4 keystream XOR with plaintext
3. Integrity: CRC-32 checksum (ICV)
4. Transmission: IV (plaintext) + Encrypted(Data + ICV)

Critical Weaknesses:
1. Small IV Space (24 bits)
2. RC4 Key Scheduling Weaknesses  
3. No Replay Protection
4. Weak CRC-32 Integrity
5. Static Key Management

Timeline:
1997 - WEP introduced
2001 - First cryptographic weaknesses published
2004 - WPA became mandatory
2007 - PTW attack (crack in minutes)
2012 - WEP officially deprecated

Modern Alternatives:
✓ WPA2 (AES-CCMP)
✓ WPA3 
✗ WEP - NEVER USE

DO NOT USE WEP IN PRODUCTION!
"""
        
        text_widget.insert(tk.END, wep_info)
        text_widget.config(state='disabled')
    
    def show_rc4_info(self):
        """Show RC4 cipher information"""
        info_window = tk.Toplevel(self.root)
        info_window.title("RC4 Cipher Information")
        info_window.geometry("700x500")
        
        text_widget = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        rc4_info = """RC4 STREAM CIPHER

Overview:
RC4 is a stream cipher designed by Ron Rivest in 1987.

Algorithm:
1. Key Scheduling Algorithm (KSA): Initialize state
2. Pseudo-Random Generation Algorithm (PRGA): Generate keystream
3. Encryption: ciphertext = plaintext XOR keystream

Weaknesses:
✗ Weak keys exist
✗ Biased output in first bytes
✗ Related key attacks possible
✗ Statistical biases

Status: DEPRECATED (2016)

Modern Alternatives:
✓ AES
✓ ChaCha20
✓ Salsa20

Educational Value:
Still studied to understand:
• Stream cipher principles
• Importance of proper IV usage
• Cryptographic evolution
"""
        
        text_widget.insert(tk.END, rc4_info)
        text_widget.config(state='disabled')


def main():
    """Main entry point"""
    root = tk.Tk()
    app = WEPSimulator(root)
    root.mainloop()


if __name__ == "__main__":
    main()