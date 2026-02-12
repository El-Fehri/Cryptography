import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

class DESKeyVerifierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Vérificateur de clés DES semi-faibles")
        self.root.geometry("800x600")
        
        # Style
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabel', padding=5)
        style.configure('TEntry', padding=5)

        # Frame principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Entrées pour les clés
        ttk.Label(main_frame, text="Première clé (hex):").grid(row=0, column=0, sticky=tk.W)
        self.key1_var = tk.StringVar(value="0x011F011F010E010E")
        self.key1_entry = ttk.Entry(main_frame, textvariable=self.key1_var, width=40)
        self.key1_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(main_frame, text="Deuxième clé (hex):").grid(row=1, column=0, sticky=tk.W)
        self.key2_var = tk.StringVar(value="0x1F011F010E010E01")
        self.key2_entry = ttk.Entry(main_frame, textvariable=self.key2_var, width=40)
        self.key2_entry.grid(row=1, column=1, padx=5, pady=5)

        # Zone de texte pour le message
        ttk.Label(main_frame, text="Message à tester:").grid(row=2, column=0, sticky=tk.W)
        self.text_input = scrolledtext.ScrolledText(main_frame, height=4, width=50)
        self.text_input.grid(row=2, column=1, padx=5, pady=5)
        self.text_input.insert(tk.END, "Ceci est un test.")

        # Bouton de vérification
        self.verify_button = ttk.Button(main_frame, text="Vérifier les clés", command=self.verify_keys)
        self.verify_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Zone de résultats
        ttk.Label(main_frame, text="Résultats:").grid(row=4, column=0, sticky=tk.W)
        self.results_text = scrolledtext.ScrolledText(main_frame, height=15, width=70)
        self.results_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        # Bouton pour effacer les résultats
        self.clear_button = ttk.Button(main_frame, text="Effacer les résultats", command=self.clear_results)
        self.clear_button.grid(row=6, column=0, columnspan=2, pady=10)

    def hex_to_bytes(self, hex_string):
        try:
            hex_string = hex_string.replace('0x', '').replace(' ', '')
            return bytes.fromhex(hex_string)
        except ValueError as e:
            raise ValueError(f"Format hexadécimal invalide: {str(e)}")

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)

    def verify_keys(self):
        try:
            # Récupérer les entrées
            key1_hex = self.key1_var.get()
            key2_hex = self.key2_var.get()
            text_to_test = self.text_input.get(1.0, tk.END).strip()

            # Convertir les clés
            key1 = self.hex_to_bytes(key1_hex)
            key2 = self.hex_to_bytes(key2_hex)

            if len(key1) != 8 or len(key2) != 8:
                raise ValueError("Les clés doivent faire 64 bits (8 bytes)")

            # Préparation du texte
            text = text_to_test.encode('utf-8')
            padded_text = pad(text, DES.block_size)

            # Premier chiffrement
            cipher1 = DES.new(key1, DES.MODE_ECB)
            first_encryption = cipher1.encrypt(padded_text)

            # Deuxième chiffrement
            cipher2 = DES.new(key2, DES.MODE_ECB)
            second_encryption = cipher2.encrypt(first_encryption)

            # Déchiffrement final
            final_text = unpad(second_encryption, DES.block_size).decode('utf-8')

            # Vérification
            is_semi_weak = final_text == text_to_test

            # Afficher les résultats
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "=== Résultats de la vérification ===\n\n")
            self.results_text.insert(tk.END, f"Statut: Les clés sont {'semi-faibles' if is_semi_weak else 'non semi-faibles'}\n\n")
            self.results_text.insert(tk.END, f"Texte original: {text_to_test}\n")
            self.results_text.insert(tk.END, f"Premier chiffrement (hex): {first_encryption.hex()}\n")
            self.results_text.insert(tk.END, f"Texte final: {final_text}\n\n")
            
            if is_semi_weak:
                self.results_text.insert(tk.END, "✓ Vérification réussie: Les clés sont bien semi-faibles\n")
            else:
                self.results_text.insert(tk.END, "✗ Les clés ne sont pas semi-faibles\n")

        except Exception as e:
            messagebox.showerror("Erreur", str(e))

def main():
    root = tk.Tk()
    app = DESKeyVerifierGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()