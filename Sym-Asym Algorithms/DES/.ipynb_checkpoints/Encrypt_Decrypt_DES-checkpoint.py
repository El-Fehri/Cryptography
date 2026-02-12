import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

class DESEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptoraphie symetrique : DES")
        self.root.geometry("800x700")
        
        # Frame principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Entrée pour la clé
        ttk.Label(main_frame, text="Clé (format hexadécimal):").grid(row=0, column=0, sticky=tk.W)
        self.key_var = tk.StringVar(value="0x0123456789ABCDEF")
        self.key_entry = ttk.Entry(main_frame, textvariable=self.key_var, width=40)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)

        # Zone de texte d'entrée
        ttk.Label(main_frame, text="Texte à traiter:").grid(row=1, column=0, sticky=tk.W)
        self.input_text = scrolledtext.ScrolledText(main_frame, height=6, width=60)
        self.input_text.grid(row=1, column=1, padx=5, pady=5)

        # Boutons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.encrypt_button = ttk.Button(button_frame, text="Chiffrer", command=self.encrypt_text)
        self.encrypt_button.grid(row=0, column=0, padx=5)
        
        self.decrypt_button = ttk.Button(button_frame, text="Déchiffrer", command=self.decrypt_text)
        self.decrypt_button.grid(row=0, column=1, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Effacer tout", command=self.clear_all)
        self.clear_button.grid(row=0, column=2, padx=5)

        # Zone de résultat
        ttk.Label(main_frame, text="Résultat:").grid(row=4, column=0, sticky=tk.W)
        self.result_text = scrolledtext.ScrolledText(main_frame, height=6, width=60)
        self.result_text.grid(row=4, column=1, padx=5, pady=5)

    def hex_to_bytes(self, hex_string):
        try:
            hex_string = hex_string.replace('0x', '').replace(' ', '')
            if len(hex_string) != 16:
                raise ValueError("La clé doit faire exactement 64 bits (16 caractères hexadécimaux)")
            return bytes.fromhex(hex_string)
        except ValueError as e:
            raise ValueError(f"Format de clé invalide: {str(e)}")

    def encrypt_text(self):
        try:
            # Récupérer la clé et le texte
            key = self.hex_to_bytes(self.key_var.get())
            text = self.input_text.get(1.0, tk.END).strip().encode('utf-8')
            
            # Padding
            padded_text = pad(text, DES.block_size)
            
            # Chiffrement
            cipher = DES.new(key, DES.MODE_ECB)
            encrypted_text = cipher.encrypt(padded_text)
            
            # Afficher le résultat selon le format choisi
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, encrypted_text.hex())
            
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def decrypt_text(self):
        try:
            # Récupérer la clé
            key = self.hex_to_bytes(self.key_var.get())
            input_text = self.input_text.get(1.0, tk.END).strip()
            
            try:
                # Essayer d'abord le format hexadécimal
                if all(c in '0123456789ABCDEFabcdef' for c in input_text):
                    encrypted_text = bytes.fromhex(input_text)
                else:
                    # Sinon essayer le format base64
                    encrypted_text = binascii.a2b_base64(input_text)
            except:
                raise ValueError("Le texte d'entrée doit être en format hexadécimal ou base64")
            
            # Déchiffrement
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(encrypted_text), DES.block_size)
            
            # Afficher le résultat
            self.result_text.delete(1.0, tk.END)
            try:
                # Essayer de décoder en UTF-8
                self.result_text.insert(tk.END, decrypted_text.decode('utf-8'))
            except UnicodeDecodeError:
                # Si le décodage échoue, afficher en hexadécimal
                self.result_text.insert(tk.END, decrypted_text.hex())
            
        except Exception as e:
            messagebox.showerror("Erreur de déchiffrement", 
                               "Erreur lors du déchiffrement. Vérifiez que :\n"
                               "1. La clé est correcte\n"
                               "2. Le texte chiffré est au bon format (hex ou base64)\n"
                               "3. Le texte n'a pas été modifié\n\n"
                               f"Détail de l'erreur : {str(e)}")

    def clear_all(self):
        self.input_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)

def main():
    root = tk.Tk()
    app = DESEncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()