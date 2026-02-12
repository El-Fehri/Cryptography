import random
import tkinter as tk
from tkinter import scrolledtext

# PC-1 and PC-2 permutation tables
pc1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
pc2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
rounds = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Generating key of 64 bits
def key_gen():
    key = []   
    for i in range(7):
        key.append(random.choice([0, 1]))

    for i in range(7, 64):
        if (i + 1) % 8 == 0:  
            xor = key[i - 7] 
            for b in key[i - 6:i]:  
                xor ^= b
            key.append(xor)  
        else:
            key.append(random.choice([0, 1]))  
    return key

# Permutation
def permutation(key, perm):
    return [key[i - 1] for i in perm]

# Split the key
def split_key(key):
    mid = len(key) // 2
    return key[:mid], key[mid:]

# Shift left key halves
def left_shifts(key, n):
    return key[n:] + key[:n]

# Generate subkeys from k1 to k16
def generate_subkeys(k):
    subkeys = []  # List to store subkeys from k1 to k16

    # Apply PC-1 permutation to the initial key
    pk = permutation(k, pc1)
    
    # Split the permuted key into two halves
    l, r = split_key(pk)
    
    # Generate 16 subkeys
    for i in range(16):
        # Perform the left shift for both halves
        shifts = rounds[i]  # Number of shifts for the current round
        l = left_shifts(l, shifts)
        r = left_shifts(r, shifts)

        # Combine the left and right halves
        combined_key = l + r

        # Apply PC-2 permutation to get the subkey
        subkey = permutation(combined_key, pc2)
        subkeys.append(subkey)

    return subkeys

def binary_to_hex(binary_key):
    # Convert binary list to a string
    binary_str = ''.join(map(str, binary_key))
    # Convert the binary string to an integer, then to hexadecimal
    hex_str = hex(int(binary_str, 2))[2:].upper()  # Remove '0x' prefix and make uppercase
    # Pad with leading zeros to make it even-length (if needed)
    return hex_str.zfill(len(binary_key) // 4)

def hex_to_binary(hex_key):
    # Convert hex string to binary string
    binary_str = bin(int(hex_key, 16))[2:].zfill(64)
    # Convert binary string to a list of integers
    return [int(bit) for bit in binary_str]

def display_key_and_subkeys():
    user_key = key_entry.get().strip()

    if user_key:
        # Validate the input key length and content
        if len(user_key) != 16 or not all(c in '0123456789ABCDEFabcdef' for c in user_key):
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.END, "Invalid key! Please enter a 16-character hexadecimal key.")
            return
        # Convert the input key to binary
        k = hex_to_binary(user_key)
    else:
        # Generate a random key
        k = key_gen()

    # Convert the main key to hexadecimal
    hex_key = binary_to_hex(k)

    # Generate subkeys
    subkeys = generate_subkeys(k)

    # Display the results in the text widget
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"La cle principale:\nHex: {hex_key}\t\t")
    output_text.insert(tk.END, "Bin:\t")
    output_text.insert(tk.END, ''.join(map(str, k)) + "\n")

    for i, subkey in enumerate(subkeys, 1):
        # Convert the subkey to hexadecimal
        hex_subkey = binary_to_hex(subkey)

        output_text.insert(tk.END, f"Subkey k{i}:\n")
        output_text.insert(tk.END, f"Hex: {hex_subkey}\t\t Bin: ")
        output_text.insert(tk.END, ''.join(map(str, subkey)) + "\n")

# Create the main window
root = tk.Tk()
root.title("DES Key Generator")

# Create a frame for the key input
key_frame = tk.Frame(root)
key_frame.pack(pady=10)

key_label = tk.Label(key_frame, text="Cle hex (optional):")
key_label.pack(side=tk.LEFT, padx=5)

key_entry = tk.Entry(key_frame, width=70)
key_entry.pack(side=tk.LEFT, padx=5)

# Create a frame for the button
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Create the generate button
generate_button = tk.Button(button_frame, text="Generer", command=display_key_and_subkeys)
generate_button.pack()

# Create a scrolled text widget for displaying the output
output_text = scrolledtext.ScrolledText(root, width=120, height=30)
output_text.pack(padx=10, pady=10)

# Run the Tkinter event loop
root.mainloop()
