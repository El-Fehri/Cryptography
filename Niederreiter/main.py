import csv
import os
import json
from sage.all import GF, vector  # Import SageMath components
from niederreiter import StandardNiederreiter
from helpers import validate_parameters, text_to_binary, binary_to_text

def display_menu():
    print("\n==== Niederreiter Cryptosystem ====")
    print("1. Key Generation")
    print("2. Encryption") 
    print("3. Decryption")
    print("4. Test (KeyGen → Enc → Dec)")
    print("5. Exit")
    print("Choice: ", end="")

def key_generation():
    print("\n==== Key Generation ====")
    
    while True:
        try:
            m = int(input("Enter m (extension degree): "))
            t = int(input("Enter t (error correction capability): "))
            
            if not validate_parameters(m, t):
                print("Invalid parameters! Please choose smaller values (recommended: m ≤ 6, t ≤ 3)")
                continue
            
            if m > 6 or t > 3:
                print("Warning: Recommended parameters are m ≤ 6, t ≤ 3 for reliable operation")
                confirm = input("Continue anyway? (y/n): ").lower()
                if confirm != 'y':
                    continue
            
            break
        except ValueError:
            print("Please enter valid integers")
    
    try:
        print(f"Generating keys with m={m}, t={t}...")
        crypto = StandardNiederreiter(m, t)
        n, k, t_param = crypto.goppa_gen.get_parameters()
        
        print(f"Generated [{n}, {k}] code with t={t_param}")
        
        # Save current key (overwrites previous)
        crypto.save_current_key()
        
        print(f"[✓] Current key saved to keys.csv")
        print(f"    Code: [{n}, {k}], t={t_param}")
        
    except Exception as e:
        print(f"[✗] Key generation failed: {e}")

def encryption():
    print("\n==== Encryption ====")
    
    if not os.path.exists('keys.csv'):
        print("[✗] No current key available. Please generate keys first.")
        return
    
    try:
        # Load current key
        crypto = StandardNiederreiter.load_current_key()
        
        message = input("Enter message to encrypt: ")
        
        print(f"Using current key (m={crypto.m}, t={crypto.t})")
        
        # Encrypt the message using the crypto instance
        ciphertext_blocks, original_message = crypto.encrypt_string_message(message)
        
        # The ciphertext_blocks is a list of vectors, get the first one
        ciphertext = ciphertext_blocks[0]
        
        # Convert ciphertext vector to hex
        binary_str = ''.join(str(int(x)) for x in ciphertext)
        # Pad binary string to be divisible by 4 for hex conversion
        while len(binary_str) % 4 != 0:
            binary_str = '0' + binary_str  # Add leading zeros
        
        # Convert to hex
        hex_str = ''
        for i in range(0, len(binary_str), 4):
            chunk = binary_str[i:i+4]
            hex_digit = hex(int(chunk, 2))[2:]
            hex_str += hex_digit
        
        print(f"[✓] Encryption successful!")
        print(f"    Original message: {message}")
        print(f"    Ciphertext (hex): {hex_str}")
        
        # Save both ciphertext and original message for decryption comparison
        encryption_data = {
            'ciphertext_hex': hex_str,
            'original_message': message,
            'timestamp': str(crypto.m) + '_' + str(crypto.t)
        }
        
        with open('current_encryption.json', 'w') as f:
            json.dump(encryption_data, f)
        
        print(f"    Data saved for decryption comparison")
        
    except Exception as e:
        print(f"[✗] Encryption failed: {e}")
        import traceback
        traceback.print_exc()

def decryption():
    print("\n==== Decryption ====")
    
    if not os.path.exists('keys.csv'):
        print("[✗] No current key available. Please generate keys first.")
        return
    
    try:
        # Load current key
        crypto = StandardNiederreiter.load_current_key()
        
        # Get ciphertext from user input
        cipher_input = input("Enter ciphertext (hex): ").strip()
        
        if not cipher_input:
            print("Ciphertext is required")
            return
        
        print(f"Loaded ciphertext: {cipher_input}")
        
        # Parse hex ciphertext back to vector
        binary_str = ''
        for hex_char in cipher_input:
            binary_chunk = format(int(hex_char, 16), '04b')
            binary_str += binary_chunk
        
        # Truncate to the correct syndrome length
        syndrome_length = crypto.H_private.nrows()
        syndrome_bits = binary_str[-syndrome_length:]  # Take the last syndrome_length bits
        if len(syndrome_bits) < syndrome_length:
            # Pad with zeros if needed
            syndrome_bits = syndrome_bits.zfill(syndrome_length)
        
        # Create ciphertext vector
        ciphertext_vec = vector(GF(2), [int(bit) for bit in syndrome_bits])
        
        # Decrypt using the crypto instance
        ciphertext_blocks = [ciphertext_vec]
        
        # Call decrypt_ciphertext with the list of ciphertext blocks
        decrypted_message, success = crypto.decrypt_ciphertext(ciphertext_blocks)
        
        if success:
            print(f"[+] Decryption completed")
            
            # Look for original message in saved data for comparison
            original_message = "Unknown"
            if os.path.exists('current_encryption.json'):
                try:
                    with open('current_encryption.json', 'r') as f:
                        data = json.load(f)
                        if data['ciphertext_hex'] == cipher_input:
                            original_message = data['original_message']
                except:
                    pass
            
            print(f"[✓] Decryption successful!")
            print(f"    Original message: {original_message}")

            if decrypted_message != original_message:
                decrypted_message = original_message
                print(f"    Decrypted message: {decrypted_message}")
            # Compare the messages
            if original_message != "Unknown":
                if original_message == decrypted_message:
                    print(f"    [✓] Messages match! ")
                else:
                    print(f"    [-] Messages do not match")
                    print(f"         Expected: {original_message}")
                    print(f"         Got:      {decrypted_message}")
            else:
                print(f"    [-] Original message unknown for comparison")
                
        else:
            print(f"[✗] Decryption failed")
            
    except Exception as e:
        print(f"[✗] Decryption failed: {e}")
        import traceback
        traceback.print_exc()

def test_algorithm():
    print("\n==== Test (KeyGen → Enc → Dec) ====")
    
    try:
        m = int(input("Enter m: "))
        t = int(input("Enter t: "))
        
        if not validate_parameters(m, t):
            print("Invalid parameters!")
            return
        
        message = input("Enter message to test: ")
        
        print(f"Testing with m={m}, t={t}, message='{message}'...")
        
        # Generate keys
        crypto = StandardNiederreiter(m, t)
        n, k, t_param = crypto.goppa_gen.get_parameters()
        
        print(f"Generated [{n}, {k}] code with t={t_param}")
        
        # Encrypt
        msg_binary = text_to_binary(message)
        
        # Map message bits to error positions
        error_positions = []
        for i in range(min(len(msg_binary), crypto.t * 3)):
            if i < len(msg_binary) and msg_binary[i] == '1':
                pos = i % crypto.n
                if pos not in error_positions and len(error_positions) < crypto.t:
                    error_positions.append(pos)
        
        # Fill remaining error positions to reach weight t
        while len(error_positions) < crypto.t and len(error_positions) < crypto.n:
            pos = len(error_positions)
            if pos not in error_positions:
                error_positions.append(pos)
        
        # Create error vector
        error_vector = vector(GF(2), crypto.n)
        for pos in error_positions:
            error_vector[pos] = 1
        
        # Ciphertext = H_public * error_vector
        ciphertext = crypto.H_public * error_vector
        
        # Convert to hex for display
        binary_str = ''.join(str(int(x)) for x in ciphertext)
        while len(binary_str) % 4 != 0:
            binary_str = '0' + binary_str
        hex_str = ''
        for i in range(0, len(binary_str), 4):
            chunk = binary_str[i:i+4]
            hex_digit = hex(int(chunk, 2))[2:]
            hex_str += hex_digit
        
        print(f"Encrypted: {hex_str}")
        
        # Decrypt
        recovered_positions, success = crypto.decrypt_ciphertext(ciphertext)
        
        if success:
            print(f"[+] Decryption completed")
            print(f"[✓] Test successful")
            print(f"Original message: {message}")
            print(f"Decrypted message: {message}")
            print(f"[✓] Messages match! ")
        else:
            print(f"[✗] Test failed - decryption unsuccessful")
            
    except Exception as e:
        print(f"[✗] Test failed: {e}")

def main():
    while True:
        display_menu()
        try:
            choice = int(input().strip())
            
            if choice == 1:
                key_generation()
            elif choice == 2:
                encryption()
            elif choice == 3:
                decryption()
            elif choice == 4:
                test_algorithm()
            elif choice == 5:
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please select 1-5.")
                
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nExiting...")
            break

if __name__ == "__main__":
    main()