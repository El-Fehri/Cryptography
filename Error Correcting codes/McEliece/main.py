from mceliece import McEliece
from helpers import Helpers
from sage.all import vector, GF
import math


def main():
    print("\n===== McEliece Cryptosystem =====\n")
    
    mc_instance = None
    current_params = None
    last_ciphertext = None
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("1. Generate new keys")
        print("2. Encrypt a message")
        print("3. Decrypt ciphertext")
        print("4. Test encryption/decryption cycle")
        print("5. Exit")
        
        choice = input("\nChoose option (1-5): ").strip()
        
        if choice == "5":
            print("Goodbye!")
            break
        
        elif choice == "1":
            print("\n" + "="*60)
            print("KEY GENERATION")
            m = int(input("Enter m (field size GF(2^m), recommend 4-8): "))
            t = int(input("Enter t (error correction capability, recommend 1-10): "))
            
            mc_instance = McEliece(m, t)
            pk, sk = mc_instance.keyGen(None)
            
            k = sk['k']
            n = sk['n']
            
            print(f"\n✓ Keys generated successfully!")
            print(f"  Parameters: n={n}, k={k}, t={t}")
            print(f"  Max message bits per block: {k}")
            print(f"  Max characters per block: {k//8}")
            
            current_params = {'m': m, 't': t, 'n': n, 'k': k}
            
        elif choice == "2":
            if mc_instance is None:
                print("\n✗ Please generate keys first (option 1)")
                continue
            
            print("\n" + "="*60)
            print("ENCRYPTION")
            print(f"Current parameters: n={current_params['n']}, k={current_params['k']}, t={current_params['t']}")
            
            message = input("\nEnter message to encrypt: ")
            print(f"\nMessage: '{message}'")
            print(f"Length: {len(message)} characters = {len(message)*8} bits")
            
            m_bin = Helpers.string_to_binary(message)
            print(f"Binary: {m_bin[:64]}..." if len(m_bin) > 64 else f"Binary: {m_bin}")
            
            k = current_params['k']
            n = current_params['n']
            t = current_params['t']
            
            # Split into blocks
            blocks = []
            for i in range(0, len(m_bin), k):
                block = m_bin[i:i+k]
                if len(block) < k:
                    # Pad with zeros ONLY for the last block
                    block = block + '0' * (k - len(block))
                blocks.append(block)
            
            print(f"\nSplit into {len(blocks)} block(s) of {k} bits each")
            
            # Encrypt each block
            ciphertexts_hex = []
            
            for i, block in enumerate(blocks):
                print(f"\n--- Block {i+1}/{len(blocks)} ---")
                print(f"Message bits: {block}")
                
                m_vec = vector(GF(2), [int(b) for b in block])
                cipher = mc_instance.encrypt(m_vec)
                
                cipher_hex = Helpers.vector_to_hex(cipher)
                cipher_bin = ''.join(str(int(b)) for b in cipher.list())
                
                ciphertexts_hex.append(cipher_hex)
                
                print(f"Ciphertext weight: {sum(cipher)} (should be ~{t})")
                print(f"Ciphertext length: {len(cipher_bin)} bits (should be {n})")
                print(f"Ciphertext (hex, {len(cipher_hex)} chars): {cipher_hex}")
                print(f"Ciphertext (bin): {cipher_bin}")
            
            # Combine all ciphertexts
            full_cipher_hex = ''.join(ciphertexts_hex)
            full_cipher_bin = ''.join([Helpers.hex_to_binary(h) for h in ciphertexts_hex])
            
            print(f"\n" + "="*60)
            print("ENCRYPTION COMPLETE")
            print(f"Total message bits: {len(m_bin)}")
            print(f"Total ciphertext bits: {len(full_cipher_bin)}")
            print(f"Total ciphertext hex chars: {len(full_cipher_hex)}")
            print(f"\nFull ciphertext (hex): {full_cipher_hex}")
            
            # Calculate hex digits per block for decryption
            hex_per_block = math.ceil(n / 4)  # Correct calculation
            print(f"\nNote: Each ciphertext block is {n} bits = {hex_per_block} hex digits")
            print(f"Hex blocks: {' '.join(ciphertexts_hex)}")
            
            # Save for later use
            last_ciphertext = full_cipher_hex
        
        elif choice == "3":
            if mc_instance is None:
                print("\n✗ Please generate keys first (option 1)")
                continue
            
            print("\n" + "="*60)
            print("DECRYPTION")
            print(f"Current parameters: n={current_params['n']}, k={current_params['k']}, t={current_params['t']}")
            
            print("\nPaste ciphertext or:")
            print("1. Use last generated ciphertext")
            print("2. Enter new ciphertext")
            
            subchoice = input("Choose (1/2): ").strip()
            
            if subchoice == "1" and last_ciphertext is not None:
                hex_input = last_ciphertext
                print(f"\nUsing last ciphertext: {hex_input}")
            else:
                hex_input = input("\nEnter ciphertext (hex): ").strip()
            
            n = current_params['n']
            k = current_params['k']
            
            # Calculate hex digits per block CORRECTLY
            hex_per_block = math.ceil(n / 4)
            print(f"\nEach block is {n} bits = {hex_per_block} hex digits")
            print(f"Total hex input length: {len(hex_input)} characters")
            
            # Check if length is divisible by hex_per_block
            if len(hex_input) % hex_per_block != 0:
                print(f"Warning: Hex length {len(hex_input)} not divisible by {hex_per_block}")
                print(f"Missing {hex_per_block - (len(hex_input) % hex_per_block)} hex digits")
                # Pad with zeros if needed
                hex_input = hex_input + '0' * (hex_per_block - (len(hex_input) % hex_per_block))
            
            # Split into blocks
            hex_blocks = []
            for i in range(0, len(hex_input), hex_per_block):
                block = hex_input[i:i+hex_per_block]
                hex_blocks.append(block)
            
            print(f"Found {len(hex_blocks)} ciphertext block(s)")
            print(f"Hex blocks: {' '.join(hex_blocks)}")
            
            # Decrypt each block
            decrypted_bits = ""
            successes = 0
            
            for i, hex_block in enumerate(hex_blocks):
                print(f"\n--- Decrypting Block {i+1}/{len(hex_blocks)} ---")
                print(f"Block hex: {hex_block} ({len(hex_block)} chars)")
                
                # Convert hex to binary first
                bin_str = Helpers.hex_to_binary(hex_block)
                print(f"Block binary ({len(bin_str)} bits): {bin_str}")
                
                # Convert to vector
                cipher = vector(GF(2), [int(b) for b in bin_str])
                
                if len(cipher) != n:
                    print(f"Warning: Block {i+1} has {len(cipher)} bits, expected {n}")
                    if len(cipher) < n:
                        cipher = vector(GF(2), list(cipher) + [0] * (n - len(cipher)))
                    else:
                        cipher = cipher[:n]
                
                decrypted = mc_instance.decrypt(cipher)
                
                if decrypted is not None:
                    block_bits = ''.join(str(int(b)) for b in decrypted.list())
                    decrypted_bits += block_bits[:k]  # Take only k bits
                    successes += 1
                    print(f"✓ Block {i+1} decrypted successfully")
                    print(f"  Decrypted bits: {block_bits}")
                    print(f"  Taking first {k} bits: {block_bits[:k]}")
                else:
                    print(f"✗ Block {i+1} decryption failed!")
                    decrypted_bits += '0' * k
            
            # Convert to string
            decrypted_str = Helpers.binary_to_string(decrypted_bits)
            
            # Remove trailing null characters
            decrypted_str = decrypted_str.rstrip('\x00')
            
            print(f"\n" + "="*60)
            print("DECRYPTION COMPLETE")
            print(f"Successfully decrypted: {successes}/{len(hex_blocks)} blocks")
            print(f"Decrypted binary length: {len(decrypted_bits)} bits")
            print(f"\nDecrypted message: '{decrypted_str}'")
            print(f"Message length: {len(decrypted_str)} characters")
            
            # Show the actual decrypted binary
            print(f"\nDecrypted binary: {decrypted_bits}")
            
            # Also show original message binary for comparison
            if last_ciphertext and hex_input == last_ciphertext:
                # We can show what was originally encrypted
                print(f"\nFor comparison, original message binary was:")
                original_bin = Helpers.string_to_binary(input("Enter original message to compare: "))
                print(f"Original: {original_bin}")
                print(f"Decrypted: {decrypted_bits[:len(original_bin)]}")
                if decrypted_bits[:len(original_bin)] == original_bin:
                    print("✓ Binary matches perfectly!")
        
        elif choice == "4":
            if mc_instance is None:
                print("\n✗ Please generate keys first (option 1)")
                continue
            
            print("\n" + "="*60)
            print("TEST ENCRYPTION/DECRYPTION CYCLE")
            
            # Simple test
            test_msg = "Hi"
            print(f"\nTesting with message: '{test_msg}'")
            
            k = current_params['k']
            n = current_params['n']
            t = current_params['t']
            
            # Convert to binary
            m_bin = Helpers.string_to_binary(test_msg)
            print(f"Original binary: {m_bin}")
            
            # Pad to multiple of k
            if len(m_bin) % k != 0:
                padded_len = ((len(m_bin) + k - 1) // k) * k
                m_bin_padded = m_bin + '0' * (padded_len - len(m_bin))
            else:
                m_bin_padded = m_bin
            
            blocks = len(m_bin_padded) // k
            print(f"Blocks needed: {blocks}")
            
            # Encrypt
            print("\n--- ENCRYPTION ---")
            cipher_hex_blocks = []
            
            for i in range(blocks):
                block_start = i * k
                block_end = (i + 1) * k
                block_bits = m_bin_padded[block_start:block_end]
                
                print(f"\nBlock {i+1}: {block_bits}")
                m_vec = vector(GF(2), [int(b) for b in block_bits])
                cipher = mc_instance.encrypt(m_vec)
                cipher_hex = Helpers.vector_to_hex(cipher)
                cipher_hex_blocks.append(cipher_hex)
                print(f"Ciphertext {i+1}: {cipher_hex}")
                print(f"  Weight: {sum(cipher)} (expected: {t})")
            
            full_cipher = ''.join(cipher_hex_blocks)
            print(f"\nFull ciphertext: {full_cipher}")
            
            # Decrypt
            print("\n--- DECRYPTION ---")
            hex_per_block = math.ceil(n / 4)
            
            decrypted_bits = ""
            for i, hex_block in enumerate(cipher_hex_blocks):
                print(f"\nDecrypting block {i+1}...")
                cipher = Helpers.hex_to_vector(hex_block, n)
                decrypted = mc_instance.decrypt(cipher)
                
                if decrypted is not None:
                    block_bits = ''.join(str(int(b)) for b in decrypted.list())
                    decrypted_bits += block_bits[:k]
                    print(f"  Success: {block_bits[:k]}")
                else:
                    print(f"  Failed!")
                    decrypted_bits += '0' * k
            
            # Compare
            print(f"\n--- RESULTS ---")
            print(f"Original:  {m_bin_padded}")
            print(f"Decrypted: {decrypted_bits}")
            
            if m_bin_padded == decrypted_bits:
                print("\n✓ PERFECT MATCH!")
            else:
                print("\n✗ MISMATCH!")
                # Find where they differ
                for j in range(min(len(m_bin_padded), len(decrypted_bits))):
                    if m_bin_padded[j] != decrypted_bits[j]:
                        print(f"First difference at position {j}: '{m_bin_padded[j]}' vs '{decrypted_bits[j]}'")
                        break


if __name__ == "__main__":
    main()