#  Import Libraries 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import time
import json

#  Derive Master Key from Password 
def derive_key(password: str, hash_algo: str = "sha256", iterations: int = 100000) -> tuple:
    # Generate random 16-byte salt
    salt = os.urandom(16)

    # Choose hashing algorithm based on user input
    if hash_algo == "sha256":
        algorithm = hashes.SHA256()
    elif hash_algo == "sha512":
        algorithm = hashes.SHA512()
    else:
        raise ValueError("Unsupported hash algorithm")

    # Create PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=32,  # 256-bit key output
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(password.encode())  # Derive the master key
    return base64.urlsafe_b64encode(key), salt  # Return key in base64 and salt

#  Derive Encryption and HMAC Subkeys 
def derive_subkeys(master_key: bytes) -> tuple:
    # Use fixed salts for subkey derivation
    salt_enc = b"encryption"
    salt_hmac = b"hmac"

    # Derive encryption key
    kdf_enc = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_enc,
        iterations=1,
        backend=default_backend()
    )
    encryption_key = kdf_enc.derive(master_key)

    # Derive HMAC key
    kdf_hmac = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_hmac,
        iterations=1,
        backend=default_backend()
    )
    hmac_key = kdf_hmac.derive(master_key)

    return encryption_key, hmac_key

#  Encrypt the File Using CBC Mode 
def encrypt_file(input_file_path, output_file_path, encryption_key, algorithm_name):
    # Read plaintext from file
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

    # Select encryption algorithm and set block size
    if algorithm_name == "AES128":
        key = encryption_key[:16]
        algo = algorithms.AES(key)
        block_size = 16
    elif algorithm_name == "AES256":
        key = encryption_key[:32]
        algo = algorithms.AES(key)
        block_size = 16
    elif algorithm_name == "3DES":
        key = encryption_key[:24]
        algo = algorithms.TripleDES(key)
        block_size = 8
    else:
        raise ValueError("Unsupported algorithm. Choose AES128, AES256, or 3DES.")

    # Generate random IV
    iv = os.urandom(block_size)

    # Pad plaintext using PKCS7 padding
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded data
    cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save ciphertext to output file
    with open(output_file_path, 'wb') as f:
        f.write(ciphertext)

    return iv, ciphertext

# Create HMAC over IV and Ciphertext 
def create_hmac(hmac_key, iv, ciphertext):
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)  # HMAC over IV + ciphertext
    return h.finalize()

# Save Metadata to JSON 
def save_metadata(output_file_path, iv, ciphertext, hmac_value, salt, algorithm_name):
    # Create metadata dictionary
    metadata = {
        "algorithm": algorithm_name,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac": hmac_value.hex()
    }

    # Save metadata as a JSON file
    metadata_file_path = output_file_path + ".meta.json"
    with open(metadata_file_path, 'w') as f:
        json.dump(metadata, f, indent=4)

    print(f"\n Metadata saved successfully in {metadata_file_path}!")

# ------------------ Load Metadata from JSON ------------------
def load_metadata(metadata_file_path):   
    with open(metadata_file_path, 'r') as f:
        metadata = json.load(f)

    # Extract and decode values
    algorithm_name = metadata["algorithm"] # algorithm name
    salt = bytes.fromhex(metadata["salt"]) #salt
    iv = bytes.fromhex(metadata["iv"]) #IV 
    ciphertext = bytes.fromhex(metadata["ciphertext"]) #convert ciphertext
    hmac_value = bytes.fromhex(metadata["hmac"]) #convert hmac value
    return algorithm_name, salt, iv, ciphertext, hmac_value #return values

#                    Verify HMAC
def verify_hmac(hmac_key, iv, ciphertext, expected_hmac):
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    try:
        h.verify(expected_hmac)
        print("\n HMAC verification successful! Data is intact.")
        return True
    except Exception:
        print("\n HMAC verification failed! Data may be tampered.")
        return False

#  Decrypt the Encrypted File 
def decrypt_file(output_file_path, encryption_key, iv, ciphertext, algorithm_name):
    # Select cipher algorithm
    if algorithm_name == "AES128":
        key = encryption_key[:16]
        algo = algorithms.AES(key)
        block_size = 16
    elif algorithm_name == "AES256":
        key = encryption_key[:32]
        algo = algorithms.AES(key)
        block_size = 16
    elif algorithm_name == "3DES":
        key = encryption_key[:24]
        algo = algorithms.TripleDES(key)
        block_size = 8
    else:
        raise ValueError("Unsupported algorithm. Choose AES128, AES256, or 3DES.")

    # Create decryptor
    cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save decrypted data to a new file
    decrypted_file_path = output_file_path.replace(".enc", ".dec.txt")
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    print(f"\n File decrypted successfully!")
    print(f"Decrypted file saved as: {decrypted_file_path}")


#                       Main Program Starts Here 
if __name__ == "__main__":
    # User inputs
    password = input("Enter your password: ")
    hash_algo = input("Choose hash algorithm (sha256 or sha512): ").strip().lower()
    try:
        iterations = int(input("Enter number of iterations (e.g., 100000): "))
    except ValueError:
        print("Invalid input. Using 100000 iterations.")
        iterations = 100000

    # Derive master key
    start = time.time()
    key_b64, salt = derive_key(password, hash_algo=hash_algo, iterations=iterations)
    end = time.time()

    # Performance measurement
    elapsed = end - start
    per_second = int(iterations / elapsed)

    print("\n Key Derivation Complete")
    print(f"Salt (hex): {salt.hex()}")
    print(f"Master Key (Base64): {key_b64.decode()}")
    print(f"\n Benchmark: {iterations} iterations took {elapsed:.4f} seconds")
    print(f" Approx. {per_second:,} iterations/second")
    print(f"Total time: {elapsed:.4f} seconds")

    # Derive encryption and HMAC keys from master key
    master_key_bytes = base64.urlsafe_b64decode(key_b64)
    encryption_key, hmac_key = derive_subkeys(master_key_bytes)

    # Print derived subkeys
    print("\n Subkeys Derived from Master Key:")
    print(f"Encryption Key (hex): {encryption_key.hex()}")
    print(f"HMAC Key (hex): {hmac_key.hex()}")

    # Encrypt file
    algorithm_name = input("\nEnter encryption algorithm (AES128, AES256, or 3DES): ").strip().upper()
    input_file_path = "somefile.txt"
    output_file_path = "somefile.enc"

    iv, ciphertext = encrypt_file(input_file_path, output_file_path, encryption_key, algorithm_name)

    print(f"\n File encrypted successfully using {algorithm_name}!")
    print(f"IV (hex): {iv.hex()}")
    print(f"Encrypted file saved as: {output_file_path}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Create HMAC
    hmac_value = create_hmac(hmac_key, iv, ciphertext)
    print(f"\n HMAC generated successfully!")
    print(f"HMAC (hex): {hmac_value.hex()}")

    # Save metadata
    save_metadata(output_file_path, iv, ciphertext, hmac_value, salt, algorithm_name)

    # Load metadata (for verification)
    print("\n🔍 Loading metadata back for verification...")
    loaded_algorithm, loaded_salt, loaded_iv, loaded_ciphertext, loaded_hmac_value = load_metadata(output_file_path + ".meta.json")

    # Print loaded metadata
    print(f"Algorithm loaded: {loaded_algorithm}")
    print(f"Salt loaded (hex): {loaded_salt.hex()}")
    print(f"IV loaded (hex): {loaded_iv.hex()}")
    print(f"Ciphertext loaded length: {len(loaded_ciphertext)} bytes")
    print(f"HMAC loaded (hex): {loaded_hmac_value.hex()}")
    print("\n Metadata loaded successfully!")

# Verify HMAC
    print("\n Verifying HMAC...")
    if verify_hmac(hmac_key, loaded_iv, loaded_ciphertext, loaded_hmac_value):
        print("HMAC verification successful!")
    else:
        print("HMAC verification failed!")
    print("\n program successfully completed!")

    # Decrypt the file
    if verify_hmac(hmac_key, loaded_iv, loaded_ciphertext, loaded_hmac_value):
        print("\n Decrypting the file...")
        decrypt_file(output_file_path, encryption_key, loaded_iv, loaded_ciphertext, loaded_algorithm)
    else:
        print("\n HMAC verification failed. Cannot decrypt the file.")
    print("\n Decryption process completed!")
    print("\n Program completed successfully!")
    print("\n Thank you for using the encryption program!")
    print("\n Exiting the program.")
    print("\n Goodbye!")
    print("\n" + "="*50)
    print("\n" + "="*50)