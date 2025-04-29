Task- File encryption and decryption.
Subject- Secure Software Development

Objective: The main aim of this assignment is to design and implement a secure file
encryption and decryption utility using password based encryption and PBKD2 key
derivation, supporting AES128, AES256, 3DES algorithms in CBC Mode, along with Hmac
for integrity verification and metadata for secure decryption.
Step 1: Environment Setup (MacOs – vscode + python)
1. Install VS Code and python extension
2. Create a Project file (File_Encryption_Assignment)
3. Setup Virtual Environment (python3 -m venv venv), which keeps project files isolated
4. In project folder create a two file (encryptor.py, and somefile.txt)
5. Install cryptography library using terminal (pip install cryptography)
STEP 2: Key Derivation using PBKD2
Objective: To securely derive an encryption key from user supplied password using the
PBKD2 method, supporting both the SHA256 and SHA512 as underlying hash algorithms.
Code explanation:
imports:
PBKD2HMAC: Used to perform the key derivation using PBKD2
Hashes: gives us access to SHA256 and SHA512
default_backend: Required by PBKD2
OS: used to generate random salt
base64: converts the binary key into a readable format
Derive Key function:
Function to create a key from password.
Takes user’s input like password , hash algorithm, and number of iterations
salt: os.urandom(16)
generates a random 16-bit salt to ensure key requirements
create a pbkdf2 : uses a PBKDF2 to create a strong 256 bit key from the password
main function:
Takes user input for password and hash algorithm
asks users to enter the iteration count, If the user enter invalid input it uses a default
It also measures how long the key derivation takes place
Calculates how many iterations per second the machine can be handle.
Output: for sha256
input: VinayUpperla@2025
number of iterations: 100,000
hash algorithm: sha256
output: for sha512
input: VinayUpperla@2025
number of iterations: 100,000
hash algorithm: sha512
Subkey Derivation for encryption and HMAC:
objective: To derive two cryptographically independent subkeys which are, one for
encryption and one for HMAC from a previously generated master key , using PBKDF2
Implementation details:
Input: Master key (32 bytes derived from PBKD2)
Kdf used: PBKDF2 -HMAC
Salt: Fixed content specific strings
“encryption” for encryption key
“hmac” for HMAC key
iterations: 1
output:
result: Two 256-bit(32 byte) keys.
This approach avoids key reuse between encryption and authentication operations, which
is critical.
STEP 3: File Encryption using CBC Mode
objective: To securely encrpt the contents of a file using CBC mode with the option of user
selected algorithm like AES 128, AES 256 or 3DES. Also a random IV is generated to ensure
ciphertext uniqueness
code explanation:
when the encrypt_file() function is called.
1. The input file is read in binary mode, and the plaintext is loaded into memory
2. Based on the user’s choice the appropriate cipher is selected, and a matching key size
and block size are set.
3. A random IV is generated to make the encryption unique and secure
4. PKSC7 Padding is applied to the plaintext so that its size become a perfect multiple of
the block size
5. A cipher object is created using selected algorithm
6. The padded plaintext is encrypted using CBC Mode , and the resulting cipher text is
written into a new output file into.
output:
STEP 4: Saving the data as metadata
Objective: To securely store the encryption details by saving them into metadata file after
the encryption process.
After encrypting the file HMAC
1. 2. 4. 5. 6. Algorithm: The encryption algo used (AES128, AES256, 3DES)
Salt: PBKD2 key dervivation (hex encoded)
3. IV: initialization vector
Hash_algorithm: hash algo used for PBKD2 (sha256 or sha512)
Iterations: no.of PBKD2 iterations used
Hmac: The generated HMAC value over IV and ciphertext
Output:
The encryption process completed successfully. All the necessary data (algorithm, salt, IV
and HMAC ) was saved into a Json file(somefile.meta.json) for future decryption.
STEP6: Loading Metadata
Objective: load the encryption metadata saved during the encryption process. The
metadata contains all the necessary info required for verifying data integrity.
Code explanation: After saving the metadata in json file
1. A function load_metadata was created
2. It performs:
Opens the metadata file
Reads and parses all saved fields
decodes the hex encoded fields
return these decoded values for later use.
Output:
The program successfully loaded all fields from the metadata file.
STEP 7: Verifying HMAC
hmac verification was successfully implemented to ensure data integrity. Only when
the computed HMAC matched the store HMAC was decryption allowed, protecting
against tampering or corrupted data.
STEP 8: Decrypt File
Objective: Decrypt the encrypted file back to its original plain text form, using the
encryption key and IV only after verifying the integrity of the ciphertext using HMAC
verification.
The decrypt_file() function reads the encrypted ciphertext and IV, reconstructs the
original cipher using the encryption key and algorithm, decrypt the data and removes
the padding and saves the recovered plain text into a txt file.
Output:
After successful hmac verification, the encrypted file was decrypted correctly and the
original plaintext was recovered without any errors. The decrypted content was saved
into a new txt file. Completing the decryption process successfully and validating the
integrity of the data.
