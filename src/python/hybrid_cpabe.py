import ctypes
from ctypes import c_char_p
import sys
import os

# Đường dẫn đến thư viện .dll (same directory as this script)
script_dir = os.path.dirname(os.path.abspath(__file__))
lib_path = os.path.join(script_dir, "hybrid-cp-abe.dll")

if not os.path.exists(lib_path):
    print(f"Error: DLL not found at {lib_path}")
    print(f"   Make sure hybrid-cp-abe.dll is in the same directory as this script.")
    sys.exit(1)

# Tải thư viện .dylib/.so
abe_lib = ctypes.CDLL(lib_path)

# Thiết lập nguyên mẫu các hàm
abe_lib.setup.argtypes = [c_char_p]
abe_lib.setup.restype = ctypes.c_int

abe_lib.generateSecretKey.argtypes = [c_char_p, c_char_p, c_char_p]
abe_lib.generateSecretKey.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_encrypt.restype = ctypes.c_int

abe_lib.hybrid_cpabe_decrypt.argtypes = [c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_decrypt.restype = ctypes.c_int

abe_lib.getVersion.argtypes = []
abe_lib.getVersion.restype = c_char_p

abe_lib.getErrorMessage.argtypes = [ctypes.c_int]
abe_lib.getErrorMessage.restype = c_char_p

# Error codes
HCPABE_SUCCESS = 0
HCPABE_ERR_FILE_NOT_FOUND = -1
HCPABE_ERR_INVALID_KEY = -2
HCPABE_ERR_POLICY_MISMATCH = -3
HCPABE_ERR_CRYPTO_FAILED = -4

# Các hàm Python gọi hàm từ thư viện C++
def call_setup(path_to_save_file):
    result = abe_lib.setup(path_to_save_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Setup completed successfully!")
        print(f"   Files created in: {path_to_save_file}/")
        print(f"   - cpabe_msk.key (Master Secret Key)")
        print(f"   - cpabe_pk.key  (Public Parameters)")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_generate_secret_key(master_key_file, attributes, private_key_file):
    result = abe_lib.generateSecretKey(master_key_file.encode('utf-8'),
                                        attributes.encode('utf-8'),
                                        private_key_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Secret key generated successfully!")
        print(f"   Attributes: {attributes}")
        print(f"   Output: {private_key_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Key generation failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt(public_key_file, plaintext_file, policy, ciphertext_file):
    result = abe_lib.hybrid_cpabe_encrypt(public_key_file.encode('utf-8'),
                                   plaintext_file.encode('utf-8'),
                                   policy.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Encryption successful!")
        print(f"   Policy: {policy}")
        print(f"   Output: {ciphertext_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_decrypt(private_key_file, ciphertext_file, recovertext_file):
    result = abe_lib.hybrid_cpabe_decrypt(private_key_file.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'),
                                   recovertext_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Decryption successful!")
        print(f"   Output: {recovertext_file}")
    elif result == HCPABE_ERR_POLICY_MISMATCH:
        print(f"Decryption failed: Attributes do not satisfy policy")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Decryption failed: {error_msg} (code: {result})")
    return result

# Main function to handle CLI in Python
if __name__ == "__main__":
    # Print version info
    version = abe_lib.getVersion().decode('utf-8')
    print(f"Hybrid CP-ABE Library v{version} (Python Wrapper)")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [setup|genkey|encrypt|decrypt]")
        print()
        print("Commands:")
        print("  setup   <path>                          - Generate master & public keys")
        print("  genkey  <msk> <attrs> <out>             - Generate secret key")
        print("  encrypt <pk> <file> <policy> <out>      - Encrypt file")
        print("  decrypt <sk> <file> <out>               - Decrypt file")
        print()
        print("Examples:")
        print(f"  python {sys.argv[0]} setup ./keys")
        print(f"  python {sys.argv[0]} genkey ./keys/cpabe_msk.key \"admin it\" ./keys/user.key")
        print(f"  python {sys.argv[0]} encrypt ./keys/cpabe_pk.key data.txt \"(admin and it)\" data.enc")
        print(f"  python {sys.argv[0]} decrypt ./keys/user.key data.enc data.dec")
        sys.exit(1)

    mode = sys.argv[1]

    try:
        if mode == "setup":
            if len(sys.argv) != 3:
                print(f"Usage: python {sys.argv[0]} setup <path_to_save_keys>")
                sys.exit(1)
            path = sys.argv[2]
            result = call_setup(path)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "genkey":
            if len(sys.argv) != 5:
                print(f"Usage: python {sys.argv[0]} genkey <master_key_file> <attributes> <private_key_file>")
                print(f"Example: python {sys.argv[0]} genkey ./keys/cpabe_msk.key \"admin it security\" ./keys/alice.key")
                sys.exit(1)
            master_key_file = sys.argv[2]
            attributes = sys.argv[3]
            private_key_file = sys.argv[4]
            result = call_generate_secret_key(master_key_file, attributes, private_key_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "encrypt":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>")
                print(f"Example: python {sys.argv[0]} encrypt ./keys/cpabe_pk.key data.txt \"(admin and it)\" data.enc")
                sys.exit(1)
            public_key_file = sys.argv[2]
            plaintext_file = sys.argv[3]
            policy = sys.argv[4]
            ciphertext_file = sys.argv[5]
            result = call_hybrid_cpabe_encrypt(public_key_file, plaintext_file, policy, ciphertext_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "decrypt":
            if len(sys.argv) != 5:
                print(f"Usage: python {sys.argv[0]} decrypt <private_key_file> <ciphertext_file> <recovertext_file>")
                print(f"Example: python {sys.argv[0]} decrypt ./keys/alice.key data.enc data.dec")
                sys.exit(1)
            private_key_file = sys.argv[2]
            ciphertext_file = sys.argv[3]
            recovertext_file = sys.argv[4]
            result = call_hybrid_cpabe_decrypt(private_key_file, ciphertext_file, recovertext_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        else:
            print(f"Invalid command: {mode}")
            print(f"Valid commands: setup, genkey, encrypt, decrypt")
            sys.exit(1)
            
    except Exception as ex:
        print(f"Exception: {ex}")
        sys.exit(1)