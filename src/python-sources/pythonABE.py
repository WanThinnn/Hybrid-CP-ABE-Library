import ctypes
from ctypes import c_char_p
import sys
import os

# Đường dẫn đến thư viện .dylib hoặc .so của bạn
lib_path = os.path.join(os.getcwd(), "libhybrid-cp-abe.dll")  # hoặc "libabe.so" trên Linux

# Tải thư viện .dylib/.so
abe_lib = ctypes.CDLL(lib_path)

# Thiết lập nguyên mẫu các hàm
abe_lib.setup.argtypes = [c_char_p]
abe_lib.setup.restype = None

abe_lib.generateSecretKey.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.generateSecretKey.restype = None

abe_lib.AC17encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.AC17encrypt.restype = None

abe_lib.AC17decrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.AC17decrypt.restype = None

# Các hàm Python gọi hàm từ thư viện C++
def call_setup(path_to_save_file):
    abe_lib.setup(path_to_save_file.encode('utf-8'))

def call_generate_secret_key(public_key_file, master_key_file, attributes, private_key_file):
    abe_lib.generateSecretKey(public_key_file.encode('utf-8'), 
                              master_key_file.encode('utf-8'),
                              attributes.encode('utf-8'),
                              private_key_file.encode('utf-8'))

def call_AC17encrypt(public_key_file, plaintext_file, policy, ciphertext_file):
    abe_lib.AC17encrypt(public_key_file.encode('utf-8'),
                           plaintext_file.encode('utf-8'),
                           policy.encode('utf-8'),
                           ciphertext_file.encode('utf-8'))

def call_AC17decrypt(public_key_file, private_key_file, ciphertext_file, recovertext_file):
    abe_lib.AC17decrypt(public_key_file.encode('utf-8'),
                           private_key_file.encode('utf-8'),
                           ciphertext_file.encode('utf-8'),
                           recovertext_file.encode('utf-8'))

# Main function to handle CLI in Python
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [setup|genkey|encrypt|decrypt]")
        sys.exit(1)

    mode = sys.argv[1]

    try:
        if mode == "setup":
            if len(sys.argv) != 3:
                print(f"Usage: python {sys.argv[0]} setup <path_to_save_file>")
                sys.exit(1)
            path = sys.argv[2]
            call_setup(path)
        elif mode == "genkey":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} genkey <public_key_file> <master_key_file> <attributes> <private_key_file>")
                sys.exit(1)
            public_key_file = sys.argv[2]
            master_key_file = sys.argv[3]
            attributes = sys.argv[4]
            private_key_file = sys.argv[5]
        
            call_generate_secret_key(public_key_file, master_key_file, attributes, private_key_file)
        elif mode == "encrypt":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>")
                sys.exit(1)
            public_key_file = sys.argv[2]
            plaintext_file = sys.argv[3]
            policy = sys.argv[4]
            ciphertext_file = sys.argv[5]
            call_AC17encrypt(public_key_file, plaintext_file, policy, ciphertext_file)
        elif mode == "decrypt":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} decrypt <public_key_file> <private_key_file> <ciphertext_file> <recovertext_file>")
                sys.exit(1)
            public_key_file = sys.argv[2]
            private_key_file = sys.argv[3]
            ciphertext_file = sys.argv[4]
            recovertext_file = sys.argv[5]
            call_AC17decrypt(public_key_file, private_key_file, ciphertext_file, recovertext_file)
        else:
            print(f"Invalid command: {mode}")
            print(f"Usage: python {sys.argv[0]} [setup|genkey|encrypt|decrypt]")
    except Exception as ex:
        print(f"Exception: {ex}")