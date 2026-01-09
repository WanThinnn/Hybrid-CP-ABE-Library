#!/usr/bin/env python3
"""
Test script for Hybrid CP-ABE DLL
Tests all core functions: setup, genkey, encrypt, decrypt
"""

import os
import sys
import ctypes
from ctypes import c_char_p, c_int, c_size_t, POINTER, c_ubyte
from pathlib import Path

# ============================================================================
# Load DLL
# ============================================================================
dll_path = Path(__file__).parent / "lib" / "dynamic-lib" / "libhybrid-cp-abe.dll"

if not dll_path.exists():
    print(f"❌ Error: DLL not found at {dll_path}")
    sys.exit(1)

try:
    lib = ctypes.CDLL(str(dll_path))
    print(f"✅ DLL loaded: {dll_path}")
except Exception as e:
    print(f"❌ Failed to load DLL: {e}")
    sys.exit(1)

# ============================================================================
# Define function signatures
# ============================================================================

# const char* getVersion(void)
lib.getVersion.restype = c_char_p
lib.getVersion.argtypes = []

# const char* getErrorMessage(int errorCode)
lib.getErrorMessage.restype = c_char_p
lib.getErrorMessage.argtypes = [c_int]

# int setup(const char *path)
lib.setup.restype = c_int
lib.setup.argtypes = [c_char_p]

# int generateSecretKey(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
lib.generateSecretKey.restype = c_int
lib.generateSecretKey.argtypes = [c_char_p, c_char_p, c_char_p]

# int AC17encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
lib.AC17encrypt.restype = c_int
lib.AC17encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

# int AC17decrypt(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
lib.AC17decrypt.restype = c_int
lib.AC17decrypt.argtypes = [c_char_p, c_char_p, c_char_p]

# void freeBuffer(unsigned char *buffer)
lib.freeBuffer.restype = None
lib.freeBuffer.argtypes = [POINTER(c_ubyte)]

# ============================================================================
# Error Codes
# ============================================================================
HCPABE_SUCCESS = 0
HCPABE_ERR_FILE_NOT_FOUND = -1
HCPABE_ERR_INVALID_KEY = -2
HCPABE_ERR_POLICY_MISMATCH = -3
HCPABE_ERR_CRYPTO_FAILED = -4

# ============================================================================
# Helper Functions
# ============================================================================

def get_version():
    """Get library version"""
    version = lib.getVersion()
    return version.decode('utf-8') if version else "Unknown"

def get_error_message(error_code):
    """Get error message from error code"""
    msg = lib.getErrorMessage(error_code)
    return msg.decode('utf-8') if msg else "Unknown error"

def check_result(result, operation):
    """Check operation result and print status"""
    if result == HCPABE_SUCCESS:
        print(f"  ✅ {operation}: SUCCESS")
        return True
    else:
        error_msg = get_error_message(result)
        print(f"  ❌ {operation}: FAILED - {error_msg} (code: {result})")
        return False

# ============================================================================
# Test Functions
# ============================================================================

def test_version():
    """Test getVersion function"""
    print("\n📌 Test 1: Get Version")
    version = get_version()
    print(f"  Library version: {version}")
    return True

def test_setup(test_dir):
    """Test setup function"""
    print("\n📌 Test 2: Setup (Generate Master Key & Public Key)")
    
    keys_dir = test_dir / "keys"
    keys_dir.mkdir(exist_ok=True)
    
    result = lib.setup(str(keys_dir).encode('utf-8'))
    success = check_result(result, "Setup")
    
    if success:
        msk_path = keys_dir / "cpabe_msk.key"
        pk_path = keys_dir / "cpabe_pk.key"
        
        if msk_path.exists() and pk_path.exists():
            print(f"  📁 Master key: {msk_path}")
            print(f"  📁 Public key: {pk_path}")
        else:
            print(f"  ⚠️  Warning: Key files not found")
            success = False
    
    return success

def test_generate_secret_key(test_dir):
    """Test generateSecretKey function"""
    print("\n📌 Test 3: Generate Secret Key")
    
    keys_dir = test_dir / "keys"
    msk_file = keys_dir / "cpabe_msk.key"
    sk_file = keys_dir / "alice.key"
    
    attributes = "admin it security"
    
    result = lib.generateSecretKey(
        str(msk_file).encode('utf-8'),
        attributes.encode('utf-8'),
        str(sk_file).encode('utf-8')
    )
    success = check_result(result, "Generate Secret Key")
    
    if success and sk_file.exists():
        print(f"  📁 Secret key: {sk_file}")
        print(f"  🔑 Attributes: {attributes}")
    
    return success

def test_encrypt(test_dir):
    """Test AC17encrypt function"""
    print("\n📌 Test 4: Encrypt File")
    
    keys_dir = test_dir / "keys"
    pk_file = keys_dir / "cpabe_pk.key"
    
    # Create test plaintext file
    plaintext_file = test_dir / "plaintext.txt"
    plaintext_content = "Hello, this is a secret message for testing Hybrid CP-ABE!\n这是一个测试消息 🔐"
    plaintext_file.write_text(plaintext_content, encoding='utf-8')
    
    ciphertext_file = test_dir / "ciphertext.enc"
    
    # Policy: (admin AND it) OR security
    policy = '("admin" and "it") or "security"'
    
    result = lib.AC17encrypt(
        str(pk_file).encode('utf-8'),
        str(plaintext_file).encode('utf-8'),
        policy.encode('utf-8'),
        str(ciphertext_file).encode('utf-8')
    )
    success = check_result(result, "Encrypt")
    
    if success and ciphertext_file.exists():
        print(f"  📁 Plaintext: {plaintext_file} ({plaintext_file.stat().st_size} bytes)")
        print(f"  📁 Ciphertext: {ciphertext_file} ({ciphertext_file.stat().st_size} bytes)")
        print(f"  🔒 Policy: {policy}")
    
    return success

def test_decrypt(test_dir):
    """Test AC17decrypt function"""
    print("\n📌 Test 5: Decrypt File")
    
    keys_dir = test_dir / "keys"
    sk_file = keys_dir / "alice.key"
    ciphertext_file = test_dir / "ciphertext.enc"
    recovered_file = test_dir / "recovered.txt"
    
    result = lib.AC17decrypt(
        str(sk_file).encode('utf-8'),
        str(ciphertext_file).encode('utf-8'),
        str(recovered_file).encode('utf-8')
    )
    success = check_result(result, "Decrypt")
    
    if success and recovered_file.exists():
        print(f"  📁 Recovered: {recovered_file}")
        
        # Verify content matches
        original = (test_dir / "plaintext.txt").read_text(encoding='utf-8')
        recovered = recovered_file.read_text(encoding='utf-8')
        
        if original == recovered:
            print(f"  ✅ Content verification: PASSED")
            print(f"  📝 Content: {recovered[:50]}...")
        else:
            print(f"  ❌ Content verification: FAILED")
            success = False
    
    return success

def test_decrypt_wrong_key(test_dir):
    """Test decrypt with wrong attributes (should fail)"""
    print("\n📌 Test 6: Decrypt with Wrong Key (Should Fail)")
    
    keys_dir = test_dir / "keys"
    msk_file = keys_dir / "cpabe_msk.key"
    wrong_sk_file = keys_dir / "bob.key"
    ciphertext_file = test_dir / "ciphertext.enc"
    recovered_file = test_dir / "recovered_wrong.txt"
    
    # Generate key with different attributes (doesn't satisfy policy)
    attributes = "user guest"
    result = lib.generateSecretKey(
        str(msk_file).encode('utf-8'),
        attributes.encode('utf-8'),
        str(wrong_sk_file).encode('utf-8')
    )
    
    if result == HCPABE_SUCCESS:
        print(f"  🔑 Bob's attributes: {attributes}")
        
        # Try to decrypt (should fail)
        result = lib.AC17decrypt(
            str(wrong_sk_file).encode('utf-8'),
            str(ciphertext_file).encode('utf-8'),
            str(recovered_file).encode('utf-8')
        )
        
        if result == HCPABE_ERR_POLICY_MISMATCH:
            print(f"  ✅ Correctly rejected: {get_error_message(result)}")
            return True
        else:
            print(f"  ❌ Unexpected result: {get_error_message(result)}")
            return False
    
    return False

# ============================================================================
# Main Test Runner
# ============================================================================

def main():
    print("=" * 70)
    print("🧪 Hybrid CP-ABE DLL Test Suite")
    print("=" * 70)
    
    # Setup test directory
    test_dir = Path(__file__).parent / "test" / "python_dll_test"
    test_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n📂 Test directory: {test_dir}")
    
    # Run tests
    tests = [
        ("Version Info", test_version),
        ("Setup", lambda: test_setup(test_dir)),
        ("Generate Secret Key", lambda: test_generate_secret_key(test_dir)),
        ("Encrypt", lambda: test_encrypt(test_dir)),
        ("Decrypt", lambda: test_decrypt(test_dir)),
        ("Decrypt Wrong Key", lambda: test_decrypt_wrong_key(test_dir)),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Test Summary")
    print("=" * 70)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\n🎯 Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All tests passed!")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
