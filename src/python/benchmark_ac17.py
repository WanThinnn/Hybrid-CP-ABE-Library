import os
import sys
import time
import json
import matplotlib.pyplot as plt
import numpy as np
import hashlib
from Crypto.Cipher import AES

# Charm imports
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.ac17 import AC17CPABE
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False
    print("Warning: charm-crypto is not installed or failed to import.")



# Custom library imports
from hybrid_cpabe import (
    call_setup,
    call_generate_secret_key,
    call_hybrid_cpabe_encrypt,
    call_hybrid_cpabe_decrypt,
    call_hybrid_cpabe_encryptBuffer,
    call_hybrid_cpabe_decryptBuffer,
    HCPABE_SUCCESS
)

# Constants
ITERATIONS = 50
RESULTS_DIR = "results"
TEMP_DIR = "temp_bench"
POLICY = "(((((ATTR1 AND ATTR2) AND ATTR3) AND (ATTR4 OR ATTR5)) AND ((ATTR6 AND ATTR7) OR (ATTR8 AND ATTR9))) AND (ATTR10 OR ATTR11))"
ATTRIBUTES = "ATTR1 ATTR2 ATTR3 ATTR4 ATTR8 ATTR9 ATTR11 EXTRA1 EXTRA2 EXTRA3 EXTRA4 EXTRA5"
ATTR_LIST = ['ATTR1', 'ATTR2', 'ATTR3', 'ATTR4', 'ATTR8', 'ATTR9', 'ATTR11', 'EXTRA1', 'EXTRA2', 'EXTRA3', 'EXTRA4', 'EXTRA5']
PLAINTEXT_DATA = b"Hello, this is a test for Hybrid CP-ABE benchmarking! Just padding with some more bytes to make it realistic."

def ensure_dirs():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

def benchmark_charm():
    if not CHARM_AVAILABLE:
        return None
    
    print("--- Benchmarking Charm Crypto AC17 ---")
    group = PairingGroup('BN254')
    ac17 = AC17CPABE(group_obj=group, assump_size=2)
    
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    # Setup
    start = time.time()
    for _ in range(ITERATIONS):
        (pk, msk) = ac17.setup()
    times['setup'] = (time.time() - start) / ITERATIONS
    
    # Keygen
    start = time.time()
    for _ in range(ITERATIONS):
        sk = ac17.keygen(pk, msk, ATTR_LIST)
    times['keygen'] = (time.time() - start) / ITERATIONS
    
    # Encrypt
    start = time.time()
    for _ in range(ITERATIONS):
        # 1. Generate 12288-bit (1536 bytes) random key
        rand_key = os.urandom(1536)
        
        # 2. Hybrid KEM with ABE (since Charm AC17 only encrypts GT)
        k = group.random(GT)
        aes_kem_key = hashlib.sha256(group.serialize(k)).digest()
        
        kem_cipher = AES.new(aes_kem_key, AES.MODE_GCM)
        enc_rand_key, kem_tag = kem_cipher.encrypt_and_digest(rand_key)
        kem_nonce = kem_cipher.nonce
        
        ctxt = ac17.encrypt(pk, k, POLICY)
        
        # 3. Hash random key to AES key
        aes_key = hashlib.sha3_256(rand_key).digest()
        
        # 4. Encrypt Data with AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(PLAINTEXT_DATA)
        nonce = cipher.nonce
        
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    # Decrypt
    start = time.time()
    for _ in range(ITERATIONS):
        # 1. Decrypt ABE KEM
        recovered_k = ac17.decrypt(pk, ctxt, sk)
        aes_kem_key_rec = hashlib.sha256(group.serialize(recovered_k)).digest()
        
        # 2. Decrypt random key
        kem_cipher_rec = AES.new(aes_kem_key_rec, AES.MODE_GCM, nonce=kem_nonce)
        recovered_rand_key = kem_cipher_rec.decrypt_and_verify(enc_rand_key, kem_tag)
        
        # 3. Hash to AES key
        aes_key_rec = hashlib.sha3_256(recovered_rand_key).digest()
        
        # 4. Decrypt Data
        cipher_rec = AES.new(aes_key_rec, AES.MODE_GCM, nonce=nonce)
        recovered_msg = cipher_rec.decrypt_and_verify(ct, tag)
        
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    if PLAINTEXT_DATA != recovered_msg:
        print("Warning: Charm decryption failed during benchmark!")
        
    return times

def benchmark_custom_file():
    print("--- Benchmarking Custom Library (File I/O) ---")
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    msk_path = os.path.join(TEMP_DIR, "cpabe_msk.key")
    pk_path = os.path.join(TEMP_DIR, "cpabe_pk.key")
    sk_path = os.path.join(TEMP_DIR, "user.key")
    pt_path = os.path.join(TEMP_DIR, "data.txt")
    ct_path = os.path.join(TEMP_DIR, "data.enc")
    dt_path = os.path.join(TEMP_DIR, "data.dec")
    
    with open(pt_path, "wb") as f:
        f.write(PLAINTEXT_DATA)
        
    # Setup
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_setup(TEMP_DIR)
        if res != HCPABE_SUCCESS: raise Exception("Setup failed")
    times['setup'] = (time.time() - start) / ITERATIONS
    
    # Keygen
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_generate_secret_key(msk_path, ATTRIBUTES, sk_path)
        if res != HCPABE_SUCCESS: raise Exception("Keygen failed")
    times['keygen'] = (time.time() - start) / ITERATIONS
    
    # Encrypt File
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_hybrid_cpabe_encrypt(pk_path, pt_path, POLICY, ct_path)
        if res != HCPABE_SUCCESS: raise Exception("Encrypt failed")
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    # Decrypt File
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_hybrid_cpabe_decrypt(sk_path, ct_path, dt_path)
        if res != HCPABE_SUCCESS: raise Exception("Decrypt failed")
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    return times

def benchmark_custom_buffer():
    print("--- Benchmarking Custom Library (Buffer) ---")
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    # Re-use setup and keygen from file for Buffer (since Custom Library only has File Setup/Keygen)
    # The prompt mainly asks to compare call_hybrid_cpabe_encrypt with call_hybrid_cpabe_encryptBuffer
    msk_path = os.path.join(TEMP_DIR, "cpabe_msk.key")
    pk_path = os.path.join(TEMP_DIR, "cpabe_pk.key")
    sk_path = os.path.join(TEMP_DIR, "user.key")
    
    # Do one setup and keygen to get keys
    call_setup(TEMP_DIR)
    call_generate_secret_key(msk_path, ATTRIBUTES, sk_path)
    
    with open(pk_path, "rb") as f: pk_bytes = f.read()
    with open(sk_path, "rb") as f: sk_bytes = f.read()
    
    # Setup (Just copying File Setup time as Buffer Setup isn't a separate function)
    # Or we can just omit Setup/Keygen for Buffer, but to plot nicely we can just copy File Setup/Keygen 
    # since it's the exact same operations. We'll leave them as 0 to highlight the difference in Encrypt/Decrypt
    
    # Encrypt Buffer
    start = time.time()
    for _ in range(ITERATIONS):
        ct_bytes = call_hybrid_cpabe_encryptBuffer(pk_bytes, PLAINTEXT_DATA, POLICY)
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    # Decrypt Buffer
    start = time.time()
    for _ in range(ITERATIONS):
        pt_bytes = call_hybrid_cpabe_decryptBuffer(sk_bytes, ct_bytes)
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    if pt_bytes != PLAINTEXT_DATA:
        print("Warning: Custom Buffer decryption failed during benchmark!")
        
    return times

def plot_results(results):
    labels = ['Setup', 'KeyGen', 'Encrypt', 'Decrypt']
    
    charm_means = [
        results['charm']['setup'] * 1000 if results.get('charm') else 0,
        results['charm']['keygen'] * 1000 if results.get('charm') else 0,
        results['charm']['encrypt'] * 1000 if results.get('charm') else 0,
        results['charm']['decrypt'] * 1000 if results.get('charm') else 0
    ]
    
    custom_file_means = [
        results['custom_file']['setup'] * 1000,
        results['custom_file']['keygen'] * 1000,
        results['custom_file']['encrypt'] * 1000,
        results['custom_file']['decrypt'] * 1000
    ]
    
    custom_buffer_means = [
        results['custom_file']['setup'] * 1000, # Use file setup time as it's the same
        results['custom_file']['keygen'] * 1000, # Use file keygen time as it's the same
        results['custom_buffer']['encrypt'] * 1000,
        results['custom_buffer']['decrypt'] * 1000
    ]

    x = np.arange(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width, charm_means, width, label='Charm (AC17)')
    rects2 = ax.bar(x, custom_file_means, width, label='Custom Lib (File I/O)')
    rects3 = ax.bar(x + width, custom_buffer_means, width, label='Custom Lib (Buffer)')

    ax.set_ylabel('Time (ms)')
    ax.set_title(f'CP-ABE Performance Benchmark (Average over {ITERATIONS} iterations)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    
    # Add values on top of bars
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            if height > 0:
                ax.annotate(f'{height:.2f}',
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),  # 3 points vertical offset
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=8)

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)

    fig.tight_layout()
    chart_path = os.path.join(RESULTS_DIR, 'benchmark_chart.png')
    plt.savefig(chart_path, dpi=300)
    print(f"Chart saved to {chart_path}")
    
    # Also create a specific chart focusing ONLY on Encrypt and Decrypt
    fig2, ax2 = plt.subplots(figsize=(8, 6))
    enc_dec_labels = ['Encrypt', 'Decrypt']
    x2 = np.arange(len(enc_dec_labels))
    
    charm_ed = [charm_means[2], charm_means[3]]
    file_ed = [custom_file_means[2], custom_file_means[3]]
    buf_ed = [custom_buffer_means[2], custom_buffer_means[3]]
    
    rects1_ed = ax2.bar(x2 - width, charm_ed, width, label='Charm (AC17)')
    rects2_ed = ax2.bar(x2, file_ed, width, label='Custom Lib (File I/O)')
    rects3_ed = ax2.bar(x2 + width, buf_ed, width, label='Custom Lib (Buffer)')
    
    ax2.set_ylabel('Time (ms)')
    ax2.set_title('Encrypt and Decrypt Performance Comparison')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(enc_dec_labels)
    ax2.legend()
    
    autolabel(rects1_ed)
    autolabel(rects2_ed)
    autolabel(rects3_ed)
    
    fig2.tight_layout()
    chart2_path = os.path.join(RESULTS_DIR, 'encrypt_decrypt_focus_chart.png')
    plt.savefig(chart2_path, dpi=300)
    print(f"Focus chart saved to {chart2_path}")

def main():
    ensure_dirs()
    
    results = {}
    
    results['charm'] = benchmark_charm()
    results['custom_file'] = benchmark_custom_file()
    results['custom_buffer'] = benchmark_custom_buffer()
    
    # Save raw results
    results_path = os.path.join(RESULTS_DIR, "benchmark_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {results_path}")
    
    plot_results(results)

if __name__ == "__main__":
    # Redirect stdout to devnull during the benchmark for clean output, unless we are printing headers
    import builtins
    original_print = builtins.print
    
    def quiet_print(*args, **kwargs):
        if args and isinstance(args[0], str) and (args[0].startswith("---") or args[0].startswith("Chart") or args[0].startswith("Focus") or args[0].startswith("Results") or args[0].startswith("Warning")):
            original_print(*args, **kwargs)
            
    builtins.print = quiet_print
    main()
    builtins.print = original_print
    print("Benchmarking completed successfully!")
