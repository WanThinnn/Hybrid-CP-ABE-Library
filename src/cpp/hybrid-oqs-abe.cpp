#include "hybrid-pq-cp-abe.h"
#include "rabe/rabe.h"
#include <oqs/oqs.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/files.h>
#include <sys/stat.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <cstring>

#ifdef _MSC_VER
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>

extern "C" {
    void* __mingw_aligned_malloc(size_t size, size_t alignment) {
        return _aligned_malloc(size, alignment);
    }
    void __mingw_aligned_free(void* memblock) {
        _aligned_free(memblock);
    }
    int __mingw_fprintf(FILE* const file, const char* format, ...) {
        va_list args;
        va_start(args, format);
        int ret = vfprintf(file, format, args);
        va_end(args);
        return ret;
    }
}
#pragma comment(linker, "/alternatename:___chkstk_ms=__chkstk")
#endif

// Helper functions duplicated from hybrid-cp-abe.cpp
static void secureWipe(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
}

static bool SaveFile(const std::string &filename, const char *data, const std::string &format)
{
    if (data == nullptr) return false;
    size_t data_len = std::strlen(data);
    try {
        if (format == "JsonText" || format == "Original") {
            CryptoPP::FileSink file(filename.c_str(), true);
            file.Put(reinterpret_cast<const CryptoPP::byte *>(data), data_len);
            file.MessageEnd();
        } else if (format == "Base64") {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str()), false));
        } else if (format == "HEX") {
            CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new CryptoPP::HexEncoder(new CryptoPP::FileSink(filename.c_str()), false));
        } else return false;
    } catch (...) { return false; }
    return true;
}

static bool LoadFile(const std::string &filename, std::string &data, const std::string &format)
{
    try {
        std::string encodedData;
        CryptoPP::FileSource fs(filename.c_str(), true, new CryptoPP::StringSink(encodedData));
        if (format == "Base64") {
            CryptoPP::StringSource ss(encodedData, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(data)));
        } else if (format == "HEX") {
            CryptoPP::StringSource ss(encodedData, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(data)));
        } else if (format == "JsonText" || format == "Original") {
            data = encodedData;
        } else return false;
    } catch (...) { return false; }
    return true;
}

static std::string extractPqcKey(const std::string& jsonStr, const std::string& keyName) {
    std::string searchKey = "\"" + keyName + "\":\"";
    size_t pos = jsonStr.find(searchKey);
    if (pos == std::string::npos) {
        searchKey = "\"" + keyName + "\": \"";
        pos = jsonStr.find(searchKey);
        if (pos == std::string::npos) return "";
    }
    pos += searchKey.length();
    size_t endPos = jsonStr.find("\"", pos);
    if (endPos == std::string::npos) return "";
    return jsonStr.substr(pos, endPos - pos);
}

int hybrid_cpabe_setup_with_pqc(const char *path)
{
    std::string strPath(path);
    std::string strFileFormat = HybridCPABE::DEFAULT_KEY_FORMAT;
    try
    {
        Ac17SetupResult setupResult = rabe_ac17_init();
        char *masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        char *publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);
        if (!masterKeyJson || !publicKeyJson)
            throw std::runtime_error("Failed to convert keys to JSON.");

        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
        if (!sig) {
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        std::vector<uint8_t> pqc_pub(sig->length_public_key);
        std::vector<uint8_t> pqc_priv(sig->length_secret_key);
        if (OQS_SIG_keypair(sig, pqc_pub.data(), pqc_priv.data()) != OQS_SUCCESS) {
            OQS_SIG_free(sig);
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            return HCPABE_ERR_CRYPTO_FAILED;
        }
        OQS_SIG_free(sig);

        std::string pqcPubBase64, pqcSecBase64;
        CryptoPP::StringSource(pqc_pub.data(), pqc_pub.size(), true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcPubBase64), false));
        CryptoPP::StringSource(pqc_priv.data(), pqc_priv.size(), true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(pqcSecBase64), false));

        std::string msKeyStr(masterKeyJson);
        std::string pbKeyStr(publicKeyJson);

        size_t msLastBrace = msKeyStr.find_last_of("}");
        if (msLastBrace != std::string::npos) msKeyStr.insert(msLastBrace, ",\"pqc_private_key\":\"" + pqcSecBase64 + "\"");
        size_t pbLastBrace = pbKeyStr.find_last_of("}");
        if (pbLastBrace != std::string::npos) pbKeyStr.insert(pbLastBrace, ",\"pqc_public_key\":\"" + pqcPubBase64 + "\"");

        std::string mskPath, pkPath;
        struct stat info;
        if (stat(strPath.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
            mskPath = strPath + "/cpabe_msk.key";
            pkPath = strPath + "/cpabe_pk.key";
        } else if (strPath.empty() || strPath.back() == '/' || strPath.back() == '\\') {
            mskPath = strPath + "cpabe_msk.key";
            pkPath = strPath + "cpabe_pk.key";
        } else {
            mskPath = strPath + "_msk.key";
            pkPath = strPath + "_pk.key";
        }

        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            bool msSaved = SaveFile(mskPath, msKeyStr.c_str(), strFileFormat);
            bool pbSaved = SaveFile(pkPath, pbKeyStr.c_str(), strFileFormat);
            
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            
            if (!msSaved || !pbSaved) return HCPABE_ERR_FILE_NOT_FOUND;
            
            std::cout << "Setup with PQC completed successfully." << std::endl;
            return HCPABE_SUCCESS;
        }
        else
        {
            rabe_free_json(masterKeyJson);
            rabe_free_json(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            return HCPABE_ERR_UNSUPPORTED_FORMAT;
        }
    }
    catch (...) { return HCPABE_ERR_CRYPTO_FAILED; }
}

int hybrid_cpabe_encryptBuffer_and_sign(
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *masterKey, size_t mskLen,
    const unsigned char *plaintext, size_t ptLen,
    const char *policy,
    unsigned char **ciphertext, size_t *ctLen)
{
    std::string mskStr(reinterpret_cast<const char*>(masterKey), mskLen);
    
    std::string pqcPrivBase64 = extractPqcKey(mskStr, "pqc_private_key");
    if (pqcPrivBase64.empty()) {
        std::cout << "DEBUG: pqcPrivBase64 is empty!" << std::endl;
        return HCPABE_ERR_INVALID_KEY;
    }

    std::string pqcPrivRaw;
    CryptoPP::StringSource(pqcPrivBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPrivRaw)));

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) return HCPABE_ERR_CRYPTO_FAILED;

    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature.data(), &sig_len, plaintext, ptLen, (const uint8_t*)pqcPrivRaw.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    OQS_SIG_free(sig);

    uint32_t sig_len_32 = static_cast<uint32_t>(sig_len);
    std::vector<uint8_t> payload;
    payload.reserve(4 + sig_len + ptLen);
    uint8_t* slen_ptr = reinterpret_cast<uint8_t*>(&sig_len_32);
    payload.insert(payload.end(), slen_ptr, slen_ptr + 4);
    payload.insert(payload.end(), signature.begin(), signature.begin() + sig_len);
    payload.insert(payload.end(), plaintext, plaintext + ptLen);

    // Strip PQC public key from public key JSON before passing to RABE
    std::string pkJson(reinterpret_cast<const char*>(publicKey), pkLen);
    size_t posPk = pkJson.find(",\"pqc_public_key\"");
    if (posPk != std::string::npos) {
        pkJson.erase(posPk);
        pkJson += "}";
    }

    int res = hybrid_cpabe_encryptBuffer((const unsigned char*)pkJson.data(), pkJson.size(), payload.data(), payload.size(), policy, ciphertext, ctLen);
    if (res != HCPABE_SUCCESS) {
        std::cout << "DEBUG: hybrid_cpabe_encryptBuffer returned " << res << std::endl;
    }
    
    secureWipe(&pqcPrivRaw[0], pqcPrivRaw.size());
    secureWipe(payload.data(), payload.size());
    return res;
}

int hybrid_cpabe_decryptBuffer_and_verify(
    const unsigned char *privateKey, size_t skLen,
    const unsigned char *publicKey, size_t pkLen,
    const unsigned char *ciphertext, size_t ctLen,
    unsigned char **plaintext, size_t *ptLen)
{
    unsigned char *payload = nullptr;
    size_t payloadLen = 0;
    int res = hybrid_cpabe_decryptBuffer(privateKey, skLen, ciphertext, ctLen, &payload, &payloadLen);
    if (res != HCPABE_SUCCESS) return res;

    std::string pkStr(reinterpret_cast<const char*>(publicKey), pkLen);
    
    std::string pqcPubBase64 = extractPqcKey(pkStr, "pqc_public_key");
    if (pqcPubBase64.empty()) {
        freeBuffer(payload);
        return HCPABE_ERR_INVALID_KEY;
    }

    std::string pqcPubRaw;
    CryptoPP::StringSource(pqcPubBase64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(pqcPubRaw)));

    if (payloadLen < 4) {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }
    uint32_t sig_len_32 = 0;
    std::memcpy(&sig_len_32, payload, 4);
    if (payloadLen < 4 + sig_len_32) {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    const uint8_t *signature = payload + 4;
    const uint8_t *original_pt = payload + 4 + sig_len_32;
    size_t original_pt_len = payloadLen - 4 - sig_len_32;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) {
        freeBuffer(payload);
        return HCPABE_ERR_CRYPTO_FAILED;
    }

    if (OQS_SIG_verify(sig, original_pt, original_pt_len, signature, sig_len_32, (const uint8_t*)pqcPubRaw.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_SIGNATURE_INVALID;
    }
    OQS_SIG_free(sig);

    *ptLen = original_pt_len;
    *plaintext = (unsigned char *)malloc(*ptLen);
    if (!*plaintext) {
        secureWipe(payload, payloadLen);
        freeBuffer(payload);
        return HCPABE_ERR_MEMORY;
    }
    std::memcpy(*plaintext, original_pt, *ptLen);

    secureWipe(payload, payloadLen);
    freeBuffer(payload);
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_encrypt_and_sign(const char *publicKeyFile, const char *masterKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    std::string pkData, mskData, plaintext;
    if (!LoadFile(publicKeyFile, pkData, "Base64") || !LoadFile(masterKeyFile, mskData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ptF(plaintextFile, std::ios::binary);
    if (!ptF) return HCPABE_ERR_FILE_NOT_FOUND;
    plaintext.assign((std::istreambuf_iterator<char>(ptF)), std::istreambuf_iterator<char>());

    unsigned char *ct = nullptr;
    size_t ctLen = 0;
    int res = hybrid_cpabe_encryptBuffer_and_sign(
        (const unsigned char*)pkData.data(), pkData.size(),
        (const unsigned char*)mskData.data(), mskData.size(),
        (const unsigned char*)plaintext.data(), plaintext.size(),
        policy, &ct, &ctLen);
    
    if (res != HCPABE_SUCCESS) return res;

    try {
        CryptoPP::FileSink fileSink(ciphertextFile, true);
        fileSink.Put(ct, ctLen);
        fileSink.MessageEnd();
    } catch (...) {
        freeBuffer(ct);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(ct);
    std::cout << "Encrypt & Sign successful!" << std::endl;
    return HCPABE_SUCCESS;
}

int hybrid_cpabe_decrypt_and_verify(const char *privateKeyFile, const char *publicKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    std::string pkData, skData, ciphertext;
    if (!LoadFile(publicKeyFile, pkData, "Base64") || !LoadFile(privateKeyFile, skData, "Base64")) return HCPABE_ERR_FILE_NOT_FOUND;

    std::ifstream ctF(ciphertextFile, std::ios::binary);
    if (!ctF) return HCPABE_ERR_FILE_NOT_FOUND;
    ciphertext.assign((std::istreambuf_iterator<char>(ctF)), std::istreambuf_iterator<char>());

    unsigned char *pt = nullptr;
    size_t ptLen = 0;
    int res = hybrid_cpabe_decryptBuffer_and_verify(
        (const unsigned char*)skData.data(), skData.size(),
        (const unsigned char*)pkData.data(), pkData.size(),
        (const unsigned char*)ciphertext.data(), ciphertext.size(),
        &pt, &ptLen);
    
    if (res != HCPABE_SUCCESS) return res;

    try {
        CryptoPP::FileSink fileSink(recovertextFile, true);
        fileSink.Put(pt, ptLen);
        fileSink.MessageEnd();
    } catch (...) {
        freeBuffer(pt);
        return HCPABE_ERR_FILE_NOT_FOUND;
    }
    freeBuffer(pt);
    std::cout << "Decrypt & Verify successful!" << std::endl;
    return HCPABE_SUCCESS;
}
