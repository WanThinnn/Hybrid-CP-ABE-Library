/**
 * @file oqs_main.cpp
 * @brief CLI wrapper cho thư viện Hybrid OQS ABE (PQC Signatures)
 * 
 * File này cung cấp giao diện dòng lệnh để sử dụng các chức năng
 * của thư viện Hybrid CP-ABE tích hợp chữ ký lượng tử ML-DSA-87: 
 * setup_with_pqc, genkey, encrypt_and_sign, decrypt_and_verify.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "hybrid-cp-abe.h"

void printUsage(const char* programName)
{
    std::cout << "Hybrid OQS ABE Library (PQC Signatures) v" << getVersion() << std::endl;
    std::cout << "Usage: " << programName << " [command] [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  setup   <path>                                       - Generate MSK, PK and PQC keys" << std::endl;
    std::cout << "  genkey  <master_key> <attrs> <out_file>              - Generate private key from attributes" << std::endl;
    std::cout << "  encrypt <pub_key> <msk_key> <file> <policy> <out>    - Encrypt and Sign file" << std::endl;
    std::cout << "  decrypt <priv_key> <pub_key> <file> <out>            - Decrypt and Verify file" << std::endl;
    std::cout << "  encrypt_buffer <pub_key> <msk_key> <text> <policy> <out> - Encrypt and Sign text string" << std::endl;
    std::cout << "  decrypt_buffer <priv_key> <pub_key> <file>               - Decrypt and Verify to stdout" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " setup ./keys" << std::endl;
    std::cout << "  " << programName << " genkey ./keys/cpabe_msk.key \"admin it\" ./keys/user.key" << std::endl;
    std::cout << "  " << programName << " encrypt ./keys/cpabe_pk.key ./keys/cpabe_msk.key data.txt \"\\\"admin\\\" and \\\"it\\\"\" data.enc" << std::endl;
    std::cout << "  " << programName << " decrypt ./keys/user.key ./keys/cpabe_pk.key data.enc data.dec" << std::endl;
    std::cout << "  " << programName << " encrypt_buffer ./keys/cpabe_pk.key ./keys/cpabe_msk.key \"Secret\" \"\\\"admin\\\"\" secret.enc" << std::endl;
    std::cout << "  " << programName << " decrypt_buffer ./keys/user.key ./keys/cpabe_pk.key secret.enc" << std::endl;
}

#include <fstream>
#include <sstream>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string mode = argv[1];
    
    // Handle help command
    if (mode == "-h" || mode == "--help" || mode == "help")
    {
        printUsage(argv[0]);
        return 0;
    }
    
    // Handle version command
    if (mode == "-v" || mode == "--version" || mode == "version")
    {
        std::cout << "Hybrid OQS ABE Library v" << getVersion() << std::endl;
        return 0;
    }
    
    int result = HCPABE_SUCCESS;
    
    try
    {
        if (mode == "setup")
        {
            if (argc < 3)
            {
                std::cerr << "Usage: " << argv[0] << " setup <path_to_save_keys>" << std::endl;
                return 1;
            }
            result = hybrid_cpabe_setup_with_pqc(argv[2]);
        }
        else if (mode == "genkey")
        {
            if (argc < 5)
            {
                std::cerr << "Usage: " << argv[0] << " genkey <master_key_file> <attributes> <private_key_file>" << std::endl;
                return 1;
            }
            result = generateSecretKey(argv[2], argv[3], argv[4]);
        }
        else if (mode == "encrypt")
        {
            if (argc < 7)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt <public_key_file> <master_key_file> <plaintext_file> <policy> <ciphertext_file>" << std::endl;
                return 1;
            }
            result = hybrid_cpabe_encrypt_and_sign(argv[2], argv[3], argv[4], argv[5], argv[6]);
        }
        else if (mode == "decrypt")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt <private_key_file> <public_key_file> <ciphertext_file> <recovertext_file>" << std::endl;
                return 1;
            }
            result = hybrid_cpabe_decrypt_and_verify(argv[2], argv[3], argv[4], argv[5]);
        }
        else if (mode == "encrypt_buffer")
        {
            if (argc < 7)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt_buffer <public_key_file> <master_key_file> <text_string> <policy> <ciphertext_file>" << std::endl;
                return 1;
            }
            
            // Read PK
            std::ifstream pkFile(argv[2], std::ios::binary);
            if (!pkFile) return 1;
            std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
            pkFile.close();
            
            std::string decodedPkStr;
            CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
            
            // Read MSK
            std::ifstream mskFile(argv[3], std::ios::binary);
            if (!mskFile) return 1;
            std::string mskStr((std::istreambuf_iterator<char>(mskFile)), std::istreambuf_iterator<char>());
            mskFile.close();
            std::string decodedMskStr;
            CryptoPP::StringSource(mskStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedMskStr)));
            
            std::string ptStr = argv[4];
            unsigned char* ct = nullptr;
            size_t ctLen = 0;
            
            result = hybrid_cpabe_encryptBuffer_and_sign(
                                                (const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                (const unsigned char*)decodedMskStr.data(), decodedMskStr.size(), 
                                                (const unsigned char*)ptStr.data(), ptStr.size(), 
                                                argv[5], &ct, &ctLen);
            if (result == HCPABE_SUCCESS) {
                std::ofstream outFile(argv[6], std::ios::binary);
                outFile.write((char*)ct, ctLen);
                outFile.close();
                freeBuffer(ct);
            }
        }
        else if (mode == "decrypt_buffer")
        {
            if (argc < 5)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt_buffer <private_key_file> <public_key_file> <ciphertext_file>" << std::endl;
                return 1;
            }
            
            // Read SK
            std::ifstream skFile(argv[2], std::ios::binary);
            if (!skFile) return 1;
            std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
            skFile.close();
            
            std::string decodedSkStr;
            CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));
            
            // Read PK
            std::ifstream pkFile(argv[3], std::ios::binary);
            if (!pkFile) return 1;
            std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
            pkFile.close();
            std::string decodedPkStr;
            CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
            
            // Read CT
            std::ifstream ctFile(argv[4], std::ios::binary);
            if (!ctFile) return 1;
            std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
            ctFile.close();
            
            unsigned char* pt = nullptr;
            size_t ptLen = 0;
            
            result = hybrid_cpabe_decryptBuffer_and_verify(
                                                (const unsigned char*)decodedSkStr.data(), decodedSkStr.size(), 
                                                (const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                (const unsigned char*)ctStr.data(), ctStr.size(), 
                                                &pt, &ptLen);
            if (result == HCPABE_SUCCESS) {
                std::string ptOut((char*)pt, ptLen);
                std::cout << "Decrypted Buffer: " << ptOut << std::endl;
                freeBuffer(pt);
            }
        }
        else
        {
            std::cerr << "Error: Invalid command '" << mode << "'" << std::endl;
            std::cerr << "Use '" << argv[0] << " --help' for usage information." << std::endl;
            return 1;
        }
        
        // Print error message if operation failed
        if (result != HCPABE_SUCCESS)
        {
            std::cerr << "Operation failed: " << getErrorMessage(result) << " (code: " << result << ")" << std::endl;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    
    return (result == HCPABE_SUCCESS) ? 0 : 1;
}
