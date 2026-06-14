/**
 * @file main.cpp
 * @brief CLI wrapper cho thư viện Hybrid CP-ABE
 * 
 * File này cung cấp giao diện dòng lệnh để sử dụng các chức năng
 * của thư viện Hybrid CP-ABE: setup, genkey, encrypt, decrypt.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

#include "hybrid-cp-abe.h"

void printUsage(const char* programName)
{
    std::cout << "Hybrid CP-ABE Library v" << getVersion() << std::endl;
    std::cout << "Usage: " << programName << " [command] [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  setup   <path>                           - Generate master key and public key" << std::endl;
    std::cout << "  genkey  <master_key> <attrs> <out_file>  - Generate private key from attributes" << std::endl;
    std::cout << "  encrypt <pub_key> <file> <policy> <out>  - Encrypt file with access policy" << std::endl;
    std::cout << "  decrypt <priv_key> <file> <out>          - Decrypt file" << std::endl;
    std::cout << "  encrypt_buffer <pub_key> <text> <policy> <out> - Encrypt text string to file" << std::endl;
    std::cout << "  decrypt_buffer <priv_key> <file>               - Decrypt file to stdout" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " setup ./keys" << std::endl;
    std::cout << "  " << programName << " genkey ./keys/cpabe_msk.key \"admin it\" ./keys/user.key" << std::endl;
    std::cout << "  " << programName << " encrypt ./keys/cpabe_pk.key data.txt \"\\\"admin\\\" and \\\"it\\\"\" data.enc" << std::endl;
    std::cout << "  " << programName << " decrypt ./keys/user.key data.enc data.dec" << std::endl;
    std::cout << "  " << programName << " encrypt_buffer ./keys/cpabe_pk.key \"Secret Message\" \"\\\"admin\\\"\" secret.enc" << std::endl;
    std::cout << "  " << programName << " decrypt_buffer ./keys/user.key secret.enc" << std::endl;
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
        std::cout << "Hybrid CP-ABE Library v" << getVersion() << std::endl;
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
            result = setup(argv[2]);
        }
        else if (mode == "genkey")
        {
            if (argc < 5)
            {
                std::cerr << "Usage: " << argv[0] << " genkey <master_key_file> <attributes> <private_key_file>" << std::endl;
                std::cerr << "Note: publicKeyFile parameter has been removed in v2.0" << std::endl;
                return 1;
            }
            result = generateSecretKey(argv[2], argv[3], argv[4]);
        }
        else if (mode == "encrypt")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>" << std::endl;
                return 1;
            }
            result = hybrid_cpabe_encrypt(argv[2], argv[3], argv[4], argv[5]);
        }
        else if (mode == "decrypt")
        {
            if (argc < 5)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt <private_key_file> <ciphertext_file> <recovertext_file>" << std::endl;
                return 1;
            }
            result = hybrid_cpabe_decrypt(argv[2], argv[3], argv[4]);
        }
        else if (mode == "encrypt_buffer")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt_buffer <public_key_file> <text_string> <policy> <ciphertext_file>" << std::endl;
                return 1;
            }
            
            // Read PK
            std::ifstream pkFile(argv[2], std::ios::binary);
            if (!pkFile) { std::cerr << "Cannot open public key file." << std::endl; return 1; }
            std::string pkStr((std::istreambuf_iterator<char>(pkFile)), std::istreambuf_iterator<char>());
            pkFile.close();
            
            std::string decodedPkStr;
            CryptoPP::StringSource(pkStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedPkStr)));
            
            std::string ptStr = argv[3];
            unsigned char* ct = nullptr;
            size_t ctLen = 0;
            
            result = hybrid_cpabe_encryptBuffer((const unsigned char*)decodedPkStr.data(), decodedPkStr.size(), 
                                                (const unsigned char*)ptStr.data(), ptStr.size(), 
                                                argv[4], &ct, &ctLen);
            if (result == HCPABE_SUCCESS) {
                std::ofstream outFile(argv[5], std::ios::binary);
                outFile.write((char*)ct, ctLen);
                outFile.close();
                freeBuffer(ct);
            }
        }
        else if (mode == "decrypt_buffer")
        {
            if (argc < 4)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt_buffer <private_key_file> <ciphertext_file>" << std::endl;
                return 1;
            }
            
            // Read SK
            std::ifstream skFile(argv[2], std::ios::binary);
            if (!skFile) { std::cerr << "Cannot open private key file." << std::endl; return 1; }
            std::string skStr((std::istreambuf_iterator<char>(skFile)), std::istreambuf_iterator<char>());
            skFile.close();
            
            std::string decodedSkStr;
            CryptoPP::StringSource(skStr, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSkStr)));
            
            // Read CT
            std::ifstream ctFile(argv[3], std::ios::binary);
            if (!ctFile) { std::cerr << "Cannot open ciphertext file." << std::endl; return 1; }
            std::string ctStr((std::istreambuf_iterator<char>(ctFile)), std::istreambuf_iterator<char>());
            ctFile.close();
            
            unsigned char* pt = nullptr;
            size_t ptLen = 0;
            
            result = hybrid_cpabe_decryptBuffer((const unsigned char*)decodedSkStr.data(), decodedSkStr.size(), 
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
