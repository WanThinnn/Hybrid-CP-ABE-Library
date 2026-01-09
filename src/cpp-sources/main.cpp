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
    std::cout << "  decrypt <priv_key> <file> <out>         - Decrypt file" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " setup ./keys" << std::endl;
    std::cout << "  " << programName << " genkey ./keys/cpabe_msk.key \"admin it\" ./keys/user.key" << std::endl;
    std::cout << "  " << programName << " encrypt ./keys/cpabe_pk.key data.txt \"\\\"admin\\\" and \\\"it\\\"\" data.enc" << std::endl;
    std::cout << "  " << programName << " decrypt ./keys/user.key data.enc data.dec" << std::endl;
}

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
