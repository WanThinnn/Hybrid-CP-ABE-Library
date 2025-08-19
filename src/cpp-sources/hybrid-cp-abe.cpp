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

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <cstring>

// #include <winsock2.h>
#include "rabe/rabe.h"
#include "hybrid-cp-abe.h"

using namespace std;
using namespace CryptoPP;

// Hàm splitAttributes: không thay đổi.
std::vector<std::string> splitAttributes(const std::string &input)
{
    std::vector<std::string> result;
    std::istringstream ss(input);
    std::string item;
    while (std::getline(ss, item, ' '))
    {
        result.push_back(item);
    }
    return result;
}

// Hàm chuyển sang chữ thường (dùng std::string)
std::string toLowerCase(const std::string &str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return lowerStr;
}

// Hàm chuyển đổi dữ liệu thành vector<uint8_t>
std::vector<uint8_t> convertToByteArray(const void *data, size_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument("Null pointer with non-zero length!");
    }
    const uint8_t *bytePtr = static_cast<const uint8_t *>(data);
    return std::vector<uint8_t>(bytePtr, bytePtr + length);
}

// Hàm ensureJsonString đã được chuyển về trả về std::string
std::string ensureJsonString(const std::string &input)
{
    std::string lowerInput = toLowerCase(input);
    std::istringstream iss(lowerInput);
    std::string token;
    std::vector<std::string> tokens;
    std::string output;
    while (iss >> token)
    {
        size_t start = 0, end = 0;
        while (end < token.size())
        {
            if (token[end] == '(' || token[end] == ')')
            {
                if (start != end)
                {
                    tokens.push_back("\"" + token.substr(start, end - start) + "\"");
                }
                tokens.push_back(std::string(1, token[end]));
                start = end + 1;
            }
            end++;
        }
        if (start != end)
        {
            tokens.push_back("\"" + token.substr(start, end - start) + "\"");
        }
    }
    for (const auto &t : tokens)
    {
        output += t + " ";
    }
    if (!output.empty() && output.back() == ' ')
    {
        output.pop_back();
    }
    return output;
}

// Hàm SaveFile: không thay đổi nhiều, chỉ giữ lại cách dùng std::string.
bool SaveFile(const std::string &filename, const char *data, const std::string &format)
{
    if (data == nullptr)
    {
        std::cerr << "Error: Null data passed to SaveFile" << std::endl;
        return false;
    }
    size_t data_len = std::strlen(data);
    try
    {
        if (format == "JsonText" || format == "Original")
        {
            FileSink file(filename.c_str(), true);
            file.Put(reinterpret_cast<const CryptoPP::byte *>(data), data_len);
            file.MessageEnd();
        }
        else if (format == "Base64")
        {
            StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new Base64Encoder(new FileSink(filename.c_str()), false));
        }
        else if (format == "HEX")
        {
            StringSource ss(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                new HexEncoder(new FileSink(filename.c_str()), false));
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'JsonText', 'Base64', 'HEX' or 'Original'\n";
            return false;
        }
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return false;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

// Hàm LoadFile: giữ nguyên chức năng.
bool LoadFile(const std::string &filename, std::string &data, const std::string &format)
{
    try
    {
        std::string encodedData;
        FileSource fs(filename.c_str(), true, new StringSink(encodedData));
        if (format == "Base64")
        {
            StringSource ss(encodedData, true,
                new Base64Decoder(new StringSink(data)));
        }
        else if (format == "HEX")
        {
            StringSource ss(encodedData, true,
                new HexDecoder(new StringSink(data)));
        }
        else if (format == "JsonText" || format == "Original")
        {
            data = encodedData;
        }
        else
        {
            std::cerr << "Unsupported format. Please choose 'Base64', 'HEX', 'JsonText', or 'Original'\n";
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << "CryptoPP Exception: " << e.what() << std::endl;
        return false;
    }
    return true;
}

// setup function
int setup(const char *path)
{
    std::string strPath(path);
    std::string strFileFormat = "Base64";
    try
    {
        Ac17SetupResult setupResult = rabe_ac17_init();
        char *masterKeyJson = rabe_ac17_master_key_to_json(setupResult.master_key);
        char *publicKeyJson = rabe_ac17_public_key_to_json(setupResult.public_key);
        if (!masterKeyJson || !publicKeyJson)
        {
            throw std::runtime_error("Failed to convert master key or public key to JSON.");
        }
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(strPath + "/master_key.key", masterKeyJson, strFileFormat);
            SaveFile(strPath + "/public_key.key", publicKeyJson, strFileFormat);
            std::cout << "Setup completed successfully." << std::endl;
            free(masterKeyJson);
            free(publicKeyJson);
            rabe_ac17_free_master_key(setupResult.master_key);
            rabe_ac17_free_public_key(setupResult.public_key);
            return 0; // Thành công: trả về 0
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Setup failed: " << ex.what() << std::endl;
        return -1;
    }
}

// generateSecretKey function
int generateSecretKey(const char *publicKeyFile, const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
{
    std::string strFileFormat = "Base64";
    std::string masterKeyStr;
    try
    {
        std::string masterKeyData;
        if (!LoadFile(masterKeyFile, masterKeyData, strFileFormat))
            throw std::runtime_error("Failed to load master key file.");
        masterKeyStr = masterKeyData;
        const void *masterKey = rabe_ac17_master_key_from_json(masterKeyStr.c_str());
        if (!masterKey)
            throw std::runtime_error("Failed to convert master key from JSON.");
        std::string lowerAttributes = toLowerCase(attributes);
        std::vector<std::string> attrVec = splitAttributes(lowerAttributes);
        std::vector<const char *> attrList;
        for (const auto &attr : attrVec)
        {
            attrList.push_back(attr.c_str());
        }
        const void *secretKey = rabe_cp_ac17_generate_secret_key(masterKey, attrList.data(), attrList.size());
        if (!secretKey)
            throw std::runtime_error("Failed to generate private key.");
        char *secretKeyJson = rabe_cp_ac17_secret_key_to_json(secretKey);
        if (!secretKeyJson)
            throw std::runtime_error("Failed to convert private key to JSON.");
        if (strFileFormat == "JsonText" || strFileFormat == "HEX" || strFileFormat == "Base64")
        {
            SaveFile(privateKeyFile, secretKeyJson, strFileFormat);
            std::cout << "Private key generated successfully." << std::endl;
        }
        else
        {
            throw std::invalid_argument("Unsupported key format. Please choose 'JsonText', 'Base64', or 'HEX'.");
        }
        // Giải phóng bộ nhớ trước khi kết thúc
        free(secretKeyJson);
        rabe_cp_ac17_free_secret_key(secretKey);
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error generating private key: " << ex.what() << std::endl;
        return -1;
    }
}

// AC17encrypt function
int AC17encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
{
    try
    {
        std::string strPublicKeyFile(publicKeyFile);
        std::string strPlaintextFile(plaintextFile);
        std::string strCiphertextFile(ciphertextFile);

        AutoSeededRandomPool prng;
        CryptoPP::Integer randomKey(prng, 12288);
        std::string randomKeyStr;
        randomKey.Encode(StringSink(randomKeyStr).Ref(), randomKey.MinEncodedSize());

        // Mã hóa randomKey bằng CP-ABE
        std::string publicKeyData;
        if (!LoadFile(strPublicKeyFile, publicKeyData, "Base64"))
            throw std::runtime_error("Failed to load public key file.");
        const void *publicKey = rabe_ac17_public_key_from_json(publicKeyData.c_str());
        // Sử dụng std::string cho jsonPolicy
        std::string jsonPolicy = ensureJsonString(policy);
        const void *encryptedKey = rabe_cp_ac17_encrypt(publicKey, jsonPolicy.c_str(), randomKeyStr.c_str(), randomKeyStr.size());
        if (!encryptedKey)
            throw std::runtime_error("CP-ABE encryption failed.");
        // Lấy chuỗi JSON từ cipher
        char *encryptedKeyJson = rabe_cp_ac17_cipher_to_json(encryptedKey);
        if (!encryptedKeyJson)
            throw std::runtime_error("Failed to convert cipher to JSON.");
        std::string encryptedKeyB = encryptedKeyJson;
        // Giải phóng bộ nhớ của cipher theo hướng dẫn của thư viện RABE
        rabe_cp_ac17_free_cipher(encryptedKey);
        free(encryptedKeyJson);

        // Tạo khóa AES từ randomKey (hash bằng SHA3-256)
        SHA3_256 hash;
        std::string aesKey(hash.DigestSize(), 0);
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(randomKeyStr.data()), randomKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        // Đọc plaintext từ file
        ifstream file(strPlaintextFile, ios::binary);
        if (!file)
            throw std::runtime_error("Failed to open plaintext file.");
        std::string plaintext((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

        // Mã hóa AES-GCM
        GCM<AES>::Encryption aes_gcm;
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(aesKey.data()), aesKey.size());
        CryptoPP::byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        aes_gcm.SetKeyWithIV(key, key.size(), iv);

        std::string ciphertext;
        AuthenticatedEncryptionFilter ef(aes_gcm, new StringSink(ciphertext));
        ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const CryptoPP::byte *>(plaintext.data()), plaintext.size());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // Ghép nối IV, độ dài của encryptedKey, encryptedKey, và ciphertext
        std::string combined;
        combined.append(reinterpret_cast<const char *>(iv), sizeof(iv));
        uint64_t lenEncryptedKey = encryptedKeyB.size();
        combined.append(reinterpret_cast<const char *>(&lenEncryptedKey), sizeof(lenEncryptedKey));
        combined.append(encryptedKeyB);
        combined.append(ciphertext);

        // Mã hóa cuối cùng sang Base64
        std::string finalOutput;
        StringSource ss(combined, true, new Base64Encoder(new StringSink(finalOutput)));
        if (!SaveFile(strCiphertextFile, finalOutput.c_str(), "Original"))
            throw std::runtime_error("Failed to save ciphertext to file.");
        std::cout << "Encryption successful!" << std::endl;
        return 0;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return -1;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return -1;
    }
}

// AC17decrypt function
int AC17decrypt(const char *publicKeyFile, const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
{
    try
    {
        std::string strCiphertextFile(ciphertextFile);
        std::string encodedCiphertext;
        FileSource fileSource(strCiphertextFile.c_str(), true, new StringSink(encodedCiphertext));

        // Giải mã Base64
        std::string decodedCiphertext;
        StringSource ss1(encodedCiphertext, true, new Base64Decoder(new StringSink(decodedCiphertext)));

        if (decodedCiphertext.size() < AES::BLOCKSIZE)
            throw std::runtime_error("Invalid ciphertext: too small to contain IV.");
        
        CryptoPP::byte iv[AES::BLOCKSIZE];
        std::memcpy(iv, decodedCiphertext.data(), sizeof(iv));
        uint64_t offset = sizeof(iv);
        if (decodedCiphertext.size() < offset + sizeof(uint64_t))
            throw std::runtime_error("Invalid ciphertext: too small to contain encrypted key length.");
        uint64_t lenEncryptedKey;
        std::memcpy(&lenEncryptedKey, decodedCiphertext.data() + offset, sizeof(lenEncryptedKey));
        offset += sizeof(lenEncryptedKey);
        if (decodedCiphertext.size() < offset + lenEncryptedKey)
            throw std::runtime_error("Invalid ciphertext: insufficient size for encrypted key.");
        std::string encryptedKeyB = decodedCiphertext.substr(offset, lenEncryptedKey);
        offset += lenEncryptedKey;
        std::string ciphertext = decodedCiphertext.substr(offset);

        // Tải private key
        std::string secretKeyData;
        if (!LoadFile(privateKeyFile, secretKeyData, "Base64"))
            throw std::runtime_error("Failed to load private key.");
        const void *secretKey = rabe_cp_ac17_secret_key_from_json(secretKeyData.c_str());
        if (!secretKey)
            throw std::runtime_error("Failed to parse private key.");

        // Giải mã khóa ngẫu nhiên bằng CP-ABE
        const void *encryptedKey = rabe_cp_ac17_cipher_from_json(encryptedKeyB.c_str());
        if (!encryptedKey)
        {
            rabe_cp_ac17_free_secret_key(secretKey);
            throw std::runtime_error("Failed to load cipher.");
        }
        CBoxedBuffer recoveredKey = rabe_cp_ac17_decrypt(encryptedKey, secretKey);
        if (!recoveredKey.buffer)
        {
            const char *error = rabe_get_thread_last_error();
            rabe_cp_ac17_free_secret_key(secretKey);
            rabe_cp_ac17_free_cipher(encryptedKey);
            throw std::runtime_error(string("CP-ABE Decryption failed: ") + (error ? error : "Unknown error"));
        }
        CryptoPP::Integer recoveredRandomKey(reinterpret_cast<const CryptoPP::byte *>(recoveredKey.buffer), recoveredKey.len);
        SHA3_256 hash;
        std::string aesKey(hash.DigestSize(), 0);
        std::string recoveredKeyStr;
        recoveredRandomKey.Encode(StringSink(recoveredKeyStr).Ref(), recoveredRandomKey.MinEncodedSize());
        hash.Update(reinterpret_cast<const CryptoPP::byte *>(recoveredKeyStr.data()), recoveredKeyStr.size());
        hash.Final(reinterpret_cast<CryptoPP::byte *>(&aesKey[0]));

        std::string recovered;
        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte *>(aesKey.data()), aesKey.size(), iv);
        AuthenticatedDecryptionFilter df(decryptor, new StringSink(recovered), AuthenticatedDecryptionFilter::DEFAULT_FLAGS);
        StringSource ss2(ciphertext, true, new Redirector(df));
        if (!df.GetLastResult())
            throw std::runtime_error("Decryption failed: MAC not valid.");

        FileSink fileSink(recovertextFile);
        fileSink.Put(reinterpret_cast<const CryptoPP::byte *>(recovered.data()), recovered.size());
        std::cout << "Decryption successful!" << std::endl;
        // Giải phóng bộ nhớ các đối tượng nhạy cảm
        rabe_cp_ac17_free_secret_key(secretKey);
        rabe_cp_ac17_free_cipher(encryptedKey);
        return 0;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << "Crypto++ exception: " << ex.what() << std::endl;
        return -1;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return -1;
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " [setup|genkey|encrypt|decrypt]" << std::endl;
        return 1;
    }
    std::string mode = argv[1];
    try
    {
        if (mode == "setup")
        {
            if (argc < 3)
            {
                std::cerr << "Usage: " << argv[0] << " setup <path_to_save_file>" << std::endl;
                return 1;
            }
            setup(argv[2]);
        }
        else if (mode == "genkey")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " genkey <public_key_file> <master_key_file> <attributes> <private_key_file>" << std::endl;
                return 1;
            }
            generateSecretKey(argv[2], argv[3], argv[4], argv[5]);
        }
        else if (mode == "encrypt")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>" << std::endl;
                return 1;
            }
            AC17encrypt(argv[2], argv[3], argv[4], argv[5]);
        }
        else if (mode == "decrypt")
        {
            if (argc < 6)
            {
                std::cerr << "Usage: " << argv[0] << " decrypt <public_key_file> <private_key_file> <ciphertext_file> <recovertext_file>" << std::endl;
                return 1;
            }
            AC17decrypt(argv[2], argv[3], argv[4], argv[5]);
        }
        else
        {
            std::cerr << "Invalid command: " << mode << std::endl;
            std::cerr << "Usage: " << argv[0] << " [setup|genkey|encrypt|decrypt]" << std::endl;
            return 1;
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
