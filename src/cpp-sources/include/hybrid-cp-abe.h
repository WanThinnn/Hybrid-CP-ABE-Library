#ifndef HYBRID_CP_ABE_H
#define HYBRID_CP_ABE_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#ifdef BUILD_DLL
// Khi xây dựng (export) thư viện DLL
#define LIB_API __declspec(dllexport)
#elif defined(USE_DLL)
// Khi sử dụng (import) thư viện DLL
#define LIB_API __declspec(dllimport)
#else
// Khi sử dụng thư viện tĩnh
#define LIB_API
#endif
#else
// Với các hệ điều hành khác không cần định nghĩa đặc biệt
#define LIB_API
#endif

// ============================================================================
// Constants
// ============================================================================
namespace HybridCPABE {
    constexpr size_t GCM_IV_SIZE = 12;          // 96-bit theo NIST SP 800-38D
    constexpr size_t AES_KEY_SIZE = 32;         // 256-bit AES key
    constexpr uint8_t FORMAT_VERSION = 0x01;    // Ciphertext format version
    const char* const LIB_VERSION = "2.0.0";
    const char* const DEFAULT_KEY_FORMAT = "Base64";
}

// ============================================================================
// Error Codes
// ============================================================================
typedef enum {
    HCPABE_SUCCESS = 0,
    HCPABE_ERR_FILE_NOT_FOUND = -1,
    HCPABE_ERR_INVALID_KEY = -2,
    HCPABE_ERR_POLICY_MISMATCH = -3,
    HCPABE_ERR_CRYPTO_FAILED = -4,
    HCPABE_ERR_INVALID_PARAM = -5,
    HCPABE_ERR_MEMORY = -6,
    HCPABE_ERR_UNSUPPORTED_FORMAT = -7,
    HCPABE_ERR_VERSION_MISMATCH = -8
} HCPABEError;

// ============================================================================
// C API - File-based Operations
// ============================================================================
extern "C"
{
    // Khởi tạo hệ thống - tạo Master Key và Public Key
    LIB_API int setup(const char *path);
    
    // Tạo Private Key từ tập thuộc tính
    // Đã xóa tham số publicKeyFile không sử dụng
    LIB_API int generateSecretKey(const char *masterKeyFile, 
                                   const char *attributes, 
                                   const char *privateKeyFile);
    
    // Mã hóa file với chính sách truy cập
    LIB_API int AC17encrypt(const char *publicKeyFile, 
                            const char *plaintextFile, 
                            const char *policy, 
                            const char *ciphertextFile);
    
    // Giải mã file (cần thuộc tính thỏa mãn policy)
    LIB_API int AC17decrypt(const char *publicKeyFile, 
                            const char *privateKeyFile, 
                            const char *ciphertextFile, 
                            const char *recovertextFile);

    // ========================================================================
    // Buffer-based Operations (API mới)
    // ========================================================================
    
    // Mã hóa từ buffer
    LIB_API int AC17encryptBuffer(
        const unsigned char *publicKey, size_t pkLen,
        const unsigned char *plaintext, size_t ptLen,
        const char *policy,
        unsigned char **ciphertext, size_t *ctLen
    );
    
    // Giải mã từ buffer
    LIB_API int AC17decryptBuffer(
        const unsigned char *privateKey, size_t skLen,
        const unsigned char *ciphertext, size_t ctLen,
        unsigned char **plaintext, size_t *ptLen
    );
    
    // ========================================================================
    // Utility Functions
    // ========================================================================
    
    // Lấy phiên bản thư viện
    LIB_API const char* getVersion(void);
    
    // Lấy thông báo lỗi từ error code
    LIB_API const char* getErrorMessage(int errorCode);
    
    // Giải phóng buffer được cấp phát bởi thư viện
    LIB_API void freeBuffer(unsigned char *buffer);
}

#endif // HYBRID_CP_ABE_H
