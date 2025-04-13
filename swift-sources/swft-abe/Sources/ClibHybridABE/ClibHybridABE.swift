import Foundation

// Đảm bảo rằng Swift biết về các hàm C này
@_silgen_name("setup")
func setup(_ path: UnsafePointer<CChar>) -> Int

@_silgen_name("generateSecretKey")
func generateSecretKey(_ publicKeyFile: UnsafePointer<CChar>, _ masterKeyFile: UnsafePointer<CChar>, _ attributes: UnsafePointer<CChar>, _ privateKeyFile: UnsafePointer<CChar>) -> Int

@_silgen_name("AC17encrypt")
func AC17encrypt(_ publicKeyFile: UnsafePointer<CChar>, _ plaintextFile: UnsafePointer<CChar>, _ policy: UnsafePointer<CChar>, _ ciphertextFile: UnsafePointer<CChar>) -> Int

@_silgen_name("AC17decrypt")
func AC17decrypt(_ publicKeyFile: UnsafePointer<CChar>, _ privateKeyFile: UnsafePointer<CChar>, _ ciphertextFile: UnsafePointer<CChar>, _ recovertextFile: UnsafePointer<CChar>) -> Int

// Hàm setup
if let pathCString = "setup".cString(using: .utf8) {
    let result = setup(pathCString)
    print("Setup result: \(result)")
} else {
    print("Failed to convert string to UTF-8 for setup.")
}

// Hàm generateSecretKey
if let publicKeyFileCString = "setup/public_key.key".cString(using: .utf8),
   let masterKeyFileCString = "setup/master_key.key".cString(using: .utf8),
   let attributesCString = "A B C D".cString(using: .utf8),
   let privateKeyFileCString = "setup/private.key".cString(using: .utf8) {
    let result = generateSecretKey(publicKeyFileCString, masterKeyFileCString, attributesCString, privateKeyFileCString)
    print("Generate Secret Key result: \(result)")
} else {
    print("Failed to convert string to UTF-8 for generateSecretKey.")
}

// Hàm AC17encrypt
if let publicKeyFileCString = "setup/public_key.key".cString(using: .utf8),
   let plaintextFileCString = "setup/plaintext.txt".cString(using: .utf8),
   let policyCString = "((A or B) and C)".cString(using: .utf8),
   let ciphertextFileCString = "setup/ciphertextFile.txt".cString(using: .utf8) {
    let result = AC17encrypt(publicKeyFileCString, plaintextFileCString, policyCString, ciphertextFileCString)
    print("AC17encrypt result: \(result)")
} else {
    print("Failed to convert string to UTF-8 for AC17encrypt.")
}

// Hàm AC17decrypt
if let publicKeyFileCString = "setup/public_key.key".cString(using: .utf8),
   let privateKeyFileCString = "setup/private.key".cString(using: .utf8),
   let ciphertextFileCString = "setup/ciphertextFile.txt".cString(using: .utf8),
   let recovertextFileCString = "setup/recovertextFile.txt".cString(using: .utf8) {
    let result = AC17decrypt(publicKeyFileCString, privateKeyFileCString, ciphertextFileCString, recovertextFileCString)
    print("AC17decrypt result: \(result)")
} else {
    print("Failed to convert string to UTF-8 for AC17decrypt.")
}
