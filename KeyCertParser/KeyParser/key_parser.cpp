/**
 * @file key_parser.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-06-21
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "key_parser.h"

KeyParser::KeyParser(fs::path filePath, std::string algoName) {
    // OpenSSL init
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load the file from certificate
    FILE* filePointer = fopen(filePath.c_str(), "rb");
    if(nullptr == filePointer) {
        throw std::runtime_error("[CertParser Constructor] Cannot open the key file");
    }

    // Get the key pointer with the openssl api
    evp_key_unique_ptr privateKey_ptr(d2i_PrivateKey_fp(filePointer, nullptr));
    
    // close the file
    fclose(filePointer);

    if(nullptr == privateKey_ptr) {
        throw std::runtime_error("Can not get the private key from the file.");
    }

    // Check if the expected name is correct
    if(EVP_PKEY_is_a(privateKey_ptr.get(), algoName.c_str())) {
        // Coppy the algorithm name to
        this->algorithmName = algoName;
    } else {
        throw std::runtime_error("Key file is not contains key of: " + algoName);
    }

    /* --- GET THE PRIVATE KEY NAME --- */
    const char* tempString = EVP_PKEY_get0_type_name(privateKey_ptr.get());
    
    // store the public key to the algorithms name
    this->algorithmName = tempString;

    /* --- GET THE PRIVATE KEY ID --- */
    this->keyId = EVP_PKEY_get_id(privateKey_ptr.get());

    /* --- GET THE KEY SIZE --- */
    this->keySize = EVP_PKEY_get_size(privateKey_ptr.get());

    /* --- GET THE SECURITY BIT --- */
    this->securityBits = EVP_PKEY_get_security_bits(privateKey_ptr.get());

    /* --- GET THE PRIVATE KEY CONTENT --- */
    this->getPrivKey(privateKey_ptr);

}

void KeyParser::getPrivKey(const evp_key_unique_ptr& evpKeyPtr) {
    // temporary check val
    int tempCheckValue{0};
    
    if(nullptr == evpKeyPtr) {
        throw std::runtime_error("[KeyParser][Constructor][getPrivKey] Cannot get the pointer structure");
    }

    // holder of the key size
    size_t privKeySize{0};

    // Get the key size first 
    tempCheckValue = EVP_PKEY_get_raw_private_key(evpKeyPtr.get(), nullptr, &privKeySize);

    if(tempCheckValue != 1) {
        throw std::runtime_error("[KeyParser][Constructor][getPrivKey] Cannot get the public key");
    }

    // Now actually get the key size
    std::vector<uint8_t> tempPrivateKey(privKeySize);
    tempCheckValue = EVP_PKEY_get_raw_private_key(evpKeyPtr.get(), tempPrivateKey.data(), &privKeySize);

    if(tempCheckValue != 1) {
        throw std::runtime_error("[KeyParser][Constructor][getPrivKey] Cannot get the public key");
    }

    // Move the vector back to the global
    this->privateKey = std::move(tempPrivateKey);
}


KeyParser::~KeyParser() {
    /* Clean all the artifact of the OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
}