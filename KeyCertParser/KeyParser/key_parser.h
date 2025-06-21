/**
 * @file key_parser.h
 * @author your name (you@domain.com)
 * @brief Wrapper for openssl in reading the key in C++
 * @version 0.1
 * @date 2025-06-21
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <array>
#include <stdexcept>
#include <iostream>
#include <string>
#include <memory>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

class KeyParser {
public:
    /* Private and the public key of the key */
    std::vector<uint8_t> privateKey;
    std::string algorithmName;
    size_t keySize;
    int keyId;
    int securityBits;

    // Deleter functor for std::unique_ptr
    class X509_Deleter {
        public:
        void operator()(X509* cert) {if(cert) X509_free(cert);}
    };

    class EVP_PKEY_Deleter {
        public:
        void operator()(EVP_PKEY* pkey) {if(pkey) EVP_PKEY_free(pkey);}
    };

    class BIO_Deleter {
        public:
        void operator()(BIO* bio) {if(bio) BIO_free(bio);}
    };

    class BIGNUM_Deleter {
        public:
        void operator()(BIGNUM* bignum) {if(bignum) BN_free(bignum);}
    };

    // Redefine the unique pointer
    using x509_unique_ptr = std::unique_ptr<X509, X509_Deleter>;
    using evp_key_unique_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
    using bio_unique_ptr = std::unique_ptr<BIO, BIO_Deleter>;
    using bignum_unique_ptr = std::unique_ptr<BIGNUM, BIGNUM_Deleter>;


    /**
     * @brief Construct a new Key Parser object
     * 
     * @param file_path Path to the location of Key
     * @param algoName Algorithm name (will be validated)
     */
    KeyParser(fs::path filePath, std::string algoName);

    ~KeyParser(); 

    // Fobbiden method, object shall not coppy or move to other object
    KeyParser& operator=(const KeyParser&) = delete;
    KeyParser& operator=(KeyParser&&) noexcept = delete;
    KeyParser(const KeyParser&) = delete;
    KeyParser(KeyParser&&) = delete;

private:
    /**
     * @brief Get the Priv Key object. Just to make the module easier to read
     * 
     * @param evpKeyPtr Pointer to the EVP_KEY.
     */
    void getPrivKey(const evp_key_unique_ptr& evpKeyPtr);
};