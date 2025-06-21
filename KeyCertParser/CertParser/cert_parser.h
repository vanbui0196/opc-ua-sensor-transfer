/**
 * @file cert_parser.h
 * @author Khanh Van Buii
 * @brief C++ wrapper for Certificate Parser of OpenSSL
 * @version 0.1.0
 * @date 2025-06-19
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

class CertParser {
public:
    // Certificate main attribute
    std::vector<uint8_t> publicKey;
    std::string certVersion;
    std::string serialNumber;
    std::string subjectInfo;
    std::string issuerInfo;
    time_t certValidBefore;
    time_t certValidAfter;
    std::string certSignatureType;

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
     * @brief Check if the certificate is valid (time, signature)
     * 
     * @return true VALID
     * @return false NOT_VALID
     */
    bool certIsValid();

    // Constructor
    CertParser(fs::path filePath);
    ~CertParser();

    // Fobidded operator, object handler shall not be delegated
    CertParser& operator=(const CertParser&) = delete;
    CertParser& operator=(CertParser&&) noexcept = delete;
    CertParser(const CertParser&) = delete;
    CertParser(CertParser&&) = delete;
private:
    /* Certificate validity information */
    struct {
        bool certSigValid = false;
        bool certTimeValid = false;
    } CertValidInfo;
    /**
     * @brief Function to get the general information of the certificate
     * 
     * @param cert Pointer to the certificate
     */
    void readCertInfo(const x509_unique_ptr& cert);

    /**
     * @brief Get the Public Key from the certificate
     * 
     * @param cert Pointer to the certificate
     */
    void readCertPubkey(const x509_unique_ptr& cert);

    /**
     * @brief Update the certificate validity
     * 
     * @param cert Pointer to the certificate
     */
    void certValidate(const x509_unique_ptr& cert);

    time_t asn1_timeConversion(const ASN1_TIME* timePtr);
};