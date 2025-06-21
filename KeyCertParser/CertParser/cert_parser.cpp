/**
 * @file cert_parser.cpp
 * @author Khanh Van Bui
 * @brief Encapsulation for the OpenSSL library of certificate handler
 * @version 0.1
 * @date 2025-06-20
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "cert_parser.h"

CertParser::CertParser(fs::path filePath) {

    // OpenSSL init
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Load the file from certificate
    FILE* filePointer = fopen(filePath.c_str(), "rb");
    if(nullptr == filePointer) {
        throw std::runtime_error("[CertParser Constructor] Cannot open the certificate file");
    }
    
    // Get the certificate with th
    x509_unique_ptr cert{d2i_X509_fp(filePointer, nullptr)};
    
    // Close the file pointer
    fclose(filePointer);
    
    // Validate if the pointer is valid
    if(nullptr == cert.get()) {
        throw std::runtime_error("[CertParser Constructor] Cannot get the certificate content from .DER file");
    }

    // Get the certificate
    this->readCertInfo(cert);

    // Get the public key from certificate
    this->readCertPubkey(cert);

    // Validate if the certificate -> update the certificate
    this->certValidate(cert);
}

void CertParser::readCertInfo(const x509_unique_ptr& cert) {
    
    if(nullptr == cert) {
        throw std::runtime_error("[CertParser] Certificate is notable to be handled");
    }

    /* Local variable */
    char* ptrTmpString; // temporary variable for holding the memory
    
    /* ====== Get the certificate version ====== */
    long _version = X509_get_version(cert.get());
    this->certVersion = "X509 v" + std::to_string(_version + 1);

    /* ====== Get the certificate number ====== */
    // get the number in the ASN1 format
    ASN1_INTEGER* serialNumber = X509_get_serialNumber(cert.get());
    
    // convert the number to bignum format
    bignum_unique_ptr bigNumSerial(ASN1_INTEGER_to_BN(serialNumber, nullptr));
    ptrTmpString = BN_bn2hex(bigNumSerial.get());

    // update the serial number (copy to global number)
    this->serialNumber = ptrTmpString;

    // free data for next information
    OPENSSL_free(ptrTmpString);

    /* ====== Get the subject info ====== */
    X509_NAME* subjecdInfo = X509_get_subject_name(cert.get());

    // get the pointer to the subject information
    ptrTmpString = X509_NAME_oneline(subjecdInfo, nullptr, 0);

    // store the variable object attribute
    this->subjectInfo = ptrTmpString;

    // free data fro next information
    OPENSSL_free(ptrTmpString);

    /* ====== Get the issuer info ====== */
    X509_NAME* issuerInfo = X509_get_issuer_name(cert.get());

    // get the pointer to the issuer information
    ptrTmpString = X509_NAME_oneline(issuerInfo, nullptr, 0);

    // store the data to object attribute
    this->issuerInfo = ptrTmpString;

    // free the memory for the next object
    OPENSSL_free(ptrTmpString);

    /* ====== Get the time validity ====== */
    // temporary for convertion time
    tm temp_time;

    ASN1_TIME* after_asn1Time = X509_get_notBefore(cert.get());
    ASN1_TIME* before_ans1Time = X509_get_notAfter(cert.get());

    this->certValidBefore = this->asn1_timeConversion(before_ans1Time);
    this->certValidAfter = this->asn1_timeConversion(after_asn1Time);

    /* Note: It is not required and shall not free the memory pointed by the pointer */

    /* ====== Get the signature type ====== */
    const X509_ALGOR* sigAlgo;

    // Fetch the signature from certificate
    X509_get0_signature(nullptr, &sigAlgo, cert.get());

    const ASN1_OBJECT* sigAlgoObj;
    X509_ALGOR_get0(&sigAlgoObj, nullptr, nullptr, sigAlgo);

    std::array<char,128> sigAlgoName; sigAlgoName.fill(0);
    OBJ_obj2txt(sigAlgoName.data(), sigAlgoName.size(), sigAlgoObj, 0);

    // Get the signature name from the certificate
    this->certSignatureType = sigAlgoName.data();
}

time_t CertParser::asn1_timeConversion(const ASN1_TIME* timePtr) {
    
    // Temporary variable to hold the conversion
    struct tm tm_time = {};
    
    if (ASN1_TIME_to_tm(timePtr, &tm_time) != 1) {
        throw std::runtime_error("Failed to convert ASN1_TIME");
    }
    return timegm(&tm_time);
}

void CertParser::readCertPubkey(const x509_unique_ptr& cert) {
    
    /* Local variable */
    int tmpRetVal = 0;

    if(nullptr == cert) {
        throw std::runtime_error("[Pubkey] Content of certificate is not readible");
    }

    // call the openssl api to get the public key
    evp_key_unique_ptr pubKeyPtr(X509_get_pubkey(cert.get()));

    if(nullptr == pubKeyPtr) {
        throw std::runtime_error("[Pubkey] Null pointer is returned on the public key");
    }

    // Convert the key to IO format for storing
    size_t keyLength = 0;

    // First call to get the key length
    tmpRetVal = EVP_PKEY_get_raw_public_key(pubKeyPtr.get(), nullptr, &keyLength);

    if(1 != tmpRetVal) {
        throw std::runtime_error("[Pub Key] Cannot get the public key from certificate");
    }

    // Allocate memory for the key
    std::vector<uint8_t> tmpPubkey(keyLength);

    // Recall the API again to get the key value
    tmpRetVal = EVP_PKEY_get_raw_public_key(pubKeyPtr.get(), tmpPubkey.data(), &keyLength);

    if(1 != tmpRetVal) {
        throw std::runtime_error("[Pub Key] Cannot get the public key from certificate");
    }

    // Get the data for the object attribute
    this->publicKey = std::move(tmpPubkey);
}

void CertParser::certValidate(const x509_unique_ptr& cert) {
    /* Local variable */
    int locVerifyResult{0};
    bool locTimeValidity = false;

    if(nullptr == cert) {
        throw std::runtime_error("[Certificate Validate] Certificate is Null");
    }

    /* --- VERIFY THE CERTIFICATE VALIDITY ---*/
    // call the openssl api to get the public key
    evp_key_unique_ptr pubKeyPtr(X509_get_pubkey(cert.get()));

    if(nullptr == pubKeyPtr) {
        throw std::runtime_error("[Certificate Validate] Null pointer is returned on the public key");
    }

    // call the openssl api to verify the certificate
    locVerifyResult = X509_verify(cert.get(), pubKeyPtr.get());

    if(1 == locVerifyResult) {
        this->CertValidInfo.certSigValid = true;
    }

    /* --- VERIFY THE CERTIFICATE DATE VALIDITY ---*/
    // Get the current time
    time_t currentTime = time(nullptr);

    // Check if this->cerValidAfter < currentTime < this->cerValidBefore
    if((this->certValidAfter < currentTime) && (currentTime < this->certValidBefore)) {
        locTimeValidity = true;
    }
    this->CertValidInfo.certTimeValid = locTimeValidity;
    
}

bool CertParser::certIsValid() {
    // Return value
    bool retVal = false;

    // Update the return value
    if((this->CertValidInfo.certSigValid == true) && (this->CertValidInfo.certTimeValid == true)) {
        retVal = true;
    } else {
        retVal = false;
    }
    return retVal;
}

CertParser::~CertParser() {
    // Clear all the thing from the OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}