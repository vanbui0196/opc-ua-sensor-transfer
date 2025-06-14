#pragma once
#include <cstdint>
#include <iostream>
#include <random>
#include <array>
#include <cstdint>
#include <algorithm>
#include <functional>
#include <cstring> 
#include "config.h"
#include "constant.h"
#include "poly_algo.h"
#include "poly_vector.h"
#include "utils.h"

class MLDSA { 
private:
    bool test_mode;
    
    void SignInternal(uint8_t* SignMessage, size_t* SignMessageLength,
                      const uint8_t* Mesage, size_t MessageLength,
                      const uint8_t* Pre, size_t PreLenth, const std::array<uint8_t, RNDBYTES> randombuf, 
                      const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key);

    int VerifyInternal(const uint8_t* Signature, size_t SignatureLength, const uint8_t* Message, 
    size_t MessageLength, uint8_t* Pre, size_t PreLength, const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key);
public:
    MLDSA();
    MLDSA(bool mode);

    void pkEncode(const std::array<uint8_t, SEEDBYTES>& rho, PolyVector<K> t1, std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& pkArray);
    
    void skEncode(const std::array<uint8_t, SEEDBYTES>& rho, 
        const std::array<uint8_t, TRBYTES>& tr, 
        const std::array<uint8_t, SEEDBYTES>& key,
        PolyVector<L>& s1, PolyVector<K>& s2, PolyVector<K>& t0,
        std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& skArray);
                  
    void skDecode(std::array<uint8_t,SEEDBYTES>& rho, std::array<uint8_t, TRBYTES>& tr, std::array<uint8_t,SEEDBYTES>& key,
    PolyVector<K>& t0, PolyVector<L>& s1, PolyVector<K>& s2, const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key);

    void pkDecode(std::array<uint8_t,SEEDBYTES>& rho, PolyVector<K>& t1,const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key);

    void sigEncode(uint8_t* SignMessage, const std::array<uint8_t, CTILDEBYTES>& sample_in_ball_seed, 
        PolyVector<L>& z, 
        PolyVector<K>& h);

    int sigDecode(std::array<uint8_t, CTILDEBYTES>& sample_in_ball_seed, 
        PolyVector<L>& z, 
        PolyVector<K>& h,
        const uint8_t* Signature);

    void KeyGen(std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& pkInArr, std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& skInArr);

    int Sign(uint8_t* SignMessage, size_t* SignMessageLength,
              const uint8_t* Mesage, size_t MessageLength,
              const uint8_t* ctx, size_t ctxlen, 
              const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key);

    int Verify(const uint8_t* Signature, 
                size_t SignatureLength, 
                const uint8_t* Message, 
                size_t MessageLength, 
                const uint8_t* ctx,
                size_t ctxlen, const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key);

};