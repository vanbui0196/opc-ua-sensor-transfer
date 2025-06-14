#include "mldsa.h"


MLDSA::MLDSA() : test_mode{false} {
}

MLDSA::MLDSA(bool mode) : test_mode{mode} {
}

void MLDSA::KeyGen(std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& pkArray, 
    std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& skArray) {

    // Polynomial components
    PolyMatrix<L, K> A;                    // Public matrix
    PolyVector<K> t;                       // Public key vector
    PolyVector<K> t1;                      // Public key vector (high bits)
    PolyVector<L> s1;                      // Secret key vector
    PolyVector<K> s2;                      // Secret key vector
    PolyVector<K> t0;                      // Secret key vector (low bits)

    // array for get random value
    std::array<uint8_t, SEEDBYTES + CRHBYTES + SEEDBYTES> seedbuf; // buffer for sheed byte
    std::array<uint8_t, TRBYTES> tr; // buffer for the tr part
    std::array<uint8_t, SEEDBYTES> rho;
    std::array<uint8_t, CRHBYTES> rhoprime;
    std::array<uint8_t, SEEDBYTES> key;

    // initalize the variable to zero
    seedbuf.fill(0);
    tr.fill(0);
    rho.fill(0);
    rhoprime.fill(0);
    key.fill(0);


    if(true == this->test_mode) {
        for(size_t i = 0; i < SEEDBYTES; i++) {
            seedbuf.at(i) = i;
        }
    }
    else 
    {
        // Use kernel to get the random values
        bool retVal = false;
        do {
            retVal = mldsa::utils::get_random_bytes(seedbuf.data(), SEEDBYTES);
        } while(retVal == false);
    }

    seedbuf[SEEDBYTES+0] = K;
    seedbuf[SEEDBYTES+1] = L;
    shake256(seedbuf.data(), 2*SEEDBYTES + CRHBYTES, seedbuf.data(), SEEDBYTES+2);

    // Copy the array
    std::copy(seedbuf.begin(), seedbuf.begin() + SEEDBYTES, rho.begin());
    std::copy(seedbuf.begin() + SEEDBYTES, seedbuf.begin() + SEEDBYTES + CRHBYTES, rhoprime.begin());
    std::copy(seedbuf.begin() + SEEDBYTES + CRHBYTES, seedbuf.begin() + SEEDBYTES + CRHBYTES + SEEDBYTES, key.begin());

    // smaple the matrix A based on the rho -> having A -> Â actually
    A.expand(rho); //tested
    
    // sample the vector s1 and s2 -> having s1, s2
    s1.vector_uniform_eta(rhoprime, 0); // tested
    s2.vector_uniform_eta(rhoprime, L); //tested

    PolyVector<L> s1_hat = s1;
    s1_hat.vector_NTT();
    t = matrix_multiply(A, s1_hat); //-> t = A * s1
    t.vector_reduced();
    t.vector_invNTT(); // tested

    t = t + s2; //-> t = A*s1 + s2

    t.vector_caddq(); // -> adding the value to the coefficient in case of negative

    // Extract highbit and low bit part
    t.vector_power2round(t1, t0); // -> decompose the vector (t1, t0) -> tested

    // encode the public key
    this->pkEncode(rho,t1,pkArray); // tested -> pk

    // compute the tr for the private key
    shake256(tr.data(), TRBYTES, pkArray.data(), CRYPTO_PUBLICKEYBYTES); // tested

    // pack the secret key
    this->skEncode(rho,tr,key,s1,s2,t0,skArray); // tested

}

/**
 * @brief Encode the public key
 * TESTED
 * @param rho 
 */
void MLDSA::pkEncode(const std::array<uint8_t, SEEDBYTES>& rho, PolyVector<K> t1,std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& pkArray) {
    
    // Copy rho into the public key
    for(size_t i = 0; i < SEEDBYTES; i++) {
        pkArray[i] = rho.at(i);
    }

    // pack the vector to the buffer
    t1.vector_packt1(pkArray.data() + SEEDBYTES);
}

void MLDSA::pkDecode(std::array<uint8_t,SEEDBYTES>& rho, PolyVector<K>& t1,const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key) {
    size_t track_pos{0};

    for(size_t i = 0; i < SEEDBYTES; i++) {
        rho.at(i) = public_key.at(i);
    }
    track_pos += SEEDBYTES;

    t1.vector_unpackt1(public_key.data() + track_pos);
}

/**
 * @brief Encode secret key
 * TESTED
 * @param rho Seed
 * @param tr Hash public key
 * @param key 
 */
void MLDSA::skEncode(const std::array<uint8_t, SEEDBYTES>& rho, 
    const std::array<uint8_t, TRBYTES>& tr, 
    const std::array<uint8_t, SEEDBYTES>& key,
    PolyVector<L>& s1, PolyVector<K>& s2, PolyVector<K>& t0,
    std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& skArray) 
{
    size_t adding_pos{0};
    // copy the data from rho in to secret key
    std::copy(rho.begin(),rho.end(), skArray.begin() + adding_pos);
    adding_pos += SEEDBYTES;

    // copy the data from key in secret key buffer
    std::copy(key.begin(),key.end(), skArray.begin() + adding_pos);
    adding_pos+= SEEDBYTES;

    // copy the data from tr (hash of the public key) in to secret key
    std::copy(tr.begin(),tr.end(), skArray.begin() + adding_pos);
    adding_pos+= TRBYTES;

    // pack s1 -> secret key buffer (L size)
    s1.vector_packeta(skArray.data() + adding_pos);
    adding_pos += L * POLYETA_PACKEDBYTES;

    // pack s2 -> secret key buffer (K size)
    s2.vector_packeta(skArray.data() + adding_pos);
    adding_pos += K * POLYETA_PACKEDBYTES;

    // pack t0 into buffer
    t0.vector_packt0(skArray.data() + adding_pos);
    adding_pos += K * POLYT0_PACKEDBYTES; // this does not has any purpose
}

/**
 * @brief Decode SK
 * TESTED
 * @param rho rho for Matrix
 * @param tr hash of PK
 * @param key 
 * @param t0 t0 vector
 * @param s1 secret key
 * @param s2 secret key
 * @param secret_key array of secret key
 */
void MLDSA::skDecode(std::array<uint8_t,SEEDBYTES>& rho, std::array<uint8_t, TRBYTES>& tr, std::array<uint8_t,SEEDBYTES>& key,
              PolyVector<K>& t0, PolyVector<L>& s1, PolyVector<K>& s2, const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key) 
{
    // Position tracking variable
    size_t tracking_pos{0};

    // Copy data from secrekey in to the rho
    for(size_t i = 0; i < SEEDBYTES; i++) {
        rho.at(i) = secret_key.at(tracking_pos + i);
    }
    tracking_pos += SEEDBYTES;

    // Copy data from secrekey in to the KEY
    for(size_t i = 0; i < SEEDBYTES; i++) {
        key.at(i) = secret_key.at(tracking_pos + i);
    }
    tracking_pos += SEEDBYTES;

    // Copy data from secrekey in to the TR
    for(size_t i = 0; i < TRBYTES; i++) {
        tr.at(i) = secret_key.at(tracking_pos + i);
    }
    tracking_pos += TRBYTES;

    // Unpack the data in to s1 vector
    s1.vector_unpacketa(secret_key.data() + tracking_pos);
    tracking_pos += L*POLYETA_PACKEDBYTES;

    // Upack the data into s2 vector
    s2.vector_unpacketa(secret_key.data() + tracking_pos);
    tracking_pos += K*POLYETA_PACKEDBYTES;

    //Unpack the data into t0 vector
    t0.vector_unpackt0(secret_key.data() + tracking_pos);
    tracking_pos += K * POLYT0_PACKEDBYTES; // not needed, just for the fullfilment
}


int MLDSA::Sign(uint8_t* SignMessage, size_t* SignMessageLength,
    const uint8_t* Mesage, size_t MessageLength,
    const uint8_t* ctx, size_t ctxlen, const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key) 
{
    uint8_t Pre[257] = {0};

    // Error case
    if(ctxlen > 255) {
        return -1;
    }

    // CTX handling
    Pre[0] = 0; Pre[1] = ctxlen;
    for(size_t i = 0; i < ctxlen; i++)
    {
        Pre[2 + i] = ctx[i];
    }

    // Handling the buffer mode
    std::array<uint8_t, RNDBYTES> random_buffer = {0};

    if(this->test_mode == false) {
        mldsa::utils::get_random_bytes(random_buffer.data(), RNDBYTES);
    }

    // Call the internal method for handling the Signing
    SignInternal(SignMessage, SignMessageLength, Mesage, MessageLength, Pre, ctxlen + 2, random_buffer, secret_key);

    return 0;
}

void MLDSA::SignInternal(uint8_t* SignMessage, size_t* SignMessageLength,
    const uint8_t* Mesage, size_t MessageLength,
    const uint8_t* Pre, size_t PreLenth, const std::array<uint8_t, RNDBYTES> randombuf, 
    const std::array<uint8_t, CRYPTO_SECRETKEYBYTES>& secret_key) 
{

    // local variable
    bool valid_signature{false};
    uint16_t nonce{0};
    uint32_t total_hint{0};

    // Local matrix and vector
    PolyMatrix<L, K> A;                       // Public matrix

    // Local variable (unpack key)
    std::array<uint8_t,SEEDBYTES> rho = {0}; 
    std::array<uint8_t, TRBYTES> tr = {0}; 
    std::array<uint8_t,SEEDBYTES> key = {0};
    PolyVector<K> t0; 
    PolyVector<L> s1; 
    PolyVector<K> s2;
    PolyVector<L> y, z;
    PolyVector<K> w, w1, w0, h;
    

    // Local variable (Seed of Shake)
    std::array<uint8_t, CRHBYTES> mu{0};        // µ
    std::array<uint8_t, CRHBYTES> rhoprime{0};  // ϱ"
    std::array<uint8_t, CTILDEBYTES> sample_in_ball_seed;    // seed for the sample in ball function

    // Local variable (sample in ball)
    Polynomial challengePoly;                   // c̃

    // Local variable (shake)
    keccak_state hashState;

    // Line 1: Decode the secret key
    this->skDecode(rho,tr,key,t0,s1,s2,secret_key); // check that rho,tr,key,t0,s1,s2 having same value

    // Line 2: convert s1 to the NTT domain
    s1.vector_NTT();

    // Line 3: convert s2 to NTT domain
    s2.vector_NTT();

    // Line 4: convert t0 in to t0 domain
    t0.vector_NTT();

    // Line 5: Sample A in NTT domain
    A.expand(rho); // check that A has the correct value

    /* Line 6: Compute µ = H(tr, M' = (Pre + Message)) -> 64 bytes, note: M' = 0 + ctxlen + ctx + M */
    shake256_init(&hashState);
    shake256_absorb(&hashState, tr.data(), TRBYTES);
    shake256_absorb(&hashState, Pre, PreLenth);
    shake256_absorb(&hashState, Mesage, MessageLength);
    shake256_finalize(&hashState);
    shake256_squeeze(mu.data(), CRHBYTES, &hashState);

    /* Line 7:  Compute ϱ" (rhoprime) = H(K, rnd, muy) -> 64 bytes */ // tested that rhoprime and mu has the same data with the test code
    shake256_init(&hashState);
    shake256_absorb(&hashState, key.data(), SEEDBYTES);
    shake256_absorb(&hashState, randombuf.data(), RNDBYTES);
    shake256_absorb(&hashState, mu.data(), CRHBYTES);
    shake256_finalize(&hashState);
    shake256_squeeze(rhoprime.data(), CRHBYTES, &hashState);

    // Move to while statement since goto never a good ideas of handling
    while(false == valid_signature) {
        // Line 11 sample y
        y.vector_uniform_gamma1(rhoprime, nonce++); // TESTED

        // store the vector z
        z = y; /* deep copy */
        z.vector_NTT();

        /*Line 12 w = A * y  -> return w in polynomial domain */
        w = matrix_multiply(A, z); // TESTED
        w.vector_reduced();
        w.vector_invNTT();
        w.vector_caddq();

        // Line 13, decompose
        w.vector_decompose(w1,w0); // TESTED

        // Line 15 c̃ = H(mu, w1Encode(packw1),CTILDEBYTES)
        w1.vector_packw1(SignMessage);
        shake256_init(&hashState);
        shake256_absorb(&hashState, mu.data(), CRHBYTES);
        shake256_absorb(&hashState, SignMessage, K*POLYW1_PACKEDBYTES);
        shake256_finalize(&hashState);
        shake256_squeeze(SignMessage, CTILDEBYTES, &hashState); // CTILDEBYTES = LAMBDA / 4

        // Line 16 c = SampleInBall(c̃)
        std::memcpy(sample_in_ball_seed.data(), SignMessage, CTILDEBYTES);
        challengePoly.polynomial_sample_in_ball(sample_in_ball_seed); // TESTED

        // Line 17: ĉ = NTT(c)
        challengePoly.NTT();

        // Line 18 temporary z = <<c*s1>> = c * s1
        vector_and_poly_pointwise_multiply(z, challengePoly, s1);
        z.vector_invNTT();

        // Line 20 z = y + <<c*s1>> 
        z = z + y;  // TESTED
        z.vector_reduced();

        // Line 23: check norm form GAMMA1 - BETA
        if(z.vector_checknorm(GAMMA1 - BETA)) {
            continue;
        }

        // Line 19 temporary h = <<c*s2>> = c * s2
        vector_and_poly_pointwise_multiply(h, challengePoly, s2);
        h.vector_invNTT();
        
        // Line 21: r0 = LowBits(w - h) = LowBits(w - <<c*s2>>)
        w0 = w0 - h; // w0 - <<c*s2>> Tested
        w0.vector_reduced(); // TESTED

        // Line 23: Check norm for GAMMA2 - BETA
        if(w0.vector_checknorm(GAMMA2 - BETA)) {
            continue;
        }

        // Line 25: Compute hint
        //h = <<c * t0>>
        vector_and_poly_pointwise_multiply(h, challengePoly, t0);
        h.vector_invNTT();
        h.vector_reduced(); // h = <<c * t0>> TESTED

        // Line 28: Check boundary for the hint
        if(h.vector_checknorm(GAMMA2)) {
            continue;
        }
        // Line 26
        w0 = w0 + h; // w0 = w0 - <<c*s2>> +  <<c * t0>> // tested
        total_hint = vector_make_hint(h, w0, w1); //tested

        if(total_hint > OMEGA) {
            continue;
        }

        valid_signature = true;

    } // end of sampling the y matix
    *SignMessageLength = CRYPTO_BYTES;
    this->sigEncode(SignMessage,sample_in_ball_seed,z,h);

}


int MLDSA::Verify(const uint8_t* Signature, 
    size_t SignatureLength, 
    const uint8_t* Message, 
    size_t MessageLength, 
    const uint8_t* ctx,
    size_t ctxlen, const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key) 
{
    uint8_t Pre[257];

    if(ctxlen > 255)
    {
        return -1;
    }

    Pre[0] = 0;
    Pre[1] = ctxlen;
    for(size_t i = 0; i < ctxlen; i++)
    {
        Pre[2 + i] = ctx[i];
    }
    return this->VerifyInternal(Signature, SignatureLength, Message, MessageLength, Pre, ctxlen + 2, public_key);
}

int MLDSA::VerifyInternal(const uint8_t* Signature, 
    size_t SignatureLength, 
    const uint8_t* Message, 
    size_t MessageLength, uint8_t* Pre, size_t PreLength, const std::array<uint8_t, CRYPTO_PUBLICKEYBYTES>& public_key)
{
    // Local variable
    std::array<uint8_t, K * POLYW1_PACKEDBYTES> buf = {0};
    std::array<uint8_t, SEEDBYTES> rho = {0};
    std::array<uint8_t, CRHBYTES> mu = {0};
    std::array<uint8_t, CTILDEBYTES> sample_in_ball_seed = {0};
    std::array<uint8_t, CTILDEBYTES> sample_in_ball_seed2 = {0};

    Polynomial poly_challenge;
    PolyMatrix<L, K> A;
    PolyVector<L> z;

    PolyVector<K> t1,w1,h;
    keccak_state state;

    if(SignatureLength != CRYPTO_BYTES) {
        return -1;
    }

    this->pkDecode(rho,t1,public_key); // TESTED
    
    if(1 == this->sigDecode(sample_in_ball_seed, z, h, Signature)) {
        return -1;
    } // TESTED (z,h, sambple_in_ball_seed has the correct value)

    if(z.vector_checknorm(GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute H(H(rho, t1), pre, msg) */
    shake256(mu.data(), TRBYTES, public_key.data(), CRYPTO_PUBLICKEYBYTES);
    shake256_init(&state);
    shake256_absorb(&state, mu.data(), TRBYTES);
    shake256_absorb(&state, Pre, PreLength);
    shake256_absorb(&state, Message, MessageLength);
    shake256_finalize(&state);
    shake256_squeeze(mu.data(), CRHBYTES, &state);

    // Signature verification
    poly_challenge.polynomial_sample_in_ball(sample_in_ball_seed);
    A.expand(rho);

    z.vector_NTT();
    w1 = matrix_multiply(A,z); //TESTED

    poly_challenge.NTT();
    t1.vector_shiftl();
    t1.vector_NTT();
    vector_and_poly_pointwise_multiply(t1,poly_challenge,t1); // TESTED



    w1 = w1 - t1;
    w1.vector_reduced();
    w1.vector_invNTT(); // TESTED
    

    w1.vector_caddq();

    vector_use_hint(w1,w1,h); // TESTED

    w1.vector_packw1(buf.data());

    shake256_init(&state);
    shake256_absorb(&state, mu.data(), CRHBYTES);
    shake256_absorb(&state, buf.data(), K*POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(sample_in_ball_seed2.data(), CTILDEBYTES, &state);

    for(size_t i = 0; i < CTILDEBYTES; i++) {
        if(sample_in_ball_seed.at(i) != sample_in_ball_seed2.at(i)) {
            return -1;
        }
    }

    return 0;
}


void MLDSA::sigEncode(uint8_t* SignMessage, const std::array<uint8_t, CTILDEBYTES>& sample_in_ball_seed, 
    PolyVector<L>& z, 
    PolyVector<K>& h) 
{
    // Copy c̃ seed
    for(size_t i = 0; i < CTILDEBYTES; i++) {
        SignMessage[i] = sample_in_ball_seed.at(i);
    }
    SignMessage += CTILDEBYTES;
    
    z.vector_packz(SignMessage);
    SignMessage += L*POLYZ_PACKEDBYTES;

    for(int i = 0; i < OMEGA + K; i++) {
        SignMessage[i] = 0;
    }

    int k = 0;
    for(size_t i = 0; i < K; i++) {
        for(size_t j =0; j < N; j++) {
            if(h.access_poly_at(i).get_value(j) != 0) {
                SignMessage[k++] = j;
            }
        }
        SignMessage[OMEGA + i] = k;
    }
}
// TESTED
int MLDSA::sigDecode(std::array<uint8_t, CTILDEBYTES>& sample_in_ball_seed, 
    PolyVector<L>& z, 
    PolyVector<K>& h,
    const uint8_t* Signature) 
{
    for(size_t i = 0; i < CTILDEBYTES; ++i) {
        sample_in_ball_seed.at(i) = Signature[i];
    }
    Signature += CTILDEBYTES;

    z.vector_unpackz(Signature);
    Signature += L*POLYZ_PACKEDBYTES;

    size_t k = 0;
    for(size_t i = 0; i < K; ++i) {

      if(Signature[OMEGA + i] < k || Signature[OMEGA + i] > OMEGA)
      {
        return 1;
      }

      for(size_t j = k; j < Signature[OMEGA + i]; ++j) {
        /* Coefficients are ordered for strong unforgeability */
        if(j > k && Signature[j] <= Signature[j-1]) return 1;
        h.access_poly_at(i).set_value(Signature[j], 1);
      }
  
      k = Signature[OMEGA + i];
    }

      /* Extra indices are zero for strong unforgeability */
    for(size_t j = k; j < OMEGA; ++j)
    {
        if(Signature[j])
        {
            return 1;
        }
    }
    return 0;
}