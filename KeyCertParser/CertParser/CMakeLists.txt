add_library(CertParser STATIC cert_parser.cpp cert_parser.h)

# In case that the variable is not defined by the parent => Then
if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "/opt/openssl-3.5.0/" CACHE PATH "Root Dir to OpenSSL")
endif()

# Find the library of the SSL and CRYPTO of the OpenSSL
find_library(OPENSSL_SSL_LIBRARY
             NAMES ssl
             HINTS ${OPENSSL_ROOT_DIR}/lib
             REQUIRED
)   

# Find the crypto library
find_library(OPENSSL_CRYPTO_LIBRARY
            NAMES crypto 
            HINTS ${OPENSSL_ROOT_DIR}/lib
            REQUIRED
)

if(NOT OPENSSL_SSL_LIBRARY OR NOT OPENSSL_CRYPTO_LIBRARY)
    message(FATAL_ERROR "Open library is not able to be founded in ${OPENSSL_ROOT_DIR}/lib")
endif()

# Debug message, openssl still can be found -> but it could be in the /usr/bin for default openssl
message("[CertParser]: OPENSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}")
message("[CertParser]: OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")


# Include all of the current directory
target_include_directories(CertParser 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR} 
        ${OPENSSL_ROOT_DIR}/include
        )

# Link the library for inclusion
target_link_libraries(CertParser
    PUBLIC
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
)

# Set the compile feature for library
target_compile_features(CertParser PUBLIC cxx_std_20)

