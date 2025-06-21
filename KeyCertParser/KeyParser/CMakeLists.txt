add_library(KeyParser STATIC 
            key_parser.cpp
            key_parser.h
)

# Check for the library inclusion
if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "/opt/openssl-3.5.0/" CACHE PATH "Root Dir to OpenSSL")
endif()

# Find the library for both libssl and libcrypto of openssl
find_library(OPENSSL_SSL_LIBRARY
             NAMES ssl
             HINTS ${OPENSSL_ROOT_DIR}/lib
             REQUIRED
)   

find_library(OPENSSL_CRYPTO_LIBRARY
                NAMES crypto
                HINTS ${OPENSSL_ROOT_DIR}/lib
                REQUIRED
)

# Validate if the it is able to find the openssl
if(NOT OPENSSL_SSL_LIBRARY OR NOT OPENSSL_CRYPTO_LIBRARY)
    message(FATAL_ERROR "[KeyParser] Not able to find the OpenSSL library")
endif()

# There are some case that CMake find the library but not the correct version of
# OpenSSL installed in the /opt/ folder
message("[KeyParser][Debug] OPENSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}")
message("[KeyParser][Debug] OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")

# Include the the library for further development
target_include_directories(KeyParser
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPENSSL_ROOT_DIR}/include
)

target_link_libraries(KeyParser 
    PUBLIC
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
)

# Set the project compilation target
target_compile_features(KeyParser PUBLIC cxx_std_20)