cmake_minimum_required(VERSION 3.25)
project(CertKeyParser LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "/opt/openssl-3.5.0/" CACHE PATH "Root directory for OpenSSL")
endif()

# Add subdirectories for libraries
add_subdirectory(CertParser) # Get the CertParser Library
add_subdirectory(KeyParser) # Get th KeyParser library
