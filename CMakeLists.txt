cmake_minimum_required(VERSION 3.10)

project(opcua_server
        VERSION 1.0.0
        LANGUAGES CXX C) # Add C language support


# (Actually project only compatible with the C99 version)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Remove the casting warning -> Despite it not safe casting, but there are no other choice
add_compile_options(-Wno-write-strings)

# Add the library of MLDSA
add_subdirectory(mldsa)

# Add the inclusion
include_directories(include)




# Find the library
# 1. Open62541
find_package(open62541 CONFIG REQUIRED)
# 2. Boost
find_package(Boost CONFIG REQUIRED)

# Set source file
set(SOURCES_FILES 
        src/server.cpp 
        src/i2c.cpp
        mldsa/ref/source/fips202.c
)

# Include the library for key and certificate parser
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/KeyCertParser)

# Add project execution
add_executable(${PROJECT_NAME} 
        ${SOURCES_FILES})

# Link the library to project
target_link_libraries(${PROJECT_NAME} PRIVATE 
                open62541::open62541                            # -> open62541
                /usr/lib/aarch64-linux-gnu/libgpiod.so          # -> gpiod
                Boost::boost                                    # -> Boost
                mldsa_mode2                                     # -> mldsa mode
                CertParser                                      # -> Certificate parser with OpenSSL support
                KeyParser                                       # -> Key reader with OpenSSL support
)