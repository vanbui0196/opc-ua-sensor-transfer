# Optional: Build test executable (only if this is standalone or explicitly requested)
option(MLDSA_BUILD_TESTS "Build MLDSA test executables" OFF)

if(MLDSA_BUILD_TESTS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/main.cpp)
    add_executable(mldsa_mode2_test ${CMAKE_CURRENT_SOURCE_DIR}/test/main.cpp)
    target_link_libraries(mldsa_mode2_test PRIVATE mldsa_mode2)
    target_compile_definitions(mldsa_mode2_test PRIVATE DILITHIUM_MODE=2)
    
    add_executable(mldsa_mode3_test ${CMAKE_CURRENT_SOURCE_DIR}/test/main.cpp)
    target_link_libraries(mldsa_mode3_test PRIVATE mldsa_mode3)
    target_compile_definitions(mldsa_mode3_test PRIVATE DILITHIUM_MODE=3)
    
    add_executable(mldsa_mode5_test ${CMAKE_CURRENT_SOURCE_DIR}/test/main.cpp)
    target_link_libraries(mldsa_mode5_test PRIVATE mldsa_mode5)
    target_compile_definitions(mldsa_mode5_test PRIVATE DILITHIUM_MODE=5)
endif()# MLDSA Library CMakeLists.txt
# This file is designed to be included as a subdirectory in a parent project

# Only set project if this is the top-level CMakeLists.txt
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.25)
    project(mldsa
            VERSION 1.0.0
            LANGUAGES C CXX)
    
    # Set the version to C++20
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# Set the source files (relative to current directory)
set(MLDSA_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/source/mldsa.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/source/poly_algo.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/source/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ref/source/stream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ref/source/fips202.c)

#set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/ref/source/fips202.cpp PROPERTIES LANGUAGE C)

# Create static libraries for different modes
add_library(mldsa_mode2 STATIC ${MLDSA_SOURCES})
target_compile_definitions(mldsa_mode2 PRIVATE DILITHIUM_MODE=2)
target_include_directories(mldsa_mode2 PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ref/include>
    $<INSTALL_INTERFACE:include/mldsa>)

add_library(mldsa_mode3 STATIC ${MLDSA_SOURCES})
target_compile_definitions(mldsa_mode3 PRIVATE DILITHIUM_MODE=3)
target_include_directories(mldsa_mode3 PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ref/include>
    $<INSTALL_INTERFACE:include/mldsa>)

add_library(mldsa_mode5 STATIC ${MLDSA_SOURCES})
target_compile_definitions(mldsa_mode5 PRIVATE DILITHIUM_MODE=5)
target_include_directories(mldsa_mode5 PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ref/include>
    $<INSTALL_INTERFACE:include/mldsa>)

# Create aliases for easier usage (optional)
add_library(mldsa::mode2 ALIAS mldsa_mode2)
add_library(mldsa::mode3 ALIAS mldsa_mode3)
add_library(mldsa::mode5 ALIAS mldsa_mode5)

# Enable compile commands export
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)