#!/usr/bin/bash
rm ./server
rm -rf build
mkdir build

# CMake generation
cmake . -Bbuild

# CMake build folder
cmake --build build

# copy the file from build to current location
cp build/opcua_server server