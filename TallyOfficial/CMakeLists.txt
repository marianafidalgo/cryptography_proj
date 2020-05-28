# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEALExamples VERSION 3.4.5 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY)

add_executable(tally tallyofficial.cpp ../Counter/counter.cpp)


# Import Microsoft SEAL
find_package(SEAL 3.4.5 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

find_package(OpenSSL REQUIRED)

target_link_libraries(tally PUBLIC SEAL::seal OpenSSL::SSL OpenSSL::Crypto)

set(HEADER_FILES ${YOUR_DIRECTORY}/../Header.h ../Counter/counter.hpp)

