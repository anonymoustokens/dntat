cmake_minimum_required(VERSION 3.10)
project(NTAT VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/inc /Users/simonlion/mcl/include ${OPENSSL_INCLUDE_DIR})

# Create the benchmark executable
add_executable(ntat_benchmark
    ${CMAKE_SOURCE_DIR}/src/ntat.cpp
    ${CMAKE_SOURCE_DIR}/src/benchmark.cpp
)

find_package(Threads REQUIRED)

target_link_libraries(ntat_benchmark
    /Users/simonlion/mcl/lib/libmcl.a
    /Users/simonlion/mcl/lib/libmclbn256.a
    OpenSSL::Crypto
    Threads::Threads
)

set(CMAKE_BUILD_TYPE Release)
target_compile_options(ntat_benchmark PRIVATE -O3 -march=native)
