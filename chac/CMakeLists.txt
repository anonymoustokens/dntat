cmake_minimum_required(VERSION 3.10)
project(CHAC VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/src /Users/simonlion/mcl/include ${OPENSSL_INCLUDE_DIR})

add_executable(chac_benchmark src/main.cpp)
target_link_libraries(chac_benchmark 
    /Users/simonlion/mcl/lib/libmcl.a 
    /Users/simonlion/mcl/lib/libmclbn256.a 
    OpenSSL::Crypto
)
target_compile_options(chac_benchmark PRIVATE -O3 -march=native)
