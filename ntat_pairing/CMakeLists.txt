cmake_minimum_required(VERSION 3.10)

project(NTAT_CPP_MCL VERSION 1.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/inc /Users/simonlion/mcl/include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Create the benchmark executable
add_executable(ntat_benchmark 
    ${CMAKE_SOURCE_DIR}/src/ntat_pairing.cpp
    ${CMAKE_SOURCE_DIR}/src/benchmark.cpp
)

target_link_libraries(ntat_benchmark 
    /Users/simonlion/mcl/lib/libmcl.a 
    /Users/simonlion/mcl/lib/libmclbn256.a
    ${OPENSSL_LIBRARIES}
)

# Create the simple test executable
add_executable(test_simple 
    ${CMAKE_SOURCE_DIR}/src/ntat_pairing.cpp
    ${CMAKE_SOURCE_DIR}/src/test_simple.cpp
)

target_link_libraries(test_simple 
    /Users/simonlion/mcl/lib/libmcl.a 
    /Users/simonlion/mcl/lib/libmclbn256.a
    ${OPENSSL_LIBRARIES}
)

set(CMAKE_BUILD_TYPE Release)
target_compile_options(ntat_benchmark PRIVATE -O3 -march=native)
target_compile_options(test_simple PRIVATE -O3 -march=native)
