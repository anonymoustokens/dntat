cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(DNTAT VERSION 1.0)

# if(NOT CMAKE_BUILD_TYPE)
#     set(CMAKE_BUILD_TYPE Release)
# endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Define the path to the MCL library
#set(MCLPATH "/Users/simonlion/mcl")

include_directories(${CMAKE_SOURCE_DIR}/inc /Users/simonlion/mcl/include)

# Create the test2 executable (original redemption test)
add_executable(test2 ${CMAKE_SOURCE_DIR}/src/test2.cpp)
target_link_libraries(test2 /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test2 PRIVATE -O3 -march=native)

# Create the DNTAT executable (full DNTAT protocol implementation)
add_executable(DNTAT 
    ${CMAKE_SOURCE_DIR}/src/dntat_ps.cpp
    ${CMAKE_SOURCE_DIR}/src/test_dntat.cpp
)
target_link_libraries(DNTAT /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(DNTAT PRIVATE -O3 -march=native -std=c++11)

# Create the simple test executable
add_executable(test_simple 
    ${CMAKE_SOURCE_DIR}/src/dntat_ps.cpp
    ${CMAKE_SOURCE_DIR}/src/test_simple.cpp
)
target_link_libraries(test_simple /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_simple PRIVATE -O3 -march=native)

# Create the debug test executable
add_executable(test_debug ${CMAKE_SOURCE_DIR}/src/test_debug.cpp)
target_link_libraries(test_debug /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_debug PRIVATE -O3 -march=native)

# Create the multi-signer test executable
add_executable(test_multi_signer ${CMAKE_SOURCE_DIR}/src/test_multi_signer.cpp)
target_link_libraries(test_multi_signer /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_multi_signer PRIVATE -O3 -march=native)

# Create the full debug test executable
add_executable(test_full_debug 
    ${CMAKE_SOURCE_DIR}/src/dntat_ps.cpp
    ${CMAKE_SOURCE_DIR}/src/test_full_debug.cpp
)
target_link_libraries(test_full_debug /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_full_debug PRIVATE -O3 -march=native)

# Create the aggregation test executable
add_executable(test_aggregation 
    ${CMAKE_SOURCE_DIR}/src/dntat_ps.cpp
    ${CMAKE_SOURCE_DIR}/src/test_aggregation.cpp
)
target_link_libraries(test_aggregation /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_aggregation PRIVATE -O3 -march=native)

# Create the single sigma test executable
add_executable(test_single_sigma ${CMAKE_SOURCE_DIR}/src/test_single_sigma.cpp)
target_link_libraries(test_single_sigma /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)
target_compile_options(test_single_sigma PRIVATE -O3 -march=native)

set(CMAKE_BUILD_TYPE Release)

