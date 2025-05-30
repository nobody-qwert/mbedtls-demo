cmake_minimum_required(VERSION 3.10)
project(TSAVerification)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find mbedTLS
find_package(PkgConfig REQUIRED)
pkg_check_modules(MBEDTLS REQUIRED mbedtls mbedcrypto mbedx509)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${MBEDTLS_INCLUDE_DIRS})

# Source files
set(SOURCES
    src/tsa_verifier.cpp
)

# Create library
add_library(tsa_verifier STATIC ${SOURCES})
target_link_libraries(tsa_verifier ${MBEDTLS_LIBRARIES})

# Create test executable
add_executable(test_tsa test/test_tsa.cpp)
target_link_libraries(test_tsa tsa_verifier ${MBEDTLS_LIBRARIES})

# Add compile flags
target_compile_options(tsa_verifier PRIVATE ${MBEDTLS_CFLAGS_OTHER})
target_compile_options(test_tsa PRIVATE ${MBEDTLS_CFLAGS_OTHER})

# Installation
install(TARGETS tsa_verifier
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib)

install(FILES include/tsa_verifier.h
    DESTINATION include)

# Copy scripts to build directory
file(COPY scripts DESTINATION ${CMAKE_BINARY_DIR})
