# Optional CMake build, for Gradle externalNativeBuild { cmake { } } users.
# The primary, documented build is Android.mk (ndk-build). See IMPORT.md.
cmake_minimum_required(VERSION 3.10)
project(slophook C ASM)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    message(FATAL_ERROR "slophook supports arm64-v8a only (got ${CMAKE_SYSTEM_PROCESSOR})")
endif()

add_library(slophook STATIC
    src/hook.c
    src/mem.c
    src/patch.c
    src/put.c
    src/arm64_relocate.c
    src/bridge_arm64.S)

target_include_directories(slophook PUBLIC include)
target_compile_options(slophook PRIVATE -O2 -Wall -Wextra -fvisibility=hidden)

option(SLOPHOOK_BRANCH_PROTECTION "Keep BTI/PAC marking" OFF)
if(SLOPHOOK_BRANCH_PROTECTION)
    target_compile_options(slophook PRIVATE -mbranch-protection=standard)
endif()

find_library(LOG_LIB log)
if(LOG_LIB)
    target_link_libraries(slophook PUBLIC ${LOG_LIB})
endif()
