# Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 1.1.0)

set(SRUN_CRYPTO "openssl" CACHE STRING "The crypto library to use")
set_property(CACHE SRUN_CRYPTO PROPERTY STRINGS "openssl" "mbedtls" "self")
string(TOLOWER "${SRUN_CRYPTO}" SRUN_CRYPTO)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
add_executable(${PROJECT_NAME} srun.c main.c)

# ---- Compiler options ----
target_compile_definitions(${PROJECT_NAME} PRIVATE _GNU_SOURCE)

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra
    $<$<CONFIG:Debug>:-pedantic -fsanitize=address,undefined -fstack-protector-all -fno-omit-frame-pointer -ggdb>
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Linux>>:-fsanitize=leak>
    $<$<CONFIG:Release>:-O3>
)
target_link_options(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Linux>>:-fsanitize=leak>
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/platform"
)

# ---- Git revision ----
find_package(Git)
if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --always --tags --dirty
            OUTPUT_VARIABLE SRUN_GIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif ()

string(TIMESTAMP SRUN_BUILD_TIME "%Y-%m-%d %H:%M:%S")
set(SRUN_VERSION "${CMAKE_PROJECT_VERSION}")

# ---- Config header ----
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/srun_config.h"
)
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

# ---- libbsd ----
if (NOT (APPLE OR BSD))
    find_library(LIBBSD_LIB NAMES bsd libbsd)
    find_path(LIBBSD_INCLUDE_DIRS bsd/readpassphrase.h)
    if (LIBBSD_LIB AND LIBBSD_INCLUDE_DIRS)
        message(STATUS "Found libbsd: ${LIBBSD_LIB}")
        target_include_directories(${PROJECT_NAME} PRIVATE ${LIBBSD_INCLUDE_DIRS})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBBSD_LIB})
    else ()
        message(WARNING "libbsd not found, will use potentially insecure fallback implementation")
    endif ()
endif ()

# ---- libcurl ----
find_package(CURL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE CURL::libcurl)
target_sources(${PROJECT_NAME} PRIVATE platform/libcurl.c)

# ---- cJSON ----
find_package(cJSON REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${CJSON_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CJSON_LIBRARIES})
target_sources(${PROJECT_NAME} PRIVATE platform/cjson.c)

# ---- crypto (mbedtls / openssl / self) ----
find_library(MbedCrypto_LIB mbedcrypto)
find_path(MbedCrypto_INCLUDE_DIR mbedtls/md.h)
find_package(OpenSSL COMPONENTS Crypto)

if (MbedCrypto_LIB AND MbedCrypto_INCLUDE_DIR AND (NOT OpenSSL_FOUND OR SRUN_CRYPTO STREQUAL "mbedtls"))
    message(STATUS "Found MbedTLS: ${MbedCrypto_LIB}")
    target_include_directories(${PROJECT_NAME} PRIVATE ${MbedCrypto_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${MbedCrypto_LIB})
    target_sources(${PROJECT_NAME} PRIVATE platform/mbedtls.c)
elseif (OpenSSL_FOUND AND NOT (SRUN_CRYPTO STREQUAL "self"))
    if (NOT (SRUN_CRYPTO STREQUAL "openssl"))
        message(WARNING "Could not find specified crypto library: ${SRUN_CRYPTO}. Using OpenSSL instead")
    endif ()
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
    target_sources(${PROJECT_NAME} PRIVATE platform/openssl.c)
else ()
    if (NOT (SRUN_CRYPTO STREQUAL "self"))
        message(WARNING "Could not find crypto library: ${SRUN_CRYPTO}")
    endif ()
    message(STATUS "Using self-implemented crypto functions")
    target_sources(${PROJECT_NAME} PRIVATE platform/md.c)
endif ()
