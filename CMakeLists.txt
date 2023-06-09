# Copyright © 2023 45gfg9 <45gfg9@45gfg9.net>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 0.9)

# uncomment these lines to provide default values
# be aware password is stored in plain-text and can be exported easily
#
#set(SRUN_CONF_AC_ID 1)
#set(SRUN_CONF_AUTH_URL "https://example.com")
#set(SRUN_CONF_DEFAULT_USERNAME "TanikazeAmane")
#set(SRUN_CONF_DEFAULT_PASSWORD "p4ssw@rd")
#set(SRUN_CONF_DEFAULT_CERTFILE "example-cert.pem")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
add_executable(${PROJECT_NAME} srun.c main.c)

# find current Git revision
find_package(Git)
if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%h
            OUTPUT_VARIABLE SRUN_GIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
else ()
    set(SRUN_GIT_HASH "unknown")
endif ()

if (APPLE)
    # have to handle OpenSSL on macOS to use Homebrew version
    find_package(OpenSSL QUIET)
    if (NOT OPENSSL_FOUND)
        execute_process(
                COMMAND brew --prefix
                OUTPUT_VARIABLE OPENSSL_ROOT_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        string(APPEND OPENSSL_ROOT_DIR "/opt/openssl")
    endif ()
else ()
    # have to configure libbsd on other platforms
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LibBSD REQUIRED IMPORTED_TARGET libbsd)
    target_link_libraries(${PROJECT_NAME} PUBLIC PkgConfig::LibBSD)
endif ()

string(TIMESTAMP SRUN_BUILD_TIME "%Y-%m-%d %H:%M:%S")
set(SRUN_VERSION "${CMAKE_PROJECT_VERSION}")

if (SRUN_CONF_DEFAULT_CERTFILE)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${SRUN_CONF_DEFAULT_CERTFILE}" SRUN_CONF_DEFAULT_CERT)
    string(REPLACE "\n" "\\n" SRUN_CONF_DEFAULT_CERT "${SRUN_CONF_DEFAULT_CERT}")
endif ()

if (NOT SRUN_CONF_DEFAULT_USERNAME AND SRUN_CONF_DEFAULT_PASSWORD)
    message(WARNING "Cannot set password without username")
    unset(SRUN_CONF_DEFAULT_PASSWORD)
endif ()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h")

find_package(CURL REQUIRED)
find_package(cJSON REQUIRED)
find_package(OpenSSL REQUIRED)

#add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O0)
#add_link_options(-fsanitize=address)

include_directories(${OPENSSL_INCLUDE_DIR} ${CJSON_INCLUDE_DIR} ${CURL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_CRYPTO_LIBRARIES} ${CJSON_LIBRARIES} ${CURL_LIBRARIES})
