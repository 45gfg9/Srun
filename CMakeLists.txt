cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 0.7)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

# uncomment these lines and change accordingly
#set(SRUN_CONF_AC_ID 1)
#set(SRUN_CONF_AUTH_URL "https://example.com")
# These two lines are optional
#set(SRUN_CONF_DEFAULT_USERNAME "TanikazeAmane")
#set(SRUN_CONF_DEFAULT_PASSWORD "p4ssw@rd")

# find current Git revision
find_package(Git)
if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%h
            OUTPUT_VARIABLE GIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
else ()
    message(WARNING "CMake did not find Git. The compiled binary will not contain revision hash.")
endif ()

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M:%S")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h")

find_package(CURL REQUIRED)
find_package(cJSON REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O0)
add_link_options(-fsanitize=address)

add_executable(${PROJECT_NAME} srun.c main.c)
include_directories(${OPENSSL_INCLUDE_DIR} ${CJSON_INCLUDE_DIR} ${CURL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_CRYPTO_LIBRARIES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${CURL_LIBRARIES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${CJSON_LIBRARIES})

if (NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LibBSD REQUIRED IMPORTED_TARGET libbsd)
    target_link_libraries(${PROJECT_NAME} PUBLIC PkgConfig::LibBSD)
endif ()
