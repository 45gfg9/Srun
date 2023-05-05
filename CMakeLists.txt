cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 0.6)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(cJSON REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# TODO: compile time information

#add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g -O0)
#add_link_options(-fsanitize=address)

add_executable(srun srun.c main.c)
include_directories(${OPENSSL_INCLUDE_DIR} ${CJSON_INCLUDE_DIR} ${CURL_INCLUDE_DIR})
target_link_libraries(srun PUBLIC ${OPENSSL_CRYPTO_LIBRARIES})
target_link_libraries(srun PUBLIC ${CURL_LIBRARIES})
target_link_libraries(srun PUBLIC ${CJSON_LIBRARIES})
