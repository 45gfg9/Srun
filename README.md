# Srun

Yet another Srun login utility, but written in C and with ESP32 support.

The main files `srun.h` and `srun.c` can be dropped into an existing project and compile along with it. You may also build a binary directly for your OS.

## Build for \*nix

Dependencies:
- OpenSSL 3
- LibcURL
- cJSON

```sh
sudo apt install cmake openssl curl libcjson-dev
mkdir build
cd build
cmake ..
make
```

## Build for ESP32

> No ESP32 support yet!

The ESP32 version uses Mbed TLS library comes along with ESP-IDF. The source should be able to detect this automatically.
