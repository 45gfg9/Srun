# SrunLogin

Yet another Srun login utility, but written in C and with ESP32 support.

The main files `srun_login.h` and `srun_login.c` can be dropped into an existing project and compile along with it. You may also `make` a binary directly with `main.c`.

## Build for \*nix

Make sure you have OpenSSL 3 and libcurl installed. You may need to modify the Makefile accordingly, or pass arguments to `make` as demonstrated below.

```sh
apt install openssl curl
make AUTH_SERVER=www.example.com
```

If you rather prefer using Mbed TLS on \*nix, pass `MBEDTLS=1` to `make`.

```sh
apt install libmbedtls-dev
make AUTH_SERVER=www.example.com MBEDTLS=1
```

## Build for ESP32

The ESP32 version uses Mbed TLS library comes along with ESP-IDF. The source should be able to detect this automatically.
