# Srun

Yet another Srun login utility, but written in C and with ESP32 support.

The main files `srun.h` and `srun.c` can be dropped into an existing project and compile along with it. You may also build an executable directly for your OS.

## Build for \*nix

Dependencies:
- OpenSSL 3
- LibcURL
- cJSON

```sh
sudo apt install cmake openssl libcurl4-openssl-dev libcjson-dev
mkdir build
cd build
cmake ..
make
```

## Build for ESP32

> ESP32 support is not yet stable...?

The ESP32 version uses Mbed TLS library comes along with ESP-IDF. The source should be able to detect this automatically.

## Example Usage

### Login

```c
srun_handle handle = srun_create();
srun_setopt(handle, SRUNOPT_USERNAME, "username");
srun_setopt(handle, SRUNOPT_AUTH_SERVER, "auth server URL");
srun_setopt(handle, SRUNOPT_AC_ID, AUTH_SERVER_AC_ID); // int type
srun_setopt(handle, SRUNOPT_PASSWORD, "password");
srun_setopt(handle, SRUNOPT_SERVER_CERT, "auth server certificate (PEM format)"); // explained below
printf("login result: %d\n", srun_login(handle));
srun_cleanup(handle);
handle = NULL;
```

The server certificate needs to be set if your auth server uses HTTPS, and if either:

- you are running on ESP32
- your auth server uses a self-signed certificate (that is not trusted by your system's global CA store)

For security concerns there is no option to skip certificate verification. Evaluate the risk before modifying the code yourself please.

All fields *except server certificate* is copied into the context. The password field is used as HMAC-MD5 key and is freed as soon as the hash completes (and is overwritten with zeroes after that), which also means that two consecutive logins will not work, but why would you do that?

### Logout

```c
srun_handle handle = srun_create();
srun_setopt(handle, SRUNOPT_AUTH_SERVER, "auth server URL");
srun_setopt(handle, SRUNOPT_SERVER_CERT, "auth server certificate (PEM format)");
printf("logout result: %d\n", srun_logout(handle));
srun_cleanup(handle);
handle = NULL;
```

Username, password and ac_id are not needed when logging out.
