AUTH_SERVER=www.example.com # do not use quotes
MBEDTLS=0

CC=gcc
CPPFLAGS=-DSRUN_LOGIN_AUTH_SERVER=\"$(AUTH_SERVER)\"
CFLAGS=-Wall -Wextra -std=c11 -O2 -lcurl


ifeq ($(MBEDTLS),1)
	CPPFLAGS+=-DSRUN_LOGIN_USE_MBEDTLS
	CFLAGS+=-lmbedtls -lmbedx509 -lmbedcrypto
else
	CFLAGS+=-lcrypto
endif

.PHONY:
all: srun_login.o

.PHONY:
clean:
	rm -f *.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
