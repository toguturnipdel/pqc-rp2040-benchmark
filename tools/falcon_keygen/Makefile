# Host build of the Falcon key-provisioning tool against the firmware's wolfSSL tree.
WOLFSSL_ROOT ?= $(HOME)/pico/wolfssl
SRC := $(filter-out %/misc.c %/evp.c,$(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.c))
CFLAGS ?= -O2
falcon_keygen: falcon_keygen.c user_settings.h
	$(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS -I. -I$(WOLFSSL_ROOT) falcon_keygen.c $(SRC) -o $@ -lm
clean:
	rm -f falcon_keygen
