# Linux build of the firmware handshake client (hs_core.c) for the pty test.
WOLFSSL_ROOT ?= $(HOME)/pico/wolfssl
SRC := $(filter-out %/misc.c %/evp.c,$(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.c))
hs_sim: hs_sim.c ../../firmware/src/hs_core.c ../../firmware/src/hs_core.h user_settings.h
	$(CC) -O2 -DWOLFSSL_USER_SETTINGS -I. -I../../firmware/src -I$(WOLFSSL_ROOT) hs_sim.c ../../firmware/src/hs_core.c $(SRC) -o $@ -lm
clean:
	rm -f hs_sim
