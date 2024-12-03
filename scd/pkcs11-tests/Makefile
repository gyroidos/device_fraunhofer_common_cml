CC ?= gcc
CFLAGS := -std=gnu99 -I.. -I../include -I../common -I../pkcs11-lib -L../common -Wall -Wextra -Wformat

SRC_FILES := \
	../common/mem.c \
	../common/file.c \
	../common/munit.c \
	../p11token.c \
	../pkcs11-lib/libpkcs11.c \
	p11token-test.c

all: p11test

p11test: libcommon $(SRC_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) -lcommon -ldl -o $@

libcommon:
	$(MAKE) -C ../common libcommon 

test:
	bash run_test.sh

clean:
	rm p11test