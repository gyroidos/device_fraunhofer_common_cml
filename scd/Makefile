#
# This file is part of GyroidOS
# Copyright(c) 2013 - 2018 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2 (GPL 2), as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
#

CC ?= gcc
DEVELOPMENT_BUILD ?= y
AGGRESSIVE_WARNINGS ?= y
SANITIZERS ?= n
WCAST_ALIGN ?= y
TRUSTME_SCHSM ?= n
SYSTEMD ?= n
TRUSTME_PKCS11 ?= y

LOCAL_CFLAGS := -std=gnu99 -I.. -I../include -I../tpm2d -Icommon -pedantic -O2
LOCAL_CFLAGS += -DTPM_POSIX
LOCAL_CFLAGS += -Wall -Wextra -Wformat -Wformat-security -Wno-deprecated-declarations -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie

LOCAL_LFLAGS := -lc -Lcommon
ifeq ($(SYSTEMD),y)
	LOCAL_LFLAGS += -lcommon_full_systemd -lsystemd
else
	LOCAL_LFLAGS += -lcommon_full
endif
LOCAL_LFLAGS += -lprotobuf-c -lprotobuf-c-text -lssl -lcrypto

ifeq ($(WCAST_ALIGN),y)
    LOCAL_CFLAGS += -Wcast-align
endif
ifeq ($(CC),gcc)
    # clang does not support stack clash protection yet
    LOCAL_CFLAGS += -fstack-clash-protection
endif
ifeq ($(DEVELOPMENT_BUILD),y)
    # what are we building? development or production code?
    LOCAL_CFLAGS += -ggdb -DDEBUG_BUILD
endif
ifeq ($(AGGRESSIVE_WARNINGS),y)
    # on CI (and also for well-behaved developers) warnings should be
    # converted to errors; this helps us redistribute the code base without any pain;
    # pure builds are better than polluted builds.
    LOCAL_CFLAGS += -Werror
endif
ifeq ($(SANITIZERS),y)
    # if requested, we enable sanitization for easier debugging
    # this requires libasan libasan-static libubsan libubsan-static
    # to be installed on the build host
    LOCAL_CFLAGS += -lasan -fsanitize=address -fsanitize=undefined -fsanitize-recover=address
endif
ifeq ($(TRUSTME_SCHSM), y)
    # If requested, we build sc-hsm support into trustme
    LOCAL_CFLAGS += -DENABLESCHSM
	LOCAL_LFLAGS += -lctccid
    SRC_FILES += \
	sc-hsm-lib/sc-hsm-cardservice.c \
	sc-hsm-lib/bn-se-cardservice.c \
	sc-hsm-lib/cardservice.c \
	usbtoken.c
endif
ifeq ($(SYSTEMD),y)
	LOCAL_CFLAGS += \
		-DSYSTEMD \
		-DSCD_CONTROL_SOCKET=NULL
endif
ifeq ($(TRUSTME_PKCS11), y)
    # If requested, we build sc-hsm support into trustme
    LOCAL_CFLAGS += -DENABLEPKCS11 -I../pkcs11-lib 
	LOCAL_LDFLAGS += -ldl
    SRC_FILES += \
	p11token.c \
	pkcs11-lib/libpkcs11.c \
	pkcs11-lib/libscdl.c
endif


SRC_FILES += \
	device.pb-c.c \
	scd.pb-c.c \
	control.c \
	softtoken.c \
	token.c \
	scd.c \
	tokencontrol.pb-c.c


.PHONY: all
all: scd

ifeq ($(CC_MODE),y)
protobuf: device.proto scd.proto tokencontrol.proto
	ln -sf ../daemon/cc_mode/device.proto device.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. device.proto
	protoc-c --c_out=. tokencontrol.proto

else
protobuf: device.proto scd.proto tokencontrol.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. device.proto
	protoc-c --c_out=. tokencontrol.proto

endif

$(SRC_FILES): protobuf

libcommon:
ifeq ($(SYSTEMD),y)
	$(MAKE) -C common libcommon_full_systemd WITH_OPENSSL=y WITH_PROTOBUF_TEXT=y
else
	$(MAKE) -C common libcommon_full WITH_OPENSSL=y WITH_PROTOBUF_TEXT=y
endif

scd: libcommon $(SRC_FILES)
	$(CC) $(LOCAL_CFLAGS) $(SRC_FILES) $(LOCAL_LFLAGS) -o scd


.PHONY: clean
clean:
	rm -f scd *.o *.pb-c.*
	$(MAKE) -C common clean
