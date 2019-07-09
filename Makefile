# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
#
# Script to import CrypTech code into DKS HSM folders.
#
DKS_ROOT := $(abspath ../..)

LIBHAL_TARGET := serial

ifndef CRYPTECH_ROOT
  CRYPTECH_ROOT := ${DKS_ROOT}/CrypTech
endif

LIBRESSL_BLD := ${DKS_ROOT}/sw/thirdparty/libressl
LIBERSSL_INCLUDE    := ${LIBRESSL_BLD}/include
LIBRESSL_LIB_DIR    := ${LIBRESSL_BLD}/lib
LIBRESSL_LIBS       := ${LIBRESSL_LIB_DIR}/libtls.a ${LIBRESSL_LIB_DIR}/libssl.a ${LIBRESSL_LIB_DIR}/libcrypto.a

LIBS_DIR := ${DKS_ROOT}/sw/client-side-tools/libs

LIBDKS_SRC := ${DKS_ROOT}/sw/libdks
LIBDKS_BUILD := ${LIBS_DIR}/libdks

LIBHAL_SRC	?= ${CRYPTECH_ROOT}/sw/libhal
LIBHAL_BLD	?= ${LIBS_DIR}/libhal

LIBTFM_SRC	?= ${CRYPTECH_ROOT}/sw/thirdparty/libtfm
LIBTFM_BLD	?= ${LIBS_DIR}/libtfm

LIBB64_SRC := libs/base64.c

LIBMDNS_SRC := libs/mdns

PKCS11_SRC := ${DKS_ROOT}/sw/pkcs11

LIBS	:= ${LIBHAL_BLD}/libhal.a ${LIBDKS_BUILD}/libdks.a ${LIBTFM_BLD}/libtfm.a

FLAGS := -g

all : bin/dks_setup_console bin/dks_cryptech_backup bin/findHSM

bin/dks_setup_console : dks_setup_console.o ${LIBS}
	mkdir -p bin
	gcc dks_setup_console.o ${LIBS} ${LIBRESSL_LIBS} -lpthread  -o bin/dks_setup_console

bin/dks_cryptech_backup : dks_cryptech_backup.o cryptech_device.o serial.o cryptech_device_cty.o base64.o ${LIBS}
	mkdir -p bin
	gcc dks_cryptech_backup.o cryptech_device.o serial.o cryptech_device_cty.o base64.o ${LIBS} -lpthread  -o bin/dks_cryptech_backup

bin/findHSM : ${LIBMDNS_SRC}/mdns.h findHSM.c
	mkdir -p bin
	gcc $(FLAGS) -I${LIBMDNS_SRC} findHSM.c -o bin/findHSM

dks_setup_console.o : dks_setup_console.c
	gcc $(FLAGS) -I${LIBERSSL_INCLUDE} -I${LIBDKS_SRC} -O -c dks_setup_console.c

dks_cryptech_backup.o : dks_cryptech_backup.c
	gcc $(FLAGS) -I${LIBDKS_SRC} -O -c dks_cryptech_backup.c

cryptech_device.o : cryptech_device.c cryptech_device.h
	gcc $(FLAGS) -I${LIBHAL_SRC} -I${LIBDKS_SRC} -I${LIBB64_SRC} -I$(PKCS11_SRC) -O -c cryptech_device.c

cryptech_device_cty.o : cryptech_device_cty.c cryptech_device_cty.h
	gcc $(FLAGS) -I${LIBHAL_SRC} -O -c cryptech_device_cty.c

base64.o : ${LIBB64_SRC}/base64.c ${LIBB64_SRC}/base64.h
	gcc $(FLAGS) -O -c ${LIBB64_SRC}/base64.c

serial.o : serial.c serial.h
	gcc $(FLAGS) -I${LIBHAL_SRC} -O -c serial.c

${LIBDKS_BUILD}/libdks.a: .FORCE
	${MAKE} -C ${LIBDKS_BUILD}

${LIBHAL_BLD}/libhal.a: .FORCE ${LIBTFM_BLD}/libtfm.a
	${MAKE} -C ${LIBHAL_BLD} ${LIBHAL_TARGET}

${LIBTFM_BLD}/libtfm.a: .FORCE
	${MAKE} -C ${LIBTFM_BLD}

clean:
	rm -rf *.o
	rm bin/dks_setup_console
	${MAKE} -C libs/libdks  $@
	${MAKE} -C libs/libhal  $@
	${MAKE} -C libs/libtfm  $@

.FORCE:
