# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
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

LIBS	:= ${LIBHAL_BLD}/libhal.a ${LIBDKS_BUILD}/libdks.a ${LIBTFM_BLD}/libtfm.a

all : bin/dks_setup_console

bin/dks_setup_console : dks_setup_console.o cryptech_device.o ${LIBS}
	gcc dks_setup_console.o ${LIBS} ${LIBRESSL_LIBS} -lpthread  -o bin/dks_setup_console

dks_setup_console.o : dks_setup_console.c
	gcc -I${LIBERSSL_INCLUDE} -I${LIBDKS_SRC} -O -c dks_setup_console.c

cryptech_device.o : cryptech_device.c cryptech_device.h
	gcc -I${LIBHAL_SRC} -O -c cryptech_device.c

${LIBDKS_BUILD}/libdks.a: .FORCE
	${MAKE} -C ${LIBDKS_BUILD}

${LIBHAL_BLD}/libhal.a: .FORCE ${LIBTFM_BLD}/libtfm.a
	${MAKE} -C ${LIBHAL_BLD} ${LIBHAL_TARGET}

${LIBTFM_BLD}/libtfm.a: .FORCE
	${MAKE} -C ${LIBTFM_BLD}

clean:
	rm -rf *.o
	rm bin/dks_setup_console
	${MAKE} -C libdks  $@

.FORCE: