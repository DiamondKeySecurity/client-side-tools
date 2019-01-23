# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
DKS_ROOT := $(abspath ../..)

LIBHAL_TARGET := tcpdaemon

ifndef CRYPTECH_ROOT
  CRYPTECH_ROOT := ${DKS_ROOT}/CrypTech
endif

LIBRESSL_BLD := ${DKS_ROOT}/sw/thirdparty/libressl
LIBERSSL_INCLUDE    := ${LIBRESSL_BLD}/include
LIBRESSL_LIB_DIR    := ${LIBRESSL_BLD}/lib
LIBRESSL_LIBS       := ${LIBRESSL_LIB_DIR}/libtls.a ${LIBRESSL_LIB_DIR}/libssl.a ${LIBRESSL_LIB_DIR}/libcrypto.a

LIBDKS_SRC := ${DKS_ROOT}/sw/libdks
LIBDKS_BUILD := ${DKS_ROOT}/sw/client-side-tools/libdks

LIBHAL_SRC	?= ${CRYPTECH_ROOT}/sw/libhal
LIBHAL_BLD	?= ${DKS_ROOT}/sw/client-side-tools/libhal

LIBTFM_SRC	?= ${CRYPTECH_ROOT}/sw/thirdparty/libtfm
LIBTFM_BLD	?= ${DKS_ROOT}/sw/client-side-tools/libtfm

LIBS	:= ${LIBHAL_BLD}/libhal.a ${LIBDKS_BUILD}/libdks.a ${LIBTFM_BLD}/libtfm.a

all : dks_setup_console dks_keygen

dks_setup_console : dks_setup_console.o ${LIBS}
	gcc dks_setup_console.o ${LIBS} ${LIBRESSL_LIBS} -lpthread  -o dks_setup_console

dks_setup_console.o : dks_setup_console.c
	gcc -I${LIBERSSL_INCLUDE} -I${LIBDKS_SRC} -O -c dks_setup_console.c

dks_keygen : dks_keygen.o ${LIBS}
	gcc dks_keygen.o ${LIBS} ${LIBRESSL_LIBS} -lpthread  -o dks_keygen

dks_keygen.o : dks_keygen.c
	gcc -I${LIBERSSL_INCLUDE} -I${LIBDKS_SRC} -I${LIBHAL_SRC} -O -c dks_keygen.c

${LIBDKS_BUILD}/libdks.a: .FORCE
	${MAKE} -C libdks

${LIBHAL_BLD}/libhal.a: .FORCE ${LIBTFM_BLD}/libtfm.a
	${MAKE} -C libhal ${LIBHAL_TARGET}

${LIBTFM_BLD}/libtfm.a: .FORCE
	${MAKE} -C libtfm

clean:
	rm -rf *.o
	rm -rf dks_setup_console
	${MAKE} -C libdks  $@

.FORCE: