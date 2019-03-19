DKS_ROOT ?= $(abspath ../../../..)

ifndef CRYPTECH_ROOT
  CRYPTECH_ROOT := ${DKS_ROOT}/CrypTech
endif


# add paths for LibreSSL
LIBRESSL_DIR := ${DKS_ROOT}/sw/thirdparty/libressl


LIBHAL_SRC   ?= ${CRYPTECH_ROOT}/sw/libhal
LIBTFM_BLD   ?= $(abspath ../libtfm)

CFLAGS += -I${LIBHAL_SRC}

vpath %.c ${LIBHAL_SRC}
vpath %.h ${LIBHAL_SRC}:${LIBTFM_BLD}

include ${LIBHAL_SRC}/Makefile