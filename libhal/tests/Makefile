ifndef CRYPTECH_ROOT
  CRYPTECH_ROOT := $(abspath ../../../../CrypTech)
endif

LIBHAL_SRC	?= ${CRYPTECH_ROOT}/sw/libhal
LIBHAL_BLD	= $(abspath ..)

LIBTFM_SRC	?= ${CRYPTECH_ROOT}/sw/thirdparty/libtfm
LIBTFM_BLD	= $(abspath ../../libtfm)

# add paths for LibreSSL
# LIBERSSL_INCLUDE should be altered if libressl was installed on a different path
# LibreSSL is used by the the Diamond Key Security, NFP to connect to the DKS HSM
# using a secure TCP socket
LIBRESSL_DIR	:= /opt/libressl
LIBERSSL_INCLUDE	:= ${LIBRESSL_DIR}/include
LIBRESSL_LIB_DIR	:= ${LIBRESSL_DIR}/lib
LIBRESSL_LIBS	:= ${LIBRESSL_LIB_DIR}/libtls.a ${LIBRESSL_LIB_DIR}/libssl.a ${LIBRESSL_LIB_DIR}/libcrypto.a

ADDITIONAL_LIBS := ${LIBRESSL_LIBS}

vpath %.c ${LIBHAL_SRC}/tests
vpath %.h ${LIBHAL_SRC}/tests:${LIBTFM_BLD}

include ${LIBHAL_SRC}/tests/Makefile
