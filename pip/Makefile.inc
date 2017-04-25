#CFLAGS+=-I${.CURDIR}/include -I${.CURDIR}/../../include
#CFLAGS+=-I${.CURDIR}/${LIBC_ARCH}

LWIP_BASE_DIR=${.CURDIR}/lwip
.PATH: ${.CURDIR}/lwip

CFLAGS+=-I${LWIP_BASE_DIR}/lwip_new/include/common


LWIP_COMMON_DIR=${LWIP_BASE_DIR}/lwip_new/common
LWIP_COMMON_MAKE=${LWIP_COMMON_DIR}/Makefile.bsd



LWIP_LIBRARY_DIR=${LWIP_BASE_DIR}/lwip_new/lwip_systems/library
LWIP_LIBRARY_MAKE=${LWIP_LIBRARY_DIR}/Makefile.bsd


.include <$(LWIP_COMMON_MAKE)>
.include <$(LWIP_LIBRARY_MAKE)>

#.include "./lwip/lwip/lwip_new/lwip_systems/library/Makefile.in" 
#.include "./lwip/lwip/lwip_new/lwip_systems/library/base/Makefile.inc"

#SRCS+= lwip_extlib.c

