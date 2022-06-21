# $FreeBSD$
.PATH:  ${SRCTOP}/sys/dev/device_simulation_freebsd

KMOD=	madbus
SRCS= \
	madbusmain.c \
	mbdevthread.c
SRCS+=	${LINUXKPI_GENSRCS}

CFLAGS+= -I${SRCTOP}/sys/compat/linuxkpi/common/include

.include <bsd.kmod.mk>

# DEBUG = y
# KMOD= madbus
# SRCS= madbus.h \
# madbusmain.c mbdevthread.c \
# vnode_if.h device_if.h bus_if.h pci_if.h
# # CFLAGS= -I/usr/src/sys/compat/linuxkpi/common/include -I../../include
# .include <bsd.kmod.mk>


# # madbusioctls.h maddefs.h madkonsts.h \
