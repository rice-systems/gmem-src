#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD$

.include <src.opts.mk>

MAN=	\
	beinstall.8 \
	crash.8 \
	diskless.8 \
	intro.8 \
	nanobsd.8 \
	rc.8 \
	rc.sendmail.8 \
	rc.subr.8 \
	rescue.8 \
	${_uefi.8} \

MLINKS= \
	beinstall.8 beinstall.sh.8 \
	nanobsd.8 nanobsd.sh.8 \
	rc.8 rc.d.8 \
	rc.8 rc.firewall.8 \
	rc.8 rc.local.8 \
	rc.8 rc.network.8 \
	rc.8 rc.pccard.8 \
	rc.8 rc.resume.8 \
	rc.8 rc.serial.8 \
	rc.8 rc.shutdown.8

.if ${MK_NIS} != "no"
MAN+=	yp.8

MLINKS+=yp.8 NIS.8 \
	yp.8 nis.8 \
	yp.8 YP.8
.endif

# This makes more sense for aarch 64 and amd64
# we decide to install all manpages in all architectures
_uefi.8= uefi.8

MLINKS+=uefi.8 efi.8

.include <bsd.prog.mk>
