#	@(#)Makefile	8.2 (Berkeley) 2/3/94
# $FreeBSD: src/lib/libc/Makefile,v 1.31 2001/08/13 21:48:43 peter Exp $
#
# All library objects contain rcsid strings by default; they may be
# excluded as a space-saving measure.  To produce a library that does
# not contain these strings, delete -DLIBC_RCS and -DSYSLIBC_RCS
# from CFLAGS below.  To remove these strings from just the system call
# stubs, remove just -DSYSLIBC_RCS from CFLAGS.
#
# Yes, we build everything with -g, and strip it out later...
#
LIB=syscall
SHLIB_MAJOR= 1
SHLIB_MINOR= 0
.if (${MACHINE_ARCH} == unknown)
MACHINE_ARCH != /usr/bin/arch
.endif 
.if !empty $(MACHINE_ARCH:M*64)
LP64 = 1
.endif
CC = gcc
.ifdef ALTFRAMEWORKSPATH
PRIVINC = -F${ALTFRAMEWORKSPATH} -I${ALTFRAMEWORKSPATH}/System.framework/PrivateHeaders
.else
PRIVINC = -I${NEXT_ROOT}/System/Library/Frameworks/System.framework/PrivateHeaders
.endif
CFLAGS += ${PRIVINC}
CFLAGS += -no-cpp-precomp -force_cpusubtype_ALL
CFLAGS += -fno-common -pipe -Wmost -g
AINC= -no-cpp-precomp -force_cpusubtype_ALL
AINC+= -arch ${MACHINE_ARCH} -g
CLEANFILES+=tags
INSTALL_PIC_ARCHIVE=	yes
PRECIOUSLIB=	yes

# workaround for 3649783
AINC += -fdollars-in-identifiers

# If these aren't set give it expected defaults
DESTDIR ?= ${DSTROOT}
MAKEOBJDIR ?= ${OBJROOT}

# add version string
SRCS += libsyscall_version.c
libsyscall_version.c:
	/Developer/Makefiles/bin/version.pl Libsyscall > $@

CFLAGS += -I${SYMROOT}
.include "${.CURDIR}/Makefile.inc"
.PATH: ${SYMROOT}
.include "Makefile.xbs"
.if exists(/usr/share/mk/bsd.init.mk)
.include <bsd.init.mk>
.endif
.include <bsd.man.mk>
