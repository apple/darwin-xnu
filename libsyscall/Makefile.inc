# $FreeBSD: src/lMakefile.inc,v 1.7 2001/04/04 18:17:25 tmm Exp $
#
# This file contains make rules that are shared by libc and libc_r.
#
# Define (empty) variables so that make doesn't give substitution
# errors if the included makefiles don't change these:
MDSRCS=
MISRCS=
MDASM=
MIASM=
NOASM=

# SUPPRESSSRCS is used to prevent machine-independent files from being
# built, when a machine-dependent file defines multiple symbols.
# Use MDSRCS to block one file, and SUPPRESSSRCS to block the others.
SUPPRESSSRCS=

# set object file suffix
.if make(lib${LIB}_static.a)
OBJSUFFIX = o
.endif
.if make(lib${LIB}_profile.a)
OBJSUFFIX = po
.endif
.if make(lib${LIB}_debug.a)
OBJSUFFIX = do
.endif
.if make(lib${LIB}.a)
OBJSUFFIX = So
.endif

.if exists(${OBJROOT}/sys/Makefile.inc)
.include "${OBJROOT}/sys/Makefile.inc"
.endif
.include "${.CURDIR}/include/Makefile.inc"
.include "${.CURDIR}/mach/Makefile.inc"

# If there are no machine dependent sources, append all the
# machine-independent sources:
.if empty(MDSRCS)
SRCS+=	${MISRCS}
.else
# Append machine-dependent sources, then append machine-independent sources
# for which there is no machine-dependent variant, and not being suppressed.
SRCS+=	${MDSRCS}
_SUPPRESS= ${MDSRCS} ${SUPPRESSSRCS}
.for _src in ${MISRCS}
.if ${_SUPPRESS:R:M${_src:R}} == ""
SRCS+=	${_src}
.endif
.endfor
.endif
