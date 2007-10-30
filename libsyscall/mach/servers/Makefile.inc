.PATH: ${.CURDIR}/${MACHINE_ARCH}/mach/servers ${.CURDIR}/mach/servers

SRVMIGDEFS += netname.defs

SRVMIGHDRS = ${SRVMIGDEFS:S/.defs$/.h/}
#SRVMIGHDRS = ${SRVMIGDEFS:S/.defs$/.h/:S/^/${.CURDIR}\/mach\/servers\//}
SRVMIGSRCS = ${SRVMIGDEFS:S/.defs$/User.c/}

SRVHDRS = netname_defs.h key_defs.h nm_defs.h ls_defs.h 
SRVHDRS := ${SRVHDRS:S/^/${.CURDIR}\/mach\/servers\//}
SRVHDRS += ${SRVMIGHDRS}

MISRCS+= ${SRVMIGDEFS:S/.defs$/User.defs/}

CLEANFILES += ${SRVMIGHDRS} ${SRVMIGHDRS:S/.h$/User.c/} \
		${SRVMIGHDRS:S/.h$/Server.c/}
