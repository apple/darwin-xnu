#
# @OSF_COPYRIGHT@
#
#
# HISTORY
# 
# Revision 1.1.1.1  1998/09/22 21:05:31  wsanchez
# Import of Mac OS X kernel (~semeria)
#
# Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
# Import of OSF Mach kernel (~mburg)
#
# Revision 1.1.6.1  1994/09/23  02:33:31  ezf
# 	change marker to not FREE
# 	[1994/09/22  21:38:48  ezf]
#
# Revision 1.1.2.2  1993/08/04  19:32:26  gm
# 	CR9605: Add SUBDIRS to mach_kernel build process.
# 	[1993/08/03  13:30:04  gm]
# 
# $EndLog$

T_M_FILES	= ${MACH_I386_FILES}

MACH_I386_FILES = mach_i386_server.c mach_i386_server.h

.ORDER:  ${MACH_I386_FILES}

${MACH_I386_FILES}: mach/i386/mach_i386.defs
	${_MIG_} ${_MIGFLAGS_} ${MIGKSFLAGS}		\
		-header /dev/null			\
		-user /dev/null				\
		-sheader mach_i386_server.h		\
		-server mach_i386_server.c		\
		${mach/i386/mach_i386.defs:P}
