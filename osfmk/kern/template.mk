#
# @OSF_FREE_COPYRIGHT@
#
#
# HISTORY
# 
# Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
# Import of Mac OS X kernel (~semeria)
#
# Revision 1.1.1.1  1998/03/07 02:25:56  wsanchez
# Import of OSF Mach kernel (~mburg)
#
# Revision 1.1.4.1  1995/02/23  17:32:24  alanl
# 	Taken from DIPC2_SHARED.  Add -X to MIG ala norma/template.mk
# 	[1995/02/22  20:46:31  alanl]
#
# Revision 1.1.2.1  1994/08/04  02:26:22  mmp
# 	Initial revision: NORMA_TASK split out from NORMA_INTERNAL and
# 	moved here from norma/template.mk.
# 	[1994/08/03  20:29:11  mmp]
# 
# $EndLog$

VPATH		= ..:../..

MIGFLAGS	= -MD ${IDENT} -X
MIGKSFLAGS	= -DKERNEL_SERVER
MIGKUFLAGS	= -DKERNEL_USER

NORMA_TASK_FILES =				\
	norma_task_server.h			\
	norma_task_server.c 

NORMA_TASK_USER_FILES =				\
	norma_task.h				\
	norma_task_user.c

OTHERS		= ${NORMA_TASK_FILES} ${NORMA_TASK_USER_FILES}

INCFLAGS	= -I.. -I../..
MDINCFLAGS	= -I.. -I../..

DEPENDENCIES	=

.include <${RULES_MK}>

.ORDER: ${NORMA_TASK_FILES}

${NORMA_TASK_FILES}:  kern/norma_task.defs
	${_MIG_} ${_MIGFLAGS_} ${MIGKSFLAGS}		\
		-header /dev/null			\
		-user /dev/null				\
		-sheader norma_task_server.h		\
                -server norma_task_server.c		\
                ${kern/norma_task.defs:P}

.ORDER: ${NORMA_TASK_USER_FILES}

${NORMA_TASK_USER_FILES}:  kern/norma_task.defs
	${_MIG_} ${_MIGFLAGS_} ${MIGKUFLAGS}		\
		-header norma_task.h			\
		-user norma_task_user.c			\
		-server /dev/null			\
                ${kern/norma_task.defs:P}

.if exists(depend.mk)
.include "depend.mk"
.endif
