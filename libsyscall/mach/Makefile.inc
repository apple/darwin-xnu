# machine-dependent mach sources
ARCHDIR = ${MACHINE_ARCH:C/^armv.*$/arm/}
.if exists(${.CURDIR}/mach/${ARCHDIR}/Makefile.inc)
.include "${.CURDIR}/mach/${ARCHDIR}/Makefile.inc"
.endif

.PATH: ${.CURDIR}/mach

.include "${.CURDIR}/mach/headers/Makefile.inc"
.include "${.CURDIR}/mach/servers/Makefile.inc"

MD_MIGDEFS += task.defs \
	thread_act.defs 

MD_MIGHDRS += ${MD_MIGDEFS:.defs=.h}

MIGDEFS += \
	clock.defs \
	clock_priv.defs \
	exc.defs \
	host_priv.defs \
	host_security.defs \
	ledger.defs \
	lock_set.defs \
	mach_port.defs \
	mach_host.defs \
	mach_vm.defs \
	processor.defs \
	processor_set.defs \
	vm_map.defs

MIGHDRS = ${MIGDEFS:.defs=.h}
MIGHDRS += clock_reply.h
MACH_INSTHDRS += ${MIGHDRS}

# These files are generated from the .defs files
MIGSRCS = ${MIGDEFS:.defs=User.c} ${MD_MIGDEFS:.defs=User.c}

MISRCS += ${MIGSRCS} \
	bootstrap_ports.c \
	clock_sleep.c \
	error_codes.c \
	excServer.c \
	excUser.c \
	exc_catcher.c \
	exc_catcher_state.c \
	exc_catcher_state_identity.c \
	fprintf_stderr.c \
	mig_allocate.c \
	mig_deallocate.c \
	mig_reply_setup.c  \
	mig_strncpy.c \
	mach_error.c \
	mach_error_string.c \
	mach_init.c \
	mach_init_libSystem.c \
	mach_init_ports.c \
	mach_msg.c \
	mach_traps.s \
	ms_thread_switch.c  \
	notifyUser.c \
	panic.c  \
	port_obj.c  \
	sbrk.c  \
	semaphore.c  \
	slot_name.c 

CLEANFILES += ${MIGHDRS} ${MIGSRCS} ${MD_MIGDEFS:.defs=Server.c} \
		${MIGDEFS:.defs=Server.c} exc.h excUser.c excServer.c \
		notify.h notifyUser.c notifyServer.c

MAN2 += brk.2

MLINKS += brk.2 sbrk.2
