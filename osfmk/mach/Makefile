export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	machine

INSTINC_SUBDIRS_PPC = \
	ppc

INSTINC_SUBDIRS_I386 = \
	i386

EXPINC_SUBDIRS = \
	machine

EXPINC_SUBDIRS_PPC = \
	ppc

EXPINC_SUBDIRS_I386 = \
	i386

MIG_TYPES = \
	clock_types.defs \
	mach_types.defs \
	std_types.defs

MIG_DEFS =	\
	bootstrap.defs  \
	clock.defs \
	clock_priv.defs \
	clock_reply.defs \
	exc.defs \
	host_priv.defs \
	host_security.defs \
	ledger.defs \
	lock_set.defs \
	mach_host.defs \
	mach_port.defs \
	notify.defs \
	processor.defs \
	processor_set.defs \
	task.defs \
	thread_act.defs \
	vm_map.defs \
	upl.defs

MACH_PRIVATE_DEFS = \
	memory_object.defs \
	memory_object_control.defs \
	memory_object_default.defs \
	memory_object_name.defs

#
# MIG-generated headers that are traditionally used by user
# level code.
#
MIG_USHDRS = \
	clock_reply_server.h \
	exc_server.h \
	memory_object_server.h \
	memory_object_default_server.h \
	notify_server.h

MIG_UUHDRS = \
	bootstrap.h  \
	clock.h \
	clock_priv.h \
	host_priv.h \
	host_security.h \
	ledger.h \
	lock_set.h \
	mach_host.h \
	mach_port.h \
	memory_object_control.h \
	memory_object_name.h \
	processor.h \
	processor_set.h \
	task.h \
	thread_act.h \
	upl.h \
	vm_map.h

MIGINCLUDES = ${MIG_UUHDRS} ${MIG_USHDRS}

DATAFILES = \
        boolean.h \
	boot_info.h \
        clock_types.h \
        error.h \
	exception.h \
	exception_types.h \
        host_info.h \
	host_reboot.h \
	kern_return.h \
        kmod.h \
	mach_ioctl.h \
        mach_param.h \
	mach_time.h \
	mach_traps.h \
        mach_types.h \
	machine.h \
        mach_syscalls.h \
        memory_object_types.h \
        message.h \
	mig.h \
	mig_errors.h \
	mig_log.h \
	ndr.h \
        notify.h \
	policy.h \
	port.h \
        processor_info.h \
	rpc.h \
        semaphore.h \
	shared_memory_server.h \
	std_types.h \
	sync_policy.h \
        syscall_sw.h \
	task_info.h \
	task_ledger.h \
	task_policy.h \
	task_special_ports.h \
        thread_info.h \
	thread_policy.h \
	thread_special_ports.h \
        thread_status.h \
	thread_switch.h \
	time_value.h \
        vm_attributes.h \
        vm_behavior.h \
	vm_inherit.h \
	vm_param.h \
        vm_prot.h \
        vm_region.h \
	vm_statistics.h \
	vm_sync.h \
	vm_types.h \
	${MIG_TYPES} \
	${MIG_DEFS}

INSTALL_MI_LIST	= \
	${DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = mach

EXPORT_MI_LIST	= \
	mach_interface.h \
        etap.h etap_events.h \
	${DATAFILES}

EXPORT_MI_GEN_LIST = \
	${MIGINCLUDES}

EXPORT_MI_DIR = mach

.ORDER: ${MIGINCLUDES}

${MIGINCLUDES} : ${MIG_TYPES}

.ORDER: ${MIG_UUHDRS}

${MIG_UUHDRS} : \
	%.h : %.defs
	$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header $@ 		\
		$<

.ORDER: ${MIG_USHDRS}

${MIG_USHDRS} : \
	%_server.h : %.defs
	$(MIG) $(MIGFLAGS)		\
		-server /dev/null	\
		-user /dev/null		\
		-header /dev/null	\
		-sheader $@ 		\
		$<

#
# Build path
#
COMP_SUBDIRS_I386 = \
	i386

INCFLAGS_MAKEFILE= -I..

MIGKSFLAGS      = -DMACH_KERNEL_PRIVATE -DKERNEL_SERVER=1
MIGKUFLAGS      = -DMACH_KERNEL_PRIVATE -DKERNEL_USER=1 -maxonstack 1024
#
# MIG-generated headers that are traditionally used by kernel
# level code.
#
MIG_KUHDRS = \
	clock_reply.h \
	exc.h \
	memory_object.h \
	memory_object_default.h \
	upl.h \
	vm_map.h

MIG_KUSRC = \
	clock_reply_user.c \
	exc_user.c \
	memory_object_user.c \
	memory_object_default_user.c \
	upl_user.c \
	vm_map_user.c

MIG_KSHDRS = \
	clock_server.h \
	clock_priv_server.h \
	exc_server.h \
	host_priv_server.h \
	host_security_server.h \
	ledger_server.h \
	lock_set_server.h \
	mach_host_server.h \
	mach_port_server.h \
	memory_object_server.h \
	memory_object_control_server.h \
	memory_object_default_server.h \
	memory_object_name_server.h \
	notify_server.h \
	processor_server.h \
	processor_set_server.h \
	semaphore_server.h \
	task_server.h \
	thread_act_server.h \
	upl_server.h \
	vm_map_server.h

MIG_KSSRC = \
	clock_server.c \
	clock_priv_server.c \
	exc_server.c \
	host_priv_server.c \
	host_security_server.c \
	ledger_server.c \
	lock_set_server.c \
	mach_host_server.c \
	mach_port_server.c \
	memory_object_server.c \
	memory_object_control_server.c \
	memory_object_default_server.c \
	memory_object_name_server.c \
	notify_server.c \
	processor_server.c \
	processor_set_server.c \
	semaphore_server.c \
	task_server.c \
	thread_act_server.c \
	upl_server.c \
	vm_map_server.c

#
# JMM -
# Since there are two generated header files with the same name, one for
# install and export, the other for internal use (and they are different)
# we can't explicitly list two rules for the same target.  So rules for
# generating internal headers will be handled implicitly by creating rules
# to generate the internal C sources, and the headers get created as a
# side-effect.
#
#
# This is all temporary scaffolding, as we are moving to a model where
# the MIG-generated code is identical in all environments.  At first, it
# will contain some environment-specific ifdefs, but over time should not
# even require that as we move towards making all the environments look
# the same.
#
COMP_FILES = ${MIG_KUSRC} ${MIG_KSSRC}

${COMP_FILES} : ${MIG_TYPES}
        
.ORDER: ${MIG_KUSRC}                           

${MIG_KUSRC} : \
	%_user.c : %.defs
	${MIG} ${MIGFLAGS} ${MIGKUFLAGS}        \
		-user    $*_user.c              \
		-header  $*.h              \
		-server  /dev/null		\
		-sheader /dev/null		\
		$<

.ORDER: ${MIG_KSSRC}                           
        
${MIG_KSSRC}: \
	%_server.c : %.defs
	${MIG} ${MIGFLAGS} ${MIGKSFLAGS}        \
		-user    /dev/null              \
		-header  /dev/null              \
		-server  $*_server.c		\
		-sheader $*_server.h		\
		$<
        

include $(MakeInc_rule)
include $(MakeInc_dir)
