export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

ALLPRODUCTS = AppleTV iPhone MacOSX
PRODUCT = $(shell tconf --product)
EXTRAUNIFDEF = $(foreach x,$(ALLPRODUCTS),$(if $(findstring $(PRODUCT),$(x)),-DPRODUCT_$(x),-UPRODUCT_$(x)))
SINCFRAME_UNIFDEF += $(EXTRAUNIFDEF)
SPINCFRAME_UNIFDEF += $(EXTRAUNIFDEF)
KINCFRAME_UNIFDEF += $(EXTRAUNIFDEF)
KPINCFRAME_UNIFDEF += $(EXTRAUNIFDEF)

INSTINC_SUBDIRS = \

INSTINC_SUBDIRS_PPC = \

INSTINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS = \

EXPINC_SUBDIRS_PPC = \

EXPINC_SUBDIRS_I386 = \

# Installs header file for user level -  
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
#	  $(DSTROOT)/usr/include/
DATAFILES = \
	appleapiopts.h 	acct.h aio.h attr.h \
	buf.h cdefs.h conf.h \
	dir.h dirent.h disk.h dkstat.h dtrace.h dtrace_glue.h dtrace_impl.h \
	errno.h ev.h event.h fasttrap.h fasttrap_isa.h fcntl.h file.h filedesc.h filio.h gmon.h \
	ioccom.h ioctl.h \
	ioctl_compat.h ipc.h kernel.h kernel_types.h kern_event.h loadable_fs.h lock.h lockf.h \
	kauth.h kdebug.h kern_control.h kern_memorystatus.h lctx.h malloc.h \
	mbuf.h mman.h mount.h msg.h msgbuf.h netport.h param.h paths.h pipe.h poll.h \
	proc.h  proc_info.h ptrace.h queue.h quota.h random.h reboot.h resource.h resourcevar.h \
	sbuf.h posix_sem.h posix_shm.h sdt.h \
	select.h sem.h semaphore.h shm.h signal.h signalvar.h socket.h socketvar.h sockio.h stat.h \
	sysctl.h syslimits.h syslog.h sys_domain.h termios.h  time.h \
	timeb.h times.h tprintf.h trace.h tty.h  ttychars.h ttycom.h \
	ttydefaults.h ttydev.h  types.h ubc.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	user.h utfconv.h utsname.h vadvise.h vcmd.h \
	vm.h vmmeter.h vmparam.h vnioctl.h vnode.h vnode_if.h vstat.h wait.h xattr.h \
	_select.h _structs.h _types.h _endian.h domain.h protosw.h \
	spawn.h

# Installs header file for Apple internal use in user level - 
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
PRIVATE_DATAFILES = \
	codesign.h \
	disklabel.h \
	fsctl.h \
	fsgetpath.h \
	fslog.h \
	ipcs.h \
	shm_internal.h \
	spawn_internal.h \
	tree.h \
	ux_exception.h \
	proc_info.h \
	vnioctl.h

# Installs header file for kernel extensions - 
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
KERNELFILES = \
	appleapiopts.h 	 attr.h \
	buf.h cdefs.h conf.h \
	dir.h dirent.h disk.h disklabel.h dkstat.h  \
	errno.h ev.h event.h fcntl.h file.h filio.h \
	ioccom.h ioctl.h ipc.h \
	ioctl_compat.h  kernel.h kernel_types.h kern_event.h lctx.h lock.h lockf.h \
	kauth.h kdebug.h  md5.h kern_callout.h kern_control.h kern_memorystatus.h imgact.h malloc.h namei.h \
	mman.h mbuf.h mount.h netport.h param.h paths.h \
	proc.h  queue.h random.h resource.h \
	sbuf.h posix_sem.h posix_shm.h sem.h shm.h \
	select.h signal.h socket.h socketvar.h sockio.h stat.h \
	sysctl.h syslimits.h syslog.h systm.h sys_domain.h  time.h \
	types.h ubc.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	utfconv.h vm.h vmparam.h vnode.h vnode_if.h xattr.h \
	_select.h _structs.h _types.h _endian.h protosw.h domain.h \
	kpi_mbuf.h kpi_socket.h kpi_socketfilter.h \
	ttycom.h termios.h msg.h \
	wait.h \
	spawn.h
# The last line was added to export needed headers for the MAC calls
# whose source is outside of the xnu/bsd tree.


# Installs header file for Apple internal use for kernel extensions - 
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \
	cprotect.h \
	decmpfs.h \
	disktab.h \
	fbt.h \
	fsctl.h \
	fslog.h \
	mach_swapon.h \
	msgbuf.h \
	eventvar.h \
	quota.h \
	sem_internal.h \
	shm_internal.h \
	signalvar.h \
	tty.h  ttychars.h \
	ttydefaults.h ttydev.h \
	user.h \
	vfs_context.h \
	vmmeter.h \
	spawn_internal.h


# /System/Library/Frameworks/System.framework/Headers and /usr/include
INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_GEN_LIST = syscall.h

INSTALL_MI_DIR = sys

EXPORT_MI_LIST	= ${KERNELFILES} ${PRIVATE_KERNELFILES} linker_set.h bsdtask_info.h filedesc.h pipe.h resourcevar.h semaphore.h \
								vnode_internal.h proc_internal.h file_internal.h mount_internal.h \
								uio_internal.h

EXPORT_MI_GEN_LIST = syscall.h sysproto.h

EXPORT_MI_DIR = sys

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST =  ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_KF_MI_LCL_GEN_LIST = sysproto.h

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_GEN_LIST = 

MAKESYSCALLS = $(SRCROOT)/bsd/kern/makesyscalls.sh

syscall.h: $(SRCROOT)/bsd/kern/syscalls.master $(MAKESYSCALLS)
	@echo "Generating bsd/sys/$@ from $<";
	$(_v)$(MAKESYSCALLS) $< header > /dev/null

sysproto.h: $(SRCROOT)/bsd/kern/syscalls.master $(MAKESYSCALLS)
	@echo "Generating bsd/sys/$@ from $<";
	$(_v)$(MAKESYSCALLS) $< proto > /dev/null

include $(MakeInc_rule)
include $(MakeInc_dir)


