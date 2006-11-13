export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \

INSTINC_SUBDIRS_PPC = \

INSTINC_SUBDIRS_I386 = \

EXPINC_SUBDIRS = \

EXPINC_SUBDIRS_PPC = \

EXPINC_SUBDIRS_I386 = \

# In both the framework PrivateHeader area and /usr/include/sys
DATAFILES = \
	appleapiopts.h 	acct.h aio.h attr.h \
	buf.h cdefs.h conf.h \
	dir.h dirent.h disk.h dkstat.h  \
	errno.h ev.h event.h fcntl.h file.h filedesc.h filio.h gmon.h \
	ioccom.h ioctl.h \
	ioctl_compat.h ipc.h kernel.h kernel_types.h kern_event.h loadable_fs.h lock.h lockf.h \
	kauth.h kdebug.h md5.h kern_control.h malloc.h \
	mbuf.h mman.h mount.h msg.h msgbuf.h mtio.h netport.h param.h paths.h pipe.h poll.h \
	proc.h  ptrace.h queue.h quota.h random.h reboot.h resource.h resourcevar.h \
	select.h sem.h semaphore.h shm.h signal.h signalvar.h socket.h socketvar.h sockio.h stat.h \
	syscall.h sysctl.h syslimits.h syslog.h sys_domain.h termios.h  time.h \
	timeb.h times.h tprintf.h trace.h tty.h  ttychars.h ttycom.h \
	ttydefaults.h ttydev.h  types.h ubc.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	user.h utfconv.h utsname.h vadvise.h vcmd.h  version.h \
	vm.h vmmeter.h vmparam.h vnioctl.h vnode.h vnode_if.h vstat.h wait.h xattr.h \
	_types.h _endian.h domain.h protosw.h 

# Only in the framework PrivateHeader area
PRIVATE_DATAFILES = \
	disklabel.h \
	ipcs.h \
	sem_internal.h \
	shm_internal.h \
	ux_exception.h \
	ktrace.h \
	proc_info.h \
	vnioctl.h

# KERNELFILES will appear only in the kernel framework
KERNELFILES = \
	appleapiopts.h 	 attr.h \
	buf.h cdefs.h conf.h \
	dir.h dirent.h disk.h dkstat.h  \
	errno.h ev.h event.h fcntl.h file.h filedesc.h filio.h \
	ioccom.h ioctl.h \
	ioctl_compat.h  kernel.h kernel_types.h kern_event.h  lock.h lockf.h \
	kauth.h kdebug.h  md5.h kern_control.h malloc.h namei.h \
	mman.h mbuf.h mount.h  mtio.h netport.h param.h paths.h \
	proc.h  queue.h quota.h random.h resource.h resourcevar.h \
	select.h signal.h socket.h socketvar.h sockio.h stat.h \
	sysctl.h syslimits.h syslog.h systm.h sys_domain.h  time.h \
	types.h ubc.h ucontext.h ucred.h uio.h un.h unistd.h unpcb.h \
	utfconv.h  version.h \
	vm.h vmparam.h vnode.h vnode_if.h xattr.h \
	_types.h _endian.h protosw.h domain.h \
	kpi_mbuf.h kpi_socket.h kpi_socketfilter.h \
	ttycom.h termios.h


# Only in the private kernel framework
PRIVATE_KERNELFILES = \
	disktab.h \
	file_internal.h \
	mach_swapon.h \
	msgbuf.h \
	eventvar.h \
	mount_internal.h \
	proc_internal.h \
	ptrace_internal.h \
	vnode_internal.h \
	signalvar.h \
	tty.h  ttychars.h \
	ttydefaults.h ttydev.h \
	user.h \
	ubc_internal.h \
	uio_internal.h \
	vfs_context.h 
	

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_DIR = sys

EXPORT_MI_LIST	= ${KERNELFILES} ${PRIVATE_KERNELFILES} syscall.h ktrace.h linker_set.h bsdtask_info.h

EXPORT_MI_DIR = sys

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders

INSTALL_KF_MI_LCL_LIST =  ${KERNELFILES} ${PRIVATE_KERNELFILES}

# /System/Library/Frameworks/Kernel.framework/Headers

INSTALL_KF_MI_LIST = ${KERNELFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)


