/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*
* DEPRECATED sysctl system call code
 *
 * Everything in this file is deprecated. Sysctls should be handled
 * by the code in kern_newsysctl.c.
 * The remaining "case" sections are supposed to be converted into
 * SYSCTL_*-style definitions, and as soon as all of them are gone,
 * this source file is supposed to die.
 *
 * DO NOT ADD ANY MORE "case" SECTIONS TO THIS FILE, instead define
 * your sysctl with SYSCTL_INT, SYSCTL_PROC etc. in your source file.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/unistd.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/namei.h>
#include <sys/tty.h>
#include <sys/disklabel.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/aio_kern.h>
#include <sys/reboot.h>

#include <bsm/audit_kernel.h>

#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>

#include <sys/mount_internal.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>

#include <IOKit/IOPlatformExpert.h>
#include <pexpert/pexpert.h>

#include <machine/machine_routines.h>
#include <machine/exec.h>

#include <vm/vm_protos.h>

#ifdef __i386__
#include <i386/cpuid.h>
#endif

sysctlfn kern_sysctl;
#ifdef DEBUG
sysctlfn debug_sysctl;
#endif
extern sysctlfn net_sysctl;
extern sysctlfn cpu_sysctl;
extern int aio_max_requests;  				
extern int aio_max_requests_per_process;	
extern int aio_worker_threads;				
extern int lowpri_IO_window_msecs;
extern int lowpri_IO_delay_msecs;
extern int nx_enabled;
extern int speculative_reads_disabled;

static void
fill_eproc(proc_t p, struct eproc *ep);
static void
fill_externproc(proc_t p, struct extern_proc *exp);
static void
fill_user_eproc(proc_t p, struct user_eproc *ep);
static void
fill_user_proc(proc_t p, struct user_kinfo_proc *kp);
static void
fill_user_externproc(proc_t p, struct user_extern_proc *exp);
extern int 
kdbg_control(int *name, u_int namelen, user_addr_t where, size_t * sizep);
int
kdebug_ops(int *name, u_int namelen, user_addr_t where, size_t *sizep, proc_t p);
#if NFSCLIENT
extern int 
netboot_root(void);
#endif
int
pcsamples_ops(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
              proc_t p);
__private_extern__ kern_return_t
reset_vmobjectcache(unsigned int val1, unsigned int val2);
int
sysctl_doproc(int *name, u_int namelen, user_addr_t where, size_t *sizep);
int 
sysctl_doprof(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
			  user_addr_t newp, size_t newlen);
static void
fill_proc(proc_t p, struct kinfo_proc *kp);
int
sysctl_procargs(int *name, u_int namelen, user_addr_t where, 
				size_t *sizep, proc_t cur_proc);
static int
sysctl_procargs2(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
                 proc_t cur_proc);
static int
sysctl_procargsx(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
                 proc_t cur_proc, int argc_yes);
int
sysctl_struct(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, 
              size_t newlen, void *sp, int len);

static int sysdoproc_filt_KERN_PROC_PID(proc_t p, void * arg);
static int sysdoproc_filt_KERN_PROC_PGRP(proc_t p, void * arg);
static int sysdoproc_filt_KERN_PROC_TTY(proc_t p, void * arg);
static int  sysdoproc_filt_KERN_PROC_UID(proc_t p, void * arg);
static int  sysdoproc_filt_KERN_PROC_RUID(proc_t p, void * arg);
static int  sysdoproc_filt_KERN_PROC_LCID(proc_t p, void * arg);
int sysdoproc_callback(proc_t p, void *arg);

static int __sysctl_funneled(proc_t p, struct __sysctl_args *uap, register_t *retval);

extern void IORegistrySetOSBuildVersion(char * build_version); 

static void
loadavg32to64(struct loadavg *la32, struct user_loadavg *la64)
{
	la64->ldavg[0]	= la32->ldavg[0];
	la64->ldavg[1]	= la32->ldavg[1];
	la64->ldavg[2]	= la32->ldavg[2];
	la64->fscale	= (user_long_t)la32->fscale;
}

/*
 * Locking and stats
 */
static struct sysctl_lock memlock;

/* sysctl() syscall */
int
__sysctl(proc_t p, struct __sysctl_args *uap, register_t *retval)
{
	boolean_t funnel_state;
	int error;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	error = __sysctl_funneled(p, uap, retval);
	thread_funnel_set(kernel_flock, funnel_state);
	return(error);
}

static int
__sysctl_funneled(proc_t p, struct __sysctl_args *uap, __unused register_t *retval)
{
	int error, dolock = 1;
	size_t savelen = 0, oldlen = 0, newlen;
	sysctlfn *fnp = NULL;
	int name[CTL_MAXNAME];
	int error1;
	boolean_t memlock_taken = FALSE;
	boolean_t vslock_taken = FALSE;
#if CONFIG_MACF
	kauth_cred_t my_cred;
#endif

	/*
	 * all top-level sysctl names are non-terminal
	 */
	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);
	error = copyin(uap->name, &name[0], uap->namelen * sizeof(int));
	if (error)
		return (error);
		
	AUDIT_ARG(ctlname, name, uap->namelen);

	if (proc_is64bit(p)) {
		/* uap->newlen is a size_t value which grows to 64 bits 
		 * when coming from a 64-bit process.  since it's doubtful we'll 
		 * have a sysctl newp buffer greater than 4GB we shrink it to size_t
		 */
		newlen = CAST_DOWN(size_t, uap->newlen);
	}
	else {
		newlen = uap->newlen;
	}

	/* CTL_UNSPEC is used to get oid to AUTO_OID */
	if (uap->new != USER_ADDR_NULL
	    && ((name[0] == CTL_KERN
		&& !(name[1] == KERN_IPC || name[1] == KERN_PANICINFO || name[1] == KERN_PROCDELAYTERM || 
		     name[1] == KERN_PROC_LOW_PRI_IO || name[1] == KERN_PROCNAME || name[1] == KERN_RAGEVNODE || name[1] == KERN_CHECKOPENEVT))
	    || (name[0] == CTL_HW)
	    || (name[0] == CTL_VM))
	    && (error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

/* XXX: KERN, VFS and DEBUG are handled by their respective functions,
 * but there is a fallback for all sysctls other than VFS to
 * userland_sysctl() - KILL THIS! */
	switch (name[0]) {
	case CTL_KERN:
		fnp = kern_sysctl;
		if ((name[1] != KERN_VNODE) && (name[1] != KERN_FILE) 
			&& (name[1] != KERN_PROC))
			dolock = 0;
		break;
	case CTL_VFS:
		fnp = vfs_sysctl;
		break;
#ifdef DEBUG
	case CTL_DEBUG:
		fnp = debug_sysctl;
		break;
#endif
	default:
		fnp = NULL;
	}

	if (uap->oldlenp != USER_ADDR_NULL) {
		uint64_t	oldlen64 = fuulong(uap->oldlenp);

		oldlen = CAST_DOWN(size_t, oldlen64);
		/*
		 * If more than 4G, clamp to 4G - useracc() below will catch
		 * with an EFAULT, if it's actually necessary.
		 */
		if (oldlen64 > 0x00000000ffffffffULL)
			oldlen = 0xffffffffUL;
	}

	if (uap->old != USER_ADDR_NULL) {
		if (!useracc(uap->old, (user_size_t)oldlen, B_WRITE))
			return (EFAULT);
		/*
		 * The kernel debug mechanism does not need to take this lock, and
		 * we don't grab the memlock around calls to KERN_PROC because it is reentrant.
		 * Grabbing the lock for a KERN_PROC sysctl makes a deadlock possible 5024049.
		 */
		if (!((name[1] == KERN_KDEBUG) && (name[2] == KERN_KDGETENTROPY)) &&
		    !(name[1] == KERN_PROC)) {
		        MEMLOCK_LOCK();
			memlock_taken = TRUE;
                }

		if (dolock && oldlen) {
		        if ((error = vslock(uap->old, (user_size_t)oldlen))) {
			        if (memlock_taken == TRUE)
				        MEMLOCK_UNLOCK();
				return(error);
			}
			savelen = oldlen;
			vslock_taken = TRUE;
		}
	}

#if CONFIG_MACF
	my_cred = kauth_cred_proc_ref(p);
	error = mac_system_check_sysctl(
	    my_cred, 
	    (int *) name,
	    uap->namelen,
  	    uap->old,
	    uap->oldlenp,
	    fnp == kern_sysctl ? 1 : 0,
	    uap->new,
	    newlen
   	);
	kauth_cred_unref(&my_cred);
	if (!error) {
#endif
	if (fnp) {
	        error = (*fnp)(name + 1, uap->namelen - 1, uap->old,
                       &oldlen, uap->new, newlen, p);
	}
	else
	        error = ENOTSUP;
#if CONFIG_MACF
	}
#endif

	if (vslock_taken == TRUE) {
	        error1 = vsunlock(uap->old, (user_size_t)savelen, B_WRITE);
		if (!error)
		        error = error1;
        }
	if (memlock_taken == TRUE)
	        MEMLOCK_UNLOCK();

	if ( (name[0] != CTL_VFS) && (error == ENOTSUP)) {
	        size_t  tmp = oldlen;
		boolean_t funnel_state;

		/*
		 * Drop the funnel when calling new sysctl code, which will conditionally
		 * grab the funnel if it really needs to.
		 */
		funnel_state = thread_funnel_set(kernel_flock, FALSE);
		
		error = userland_sysctl(p, name, uap->namelen, uap->old, &tmp, 
		                        1, uap->new, newlen, &oldlen);

		thread_funnel_set(kernel_flock, funnel_state);
	}

	if ((error) && (error != ENOMEM))
		return (error);

	if (uap->oldlenp != USER_ADDR_NULL)
	        error = suulong(uap->oldlenp, oldlen);

	return (error);
}

/*
 * Attributes stored in the kernel.
 */
__private_extern__ char corefilename[MAXPATHLEN+1];
__private_extern__ int do_coredump;
__private_extern__ int sugid_coredump;

#if COUNT_SYSCALLS
__private_extern__ int do_count_syscalls;
#endif

#ifdef INSECURE
int securelevel = -1;
#else
int securelevel;
#endif

static int
sysctl_affinity(
	int *name,
	u_int namelen,
	user_addr_t oldBuf,
	size_t *oldSize,
	user_addr_t newBuf,
	__unused size_t newSize,
	proc_t cur_proc)
{
	if (namelen < 1)
		return (ENOTSUP);

	if (name[0] == 0 && 1 == namelen) {
		return sysctl_rdint(oldBuf, oldSize, newBuf,
			                (cur_proc->p_flag & P_AFFINITY) ? 1 : 0);
	} else if (name[0] == 1 && 2 == namelen) {
		if (name[1] == 0) {
			OSBitAndAtomic(~((uint32_t)P_AFFINITY), (UInt32 *)&cur_proc->p_flag);
		} else {
			OSBitOrAtomic(P_AFFINITY, (UInt32 *)&cur_proc->p_flag);
		}
		return 0;
	}
	return (ENOTSUP);
}

static int
sysctl_translate(
	int *name,
	u_int namelen,
	user_addr_t oldBuf,
	size_t *oldSize,
	user_addr_t newBuf,
	__unused size_t newSize,
	proc_t cur_proc)
{
	proc_t p;
	int istranslated = 0;
	kauth_cred_t my_cred;
	uid_t uid;

	if (namelen != 1)
		return (ENOTSUP);

	p = proc_find(name[0]);
	if (p == NULL)
		return (EINVAL);

	my_cred = kauth_cred_proc_ref(p);
	uid = kauth_cred_getuid(my_cred);
	kauth_cred_unref(&my_cred);
	if ((uid != kauth_cred_getuid(kauth_cred_get())) 
		&& suser(kauth_cred_get(), &cur_proc->p_acflag)) {
		proc_rele(p);
		return (EPERM);
	}

	istranslated = (p->p_flag & P_TRANSLATED);
	proc_rele(p);
	return sysctl_rdint(oldBuf, oldSize, newBuf,
		                (istranslated != 0) ? 1 : 0);
}

int
set_archhandler(__unused proc_t p, int arch)
{
	int error;
	struct nameidata nd;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	struct exec_archhandler *archhandler;

	switch(arch) {
	case CPU_TYPE_POWERPC:
		archhandler = &exec_archhandler_ppc;
		break;
	default:
		return (EBADARCH);
	}

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32,
		   CAST_USER_ADDR_T(archhandler->path), ctx);
	error = namei(&nd);
	if (error)
		return (error);
	nameidone(&nd);
	
	/* Check mount point */
	if ((nd.ni_vp->v_mount->mnt_flag & MNT_NOEXEC) ||
		(nd.ni_vp->v_type != VREG)) {
		vnode_put(nd.ni_vp);
		return (EACCES);
	}
	
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);
	error = vnode_getattr(nd.ni_vp, &va, ctx);
	if (error) {
		vnode_put(nd.ni_vp);
		return (error);
	}
	vnode_put(nd.ni_vp);
	
	archhandler->fsid = va.va_fsid;
	archhandler->fileid = (u_long)va.va_fileid;
	return 0;
}

/* XXX remove once Rosetta is rev'ed */
/*****************************************************************************/
static int
sysctl_exec_archhandler_ppc(
	__unused int *name,
	__unused u_int namelen,
	user_addr_t oldBuf,
	size_t *oldSize,
	user_addr_t newBuf,
	size_t newSize,
	proc_t p)
{
	int error;
	size_t len;
	char handler[sizeof(exec_archhandler_ppc.path)];
	vfs_context_t ctx = vfs_context_current();

	if (oldSize) {
		len = strlen(exec_archhandler_ppc.path) + 1;
		if (oldBuf) {
			if (*oldSize < len)
				return (ENOMEM);
			error = copyout(exec_archhandler_ppc.path, oldBuf, len);
			if (error)
				return (error);
		}
		*oldSize = len - 1;
	}
	if (newBuf) {
		error = suser(vfs_context_ucred(ctx), &p->p_acflag);
		if (error)
			return (error);
		if (newSize >= sizeof(exec_archhandler_ppc.path))
			return (ENAMETOOLONG);
		error = copyin(newBuf, handler, newSize);
		if (error)
			return (error);
		handler[newSize] = 0;
		strlcpy(exec_archhandler_ppc.path, handler, MAXPATHLEN);
		error = set_archhandler(p, CPU_TYPE_POWERPC);
		if (error)
			return (error);
	}
	return 0;
}
/*****************************************************************************/

static int
sysctl_handle_exec_archhandler_ppc(struct sysctl_oid *oidp, void *arg1,
		int arg2, struct sysctl_req *req)
{
	int error = 0;

	error = sysctl_handle_string(oidp, arg1, arg2, req);

	if (error)
		goto done;

	if (req->newptr)
		error = set_archhandler(req->p, CPU_TYPE_POWERPC);

done:
	return error;

}

SYSCTL_NODE(_kern, KERN_EXEC, exec, CTLFLAG_RD|CTLFLAG_LOCKED, 0, "");

SYSCTL_NODE(_kern_exec, OID_AUTO, archhandler, CTLFLAG_RD|CTLFLAG_LOCKED, 0, "");

SYSCTL_PROC(_kern_exec_archhandler, OID_AUTO, powerpc,
	    CTLTYPE_STRING | CTLFLAG_RW, exec_archhandler_ppc.path, 0,
	    sysctl_handle_exec_archhandler_ppc, "A", "");

extern int get_kernel_symfile(proc_t, char **);
__private_extern__ int 
sysctl_dopanicinfo(int *, u_int, user_addr_t, size_t *, user_addr_t, 
                   size_t, proc_t);

/*
 * kernel related system variables.
 */
int
kern_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
            user_addr_t newp, size_t newlen, proc_t p)
{
	/* all sysctl names not listed below are terminal at this level */
	if (namelen != 1
		&& !(name[0] == KERN_PROC
			|| name[0] == KERN_PROF 
			|| name[0] == KERN_KDEBUG
#if !CONFIG_EMBEDDED
			|| name[0] == KERN_PROCARGS
#endif
			|| name[0] == KERN_PROCARGS2
			|| name[0] == KERN_IPC
			|| name[0] == KERN_SYSV
			|| name[0] == KERN_AFFINITY
			|| name[0] == KERN_TRANSLATE
			|| name[0] == KERN_EXEC
			|| name[0] == KERN_PANICINFO
			|| name[0] == KERN_POSIX
			|| name[0] == KERN_TFP
			|| name[0] == KERN_TTY
#if CONFIG_LCTX
			|| name[0] == KERN_LCTX
#endif
						)
		)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case KERN_PROC:
		return (sysctl_doproc(name + 1, namelen - 1, oldp, oldlenp));
#ifdef GPROF
	case KERN_PROF:
		return (sysctl_doprof(name + 1, namelen - 1, oldp, oldlenp,
		    newp, newlen));
#endif
	case KERN_KDEBUG:
		return (kdebug_ops(name + 1, namelen - 1, oldp, oldlenp, p));
#if !CONFIG_EMBEDDED
	case KERN_PROCARGS:
		/* new one as it does not use kinfo_proc */
		return (sysctl_procargs(name + 1, namelen - 1, oldp, oldlenp, p));
#endif
	case KERN_PROCARGS2:
		/* new one as it does not use kinfo_proc */
		return (sysctl_procargs2(name + 1, namelen - 1, oldp, oldlenp, p));
#if PANIC_INFO
	case KERN_PANICINFO:
		return(sysctl_dopanicinfo(name + 1, namelen - 1, oldp, oldlenp,
			newp, newlen, p));
#endif
	case KERN_AFFINITY:
		return sysctl_affinity(name+1, namelen-1, oldp, oldlenp,
									newp, newlen, p);
	case KERN_TRANSLATE:
		return sysctl_translate(name+1, namelen-1, oldp, oldlenp, newp,
				      newlen, p);

		/* XXX remove once Rosetta has rev'ed */
	case KERN_EXEC:
		return sysctl_exec_archhandler_ppc(name+1, namelen-1, oldp,
						   oldlenp, newp, newlen, p);
#if COUNT_SYSCALLS
	case KERN_COUNT_SYSCALLS:
	{
		/* valid values passed in:
		 * = 0 means don't keep called counts for each bsd syscall
		 * > 0 means keep called counts for each bsd syscall
		 * = 2 means dump current counts to the system log
		 * = 3 means reset all counts
		 * for example, to dump current counts:  
		 *		sysctl -w kern.count_calls=2
		 */
		error = sysctl_int(oldp, oldlenp, newp, newlen, &tmp);
		if ( error != 0 ) {
			return (error);
		}
			
		if ( tmp == 1 ) {
			do_count_syscalls = 1;
		}
		else if ( tmp == 0 || tmp == 2 || tmp == 3 ) {
			extern int 			nsysent;
			extern int			syscalls_log[];
			extern const char *	syscallnames[];
			int			i;
			for ( i = 0; i < nsysent; i++ ) {
				if ( syscalls_log[i] != 0 ) {
					if ( tmp == 2 ) {
						printf("%d calls - name %s \n", syscalls_log[i], syscallnames[i]);
					}
					else {
						syscalls_log[i] = 0;
					}
				}
			}
			if ( tmp != 0 ) {
				do_count_syscalls = 1;
			}
		}
		return (0);
	}
#endif
	default:
		return (ENOTSUP);
	}
	/* NOTREACHED */
}

#ifdef DEBUG
/*
 * Debugging related system variables.
 */
#if DIAGNOSTIC
extern
#endif /* DIAGNOSTIC */
struct ctldebug debug0, debug1;
struct ctldebug debug2, debug3, debug4;
struct ctldebug debug5, debug6, debug7, debug8, debug9;
struct ctldebug debug10, debug11, debug12, debug13, debug14;
struct ctldebug debug15, debug16, debug17, debug18, debug19;
static struct ctldebug *debugvars[CTL_DEBUG_MAXID] = {
	&debug0, &debug1, &debug2, &debug3, &debug4,
	&debug5, &debug6, &debug7, &debug8, &debug9,
	&debug10, &debug11, &debug12, &debug13, &debug14,
	&debug15, &debug16, &debug17, &debug18, &debug19,
};
int
debug_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
             user_addr_t newp, size_t newlen, __unused proc_t p)
{
	struct ctldebug *cdp;

	/* all sysctl names at this level are name and field */
	if (namelen != 2)
		return (ENOTDIR);		/* overloaded */
	if (name[0] < 0 || name[0] >= CTL_DEBUG_MAXID)
                return (ENOTSUP);
	cdp = debugvars[name[0]];
	if (cdp->debugname == 0)
		return (ENOTSUP);
	switch (name[1]) {
	case CTL_DEBUG_NAME:
		return (sysctl_rdstring(oldp, oldlenp, newp, cdp->debugname));
	case CTL_DEBUG_VALUE:
		return (sysctl_int(oldp, oldlenp, newp, newlen, cdp->debugvar));
	default:
		return (ENOTSUP);
	}
	/* NOTREACHED */
}
#endif /* DEBUG */

/*
 * The following sysctl_* functions should not be used
 * any more, as they can only cope with callers in
 * user mode: Use new-style
 *  sysctl_io_number()
 *  sysctl_io_string()
 *  sysctl_io_opaque()
 * instead.
 */

/*
 * Validate parameters and get old / set new parameters
 * for an integer-valued sysctl function.
 */
int
sysctl_int(user_addr_t oldp, size_t *oldlenp, 
           user_addr_t newp, size_t newlen, int *valp)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp && newlen != sizeof(int))
		return (EINVAL);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout(valp, oldp, sizeof(int));
	if (error == 0 && newp) {
		error = copyin(newp, valp, sizeof(int));
		AUDIT_ARG(value, *valp);
	}
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdint(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, int val)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout((caddr_t)&val, oldp, sizeof(int));
	return (error);
}

/*
 * Validate parameters and get old / set new parameters
 * for an quad(64bit)-valued sysctl function.
 */
int
sysctl_quad(user_addr_t oldp, size_t *oldlenp, 
            user_addr_t newp, size_t newlen, quad_t *valp)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && *oldlenp < sizeof(quad_t))
		return (ENOMEM);
	if (newp && newlen != sizeof(quad_t))
		return (EINVAL);
	*oldlenp = sizeof(quad_t);
	if (oldp)
		error = copyout(valp, oldp, sizeof(quad_t));
	if (error == 0 && newp)
		error = copyin(newp, valp, sizeof(quad_t));
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdquad(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, quad_t val)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && *oldlenp < sizeof(quad_t))
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = sizeof(quad_t);
	if (oldp)
		error = copyout((caddr_t)&val, oldp, sizeof(quad_t));
	return (error);
}

/*
 * Validate parameters and get old / set new parameters
 * for a string-valued sysctl function.  Unlike sysctl_string, if you
 * give it a too small (but larger than 0 bytes) buffer, instead of
 * returning ENOMEM, it truncates the returned string to the buffer
 * size.  This preserves the semantics of some library routines
 * implemented via sysctl, which truncate their returned data, rather
 * than simply returning an error. The returned string is always NUL
 * terminated.
 */
int
sysctl_trstring(user_addr_t oldp, size_t *oldlenp, 
              user_addr_t newp, size_t newlen, char *str, int maxlen)
{
	int len, copylen, error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	copylen = len = strlen(str) + 1;
	if (oldp && (len < 0 || *oldlenp < 1))
		return (ENOMEM);
	if (oldp && (*oldlenp < (size_t)len))
		copylen = *oldlenp + 1;
	if (newp && (maxlen < 0 || newlen >= (size_t)maxlen))
		return (EINVAL);
	*oldlenp = copylen - 1; /* deal with NULL strings correctly */
	if (oldp) {
		error = copyout(str, oldp, copylen);
		if (!error) {
			unsigned char c = 0;
			/* NUL terminate */
			oldp += *oldlenp;
			error = copyout((void *)&c, oldp, sizeof(char));
		}
	}
	if (error == 0 && newp) {
		error = copyin(newp, str, newlen);
		str[newlen] = 0;
		AUDIT_ARG(text, (char *)str);
	}
	return (error);
}

/*
 * Validate parameters and get old / set new parameters
 * for a string-valued sysctl function.
 */
int
sysctl_string(user_addr_t oldp, size_t *oldlenp, 
              user_addr_t newp, size_t newlen, char *str, int maxlen)
{
	int len, error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	len = strlen(str) + 1;
	if (oldp && (len < 0 || *oldlenp < (size_t)len))
		return (ENOMEM);
	if (newp && (maxlen < 0 || newlen >= (size_t)maxlen))
		return (EINVAL);
	*oldlenp = len -1; /* deal with NULL strings correctly */
	if (oldp) {
		error = copyout(str, oldp, len);
	}
	if (error == 0 && newp) {
		error = copyin(newp, str, newlen);
		str[newlen] = 0;
		AUDIT_ARG(text, (char *)str);
	}
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdstring(user_addr_t oldp, size_t *oldlenp, 
                user_addr_t newp, char *str)
{
	int len, error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	len = strlen(str) + 1;
	if (oldp && *oldlenp < (size_t)len)
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = len;
	if (oldp)
		error = copyout(str, oldp, len);
	return (error);
}

/*
 * Validate parameters and get old / set new parameters
 * for a structure oriented sysctl function.
 */
int
sysctl_struct(user_addr_t oldp, size_t *oldlenp, 
              user_addr_t newp, size_t newlen, void *sp, int len)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && (len < 0 || *oldlenp < (size_t)len))
		return (ENOMEM);
	if (newp && (len < 0 || newlen > (size_t)len))
		return (EINVAL);
	if (oldp) {
		*oldlenp = len;
		error = copyout(sp, oldp, len);
	}
	if (error == 0 && newp)
		error = copyin(newp, sp, len);
	return (error);
}

/*
 * Validate parameters and get old parameters
 * for a structure oriented sysctl function.
 */
int
sysctl_rdstruct(user_addr_t oldp, size_t *oldlenp, 
                user_addr_t newp, void *sp, int len)
{
	int error = 0;

	if (oldp != USER_ADDR_NULL && oldlenp == NULL)
		return (EFAULT);
	if (oldp && (len < 0 || *oldlenp < (size_t)len))
		return (ENOMEM);
	if (newp)
		return (EPERM);
	*oldlenp = len;
	if (oldp)
		error = copyout(sp, oldp, len);
	return (error);
}

/*
 * Get file structures.
 */
static int
sysctl_file
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	struct fileglob *fg;
	struct extern_file nef;

	if (req->oldptr == USER_ADDR_NULL) {
		/*
		 * overestimate by 10 files
		 */
		req->oldidx = sizeof(filehead) + (nfiles + 10) * sizeof(struct extern_file);
		return (0);
	}

	/*
	 * first copyout filehead
	 */
	error = SYSCTL_OUT(req, &filehead, sizeof(filehead));
	if (error)
		return (error);

	/*
	 * followed by an array of file structures
	 */
	for (fg = filehead.lh_first; fg != 0; fg = fg->f_list.le_next) {
        nef.f_list.le_next =  (struct extern_file *)fg->f_list.le_next;
        nef.f_list.le_prev =  (struct extern_file **)fg->f_list.le_prev;
		nef.f_flag = (fg->fg_flag & FMASK);
		nef.f_type = fg->fg_type;
		nef.f_count = fg->fg_count;
		nef.f_msgcount = fg->fg_msgcount;
		nef.f_cred = fg->fg_cred;
		nef.f_ops = fg->fg_ops;
		nef.f_offset = fg->fg_offset;
		nef.f_data = fg->fg_data;
		error = SYSCTL_OUT(req, &nef, sizeof(nef));
		if (error)
			return (error);
	}
	return (0);
}

SYSCTL_PROC(_kern, KERN_FILE, file,
		CTLTYPE_STRUCT | CTLFLAG_RW,
		0, 0, sysctl_file, "S,filehead", "");

static int
sysdoproc_filt_KERN_PROC_PID(proc_t p, void * arg)
{
	if (p->p_pid != (pid_t)arg)
		return(0);
	else
		return(1);
}

static int
sysdoproc_filt_KERN_PROC_PGRP(proc_t p, void * arg)
{
	if (p->p_pgrpid != (pid_t)arg)
		return(0);
	else
	  return(1);
}

static int
sysdoproc_filt_KERN_PROC_TTY(proc_t p, void * arg)
{
	boolean_t funnel_state;
	int retval;

	
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	/* This is very racy but list lock is held.. Hmmm. */
	if ((p->p_flag & P_CONTROLT) == 0 ||
		(p->p_pgrp == NULL) || (p->p_pgrp->pg_session == NULL) ||
			p->p_pgrp->pg_session->s_ttyp == NULL ||
			p->p_pgrp->pg_session->s_ttyp->t_dev != (dev_t)arg)
				retval = 0;
	else
		retval = 1;

	thread_funnel_set(kernel_flock, funnel_state);

	return(retval);
}

static int
sysdoproc_filt_KERN_PROC_UID(proc_t p, void * arg)
{
	kauth_cred_t my_cred;
	uid_t uid;

	if (p->p_ucred == NULL)
		return(0);
	my_cred = kauth_cred_proc_ref(p);
	uid = kauth_cred_getuid(my_cred);
	kauth_cred_unref(&my_cred);

	if (uid != (uid_t)arg)
		return(0);
	else
		return(1);
}


static int
sysdoproc_filt_KERN_PROC_RUID(proc_t p, void * arg)
{
	kauth_cred_t my_cred;
	uid_t ruid;

	if (p->p_ucred == NULL)
		return(0);
	my_cred = kauth_cred_proc_ref(p);
	ruid = my_cred->cr_ruid;
	kauth_cred_unref(&my_cred);

	if (ruid != (uid_t)arg)
		return(0);
	else
		return(1);
}

static int
sysdoproc_filt_KERN_PROC_LCID(proc_t p, void * arg)
{
	if ((p->p_lctx == NULL) ||
		(p->p_lctx->lc_id != (pid_t)arg))
		return(0);
	else
		return(1);
}

/*
 * try over estimating by 5 procs
 */
#define KERN_PROCSLOP	(5 * sizeof (struct kinfo_proc))
struct sysdoproc_args {
	int	buflen;
	caddr_t	kprocp;
	boolean_t is_64_bit;
	user_addr_t	dp;
	size_t needed;
	int sizeof_kproc;
	int * errorp;
	int uidcheck;
	int ruidcheck;
	int ttycheck;
	int uidval;
};

int
sysdoproc_callback(proc_t p, void * arg)
{
	struct sysdoproc_args * args = (struct sysdoproc_args *)arg;
	int error=0;

	if (args->buflen >= args->sizeof_kproc) {
		if ((args->ruidcheck != 0)  && (sysdoproc_filt_KERN_PROC_RUID(p, (void *)args->uidval) == 0))
			return(PROC_RETURNED);
		if ((args->uidcheck != 0)  && (sysdoproc_filt_KERN_PROC_UID(p, (void *)args->uidval) == 0))
			return(PROC_RETURNED);
		if ((args->ttycheck != 0)  && (sysdoproc_filt_KERN_PROC_TTY(p, (void *)args->uidval) == 0))
			return(PROC_RETURNED);

		bzero(args->kprocp, args->sizeof_kproc);
		if (args->is_64_bit) {
			fill_user_proc(p, (struct user_kinfo_proc *) args->kprocp);
		}
		else {
			fill_proc(p, (struct kinfo_proc *) args->kprocp);
		}
		error = copyout(args->kprocp, args->dp, args->sizeof_kproc);
		if (error) {
			*args->errorp = error;
			return(PROC_RETURNED_DONE);
			return (error);
		}
		args->dp += args->sizeof_kproc;
		args->buflen -= args->sizeof_kproc;
	}
	args->needed += args->sizeof_kproc;
	return(PROC_RETURNED);
}

int
sysctl_doproc(int *name, u_int namelen, user_addr_t where, size_t *sizep)
{
	user_addr_t dp = where;
	size_t needed = 0;
	int buflen = where != USER_ADDR_NULL ? *sizep : 0;
	int error = 0;
	boolean_t is_64_bit = FALSE;
	struct kinfo_proc       kproc;
	struct user_kinfo_proc  user_kproc;
	int sizeof_kproc;
	caddr_t kprocp;
	int (*filterfn)(proc_t, void *) = 0;
	struct sysdoproc_args args;
	int uidcheck = 0;
	int ruidcheck = 0;
	int ttycheck = 0;

	if (namelen != 2 && !(namelen == 1 && name[0] == KERN_PROC_ALL))
		return (EINVAL);
	is_64_bit = proc_is64bit(current_proc()); 
	if (is_64_bit) {
		sizeof_kproc = sizeof(user_kproc);
		kprocp = (caddr_t) &user_kproc;
	}
	else {
		sizeof_kproc = sizeof(kproc);
		kprocp = (caddr_t) &kproc;
	}


	switch (name[0]) {

		case KERN_PROC_PID:
			filterfn = sysdoproc_filt_KERN_PROC_PID;
			break;

		case KERN_PROC_PGRP:
			filterfn = sysdoproc_filt_KERN_PROC_PGRP;
			break;
	
		case KERN_PROC_TTY:
			ttycheck = 1;
			break;

		case KERN_PROC_UID:
			uidcheck = 1;
			break;

		case KERN_PROC_RUID:
			ruidcheck = 1;
			break;

#if CONFIG_LCTX
		case KERN_PROC_LCID:
			filterfn = sysdoproc_filt_KERN_PROC_LCID;
			break;
#endif
	}

	error = 0;
	args.buflen = buflen;
	args.kprocp = kprocp;
	args.is_64_bit = is_64_bit;
	args.dp = dp;
	args.needed = needed;
	args.errorp = &error;
	args.uidcheck = uidcheck;
	args.ruidcheck = ruidcheck;
	args.ttycheck = ttycheck;
	args.sizeof_kproc = sizeof_kproc;
	args.uidval = name[1];

	proc_iterate((PROC_ALLPROCLIST | PROC_ZOMBPROCLIST), sysdoproc_callback, &args, filterfn, (void *)name[1]);

	if (error)
		return(error);

	dp = args.dp;
	needed = args.needed;
	
	if (where != USER_ADDR_NULL) {
		*sizep = dp - where;
		if (needed > *sizep)
			return (ENOMEM);
	} else {
		needed += KERN_PROCSLOP;
		*sizep = needed;
	}
	return (0);
}

/*
 * Fill in an eproc structure for the specified process.
 */
static void
fill_eproc(proc_t p, struct eproc *ep)
{
	struct tty *tp;
	kauth_cred_t my_cred;
	struct pgrp * pg;
	struct session * sessp;

	pg = proc_pgrp(p);
	sessp = proc_session(p);

	ep->e_paddr = p;

	if (pg != PGRP_NULL) {
		ep->e_sess = sessp;
		ep->e_pgid = p->p_pgrpid;
		ep->e_jobc = pg->pg_jobc;
		if ((sessp != SESSION_NULL) && sessp->s_ttyvp)
			ep->e_flag = EPROC_CTTY;
	} else {
		ep->e_sess = (struct session *)0;
		ep->e_pgid = 0;
		ep->e_jobc = 0;
	}
#if CONFIG_LCTX
	if (p->p_lctx) {
		ep->e_lcid = p->p_lctx->lc_id;
	} else {
		ep->e_lcid = 0;
	}
#endif
	ep->e_ppid = p->p_ppid;
	/* Pre-zero the fake historical pcred */
	bzero(&ep->e_pcred, sizeof(struct _pcred));
	if (p->p_ucred) {
		my_cred = kauth_cred_proc_ref(p);

		/* A fake historical pcred */
		ep->e_pcred.p_ruid = my_cred->cr_ruid;
		ep->e_pcred.p_svuid = my_cred->cr_svuid;
		ep->e_pcred.p_rgid = my_cred->cr_rgid;
		ep->e_pcred.p_svgid = my_cred->cr_svgid;
		/* A fake historical *kauth_cred_t */
		ep->e_ucred.cr_ref = my_cred->cr_ref;
		ep->e_ucred.cr_uid = kauth_cred_getuid(my_cred);
		ep->e_ucred.cr_ngroups = my_cred->cr_ngroups;
		bcopy(my_cred->cr_groups, ep->e_ucred.cr_groups, NGROUPS*sizeof(gid_t));

		kauth_cred_unref(&my_cred);
	}
	if (p->p_stat == SIDL || p->p_stat == SZOMB) {
		ep->e_vm.vm_tsize = 0;
		ep->e_vm.vm_dsize = 0;
		ep->e_vm.vm_ssize = 0;
	}
	ep->e_vm.vm_rssize = 0;

	if ((p->p_flag & P_CONTROLT) && (sessp != SESSION_NULL) &&
	     (tp = sessp->s_ttyp)) {
		ep->e_tdev = tp->t_dev;
		ep->e_tpgid = sessp->s_ttypgrpid;
		ep->e_tsess = tp->t_session;
	} else
		ep->e_tdev = NODEV;

	if (SESS_LEADER(p, sessp))
		ep->e_flag |= EPROC_SLEADER;
	bzero(&ep->e_wmesg[0], WMESGLEN+1);
	ep->e_xsize = ep->e_xrssize = 0;
	ep->e_xccount = ep->e_xswrss = 0;
	if (sessp != SESSION_NULL)
		session_rele(sessp);
	if(pg != PGRP_NULL)
		pg_rele(pg);
}

/*
 * Fill in an LP64 version of eproc structure for the specified process.
 */
static void
fill_user_eproc(proc_t p, struct user_eproc *ep)
{
	struct tty *tp;
	struct	session *sessp = NULL;
	struct pgrp * pg;
	kauth_cred_t my_cred;
	
	pg = proc_pgrp(p);
	sessp = proc_session(p);

	ep->e_paddr = CAST_USER_ADDR_T(p);
	if (pg != PGRP_NULL) {
		ep->e_sess = CAST_USER_ADDR_T(sessp);
		ep->e_pgid = p->p_pgrpid;
		ep->e_jobc = pg->pg_jobc;
		if (sessp != SESSION_NULL) {
            		if (sessp->s_ttyvp)
			    ep->e_flag = EPROC_CTTY;
		}
	} else {
		ep->e_sess = USER_ADDR_NULL;
		ep->e_pgid = 0;
		ep->e_jobc = 0;
	}
#if CONFIG_LCTX
	if (p->p_lctx) {
		ep->e_lcid = p->p_lctx->lc_id;
	} else {
		ep->e_lcid = 0;
	}
#endif
	ep->e_ppid = p->p_ppid;
	/* Pre-zero the fake historical pcred */
	bzero(&ep->e_pcred, sizeof(ep->e_pcred));
	if (p->p_ucred) {
		my_cred = kauth_cred_proc_ref(p);

		/* A fake historical pcred */
		ep->e_pcred.p_ruid = my_cred->cr_ruid;
		ep->e_pcred.p_svuid = my_cred->cr_svuid;
		ep->e_pcred.p_rgid = my_cred->cr_rgid;
		ep->e_pcred.p_svgid = my_cred->cr_svgid;

		/* A fake historical *kauth_cred_t */
		ep->e_ucred.cr_ref = my_cred->cr_ref;
		ep->e_ucred.cr_uid = kauth_cred_getuid(my_cred);
		ep->e_ucred.cr_ngroups = my_cred->cr_ngroups;
		bcopy(my_cred->cr_groups, ep->e_ucred.cr_groups, NGROUPS*sizeof(gid_t));

		kauth_cred_unref(&my_cred);
	}
	if (p->p_stat == SIDL || p->p_stat == SZOMB) {
		ep->e_vm.vm_tsize = 0;
		ep->e_vm.vm_dsize = 0;
		ep->e_vm.vm_ssize = 0;
	}
	ep->e_vm.vm_rssize = 0;

	if ((p->p_flag & P_CONTROLT) && (sessp != SESSION_NULL) &&
	     (tp = sessp->s_ttyp)) {
		ep->e_tdev = tp->t_dev;
		ep->e_tpgid = sessp->s_ttypgrpid;
		ep->e_tsess = CAST_USER_ADDR_T(tp->t_session);
	} else
		ep->e_tdev = NODEV;

	if (SESS_LEADER(p, sessp))
		ep->e_flag |= EPROC_SLEADER;
	bzero(&ep->e_wmesg[0], WMESGLEN+1);
	ep->e_xsize = ep->e_xrssize = 0;
	ep->e_xccount = ep->e_xswrss = 0;
	if (sessp != SESSION_NULL)
		session_rele(sessp);
	if (pg != PGRP_NULL)
		pg_rele(pg);
}

/*
 * Fill in an eproc structure for the specified process.
 */
static void
fill_externproc(proc_t p, struct extern_proc *exp)
{
	exp->p_forw = exp->p_back = NULL;
	exp->p_starttime = p->p_start;
	exp->p_vmspace = NULL;
	exp->p_sigacts = p->p_sigacts;
	exp->p_flag  = p->p_flag;
	if (p->p_lflag & P_LTRACED)
		exp->p_flag |= P_TRACED;
	if (p->p_lflag & P_LPPWAIT)
		exp->p_flag |= P_PPWAIT;
	if (p->p_lflag & P_LEXIT)
		exp->p_flag |= P_WEXIT;
	exp->p_stat  = p->p_stat ;
	exp->p_pid  = p->p_pid ;
	exp->p_oppid  = p->p_oppid ;
	/* Mach related  */
	exp->user_stack  = CAST_DOWN(caddr_t, p->user_stack);
	exp->exit_thread  = p->exit_thread ;
	exp->p_debugger  = p->p_debugger ;
	exp->sigwait  = p->sigwait ;
	/* scheduling */
#ifdef _PROC_HAS_SCHEDINFO_
	exp->p_estcpu  = p->p_estcpu ;
	exp->p_pctcpu  = p->p_pctcpu ;
	exp->p_slptime  = p->p_slptime ;
#else
	exp->p_estcpu  = 0 ;
	exp->p_pctcpu  = 0 ;
	exp->p_slptime = 0 ;
#endif
	exp->p_cpticks  = 0 ;
	exp->p_wchan  = 0 ;
	exp->p_wmesg  = 0 ;
	exp->p_swtime  = 0 ;
	bcopy(&p->p_realtimer, &exp->p_realtimer,sizeof(struct itimerval));
	bcopy(&p->p_rtime, &exp->p_rtime,sizeof(struct timeval));
	exp->p_uticks  = 0 ;
	exp->p_sticks  = 0 ;
	exp->p_iticks  = 0 ;
	exp->p_traceflag  = 0;
	exp->p_tracep  = 0 ;
	exp->p_siglist  = 0 ;	/* No longer relevant */
	exp->p_textvp  = p->p_textvp ;
	exp->p_holdcnt = 0 ;
	exp->p_sigmask  = 0 ;	/* no longer avaialable */
	exp->p_sigignore  = p->p_sigignore ;
	exp->p_sigcatch  = p->p_sigcatch ;
	exp->p_priority  = p->p_priority ;
	exp->p_usrpri  = 0 ;
	exp->p_nice  = p->p_nice ;
	bcopy(&p->p_comm, &exp->p_comm,MAXCOMLEN);
	exp->p_comm[MAXCOMLEN] = '\0';
	exp->p_pgrp  = p->p_pgrp ;
	exp->p_addr  = NULL;
	exp->p_xstat  = p->p_xstat ;
	exp->p_acflag  = p->p_acflag ;
	exp->p_ru  = p->p_ru ;		/* XXX may be NULL */
}

/*
 * Fill in an LP64 version of extern_proc structure for the specified process.
 */
static void
fill_user_externproc(proc_t p, struct user_extern_proc *exp)
{
	exp->p_forw = exp->p_back = USER_ADDR_NULL;
	exp->p_starttime.tv_sec = p->p_start.tv_sec;
	exp->p_starttime.tv_usec = p->p_start.tv_usec;
	exp->p_vmspace = USER_ADDR_NULL;
	exp->p_sigacts = CAST_USER_ADDR_T(p->p_sigacts);
	exp->p_flag  = p->p_flag;
	if (p->p_lflag & P_LTRACED)
		exp->p_flag |= P_TRACED;
	if (p->p_lflag & P_LPPWAIT)
		exp->p_flag |= P_PPWAIT;
	if (p->p_lflag & P_LEXIT)
		exp->p_flag |= P_WEXIT;
	exp->p_stat  = p->p_stat ;
	exp->p_pid  = p->p_pid ;
	exp->p_oppid  = p->p_oppid ;
	/* Mach related  */
	exp->user_stack  = p->user_stack;
	exp->exit_thread  = CAST_USER_ADDR_T(p->exit_thread);
	exp->p_debugger  = p->p_debugger ;
	exp->sigwait  = p->sigwait ;
	/* scheduling */
#ifdef _PROC_HAS_SCHEDINFO_
	exp->p_estcpu  = p->p_estcpu ;
	exp->p_pctcpu  = p->p_pctcpu ;
	exp->p_slptime  = p->p_slptime ;
#else
	exp->p_estcpu  = 0 ;
	exp->p_pctcpu  = 0 ;
	exp->p_slptime = 0 ;
#endif
	exp->p_cpticks  = 0 ;
	exp->p_wchan  = 0;
	exp->p_wmesg  = 0;
	exp->p_swtime  = 0 ;
	exp->p_realtimer.it_interval.tv_sec = p->p_realtimer.it_interval.tv_sec;
	exp->p_realtimer.it_interval.tv_usec = p->p_realtimer.it_interval.tv_usec;
	exp->p_realtimer.it_value.tv_sec = p->p_realtimer.it_value.tv_sec;
	exp->p_realtimer.it_value.tv_usec = p->p_realtimer.it_value.tv_usec;
	exp->p_rtime.tv_sec = p->p_rtime.tv_sec;
	exp->p_rtime.tv_usec = p->p_rtime.tv_usec;
	exp->p_uticks  = 0 ;
	exp->p_sticks  = 0 ;
	exp->p_iticks  = 0 ;
	exp->p_traceflag  = 0 ;
	exp->p_tracep  = 0;
	exp->p_siglist  = 0 ;	/* No longer relevant */
	exp->p_textvp  = CAST_USER_ADDR_T(p->p_textvp);
	exp->p_holdcnt = 0 ;
	exp->p_sigmask  = 0 ;	/* no longer avaialable */
	exp->p_sigignore  = p->p_sigignore ;
	exp->p_sigcatch  = p->p_sigcatch ;
	exp->p_priority  = p->p_priority ;
	exp->p_usrpri  = 0 ;
	exp->p_nice  = p->p_nice ;
	bcopy(&p->p_comm, &exp->p_comm,MAXCOMLEN);
	exp->p_comm[MAXCOMLEN] = '\0';
	exp->p_pgrp  = CAST_USER_ADDR_T(p->p_pgrp);
	exp->p_addr  = USER_ADDR_NULL;
	exp->p_xstat  = p->p_xstat ;
	exp->p_acflag  = p->p_acflag ;
	exp->p_ru  = CAST_USER_ADDR_T(p->p_ru);		/* XXX may be NULL */
}

static void
fill_proc(proc_t p, struct kinfo_proc *kp)
{
	fill_externproc(p, &kp->kp_proc);
	fill_eproc(p, &kp->kp_eproc);
}

static void
fill_user_proc(proc_t p, struct user_kinfo_proc *kp)
{
	fill_user_externproc(p, &kp->kp_proc);
	fill_user_eproc(p, &kp->kp_eproc);
}

int
kdebug_ops(int *name, u_int namelen, user_addr_t where, 
           size_t *sizep, proc_t p)
{
	int ret=0;

	if (namelen == 0)
		return(ENOTSUP);

    ret = suser(kauth_cred_get(), &p->p_acflag);
	if (ret)
		return(ret);

	switch(name[0]) {
	case KERN_KDEFLAGS:
	case KERN_KDDFLAGS:
	case KERN_KDENABLE:
	case KERN_KDGETBUF:
	case KERN_KDSETUP:
	case KERN_KDREMOVE:
	case KERN_KDSETREG:
	case KERN_KDGETREG:
	case KERN_KDREADTR:
	case KERN_KDPIDTR:
	case KERN_KDTHRMAP:
	case KERN_KDPIDEX:
	case KERN_KDSETRTCDEC:
	case KERN_KDSETBUF:
	case KERN_KDGETENTROPY:
	        ret = kdbg_control(name, namelen, where, sizep);
	        break;
	default:
		ret= ENOTSUP;
		break;
	}
	return(ret);
}


/*
 * Return the top *sizep bytes of the user stack, or the entire area of the
 * user stack down through the saved exec_path, whichever is smaller.
 */
int
sysctl_procargs(int *name, u_int namelen, user_addr_t where, 
                size_t *sizep, proc_t cur_proc)
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 0);
}

static int
sysctl_procargs2(int *name, u_int namelen, user_addr_t where, 
                 size_t *sizep, proc_t cur_proc)
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 1);
}

static int
sysctl_procargsx(int *name, u_int namelen, user_addr_t where, 
                 size_t *sizep, proc_t cur_proc, int argc_yes)
{
	proc_t p;
	int buflen = where != USER_ADDR_NULL ? *sizep : 0;
	int error = 0;
	struct _vm_map *proc_map;
	struct task * task;
	vm_map_copy_t	tmp;
	user_addr_t	arg_addr;
	size_t		arg_size;
	caddr_t data;
	size_t argslen=0;
	int size;
	vm_offset_t	copy_start, copy_end;
	kern_return_t ret;
	int pid;
	kauth_cred_t my_cred;
	uid_t uid;

	if ( namelen < 1 )
		return(EINVAL);

	if (argc_yes)
		buflen -= sizeof(int);		/* reserve first word to return argc */

	/* we only care about buflen when where (oldp from sysctl) is not NULL. */
	/* when where (oldp from sysctl) is NULL and sizep (oldlenp from sysctl */
	/* is not NULL then the caller wants us to return the length needed to */
	/* hold the data we would return */ 
	if (where != USER_ADDR_NULL && (buflen <= 0 || buflen > ARG_MAX)) {
		return(EINVAL);
	}
	arg_size = buflen;

	/*
	 *	Lookup process by pid
	 */
	pid = name[0];
	p = proc_find(pid);
	if (p == NULL) {
		return(EINVAL);
	}

	/*
	 *	Copy the top N bytes of the stack.
	 *	On all machines we have so far, the stack grows
	 *	downwards.
	 *
	 *	If the user expects no more than N bytes of
	 *	argument list, use that as a guess for the
	 *	size.
	 */

	if (!p->user_stack) {
		proc_rele(p);
		return(EINVAL);
	}

	if (where == USER_ADDR_NULL) {
		/* caller only wants to know length of proc args data */
		if (sizep == NULL) {
			proc_rele(p);
			return(EFAULT);
		}
			
		 size = p->p_argslen;
		proc_rele(p);
		 if (argc_yes) {
		 	size += sizeof(int);
		 }
		 else {
			/*
			 * old PROCARGS will return the executable's path and plus some
			 * extra space for work alignment and data tags
			 */
		 	size += PATH_MAX + (6 * sizeof(int));
		 }
		size += (size & (sizeof(int) - 1)) ? (sizeof(int) - (size & (sizeof(int) - 1))) : 0;
		*sizep = size;
		return (0);
	}
	
	my_cred = kauth_cred_proc_ref(p);
	uid = kauth_cred_getuid(my_cred);
	kauth_cred_unref(&my_cred);

	if ((uid != kauth_cred_getuid(kauth_cred_get())) 
		&& suser(kauth_cred_get(), &cur_proc->p_acflag)) {
		proc_rele(p);
		return (EINVAL);
	}

	if ((u_int)arg_size > p->p_argslen)
	        arg_size = round_page(p->p_argslen);

	arg_addr = p->user_stack - arg_size;


	/*
	 *	Before we can block (any VM code), make another
	 *	reference to the map to keep it alive.  We do
	 *	that by getting a reference on the task itself.
	 */
	task = p->task;
	if (task == NULL) {
		proc_rele(p);
		return(EINVAL);
	}
	
	argslen = p->p_argslen;
	/*
	 * Once we have a task reference we can convert that into a
	 * map reference, which we will use in the calls below.  The
	 * task/process may change its map after we take this reference
	 * (see execve), but the worst that will happen then is a return
	 * of stale info (which is always a possibility).
	 */
	task_reference(task);
	proc_rele(p);
	proc_map = get_task_map_reference(task);
	task_deallocate(task);
	
	if (proc_map == NULL)
		return(EINVAL);


	ret = kmem_alloc(kernel_map, &copy_start, round_page(arg_size));
	if (ret != KERN_SUCCESS) {
		vm_map_deallocate(proc_map);
		return(ENOMEM);
	}

	copy_end = round_page(copy_start + arg_size);

	if( vm_map_copyin(proc_map, (vm_map_address_t)arg_addr, 
			  (vm_map_size_t)arg_size, FALSE, &tmp) != KERN_SUCCESS) {
			vm_map_deallocate(proc_map);
			kmem_free(kernel_map, copy_start,
					round_page(arg_size));
			return (EIO);
	}

	/*
	 *	Now that we've done the copyin from the process'
	 *	map, we can release the reference to it.
	 */
	vm_map_deallocate(proc_map);

	if( vm_map_copy_overwrite(kernel_map, 
				  (vm_map_address_t)copy_start, 
				  tmp, FALSE) != KERN_SUCCESS) {
			kmem_free(kernel_map, copy_start,
					round_page(arg_size));
			return (EIO);
	}

	if (arg_size > argslen) {
		data = (caddr_t) (copy_end - argslen);
		size = argslen;
	} else {
		data = (caddr_t) (copy_end - arg_size);
		size = arg_size;
	}

	if (argc_yes) {
		/* Put processes argc as the first word in the copyout buffer */
		suword(where, p->p_argc);
		error = copyout(data, (where + sizeof(int)), size);
		size += sizeof(int);
	} else {
		error = copyout(data, where, size);

		/*
		 * Make the old PROCARGS work to return the executable's path
		 * But, only if there is enough space in the provided buffer
		 *
		 * on entry: data [possibily] points to the beginning of the path 
		 * 
		 * Note: we keep all pointers&sizes aligned to word boundries
		 */
		if ( (! error) && (buflen > 0 && (u_int)buflen > argslen) )
		{
			int binPath_sz, alignedBinPath_sz = 0;
			int extraSpaceNeeded, addThis;
			user_addr_t placeHere;
			char * str = (char *) data;
			int max_len = size;

			/* Some apps are really bad about messing up their stacks
			   So, we have to be extra careful about getting the length
			   of the executing binary.  If we encounter an error, we bail.
			*/

			/* Limit ourselves to PATH_MAX paths */
			if ( max_len > PATH_MAX ) max_len = PATH_MAX;

			binPath_sz = 0;

			while ( (binPath_sz < max_len-1) && (*str++ != 0) )
				binPath_sz++;

			/* If we have a NUL terminator, copy it, too */
			if (binPath_sz < max_len-1) binPath_sz += 1;

			/* Pre-Flight the space requiremnts */

			/* Account for the padding that fills out binPath to the next word */
			alignedBinPath_sz += (binPath_sz & (sizeof(int)-1)) ? (sizeof(int)-(binPath_sz & (sizeof(int)-1))) : 0;

			placeHere = where + size;

			/* Account for the bytes needed to keep placeHere word aligned */ 
			addThis = (placeHere & (sizeof(int)-1)) ? (sizeof(int)-(placeHere & (sizeof(int)-1))) : 0;

			/* Add up all the space that is needed */
			extraSpaceNeeded = alignedBinPath_sz + addThis + binPath_sz + (4 * sizeof(int));

			/* is there is room to tack on argv[0]? */
			if ( (buflen & ~(sizeof(int)-1)) >= ( argslen + extraSpaceNeeded ))
			{
				placeHere += addThis;
				suword(placeHere, 0);
				placeHere += sizeof(int);
				suword(placeHere, 0xBFFF0000);
				placeHere += sizeof(int);
				suword(placeHere, 0);
				placeHere += sizeof(int);
				error = copyout(data, placeHere, binPath_sz);
				if ( ! error )
				{
					placeHere += binPath_sz;
					suword(placeHere, 0);
					size += extraSpaceNeeded;
				}
			}
		}
	}

	if (copy_start != (vm_offset_t) 0) {
		kmem_free(kernel_map, copy_start, copy_end - copy_start);
	}
	if (error) {
		return(error);
	}

	if (where != USER_ADDR_NULL)
		*sizep = size;
	return (0);
}


/*
 * Max number of concurrent aio requests
 */
static int
sysctl_aiomax
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, aio_max_requests, sizeof(int), &new_value, &changed);
	if (changed) {
		 /* make sure the system-wide limit is greater than the per process limit */
		if (new_value >= aio_max_requests_per_process)
			aio_max_requests = new_value;
		else
			error = EINVAL;
	}
	return(error);
}


/*
 * Max number of concurrent aio requests per process
 */
static int
sysctl_aioprocmax
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, aio_max_requests_per_process, sizeof(int), &new_value, &changed);
	if (changed) {
		/* make sure per process limit is less than the system-wide limit */
		if (new_value <= aio_max_requests && new_value >= AIO_LISTIO_MAX)
			aio_max_requests_per_process = new_value;
		else
			error = EINVAL;
	}
	return(error);
}


/*
 * Max number of async IO worker threads
 */
static int
sysctl_aiothreads
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, aio_worker_threads, sizeof(int), &new_value, &changed);
	if (changed) {
		/* we only allow an increase in the number of worker threads */
	        if (new_value > aio_worker_threads ) {
		        _aio_create_worker_threads((new_value - aio_worker_threads));
			aio_worker_threads = new_value;
		}
		else
		        error = EINVAL;
	}
	return(error);
}


/*
 * System-wide limit on the max number of processes
 */
static int
sysctl_maxproc
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, maxproc, sizeof(int), &new_value, &changed);
	if (changed) {
		AUDIT_ARG(value, new_value);
		/* make sure the system-wide limit is less than the configured hard
		   limit set at kernel compilation */
		if (new_value <= hard_maxproc && new_value > 0)
			maxproc = new_value;
		else
			error = EINVAL;
	}
	return(error);
}

SYSCTL_STRING(_kern, KERN_OSTYPE, ostype, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		ostype, 0, "");
SYSCTL_STRING(_kern, KERN_OSRELEASE, osrelease, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		osrelease, 0, "");
SYSCTL_INT(_kern, KERN_OSREV, osrevision, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, BSD, "");
SYSCTL_STRING(_kern, KERN_VERSION, version, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		version, 0, "");

/* PR-5293665: need to use a callback function for kern.osversion to set
 * osversion in IORegistry */

static int
sysctl_osversion(__unused struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    int rval = 0;

    rval = sysctl_handle_string(oidp, arg1, arg2, req);

    if (req->newptr) {
        IORegistrySetOSBuildVersion((char *)arg1); 
    }

    return rval;
}

SYSCTL_PROC(_kern, KERN_OSVERSION, osversion,
        CTLFLAG_RW | CTLFLAG_KERN | CTLTYPE_STRING,
        osversion, 256 /* OSVERSIZE*/, 
        sysctl_osversion, "A", "");

static int
sysctl_sysctl_bootargs
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error;
	char buf[256];

	strlcpy(buf, PE_boot_args(), 256);
	error = sysctl_io_string(req, buf, 256, 0, NULL);
	return(error);
}

SYSCTL_PROC(_kern, OID_AUTO, bootargs,
	CTLFLAG_LOCKED | CTLFLAG_RD | CTLFLAG_KERN | CTLTYPE_STRING,
	NULL, 0,
	sysctl_sysctl_bootargs, "A", "bootargs");

SYSCTL_INT(_kern, KERN_MAXFILES, maxfiles, 
		CTLFLAG_RW | CTLFLAG_KERN, 
		&maxfiles, 0, "");
SYSCTL_INT(_kern, KERN_ARGMAX, argmax, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, ARG_MAX, "");
SYSCTL_INT(_kern, KERN_POSIX1, posix1version, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, _POSIX_VERSION, "");
SYSCTL_INT(_kern, KERN_NGROUPS, ngroups, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, NGROUPS_MAX, "");
SYSCTL_INT(_kern, KERN_JOB_CONTROL, job_control, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, 1, "");
#if 1	/* _POSIX_SAVED_IDS from <unistd.h> */
SYSCTL_INT(_kern, KERN_SAVED_IDS, saved_ids, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, 1, "");
#else
SYSCTL_INT(_kern, KERN_SAVED_IDS, saved_ids, 
		CTLFLAG_RD | CTLFLAG_KERN, 
		NULL, 0, "");
#endif

static int
sysctl_maxvnodes (__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	unsigned int oldval = desiredvnodes;
	int error = sysctl_io_number(req, desiredvnodes, sizeof(int), &desiredvnodes, NULL);
	reset_vmobjectcache(oldval, desiredvnodes);
	resize_namecache(desiredvnodes);
	return(error);
}

SYSCTL_PROC(_kern, KERN_MAXVNODES, maxvnodes,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_maxvnodes, "I", "");

SYSCTL_PROC(_kern, KERN_MAXPROC, maxproc,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_maxproc, "I", "");

SYSCTL_PROC(_kern, KERN_AIOMAX, aiomax,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_aiomax, "I", "");

SYSCTL_PROC(_kern, KERN_AIOPROCMAX, aioprocmax,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_aioprocmax, "I", "");

SYSCTL_PROC(_kern, KERN_AIOTHREADS, aiothreads,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_aiothreads, "I", "");

static int
sysctl_securelvl
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, securelevel, sizeof(int), &new_value, &changed);
	if (changed) {
		if (!(new_value < securelevel && req->p->p_pid != 1)) {
			proc_list_lock();
			securelevel = new_value;
			proc_list_unlock();
		} else {
			error = EPERM;
		}
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_SECURELVL, securelevel,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_securelvl, "I", "");


static int
sysctl_domainname
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, changed;
	error = sysctl_io_string(req, domainname, sizeof(domainname), 0, &changed);
	if (changed) {
		domainnamelen = strlen(domainname);
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_DOMAINNAME, nisdomainname,
		CTLTYPE_STRING | CTLFLAG_RW,
		0, 0, sysctl_domainname, "A", "");

SYSCTL_INT(_kern, KERN_HOSTID, hostid, 
		CTLFLAG_RW | CTLFLAG_KERN, 
		&hostid, 0, "");

static int
sysctl_hostname
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, changed;
	error = sysctl_io_string(req, hostname, sizeof(hostname), 1, &changed);
	if (changed) {
		hostnamelen = req->newlen;
	}
	return(error);
}


SYSCTL_PROC(_kern, KERN_HOSTNAME, hostname,
		CTLTYPE_STRING | CTLFLAG_RW,
		0, 0, sysctl_hostname, "A", "");

static int
sysctl_procname
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	/* Original code allowed writing, I'm copying this, although this all makes
	   no sense to me. Besides, this sysctl is never used. */
	return sysctl_io_string(req, &req->p->p_name[0], (2*MAXCOMLEN+1), 1, NULL);
}

SYSCTL_PROC(_kern, KERN_PROCNAME, procname,
		CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_ANYBODY,
		0, 0, sysctl_procname, "A", "");

SYSCTL_INT(_kern, KERN_SPECULATIVE_READS, speculative_reads_disabled, 
		CTLFLAG_RW | CTLFLAG_KERN, 
		&speculative_reads_disabled, 0, "");

static int
sysctl_boottime
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	struct timeval t;

	t.tv_sec = boottime_sec();
	t.tv_usec = 0;

	return sysctl_io_opaque(req, &t, sizeof(t), NULL);
}

SYSCTL_PROC(_kern, KERN_BOOTTIME, boottime,
		CTLTYPE_STRUCT | CTLFLAG_RD,
		0, 0, sysctl_boottime, "S,timeval", "");

static int
sysctl_symfile
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	char *str;
	int error = get_kernel_symfile(req->p, &str);
	if (error)
		return (error);
	return sysctl_io_string(req, str, 0, 0, NULL);
}


SYSCTL_PROC(_kern, KERN_SYMFILE, symfile,
		CTLTYPE_STRING | CTLFLAG_RD,
		0, 0, sysctl_symfile, "A", "");

#if NFSCLIENT
static int
sysctl_netboot
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	return sysctl_io_number(req, netboot_root(), sizeof(int), NULL, NULL);
}

SYSCTL_PROC(_kern, KERN_NETBOOT, netboot,
		CTLTYPE_INT | CTLFLAG_RD,
		0, 0, sysctl_netboot, "I", "");
#endif

static int
sysctl_usrstack
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	return sysctl_io_number(req, (int)req->p->user_stack, sizeof(int), NULL, NULL);
}

SYSCTL_PROC(_kern, KERN_USRSTACK, usrstack,
		CTLTYPE_INT | CTLFLAG_RD,
		0, 0, sysctl_usrstack, "I", "");

static int
sysctl_usrstack64
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	return sysctl_io_number(req, req->p->user_stack, sizeof(req->p->user_stack), NULL, NULL);
}

SYSCTL_PROC(_kern, KERN_USRSTACK64, usrstack64,
		CTLTYPE_QUAD | CTLFLAG_RD,
		0, 0, sysctl_usrstack64, "Q", "");

SYSCTL_STRING(_kern, KERN_COREFILE, corefile, 
		CTLFLAG_RW | CTLFLAG_KERN, 
		corefilename, sizeof(corefilename), "");

static int
sysctl_coredump
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
#ifdef SECURE_KERNEL
	return (ENOTSUP);
#endif
	int new_value, changed;
	int error = sysctl_io_number(req, do_coredump, sizeof(int), &new_value, &changed);
	if (changed) {
		if ((new_value == 0) || (new_value == 1))
			do_coredump = new_value;
		else
			error = EINVAL;
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_COREDUMP, coredump,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_coredump, "I", "");

static int
sysctl_suid_coredump
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
#ifdef SECURE_KERNEL
	return (ENOTSUP);
#endif
	int new_value, changed;
	int error = sysctl_io_number(req, sugid_coredump, sizeof(int), &new_value, &changed);
	if (changed) {
		if ((new_value == 0) || (new_value == 1))
			sugid_coredump = new_value;
		else
			error = EINVAL;
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_SUGID_COREDUMP, sugid_coredump,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_suid_coredump, "I", "");

static int
sysctl_delayterm
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	struct proc *p = req->p;
	int new_value, changed;
	int error = sysctl_io_number(req, (req->p->p_lflag & P_LDELAYTERM)? 1: 0, sizeof(int), &new_value, &changed);
	if (changed) {
		proc_lock(p);
		if (new_value)
			req->p->p_lflag |=  P_LDELAYTERM;
		else
			req->p->p_lflag &=  ~P_LDELAYTERM;
		proc_unlock(p);
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_PROCDELAYTERM, delayterm,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_delayterm, "I", "");

static int
sysctl_proc_low_pri_io
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	struct proc *p = req->p;
	int new_value, old_value, changed;
	int error;

	proc_lock(p);
    switch (req->p->p_iopol_disk) {
    case IOPOL_DEFAULT:
    case IOPOL_NORMAL:
        old_value = 0;
        break;
    case IOPOL_THROTTLE:
        old_value = 1;
        break;
    case IOPOL_PASSIVE:
        old_value = 2;
        break;
    default:
        /* this should never happen, but to be robust, return the default value */
        old_value = 0;
        break;
    }
	proc_unlock(p);
	
	error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);
	if (changed) {
		proc_lock(p);
        if (new_value & 0x01)
            req->p->p_iopol_disk = IOPOL_THROTTLE;
        else if (new_value & 0x02)
            req->p->p_iopol_disk = IOPOL_PASSIVE;
        else if (new_value == 0)
            req->p->p_iopol_disk = IOPOL_NORMAL;
		proc_unlock(p);
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_PROC_LOW_PRI_IO, proc_low_pri_io,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_proc_low_pri_io, "I", "");

static int
sysctl_rage_vnode
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	struct proc *p = req->p;
        struct  uthread *ut;
	int new_value, old_value, changed;
	int error;

	ut = get_bsdthread_info(current_thread());

	if (ut->uu_flag & UT_RAGE_VNODES)
	        old_value = KERN_RAGE_THREAD;
	else if (p->p_lflag & P_LRAGE_VNODES)
	        old_value = KERN_RAGE_PROC;
	else
	        old_value = 0;

	error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (error == 0) {
	        switch (new_value) {
		case KERN_RAGE_PROC:
		        proc_lock(p);
			p->p_lflag |= P_LRAGE_VNODES;
			proc_unlock(p);
			break;
		case KERN_UNRAGE_PROC:
		        proc_lock(p);
			p->p_lflag &= ~P_LRAGE_VNODES;
			proc_unlock(p);
			break;

		case KERN_RAGE_THREAD:
			ut->uu_flag |= UT_RAGE_VNODES;
			break;
		case KERN_UNRAGE_THREAD:
		        ut = get_bsdthread_info(current_thread());
			ut->uu_flag &= ~UT_RAGE_VNODES;
			break;
		}
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_RAGEVNODE, rage_vnode,
		CTLTYPE_INT | CTLFLAG_RW,
		0, 0, sysctl_rage_vnode, "I", "");


static int
sysctl_kern_check_openevt
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	struct proc *p = req->p;
	int new_value, old_value, changed;
	int error;

	if (p->p_flag & P_CHECKOPENEVT) {
		old_value = KERN_OPENEVT_PROC;
	} else {
	        old_value = 0;
	}

	error = sysctl_io_number(req, old_value, sizeof(int), &new_value, &changed);

	if (error == 0) {
	        switch (new_value) {
		case KERN_OPENEVT_PROC:
			OSBitOrAtomic(P_CHECKOPENEVT, (UInt32 *)&p->p_flag);
			break;

		case KERN_UNOPENEVT_PROC:
			OSBitAndAtomic(~((uint32_t)P_CHECKOPENEVT), (UInt32 *)&p->p_flag);
			break;

		default:
			error = EINVAL;
		}
	}
	return(error);
}

SYSCTL_PROC(_kern, KERN_CHECKOPENEVT, check_openevt, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            0, 0, sysctl_kern_check_openevt, "I", "set the per-process check-open-evt flag");



static int
sysctl_nx
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
#ifdef SECURE_KERNEL
	return ENOTSUP;
#endif
	int new_value, changed;
	int error;

	error = sysctl_io_number(req, nx_enabled, sizeof(nx_enabled), &new_value, &changed);
	if (error)
		return error;

	if (changed) {
#ifdef __i386__
		/*
		 * Only allow setting if NX is supported on the chip
		 */
		if (!(cpuid_extfeatures() & CPUID_EXTFEATURE_XD))
			return ENOTSUP;
#endif
		nx_enabled = new_value;
	}
	return(error);
}



SYSCTL_PROC(_kern, KERN_NX_PROTECTION, nx, 
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_KERN, 
		0, 0, sysctl_nx, "I", "");

static int
sysctl_loadavg
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
		if (proc_is64bit(req->p)) {
			struct user_loadavg loadinfo64;
			loadavg32to64(&averunnable, &loadinfo64);
			return sysctl_io_opaque(req, &loadinfo64, sizeof(loadinfo64), NULL);
		} else {
			return sysctl_io_opaque(req, &averunnable, sizeof(averunnable), NULL);
		}
}

SYSCTL_PROC(_vm, VM_LOADAVG, loadavg,
		CTLTYPE_STRUCT | CTLFLAG_RD,
		0, 0, sysctl_loadavg, "S,loadavg", "");

static int
sysctl_swapusage
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
		int			error;
		uint64_t		swap_total;
		uint64_t		swap_avail;
		uint32_t		swap_pagesize;
		boolean_t		swap_encrypted;
		struct xsw_usage	xsu;

		error = macx_swapinfo(&swap_total,
				      &swap_avail,
				      &swap_pagesize,
				      &swap_encrypted);
		if (error)
			return error;

		xsu.xsu_total = swap_total;
		xsu.xsu_avail = swap_avail;
		xsu.xsu_used = swap_total - swap_avail;
		xsu.xsu_pagesize = swap_pagesize;
		xsu.xsu_encrypted = swap_encrypted;
		return sysctl_io_opaque(req, &xsu, sizeof(xsu), NULL);
}



SYSCTL_PROC(_vm, VM_SWAPUSAGE, swapusage,
		CTLTYPE_STRUCT | CTLFLAG_RD,
		0, 0, sysctl_swapusage, "S,xsw_usage", "");


/* this kernel does NOT implement shared_region_make_private_np() */
SYSCTL_INT(_kern, KERN_SHREG_PRIVATIZABLE, shreg_private, 
		CTLFLAG_RD, 
		NULL, 0, "");

#if __i386__
static int
sysctl_sysctl_exec_affinity(__unused struct sysctl_oid *oidp,
			   __unused void *arg1, __unused int arg2,
			   struct sysctl_req *req)
{
	proc_t cur_proc = req->p;
	int error;
	
	if (req->oldptr != USER_ADDR_NULL) {
		cpu_type_t oldcputype = (cur_proc->p_flag & P_AFFINITY) ? CPU_TYPE_POWERPC : CPU_TYPE_I386;
		if ((error = SYSCTL_OUT(req, &oldcputype, sizeof(oldcputype))))
			return error;
	}

	if (req->newptr != USER_ADDR_NULL) {
		cpu_type_t newcputype;
		if ((error = SYSCTL_IN(req, &newcputype, sizeof(newcputype))))
			return error;
		if (newcputype == CPU_TYPE_I386)
			OSBitAndAtomic(~((uint32_t)P_AFFINITY), (UInt32 *)&cur_proc->p_flag);
		else if (newcputype == CPU_TYPE_POWERPC)
			OSBitOrAtomic(P_AFFINITY, (UInt32 *)&cur_proc->p_flag);
		else
			return (EINVAL);
	}
	
	return 0;
}
SYSCTL_PROC(_sysctl, OID_AUTO, proc_exec_affinity, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY, 0, 0, sysctl_sysctl_exec_affinity ,"I","proc_exec_affinity");
#endif

static int
fetch_process_cputype(
	proc_t cur_proc,
	int *name,
	u_int namelen,
	cpu_type_t *cputype)
{
	proc_t p = PROC_NULL;
	int refheld = 0;
	cpu_type_t ret = 0;
	int error = 0;
	
	if (namelen == 0)
		p = cur_proc;
	else if (namelen == 1) {
		p = proc_find(name[0]);
		if (p == NULL)
			return (EINVAL);
		refheld = 1;
	} else {
		error = EINVAL;
		goto out;
	}

#if __i386__
	if (p->p_flag & P_TRANSLATED) {
		ret = CPU_TYPE_POWERPC;
	}
	else
#endif
	{
		ret = cpu_type();
		if (IS_64BIT_PROCESS(p))
			ret |= CPU_ARCH_ABI64;
	}
	*cputype = ret;
	
	if (refheld != 0)
		proc_rele(p);
out:
	return (error);
}

static int
sysctl_sysctl_native(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
		    struct sysctl_req *req)
{
	int error;
	cpu_type_t proc_cputype = 0;
	if ((error = fetch_process_cputype(req->p, (int *)arg1, arg2, &proc_cputype)) != 0)
		return error;
	int res = 1;
	if ((proc_cputype & ~CPU_ARCH_MASK) != (cpu_type() & ~CPU_ARCH_MASK))
		res = 0;
	return SYSCTL_OUT(req, &res, sizeof(res));
}	
SYSCTL_PROC(_sysctl, OID_AUTO, proc_native, CTLTYPE_NODE|CTLFLAG_RD, 0, 0, sysctl_sysctl_native ,"I","proc_native");

static int
sysctl_sysctl_cputype(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
		     struct sysctl_req *req)
{
	int error;
	cpu_type_t proc_cputype = 0;
	if ((error = fetch_process_cputype(req->p, (int *)arg1, arg2, &proc_cputype)) != 0)
		return error;
	return SYSCTL_OUT(req, &proc_cputype, sizeof(proc_cputype));
}
SYSCTL_PROC(_sysctl, OID_AUTO, proc_cputype, CTLTYPE_NODE|CTLFLAG_RD, 0, 0, sysctl_sysctl_cputype ,"I","proc_cputype");

static int
sysctl_safeboot
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	return sysctl_io_number(req, boothowto & RB_SAFEBOOT ? 1 : 0, sizeof(int), NULL, NULL);
}

SYSCTL_PROC(_kern, KERN_SAFEBOOT, safeboot,
		CTLTYPE_INT | CTLFLAG_RD,
		0, 0, sysctl_safeboot, "I", "");

static int
sysctl_singleuser
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	return sysctl_io_number(req, boothowto & RB_SINGLE ? 1 : 0, sizeof(int), NULL, NULL);
}

SYSCTL_PROC(_kern, OID_AUTO, singleuser,
		CTLTYPE_INT | CTLFLAG_RD,
		0, 0, sysctl_singleuser, "I", "");

/*
 * Controls for debugging affinity sets - see osfmk/kern/affinity.c
 */
extern boolean_t	affinity_sets_enabled;
extern int		affinity_sets_mapping;

SYSCTL_INT (_kern, OID_AUTO, affinity_sets_enabled,
	    CTLFLAG_RW, (int *) &affinity_sets_enabled, 0, "hinting enabled");
SYSCTL_INT (_kern, OID_AUTO, affinity_sets_mapping,
	    CTLFLAG_RW, &affinity_sets_mapping, 0, "mapping policy");

/*
 * Limit on total memory users can wire.
 *
 * vm_global_user_wire_limit - system wide limit on wired memory from all processes combined. 
 *
 * vm_user_wire_limit - per address space limit on wired memory.  This puts a cap on the process's rlimit value.
 *
 * These values are initialized to reasonable defaults at boot time based on the available physical memory in
 * kmem_init().
 *
 * All values are in bytes.
 */

vm_map_size_t	vm_global_user_wire_limit;
vm_map_size_t	vm_user_wire_limit;

SYSCTL_QUAD(_vm, OID_AUTO, global_user_wire_limit, CTLFLAG_RW, &vm_global_user_wire_limit, "");
SYSCTL_QUAD(_vm, OID_AUTO, user_wire_limit, CTLFLAG_RW, &vm_user_wire_limit, "");
