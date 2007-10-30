/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * sysctl system call.
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

#include <bsm/audit_kernel.h>

#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>

extern vm_map_t bsd_pageable_map;

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
extern sysctlfn vm_sysctl;
extern sysctlfn vfs_sysctl;
extern sysctlfn net_sysctl;
extern sysctlfn cpu_sysctl;
extern int aio_max_requests;  				
extern int aio_max_requests_per_process;	
extern int aio_worker_threads;				
extern int maxfilesperproc;
extern int lowpri_IO_window_msecs;
extern int lowpri_IO_delay_msecs;
extern int nx_enabled;

static void
fill_eproc(struct proc *p, struct eproc *ep);
static void
fill_externproc(struct proc *p, struct extern_proc *exp);
static void
fill_user_eproc(struct proc *p, struct user_eproc *ep);
static void
fill_user_proc(struct proc *p, struct user_kinfo_proc *kp);
static void
fill_user_externproc(struct proc *p, struct user_extern_proc *exp);
extern int 
kdbg_control(int *name, u_int namelen, user_addr_t where, size_t * sizep);
int
kdebug_ops(int *name, u_int namelen, user_addr_t where, size_t *sizep, struct proc *p);
#if NFSCLIENT
extern int 
netboot_root(void);
#endif
int
pcsamples_ops(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
              struct proc *p);
__private_extern__ kern_return_t
reset_vmobjectcache(unsigned int val1, unsigned int val2);
extern int
resize_namecache(u_int newsize);
static int
sysctl_aiomax(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen);
static int
sysctl_aioprocmax(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen);
static int
sysctl_aiothreads(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen);
extern int
sysctl_clockrate(user_addr_t where, size_t *sizep);
int
sysctl_doproc(int *name, u_int namelen, user_addr_t where, size_t *sizep);
int 
sysctl_doprof(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
			  user_addr_t newp, size_t newlen);
int
sysctl_file(user_addr_t where, size_t *sizep);
static void
fill_proc(struct proc *p, struct kinfo_proc *kp);
static int
sysctl_maxfilesperproc(user_addr_t oldp, size_t *oldlenp, 
                       user_addr_t newp, size_t newlen);
static int
sysctl_maxprocperuid(user_addr_t oldp, size_t *oldlenp, 
                     user_addr_t newp, size_t newlen);
static int
sysctl_maxproc(user_addr_t oldp, size_t *oldlenp, 
               user_addr_t newp, size_t newlen);
int
sysctl_procargs(int *name, u_int namelen, user_addr_t where, 
				size_t *sizep, struct proc *cur_proc);
static int
sysctl_procargs2(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
                 struct proc *cur_proc);
static int
sysctl_procargsx(int *name, u_int namelen, user_addr_t where, size_t *sizep, 
                 struct proc *cur_proc, int argc_yes);
int
sysctl_struct(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, 
              size_t newlen, void *sp, int len);
extern int
sysctl_vnode(user_addr_t where, size_t *sizep);


/*
 * temporary location for vm_sysctl.  This should be machine independant
 */
 
extern uint32_t mach_factor[3];

static void
loadavg32to64(struct loadavg *la32, struct user_loadavg *la64)
{
	la64->ldavg[0]	= la32->ldavg[0];
	la64->ldavg[1]	= la32->ldavg[1];
	la64->ldavg[2]	= la32->ldavg[2];
	la64->fscale	= (user_long_t)la32->fscale;
}

int
vm_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp, 
          user_addr_t newp, size_t newlen, __unused struct proc *p)
{
	struct loadavg loadinfo;

	switch (name[0]) {
	case VM_LOADAVG:
		if (proc_is64bit(p)) {
			struct user_loadavg loadinfo64;
			loadavg32to64(&averunnable, &loadinfo64);
			return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&loadinfo64, sizeof(loadinfo64)));
		} else {
			return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&averunnable, sizeof(struct loadavg)));
		}
	case VM_MACHFACTOR:
		loadinfo.ldavg[0] = mach_factor[0];
		loadinfo.ldavg[1] = mach_factor[1];
		loadinfo.ldavg[2] = mach_factor[2];
		loadinfo.fscale = LSCALE;
		if (proc_is64bit(p)) {
			struct user_loadavg loadinfo64;
			loadavg32to64(&loadinfo, &loadinfo64);
			return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&loadinfo64, sizeof(loadinfo64)));
		} else {
			return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&loadinfo, sizeof(struct loadavg)));
		}
	case VM_SWAPUSAGE: {
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
		return sysctl_struct(oldp, oldlenp, newp, newlen,
				     &xsu, sizeof (struct xsw_usage));
	}
	case VM_METER:
		return (ENOTSUP);
	case VM_MAXID:
		return (ENOTSUP);
	default:
		return (ENOTSUP);
	}
	/* NOTREACHED */
	return (ENOTSUP);
}

/*
 * Locking and stats
 */
static struct sysctl_lock {
	int	sl_lock;
	int	sl_want;
	int	sl_locked;
} memlock;

int
__sysctl(struct proc *p, struct __sysctl_args *uap, __unused register_t *retval)
{
	int error, dolock = 1;
	size_t savelen = 0, oldlen = 0, newlen;
	sysctlfn *fnp = NULL;
	int name[CTL_MAXNAME];
	int i;
	int error1;

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
		     name[1] == KERN_PROC_LOW_PRI_IO || name[1] == KERN_PROCNAME || name[1] == KERN_THALTSTACK))
	    || (name[0] == CTL_HW)
	    || (name[0] == CTL_VM)
		|| (name[0] == CTL_VFS))
	    && (error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

	switch (name[0]) {
	case CTL_KERN:
		fnp = kern_sysctl;
		if ((name[1] != KERN_VNODE) && (name[1] != KERN_FILE) 
			&& (name[1] != KERN_PROC))
			dolock = 0;
		break;
	case CTL_VM:
		fnp = vm_sysctl; 
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

		/* The pc sampling mechanism does not need to take this lock */
		if ((name[1] != KERN_PCSAMPLES) &&
		    (!((name[1] == KERN_KDEBUG) && (name[2] == KERN_KDGETENTROPY)))) {
		  while (memlock.sl_lock) {
			memlock.sl_want = 1;
			sleep((caddr_t)&memlock, PRIBIO+1);
			memlock.sl_locked++;
		  }
		  memlock.sl_lock = 1;
		}

		if (dolock && oldlen &&
		    (error = vslock(uap->old, (user_size_t)oldlen))) {
			if ((name[1] != KERN_PCSAMPLES) &&
			   (! ((name[1] == KERN_KDEBUG) && (name[2] == KERN_KDGETENTROPY)))) {
		  		memlock.sl_lock = 0;
		  		if (memlock.sl_want) {
		        	memlock.sl_want = 0;
					wakeup((caddr_t)&memlock);
		  		}
			}
			return(error);
		}
		savelen = oldlen;
	}

	if (fnp) {
        error = (*fnp)(name + 1, uap->namelen - 1, uap->old,
                       &oldlen, uap->new, newlen, p);
	}
	else
	    error = ENOTSUP;

	if ( (name[0] != CTL_VFS) && (error == ENOTSUP)) {
	    size_t  tmp = oldlen;
		error = userland_sysctl(p, name, uap->namelen, uap->old, &tmp, 
		                        1, uap->new, newlen, &oldlen);
	}

	if (uap->old != USER_ADDR_NULL) {
		if (dolock && savelen) {
			error1 = vsunlock(uap->old, (user_size_t)savelen, B_WRITE);
			if (!error &&  error1)
				error = error1;
		}
		if (name[1] != KERN_PCSAMPLES) {
		  memlock.sl_lock = 0;
		  if (memlock.sl_want) {
		        memlock.sl_want = 0;
			wakeup((caddr_t)&memlock);
		  }
		}
	}
	if ((error) && (error != ENOMEM))
		return (error);

	if (uap->oldlenp != USER_ADDR_NULL) {
	    i =	suulong(uap->oldlenp, oldlen);
		if (i) 
		    return i;
	}

	return (error);
}

/*
 * Attributes stored in the kernel.
 */
__private_extern__ char corefilename[MAXPATHLEN+1];
__private_extern__ int do_coredump;
__private_extern__ int sugid_coredump;


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
	struct proc *cur_proc)
{
	if (namelen < 1)
		return (ENOTSUP);

	if (name[0] == 0 && 1 == namelen) {
		return sysctl_rdint(oldBuf, oldSize, newBuf,
			                (cur_proc->p_flag & P_AFFINITY) ? 1 : 0);
	} else if (name[0] == 1 && 2 == namelen) {
		if (name[1] == 0) {
			cur_proc->p_flag &= ~P_AFFINITY;
		} else {
			cur_proc->p_flag |= P_AFFINITY;
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
	struct proc *cur_proc)
{
	struct proc *p;

	if (namelen != 1)
		return (ENOTSUP);

	p = pfind(name[0]);
	if (p == NULL)
		return (EINVAL);

	if ((kauth_cred_getuid(p->p_ucred) != kauth_cred_getuid(kauth_cred_get())) 
		&& suser(kauth_cred_get(), &cur_proc->p_acflag))
		return (EPERM);

	return sysctl_rdint(oldBuf, oldSize, newBuf,
		                (p->p_flag & P_TRANSLATED) ? 1 : 0);
}

int
set_archhandler(struct proc *p, int arch)
{
	int error;
	struct nameidata nd;
	struct vnode_attr va;
	struct vfs_context context;
	char *archhandler;

	switch(arch) {
	case CPU_TYPE_POWERPC:
		archhandler = exec_archhandler_ppc.path;
		break;
	default:
		return (EBADARCH);
	}

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32,
		   CAST_USER_ADDR_T(archhandler), &context);
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
	error = vnode_getattr(nd.ni_vp, &va, &context);
	if (error) {
		vnode_put(nd.ni_vp);
		return (error);
	}
	vnode_put(nd.ni_vp);
	
	exec_archhandler_ppc.fsid = va.va_fsid;
	exec_archhandler_ppc.fileid = (u_long)va.va_fileid;
	return 0;
}

static int
sysctl_exec_archhandler_ppc(
	__unused int *name,
	__unused u_int namelen,
	user_addr_t oldBuf,
	size_t *oldSize,
	user_addr_t newBuf,
	size_t newSize,
	struct proc *p)
{
	int error;
	size_t len;
	struct nameidata nd;
	struct vnode_attr va;
	char handler[sizeof(exec_archhandler_ppc.path)];
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

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
		error = suser(context.vc_ucred, &p->p_acflag);
		if (error)
			return (error);
		if (newSize >= sizeof(exec_archhandler_ppc.path))
			return (ENAMETOOLONG);
		error = copyin(newBuf, handler, newSize);
		if (error)
			return (error);
		handler[newSize] = 0;
		strcpy(exec_archhandler_ppc.path, handler);
		error = set_archhandler(p, CPU_TYPE_POWERPC);
		if (error)
			return (error);
	}
	return 0;
}

SYSCTL_NODE(_kern, KERN_EXEC, exec, CTLFLAG_RD, 0, "");

SYSCTL_NODE(_kern_exec, OID_AUTO, archhandler, CTLFLAG_RD, 0, "");

SYSCTL_STRING(_kern_exec_archhandler, OID_AUTO, powerpc, CTLFLAG_RD,
		exec_archhandler_ppc.path, 0, "");

extern int get_kernel_symfile( struct proc *, char **);
__private_extern__ int 
sysctl_dopanicinfo(int *, u_int, user_addr_t, size_t *, user_addr_t, 
                   size_t, struct proc *);

/*
 * kernel related system variables.
 */
int
kern_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
            user_addr_t newp, size_t newlen, struct proc *p)
{
	int error, level, inthostid, tmp;
	unsigned int oldval=0;
	char *str;
	/* all sysctl names not listed below are terminal at this level */
	if (namelen != 1
		&& !(name[0] == KERN_PROC
			|| name[0] == KERN_PROF 
			|| name[0] == KERN_KDEBUG
			|| name[0] == KERN_PROCARGS
			|| name[0] == KERN_PROCARGS2
			|| name[0] == KERN_PCSAMPLES
			|| name[0] == KERN_IPC
			|| name[0] == KERN_SYSV
			|| name[0] == KERN_AFFINITY
			|| name[0] == KERN_TRANSLATE
			|| name[0] == KERN_EXEC
			|| name[0] == KERN_PANICINFO
			|| name[0] == KERN_POSIX
			|| name[0] == KERN_TFP)
		)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case KERN_OSTYPE:
		return (sysctl_rdstring(oldp, oldlenp, newp, ostype));
	case KERN_OSRELEASE:
		return (sysctl_rdstring(oldp, oldlenp, newp, osrelease));
	case KERN_OSREV:
		return (sysctl_rdint(oldp, oldlenp, newp, BSD));
	case KERN_VERSION:
		return (sysctl_rdstring(oldp, oldlenp, newp, version));
	case KERN_MAXVNODES:
		oldval = desiredvnodes;
		error = sysctl_int(oldp, oldlenp, newp, 
				newlen, &desiredvnodes);
		reset_vmobjectcache(oldval, desiredvnodes);
		resize_namecache(desiredvnodes);
		return(error);
	case KERN_MAXPROC:
		return (sysctl_maxproc(oldp, oldlenp, newp, newlen));
	case KERN_MAXFILES:
		return (sysctl_int(oldp, oldlenp, newp, newlen, &maxfiles));
	case KERN_MAXPROCPERUID:
		return( sysctl_maxprocperuid( oldp, oldlenp, newp, newlen ) );
	case KERN_MAXFILESPERPROC:
		return( sysctl_maxfilesperproc( oldp, oldlenp, newp, newlen ) );
	case KERN_ARGMAX:
		return (sysctl_rdint(oldp, oldlenp, newp, ARG_MAX));
	case KERN_SECURELVL:
		level = securelevel;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &level)) ||
		    newp == USER_ADDR_NULL)
			return (error);
		if (level < securelevel && p->p_pid != 1)
			return (EPERM);
		securelevel = level;
		return (0);
	case KERN_HOSTNAME:
		error = sysctl_trstring(oldp, oldlenp, newp, newlen,
		    hostname, sizeof(hostname));
		if (newp && !error)
			hostnamelen = newlen;
		return (error);
	case KERN_DOMAINNAME:
		error = sysctl_string(oldp, oldlenp, newp, newlen,
		    domainname, sizeof(domainname));
		if (newp && !error)
			domainnamelen = newlen;
		return (error);
	case KERN_HOSTID:
		inthostid = hostid;  /* XXX assumes sizeof long <= sizeof int */
		error =  sysctl_int(oldp, oldlenp, newp, newlen, &inthostid);
		hostid = inthostid;
		return (error);
	case KERN_CLOCKRATE:
		return (sysctl_clockrate(oldp, oldlenp));
	case KERN_BOOTTIME:
	{
		struct timeval	t;

		t.tv_sec = boottime_sec();
		t.tv_usec = 0;

		return (sysctl_rdstruct(oldp, oldlenp, newp, &t,
		    sizeof(struct timeval)));
	}
	case KERN_VNODE:
		return (sysctl_vnode(oldp, oldlenp));
	case KERN_PROC:
		return (sysctl_doproc(name + 1, namelen - 1, oldp, oldlenp));
	case KERN_FILE:
		return (sysctl_file(oldp, oldlenp));
#ifdef GPROF
	case KERN_PROF:
		return (sysctl_doprof(name + 1, namelen - 1, oldp, oldlenp,
		    newp, newlen));
#endif
	case KERN_POSIX1:
		return (sysctl_rdint(oldp, oldlenp, newp, _POSIX_VERSION));
	case KERN_NGROUPS:
		return (sysctl_rdint(oldp, oldlenp, newp, NGROUPS_MAX));
	case KERN_JOB_CONTROL:
		return (sysctl_rdint(oldp, oldlenp, newp, 1));
	case KERN_SAVED_IDS:
#ifdef _POSIX_SAVED_IDS
		return (sysctl_rdint(oldp, oldlenp, newp, 1));
#else
		return (sysctl_rdint(oldp, oldlenp, newp, 0));
#endif
	case KERN_KDEBUG:
		return (kdebug_ops(name + 1, namelen - 1, oldp, oldlenp, p));
	case KERN_PCSAMPLES:
		return (pcsamples_ops(name + 1, namelen - 1, oldp, oldlenp, p));
	case KERN_PROCARGS:
		/* new one as it does not use kinfo_proc */
		return (sysctl_procargs(name + 1, namelen - 1, oldp, oldlenp, p));
	case KERN_PROCARGS2:
		/* new one as it does not use kinfo_proc */
		return (sysctl_procargs2(name + 1, namelen - 1, oldp, oldlenp, p));
	case KERN_SYMFILE:
		error = get_kernel_symfile( p, &str );
		if ( error )
			return error;
		return (sysctl_rdstring(oldp, oldlenp, newp, str));
#if NFSCLIENT
	case KERN_NETBOOT:
		return (sysctl_rdint(oldp, oldlenp, newp, netboot_root()));
#endif
	case KERN_PANICINFO:
		return(sysctl_dopanicinfo(name + 1, namelen - 1, oldp, oldlenp,
			newp, newlen, p));
	case KERN_AFFINITY:
		return sysctl_affinity(name+1, namelen-1, oldp, oldlenp,
									newp, newlen, p);
	case KERN_TRANSLATE:
		return sysctl_translate(name+1, namelen-1, oldp, oldlenp, newp,
				      newlen, p);
	case KERN_CLASSICHANDLER:
		return sysctl_exec_archhandler_ppc(name+1, namelen-1, oldp,
						   oldlenp, newp, newlen, p);
	case KERN_AIOMAX:
		return( sysctl_aiomax( oldp, oldlenp, newp, newlen ) );
	case KERN_AIOPROCMAX:
		return( sysctl_aioprocmax( oldp, oldlenp, newp, newlen ) );
	case KERN_AIOTHREADS:
		return( sysctl_aiothreads( oldp, oldlenp, newp, newlen ) );
	case KERN_USRSTACK:
		return (sysctl_rdint(oldp, oldlenp, newp, (uintptr_t)p->user_stack));
	case KERN_USRSTACK64:
		return (sysctl_rdquad(oldp, oldlenp, newp, p->user_stack));
	case KERN_COREFILE:
		error = sysctl_string(oldp, oldlenp, newp, newlen,
		    corefilename, sizeof(corefilename));
		return (error);
	case KERN_COREDUMP:
		tmp = do_coredump;
		error = sysctl_int(oldp, oldlenp, newp, newlen, &do_coredump);
		if (!error && ((do_coredump < 0) || (do_coredump > 1))) {
			do_coredump = tmp;
			error = EINVAL;
		}
		return (error);
	case KERN_SUGID_COREDUMP:
		tmp = sugid_coredump;
		error = sysctl_int(oldp, oldlenp, newp, newlen, &sugid_coredump);
		if (!error && ((sugid_coredump < 0) || (sugid_coredump > 1))) {
			sugid_coredump = tmp;
			error = EINVAL;
		}
		return (error);
	case KERN_PROCDELAYTERM:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(int))
			return (ENOMEM);
		if ( newp && newlen != sizeof(int) )
			return(EINVAL);
		*oldlenp = sizeof(int);
		old_value = (p->p_lflag & P_LDELAYTERM)? 1: 0;
		if (oldp && (error = copyout( &old_value, oldp, sizeof(int))))
			return(error);
        	if (error == 0 && newp )
                	error = copyin( newp, &new_value, sizeof(int) );
        	if (error == 0 && newp) {
                	if (new_value)
                        	p->p_lflag |=  P_LDELAYTERM;
                	else
                        	p->p_lflag &=  ~P_LDELAYTERM;
        	}
		return(error);
	}
	case KERN_PROC_LOW_PRI_IO:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(int))
			return (ENOMEM);
		if ( newp && newlen != sizeof(int) )
			return(EINVAL);
		*oldlenp = sizeof(int);

		old_value = (p->p_lflag & P_LLOW_PRI_IO)? 0x01: 0;
		if (p->p_lflag & P_LBACKGROUND_IO)
		        old_value |= 0x02;

		if (oldp && (error = copyout( &old_value, oldp, sizeof(int))))
			return(error);
        	if (error == 0 && newp )
                	error = copyin( newp, &new_value, sizeof(int) );
        	if (error == 0 && newp) {
                	if (new_value & 0x01)
                        	p->p_lflag |= P_LLOW_PRI_IO;
			else if (new_value & 0x02)
                        	p->p_lflag |= P_LBACKGROUND_IO;
                	else if (new_value == 0)
                        	p->p_lflag &= ~(P_LLOW_PRI_IO | P_LBACKGROUND_IO);
        	}
		return(error);
	}
	case KERN_LOW_PRI_WINDOW:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(old_value) )
			return (ENOMEM);
		if ( newp && newlen != sizeof(new_value) )
			return(EINVAL);
		*oldlenp = sizeof(old_value);

		old_value = lowpri_IO_window_msecs;

		if (oldp && (error = copyout( &old_value, oldp, *oldlenp)))
			return(error);
        	if (error == 0 && newp )
                	error = copyin( newp, &new_value, sizeof(newlen) );
        	if (error == 0 && newp) {
		        lowpri_IO_window_msecs = new_value;
        	}
		return(error);
	}
	case KERN_LOW_PRI_DELAY:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(old_value) )
			return (ENOMEM);
		if ( newp && newlen != sizeof(new_value) )
			return(EINVAL);
		*oldlenp = sizeof(old_value);

		old_value = lowpri_IO_delay_msecs;

		if (oldp && (error = copyout( &old_value, oldp, *oldlenp)))
			return(error);
        	if (error == 0 && newp )
                	error = copyin( newp, &new_value, sizeof(newlen) );
        	if (error == 0 && newp) {
		        lowpri_IO_delay_msecs = new_value;
        	}
		return(error);
	}
	case KERN_NX_PROTECTION:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(old_value) )
			return (ENOMEM);
		if ( newp && newlen != sizeof(new_value) )
			return(EINVAL);
		*oldlenp = sizeof(old_value);

		old_value = nx_enabled;

		if (oldp && (error = copyout( &old_value, oldp, *oldlenp)))
			return(error);
#ifdef __i386__
		/*
		 * Only allow setting if NX is supported on the chip
		 */
		if (cpuid_extfeatures() & CPUID_EXTFEATURE_XD) {
#endif
        		if (error == 0 && newp)
                		error = copyin(newp, &new_value,
					       sizeof(newlen));
        		if (error == 0 && newp)
		        	nx_enabled = new_value;
#ifdef __i386__
        	} else if (newp) {
			error = ENOTSUP;
		}
#endif
		return(error);
	}
	case KERN_SHREG_PRIVATIZABLE:
		/* this kernel does implement shared_region_make_private_np() */
		return (sysctl_rdint(oldp, oldlenp, newp, 1));
	case KERN_PROCNAME:
		error = sysctl_trstring(oldp, oldlenp, newp, newlen,
		    &p->p_name[0], (2*MAXCOMLEN+1));
		return (error);
	case KERN_THALTSTACK:
	{
		int	 old_value, new_value;

		error = 0;
		if (oldp && *oldlenp < sizeof(int))
			return (ENOMEM);
		if ( newp && newlen != sizeof(int) )
			return(EINVAL);
		*oldlenp = sizeof(int);
		old_value = (p->p_lflag & P_LTHSIGSTACK)? 1: 0;
		if (oldp && (error = copyout( &old_value, oldp, sizeof(int))))
			return(error);
        	if (error == 0 && newp )
                	error = copyin( newp, &new_value, sizeof(int) );
        	if (error == 0 && newp) {
                	if (new_value) {
							/* we cannot swich midstream if inuse */
							if ((p->p_sigacts->ps_flags & SAS_ALTSTACK) == SAS_ALTSTACK)
								return(EPERM);
                        	p->p_lflag |=  P_LTHSIGSTACK;
                	} else {
							/* we cannot swich midstream */
							if ((p->p_lflag & P_LTHSIGSTACK) == P_LTHSIGSTACK)
								return(EPERM);
							p->p_lflag &=  ~P_LTHSIGSTACK;
					}
        	}
		return(error);
	}
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
             user_addr_t newp, size_t newlen, struct proc *p)
{
	struct ctldebug *cdp;

	/* all sysctl names at this level are name and field */
	if (namelen != 2)
		return (ENOTDIR);		/* overloaded */
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
sysctl_rdquad(oldp, oldlenp, newp, val)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	quad_t val;
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
		error = copyout((caddr_t)&val, CAST_USER_ADDR_T(oldp), sizeof(quad_t));
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
int
sysctl_file(user_addr_t where, size_t *sizep)
{
	int buflen, error;
	struct fileglob *fg;
	user_addr_t start = where;
	struct extern_file nef;

	buflen = *sizep;
	if (where == USER_ADDR_NULL) {
		/*
		 * overestimate by 10 files
		 */
		*sizep = sizeof(filehead) + (nfiles + 10) * sizeof(struct extern_file);
		return (0);
	}

	/*
	 * first copyout filehead
	 */
	if (buflen < 0 || (size_t)buflen < sizeof(filehead)) {
		*sizep = 0;
		return (0);
	}
    error = copyout((caddr_t)&filehead, where, sizeof(filehead));
	if (error)
		return (error);
	buflen -= sizeof(filehead);
	where += sizeof(filehead);

	/*
	 * followed by an array of file structures
	 */
	for (fg = filehead.lh_first; fg != 0; fg = fg->f_list.le_next) {
		if (buflen < 0 || (size_t)buflen < sizeof(struct extern_file)) {
			*sizep = where - start;
			return (ENOMEM);
		}
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
        error = copyout((caddr_t)&nef, where, sizeof (struct extern_file));
		if (error)
			return (error);
		buflen -= sizeof(struct extern_file);
		where += sizeof(struct extern_file);
	}
    *sizep = where - start;
	return (0);
}

/*
 * try over estimating by 5 procs
 */
#define KERN_PROCSLOP	(5 * sizeof (struct kinfo_proc))

int
sysctl_doproc(int *name, u_int namelen, user_addr_t where, size_t *sizep)
{
	struct proc *p;
	user_addr_t dp = where;
	size_t needed = 0;
	int buflen = where != USER_ADDR_NULL ? *sizep : 0;
	int doingzomb;
	int error = 0;
	boolean_t is_64_bit = FALSE;
	struct kinfo_proc       kproc;
	struct user_kinfo_proc  user_kproc;
	int sizeof_kproc;
	caddr_t kprocp;

	if (namelen != 2 && !(namelen == 1 && name[0] == KERN_PROC_ALL))
		return (EINVAL);
	p = allproc.lh_first;
	doingzomb = 0;
	is_64_bit = proc_is64bit(current_proc()); 
	if (is_64_bit) {
		sizeof_kproc = sizeof(user_kproc);
		kprocp = (caddr_t) &user_kproc;
	}
	else {
		sizeof_kproc = sizeof(kproc);
		kprocp = (caddr_t) &kproc;
	}
again:
	for (; p != 0; p = p->p_list.le_next) {
		/*
		 * Skip embryonic processes.
		 */
		if (p->p_stat == SIDL)
			continue;
		/*
		 * TODO - make more efficient (see notes below).
		 * do by session.
		 */
		switch (name[0]) {

		case KERN_PROC_PID:
			/* could do this with just a lookup */
			if (p->p_pid != (pid_t)name[1])
				continue;
			break;

		case KERN_PROC_PGRP:
			/* could do this by traversing pgrp */
			if (p->p_pgrp->pg_id != (pid_t)name[1])
				continue;
			break;

		case KERN_PROC_TTY:
			if ((p->p_flag & P_CONTROLT) == 0 ||
				(p->p_session == NULL) ||
			    p->p_session->s_ttyp == NULL ||
			    p->p_session->s_ttyp->t_dev != (dev_t)name[1])
				continue;
			break;

		case KERN_PROC_UID:
			if ((p->p_ucred == NULL) ||
				(kauth_cred_getuid(p->p_ucred) != (uid_t)name[1]))
				continue;
			break;

		case KERN_PROC_RUID:
			if ((p->p_ucred == NULL) ||
				(p->p_ucred->cr_ruid != (uid_t)name[1]))
				continue;
			break;
		}
		if (buflen >= sizeof_kproc) {
			bzero(kprocp, sizeof_kproc);
			if (is_64_bit) {
				fill_user_proc(p, (struct user_kinfo_proc *) kprocp);
			}
			else {
				fill_proc(p, (struct kinfo_proc *) kprocp);
			}
			error = copyout(kprocp, dp, sizeof_kproc);
			if (error)
				return (error);
			dp += sizeof_kproc;
			buflen -= sizeof_kproc;
		}
		needed += sizeof_kproc;
	}
	if (doingzomb == 0) {
		p = zombproc.lh_first;
		doingzomb++;
		goto again;
	}
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
fill_eproc(p, ep)
	register struct proc *p;
	register struct eproc *ep;
{
	register struct tty *tp;

	ep->e_paddr = p;
	if (p->p_pgrp) {
		ep->e_sess = p->p_pgrp->pg_session;
		ep->e_pgid = p->p_pgrp->pg_id;
		ep->e_jobc = p->p_pgrp->pg_jobc;
		if (ep->e_sess && ep->e_sess->s_ttyvp)
			ep->e_flag = EPROC_CTTY;
	} else {
		ep->e_sess = (struct session *)0;
		ep->e_pgid = 0;
		ep->e_jobc = 0;
	}
	ep->e_ppid = (p->p_pptr) ? p->p_pptr->p_pid : 0;
	/* Pre-zero the fake historical pcred */
	bzero(&ep->e_pcred, sizeof(struct _pcred));
	if (p->p_ucred) {
		/* XXX not ref-counted */

		/* A fake historical pcred */
		ep->e_pcred.p_ruid = p->p_ucred->cr_ruid;
		ep->e_pcred.p_svuid = p->p_ucred->cr_svuid;
		ep->e_pcred.p_rgid = p->p_ucred->cr_rgid;
		ep->e_pcred.p_svgid = p->p_ucred->cr_svgid;

		/* A fake historical *kauth_cred_t */
		ep->e_ucred.cr_ref = p->p_ucred->cr_ref;
		ep->e_ucred.cr_uid = kauth_cred_getuid(p->p_ucred);
		ep->e_ucred.cr_ngroups = p->p_ucred->cr_ngroups;
		bcopy(p->p_ucred->cr_groups, ep->e_ucred.cr_groups, NGROUPS*sizeof(gid_t));

	}
	if (p->p_stat == SIDL || p->p_stat == SZOMB) {
		ep->e_vm.vm_tsize = 0;
		ep->e_vm.vm_dsize = 0;
		ep->e_vm.vm_ssize = 0;
	}
	ep->e_vm.vm_rssize = 0;

	if ((p->p_flag & P_CONTROLT) && (ep->e_sess) &&
	     (tp = ep->e_sess->s_ttyp)) {
		ep->e_tdev = tp->t_dev;
		ep->e_tpgid = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		ep->e_tsess = tp->t_session;
	} else
		ep->e_tdev = NODEV;

	if (SESS_LEADER(p))
		ep->e_flag |= EPROC_SLEADER;
	if (p->p_wmesg)
		strncpy(ep->e_wmesg, p->p_wmesg, WMESGLEN);
	ep->e_xsize = ep->e_xrssize = 0;
	ep->e_xccount = ep->e_xswrss = 0;
}

/*
 * Fill in an LP64 version of eproc structure for the specified process.
 */
static void
fill_user_eproc(register struct proc *p, register struct user_eproc *ep)
{
	register struct tty *tp;
	struct	session *sessionp = NULL;

	ep->e_paddr = CAST_USER_ADDR_T(p);
	if (p->p_pgrp) {
	    sessionp = p->p_pgrp->pg_session;
		ep->e_sess = CAST_USER_ADDR_T(sessionp);
		ep->e_pgid = p->p_pgrp->pg_id;
		ep->e_jobc = p->p_pgrp->pg_jobc;
		if (sessionp) {
            if (sessionp->s_ttyvp)
			    ep->e_flag = EPROC_CTTY;
		}
	} else {
		ep->e_sess = USER_ADDR_NULL;
		ep->e_pgid = 0;
		ep->e_jobc = 0;
	}
	ep->e_ppid = (p->p_pptr) ? p->p_pptr->p_pid : 0;
	/* Pre-zero the fake historical pcred */
	bzero(&ep->e_pcred, sizeof(ep->e_pcred));
	if (p->p_ucred) {
		/* XXX not ref-counted */

		/* A fake historical pcred */
		ep->e_pcred.p_ruid = p->p_ucred->cr_ruid;
		ep->e_pcred.p_svuid = p->p_ucred->cr_svuid;
		ep->e_pcred.p_rgid = p->p_ucred->cr_rgid;
		ep->e_pcred.p_svgid = p->p_ucred->cr_svgid;

		/* A fake historical *kauth_cred_t */
		ep->e_ucred.cr_ref = p->p_ucred->cr_ref;
		ep->e_ucred.cr_uid = kauth_cred_getuid(p->p_ucred);
		ep->e_ucred.cr_ngroups = p->p_ucred->cr_ngroups;
		bcopy(p->p_ucred->cr_groups, ep->e_ucred.cr_groups, NGROUPS*sizeof(gid_t));

	}
	if (p->p_stat == SIDL || p->p_stat == SZOMB) {
		ep->e_vm.vm_tsize = 0;
		ep->e_vm.vm_dsize = 0;
		ep->e_vm.vm_ssize = 0;
	}
	ep->e_vm.vm_rssize = 0;

	if ((p->p_flag & P_CONTROLT) && (sessionp) &&
	     (tp = sessionp->s_ttyp)) {
		ep->e_tdev = tp->t_dev;
		ep->e_tpgid = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		ep->e_tsess = CAST_USER_ADDR_T(tp->t_session);
	} else
		ep->e_tdev = NODEV;

	if (SESS_LEADER(p))
		ep->e_flag |= EPROC_SLEADER;
	if (p->p_wmesg)
		strncpy(ep->e_wmesg, p->p_wmesg, WMESGLEN);
	ep->e_xsize = ep->e_xrssize = 0;
	ep->e_xccount = ep->e_xswrss = 0;
}

/*
 * Fill in an eproc structure for the specified process.
 */
static void
fill_externproc(p, exp)
	register struct proc *p;
	register struct extern_proc *exp;
{
	exp->p_forw = exp->p_back = NULL;
	if (p->p_stats)
		exp->p_starttime = p->p_stats->p_start;
	exp->p_vmspace = NULL;
	exp->p_sigacts = p->p_sigacts;
	exp->p_flag  = p->p_flag;
	exp->p_stat  = p->p_stat ;
	exp->p_pid  = p->p_pid ;
	exp->p_oppid  = p->p_oppid ;
	exp->p_dupfd  = p->p_dupfd ;
	/* Mach related  */
	exp->user_stack  = CAST_DOWN(caddr_t, p->user_stack);
	exp->exit_thread  = p->exit_thread ;
	exp->p_debugger  = p->p_debugger ;
	exp->sigwait  = p->sigwait ;
	/* scheduling */
	exp->p_estcpu  = p->p_estcpu ;
	exp->p_cpticks  = p->p_cpticks ;
	exp->p_pctcpu  = p->p_pctcpu ;
	exp->p_wchan  = p->p_wchan ;
	exp->p_wmesg  = p->p_wmesg ;
	exp->p_swtime  = p->p_swtime ;
	exp->p_slptime  = p->p_slptime ;
	bcopy(&p->p_realtimer, &exp->p_realtimer,sizeof(struct itimerval));
	bcopy(&p->p_rtime, &exp->p_rtime,sizeof(struct timeval));
	exp->p_uticks  = p->p_uticks ;
	exp->p_sticks  = p->p_sticks ;
	exp->p_iticks  = p->p_iticks ;
	exp->p_traceflag  = p->p_traceflag ;
	exp->p_tracep  = p->p_tracep ;
	exp->p_siglist  = 0 ;	/* No longer relevant */
	exp->p_textvp  = p->p_textvp ;
	exp->p_holdcnt = 0 ;
	exp->p_sigmask  = 0 ;	/* no longer avaialable */
	exp->p_sigignore  = p->p_sigignore ;
	exp->p_sigcatch  = p->p_sigcatch ;
	exp->p_priority  = p->p_priority ;
	exp->p_usrpri  = p->p_usrpri ;
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
fill_user_externproc(register struct proc *p, register struct user_extern_proc *exp)
{
	exp->p_forw = exp->p_back = USER_ADDR_NULL;
	if (p->p_stats) {
		exp->p_starttime.tv_sec = p->p_stats->p_start.tv_sec;
		exp->p_starttime.tv_usec = p->p_stats->p_start.tv_usec;
	}
	exp->p_vmspace = USER_ADDR_NULL;
	exp->p_sigacts = CAST_USER_ADDR_T(p->p_sigacts);
	exp->p_flag  = p->p_flag;
	exp->p_stat  = p->p_stat ;
	exp->p_pid  = p->p_pid ;
	exp->p_oppid  = p->p_oppid ;
	exp->p_dupfd  = p->p_dupfd ;
	/* Mach related  */
	exp->user_stack  = p->user_stack;
	exp->exit_thread  = CAST_USER_ADDR_T(p->exit_thread);
	exp->p_debugger  = p->p_debugger ;
	exp->sigwait  = p->sigwait ;
	/* scheduling */
	exp->p_estcpu  = p->p_estcpu ;
	exp->p_cpticks  = p->p_cpticks ;
	exp->p_pctcpu  = p->p_pctcpu ;
	exp->p_wchan  = CAST_USER_ADDR_T(p->p_wchan);
	exp->p_wmesg  = CAST_USER_ADDR_T(p->p_wmesg);
	exp->p_swtime  = p->p_swtime ;
	exp->p_slptime  = p->p_slptime ;
	exp->p_realtimer.it_interval.tv_sec = p->p_realtimer.it_interval.tv_sec;
	exp->p_realtimer.it_interval.tv_usec = p->p_realtimer.it_interval.tv_usec;
	exp->p_realtimer.it_value.tv_sec = p->p_realtimer.it_value.tv_sec;
	exp->p_realtimer.it_value.tv_usec = p->p_realtimer.it_value.tv_usec;
	exp->p_rtime.tv_sec = p->p_rtime.tv_sec;
	exp->p_rtime.tv_usec = p->p_rtime.tv_usec;
	exp->p_uticks  = p->p_uticks ;
	exp->p_sticks  = p->p_sticks ;
	exp->p_iticks  = p->p_iticks ;
	exp->p_traceflag  = p->p_traceflag ;
	exp->p_tracep  = CAST_USER_ADDR_T(p->p_tracep);
	exp->p_siglist  = 0 ;	/* No longer relevant */
	exp->p_textvp  = CAST_USER_ADDR_T(p->p_textvp);
	exp->p_holdcnt = 0 ;
	exp->p_sigmask  = 0 ;	/* no longer avaialable */
	exp->p_sigignore  = p->p_sigignore ;
	exp->p_sigcatch  = p->p_sigcatch ;
	exp->p_priority  = p->p_priority ;
	exp->p_usrpri  = p->p_usrpri ;
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
fill_proc(p, kp)
	register struct proc *p;
	register struct kinfo_proc *kp;
{
	fill_externproc(p, &kp->kp_proc);
	fill_eproc(p, &kp->kp_eproc);
}

static void
fill_user_proc(register struct proc *p, register struct user_kinfo_proc *kp)
{
	fill_user_externproc(p, &kp->kp_proc);
	fill_user_eproc(p, &kp->kp_eproc);
}

int
kdebug_ops(int *name, u_int namelen, user_addr_t where, 
           size_t *sizep, struct proc *p)
{
	int ret=0;

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

extern int pcsamples_control(int *name, u_int namelen, user_addr_t where,
                             size_t * sizep);

int
pcsamples_ops(int *name, u_int namelen, user_addr_t where, 
			  size_t *sizep, struct proc *p)
{
	int ret=0;

    ret = suser(kauth_cred_get(), &p->p_acflag);
	if (ret)
		return(ret);

	switch(name[0]) {
	case KERN_PCDISABLE:
	case KERN_PCGETBUF:
	case KERN_PCSETUP:
	case KERN_PCREMOVE:
	case KERN_PCREADBUF:
	case KERN_PCSETREG:
	case KERN_PCSETBUF:
	case KERN_PCCOMM:
	        ret = pcsamples_control(name, namelen, where, sizep);
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
                size_t *sizep, struct proc *cur_proc)
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 0);
}

static int
sysctl_procargs2(int *name, u_int namelen, user_addr_t where, 
                 size_t *sizep, struct proc *cur_proc)
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 1);
}

static int
sysctl_procargsx(int *name, __unused u_int namelen, user_addr_t where, 
                 size_t *sizep, struct proc *cur_proc, int argc_yes)
{
	struct proc *p;
	int buflen = where != USER_ADDR_NULL ? *sizep : 0;
	int error = 0;
	struct vm_map *proc_map;
	struct task * task;
	vm_map_copy_t	tmp;
	user_addr_t	arg_addr;
	size_t		arg_size;
	caddr_t data;
	int size;
	vm_offset_t	copy_start, copy_end;
	kern_return_t ret;
	int pid;

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
	p = pfind(pid);
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

	if (!p->user_stack)
		return(EINVAL);

	if (where == USER_ADDR_NULL) {
		/* caller only wants to know length of proc args data */
		if (sizep == NULL)
			return(EFAULT);
			
		 size = p->p_argslen;
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
	
	if ((kauth_cred_getuid(p->p_ucred) != kauth_cred_getuid(kauth_cred_get())) 
		&& suser(kauth_cred_get(), &cur_proc->p_acflag))
		return (EINVAL);

	if ((u_int)arg_size > p->p_argslen)
	        arg_size = round_page(p->p_argslen);

	arg_addr = p->user_stack - arg_size;


	/*
	 *	Before we can block (any VM code), make another
	 *	reference to the map to keep it alive.  We do
	 *	that by getting a reference on the task itself.
	 */
	task = p->task;
	if (task == NULL)
		return(EINVAL);
	
	/*
	 * Once we have a task reference we can convert that into a
	 * map reference, which we will use in the calls below.  The
	 * task/process may change its map after we take this reference
	 * (see execve), but the worst that will happen then is a return
	 * of stale info (which is always a possibility).
	 */
	task_reference(task);
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

	if (arg_size > p->p_argslen) {
		data = (caddr_t) (copy_end - p->p_argslen);
		size = p->p_argslen;
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
		if ( (! error) && (buflen > 0 && (u_int)buflen > p->p_argslen) )
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
			if ( (buflen & ~(sizeof(int)-1)) >= ( p->p_argslen + extraSpaceNeeded ))
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
 * Validate parameters and get old / set new parameters
 * for max number of concurrent aio requests.  Makes sure
 * the system wide limit is greater than the per process
 * limit.
 */
static int
sysctl_aiomax(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen)
{
	int 	error = 0;
	int		new_value;

	if ( oldp && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp )
		error = copyout( &aio_max_requests, oldp, sizeof(int) );
	if ( error == 0 && newp )
		error = copyin( newp, &new_value, sizeof(int) );
	if ( error == 0 && newp ) {
		if ( new_value >= aio_max_requests_per_process )
			aio_max_requests = new_value;
		else
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_aiomax */


/*
 * Validate parameters and get old / set new parameters
 * for max number of concurrent aio requests per process.  
 * Makes sure per process limit is less than the system wide
 * limit.
 */
static int
sysctl_aioprocmax(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen )
{
	int 	error = 0;
	int		new_value = 0;

	if ( oldp && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp )
		error = copyout( &aio_max_requests_per_process, oldp, sizeof(int) );
	if ( error == 0 && newp )
		error = copyin( newp, &new_value, sizeof(int) );
	if ( error == 0 && newp ) {
		if ( new_value <= aio_max_requests && new_value >= AIO_LISTIO_MAX )
			aio_max_requests_per_process = new_value;
		else
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_aioprocmax */


/*
 * Validate parameters and get old / set new parameters
 * for max number of async IO worker threads.  
 * We only allow an increase in the number of worker threads.
 */
static int
sysctl_aiothreads(user_addr_t oldp, size_t *oldlenp, user_addr_t newp, size_t newlen)
{
	int 	error = 0;
	int		new_value;

	if ( oldp && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp )
		error = copyout( &aio_worker_threads, oldp, sizeof(int) );
	if ( error == 0 && newp )
		error = copyin( newp, &new_value, sizeof(int) );
	if ( error == 0 && newp ) {
	        if (new_value > aio_worker_threads ) {
		        _aio_create_worker_threads( (new_value - aio_worker_threads) );
			aio_worker_threads = new_value;
		}
		else
		        error = EINVAL;
	}
	return( error );
	
} /* sysctl_aiothreads */


/*
 * Validate parameters and get old / set new parameters
 * for max number of processes per UID.
 * Makes sure per UID limit is less than the system wide limit.
 */
static int
sysctl_maxprocperuid(user_addr_t oldp, size_t *oldlenp, 
                     user_addr_t newp, size_t newlen)
{
	int 	error = 0;
	int		new_value;

	if ( oldp != USER_ADDR_NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != USER_ADDR_NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != USER_ADDR_NULL )
		error = copyout( &maxprocperuid, oldp, sizeof(int) );
	if ( error == 0 && newp != USER_ADDR_NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 ) {
			AUDIT_ARG(value, new_value);
			if ( new_value <= maxproc && new_value > 0 )
				maxprocperuid = new_value;
			else
				error = EINVAL;
		}
		else 
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_maxprocperuid */


/*
 * Validate parameters and get old / set new parameters
 * for max number of files per process.
 * Makes sure per process limit is less than the system-wide limit.
 */
static int
sysctl_maxfilesperproc(user_addr_t oldp, size_t *oldlenp, 
                       user_addr_t newp, size_t newlen)
{
	int 	error = 0;
	int		new_value;

	if ( oldp != USER_ADDR_NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != USER_ADDR_NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != USER_ADDR_NULL )
		error = copyout( &maxfilesperproc, oldp, sizeof(int) );
	if ( error == 0 && newp != USER_ADDR_NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 ) {
			AUDIT_ARG(value, new_value);
			if ( new_value < maxfiles && new_value > 0 )
				maxfilesperproc = new_value;
			else
				error = EINVAL;
		}
		else
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_maxfilesperproc */


/*
 * Validate parameters and get old / set new parameters
 * for the system-wide limit on the max number of processes.
 * Makes sure the system-wide limit is less than the configured hard
 * limit set at kernel compilation.
 */
static int
sysctl_maxproc(user_addr_t oldp, size_t *oldlenp, 
               user_addr_t newp, size_t newlen )
{
	int 	error = 0;
	int	new_value;

	if ( oldp != USER_ADDR_NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != USER_ADDR_NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != USER_ADDR_NULL )
		error = copyout( &maxproc, oldp, sizeof(int) );
	if ( error == 0 && newp != USER_ADDR_NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 ) {
			AUDIT_ARG(value, new_value);
			if ( new_value <= hard_maxproc && new_value > 0 )
			maxproc = new_value;
			else
				error = EINVAL;
		}
		else
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_maxproc */

#if __i386__
static int
sysctl_sysctl_exec_affinity SYSCTL_HANDLER_ARGS
{
	struct proc *cur_proc = req->p;
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
			cur_proc->p_flag &= ~P_AFFINITY;
		else if (newcputype == CPU_TYPE_POWERPC)
			cur_proc->p_flag |= P_AFFINITY;
		else
			return (EINVAL);
	}
	
	return 0;
}
SYSCTL_PROC(_sysctl, OID_AUTO, proc_exec_affinity, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY, 0, 0, sysctl_sysctl_exec_affinity ,"I","proc_exec_affinity");
#endif

static int
fetch_process_cputype(
	struct proc *cur_proc,
	int *name,
	u_int namelen,
	cpu_type_t *cputype)
{
	struct proc *p = NULL;
	cpu_type_t ret = 0;
	
	if (namelen == 0)
		p = cur_proc;
	else if (namelen == 1) {
		p = pfind(name[0]);
		if (p == NULL)
			return (EINVAL);
		if ((kauth_cred_getuid(p->p_ucred) != kauth_cred_getuid(kauth_cred_get())) 
			&& suser(kauth_cred_get(), &cur_proc->p_acflag))
			return (EPERM);
	} else {
		return EINVAL;
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
	
	return 0;
}

static int
sysctl_sysctl_native SYSCTL_HANDLER_ARGS
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
sysctl_sysctl_cputype SYSCTL_HANDLER_ARGS
{
	int error;
	cpu_type_t proc_cputype = 0;
	if ((error = fetch_process_cputype(req->p, (int *)arg1, arg2, &proc_cputype)) != 0)
		return error;
	return SYSCTL_OUT(req, &proc_cputype, sizeof(proc_cputype));
}
SYSCTL_PROC(_sysctl, OID_AUTO, proc_cputype, CTLTYPE_NODE|CTLFLAG_RD, 0, 0, sysctl_sysctl_cputype ,"I","proc_cputype");

