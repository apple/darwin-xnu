/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/vnode.h>
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
#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <vm/vm_kern.h>
#include <mach/host_info.h>

extern vm_map_t bsd_pageable_map;

#include <sys/mount.h>
#include <sys/kdebug.h>

#include <IOKit/IOPlatformExpert.h>
#include <pexpert/pexpert.h>

#include <machine/machine_routines.h>

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
extern int maxprocperuid;
extern int maxfilesperproc;


int
userland_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t 
		*oldlenp, int inkernel, void *new, size_t newlen, size_t *retval);

static int
sysctl_aiomax( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static int
sysctl_aioprocmax( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static int
sysctl_aiothreads( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static void
fill_proc(struct proc *p, struct kinfo_proc *kp);
static int
sysctl_maxfilesperproc( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static int
sysctl_maxprocperuid( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static int
sysctl_maxproc( void *oldp, size_t *oldlenp, void *newp, size_t newlen );
static int
sysctl_procargs2( int *name, u_int namelen, char *where, size_t *sizep, struct proc *cur_proc);
static int
sysctl_procargsx( int *name, u_int namelen, char *where, size_t *sizep, struct proc *cur_proc, int argc_yes);


/*
 * temporary location for vm_sysctl.  This should be machine independant
 */
int
vm_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	extern uint32_t mach_factor[3];
	struct loadavg loadinfo;

	switch (name[0]) {
	case VM_LOADAVG:
		return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&averunnable, sizeof(struct loadavg)));
	case VM_MACHFACTOR:
		loadinfo.ldavg[0] = mach_factor[0];
		loadinfo.ldavg[1] = mach_factor[1];
		loadinfo.ldavg[2] = mach_factor[2];
		loadinfo.fscale = LSCALE;
		return (sysctl_struct(oldp, oldlenp, newp, newlen,
					&loadinfo, sizeof(struct loadavg)));
	case VM_METER:
		return (EOPNOTSUPP);
	case VM_MAXID:
		return (EOPNOTSUPP);
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
	return (EOPNOTSUPP);
}

/*
 * Locking and stats
 */
static struct sysctl_lock {
	int	sl_lock;
	int	sl_want;
	int	sl_locked;
} memlock;

struct __sysctl_args {
	int *name;
	u_int namelen;
	void *old;
	size_t *oldlenp;
	void *new;
	size_t newlen;
};
int
__sysctl(p, uap, retval)
	struct proc *p;
	register struct __sysctl_args *uap;
	register_t *retval;
{
	int error, dolock = 1;
	size_t savelen, oldlen = 0;
	sysctlfn *fn;
	int name[CTL_MAXNAME];
	int i;
	int error1;

	/*
	 * all top-level sysctl names are non-terminal
	 */
	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);
	if (error =
	    copyin(uap->name, &name, uap->namelen * sizeof(int)))
		return (error);

	/* CTL_UNSPEC is used to get oid to AUTO_OID */
	if (uap->new != NULL
		&& ((name[0] == CTL_KERN
				&& !(name[1] == KERN_IPC || name[1] == KERN_PANICINFO))
			|| (name[0] == CTL_HW)
			|| (name[0] == CTL_VM)
			|| (name[0] == CTL_VFS))
		&& (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);

	switch (name[0]) {
	case CTL_KERN:
		fn = kern_sysctl;
		if ((name[1] != KERN_VNODE) && (name[1] != KERN_FILE) 
			&& (name[1] != KERN_PROC))
			dolock = 0;
		break;
	case CTL_VM:
		fn = vm_sysctl;
		break;
                
	case CTL_VFS:
		fn = vfs_sysctl;
		break;
#ifdef DEBUG
	case CTL_DEBUG:
		fn = debug_sysctl;
		break;
#endif
	default:
		fn = 0;
	}

	if (uap->oldlenp &&
	    (error = copyin(uap->oldlenp, &oldlen, sizeof(oldlen))))
		return (error);

	if (uap->old != NULL) {
		if (!useracc(uap->old, oldlen, B_WRITE))
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

		if (dolock && oldlen && (error = vslock(uap->old, oldlen))) {
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

	if (fn)
	    error = (*fn)(name + 1, uap->namelen - 1, uap->old,
			  &oldlen, uap->new, uap->newlen, p);
	else
	    error = EOPNOTSUPP;

	if ( (name[0] != CTL_VFS) && (error == EOPNOTSUPP))
		error = userland_sysctl(p, name, uap->namelen,
					uap->old, uap->oldlenp, 0,
					uap->new, uap->newlen, &oldlen);

	if (uap->old != NULL) {
		if (dolock && savelen) {
			error1 = vsunlock(uap->old, savelen, B_WRITE);
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

	if (uap->oldlenp) {
		i = copyout(&oldlen, uap->oldlenp, sizeof(oldlen));
		if (i) 
		    return i;
	}

	return (error);
}

/*
 * Attributes stored in the kernel.
 */
extern char hostname[MAXHOSTNAMELEN]; /* defined in bsd/kern/init_main.c */
extern int hostnamelen;
extern char domainname[MAXHOSTNAMELEN];
extern int domainnamelen;
extern char classichandler[32];
extern long classichandler_fsid;
extern long classichandler_fileid;

extern long hostid;
#ifdef INSECURE
int securelevel = -1;
#else
int securelevel;
#endif

static int
sysctl_affinity(name, namelen, oldBuf, oldSize, newBuf, newSize, cur_proc)
	int *name;
	u_int namelen;
	char *oldBuf;
	size_t *oldSize;
	char *newBuf;
	size_t newSize;
	struct proc *cur_proc;
{
	if (namelen < 1)
		return (EOPNOTSUPP);

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
	return (EOPNOTSUPP);
}

static int
sysctl_classic(name, namelen, oldBuf, oldSize, newBuf, newSize, cur_proc)
	int *name;
	u_int namelen;
	char *oldBuf;
	size_t *oldSize;
	char *newBuf;
	size_t newSize;
	struct proc *cur_proc;
{
	int newVal;
	int err;
	struct proc *p;

	if (namelen != 1)
		return (EOPNOTSUPP);

	p = pfind(name[0]);
	if (p == NULL)
		return (EINVAL);

	if ((p->p_ucred->cr_uid != cur_proc->p_ucred->cr_uid) 
		&& suser(cur_proc->p_ucred, &cur_proc->p_acflag))
		return (EPERM);

	return sysctl_rdint(oldBuf, oldSize, newBuf,
		(p->p_flag & P_CLASSIC) ? 1 : 0);
}

static int
sysctl_classichandler(name, namelen, oldBuf, oldSize, newBuf, newSize, p)
	int *name;
	u_int namelen;
	char *oldBuf;
	size_t *oldSize;
	char *newBuf;
	size_t newSize;
	struct proc *p;
{
	int error;
	int len;
	struct nameidata nd;
	struct vattr vattr;
	char handler[sizeof(classichandler)];

	if ((error = suser(p->p_ucred, &p->p_acflag)))
		return (error);
	len = strlen(classichandler) + 1;
	if (oldBuf && *oldSize < len)
		return (ENOMEM);
	if (newBuf && newSize >= sizeof(classichandler))
		return (ENAMETOOLONG);
	*oldSize = len - 1;
	if (newBuf) {
		error = copyin(newBuf, handler, newSize);
		if (error)
			return (error);
		handler[newSize] = 0;

		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
				handler, p);
		error = namei(&nd);
		if (error)
			return (error);
		/* Check mount point */
		if ((nd.ni_vp->v_mount->mnt_flag & MNT_NOEXEC) ||
			(nd.ni_vp->v_type != VREG)) {
			vput(nd.ni_vp);
			return (EACCES);
		}
		error = VOP_GETATTR(nd.ni_vp, &vattr, p->p_ucred, p);
		if (error) {
			vput(nd.ni_vp);
			return (error);
		}
		classichandler_fsid = vattr.va_fsid;
		classichandler_fileid = vattr.va_fileid;
		vput(nd.ni_vp);
	}
	if (oldBuf) {
		error = copyout(classichandler, oldBuf, len);
		if (error)
			return (error);
	}
	if (newBuf) {
		strcpy(classichandler, handler);
	}
	return (error);
}


extern int get_kernel_symfile( struct proc *, char **);
extern int sysctl_dopanicinfo(int *, u_int, void *, size_t *,
			void *, size_t, struct proc *);

/*
 * kernel related system variables.
 */
int
kern_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	int error, level, inthostid;
	unsigned int oldval=0;
	char *str;
	extern char ostype[], osrelease[], version[];
	extern int netboot_root();

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
			|| name[0] == KERN_CLASSIC
			|| name[0] == KERN_PANICINFO)
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
		    newp == NULL)
			return (error);
		if (level < securelevel && p->p_pid != 1)
			return (EPERM);
		securelevel = level;
		return (0);
	case KERN_HOSTNAME:
		error = sysctl_string(oldp, oldlenp, newp, newlen,
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
		return (sysctl_rdstruct(oldp, oldlenp, newp, &boottime,
		    sizeof(struct timeval)));
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
	case KERN_NETBOOT:
		return (sysctl_rdint(oldp, oldlenp, newp, netboot_root()));
	case KERN_PANICINFO:
		return(sysctl_dopanicinfo(name + 1, namelen - 1, oldp, oldlenp,
			newp, newlen, p));
	case KERN_AFFINITY:
		return sysctl_affinity(name+1, namelen-1, oldp, oldlenp,
									newp, newlen, p);
	case KERN_CLASSIC:
		return sysctl_classic(name+1, namelen-1, oldp, oldlenp,
								newp, newlen, p);
	case KERN_CLASSICHANDLER:
		return sysctl_classichandler(name+1, namelen-1, oldp, oldlenp,
										newp, newlen, p);
	case KERN_AIOMAX:
		return( sysctl_aiomax( oldp, oldlenp, newp, newlen ) );
	case KERN_AIOPROCMAX:
		return( sysctl_aioprocmax( oldp, oldlenp, newp, newlen ) );
	case KERN_AIOTHREADS:
		return( sysctl_aiothreads( oldp, oldlenp, newp, newlen ) );
	default:
		return (EOPNOTSUPP);
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
debug_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	struct ctldebug *cdp;

	/* all sysctl names at this level are name and field */
	if (namelen != 2)
		return (ENOTDIR);		/* overloaded */
	cdp = debugvars[name[0]];
	if (cdp->debugname == 0)
		return (EOPNOTSUPP);
	switch (name[1]) {
	case CTL_DEBUG_NAME:
		return (sysctl_rdstring(oldp, oldlenp, newp, cdp->debugname));
	case CTL_DEBUG_VALUE:
		return (sysctl_int(oldp, oldlenp, newp, newlen, cdp->debugvar));
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}
#endif /* DEBUG */

/*
 * Validate parameters and get old / set new parameters
 * for an integer-valued sysctl function.
 */
int
sysctl_int(oldp, oldlenp, newp, newlen, valp)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	int *valp;
{
	int error = 0;

	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp && newlen != sizeof(int))
		return (EINVAL);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout(valp, oldp, sizeof(int));
	if (error == 0 && newp)
		error = copyin(newp, valp, sizeof(int));
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdint(oldp, oldlenp, newp, val)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	int val;
{
	int error = 0;

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
sysctl_quad(oldp, oldlenp, newp, newlen, valp)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	quad_t *valp;
{
	int error = 0;

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
 * for a string-valued sysctl function.
 */
int
sysctl_string(oldp, oldlenp, newp, newlen, str, maxlen)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	char *str;
	int maxlen;
{
	int len, error = 0;

	len = strlen(str) + 1;
	if (oldp && *oldlenp < len)
		return (ENOMEM);
	if (newp && newlen >= maxlen)
		return (EINVAL);
	*oldlenp = len -1; /* deal with NULL strings correctly */
	if (oldp) {
		error = copyout(str, oldp, len);
	}
	if (error == 0 && newp) {
		error = copyin(newp, str, newlen);
		str[newlen] = 0;
	}
	return (error);
}

/*
 * As above, but read-only.
 */
int
sysctl_rdstring(oldp, oldlenp, newp, str)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	char *str;
{
	int len, error = 0;

	len = strlen(str) + 1;
	if (oldp && *oldlenp < len)
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
sysctl_struct(oldp, oldlenp, newp, newlen, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	void *sp;
	int len;
{
	int error = 0;

	if (oldp && *oldlenp < len)
		return (ENOMEM);
	if (newp && newlen > len)
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
sysctl_rdstruct(oldp, oldlenp, newp, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp, *sp;
	int len;
{
	int error = 0;

	if (oldp && *oldlenp < len)
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
sysctl_file(where, sizep)
	char *where;
	size_t *sizep;
{
	int buflen, error;
	struct file *fp;
	char *start = where;

	buflen = *sizep;
	if (where == NULL) {
		/*
		 * overestimate by 10 files
		 */
		*sizep = sizeof(filehead) + (nfiles + 10) * sizeof(struct file);
		return (0);
	}

	/*
	 * first copyout filehead
	 */
	if (buflen < sizeof(filehead)) {
		*sizep = 0;
		return (0);
	}
	if (error = copyout((caddr_t)&filehead, where, sizeof(filehead)))
		return (error);
	buflen -= sizeof(filehead);
	where += sizeof(filehead);

	/*
	 * followed by an array of file structures
	 */
	for (fp = filehead.lh_first; fp != 0; fp = fp->f_list.le_next) {
		if (buflen < sizeof(struct file)) {
			*sizep = where - start;
			return (ENOMEM);
		}
		if (error = copyout((caddr_t)fp, where, sizeof (struct file)))
			return (error);
		buflen -= sizeof(struct file);
		where += sizeof(struct file);
	}
	*sizep = where - start;
	return (0);
}

/*
 * try over estimating by 5 procs
 */
#define KERN_PROCSLOP	(5 * sizeof (struct kinfo_proc))

int
sysctl_doproc(name, namelen, where, sizep)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
{
	register struct proc *p;
	register struct kinfo_proc *dp = (struct kinfo_proc *)where;
	register int needed = 0;
	int buflen = where != NULL ? *sizep : 0;
	int doingzomb;
	struct kinfo_proc kproc;
	int error = 0;

	if (namelen != 2 && !(namelen == 1 && name[0] == KERN_PROC_ALL))
		return (EINVAL);
	p = allproc.lh_first;
	doingzomb = 0;
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
				(p->p_ucred->cr_uid != (uid_t)name[1]))
				continue;
			break;

		case KERN_PROC_RUID:
			if ((p->p_ucred == NULL) ||
				(p->p_cred->p_ruid != (uid_t)name[1]))
				continue;
			break;
		}
		if (buflen >= sizeof(struct kinfo_proc)) {
			bzero(&kproc, sizeof(struct kinfo_proc));
			fill_proc(p, &kproc);
			if (error = copyout((caddr_t)&kproc, &dp->kp_proc,
			    sizeof(struct kinfo_proc)))
				return (error);
			dp++;
			buflen -= sizeof(struct kinfo_proc);
		}
		needed += sizeof(struct kinfo_proc);
	}
	if (doingzomb == 0) {
		p = zombproc.lh_first;
		doingzomb++;
		goto again;
	}
	if (where != NULL) {
		*sizep = (caddr_t)dp - where;
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
	if (p->p_cred) {
		ep->e_pcred = *p->p_cred;
		if (p->p_ucred)
			ep->e_ucred = *p->p_ucred;
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
	exp->user_stack  = p->user_stack ;
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
	exp->p_ru  = p->p_ru ;
}

static void
fill_proc(p, kp)
	register struct proc *p;
	register struct kinfo_proc *kp;
{
	fill_externproc(p, &kp->kp_proc);
	fill_eproc(p, &kp->kp_eproc);
}

int
kdebug_ops(name, namelen, where, sizep, p)
int *name;
u_int namelen;
char *where;
size_t *sizep;
struct proc *p;
{
	int size=*sizep;
	int ret=0;
	extern int kdbg_control(int *name, u_int namelen,
		char * where,size_t * sizep);

	if (ret = suser(p->p_ucred, &p->p_acflag))
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
		ret= EOPNOTSUPP;
		break;
	}
	return(ret);
}

int
pcsamples_ops(name, namelen, where, sizep, p)
int *name;
u_int namelen;
char *where;
size_t *sizep;
struct proc *p;
{
	int ret=0;
	extern int pcsamples_control(int *name, u_int namelen,
		char * where,size_t * sizep);

	if (ret = suser(p->p_ucred, &p->p_acflag))
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
		ret= EOPNOTSUPP;
		break;
	}
	return(ret);
}

/*
 * Return the top *sizep bytes of the user stack, or the entire area of the
 * user stack down through the saved exec_path, whichever is smaller.
 */
int
sysctl_procargs(name, namelen, where, sizep, cur_proc)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
	struct proc *cur_proc;
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 0);
}

static int
sysctl_procargs2(name, namelen, where, sizep, cur_proc)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
	struct proc *cur_proc;
{
	return sysctl_procargsx( name, namelen, where, sizep, cur_proc, 1);
}

static int
sysctl_procargsx(name, namelen, where, sizep, cur_proc, argc_yes)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
	struct proc *cur_proc;
	int argc_yes;
{
	register struct proc *p;
	register int needed = 0;
	int buflen = where != NULL ? *sizep : 0;
	int error = 0;
	struct vm_map *proc_map;
	struct task * task;
	vm_map_copy_t	tmp;
	vm_offset_t	arg_addr;
	vm_size_t	arg_size;
	caddr_t data;
	unsigned size;
	vm_offset_t	copy_start, copy_end;
	int		*ip;
	kern_return_t ret;
	int pid;

	if (argc_yes)
		buflen -= NBPW;		/* reserve first word to return argc */

	if ((buflen <= 0) || (buflen > ARG_MAX)) {
		return(EINVAL);
	}
	arg_size = buflen;

	/*
	 *	Lookup process by pid
	 */
	pid = name[0];

 restart:
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

	if ((p->p_ucred->cr_uid != cur_proc->p_ucred->cr_uid) 
		&& suser(cur_proc->p_ucred, &cur_proc->p_acflag))
		return (EINVAL);
	arg_addr = (vm_offset_t)(p->user_stack - arg_size);


	/*
	 *	Before we can block (any VM code), make another
	 *	reference to the map to keep it alive.  We do
	 *	that by getting a reference on the task itself.
	 */
	task = p->task;
	if (task == NULL)
		return(EINVAL);
	
	/*
	 * A regular task_reference call can block, causing the funnel
	 * to be dropped and allowing the proc/task to get freed.
	 * Instead, we issue a non-blocking attempt at the task reference,
	 * and look up the proc/task all over again if that fails.
	 */
	if (!task_reference_try(task)) {
		mutex_pause();
		goto restart;
	}

	ret = kmem_alloc(kernel_map, &copy_start, round_page_32(arg_size));
	if (ret != KERN_SUCCESS) {
		task_deallocate(task);
		return(ENOMEM);
	}

	proc_map = get_task_map(task);
	copy_end = round_page_32(copy_start + arg_size);

	if( vm_map_copyin(proc_map, trunc_page(arg_addr), round_page_32(arg_size), 
			FALSE, &tmp) != KERN_SUCCESS) {
			task_deallocate(task);
			kmem_free(kernel_map, copy_start,
					round_page_32(arg_size));
			return (EIO);
	}

	/*
	 *	Now that we've done the copyin from the process'
	 *	map, we can release the reference to it.
	 */
	task_deallocate(task);

	if( vm_map_copy_overwrite(kernel_map, copy_start, 
		tmp, FALSE) != KERN_SUCCESS) {
			kmem_free(kernel_map, copy_start,
					round_page_32(arg_size));
			return (EIO);
	}

	data = (caddr_t) (copy_end - arg_size);

	if (buflen > p->p_argslen) {
		data = &data[buflen - p->p_argslen];
		size = p->p_argslen;
	} else {
		size = buflen;
	}

	if (argc_yes) {
		/* Put processes argc as the first word in the copyout buffer */
		suword(where, p->p_argc);
		error = copyout(data, where + NBPW, size);
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

		if ( (! error) && (buflen > p->p_argslen) )
		{
			int binPath_sz;
			int extraSpaceNeeded, addThis;
			char * placeHere;
			char * str = (char *) data;
			unsigned int max_len = size;

			/* Some apps are really bad about messing up their stacks
			   So, we have to be extra careful about getting the length
			   of the executing binary.  If we encounter an error, we bail.
			*/

			/* Limit ourselves to PATH_MAX paths */
			if ( max_len > PATH_MAX ) max_len = PATH_MAX;

			binPath_sz = 0;

			while ( (binPath_sz < max_len-1) && (*str++ != 0) )
				binPath_sz++;

			if (binPath_sz < max_len-1) binPath_sz += 1;

			/* Pre-Flight the space requiremnts */

			/* Account for the padding that fills out binPath to the next word */
			binPath_sz += (binPath_sz & (NBPW-1)) ? (NBPW-(binPath_sz & (NBPW-1))) : 0;

			placeHere = where + size;

			/* Account for the bytes needed to keep placeHere word aligned */ 
			addThis = ((unsigned long)placeHere & (NBPW-1)) ? (NBPW-((unsigned long)placeHere & (NBPW-1))) : 0;

			/* Add up all the space that is needed */
			extraSpaceNeeded = binPath_sz + addThis + (4 * NBPW);

			/* is there is room to tack on argv[0]? */
			if ( (buflen & ~(NBPW-1)) >= ( p->p_argslen + extraSpaceNeeded ))
			{
				placeHere += addThis;
				suword(placeHere, 0);
				placeHere += NBPW;
				suword(placeHere, 0xBFFF0000);
				placeHere += NBPW;
				suword(placeHere, 0);
				placeHere += NBPW;
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

	if (where != NULL)
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
sysctl_aiomax( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
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
sysctl_aioprocmax( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
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
sysctl_aiothreads( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
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
sysctl_maxprocperuid( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
{
	int 	error = 0;
	int		new_value;

	if ( oldp != NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != NULL )
		error = copyout( &maxprocperuid, oldp, sizeof(int) );
	if ( error == 0 && newp != NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 && new_value <= maxproc && new_value > 0 )
			maxprocperuid = new_value;
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
sysctl_maxfilesperproc( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
{
	int 	error = 0;
	int		new_value;

	if ( oldp != NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != NULL )
		error = copyout( &maxfilesperproc, oldp, sizeof(int) );
	if ( error == 0 && newp != NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 && new_value < maxfiles && new_value > 0 )
			maxfilesperproc = new_value;
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
sysctl_maxproc( void *oldp, size_t *oldlenp, void *newp, size_t newlen )
{
	int 	error = 0;
	int	new_value;

	if ( oldp != NULL && *oldlenp < sizeof(int) )
		return (ENOMEM);
	if ( newp != NULL && newlen != sizeof(int) )
		return (EINVAL);
		
	*oldlenp = sizeof(int);
	if ( oldp != NULL )
		error = copyout( &maxproc, oldp, sizeof(int) );
	if ( error == 0 && newp != NULL ) {
		error = copyin( newp, &new_value, sizeof(int) );
		if ( error == 0 && new_value <= hard_maxproc && new_value > 0 )
			maxproc = new_value;
		else
			error = EINVAL;
	}
	return( error );
	
} /* sysctl_maxproc */
