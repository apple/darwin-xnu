/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
/*
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
 
#include <cputypes.h>

/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	from: @(#)kern_exec.c	8.1 (Berkeley) 6/10/93
 */
#include <machine/reg.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/vnode.h>		
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/acct.h>
#include <sys/exec.h>
#include <sys/kdebug.h>
#include <sys/signal.h>

#include <mach/vm_param.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_shared_memory_server.h>

#include <kern/thread.h>
#include <kern/task.h>

#include <kern/ast.h>
#include <kern/mach_loader.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <machine/vmparam.h>
#if KTRACE   
#include <sys/ktrace.h>
#endif

int	app_profile = 0;

extern vm_map_t bsd_pageable_map;

#define	ROUND_PTR(type, addr)	\
	(type *)( ( (unsigned)(addr) + 16 - 1) \
		  & ~(16 - 1) )

static int load_return_to_errno(load_return_t lrtn);
int execve(struct proc *p, struct execve_args *uap, register_t *retval);
static int execargs_alloc(vm_offset_t *addrp);
static int execargs_free(vm_offset_t addr);

int
execv(p, args, retval)
	struct proc *p;
	void *args;
	int *retval;
{
	((struct execve_args *)args)->envp = NULL;
	return (execve(p, args, retval));
}

/* ARGSUSED */
int
execve(p, uap, retval)
	register struct proc *p;
	register struct execve_args *uap;
	register_t *retval;
{
	register struct ucred *cred = p->p_ucred;
	register struct filedesc *fdp = p->p_fd;
	register nc;
	register char *cp;
	int na, ne, ucp, ap, cc;
	unsigned len;
	int indir;
	char *sharg;
	char *execnamep;
	struct vnode *vp;
	struct vattr vattr;
	struct vattr origvattr;
	vm_offset_t execargs;
	struct nameidata nd;
	struct ps_strings ps;
#define	SHSIZE	512
	char cfarg[SHSIZE];
	boolean_t		is_fat;
	kern_return_t		ret;
	struct mach_header	*mach_header;
	struct fat_header	*fat_header;
	struct fat_arch		fat_arch;
	load_return_t		lret;
	load_result_t		load_result;
	struct uthread		*uthread;
	vm_map_t old_map;
	vm_map_t map;
	int i;
	boolean_t		new_shared_regions = FALSE;
	union {
		/* #! and name of interpreter */
		char			ex_shell[SHSIZE];
		/* Mach-O executable */
		struct mach_header	mach_header;
		/* Fat executable */
		struct fat_header	fat_header;
		char	pad[512];
	} exdata;
	int resid, error;
	char *savedpath;
	int savedpathlen = 0;
	vm_offset_t *execargsp;
	char *cpnospace;
	task_t  task;
	task_t new_task;
	thread_act_t thr_act;
	int numthreads;
	int vfexec=0;
	unsigned long arch_offset =0;
	unsigned long arch_size = 0;
        char		*ws_cache_name = NULL;	/* used for pre-heat */

	task = current_task();
	thr_act = current_act();
	uthread = get_bsdthread_info(thr_act);

	if (uthread->uu_flag & P_VFORK) {
			vfexec = 1; /* Mark in exec */
	} else {
		if (task != kernel_task) { 
			numthreads = get_task_numacts(task);
			if (numthreads <= 0 )
				return(EINVAL);
			if (numthreads > 1) {
				return(EOPNOTSUPP);
			}
		}
	}

	error = execargs_alloc(&execargs);
	if (error)
		return(error);

	savedpath = execargs;

	/*
	 * To support new app package launching for Mac OS X, the dyld
	 * needs the first argument to execve() stored on the user stack.
	 * Copyin the "path" at the begining of the "execargs" buffer
	 * allocated above.
	 *
	 * We have to do this before namei() because in case of
	 * symbolic links, namei() would overwrite the original "path".
	 * In case the last symbolic link resolved was a relative pathname
	 * we would lose the original "path", which could be an
	 * absolute pathname. This might be unacceptable for dyld.
	 */
	/* XXX We could optimize to avoid copyinstr in the namei() */
	
	error = copyinstr(uap->fname, savedpath, MAXPATHLEN, &savedpathlen);
	if (error)
		return (error);
	/*
	 * copyinstr will put in savedpathlen, the count of
	 * characters (including NULL) in the path.
	 */

	if(app_profile != 0) {

		/* grab the name of the file out of its path */
		/* we will need this for lookup within the   */
		/* name file */
		ws_cache_name = savedpath + savedpathlen;
               	while (ws_cache_name[0] != '/') {
               		if(ws_cache_name == savedpath) {
               	        	ws_cache_name--;
               	         	break;
                      	}
               		ws_cache_name--;
               	}
               	ws_cache_name++;
	}
	
	/* Save the name aside for future use */
	execargsp = (vm_offset_t *)((char *)(execargs) + savedpathlen);
	
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | SAVENAME,
					UIO_USERSPACE, uap->fname, p);
	if ((error = namei(&nd)))
		goto bad1;
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_READ);

	if ((error = VOP_GETATTR(vp, &origvattr, p->p_ucred, p)))
		goto bad;

	/* Check mount point */
	if (vp->v_mount->mnt_flag & MNT_NOEXEC) {
		error = EACCES;
		goto bad;
	}

	indir = 0;
	if ((vp->v_mount->mnt_flag & MNT_NOSUID) || (p->p_flag & P_TRACED))
		origvattr.va_mode &= ~(VSUID | VSGID);
		
	*(&vattr) = *(&origvattr);

again:
	error = check_exec_access(p, vp, &vattr);
	if (error)
		goto bad;

	/*
	 * Read in first few bytes of file for segment sizes, magic number:
	 *	407 = plain executable
	 *	410 = RO text
	 *	413 = demand paged RO text
	 * Also an ASCII line beginning with #! is
	 * the file name of a ``shell'' and arguments may be prepended
	 * to the argument list if given here.
	 *
	 * SHELL NAMES ARE LIMITED IN LENGTH.
	 *
	 * ONLY ONE ARGUMENT MAY BE PASSED TO THE SHELL FROM
	 * THE ASCII LINE.
	 */

	exdata.ex_shell[0] = '\0';	/* for zero length files */

	error = vn_rdwr(UIO_READ, vp, (caddr_t)&exdata, sizeof (exdata), 0,
			UIO_SYSSPACE, IO_NODELOCKED, p->p_ucred, &resid, p);

	if (error)
		goto bad;

#ifndef lint
	if (resid > sizeof(exdata) - min(sizeof(exdata.mach_header),
					 sizeof(exdata.fat_header))
	    && exdata.ex_shell[0] != '#') {
		error = ENOEXEC;
		goto bad;
	}
#endif /* lint */
	mach_header = &exdata.mach_header;
	fat_header = &exdata.fat_header;
	if (mach_header->magic == MH_MAGIC)
	    is_fat = FALSE;
	else if (fat_header->magic == FAT_MAGIC ||
		 fat_header->magic == FAT_CIGAM)
	    is_fat = TRUE;
	else if (mach_header->magic == MH_CIGAM) {
	    error = EBADARCH;
	    goto bad;
	} else {
		if (exdata.ex_shell[0] != '#' ||
		    exdata.ex_shell[1] != '!' ||
		    indir) {
			error = ENOEXEC;
			goto bad;
		}
		cp = &exdata.ex_shell[2];		/* skip "#!" */
		while (cp < &exdata.ex_shell[SHSIZE]) {
			if (*cp == '\t')
				*cp = ' ';
			else if (*cp == '\n') {
				*cp = '\0';
				break;
			}
			cp++;
		}
		if (*cp != '\0') {
			error = ENOEXEC;
			goto bad;
		}
		cp = &exdata.ex_shell[2];
		while (*cp == ' ')
			cp++;
		execnamep = cp;
		while (*cp && *cp != ' ')
			cp++;
		cfarg[0] = '\0';
		cpnospace = cp;
		if (*cp) {
			*cp++ = '\0';
			while (*cp == ' ')
				cp++;
			if (*cp)
				bcopy((caddr_t)cp, (caddr_t)cfarg, SHSIZE);
		}

		/*
		 * Support for new app package launching for Mac OS X.
		 * We are about to retry the execve() by changing the path to the
		 * interpreter name. Need to re-initialize the savedpath and
		 * savedpathlen. +1 for NULL.
		 */
		savedpathlen = (cpnospace - execnamep + 1);
		error = copystr(execnamep, savedpath, savedpathlen, &savedpathlen);
		if (error)
			goto bad;

		/* Save the name aside for future use */
		execargsp = (vm_offset_t *)((char *)(execargs) + savedpathlen);

		indir = 1;
		vput(vp);
		nd.ni_cnd.cn_nameiop = LOOKUP;
		nd.ni_cnd.cn_flags = (nd.ni_cnd.cn_flags & HASBUF) |
						(FOLLOW | LOCKLEAF | SAVENAME);
		nd.ni_segflg = UIO_SYSSPACE;
		nd.ni_dirp = execnamep;
		if ((error = namei(&nd)))
			goto bad1;
		vp = nd.ni_vp;
		VOP_LEASE(vp, p, cred, LEASE_READ);
		if ((error = VOP_GETATTR(vp, &vattr, p->p_ucred, p)))
			goto bad;
		goto again;
	}

	/*
	 * Collect arguments on "file" in swap space.
	 */
	na = 0;
	ne = 0;
	nc = 0;
	cc = 0;
	/*
	 * Support for new app package launching for Mac OS X allocates
	 * the "path" at the begining.
	 * execargs get allocated after that
	 */
	cp = (char *) execargsp;	/* running pointer for copy */
	/*
	 * size of execargs less sizeof "path",
	 * a pointer to "path" and a NULL poiter
	 */
	cc = NCARGS - savedpathlen - 2*NBPW;
	/*
	 * Copy arguments into file in argdev area.
	 */
	if (uap->argp) for (;;) {
		ap = NULL;
		sharg = NULL;
		if (indir && na == 0) {
			sharg = nd.ni_cnd.cn_nameptr;
			ap = (int)sharg;
			uap->argp++;		/* ignore argv[0] */
		} else if (indir && (na == 1 && cfarg[0])) {
			sharg = cfarg;
			ap = (int)sharg;
		} else if (indir && (na == 1 || (na == 2 && cfarg[0])))
			ap = (int)uap->fname;
		else if (uap->argp) {
			ap = fuword((caddr_t)uap->argp);
			uap->argp++;
		}
		if (ap == NULL && uap->envp) {
			uap->argp = NULL;
			if ((ap = fuword((caddr_t)uap->envp)) != NULL)
				uap->envp++, ne++;
		}
		if (ap == NULL)
			break;
		na++;
		if (ap == -1) {
			error = EFAULT;
			break;
		}
		do {
			if (nc >= (NCARGS - savedpathlen - 2*NBPW -1)) {
				error = E2BIG;
				break;
			}
			if (sharg) {
				error = copystr(sharg, cp, (unsigned)cc, &len);
				sharg += len;
			} else {
				error = copyinstr((caddr_t)ap, cp, (unsigned)cc,
				    &len);
				ap += len;
			}
			cp += len;
			nc += len;
			cc -= len;
		} while (error == ENAMETOOLONG);
		if (error) {
			goto bad;
		}
	}
	nc = (nc + NBPW-1) & ~(NBPW-1);

	/*
	 * If we have a fat file, find "our" executable.
	 */
	if (is_fat) {
		/*
		 * Look up our architecture in the fat file.
		 */
		lret = fatfile_getarch(vp, (vm_offset_t)fat_header, &fat_arch);
		if (lret != LOAD_SUCCESS) {
			error = load_return_to_errno(lret);
			goto bad;
		}
		/* Read the Mach-O header out of it */
		error = vn_rdwr(UIO_READ, vp, (caddr_t)&exdata.mach_header,
				sizeof (exdata.mach_header),
				fat_arch.offset,
				UIO_SYSSPACE, (IO_UNIT|IO_NODELOCKED), cred, &resid, p);

		if (error) {
			goto bad;
		}

		/* Did we read a complete header? */
		if (resid) {
			error = EBADEXEC;
			goto bad;
		}

		/* Is what we found a Mach-O executable */
		if (mach_header->magic != MH_MAGIC) {
			error = ENOEXEC;
			goto bad;
		}

		arch_offset = fat_arch.offset;
		arch_size = fat_arch.size;
	} else {
		/*
		 *	Load the Mach-O file.
		 */
		arch_offset = 0;
		arch_size = (u_long)vattr.va_size;
	}

	if (vfexec) {
 		kern_return_t	result;

		result = task_create_local(task, FALSE, FALSE, &new_task);
		if (result != KERN_SUCCESS)
	    	printf("execve: task_create failed. Code: 0x%x\n", result);
		p->task = new_task;
		set_bsdtask_info(new_task, p);
		if (p->p_nice != 0)
			resetpriority(p);
		task = new_task;
		map = get_task_map(new_task);
		result = thread_create(new_task, &thr_act);
		if (result != KERN_SUCCESS)
	    	printf("execve: thread_create failed. Code: 0x%x\n", result);
		uthread = get_bsdthread_info(thr_act);
	} else {
		map = VM_MAP_NULL;

	}

	/*
	 *	Load the Mach-O file.
	 */
	VOP_UNLOCK(vp, 0, p);
	if(ws_cache_name) {
		tws_handle_startup_file(task, cred->cr_uid, 
			ws_cache_name, vp, &new_shared_regions);
	}
	if (new_shared_regions) {
		shared_region_mapping_t	new_shared_region;
		shared_region_mapping_t	old_shared_region;
	
		if (shared_file_create_system_region(&new_shared_region))
			panic("couldn't create system_shared_region\n");

		vm_get_shared_region(task, &old_shared_region);
		vm_set_shared_region(task, new_shared_region);

		shared_region_mapping_dealloc(old_shared_region);
	}

	lret = load_machfile(vp, mach_header, arch_offset,
				arch_size, &load_result, thr_act, map);

	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto badtoolate;
	}

	/* load_machfile() maps the vnode */
	ubc_map(vp);

	/*
	 * deal with set[ug]id.
	 */
	p->p_flag &= ~P_SUGID;
	if (((origvattr.va_mode & VSUID) != 0 &&
	    p->p_ucred->cr_uid != origvattr.va_uid)
	    || (origvattr.va_mode & VSGID) != 0 &&
	    p->p_ucred->cr_gid != origvattr.va_gid) {
		p->p_ucred = crcopy(cred);
#if KTRACE
		/*
		 * If process is being ktraced, turn off - unless
		 * root set it.
		 */
		if (p->p_tracep && !(p->p_traceflag & KTRFAC_ROOT)) {
			struct vnode *tvp = p->p_tracep;
			p->p_tracep = NULL;
			p->p_traceflag = 0;
			vrele(tvp);
		}
#endif
		if (origvattr.va_mode & VSUID)
			p->p_ucred->cr_uid = origvattr.va_uid;
		if (origvattr.va_mode & VSGID)
			p->p_ucred->cr_gid = origvattr.va_gid;

		set_security_token(p);
		p->p_flag |= P_SUGID;

		/* Radar 2261856; setuid security hole fix */
		/* Patch from OpenBSD: A. Ramesh */
		/*
		 * XXX For setuid processes, attempt to ensure that
		 * stdin, stdout, and stderr are already allocated.
		 * We do not want userland to accidentally allocate
		 * descriptors in this range which has implied meaning
		 * to libc.
		 */
		for (i = 0; i < 3; i++) {
			extern struct fileops vnops;
			struct nameidata nd1;
			struct file *fp;
			int indx;

			if (p->p_fd->fd_ofiles[i] == NULL) {
				if ((error = falloc(p, &fp, &indx)) != 0)
					continue;
				NDINIT(&nd1, LOOKUP, FOLLOW, UIO_SYSSPACE,
				    "/dev/null", p);
				if ((error = vn_open(&nd1, FREAD, 0)) != 0) {
					ffree(fp);
					p->p_fd->fd_ofiles[indx] = NULL;
					break;
				}
				fp->f_flag = FREAD;
				fp->f_type = DTYPE_VNODE;
				fp->f_ops = &vnops;
				fp->f_data = (caddr_t)nd1.ni_vp;
				VOP_UNLOCK(nd1.ni_vp, 0, p);
			}
		}
	}
	p->p_cred->p_svuid = p->p_ucred->cr_uid;
	p->p_cred->p_svgid = p->p_ucred->cr_gid;

	if (!vfexec && (p->p_flag & P_TRACED))
		psignal(p, SIGTRAP);

	if (error) {
		goto badtoolate;
	}
	VOP_LOCK(vp,  LK_EXCLUSIVE | LK_RETRY, p);
	vput(vp);
	vp = NULL;
	
	if (load_result.unixproc &&
		create_unix_stack(get_task_map(task),
				  load_result.user_stack, load_result.customstack, p)) {
		error = load_return_to_errno(LOAD_NOSPACE);
		goto badtoolate;
	}

	if (vfexec) {
		uthread->uu_ar0 = (void *)get_user_regs(thr_act);
	}

	/*
	 * Copy back arglist if necessary.
	 */


	ucp = p->user_stack;
	if (vfexec) {
		old_map = vm_map_switch(get_task_map(task));
	}
	if (load_result.unixproc) {
		int pathptr;
		
		ucp = ucp - nc - NBPW;	/* begining of the STRING AREA */

		/*
		 * Support for new app package launching for Mac OS X allocates
		 * the "path" at the begining of the execargs buffer.
		 * copy it just before the string area.
		 */
		savedpathlen = (savedpathlen + NBPW-1) & ~(NBPW-1);
		len = 0;
		pathptr = ucp - savedpathlen;
		error = copyoutstr(savedpath, (caddr_t)pathptr,
					(unsigned)savedpathlen, &len);
		if (error) {
			if (vfexec)
				vm_map_switch(old_map);
			goto badtoolate;
		}
		
		/* Save a NULL pointer below it */
		(void) suword((caddr_t)(pathptr - NBPW), 0);

		/* Save the pointer to "path" just below it */
		(void) suword((caddr_t)(pathptr - 2*NBPW), pathptr);

		/*
		 * na includes arg[] and env[].
		 * NBPW for 2 NULL one each ofter arg[argc -1] and env[n]
		 * NBPW for argc
		 * skip over saved path, NBPW for pointer to path,
		 * and NBPW for the NULL after pointer to path.
		 */
		ap = ucp - na*NBPW - 3*NBPW - savedpathlen - 2*NBPW;
#if defined(ppc)
		thread_setuserstack(thr_act, ap);	/* Set the stack */
#else
		uthread->uu_ar0[SP] = ap;
#endif
		(void) suword((caddr_t)ap, na-ne); /* argc */
		nc = 0;
		cc = 0;

		cp = (char *) execargsp;
		cc = NCARGS - savedpathlen - 2*NBPW;
		ps.ps_argvstr = (char *)ucp;	/* first argv string */
		ps.ps_nargvstr = na - ne;		/* argc */
		for (;;) {
			ap += NBPW;
			if (na == ne) {
				(void) suword((caddr_t)ap, 0);
				ap += NBPW;
				ps.ps_envstr = (char *)ucp;
				ps.ps_nenvstr = ne;
			}
			if (--na < 0)
				break;
			(void) suword((caddr_t)ap, ucp);
			do {
				error = copyoutstr(cp, (caddr_t)ucp,
						   (unsigned)cc, &len);
				ucp += len;
				cp += len;
				nc += len;
				cc -= len;
			} while (error == ENAMETOOLONG);
			if (error == EFAULT)
				break;	/* bad stack - user's problem */
		}
		(void) suword((caddr_t)ap, 0);
	}
	
	if (load_result.dynlinker) {
#if defined(ppc)
		ap = thread_adjuserstack(thr_act, -4);	/* Adjust the stack */
#else
		ap = uthread->uu_ar0[SP] -= 4;
#endif
		(void) suword((caddr_t)ap, load_result.mach_header);
	}

	if (vfexec) {
		vm_map_switch(old_map);
	}
#if defined(ppc)
	thread_setentrypoint(thr_act, load_result.entry_point);	/* Set the entry point */
#elif defined(i386) 
 	uthread->uu_ar0[PC] = load_result.entry_point;
#else
#error architecture not implemented!
#endif	

	/* Stop profiling */
	stopprofclock(p);

	/*
	 * Reset signal state.
	 */
	execsigs(p, thr_act);

	/*
	 * Close file descriptors
	 * which specify close-on-exec.
	 */
	fdexec(p);
	/* FIXME: Till vmspace inherit is fixed: */
	if (!vfexec && p->vm_shm)
		shmexit(p);
	/* Clean up the semaphores */
	semexit(p);

	/*
	 * Remember file name for accounting.
	 */
	p->p_acflag &= ~AFORK;
	if (nd.ni_cnd.cn_namelen > MAXCOMLEN)
		nd.ni_cnd.cn_namelen = MAXCOMLEN;
	bcopy((caddr_t)nd.ni_cnd.cn_nameptr, (caddr_t)p->p_comm,
	    (unsigned)nd.ni_cnd.cn_namelen);
	p->p_comm[nd.ni_cnd.cn_namelen] = '\0';

	{
	  /* This is for kdebug */
	  long dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

	  /* Collect the pathname for tracing */
	  kdbg_trace_string(p, &dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

	  if (vfexec)
	          KERNEL_DEBUG_CONSTANT1((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, getshuttle_thread(thr_act));
	  else
	          KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
	}

	/*
	 * mark as execed, wakeup the process that vforked (if any) and tell
	 * it that it now has it's own resources back
	 */
	p->p_flag |= P_EXEC;
	if (p->p_pptr && (p->p_flag & P_PPWAIT)) {
		p->p_flag &= ~P_PPWAIT;
		wakeup((caddr_t)p->p_pptr);
	}

	if (vfexec && (p->p_flag & P_TRACED)) {
			psignal_vfork(p, new_task, thr_act, SIGTRAP);
	}

badtoolate:
	if (vfexec) {
		task_deallocate(new_task);
		act_deallocate(thr_act);
		if (error)
			error = 0;
	}
bad:
	FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
	if (vp)
		vput(vp);
bad1:
	if (execargs)
		execargs_free(execargs);
	if (!error && vfexec) {
			vfork_return(current_act(), p->p_pptr, p, retval);
			(void) thread_resume(thr_act);
			return(0);
	}
	return(error);
}


#define	unix_stack_size(p)	(p->p_rlimit[RLIMIT_STACK].rlim_cur)

kern_return_t
create_unix_stack(map, user_stack, customstack, p)
	vm_map_t	map;
	vm_offset_t	user_stack;
	int			customstack;
	struct proc	*p;
{
	vm_size_t	size;
	vm_offset_t	addr;

	p->user_stack = user_stack;
	if (!customstack) {
		size = round_page(unix_stack_size(p));
		addr = trunc_page(user_stack - size);
		return (vm_allocate(map,&addr, size, FALSE));
	} else
		return(KERN_SUCCESS);
}

#include <sys/reboot.h>

char		init_program_name[128] = "/sbin/mach_init\0";

char		init_args[128] = "";

struct execve_args	init_exec_args;
int		init_attempts = 0;


void
load_init_program(p)
	struct proc *p;
{
	vm_offset_t	init_addr;
	int		*old_ap;
	char		*argv[3];
	int		error;
	register_t retval[2];
	struct uthread * ut;

	error = 0;

	/* init_args are copied in string form directly from bootstrap */
	
	do {
		if (boothowto & RB_INITNAME) {
			printf("init program? ");
#if FIXME  /* [ */
			gets(init_program_name, init_program_name);
#endif  /* FIXME ] */
		}

		if (error && ((boothowto & RB_INITNAME) == 0) &&
					(init_attempts == 1)) {
			static char other_init[] = "/etc/mach_init";
			printf("Load of %s, errno %d, trying %s\n",
				init_program_name, error, other_init);
			error = 0;
			bcopy(other_init, init_program_name,
							sizeof(other_init));
		}

		init_attempts++;

		if (error) {
			printf("Load of %s failed, errno %d\n",
					init_program_name, error);
			error = 0;
			boothowto |= RB_INITNAME;
			continue;
		}

		/*
		 *	Copy out program name.
		 */

		init_addr = VM_MIN_ADDRESS;
		(void) vm_allocate(current_map(), &init_addr,
				   PAGE_SIZE, TRUE);
		if (init_addr == 0)
			init_addr++;
		(void) copyout((caddr_t) init_program_name,
				(caddr_t) (init_addr),
				(unsigned) sizeof(init_program_name)+1);

		argv[0] = (char *) init_addr;
		init_addr += sizeof(init_program_name);
		init_addr = (vm_offset_t)ROUND_PTR(char, init_addr);

		/*
		 *	Put out first (and only) argument, similarly.
		 *	Assumes everything fits in a page as allocated
		 *	above.
		 */

		(void) copyout((caddr_t) init_args,
				(caddr_t) (init_addr),
				(unsigned) sizeof(init_args));

		argv[1] = (char *) init_addr;
		init_addr += sizeof(init_args);
		init_addr = (vm_offset_t)ROUND_PTR(char, init_addr);

		/*
		 *	Null-end the argument list
		 */

		argv[2] = (char *) 0;
		
		/*
		 *	Copy out the argument list.
		 */
		
		(void) copyout((caddr_t) argv,
				(caddr_t) (init_addr),
				(unsigned) sizeof(argv));

		/*
		 *	Set up argument block for fake call to execve.
		 */

		init_exec_args.fname = argv[0];
		init_exec_args.argp = (char **) init_addr;
		init_exec_args.envp = 0;
		
		/* So that mach_init task 
		 * is set with uid,gid 0 token 
		 */
		set_security_token(p);

		error = execve(p,&init_exec_args,retval);
	} while (error);
}

/*
 * Convert a load_return_t to an errno.
 */
static int 
load_return_to_errno(load_return_t lrtn)
{
	switch (lrtn) {
	    case LOAD_SUCCESS:
		return 0;
	    case LOAD_BADARCH:
	    	return EBADARCH;
	    case LOAD_BADMACHO:
	    	return EBADMACHO;
	    case LOAD_SHLIB:
	    	return ESHLIBVERS;
	    case LOAD_NOSPACE:
	    	return ENOMEM;
	    case LOAD_PROTECT:
	    	return EACCES;
	    case LOAD_RESOURCE:
	    case LOAD_FAILURE:
	    default:
	    	return EBADEXEC;
	}
}

/*
 * exec_check_access()
 */
int
check_exec_access(p, vp, vap)
	struct proc  *p;
	struct vnode *vp;
	struct vattr *vap;
{
	int flag;
	int error;

	if (error = VOP_ACCESS(vp, VEXEC, p->p_ucred, p))
		return (error);
	flag = p->p_flag;
	if (flag & P_TRACED) {
		if (error = VOP_ACCESS(vp, VREAD, p->p_ucred, p))
			return (error);
	}
	if (vp->v_type != VREG ||
	    (vap->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
		return (EACCES);
	return (0);
}

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

extern semaphore_t execve_semaphore;

static int
execargs_alloc(addrp)
	vm_offset_t	*addrp;
{
	kern_return_t kret;

	kret = semaphore_wait(execve_semaphore);
	if (kret != KERN_SUCCESS)
		switch (kret) {
		default:
			return (EINVAL);
		case KERN_INVALID_ADDRESS:
		case KERN_PROTECTION_FAILURE:
			return (EACCES);
		case KERN_ABORTED:
		case KERN_OPERATION_TIMED_OUT:
			return (EINTR);
		}

	kret = kmem_alloc_pageable(bsd_pageable_map, addrp, NCARGS);
	if (kret != KERN_SUCCESS)
		return (ENOMEM);

	return (0);
}

static int
execargs_free(addr)
	vm_offset_t	addr;
{
	kern_return_t kret;

	kmem_free(bsd_pageable_map, addr, NCARGS);

	kret = semaphore_signal(execve_semaphore);
	switch (kret) { 
	case KERN_INVALID_ADDRESS:
	case KERN_PROTECTION_FAILURE:
		return (EINVAL);
	case KERN_ABORTED:
	case KERN_OPERATION_TIMED_OUT:
		return (EINTR);
	case KERN_SUCCESS:
		return(0);
	default:
		return (EINVAL);
	}
}

