/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
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
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>		
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/uio_internal.h>
#include <sys/acct.h>
#include <sys/exec.h>
#include <sys/kdebug.h>
#include <sys/signal.h>
#include <sys/aio_kern.h>
#include <sys/sysproto.h>
#include <sys/shm_internal.h>		/* shmexec() */
#include <sys/ubc_internal.h>		/* ubc_map() */

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pager.h>
#include <vm/vm_kern.h>
#include <vm/task_working_set.h>
#include <vm/vm_shared_memory_server.h>

/*
 * Mach things for which prototypes are unavailable from Mach headers
 */
void		ipc_task_reset(
			task_t		task);

extern struct savearea *get_user_regs(thread_t);


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
#include <sys/imgact.h>


/*
 * SIZE_MAXPTR		The maximum size of a user space pointer, in bytes
 * SIZE_IMG_STRSPACE	The available string space, minus two pointers; we
 *			define it interms of the maximum, since we don't
 *			know the pointer size going in, until after we've
 *			parsed the executable image.
 */
#define	SIZE_MAXPTR		8				/* 64 bits */
#define	SIZE_IMG_STRSPACE	(NCARGS - 2 * SIZE_MAXPTR)

int	app_profile = 0;

extern vm_map_t bsd_pageable_map;
extern struct fileops vnops;

#define	ROUND_PTR(type, addr)	\
	(type *)( ( (unsigned)(addr) + 16 - 1) \
		  & ~(16 - 1) )

struct image_params;	/* Forward */
static int exec_copyout_strings(struct image_params *imgp, user_addr_t *stackp);
static int load_return_to_errno(load_return_t lrtn);
static int execargs_alloc(struct image_params *imgp);
static int execargs_free(struct image_params *imgp);
static int exec_check_permissions(struct image_params *imgp);
static int exec_extract_strings(struct image_params *imgp);
static int exec_handle_sugid(struct image_params *imgp);
static int sugid_scripts = 0;
SYSCTL_INT (_kern, OID_AUTO, sugid_scripts, CTLFLAG_RW, &sugid_scripts, 0, "");
static kern_return_t create_unix_stack(vm_map_t map, user_addr_t user_stack,
					int customstack, struct proc *p);
static int copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size);

/* XXX forward; should be in headers, but can't be for one reason or another */
extern int grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype);
extern void vfork_return(thread_t th_act,
				struct proc * p,
				struct proc *p2,
				register_t *retval);


extern char classichandler[32];
extern uint32_t classichandler_fsid;
extern long classichandler_fileid;


/*
 * exec_add_string
 *
 * Add the requested string to the string space area.
 *
 * Parameters;	struct image_params *		image parameter block
 *		user_addr_t			string to add to strings area
 *		uio_seg				segment where string is located
 *
 * Returns:	0			Success
 *		!0			Failure errno from copyinstr()
 *
 * Implicit returns:
 *		(imgp->ip_strendp)	updated location of next add, if any
 *		(imgp->ip_strspace)	updated byte count of space remaining
 */
static int
exec_add_string(struct image_params *imgp, user_addr_t str, /*uio_seg*/int seg)
{
        int error = 0;

        do {
                size_t len = 0;
		if (imgp->ip_strspace <= 0) {
			error = E2BIG;
			break;
		}
		if (IS_UIO_SYS_SPACE(seg)) {
			char *kstr = CAST_DOWN(char *,str);	/* SAFE */
			error = copystr(kstr, imgp->ip_strendp, imgp->ip_strspace, &len);
		} else  {
			error = copyinstr(str, imgp->ip_strendp, imgp->ip_strspace,
			    &len);
		}
		imgp->ip_strendp += len;
		imgp->ip_strspace -= len;
	} while (error == ENAMETOOLONG);

	return error;
}

/*
 * exec_save_path
 *
 * To support new app package launching for Mac OS X, the dyld needs the
 * first argument to execve() stored on the user stack.
 *
 * Save the executable path name at the top of the strings area and set
 * the argument vector pointer to the location following that to indicate
 * the start of the argument and environment tuples, setting the remaining
 * string space count to the size of the string area minus the path length
 * and a reserve for two pointers.
 *
 * Parameters;	struct image_params *		image parameter block
 *		char *				path used to invoke program
 *		uio_seg				segment where path is located
 *
 * Returns:	int			0	Success
 *					!0	Failure: error number
 * Implicit returns:
 *		(imgp->ip_strings)		saved path
 *		(imgp->ip_strspace)		space remaining in ip_strings
 *		(imgp->ip_argv)			beginning of argument list
 *		(imgp->ip_strendp)		start of remaining copy area
 *
 * Note:	We have to do this before the initial namei() since in the
 *		path contains symbolic links, namei() will overwrite the
 *		original path buffer contents.  If the last symbolic link
 *		resolved was a relative pathname, we would lose the original
 *		"path", which could be an absolute pathname. This might be
 *		unacceptable for dyld.
 */
static int
exec_save_path(struct image_params *imgp, user_addr_t path, /*uio_seg*/int seg)
{
	int error;
	size_t	len;
	char *kpath = CAST_DOWN(char *,path);	/* SAFE */

	imgp->ip_strendp = imgp->ip_strings;
	imgp->ip_strspace = SIZE_IMG_STRSPACE;

	len = MIN(MAXPATHLEN, imgp->ip_strspace);

	switch( seg) {
	case UIO_USERSPACE32:
	case UIO_USERSPACE64:	/* Same for copyin()... */
		error = copyinstr(path, imgp->ip_strings, len, &len);
		break;
	case UIO_SYSSPACE32:
		error = copystr(kpath, imgp->ip_strings, len, &len);
		break;
	default:
		error = EFAULT;
		break;
	}

	if (!error) {
		imgp->ip_strendp += len;
		imgp->ip_strspace -= len;
		imgp->ip_argv = imgp->ip_strendp;
	}

	return(error);
}



/*
 * exec_shell_imgact
 *
 * Image activator for interpreter scripts.  If the image begins with the
 * characters "#!", then it is an interpreter script.  Verify that we are
 * not already executing in Classic mode, and that the length of the script
 * line indicating the interpreter is not in excess of the maximum allowed
 * size.  If this is the case, then break out the arguments, if any, which
 * are separated by white space, and copy them into the argument save area
 * as if they were provided on the command line before all other arguments.
 * The line ends when we encounter a comment character ('#') or newline.
 *
 * Parameters;	struct image_params *	image parameter block
 *
 * Returns:	-1			not an interpreter (keep looking)
 *		-3			Success: interpreter: relookup
 *		>0			Failure: interpreter: error number
 *
 * A return value other than -1 indicates subsequent image activators should
 * not be given the opportunity to attempt to activate the image.
 */
static int
exec_shell_imgact(struct image_params *imgp)
{
	char *vdata = imgp->ip_vdata;
	char *ihp;
	char *line_endp;
	char *interp;

	/*
	 * Make sure it's a shell script.  If we've already redirected
	 * from an interpreted file once, don't do it again.
	 *
	 * Note: We disallow Classic, since the expectation is that we
	 * may run a Classic interpreter, but not an interpret a Classic
	 * image.  This is consistent with historical behaviour.
	 */
	if (vdata[0] != '#' ||
	    vdata[1] != '!' ||
	    (imgp->ip_flags & IMGPF_INTERPRET) != 0) {
		return (-1);
	}


	imgp->ip_flags |= IMGPF_INTERPRET;

        /* Check to see if SUGID scripts are permitted.  If they aren't then
	 * clear the SUGID bits.
	 * imgp->ip_vattr is known to be valid.
         */
        if (sugid_scripts == 0) {
	   imgp->ip_origvattr->va_mode &= ~(VSUID | VSGID);
	}

	/* Find the nominal end of the interpreter line */
	for( ihp = &vdata[2]; *ihp != '\n' && *ihp != '#'; ihp++) {
		if (ihp >= &vdata[IMG_SHSIZE])
			return (ENOEXEC);
	}

	line_endp = ihp;
	ihp = &vdata[2];
	/* Skip over leading spaces - until the interpreter name */
	while ( ihp < line_endp && ((*ihp == ' ') || (*ihp == '\t')))
		ihp++;

	/*
	 * Find the last non-whitespace character before the end of line or
	 * the beginning of a comment; this is our new end of line.
	 */
	for (;line_endp > ihp && ((*line_endp == ' ') || (*line_endp == '\t')); line_endp--)
		continue;

	/* Empty? */
	if (line_endp == ihp)
		return (ENOEXEC);

	/* copy the interpreter name */
	interp = imgp->ip_interp_name;
	while ((ihp < line_endp) && (*ihp != ' ') && (*ihp != '\t'))
		*interp++ = *ihp++;
	*interp = '\0';

	exec_save_path(imgp, CAST_USER_ADDR_T(imgp->ip_interp_name),
							UIO_SYSSPACE32);

	ihp = &vdata[2];
	while (ihp < line_endp) {
		/* Skip leading whitespace before each argument */
		while ((*ihp == ' ') || (*ihp == '\t'))
			ihp++;

		if (ihp >= line_endp)
			break;

		/* We have an argument; copy it */
		while ((ihp < line_endp) && (*ihp != ' ') && (*ihp != '\t')) {  
			*imgp->ip_strendp++ = *ihp++;
			imgp->ip_strspace--;
		}
		*imgp->ip_strendp++ = 0;
		imgp->ip_strspace--;
		imgp->ip_argc++;
	}

	return (-3);
}



/*
 * exec_fat_imgact
 *
 * Image activator for fat 1.0 binaries.  If the binary is fat, then we
 * need to select an image from it internally, and make that the image
 * we are going to attempt to execute.  At present, this consists of
 * reloading the first page for the image with a first page from the
 * offset location indicated by the fat header.
 *
 * Important:	This image activator is byte order neutral.
 *
 * Note:	If we find an encapsulated binary, we make no assertions
 *		about its  validity; instead, we leave that up to a rescan
 *		for an activator to claim it, and, if it is claimed by one,
 *		that activator is responsible for determining validity.
 */
static int
exec_fat_imgact(struct image_params *imgp)
{
	struct proc *p = vfs_context_proc(imgp->ip_vfs_context);
	kauth_cred_t cred = p->p_ucred;
	struct fat_header *fat_header = (struct fat_header *)imgp->ip_vdata;
	struct fat_arch fat_arch;
	int resid, error;
	load_return_t lret;

	/* Make sure it's a fat binary */
	if ((fat_header->magic != FAT_MAGIC) &&
            (fat_header->magic != FAT_CIGAM)) {
	    	error = -1;
		goto bad;
	}

	/* Look up our preferred architecture in the fat file. */
	lret = fatfile_getarch_affinity(imgp->ip_vp,
					(vm_offset_t)fat_header,
					&fat_arch,
					(p->p_flag & P_AFFINITY));
	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto bad;
	}

	/* Read the Mach-O header out of it */
	error = vn_rdwr(UIO_READ, imgp->ip_vp, imgp->ip_vdata,
			PAGE_SIZE, fat_arch.offset,
			UIO_SYSSPACE32, (IO_UNIT|IO_NODELOCKED),
			cred, &resid, p);
	if (error) {
		goto bad;
	}

	/* Did we read a complete header? */
	if (resid) {
		error = EBADEXEC;
		goto bad;
	}

	/* Success.  Indicate we have identified an encapsulated binary */
	error = -2;
	imgp->ip_arch_offset = (user_size_t)fat_arch.offset;
	imgp->ip_arch_size = (user_size_t)fat_arch.size;

bad:
	return (error);
}

/*
 * exec_mach_imgact
 *
 * Image activator for mach-o 1.0 binaries.
 *
 * Important:	This image activator is NOT byte order neutral.
 */
static int
exec_mach_imgact(struct image_params *imgp)
{
	struct mach_header *mach_header = (struct mach_header *)imgp->ip_vdata;
	kauth_cred_t		cred = vfs_context_ucred(imgp->ip_vfs_context);
	struct proc		*p = vfs_context_proc(imgp->ip_vfs_context);
	int			error = 0;
	int			vfexec = 0;
	task_t			task;
	task_t			new_task;
	thread_t		thread;
	struct uthread		*uthread;
	vm_map_t old_map = VM_MAP_NULL;
	vm_map_t map;
	boolean_t				clean_regions = FALSE;
    shared_region_mapping_t initial_region = NULL;
	load_return_t		lret;
	load_result_t		load_result;
		
	/*
	 * make sure it's a Mach-O 1.0 or Mach-O 2.0 binary; the difference
	 * is a reserved field on the end, so for the most part, we can
	 * treat them as if they were identical.
	 */
	if ((mach_header->magic != MH_MAGIC) &&
	    (mach_header->magic != MH_MAGIC_64)) {
	error = -1;
		goto bad;
	}

	task = current_task();
	thread = current_thread();
	uthread = get_bsdthread_info(thread);

	if (uthread->uu_flag & UT_VFORK)
		vfexec = 1;	 /* Mark in exec */

	if ((mach_header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64)
		imgp->ip_flags |= IMGPF_IS_64BIT;

	if (!grade_binary(mach_header->cputype, mach_header->cpusubtype)) {
		error = EBADARCH;
		goto bad;
	}

	/*
	 * Copy in arguments/environment from the old process, if the
	 * vector is non-NULL (i.e. exec is not being called from
	 * load_init_program(), as a special case, at system startup).
	 */
	if (imgp->ip_user_argv != 0LL) {
		error = exec_extract_strings(imgp);
		if (error)
			goto bad;
	}

	/*
	 * Hack for binary compatability; put three NULs on the end of the
	 * string area, and round it up to the next word boundary.  This
	 * ensures padding with NULs to the boundary.
	 */
	imgp->ip_strendp[0] = 0;
	imgp->ip_strendp[1] = 0;
	imgp->ip_strendp[2] = 0;
	imgp->ip_strendp += (((imgp->ip_strendp - imgp->ip_strings) + NBPW-1) & ~(NBPW-1));


	if (vfexec) {
 		kern_return_t	result;

		result = task_create_internal(task, FALSE, &new_task);
		if (result != KERN_SUCCESS)
	    	printf("execve: task_create failed. Code: 0x%x\n", result);
		p->task = new_task;
		set_bsdtask_info(new_task, p);
		if (p->p_nice != 0)
			resetpriority(p);
		map = get_task_map(new_task);
		result = thread_create(new_task, &imgp->ip_vfork_thread);
		if (result != KERN_SUCCESS)
	    	printf("execve: thread_create failed. Code: 0x%x\n", result);
		/* reset local idea of task, thread, uthread */
		task = new_task;
		thread = imgp->ip_vfork_thread;
		uthread = get_bsdthread_info(thread);
	} else {
		map = VM_MAP_NULL;
	}

	/*
	 * We set these flags here; this is OK, since if we fail after
	 * this point, we have already destroyed the parent process anyway.
	 */
	if (imgp->ip_flags & IMGPF_IS_64BIT) {
		task_set_64bit(task, TRUE);
		p->p_flag |= P_LP64;
	} else {
		task_set_64bit(task, FALSE);
		p->p_flag &= ~P_LP64;
	}

	/*
	 *	Load the Mach-O file.
	 */
/* LP64 - remove following "if" statement after osfmk/vm/task_working_set.c */
if((imgp->ip_flags & IMGPF_IS_64BIT) == 0)
	if(imgp->ip_tws_cache_name) {
		tws_handle_startup_file(task, kauth_cred_getuid(cred), 
			imgp->ip_tws_cache_name, imgp->ip_vp, &clean_regions);
	}

	vm_get_shared_region(task, &initial_region);

	
	/*
	 * NOTE: An error after this point  indicates we have potentially
	 * destroyed or overwrote some process state while attempting an
	 * execve() following a vfork(), which is an unrecoverable condition.
	 */

	/*
	 * We reset the task to 64-bit (or not) here.  It may have picked up
	 * a new map, and we need that to reflect its true 64-bit nature.
	 */
	task_set_64bit(task, 
		       ((imgp->ip_flags & IMGPF_IS_64BIT) == IMGPF_IS_64BIT));

	/*
	 * Actually load the image file we previously decided to load.
	 */
	lret = load_machfile(imgp, mach_header, thread, map, clean_regions, &load_result);

	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto badtoolate;
	}

	/* load_machfile() maps the vnode */
	(void)ubc_map(imgp->ip_vp, PROT_EXEC);

	/*
	 * deal with set[ug]id.
	 */
	error = exec_handle_sugid(imgp);

	KNOTE(&p->p_klist, NOTE_EXEC);

	if (!vfexec && (p->p_flag & P_TRACED))
		psignal(p, SIGTRAP);

	if (error) {
		goto badtoolate;
	}
	vnode_put(imgp->ip_vp);
	imgp->ip_vp = NULL;
	
	if (load_result.unixproc &&
		create_unix_stack(get_task_map(task),
				  load_result.user_stack, load_result.customstack, p)) {
		error = load_return_to_errno(LOAD_NOSPACE);
		goto badtoolate;
	}

	if (vfexec) {
		uthread->uu_ar0 = (void *)get_user_regs(thread);
		old_map = vm_map_switch(get_task_map(task));
	}

	if (load_result.unixproc) {
		user_addr_t	ap;

		/*
		 * Copy the strings area out into the new process address
		 * space.
		 */
		ap = p->user_stack;
		error = exec_copyout_strings(imgp, &ap);
		if (error) {
			if (vfexec)
				vm_map_switch(old_map);
			goto badtoolate;
		}
		/* Set the stack */
		thread_setuserstack(thread, ap);
	}
	
	if (load_result.dynlinker) {
		uint64_t	ap;

		/* Adjust the stack */
		if (imgp->ip_flags & IMGPF_IS_64BIT) {
			ap = thread_adjuserstack(thread, -8);
			(void)copyoutptr(load_result.mach_header, ap, 8);
		} else {
			ap = thread_adjuserstack(thread, -4);
			(void)suword(ap, load_result.mach_header);
		}
	}

	if (vfexec) {
		vm_map_switch(old_map);
	}
	/* Set the entry point */
	thread_setentrypoint(thread, load_result.entry_point);

	/* Stop profiling */
	stopprofclock(p);

	/*
	 * Reset signal state.
	 */
	execsigs(p, thread);

	/*
	 * Close file descriptors
	 * which specify close-on-exec.
	 */
	fdexec(p);

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	_aio_exec( p );

	/* FIXME: Till vmspace inherit is fixed: */
	if (!vfexec && p->vm_shm)
		shmexec(p);
	/* Clean up the semaphores */
	semexit(p);

	/*
	 * Remember file name for accounting.
	 */
	p->p_acflag &= ~AFORK;
	/* If the translated name isn't NULL, then we want to use
	 * that translated name as the name we show as the "real" name.
	 * Otherwise, use the name passed into exec.
	 */
	if (0 != imgp->ip_p_comm[0]) {
		bcopy((caddr_t)imgp->ip_p_comm, (caddr_t)p->p_comm,
			sizeof(p->p_comm));
	} else {
		if (imgp->ip_ndp->ni_cnd.cn_namelen > MAXCOMLEN)
			imgp->ip_ndp->ni_cnd.cn_namelen = MAXCOMLEN;
		bcopy((caddr_t)imgp->ip_ndp->ni_cnd.cn_nameptr, (caddr_t)p->p_comm,
			(unsigned)imgp->ip_ndp->ni_cnd.cn_namelen);
		p->p_comm[imgp->ip_ndp->ni_cnd.cn_namelen] = '\0';
	}

	{
	  /* This is for kdebug */
	  long dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

	  /* Collect the pathname for tracing */
	  kdbg_trace_string(p, &dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);



	  if (vfexec)
	  {
		  KERNEL_DEBUG_CONSTANT1((TRACEDBG_CODE(DBG_TRACE_DATA, 2)) | DBG_FUNC_NONE,
		                        p->p_pid ,0,0,0, (unsigned int)thread);
	          KERNEL_DEBUG_CONSTANT1((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, (unsigned int)thread);
	  }
	  else
	  {
		  KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_DATA, 2)) | DBG_FUNC_NONE,
		                        p->p_pid ,0,0,0,0);
	          KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
	  }
	}

		p->p_flag &= ~P_CLASSIC;

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
		psignal_vfork(p, new_task, thread, SIGTRAP);
	}

badtoolate:
	if (vfexec) {
		task_deallocate(new_task);
		thread_deallocate(thread);
		if (error)
			error = 0;
	}

bad:
	return(error);
}




/*
 * Our image activator table; this is the table of the image types we are
 * capable of loading.  We list them in order of preference to ensure the
 * fastest image load speed.
 *
 * XXX hardcoded, for now; should use linker sets
 */
struct execsw {
	int (*ex_imgact)(struct image_params *);
	const char *ex_name;
} execsw[] = {
	{ exec_mach_imgact,		"Mach-o Binary" },
	{ exec_fat_imgact,		"Fat Binary" },
	{ exec_shell_imgact,		"Interpreter Script" },
	{ NULL, NULL}
};


/*
 * TODO:	Dynamic linker header address on stack is copied via suword()
 */
/* ARGSUSED */
int
execve(struct proc *p, struct execve_args *uap, register_t *retval)
{
	kauth_cred_t cred = p->p_ucred;
	struct image_params image_params, *imgp;
	struct vnode_attr va;
	struct vnode_attr origva;
	struct nameidata nd;
	struct uthread		*uthread;
	int i;
	int resid, error;
	task_t  task;
	int numthreads;
	int vfexec=0;
	int once = 1;	/* save SGUID-ness for interpreted files */
	char alt_p_comm[sizeof(p->p_comm)] = {0};	/* for Classic */
	int is_64 = IS_64BIT_PROCESS(p);
	int seg = (is_64 ? UIO_USERSPACE64 : UIO_USERSPACE32);
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = p->p_ucred;	/* XXX must NOT be kauth_cred_get() */


	imgp = &image_params;

	/* Initialize the common data in the image_params structure */
	bzero(imgp, sizeof(*imgp));
	imgp->ip_user_fname = uap->fname;
	imgp->ip_user_argv = uap->argp;
	imgp->ip_user_envv = uap->envp;
	imgp->ip_vattr = &va;
	imgp->ip_origvattr = &origva;
	imgp->ip_vfs_context = &context;
	imgp->ip_flags = (is_64 ? IMGPF_WAS_64BIT : IMGPF_NONE);
	imgp->ip_tws_cache_name = NULL;
	imgp->ip_p_comm = alt_p_comm;		/* for Classic */

	/*
         * XXXAUDIT: Currently, we only audit the pathname of the binary.
         * There may also be poor interaction with dyld.
         */

	task = current_task();
	uthread = get_bsdthread_info(current_thread());

	if (uthread->uu_flag & UT_VFORK) {
			vfexec = 1; /* Mark in exec */
	} else {
		if (task != kernel_task) { 
			numthreads = get_task_numacts(task);
			if (numthreads <= 0 )
				return(EINVAL);
			if (numthreads > 1) {
				return(ENOTSUP);
			}
		}
	}

	error = execargs_alloc(imgp);
	if (error)
		return(error);
	
	/*
	 * XXXAUDIT: Note: the double copyin introduces an audit
	 * race.  To correct this race, we must use a single
	 * copyin(), e.g. by passing a flag to namei to indicate an
	 * external path buffer is being used.
	 */
	error = exec_save_path(imgp, uap->fname, seg);
	if (error) {
		execargs_free(imgp);
		return(error);
	}

	/*
	 * No app profiles under chroot
	 */
	if((p->p_fd->fd_rdir == NULLVP) && (app_profile != 0)) {

		/* grab the name of the file out of its path */
		/* we will need this for lookup within the   */
		/* name file */
		/* Scan backwards for the first '/' or start of string */
		imgp->ip_tws_cache_name = imgp->ip_strendp;
               	while (imgp->ip_tws_cache_name[0] != '/') {
               		if(imgp->ip_tws_cache_name == imgp->ip_strings) {
               	        	imgp->ip_tws_cache_name--;
               	         	break;
                      	}
               		imgp->ip_tws_cache_name--;
               	}
               	imgp->ip_tws_cache_name++;
	}
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
		seg, uap->fname, imgp->ip_vfs_context);

again:
	error = namei(&nd);
	if (error)
		goto bad;
	imgp->ip_ndp = &nd;	/* successful namei(); call nameidone() later */
	imgp->ip_vp = nd.ni_vp;	/* if set, need to vnode_put() at some point */

	error = exec_check_permissions(imgp);
	if (error)
		goto bad;

	/* Copy; avoid invocation of an interpreter overwriting the original */
	if (once) {
		once = 0;
		origva = va;
	}

	error = vn_rdwr(UIO_READ, imgp->ip_vp, imgp->ip_vdata, PAGE_SIZE, 0,
			UIO_SYSSPACE32, IO_NODELOCKED, cred, &resid, p);
	if (error)
		goto bad;
		
encapsulated_binary:
	error = -1;
	for(i = 0; error == -1 && execsw[i].ex_imgact != NULL; i++) {

		error = (*execsw[i].ex_imgact)(imgp);

		switch (error) {
		/* case -1: not claimed: continue */
		case -2:		/* Encapsulated binary */
			goto encapsulated_binary;

		case -3:		/* Interpreter */
			vnode_put(imgp->ip_vp);
			imgp->ip_vp = NULL;	/* already put */
			nd.ni_cnd.cn_nameiop = LOOKUP;
			nd.ni_cnd.cn_flags = (nd.ni_cnd.cn_flags & HASBUF) |
						(FOLLOW | LOCKLEAF);


			nd.ni_segflg = UIO_SYSSPACE32;
			nd.ni_dirp = CAST_USER_ADDR_T(imgp->ip_interp_name);
			goto again;

		default:
			break;
		}
	}
	
	/* call out to allow 3rd party notification of exec. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
	if (error == 0 && kauth_authorize_fileop_has_listeners()) {
		kauth_authorize_fileop(vfs_context_ucred(&context), KAUTH_FILEOP_EXEC, 
							   (uintptr_t)nd.ni_vp, 0);
	}
	
	/* Image not claimed by any activator? */
	if (error == -1)
		error = ENOEXEC;

bad:
	if (imgp->ip_ndp)
		nameidone(imgp->ip_ndp);
	if (imgp->ip_vp)
		vnode_put(imgp->ip_vp);
	if (imgp->ip_strings)
		execargs_free(imgp);
	if (!error && vfexec) {
			vfork_return(current_thread(), p->p_pptr, p, retval);
			(void)thread_resume(imgp->ip_vfork_thread);
			return(0);
	}
	return(error);
}


static int
copyinptr(user_addr_t froma, user_addr_t *toptr, int ptr_size)
{
	int error;

	if (ptr_size == 4) {
		/* 64 bit value containing 32 bit address */
		unsigned int i;

		error = copyin(froma, &i, 4);
		*toptr = CAST_USER_ADDR_T(i);	/* SAFE */
	} else {
		error = copyin(froma, toptr, 8);
	}
	return (error);
}


static int
copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size)
{
	int error;

	if (ptr_size == 4) {
		/* 64 bit value containing 32 bit address */
		unsigned int i = CAST_DOWN(unsigned int,ua);	/* SAFE */

		error = copyout(&i, ptr, 4);
	} else {
		error = copyout(&ua, ptr, 8);
	}
	return (error);
}


/*
 * exec_copyout_strings
 *
 * Copy out the strings segment to user space.  The strings segment is put
 * on a preinitialized stack frame.
 *
 * Parameters:	struct image_params *	the image parameter block
 *		int *			a pointer to the stack offset variable
 *
 * Returns:	0			Success
 *		!0			Faiure: errno
 *
 * Implicit returns:
 *		(*stackp)		The stack offset, modified
 *
 * Note:	The strings segment layout is backward, from the beginning
 *		of the top of the stack to consume the minimal amount of
 *		space possible; the returned stack pointer points to the
 *		end of the area consumed (stacks grow upward).
 *
 *		argc is an int; arg[i] are pointers; env[i] are pointers;
 *		exec_path is a pointer; the 0's are (void *)NULL's
 *
 * The stack frame layout is:
 *
 *	+-------------+
 * sp->	|     argc    |
 *	+-------------+
 *	|    arg[0]   |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	| arg[argc-1] |
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	|    env[0]   |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	|    env[n]   |
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	|  exec_path  |	In MacOS X PR2 Beaker2E the path passed to exec() is
 *	+-------------+	passed on the stack just after the trailing 0 of the
 *	|      0      | the envp[] array as a pointer to a string.
 *	+-------------+
 *	|  PATH AREA  |
 *	+-------------+
 *	| STRING AREA |
 *	       :
 *	       :
 *	|             | <- p->user_stack
 *	+-------------+
 *
 * Although technically a part of the STRING AREA, we treat the PATH AREA as
 * a separate entity.  This allows us to align the beginning of the PATH AREA
 * to a pointer boundary so that the exec_path, env[i], and argv[i] pointers
 * which preceed it on the stack are properly aligned.
 *
 * TODO:	argc copied with suword(), which takes a 64 bit address
 */
static int
exec_copyout_strings(struct image_params *imgp, user_addr_t *stackp)
{
	struct proc *p = vfs_context_proc(imgp->ip_vfs_context);
	int	ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;
	char	*argv = imgp->ip_argv;	/* modifiable copy of argv */
	user_addr_t	string_area;	/* *argv[], *env[] */
	user_addr_t	path_area;	/* package launch path */
	user_addr_t	ptr_area;	/* argv[], env[], exec_path */
	user_addr_t	stack;
	int	stringc = imgp->ip_argc + imgp->ip_envc;
	int len;
	int error;
	int strspace;

	stack = *stackp;

	/*
	 * Set up pointers to the beginning of the string area, the beginning
	 * of the path area, and the beginning of the pointer area (actually,
	 * the location of argc, an int, which may be smaller than a pointer,
	 * but we use ptr_size worth of space for it, for alignment).
	 */
	string_area = stack - (((imgp->ip_strendp - imgp->ip_strings) + ptr_size-1) & ~(ptr_size-1)) - ptr_size;
	path_area = string_area - (((imgp->ip_argv - imgp->ip_strings) + ptr_size-1) & ~(ptr_size-1));
	ptr_area = path_area - ((imgp->ip_argc + imgp->ip_envc + 4) * ptr_size) - ptr_size /*argc*/;

	/* Return the initial stack address: the location of argc */
	*stackp = ptr_area;

	/*
	 * Record the size of the arguments area so that sysctl_procargs()
	 * can return the argument area without having to parse the arguments.
	 */
	p->p_argc = imgp->ip_argc;
	p->p_argslen = (int)(stack - path_area);


	/*
	 * Support for new app package launching for Mac OS X allocates
	 * the "path" at the begining of the imgp->ip_strings buffer.
	 * copy it just before the string area.
	 */
	len = 0;
	error = copyoutstr(imgp->ip_strings, path_area,
				(unsigned)(imgp->ip_argv - imgp->ip_strings),
				(size_t *)&len);
	if (error)
		goto bad;


	/* Save a NULL pointer below it */
	(void)copyoutptr(0LL, path_area - ptr_size, ptr_size);

	/* Save the pointer to "path" just below it */
	(void)copyoutptr(path_area, path_area - 2*ptr_size, ptr_size);

	/*
	 * ptr_size for 2 NULL one each ofter arg[argc -1] and env[n]
	 * ptr_size for argc
	 * skip over saved path, ptr_size for pointer to path,
	 * and ptr_size for the NULL after pointer to path.
	 */

	/* argc (int32, stored in a ptr_size area) */
	(void)suword(ptr_area, imgp->ip_argc);
	ptr_area += sizeof(int);
	/* pad to ptr_size, if 64 bit image, to ensure user stack alignment */
	if (imgp->ip_flags & IMGPF_IS_64BIT) {
		(void)suword(ptr_area, 0);	/* int, not long: ignored */
		ptr_area += sizeof(int);
	}


	/*
	 * We use (string_area - path_area) here rather than the more
	 * intuitive (imgp->ip_argv - imgp->ip_strings) because we are
	 * interested in the length of the PATH_AREA in user space,
	 * rather than the actual length of the execution path, since
	 * it includes alignment padding of the PATH_AREA + STRING_AREA
	 * to a ptr_size boundary.
	 */
	strspace = SIZE_IMG_STRSPACE - (string_area - path_area);
	for (;;) {
		if (stringc == imgp->ip_envc) {
			/* argv[n] = NULL */
			(void)copyoutptr(0LL, ptr_area, ptr_size);
			ptr_area += ptr_size;
		}
		if (--stringc < 0)
			break;

		/* pointer: argv[n]/env[n] */
		(void)copyoutptr(string_area, ptr_area, ptr_size);

		/* string : argv[n][]/env[n][] */
		do {
			if (strspace <= 0) {
				error = E2BIG;
				break;
			}
			error = copyoutstr(argv, string_area,
						(unsigned)strspace,
						(size_t *)&len);
			string_area += len;
			argv += len;
			strspace -= len;
		} while (error == ENAMETOOLONG);
		if (error == EFAULT || error == E2BIG)
			break;	/* bad stack - user's problem */
		ptr_area += ptr_size;
	}
	/* env[n] = NULL */
	(void)copyoutptr(0LL, ptr_area, ptr_size);

bad:
	return(error);
}


/*
 * exec_extract_strings
 *
 * Copy arguments and environment from user space into work area; we may
 * have already copied some early arguments into the work area, and if
 * so, any arguments opied in are appended to those already there.
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	0			Success
 *		!0			Failure: errno
 *
 * Implicit returns;
 *		(imgp->ip_argc)		Count of arguments, updated
 *		(imgp->ip_envc)		Count of environment strings, updated
 *
 *
 * Notes:	The argument and environment vectors are user space pointers
 *		to arrays of user space pointers.
 */
static int
exec_extract_strings(struct image_params *imgp)
{
	int error = 0;
	struct proc *p = vfs_context_proc(imgp->ip_vfs_context);
	int seg = (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32);
	int	ptr_size = (imgp->ip_flags & IMGPF_WAS_64BIT) ? 8 : 4;
	user_addr_t	argv = imgp->ip_user_argv;
	user_addr_t	envv = imgp->ip_user_envv;

	/* Now, get rest of arguments */

	/*
	 * If we are running an interpreter, replace the av[0] that was
	 * passed to execve() with the fully qualified path name that was
	 * passed to execve() for interpreters which do not use the PATH
	 * to locate their script arguments.
	 */
	if((imgp->ip_flags & IMGPF_INTERPRET) != 0 && argv != 0LL) {
		user_addr_t	arg;

		error = copyinptr(argv, &arg, ptr_size);
		if (error)
			goto bad;
		if (arg != 0LL && arg != (user_addr_t)-1) {
			argv += ptr_size;
			error = exec_add_string(imgp, imgp->ip_user_fname, seg);
			if (error)
				goto bad;
			imgp->ip_argc++;
		}
	}

	while (argv != 0LL) {
		user_addr_t	arg;

		error = copyinptr(argv, &arg, ptr_size);
		if (error)
			goto bad;

		argv += ptr_size;
		if (arg == 0LL) {
			break;
		} else if (arg == (user_addr_t)-1) {
			/* Um... why would it be -1? */
			error = EFAULT;
			goto bad;
		}
		/*
		* av[n...] = arg[n]
		*/
		error = exec_add_string(imgp, arg, seg);
		if (error)
			goto bad;
		imgp->ip_argc++;
	}	 

	/* Now, get the environment */
	while (envv != 0LL) {
		user_addr_t	env;

		error = copyinptr(envv, &env, ptr_size);
		if (error)
			goto bad;

		envv += ptr_size;
		if (env == 0LL) {
			break;
		} else if (env == (user_addr_t)-1) {
			error = EFAULT;
			goto bad;
		}
		/*
		* av[n...] = env[n]
		*/
		error = exec_add_string(imgp, env, seg);
		if (error)
			goto bad;
		imgp->ip_envc++;
	}
bad:
	return error;
}


#define	unix_stack_size(p)	(p->p_rlimit[RLIMIT_STACK].rlim_cur)

static int
exec_check_permissions(struct image_params *imgp)
{
	struct vnode *vp = imgp->ip_vp;
	struct vnode_attr *vap = imgp->ip_vattr;
	struct proc *p = vfs_context_proc(imgp->ip_vfs_context);
	int error;
	kauth_action_t action;

	/* Only allow execution of regular files */
	if (!vnode_isreg(vp))
		return (EACCES);
	
	/* Get the file attributes that we will be using here and elsewhere */
	VATTR_INIT(vap);
	VATTR_WANTED(vap, va_uid);
	VATTR_WANTED(vap, va_gid);
	VATTR_WANTED(vap, va_mode);
	VATTR_WANTED(vap, va_fsid);
	VATTR_WANTED(vap, va_fileid);
	VATTR_WANTED(vap, va_data_size);
	if ((error = vnode_getattr(vp, vap, imgp->ip_vfs_context)) != 0)
		return (error);

	/*
	 * Ensure that at least one execute bit is on - otherwise root
	 * will always succeed, and we don't want to happen unless the
	 * file really is executable.
	 */
	if ((vap->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
		return (EACCES);

	/* Disallow zero length files */
	if (vap->va_data_size == 0)
		return (ENOEXEC);

	imgp->ip_arch_offset = (user_size_t)0;
	imgp->ip_arch_size = vap->va_data_size;

	/* Disable setuid-ness for traced programs or if MNT_NOSUID */
	if ((vp->v_mount->mnt_flag & MNT_NOSUID) || (p->p_flag & P_TRACED))
		vap->va_mode &= ~(VSUID | VSGID);

  	/* Check for execute permission */
 	action = KAUTH_VNODE_EXECUTE;
  	/* Traced images must also be readable */
 	if (p->p_flag & P_TRACED)
 		action |= KAUTH_VNODE_READ_DATA;
 	if ((error = vnode_authorize(vp, NULL, action, imgp->ip_vfs_context)) != 0)
		return (error);

	/* Don't let it run if anyone had it open for writing */
	if (vp->v_writecount)
		return (ETXTBSY);


	/* XXX May want to indicate to underlying FS that vnode is open */

	return (error);
}

/*
 * exec_handle_sugid
 *
 * Initially clear the P_SUGID in the process flags; if an SUGID process is
 * exec'ing a non-SUGID image, then  this is the point of no return.
 *
 * If the image being activated is SUGI, then replace the credential with a
 * copy, disable tracing (unless the tracing process is root), reset the
 * mach task port to revoke it, set the P_SUGID bit,
 *
 * If the saved user and group ID will be changing, then make sure it happens
 * to a new credential, rather than a shared one.
 *
 * Set the security token (this is probably obsolete, given that the token
 * should not technically be separate from the credential itself).
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	void			No failure indication
 *
 * Implicit returns:
 *		<process credential>	Potentially modified/replaced
 *		<task port>		Potentially revoked
 *		<process flags>		P_SUGID bit potentially modified
 *		<security token>	Potentially modified
 */
static int
exec_handle_sugid(struct image_params *imgp)
{
	kauth_cred_t		cred = vfs_context_ucred(imgp->ip_vfs_context);
	struct proc		*p = vfs_context_proc(imgp->ip_vfs_context);
	int			i;
	int			error = 0;
	static struct vnode	*dev_null = NULLVP;

	p->p_flag &= ~P_SUGID;

	if (((imgp->ip_origvattr->va_mode & VSUID) != 0 &&
	     kauth_cred_getuid(cred) != imgp->ip_origvattr->va_uid) ||
	    ((imgp->ip_origvattr->va_mode & VSGID) != 0 &&
	     cred->cr_gid != imgp->ip_origvattr->va_gid)) {
#if KTRACE
		/*
		 * If process is being ktraced, turn off - unless
		 * root set it.
		 */
		if (p->p_tracep && !(p->p_traceflag & KTRFAC_ROOT)) {
			struct vnode *tvp = p->p_tracep;
			p->p_tracep = NULL;
			p->p_traceflag = 0;
			vnode_rele(tvp);
		}
#endif
	    /*
		 * Replace the credential with a copy of itself if euid or egid change.
		 */
		if (imgp->ip_origvattr->va_mode & VSUID) {
			p->p_ucred = kauth_cred_seteuid(p->p_ucred, imgp->ip_origvattr->va_uid);
		}
		if (imgp->ip_origvattr->va_mode & VSGID) {
			p->p_ucred = kauth_cred_setegid(p->p_ucred, imgp->ip_origvattr->va_gid);
		}

		/*
		 * Have mach reset the task port.  We don't want
		 * anyone who had the task port before a setuid
		 * exec to be able to access/control the task
		 * after.
		 */
		if (current_task() == p->task)
			ipc_task_reset(p->task);

		p->p_flag |= P_SUGID;

		/* Cache the vnode for /dev/null the first time around */
		if (dev_null == NULLVP) {
			struct nameidata nd1;

			NDINIT(&nd1, LOOKUP, FOLLOW, UIO_SYSSPACE32,
			    CAST_USER_ADDR_T("/dev/null"),
			    imgp->ip_vfs_context);

			if ((error = vn_open(&nd1, FREAD, 0)) == 0) {
				dev_null = nd1.ni_vp;
				/*
				 * vn_open returns with both a use_count
				 * and an io_count on the found vnode
				 * drop the io_count, but keep the use_count
				 */
				vnode_put(nd1.ni_vp);
			}
		}

		/* Radar 2261856; setuid security hole fix */
		/* Patch from OpenBSD: A. Ramesh */
		/*
		 * XXX For setuid processes, attempt to ensure that
		 * stdin, stdout, and stderr are already allocated.
		 * We do not want userland to accidentally allocate
		 * descriptors in this range which has implied meaning
		 * to libc.
		 */
		if (dev_null != NULLVP) {
			for (i = 0; i < 3; i++) {
				struct fileproc *fp;
				int indx;

				if (p->p_fd->fd_ofiles[i] != NULL)
					continue;

				if ((error = falloc(p, &fp, &indx)) != 0)
					continue;

				if ((error = vnode_ref_ext(dev_null, FREAD)) != 0) {
					fp_free(p, indx, fp);
					break;
				}

				fp->f_fglob->fg_flag = FREAD;
				fp->f_fglob->fg_type = DTYPE_VNODE;
				fp->f_fglob->fg_ops = &vnops;
				fp->f_fglob->fg_data = (caddr_t)dev_null;
				
				proc_fdlock(p);
				*fdflags(p, indx) &= ~UF_RESERVED;
				fp_drop(p, indx, fp, 1);
				proc_fdunlock(p);
			}
			/*
			 * for now we need to drop the reference immediately
			 * since we don't have any mechanism in place to
			 * release it before starting to unmount "/dev"
			 * during a reboot/shutdown
			 */
			vnode_rele(dev_null);
			dev_null = NULLVP;
		}
	}

	/*
	 * Implement the semantic where the effective user and group become
	 * the saved user and group in exec'ed programs.
	 */
	p->p_ucred = kauth_cred_setsvuidgid(p->p_ucred, kauth_cred_getuid(p->p_ucred),  p->p_ucred->cr_gid);
	
	/* XXX Obsolete; security token should not be separate from cred */
	set_security_token(p);

	return(error);
}

static kern_return_t
create_unix_stack(vm_map_t map, user_addr_t user_stack, int customstack,
			struct proc *p)
{
	mach_vm_size_t	size;
	mach_vm_offset_t addr;

	p->user_stack = user_stack;
	if (!customstack) {
		size = mach_vm_round_page(unix_stack_size(p));
		addr = mach_vm_trunc_page(user_stack - size);
		return (mach_vm_allocate(map, &addr, size,
					VM_MAKE_TAG(VM_MEMORY_STACK) |
					VM_FLAGS_FIXED));
	} else
		return(KERN_SUCCESS);
}

#include <sys/reboot.h>

static char		init_program_name[128] = "/sbin/launchd";
static const char *	other_init = "/sbin/mach_init";

char		init_args[128] = "";

struct execve_args	init_exec_args;
int		init_attempts = 0;


void
load_init_program(struct proc *p)
{
	vm_offset_t	init_addr;
	char		*argv[3];
	int			error;
	register_t 	retval[2];

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
				   PAGE_SIZE, VM_FLAGS_ANYWHERE);
		if (init_addr == 0)
			init_addr++;

		(void) copyout((caddr_t) init_program_name,
				CAST_USER_ADDR_T(init_addr),
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
				CAST_USER_ADDR_T(init_addr),
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
				CAST_USER_ADDR_T(init_addr),
				(unsigned) sizeof(argv));

		/*
		 *	Set up argument block for fake call to execve.
		 */

		init_exec_args.fname = CAST_USER_ADDR_T(argv[0]);
		init_exec_args.argp = CAST_USER_ADDR_T((char **)init_addr);
		init_exec_args.envp = CAST_USER_ADDR_T(0);
		
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
	    case LOAD_RESOURCE:
	    	return ENOMEM;
	    case LOAD_PROTECT:
	    	return EACCES;
		case LOAD_ENOENT:
			return ENOENT;
		case LOAD_IOERROR:
			return EIO;
	    case LOAD_FAILURE:
	    default:
	    	return EBADEXEC;
	}
}

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

extern semaphore_t execve_semaphore;

/*
 * The block of memory used by the execve arguments.  At the same time,
 * we allocate a page so that we can read in the first page of the image.
 */
static int
execargs_alloc(struct image_params *imgp)
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

	kret = kmem_alloc_pageable(bsd_pageable_map, (vm_offset_t *)&imgp->ip_strings, NCARGS + PAGE_SIZE);
	imgp->ip_vdata = imgp->ip_strings + NCARGS;
	if (kret != KERN_SUCCESS) {
	        semaphore_signal(execve_semaphore);
		return (ENOMEM);
	}
	return (0);
}

static int
execargs_free(struct image_params *imgp)
{
	kern_return_t kret;

	kmem_free(bsd_pageable_map, (vm_offset_t)imgp->ip_strings, NCARGS + PAGE_SIZE);
	imgp->ip_strings = NULL;

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
