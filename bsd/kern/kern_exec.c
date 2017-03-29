/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
/*
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
 
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#include <machine/reg.h>
#include <machine/cpu_capabilities.h>

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
#include <sys/persona.h>
#include <sys/reason.h>
#if SYSV_SHM
#include <sys/shm_internal.h>		/* shmexec() */
#endif
#include <sys/ubc_internal.h>		/* ubc_map() */
#include <sys/spawn.h>
#include <sys/spawn_internal.h>
#include <sys/process_policy.h>
#include <sys/codesign.h>
#include <sys/random.h>
#include <crypto/sha1.h>

#include <libkern/libkern.h>

#include <security/audit/audit.h>

#include <ipc/ipc_types.h>

#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/task_access.h>
#include <mach/thread_act.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>

#include <kern/sched_prim.h> /* thread_wakeup() */
#include <kern/affinity.h>
#include <kern/assert.h>
#include <kern/task.h>
#include <kern/coalition.h>
#include <kern/policy_internal.h>
#include <kern/kalloc.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_mach_internal.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>
#include <vm/vm_pageout.h>

#include <kdp/kdp_dyld.h>

#include <machine/pal_routines.h>

#include <pexpert/pexpert.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void dtrace_proc_exec(proc_t);
extern void (*dtrace_proc_waitfor_exec_ptr)(proc_t);

/*
 * Since dtrace_proc_waitfor_exec_ptr can be added/removed in dtrace_subr.c,
 * we will store its value before actually calling it.
 */
static void (*dtrace_proc_waitfor_hook)(proc_t) = NULL;

#include <sys/dtrace_ptss.h>
#endif

/* support for child creation in exec after vfork */
thread_t fork_create_child(task_t parent_task, coalition_t *parent_coalition, proc_t child_proc, int inherit_memory, int is64bit, int in_exec);
void vfork_exit(proc_t p, int rv);
extern void proc_apply_task_networkbg_internal(proc_t, thread_t);
extern void task_set_did_exec_flag(task_t task);
extern void task_clear_exec_copy_flag(task_t task);
proc_t proc_exec_switch_task(proc_t p, task_t old_task, task_t new_task, thread_t new_thread);
boolean_t task_is_active(task_t);
boolean_t thread_is_active(thread_t thread);
void thread_copy_resource_info(thread_t dst_thread, thread_t src_thread);
void *ipc_importance_exec_switch_task(task_t old_task, task_t new_task);
extern void ipc_importance_release(void *elem);

/*
 * Mach things for which prototypes are unavailable from Mach headers
 */
void		ipc_task_reset(
			task_t		task);
void		ipc_thread_reset(
			thread_t	thread);
kern_return_t ipc_object_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		*objectp);
void ipc_port_release_send(ipc_port_t);

#if DEVELOPMENT || DEBUG
void task_importance_update_owner_info(task_t);
#endif

extern struct savearea *get_user_regs(thread_t);

__attribute__((noinline)) int __EXEC_WAITING_ON_TASKGATED_CODE_SIGNATURE_UPCALL__(mach_port_t task_access_port, int32_t new_pid);

#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ast.h>
#include <kern/mach_loader.h>
#include <kern/mach_fat.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <machine/vmparam.h>
#include <sys/imgact.h>

#include <sys/sdt.h>


/*
 * EAI_ITERLIMIT	The maximum number of times to iterate an image
 *			activator in exec_activate_image() before treating
 *			it as malformed/corrupt.
 */
#define EAI_ITERLIMIT		3

/*
 * For #! interpreter parsing
 */
#define IS_WHITESPACE(ch) ((ch == ' ') || (ch == '\t'))
#define IS_EOL(ch) ((ch == '#') || (ch == '\n'))

extern vm_map_t bsd_pageable_map;
extern const struct fileops vnops;

#define	USER_ADDR_ALIGN(addr, val) \
	( ( (user_addr_t)(addr) + (val) - 1) \
		& ~((val) - 1) )

struct image_params;	/* Forward */
static int exec_activate_image(struct image_params *imgp);
static int exec_copyout_strings(struct image_params *imgp, user_addr_t *stackp);
static int load_return_to_errno(load_return_t lrtn);
static int execargs_alloc(struct image_params *imgp);
static int execargs_free(struct image_params *imgp);
static int exec_check_permissions(struct image_params *imgp);
static int exec_extract_strings(struct image_params *imgp);
static int exec_add_apple_strings(struct image_params *imgp, const load_result_t *load_result);
static int exec_handle_sugid(struct image_params *imgp);
static int sugid_scripts = 0;
SYSCTL_INT (_kern, OID_AUTO, sugid_scripts, CTLFLAG_RW | CTLFLAG_LOCKED, &sugid_scripts, 0, "");
static kern_return_t create_unix_stack(vm_map_t map, load_result_t* load_result, proc_t p);
static int copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size);
static void exec_resettextvp(proc_t, struct image_params *);
static int check_for_signature(proc_t, struct image_params *);
static void exec_prefault_data(proc_t, struct image_params *, load_result_t *);
static errno_t exec_handle_port_actions(struct image_params *imgp, boolean_t * portwatch_present, ipc_port_t * portwatch_ports);
static errno_t exec_handle_spawnattr_policy(proc_t p, int psa_apptype, uint64_t psa_qos_clamp, uint64_t psa_darwin_role,
                             ipc_port_t * portwatch_ports, int portwatch_count);

/*
 * exec_add_user_string
 *
 * Add the requested string to the string space area.
 *
 * Parameters;	struct image_params *		image parameter block
 *		user_addr_t			string to add to strings area
 *		int				segment from which string comes
 *		boolean_t			TRUE if string contributes to NCARGS
 *
 * Returns:	0			Success
 *		!0			Failure errno from copyinstr()
 *
 * Implicit returns:
 *		(imgp->ip_strendp)	updated location of next add, if any
 *		(imgp->ip_strspace)	updated byte count of space remaining
 *		(imgp->ip_argspace) updated byte count of space in NCARGS
 */
static int
exec_add_user_string(struct image_params *imgp, user_addr_t str, int seg, boolean_t is_ncargs)
{
	int error = 0;
	
	do {
		size_t len = 0;
		int space;
		
		if (is_ncargs)
			space = imgp->ip_argspace; /* by definition smaller than ip_strspace */
		else
			space = imgp->ip_strspace;
		
		if (space <= 0) {
			error = E2BIG;
			break;
		}
		
		if (!UIO_SEG_IS_USER_SPACE(seg)) {
			char *kstr = CAST_DOWN(char *,str);	/* SAFE */
			error = copystr(kstr, imgp->ip_strendp, space, &len);
		} else  {
			error = copyinstr(str, imgp->ip_strendp, space, &len);
		}

		imgp->ip_strendp += len;
		imgp->ip_strspace -= len;
		if (is_ncargs)
			imgp->ip_argspace -= len;
		
	} while (error == ENAMETOOLONG);
	
	return error;
}

/*
 * dyld is now passed the executable path as a getenv-like variable
 * in the same fashion as the stack_guard and malloc_entropy keys.
 */
#define	EXECUTABLE_KEY "executable_path="

/*
 * exec_save_path
 *
 * To support new app package launching for Mac OS X, the dyld needs the
 * first argument to execve() stored on the user stack.
 *
 * Save the executable path name at the bottom of the strings area and set
 * the argument vector pointer to the location following that to indicate
 * the start of the argument and environment tuples, setting the remaining
 * string space count to the size of the string area minus the path length.
 *
 * Parameters;	struct image_params *		image parameter block
 *		char *				path used to invoke program
 *		int				segment from which path comes
 *
 * Returns:	int			0	Success
 *		EFAULT				Bad address
 *	copy[in]str:EFAULT			Bad address
 *	copy[in]str:ENAMETOOLONG		Filename too long
 *
 * Implicit returns:
 *		(imgp->ip_strings)		saved path
 *		(imgp->ip_strspace)		space remaining in ip_strings
 *		(imgp->ip_strendp)		start of remaining copy area
 *		(imgp->ip_argspace)		space remaining of NCARGS
 *		(imgp->ip_applec)		Initial applev[0]
 *
 * Note:	We have to do this before the initial namei() since in the
 *		path contains symbolic links, namei() will overwrite the
 *		original path buffer contents.  If the last symbolic link
 *		resolved was a relative pathname, we would lose the original
 *		"path", which could be an absolute pathname. This might be
 *		unacceptable for dyld.
 */
static int
exec_save_path(struct image_params *imgp, user_addr_t path, int seg, const char **excpath)
{
	int error;
	size_t len;
	char *kpath;

	// imgp->ip_strings can come out of a cache, so we need to obliterate the
	// old path.
	memset(imgp->ip_strings, '\0', strlen(EXECUTABLE_KEY) + MAXPATHLEN);

	len = MIN(MAXPATHLEN, imgp->ip_strspace);

	switch(seg) {
	case UIO_USERSPACE32:
	case UIO_USERSPACE64:	/* Same for copyin()... */
		error = copyinstr(path, imgp->ip_strings + strlen(EXECUTABLE_KEY), len, &len);
		break;
	case UIO_SYSSPACE:
		kpath = CAST_DOWN(char *,path);	/* SAFE */
		error = copystr(kpath, imgp->ip_strings + strlen(EXECUTABLE_KEY), len, &len);
		break;
	default:
		error = EFAULT;
		break;
	}

	if (!error) {
		bcopy(EXECUTABLE_KEY, imgp->ip_strings, strlen(EXECUTABLE_KEY));
		len += strlen(EXECUTABLE_KEY);

		imgp->ip_strendp += len;
		imgp->ip_strspace -= len;

		if (excpath) {
			*excpath = imgp->ip_strings + strlen(EXECUTABLE_KEY);
		}
	}

	return(error);
}

/*
 * exec_reset_save_path
 *
 * If we detect a shell script, we need to reset the string area
 * state so that the interpreter can be saved onto the stack.

 * Parameters;	struct image_params *		image parameter block
 *
 * Returns:	int			0	Success
 *
 * Implicit returns:
 *		(imgp->ip_strings)		saved path
 *		(imgp->ip_strspace)		space remaining in ip_strings
 *		(imgp->ip_strendp)		start of remaining copy area
 *		(imgp->ip_argspace)		space remaining of NCARGS
 *
 */
static int
exec_reset_save_path(struct image_params *imgp)
{
	imgp->ip_strendp = imgp->ip_strings;
	imgp->ip_argspace = NCARGS;
	imgp->ip_strspace = ( NCARGS + PAGE_SIZE );

	return (0);
}

/*
 * exec_shell_imgact
 *
 * Image activator for interpreter scripts.  If the image begins with
 * the characters "#!", then it is an interpreter script.  Verify the
 * length of the script line indicating the interpreter is not in
 * excess of the maximum allowed size.  If this is the case, then
 * break out the arguments, if any, which are separated by white
 * space, and copy them into the argument save area as if they were
 * provided on the command line before all other arguments.  The line
 * ends when we encounter a comment character ('#') or newline.
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
	char *line_startp, *line_endp;
	char *interp;
	proc_t p;
	struct fileproc *fp;
	int fd;
	int error;

	/*
	 * Make sure it's a shell script.  If we've already redirected
	 * from an interpreted file once, don't do it again.
	 */
	if (vdata[0] != '#' ||
	    vdata[1] != '!' ||
	    (imgp->ip_flags & IMGPF_INTERPRET) != 0) {
		return (-1);
	}

	if (imgp->ip_origcputype != 0) {
		/* Fat header previously matched, don't allow shell script inside */
		return (-1);
	}

	imgp->ip_flags |= IMGPF_INTERPRET;
	imgp->ip_interp_sugid_fd = -1;
	imgp->ip_interp_buffer[0] = '\0';

	/* Check to see if SUGID scripts are permitted.  If they aren't then
	 * clear the SUGID bits.
	 * imgp->ip_vattr is known to be valid.
	 */
	if (sugid_scripts == 0) {
		imgp->ip_origvattr->va_mode &= ~(VSUID | VSGID);
	}

	/* Try to find the first non-whitespace character */
	for( ihp = &vdata[2]; ihp < &vdata[IMG_SHSIZE]; ihp++ ) {
		if (IS_EOL(*ihp)) {
			/* Did not find interpreter, "#!\n" */
			return (ENOEXEC);
		} else if (IS_WHITESPACE(*ihp)) {
			/* Whitespace, like "#!    /bin/sh\n", keep going. */
		} else {
			/* Found start of interpreter */
			break;
		}
	}

	if (ihp == &vdata[IMG_SHSIZE]) {
		/* All whitespace, like "#!           " */
		return (ENOEXEC);
	}

	line_startp = ihp;

	/* Try to find the end of the interpreter+args string */
	for ( ; ihp < &vdata[IMG_SHSIZE]; ihp++ ) {
		if (IS_EOL(*ihp)) {
			/* Got it */
			break;
		} else {
			/* Still part of interpreter or args */
		}
	}

	if (ihp == &vdata[IMG_SHSIZE]) {
		/* A long line, like "#! blah blah blah" without end */
		return (ENOEXEC);
	}

	/* Backtrack until we find the last non-whitespace */
	while (IS_EOL(*ihp) || IS_WHITESPACE(*ihp)) {
		ihp--;
	}

	/* The character after the last non-whitespace is our logical end of line */
	line_endp = ihp + 1;

	/*
	 * Now we have pointers to the usable part of:
	 *
	 * "#!  /usr/bin/int first    second   third    \n"
	 *      ^ line_startp                       ^ line_endp
	 */

	/* copy the interpreter name */
	interp = imgp->ip_interp_buffer;
	for ( ihp = line_startp; (ihp < line_endp) && !IS_WHITESPACE(*ihp); ihp++)
		*interp++ = *ihp;
	*interp = '\0';

	exec_reset_save_path(imgp);
	exec_save_path(imgp, CAST_USER_ADDR_T(imgp->ip_interp_buffer),
							UIO_SYSSPACE, NULL);

	/* Copy the entire interpreter + args for later processing into argv[] */
	interp = imgp->ip_interp_buffer;
	for ( ihp = line_startp; (ihp < line_endp); ihp++)
		*interp++ = *ihp;
	*interp = '\0';

	/*
	 * If we have a SUID oder SGID script, create a file descriptor
	 * from the vnode and pass /dev/fd/%d instead of the actual
	 * path name so that the script does not get opened twice
	 */
	if (imgp->ip_origvattr->va_mode & (VSUID | VSGID)) {
		p = vfs_context_proc(imgp->ip_vfs_context);
		error = falloc(p, &fp, &fd, imgp->ip_vfs_context);
		if (error)
			return(error);

		fp->f_fglob->fg_flag = FREAD;
		fp->f_fglob->fg_ops = &vnops;
		fp->f_fglob->fg_data = (caddr_t)imgp->ip_vp;
		
		proc_fdlock(p);
		procfdtbl_releasefd(p, fd, NULL);
		fp_drop(p, fd, fp, 1);
		proc_fdunlock(p);
		vnode_ref(imgp->ip_vp);

		imgp->ip_interp_sugid_fd = fd;
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
 * Parameters;	struct image_params *	image parameter block
 *
 * Returns:	-1			not a fat binary (keep looking)
 *		-2			Success: encapsulated binary: reread
 *		>0			Failure: error number
 *
 * Important:	This image activator is byte order neutral.
 *
 * Note:	A return value other than -1 indicates subsequent image
 *		activators should not be given the opportunity to attempt
 *		to activate the image.
 *
 * 		If we find an encapsulated binary, we make no assertions
 *		about its  validity; instead, we leave that up to a rescan
 *		for an activator to claim it, and, if it is claimed by one,
 *		that activator is responsible for determining validity.
 */
static int
exec_fat_imgact(struct image_params *imgp)
{
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	kauth_cred_t cred = kauth_cred_proc_ref(p);
	struct fat_header *fat_header = (struct fat_header *)imgp->ip_vdata;
	struct _posix_spawnattr *psa = NULL;
	struct fat_arch fat_arch;
	int resid, error;
	load_return_t lret;

	if (imgp->ip_origcputype != 0) {
		/* Fat header previously matched, don't allow another fat file inside */
		error = -1; /* not claimed */
		goto bad;
	}

	/* Make sure it's a fat binary */
	if (OSSwapBigToHostInt32(fat_header->magic) != FAT_MAGIC) {
		error = -1; /* not claimed */
		goto bad;
	}

	/* imgp->ip_vdata has PAGE_SIZE, zerofilled if the file is smaller */
	lret = fatfile_validate_fatarches((vm_offset_t)fat_header, PAGE_SIZE);
	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto bad;
	}

	/* If posix_spawn binprefs exist, respect those prefs. */
	psa = (struct _posix_spawnattr *) imgp->ip_px_sa;
	if (psa != NULL && psa->psa_binprefs[0] != 0) {
		uint32_t pr = 0;

		/* Check each preference listed against all arches in header */
		for (pr = 0; pr < NBINPREFS; pr++) {
			cpu_type_t pref = psa->psa_binprefs[pr];
			if (pref == 0) {
				/* No suitable arch in the pref list */
				error = EBADARCH;
				goto bad;
			}

			if (pref == CPU_TYPE_ANY) {
				/* Fall through to regular grading */
				goto regular_grading;
			}

			lret = fatfile_getbestarch_for_cputype(pref,
							(vm_offset_t)fat_header,
							PAGE_SIZE,
							&fat_arch);
			if (lret == LOAD_SUCCESS) {
				goto use_arch;
			}
		}

		/* Requested binary preference was not honored */
		error = EBADEXEC;
		goto bad;
	}

regular_grading:
	/* Look up our preferred architecture in the fat file. */
	lret = fatfile_getbestarch((vm_offset_t)fat_header,
				PAGE_SIZE,
				&fat_arch);
	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto bad;
	}

use_arch:
	/* Read the Mach-O header out of fat_arch */
	error = vn_rdwr(UIO_READ, imgp->ip_vp, imgp->ip_vdata,
			PAGE_SIZE, fat_arch.offset,
			UIO_SYSSPACE, (IO_UNIT|IO_NODELOCKED),
			cred, &resid, p);
	if (error) {
		goto bad;
	}

	if (resid) {
		memset(imgp->ip_vdata + (PAGE_SIZE - resid), 0x0, resid);
	}

	/* Success.  Indicate we have identified an encapsulated binary */
	error = -2;
	imgp->ip_arch_offset = (user_size_t)fat_arch.offset;
	imgp->ip_arch_size = (user_size_t)fat_arch.size;
	imgp->ip_origcputype = fat_arch.cputype;
	imgp->ip_origcpusubtype = fat_arch.cpusubtype;

bad:
	kauth_cred_unref(&cred);
	return (error);
}

static int
activate_exec_state(task_t task, proc_t p, thread_t thread, load_result_t *result)
{
	int ret;

	task_set_dyld_info(task, MACH_VM_MIN_ADDRESS, 0);
	if (result->is64bit) {
		task_set_64bit(task, TRUE);
		OSBitOrAtomic(P_LP64, &p->p_flag);
	} else {
		task_set_64bit(task, FALSE);
		OSBitAndAtomic(~((uint32_t)P_LP64), &p->p_flag);
	}

	ret = thread_state_initialize(thread);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	if (result->threadstate) {
		uint32_t *ts = result->threadstate;
		uint32_t total_size = result->threadstate_sz;

		while (total_size > 0) {
			uint32_t flavor = *ts++;
			uint32_t size = *ts++;

			ret = thread_setstatus(thread, flavor, (thread_state_t)ts, size);
			if (ret) {
				return ret;
			}
			ts += size;
			total_size -= (size + 2) * sizeof(uint32_t);
		}
	}

	thread_setentrypoint(thread, result->entry_point);

	return KERN_SUCCESS;
}


/*
 * Set p->p_comm and p->p_name to the name passed to exec
 */
static void
set_proc_name(struct image_params *imgp, proc_t p)
{
	int p_name_len = sizeof(p->p_name) - 1;

	if (imgp->ip_ndp->ni_cnd.cn_namelen > p_name_len) {
		imgp->ip_ndp->ni_cnd.cn_namelen = p_name_len;
	}

	bcopy((caddr_t)imgp->ip_ndp->ni_cnd.cn_nameptr, (caddr_t)p->p_name,
		(unsigned)imgp->ip_ndp->ni_cnd.cn_namelen);
	p->p_name[imgp->ip_ndp->ni_cnd.cn_namelen] = '\0';

	if (imgp->ip_ndp->ni_cnd.cn_namelen > MAXCOMLEN) {
		imgp->ip_ndp->ni_cnd.cn_namelen = MAXCOMLEN;
	}

	bcopy((caddr_t)imgp->ip_ndp->ni_cnd.cn_nameptr, (caddr_t)p->p_comm,
		(unsigned)imgp->ip_ndp->ni_cnd.cn_namelen);
	p->p_comm[imgp->ip_ndp->ni_cnd.cn_namelen] = '\0';
}

/*
 * exec_mach_imgact
 *
 * Image activator for mach-o 1.0 binaries.
 *
 * Parameters;	struct image_params *	image parameter block
 *
 * Returns:	-1			not a fat binary (keep looking)
 *		-2			Success: encapsulated binary: reread
 *		>0			Failure: error number
 *		EBADARCH		Mach-o binary, but with an unrecognized
 *					architecture
 *		ENOMEM			No memory for child process after -
 *					can only happen after vfork()
 *
 * Important:	This image activator is NOT byte order neutral.
 *
 * Note:	A return value other than -1 indicates subsequent image
 *		activators should not be given the opportunity to attempt
 *		to activate the image.
 *
 * TODO:	More gracefully handle failures after vfork
 */
static int
exec_mach_imgact(struct image_params *imgp)
{
	struct mach_header *mach_header = (struct mach_header *)imgp->ip_vdata;
	proc_t			p = vfs_context_proc(imgp->ip_vfs_context);
	int			error = 0;
	task_t			task;
	task_t			new_task = NULL; /* protected by vfexec */
	thread_t		thread;
	struct uthread		*uthread;
	vm_map_t old_map = VM_MAP_NULL;
	vm_map_t map = VM_MAP_NULL;
	load_return_t		lret;
	load_result_t		load_result;
	struct _posix_spawnattr *psa = NULL;
	int			spawn = (imgp->ip_flags & IMGPF_SPAWN);
	int			vfexec = (imgp->ip_flags & IMGPF_VFORK_EXEC);
	int			exec = (imgp->ip_flags & IMGPF_EXEC);
	os_reason_t		exec_failure_reason = OS_REASON_NULL;

	/*
	 * make sure it's a Mach-O 1.0 or Mach-O 2.0 binary; the difference
	 * is a reserved field on the end, so for the most part, we can
	 * treat them as if they were identical. Reverse-endian Mach-O
	 * binaries are recognized but not compatible.
 	 */
	if ((mach_header->magic == MH_CIGAM) ||
	    (mach_header->magic == MH_CIGAM_64)) {
		error = EBADARCH;
		goto bad;
	}

	if ((mach_header->magic != MH_MAGIC) &&
	    (mach_header->magic != MH_MAGIC_64)) {
		error = -1;
		goto bad;
	}

	if (mach_header->filetype != MH_EXECUTE) {
		error = -1;
		goto bad;
	}

	if (imgp->ip_origcputype != 0) {
		/* Fat header previously had an idea about this thin file */
		if (imgp->ip_origcputype != mach_header->cputype ||
			imgp->ip_origcpusubtype != mach_header->cpusubtype) {
			error = EBADARCH;
			goto bad;
		}
	} else {
		imgp->ip_origcputype = mach_header->cputype;
		imgp->ip_origcpusubtype = mach_header->cpusubtype;
	}

	task = current_task();
	thread = current_thread();
	uthread = get_bsdthread_info(thread);

	if ((mach_header->cputype & CPU_ARCH_ABI64) == CPU_ARCH_ABI64)
		imgp->ip_flags |= IMGPF_IS_64BIT;

	/* If posix_spawn binprefs exist, respect those prefs. */
	psa = (struct _posix_spawnattr *) imgp->ip_px_sa;
	if (psa != NULL && psa->psa_binprefs[0] != 0) {
		int pr = 0;
		for (pr = 0; pr < NBINPREFS; pr++) {
			cpu_type_t pref = psa->psa_binprefs[pr];
			if (pref == 0) {
				/* No suitable arch in the pref list */
				error = EBADARCH;
				goto bad;
			}

			if (pref == CPU_TYPE_ANY) {
				/* Jump to regular grading */
				goto grade;
			}

			if (pref == imgp->ip_origcputype) {
				/* We have a match! */
				goto grade;
			}
		}
		error = EBADARCH;
		goto bad;
	}
grade:
	if (!grade_binary(imgp->ip_origcputype, imgp->ip_origcpusubtype & ~CPU_SUBTYPE_MASK)) {
		error = EBADARCH;
		goto bad;
	}

	/* Copy in arguments/environment from the old process */
	error = exec_extract_strings(imgp);
	if (error)
		goto bad;

	AUDIT_ARG(argv, imgp->ip_startargv, imgp->ip_argc, 
	    imgp->ip_endargv - imgp->ip_startargv);
	AUDIT_ARG(envv, imgp->ip_endargv, imgp->ip_envc,
	    imgp->ip_endenvv - imgp->ip_endargv);

	/*
	 * We are being called to activate an image subsequent to a vfork()
	 * operation; in this case, we know that our task, thread, and
	 * uthread are actually those of our parent, and our proc, which we
	 * obtained indirectly from the image_params vfs_context_t, is the
	 * new child process.
	 */
	if (vfexec) {
		imgp->ip_new_thread = fork_create_child(task, NULL, p, FALSE, (imgp->ip_flags & IMGPF_IS_64BIT), FALSE);
		/* task and thread ref returned, will be released in __mac_execve */
		if (imgp->ip_new_thread == NULL) {
			error = ENOMEM;
			goto bad;
		}
	}


	/* reset local idea of thread, uthread, task */
	thread = imgp->ip_new_thread;
	uthread = get_bsdthread_info(thread);
	task = new_task = get_threadtask(thread);

	/*
	 *	Load the Mach-O file.
	 *
	 * NOTE: An error after this point  indicates we have potentially
	 * destroyed or overwritten some process state while attempting an
	 * execve() following a vfork(), which is an unrecoverable condition.
	 * We send the new process an immediate SIGKILL to avoid it executing
	 * any instructions in the mutated address space. For true spawns,
	 * this is not the case, and "too late" is still not too late to
	 * return an error code to the parent process.
	 */

	/*
	 * Actually load the image file we previously decided to load.
	 */
	lret = load_machfile(imgp, mach_header, thread, &map, &load_result);
	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_BAD_MACHO, 0, 0);
		if (lret == LOAD_BADMACHO_UPX) {
			/* set anything that might be useful in the crash report */
			set_proc_name(imgp, p);

			exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_UPX);
			exec_failure_reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
			exec_failure_reason->osr_flags |= OS_REASON_FLAG_CONSISTENT_FAILURE;
		} else {
			exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_BAD_MACHO);
		}

		goto badtoolate;
	}

	proc_lock(p);
	p->p_cputype = imgp->ip_origcputype;
	p->p_cpusubtype = imgp->ip_origcpusubtype;
	proc_unlock(p);

	vm_map_set_user_wire_limit(map, p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur);

	/* 
	 * Set code-signing flags if this binary is signed, or if parent has
	 * requested them on exec.
	 */
	if (load_result.csflags & CS_VALID) {
		imgp->ip_csflags |= load_result.csflags & 
			(CS_VALID|CS_SIGNED|CS_DEV_CODE|
			 CS_HARD|CS_KILL|CS_RESTRICT|CS_ENFORCEMENT|CS_REQUIRE_LV|
			 CS_ENTITLEMENTS_VALIDATED|CS_DYLD_PLATFORM|
			 CS_ENTITLEMENT_FLAGS|
			 CS_EXEC_SET_HARD|CS_EXEC_SET_KILL|CS_EXEC_SET_ENFORCEMENT);
	} else {
		imgp->ip_csflags &= ~CS_VALID;
	}

	if (p->p_csflags & CS_EXEC_SET_HARD)
		imgp->ip_csflags |= CS_HARD;
	if (p->p_csflags & CS_EXEC_SET_KILL)
		imgp->ip_csflags |= CS_KILL;
	if (p->p_csflags & CS_EXEC_SET_ENFORCEMENT)
		imgp->ip_csflags |= CS_ENFORCEMENT;
	if (p->p_csflags & CS_EXEC_SET_INSTALLER)
		imgp->ip_csflags |= CS_INSTALLER;

	/*
	 * Set up the system reserved areas in the new address space.
	 */
	vm_map_exec(map, task, load_result.is64bit, (void *)p->p_fd->fd_rdir, cpu_type());

	/*
	 * Close file descriptors which specify close-on-exec.
	 */
	fdexec(p, psa != NULL ? psa->psa_flags : 0);

	/*
	 * deal with set[ug]id.
	 */
	error = exec_handle_sugid(imgp);
	if (error) {
		vm_map_deallocate(map);

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_SUGID_FAILURE, 0, 0);
		exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_SUGID_FAILURE);
		goto badtoolate;
	}

	/*
	 * Commit to new map.
	 *
	 * Swap the new map for the old for target task, which consumes
	 * our new map reference but each leaves us responsible for the
	 * old_map reference.  That lets us get off the pmap associated
	 * with it, and then we can release it.
	 *
	 * The map needs to be set on the target task which is different
	 * than current task, thus swap_task_map is used instead of
	 * vm_map_switch.
	 */
	old_map = swap_task_map(task, thread, map);
	vm_map_deallocate(old_map);
	old_map = NULL;

	lret = activate_exec_state(task, p, thread, &load_result);
	if (lret != KERN_SUCCESS) {

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_ACTV_THREADSTATE, 0, 0);
		exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_ACTV_THREADSTATE);
		goto badtoolate;
	}

	/*
	 * deal with voucher on exec-calling thread.
	 */
	if (imgp->ip_new_thread == NULL)
		thread_set_mach_voucher(current_thread(), IPC_VOUCHER_NULL);

	/* Make sure we won't interrupt ourself signalling a partial process */
	if (!vfexec && !spawn && (p->p_lflag & P_LTRACED))
		psignal(p, SIGTRAP);

	if (load_result.unixproc &&
		create_unix_stack(get_task_map(task),
				  &load_result,
				  p) != KERN_SUCCESS) {
		error = load_return_to_errno(LOAD_NOSPACE);

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_STACK_ALLOC, 0, 0);
		exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_STACK_ALLOC);
		goto badtoolate;
	}

	error = exec_add_apple_strings(imgp, &load_result);
	if (error) {

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_APPLE_STRING_INIT, 0, 0);
		exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_APPLE_STRING_INIT);
		goto badtoolate;
	}

	/* Switch to target task's map to copy out strings */
	old_map = vm_map_switch(get_task_map(task));

	if (load_result.unixproc) {
		user_addr_t	ap;

		/*
		 * Copy the strings area out into the new process address
		 * space.
		 */
		ap = p->user_stack;
		error = exec_copyout_strings(imgp, &ap);
		if (error) {
			vm_map_switch(old_map);

			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_COPYOUT_STRINGS, 0, 0);
			exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_COPYOUT_STRINGS);
			goto badtoolate;
		}
		/* Set the stack */
		thread_setuserstack(thread, ap);
	}

	if (load_result.dynlinker) {
		uint64_t	ap;
		int			new_ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;

		/* Adjust the stack */
		ap = thread_adjuserstack(thread, -new_ptr_size);
		error = copyoutptr(load_result.mach_header, ap, new_ptr_size);

		if (error) {
			vm_map_switch(old_map);

			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_COPYOUT_DYNLINKER, 0, 0);
			exec_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_COPYOUT_DYNLINKER);
			goto badtoolate;
		}
		task_set_dyld_info(task, load_result.all_image_info_addr,
		    load_result.all_image_info_size);
	}

	/* Avoid immediate VM faults back into kernel */
	exec_prefault_data(p, imgp, &load_result);

	vm_map_switch(old_map);

	/* Stop profiling */
	stopprofclock(p);

	/*
	 * Reset signal state.
	 */
	execsigs(p, thread);

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	_aio_exec( p );

#if SYSV_SHM
	/* FIXME: Till vmspace inherit is fixed: */
	if (!vfexec && p->vm_shm)
		shmexec(p);
#endif
#if SYSV_SEM
	/* Clean up the semaphores */
	semexit(p);
#endif

	/*
	 * Remember file name for accounting.
	 */
	p->p_acflag &= ~AFORK;

	set_proc_name(imgp, p);

#if CONFIG_SECLUDED_MEMORY
	if (secluded_for_apps) {
		if (strncmp(p->p_name,
			    "Camera",
			    sizeof (p->p_name)) == 0 ||
#if 00
		    strncmp(p->p_name,
			    "camerad",
			    sizeof (p->p_name)) == 0 ||
#endif
		    strncmp(p->p_name,
			    "testCamera",
			    sizeof (p->p_name)) == 0) {
			task_set_could_use_secluded_mem(task, TRUE);
		} else {
			task_set_could_use_secluded_mem(task, FALSE);
		}
		if (strncmp(p->p_name,
			    "mediaserverd",
			    sizeof (p->p_name)) == 0) {
			task_set_could_also_use_secluded_mem(task, TRUE);
		}
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	pal_dbg_set_task_name( task );

#if DEVELOPMENT || DEBUG
	/* 
	 * Update the pid an proc name for importance base if any
	 */
	task_importance_update_owner_info(task);
#endif

	memcpy(&p->p_uuid[0], &load_result.uuid[0], sizeof(p->p_uuid));

#if CONFIG_DTRACE
	dtrace_proc_exec(p);
#endif

	if (kdebug_enable) {
		long dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		/*
		 * Collect the pathname for tracing
		 */
		kdbg_trace_string(p, &dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

		KERNEL_DEBUG_CONSTANT1(TRACE_DATA_EXEC | DBG_FUNC_NONE,
				p->p_pid ,0,0,0, (uintptr_t)thread_tid(thread));
		KERNEL_DEBUG_CONSTANT1(TRACE_STRING_EXEC | DBG_FUNC_NONE,
				dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, (uintptr_t)thread_tid(thread));
	}

	/*
	 * If posix_spawned with the START_SUSPENDED flag, stop the
	 * process before it runs.
	 */
	if (imgp->ip_px_sa != NULL) {
		psa = (struct _posix_spawnattr *) imgp->ip_px_sa;
		if (psa->psa_flags & POSIX_SPAWN_START_SUSPENDED) {
			proc_lock(p);
			p->p_stat = SSTOP;
			proc_unlock(p);
			(void) task_suspend_internal(task);
		}
	}

	/*
	 * mark as execed, wakeup the process that vforked (if any) and tell
	 * it that it now has its own resources back
	 */
	OSBitOrAtomic(P_EXEC, &p->p_flag);
	proc_resetregister(p);
	if (p->p_pptr && (p->p_lflag & P_LPPWAIT)) {
		proc_lock(p);
		p->p_lflag &= ~P_LPPWAIT;
		proc_unlock(p);
		wakeup((caddr_t)p->p_pptr);
	}

	/*
	 * Pay for our earlier safety; deliver the delayed signals from
	 * the incomplete vfexec process now that it's complete.
	 */
	if (vfexec && (p->p_lflag & P_LTRACED)) {
		psignal_vfork(p, new_task, thread, SIGTRAP);
	}

	goto done;

badtoolate:
	/* Don't allow child process to execute any instructions */
	if (!spawn) {
		if (vfexec) {
			assert(exec_failure_reason != OS_REASON_NULL);
			psignal_vfork_with_reason(p, new_task, thread, SIGKILL, exec_failure_reason);
			exec_failure_reason = OS_REASON_NULL;
		} else {
			assert(exec_failure_reason != OS_REASON_NULL);
			psignal_with_reason(p, SIGKILL, exec_failure_reason);
			exec_failure_reason = OS_REASON_NULL;

			if (exec) {
				/* Terminate the exec copy task */
				task_terminate_internal(task);
			}
		}

		/* We can't stop this system call at this point, so just pretend we succeeded */
		error = 0;
	} else {
		os_reason_free(exec_failure_reason);
		exec_failure_reason = OS_REASON_NULL;
	}
	
done:
	if (!spawn) {
		/* notify only if it has not failed due to FP Key error */
		if ((p->p_lflag & P_LTERM_DECRYPTFAIL) == 0)
			proc_knote(p, NOTE_EXEC);
	}

	if (load_result.threadstate) {
		kfree(load_result.threadstate, load_result.threadstate_sz);
		load_result.threadstate = NULL;
	}

bad:
	/* If we hit this, we likely would have leaked an exit reason */
	assert(exec_failure_reason == OS_REASON_NULL);
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
 * exec_activate_image
 *
 * Description:	Iterate through the available image activators, and activate
 *		the image associated with the imgp structure.  We start with
 *		the
 *
 * Parameters:	struct image_params *	Image parameter block
 *
 * Returns:	0			Success
 *		EBADEXEC		The executable is corrupt/unknown
 *	execargs_alloc:EINVAL		Invalid argument
 *	execargs_alloc:EACCES		Permission denied
 *	execargs_alloc:EINTR		Interrupted function
 *	execargs_alloc:ENOMEM		Not enough space
 *	exec_save_path:EFAULT		Bad address
 *	exec_save_path:ENAMETOOLONG	Filename too long
 *	exec_check_permissions:EACCES	Permission denied
 *	exec_check_permissions:ENOEXEC	Executable file format error
 *	exec_check_permissions:ETXTBSY	Text file busy [misuse of error code]
 *	exec_check_permissions:???
 *	namei:???
 *	vn_rdwr:???			[anything vn_rdwr can return]
 *	<ex_imgact>:???			[anything an imgact can return]
 *	EDEADLK				Process is being terminated
 */
static int
exec_activate_image(struct image_params *imgp)
{
	struct nameidata *ndp = NULL;
	const char *excpath;
	int error;
	int resid;
	int once = 1;	/* save SGUID-ness for interpreted files */
	int i;
	int itercount = 0;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);

	error = execargs_alloc(imgp);
	if (error)
		goto bad_notrans;
	
	error = exec_save_path(imgp, imgp->ip_user_fname, imgp->ip_seg, &excpath);
	if (error) {
		goto bad_notrans;
	}

	/* Use excpath, which contains the copyin-ed exec path */
	DTRACE_PROC1(exec, uintptr_t, excpath);

	MALLOC(ndp, struct nameidata *, sizeof(*ndp), M_TEMP, M_WAITOK | M_ZERO);
	if (ndp == NULL) {
		error = ENOMEM;
		goto bad_notrans;
	}

	NDINIT(ndp, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
		   UIO_SYSSPACE, CAST_USER_ADDR_T(excpath), imgp->ip_vfs_context);

again:
	error = namei(ndp);
	if (error)
		goto bad_notrans;
	imgp->ip_ndp = ndp;	/* successful namei(); call nameidone() later */
	imgp->ip_vp = ndp->ni_vp;	/* if set, need to vnode_put() at some point */

	/*
	 * Before we start the transition from binary A to binary B, make
	 * sure another thread hasn't started exiting the process.  We grab
	 * the proc lock to check p_lflag initially, and the transition
	 * mechanism ensures that the value doesn't change after we release
	 * the lock.
	 */
	proc_lock(p);
	if (p->p_lflag & P_LEXIT) {
		error = EDEADLK;
		proc_unlock(p);
		goto bad_notrans;
	}
	error = proc_transstart(p, 1, 0);
	proc_unlock(p);
	if (error)
		goto bad_notrans;

	error = exec_check_permissions(imgp);
	if (error)
		goto bad;

	/* Copy; avoid invocation of an interpreter overwriting the original */
	if (once) {
		once = 0;
		*imgp->ip_origvattr = *imgp->ip_vattr;
	}

	error = vn_rdwr(UIO_READ, imgp->ip_vp, imgp->ip_vdata, PAGE_SIZE, 0,
			UIO_SYSSPACE, IO_NODELOCKED,
			vfs_context_ucred(imgp->ip_vfs_context),
			&resid, vfs_context_proc(imgp->ip_vfs_context));
	if (error)
		goto bad;

	if (resid) {
		memset(imgp->ip_vdata + (PAGE_SIZE - resid), 0x0, resid);
	}

encapsulated_binary:
	/* Limit the number of iterations we will attempt on each binary */
	if (++itercount > EAI_ITERLIMIT) {
		error = EBADEXEC;
		goto bad;
	}
	error = -1;
	for(i = 0; error == -1 && execsw[i].ex_imgact != NULL; i++) {

		error = (*execsw[i].ex_imgact)(imgp);

		switch (error) {
		/* case -1: not claimed: continue */
		case -2:		/* Encapsulated binary, imgp->ip_XXX set for next iteration */
			goto encapsulated_binary;

		case -3:		/* Interpreter */
#if CONFIG_MACF
			/*
			 * Copy the script label for later use. Note that
			 * the label can be different when the script is
			 * actually read by the interpreter.
			 */
			if (imgp->ip_scriptlabelp)
				mac_vnode_label_free(imgp->ip_scriptlabelp);
			imgp->ip_scriptlabelp = mac_vnode_label_alloc();
			if (imgp->ip_scriptlabelp == NULL) {
				error = ENOMEM;
				break;
			}
			mac_vnode_label_copy(imgp->ip_vp->v_label,
					     imgp->ip_scriptlabelp);

			/*
			 * Take a ref of the script vnode for later use.
			 */
			if (imgp->ip_scriptvp)
				vnode_put(imgp->ip_scriptvp);
			if (vnode_getwithref(imgp->ip_vp) == 0)
				imgp->ip_scriptvp = imgp->ip_vp;
#endif

			nameidone(ndp);

			vnode_put(imgp->ip_vp);
			imgp->ip_vp = NULL;	/* already put */
			imgp->ip_ndp = NULL; /* already nameidone */

			/* Use excpath, which exec_shell_imgact reset to the interpreter */
			NDINIT(ndp, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF,
				   UIO_SYSSPACE, CAST_USER_ADDR_T(excpath), imgp->ip_vfs_context);

			proc_transend(p, 0);
			goto again;

		default:
			break;
		}
	}

	/*
	 * Call out to allow 3rd party notification of exec. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
	if (error == 0 && kauth_authorize_fileop_has_listeners()) {
		kauth_authorize_fileop(vfs_context_ucred(imgp->ip_vfs_context),
					KAUTH_FILEOP_EXEC,
					(uintptr_t)ndp->ni_vp, 0);
	}
bad:
	proc_transend(p, 0);

bad_notrans:
	if (imgp->ip_strings)
		execargs_free(imgp);
	if (imgp->ip_ndp)
		nameidone(imgp->ip_ndp);
	if (ndp)
		FREE(ndp, M_TEMP);

	return (error);
}


/*
 * exec_handle_spawnattr_policy
 *
 * Description: Decode and apply the posix_spawn apptype, qos clamp, and watchport ports to the task.
 *
 * Parameters:  proc_t p                process to apply attributes to
 *              int psa_apptype         posix spawn attribute apptype
 *
 * Returns:     0                       Success
 */
static errno_t
exec_handle_spawnattr_policy(proc_t p, int psa_apptype, uint64_t psa_qos_clamp, uint64_t psa_darwin_role,
                             ipc_port_t * portwatch_ports, int portwatch_count)
{
	int apptype     = TASK_APPTYPE_NONE;
	int qos_clamp   = THREAD_QOS_UNSPECIFIED;
	int role        = TASK_UNSPECIFIED;

	if ((psa_apptype & POSIX_SPAWN_PROC_TYPE_MASK) != 0) {
		int proctype = psa_apptype & POSIX_SPAWN_PROC_TYPE_MASK;

		switch(proctype) {
			case POSIX_SPAWN_PROC_TYPE_DAEMON_INTERACTIVE:
				apptype = TASK_APPTYPE_DAEMON_INTERACTIVE;
				break;
			case POSIX_SPAWN_PROC_TYPE_DAEMON_STANDARD:
				apptype = TASK_APPTYPE_DAEMON_STANDARD;
				break;
			case POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE:
				apptype = TASK_APPTYPE_DAEMON_ADAPTIVE;
				break;
			case POSIX_SPAWN_PROC_TYPE_DAEMON_BACKGROUND:
				apptype = TASK_APPTYPE_DAEMON_BACKGROUND;
				break;
			case POSIX_SPAWN_PROC_TYPE_APP_DEFAULT:
				apptype = TASK_APPTYPE_APP_DEFAULT;
				break;
			case POSIX_SPAWN_PROC_TYPE_APP_TAL:
				apptype = TASK_APPTYPE_APP_TAL;
				break;
			default:
				apptype = TASK_APPTYPE_NONE;
				/* TODO: Should an invalid value here fail the spawn? */
				break;
		}
	}

	if (psa_qos_clamp != POSIX_SPAWN_PROC_CLAMP_NONE) {
		switch (psa_qos_clamp) {
			case POSIX_SPAWN_PROC_CLAMP_UTILITY:
				qos_clamp = THREAD_QOS_UTILITY;
				break;
			case POSIX_SPAWN_PROC_CLAMP_BACKGROUND:
				qos_clamp = THREAD_QOS_BACKGROUND;
				break;
			case POSIX_SPAWN_PROC_CLAMP_MAINTENANCE:
				qos_clamp = THREAD_QOS_MAINTENANCE;
				break;
			default:
				qos_clamp = THREAD_QOS_UNSPECIFIED;
				/* TODO: Should an invalid value here fail the spawn? */
				break;
		}
	}

	if (psa_darwin_role != PRIO_DARWIN_ROLE_DEFAULT) {
		proc_darwin_role_to_task_role(psa_darwin_role, &role);
	}

	if (apptype   != TASK_APPTYPE_NONE      ||
	    qos_clamp != THREAD_QOS_UNSPECIFIED ||
	    role      != TASK_UNSPECIFIED) {
		proc_set_task_spawnpolicy(p->task, apptype, qos_clamp, role,
		                          portwatch_ports, portwatch_count);
	}

	return (0);
}


/*
 * exec_handle_port_actions
 *
 * Description:	Go through the _posix_port_actions_t contents, 
 * 		calling task_set_special_port, task_set_exception_ports
 * 		and/or audit_session_spawnjoin for the current task.
 *
 * Parameters:	struct image_params *	Image parameter block
 *
 * Returns:	0			Success
 * 		EINVAL			Failure
 * 		ENOTSUP			Illegal posix_spawn attr flag was set
 */
static errno_t
exec_handle_port_actions(struct image_params *imgp, boolean_t * portwatch_present,
                         ipc_port_t * portwatch_ports)
{
	_posix_spawn_port_actions_t pacts = imgp->ip_px_spa;
#if CONFIG_AUDIT
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
#endif
	_ps_port_action_t *act = NULL;
	task_t task = get_threadtask(imgp->ip_new_thread);
	ipc_port_t port = NULL;
	errno_t ret = 0;
	int i;
	kern_return_t kr;

	*portwatch_present = FALSE;

	for (i = 0; i < pacts->pspa_count; i++) {
		act = &pacts->pspa_actions[i];

		if (MACH_PORT_VALID(act->new_port)) {
			kr = ipc_object_copyin(get_task_ipcspace(current_task()),
			                       act->new_port, MACH_MSG_TYPE_COPY_SEND,
			                       (ipc_object_t *) &port);

			if (kr != KERN_SUCCESS) {
				ret = EINVAL;
				goto done;
			}
		} else {
			/* it's NULL or DEAD */
			port = CAST_MACH_NAME_TO_PORT(act->new_port);
		}

		switch (act->port_type) {
		case PSPA_SPECIAL:
			kr = task_set_special_port(task, act->which, port);

			if (kr != KERN_SUCCESS)
				ret = EINVAL;
			break;

		case PSPA_EXCEPTION:
			kr = task_set_exception_ports(task, act->mask, port,
			                              act->behavior, act->flavor);
			if (kr != KERN_SUCCESS)
				ret = EINVAL;
			break;
#if CONFIG_AUDIT
		case PSPA_AU_SESSION:
			ret = audit_session_spawnjoin(p, task, port);
			if (ret) {
				/* audit_session_spawnjoin() has already dropped the reference in case of error. */
				goto done;
			}

			break;
#endif
		case PSPA_IMP_WATCHPORTS:
			if (portwatch_ports != NULL && IPC_PORT_VALID(port)) {
				*portwatch_present = TRUE;
				/* hold on to this till end of spawn */
				portwatch_ports[i] = port;
			} else {
				ipc_port_release_send(port);
			}

			break;
		default:
			ret = EINVAL;
			break;
		}

		if (ret) {
			/* action failed, so release port resources */
			ipc_port_release_send(port);
			break;
		}
	}

done:
	if (0 != ret)
		DTRACE_PROC1(spawn__port__failure, mach_port_name_t, act->new_port);
	return (ret);
}

/*
 * exec_handle_file_actions
 *
 * Description:	Go through the _posix_file_actions_t contents applying the
 *		open, close, and dup2 operations to the open file table for
 *		the current process.
 *
 * Parameters:	struct image_params *	Image parameter block
 *
 * Returns:	0			Success
 *		???
 *
 * Note:	Actions are applied in the order specified, with the credential
 *		of the parent process.  This is done to permit the parent
 *		process to utilize POSIX_SPAWN_RESETIDS to drop privilege in
 *		the child following operations the child may in fact not be
 *		normally permitted to perform.
 */
static int
exec_handle_file_actions(struct image_params *imgp, short psa_flags)
{
	int error = 0;
	int action;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	_posix_spawn_file_actions_t px_sfap = imgp->ip_px_sfa;
	int ival[2];		/* dummy retval for system calls) */

	for (action = 0; action < px_sfap->psfa_act_count; action++) {
		_psfa_action_t *psfa = &px_sfap->psfa_act_acts[ action];

		switch(psfa->psfaa_type) {
		case PSFA_OPEN: {
			/*
			 * Open is different, in that it requires the use of
			 * a path argument, which is normally copied in from
			 * user space; because of this, we have to support an
			 * open from kernel space that passes an address space
			 * context of UIO_SYSSPACE, and casts the address
			 * argument to a user_addr_t.
			 */
			char *bufp = NULL;
			struct vnode_attr *vap;
			struct nameidata *ndp;
			int mode = psfa->psfaa_openargs.psfao_mode;
			struct dup2_args dup2a;
			struct close_nocancel_args ca;
			int origfd;

			MALLOC(bufp, char *, sizeof(*vap) + sizeof(*ndp), M_TEMP, M_WAITOK | M_ZERO);
			if (bufp == NULL) {
				error = ENOMEM;
				break;
			}

			vap = (struct vnode_attr *) bufp;
			ndp = (struct nameidata *) (bufp + sizeof(*vap));

			VATTR_INIT(vap);
			/* Mask off all but regular access permissions */
			mode = ((mode &~ p->p_fd->fd_cmask) & ALLPERMS) & ~S_ISTXT;
			VATTR_SET(vap, va_mode, mode & ACCESSPERMS);

			NDINIT(ndp, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(psfa->psfaa_openargs.psfao_path),
			       imgp->ip_vfs_context);

			error = open1(imgp->ip_vfs_context, 
					ndp,
					psfa->psfaa_openargs.psfao_oflag,
					vap,
					fileproc_alloc_init, NULL,
					ival);

			FREE(bufp, M_TEMP);

			/*
			 * If there's an error, or we get the right fd by
			 * accident, then drop out here.  This is easier than
			 * reworking all the open code to preallocate fd
			 * slots, and internally taking one as an argument.
			 */
			if (error || ival[0] == psfa->psfaa_filedes)
				break;

			origfd = ival[0];
			/*
			 * If we didn't fall out from an error, we ended up
			 * with the wrong fd; so now we've got to try to dup2
			 * it to the right one.
			 */
			dup2a.from = origfd;
			dup2a.to = psfa->psfaa_filedes;

			/*
			 * The dup2() system call implementation sets
			 * ival to newfd in the success case, but we
			 * can ignore that, since if we didn't get the
			 * fd we wanted, the error will stop us.
			 */
			error = dup2(p, &dup2a, ival);
			if (error)
				break;

			/*
			 * Finally, close the original fd.
			 */
			ca.fd = origfd;

			error = close_nocancel(p, &ca, ival);
			}
			break;

		case PSFA_DUP2: {
			struct dup2_args dup2a;

			dup2a.from = psfa->psfaa_filedes;
			dup2a.to = psfa->psfaa_openargs.psfao_oflag;

			/*
			 * The dup2() system call implementation sets
			 * ival to newfd in the success case, but we
			 * can ignore that, since if we didn't get the
			 * fd we wanted, the error will stop us.
			 */
			error = dup2(p, &dup2a, ival);
			}
			break;

		case PSFA_CLOSE: {
			struct close_nocancel_args ca;

			ca.fd = psfa->psfaa_filedes;

			error = close_nocancel(p, &ca, ival);
			}
			break;

		case PSFA_INHERIT: {
			struct fcntl_nocancel_args fcntla;

			/*
			 * Check to see if the descriptor exists, and
			 * ensure it's -not- marked as close-on-exec.
			 *
			 * Attempting to "inherit" a guarded fd will
			 * result in a error.
			 */
			fcntla.fd = psfa->psfaa_filedes;
			fcntla.cmd = F_GETFD;
			if ((error = fcntl_nocancel(p, &fcntla, ival)) != 0)
				break;

			if ((ival[0] & FD_CLOEXEC) == FD_CLOEXEC) {
				fcntla.fd = psfa->psfaa_filedes;
				fcntla.cmd = F_SETFD;
				fcntla.arg = ival[0] & ~FD_CLOEXEC;
				error = fcntl_nocancel(p, &fcntla, ival);
			}

			}
			break;

		default:
			error = EINVAL;
			break;
		}

		/* All file actions failures are considered fatal, per POSIX */

		if (error) {
			if (PSFA_OPEN == psfa->psfaa_type) {
				DTRACE_PROC1(spawn__open__failure, uintptr_t,
			            psfa->psfaa_openargs.psfao_path);
			} else {
				DTRACE_PROC1(spawn__fd__failure, int, psfa->psfaa_filedes);
			}
			break;
		}
	}

	if (error != 0 || (psa_flags & POSIX_SPAWN_CLOEXEC_DEFAULT) == 0)
		return (error);

	/*
	 * If POSIX_SPAWN_CLOEXEC_DEFAULT is set, behave (during
	 * this spawn only) as if "close on exec" is the default
	 * disposition of all pre-existing file descriptors.  In this case,
	 * the list of file descriptors mentioned in the file actions
	 * are the only ones that can be inherited, so mark them now.
	 *
	 * The actual closing part comes later, in fdexec().
	 */
	proc_fdlock(p);
	for (action = 0; action < px_sfap->psfa_act_count; action++) {
		_psfa_action_t *psfa = &px_sfap->psfa_act_acts[action];
		int fd = psfa->psfaa_filedes;

		switch (psfa->psfaa_type) {
		case PSFA_DUP2:
			fd = psfa->psfaa_openargs.psfao_oflag;
			/*FALLTHROUGH*/
		case PSFA_OPEN:
		case PSFA_INHERIT:
			*fdflags(p, fd) |= UF_INHERIT;
			break;

		case PSFA_CLOSE:
			break;
		}
	}
	proc_fdunlock(p);

	return (0);
}

#if CONFIG_MACF
/*
 * exec_spawnattr_getmacpolicyinfo
 */
void *
exec_spawnattr_getmacpolicyinfo(const void *macextensions, const char *policyname, size_t *lenp)
{
	const struct _posix_spawn_mac_policy_extensions *psmx = macextensions;
	int i;

	if (psmx == NULL)
		return NULL;

	for (i = 0; i < psmx->psmx_count; i++) {
		const _ps_mac_policy_extension_t *extension = &psmx->psmx_extensions[i];
		if (strncmp(extension->policyname, policyname, sizeof(extension->policyname)) == 0) {
			if (lenp != NULL)
				*lenp = extension->datalen;
			return extension->datap;
		}
	}

	if (lenp != NULL)
		*lenp = 0;
	return NULL;
}

static int
spawn_copyin_macpolicyinfo(const struct user__posix_spawn_args_desc *px_args, _posix_spawn_mac_policy_extensions_t *psmxp)
{
	_posix_spawn_mac_policy_extensions_t psmx = NULL;
	int error = 0;
	int copycnt = 0;
	int i = 0;

	*psmxp = NULL;

	if (px_args->mac_extensions_size < PS_MAC_EXTENSIONS_SIZE(1) ||
	    px_args->mac_extensions_size > PAGE_SIZE) {
		error = EINVAL;
		goto bad;
	}

	MALLOC(psmx, _posix_spawn_mac_policy_extensions_t, px_args->mac_extensions_size, M_TEMP, M_WAITOK);
	if ((error = copyin(px_args->mac_extensions, psmx, px_args->mac_extensions_size)) != 0)
		goto bad;

	if (PS_MAC_EXTENSIONS_SIZE(psmx->psmx_count) > px_args->mac_extensions_size) {
		error = EINVAL;
		goto bad;
	}

	for (i = 0; i < psmx->psmx_count; i++) {
		_ps_mac_policy_extension_t *extension = &psmx->psmx_extensions[i];
		if (extension->datalen == 0 || extension->datalen > PAGE_SIZE) {
			error = EINVAL;
			goto bad;
		}
	}

	for (copycnt = 0; copycnt < psmx->psmx_count; copycnt++) {
		_ps_mac_policy_extension_t *extension = &psmx->psmx_extensions[copycnt];
		void *data = NULL;

		MALLOC(data, void *, extension->datalen, M_TEMP, M_WAITOK);
		if ((error = copyin(extension->data, data, extension->datalen)) != 0) {
			FREE(data, M_TEMP);
			goto bad;
		}
		extension->datap = data;
	}

	*psmxp = psmx;
	return 0;

bad:
	if (psmx != NULL) {
		for (i = 0; i < copycnt; i++)
			FREE(psmx->psmx_extensions[i].datap, M_TEMP);
		FREE(psmx, M_TEMP);
	}
	return error;
}

static void
spawn_free_macpolicyinfo(_posix_spawn_mac_policy_extensions_t psmx)
{
	int i;

	if (psmx == NULL)
		return;
	for (i = 0; i < psmx->psmx_count; i++)
		FREE(psmx->psmx_extensions[i].datap, M_TEMP);
	FREE(psmx, M_TEMP);
}
#endif /* CONFIG_MACF */

#if CONFIG_COALITIONS
static inline void spawn_coalitions_release_all(coalition_t coal[COALITION_NUM_TYPES])
{
	for (int c = 0; c < COALITION_NUM_TYPES; c++) {
		if (coal[c]) {
			coalition_remove_active(coal[c]);
			coalition_release(coal[c]);
		}
	}
}
#endif

#if CONFIG_PERSONAS
static int spawn_validate_persona(struct _posix_spawn_persona_info *px_persona)
{
	int error = 0;
	struct persona *persona = NULL;
	int verify = px_persona->pspi_flags & POSIX_SPAWN_PERSONA_FLAGS_VERIFY;

	/*
	 * TODO: rdar://problem/19981151
	 * Add entitlement check!
	 */
	if (!kauth_cred_issuser(kauth_cred_get()))
		return EPERM;

	persona = persona_lookup(px_persona->pspi_id);
	if (!persona) {
		error = ESRCH;
		goto out;
	}

	if (verify) {
		if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_UID) {
			if (px_persona->pspi_uid != persona_get_uid(persona)) {
				error = EINVAL;
				goto out;
			}
		}
		if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_GID) {
			if (px_persona->pspi_gid != persona_get_gid(persona)) {
				error = EINVAL;
				goto out;
			}
		}
		if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_GROUPS) {
			int ngroups = 0;
			gid_t groups[NGROUPS_MAX];

			if (persona_get_groups(persona, &ngroups, groups,
					       px_persona->pspi_ngroups) != 0) {
				error = EINVAL;
				goto out;
			}
			if (ngroups != (int)px_persona->pspi_ngroups) {
				error = EINVAL;
				goto out;
			}
			while (ngroups--) {
				if (px_persona->pspi_groups[ngroups] != groups[ngroups]) {
					error = EINVAL;
					goto out;
				}
			}
			if (px_persona->pspi_gmuid != persona_get_gmuid(persona)) {
				error = EINVAL;
				goto out;
			}
		}
	}

out:
	if (persona)
		persona_put(persona);

	return error;
}

static int spawn_persona_adopt(proc_t p, struct _posix_spawn_persona_info *px_persona)
{
	int ret;
	kauth_cred_t cred;
	struct persona *persona = NULL;
	int override = !!(px_persona->pspi_flags & POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);

	if (!override)
		return persona_proc_adopt_id(p, px_persona->pspi_id, NULL);

	/*
	 * we want to spawn into the given persona, but we want to override
	 * the kauth with a different UID/GID combo
	 */
	persona = persona_lookup(px_persona->pspi_id);
	if (!persona)
		return ESRCH;

	cred = persona_get_cred(persona);
	if (!cred) {
		ret = EINVAL;
		goto out;
	}

	if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_UID) {
		cred = kauth_cred_setresuid(cred,
					    px_persona->pspi_uid,
					    px_persona->pspi_uid,
					    px_persona->pspi_uid,
					    KAUTH_UID_NONE);
	}

	if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_GID) {
		cred = kauth_cred_setresgid(cred,
					    px_persona->pspi_gid,
					    px_persona->pspi_gid,
					    px_persona->pspi_gid);
	}

	if (px_persona->pspi_flags & POSIX_SPAWN_PERSONA_GROUPS) {
		cred = kauth_cred_setgroups(cred,
					    px_persona->pspi_groups,
					    px_persona->pspi_ngroups,
					    px_persona->pspi_gmuid);
	}

	ret = persona_proc_adopt(p, persona, cred);

out:
	persona_put(persona);
	return ret;
}
#endif

/*
 * posix_spawn
 *
 * Parameters:	uap->pid		Pointer to pid return area
 *		uap->fname		File name to exec
 *		uap->argp		Argument list
 *		uap->envp		Environment list
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		ENOTSUP			Not supported
 *		ENOEXEC			Executable file format error
 *	exec_activate_image:EINVAL	Invalid argument
 *	exec_activate_image:EACCES	Permission denied
 *	exec_activate_image:EINTR	Interrupted function
 *	exec_activate_image:ENOMEM	Not enough space
 *	exec_activate_image:EFAULT	Bad address
 *	exec_activate_image:ENAMETOOLONG	Filename too long
 *	exec_activate_image:ENOEXEC	Executable file format error
 *	exec_activate_image:ETXTBSY	Text file busy [misuse of error code]
 *	exec_activate_image:EBADEXEC	The executable is corrupt/unknown
 *	exec_activate_image:???
 *	mac_execve_enter:???
 *
 * TODO:	Expect to need __mac_posix_spawn() at some point...
 *		Handle posix_spawnattr_t
 *		Handle posix_spawn_file_actions_t
 */
int
posix_spawn(proc_t ap, struct posix_spawn_args *uap, int32_t *retval)
{
	proc_t p = ap;		/* quiet bogus GCC vfork() warning */
	user_addr_t pid = uap->pid;
	int ival[2];		/* dummy retval for setpgid() */
	char *bufp = NULL; 
	struct image_params *imgp;
	struct vnode_attr *vap;
	struct vnode_attr *origvap;
	struct uthread	*uthread = 0;	/* compiler complains if not set to 0*/
	int error, sig;
	int is_64 = IS_64BIT_PROCESS(p);
	struct vfs_context context;
	struct user__posix_spawn_args_desc px_args;
	struct _posix_spawnattr px_sa;
	_posix_spawn_file_actions_t px_sfap = NULL;
	_posix_spawn_port_actions_t px_spap = NULL;
	struct __kern_sigaction vec;
	boolean_t spawn_no_exec = FALSE;
	boolean_t proc_transit_set = TRUE;
	boolean_t exec_done = FALSE;
	int portwatch_count = 0;
	ipc_port_t * portwatch_ports = NULL;
	vm_size_t px_sa_offset = offsetof(struct _posix_spawnattr, psa_ports);
	task_t new_task = NULL;
	boolean_t should_release_proc_ref = FALSE;
	void *inherit = NULL;
#if CONFIG_PERSONAS
	struct _posix_spawn_persona_info *px_persona = NULL;
#endif

	/*
	 * Allocate a big chunk for locals instead of using stack since these  
	 * structures are pretty big.
	 */
	MALLOC(bufp, char *, (sizeof(*imgp) + sizeof(*vap) + sizeof(*origvap)), M_TEMP, M_WAITOK | M_ZERO);
	imgp = (struct image_params *) bufp;
	if (bufp == NULL) {
		error = ENOMEM;
		goto bad;
	}
	vap = (struct vnode_attr *) (bufp + sizeof(*imgp));
	origvap = (struct vnode_attr *) (bufp + sizeof(*imgp) + sizeof(*vap));

	/* Initialize the common data in the image_params structure */
	imgp->ip_user_fname = uap->path;
	imgp->ip_user_argv = uap->argv;
	imgp->ip_user_envv = uap->envp;
	imgp->ip_vattr = vap;
	imgp->ip_origvattr = origvap;
	imgp->ip_vfs_context = &context;
	imgp->ip_flags = (is_64 ? IMGPF_WAS_64BIT : IMGPF_NONE);
	imgp->ip_seg = (is_64 ? UIO_USERSPACE64 : UIO_USERSPACE32);
	imgp->ip_mac_return = 0;
	imgp->ip_px_persona = NULL;
	imgp->ip_cs_error = OS_REASON_NULL;

	if (uap->adesc != USER_ADDR_NULL) {
		if(is_64) {
			error = copyin(uap->adesc, &px_args, sizeof(px_args));
		} else {
			struct user32__posix_spawn_args_desc px_args32;

			error = copyin(uap->adesc, &px_args32, sizeof(px_args32));

			/*
			 * Convert arguments descriptor from external 32 bit
			 * representation to internal 64 bit representation
			 */
			px_args.attr_size = px_args32.attr_size;
			px_args.attrp = CAST_USER_ADDR_T(px_args32.attrp);
			px_args.file_actions_size = px_args32.file_actions_size;
			px_args.file_actions = CAST_USER_ADDR_T(px_args32.file_actions);
			px_args.port_actions_size = px_args32.port_actions_size;
			px_args.port_actions = CAST_USER_ADDR_T(px_args32.port_actions);
			px_args.mac_extensions_size = px_args32.mac_extensions_size;
			px_args.mac_extensions = CAST_USER_ADDR_T(px_args32.mac_extensions);
			px_args.coal_info_size = px_args32.coal_info_size;
			px_args.coal_info = CAST_USER_ADDR_T(px_args32.coal_info);
			px_args.persona_info_size = px_args32.persona_info_size;
			px_args.persona_info = CAST_USER_ADDR_T(px_args32.persona_info);
		}
		if (error)
			goto bad;

		if (px_args.attr_size != 0) {
			/* 
			 * We are not copying the port_actions pointer, 
			 * because we already have it from px_args. 
			 * This is a bit fragile: <rdar://problem/16427422>
			 */

			if ((error = copyin(px_args.attrp, &px_sa, px_sa_offset) != 0)) 
			goto bad;
		
			bzero( (void *)( (unsigned long) &px_sa + px_sa_offset), sizeof(px_sa) - px_sa_offset );  	

			imgp->ip_px_sa = &px_sa;
		}
		if (px_args.file_actions_size != 0) {
			/* Limit file_actions to allowed number of open files */
			int maxfa = (p->p_limit ? p->p_rlimit[RLIMIT_NOFILE].rlim_cur : NOFILE);
			if (px_args.file_actions_size < PSF_ACTIONS_SIZE(1) ||
				px_args.file_actions_size > PSF_ACTIONS_SIZE(maxfa)) {
				error = EINVAL;
				goto bad;
			}
			MALLOC(px_sfap, _posix_spawn_file_actions_t, px_args.file_actions_size, M_TEMP, M_WAITOK);
			if (px_sfap == NULL) {
				error = ENOMEM;
				goto bad;
			}
			imgp->ip_px_sfa = px_sfap;

			if ((error = copyin(px_args.file_actions, px_sfap, 
							px_args.file_actions_size)) != 0)
				goto bad;

			/* Verify that the action count matches the struct size */
			if (PSF_ACTIONS_SIZE(px_sfap->psfa_act_count) != px_args.file_actions_size) {
				error = EINVAL;
				goto bad;
			}
		}
		if (px_args.port_actions_size != 0) {
			/* Limit port_actions to one page of data */
			if (px_args.port_actions_size < PS_PORT_ACTIONS_SIZE(1) ||
				px_args.port_actions_size > PAGE_SIZE) {
				error = EINVAL;
				goto bad;
			}

			MALLOC(px_spap, _posix_spawn_port_actions_t, 
					px_args.port_actions_size, M_TEMP, M_WAITOK);
			if (px_spap == NULL) {
				error = ENOMEM;
				goto bad;
			}
			imgp->ip_px_spa = px_spap;

			if ((error = copyin(px_args.port_actions, px_spap, 
							px_args.port_actions_size)) != 0)
				goto bad;

			/* Verify that the action count matches the struct size */
			if (PS_PORT_ACTIONS_SIZE(px_spap->pspa_count) != px_args.port_actions_size) {
				error = EINVAL;
				goto bad;
			}
		}
#if CONFIG_PERSONAS
		/* copy in the persona info */
		if (px_args.persona_info_size != 0 && px_args.persona_info != 0) {
			/* for now, we need the exact same struct in user space */
			if (px_args.persona_info_size != sizeof(*px_persona)) {
				error = ERANGE;
				goto bad;
			}

			MALLOC(px_persona, struct _posix_spawn_persona_info *, px_args.persona_info_size, M_TEMP, M_WAITOK|M_ZERO);
			if (px_persona == NULL) {
				error = ENOMEM;
				goto bad;
			}
			imgp->ip_px_persona = px_persona;

			if ((error = copyin(px_args.persona_info, px_persona,
					    px_args.persona_info_size)) != 0)
				goto bad;
			if ((error = spawn_validate_persona(px_persona)) != 0)
				goto bad;
		}
#endif
#if CONFIG_MACF
		if (px_args.mac_extensions_size != 0) {
			if ((error = spawn_copyin_macpolicyinfo(&px_args, (_posix_spawn_mac_policy_extensions_t *)&imgp->ip_px_smpx)) != 0)
				goto bad;
		}
#endif /* CONFIG_MACF */
	}

	/* set uthread to parent */
	uthread = get_bsdthread_info(current_thread());

	/*
	 * <rdar://6640530>; this does not result in a behaviour change
	 * relative to Leopard, so there should not be any existing code
	 * which depends on it.
	 */
	if (uthread->uu_flag & UT_VFORK) {
	    error = EINVAL;
	    goto bad;
	}

	/*
	 * If we don't have the extension flag that turns "posix_spawn()"
	 * into "execve() with options", then we will be creating a new
	 * process which does not inherit memory from the parent process,
	 * which is one of the most expensive things about using fork()
	 * and execve().
	 */
	if (imgp->ip_px_sa == NULL || !(px_sa.psa_flags & POSIX_SPAWN_SETEXEC)){

		/* Set the new task's coalition, if it is requested.  */
		coalition_t coal[COALITION_NUM_TYPES] = { COALITION_NULL };
#if CONFIG_COALITIONS
		int i, ncoals;
		kern_return_t kr = KERN_SUCCESS;
		struct _posix_spawn_coalition_info coal_info;
		int coal_role[COALITION_NUM_TYPES];

		if (imgp->ip_px_sa == NULL || !px_args.coal_info)
			goto do_fork1;

		memset(&coal_info, 0, sizeof(coal_info));

		if (px_args.coal_info_size > sizeof(coal_info))
			px_args.coal_info_size = sizeof(coal_info);
		error = copyin(px_args.coal_info,
			       &coal_info, px_args.coal_info_size);
		if (error != 0)
			goto bad;

		ncoals = 0;
		for (i = 0; i < COALITION_NUM_TYPES; i++) {
			uint64_t cid = coal_info.psci_info[i].psci_id;
			if (cid != 0) {
				/*
				 * don't allow tasks which are not in a
				 * privileged coalition to spawn processes
				 * into coalitions other than their own
				 */
				if (!task_is_in_privileged_coalition(p->task, i)) {
					coal_dbg("ERROR: %d not in privilegd "
						 "coalition of type %d",
						 p->p_pid, i);
					spawn_coalitions_release_all(coal);
					error = EPERM;
					goto bad;
				}

				coal_dbg("searching for coalition id:%llu", cid);
				/*
				 * take a reference and activation on the
				 * coalition to guard against free-while-spawn
				 * races
				 */
				coal[i] = coalition_find_and_activate_by_id(cid);
				if (coal[i] == COALITION_NULL) {
					coal_dbg("could not find coalition id:%llu "
						 "(perhaps it has been terminated or reaped)", cid);
					/*
					 * release any other coalition's we
					 * may have a reference to
					 */
					spawn_coalitions_release_all(coal);
					error = ESRCH;
					goto bad;
				}
				if (coalition_type(coal[i]) != i) {
					coal_dbg("coalition with id:%lld is not of type:%d"
						 " (it's type:%d)", cid, i, coalition_type(coal[i]));
					error = ESRCH;
					goto bad;
				}
				coal_role[i] = coal_info.psci_info[i].psci_role;
				ncoals++;
			}
		}
		if (ncoals < COALITION_NUM_TYPES) {
			/*
			 * If the user is attempting to spawn into a subset of
			 * the known coalition types, then make sure they have
			 * _at_least_ specified a resource coalition. If not,
			 * the following fork1() call will implicitly force an
			 * inheritance from 'p' and won't actually spawn the
			 * new task into the coalitions the user specified.
			 * (also the call to coalitions_set_roles will panic)
			 */
			if (coal[COALITION_TYPE_RESOURCE] == COALITION_NULL) {
				spawn_coalitions_release_all(coal);
				error = EINVAL;
				goto bad;
			}
		}
do_fork1:
#endif /* CONFIG_COALITIONS */

		/*
		 * note that this will implicitly inherit the
		 * caller's persona (if it exists)
		 */
		error = fork1(p, &imgp->ip_new_thread, PROC_CREATE_SPAWN, coal);
		/* returns a thread and task reference */

		if (error == 0) {
			new_task = get_threadtask(imgp->ip_new_thread);
		}
#if CONFIG_COALITIONS
		/* set the roles of this task within each given coalition */
		if (error == 0) {
			kr = coalitions_set_roles(coal, get_threadtask(imgp->ip_new_thread), coal_role);
			if (kr != KERN_SUCCESS)
				error = EINVAL;
		}

		/* drop our references and activations - fork1() now holds them */
		spawn_coalitions_release_all(coal);
#endif /* CONFIG_COALITIONS */
		if (error != 0) {
			goto bad;
		}
		imgp->ip_flags |= IMGPF_SPAWN;	/* spawn w/o exec */
		spawn_no_exec = TRUE;		/* used in later tests */

#if CONFIG_PERSONAS
		/*
		 * If the parent isn't in a persona (launchd), and
		 * hasn't specified a new persona for the process,
		 * then we'll put the process into the system persona
		 *
		 * TODO: this will have to be re-worked because as of
		 *       now, without any launchd adoption, the resulting
		 *       xpcproxy process will not have sufficient
		 *       privileges to setuid/gid.
		 */
#if 0
		if (!proc_has_persona(p) && imgp->ip_px_persona == NULL) {
			MALLOC(px_persona, struct _posix_spawn_persona_info *,
			       sizeof(*px_persona), M_TEMP, M_WAITOK|M_ZERO);
			if (px_persona == NULL) {
				error = ENOMEM;
				goto bad;
			}
			px_persona->pspi_id = persona_get_id(g_system_persona);
			imgp->ip_px_persona = px_persona;
		}
#endif /* 0 */
#endif /* CONFIG_PERSONAS */
	} else {
		/*
		 * For execve case, create a new task and thread
		 * which points to current_proc. The current_proc will point
		 * to the new task after image activation and proc ref drain.
		 *
		 * proc (current_proc) <-----  old_task (current_task)
		 *  ^ |                                ^
		 *  | |                                |
		 *  | ----------------------------------
		 *  |
		 *  --------- new_task (task marked as TF_EXEC_COPY)
		 *
		 * After image activation, the proc will point to the new task
		 * and would look like following.
		 *
		 * proc (current_proc)  <-----  old_task (current_task, marked as TPF_DID_EXEC)
		 *  ^ |
		 *  | |
		 *  | ----------> new_task
		 *  |               |
		 *  -----------------
		 *
		 * During exec any transition from new_task -> proc is fine, but don't allow
		 * transition from proc->task, since it will modify old_task.
		 */
		imgp->ip_new_thread = fork_create_child(current_task(),
					NULL, p, FALSE, p->p_flag & P_LP64, TRUE);
		/* task and thread ref returned by fork_create_child */
		if (imgp->ip_new_thread == NULL) {
			error = ENOMEM;
			goto bad;
		}

		new_task = get_threadtask(imgp->ip_new_thread);
		imgp->ip_flags |= IMGPF_EXEC;
	}

	if (spawn_no_exec) {
		p = (proc_t)get_bsdthreadtask_info(imgp->ip_new_thread);
		
		/*
		 * We had to wait until this point before firing the
		 * proc:::create probe, otherwise p would not point to the
		 * child process.
		 */
		DTRACE_PROC1(create, proc_t, p);
	}
	assert(p != NULL);

	context.vc_thread = imgp->ip_new_thread;
	context.vc_ucred = p->p_ucred;	/* XXX must NOT be kauth_cred_get() */

	/*
	 * Post fdcopy(), pre exec_handle_sugid() - this is where we want
	 * to handle the file_actions.  Since vfork() also ends up setting
	 * us into the parent process group, and saved off the signal flags,
	 * this is also where we want to handle the spawn flags.
	 */

	/* Has spawn file actions? */
	if (imgp->ip_px_sfa != NULL) {
		/*
		 * The POSIX_SPAWN_CLOEXEC_DEFAULT flag
		 * is handled in exec_handle_file_actions().
		 */
		if ((error = exec_handle_file_actions(imgp,
		    imgp->ip_px_sa != NULL ? px_sa.psa_flags : 0)) != 0)
			goto bad;
	}

	/* Has spawn port actions? */
	if (imgp->ip_px_spa != NULL) {
		boolean_t is_adaptive = FALSE;
		boolean_t portwatch_present = FALSE;

		/* Will this process become adaptive? The apptype isn't ready yet, so we can't look there. */
		if (imgp->ip_px_sa != NULL && px_sa.psa_apptype == POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE)
			is_adaptive = TRUE;

		/*
		 * portwatch only:
		 * Allocate a place to store the ports we want to bind to the new task
		 * We can't bind them until after the apptype is set.
		 */
		if (px_spap->pspa_count != 0 && is_adaptive) {
			portwatch_count = px_spap->pspa_count;
			MALLOC(portwatch_ports, ipc_port_t *, (sizeof(ipc_port_t) * portwatch_count), M_TEMP, M_WAITOK | M_ZERO);
		} else {
			portwatch_ports = NULL;
		}

		if ((error = exec_handle_port_actions(imgp, &portwatch_present, portwatch_ports)) != 0)
			goto bad;

		if (portwatch_present == FALSE && portwatch_ports != NULL) {
			FREE(portwatch_ports, M_TEMP);
			portwatch_ports = NULL;
			portwatch_count = 0;
		}
	}

	/* Has spawn attr? */
	if (imgp->ip_px_sa != NULL) {
		/*
		 * Set the process group ID of the child process; this has
		 * to happen before the image activation.
		 */
		if (px_sa.psa_flags & POSIX_SPAWN_SETPGROUP) {
			struct setpgid_args spga;
			spga.pid = p->p_pid;
			spga.pgid = px_sa.psa_pgroup;
			/*
			 * Effectively, call setpgid() system call; works
			 * because there are no pointer arguments.
			 */
			if((error = setpgid(p, &spga, ival)) != 0)
				goto bad;
		}

		/*
		 * Reset UID/GID to parent's RUID/RGID; This works only
		 * because the operation occurs *after* the vfork() and
		 * before the call to exec_handle_sugid() by the image
		 * activator called from exec_activate_image().  POSIX
		 * requires that any setuid/setgid bits on the process
		 * image will take precedence over the spawn attributes
		 * (re)setting them.
		 *
		 * Modifications to p_ucred must be guarded using the
		 * proc's ucred lock. This prevents others from accessing
		 * a garbage credential.
		 */
		while (px_sa.psa_flags & POSIX_SPAWN_RESETIDS) {
			kauth_cred_t my_cred = kauth_cred_proc_ref(p);
			kauth_cred_t my_new_cred = kauth_cred_setuidgid(my_cred, kauth_cred_getruid(my_cred), kauth_cred_getrgid(my_cred));

			if (my_cred == my_new_cred) {
				kauth_cred_unref(&my_cred);
				break;
			}

			/* update cred on proc */
			proc_ucred_lock(p);

			if (p->p_ucred != my_cred) {
				proc_ucred_unlock(p);
				kauth_cred_unref(&my_new_cred);
				continue;
			}

			/* donate cred reference on my_new_cred to p->p_ucred */
			p->p_ucred = my_new_cred;
			PROC_UPDATE_CREDS_ONPROC(p);
			proc_ucred_unlock(p);

			/* drop additional reference that was taken on the previous cred */
			kauth_cred_unref(&my_cred);
		}

#if CONFIG_PERSONAS
		if (spawn_no_exec && imgp->ip_px_persona != NULL) {
			/*
			 * If we were asked to spawn a process into a new persona,
			 * do the credential switch now (which may override the UID/GID
			 * inherit done just above). It's important to do this switch
			 * before image activation both for reasons stated above, and
			 * to ensure that the new persona has access to the image/file
			 * being executed.
			 */
			error = spawn_persona_adopt(p, imgp->ip_px_persona);
			if (error != 0)
				goto bad;
		}
#endif /* CONFIG_PERSONAS */
#if !SECURE_KERNEL
		/*
		 * Disable ASLR for the spawned process.
		 *
		 * But only do so if we are not embedded + RELEASE.
		 * While embedded allows for a boot-arg (-disable_aslr)
		 * to deal with this (which itself is only honored on
		 * DEVELOPMENT or DEBUG builds of xnu), it is often
		 * useful or necessary to disable ASLR on a per-process
		 * basis for unit testing and debugging.
		 */
		if (px_sa.psa_flags & _POSIX_SPAWN_DISABLE_ASLR)
			OSBitOrAtomic(P_DISABLE_ASLR, &p->p_flag);
#endif /* !SECURE_KERNEL */

		/*
		 * Forcibly disallow execution from data pages for the spawned process
		 * even if it would otherwise be permitted by the architecture default.
		 */
		if (px_sa.psa_flags & _POSIX_SPAWN_ALLOW_DATA_EXEC)
			imgp->ip_flags |= IMGPF_ALLOW_DATA_EXEC;
	}

	/*
	 * Disable ASLR during image activation.  This occurs either if the
	 * _POSIX_SPAWN_DISABLE_ASLR attribute was found above or if
	 * P_DISABLE_ASLR was inherited from the parent process.
	 */
	if (p->p_flag & P_DISABLE_ASLR)
		imgp->ip_flags |= IMGPF_DISABLE_ASLR;

	/* 
	 * Clear transition flag so we won't hang if exec_activate_image() causes
	 * an automount (and launchd does a proc sysctl to service it).
	 *
	 * <rdar://problem/6848672>, <rdar://problem/5959568>.
	 */
	if (spawn_no_exec) {
		proc_transend(p, 0);
		proc_transit_set = 0;
	}

#if MAC_SPAWN	/* XXX */
	if (uap->mac_p != USER_ADDR_NULL) {
		error = mac_execve_enter(uap->mac_p, imgp);
		if (error)
			goto bad;
	}
#endif

	/*
	 * Activate the image
	 */
	error = exec_activate_image(imgp);
	
	if (error == 0 && !spawn_no_exec) {
		p = proc_exec_switch_task(p, current_task(), new_task, imgp->ip_new_thread);
		/* proc ref returned */
		should_release_proc_ref = TRUE;
	}

	if (error == 0) {
		/* process completed the exec */
		exec_done = TRUE;
	} else if (error == -1) {
		/* Image not claimed by any activator? */
		error = ENOEXEC;
	}

	/*
	 * If we have a spawn attr, and it contains signal related flags,
	 * the we need to process them in the "context" of the new child
	 * process, so we have to process it following image activation,
	 * prior to making the thread runnable in user space.  This is
	 * necessitated by some signal information being per-thread rather
	 * than per-process, and we don't have the new allocation in hand
	 * until after the image is activated.
	 */
	if (!error && imgp->ip_px_sa != NULL) {
		thread_t child_thread = imgp->ip_new_thread;
		uthread_t child_uthread = get_bsdthread_info(child_thread);

		/*
		 * Mask a list of signals, instead of them being unmasked, if
		 * they were unmasked in the parent; note that some signals
		 * are not maskable.
		 */
		if (px_sa.psa_flags & POSIX_SPAWN_SETSIGMASK)
			child_uthread->uu_sigmask = (px_sa.psa_sigmask & ~sigcantmask);
		/*
		 * Default a list of signals instead of ignoring them, if
		 * they were ignored in the parent.  Note that we pass
		 * spawn_no_exec to setsigvec() to indicate that we called
		 * fork1() and therefore do not need to call proc_signalstart()
		 * internally.
		 */
		if (px_sa.psa_flags & POSIX_SPAWN_SETSIGDEF) {
			vec.sa_handler = SIG_DFL;
			vec.sa_tramp = 0;
			vec.sa_mask = 0;
			vec.sa_flags = 0;
			for (sig = 1; sig < NSIG; sig++)
				if (px_sa.psa_sigdefault & (1 << (sig-1))) {
					error = setsigvec(p, child_thread, sig, &vec, spawn_no_exec);
			}
		}

		/*
		 * Activate the CPU usage monitor, if requested. This is done via a task-wide, per-thread CPU
		 * usage limit, which will generate a resource exceeded exception if any one thread exceeds the
		 * limit.
		 *
		 * Userland gives us interval in seconds, and the kernel SPI expects nanoseconds.
		 */
		if (px_sa.psa_cpumonitor_percent != 0) {
			/*
			 * Always treat a CPU monitor activation coming from spawn as entitled. Requiring
			 * an entitlement to configure the monitor a certain way seems silly, since
			 * whomever is turning it on could just as easily choose not to do so.
			 */
			error = proc_set_task_ruse_cpu(p->task,
					TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC,
					px_sa.psa_cpumonitor_percent,
					px_sa.psa_cpumonitor_interval * NSEC_PER_SEC,
					0, TRUE);
		}
	}

bad:

	if (error == 0) {
		/* reset delay idle sleep status if set */
		if ((p->p_flag & P_DELAYIDLESLEEP) == P_DELAYIDLESLEEP)
			OSBitAndAtomic(~((uint32_t)P_DELAYIDLESLEEP), &p->p_flag);
		/* upon  successful spawn, re/set the proc control state */
		if (imgp->ip_px_sa != NULL) {
			switch (px_sa.psa_pcontrol) {
				case POSIX_SPAWN_PCONTROL_THROTTLE:
					p->p_pcaction = P_PCTHROTTLE;
					break;
				case POSIX_SPAWN_PCONTROL_SUSPEND:
					p->p_pcaction = P_PCSUSP;
					break;
				case POSIX_SPAWN_PCONTROL_KILL:
					p->p_pcaction = P_PCKILL;
					break;
				case POSIX_SPAWN_PCONTROL_NONE:
				default:
					p->p_pcaction = 0;
					break;
			};
		}
		exec_resettextvp(p, imgp);
		
#if CONFIG_MEMORYSTATUS
		/* Has jetsam attributes? */
		if (imgp->ip_px_sa != NULL && (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_SET)) {
			/*
			 * With 2-level high-water-mark support, POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND is no
			 * longer relevant, as background limits are described via the inactive limit slots.
			 * At the kernel layer, the flag is ignored.
			 *
			 * That said, however, if the POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND is passed in,
			 * we attempt to mimic previous behavior by forcing the BG limit data into the
			 * inactive/non-fatal mode and force the active slots to hold system_wide/fatal mode.
			 * The kernel layer will flag this mapping.
			 */
			if (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND) {
				memorystatus_update(p, px_sa.psa_priority, 0,
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_USE_EFFECTIVE_PRIORITY),
					    TRUE,
					    -1, TRUE,
					    px_sa.psa_memlimit_inactive, FALSE,
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND));
			} else {
				memorystatus_update(p, px_sa.psa_priority, 0,
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_USE_EFFECTIVE_PRIORITY),
					    TRUE,
					    px_sa.psa_memlimit_active,
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_MEMLIMIT_ACTIVE_FATAL),
					    px_sa.psa_memlimit_inactive,
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_MEMLIMIT_INACTIVE_FATAL),
					    (px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND));
			}

		}
#endif /* CONFIG_MEMORYSTATUS */
	}

	/*
	 * If we successfully called fork1(), we always need to do this;
	 * we identify this case by noting the IMGPF_SPAWN flag.  This is
	 * because we come back from that call with signals blocked in the
	 * child, and we have to unblock them, but we want to wait until
	 * after we've performed any spawn actions.  This has to happen
	 * before check_for_signature(), which uses psignal.
	 */
	if (spawn_no_exec) {
		if (proc_transit_set)
			proc_transend(p, 0);

		/*
		 * Drop the signal lock on the child which was taken on our
		 * behalf by forkproc()/cloneproc() to prevent signals being
		 * received by the child in a partially constructed state.
		 */
		proc_signalend(p, 0);

		/* flag the 'fork' has occurred */
		proc_knote(p->p_pptr, NOTE_FORK | p->p_pid);
		/* then flag exec has occurred */
		/* notify only if it has not failed due to FP Key error */
		if ((p->p_lflag & P_LTERM_DECRYPTFAIL) == 0)
			proc_knote(p, NOTE_EXEC);
	}

	if (error == 0) {
		/*
		 * We need to initialize the bank context behind the protection of
		 * the proc_trans lock to prevent a race with exit. We can't do this during
		 * exec_activate_image because task_bank_init checks entitlements that
		 * aren't loaded until subsequent calls (including exec_resettextvp).
		 */
		error = proc_transstart(p, 0, 0);

		if (error == 0) {
			task_bank_init(get_threadtask(imgp->ip_new_thread));
			proc_transend(p, 0);
		}
	}

	/* Inherit task role from old task to new task for exec */
	if (error == 0 && !spawn_no_exec) {
		proc_inherit_task_role(get_threadtask(imgp->ip_new_thread), current_task());
	}

	/*
	 * Apply the spawnattr policy, apptype (which primes the task for importance donation),
	 * and bind any portwatch ports to the new task.
	 * This must be done after the exec so that the child's thread is ready,
	 * and after the in transit state has been released, because priority is
	 * dropped here so we need to be prepared for a potentially long preemption interval
	 *
	 * TODO: Consider splitting this up into separate phases
	 */
	if (error == 0 && imgp->ip_px_sa != NULL) {
		struct _posix_spawnattr *psa = (struct _posix_spawnattr *) imgp->ip_px_sa;

		exec_handle_spawnattr_policy(p, psa->psa_apptype, psa->psa_qos_clamp, psa->psa_darwin_role,
		                              portwatch_ports, portwatch_count);
	}

	/*
	 * Need to transfer pending watch port boosts to the new task while still making
	 * sure that the old task remains in the importance linkage. Create an importance
	 * linkage from old task to new task, then switch the task importance base
	 * of old task and new task. After the switch the port watch boost will be
	 * boosting the new task and new task will be donating importance to old task.
	 */
	if (error == 0 && task_did_exec(current_task())) {
		inherit = ipc_importance_exec_switch_task(current_task(), get_threadtask(imgp->ip_new_thread));
	}

	if (error == 0) {
		/* Apply the main thread qos */		
		thread_t main_thread = imgp->ip_new_thread;
		task_set_main_thread_qos(get_threadtask(imgp->ip_new_thread), main_thread);

#if CONFIG_MACF
		/*
		 * Processes with the MAP_JIT entitlement are permitted to have
		 * a jumbo-size map.
		 */
		if (mac_proc_check_map_anon(p, 0, 0, 0, MAP_JIT, NULL) == 0) {
			vm_map_set_jumbo(get_task_map(p->task));
		}
#endif /* CONFIG_MACF */
	}

	/*
	 * Release any ports we kept around for binding to the new task
	 * We need to release the rights even if the posix_spawn has failed.
	 */
	if (portwatch_ports != NULL) {
		for (int i = 0; i < portwatch_count; i++) {
			ipc_port_t port = NULL;
			if ((port = portwatch_ports[i]) != NULL) {
				ipc_port_release_send(port);
			}
		}
		FREE(portwatch_ports, M_TEMP);
		portwatch_ports = NULL;
		portwatch_count = 0;
	}

	/*
	 * We have to delay operations which might throw a signal until after
	 * the signals have been unblocked; however, we want that to happen
	 * after exec_resettextvp() so that the textvp is correct when they
	 * fire.
	 */
	if (error == 0) {
		error = check_for_signature(p, imgp);

		/*
		 * Pay for our earlier safety; deliver the delayed signals from
		 * the incomplete spawn process now that it's complete.
		 */
		if (imgp != NULL && spawn_no_exec && (p->p_lflag & P_LTRACED)) {
			psignal_vfork(p, p->task, imgp->ip_new_thread, SIGTRAP);
		}

		if (error == 0 && !spawn_no_exec)
			KDBG(BSDDBG_CODE(DBG_BSD_PROC,BSD_PROC_EXEC),
			     p->p_pid);
	}


	if (imgp != NULL) {
		if (imgp->ip_vp)
			vnode_put(imgp->ip_vp);
		if (imgp->ip_scriptvp)
			vnode_put(imgp->ip_scriptvp);
		if (imgp->ip_strings)
			execargs_free(imgp);
		if (imgp->ip_px_sfa != NULL)
			FREE(imgp->ip_px_sfa, M_TEMP);
		if (imgp->ip_px_spa != NULL)
			FREE(imgp->ip_px_spa, M_TEMP);
#if CONFIG_PERSONAS
		if (imgp->ip_px_persona != NULL)
			FREE(imgp->ip_px_persona, M_TEMP);
#endif
#if CONFIG_MACF
		if (imgp->ip_px_smpx != NULL)
			spawn_free_macpolicyinfo(imgp->ip_px_smpx);
		if (imgp->ip_execlabelp)
			mac_cred_label_free(imgp->ip_execlabelp);
		if (imgp->ip_scriptlabelp)
			mac_vnode_label_free(imgp->ip_scriptlabelp);
		if (imgp->ip_cs_error != OS_REASON_NULL) {
			os_reason_free(imgp->ip_cs_error);
			imgp->ip_cs_error = OS_REASON_NULL;
		}
#endif
	}

#if CONFIG_DTRACE
	if (spawn_no_exec) {
		/*
		 * In the original DTrace reference implementation,
		 * posix_spawn() was a libc routine that just
		 * did vfork(2) then exec(2).  Thus the proc::: probes
		 * are very fork/exec oriented.  The details of this
		 * in-kernel implementation of posix_spawn() is different
		 * (while producing the same process-observable effects)
		 * particularly w.r.t. errors, and which thread/process
		 * is constructing what on behalf of whom.
		 */
		if (error) {
			DTRACE_PROC1(spawn__failure, int, error);
		} else {
			DTRACE_PROC(spawn__success);
			/*
			 * Some DTrace scripts, e.g. newproc.d in
			 * /usr/bin, rely on the the 'exec-success'
			 * probe being fired in the child after the
			 * new process image has been constructed
			 * in order to determine the associated pid.
			 *
			 * So, even though the parent built the image
			 * here, for compatibility, mark the new thread
			 * so 'exec-success' fires on it as it leaves
			 * the kernel.
			 */
			dtrace_thread_didexec(imgp->ip_new_thread);
		}
	} else {
		if (error) {
			DTRACE_PROC1(exec__failure, int, error);
		} else {
			DTRACE_PROC(exec__success);
		}
	}

	if ((dtrace_proc_waitfor_hook = dtrace_proc_waitfor_exec_ptr) != NULL) {
		(*dtrace_proc_waitfor_hook)(p);
	}
#endif
	/*
	 * exec-success dtrace probe fired, clear bsd_info from
	 * old task if it did exec.
	 */
	if (task_did_exec(current_task())) {
		set_bsdtask_info(current_task(), NULL);
	}

	/* clear bsd_info from new task and terminate it if exec failed  */
	if (new_task != NULL && task_is_exec_copy(new_task)) {
		set_bsdtask_info(new_task, NULL);
		task_terminate_internal(new_task);
	}

	/* Return to both the parent and the child? */
	if (imgp != NULL && spawn_no_exec) {
		/*
		 * If the parent wants the pid, copy it out
		 */
		if (pid != USER_ADDR_NULL)
			(void)suword(pid, p->p_pid);
		retval[0] = error;

		/*
		 * If we had an error, perform an internal reap ; this is
		 * entirely safe, as we have a real process backing us.
		 */
		if (error) {
			proc_list_lock();
			p->p_listflag |= P_LIST_DEADPARENT;
			proc_list_unlock();
			proc_lock(p);
			/* make sure no one else has killed it off... */
			if (p->p_stat != SZOMB && p->exit_thread == NULL) {
				p->exit_thread = current_thread();
				proc_unlock(p);
				exit1(p, 1, (int *)NULL);
			} else {
				/* someone is doing it for us; just skip it */
				proc_unlock(p);
			}
		}
	}

	/*
	 * Do not terminate the current task, if proc_exec_switch_task did not
	 * switch the tasks, terminating the current task without the switch would
	 * result in loosing the SIGKILL status.
	 */
	if (task_did_exec(current_task())) {
		/* Terminate the current task, since exec will start in new task */
		task_terminate_internal(current_task());
	}

	/* Release the thread ref returned by fork_create_child/fork1 */
	if (imgp != NULL && imgp->ip_new_thread) {
		/* wake up the new thread */
		task_clear_return_wait(get_threadtask(imgp->ip_new_thread));
		thread_deallocate(imgp->ip_new_thread);
		imgp->ip_new_thread = NULL;
	}

	/* Release the ref returned by fork_create_child/fork1 */
	if (new_task) {
		task_deallocate(new_task);
		new_task = NULL;
	}

	if (should_release_proc_ref) {
		proc_rele(p);
	}

	if (bufp != NULL) {
		FREE(bufp, M_TEMP);
	}

	if (inherit != NULL) {
		ipc_importance_release(inherit);
	}
	
	return(error);
}

/*
 * proc_exec_switch_task
 *
 * Parameters:  p			proc
 *		old_task		task before exec
 *		new_task		task after exec
 *		new_thread		thread in new task
 *
 * Returns: proc.
 *
 * Note: The function will switch the task pointer of proc
 * from old task to new task. The switch needs to happen
 * after draining all proc refs and inside a proc translock.
 * In the case of failure to switch the task, which might happen
 * if the process received a SIGKILL or jetsam killed it, it will make
 * sure that the new tasks terminates. User proc ref returned
 * to caller.
 *
 * This function is called after point of no return, in the case
 * failure to switch, it will terminate the new task and swallow the
 * error and let the terminated process complete exec and die.
 */
proc_t
proc_exec_switch_task(proc_t p, task_t old_task, task_t new_task, thread_t new_thread)
{
	int error = 0;
	boolean_t task_active;
	boolean_t proc_active;
	boolean_t thread_active;
	thread_t old_thread = current_thread();

	/*
	 * Switch the task pointer of proc to new task.
	 * Before switching the task, wait for proc_refdrain.
	 * After the switch happens, the proc can disappear,
	 * take a ref before it disappears.
	 */
	p = proc_refdrain_with_refwait(p, TRUE);
	/* extra proc ref returned to the caller */

	assert(get_threadtask(new_thread) == new_task);
	task_active = task_is_active(new_task);

	/* Take the proc_translock to change the task ptr */
	proc_lock(p);
	proc_active = !(p->p_lflag & P_LEXIT);

	/* Check if the current thread is not aborted due to SIGKILL */
	thread_active = thread_is_active(old_thread);

	/*
	 * Do not switch the task if the new task or proc is already terminated
	 * as a result of error in exec past point of no return
	 */
	if (proc_active && task_active && thread_active) {
		error = proc_transstart(p, 1, 0);
		if (error == 0) {
			uthread_t new_uthread = get_bsdthread_info(new_thread);
			uthread_t old_uthread = get_bsdthread_info(current_thread());

			/*
			 * bsd_info of old_task will get cleared in execve and posix_spawn
			 * after firing exec-success/error dtrace probe.
			 */
			p->task = new_task;

			/* Copy the signal state, dtrace state and set bsd ast on new thread */
			act_set_astbsd(new_thread);
			new_uthread->uu_siglist = old_uthread->uu_siglist;
			new_uthread->uu_sigwait = old_uthread->uu_sigwait;
			new_uthread->uu_sigmask = old_uthread->uu_sigmask;
			new_uthread->uu_oldmask = old_uthread->uu_oldmask;
			new_uthread->uu_vforkmask = old_uthread->uu_vforkmask;
			new_uthread->uu_exit_reason = old_uthread->uu_exit_reason;
#if CONFIG_DTRACE
			new_uthread->t_dtrace_sig = old_uthread->t_dtrace_sig;
			new_uthread->t_dtrace_stop = old_uthread->t_dtrace_stop;
			new_uthread->t_dtrace_resumepid = old_uthread->t_dtrace_resumepid;
			assert(new_uthread->t_dtrace_scratch == NULL);
			new_uthread->t_dtrace_scratch = old_uthread->t_dtrace_scratch;

			old_uthread->t_dtrace_sig = 0;
			old_uthread->t_dtrace_stop = 0;
			old_uthread->t_dtrace_resumepid = 0;
			old_uthread->t_dtrace_scratch = NULL;
#endif
			/* Copy the resource accounting info */
			thread_copy_resource_info(new_thread, current_thread());

			/* Clear the exit reason and signal state on old thread */
			old_uthread->uu_exit_reason = NULL;
			old_uthread->uu_siglist = 0;

			/* Add the new uthread to proc uthlist and remove the old one */
			TAILQ_INSERT_TAIL(&p->p_uthlist, new_uthread, uu_list);
			TAILQ_REMOVE(&p->p_uthlist, old_uthread, uu_list);

			task_set_did_exec_flag(old_task);
			task_clear_exec_copy_flag(new_task);

			proc_transend(p, 1);
		}
	}

	proc_unlock(p);
	proc_refwake(p);

	if (error != 0 || !task_active || !proc_active || !thread_active) {
		task_terminate_internal(new_task);
	}

	return p;
}

/*
 * execve
 *
 * Parameters:	uap->fname		File name to exec
 *		uap->argp		Argument list
 *		uap->envp		Environment list
 *
 * Returns:	0			Success
 *	__mac_execve:EINVAL		Invalid argument
 *	__mac_execve:ENOTSUP		Invalid argument
 *	__mac_execve:EACCES		Permission denied
 *	__mac_execve:EINTR		Interrupted function
 *	__mac_execve:ENOMEM		Not enough space
 *	__mac_execve:EFAULT		Bad address
 *	__mac_execve:ENAMETOOLONG	Filename too long
 *	__mac_execve:ENOEXEC		Executable file format error
 *	__mac_execve:ETXTBSY		Text file busy [misuse of error code]
 *	__mac_execve:???
 *
 * TODO:	Dynamic linker header address on stack is copied via suword()
 */
/* ARGSUSED */
int
execve(proc_t p, struct execve_args *uap, int32_t *retval)
{
	struct __mac_execve_args muap;
	int err;

	memoryshot(VM_EXECVE, DBG_FUNC_NONE);

	muap.fname = uap->fname;
	muap.argp = uap->argp;
	muap.envp = uap->envp;
	muap.mac_p = USER_ADDR_NULL;
	err = __mac_execve(p, &muap, retval);

	return(err);
}

/*
 * __mac_execve
 *
 * Parameters:	uap->fname		File name to exec
 *		uap->argp		Argument list
 *		uap->envp		Environment list
 *		uap->mac_p		MAC label supplied by caller
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		ENOTSUP			Not supported
 *		ENOEXEC			Executable file format error
 *	exec_activate_image:EINVAL	Invalid argument
 *	exec_activate_image:EACCES	Permission denied
 *	exec_activate_image:EINTR	Interrupted function
 *	exec_activate_image:ENOMEM	Not enough space
 *	exec_activate_image:EFAULT	Bad address
 *	exec_activate_image:ENAMETOOLONG	Filename too long
 *	exec_activate_image:ENOEXEC	Executable file format error
 *	exec_activate_image:ETXTBSY	Text file busy [misuse of error code]
 *	exec_activate_image:EBADEXEC	The executable is corrupt/unknown
 *	exec_activate_image:???
 *	mac_execve_enter:???
 *
 * TODO:	Dynamic linker header address on stack is copied via suword()
 */
int
__mac_execve(proc_t p, struct __mac_execve_args *uap, int32_t *retval)
{
	char *bufp = NULL; 
	struct image_params *imgp;
	struct vnode_attr *vap;
	struct vnode_attr *origvap;
	int error;
	int is_64 = IS_64BIT_PROCESS(p);
	struct vfs_context context;
	struct uthread	*uthread;
	task_t new_task = NULL;
	boolean_t should_release_proc_ref = FALSE;
	boolean_t exec_done = FALSE;
	boolean_t in_vfexec = FALSE;
	void *inherit = NULL;

	context.vc_thread = current_thread();
	context.vc_ucred = kauth_cred_proc_ref(p);	/* XXX must NOT be kauth_cred_get() */

	/* Allocate a big chunk for locals instead of using stack since these  
	 * structures a pretty big.
	 */
	MALLOC(bufp, char *, (sizeof(*imgp) + sizeof(*vap) + sizeof(*origvap)), M_TEMP, M_WAITOK | M_ZERO);
	imgp = (struct image_params *) bufp;
	if (bufp == NULL) {
		error = ENOMEM;
		goto exit_with_error;
	}
	vap = (struct vnode_attr *) (bufp + sizeof(*imgp));
	origvap = (struct vnode_attr *) (bufp + sizeof(*imgp) + sizeof(*vap));
	
	/* Initialize the common data in the image_params structure */
	imgp->ip_user_fname = uap->fname;
	imgp->ip_user_argv = uap->argp;
	imgp->ip_user_envv = uap->envp;
	imgp->ip_vattr = vap;
	imgp->ip_origvattr = origvap;
	imgp->ip_vfs_context = &context;
	imgp->ip_flags = (is_64 ? IMGPF_WAS_64BIT : IMGPF_NONE) | ((p->p_flag & P_DISABLE_ASLR) ? IMGPF_DISABLE_ASLR : IMGPF_NONE);
	imgp->ip_seg = (is_64 ? UIO_USERSPACE64 : UIO_USERSPACE32);
	imgp->ip_mac_return = 0;
	imgp->ip_cs_error = OS_REASON_NULL;

#if CONFIG_MACF
	if (uap->mac_p != USER_ADDR_NULL) {
		error = mac_execve_enter(uap->mac_p, imgp);
		if (error) {
			kauth_cred_unref(&context.vc_ucred);
			goto exit_with_error;
		}
	}
#endif
	uthread = get_bsdthread_info(current_thread());
	if (uthread->uu_flag & UT_VFORK) {
		imgp->ip_flags |= IMGPF_VFORK_EXEC;
		in_vfexec = TRUE;
	} else {
		imgp->ip_flags |= IMGPF_EXEC;

		/*
		 * For execve case, create a new task and thread
		 * which points to current_proc. The current_proc will point
		 * to the new task after image activation and proc ref drain.
		 *
		 * proc (current_proc) <-----  old_task (current_task)
		 *  ^ |                                ^
		 *  | |                                |
		 *  | ----------------------------------
		 *  |
		 *  --------- new_task (task marked as TF_EXEC_COPY)
		 *
		 * After image activation, the proc will point to the new task
		 * and would look like following.
		 *
		 * proc (current_proc)  <-----  old_task (current_task, marked as TPF_DID_EXEC)
		 *  ^ |
		 *  | |
		 *  | ----------> new_task
		 *  |               |
		 *  -----------------
		 *
		 * During exec any transition from new_task -> proc is fine, but don't allow
		 * transition from proc->task, since it will modify old_task.
		 */
		imgp->ip_new_thread = fork_create_child(current_task(),
					NULL, p, FALSE, p->p_flag & P_LP64, TRUE);
		/* task and thread ref returned by fork_create_child */
		if (imgp->ip_new_thread == NULL) {
			error = ENOMEM;
			goto exit_with_error;
		}

		new_task = get_threadtask(imgp->ip_new_thread);
		context.vc_thread = imgp->ip_new_thread;
	}

	error = exec_activate_image(imgp);
	/* thread and task ref returned for vfexec case */

	if (imgp->ip_new_thread != NULL) {
		/*
		 * task reference might be returned by exec_activate_image
		 * for vfexec.
		 */
		new_task = get_threadtask(imgp->ip_new_thread);
	}

	if (!error && !in_vfexec) {
		p = proc_exec_switch_task(p, current_task(), new_task, imgp->ip_new_thread);
		/* proc ref returned */
		should_release_proc_ref = TRUE;
	}

	kauth_cred_unref(&context.vc_ucred);
	
	/* Image not claimed by any activator? */
	if (error == -1)
		error = ENOEXEC;

	if (!error) {
		exec_done = TRUE;
		assert(imgp->ip_new_thread != NULL);

		exec_resettextvp(p, imgp);
		error = check_for_signature(p, imgp);
	}	
	if (imgp->ip_vp != NULLVP)
		vnode_put(imgp->ip_vp);
	if (imgp->ip_scriptvp != NULLVP)
		vnode_put(imgp->ip_scriptvp);
	if (imgp->ip_strings)
		execargs_free(imgp);
#if CONFIG_MACF
	if (imgp->ip_execlabelp)
		mac_cred_label_free(imgp->ip_execlabelp);
	if (imgp->ip_scriptlabelp)
		mac_vnode_label_free(imgp->ip_scriptlabelp);
#endif
	if (imgp->ip_cs_error != OS_REASON_NULL) {
		os_reason_free(imgp->ip_cs_error);
		imgp->ip_cs_error = OS_REASON_NULL;
	}

	if (!error) {
		/*
		 * We need to initialize the bank context behind the protection of
		 * the proc_trans lock to prevent a race with exit. We can't do this during
		 * exec_activate_image because task_bank_init checks entitlements that
		 * aren't loaded until subsequent calls (including exec_resettextvp).
		 */
		error = proc_transstart(p, 0, 0);
	}

	if (!error) {
		task_bank_init(get_threadtask(imgp->ip_new_thread));
		proc_transend(p, 0);

		/* Sever any extant thread affinity */
		thread_affinity_exec(current_thread());

		/* Inherit task role from old task to new task for exec */
		if (!in_vfexec) {
			proc_inherit_task_role(get_threadtask(imgp->ip_new_thread), current_task());
		}

		thread_t main_thread = imgp->ip_new_thread;

		task_set_main_thread_qos(new_task, main_thread);

#if CONFIG_MACF
		/*
		 * Processes with the MAP_JIT entitlement are permitted to have
		 * a jumbo-size map.
		 */
		if (mac_proc_check_map_anon(p, 0, 0, 0, MAP_JIT, NULL) == 0) {
			vm_map_set_jumbo(get_task_map(new_task));
		}
#endif /* CONFIG_MACF */

		DTRACE_PROC(exec__success);

#if CONFIG_DTRACE
		if ((dtrace_proc_waitfor_hook = dtrace_proc_waitfor_exec_ptr) != NULL)
			(*dtrace_proc_waitfor_hook)(p);
#endif

		if (in_vfexec) {
			vfork_return(p, retval, p->p_pid);
		}
	} else {
		DTRACE_PROC1(exec__failure, int, error);
	}

exit_with_error:

	/*
	 * exec-success dtrace probe fired, clear bsd_info from
	 * old task if it did exec.
	 */
	if (task_did_exec(current_task())) {
		set_bsdtask_info(current_task(), NULL);
	}

	/* clear bsd_info from new task and terminate it if exec failed  */
	if (new_task != NULL && task_is_exec_copy(new_task)) {
		set_bsdtask_info(new_task, NULL);
		task_terminate_internal(new_task);
	}

	/*
	 * Need to transfer pending watch port boosts to the new task while still making
	 * sure that the old task remains in the importance linkage. Create an importance
	 * linkage from old task to new task, then switch the task importance base
	 * of old task and new task. After the switch the port watch boost will be
	 * boosting the new task and new task will be donating importance to old task.
	 */
	if (error == 0 && task_did_exec(current_task())) {
		inherit = ipc_importance_exec_switch_task(current_task(), get_threadtask(imgp->ip_new_thread));
	}

	if (imgp != NULL) {
		/*
		 * Do not terminate the current task, if proc_exec_switch_task did not
		 * switch the tasks, terminating the current task without the switch would
		 * result in loosing the SIGKILL status.
		 */
		if (task_did_exec(current_task())) {
			/* Terminate the current task, since exec will start in new task */
			task_terminate_internal(current_task());
		}

		/* Release the thread ref returned by fork_create_child */
		if (imgp->ip_new_thread) {
			/* wake up the new exec thread */
			task_clear_return_wait(get_threadtask(imgp->ip_new_thread));
			thread_deallocate(imgp->ip_new_thread);
			imgp->ip_new_thread = NULL;
		}
	}

	/* Release the ref returned by fork_create_child */
	if (new_task) {
		task_deallocate(new_task);
		new_task = NULL;
	}

	if (should_release_proc_ref) {
		proc_rele(p);
	}

	if (bufp != NULL) {
		FREE(bufp, M_TEMP);
	}

	if (inherit != NULL) {
		ipc_importance_release(inherit);
	}
	
	return(error);
}


/*
 * copyinptr
 *
 * Description:	Copy a pointer in from user space to a user_addr_t in kernel
 *		space, based on 32/64 bitness of the user space
 *
 * Parameters:	froma			User space address
 *		toptr			Address of kernel space user_addr_t
 *		ptr_size		4/8, based on 'froma' address space
 *
 * Returns:	0			Success
 *		EFAULT			Bad 'froma'
 *
 * Implicit returns:
 *		*ptr_size		Modified
 */
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


/*
 * copyoutptr
 *
 * Description:	Copy a pointer out from a user_addr_t in kernel space to
 *		user space, based on 32/64 bitness of the user space
 *
 * Parameters:	ua			User space address to copy to
 *		ptr			Address of kernel space user_addr_t
 *		ptr_size		4/8, based on 'ua' address space
 *
 * Returns:	0			Success
 *		EFAULT			Bad 'ua'
 *
 */
static int
copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size)
{
	int error;

	if (ptr_size == 4) {
		/* 64 bit value containing 32 bit address */
		unsigned int i = CAST_DOWN_EXPLICIT(unsigned int,ua);	/* SAFE */

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
 *		end of the area consumed (stacks grow downward).
 *
 *		argc is an int; arg[i] are pointers; env[i] are pointers;
 *		the 0's are (void *)NULL's
 *
 * The stack frame layout is:
 *
 *      +-------------+ <- p->user_stack
 *      |     16b     |
 *      +-------------+
 *      | STRING AREA |
 *      |      :      |
 *      |      :      |
 *      |      :      |
 *      +- -- -- -- --+
 *      |  PATH AREA  |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      |  applev[n]  |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |  applev[1]  |
 *      +-------------+
 *      | exec_path / |
 *      |  applev[0]  |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      |    env[n]   |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |    env[0]   |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      | arg[argc-1] |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |    arg[0]   |
 *      +-------------+
 *      |     argc    |
 * sp-> +-------------+
 *
 * Although technically a part of the STRING AREA, we treat the PATH AREA as
 * a separate entity.  This allows us to align the beginning of the PATH AREA
 * to a pointer boundary so that the exec_path, env[i], and argv[i] pointers
 * which preceed it on the stack are properly aligned.
 */

static int
exec_copyout_strings(struct image_params *imgp, user_addr_t *stackp)
{
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	int	ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;
	int	ptr_area_size;
	void *ptr_buffer_start, *ptr_buffer;
	int string_size;

	user_addr_t	string_area;	/* *argv[], *env[] */
	user_addr_t	ptr_area;	/* argv[], env[], applev[] */
	user_addr_t argc_area;	/* argc */
	user_addr_t	stack;
	int error;

	unsigned i;
	struct copyout_desc {
		char	*start_string;
		int		count;
#if CONFIG_DTRACE
		user_addr_t	*dtrace_cookie;
#endif
		boolean_t	null_term;
	} descriptors[] = {
		{
			.start_string = imgp->ip_startargv,
			.count = imgp->ip_argc,
#if CONFIG_DTRACE
			.dtrace_cookie = &p->p_dtrace_argv,
#endif
			.null_term = TRUE
		},
		{
			.start_string = imgp->ip_endargv,
			.count = imgp->ip_envc,
#if CONFIG_DTRACE
			.dtrace_cookie = &p->p_dtrace_envp,
#endif
			.null_term = TRUE
		},
		{
			.start_string = imgp->ip_strings,
			.count = 1,
#if CONFIG_DTRACE
			.dtrace_cookie = NULL,
#endif
			.null_term = FALSE
		},
		{
			.start_string = imgp->ip_endenvv,
			.count = imgp->ip_applec - 1, /* exec_path handled above */
#if CONFIG_DTRACE
			.dtrace_cookie = NULL,
#endif
			.null_term = TRUE
		}
	};

	stack = *stackp;

	/*
	 * All previous contributors to the string area
	 * should have aligned their sub-area
	 */
	if (imgp->ip_strspace % ptr_size != 0) {
		error = EINVAL;
		goto bad;
	}

	/* Grow the stack down for the strings we've been building up */
	string_size = imgp->ip_strendp - imgp->ip_strings;
	stack -= string_size;
	string_area = stack;

	/*
	 * Need room for one pointer for each string, plus
	 * one for the NULLs terminating the argv, envv, and apple areas.
	 */
	ptr_area_size = (imgp->ip_argc + imgp->ip_envc + imgp->ip_applec + 3) *
	    ptr_size;
	stack -= ptr_area_size;
	ptr_area = stack;

	/* We'll construct all the pointer arrays in our string buffer,
	 * which we already know is aligned properly, and ip_argspace
	 * was used to verify we have enough space.
	 */
	ptr_buffer_start = ptr_buffer = (void *)imgp->ip_strendp;

	/*
	 * Need room for pointer-aligned argc slot.
	 */
	stack -= ptr_size;
	argc_area = stack;

	/*
	 * Record the size of the arguments area so that sysctl_procargs()
	 * can return the argument area without having to parse the arguments.
	 */
	proc_lock(p);
	p->p_argc = imgp->ip_argc;
	p->p_argslen = (int)(*stackp - string_area);
	proc_unlock(p);

	/* Return the initial stack address: the location of argc */
	*stackp = stack;

	/*
	 * Copy out the entire strings area.
	 */
	error = copyout(imgp->ip_strings, string_area,
						   string_size);
	if (error)
		goto bad;

	for (i = 0; i < sizeof(descriptors)/sizeof(descriptors[0]); i++) {
		char *cur_string = descriptors[i].start_string;
		int j;

#if CONFIG_DTRACE
		if (descriptors[i].dtrace_cookie) {
			proc_lock(p);
			*descriptors[i].dtrace_cookie = ptr_area + ((uintptr_t)ptr_buffer - (uintptr_t)ptr_buffer_start); /* dtrace convenience */
			proc_unlock(p);
		}
#endif /* CONFIG_DTRACE */

		/*
		 * For each segment (argv, envv, applev), copy as many pointers as requested
		 * to our pointer buffer.
		 */
		for (j = 0; j < descriptors[i].count; j++) {
			user_addr_t cur_address = string_area + (cur_string - imgp->ip_strings);
			
			/* Copy out the pointer to the current string. Alignment has been verified  */
			if (ptr_size == 8) {
				*(uint64_t *)ptr_buffer = (uint64_t)cur_address;
			} else {
				*(uint32_t *)ptr_buffer = (uint32_t)cur_address;
			}
			
			ptr_buffer = (void *)((uintptr_t)ptr_buffer + ptr_size);
			cur_string += strlen(cur_string) + 1; /* Only a NUL between strings in the same area */
		}

		if (descriptors[i].null_term) {
			if (ptr_size == 8) {
				*(uint64_t *)ptr_buffer = 0ULL;
			} else {
				*(uint32_t *)ptr_buffer = 0;
			}
			
			ptr_buffer = (void *)((uintptr_t)ptr_buffer + ptr_size);
		}
	}

	/*
	 * Copy out all our pointer arrays in bulk.
	 */
	error = copyout(ptr_buffer_start, ptr_area,
					ptr_area_size);
	if (error)
		goto bad;

	/* argc (int32, stored in a ptr_size area) */
	error = copyoutptr((user_addr_t)imgp->ip_argc, argc_area, ptr_size);
	if (error)
		goto bad;

bad:
	return(error);
}


/*
 * exec_extract_strings
 *
 * Copy arguments and environment from user space into work area; we may
 * have already copied some early arguments into the work area, and if
 * so, any arguments opied in are appended to those already there.
 * This function is the primary manipulator of ip_argspace, since
 * these are the arguments the client of execve(2) knows about. After
 * each argv[]/envv[] string is copied, we charge the string length
 * and argv[]/envv[] pointer slot to ip_argspace, so that we can
 * full preflight the arg list size.
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	0			Success
 *		!0			Failure: errno
 *
 * Implicit returns;
 *		(imgp->ip_argc)		Count of arguments, updated
 *		(imgp->ip_envc)		Count of environment strings, updated
 *		(imgp->ip_argspace)	Count of remaining of NCARGS
 *		(imgp->ip_interp_buffer)	Interpreter and args (mutated in place)
 *
 *
 * Note:	The argument and environment vectors are user space pointers
 *		to arrays of user space pointers.
 */
static int
exec_extract_strings(struct image_params *imgp)
{
	int error = 0;
	int	ptr_size = (imgp->ip_flags & IMGPF_WAS_64BIT) ? 8 : 4;
	int new_ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;
	user_addr_t	argv = imgp->ip_user_argv;
	user_addr_t	envv = imgp->ip_user_envv;

	/*
	 * Adjust space reserved for the path name by however much padding it
	 * needs. Doing this here since we didn't know if this would be a 32- 
	 * or 64-bit process back in exec_save_path.
	 */
	while (imgp->ip_strspace % new_ptr_size != 0) {
		*imgp->ip_strendp++ = '\0';
		imgp->ip_strspace--;
		/* imgp->ip_argspace--; not counted towards exec args total */
	}

	/*
	 * From now on, we start attributing string space to ip_argspace
	 */
	imgp->ip_startargv = imgp->ip_strendp;
	imgp->ip_argc = 0;

	if((imgp->ip_flags & IMGPF_INTERPRET) != 0) {
		user_addr_t	arg;
		char *argstart, *ch;

		/* First, the arguments in the "#!" string are tokenized and extracted. */
		argstart = imgp->ip_interp_buffer;
		while (argstart) {
			ch = argstart;
			while (*ch && !IS_WHITESPACE(*ch)) {
				ch++;
			}

			if (*ch == '\0') {
				/* last argument, no need to NUL-terminate */
				error = exec_add_user_string(imgp, CAST_USER_ADDR_T(argstart), UIO_SYSSPACE, TRUE);
				argstart = NULL;
			} else {
				/* NUL-terminate */
				*ch = '\0';
				error = exec_add_user_string(imgp, CAST_USER_ADDR_T(argstart), UIO_SYSSPACE, TRUE);

				/*
				 * Find the next string. We know spaces at the end of the string have already
				 * been stripped.
				 */
				argstart = ch + 1;
				while (IS_WHITESPACE(*argstart)) {
					argstart++;
				}
			}

			/* Error-check, regardless of whether this is the last interpreter arg or not */
			if (error)
				goto bad;
			if (imgp->ip_argspace < new_ptr_size) {
				error = E2BIG;
				goto bad;
			}
			imgp->ip_argspace -= new_ptr_size; /* to hold argv[] entry */
			imgp->ip_argc++;
		}

		if (argv != 0LL) {
			/*
			 * If we are running an interpreter, replace the av[0] that was
			 * passed to execve() with the path name that was
			 * passed to execve() for interpreters which do not use the PATH
			 * to locate their script arguments.
			 */
			error = copyinptr(argv, &arg, ptr_size);
			if (error)
				goto bad;
			if (arg != 0LL) {
				argv += ptr_size; /* consume without using */
			}
		}

		if (imgp->ip_interp_sugid_fd != -1) {
			char temp[19]; /* "/dev/fd/" + 10 digits + NUL */
			snprintf(temp, sizeof(temp), "/dev/fd/%d", imgp->ip_interp_sugid_fd);
			error = exec_add_user_string(imgp, CAST_USER_ADDR_T(temp), UIO_SYSSPACE, TRUE);
		} else {
			error = exec_add_user_string(imgp, imgp->ip_user_fname, imgp->ip_seg, TRUE);
		}
		
		if (error)
			goto bad;
		if (imgp->ip_argspace < new_ptr_size) {
			error = E2BIG;
			goto bad;
		}
		imgp->ip_argspace -= new_ptr_size; /* to hold argv[] entry */
		imgp->ip_argc++;
	}

	while (argv != 0LL) {
		user_addr_t	arg;

		error = copyinptr(argv, &arg, ptr_size);
		if (error)
			goto bad;

		if (arg == 0LL) {
			break;
		}

		argv += ptr_size;

		/*
		* av[n...] = arg[n]
		*/
		error = exec_add_user_string(imgp, arg, imgp->ip_seg, TRUE);
		if (error)
			goto bad;
		if (imgp->ip_argspace < new_ptr_size) {
			error = E2BIG;
			goto bad;
		}
		imgp->ip_argspace -= new_ptr_size; /* to hold argv[] entry */
		imgp->ip_argc++;
	}	 

	/* Save space for argv[] NULL terminator */
	if (imgp->ip_argspace < new_ptr_size) {
		error = E2BIG;
		goto bad;
	}
	imgp->ip_argspace -= new_ptr_size;
	
	/* Note where the args ends and env begins. */
	imgp->ip_endargv = imgp->ip_strendp;
	imgp->ip_envc = 0;

	/* Now, get the environment */
	while (envv != 0LL) {
		user_addr_t	env;

		error = copyinptr(envv, &env, ptr_size);
		if (error)
			goto bad;

		envv += ptr_size;
		if (env == 0LL) {
			break;
		}
		/*
		* av[n...] = env[n]
		*/
		error = exec_add_user_string(imgp, env, imgp->ip_seg, TRUE);
		if (error)
			goto bad;
		if (imgp->ip_argspace < new_ptr_size) {
			error = E2BIG;
			goto bad;
		}
		imgp->ip_argspace -= new_ptr_size; /* to hold envv[] entry */
		imgp->ip_envc++;
	}

	/* Save space for envv[] NULL terminator */
	if (imgp->ip_argspace < new_ptr_size) {
		error = E2BIG;
		goto bad;
	}
	imgp->ip_argspace -= new_ptr_size;

	/* Align the tail of the combined argv+envv area */
	while (imgp->ip_strspace % new_ptr_size != 0) {
		if (imgp->ip_argspace < 1) {
			error = E2BIG;
			goto bad;
		}
		*imgp->ip_strendp++ = '\0';
		imgp->ip_strspace--;
		imgp->ip_argspace--;
	}
	
	/* Note where the envv ends and applev begins. */
	imgp->ip_endenvv = imgp->ip_strendp;

	/*
	 * From now on, we are no longer charging argument
	 * space to ip_argspace.
	 */

bad:
	return error;
}

/*
 * Libc has an 8-element array set up for stack guard values.  It only fills
 * in one of those entries, and both gcc and llvm seem to use only a single
 * 8-byte guard.  Until somebody needs more than an 8-byte guard value, don't
 * do the work to construct them.
 */
#define	GUARD_VALUES 1
#define	GUARD_KEY "stack_guard="

/*
 * System malloc needs some entropy when it is initialized.
 */
#define	ENTROPY_VALUES 2
#define ENTROPY_KEY "malloc_entropy="

/*
 * System malloc engages nanozone for UIAPP.
 */
#define NANO_ENGAGE_KEY "MallocNanoZone=1"

#define PFZ_KEY "pfz="
extern user32_addr_t commpage_text32_location;
extern user64_addr_t commpage_text64_location;

#define MAIN_STACK_VALUES 4
#define MAIN_STACK_KEY "main_stack="

#define HEX_STR_LEN 18 // 64-bit hex value "0x0123456701234567"

static int
exec_add_entropy_key(struct image_params *imgp,
		     const char *key,
		     int values,
		     boolean_t embedNUL)
{
	const int limit = 8;
	uint64_t entropy[limit];
	char str[strlen(key) + (HEX_STR_LEN + 1) * limit + 1];
	if (values > limit) {
		values = limit;
	}

    read_random(entropy, sizeof(entropy[0]) * values);

	if (embedNUL) {
		entropy[0] &= ~(0xffull << 8);
	}

	int len = snprintf(str, sizeof(str), "%s0x%llx", key, entropy[0]);
	int remaining = sizeof(str) - len;
	for (int i = 1; i < values && remaining > 0; ++i) {
		int start = sizeof(str) - remaining;
		len = snprintf(&str[start], remaining, ",0x%llx", entropy[i]);
		remaining -= len;
	}

	return exec_add_user_string(imgp, CAST_USER_ADDR_T(str), UIO_SYSSPACE, FALSE);
}

/*
 * Build up the contents of the apple[] string vector
 */
static int
exec_add_apple_strings(struct image_params *imgp,
		       const load_result_t *load_result)
{
	int error;
	int img_ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;

	/* exec_save_path stored the first string */
	imgp->ip_applec = 1;

	/* adding the pfz string */
	{
		char pfz_string[strlen(PFZ_KEY) + HEX_STR_LEN + 1];

		if (img_ptr_size == 8) {
			snprintf(pfz_string, sizeof(pfz_string), PFZ_KEY "0x%llx", commpage_text64_location);
		} else {
			snprintf(pfz_string, sizeof(pfz_string), PFZ_KEY "0x%x", commpage_text32_location);
		}
		error = exec_add_user_string(imgp, CAST_USER_ADDR_T(pfz_string), UIO_SYSSPACE, FALSE);
		if (error) {
			goto bad;
		}
		imgp->ip_applec++;
	}

	/* adding the NANO_ENGAGE_KEY key */
	if (imgp->ip_px_sa) {
		int proc_flags = (((struct _posix_spawnattr *) imgp->ip_px_sa)->psa_flags);

		if ((proc_flags & _POSIX_SPAWN_NANO_ALLOCATOR) == _POSIX_SPAWN_NANO_ALLOCATOR) {
			const char *nano_string = NANO_ENGAGE_KEY;
			error = exec_add_user_string(imgp, CAST_USER_ADDR_T(nano_string), UIO_SYSSPACE, FALSE);
			if (error){
				goto bad;
			}
			imgp->ip_applec++;
		}
	}

	/*
	 * Supply libc with a collection of random values to use when
	 * implementing -fstack-protector.
	 *
	 * (The first random string always contains an embedded NUL so that
	 * __stack_chk_guard also protects against C string vulnerabilities)
	 */
	error = exec_add_entropy_key(imgp, GUARD_KEY, GUARD_VALUES, TRUE);
	if (error) {
		goto bad;
	}
	imgp->ip_applec++;

	/*
	 * Supply libc with entropy for system malloc.
	 */
	error = exec_add_entropy_key(imgp, ENTROPY_KEY, ENTROPY_VALUES, FALSE);
	if (error) {
		goto bad;
	}
	imgp->ip_applec++;

	/* 
	 * Add MAIN_STACK_KEY: Supplies the address and size of the main thread's
	 * stack if it was allocated by the kernel.
	 *
	 * The guard page is not included in this stack size as libpthread
	 * expects to add it back in after receiving this value.
	 */
	if (load_result->unixproc) {
		char stack_string[strlen(MAIN_STACK_KEY) + (HEX_STR_LEN + 1) * MAIN_STACK_VALUES + 1];
		snprintf(stack_string, sizeof(stack_string),
			 MAIN_STACK_KEY "0x%llx,0x%llx,0x%llx,0x%llx",
			 (uint64_t)load_result->user_stack,
			 (uint64_t)load_result->user_stack_size,
			 (uint64_t)load_result->user_stack_alloc,
			 (uint64_t)load_result->user_stack_alloc_size);
		error = exec_add_user_string(imgp, CAST_USER_ADDR_T(stack_string), UIO_SYSSPACE, FALSE);
		if (error) {
			goto bad;
		}
		imgp->ip_applec++;
	}

	/* Align the tail of the combined applev area */
	while (imgp->ip_strspace % img_ptr_size != 0) {
		*imgp->ip_strendp++ = '\0';
		imgp->ip_strspace--;
	}

bad:
	return error;
}

#define	unix_stack_size(p)	(p->p_rlimit[RLIMIT_STACK].rlim_cur)

/*
 * exec_check_permissions
 *
 * Description:	Verify that the file that is being attempted to be executed
 *		is in fact allowed to be executed based on it POSIX file
 *		permissions and other access control criteria
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	0			Success
 *		EACCES			Permission denied
 *		ENOEXEC			Executable file format error
 *		ETXTBSY			Text file busy [misuse of error code]
 *	vnode_getattr:???
 *	vnode_authorize:???
 */
static int
exec_check_permissions(struct image_params *imgp)
{
	struct vnode *vp = imgp->ip_vp;
	struct vnode_attr *vap = imgp->ip_vattr;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
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
	if (!vfs_authopaque(vnode_mount(vp)) && ((vap->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0))
		return (EACCES);

	/* Disallow zero length files */
	if (vap->va_data_size == 0)
		return (ENOEXEC);

	imgp->ip_arch_offset = (user_size_t)0;
	imgp->ip_arch_size = vap->va_data_size;

	/* Disable setuid-ness for traced programs or if MNT_NOSUID */
	if ((vp->v_mount->mnt_flag & MNT_NOSUID) || (p->p_lflag & P_LTRACED))
		vap->va_mode &= ~(VSUID | VSGID);

	/*
	 * Disable _POSIX_SPAWN_ALLOW_DATA_EXEC and _POSIX_SPAWN_DISABLE_ASLR
	 * flags for setuid/setgid binaries.
	 */
	if (vap->va_mode & (VSUID | VSGID))
		imgp->ip_flags &= ~(IMGPF_ALLOW_DATA_EXEC | IMGPF_DISABLE_ASLR);

#if CONFIG_MACF
	error = mac_vnode_check_exec(imgp->ip_vfs_context, vp, imgp);
	if (error)
		return (error);
#endif

  	/* Check for execute permission */
 	action = KAUTH_VNODE_EXECUTE;
  	/* Traced images must also be readable */
 	if (p->p_lflag & P_LTRACED)
 		action |= KAUTH_VNODE_READ_DATA;
 	if ((error = vnode_authorize(vp, NULL, action, imgp->ip_vfs_context)) != 0)
		return (error);

#if 0
	/* Don't let it run if anyone had it open for writing */
	vnode_lock(vp);
	if (vp->v_writecount) {
		panic("going to return ETXTBSY %x", vp);
		vnode_unlock(vp);
		return (ETXTBSY);
	}
	vnode_unlock(vp);
#endif


	/* XXX May want to indicate to underlying FS that vnode is open */

	return (error);
}


/*
 * exec_handle_sugid
 *
 * Initially clear the P_SUGID in the process flags; if an SUGID process is
 * exec'ing a non-SUGID image, then  this is the point of no return.
 *
 * If the image being activated is SUGID, then replace the credential with a
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
	proc_t			p = vfs_context_proc(imgp->ip_vfs_context);
	kauth_cred_t		cred = vfs_context_ucred(imgp->ip_vfs_context);
	kauth_cred_t		my_cred, my_new_cred;
	int			i;
	int			leave_sugid_clear = 0;
	int			mac_reset_ipc = 0;
	int			error = 0;
	task_t			task = NULL;
#if CONFIG_MACF
	int			mac_transition, disjoint_cred = 0;
	int 		label_update_return = 0;

	/*
	 * Determine whether a call to update the MAC label will result in the
	 * credential changing.
	 *
	 * Note:	MAC policies which do not actually end up modifying
	 *		the label subsequently are strongly encouraged to
	 *		return 0 for this check, since a non-zero answer will
	 *		slow down the exec fast path for normal binaries.
	 */
	mac_transition = mac_cred_check_label_update_execve(
							imgp->ip_vfs_context,
							imgp->ip_vp,
							imgp->ip_arch_offset,
							imgp->ip_scriptvp,
							imgp->ip_scriptlabelp,
							imgp->ip_execlabelp,
							p,
							imgp->ip_px_smpx);
#endif

	OSBitAndAtomic(~((uint32_t)P_SUGID), &p->p_flag);

	/*
	 * Order of the following is important; group checks must go last,
	 * as we use the success of the 'ismember' check combined with the
	 * failure of the explicit match to indicate that we will be setting
	 * the egid of the process even though the new process did not
	 * require VSUID/VSGID bits in order for it to set the new group as
	 * its egid.
	 *
	 * Note:	Technically, by this we are implying a call to
	 *		setegid() in the new process, rather than implying
	 *		it used its VSGID bit to set the effective group,
	 *		even though there is no code in that process to make
	 *		such a call.
	 */
	if (((imgp->ip_origvattr->va_mode & VSUID) != 0 &&
	     kauth_cred_getuid(cred) != imgp->ip_origvattr->va_uid) ||
	    ((imgp->ip_origvattr->va_mode & VSGID) != 0 &&
		 ((kauth_cred_ismember_gid(cred, imgp->ip_origvattr->va_gid, &leave_sugid_clear) || !leave_sugid_clear) ||
		 (kauth_cred_getgid(cred) != imgp->ip_origvattr->va_gid)))) {

#if CONFIG_MACF
/* label for MAC transition and neither VSUID nor VSGID */
handle_mac_transition:
#endif

		/*
		 * Replace the credential with a copy of itself if euid or
		 * egid change.
		 *
		 * Note:	setuid binaries will automatically opt out of
		 *		group resolver participation as a side effect
		 *		of this operation.  This is an intentional
		 *		part of the security model, which requires a
		 *		participating credential be established by
		 *		escalating privilege, setting up all other
		 *		aspects of the credential including whether
		 *		or not to participate in external group
		 *		membership resolution, then dropping their
		 *		effective privilege to that of the desired
		 *		final credential state.
		 *
		 * Modifications to p_ucred must be guarded using the
		 * proc's ucred lock. This prevents others from accessing
		 * a garbage credential.
		 */
		while (imgp->ip_origvattr->va_mode & VSUID) {
			my_cred = kauth_cred_proc_ref(p);
			my_new_cred = kauth_cred_setresuid(my_cred, KAUTH_UID_NONE, imgp->ip_origvattr->va_uid, imgp->ip_origvattr->va_uid, KAUTH_UID_NONE);

			if (my_new_cred == my_cred) {
				kauth_cred_unref(&my_cred);
				break;
			}

			/* update cred on proc */
			proc_ucred_lock(p);

			if (p->p_ucred != my_cred) {
				proc_ucred_unlock(p);
				kauth_cred_unref(&my_new_cred);
				continue;
			}

			/* donate cred reference on my_new_cred to p->p_ucred */
			p->p_ucred = my_new_cred;
			PROC_UPDATE_CREDS_ONPROC(p);
			proc_ucred_unlock(p);

			/* drop additional reference that was taken on the previous cred */
			kauth_cred_unref(&my_cred);

			break;
		}

		while (imgp->ip_origvattr->va_mode & VSGID) {
			my_cred = kauth_cred_proc_ref(p);
			my_new_cred = kauth_cred_setresgid(my_cred, KAUTH_GID_NONE, imgp->ip_origvattr->va_gid, imgp->ip_origvattr->va_gid);

			if (my_new_cred == my_cred) {
				kauth_cred_unref(&my_cred);
				break;
			}

			/* update cred on proc */
			proc_ucred_lock(p);

			if (p->p_ucred != my_cred) {
				proc_ucred_unlock(p);
				kauth_cred_unref(&my_new_cred);
				continue;
			}

			/* donate cred reference on my_new_cred to p->p_ucred */
			p->p_ucred = my_new_cred;
			PROC_UPDATE_CREDS_ONPROC(p);
			proc_ucred_unlock(p);

			/* drop additional reference that was taken on the previous cred */
			kauth_cred_unref(&my_cred);

			break;
		}

#if CONFIG_MACF
		/* 
		 * If a policy has indicated that it will transition the label,
		 * before making the call into the MAC policies, get a new
		 * duplicate credential, so they can modify it without
		 * modifying any others sharing it.
		 */
		if (mac_transition) { 
			/*
			 * This hook may generate upcalls that require
			 * importance donation from the kernel.
			 * (23925818)
			 */
			thread_t thread = current_thread();
			thread_enable_send_importance(thread, TRUE);
			kauth_proc_label_update_execve(p,
						imgp->ip_vfs_context,
						imgp->ip_vp, 
						imgp->ip_arch_offset,
						imgp->ip_scriptvp,
						imgp->ip_scriptlabelp,
						imgp->ip_execlabelp,
						&imgp->ip_csflags,
						imgp->ip_px_smpx,
						&disjoint_cred, /* will be non zero if disjoint */
						&label_update_return);
			thread_enable_send_importance(thread, FALSE);

			if (disjoint_cred) {
				/*
				 * If updating the MAC label resulted in a
				 * disjoint credential, flag that we need to
				 * set the P_SUGID bit.  This protects
				 * against debuggers being attached by an
				 * insufficiently privileged process onto the
				 * result of a transition to a more privileged
				 * credential.
				 */
				leave_sugid_clear = 0;
			}
			
			imgp->ip_mac_return = label_update_return;
		}
		
		mac_reset_ipc = mac_proc_check_inherit_ipc_ports(p, p->p_textvp, p->p_textoff, imgp->ip_vp, imgp->ip_arch_offset, imgp->ip_scriptvp);

#endif	/* CONFIG_MACF */

		/*
		 * If 'leave_sugid_clear' is non-zero, then we passed the
		 * VSUID and MACF checks, and successfully determined that
		 * the previous cred was a member of the VSGID group, but
		 * that it was not the default at the time of the execve,
		 * and that the post-labelling credential was not disjoint.
		 * So we don't set the P_SUGID or reset mach ports and fds 
		 * on the basis of simply running this code.
		 */
		if (mac_reset_ipc || !leave_sugid_clear) {
			/*
			 * Have mach reset the task and thread ports.
			 * We don't want anyone who had the ports before
			 * a setuid exec to be able to access/control the
			 * task/thread after.
			 */
			ipc_task_reset((imgp->ip_new_thread != NULL) ?
					get_threadtask(imgp->ip_new_thread) : p->task);
			ipc_thread_reset((imgp->ip_new_thread != NULL) ?
				 	 imgp->ip_new_thread : current_thread());
		}

		if (!leave_sugid_clear) {
			/*
			 * Flag the process as setuid.
			 */
			OSBitOrAtomic(P_SUGID, &p->p_flag);

			/*
			 * Radar 2261856; setuid security hole fix
			 * XXX For setuid processes, attempt to ensure that
			 * stdin, stdout, and stderr are already allocated.
			 * We do not want userland to accidentally allocate
			 * descriptors in this range which has implied meaning
			 * to libc.
			 */
			for (i = 0; i < 3; i++) {

				if (p->p_fd->fd_ofiles[i] != NULL)
					continue;

				/*
				 * Do the kernel equivalent of
				 *
				 * 	if i == 0
				 * 		(void) open("/dev/null", O_RDONLY);
				 * 	else 
				 * 		(void) open("/dev/null", O_WRONLY);
				 */

				struct fileproc *fp;
				int indx;
				int flag;
				struct nameidata *ndp = NULL;

				if (i == 0)
					flag = FREAD;
				else 
					flag = FWRITE;

				if ((error = falloc(p,
				    &fp, &indx, imgp->ip_vfs_context)) != 0)
					continue;

				MALLOC(ndp, struct nameidata *, sizeof(*ndp), M_TEMP, M_WAITOK | M_ZERO);
				if (ndp == NULL) {
					fp_free(p, indx, fp);
					error = ENOMEM;
					break;
				}

				NDINIT(ndp, LOOKUP, OP_OPEN, FOLLOW, UIO_SYSSPACE,
				    CAST_USER_ADDR_T("/dev/null"),
				    imgp->ip_vfs_context);

				if ((error = vn_open(ndp, flag, 0)) != 0) {
					fp_free(p, indx, fp);
					FREE(ndp, M_TEMP);
					break;
				}

				struct fileglob *fg = fp->f_fglob;

				fg->fg_flag = flag;
				fg->fg_ops = &vnops;
				fg->fg_data = ndp->ni_vp;

				vnode_put(ndp->ni_vp);

				proc_fdlock(p);
				procfdtbl_releasefd(p, indx, NULL);
				fp_drop(p, indx, fp, 1);
				proc_fdunlock(p);

				FREE(ndp, M_TEMP);
			}
		}
	}
#if CONFIG_MACF
	else {
		/*
		 * We are here because we were told that the MAC label will
		 * be transitioned, and the binary is not VSUID or VSGID; to
		 * deal with this case, we could either duplicate a lot of
		 * code, or we can indicate we want to default the P_SUGID
		 * bit clear and jump back up.
		 */
		if (mac_transition) {
			leave_sugid_clear = 1;
			goto handle_mac_transition;
		}
	}

#endif	/* CONFIG_MACF */

	/*
	 * Implement the semantic where the effective user and group become
	 * the saved user and group in exec'ed programs.
	 *
	 * Modifications to p_ucred must be guarded using the
	 * proc's ucred lock. This prevents others from accessing
	 * a garbage credential.
	 */
	for (;;) {
		my_cred = kauth_cred_proc_ref(p);
		my_new_cred = kauth_cred_setsvuidgid(my_cred, kauth_cred_getuid(my_cred),  kauth_cred_getgid(my_cred));

		if (my_new_cred == my_cred) {
			kauth_cred_unref(&my_cred);
			break;
		}

		/* update cred on proc */
		proc_ucred_lock(p);

		if (p->p_ucred != my_cred) {
			proc_ucred_unlock(p);
			kauth_cred_unref(&my_new_cred);
			continue;
		}

		/* donate cred reference on my_new_cred to p->p_ucred */
		p->p_ucred = my_new_cred;
		PROC_UPDATE_CREDS_ONPROC(p);
		proc_ucred_unlock(p);

		/* drop additional reference that was taken on the previous cred */
		kauth_cred_unref(&my_cred);

		break;
	}


	/* Update the process' identity version and set the security token */
	p->p_idversion++;

	if (imgp->ip_new_thread != NULL) {
		task = get_threadtask(imgp->ip_new_thread);
	} else {
		task = p->task;
	}
	set_security_token_task_internal(p, task);

	return(error);
}


/*
 * create_unix_stack
 *
 * Description:	Set the user stack address for the process to the provided
 *		address.  If a custom stack was not set as a result of the
 *		load process (i.e. as specified by the image file for the
 *		executable), then allocate the stack in the provided map and
 *		set up appropriate guard pages for enforcing administrative
 *		limits on stack growth, if they end up being needed.
 *
 * Parameters:	p			Process to set stack on
 *		load_result		Information from mach-o load commands
 *		map			Address map in which to allocate the new stack
 *
 * Returns:	KERN_SUCCESS		Stack successfully created
 *		!KERN_SUCCESS		Mach failure code
 */
static kern_return_t
create_unix_stack(vm_map_t map, load_result_t* load_result, 
			proc_t p)
{
	mach_vm_size_t		size, prot_size;
	mach_vm_offset_t	addr, prot_addr;
	kern_return_t		kr;

	mach_vm_address_t	user_stack = load_result->user_stack;
	
	proc_lock(p);
	p->user_stack = user_stack;
	proc_unlock(p);

	if (load_result->user_stack_alloc_size > 0) {
		/*
		 * Allocate enough space for the maximum stack size we
		 * will ever authorize and an extra page to act as
		 * a guard page for stack overflows. For default stacks,
		 * vm_initial_limit_stack takes care of the extra guard page.
		 * Otherwise we must allocate it ourselves.
		 */
		if (mach_vm_round_page_overflow(load_result->user_stack_alloc_size, &size)) {
			return KERN_INVALID_ARGUMENT;
		}
		addr = mach_vm_trunc_page(load_result->user_stack - size);
		kr = mach_vm_allocate(map, &addr, size,
				      VM_MAKE_TAG(VM_MEMORY_STACK) |
				      VM_FLAGS_FIXED);
		if (kr != KERN_SUCCESS) {
			// Can't allocate at default location, try anywhere
			addr = 0;
			kr = mach_vm_allocate(map, &addr, size,
					      VM_MAKE_TAG(VM_MEMORY_STACK) |
					      VM_FLAGS_ANYWHERE);
			if (kr != KERN_SUCCESS) {
				return kr;
			}

			user_stack = addr + size;
			load_result->user_stack = user_stack;

			proc_lock(p);
			p->user_stack = user_stack;
			proc_unlock(p);
		}

		load_result->user_stack_alloc = addr;

		/*
		 * And prevent access to what's above the current stack
		 * size limit for this process.
		 */
		if (load_result->user_stack_size == 0) {
			load_result->user_stack_size = unix_stack_size(p);
			prot_size = mach_vm_trunc_page(size - load_result->user_stack_size);
		} else {
			prot_size = PAGE_SIZE;
		}

		prot_addr = addr;
		kr = mach_vm_protect(map,
				     prot_addr,
				     prot_size,
				     FALSE,
				     VM_PROT_NONE);
		if (kr != KERN_SUCCESS) {
			(void)mach_vm_deallocate(map, addr, size);
			return kr;
		}
	}

	return KERN_SUCCESS;
}

#include <sys/reboot.h>

/*
 * load_init_program_at_path
 *
 * Description:	Load the "init" program; in most cases, this will be "launchd"
 *
 * Parameters:	p			Process to call execve() to create
 *					the "init" program
 *		scratch_addr		Page in p, scratch space
 *		path			NULL terminated path
 *
 * Returns:	KERN_SUCCESS		Success
 *		!KERN_SUCCESS 		See execve/mac_execve for error codes
 *
 * Notes:	The process that is passed in is the first manufactured
 *		process on the system, and gets here via bsd_ast() firing
 *		for the first time.  This is done to ensure that bsd_init()
 *		has run to completion.
 *
 *		The address map of the first manufactured process matches the
 *		word width of the kernel. Once the self-exec completes, the
 *		initproc might be different.
 */
static int
load_init_program_at_path(proc_t p, user_addr_t scratch_addr, const char* path)
{
	int retval[2];
	int error;
	struct execve_args init_exec_args;
	user_addr_t argv0 = USER_ADDR_NULL, argv1 = USER_ADDR_NULL;

	/*
	 * Validate inputs and pre-conditions
	 */
	assert(p);
	assert(scratch_addr);
	assert(path);

	/*
	 * Copy out program name.
	 */
	size_t path_length = strlen(path) + 1;
	argv0 = scratch_addr;
	error = copyout(path, argv0, path_length);
	if (error)
		return error;

	scratch_addr = USER_ADDR_ALIGN(scratch_addr + path_length, sizeof(user_addr_t));

	/*
	 * Put out first (and only) argument, similarly.
	 * Assumes everything fits in a page as allocated above.
	 */
	if (boothowto & RB_SINGLE) {
		const char *init_args = "-s";
		size_t init_args_length = strlen(init_args)+1;

		argv1 = scratch_addr;
		error = copyout(init_args, argv1, init_args_length);
		if (error)
			return error;

		scratch_addr = USER_ADDR_ALIGN(scratch_addr + init_args_length, sizeof(user_addr_t));
	}

	if (proc_is64bit(p)) {
		user64_addr_t argv64bit[3];

		argv64bit[0] = argv0;
		argv64bit[1] = argv1;
		argv64bit[2] = USER_ADDR_NULL;

		error = copyout(argv64bit, scratch_addr, sizeof(argv64bit));
		if (error)
			return error;
	} else {
		user32_addr_t argv32bit[3];

		argv32bit[0] = (user32_addr_t)argv0;
		argv32bit[1] = (user32_addr_t)argv1;
		argv32bit[2] = USER_ADDR_NULL;

		error = copyout(argv32bit, scratch_addr, sizeof(argv32bit));
		if (error)
			return error;
	}

	/*
	 * Set up argument block for fake call to execve.
	 */
	init_exec_args.fname = argv0;
	init_exec_args.argp = scratch_addr;
	init_exec_args.envp = USER_ADDR_NULL;

	/*
	 * So that init task is set with uid,gid 0 token
	 */
	set_security_token(p);

	return execve(p, &init_exec_args, retval);
}

static const char * init_programs[] = {
#if DEBUG
	"/usr/local/sbin/launchd.debug",
#endif
#if DEVELOPMENT || DEBUG
	"/usr/local/sbin/launchd.development",
#endif
	"/sbin/launchd",
};

/*
 * load_init_program
 *
 * Description:	Load the "init" program; in most cases, this will be "launchd"
 *
 * Parameters:	p			Process to call execve() to create
 *					the "init" program
 *
 * Returns:	(void)
 *
 * Notes:	The process that is passed in is the first manufactured
 *		process on the system, and gets here via bsd_ast() firing
 *		for the first time.  This is done to ensure that bsd_init()
 *		has run to completion.
 *
 *		In DEBUG & DEVELOPMENT builds, the launchdsuffix boot-arg
 *		may be used to select a specific launchd executable. As with
 *		the kcsuffix boot-arg, setting launchdsuffix to "" or "release"
 *		will force /sbin/launchd to be selected.
 *
 *              Search order by build:
 *
 * DEBUG	DEVELOPMENT	RELEASE		PATH
 * ----------------------------------------------------------------------------------
 * 1		1		NA		/usr/local/sbin/launchd.$LAUNCHDSUFFIX
 * 2		NA		NA		/usr/local/sbin/launchd.debug
 * 3		2		NA		/usr/local/sbin/launchd.development
 * 4		3		1		/sbin/launchd
 */
void
load_init_program(proc_t p)
{
	uint32_t i;
	int error;
	vm_map_t map = current_map();
	mach_vm_offset_t scratch_addr = 0;
	mach_vm_size_t map_page_size = vm_map_page_size(map);

	(void) mach_vm_allocate(map, &scratch_addr, map_page_size, VM_FLAGS_ANYWHERE);
#if CONFIG_MEMORYSTATUS && CONFIG_JETSAM
	(void) memorystatus_init_at_boot_snapshot();
#endif /* CONFIG_MEMORYSTATUS && CONFIG_JETSAM */

#if DEBUG || DEVELOPMENT
	/* Check for boot-arg suffix first */
	char launchd_suffix[64];
	if (PE_parse_boot_argn("launchdsuffix", launchd_suffix, sizeof(launchd_suffix))) {
		char launchd_path[128];
		boolean_t is_release_suffix = ((launchd_suffix[0] == 0) ||
					       (strcmp(launchd_suffix, "release") == 0));

		if (is_release_suffix) {
			error = load_init_program_at_path(p, (user_addr_t)scratch_addr, "/sbin/launchd");
			if (!error)
				return;

			panic("Process 1 exec of launchd.release failed, errno %d", error);
		} else {
			strlcpy(launchd_path, "/usr/local/sbin/launchd.", sizeof(launchd_path));
			strlcat(launchd_path, launchd_suffix, sizeof(launchd_path));

			/* All the error data is lost in the loop below, don't
			 * attempt to save it. */
			if (!load_init_program_at_path(p, (user_addr_t)scratch_addr, launchd_path)) {
				return;
			}
		}
	}
#endif

	error = ENOENT;
	for (i = 0; i < sizeof(init_programs)/sizeof(init_programs[0]); i++) {
		error = load_init_program_at_path(p, (user_addr_t)scratch_addr, init_programs[i]);
		if (!error)
			return;
	}

	panic("Process 1 exec of %s failed, errno %d", ((i == 0) ? "<null>" : init_programs[i-1]), error);
}

/*
 * load_return_to_errno
 *
 * Description:	Convert a load_return_t (Mach error) to an errno (BSD error)
 *
 * Parameters:	lrtn			Mach error number
 *
 * Returns:	(int)			BSD error number
 *		0			Success
 *		EBADARCH		Bad architecture
 *		EBADMACHO		Bad Mach object file
 *		ESHLIBVERS		Bad shared library version
 *		ENOMEM			Out of memory/resource shortage
 *		EACCES			Access denied
 *		ENOENT			Entry not found (usually "file does
 *					does not exist")
 *		EIO			An I/O error occurred
 *		EBADEXEC		The executable is corrupt/unknown
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
	case LOAD_BADMACHO_UPX:
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
	case LOAD_DECRYPTFAIL:
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

/*
 * execargs_alloc
 *
 * Description:	Allocate the block of memory used by the execve arguments.
 *		At the same time, we allocate a page so that we can read in
 *		the first page of the image.
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EACCES			Permission denied
 *		EINTR			Interrupted function
 *		ENOMEM			Not enough space
 *
 * Notes:	This is a temporary allocation into the kernel address space
 *		to enable us to copy arguments in from user space.  This is
 *		necessitated by not mapping the process calling execve() into
 *		the kernel address space during the execve() system call.
 *
 *		We assemble the argument and environment, etc., into this
 *		region before copying it as a single block into the child
 *		process address space (at the top or bottom of the stack,
 *		depending on which way the stack grows; see the function
 *		exec_copyout_strings() for details).
 *
 *		This ends up with a second (possibly unnecessary) copy compared
 *		with assembing the data directly into the child address space,
 *		instead, but since we cannot be guaranteed that the parent has
 *		not modified its environment, we can't really know that it's
 *		really a block there as well.
 */


static int execargs_waiters = 0;
lck_mtx_t *execargs_cache_lock;

static void
execargs_lock_lock(void) {
	lck_mtx_lock_spin(execargs_cache_lock);
}

static void
execargs_lock_unlock(void) {
	lck_mtx_unlock(execargs_cache_lock);
}

static wait_result_t
execargs_lock_sleep(void) {
	return(lck_mtx_sleep(execargs_cache_lock, LCK_SLEEP_DEFAULT, &execargs_free_count, THREAD_INTERRUPTIBLE));
}

static kern_return_t
execargs_purgeable_allocate(char **execarg_address) {
	kern_return_t kr = vm_allocate(bsd_pageable_map, (vm_offset_t *)execarg_address, BSD_PAGEABLE_SIZE_PER_EXEC, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	assert(kr == KERN_SUCCESS);
	return kr;
}

static kern_return_t
execargs_purgeable_reference(void *execarg_address) {
	int state = VM_PURGABLE_NONVOLATILE;
	kern_return_t kr = vm_purgable_control(bsd_pageable_map, (vm_offset_t) execarg_address, VM_PURGABLE_SET_STATE, &state);

	assert(kr == KERN_SUCCESS);
	return kr;
}

static kern_return_t
execargs_purgeable_volatilize(void *execarg_address) {
	int state = VM_PURGABLE_VOLATILE | VM_PURGABLE_ORDERING_OBSOLETE;
	kern_return_t kr;
	kr = vm_purgable_control(bsd_pageable_map, (vm_offset_t) execarg_address, VM_PURGABLE_SET_STATE, &state);

	assert(kr == KERN_SUCCESS);

	return kr;
}

static void
execargs_wakeup_waiters(void) {
	thread_wakeup(&execargs_free_count);
}

static int
execargs_alloc(struct image_params *imgp)
{
	kern_return_t kret;
	wait_result_t res;
	int i, cache_index = -1;

	execargs_lock_lock();

	while (execargs_free_count == 0) {
		execargs_waiters++;
		res = execargs_lock_sleep();
		execargs_waiters--;
		if (res != THREAD_AWAKENED) {
			execargs_lock_unlock();
			return (EINTR);
		}
	}

	execargs_free_count--;

	for (i = 0; i < execargs_cache_size; i++) {
		vm_offset_t element = execargs_cache[i];
		if (element) {
			cache_index = i;
			imgp->ip_strings = (char *)(execargs_cache[i]);
			execargs_cache[i] = 0;
			break;
		}
	}

	assert(execargs_free_count >= 0);

	execargs_lock_unlock();
	
	if (cache_index == -1) {
		kret = execargs_purgeable_allocate(&imgp->ip_strings);
	}
	else
		kret = execargs_purgeable_reference(imgp->ip_strings);

	assert(kret == KERN_SUCCESS);
	if (kret != KERN_SUCCESS) {
		return (ENOMEM);
	}

	/* last page used to read in file headers */
	imgp->ip_vdata = imgp->ip_strings + ( NCARGS + PAGE_SIZE );
	imgp->ip_strendp = imgp->ip_strings;
	imgp->ip_argspace = NCARGS;
	imgp->ip_strspace = ( NCARGS + PAGE_SIZE );

	return (0);
}

/*
 * execargs_free
 *
 * Description:	Free the block of memory used by the execve arguments and the
 *		first page of the executable by a previous call to the function
 *		execargs_alloc().
 *
 * Parameters:	struct image_params *	the image parameter block
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EINTR			Oeration interrupted
 */
static int
execargs_free(struct image_params *imgp)
{
	kern_return_t kret;
	int i;
	boolean_t needs_wakeup = FALSE;
	
	kret = execargs_purgeable_volatilize(imgp->ip_strings);

	execargs_lock_lock();
	execargs_free_count++;

	for (i = 0; i < execargs_cache_size; i++) {
		vm_offset_t element = execargs_cache[i];
		if (element == 0) {
			execargs_cache[i] = (vm_offset_t) imgp->ip_strings;
			imgp->ip_strings = NULL;
			break;
		}
	}

	assert(imgp->ip_strings == NULL);

	if (execargs_waiters > 0)
		needs_wakeup = TRUE;
	
	execargs_lock_unlock();

	if (needs_wakeup == TRUE)
		execargs_wakeup_waiters();

	return ((kret == KERN_SUCCESS ? 0 : EINVAL));
}

static void
exec_resettextvp(proc_t p, struct image_params *imgp)
{
	vnode_t vp;
	off_t offset;
	vnode_t tvp  = p->p_textvp;
	int ret;

	vp = imgp->ip_vp;
	offset = imgp->ip_arch_offset;

	if (vp == NULLVP)
		panic("exec_resettextvp: expected valid vp");

	ret = vnode_ref(vp);
	proc_lock(p);
	if (ret == 0) {
		p->p_textvp = vp;
		p->p_textoff = offset;
	} else {
		p->p_textvp = NULLVP;	/* this is paranoia */
		p->p_textoff = 0;
	}
	proc_unlock(p);

	if ( tvp != NULLVP) {
		if (vnode_getwithref(tvp) == 0) {
			vnode_rele(tvp);
			vnode_put(tvp);
		}
	}	

}

/*
 * If the process is not signed or if it contains entitlements, we
 * need to communicate through the task_access_port to taskgated.
 *
 * taskgated will provide a detached code signature if present, and
 * will enforce any restrictions on entitlements.
 */

static boolean_t
taskgated_required(proc_t p, boolean_t *require_success)
{
	size_t length;
	void *blob;
	int error;

	if (cs_debug > 2)
		csvnode_print_debug(p->p_textvp);

	const int can_skip_taskgated = csproc_get_platform_binary(p) && !csproc_get_platform_path(p);
	if (can_skip_taskgated) {
		if (cs_debug) printf("taskgated not required for: %s\n", p->p_name);
		*require_success = FALSE;
		return FALSE;
	}

	if ((p->p_csflags & CS_VALID) == 0) {
		*require_success = FALSE;
		return TRUE;
	}

	error = cs_entitlements_blob_get(p, &blob, &length);
	if (error == 0 && blob != NULL) {
		/*
		 * fatal on the desktop when entitlements are present,
		 * unless we started in single-user mode 
		 */
		if ((boothowto & RB_SINGLE) == 0)
			*require_success = TRUE;
		/*
		 * Allow initproc to run without causing taskgated to launch
		 */
		if (p == initproc) {
			*require_success = FALSE;
			return FALSE;
		}

		if (cs_debug) printf("taskgated required for: %s\n", p->p_name);

		return TRUE;
	}

	*require_success = FALSE;
	return FALSE;
}

/*
 * __EXEC_WAITING_ON_TASKGATED_CODE_SIGNATURE_UPCALL__
 * 
 * Description: Waits for the userspace daemon to respond to the request
 * 		we made. Function declared non inline to be visible in
 *		stackshots and spindumps as well as debugging.
 */
__attribute__((noinline)) int 
__EXEC_WAITING_ON_TASKGATED_CODE_SIGNATURE_UPCALL__(mach_port_t task_access_port, int32_t new_pid)
{
	return find_code_signature(task_access_port, new_pid);
}

static int
check_for_signature(proc_t p, struct image_params *imgp)
{
	mach_port_t port = NULL;
	kern_return_t kr = KERN_FAILURE;
	int error = EACCES;
	boolean_t unexpected_failure = FALSE;
	unsigned char hash[SHA1_RESULTLEN];
	boolean_t require_success = FALSE;
	int spawn = (imgp->ip_flags & IMGPF_SPAWN);
	int vfexec = (imgp->ip_flags & IMGPF_VFORK_EXEC);
	os_reason_t signature_failure_reason = OS_REASON_NULL;

	/*
	 * Override inherited code signing flags with the
	 * ones for the process that is being successfully
	 * loaded
	 */
	proc_lock(p);
	p->p_csflags = imgp->ip_csflags;
	proc_unlock(p);

	/* Set the switch_protect flag on the map */
	if(p->p_csflags & (CS_HARD|CS_KILL)) {
		vm_map_switch_protect(get_task_map(p->task), TRUE);
	}
	
	/*
	 * image activation may be failed due to policy
	 * which is unexpected but security framework does not
	 * approve of exec, kill and return immediately.
	 */
	if (imgp->ip_mac_return != 0) {

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_SECURITY_POLICY, 0, 0);
		signature_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_SECURITY_POLICY);
		error = imgp->ip_mac_return;
		unexpected_failure = TRUE;
		goto done;
	}

	if (imgp->ip_cs_error != OS_REASON_NULL) {
		signature_failure_reason = imgp->ip_cs_error;
		imgp->ip_cs_error = OS_REASON_NULL;
		error = EACCES;
		goto done;
	}

	/* check if callout to taskgated is needed */
	if (!taskgated_required(p, &require_success)) {
		error = 0;
		goto done;
	}

	kr = task_get_task_access_port(p->task, &port);
	if (KERN_SUCCESS != kr || !IPC_PORT_VALID(port)) {
		error = 0;
		if (require_success) {
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
							p->p_pid, OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_TASK_ACCESS_PORT, 0, 0);
			signature_failure_reason = os_reason_create(OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_TASK_ACCESS_PORT);
			error = EACCES;
		}
		goto done;
	}

	/*
	 * taskgated returns KERN_SUCCESS if it has completed its work
	 * and the exec should continue, KERN_FAILURE if the exec should 
	 * fail, or it may error out with different error code in an 
	 * event of mig failure (e.g. process was signalled during the 
	 * rpc call, taskgated died, mig server died etc.).
	 */

	kr = __EXEC_WAITING_ON_TASKGATED_CODE_SIGNATURE_UPCALL__(port, p->p_pid);
	switch (kr) {
	case KERN_SUCCESS:
		error = 0;
		break;
	case KERN_FAILURE:
		error = EACCES;

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG, 0, 0);
		signature_failure_reason = os_reason_create(OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG);
		goto done;
	default:
		error = EACCES;

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
						p->p_pid, OS_REASON_EXEC, EXEC_EXIT_REASON_TASKGATED_OTHER, 0, 0);
		signature_failure_reason = os_reason_create(OS_REASON_EXEC, EXEC_EXIT_REASON_TASKGATED_OTHER);
		unexpected_failure = TRUE;
		goto done;
	}

	/* Only do this if exec_resettextvp() did not fail */
	if (p->p_textvp != NULLVP) {
		/*
		 * If there's a new code directory, mark this process
		 * as signed.
		 */
		if (0 == ubc_cs_getcdhash(p->p_textvp, p->p_textoff, hash)) {
			proc_lock(p);
			p->p_csflags |= CS_VALID;
			proc_unlock(p);
		}
	}

done:
	if (0 != error) {
		if (!unexpected_failure)
			p->p_csflags |= CS_KILLED;
		/* make very sure execution fails */
		if (vfexec || spawn) {
			assert(signature_failure_reason != OS_REASON_NULL);
			psignal_vfork_with_reason(p, p->task, imgp->ip_new_thread,
					SIGKILL, signature_failure_reason);
			signature_failure_reason = OS_REASON_NULL;
			error = 0;
		} else {
			assert(signature_failure_reason != OS_REASON_NULL);
			psignal_with_reason(p, SIGKILL, signature_failure_reason);
			signature_failure_reason = OS_REASON_NULL;
		}
	}

	/* If we hit this, we likely would have leaked an exit reason */
	assert(signature_failure_reason == OS_REASON_NULL);
	return error;
}

/*
 * Typically as soon as we start executing this process, the
 * first instruction will trigger a VM fault to bring the text
 * pages (as executable) into the address space, followed soon
 * thereafter by dyld data structures (for dynamic executable).
 * To optimize this, as well as improve support for hardware
 * debuggers that can only access resident pages present
 * in the process' page tables, we prefault some pages if
 * possible. Errors are non-fatal.
 */
static void exec_prefault_data(proc_t p __unused, struct image_params *imgp, load_result_t *load_result)
{
	int ret;
	size_t expected_all_image_infos_size;

	/*
	 * Prefault executable or dyld entry point.
	 */
	vm_fault(current_map(),
		 vm_map_trunc_page(load_result->entry_point,
				   vm_map_page_mask(current_map())),
		 VM_PROT_READ | VM_PROT_EXECUTE,
		 FALSE,
		 THREAD_UNINT, NULL, 0);
	
	if (imgp->ip_flags & IMGPF_IS_64BIT) {
		expected_all_image_infos_size = sizeof(struct user64_dyld_all_image_infos);
	} else {
		expected_all_image_infos_size = sizeof(struct user32_dyld_all_image_infos);
	}

	/* Decode dyld anchor structure from <mach-o/dyld_images.h> */
	if (load_result->dynlinker &&
		load_result->all_image_info_addr &&
		load_result->all_image_info_size >= expected_all_image_infos_size) {
		union {
			struct user64_dyld_all_image_infos	infos64;
			struct user32_dyld_all_image_infos	infos32;
		} all_image_infos;

		/*
		 * Pre-fault to avoid copyin() going through the trap handler
		 * and recovery path.
		 */
		vm_fault(current_map(),
			 vm_map_trunc_page(load_result->all_image_info_addr,
					   vm_map_page_mask(current_map())),
			 VM_PROT_READ | VM_PROT_WRITE,
			 FALSE,
			 THREAD_UNINT, NULL, 0);
		if ((load_result->all_image_info_addr & PAGE_MASK) + expected_all_image_infos_size > PAGE_SIZE) {
			/* all_image_infos straddles a page */
			vm_fault(current_map(),
				 vm_map_trunc_page(load_result->all_image_info_addr + expected_all_image_infos_size - 1,
						   vm_map_page_mask(current_map())),
				 VM_PROT_READ | VM_PROT_WRITE,
				 FALSE,
				 THREAD_UNINT, NULL, 0);
		}

		ret = copyin(load_result->all_image_info_addr,
					 &all_image_infos,
					 expected_all_image_infos_size);
		if (ret == 0 && all_image_infos.infos32.version >= 9) {

			user_addr_t notification_address;
			user_addr_t dyld_image_address;
			user_addr_t dyld_version_address;
			user_addr_t dyld_all_image_infos_address;
			user_addr_t dyld_slide_amount;

			if (imgp->ip_flags & IMGPF_IS_64BIT) {
				notification_address = all_image_infos.infos64.notification;
				dyld_image_address = all_image_infos.infos64.dyldImageLoadAddress;
				dyld_version_address = all_image_infos.infos64.dyldVersion;
				dyld_all_image_infos_address = all_image_infos.infos64.dyldAllImageInfosAddress;
			} else {
				notification_address = all_image_infos.infos32.notification;
				dyld_image_address = all_image_infos.infos32.dyldImageLoadAddress;
				dyld_version_address = all_image_infos.infos32.dyldVersion;
				dyld_all_image_infos_address = all_image_infos.infos32.dyldAllImageInfosAddress;
			}

			/*
			 * dyld statically sets up the all_image_infos in its Mach-O
			 * binary at static link time, with pointers relative to its default
			 * load address. Since ASLR might slide dyld before its first
			 * instruction is executed, "dyld_slide_amount" tells us how far
			 * dyld was loaded compared to its default expected load address.
			 * All other pointers into dyld's image should be adjusted by this
			 * amount. At some point later, dyld will fix up pointers to take
			 * into account the slide, at which point the all_image_infos_address
			 * field in the structure will match the runtime load address, and
			 * "dyld_slide_amount" will be 0, if we were to consult it again.
			 */

			dyld_slide_amount = load_result->all_image_info_addr - dyld_all_image_infos_address;

#if 0
			kprintf("exec_prefault: 0x%016llx 0x%08x 0x%016llx 0x%016llx 0x%016llx 0x%016llx\n",
					(uint64_t)load_result->all_image_info_addr,
					all_image_infos.infos32.version,
					(uint64_t)notification_address,
					(uint64_t)dyld_image_address,
					(uint64_t)dyld_version_address,
					(uint64_t)dyld_all_image_infos_address);
#endif

			vm_fault(current_map(),
				 vm_map_trunc_page(notification_address + dyld_slide_amount,
						   vm_map_page_mask(current_map())),
				 VM_PROT_READ | VM_PROT_EXECUTE,
				 FALSE,
				 THREAD_UNINT, NULL, 0);
			vm_fault(current_map(),
				 vm_map_trunc_page(dyld_image_address + dyld_slide_amount,
						   vm_map_page_mask(current_map())),
				 VM_PROT_READ | VM_PROT_EXECUTE,
				 FALSE,
				 THREAD_UNINT, NULL, 0);
			vm_fault(current_map(),
				 vm_map_trunc_page(dyld_version_address + dyld_slide_amount,
						   vm_map_page_mask(current_map())),
				 VM_PROT_READ,
				 FALSE,
				 THREAD_UNINT, NULL, 0);
			vm_fault(current_map(),
				 vm_map_trunc_page(dyld_all_image_infos_address + dyld_slide_amount,
						   vm_map_page_mask(current_map())),
				 VM_PROT_READ | VM_PROT_WRITE,
				 FALSE,
				 THREAD_UNINT, NULL, 0);
		}
	}
}
