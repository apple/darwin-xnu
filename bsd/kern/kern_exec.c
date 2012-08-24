/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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
#if SYSV_SHM
#include <sys/shm_internal.h>		/* shmexec() */
#endif
#include <sys/ubc_internal.h>		/* ubc_map() */
#include <sys/spawn.h>
#include <sys/spawn_internal.h>
#include <sys/codesign.h>
#include <crypto/sha1.h>

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

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_mach_internal.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <kdp/kdp_dyld.h>

#include <machine/pal_routines.h>

#include <pexpert/pexpert.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void (*dtrace_fasttrap_exec_ptr)(proc_t);
extern void (*dtrace_helpers_cleanup)(proc_t);
extern void dtrace_lazy_dofs_destroy(proc_t);

#include <sys/dtrace_ptss.h>
#endif

/* support for child creation in exec after vfork */
thread_t fork_create_child(task_t parent_task, proc_t child_proc, int inherit_memory, int is64bit);
void vfork_exit(proc_t p, int rv);
int setsigvec(proc_t, thread_t, int, struct __kern_sigaction *, boolean_t in_sigstart);
extern void proc_apply_task_networkbg_internal(proc_t, thread_t);
int task_set_cpuusage(task_t task, uint64_t percentage, uint64_t interval, uint64_t deadline, int scope);

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

extern struct savearea *get_user_regs(thread_t);


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
#define EAI_ITERLIMIT		10

/*
 * For #! interpreter parsing
 */
#define IS_WHITESPACE(ch) ((ch == ' ') || (ch == '\t'))
#define IS_EOL(ch) ((ch == '#') || (ch == '\n'))

extern vm_map_t bsd_pageable_map;
extern struct fileops vnops;

#define	ROUND_PTR(type, addr)	\
	(type *)( ( (uintptr_t)(addr) + 16 - 1) \
		  & ~(16 - 1) )

struct image_params;	/* Forward */
static int exec_activate_image(struct image_params *imgp);
static int exec_copyout_strings(struct image_params *imgp, user_addr_t *stackp);
static int load_return_to_errno(load_return_t lrtn);
static int execargs_alloc(struct image_params *imgp);
static int execargs_free(struct image_params *imgp);
static int exec_check_permissions(struct image_params *imgp);
static int exec_extract_strings(struct image_params *imgp);
static int exec_add_apple_strings(struct image_params *imgp);
static int exec_handle_sugid(struct image_params *imgp);
static int sugid_scripts = 0;
SYSCTL_INT (_kern, OID_AUTO, sugid_scripts, CTLFLAG_RW | CTLFLAG_LOCKED, &sugid_scripts, 0, "");
static kern_return_t create_unix_stack(vm_map_t map, load_result_t* load_result, proc_t p);
static int copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size);
static void exec_resettextvp(proc_t, struct image_params *);
static int check_for_signature(proc_t, struct image_params *);
static void exec_prefault_data(proc_t, struct image_params *, load_result_t *);

#if !CONFIG_EMBEDDED

/* Identify process during exec and opt into legacy behaviors */

struct legacy_behavior {
    uuid_t    process_uuid;
    uint32_t  legacy_mask;
};

static const struct legacy_behavior legacy_behaviors[] =
{
	{{ 0xF8, 0x7C, 0xC3, 0x67, 0xFB, 0x68, 0x37, 0x93, 0xBC, 0x34, 0xB2, 0xB6, 0x05, 0x2B, 0xCD, 0xE2 }, PROC_LEGACY_BEHAVIOR_IOTHROTTLE },
	{{ 0x0B, 0x4E, 0xDF, 0xD8, 0x76, 0xD1, 0x3D, 0x4D, 0x9D, 0xD7, 0x37, 0x43, 0x1C, 0xA8, 0xFB, 0x26 }, PROC_LEGACY_BEHAVIOR_IOTHROTTLE },
};
#endif /* !CONFIG_EMBEDDED */

/* We don't want this one exported */
__private_extern__
int  open1(vfs_context_t, struct nameidata *, int, struct vnode_attr *, int32_t *);

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
exec_save_path(struct image_params *imgp, user_addr_t path, int seg)
{
	int error;
	size_t	len;
	char *kpath;

	len = MIN(MAXPATHLEN, imgp->ip_strspace);

	switch(seg) {
	case UIO_USERSPACE32:
	case UIO_USERSPACE64:	/* Same for copyin()... */
		error = copyinstr(path, imgp->ip_strings, len, &len);
		break;
	case UIO_SYSSPACE:
		kpath = CAST_DOWN(char *,path);	/* SAFE */
		error = copystr(kpath, imgp->ip_strings, len, &len);
		break;
	default:
		error = EFAULT;
		break;
	}

	if (!error) {
		imgp->ip_strendp += len;
		imgp->ip_strspace -= len;
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
 * Image activator for interpreter scripts.  If the image begins with the
 * characters "#!", then it is an interpreter script.  Verify that we are
 * not already executing in PowerPC mode, and that the length of the script
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
	char *line_startp, *line_endp;
	char *interp;
	proc_t p;
	struct fileproc *fp;
	int fd;
	int error;

	/*
	 * Make sure it's a shell script.  If we've already redirected
	 * from an interpreted file once, don't do it again.
	 *
	 * Note: We disallow PowerPC, since the expectation is that we
	 * may run a PowerPC interpreter, but not an interpret a PowerPC 
	 * image.  This is consistent with historical behaviour.
	 */
	if (vdata[0] != '#' ||
	    vdata[1] != '!' ||
	    (imgp->ip_flags & IMGPF_INTERPRET) != 0) {
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
							UIO_SYSSPACE);

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
		fp->f_fglob->fg_type = DTYPE_VNODE;
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

	/* Make sure it's a fat binary */
	if ((fat_header->magic != FAT_MAGIC) &&
            (fat_header->magic != FAT_CIGAM)) {
	    	error = -1;
		goto bad;
	}

	/* If posix_spawn binprefs exist, respect those prefs. */
	psa = (struct _posix_spawnattr *) imgp->ip_px_sa;
	if (psa != NULL && psa->psa_binprefs[0] != 0) {
		struct fat_arch *arches = (struct fat_arch *) (fat_header + 1);
		int nfat_arch = 0, pr = 0, f = 0;

		nfat_arch = OSSwapBigToHostInt32(fat_header->nfat_arch);
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
				break;
			}

			for (f = 0; f < nfat_arch; f++) {
				cpu_type_t archtype = OSSwapBigToHostInt32(
						arches[f].cputype);
				cpu_type_t archsubtype = OSSwapBigToHostInt32(
						arches[f].cpusubtype) & ~CPU_SUBTYPE_MASK;
				if (pref == archtype &&
					grade_binary(archtype, archsubtype)) {
					/* We have a winner! */
					fat_arch.cputype = archtype; 
					fat_arch.cpusubtype = archsubtype; 
					fat_arch.offset = OSSwapBigToHostInt32(
							arches[f].offset);
					fat_arch.size = OSSwapBigToHostInt32(
							arches[f].size);
					fat_arch.align = OSSwapBigToHostInt32(
							arches[f].align);
					goto use_arch;
				}
			}
		}
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

use_arch:
	/* Read the Mach-O header out of fat_arch */
	error = vn_rdwr(UIO_READ, imgp->ip_vp, imgp->ip_vdata,
			PAGE_SIZE, fat_arch.offset,
			UIO_SYSSPACE, (IO_UNIT|IO_NODELOCKED),
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
	kauth_cred_unref(&cred);
	return (error);
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
	int			vfexec = 0;
	task_t			task;
	task_t			new_task = NULL; /* protected by vfexec */
	thread_t		thread;
	struct uthread		*uthread;
	vm_map_t old_map = VM_MAP_NULL;
	vm_map_t map;
	load_return_t		lret;
	load_result_t		load_result;
	struct _posix_spawnattr *psa = NULL;
	int spawn = (imgp->ip_flags & IMGPF_SPAWN);
	int apptype = 0;

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

	switch (mach_header->filetype) {
	case MH_DYLIB:
	case MH_BUNDLE:
		error = -1;
		goto bad;
	}

	if (!imgp->ip_origcputype) {
		imgp->ip_origcputype = mach_header->cputype;
		imgp->ip_origcpusubtype = mach_header->cpusubtype;
	}

	task = current_task();
	thread = current_thread();
	uthread = get_bsdthread_info(thread);

	/*
	 * Save off the vfexec state up front; we have to do this, because
	 * we need to know if we were in this state initially subsequent to
	 * creating the backing task, thread, and uthread for the child
	 * process (from the vfs_context_t from in img_parms).
	 */
	if (uthread->uu_flag & UT_VFORK)
		vfexec = 1;	 /* Mark in exec */

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
	if (!grade_binary(imgp->ip_origcputype & ~CPU_SUBTYPE_LIB64, 
				imgp->ip_origcpusubtype & ~CPU_SUBTYPE_MASK)) {
		error = EBADARCH;
		goto bad;
	}

	/* Copy in arguments/environment from the old process */
	error = exec_extract_strings(imgp);
	if (error)
		goto bad;

	error = exec_add_apple_strings(imgp);
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
	if (vfexec || spawn) {
		if (vfexec) {
			imgp->ip_new_thread = fork_create_child(task, p, FALSE, (imgp->ip_flags & IMGPF_IS_64BIT));
			if (imgp->ip_new_thread == NULL) {
				error = ENOMEM;
				goto bad;
			}
		}

		/* reset local idea of thread, uthread, task */
		thread = imgp->ip_new_thread;
		uthread = get_bsdthread_info(thread);
		task = new_task = get_threadtask(thread);
		map = get_task_map(task);
	} else {
		map = VM_MAP_NULL;
	}

	/*
	 * We set these flags here; this is OK, since if we fail after
	 * this point, we have already destroyed the parent process anyway.
	 */
	task_set_dyld_info(task, MACH_VM_MIN_ADDRESS, 0);
	if (imgp->ip_flags & IMGPF_IS_64BIT) {
		task_set_64bit(task, TRUE);
		OSBitOrAtomic(P_LP64, &p->p_flag);
	} else {
		task_set_64bit(task, FALSE);
		OSBitAndAtomic(~((uint32_t)P_LP64), &p->p_flag);
	}

	/*
	 *	Load the Mach-O file.
	 *
	 * NOTE: An error after this point  indicates we have potentially
	 * destroyed or overwritten some process state while attempting an
	 * execve() following a vfork(), which is an unrecoverable condition.
	 */

	/*
	 * Actually load the image file we previously decided to load.
	 */
	lret = load_machfile(imgp, mach_header, thread, map, &load_result);

	if (lret != LOAD_SUCCESS) {
		error = load_return_to_errno(lret);
		goto badtoolate;
	}

	vm_map_set_user_wire_limit(get_task_map(task), p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur);

	/* 
	 * Set code-signing flags if this binary is signed, or if parent has
	 * requested them on exec.
	 */
	if (load_result.csflags & CS_VALID) {
		imgp->ip_csflags |= load_result.csflags &
			(CS_VALID|
			 CS_HARD|CS_KILL|CS_EXEC_SET_HARD|CS_EXEC_SET_KILL);
	} else {
		imgp->ip_csflags &= ~CS_VALID;
	}

	if (p->p_csflags & CS_EXEC_SET_HARD)
		imgp->ip_csflags |= CS_HARD;
	if (p->p_csflags & CS_EXEC_SET_KILL)
		imgp->ip_csflags |= CS_KILL;


	/*
	 * Set up the system reserved areas in the new address space.
	 */
	vm_map_exec(get_task_map(task),
		    task,
		    (void *) p->p_fd->fd_rdir,
		    cpu_type());
	
	/*
	 * Close file descriptors which specify close-on-exec.
	 */
	fdexec(p, psa != NULL ? psa->psa_flags : 0);

	/*
	 * deal with set[ug]id.
	 */
	error = exec_handle_sugid(imgp);

	/* Make sure we won't interrupt ourself signalling a partial process */
	if (!vfexec && !spawn && (p->p_lflag & P_LTRACED))
		psignal(p, SIGTRAP);

	if (error) {
		goto badtoolate;
	}
	
	if (load_result.unixproc &&
		create_unix_stack(get_task_map(task),
				  &load_result,
				  p) != KERN_SUCCESS) {
		error = load_return_to_errno(LOAD_NOSPACE);
		goto badtoolate;
	}

	if (vfexec || spawn) {
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
			if (vfexec || spawn)
				vm_map_switch(old_map);
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
		        if (vfexec || spawn)
			        vm_map_switch(old_map);
			goto badtoolate;
		}
		task_set_dyld_info(task, load_result.all_image_info_addr,
		    load_result.all_image_info_size);
	}

	/* Avoid immediate VM faults back into kernel */
	exec_prefault_data(p, imgp, &load_result);

	if (vfexec || spawn) {
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

	pal_dbg_set_task_name( p->task );

	memcpy(&p->p_uuid[0], &load_result.uuid[0], sizeof(p->p_uuid));

#if !CONFIG_EMBEDDED
	unsigned int i;

	if (!vfexec && !spawn) {
		if (p->p_legacy_behavior & PROC_LEGACY_BEHAVIOR_IOTHROTTLE) {
			throttle_legacy_process_decr();
		}
	}

	p->p_legacy_behavior = 0;
	for (i=0; i < sizeof(legacy_behaviors)/sizeof(legacy_behaviors[0]); i++) {
		if (0 == uuid_compare(legacy_behaviors[i].process_uuid, p->p_uuid)) {
			p->p_legacy_behavior = legacy_behaviors[i].legacy_mask;
			break;
		}
	}

	if (p->p_legacy_behavior & PROC_LEGACY_BEHAVIOR_IOTHROTTLE) {
		throttle_legacy_process_incr();
	}
#endif

// <rdar://6598155> dtrace code cleanup needed
#if CONFIG_DTRACE
	/*
	 * Invalidate any predicate evaluation already cached for this thread by DTrace.
	 * That's because we've just stored to p_comm and DTrace refers to that when it
	 * evaluates the "execname" special variable. uid and gid may have changed as well.
	 */
	dtrace_set_thread_predcache(current_thread(), 0);

	/*
	 * Free any outstanding lazy dof entries. It is imperative we
	 * always call dtrace_lazy_dofs_destroy, rather than null check
	 * and call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers cleanup. The lazy dof faulting will then
	 * install new helpers which no longer belong to this process!
	 */
	dtrace_lazy_dofs_destroy(p);


	/*
    	 * Clean up any DTrace helpers for the process.
    	 */
    	if (p->p_dtrace_helpers != NULL && dtrace_helpers_cleanup) {
    		(*dtrace_helpers_cleanup)(p);
    	}
	
    	/*
    	 * Cleanup the DTrace provider associated with this process.
    	 */
	proc_lock(p);
	if (p->p_dtrace_probes && dtrace_fasttrap_exec_ptr) {
    		(*dtrace_fasttrap_exec_ptr)(p);
    	}
	proc_unlock(p);
#endif

	if (kdebug_enable) {
		long dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4;

		/*
		 * Collect the pathname for tracing
		 */
		kdbg_trace_string(p, &dbg_arg1, &dbg_arg2, &dbg_arg3, &dbg_arg4);

		if (vfexec || spawn) {
			KERNEL_DEBUG_CONSTANT1((TRACEDBG_CODE(DBG_TRACE_DATA, 2)) | DBG_FUNC_NONE,
					p->p_pid ,0,0,0, (uintptr_t)thread_tid(thread));
			KERNEL_DEBUG_CONSTANT1((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, (uintptr_t)thread_tid(thread));
		} else {
			KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_DATA, 2)) | DBG_FUNC_NONE,
					p->p_pid ,0,0,0,0);
			KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_STRING, 2)) | DBG_FUNC_NONE,
					dbg_arg1, dbg_arg2, dbg_arg3, dbg_arg4, 0);
		}
	}

	/*
	 * Ensure the 'translated' and 'affinity' flags are cleared, since we
	 * no longer run PowerPC binaries.
	 */
	OSBitAndAtomic(~((uint32_t)(P_TRANSLATED | P_AFFINITY)), &p->p_flag);

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
			(void) task_suspend(p->task);
		}
#if CONFIG_EMBEDDED
		if ((psa->psa_flags & POSIX_SPAWN_IOS_RESV1_APP_START) || (psa->psa_flags & POSIX_SPAWN_IOS_APPLE_DAEMON_START) || (psa->psa_flags & POSIX_SPAWN_IOS_APP_START)) {
			if ((psa->psa_flags & POSIX_SPAWN_IOS_RESV1_APP_START))
				apptype = PROC_POLICY_IOS_RESV1_APPTYPE;
			else if (psa->psa_flags & POSIX_SPAWN_IOS_APPLE_DAEMON_START)
				apptype = PROC_POLICY_IOS_APPLE_DAEMON;
			else if (psa->psa_flags & POSIX_SPAWN_IOS_APP_START)
				apptype = PROC_POLICY_IOS_APPTYPE;
			else
				apptype = PROC_POLICY_OSX_APPTYPE_NONE;
			proc_set_task_apptype(p->task, apptype, imgp->ip_new_thread);
			if (apptype == PROC_POLICY_IOS_RESV1_APPTYPE)
				proc_apply_task_networkbg_internal(p, NULL);
			}

		if (psa->psa_apptype & POSIX_SPAWN_APPTYPE_IOS_APPLEDAEMON) {
			apptype = PROC_POLICY_IOS_APPLE_DAEMON;
			proc_set_task_apptype(p->task, apptype, imgp->ip_new_thread);
		}
#else /* CONFIG_EMBEDDED */
		if ((psa->psa_flags & POSIX_SPAWN_OSX_TALAPP_START) || (psa->psa_flags & POSIX_SPAWN_OSX_DBCLIENT_START)) {
			if ((psa->psa_flags & POSIX_SPAWN_OSX_TALAPP_START))
				apptype = PROC_POLICY_OSX_APPTYPE_TAL;
			else if (psa->psa_flags & POSIX_SPAWN_OSX_DBCLIENT_START)
				apptype = PROC_POLICY_OSX_APPTYPE_DBCLIENT;
			else
				apptype = PROC_POLICY_OSX_APPTYPE_NONE;
			proc_set_task_apptype(p->task, apptype, NULL);
			if ((apptype == PROC_POLICY_OSX_APPTYPE_TAL) || 
				(apptype == PROC_POLICY_OSX_APPTYPE_DBCLIENT)) {
				proc_apply_task_networkbg_internal(p, NULL);
			}
		}
		if ((psa->psa_apptype & POSIX_SPAWN_APPTYPE_OSX_TAL) ||
				(psa->psa_apptype & POSIX_SPAWN_APPTYPE_OSX_WIDGET)) {
			if ((psa->psa_apptype & POSIX_SPAWN_APPTYPE_OSX_TAL))
				apptype = PROC_POLICY_OSX_APPTYPE_TAL;
			else if (psa->psa_flags & POSIX_SPAWN_APPTYPE_OSX_WIDGET)
				apptype = PROC_POLICY_OSX_APPTYPE_DBCLIENT;
			else
				apptype = PROC_POLICY_OSX_APPTYPE_NONE;
			proc_set_task_apptype(p->task, apptype, imgp->ip_new_thread);
			if ((apptype == PROC_POLICY_OSX_APPTYPE_TAL) || 
				(apptype == PROC_POLICY_OSX_APPTYPE_DBCLIENT)) {
				proc_apply_task_networkbg_internal(p, NULL);
			}
		}
#endif /* CONFIG_EMBEDDED */
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

badtoolate:
if (!spawn)
	proc_knote(p, NOTE_EXEC);

	if (vfexec || spawn) {
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
 */
static int
exec_activate_image(struct image_params *imgp)
{
	struct nameidata nd;
	int error;
	int resid;
	int once = 1;	/* save SGUID-ness for interpreted files */
	int i;
	int iterlimit = EAI_ITERLIMIT;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);

	error = execargs_alloc(imgp);
	if (error)
		goto bad;
	
	error = exec_save_path(imgp, imgp->ip_user_fname, imgp->ip_seg);
	if (error) {
		goto bad_notrans;
	}

	/* Use imgp->ip_strings, which contains the copyin-ed exec path */
	DTRACE_PROC1(exec, uintptr_t, imgp->ip_strings);

	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
		   UIO_SYSSPACE, CAST_USER_ADDR_T(imgp->ip_strings), imgp->ip_vfs_context);

again:
	error = namei(&nd);
	if (error)
		goto bad_notrans;
	imgp->ip_ndp = &nd;	/* successful namei(); call nameidone() later */
	imgp->ip_vp = nd.ni_vp;	/* if set, need to vnode_put() at some point */

	/*
	 * Before we start the transition from binary A to binary B, make
	 * sure another thread hasn't started exiting the process.  We grab
	 * the proc lock to check p_lflag initially, and the transition
	 * mechanism ensures that the value doesn't change after we release
	 * the lock.
	 */
	proc_lock(p);
	if (p->p_lflag & P_LEXIT) {
		proc_unlock(p);
		goto bad_notrans;
	}
	error = proc_transstart(p, 1);
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
		
encapsulated_binary:
	/* Limit the number of iterations we will attempt on each binary */
	if (--iterlimit == 0) {
		error = EBADEXEC;
		goto bad;
	}
	error = -1;
	for(i = 0; error == -1 && execsw[i].ex_imgact != NULL; i++) {

		error = (*execsw[i].ex_imgact)(imgp);

		switch (error) {
		/* case -1: not claimed: continue */
		case -2:		/* Encapsulated binary */
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
#endif

			nameidone(&nd);

			vnode_put(imgp->ip_vp);
			imgp->ip_vp = NULL;	/* already put */
			imgp->ip_ndp = NULL; /* already nameidone */

			/* Use imgp->ip_strings, which exec_shell_imgact reset to the interpreter */
			NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | LOCKLEAF,
				   UIO_SYSSPACE, CAST_USER_ADDR_T(imgp->ip_strings), imgp->ip_vfs_context);

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
					(uintptr_t)nd.ni_vp, 0);
	}

bad:
	proc_transend(p, 0);

bad_notrans:
	if (imgp->ip_strings)
		execargs_free(imgp);
	if (imgp->ip_ndp)
		nameidone(imgp->ip_ndp);

	return (error);
}

/*
 * exec_handle_port_actions
 *
 * Description:	Go through the _posix_port_actions_t contents, 
 * 		calling task_set_special_port, task_set_exception_ports
 * 		and/or audit_session_spawnjoin for the current task.
 *
 * Parameters:	struct image_params *	Image parameter block
 * 		short psa_flags		posix spawn attribute flags
 *
 * Returns:	0			Success
 * 		EINVAL			Failure
 * 		ENOTSUP			Illegal posix_spawn attr flag was set
 */
static errno_t
exec_handle_port_actions(struct image_params *imgp, short psa_flags)
{
	_posix_spawn_port_actions_t pacts = imgp->ip_px_spa;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	_ps_port_action_t *act = NULL;
	task_t task = p->task;
	ipc_port_t port = NULL;
	errno_t ret = 0;
	int i;

	for (i = 0; i < pacts->pspa_count; i++) {
		act = &pacts->pspa_actions[i];

		if (ipc_object_copyin(get_task_ipcspace(current_task()),
		    act->new_port, MACH_MSG_TYPE_COPY_SEND,
		    (ipc_object_t *) &port) != KERN_SUCCESS)
			return (EINVAL);

		switch (act->port_type) {
		case PSPA_SPECIAL:
			/* Only allowed when not under vfork */
			if (!(psa_flags & POSIX_SPAWN_SETEXEC))
				ret = ENOTSUP;
			else if (task_set_special_port(task,
			    act->which, port) != KERN_SUCCESS)
				ret = EINVAL;
			break;

		case PSPA_EXCEPTION:
			/* Only allowed when not under vfork */
			if (!(psa_flags & POSIX_SPAWN_SETEXEC))
				ret = ENOTSUP;
			else if (task_set_exception_ports(task, 
			    act->mask, port, act->behavior, 
			    act->flavor) != KERN_SUCCESS)
				ret = EINVAL;
			break;
#if CONFIG_AUDIT
		case PSPA_AU_SESSION:
			ret = audit_session_spawnjoin(p, port);
			break;
#endif
		default:
			ret = EINVAL;
			break;
		}

		/* action failed, so release port resources */

		if (ret) { 
			ipc_port_release_send(port);
			break;
		}
	}

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
			struct vnode_attr va;
			struct nameidata nd;
			int mode = psfa->psfaa_openargs.psfao_mode;
			struct dup2_args dup2a;
			struct close_nocancel_args ca;
			int origfd;

			VATTR_INIT(&va);
			/* Mask off all but regular access permissions */
			mode = ((mode &~ p->p_fd->fd_cmask) & ALLPERMS) & ~S_ISTXT;
			VATTR_SET(&va, va_mode, mode & ACCESSPERMS);

			NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(psfa->psfaa_openargs.psfao_path),
			       imgp->ip_vfs_context);

			error = open1(imgp->ip_vfs_context, 
					&nd,
					psfa->psfaa_openargs.psfao_oflag,
					&va,
					ival);

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
			struct fileproc *fp;
			int fd = psfa->psfaa_filedes;

			/*
			 * Check to see if the descriptor exists, and
			 * ensure it's -not- marked as close-on-exec.
			 * [Less code than the equivalent F_GETFD/F_SETFD.]
			 */
			proc_fdlock(p);
			if ((error = fp_lookup(p, fd, &fp, 1)) == 0) {
				*fdflags(p, fd) &= ~UF_EXCLOSE;
				(void) fp_drop(p, fd, fp, 1);
			}
			proc_fdunlock(p);
			}
			break;

		default:
			error = EINVAL;
			break;
		}

		/* All file actions failures are considered fatal, per POSIX */

		if (error)
			break;
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
	char alt_p_comm[sizeof(p->p_comm)] = {0};	/* for PowerPC */
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
	imgp->ip_p_comm = alt_p_comm;		/* for PowerPC */
	imgp->ip_seg = (is_64 ? UIO_USERSPACE64 : UIO_USERSPACE32);

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
		}
		if (error)
			goto bad;

		if (px_args.attr_size != 0) {
			/* 
			 * This could lose some of the port_actions pointer, 
			 * but we already have it from px_args. 
			 */
			if ((error = copyin(px_args.attrp, &px_sa, sizeof(px_sa))) != 0)
			goto bad;

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
		}
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
		if ((error = fork1(p, &imgp->ip_new_thread, PROC_CREATE_SPAWN)) != 0)
			goto bad;
		imgp->ip_flags |= IMGPF_SPAWN;	/* spawn w/o exec */
		spawn_no_exec = TRUE;		/* used in later tests */
	}

	if (spawn_no_exec)
		p = (proc_t)get_bsdthreadtask_info(imgp->ip_new_thread);
	assert(p != NULL);

	/* By default, the thread everyone plays with is the parent */
	context.vc_thread = current_thread();
	context.vc_ucred = p->p_ucred;	/* XXX must NOT be kauth_cred_get() */

	/*
	 * However, if we're not in the setexec case, redirect the context
	 * to the newly created process instead
	 */
	if (spawn_no_exec)
		context.vc_thread = imgp->ip_new_thread;

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
		/* 
		 * The check for the POSIX_SPAWN_SETEXEC flag is done in 
		 * exec_handle_port_actions().
		 */
		if ((error = exec_handle_port_actions(imgp,
		    imgp->ip_px_sa != NULL ? px_sa.psa_flags : 0)) != 0) 
			goto bad;
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
		 * The use of p_ucred is safe, since we are acting on the
		 * new process, and it has no threads other than the one
		 * we are creating for it.
		 */
		if (px_sa.psa_flags & POSIX_SPAWN_RESETIDS) {
			kauth_cred_t my_cred = p->p_ucred;
			kauth_cred_t my_new_cred = kauth_cred_setuidgid(my_cred, kauth_cred_getruid(my_cred), kauth_cred_getrgid(my_cred));
			if (my_new_cred != my_cred) {
				p->p_ucred = my_new_cred;
				/* update cred on proc */
				PROC_UPDATE_CREDS_ONPROC(p);
			}
		}

		/*
		 * Disable ASLR for the spawned process.
		 */
		if (px_sa.psa_flags & _POSIX_SPAWN_DISABLE_ASLR)
			OSBitOrAtomic(P_DISABLE_ASLR, &p->p_flag);

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
		thread_t child_thread = current_thread();
		uthread_t child_uthread = uthread;

		/*
		 * If we created a new child thread, then the thread and
		 * uthread are different than the current ones; otherwise,
		 * we leave them, since we are in the exec case instead.
		 */
		if (spawn_no_exec) {
			child_thread = imgp->ip_new_thread;
			child_uthread = get_bsdthread_info(child_thread);
		}

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
			for (sig = 0; sig < NSIG; sig++)
				if (px_sa.psa_sigdefault & (1 << sig)) {
					error = setsigvec(p, child_thread, sig + 1, &vec, spawn_no_exec);
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
			error = proc_set_task_ruse_cpu(p->task,
					TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC,
					px_sa.psa_cpumonitor_percent,
					px_sa.psa_cpumonitor_interval * NSEC_PER_SEC,
					0);
		}
	}

bad:
	if (error == 0) {
		/* reset delay idle sleep status if set */
#if !CONFIG_EMBEDDED
		if ((p->p_flag & P_DELAYIDLESLEEP) == P_DELAYIDLESLEEP)
			OSBitAndAtomic(~((uint32_t)P_DELAYIDLESLEEP), &p->p_flag);
#endif /* !CONFIG_EMBEDDED */
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
#if !CONFIG_EMBEDDED
			if ((px_sa.psa_apptype & POSIX_SPAWN_APPTYPE_DELAYIDLESLEEP) != 0)
				OSBitOrAtomic(P_DELAYIDLESLEEP, &p->p_flag);
#endif /* !CONFIG_EMBEDDED */
		}
		exec_resettextvp(p, imgp);
		
#if CONFIG_EMBEDDED
		/* Has jetsam attributes? */
		if (imgp->ip_px_sa != NULL) {
        		memorystatus_list_change((px_sa.psa_jetsam_flags & POSIX_SPAWN_JETSAM_USE_EFFECTIVE_PRIORITY),
        				p->p_pid, px_sa.psa_priority, -1, px_sa.psa_high_water_mark);
		}
#endif
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
		proc_knote(p, NOTE_EXEC);
		DTRACE_PROC1(create, proc_t, p);
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
	}


	if (imgp != NULL) {
		if (imgp->ip_vp)
			vnode_put(imgp->ip_vp);
		if (imgp->ip_strings)
			execargs_free(imgp);
		if (imgp->ip_px_sfa != NULL)
			FREE(imgp->ip_px_sfa, M_TEMP);
		if (imgp->ip_px_spa != NULL)
			FREE(imgp->ip_px_spa, M_TEMP);
		
#if CONFIG_MACF
		if (imgp->ip_execlabelp)
			mac_cred_label_free(imgp->ip_execlabelp);
		if (imgp->ip_scriptlabelp)
			mac_vnode_label_free(imgp->ip_scriptlabelp);
#endif
	}

	if (error) {
		DTRACE_PROC1(exec__failure, int, error);
	} else {
            /*
	     * <rdar://6609474> temporary - so dtrace call to current_proc()
	     * returns the child process instead of the parent.
	     */
	    if (imgp != NULL && imgp->ip_flags & IMGPF_SPAWN) {
		p->p_lflag |= P_LINVFORK;
		p->p_vforkact = current_thread();
		uthread->uu_proc = p;
		uthread->uu_flag |= UT_VFORK;
	    }
	    
	    DTRACE_PROC(exec__success);
	    
	    /*
	     * <rdar://6609474> temporary - so dtrace call to current_proc()
	     * returns the child process instead of the parent.
	     */
	    if (imgp != NULL && imgp->ip_flags & IMGPF_SPAWN) {
		p->p_lflag &= ~P_LINVFORK;
		p->p_vforkact = NULL;
		uthread->uu_proc = PROC_NULL;
		uthread->uu_flag &= ~UT_VFORK;
	    }
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
				if (exec_done == FALSE) {
					task_deallocate(get_threadtask(imgp->ip_new_thread));
					thread_deallocate(imgp->ip_new_thread);
				}
			} else {
				/* someone is doing it for us; just skip it */
				proc_unlock(p);
			}
		} else {

			/*
			 * Return" to the child
			 *
			 * Note: the image activator earlier dropped the
			 * task/thread references to the newly spawned
			 * process; this is OK, since we still have suspended
			 * queue references on them, so we should be fine
			 * with the delayed resume of the thread here.
			 */
			(void)thread_resume(imgp->ip_new_thread);
		}
	}
	if (bufp != NULL) {
		FREE(bufp, M_TEMP);
	}
	
	return(error);
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
	char alt_p_comm[sizeof(p->p_comm)] = {0};	/* for PowerPC */
	int is_64 = IS_64BIT_PROCESS(p);
	struct vfs_context context;

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
	imgp->ip_p_comm = alt_p_comm;		/* for PowerPC */
	imgp->ip_seg = (is_64 ? UIO_USERSPACE64 : UIO_USERSPACE32);

#if CONFIG_MACF
	if (uap->mac_p != USER_ADDR_NULL) {
		error = mac_execve_enter(uap->mac_p, imgp);
		if (error) {
			kauth_cred_unref(&context.vc_ucred);
			goto exit_with_error;
		}
	}
#endif

	error = exec_activate_image(imgp);

	kauth_cred_unref(&context.vc_ucred);
	
	/* Image not claimed by any activator? */
	if (error == -1)
		error = ENOEXEC;

	if (error == 0) {
		exec_resettextvp(p, imgp);
		error = check_for_signature(p, imgp);
	}	
	if (imgp->ip_vp != NULLVP)
		vnode_put(imgp->ip_vp);
	if (imgp->ip_strings)
		execargs_free(imgp);
#if CONFIG_MACF
	if (imgp->ip_execlabelp)
		mac_cred_label_free(imgp->ip_execlabelp);
	if (imgp->ip_scriptlabelp)
		mac_vnode_label_free(imgp->ip_scriptlabelp);
#endif
	if (!error) {
		struct uthread	*uthread;

		/* Sever any extant thread affinity */
		thread_affinity_exec(current_thread());

		DTRACE_PROC(exec__success);
		uthread = get_bsdthread_info(current_thread());
		if (uthread->uu_flag & UT_VFORK) {
			vfork_return(p, retval, p->p_pid);
			(void)thread_resume(imgp->ip_new_thread);
		}
	} else {
		DTRACE_PROC1(exec__failure, int, error);
	}

exit_with_error:
	if (bufp != NULL) {
		FREE(bufp, M_TEMP);
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

static char *
random_hex_str(char *str, int len)
{
	uint64_t low, high, value;
	int idx;
	char digit;

	/* A 64-bit value will only take 16 characters, plus '0x' and NULL. */
	if (len > 19)
		len = 19;

	/* We need enough room for at least 1 digit */
	if (len < 4)
		return (NULL);

	low = random();
	high = random();
	value = high << 32 | low;

	str[0] = '0';
	str[1] = 'x';
	for (idx = 2; idx < len - 1; idx++) {
		digit = value & 0xf;
		value = value >> 4;
		if (digit < 10)
			str[idx] = '0' + digit;
		else
			str[idx] = 'a' + (digit - 10);
	}
	str[idx] = '\0';
	return (str);
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

#define PFZ_KEY "pfz="
extern user32_addr_t commpage_text32_location;
extern user64_addr_t commpage_text64_location;
/*
 * Build up the contents of the apple[] string vector
 */
static int
exec_add_apple_strings(struct image_params *imgp)
{
	int i, error;
	int new_ptr_size=4;
	char guard[19];
	char guard_vec[strlen(GUARD_KEY) + 19 * GUARD_VALUES + 1];

	char entropy[19];
	char entropy_vec[strlen(ENTROPY_KEY) + 19 * ENTROPY_VALUES + 1];

	char pfz_string[strlen(PFZ_KEY) + 16 + 4 +1];
	
	if( imgp->ip_flags & IMGPF_IS_64BIT) {
		new_ptr_size = 8;
		snprintf(pfz_string, sizeof(pfz_string),PFZ_KEY "0x%llx",commpage_text64_location);
	}else{
		snprintf(pfz_string, sizeof(pfz_string),PFZ_KEY "0x%x",commpage_text32_location);
	}

	/* exec_save_path stored the first string */
	imgp->ip_applec = 1;

	/* adding the pfz string */
	error = exec_add_user_string(imgp, CAST_USER_ADDR_T(pfz_string),UIO_SYSSPACE,FALSE);
	if(error)
		goto bad;
	imgp->ip_applec++;

	/*
	 * Supply libc with a collection of random values to use when
	 * implementing -fstack-protector.
	 */
	(void)strlcpy(guard_vec, GUARD_KEY, sizeof (guard_vec));
	for (i = 0; i < GUARD_VALUES; i++) {
		random_hex_str(guard, sizeof (guard));
		if (i)
			(void)strlcat(guard_vec, ",", sizeof (guard_vec));
		(void)strlcat(guard_vec, guard, sizeof (guard_vec));
	}

	error = exec_add_user_string(imgp, CAST_USER_ADDR_T(guard_vec), UIO_SYSSPACE, FALSE);
	if (error)
		goto bad;
	imgp->ip_applec++;

	/*
	 * Supply libc with entropy for system malloc.
	 */
	(void)strlcpy(entropy_vec, ENTROPY_KEY, sizeof(entropy_vec));
	for (i = 0; i < ENTROPY_VALUES; i++) {
		random_hex_str(entropy, sizeof (entropy));
		if (i)
			(void)strlcat(entropy_vec, ",", sizeof (entropy_vec));
		(void)strlcat(entropy_vec, entropy, sizeof (entropy_vec));
	}
	
	error = exec_add_user_string(imgp, CAST_USER_ADDR_T(entropy_vec), UIO_SYSSPACE, FALSE);
	if (error)
		goto bad;
	imgp->ip_applec++;

	/* Align the tail of the combined applev area */
	while (imgp->ip_strspace % new_ptr_size != 0) {
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
	kauth_cred_t		cred = vfs_context_ucred(imgp->ip_vfs_context);
	proc_t			p = vfs_context_proc(imgp->ip_vfs_context);
	int			i;
	int			leave_sugid_clear = 0;
	int			error = 0;
#if CONFIG_MACF
	int			mac_transition;

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
							imgp->ip_scriptlabelp,
							imgp->ip_execlabelp, p);
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
		 */
		if (imgp->ip_origvattr->va_mode & VSUID) {
			p->p_ucred  = kauth_cred_setresuid(p->p_ucred, KAUTH_UID_NONE, imgp->ip_origvattr->va_uid, imgp->ip_origvattr->va_uid, KAUTH_UID_NONE);
			/* update cred on proc */
			PROC_UPDATE_CREDS_ONPROC(p);
		}
		if (imgp->ip_origvattr->va_mode & VSGID) {
			p->p_ucred = kauth_cred_setresgid(p->p_ucred, KAUTH_GID_NONE, imgp->ip_origvattr->va_gid, imgp->ip_origvattr->va_gid);
			/* update cred on proc */
			PROC_UPDATE_CREDS_ONPROC(p);
		}

#if CONFIG_MACF
		/* 
		 * If a policy has indicated that it will transition the label,
		 * before making the call into the MAC policies, get a new
		 * duplicate credential, so they can modify it without
		 * modifying any others sharing it.
		 */
		if (mac_transition) { 
			kauth_cred_t	my_cred;
			if (kauth_proc_label_update_execve(p,
						imgp->ip_vfs_context,
						imgp->ip_vp, 
						imgp->ip_scriptlabelp,
						imgp->ip_execlabelp)) {
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

			my_cred = kauth_cred_proc_ref(p);
			mac_task_label_update_cred(my_cred, p->task);
			kauth_cred_unref(&my_cred);
		}
#endif	/* CONFIG_MACF */

		/*
		 * Have mach reset the task and thread ports.
		 * We don't want anyone who had the ports before
		 * a setuid exec to be able to access/control the
		 * task/thread after.
		 */
		ipc_task_reset(p->task);
		ipc_thread_reset((imgp->ip_new_thread != NULL) ?
				 imgp->ip_new_thread : current_thread());

		/*
		 * If 'leave_sugid_clear' is non-zero, then we passed the
		 * VSUID and MACF checks, and successfully determined that
		 * the previous cred was a member of the VSGID group, but
		 * that it was not the default at the time of the execve,
		 * and that the post-labelling credential was not disjoint.
		 * So we don't set the P_SUGID on the basis of simply
		 * running this code.
		 */
		if (!leave_sugid_clear)
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
			 * 	(void) open("/dev/null", O_RDONLY);
			 */

			struct fileproc *fp;
			int indx;

			if ((error = falloc(p,
			    &fp, &indx, imgp->ip_vfs_context)) != 0)
				continue;

			struct nameidata nd1;

			NDINIT(&nd1, LOOKUP, OP_OPEN, FOLLOW, UIO_SYSSPACE,
			    CAST_USER_ADDR_T("/dev/null"),
			    imgp->ip_vfs_context);

			if ((error = vn_open(&nd1, FREAD, 0)) != 0) {
				fp_free(p, indx, fp);
				break;
			}

			struct fileglob *fg = fp->f_fglob;

			fg->fg_flag = FREAD;
			fg->fg_type = DTYPE_VNODE;
			fg->fg_ops = &vnops;
			fg->fg_data = nd1.ni_vp;

			vnode_put(nd1.ni_vp);

			proc_fdlock(p);
			procfdtbl_releasefd(p, indx, NULL);
			fp_drop(p, indx, fp, 1);
			proc_fdunlock(p);
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
	 */
	p->p_ucred = kauth_cred_setsvuidgid(p->p_ucred, kauth_cred_getuid(p->p_ucred),  kauth_cred_getgid(p->p_ucred));
	/* update cred on proc */
	PROC_UPDATE_CREDS_ONPROC(p);
	
	/* Update the process' identity version and set the security token */
	p->p_idversion++;
	set_security_token(p);

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

	if (!load_result->prog_allocated_stack) {
		/*
		 * Allocate enough space for the maximum stack size we
		 * will ever authorize and an extra page to act as
		 * a guard page for stack overflows. For default stacks,
		 * vm_initial_limit_stack takes care of the extra guard page.
		 * Otherwise we must allocate it ourselves.
		 */

		size = mach_vm_round_page(load_result->user_stack_size);
		if (load_result->prog_stack_size)
			size += PAGE_SIZE;
		addr = mach_vm_trunc_page(load_result->user_stack - size);
		kr = mach_vm_allocate(map, &addr, size,
					VM_MAKE_TAG(VM_MEMORY_STACK) |
					VM_FLAGS_FIXED);
		if (kr != KERN_SUCCESS) {
			/* If can't allocate at default location, try anywhere */
			addr = 0;
			kr = mach_vm_allocate(map, &addr, size,
								  VM_MAKE_TAG(VM_MEMORY_STACK) |
								  VM_FLAGS_ANYWHERE);
			if (kr != KERN_SUCCESS)
				return kr;

			user_stack = addr + size;
			load_result->user_stack = user_stack;

			proc_lock(p);
			p->user_stack = user_stack;
			proc_unlock(p);
		}

		/*
		 * And prevent access to what's above the current stack
		 * size limit for this process.
		 */
		prot_addr = addr;
		if (load_result->prog_stack_size)
			prot_size = PAGE_SIZE;
		else
			prot_size = mach_vm_trunc_page(size - unix_stack_size(p));
		kr = mach_vm_protect(map,
							 prot_addr,
							 prot_size,
							 FALSE,
							 VM_PROT_NONE);
		if (kr != KERN_SUCCESS) {
			(void) mach_vm_deallocate(map, addr, size);
			return kr;
		}
	}

	return KERN_SUCCESS;
}

#include <sys/reboot.h>

static char		init_program_name[128] = "/sbin/launchd";

struct execve_args	init_exec_args;

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
 */
void
load_init_program(proc_t p)
{
	vm_offset_t	init_addr;
	int		argc = 0;
	uint32_t argv[3];
	int			error;
	int 		retval[2];

	/*
	 * Copy out program name.
	 */

	init_addr = VM_MIN_ADDRESS;
	(void) vm_allocate(current_map(), &init_addr, PAGE_SIZE,
				VM_FLAGS_ANYWHERE);
	if (init_addr == 0)
		init_addr++;

	(void) copyout((caddr_t) init_program_name, CAST_USER_ADDR_T(init_addr),
			(unsigned) sizeof(init_program_name)+1);

	argv[argc++] = (uint32_t)init_addr;
	init_addr += sizeof(init_program_name);
	init_addr = (vm_offset_t)ROUND_PTR(char, init_addr);

	/*
	 * Put out first (and only) argument, similarly.
	 * Assumes everything fits in a page as allocated
	 * above.
	 */
	if (boothowto & RB_SINGLE) {
		const char *init_args = "-s";

		copyout(init_args, CAST_USER_ADDR_T(init_addr),
			strlen(init_args));

		argv[argc++] = (uint32_t)init_addr;
		init_addr += strlen(init_args);
		init_addr = (vm_offset_t)ROUND_PTR(char, init_addr);

	}

	/*
	 * Null-end the argument list
	 */
	argv[argc] = 0;
	
	/*
	 * Copy out the argument list.
	 */
	
	(void) copyout((caddr_t) argv, CAST_USER_ADDR_T(init_addr),
			(unsigned) sizeof(argv));

	/*
	 * Set up argument block for fake call to execve.
	 */

	init_exec_args.fname = CAST_USER_ADDR_T(argv[0]);
	init_exec_args.argp = CAST_USER_ADDR_T((char **)init_addr);
	init_exec_args.envp = CAST_USER_ADDR_T(0);
	
	/*
	 * So that mach_init task is set with uid,gid 0 token 
	 */
	set_security_token(p);

	error = execve(p,&init_exec_args,retval);
	if (error)
		panic("Process 1 exec of %s failed, errno %d",
		      init_program_name, error);
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

static void
execargs_lock_sleep(void) {
	lck_mtx_sleep(execargs_cache_lock, LCK_SLEEP_DEFAULT, &execargs_free_count, THREAD_UNINT);
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
	int i, cache_index = -1;

	execargs_lock_lock();

	while (execargs_free_count == 0) {
		execargs_waiters++;
		execargs_lock_sleep();
		execargs_waiters--;
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

static int 
check_for_signature(proc_t p, struct image_params *imgp)
{
	void *blob = NULL;
	size_t length = 0;
	mach_port_t port = NULL;
	kern_return_t kr = KERN_FAILURE;
	int error = EACCES;
	unsigned char hash[SHA1_RESULTLEN];

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

	/* If the process is not signed or if it contains
	 * entitlements, we need to communicate through the
	 * task_access_port to taskgated.  taskgated will provide a
	 * detached code signature if present, and will enforce any
	 * restrictions on entitlements.  taskgated returns
	 * KERN_SUCCESS if it has completed its work and the exec
	 * should continue, or KERN_FAILURE if the exec should fail.
	 */
	error = cs_entitlements_blob_get(p, &blob, &length);

	/* if signed and no entitlements, then we're done here */
	if ((p->p_csflags & CS_VALID) && NULL == blob) {
		error = 0;
		goto done;
	}

	kr = task_get_task_access_port(p->task, &port);
	if (KERN_SUCCESS != kr || !IPC_PORT_VALID(port)) {
		error = 0;
#if !CONFIG_EMBEDDED
		/* fatal on the desktop when entitlements are present */
		if (NULL != blob)
			error = EACCES;
#endif
		goto done;
	}

	kr = find_code_signature(port, p->p_pid);
	if (KERN_SUCCESS != kr) {
		error = EACCES;
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
	if (0 != error)
		/* make very sure execution fails */
		psignal(p, SIGKILL);
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
	vm_fault( current_map(),
			  vm_map_trunc_page(load_result->entry_point),
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
		vm_fault( current_map(),
				  vm_map_trunc_page(load_result->all_image_info_addr),
				  VM_PROT_READ | VM_PROT_WRITE,
				  FALSE,
				  THREAD_UNINT, NULL, 0);
		if ((load_result->all_image_info_addr & PAGE_MASK) + expected_all_image_infos_size > PAGE_SIZE) {
			/* all_image_infos straddles a page */
			vm_fault( current_map(),
					  vm_map_trunc_page(load_result->all_image_info_addr + expected_all_image_infos_size - 1),
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

			vm_fault( current_map(),
					  vm_map_trunc_page(notification_address + dyld_slide_amount),
					  VM_PROT_READ | VM_PROT_EXECUTE,
					  FALSE,
					  THREAD_UNINT, NULL, 0);
			vm_fault( current_map(),
					  vm_map_trunc_page(dyld_image_address + dyld_slide_amount),
					  VM_PROT_READ | VM_PROT_EXECUTE,
					  FALSE,
					  THREAD_UNINT, NULL, 0);
			vm_fault( current_map(),
					  vm_map_trunc_page(dyld_version_address + dyld_slide_amount),
					  VM_PROT_READ,
					  FALSE,
					  THREAD_UNINT, NULL, 0);
			vm_fault( current_map(),
					  vm_map_trunc_page(dyld_all_image_infos_address + dyld_slide_amount),
					  VM_PROT_READ | VM_PROT_WRITE,
					  FALSE,
					  THREAD_UNINT, NULL, 0);
		}
	}
}
