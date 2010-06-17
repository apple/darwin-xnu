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

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_mach_internal.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>


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
void workqueue_exit(struct proc *);


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
 * SIZE_MAXPTR		The maximum size of a user space pointer, in bytes
 * SIZE_IMG_STRSPACE	The available string space, minus two pointers; we
 *			define it interms of the maximum, since we don't
 *			know the pointer size going in, until after we've
 *			parsed the executable image.
 */
#define	SIZE_MAXPTR		8				/* 64 bits */
#define	SIZE_IMG_STRSPACE	(NCARGS - 2 * SIZE_MAXPTR)

/*
 * EAI_ITERLIMIT	The maximum number of times to iterate an image
 *			activator in exec_activate_image() before treating
 *			it as malformed/corrupt.
 */
#define EAI_ITERLIMIT		10

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
static int exec_handle_sugid(struct image_params *imgp);
static int sugid_scripts = 0;
SYSCTL_INT (_kern, OID_AUTO, sugid_scripts, CTLFLAG_RW, &sugid_scripts, 0, "");
static kern_return_t create_unix_stack(vm_map_t map, user_addr_t user_stack,
					int customstack, proc_t p);
static int copyoutptr(user_addr_t ua, user_addr_t ptr, int ptr_size);
static void exec_resettextvp(proc_t, struct image_params *);
static int check_for_signature(proc_t, struct image_params *);

/* We don't want this one exported */
__private_extern__
int  open1(vfs_context_t, struct nameidata *, int, struct vnode_attr *, int32_t *);

/*
 * exec_add_string
 *
 * Add the requested string to the string space area.
 *
 * Parameters;	struct image_params *		image parameter block
 *		user_addr_t			string to add to strings area
 *
 * Returns:	0			Success
 *		!0			Failure errno from copyinstr()
 *
 * Implicit returns:
 *		(imgp->ip_strendp)	updated location of next add, if any
 *		(imgp->ip_strspace)	updated byte count of space remaining
 */
static int
exec_add_string(struct image_params *imgp, user_addr_t str)
{
        int error = 0;

        do {
                size_t len = 0;
		if (imgp->ip_strspace <= 0) {
			error = E2BIG;
			break;
		}
		if (!UIO_SEG_IS_USER_SPACE(imgp->ip_seg)) {
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
exec_save_path(struct image_params *imgp, user_addr_t path, int seg)
{
	int error;
	size_t	len;
	char *kpath = CAST_DOWN(char *,path);	/* SAFE */

	imgp->ip_strendp = imgp->ip_strings;
	imgp->ip_strspace = SIZE_IMG_STRSPACE;

	len = MIN(MAXPATHLEN, imgp->ip_strspace);

	switch(seg) {
	case UIO_USERSPACE32:
	case UIO_USERSPACE64:	/* Same for copyin()... */
		error = copyinstr(path, imgp->ip_strings, len, &len);
		break;
	case UIO_SYSSPACE:
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

#ifdef IMGPF_POWERPC
/*
 * exec_powerpc32_imgact
 *
 * Implicitly invoke the PowerPC handler for a byte-swapped image magic
 * number.  This may happen either as a result of an attempt to invoke a
 * PowerPC image directly, or indirectly as the interpreter used in an
 * interpreter script.
 *
 * Parameters;	struct image_params *	image parameter block
 *
 * Returns:	-1		not an PowerPC image (keep looking)
 *		-3		Success: exec_archhandler_ppc: relookup
 *		>0		Failure: exec_archhandler_ppc: error number
 *
 * Note:	This image activator does not handle the case of a direct
 *		invocation of the exec_archhandler_ppc, since in that case, the
 *		exec_archhandler_ppc itself is not a PowerPC binary; instead,
 *		binary image activators must recognize the exec_archhandler_ppc;
 *		This is managed in exec_check_permissions().
 *
 * Note:	This image activator is limited to 32 bit powerpc images;
 *		if support for 64 bit powerpc images is desired, it would
 *		be more in line with this design to write a separate 64 bit
 *		image activator.
 */
static int
exec_powerpc32_imgact(struct image_params *imgp)
{
	struct mach_header *mach_header = (struct mach_header *)imgp->ip_vdata;
	int error;
	size_t len = 0;

	/*
	 * Make sure it's a PowerPC binary.  If we've already redirected
	 * from an interpreted file once, don't do it again.
	 */
	if (mach_header->magic != MH_CIGAM) {
		/*
		 * If it's a cross-architecture 64 bit binary, then claim
		 * it, but refuse to run it.
		 */
		if (mach_header->magic == MH_CIGAM_64)
			return (EBADARCH);
		return (-1);
	}

	/* If there is no exec_archhandler_ppc, we can't run it */
	if (exec_archhandler_ppc.path[0] == 0)
		return (EBADARCH);

	/* Remember the type of the original file for later grading */
	if (!imgp->ip_origcputype) {
		imgp->ip_origcputype = 
			OSSwapBigToHostInt32(mach_header->cputype);
		imgp->ip_origcpusubtype = 
			OSSwapBigToHostInt32(mach_header->cpusubtype);
	}

	/*
	 * The PowerPC flag will be set by the exec_check_permissions()
	 * call anyway; however, we set this flag here so that the relookup
	 * in execve() does not follow symbolic links, as a side effect.
	 */
	imgp->ip_flags |= IMGPF_POWERPC;

	/* impute an interpreter */
	error = copystr(exec_archhandler_ppc.path, imgp->ip_interp_name,
			IMG_SHSIZE, &len);
	if (error)
		return (error);

	/*
	 * provide a replacement string for p->p_comm; we have to use an
	 * alternate buffer for this, rather than replacing it directly,
	 * since the exec may fail and return to the parent.  In that case,
	 * we would have erroneously changed the parent p->p_comm instead.
	 */
	strlcpy(imgp->ip_p_comm, imgp->ip_ndp->ni_cnd.cn_nameptr, MAXCOMLEN+1);
						/* +1 to allow MAXCOMLEN characters to be copied */

	return (-3);
}
#endif	/* IMGPF_POWERPC */


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
	char *line_endp;
	char *interp;
	char temp[16];
	proc_t p;
	struct fileproc *fp;
	int fd;
	int error;
	size_t len;

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

#ifdef IMGPF_POWERPC
	if ((imgp->ip_flags & IMGPF_POWERPC) != 0)
		  return (EBADARCH);
#endif	/* IMGPF_POWERPC */

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
							UIO_SYSSPACE);

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

		snprintf(temp, sizeof(temp), "/dev/fd/%d", fd);
		error = copyoutstr(temp, imgp->ip_user_fname, sizeof(temp), &len);
		if (error)
			return(error);
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
	 * we need to know if we were in this state initally subsequent to
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

	AUDIT_ARG(argv, imgp->ip_argv, imgp->ip_argc, 
	    imgp->ip_strendargvp - imgp->ip_argv);
	AUDIT_ARG(envv, imgp->ip_strendargvp, imgp->ip_envc,
	    imgp->ip_strendp - imgp->ip_strendargvp);

	/*
	 * Hack for binary compatability; put three NULs on the end of the
	 * string area, and round it up to the next word boundary.  This
	 * ensures padding with NULs to the boundary.
	 */
	imgp->ip_strendp[0] = 0;
	imgp->ip_strendp[1] = 0;
	imgp->ip_strendp[2] = 0;
	imgp->ip_strendp += (((imgp->ip_strendp - imgp->ip_strings) + NBPW-1) & ~(NBPW-1));

#ifdef IMGPF_POWERPC
	/*
	 * XXX
	 *
	 * Should be factored out; this is here because we might be getting
	 * invoked this way as the result of a shell script, and the check
	 * in exec_check_permissions() is not interior to the jump back up
	 * to the "encapsulated_binary:" label in exec_activate_image().
	 */
	if (imgp->ip_vattr->va_fsid == exec_archhandler_ppc.fsid &&
		imgp->ip_vattr->va_fileid == (uint64_t)((u_long)exec_archhandler_ppc.fileid)) {
		imgp->ip_flags |= IMGPF_POWERPC;
	}
#endif	/* IMGPF_POWERPC */

	/*
	 * We are being called to activate an image subsequent to a vfork()
	 * operation; in this case, we know that our task, thread, and
	 * uthread are actualy those of our parent, and our proc, which we
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
	 * destroyed or overwrote some process state while attempting an
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
#ifdef IMGPF_POWERPC
		    imgp->ip_flags & IMGPF_POWERPC ?
		    CPU_TYPE_POWERPC :
#endif
		    cpu_type());
	
	/*
	 * Close file descriptors
	 * which specify close-on-exec.
	 */
	fdexec(p);

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
				  load_result.user_stack,
				  load_result.customstack,
				  p) != KERN_SUCCESS) {
		error = load_return_to_errno(LOAD_NOSPACE);
		goto badtoolate;
	}

	/*  
	 * There is no  continuing workq context during 
	 * vfork exec. So no need to reset then. Otherwise
	 * clear the workqueue context.
	 */
	if (vfexec == 0 && spawn == 0) {
		(void)workqueue_exit(p);
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

		/* Adjust the stack */
		if (imgp->ip_flags & IMGPF_IS_64BIT) {
			ap = thread_adjuserstack(thread, -8);
			error = copyoutptr(load_result.mach_header, ap, 8);
		} else {
			ap = thread_adjuserstack(thread, -4);
			error = suword(ap, load_result.mach_header);
		}
		if (error) {
		        if (vfexec || spawn)
			        vm_map_switch(old_map);
			goto badtoolate;
		}
		task_set_dyld_info(task, load_result.all_image_info_addr,
		    load_result.all_image_info_size);
	}

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

	memcpy(&p->p_uuid[0], &load_result.uuid[0], sizeof(p->p_uuid));

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

#ifdef IMGPF_POWERPC
	/*
	 * Mark the process as powerpc or not.  If powerpc, set the affinity
	 * flag, which will be used for grading binaries in future exec's
	 * from the process.
	 */
	if (((imgp->ip_flags & IMGPF_POWERPC) != 0))
		OSBitOrAtomic(P_TRANSLATED, &p->p_flag);
	else
#endif	/* IMGPF_POWERPC */
		OSBitAndAtomic(~((uint32_t)P_TRANSLATED), &p->p_flag);
	OSBitAndAtomic(~((uint32_t)P_AFFINITY), &p->p_flag);

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
#ifdef IMGPF_POWERPC
	{ exec_powerpc32_imgact,	"PowerPC binary" },
#endif	/* IMGPF_POWERPC */
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
	
	/*
	 * XXXAUDIT: Note: the double copyin introduces an audit
	 * race.  To correct this race, we must use a single
	 * copyin(), e.g. by passing a flag to namei to indicate an
	 * external path buffer is being used.
	 */
	error = exec_save_path(imgp, imgp->ip_user_fname, imgp->ip_seg);
	if (error) {
		goto bad_notrans;
	}

	DTRACE_PROC1(exec, uintptr_t, imgp->ip_strings);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
		imgp->ip_seg, imgp->ip_user_fname, imgp->ip_vfs_context);

again:
	error = namei(&nd);
	if (error)
		goto bad_notrans;
	imgp->ip_ndp = &nd;	/* successful namei(); call nameidone() later */
	imgp->ip_vp = nd.ni_vp;	/* if set, need to vnode_put() at some point */

	error = proc_transstart(p, 0);
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
			vnode_put(imgp->ip_vp);
			imgp->ip_vp = NULL;	/* already put */
                
			NDINIT(&nd, LOOKUP, (nd.ni_cnd.cn_flags & HASBUF) | (FOLLOW | LOCKLEAF),
				UIO_SYSSPACE, CAST_USER_ADDR_T(imgp->ip_interp_name), imgp->ip_vfs_context);

#ifdef IMGPF_POWERPC
			/*
			 * PowerPC does not follow symlinks because the
			 * code which sets exec_archhandler_ppc.fsid and
			 * exec_archhandler_ppc.fileid doesn't follow them.
			 */
			if (imgp->ip_flags & IMGPF_POWERPC)
				nd.ni_cnd.cn_flags &= ~FOLLOW;
#endif	/* IMGPF_POWERPC */

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
 * 		KERN_FAILURE		Failure
 * 		ENOTSUP			Illegal posix_spawn attr flag was set
 */
static int
exec_handle_port_actions(struct image_params *imgp, short psa_flags)
{
	_posix_spawn_port_actions_t pacts = imgp->ip_px_spa;
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	_ps_port_action_t *act = NULL;
	task_t task = p->task;
	ipc_port_t port = NULL;
	kern_return_t ret = KERN_SUCCESS;
	int i;

	for (i = 0; i < pacts->pspa_count; i++) {
		act = &pacts->pspa_actions[i];

		ret = ipc_object_copyin(get_task_ipcspace(current_task()),
				CAST_MACH_PORT_TO_NAME(act->new_port),
				MACH_MSG_TYPE_COPY_SEND,
				(ipc_object_t *) &port);

		if (ret) 			
			return ret;

		switch (act->port_type) {
			case PSPA_SPECIAL:
				/* Only allowed when not under vfork */
				if (!(psa_flags & POSIX_SPAWN_SETEXEC))
					return ENOTSUP;
				ret = task_set_special_port(task, 
						act->which, 
						port);
				break;
			case PSPA_EXCEPTION:
				/* Only allowed when not under vfork */
				if (!(psa_flags & POSIX_SPAWN_SETEXEC))
					return ENOTSUP;
				ret = task_set_exception_ports(task, 
						act->mask,
						port, 
						act->behavior, 
						act->flavor);
				break;
#if CONFIG_AUDIT
			case PSPA_AU_SESSION:
				ret = audit_session_spawnjoin(p, 
				    		port);
				break;
#endif
			default:
				ret = KERN_FAILURE;
		}
		/* action failed, so release port resources */
		if (ret) { 
			ipc_port_release_send(port);
			return ret;
		}
	}

	return ret;
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
exec_handle_file_actions(struct image_params *imgp)
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
			 * context oof UIO_SYSSPACE, and casts the address
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

			NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(psfa->psfaa_openargs.psfao_path),
			       imgp->ip_vfs_context);

			error = open1(imgp->ip_vfs_context, 
					&nd,
					psfa->psfaa_openargs.psfao_oflag,
					&va,
					ival);

			/*
			 * If there's an error, or we get the right fd by
			 * accident, then drop out here.  This is easier that
			 * rearchitecting all the open code to preallocate fd
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

		default:
			error = EINVAL;
			break;
		}
		/* All file actions failures are considered fatal, per POSIX */
		if (error)
			break;
	}

	return (error);
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

	/*
	 * Allocate a big chunk for locals instead of using stack since these  
	 * structures a pretty big.
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
	 * If we don't have the extention flag that turns "posix_spawn()"
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
	if (imgp->ip_px_sfa != NULL &&
	    (error = exec_handle_file_actions(imgp)) != 0) {
		goto bad;
	}

	/* Has spawn port actions? */
	if (imgp->ip_px_spa != NULL) { 
		/* 
		 * The check for the POSIX_SPAWN_SETEXEC flag is done in 
		 * exec_handle_port_actions().
		 */
		if((error = exec_handle_port_actions(imgp, px_sa.psa_flags)) != 0) 
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
			kauth_cred_t my_new_cred = kauth_cred_setuidgid(my_cred, my_cred->cr_ruid, my_cred->cr_rgid);
			if (my_new_cred != my_cred)
				p->p_ucred = my_new_cred;
		}
	}

	/* 
	 * Clear transition flag so we won't hang if exec_activate_image() causes
	 * an automount (and launchd does a proc sysctl to service it).
	 *
	 * <rdar://problem/6848672>, <rdar://problem/5959568>.
	 */
	if (spawn_no_exec) {
		proc_transend(p, 0);
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

	/* Image not claimed by any activator? */
	if (error == -1)
		error = ENOEXEC;

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
	}

bad:
	if (error == 0) {
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
				task_deallocate(get_threadtask(imgp->ip_new_thread));
				thread_deallocate(imgp->ip_new_thread);
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
	imgp->ip_flags = (is_64 ? IMGPF_WAS_64BIT : IMGPF_NONE);
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
 * Implicit returns:
 *		*ptr_size		Modified
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
	proc_t p = vfs_context_proc(imgp->ip_vfs_context);
	int	ptr_size = (imgp->ip_flags & IMGPF_IS_64BIT) ? 8 : 4;
	char	*argv = imgp->ip_argv;	/* modifiable copy of argv */
	user_addr_t	string_area;	/* *argv[], *env[] */
	user_addr_t	path_area;	/* package launch path */
	user_addr_t	ptr_area;	/* argv[], env[], exec_path */
	user_addr_t	stack;
	int	stringc = imgp->ip_argc + imgp->ip_envc;
	size_t len;
	int error;
	ssize_t strspace;

	stack = *stackp;

	size_t patharea_len = imgp->ip_argv - imgp->ip_strings;
	int envc_add = 0;
	
	/*
	 * Set up pointers to the beginning of the string area, the beginning
	 * of the path area, and the beginning of the pointer area (actually,
	 * the location of argc, an int, which may be smaller than a pointer,
	 * but we use ptr_size worth of space for it, for alignment).
	 */
	string_area = stack - (((imgp->ip_strendp - imgp->ip_strings) + ptr_size-1) & ~(ptr_size-1)) - ptr_size;
	path_area = string_area - ((patharea_len + ptr_size-1) & ~(ptr_size-1));
	ptr_area = path_area - ((imgp->ip_argc + imgp->ip_envc + 4 + envc_add) * ptr_size) - ptr_size /*argc*/;

	/* Return the initial stack address: the location of argc */
	*stackp = ptr_area;

	/*
	 * Record the size of the arguments area so that sysctl_procargs()
	 * can return the argument area without having to parse the arguments.
	 */
	proc_lock(p);
	p->p_argc = imgp->ip_argc;
	p->p_argslen = (int)(stack - path_area);
	proc_unlock(p);


	/*
	 * Support for new app package launching for Mac OS X allocates
	 * the "path" at the begining of the imgp->ip_strings buffer.
	 * copy it just before the string area.
	 */
	len = 0;
	error = copyoutstr(imgp->ip_strings, path_area,
						   patharea_len,
						   &len);
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

#if CONFIG_DTRACE
	p->p_dtrace_argv = ptr_area; /* user_addr_t &argv[0] for dtrace convenience */
#endif /* CONFIG_DTRACE */

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
#if CONFIG_DTRACE
			p->p_dtrace_envp = ptr_area; /* user_addr_t &env[0] for dtrace convenience */
#endif /* CONFIG_DTRACE */
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
						strspace,
						&len);
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
 * Note:	The argument and environment vectors are user space pointers
 *		to arrays of user space pointers.
 */
static int
exec_extract_strings(struct image_params *imgp)
{
	int error = 0;
	int strsz = 0;
	int	ptr_size = (imgp->ip_flags & IMGPF_WAS_64BIT) ? 8 : 4;
	user_addr_t	argv = imgp->ip_user_argv;
	user_addr_t	envv = imgp->ip_user_envv;

	/*
	 * If the argument vector is NULL, this is the system startup
	 * bootstrap from load_init_program(), and there's nothing to do
	 */
	if (imgp->ip_user_argv == 0LL)
		goto bad;

	/* Now, get rest of arguments */

	/*
	 * Adjust space reserved for the path name by however much padding it
	 * needs. Doing this here since we didn't know if this would be a 32- 
	 * or 64-bit process back in exec_save_path.
	 */
	strsz = strlen(imgp->ip_strings) + 1;
	imgp->ip_strspace -= ((strsz + ptr_size-1) & ~(ptr_size-1)) - strsz;

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
			error = exec_add_string(imgp, imgp->ip_user_fname);
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
		error = exec_add_string(imgp, arg);
		if (error)
			goto bad;
		imgp->ip_argc++;
	}	 
	
	/* Note where the args end and env begins. */
	imgp->ip_strendargvp = imgp->ip_strendp;

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
		error = exec_add_string(imgp, env);
		if (error)
			goto bad;
		imgp->ip_envc++;
	}
bad:
	return error;
}


#define	unix_stack_size(p)	(p->p_rlimit[RLIMIT_STACK].rlim_cur)

/*
 * exec_check_permissions
 *
 * Decription:	Verify that the file that is being attempted to be executed
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
	if ((vap->va_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
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


#ifdef IMGPF_POWERPC
	/*
	 * If the file we are about to attempt to load is the exec_handler_ppc,
	 * which is determined by matching the vattr fields against previously
	 * cached values, then we set the PowerPC environment flag.
	 */
	if (vap->va_fsid == exec_archhandler_ppc.fsid &&
		vap->va_fileid == (uint64_t)((uint32_t)exec_archhandler_ppc.fileid)) {
		imgp->ip_flags |= IMGPF_POWERPC;
	}
#endif	/* IMGPF_POWERPC */

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
	struct vnode	*dev_null = NULLVP;
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
		 (cred->cr_gid != imgp->ip_origvattr->va_gid)))) {

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
		}
		if (imgp->ip_origvattr->va_mode & VSGID) {
			p->p_ucred = kauth_cred_setresgid(p->p_ucred, KAUTH_GID_NONE, imgp->ip_origvattr->va_gid, imgp->ip_origvattr->va_gid);
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

		/* Cache the vnode for /dev/null the first time around */
		if (dev_null == NULLVP) {
			struct nameidata nd1;

			NDINIT(&nd1, LOOKUP, FOLLOW, UIO_SYSSPACE,
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

				if ((error = falloc(p, &fp, &indx, imgp->ip_vfs_context)) != 0)
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
				procfdtbl_releasefd(p, indx, NULL);
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
	p->p_ucred = kauth_cred_setsvuidgid(p->p_ucred, kauth_cred_getuid(p->p_ucred),  p->p_ucred->cr_gid);
	
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
 *		user_stack		Address to set stack for process to
 *		customstack		FALSE if no custom stack in binary
 *		map			Address map in which to allocate the
 *					new stack, if 'customstack' is FALSE
 *
 * Returns:	KERN_SUCCESS		Stack successfully created
 *		!KERN_SUCCESS		Mach failure code
 */
static kern_return_t
create_unix_stack(vm_map_t map, user_addr_t user_stack, int customstack,
			proc_t p)
{
	mach_vm_size_t		size, prot_size;
	mach_vm_offset_t	addr, prot_addr;
	kern_return_t		kr;

	proc_lock(p);
	p->user_stack = user_stack;
	proc_unlock(p);

	if (!customstack) {
		/*
		 * Allocate enough space for the maximum stack size we
		 * will ever authorize and an extra page to act as
		 * a guard page for stack overflows.
		 */
		size = mach_vm_round_page(MAXSSIZ);
#if STACK_GROWTH_UP
		addr = mach_vm_trunc_page(user_stack);
#else	/* STACK_GROWTH_UP */
		addr = mach_vm_trunc_page(user_stack - size);
#endif	/* STACK_GROWTH_UP */
		kr = mach_vm_allocate(map, &addr, size,
					VM_MAKE_TAG(VM_MEMORY_STACK) |
				      VM_FLAGS_FIXED);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		/*
		 * And prevent access to what's above the current stack
		 * size limit for this process.
		 */
		prot_addr = addr;
#if STACK_GROWTH_UP
		prot_addr += unix_stack_size(p);
#endif /* STACK_GROWTH_UP */
		prot_addr = mach_vm_round_page(prot_addr);
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
		panic("Process 1 exec of %s failed, errno %d\n",
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

extern semaphore_t execve_semaphore;

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
	kern_return_t kr = vm_allocate(bsd_pageable_map, (vm_offset_t *)execarg_address, NCARGS + PAGE_SIZE, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
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

	imgp->ip_vdata = imgp->ip_strings + NCARGS;

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
	mach_port_t port = NULL;
	kern_return_t error = 0;
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

	/*
	 * If the task_access_port is set and the proc isn't signed,
	 * ask for a code signature from user space. Fail the exec
	 * if permission is denied.
	 */
	error = task_get_task_access_port(p->task, &port);
	if (error == 0 && IPC_PORT_VALID(port) && !(p->p_csflags & CS_VALID)) {
		error = find_code_signature(port, p->p_pid);
		if (error == KERN_FAILURE) {
			/* Make very sure execution fails */
			psignal(p, SIGKILL);
			return EACCES;
		}

		/* Only do this if exec_resettextvp() did not fail */
		if (p->p_textvp != NULLVP) {
			/*
			 * If there's a new code directory, mark this process
			 * as signed.
			 */
			error = ubc_cs_getcdhash(p->p_textvp, p->p_textoff, hash); 
			if (error == 0) {
				proc_lock(p);
				p->p_csflags |= CS_VALID;
				proc_unlock(p);
			}
		}
	}

	return KERN_SUCCESS;
}

