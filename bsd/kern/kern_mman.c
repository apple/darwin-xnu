/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah $Hdr: vm_mmap.c 1.6 91/10/21$
 *
 *	@(#)vm_mmap.c	8.10 (Berkeley) 2/19/95
 */

/*
 * Mapped file (mmap) interface to VM
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/resourcevar.h>
#include <sys/vnode_internal.h>
#include <sys/acct.h>
#include <sys/wait.h>
#include <sys/file_internal.h>
#include <sys/vadvise.h>
#include <sys/trace.h>
#include <sys/mman.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/sysproto.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/vm_sync.h>
#include <mach/vm_behavior.h>
#include <mach/vm_inherit.h>
#include <mach/vm_statistics.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/host_priv.h>

#include <kern/cpu_number.h>
#include <kern/host.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pager.h>

int
sbrk(__unused struct proc *p, __unused struct sbrk_args *uap, __unused register_t *retval)
{
	/* Not yet implemented */
	return (ENOTSUP);
}

int
sstk(__unused struct proc *p, __unused struct sstk_args *uap, __unused register_t *retval)
{
	/* Not yet implemented */
	return (ENOTSUP);
}


struct osmmap_args {
		caddr_t	addr;
		int	len;
		int	prot;
		int	share;
		int	fd;
		long	pos;
};

int
osmmap(
	struct proc *curp,
	register struct osmmap_args *uap,
	register_t *retval)
{
	struct mmap_args newargs;
	user_addr_t addr;
	int ret;

	if ((uap->share ==  MAP_SHARED )|| (uap->share ==  MAP_PRIVATE )) {
		newargs.addr = CAST_USER_ADDR_T(uap->addr);
		newargs.len = CAST_USER_ADDR_T(uap->len);
		newargs.prot = uap->prot;
		newargs.flags = uap->share;
		newargs.fd = uap->fd;
		newargs.pos = (off_t)uap->pos;
		ret = mmap(curp, &newargs, &addr);
		if (ret == 0)
			*retval = CAST_DOWN(register_t, addr);
	} else
		ret = EINVAL;
	return ret;
}


int
mmap(struct proc *p, struct mmap_args *uap, user_addr_t *retval)
{
	/*
	 *	Map in special device (must be SHARED) or file
	 */
	struct fileproc *fp;
	register struct		vnode *vp;
	int			flags;
	int			prot;
	int			err=0;
	vm_map_t		user_map;
	kern_return_t		result;
	mach_vm_offset_t	user_addr;
	mach_vm_size_t		user_size;
	vm_object_offset_t	pageoff;
	vm_object_offset_t	file_pos;
	int			alloc_flags;
	boolean_t		docow;
	vm_prot_t		maxprot;
	void 			*handle;
	vm_pager_t		pager;
	int 			mapanon=0;
	int 			fpref=0;
	int error =0;
	int fd = uap->fd;

	user_addr = (mach_vm_offset_t)uap->addr;
	user_size = (mach_vm_size_t) uap->len;

	AUDIT_ARG(addr, user_addr);
	AUDIT_ARG(len, user_size);
	AUDIT_ARG(fd, uap->fd);

	prot = (uap->prot & VM_PROT_ALL);
	flags = uap->flags;
	vp = NULLVP;

	/*
	 * The vm code does not have prototypes & compiler doesn't do the'
	 * the right thing when you cast 64bit value and pass it in function 
	 * call. So here it is.
	 */
	file_pos = (vm_object_offset_t)uap->pos;


	/* make sure mapping fits into numeric range etc */
	if ((file_pos + user_size > (vm_object_offset_t)-PAGE_SIZE_64) ||
	    ((flags & MAP_ANON) && fd != -1))
		return (EINVAL);

	/*
	 * Align the file position to a page boundary,
	 * and save its page offset component.
	 */
	pageoff = (file_pos & PAGE_MASK);
	file_pos -= (vm_object_offset_t)pageoff;


	/* Adjust size for rounding (on both ends). */
	user_size += pageoff;			/* low end... */
	user_size = mach_vm_round_page(user_size);	/* hi end */


	/*
	 * Check for illegal addresses.  Watch out for address wrap... Note
	 * that VM_*_ADDRESS are not constants due to casts (argh).
	 */
	if (flags & MAP_FIXED) {
		/*
		 * The specified address must have the same remainder
		 * as the file offset taken modulo PAGE_SIZE, so it
		 * should be aligned after adjustment by pageoff.
		 */
		user_addr -= pageoff;
		if (user_addr & PAGE_MASK)
			return (EINVAL);
	}
#ifdef notyet
	/* DO not have apis to get this info, need to wait till then*/
	/*
	 * XXX for non-fixed mappings where no hint is provided or
	 * the hint would fall in the potential heap space,
	 * place it after the end of the largest possible heap.
	 *
	 * There should really be a pmap call to determine a reasonable
	 * location.
	 */
	else if (addr < mach_vm_round_page(p->p_vmspace->vm_daddr + MAXDSIZ))
		addr = mach_vm_round_page(p->p_vmspace->vm_daddr + MAXDSIZ);

#endif


	if (flags & MAP_ANON) {
		/*
		 * Mapping blank space is trivial.
		 */
		handle = NULL;
		maxprot = VM_PROT_ALL;
		file_pos = 0;
		mapanon = 1;
	} else {
		struct vnode_attr va;
		struct vfs_context context;
		/*
		 * Mapping file, get fp for validation. Obtain vnode and make
		 * sure it is of appropriate type.
		 */
		err = fp_lookup(p, fd, &fp, 0);
		if (err)
			return(err);
		fpref = 1;
		if(fp->f_fglob->fg_type == DTYPE_PSXSHM) {
			uap->addr = (user_addr_t)user_addr;
			uap->len = (user_size_t)user_size;
			uap->prot = prot;
			uap->flags = flags;
			uap->pos = file_pos;
			error = pshm_mmap(p, uap, retval, fp, (off_t)pageoff);
			goto bad;
		}

		if (fp->f_fglob->fg_type != DTYPE_VNODE) {
			error = EINVAL;
			goto bad;
		}
		vp = (struct vnode *)fp->f_fglob->fg_data;
		error = vnode_getwithref(vp);
		if(error != 0)
			goto bad;

		if (vp->v_type != VREG && vp->v_type != VCHR) {
			(void)vnode_put(vp);
			error = EINVAL;
			goto bad;
		}

		AUDIT_ARG(vnpath, vp, ARG_VNODE1);
		
		/* conformance change - mmap needs to update access time for mapped
		 * files
		 */
		VATTR_INIT(&va);
		nanotime(&va.va_access_time);
		VATTR_SET_ACTIVE(&va, va_access_time);
		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();
		vnode_setattr(vp, &va, &context);

		/*
		 * XXX hack to handle use of /dev/zero to map anon memory (ala
		 * SunOS).
		 */
		if (vp->v_type == VCHR || vp->v_type == VSTR) {
			(void)vnode_put(vp);
			error = ENODEV;
			goto bad;
		} else {
			/*
			 * Ensure that file and memory protections are
			 * compatible.  Note that we only worry about
			 * writability if mapping is shared; in this case,
			 * current and max prot are dictated by the open file.
			 * XXX use the vnode instead?  Problem is: what
			 * credentials do we use for determination? What if
			 * proc does a setuid?
			 */
			maxprot = VM_PROT_EXECUTE;	/* ??? */
			if (fp->f_fglob->fg_flag & FREAD)
				maxprot |= VM_PROT_READ;
			else if (prot & PROT_READ) {
				(void)vnode_put(vp);
				error = EACCES;
				goto bad;
			}
			/*
			 * If we are sharing potential changes (either via
			 * MAP_SHARED or via the implicit sharing of character
			 * device mappings), and we are trying to get write
			 * permission although we opened it without asking
			 * for it, bail out. 
			 */

			if ((flags & MAP_SHARED) != 0) {
				if ((fp->f_fglob->fg_flag & FWRITE) != 0) {
 					/*
 					 * check for write access
 					 *
 					 * Note that we already made this check when granting FWRITE
 					 * against the file, so it seems redundant here.
 					 */
 					error = vnode_authorize(vp, NULL, KAUTH_VNODE_CHECKIMMUTABLE, &context);
 
 					/* if not granted for any reason, but we wanted it, bad */
 					if ((prot & PROT_WRITE) && (error != 0)) {
 						vnode_put(vp);
  						goto bad;
  					}
 
 					/* if writable, remember */
 					if (error == 0)
  						maxprot |= VM_PROT_WRITE;

				} else if ((prot & PROT_WRITE) != 0) {
					(void)vnode_put(vp);
					error = EACCES;
					goto bad;
				}
			} else
				maxprot |= VM_PROT_WRITE;

			handle = (void *)vp;
		}
	}

	if (user_size == 0)  {
		if (!mapanon)
			(void)vnode_put(vp);
		error = 0;
		goto bad;
	}

	/*
	 *	We bend a little - round the start and end addresses
	 *	to the nearest page boundary.
	 */
	user_size = mach_vm_round_page(user_size);

	if (file_pos & PAGE_MASK_64) {
		if (!mapanon)
			(void)vnode_put(vp);
		error = EINVAL;
		goto bad;
	}

	user_map = current_map();

	if ((flags & MAP_FIXED) == 0) {
		alloc_flags = VM_FLAGS_ANYWHERE;
		user_addr = mach_vm_round_page(user_addr);
	} else {
		if (user_addr != mach_vm_trunc_page(user_addr)) {
		        if (!mapanon)
			        (void)vnode_put(vp);
			error = EINVAL;
			goto bad;
		}
		/*
		 * mmap(MAP_FIXED) will replace any existing mappings in the
		 * specified range, if the new mapping is successful.
		 * If we just deallocate the specified address range here,
		 * another thread might jump in and allocate memory in that
		 * range before we get a chance to establish the new mapping,
		 * and we won't have a chance to restore the old mappings.
		 * So we use VM_FLAGS_OVERWRITE to let Mach VM know that it
		 * has to deallocate the existing mappings and establish the
		 * new ones atomically.
		 */
		alloc_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
	}


	/*
	 * Lookup/allocate object.
	 */
	if (handle == NULL) {
		pager = NULL;
#ifdef notyet
/* Hmm .. */
#if defined(VM_PROT_READ_IS_EXEC)
		if (prot & VM_PROT_READ)
			prot |= VM_PROT_EXECUTE;

		if (maxprot & VM_PROT_READ)
			maxprot |= VM_PROT_EXECUTE;
#endif
#endif
		result = mach_vm_map(user_map, &user_addr, user_size, 0,
				alloc_flags, IPC_PORT_NULL, 0,
				FALSE, prot, maxprot,
				(flags & MAP_SHARED) ? VM_INHERIT_SHARE : 
				                       VM_INHERIT_DEFAULT);
		if (result != KERN_SUCCESS) 
				goto out;
	} else {
		UBCINFOCHECK("mmap", vp);
		pager = (vm_pager_t)ubc_getpager(vp);
		
		if (pager == NULL) {
			(void)vnode_put(vp);
			error = ENOMEM;
			goto bad;
		}

		/*
		 *  Set credentials:
		 *	FIXME: if we're writing the file we need a way to
		 *      ensure that someone doesn't replace our R/W creds
		 * 	with ones that only work for read.
		 */

		ubc_setthreadcred(vp, p, current_thread());
		docow = FALSE;
		if ((flags & (MAP_ANON|MAP_SHARED)) == 0) {
			docow = TRUE;
		}

#ifdef notyet
/* Hmm .. */
#if defined(VM_PROT_READ_IS_EXEC)
		if (prot & VM_PROT_READ)
			prot |= VM_PROT_EXECUTE;

		if (maxprot & VM_PROT_READ)
			maxprot |= VM_PROT_EXECUTE;
#endif
#endif /* notyet */

		result = mach_vm_map(user_map, &user_addr, user_size,
				0, alloc_flags, (ipc_port_t)pager, file_pos,
				docow, prot, maxprot, 
				(flags & MAP_SHARED) ? VM_INHERIT_SHARE : 
				                       VM_INHERIT_DEFAULT);

		if (result != KERN_SUCCESS)  {
				(void)vnode_put(vp);
				goto out;
		}

		(void)ubc_map(vp,(prot & ( PROT_EXEC | PROT_READ | PROT_WRITE | PROT_EXEC)));
	}

	if (!mapanon)
		(void)vnode_put(vp);

out:
	switch (result) {
	case KERN_SUCCESS:
		*retval = user_addr + pageoff;
		error = 0;
		break;
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		error =  ENOMEM;
		break;
	case KERN_PROTECTION_FAILURE:
		error =  EACCES;
		break;
	default:
		error =  EINVAL;
		break;
	}
bad:
	if (fpref)
		fp_drop(p, fd, fp, 0);
	return(error);
}

int
msync(__unused struct proc *p, struct msync_args *uap, __unused register_t *retval)
{
	mach_vm_offset_t addr;
	mach_vm_size_t size;
	int flags;
	vm_map_t user_map;
	int rv;
	vm_sync_t sync_flags=0;

	addr = (mach_vm_offset_t) uap->addr;
	size = (mach_vm_size_t)uap->len;

	if (addr & PAGE_MASK_64) {
		/* UNIX SPEC: user address is not page-aligned, return EINVAL */
		return EINVAL;
	}
	if (size == 0) {
		/*
		 * We cannot support this properly without maintaining
		 * list all mmaps done. Cannot use vm_map_entry as they could be
		 * split or coalesced by indepenedant actions. So instead of 
		 * inaccurate results, lets just return error as invalid size
		 * specified
		 */
		return (EINVAL); /* XXX breaks posix apps */
	}

	flags = uap->flags;
	/* disallow contradictory flags */
	if ((flags & (MS_SYNC|MS_ASYNC)) == (MS_SYNC|MS_ASYNC) ||
	    (flags & (MS_ASYNC|MS_INVALIDATE)) == (MS_ASYNC|MS_INVALIDATE))
		return (EINVAL);

	if (flags & MS_KILLPAGES)
	        sync_flags |= VM_SYNC_KILLPAGES;
	if (flags & MS_DEACTIVATE)
	        sync_flags |= VM_SYNC_DEACTIVATE;
	if (flags & MS_INVALIDATE)
	        sync_flags |= VM_SYNC_INVALIDATE;

	if ( !(flags & (MS_KILLPAGES | MS_DEACTIVATE))) {
	        if (flags & MS_ASYNC) 
		        sync_flags |= VM_SYNC_ASYNCHRONOUS;
		else 
		        sync_flags |= VM_SYNC_SYNCHRONOUS;
	}

	sync_flags |= VM_SYNC_CONTIGUOUS;	/* complain if holes */

	user_map = current_map();
	rv = mach_vm_msync(user_map, addr, size, sync_flags);

	switch (rv) {
	case KERN_SUCCESS:
		break;
	case KERN_INVALID_ADDRESS:	/* hole in region being sync'ed */
		return (ENOMEM);
	case KERN_FAILURE:
		return (EIO);
	default:
		return (EINVAL);
	}
	return (0);
}


int
mremap(void)
{
	/* Not yet implemented */
	return (ENOTSUP);
}

int
munmap(__unused struct proc *p, struct munmap_args *uap, __unused register_t *retval)
{
	mach_vm_offset_t	user_addr;
	mach_vm_size_t	user_size;
	kern_return_t	result;

	user_addr = (mach_vm_offset_t) uap->addr;
	user_size = (mach_vm_size_t) uap->len;

	AUDIT_ARG(addr, user_addr);
	AUDIT_ARG(len, user_size);

	if (user_addr & PAGE_MASK_64) {
		/* UNIX SPEC: user address is not page-aligned, return EINVAL */
		return EINVAL;
	}

	if (user_addr + user_size < user_addr)
		return(EINVAL);

	if (user_size == 0) {
		/* UNIX SPEC: size is 0, return EINVAL */
		return EINVAL;
	}

	result = mach_vm_deallocate(current_map(), user_addr, user_size);
	if (result != KERN_SUCCESS) {
		return(EINVAL);
	}
	return(0);
}

int
mprotect(__unused struct proc *p, struct mprotect_args *uap, __unused register_t *retval)
{
	register vm_prot_t prot;
	mach_vm_offset_t	user_addr;
	mach_vm_size_t	user_size;
	kern_return_t	result;
	vm_map_t	user_map;

	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(len, uap->len);
	AUDIT_ARG(value, uap->prot);

	user_addr = (mach_vm_offset_t) uap->addr;
	user_size = (mach_vm_size_t) uap->len;
	prot = (vm_prot_t)(uap->prot & VM_PROT_ALL);

	if (user_addr & PAGE_MASK_64) {
		/* UNIX SPEC: user address is not page-aligned, return EINVAL */
		return EINVAL;
	}
		
#ifdef notyet
/* Hmm .. */
#if defined(VM_PROT_READ_IS_EXEC)
	if (prot & VM_PROT_READ)
		prot |= VM_PROT_EXECUTE;
#endif
#endif /* notyet */

	user_map = current_map();

	result = mach_vm_protect(user_map, user_addr, user_size,
				 FALSE, prot);
	switch (result) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	case KERN_INVALID_ADDRESS:
		/* UNIX SPEC: for an invalid address range, return ENOMEM */
		return ENOMEM;
	}
	return (EINVAL);
}


int
minherit(__unused struct proc *p, struct minherit_args *uap, __unused register_t *retval)
{
	mach_vm_offset_t addr;
	mach_vm_size_t size;
	register vm_inherit_t inherit;
	vm_map_t	user_map;
	kern_return_t	result;

	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(len, uap->len);
	AUDIT_ARG(value, uap->inherit);

	addr = (mach_vm_offset_t)uap->addr;
	size = (mach_vm_size_t)uap->len;
	inherit = uap->inherit;

	user_map = current_map();
	result = mach_vm_inherit(user_map, addr, size,
				inherit);
	switch (result) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	}
	return (EINVAL);
}

int
madvise(__unused struct proc *p, struct madvise_args *uap, __unused register_t *retval)
{
	vm_map_t user_map;
	mach_vm_offset_t start;
	mach_vm_size_t size;
	vm_behavior_t new_behavior;
	kern_return_t	result;

	/*
	 * Since this routine is only advisory, we default to conservative
	 * behavior.
	 */
	switch (uap->behav) {
		case MADV_RANDOM:
			new_behavior = VM_BEHAVIOR_RANDOM;
			break;
		case MADV_SEQUENTIAL: 
			new_behavior = VM_BEHAVIOR_SEQUENTIAL;
			break;
		case MADV_NORMAL:
			new_behavior = VM_BEHAVIOR_DEFAULT;
			break;
		case MADV_WILLNEED:
			new_behavior = VM_BEHAVIOR_WILLNEED;
			break;
		case MADV_DONTNEED:
			new_behavior = VM_BEHAVIOR_DONTNEED;
			break;
		default:
			return(EINVAL);
	}

	start = (mach_vm_offset_t) uap->addr;
	size = (mach_vm_size_t) uap->len;
	
	user_map = current_map();

	result = mach_vm_behavior_set(user_map, start, size, new_behavior);
	switch (result) {
		case KERN_SUCCESS:
			return (0);
		case KERN_INVALID_ADDRESS:
			return (ENOMEM);
	}

	return (EINVAL);
}

int
mincore(__unused struct proc *p, struct mincore_args *uap, __unused register_t *retval)
{
	mach_vm_offset_t addr, first_addr, end;
	vm_map_t map;
	user_addr_t vec;
	int error;
	int vecindex, lastvecindex;
	int mincoreinfo=0;
	int pqueryinfo;
	kern_return_t	ret;
	int numref;

	char c;

	map = current_map();

	/*
	 * Make sure that the addresses presented are valid for user
	 * mode.
	 */
	first_addr = addr = mach_vm_trunc_page(uap->addr);
	end = addr + mach_vm_round_page(uap->len);

	if (end < addr)
		return (EINVAL);

	/*
	 * Address of byte vector
	 */
	vec = uap->vec;

	map = current_map();

	/*
	 * Do this on a map entry basis so that if the pages are not
	 * in the current processes address space, we can easily look
	 * up the pages elsewhere.
	 */
	lastvecindex = -1;
	for( ; addr < end; addr += PAGE_SIZE ) {
		pqueryinfo = 0;
		ret = vm_map_page_query(map, addr, &pqueryinfo, &numref);
		if (ret != KERN_SUCCESS) 
			pqueryinfo = 0;
		mincoreinfo = 0;
		if (pqueryinfo & VM_PAGE_QUERY_PAGE_PRESENT)
			mincoreinfo |= MINCORE_INCORE;
		if (pqueryinfo & VM_PAGE_QUERY_PAGE_REF)
			mincoreinfo |= MINCORE_REFERENCED;
		if (pqueryinfo & VM_PAGE_QUERY_PAGE_DIRTY)
			mincoreinfo |= MINCORE_MODIFIED;
		
		
		/*
		 * calculate index into user supplied byte vector
		 */
		vecindex = (addr - first_addr)>> PAGE_SHIFT;

		/*
		 * If we have skipped map entries, we need to make sure that
		 * the byte vector is zeroed for those skipped entries.
		 */
		while((lastvecindex + 1) < vecindex) {
			c = 0;
			error = copyout(&c, vec + lastvecindex, 1);
			if (error) {
				return (EFAULT);
			}
			++lastvecindex;
		}

		/*
		 * Pass the page information to the user
		 */
		c = (char)mincoreinfo;
		error = copyout(&c, vec + vecindex, 1);
		if (error) {
			return (EFAULT);
		}
		lastvecindex = vecindex;
	}


	/*
	 * Zero the last entries in the byte vector.
	 */
	vecindex = (end - first_addr) >> PAGE_SHIFT;
	while((lastvecindex + 1) < vecindex) {
		c = 0;
		error = copyout(&c, vec + lastvecindex, 1);
		if (error) {
			return (EFAULT);
		}
		++lastvecindex;
	}
	
	return (0);
}

int
mlock(__unused struct proc *p, struct mlock_args *uap, __unused register_t *retvalval)
{
	vm_map_t user_map;
	vm_map_offset_t addr;
	vm_map_size_t size, pageoff;
	kern_return_t	result;

	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(len, uap->len);

	addr = (vm_map_offset_t) uap->addr;
	size = (vm_map_size_t)uap->len;

	/* disable wrap around */
	if (addr + size < addr)
		return (EINVAL);

	if (size == 0)
		return (0);

	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size = vm_map_round_page(size+pageoff);

#ifdef notyet 
/* Hmm.. What am I going to do with this? */
	if (atop(size) + cnt.v_wire_count > vm_page_max_wired)
		return (EAGAIN);
#ifdef pmap_wired_count
	if (size + ptoa(pmap_wired_count(vm_map_pmap(&p->p_vmspace->vm_map))) >
	    p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur)
		return (ENOMEM);
#else
	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);
#endif
#endif /* notyet */

	user_map = current_map();

	/* have to call vm_map_wire directly to pass "I don't know" protections */
	result = vm_map_wire(user_map, addr, addr+size, VM_PROT_NONE, TRUE);
	return (result == KERN_SUCCESS ? 0 : ENOMEM);
}

int
munlock(__unused struct proc *p, struct munlock_args *uap, __unused register_t *retval)
{
	mach_vm_offset_t addr;
	mach_vm_size_t size;
	vm_map_t user_map;
	kern_return_t	result;

	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(addr, uap->len);

	addr = (mach_vm_offset_t) uap->addr;
	size = (mach_vm_size_t)uap->len;


#ifdef notyet 
/* Hmm.. What am I going to do with this? */
#ifndef pmap_wired_count
	error = suser(kauth_cred_get(), &p->p_acflag);
	if (error)
		return (error);
#endif
#endif /* notyet */

	user_map = current_map();

	/* JMM - need to remove all wirings by spec - this just removes one */
	result = mach_vm_wire(host_priv_self(), user_map, addr, size, VM_PROT_NONE);
	return (result == KERN_SUCCESS ? 0 : ENOMEM);
}


int
mlockall(__unused struct proc *p, __unused struct mlockall_args *uap, __unused register_t *retval)
{
	return (ENOSYS);
}

int
munlockall(__unused struct proc *p, __unused struct munlockall_args *uap, __unused register_t *retval)
{
	return(ENOSYS);
}


/* BEGIN DEFUNCT */
int
obreak(__unused struct proc *p, __unused struct obreak_args *uap, __unused register_t *retval)
{
	/* Not implemented, obsolete */
	return (ENOMEM);
}

int	both;

int
ovadvise(__unused struct proc *p, __unused struct ovadvise_args *uap, __unused register_t *retval)
{

#ifdef lint
	both = 0;
#endif
	return( 0 );
}
/* END DEFUNCT */

/* USV: No! need to obsolete map_fd()! mmap() already supports 64 bits */
kern_return_t
map_fd(struct map_fd_args *args)
{
	int		fd = args->fd;
	vm_offset_t	offset = args->offset;
	vm_offset_t	*va = args->va;
	boolean_t	findspace = args->findspace;
	vm_size_t	size = args->size;
	kern_return_t ret;

	AUDIT_MACH_SYSCALL_ENTER(AUE_MAPFD);
	AUDIT_ARG(addr, CAST_DOWN(user_addr_t, va));
	AUDIT_ARG(fd, fd);

	ret = map_fd_funneled( fd, (vm_object_offset_t)offset, va, findspace, size);

	AUDIT_MACH_SYSCALL_EXIT(ret);
	return ret;
}

kern_return_t
map_fd_funneled(
	int			fd,
	vm_object_offset_t	offset,
	vm_offset_t		*va,
	boolean_t		findspace,
	vm_size_t		size)
{
	kern_return_t	result;
	struct fileproc	*fp;
	struct vnode	*vp;
	void *	pager;
	vm_offset_t	map_addr=0;
	vm_size_t	map_size;
	int		err=0;
	vm_map_t	my_map;
	struct proc	*p =(struct proc *)current_proc();
	struct vnode_attr vattr;
	struct vfs_context context;

	/*
	 *	Find the inode; verify that it's a regular file.
	 */

	err = fp_lookup(p, fd, &fp, 0);
	if (err)
		return(err);
	
	if (fp->f_fglob->fg_type != DTYPE_VNODE){
		err = KERN_INVALID_ARGUMENT;
		goto bad;
	}

	if (!(fp->f_fglob->fg_flag & FREAD)) {
		err = KERN_PROTECTION_FAILURE;
		goto bad;
	}

	vp = (struct vnode *)fp->f_fglob->fg_data;
	err = vnode_getwithref(vp);
	if(err != 0) 
		goto bad;

	if (vp->v_type != VREG) {
		(void)vnode_put(vp);
		err = KERN_INVALID_ARGUMENT;
		goto bad;
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	/* conformance change - mmap needs to update access time for mapped
	 * files
	 */
	VATTR_INIT(&vattr);
	nanotime(&vattr.va_access_time);
	VATTR_SET_ACTIVE(&vattr, va_access_time);
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	vnode_setattr(vp, &vattr, &context);

	if (offset & PAGE_MASK_64) {
		printf("map_fd: file offset not page aligned(%d : %s)\n",p->p_pid, p->p_comm);
		(void)vnode_put(vp);
		err = KERN_INVALID_ARGUMENT;
		goto bad;
	}
	map_size = round_page(size);

	/*
	 * Allow user to map in a zero length file.
	 */
	if (size == 0) {
		(void)vnode_put(vp);
		err = KERN_SUCCESS;
		goto bad;
	}
	/*
	 *	Map in the file.
	 */
	UBCINFOCHECK("map_fd_funneled", vp);
	pager = (void *) ubc_getpager(vp);
	if (pager == NULL) {
		(void)vnode_put(vp);
		err = KERN_FAILURE;
		goto bad;
	}


	my_map = current_map();

	result = vm_map_64(
			my_map,
			&map_addr, map_size, (vm_offset_t)0, 
			VM_FLAGS_ANYWHERE, pager, offset, TRUE,
			VM_PROT_DEFAULT, VM_PROT_ALL,
			VM_INHERIT_DEFAULT);
	if (result != KERN_SUCCESS) {
		(void)vnode_put(vp);
		err = result;
		goto bad;
	}


	if (!findspace) {
		vm_offset_t	dst_addr;
		vm_map_copy_t	tmp;

		if (copyin(CAST_USER_ADDR_T(va), &dst_addr, sizeof (dst_addr))	||
					trunc_page_32(dst_addr) != dst_addr) {
			(void) vm_map_remove(
					my_map,
					map_addr, map_addr + map_size,
					VM_MAP_NO_FLAGS);
			(void)vnode_put(vp);
			err = KERN_INVALID_ADDRESS;
			goto bad;
		}

		result = vm_map_copyin(my_map, (vm_map_address_t)map_addr,
				       (vm_map_size_t)map_size, TRUE, &tmp);
		if (result != KERN_SUCCESS) {
			
			(void) vm_map_remove(my_map, vm_map_trunc_page(map_addr),
					vm_map_round_page(map_addr + map_size),
					VM_MAP_NO_FLAGS);
			(void)vnode_put(vp);
			err = result;
			goto bad;
		}

		result = vm_map_copy_overwrite(my_map,
					(vm_map_address_t)dst_addr, tmp, FALSE);
		if (result != KERN_SUCCESS) {
			vm_map_copy_discard(tmp);
			(void)vnode_put(vp);
			err = result;
			goto bad;
		}
	} else {
		if (copyout(&map_addr, CAST_USER_ADDR_T(va), sizeof (map_addr))) {
			(void) vm_map_remove(my_map, vm_map_trunc_page(map_addr),
					vm_map_round_page(map_addr + map_size),
					VM_MAP_NO_FLAGS);
			(void)vnode_put(vp);
			err = KERN_INVALID_ADDRESS;
			goto bad;
		}
	}

	ubc_setthreadcred(vp, current_proc(), current_thread());
	(void)ubc_map(vp, (PROT_READ | PROT_WRITE | PROT_EXEC));
	(void)vnode_put(vp);
	err = 0;
bad:
	fp_drop(p, fd, fp, 0);
	return (err);
}

