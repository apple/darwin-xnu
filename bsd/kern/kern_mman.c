/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/acct.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/vadvise.h>
#include <sys/trace.h>
#include <sys/mman.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ubc.h>

#include <mach/mach_types.h>

#include <kern/cpu_number.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pager.h>

#include <mach/vm_sync.h>
#include <mach/vm_behavior.h>
#include <mach/vm_inherit.h>
#include <mach/vm_statistics.h>

struct sbrk_args {
		int	incr;
};

/* ARGSUSED */
int
sbrk(p, uap, retval)
	struct proc *p;
	struct sbrk_args *uap;
	register_t *retval;
{
	/* Not yet implemented */
	return (EOPNOTSUPP);
}

struct sstk_args {
	int	incr;
} *uap;

/* ARGSUSED */
int
sstk(p, uap, retval)
	struct proc *p;
	struct sstk_args *uap;
	register_t *retval;
{
	/* Not yet implemented */
	return (EOPNOTSUPP);
}

#if COMPAT_43
/* ARGSUSED */
int
ogetpagesize(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = PAGE_SIZE;
	return (0);
}
#endif /* COMPAT_43 */

struct osmmap_args {
		caddr_t	addr;
		int	len;
		int	prot;
		int	share;
		int	fd;
		long	pos;
};

osmmap(curp, uap, retval)
	struct proc *curp;
	register struct osmmap_args *uap;
	register_t *retval;
{
struct mmap_args {
		caddr_t addr;
		size_t len;
		int prot;
		int flags;
		int fd;
#ifdef DOUBLE_ALIGN_PARAMS
		long pad;
#endif
		off_t pos;
} newargs;

	if ((uap->share ==  MAP_SHARED )|| (uap->share ==  MAP_PRIVATE )) {
		newargs.addr = uap->addr;
		newargs.len = (size_t)uap->len;
		newargs.prot = uap->prot;
		newargs.flags = uap->share;
		newargs.fd = uap->fd;
		newargs.pos = (off_t)uap->pos;
		return(mmap(curp,&newargs, retval));
	} else
		return(EINVAL);	
}

struct mmap_args {
		caddr_t addr;
		size_t len;
		int prot;
		int flags;
		int fd;
#ifdef DOUBLE_ALIGN_PARAMS
		long pad;
#endif
		off_t pos;
};
int
mmap(p, uap, retval)
	struct proc *p;
	struct mmap_args *uap;
	register_t *retval;
{
	/*
	 *	Map in special device (must be SHARED) or file
	 */
	struct file *fp;
	register struct		vnode *vp;
	int			flags;
	int			prot;
	int			err=0;
	vm_map_t		user_map;
	kern_return_t		result;
	vm_offset_t		user_addr;
	vm_size_t		user_size;
	vm_offset_t		pageoff;
	vm_object_offset_t	file_pos;
	boolean_t		find_space, docow;
	vm_prot_t		maxprot;
	void 			*handle;
	vm_pager_t		pager;
	int 			mapanon=0;

	user_addr = (vm_offset_t)uap->addr;
	user_size = (vm_size_t) uap->len;
	prot = (uap->prot & VM_PROT_ALL);
	flags = uap->flags;

	/*
	 * The vm code does not have prototypes & compiler doesn't do the'
	 * the right thing when you cast 64bit value and pass it in function 
	 * call. So here it is.
	 */
	file_pos = (vm_object_offset_t)uap->pos;


	/* make sure mapping fits into numeric range etc */
	if ((file_pos + user_size > (vm_object_offset_t)-PAGE_SIZE_64) ||
	    ((ssize_t) uap->len < 0 )||
	    ((flags & MAP_ANON) && uap->fd != -1))
		return (EINVAL);

	/*
	 * Align the file position to a page boundary,
	 * and save its page offset component.
	 */
	pageoff = ((vm_offset_t)file_pos & PAGE_MASK);
	file_pos -= (vm_object_offset_t)pageoff;


	/* Adjust size for rounding (on both ends). */
	user_size += pageoff;			/* low end... */
	user_size = (vm_size_t) round_page(user_size);	/* hi end */


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
		/* Address range must be all in user VM space. */
		if (VM_MAX_ADDRESS > 0 && (user_addr + user_size > VM_MAX_ADDRESS))
			return (EINVAL);
		if (VM_MIN_ADDRESS > 0 && user_addr < VM_MIN_ADDRESS)
			return (EINVAL);
		if (user_addr + user_size < user_addr)
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
	else if (addr < round_page(p->p_vmspace->vm_daddr + MAXDSIZ))
		addr = round_page(p->p_vmspace->vm_daddr + MAXDSIZ);

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
		/*
		 * Mapping file, get fp for validation. Obtain vnode and make
		 * sure it is of appropriate type.
		 */
		err = fdgetf(p, uap->fd, &fp);
		if (err)
			return(err);
		if(fp->f_type == DTYPE_PSXSHM) {
			uap->addr = user_addr;
			uap->len = user_size;
			uap->prot = prot;
			uap->flags = flags;
			uap->pos = file_pos;
			return(pshm_mmap(p, uap, retval, fp , pageoff));
		}

		if (fp->f_type != DTYPE_VNODE)
			return(EINVAL);
		vp = (struct vnode *)fp->f_data;

		if (vp->v_type != VREG && vp->v_type != VCHR)
			return (EINVAL);
		/*
		 * XXX hack to handle use of /dev/zero to map anon memory (ala
		 * SunOS).
		 */
		if (vp->v_type == VCHR || vp->v_type == VSTR) {
			return(EOPNOTSUPP);
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
			if (fp->f_flag & FREAD)
				maxprot |= VM_PROT_READ;
			else if (prot & PROT_READ)
				return (EACCES);
			/*
			 * If we are sharing potential changes (either via
			 * MAP_SHARED or via the implicit sharing of character
			 * device mappings), and we are trying to get write
			 * permission although we opened it without asking
			 * for it, bail out. 
			 */

			if ((flags & MAP_SHARED) != 0) {
				if ((fp->f_flag & FWRITE) != 0) {
					struct vattr va;
					if ((err =
					    VOP_GETATTR(vp, &va,
						        p->p_ucred, p)))
						return (err);
					if ((va.va_flags &
					    (IMMUTABLE|APPEND)) == 0)
						maxprot |= VM_PROT_WRITE;
					else if (prot & PROT_WRITE)
						return (EPERM);
				} else if ((prot & PROT_WRITE) != 0)
					return (EACCES);
			} else
				maxprot |= VM_PROT_WRITE;

			handle = (void *)vp;
		}
	}

	if (user_size == 0) 
		return(0);

	/*
	 *	We bend a little - round the start and end addresses
	 *	to the nearest page boundary.
	 */
	user_size = round_page(user_size);

	if (file_pos & PAGE_MASK_64)
		return (EINVAL);

	user_map = current_map();

	if ((flags & MAP_FIXED) == 0) {
		find_space = TRUE;
		user_addr = round_page(user_addr); 
	} else {
		if (user_addr != trunc_page(user_addr))
			return (EINVAL);
		find_space = FALSE;
		(void) vm_deallocate(user_map, user_addr, user_size);
	}


	/*
	 * Lookup/allocate object.
	 */
	if (flags & MAP_ANON) {
		/*
		 * Unnamed anonymous regions always start at 0.
		 */
		if (handle == 0)
			file_pos = 0;
	}

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
		result = vm_allocate(user_map, &user_addr, user_size, find_space);
		if (result != KERN_SUCCESS) 
				goto out;
		
	} else {
		UBCINFOCHECK("mmap", vp);
		pager = ubc_getpager(vp);
		
		if (pager == NULL)
			return (ENOMEM);

		/*
		 *  Set credentials:
		 *	FIXME: if we're writing the file we need a way to
		 *      ensure that someone doesn't replace our R/W creds
		 * 	with ones that only work for read.
		 */

		ubc_setcred(vp, p);
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

		result = vm_map_64(user_map, &user_addr, user_size,
				0, find_space, pager, file_pos, docow,
      	                  prot, maxprot, 
				VM_INHERIT_DEFAULT);

		if (result != KERN_SUCCESS) 
				goto out;

		ubc_map(vp);
	}

	if (flags & (MAP_SHARED|MAP_INHERIT)) {
		result = vm_inherit(user_map, user_addr, user_size,
				VM_INHERIT_SHARE);
		if (result != KERN_SUCCESS) {
			(void) vm_deallocate(user_map, user_addr, user_size);
			goto out;
		}
	}

out:
	switch (result) {
	case KERN_SUCCESS:
		if (!mapanon)
			*fdflags(p, uap->fd) |= UF_MAPPED;
		*retval = (register_t)(user_addr + pageoff);
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
	/*NOTREACHED*/
}

struct msync_args {
		caddr_t addr;
		int len;
		int flags;
};
int
msync(p, uap, retval)
	struct proc *p;
	struct msync_args *uap;
	register_t *retval;
{
	vm_offset_t addr;
	vm_size_t size, pageoff;
	int flags;
	vm_map_t user_map;
	int rv;
	vm_sync_t sync_flags=0;

	addr = (vm_offset_t) uap->addr;
	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size = uap->len;
	size = (vm_size_t) round_page(size);
	flags = uap->flags;

	if (addr + size < addr)
		return(EINVAL);

	user_map = current_map();

	if ((flags & (MS_ASYNC|MS_INVALIDATE)) == (MS_ASYNC|MS_INVALIDATE))
		return (EINVAL);

	if (size == 0) {
		/*
		 * We cannot support this properly without maintaining
		 * list all mmaps done. Cannot use vm_map_entry as they could be
		 * split or coalesced by indepenedant actions. So instead of 
		 * inaccurate results, lets just return error as invalid size
		 * specified
		 */
		return(EINVAL);
	}

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
	rv = vm_msync(user_map, addr, size, sync_flags);

	switch (rv) {
	case KERN_SUCCESS:
		break;
	case KERN_INVALID_ADDRESS:
		return (EINVAL);	/* Sun returns ENOMEM? */
	case KERN_FAILURE:
		return (EIO);
	default:
		return (EINVAL);
	}

	return (0);

}


mremap()
{
	/* Not yet implemented */
	return (EOPNOTSUPP);
}

struct munmap_args {
		caddr_t	addr;
		int	len;
};
munmap(p, uap, retval)
	struct proc *p;
	struct munmap_args *uap;
	register_t *retval;

{
	vm_offset_t	user_addr;
	vm_size_t	user_size, pageoff;
	kern_return_t	result;

	user_addr = (vm_offset_t) uap->addr;
	user_size = (vm_size_t) uap->len;

	pageoff = (user_addr & PAGE_MASK);

	user_addr -= pageoff;
	user_size += pageoff;
	user_size = round_page(user_size);
	if (user_addr + user_size < user_addr)
		return(EINVAL);

	if (user_size == 0)
		return (0);

	/* Address range must be all in user VM space. */
	if (VM_MAX_ADDRESS > 0 && (user_addr + user_size > VM_MAX_ADDRESS))
		return (EINVAL);
	if (VM_MIN_ADDRESS > 0 && user_addr < VM_MIN_ADDRESS)
		return (EINVAL);


	result = vm_deallocate(current_map(), user_addr, user_size);
	if (result != KERN_SUCCESS) {
		return(EINVAL);
	}
	return(0);
}

void
munmapfd(p, fd)
	struct proc *p;
	int fd;
{
	/*
	 * XXX should vm_deallocate any regions mapped to this file
	 */
	*fdflags(p, fd) &= ~UF_MAPPED;
}

struct mprotect_args {
		caddr_t addr;
		int len;
		int prot;
};
int
mprotect(p, uap, retval)
	struct proc *p;
	struct mprotect_args *uap;
	register_t *retval;
{
	register vm_prot_t prot;
	vm_offset_t	user_addr;
	vm_size_t	user_size, pageoff;
	kern_return_t	result;
	vm_map_t	user_map;

	user_addr = (vm_offset_t) uap->addr;
	user_size = (vm_size_t) uap->len;
	prot = (vm_prot_t)(uap->prot & VM_PROT_ALL);

#ifdef notyet
/* Hmm .. */
#if defined(VM_PROT_READ_IS_EXEC)
	if (prot & VM_PROT_READ)
		prot |= VM_PROT_EXECUTE;
#endif
#endif /* notyet */

	pageoff = (user_addr & PAGE_MASK);
	user_addr -= pageoff;
	user_size += pageoff;
	user_size = round_page(user_size);
	if (user_addr + user_size < user_addr)
		return(EINVAL);

	user_map = current_map();

	result = vm_map_protect(user_map, user_addr, user_addr+user_size, prot,
	   				 FALSE);
	switch (result) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	}
	return (EINVAL);
}


struct minherit_args {
	void *addr;
	size_t len;
	int inherit;
};

int
minherit(p, uap, retval)
	struct proc *p;
	struct minherit_args *uap;
	register_t *retval;
{
	vm_offset_t addr;
	vm_size_t size, pageoff;
	register vm_inherit_t inherit;
	vm_map_t	user_map;
	kern_return_t	result;

	addr = (vm_offset_t)uap->addr;
	size = uap->len;
	inherit = uap->inherit;

	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);
	if (addr + size < addr)
		return(EINVAL);

	user_map = current_map();
	result = vm_inherit(user_map, addr, size,
				inherit);
	switch (result) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	}
	return (EINVAL);
}

struct madvise_args {
		caddr_t addr;
		int len;
		int behav;
};
/* ARGSUSED */
int
madvise(p, uap, retval)
	struct proc *p;
	struct madvise_args *uap;
	register_t *retval;
{
	vm_map_t user_map;
	vm_offset_t start, end;
	vm_behavior_t new_behavior;
	kern_return_t	result;

	/*
	 * Check for illegal addresses.  Watch out for address wrap... Note
	 * that VM_*_ADDRESS are not constants due to casts (argh).
	 */
	if (VM_MAX_ADDRESS > 0 &&
		((vm_offset_t) uap->addr + uap->len) > VM_MAX_ADDRESS)
		return (EINVAL);
	if (VM_MIN_ADDRESS > 0 && uap->addr < VM_MIN_ADDRESS)
		return (EINVAL);

	if (((vm_offset_t) uap->addr + uap->len) < (vm_offset_t) uap->addr)
		return (EINVAL);

	/*
	 * Since this routine is only advisory, we default to conservative
	 * behavior.
	 */
	start = trunc_page((vm_offset_t) uap->addr);
	end = round_page((vm_offset_t) uap->addr + uap->len);
	
	user_map = current_map();

	switch (uap->behav) {
		case MADV_RANDOM:
			new_behavior = VM_BEHAVIOR_RANDOM;
		case MADV_SEQUENTIAL: 
			new_behavior = VM_BEHAVIOR_SEQUENTIAL;
		case MADV_NORMAL:
		default:
			new_behavior = VM_BEHAVIOR_DEFAULT;
	}

	result = vm_behavior_set(user_map, start, end, uap->behav);
	switch (result) {
		case KERN_SUCCESS:
			return (0);
		case KERN_INVALID_ADDRESS:
			return (EINVAL);
	}

	return (EINVAL);
}

struct mincore_args {
	const void *addr;
	size_t len;
	char *vec;
};
/* ARGSUSED */
int
mincore(p, uap, retval)
	struct proc *p;
	struct mincore_args *uap;
	register_t *retval;
{
	vm_offset_t addr, first_addr;
	vm_offset_t end;
	vm_map_t map;
	char *vec;
	int error;
	int vecindex, lastvecindex;
	int mincoreinfo=0;
	int pqueryinfo;
	kern_return_t	ret;
	int numref;

	map = current_map();

	/*
	 * Make sure that the addresses presented are valid for user
	 * mode.
	 */
	first_addr = addr = trunc_page((vm_offset_t) uap->addr);
	end = addr + (vm_size_t)round_page(uap->len);

	if (VM_MAX_ADDRESS > 0 && end > VM_MAX_ADDRESS)
		return (EINVAL);
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
	for(addr; addr < end; addr += PAGE_SIZE) {
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
			error = subyte( vec + lastvecindex, 0);
			if (error) {
				return (EFAULT);
			}
			++lastvecindex;
		}

		/*
		 * Pass the page information to the user
		 */
		error = subyte( vec + vecindex, mincoreinfo);
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
		error = subyte( vec + lastvecindex, 0);
		if (error) {
			return (EFAULT);
		}
		++lastvecindex;
	}
	
	return (0);
}

struct mlock_args {
		caddr_t addr;
		size_t len;
};

int
mlock(p, uap, retval)
	struct proc *p;
	struct mlock_args *uap;
	register_t *retval;
{
	vm_map_t user_map;
	vm_offset_t addr;
	vm_size_t size, pageoff;
	int error;
	kern_return_t	result;

	addr = (vm_offset_t) uap->addr;
	size = uap->len;

	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);

	/* disable wrap around */
	if (addr + size < addr)
		return (EINVAL);
#ifdef notyet 
/* Hmm.. What am I going to do with this? */
	if (atop(size) + cnt.v_wire_count > vm_page_max_wired)
		return (EAGAIN);
#ifdef pmap_wired_count
	if (size + ptoa(pmap_wired_count(vm_map_pmap(&p->p_vmspace->vm_map))) >
	    p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur)
		return (ENOMEM);
#else
	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);
#endif
#endif /* notyet */

	user_map = current_map();

	/* vm_wire */
	result = vm_wire(host_priv_self(), user_map, addr, size, VM_PROT_ALL);
	return (result == KERN_SUCCESS ? 0 : ENOMEM);
}

struct munlock_args {
		caddr_t addr;
		size_t len;
};
int
munlock(p, uap, retval)
	struct proc *p;
	struct munlock_args *uap;
	register_t *retval;
{
	vm_offset_t addr;
	vm_size_t size, pageoff;
	int error;
	vm_map_t user_map;
	kern_return_t	result;

	addr = (vm_offset_t) uap->addr;
	size = uap->len;

	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);

	/* disable wrap around */
	if (addr + size < addr)
		return (EINVAL);

#ifdef notyet 
/* Hmm.. What am I going to do with this? */
#ifndef pmap_wired_count
	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);
#endif
#endif /* notyet */

	user_map = current_map();

	/* vm_wire */
	result = vm_wire(host_priv_self(), user_map, addr, size, VM_PROT_NONE);
	return (result == KERN_SUCCESS ? 0 : ENOMEM);
}


struct mlockall_args {
	int	how;
};

int
mlockall(p, uap)
	struct proc *p;
	struct mlockall_args *uap;
{
	return (ENOSYS);
}

struct munlockall_args {
	int	how;
};

int
munlockall(p, uap)
	struct proc *p;
	struct munlockall_args *uap;
{
	return(ENOSYS);
}


/* BEGIN DEFUNCT */
struct obreak_args {
	char *nsiz;
};
obreak(p, uap, retval)
	struct proc *p;
	struct obreak_args *uap;
	register_t *retval;
{
	/* Not implemented, obsolete */
	return (ENOMEM);
}

int	both;

ovadvise()
{

#ifdef lint
	both = 0;
#endif
}
/* END DEFUNCT */
#if 1
int print_map_addr=0;
#endif /* 1 */

/* CDY need to fix interface to allow user to map above 32 bits */
kern_return_t map_fd(
	int		fd,
	vm_offset_t	offset,
	vm_offset_t	*va,
	boolean_t	findspace,
	vm_size_t	size)
{
	kern_return_t ret;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	ret = map_fd_funneled( fd, (vm_object_offset_t)offset, 
							va, findspace, size);

	(void) thread_funnel_set(kernel_flock, FALSE);

	return ret;
}

kern_return_t map_fd_funneled(
	int			fd,
	vm_object_offset_t	offset,
	vm_offset_t		*va,
	boolean_t		findspace,
	vm_size_t		size)
{
	kern_return_t	result;
	struct file	*fp;
	struct vnode	*vp;
	void *	pager;
	vm_offset_t	map_addr=0;
	vm_size_t	map_size;
	vm_map_copy_t	tmp;
	int		err=0;
	vm_map_t	my_map;
	struct proc	*p =(struct proc *)(get_bsdtask_info(current_task()));
#if 0
	extern int print_map_addr;
#endif /* 0 */

	/*
	 *	Find the inode; verify that it's a regular file.
	 */

	err = fdgetf(p, fd, &fp);
	if (err)
		return(err);
	
	if (fp->f_type != DTYPE_VNODE)
		return(KERN_INVALID_ARGUMENT);
	vp = (struct vnode *)fp->f_data;

	if (vp->v_type != VREG)
		return (KERN_INVALID_ARGUMENT);

	if (offset & PAGE_MASK_64) {
		printf("map_fd: file offset not page aligned(%d : %s\)n",p->p_pid, p->p_comm);
		return (KERN_INVALID_ARGUMENT);
	}
	map_size = round_page(size);

	/*
	 * Allow user to map in a zero length file.
	 */
	if (size == 0)
		return (KERN_SUCCESS);
	/*
	 *	Map in the file.
	 */
	UBCINFOCHECK("map_fd_funneled", vp);
	pager = (void *) ubc_getpager(vp);
	if (pager == NULL)
		return (KERN_FAILURE);


	my_map = current_map();

	result = vm_map_64(
			my_map,
			&map_addr, map_size, (vm_offset_t)0, TRUE,
			pager, offset, TRUE,
			VM_PROT_DEFAULT, VM_PROT_ALL,
			VM_INHERIT_DEFAULT);
	if (result != KERN_SUCCESS)
		return (result);


	if (!findspace) {
		vm_offset_t	dst_addr;
		vm_map_copy_t	tmp;

		if (copyin(va, &dst_addr, sizeof (dst_addr))	||
					trunc_page(dst_addr) != dst_addr) {
			(void) vm_map_remove(
					my_map,
					map_addr, map_addr + map_size,
					VM_MAP_NO_FLAGS);
			return (KERN_INVALID_ADDRESS);
		}

		result = vm_map_copyin(
				my_map,
				map_addr, map_size, TRUE,
				&tmp);
		if (result != KERN_SUCCESS) {
			
			(void) vm_map_remove(
					my_map,
					map_addr, map_addr + map_size,
					VM_MAP_NO_FLAGS);
			return (result);
		}

		result = vm_map_copy_overwrite(
					my_map,
					dst_addr, tmp, FALSE);
		if (result != KERN_SUCCESS) {
			vm_map_copy_discard(tmp);
			return (result);
		}
	} else {
		if (copyout(&map_addr, va, sizeof (map_addr))) {
			(void) vm_map_remove(
					my_map,
					map_addr, map_addr + map_size,
					VM_MAP_NO_FLAGS);
			return (KERN_INVALID_ADDRESS);
		}
	}

	ubc_setcred(vp, current_proc());
	ubc_map(vp);

	return (KERN_SUCCESS);
}
