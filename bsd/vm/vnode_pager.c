/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* 
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 *	File:	vnode_pager.c
 *
 *	"Swap" pager that pages to/from vnodes.  Also
 *	handles demand paging from files.
 *
 */

#include <mach/boolean.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/vnode_internal.h>
#include <sys/namei.h>
#include <sys/mount_internal.h>	/* needs internal due to fhandle_t */
#include <sys/ubc_internal.h>
#include <sys/lock.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/sdt.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>

#include <vm/vnode_pager.h>
#include <vm/vm_pageout.h>

#include <kern/assert.h>
#include <sys/kdebug.h>
#include <machine/spl.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>

#include <vm/vm_protos.h>

unsigned int vp_pagein=0;
unsigned int vp_pgodirty=0;
unsigned int vp_pgoclean=0;
unsigned int dp_pgouts=0;	/* Default pager pageouts */
unsigned int dp_pgins=0;	/* Default pager pageins */

vm_object_offset_t
vnode_pager_get_filesize(struct vnode *vp)
{

	return (vm_object_offset_t) ubc_getsize(vp);
}

kern_return_t
vnode_pager_get_pathname(
	struct vnode	*vp,
	char		*pathname,
	vm_size_t	*length_p)
{
	int	error, len;

	len = (int) *length_p;
	error = vn_getpath(vp, pathname, &len);
	if (error != 0) {
		return KERN_FAILURE;
	}
	*length_p = (vm_size_t) len;
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_filename(
	struct vnode	*vp,
	const char	**filename)
{
	*filename = vp->v_name;
	return KERN_SUCCESS;
}

kern_return_t
vnode_pager_get_cs_blobs(
	struct vnode	*vp,
	void		**blobs)
{
	*blobs = ubc_get_cs_blobs(vp);
	return KERN_SUCCESS;
}

pager_return_t
vnode_pageout(struct vnode *vp,
	upl_t			upl,
	vm_offset_t		upl_offset,
	vm_object_offset_t	f_offset,
	vm_size_t		size,
	int			flags,
	int			*errorp)
{
	int		result = PAGER_SUCCESS;
	int		error = 0;
	int		error_ret = 0;
	daddr64_t blkno;
	int isize;
	int pg_index;
	int base_index;
	int offset;
	upl_page_info_t *pl;
	vfs_context_t ctx = vfs_context_current();	/* pager context */

	isize = (int)size;

	if (isize <= 0) {
	        result    = PAGER_ERROR;
		error_ret = EINVAL;
		goto out;
	}

	if (UBCINFOEXISTS(vp) == 0) {
		result    = PAGER_ERROR;
		error_ret = EINVAL;

		if (upl && !(flags & UPL_NOCOMMIT))
		        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		goto out;
	}
	if ( !(flags & UPL_VNODE_PAGER)) {
		/*
		 * This is a pageout from the default pager,
		 * just go ahead and call vnop_pageout since
		 * it has already sorted out the dirty ranges
		 */
		dp_pgouts++;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_START, 
				      size, 1, 0, 0, 0);

		if ( (error_ret = VNOP_PAGEOUT(vp, upl, upl_offset, (off_t)f_offset,
					       (size_t)size, flags, ctx)) )
			result = PAGER_ERROR;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_END, 
				      size, 1, 0, 0, 0);

		goto out;
	}
	/*
	 * we come here for pageouts to 'real' files and
	 * for msyncs...  the upl may not contain any
	 * dirty pages.. it's our responsibility to sort
	 * through it and find the 'runs' of dirty pages
	 * to call VNOP_PAGEOUT on...
	 */
	pl = ubc_upl_pageinfo(upl);

	if (ubc_getsize(vp) == 0) {
	        /*
		 * if the file has been effectively deleted, then
		 * we need to go through the UPL and invalidate any
		 * buffer headers we might have that reference any
		 * of it's pages
		 */
		for (offset = upl_offset; isize; isize -= PAGE_SIZE, offset += PAGE_SIZE) {
#if NFSCLIENT
			if (vp->v_tag == VT_NFS)
				/* check with nfs if page is OK to drop */
				error = nfs_buf_page_inval(vp, (off_t)f_offset);
			else
#endif
			{
			        blkno = ubc_offtoblk(vp, (off_t)f_offset);
			        error = buf_invalblkno(vp, blkno, 0);
			}
			if (error) {
			        if ( !(flags & UPL_NOCOMMIT))
				        ubc_upl_abort_range(upl, offset, PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);
				if (error_ret == 0)
				        error_ret = error;
				result = PAGER_ERROR;

			} else if ( !(flags & UPL_NOCOMMIT)) {
			        ubc_upl_commit_range(upl, offset, PAGE_SIZE, UPL_COMMIT_FREE_ON_EMPTY);
			}
			f_offset += PAGE_SIZE;
		}
		goto out;
	}
	/*
	 * Ignore any non-present pages at the end of the
	 * UPL so that we aren't looking at a upl that 
	 * may already have been freed by the preceeding
	 * aborts/completions.
	 */
	base_index = upl_offset / PAGE_SIZE;

	for (pg_index = (upl_offset + isize) / PAGE_SIZE; pg_index > base_index;) {
	        if (upl_page_present(pl, --pg_index))
		        break;
		if (pg_index == base_index) {
		        /*
			 * no pages were returned, so release
			 * our hold on the upl and leave
			 */
		        if ( !(flags & UPL_NOCOMMIT))
			        ubc_upl_abort_range(upl, upl_offset, isize, UPL_ABORT_FREE_ON_EMPTY);

			goto out;
		}
	}
	isize = ((pg_index + 1) - base_index) * PAGE_SIZE;

	offset = upl_offset;
	pg_index = base_index;

	while (isize) {
		int  xsize;
		int  num_of_pages;

		if ( !upl_page_present(pl, pg_index)) {
		        /*
			 * we asked for RET_ONLY_DIRTY, so it's possible
			 * to get back empty slots in the UPL
			 * just skip over them
			 */
		        f_offset += PAGE_SIZE;
			offset   += PAGE_SIZE;
			isize    -= PAGE_SIZE;
			pg_index++;

			continue;
		}
		if ( !upl_dirty_page(pl, pg_index)) {
			/*
			 * if the page is not dirty and reached here it is
			 * marked precious or it is due to invalidation in
			 * memory_object_lock request as part of truncation
			 * We also get here from vm_object_terminate()
			 * So all you need to do in these
			 * cases is to invalidate incore buffer if it is there
			 * Note we must not sleep here if the buffer is busy - that is
			 * a lock inversion which causes deadlock.
			 */
			vp_pgoclean++;			

#if NFSCLIENT
			if (vp->v_tag == VT_NFS)
				/* check with nfs if page is OK to drop */
				error = nfs_buf_page_inval(vp, (off_t)f_offset);
			else
#endif
			{
			        blkno = ubc_offtoblk(vp, (off_t)f_offset);
			        error = buf_invalblkno(vp, blkno, 0);
			}
			if (error) {
			        if ( !(flags & UPL_NOCOMMIT))
				        ubc_upl_abort_range(upl, offset, PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);
				if (error_ret == 0)
				        error_ret = error;
				result = PAGER_ERROR;

			} else if ( !(flags & UPL_NOCOMMIT)) {
			        ubc_upl_commit_range(upl, offset, PAGE_SIZE, UPL_COMMIT_FREE_ON_EMPTY);
			}
		        f_offset += PAGE_SIZE;
			offset   += PAGE_SIZE;
			isize    -= PAGE_SIZE;
			pg_index++;

			continue;
		}
		vp_pgodirty++;

		num_of_pages = 1;
		xsize = isize - PAGE_SIZE;

		while (xsize) {
			if ( !upl_dirty_page(pl, pg_index + num_of_pages))
				break;
			num_of_pages++;
			xsize -= PAGE_SIZE;
		}
		xsize = num_of_pages * PAGE_SIZE;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_START, 
				      xsize, (int)f_offset, 0, 0, 0);

		if ( (error = VNOP_PAGEOUT(vp, upl, (vm_offset_t)offset, (off_t)f_offset,
					   xsize, flags, ctx)) ) {
		        if (error_ret == 0)
		                error_ret = error;
			result = PAGER_ERROR;
		}
		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_END, 
				      xsize, 0, 0, 0, 0);

	        f_offset += xsize;
		offset   += xsize;
		isize    -= xsize;
		pg_index += num_of_pages;
	}
out:
	if (errorp)
		*errorp = error_ret;

	return (result);
}


pager_return_t
vnode_pagein(
	struct vnode 		*vp,
	upl_t        		upl,
	vm_offset_t  		upl_offset,
	vm_object_offset_t	f_offset,
	vm_size_t     		size,
	int           		flags,
	int 			*errorp)
{
        struct uthread	*ut;
        upl_page_info_t *pl;
	int	        result = PAGER_SUCCESS;
	int		error = 0;
        int             pages_in_upl;
        int             start_pg;
        int             last_pg;
	int             first_pg;
        int             xsize;
	int		must_commit = 1;

	if (flags & UPL_NOCOMMIT)
	        must_commit = 0;

	if (UBCINFOEXISTS(vp) == 0) {
		result = PAGER_ERROR;
		error  = PAGER_ERROR;

		if (upl && must_commit)
			ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);

		goto out;
	}
	if (upl == (upl_t)NULL) {
	        if (size > (MAX_UPL_SIZE * PAGE_SIZE)) {

		  	panic("vnode_pagein: size = %x\n", size);

		        result = PAGER_ERROR;
			error  = PAGER_ERROR;
			goto out;
		}
	        ubc_create_upl(vp, f_offset, size, &upl, &pl, UPL_NOBLOCK | UPL_RET_ONLY_ABSENT | UPL_SET_LITE);

		if (upl == (upl_t)NULL) {

		  	panic("vnode_pagein: ubc_create_upl failed\n");

		        result =  PAGER_ABSENT;
			error = PAGER_ABSENT;
			goto out;
		}
		upl_offset = 0;
		first_pg = 0;
		
		/*
		 * if we get here, we've created the upl and
		 * are responsible for commiting/aborting it
		 * regardless of what the caller has passed in
		 */
		flags &= ~UPL_NOCOMMIT;
		must_commit = 1;
		
		vp_pagein++;
	} else {
	        pl = ubc_upl_pageinfo(upl);
		first_pg = upl_offset / PAGE_SIZE;

		dp_pgins++;
	}
	pages_in_upl = size / PAGE_SIZE;
	DTRACE_VM2(pgpgin, int, pages_in_upl, (uint64_t *), NULL);

	/*
	 * before we start marching forward, we must make sure we end on 
	 * a present page, otherwise we will be working with a freed
         * upl
	 */
	for (last_pg = pages_in_upl - 1; last_pg >= first_pg; last_pg--) {
		if (upl_page_present(pl, last_pg))
			break;
		if (last_pg == first_pg) {
		        /*
			 * empty UPL, no pages are present
			 */
		        if (must_commit)
			        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
			goto out;
		}
	}
	pages_in_upl = last_pg + 1;
	last_pg = first_pg;

	while (last_pg < pages_in_upl) {
	        /*
		 * skip over missing pages...
		 */
	        for ( ; last_pg < pages_in_upl; last_pg++) {
		        if (upl_page_present(pl, last_pg))
			        break;
		}
	        /*
		 * skip over 'valid' pages... we don't want to issue I/O for these
		 */
	        for (start_pg = last_pg; last_pg < pages_in_upl; last_pg++) {
		        if (!upl_valid_page(pl, last_pg))
			        break;
		}
		if (last_pg > start_pg) {
		        /*
			 * we've found a range of valid pages
			 * if we've got COMMIT responsibility
			 * commit this range of pages back to the
			 * cache unchanged
			 */
		        xsize = (last_pg - start_pg) * PAGE_SIZE;

			if (must_commit)
			        ubc_upl_abort_range(upl, start_pg * PAGE_SIZE, xsize, UPL_ABORT_FREE_ON_EMPTY);
		}
		if (last_pg == pages_in_upl)
		        /*
			 * we're done... all pages that were present
			 * have either had I/O issued on them or 
			 * were aborted unchanged...
			 */
		        break;

		if (!upl_page_present(pl, last_pg)) {
		        /*
			 * we found a range of valid pages 
			 * terminated by a missing page...
			 * bump index to the next page and continue on
			 */
		        last_pg++;
		        continue;
		}
		/*
		 * scan from the found invalid page looking for a valid
		 * or non-present page before the end of the upl is reached, if we
		 * find one, then it will be the last page of the request to
		 * 'cluster_io'
		 */
		for (start_pg = last_pg; last_pg < pages_in_upl; last_pg++) {
		        if (upl_valid_page(pl, last_pg) || !upl_page_present(pl, last_pg))
			        break;
		}
		if (last_pg > start_pg) {
		        int xoff;
		        xsize = (last_pg - start_pg) * PAGE_SIZE;
			xoff  = start_pg * PAGE_SIZE;

			if ( (error = VNOP_PAGEIN(vp, upl, (vm_offset_t) xoff,
					       (off_t)f_offset + xoff,
					       xsize, flags, vfs_context_current())) ) {
				result = PAGER_ERROR;
				error  = PAGER_ERROR;

			}
		}
        }
out:
	if (errorp)
		*errorp = result;

	ut = get_bsdthread_info(current_thread());

	if (ut->uu_lowpri_window) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this page fault
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		throttle_lowpri_io(TRUE);
	}
	return (error);
}

void
vnode_pager_shutdown(void)
{
	int i;
	vnode_t vp;

	for(i = 0; i < MAX_BACKING_STORE; i++) {
		vp = (vnode_t)(bs_port_table[i]).vp;
		if (vp) {
			(bs_port_table[i]).vp = 0;

			/* get rid of macx_swapon() reference */
			vnode_rele(vp);
		}
	}
}


void *
upl_get_internal_page_list(upl_t upl)
{
  return(UPL_GET_INTERNAL_PAGE_LIST(upl));

}
