/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/ubc.h>
#include <sys/lock.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>

#include <vm/vnode_pager.h>
#include <vm/vm_pageout.h>

#include <kern/assert.h>
#include <sys/kdebug.h>

unsigned int vp_pagein=0;
unsigned int vp_pgodirty=0;
unsigned int vp_pgoclean=0;
unsigned int dp_pgouts=0;	/* Default pager pageouts */
unsigned int dp_pgins=0;	/* Default pager pageins */

vm_object_offset_t
vnode_pager_get_filesize(struct vnode *vp)
{
	if (UBCINVALID(vp)) {
		return (vm_object_offset_t) 0;
	}

	return (vm_object_offset_t) ubc_getsize(vp);
	
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
	struct proc 	*p = current_proc();
	int		error = 0;
	int blkno=0, s;
	int cnt, isize;
	int pg_index;
	int offset;
	struct buf *bp;
	boolean_t	funnel_state;
	upl_page_info_t *pl;
	upl_t vpupl = NULL;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	isize = (int)size;

	if (isize <= 0) {
	        result = error = PAGER_ERROR;
		goto out;
	}
	UBCINFOCHECK("vnode_pageout", vp);

	if (UBCINVALID(vp)) {
		result = error = PAGER_ERROR;

		if (upl && !(flags & UPL_NOCOMMIT))
		        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		goto out;
	}
	if (upl) {
		/*
		 * This is a pageout from the Default pager,
		 * just go ahead and call VOP_PAGEOUT
		 */
		dp_pgouts++;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_START, 
				      size, 1, 0, 0, 0);

		if (error = VOP_PAGEOUT(vp, upl, upl_offset, (off_t)f_offset,
					(size_t)size, p->p_ucred, flags))
			result = error = PAGER_ERROR;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_END, 
				      size, 1, 0, 0, 0);

		goto out;
	}
	ubc_create_upl(vp, f_offset, isize, &vpupl, &pl, UPL_FOR_PAGEOUT | UPL_COPYOUT_FROM | UPL_SET_LITE);

	if (vpupl == (upl_t) 0) {
		result = error = PAGER_ABSENT;
		goto out;
	}
	/*
	 * if we get here, we've created the upl and
	 * are responsible for commiting/aborting it
	 * regardless of what the caller has passed in
	 */
	flags &= ~UPL_NOCOMMIT;

	if (ubc_getsize(vp) == 0) {
		for (offset = 0; isize; isize -= PAGE_SIZE,
					offset += PAGE_SIZE) {
			blkno = ubc_offtoblk(vp, (off_t)f_offset);
			f_offset += PAGE_SIZE;
			if ((bp = incore(vp, blkno)) &&
			    ISSET(bp->b_flags, B_BUSY)) {
				ubc_upl_abort_range(vpupl, offset, PAGE_SIZE,
						    UPL_ABORT_FREE_ON_EMPTY);
				result = error = PAGER_ERROR;
				continue;
			} else if (bp) {
				bremfree(bp);
				SET(bp->b_flags, B_BUSY | B_INVAL);
				brelse(bp);
			}
			ubc_upl_commit_range(vpupl, offset, PAGE_SIZE,
					     UPL_COMMIT_FREE_ON_EMPTY);
		}
		goto out;
	}
	pg_index = 0;
	offset   = 0;

	while (isize) {
		int  xsize;
		int  num_of_pages;

		if ( !upl_valid_page(pl, pg_index)) {
			ubc_upl_abort_range(vpupl, offset, PAGE_SIZE,
					    UPL_ABORT_FREE_ON_EMPTY);
			offset += PAGE_SIZE;
			isize  -= PAGE_SIZE;
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
			 * Note we must not sleep here if B_BUSY - that is
			 * a lock inversion which causes deadlock.
			 */
			blkno = ubc_offtoblk(vp, (off_t)(f_offset + offset));
			s = splbio();
			vp_pgoclean++;			
			if (vp->v_tag == VT_NFS) {
				/* check with nfs if page is OK to drop */
				error = nfs_buf_page_inval(vp, (off_t)(f_offset + offset));
				splx(s);
				if (error) {
					ubc_upl_abort_range(vpupl, offset, PAGE_SIZE,
							    UPL_ABORT_FREE_ON_EMPTY);
					result = error = PAGER_ERROR;
					offset += PAGE_SIZE;
					isize -= PAGE_SIZE;
					pg_index++;
					continue;
				}
			} else if ((bp = incore(vp, blkno)) &&
			    ISSET(bp->b_flags, B_BUSY | B_NEEDCOMMIT)) {
				splx(s);
				ubc_upl_abort_range(vpupl, offset, PAGE_SIZE,
						    UPL_ABORT_FREE_ON_EMPTY);
				result = error = PAGER_ERROR;
				offset += PAGE_SIZE;
				isize -= PAGE_SIZE;
				pg_index++;
				continue;
			} else if (bp) {
			        bremfree(bp);
				SET(bp->b_flags, B_BUSY | B_INVAL );
				splx(s);
				brelse(bp);
			} else
				splx(s);

			ubc_upl_commit_range(vpupl, offset, PAGE_SIZE, 
					     UPL_COMMIT_FREE_ON_EMPTY);
			offset += PAGE_SIZE;
			isize  -= PAGE_SIZE;
			pg_index++;

			continue;
		}
		vp_pgodirty++;

		num_of_pages = 1;
		xsize = isize - PAGE_SIZE;

		while (xsize) {
			if ( !upl_valid_page(pl, pg_index + num_of_pages))
				break;
			if ( !upl_dirty_page(pl, pg_index + num_of_pages))
				break;
			num_of_pages++;
			xsize -= PAGE_SIZE;
		}
		xsize = num_of_pages * PAGE_SIZE;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_START, 
				      xsize, 0, 0, 0, 0);

		if (error = VOP_PAGEOUT(vp, vpupl, (vm_offset_t)offset,
					(off_t)(f_offset + offset), xsize,
					p->p_ucred, flags))
			result = error = PAGER_ERROR;

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, 1)) | DBG_FUNC_END, 
				      xsize, 0, 0, 0, 0);

		offset += xsize;
		isize  -= xsize;
		pg_index += num_of_pages;
	}
out:
	if (errorp)
		*errorp = result;

	thread_funnel_set(kernel_flock, funnel_state);

	return (error);
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
        struct proc     *p = current_proc();
        upl_page_info_t *pl;
	int	        result = PAGER_SUCCESS;
	int		error = 0;
	int		xfer_size;
        int             pages_in_upl;
        int             start_pg;
        int             last_pg;
	int             first_pg;
        int             xsize;
	int             abort_needed = 1;
	boolean_t	funnel_state;


	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	UBCINFOCHECK("vnode_pagein", vp);

	if (UBCINVALID(vp)) {
		result = PAGER_ERROR;
		error  = PAGER_ERROR;
		if (upl && !(flags & UPL_NOCOMMIT)) {
			ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
		}
		goto out;
	}
	if (upl == (upl_t)NULL) {
	        if (size > (MAX_UPL_TRANSFER * PAGE_SIZE)) {
		        result = PAGER_ERROR;
			error  = PAGER_ERROR;
			goto out;
		}
	        ubc_create_upl(vp, f_offset, size, &upl, &pl, UPL_RET_ONLY_ABSENT | UPL_SET_LITE);

		if (upl == (upl_t)NULL) {
		        result =  PAGER_ABSENT;
			error = PAGER_ABSENT;
			goto out;
		}
		upl_offset = 0;
		/*
		 * if we get here, we've created the upl and
		 * are responsible for commiting/aborting it
		 * regardless of what the caller has passed in
		 */
		flags &= ~UPL_NOCOMMIT;
		
		vp_pagein++;
	} else {
	        pl = ubc_upl_pageinfo(upl);

		dp_pgins++;
	}
	pages_in_upl = size / PAGE_SIZE;
	first_pg     = upl_offset / PAGE_SIZE;

	/*
	 * before we start marching forward, we must make sure we end on 
	 * a present page, otherwise we will be working with a freed
         * upl
	 */
	for (last_pg = pages_in_upl - 1; last_pg >= first_pg; last_pg--) {
		if (upl_page_present(pl, last_pg))
			break;
	}
	pages_in_upl = last_pg + 1;

	for (last_pg = first_pg; last_pg < pages_in_upl;) {
	        /*
		 * scan the upl looking for the next
		 * page that is present.... if all of the 
		 * pages are absent, we're done
		 */
	        for (start_pg = last_pg; last_pg < pages_in_upl; last_pg++) {
		        if (upl_page_present(pl, last_pg))
			        break;
		}
		if (last_pg == pages_in_upl)
		        break;

	        /*
		 * if we get here, we've sitting on a page 
		 * that is present... we want to skip over
		 * any range of 'valid' pages... if this takes
		 * us to the end of the request, than we're done
		 */
	        for (start_pg = last_pg; last_pg < pages_in_upl; last_pg++) {
		        if (!upl_valid_page(pl, last_pg) || !upl_page_present(pl, last_pg))
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

			if (!(flags & UPL_NOCOMMIT))
			        ubc_upl_abort_range(upl, start_pg * PAGE_SIZE, xsize, UPL_ABORT_FREE_ON_EMPTY);

			abort_needed = 0;
		}
		if (last_pg == pages_in_upl)
		        break;

		if (!upl_page_present(pl, last_pg))
		        /*
			 * if we found a range of valid pages 
			 * terminated by a non-present page
			 * than start over
			 */
		        continue;

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

			if (error = VOP_PAGEIN(vp, upl, (vm_offset_t) xoff,
					       (off_t)f_offset + xoff,
					       xsize, p->p_ucred,
					       flags)) {
				result = PAGER_ERROR;
				error  = PAGER_ERROR;

			}
			abort_needed = 0;
		}
        }
	if (!(flags & UPL_NOCOMMIT) && abort_needed)
	        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
out:
	if (errorp)
		*errorp = result;
	thread_funnel_set(kernel_flock, funnel_state);

	return (error);
}

void
vnode_pager_shutdown()
{
	int i;
	extern struct bs_map  bs_port_table[];
	struct vnode *vp;

	for(i = 0; i < MAX_BACKING_STORE; i++) {
		vp = (struct vnode *)(bs_port_table[i]).vp;
		if (vp) {
			(bs_port_table[i]).vp = 0;
			ubc_rele(vp);
			/* get rid of macx_swapon() namei() reference */
			vrele(vp);

			/* get rid of macx_swapon() "extra" reference */
			vrele(vp);
		}
	}
}


void *
upl_get_internal_page_list(upl_t upl)
{
  return(UPL_GET_INTERNAL_PAGE_LIST(upl));

}
