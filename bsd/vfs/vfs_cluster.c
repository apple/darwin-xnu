/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)vfs_cluster.c	8.10 (Berkeley) 3/28/95
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/trace.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <libkern/libkern.h>

#include <sys/ubc.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#define CL_READ      0x01
#define CL_ASYNC     0x02
#define CL_COMMIT    0x04
#define CL_PAGEOUT   0x10
#define CL_AGE       0x20
#define CL_DUMP      0x40
#define CL_NOZERO    0x80
#define CL_PAGEIN    0x100
#define CL_DEV_MEMORY 0x200
#define CL_PRESERVE   0x400


struct clios {
        u_int  io_completed;       /* amount of io that has currently completed */
        u_int  io_issued;          /* amount of io that was successfully issued */
        int    io_error;           /* error code of first error encountered */
        int    io_wanted;          /* someone is sleeping waiting for a change in state */
};


static void cluster_zero(upl_t upl, vm_offset_t   upl_offset,
		int size, struct buf *bp);
static int cluster_read_x(struct vnode *vp, struct uio *uio,
		off_t filesize, int devblocksize, int flags);
static int cluster_write_x(struct vnode *vp, struct uio *uio,
		off_t oldEOF, off_t newEOF, off_t headOff,
		off_t tailOff, int devblocksize, int flags);
static int cluster_nocopy_read(struct vnode *vp, struct uio *uio,
		off_t filesize, int devblocksize, int flags);
static int cluster_nocopy_write(struct vnode *vp, struct uio *uio,
		off_t newEOF, int devblocksize, int flags);
static int cluster_phys_read(struct vnode *vp, struct uio *uio,
		off_t filesize, int devblocksize, int flags);
static int cluster_phys_write(struct vnode *vp, struct uio *uio,
		off_t newEOF, int devblocksize, int flags);
static int cluster_align_phys_io(struct vnode *vp, struct uio *uio,
                vm_offset_t usr_paddr, int xsize, int devblocksize, int flags);
static int cluster_push_x(struct vnode *vp, off_t EOF, daddr_t first, daddr_t last, int can_delay);
static int cluster_try_push(struct vnode *vp, off_t newEOF, int can_delay, int push_all);


/*
 * throttle the number of async writes that
 * can be outstanding on a single vnode
 * before we issue a synchronous write 
 */
#define ASYNC_THROTTLE  9

static int
cluster_iodone(bp)
	struct buf *bp;
{
        int         b_flags;
        int         error;
	int         total_size;
	int         total_resid;
	int         upl_offset;
	int         zero_offset;
	upl_t       upl;
	struct buf *cbp;
	struct buf *cbp_head;
	struct buf *cbp_next;
	struct buf *real_bp;
	struct vnode *vp;
	struct clios *iostate;
	int         commit_size;
	int         pg_offset;


	cbp_head = (struct buf *)(bp->b_trans_head);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_START,
		     (int)cbp_head, bp->b_lblkno, bp->b_bcount, bp->b_flags, 0);

	for (cbp = cbp_head; cbp; cbp = cbp->b_trans_next) {
	        /*
		 * all I/O requests that are part of this transaction
		 * have to complete before we can process it
		 */
	        if ( !(cbp->b_flags & B_DONE)) {

		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
				     (int)cbp_head, (int)cbp, cbp->b_bcount, cbp->b_flags, 0);

		        return 0;
		}
	}
	error       = 0;
	total_size  = 0;
	total_resid = 0;

	cbp        = cbp_head;
	upl_offset = cbp->b_uploffset;
	upl        = cbp->b_pagelist;
	b_flags    = cbp->b_flags;
	real_bp    = cbp->b_real_bp;
	vp         = cbp->b_vp;
	zero_offset= cbp->b_validend;
	iostate    = (struct clios *)cbp->b_iostate;

	while (cbp) {
		if (cbp->b_vectorcount > 1)
		        _FREE(cbp->b_vectorlist, M_SEGMENT);

		if ((cbp->b_flags & B_ERROR) && error == 0)
		        error = cbp->b_error;

		total_resid += cbp->b_resid;
		total_size  += cbp->b_bcount;

		cbp_next = cbp->b_trans_next;

		free_io_buf(cbp);

		cbp = cbp_next;
	}
	if (zero_offset)
	        cluster_zero(upl, zero_offset, PAGE_SIZE - (zero_offset & PAGE_MASK), real_bp);

	if ((vp->v_flag & VTHROTTLED) && (vp->v_numoutput <= (ASYNC_THROTTLE / 3))) {
	        vp->v_flag &= ~VTHROTTLED;
		wakeup((caddr_t)&vp->v_numoutput);
	}
	if (iostate) {
	        /*
		 * someone has issued multiple I/Os asynchrounsly
		 * and is waiting for them to complete (streaming)
		 */
	        if (error && iostate->io_error == 0)
		        iostate->io_error = error;

		iostate->io_completed += total_size;

		if (iostate->io_wanted) {
		        /*
		         * someone is waiting for the state of
			 * this io stream to change
			 */
		        iostate->io_wanted = 0;
			wakeup((caddr_t)&iostate->io_wanted);
		}
	}
	if ((b_flags & B_NEED_IODONE) && real_bp) {
		if (error) {
		        real_bp->b_flags |= B_ERROR;
			real_bp->b_error = error;
		}
		real_bp->b_resid = total_resid;

		biodone(real_bp);
	}
	if (error == 0 && total_resid)
	        error = EIO;

	if (b_flags & B_COMMIT_UPL) {
	        pg_offset   = upl_offset & PAGE_MASK;
		commit_size = (((pg_offset + total_size) + (PAGE_SIZE - 1)) / PAGE_SIZE) * PAGE_SIZE;

		if (error || (b_flags & B_NOCACHE) || ((b_flags & B_PHYS) && !(b_flags & B_READ))) {
		        int upl_abort_code;

			if (b_flags & B_PHYS)
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if ((b_flags & B_PAGEOUT) && (error != ENXIO)) /* transient error */
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if (b_flags & B_PGIN)
				upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR;
			else
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_DUMP_PAGES;

			ubc_upl_abort_range(upl, upl_offset - pg_offset, commit_size,
					upl_abort_code);
			
		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
				     (int)upl, upl_offset - pg_offset, commit_size,
				     0x80000000|upl_abort_code, 0);

		} else {
		        int upl_commit_flags = UPL_COMMIT_FREE_ON_EMPTY;

			if (b_flags & B_PHYS)
			        upl_commit_flags |= UPL_COMMIT_SET_DIRTY;
			else if ( !(b_flags & B_PAGEOUT))
			        upl_commit_flags |= UPL_COMMIT_CLEAR_DIRTY;
			if (b_flags & B_AGE)
			        upl_commit_flags |= UPL_COMMIT_INACTIVATE;

			ubc_upl_commit_range(upl, upl_offset - pg_offset, commit_size,
					upl_commit_flags);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
				     (int)upl, upl_offset - pg_offset, commit_size,
				     upl_commit_flags, 0);
		}
	} else 
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
			     (int)upl, upl_offset, 0, error, 0);

	return (error);
}


static void
cluster_zero(upl, upl_offset, size, bp)
	upl_t         upl;
	vm_offset_t   upl_offset;
	int           size;
	struct buf   *bp;
{
        vm_offset_t   io_addr = 0;
	int           must_unmap = 0;
	kern_return_t kret;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 23)) | DBG_FUNC_NONE,
		     upl_offset, size, (int)bp, 0, 0);

	if (bp == NULL || bp->b_data == NULL) {
	        kret = ubc_upl_map(upl, &io_addr);
		
		if (kret != KERN_SUCCESS)
		        panic("cluster_zero: ubc_upl_map() failed with (%d)", kret);
		if (io_addr == 0) 
		        panic("cluster_zero: ubc_upl_map() mapped 0");

		must_unmap = 1;
	} else
	        io_addr = (vm_offset_t)bp->b_data;
	bzero((caddr_t)(io_addr + upl_offset), size);
	
	if (must_unmap) {
	        kret = ubc_upl_unmap(upl);

		if (kret != KERN_SUCCESS)
		        panic("cluster_zero: kernel_upl_unmap failed");
	}
}

static int
cluster_io(vp, upl, upl_offset, f_offset, non_rounded_size, devblocksize, flags, real_bp, iostate)
	struct vnode *vp;
	upl_t         upl;
	vm_offset_t   upl_offset;
	off_t         f_offset;
	int           non_rounded_size;
	int           devblocksize;
	int           flags;
	struct buf   *real_bp;
	struct clios *iostate;
{
	struct buf   *cbp;
	struct iovec *iovp;
	u_int         size;
	u_int         io_size;
	int           io_flags;
	int           error = 0;
	int           retval = 0;
	struct buf   *cbp_head = 0;
	struct buf   *cbp_tail = 0;
	upl_page_info_t *pl;
	int buf_count = 0;
	int pg_count;
	int pg_offset;
	u_int max_iosize;
	u_int max_vectors;
	int priv;
	int zero_offset = 0;
	u_int  first_lblkno;

	if (flags & CL_READ) {
	        io_flags = (B_VECTORLIST | B_READ);

		vfs_io_attributes(vp, B_READ, &max_iosize, &max_vectors);
	} else {
	        io_flags = (B_VECTORLIST | B_WRITEINPROG);

		vfs_io_attributes(vp, B_WRITE, &max_iosize, &max_vectors);
	}
	pl = ubc_upl_pageinfo(upl);

	if (flags & CL_AGE)
	        io_flags |= B_AGE;
	if (flags & CL_DUMP)
	        io_flags |= B_NOCACHE;
	if (flags & CL_PAGEIN)
		io_flags |= B_PGIN;
	if (flags & CL_PAGEOUT)
		io_flags |= B_PAGEOUT;
	if (flags & CL_COMMIT)
	        io_flags |= B_COMMIT_UPL;
	if (flags & CL_PRESERVE)
	        io_flags |= B_PHYS;

	if (devblocksize)
	        size = (non_rounded_size + (devblocksize - 1)) & ~(devblocksize - 1);
	else
	        size = non_rounded_size;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 22)) | DBG_FUNC_START,
		     (int)f_offset, size, upl_offset, flags, 0);

	if ((flags & CL_READ) && ((upl_offset + non_rounded_size) & PAGE_MASK) && (!(flags & CL_NOZERO))) {
	        /*
		 * then we are going to end up
		 * with a page that we can't complete (the file size wasn't a multiple
		 * of PAGE_SIZE and we're trying to read to the end of the file
		 * so we'll go ahead and zero out the portion of the page we can't
		 * read in from the file
		 */
	        zero_offset = upl_offset + non_rounded_size;
	}
	while (size) {
		int vsize;
		int i;
		int pl_index;
		int pg_resid;
		int num_contig;
		daddr_t lblkno;
		daddr_t blkno;

		if (size > max_iosize)
		        io_size = max_iosize;
		else
		        io_size = size;

		if (error = VOP_CMAP(vp, f_offset, io_size, &blkno, (size_t *)&io_size, NULL)) {
		        if (error == EOPNOTSUPP)
			        panic("VOP_CMAP Unimplemented");
			break;
		}

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 24)) | DBG_FUNC_NONE,
			     (int)f_offset, (int)blkno, io_size, zero_offset, 0);

		if ( (!(flags & CL_READ) && (long)blkno == -1) || io_size == 0) {
			if (flags & CL_PAGEOUT) {
		        	error = EINVAL;
				break;
			};
			
			/* Try paging out the page individually before
			   giving up entirely and dumping it (it could
			   be mapped in a "hole" and require allocation
			   before the I/O:
			 */
	        	 ubc_upl_abort_range(upl, upl_offset, PAGE_SIZE_64, UPL_ABORT_FREE_ON_EMPTY);
			 if (ubc_pushdirty_range(vp, f_offset, PAGE_SIZE_64) == 0) {
			 	error = EINVAL;
			 	break;
			 };
			 
			upl_offset += PAGE_SIZE_64;
			f_offset   += PAGE_SIZE_64;
			size       -= PAGE_SIZE_64;
			continue;
		}
		lblkno = (daddr_t)(f_offset / PAGE_SIZE_64);
		/*
		 * we have now figured out how much I/O we can do - this is in 'io_size'
		 * pl_index represents the first page in the 'upl' that the I/O will occur for
		 * pg_offset is the starting point in the first page for the I/O
		 * pg_count is the number of full and partial pages that 'io_size' encompasses
		 */
		pl_index  = upl_offset / PAGE_SIZE; 
		pg_offset = upl_offset & PAGE_MASK;
		pg_count  = (io_size + pg_offset + (PAGE_SIZE - 1)) / PAGE_SIZE;

		if (flags & CL_DEV_MEMORY) {
		        /*
			 * currently, can't deal with reading 'holes' in file
			 */
		        if ((long)blkno == -1) {
			        error = EINVAL;
				break;
			}
			/*
			 * treat physical requests as one 'giant' page
			 */
			pg_count = 1;
		}
		if ((flags & CL_READ) && (long)blkno == -1) {
		        int bytes_to_zero;

		        /*
			 * if we're reading and blkno == -1, then we've got a
			 * 'hole' in the file that we need to deal with by zeroing
			 * out the affected area in the upl
			 */
		        if (zero_offset && io_size == size) {
			        /*
				 * if this upl contains the EOF and it is not a multiple of PAGE_SIZE
				 * than 'zero_offset' will be non-zero
				 * if the 'hole' returned by VOP_CMAP extends all the way to the eof
				 * (indicated by the io_size finishing off the I/O request for this UPL)
				 * than we're not going to issue an I/O for the
				 * last page in this upl... we need to zero both the hole and the tail
				 * of the page beyond the EOF, since the delayed zero-fill won't kick in 
				 */
			        bytes_to_zero = (((upl_offset + io_size) + (PAGE_SIZE - 1)) & ~PAGE_MASK) - upl_offset;

				zero_offset = 0;
			} else
			        bytes_to_zero = io_size;

		        cluster_zero(upl, upl_offset, bytes_to_zero, real_bp);
			  
			if (cbp_head)
			        /*
				 * if there is a current I/O chain pending
				 * then the first page of the group we just zero'd
				 * will be handled by the I/O completion if the zero
				 * fill started in the middle of the page
				 */
			        pg_count = (io_size - pg_offset) / PAGE_SIZE;
			else {
			        /*
				 * no pending I/O to pick up that first page
				 * so, we have to make sure it gets committed
				 * here.
				 * set the pg_offset to 0 so that the upl_commit_range
				 * starts with this page
				 */
			        pg_count = (io_size + pg_offset) / PAGE_SIZE;
				pg_offset = 0;
			}
			if (io_size == size && ((upl_offset + io_size) & PAGE_MASK))
			        /*
				 * if we're done with the request for this UPL
				 * then we have to make sure to commit the last page
				 * even if we only partially zero-filled it
				 */
			        pg_count++;

			if (pg_count) {
			        if (pg_offset)
				        pg_resid = PAGE_SIZE - pg_offset;
				else
				        pg_resid = 0;

				if (flags & CL_COMMIT)
				        ubc_upl_commit_range(upl,
							(upl_offset + pg_resid) & ~PAGE_MASK, 
							pg_count * PAGE_SIZE,
							UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
			}
			upl_offset += io_size;
			f_offset   += io_size;
			size       -= io_size;

			if (cbp_head && pg_count) 
			        goto start_io;
			continue;

		} else if (real_bp && (real_bp->b_blkno == real_bp->b_lblkno)) {
		        real_bp->b_blkno = blkno;
		}

		if (pg_count > 1) {
			if (pg_count > max_vectors) {
				io_size -= (pg_count - max_vectors) * PAGE_SIZE;

				if (io_size < 0) {
				        io_size = PAGE_SIZE - pg_offset;
					pg_count = 1;
				} else
					pg_count = max_vectors;
			}
		        /* 
			 * we need to allocate space for the vector list
			 */
			if (pg_count > 1) {
			        iovp = (struct iovec *)_MALLOC(sizeof(struct iovec) * pg_count,
							       M_SEGMENT, M_NOWAIT);
			
				if (iovp == (struct iovec *) 0) {
				        /*
					 * if the allocation fails, then throttle down to a single page
					 */
				        io_size = PAGE_SIZE - pg_offset;
					pg_count = 1;
				}
			}
		}

		/* Throttle the speculative IO */
		if ((flags & CL_ASYNC) && !(flags & CL_PAGEOUT))
			priv = 0;
		else
			priv = 1;

		cbp = alloc_io_buf(vp, priv);

		if (pg_count == 1)
		        /*
			 * we use the io vector that's reserved in the buffer header
			 * this insures we can always issue an I/O even in a low memory
			 * condition that prevents the _MALLOC from succeeding... this
			 * is necessary to prevent deadlocks with the pager
			 */
			iovp = (struct iovec *)(&cbp->b_vects[0]);

		cbp->b_vectorlist  = (void *)iovp;
		cbp->b_vectorcount = pg_count;

		if (flags & CL_DEV_MEMORY) {

			iovp->iov_len  = io_size;
		        iovp->iov_base = (caddr_t)upl_phys_page(pl, 0);

			if (iovp->iov_base == (caddr_t) 0) {
			        free_io_buf(cbp);
				error = EINVAL;
			} else
			        iovp->iov_base += upl_offset;
		} else {

		  for (i = 0, vsize = io_size; i < pg_count; i++, iovp++) {
		        int     psize;

			psize = PAGE_SIZE - pg_offset;

			if (psize > vsize)
			        psize = vsize;

			iovp->iov_len  = psize;
		        iovp->iov_base = (caddr_t)upl_phys_page(pl, pl_index + i);

			if (iovp->iov_base == (caddr_t) 0) {
				if (pg_count > 1)
				        _FREE(cbp->b_vectorlist, M_SEGMENT);
			        free_io_buf(cbp);

				error = EINVAL;
				break;
			}
			iovp->iov_base += pg_offset;
			pg_offset = 0;

			if (flags & CL_PAGEOUT) {
			        int         s;
				struct buf *bp;

			        s = splbio();
				if (bp = incore(vp, lblkno + i)) {
				        if (!ISSET(bp->b_flags, B_BUSY)) {
					        bremfree(bp);
						SET(bp->b_flags, (B_BUSY | B_INVAL));
						splx(s);
						brelse(bp);
					} else
					        panic("BUSY bp found in cluster_io");
				}
				splx(s);
			}
			vsize -= psize;
		    }
		}
		if (error)
		        break;

		if (flags & CL_ASYNC) {
			cbp->b_flags |= (B_CALL | B_ASYNC);
		        cbp->b_iodone = (void *)cluster_iodone;
		}
		cbp->b_flags |= io_flags;

		cbp->b_lblkno = lblkno;
		cbp->b_blkno  = blkno;
		cbp->b_bcount = io_size;
		cbp->b_pagelist  = upl;
		cbp->b_uploffset = upl_offset;
		cbp->b_trans_next = (struct buf *)0;

		if (cbp->b_iostate = (void *)iostate)
		        /*
			 * caller wants to track the state of this
			 * io... bump the amount issued against this stream
			 */
		        iostate->io_issued += io_size;

		if (flags & CL_READ)
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 26)) | DBG_FUNC_NONE,
				     cbp->b_lblkno, cbp->b_blkno, upl_offset, io_size, 0);
		else
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 27)) | DBG_FUNC_NONE,
				     cbp->b_lblkno, cbp->b_blkno, upl_offset, io_size, 0);

		if (cbp_head) {
		        cbp_tail->b_trans_next = cbp;
			cbp_tail = cbp;
		} else {
		        cbp_head = cbp;
			cbp_tail = cbp;
		}
		(struct buf *)(cbp->b_trans_head) = cbp_head;
		buf_count++;

		upl_offset += io_size;
		f_offset   += io_size;
		size       -= io_size;

		if ( (!(upl_offset & PAGE_MASK) && !(flags & CL_DEV_MEMORY) && ((flags & CL_ASYNC) || buf_count > 8)) || size == 0) {
		        /*
			 * if we have no more I/O to issue or
			 * the current I/O we've prepared fully
			 * completes the last page in this request
			 * and it's either an ASYNC request or 
			 * we've already accumulated more than 8 I/O's into
			 * this transaction and it's not an I/O directed to 
			 * special DEVICE memory
			 * then go ahead and issue the I/O
			 */
start_io:		
			if (real_bp) {
			        cbp_head->b_flags |= B_NEED_IODONE;
				cbp_head->b_real_bp = real_bp;
			} else
			        cbp_head->b_real_bp = (struct buf *)NULL;

			if (size == 0) {
			        /*
				 * we're about to issue the last I/O for this upl
				 * if this was a read to the eof and the eof doesn't
				 * finish on a page boundary, than we need to zero-fill
				 * the rest of the page....
				 */
			        cbp_head->b_validend = zero_offset;
			} else
			        cbp_head->b_validend = 0;
			  
		        for (cbp = cbp_head; cbp;) {
				struct buf * cbp_next;

			        if (io_flags & B_WRITEINPROG)
				        cbp->b_vp->v_numoutput++;

				cbp_next = cbp->b_trans_next;
				
				(void) VOP_STRATEGY(cbp);
				cbp = cbp_next;
			}
			if ( !(flags & CL_ASYNC)) {
			        for (cbp = cbp_head; cbp; cbp = cbp->b_trans_next)
				        biowait(cbp);

				if (error = cluster_iodone(cbp_head)) {
					if ((flags & CL_PAGEOUT) && (error == ENXIO))
						retval = 0;	/* drop the error */
					else
						retval = error;
					error  = 0;
				}
			}
			cbp_head = (struct buf *)0;
			cbp_tail = (struct buf *)0;

			buf_count = 0;
		}
	}
	if (error) {
	        int abort_size;

		io_size = 0;
		
	        for (cbp = cbp_head; cbp;) {
			struct buf * cbp_next;
 
		        if (cbp->b_vectorcount > 1)
			        _FREE(cbp->b_vectorlist, M_SEGMENT);
			upl_offset -= cbp->b_bcount;
			size       += cbp->b_bcount;
			io_size    += cbp->b_bcount;

			cbp_next = cbp->b_trans_next;
			free_io_buf(cbp);
			cbp = cbp_next;
		}
		if (iostate) {
		        /*
			 * update the error condition for this stream
			 * since we never really issued the io
			 * just go ahead and adjust it back
			 */
		        if (iostate->io_error == 0)
			        iostate->io_error = error;
			iostate->io_issued -= io_size;

			if (iostate->io_wanted) {
			        /*
				 * someone is waiting for the state of
				 * this io stream to change
				 */
			        iostate->io_wanted = 0;
				wakeup((caddr_t)&iostate->io_wanted);
			}
		}
		pg_offset  = upl_offset & PAGE_MASK;
		abort_size = ((size + pg_offset + (PAGE_SIZE - 1)) / PAGE_SIZE) * PAGE_SIZE;

		if (flags & CL_COMMIT) {
		        int upl_abort_code;

			if (flags & CL_PRESERVE)
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if ((flags & CL_PAGEOUT) && (error != ENXIO)) /* transient error */
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if (flags & CL_PAGEIN)
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR;
			else
				upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_DUMP_PAGES;

		        ubc_upl_abort_range(upl, upl_offset - pg_offset, abort_size,
						upl_abort_code);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 28)) | DBG_FUNC_NONE,
				     (int)upl, upl_offset - pg_offset, abort_size, error, 0);
		}
		if (real_bp) {
		        real_bp->b_flags |= B_ERROR;
			real_bp->b_error  = error;

			biodone(real_bp);
		}
		if (retval == 0)
		        retval = error;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 22)) | DBG_FUNC_END,
		     (int)f_offset, size, upl_offset, retval, 0);

	return (retval);
}


static int
cluster_rd_prefetch(vp, f_offset, size, filesize, devblocksize)
	struct vnode *vp;
	off_t         f_offset;
	u_int         size;
	off_t         filesize;
	int           devblocksize;
{
	int           pages_to_fetch;
	int           skipped_pages;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_START,
		     (int)f_offset, size, (int)filesize, 0, 0);

	if (f_offset >= filesize) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_END,
			     (int)f_offset, 0, 0, 0, 0);
	        return(0);
	}
	if (size > (MAX_UPL_TRANSFER * PAGE_SIZE))
	        size = MAX_UPL_TRANSFER * PAGE_SIZE;
	else
	        size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

        if ((off_t)size > (filesize - f_offset))
                size = filesize - f_offset;
	
	pages_to_fetch = (size + (PAGE_SIZE - 1)) / PAGE_SIZE;

	for (skipped_pages = 0; skipped_pages < pages_to_fetch; skipped_pages++) {
	        if (ubc_page_op(vp, f_offset, 0, 0, 0) != KERN_SUCCESS)
		        break;
		f_offset += PAGE_SIZE;
		size     -= PAGE_SIZE;
	}
	if (skipped_pages < pages_to_fetch)
	        advisory_read(vp, filesize, f_offset, size, devblocksize);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_END,
		     (int)f_offset + (pages_to_fetch * PAGE_SIZE), skipped_pages, 0, 1, 0);

	return (pages_to_fetch);
}



static void
cluster_rd_ahead(vp, b_lblkno, e_lblkno, filesize, devblocksize)
	struct vnode *vp;
	daddr_t       b_lblkno;
	daddr_t       e_lblkno;
	off_t         filesize;
	int           devblocksize;
{
	daddr_t       r_lblkno;
	off_t         f_offset;
	int           size_of_prefetch;
	int           max_pages;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_START,
		     b_lblkno, e_lblkno, vp->v_lastr, 0, 0);

	if (b_lblkno == vp->v_lastr && b_lblkno == e_lblkno) {
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
			     vp->v_ralen, vp->v_maxra, vp->v_lastr, 0, 0);
		return;
	}

	if (vp->v_lastr == -1 || (b_lblkno != vp->v_lastr && b_lblkno != (vp->v_lastr + 1) &&
		                 (b_lblkno != (vp->v_maxra + 1) || vp->v_ralen == 0))) {
	        vp->v_ralen = 0;
		vp->v_maxra = 0;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
			     vp->v_ralen, vp->v_maxra, vp->v_lastr, 1, 0);

		return;
	}
	max_pages = MAX_UPL_TRANSFER;

	vp->v_ralen = vp->v_ralen ? min(max_pages, vp->v_ralen << 1) : 1;

	if (((e_lblkno + 1) - b_lblkno) > vp->v_ralen)
	        vp->v_ralen = min(max_pages, (e_lblkno + 1) - b_lblkno);

	if (e_lblkno < vp->v_maxra) {
	        if ((vp->v_maxra - e_lblkno) > max(max_pages / 16, 4)) {

		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
				     vp->v_ralen, vp->v_maxra, vp->v_lastr, 2, 0);
			return;
		}
	}
	r_lblkno = max(e_lblkno, vp->v_maxra) + 1;
	f_offset = (off_t)r_lblkno * PAGE_SIZE_64;

	if (f_offset < filesize) {
	        size_of_prefetch = cluster_rd_prefetch(vp, f_offset, vp->v_ralen * PAGE_SIZE, filesize, devblocksize);

		if (size_of_prefetch)
		        vp->v_maxra = (r_lblkno + size_of_prefetch) - 1;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
		     vp->v_ralen, vp->v_maxra, vp->v_lastr, 3, 0);
}

int
cluster_pageout(vp, upl, upl_offset, f_offset, size, filesize, devblocksize, flags)
	struct vnode *vp;
	upl_t         upl;
	vm_offset_t   upl_offset;
	off_t         f_offset;
	int           size;
	off_t         filesize;
	int           devblocksize;
	int           flags;
{
	int           io_size;
	int           pg_size;
        off_t         max_size;
	int local_flags = CL_PAGEOUT;

	if ((flags & UPL_IOSYNC) == 0) 
		local_flags |= CL_ASYNC;
	if ((flags & UPL_NOCOMMIT) == 0) 
		local_flags |= CL_COMMIT;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 52)) | DBG_FUNC_NONE,
		     (int)f_offset, size, (int)filesize, local_flags, 0);

	/*
	 * If they didn't specify any I/O, then we are done...
	 * we can't issue an abort because we don't know how
	 * big the upl really is
	 */
	if (size <= 0)
		return (EINVAL);

        if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		if (local_flags & CL_COMMIT)
		        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (EROFS);
	}
	/*
	 * can't page-in from a negative offset
	 * or if we're starting beyond the EOF
	 * or if the file offset isn't page aligned
	 * or the size requested isn't a multiple of PAGE_SIZE
	 */
	if (f_offset < 0 || f_offset >= filesize ||
	   (f_offset & PAGE_MASK_64) || (size & PAGE_MASK)) {
		if (local_flags & CL_COMMIT)
			ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}
	max_size = filesize - f_offset;

	if (size < max_size)
	        io_size = size;
	else
	        io_size = max_size;

	pg_size = (io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	if (size > pg_size) {
		if (local_flags & CL_COMMIT)
			ubc_upl_abort_range(upl, upl_offset + pg_size, size - pg_size,
					UPL_ABORT_FREE_ON_EMPTY);
	}
	while (vp->v_numoutput >= ASYNC_THROTTLE) {
		vp->v_flag |= VTHROTTLED;
		tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "cluster_pageout", 0);
	}

	return (cluster_io(vp, upl, upl_offset, f_offset, io_size, devblocksize,
			   local_flags, (struct buf *)0, (struct clios *)0));
}

int
cluster_pagein(vp, upl, upl_offset, f_offset, size, filesize, devblocksize, flags)
	struct vnode *vp;
	upl_t         upl;
	vm_offset_t   upl_offset;
	off_t         f_offset;
	int           size;
	off_t         filesize;
	int           devblocksize;
	int           flags;
{
	u_int         io_size;
	int           rounded_size;
        off_t         max_size;
	int           retval;
	int           local_flags = 0;

	if (upl == NULL || size < 0)
	        panic("cluster_pagein: NULL upl passed in");

	if ((flags & UPL_IOSYNC) == 0)
	        local_flags |= CL_ASYNC;
	if ((flags & UPL_NOCOMMIT) == 0) 
		local_flags |= CL_COMMIT;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 56)) | DBG_FUNC_NONE,
		     (int)f_offset, size, (int)filesize, local_flags, 0);

	/*
	 * can't page-in from a negative offset
	 * or if we're starting beyond the EOF
	 * or if the file offset isn't page aligned
	 * or the size requested isn't a multiple of PAGE_SIZE
	 */
	if (f_offset < 0 || f_offset >= filesize ||
	   (f_offset & PAGE_MASK_64) || (size & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
	        if (local_flags & CL_COMMIT)
		        ubc_upl_abort_range(upl, upl_offset, size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
		return (EINVAL);
	}
	max_size = filesize - f_offset;

	if (size < max_size)
	        io_size = size;
	else
	        io_size = max_size;

	rounded_size = (io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	if (size > rounded_size && (local_flags & CL_COMMIT))
		ubc_upl_abort_range(upl, upl_offset + rounded_size,
				    size - (upl_offset + rounded_size), UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
	
	retval = cluster_io(vp, upl, upl_offset, f_offset, io_size, devblocksize,
			   local_flags | CL_READ | CL_PAGEIN, (struct buf *)0, (struct clios *)0);

	if (retval == 0) {
	        int b_lblkno;
		int e_lblkno;

		b_lblkno = (int)(f_offset / PAGE_SIZE_64);
		e_lblkno = (int)
			((f_offset + ((off_t)io_size - 1)) / PAGE_SIZE_64);

		if (!(flags & UPL_NORDAHEAD) && !(vp->v_flag & VRAOFF) && rounded_size == PAGE_SIZE) {
		        /*
			 * we haven't read the last page in of the file yet
			 * so let's try to read ahead if we're in 
			 * a sequential access pattern
			 */
		        cluster_rd_ahead(vp, b_lblkno, e_lblkno, filesize, devblocksize);
		}
	        vp->v_lastr = e_lblkno;
	}
	return (retval);
}

int
cluster_bp(bp)
	struct buf *bp;
{
        off_t  f_offset;
	int    flags;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 19)) | DBG_FUNC_START,
		     (int)bp, bp->b_lblkno, bp->b_bcount, bp->b_flags, 0);

	if (bp->b_pagelist == (upl_t) 0)
	        panic("cluster_bp: can't handle NULL upl yet\n");
	if (bp->b_flags & B_READ)
	        flags = CL_ASYNC | CL_READ;
	else
	        flags = CL_ASYNC;

	f_offset = ubc_blktooff(bp->b_vp, bp->b_lblkno);

        return (cluster_io(bp->b_vp, bp->b_pagelist, 0, f_offset, bp->b_bcount, 0, flags, bp, (struct clios *)0));
}

int
cluster_write(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         oldEOF;
	off_t         newEOF;
	off_t         headOff;
	off_t         tailOff;
	int           devblocksize;
	int           flags;
{
	int           prev_resid;
	int           clip_size;
	off_t         max_io_size;
	struct iovec  *iov;
	vm_offset_t   upl_offset;
	int           upl_size;
	int           pages_in_pl;
	upl_page_info_t *pl;
	int           upl_flags;
	upl_t         upl;
	int           retval = 0;


	if ( (!(vp->v_flag & VNOCACHE_DATA)) || (!uio) || (uio->uio_segflg != UIO_USERSPACE))
	  {
	    retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
	    return(retval);
	  }
	
	while (uio->uio_resid && uio->uio_offset < newEOF && retval == 0)
	  {
	    /* we know we have a resid, so this is safe */
	    iov = uio->uio_iov;
	    while (iov->iov_len == 0) {
	      uio->uio_iov++;
	      uio->uio_iovcnt--;
	      iov = uio->uio_iov;
	    }

            /*
             * We check every vector target and if it is physically
             * contiguous space, we skip the sanity checks.
             */

            upl_offset = (vm_offset_t)iov->iov_base & ~PAGE_MASK;
            upl_size = (upl_offset + PAGE_SIZE +(PAGE_SIZE -1)) & ~PAGE_MASK;
	    pages_in_pl = 0;
            upl_flags = UPL_QUERY_OBJECT_TYPE;
            if ((vm_map_get_upl(current_map(),
                               (vm_offset_t)iov->iov_base & ~PAGE_MASK,
                               &upl_size, &upl, NULL, &pages_in_pl, &upl_flags, 0)) != KERN_SUCCESS)
              {
		/*
		 * the user app must have passed in an invalid address
		 */
		return (EFAULT);
              }	      

            if (upl_flags & UPL_PHYS_CONTIG)
	      {
		if (flags & IO_HEADZEROFILL)
		  {
		    flags &= ~IO_HEADZEROFILL;

		    if (retval = cluster_write_x(vp, (struct uio *)0, 0, uio->uio_offset, headOff, 0, devblocksize, IO_HEADZEROFILL))
		        return(retval);
		  }

		retval = cluster_phys_write(vp, uio, newEOF, devblocksize, flags);

		if (uio->uio_resid == 0 && (flags & IO_TAILZEROFILL))
		  {
		    retval = cluster_write_x(vp, (struct uio *)0, 0, tailOff, uio->uio_offset, 0, devblocksize, IO_HEADZEROFILL);
		    return(retval);
		  }
	      }
	    else if ((uio->uio_resid < 4 * PAGE_SIZE) || (flags & (IO_TAILZEROFILL | IO_HEADZEROFILL))) 
	      {
		/*
		 * We set a threshhold of 4 pages to decide if the nocopy
		 * write loop is worth the trouble...
		 * we also come here if we're trying to zero the head and/or tail
		 * of a partially written page, and the user source is not a physically contiguous region
		 */
		retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
		return(retval);
	      }
	    else if (uio->uio_offset & PAGE_MASK_64)
	      {
		/* Bring the file offset write up to a pagesize boundary */
		clip_size = (PAGE_SIZE - (uio->uio_offset & PAGE_MASK_64));
		if (uio->uio_resid < clip_size)
		  clip_size = uio->uio_resid;
		/* 
		 * Fake the resid going into the cluster_write_x call
		 * and restore it on the way out.
		 */
		prev_resid = uio->uio_resid;
		uio->uio_resid = clip_size;
		retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
		uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
	      }
	    else if ((int)iov->iov_base & PAGE_MASK_64)
	      {
		clip_size = iov->iov_len;
		prev_resid = uio->uio_resid;
		uio->uio_resid = clip_size;
		retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
		uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
	      }
	    else
	      {
		/* 
		 * If we come in here, we know the offset into
		 * the file is on a pagesize boundary
		 */

		max_io_size = newEOF - uio->uio_offset;
		clip_size = uio->uio_resid;
		if (iov->iov_len < clip_size)
		  clip_size = iov->iov_len;
		if (max_io_size < clip_size)
		  clip_size = max_io_size;

		if (clip_size < PAGE_SIZE)
		  {
		    /*
		     * Take care of tail end of write in this vector
		     */
		    prev_resid = uio->uio_resid;
		    uio->uio_resid = clip_size;
		    retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
		    uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
		  }
		else
		  {
		    /* round clip_size down to a multiple of pagesize */
		    clip_size = clip_size & ~(PAGE_MASK);
		    prev_resid = uio->uio_resid;
		    uio->uio_resid = clip_size;
		    retval = cluster_nocopy_write(vp, uio, newEOF, devblocksize, flags);
		    if ((retval == 0) && uio->uio_resid)
		      retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags);
		    uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
		  }
	      } /* end else */
	  } /* end while */
	return(retval);
}


static int
cluster_nocopy_write(vp, uio, newEOF, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         newEOF;
	int           devblocksize;
	int           flags;
{
	upl_t            upl;
	upl_page_info_t  *pl;
	off_t 	         upl_f_offset;
	vm_offset_t      upl_offset;
	off_t            max_io_size;
	int              io_size;
	int              io_flag;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	struct iovec     *iov;
	int              i;
	int              first = 1;
	int              force_data_sync;
	int              error  = 0;
	struct clios     iostate;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 75)) | DBG_FUNC_START,
		     (int)uio->uio_offset, (int)uio->uio_resid, 
		     (int)newEOF, devblocksize, 0);

	/*
	 * When we enter this routine, we know
	 *  -- the offset into the file is on a pagesize boundary
	 *  -- the resid is a page multiple
	 *  -- the resid will not exceed iov_len
	 */
	cluster_try_push(vp, newEOF, 0, 1);

	iostate.io_completed = 0;
	iostate.io_issued = 0;
	iostate.io_error = 0;
	iostate.io_wanted = 0;

	iov = uio->uio_iov;

	while (uio->uio_resid && uio->uio_offset < newEOF && error == 0) {
	        io_size = uio->uio_resid;

		if (io_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        io_size = MAX_UPL_TRANSFER * PAGE_SIZE;

		if (first) {
	                if (io_size > (MAX_UPL_TRANSFER * PAGE_SIZE) / 4)
		                io_size = (MAX_UPL_TRANSFER * PAGE_SIZE) / 8;
			first = 0;
		}
		upl_offset = (vm_offset_t)iov->iov_base & PAGE_MASK_64;
		upl_needed_size = (upl_offset + io_size + (PAGE_SIZE -1)) & ~PAGE_MASK;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 76)) | DBG_FUNC_START,
			     (int)upl_offset, upl_needed_size, (int)iov->iov_base, io_size, 0);

		for (force_data_sync = 0; force_data_sync < 3; force_data_sync++) {
		        pages_in_pl = 0;
			upl_size = upl_needed_size;
			upl_flags = UPL_FILE_IO | UPL_COPYOUT_FROM | UPL_NO_SYNC |
		                    UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL;

			kret = vm_map_get_upl(current_map(),
					      (vm_offset_t)iov->iov_base & ~PAGE_MASK,
					      &upl_size,
					      &upl, 
					      NULL, 
					      &pages_in_pl,
					      &upl_flags,
					      force_data_sync);

			if (kret != KERN_SUCCESS) {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 76)) | DBG_FUNC_END,
					     0, 0, 0, kret, 0);

				/*
				 * cluster_nocopy_write: failed to get pagelist
				 *
				 * we may have already spun some portion of this request
				 * off as async requests... we need to wait for the I/O
				 * to complete before returning
				 */
				goto wait_for_writes;
			}
			pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
			pages_in_pl = upl_size / PAGE_SIZE;

			for (i = 0; i < pages_in_pl; i++) {
			        if (!upl_valid_page(pl, i))
				        break;		  
			}
			if (i == pages_in_pl)
			        break;

			/*
			 * didn't get all the pages back that we
			 * needed... release this upl and try again
			 */
			ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);
		}
		if (force_data_sync >= 3) {
		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 76)) | DBG_FUNC_END,
				     i, pages_in_pl, upl_size, kret, 0);

			/*
			 * for some reason, we couldn't acquire a hold on all
			 * the pages needed in the user's address space
			 *
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_writes;
		}

		/*
		 * Consider the possibility that upl_size wasn't satisfied.
		 */
		if (upl_size != upl_needed_size)
		        io_size = (upl_size - (int)upl_offset) & ~PAGE_MASK;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 76)) | DBG_FUNC_END,
			     (int)upl_offset, upl_size, (int)iov->iov_base, io_size, 0);		       

		if (io_size == 0) {
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);

			/*
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_writes;
		}
		/*
		 * Now look for pages already in the cache
		 * and throw them away.
		 */

		upl_f_offset = uio->uio_offset;   /* this is page aligned in the file */
		max_io_size = io_size;

		while (max_io_size) {
		        /*
			 * Flag UPL_POP_DUMP says if the page is found
			 * in the page cache it must be thrown away.
			 */
		        ubc_page_op(vp, 
				    upl_f_offset,
				    UPL_POP_SET | UPL_POP_BUSY | UPL_POP_DUMP,
				    0, 0);
			max_io_size  -= PAGE_SIZE_64;
			upl_f_offset += PAGE_SIZE_64;
		}
		/*
		 * we want push out these writes asynchronously so that we can overlap
		 * the preparation of the next I/O
		 * if there are already too many outstanding writes
		 * wait until some complete before issuing the next
		 */
		while ((iostate.io_issued - iostate.io_completed) > (2 * MAX_UPL_TRANSFER * PAGE_SIZE)) {
	                iostate.io_wanted = 1;
			tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_nocopy_write", 0);
		}	
		if (iostate.io_error) {
		        /*
			 * one of the earlier writes we issued ran into a hard error
			 * don't issue any more writes, cleanup the UPL
			 * that was just created but not used, then
			 * go wait for all writes that are part of this stream
			 * to complete before returning the error to the caller
			 */
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);

		        goto wait_for_writes;
	        }
		io_flag = CL_ASYNC | CL_PRESERVE | CL_COMMIT;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 77)) | DBG_FUNC_START,
			     (int)upl_offset, (int)uio->uio_offset, io_size, io_flag, 0);

		error = cluster_io(vp, upl, upl_offset, uio->uio_offset,
				   io_size, devblocksize, io_flag, (struct buf *)0, &iostate);

		iov->iov_len    -= io_size;
		iov->iov_base   += io_size;
		uio->uio_resid  -= io_size;
		uio->uio_offset += io_size;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 77)) | DBG_FUNC_END,
			     (int)upl_offset, (int)uio->uio_offset, (int)uio->uio_resid, error, 0);

	} /* end while */

wait_for_writes:
	/*
	 * make sure all async writes issued as part of this stream
	 * have completed before we return
	 */
	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_nocopy_write", 0);
	}	
	if (iostate.io_error)
		error = iostate.io_error;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 75)) | DBG_FUNC_END,
		     (int)uio->uio_offset, (int)uio->uio_resid, error, 4, 0);

	return (error);
}


static int
cluster_phys_write(vp, uio, newEOF, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t        newEOF;
	int          devblocksize;
	int          flags;
{
	upl_page_info_t *pl;
	vm_offset_t      src_paddr;
 	upl_t            upl;
	vm_offset_t      upl_offset;
	int              tail_size;
	int              io_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	struct iovec     *iov;
	int              error  = 0;

	/*
	 * When we enter this routine, we know
	 *  -- the resid will not exceed iov_len
	 *  -- the vector target address is physcially contiguous
	 */
	cluster_try_push(vp, newEOF, 0, 1);

	iov = uio->uio_iov;
	io_size = iov->iov_len;
	upl_offset = (vm_offset_t)iov->iov_base & PAGE_MASK_64;
	upl_needed_size = upl_offset + io_size;

	pages_in_pl = 0;
	upl_size = upl_needed_size;
	upl_flags = UPL_FILE_IO | UPL_COPYOUT_FROM | UPL_NO_SYNC | 
	            UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL;

	kret = vm_map_get_upl(current_map(),
			      (vm_offset_t)iov->iov_base & ~PAGE_MASK,
			      &upl_size, &upl, NULL, &pages_in_pl, &upl_flags, 0);

	if (kret != KERN_SUCCESS) {
	        /*
		 * cluster_phys_write: failed to get pagelist
		 * note: return kret here
		 */
	      return(EINVAL);
	}
	/*
	 * Consider the possibility that upl_size wasn't satisfied.
	 * This is a failure in the physical memory case.
	 */
	if (upl_size < upl_needed_size) {
	        kernel_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);
		return(EINVAL);
	}
	pl = ubc_upl_pageinfo(upl);

	src_paddr = (vm_offset_t)upl_phys_page(pl, 0) + ((vm_offset_t)iov->iov_base & PAGE_MASK);

	while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
	        int   head_size;

		head_size = devblocksize - (int)(uio->uio_offset & (devblocksize - 1));

		if (head_size > io_size)
		        head_size = io_size;

		error = cluster_align_phys_io(vp, uio, src_paddr, head_size, devblocksize, 0);

		if (error) {
		        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

			return(EINVAL);
		}
		upl_offset += head_size;
		src_paddr  += head_size;
		io_size    -= head_size;
	}
	tail_size = io_size & (devblocksize - 1);
	io_size  -= tail_size;

	if (io_size) {
	        /*
		 * issue a synchronous write to cluster_io
		 */
	        error = cluster_io(vp, upl, upl_offset, uio->uio_offset,
				   io_size, 0, CL_DEV_MEMORY, (struct buf *)0, (struct clios *)0);
	}
	if (error == 0) {
	        /*
		 * The cluster_io write completed successfully,
		 * update the uio structure
		 */
		uio->uio_resid  -= io_size;
		iov->iov_len    -= io_size;
	        iov->iov_base   += io_size;
		uio->uio_offset += io_size;
		src_paddr       += io_size;

		if (tail_size)
		        error = cluster_align_phys_io(vp, uio, src_paddr, tail_size, devblocksize, 0);
	}
	/*
	 * just release our hold on the physically contiguous
	 * region without changing any state
	 */
	ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

	return (error);
}


static int
cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         oldEOF;
	off_t         newEOF;
	off_t         headOff;
	off_t         tailOff;
	int           devblocksize;
	int           flags;
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	int              upl_size;
	off_t 	         upl_f_offset;
	int              pages_in_upl;
	int		 start_offset;
	int              xfer_resid;
	int              io_size;
	int              io_flags;
	vm_offset_t      io_address;
	int              io_offset;
	int              bytes_to_zero;
	int              bytes_to_move;
	kern_return_t    kret;
	int              retval = 0;
	int              uio_resid;
	long long        total_size;
	long long        zero_cnt;
	off_t            zero_off;
	long long        zero_cnt1;
	off_t            zero_off1;
	daddr_t          start_blkno;
	daddr_t          last_blkno;

	if (uio) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_START,
			     (int)uio->uio_offset, uio->uio_resid, (int)oldEOF, (int)newEOF, 0);

	        uio_resid = uio->uio_resid;
	} else {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_START,
			     0, 0, (int)oldEOF, (int)newEOF, 0);

	        uio_resid = 0;
	}
	zero_cnt  = 0;
	zero_cnt1 = 0;

	if (flags & IO_HEADZEROFILL) {
	        /*
		 * some filesystems (HFS is one) don't support unallocated holes within a file...
		 * so we zero fill the intervening space between the old EOF and the offset
		 * where the next chunk of real data begins.... ftruncate will also use this
		 * routine to zero fill to the new EOF when growing a file... in this case, the
		 * uio structure will not be provided
		 */
	        if (uio) {
		        if (headOff < uio->uio_offset) {
			        zero_cnt = uio->uio_offset - headOff;
				zero_off = headOff;
			}
		} else if (headOff < newEOF) {	
		        zero_cnt = newEOF - headOff;
			zero_off = headOff;
		}
	}
	if (flags & IO_TAILZEROFILL) {
	        if (uio) {
		        zero_off1 = uio->uio_offset + uio->uio_resid;

			if (zero_off1 < tailOff)
			        zero_cnt1 = tailOff - zero_off1;
		}	
	}
	if (zero_cnt == 0 && uio == (struct uio *) 0)
	  {
	    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_END,
			 retval, 0, 0, 0, 0);
	    return (0);
	  }

	while ((total_size = (uio_resid + zero_cnt + zero_cnt1)) && retval == 0) {
	        /*
		 * for this iteration of the loop, figure out where our starting point is
		 */
	        if (zero_cnt) {
		        start_offset = (int)(zero_off & PAGE_MASK_64);
			upl_f_offset = zero_off - start_offset;
		} else if (uio_resid) {
		        start_offset = (int)(uio->uio_offset & PAGE_MASK_64);
			upl_f_offset = uio->uio_offset - start_offset;
		} else {
		        start_offset = (int)(zero_off1 & PAGE_MASK_64);
			upl_f_offset = zero_off1 - start_offset;
		}
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 46)) | DBG_FUNC_NONE,
			     (int)zero_off, (int)zero_cnt, (int)zero_off1, (int)zero_cnt1, 0);

	        if (total_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        total_size = MAX_UPL_TRANSFER * PAGE_SIZE;

		/*
		 * compute the size of the upl needed to encompass
		 * the requested write... limit each call to cluster_io
		 * to the maximum UPL size... cluster_io will clip if
		 * this exceeds the maximum io_size for the device,
		 * make sure to account for 
		 * a starting offset that's not page aligned
		 */
		upl_size = (start_offset + total_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	        if (upl_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        upl_size = MAX_UPL_TRANSFER * PAGE_SIZE;

		pages_in_upl = upl_size / PAGE_SIZE;
		io_size      = upl_size - start_offset;
		
		if ((long long)io_size > total_size)
		        io_size = total_size;

		start_blkno = (daddr_t)(upl_f_offset / PAGE_SIZE_64);
		last_blkno  = start_blkno + pages_in_upl;

		kret = ubc_create_upl(vp, 
							upl_f_offset,
							upl_size,
							&upl,
							&pl,
							UPL_FLAGS_NONE);
		if (kret != KERN_SUCCESS)
			panic("cluster_write: failed to get pagelist");

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 41)) | DBG_FUNC_NONE,
			(int)upl, (int)upl_f_offset, upl_size, start_offset, 0);

		if (start_offset && !upl_valid_page(pl, 0)) {
			int   read_size;

			/*
			 * we're starting in the middle of the first page of the upl
			 * and the page isn't currently valid, so we're going to have
			 * to read it in first... this is a synchronous operation
			 */
			read_size = PAGE_SIZE;

			if ((upl_f_offset + read_size) > newEOF)
			        read_size = newEOF - upl_f_offset;

		        retval = cluster_io(vp, upl, 0, upl_f_offset, read_size, devblocksize,
					    CL_READ, (struct buf *)0, (struct clios *)0);
			if (retval) {
				/*
				 * we had an error during the read which causes us to abort
				 * the current cluster_write request... before we do, we need
				 * to release the rest of the pages in the upl without modifying
				 * there state and mark the failed page in error
				 */
				ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_DUMP_PAGES);
				ubc_upl_abort_range(upl, 0, upl_size,  UPL_ABORT_FREE_ON_EMPTY);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 45)) | DBG_FUNC_NONE,
					     (int)upl, 0, 0, retval, 0);
				break;
			}
		}
		if ((start_offset == 0 || upl_size > PAGE_SIZE) && ((start_offset + io_size) & PAGE_MASK)) {
		        /* 
			 * the last offset we're writing to in this upl does not end on a page
			 * boundary... if it's not beyond the old EOF, then we'll also need to
			 * pre-read this page in if it isn't already valid
			 */
		        upl_offset = upl_size - PAGE_SIZE;

		        if ((upl_f_offset + start_offset + io_size) < oldEOF &&
			    !upl_valid_page(pl, upl_offset / PAGE_SIZE)) {
			        int   read_size;

				read_size = PAGE_SIZE;

				if ((upl_f_offset + upl_offset + read_size) > newEOF)
				        read_size = newEOF - (upl_f_offset + upl_offset);

			        retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, read_size, devblocksize,
						    CL_READ, (struct buf *)0, (struct clios *)0);
				if (retval) {
					/*
					 * we had an error during the read which causes us to abort
					 * the current cluster_write request... before we do, we
					 * need to release the rest of the pages in the upl without
					 * modifying there state and mark the failed page in error
					 */
					ubc_upl_abort_range(upl, upl_offset, PAGE_SIZE, UPL_ABORT_DUMP_PAGES);
					ubc_upl_abort_range(upl, 0,          upl_size,  UPL_ABORT_FREE_ON_EMPTY);

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 45)) | DBG_FUNC_NONE,
						     (int)upl, 0, 0, retval, 0);
					break;
				}
			}
		}
		if ((kret = ubc_upl_map(upl, &io_address)) != KERN_SUCCESS)
		        panic("cluster_write: ubc_upl_map failed\n");
		xfer_resid = io_size;
		io_offset = start_offset;

		while (zero_cnt && xfer_resid) {

		        if (zero_cnt < (long long)xfer_resid)
			        bytes_to_zero = zero_cnt;
			else
			        bytes_to_zero = xfer_resid;

		        if ( !(flags & (IO_NOZEROVALID | IO_NOZERODIRTY))) {
				bzero((caddr_t)(io_address + io_offset), bytes_to_zero);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
					     (int)upl_f_offset + io_offset, bytes_to_zero,
					     (int)io_offset, xfer_resid, 0);
			} else {
			        int zero_pg_index;

			        bytes_to_zero = min(bytes_to_zero, PAGE_SIZE - (int)(zero_off & PAGE_MASK_64));
				zero_pg_index = (int)((zero_off - upl_f_offset) / PAGE_SIZE_64);

				if ( !upl_valid_page(pl, zero_pg_index)) {
				        bzero((caddr_t)(io_address + io_offset), bytes_to_zero); 

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
						     (int)upl_f_offset + io_offset, bytes_to_zero,
						     (int)io_offset, xfer_resid, 0);

				} else if ((flags & (IO_NOZERODIRTY | IO_NOZEROVALID)) == IO_NOZERODIRTY &&
					   !upl_dirty_page(pl, zero_pg_index)) {
				        bzero((caddr_t)(io_address + io_offset), bytes_to_zero); 

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
						     (int)upl_f_offset + io_offset, bytes_to_zero,
						     (int)io_offset, xfer_resid, 0);
				}
			}
			xfer_resid -= bytes_to_zero;
			zero_cnt   -= bytes_to_zero;
			zero_off   += bytes_to_zero;
			io_offset  += bytes_to_zero;
		}
		if (xfer_resid && uio_resid) {
			bytes_to_move = min(uio_resid, xfer_resid);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 42)) | DBG_FUNC_NONE,
				     (int)uio->uio_offset, bytes_to_move, uio_resid, xfer_resid, 0);

			retval = uiomove((caddr_t)(io_address + io_offset), bytes_to_move, uio);


			if (retval) {
			        if ((kret = ubc_upl_unmap(upl)) != KERN_SUCCESS)
				        panic("cluster_write: kernel_upl_unmap failed\n");

				ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 45)) | DBG_FUNC_NONE,
					     (int)upl, 0, 0, retval, 0);
			} else {
			        uio_resid  -= bytes_to_move;
				xfer_resid -= bytes_to_move;
				io_offset  += bytes_to_move;
			}
		}
		while (xfer_resid && zero_cnt1 && retval == 0) {

		        if (zero_cnt1 < (long long)xfer_resid)
			        bytes_to_zero = zero_cnt1;
			else
			        bytes_to_zero = xfer_resid;

		        if ( !(flags & (IO_NOZEROVALID | IO_NOZERODIRTY))) {
			        bzero((caddr_t)(io_address + io_offset), bytes_to_zero);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
					     (int)upl_f_offset + io_offset,
					     bytes_to_zero, (int)io_offset, xfer_resid, 0);
			} else {
			        int zero_pg_index;
			
			        bytes_to_zero = min(bytes_to_zero, PAGE_SIZE - (int)(zero_off1 & PAGE_MASK_64));
				zero_pg_index = (int)((zero_off1 - upl_f_offset) / PAGE_SIZE_64);

				if ( !upl_valid_page(pl, zero_pg_index)) {
				        bzero((caddr_t)(io_address + io_offset), bytes_to_zero);

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
						     (int)upl_f_offset + io_offset,
						     bytes_to_zero, (int)io_offset, xfer_resid, 0);

				} else if ((flags & (IO_NOZERODIRTY | IO_NOZEROVALID)) == IO_NOZERODIRTY &&
					   !upl_dirty_page(pl, zero_pg_index)) {
				        bzero((caddr_t)(io_address + io_offset), bytes_to_zero);

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
						     (int)upl_f_offset + io_offset,
						     bytes_to_zero, (int)io_offset, xfer_resid, 0);
				}
			}
			xfer_resid -= bytes_to_zero;
			zero_cnt1  -= bytes_to_zero;
			zero_off1  += bytes_to_zero;
			io_offset  += bytes_to_zero;
		}

		if (retval == 0) {
			int cl_index;
			int can_delay;

		        io_size += start_offset;

			if ((upl_f_offset + io_size) >= newEOF && io_size < upl_size) {
			        /*
				 * if we're extending the file with this write
				 * we'll zero fill the rest of the page so that
				 * if the file gets extended again in such a way as to leave a
				 * hole starting at this EOF, we'll have zero's in the correct spot
				 */
			        bzero((caddr_t)(io_address + io_size), upl_size - io_size);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 43)) | DBG_FUNC_NONE,
					     (int)upl_f_offset + io_size,
					     upl_size - io_size, 0, 0, 0);
			}
		        if ((kret = ubc_upl_unmap(upl)) != KERN_SUCCESS)
			        panic("cluster_write: kernel_upl_unmap failed\n");

			if (flags & IO_SYNC)
			        /*
				 * if the IO_SYNC flag is set than we need to 
				 * bypass any clusters and immediately issue
				 * the I/O
				 */
			        goto issue_io;

			if (vp->v_clen == 0)
			        /*
				 * no clusters currently present
				 */
			        goto start_new_cluster;

			/*
			 * keep track of the overall dirty page
			 * range we've developed
			 * in case we have to fall back to the
			 * VHASDIRTY method of flushing
			 */
			if (vp->v_flag & VHASDIRTY)
				goto delay_io;

			for (cl_index = 0; cl_index < vp->v_clen; cl_index++) {
			        /*
				 * we have an existing cluster... see if this write will extend it nicely
				 */
			        if (start_blkno >= vp->v_clusters[cl_index].start_pg) {
				        /*
					 * the current write starts at or after the current cluster
					 */
				        if (last_blkno <= (vp->v_clusters[cl_index].start_pg + MAX_UPL_TRANSFER)) {
					        /*
						 * we have a write that fits entirely
						 * within the existing cluster limits
						 */
					        if (last_blkno > vp->v_clusters[cl_index].last_pg)
						        /*
							 * update our idea of where the cluster ends
							 */
						        vp->v_clusters[cl_index].last_pg = last_blkno;
						break;
					}
					if (start_blkno < (vp->v_clusters[cl_index].start_pg + MAX_UPL_TRANSFER)) {
					        /*
						 * we have a write that starts in the middle of the current cluster
						 * but extends beyond the cluster's limit
						 * we'll clip the current cluster if we actually
						 * overlap with the new write
						 * and start a new cluster with the current write
						 */
						 if (vp->v_clusters[cl_index].last_pg > start_blkno)
						        vp->v_clusters[cl_index].last_pg = start_blkno;
					}
					/*
					 * we also get here for the case where the current write starts
					 * beyond the limit of the existing cluster
					 *
					 * in either case, we'll check the remaining clusters before 
					 * starting a new one
					 */
				} else {
				        /*
					 * the current write starts in front of the current cluster
					 */
				        if ((vp->v_clusters[cl_index].last_pg - start_blkno) <=  MAX_UPL_TRANSFER) {
					        /*
						 * we can just merge the old cluster
						 * with the new request and leave it
						 * in the cache
						 */
					        vp->v_clusters[cl_index].start_pg = start_blkno;

						if (last_blkno > vp->v_clusters[cl_index].last_pg) {
						        /*
							 * the current write completely
							 * envelops the existing cluster
							 */
						        vp->v_clusters[cl_index].last_pg = last_blkno;
						}
						break;
					}

					/*
					 * if we were to combine this write with the current cluster
					 * we would exceed the cluster size limit.... so,
					 * let's see if there's any overlap of the new I/O with
					 * the existing cluster...
					 * 
					 */
					if (last_blkno > vp->v_clusters[cl_index].start_pg)
					        /*
						 * the current write extends into the existing cluster
						 * clip the current cluster by moving the start position
						 * to where the current write ends
						 */
					        vp->v_clusters[cl_index].start_pg = last_blkno;
					/*
					 * if we get here, there was no way to merge
					 * the new I/O with this cluster and
					 * keep it under our maximum cluster length
					 * we'll check the remaining clusters before starting a new one
					 */
				}
			}
			if (cl_index < vp->v_clen)
			        /*
				 * we found an existing cluster that we
				 * could merger this I/O into
				 */
			        goto delay_io;

			if (vp->v_clen < MAX_CLUSTERS && !(vp->v_flag & VNOCACHE_DATA))
			        /*
				 * we didn't find an existing cluster to
				 * merge into, but there's room to start
				 * a new one
				 */
			        goto start_new_cluster;

			/*
			 * no exisitng cluster to merge with and no
			 * room to start a new one... we'll try 
			 * pushing the existing ones... if none of
			 * them are able to be pushed, we'll have
			 * to fall back on the VHASDIRTY mechanism
			 * cluster_try_push will set v_clen to the
			 * number of remaining clusters if it is
			 * unable to push all of them
			 */
			if (vp->v_flag & VNOCACHE_DATA)
			        can_delay = 0;
			else
			        can_delay = 1;

			if (cluster_try_push(vp, newEOF, 0, 0) == 0) {
			        vp->v_flag |= VHASDIRTY;
				goto delay_io;
			}
start_new_cluster:
			if (vp->v_clen == 0) {
			        vp->v_ciosiz = devblocksize;
				vp->v_cstart = start_blkno;
				vp->v_lastw  = last_blkno;
			}
			vp->v_clusters[vp->v_clen].start_pg = start_blkno;
			vp->v_clusters[vp->v_clen].last_pg  = last_blkno;
			vp->v_clen++;
delay_io:
			/*
			 * make sure we keep v_cstart and v_lastw up to 
			 * date in case we have to fall back on the
			 * V_HASDIRTY mechanism (or we've already entered it)
			 */
			if (start_blkno < vp->v_cstart)
			        vp->v_cstart = start_blkno;
			if (last_blkno > vp->v_lastw)
			        vp->v_lastw = last_blkno;

		        ubc_upl_commit_range(upl, 0, upl_size, UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
			continue;
issue_io:
			/*
			 * in order to maintain some semblance of coherency with mapped writes
			 * we need to write the cluster back out as a multiple of the PAGESIZE
			 * unless the cluster encompasses the last page of the file... in this
			 * case we'll round out to the nearest device block boundary
			 */
			io_size = upl_size;

			if ((upl_f_offset + io_size) > newEOF) {
			        io_size = newEOF - upl_f_offset;
				io_size = (io_size + (devblocksize - 1)) & ~(devblocksize - 1);
			}

			if (flags & IO_SYNC)
			        io_flags = CL_COMMIT | CL_AGE;
			else
			        io_flags = CL_COMMIT | CL_AGE | CL_ASYNC;

			if (vp->v_flag & VNOCACHE_DATA)
			        io_flags |= CL_DUMP;

			while (vp->v_numoutput >= ASYNC_THROTTLE) {
			        vp->v_flag |= VTHROTTLED;
				tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "cluster_write", 0);
			}	
			retval = cluster_io(vp, upl, 0, upl_f_offset, io_size, devblocksize,
					    io_flags, (struct buf *)0, (struct clios *)0);
		}
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_END,
		     retval, 0, 0, 0, 0);

	return (retval);
}

int
cluster_read(vp, uio, filesize, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         filesize;
	int           devblocksize;
	int           flags;
{
	int           prev_resid;
	int           clip_size;
	off_t         max_io_size;
	struct iovec  *iov;
	vm_offset_t   upl_offset;
	int           upl_size;
	int           pages_in_pl;
	upl_page_info_t *pl;
	int           upl_flags;
	upl_t         upl;
	int           retval = 0;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio->uio_resid, (int)filesize, devblocksize, 0);

	/*
	 * We set a threshhold of 4 pages to decide if the nocopy
	 * read loop is worth the trouble...
	 */

	if (!((vp->v_flag & VNOCACHE_DATA) && (uio->uio_segflg == UIO_USERSPACE)))
	  {
	    retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
	    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_END,
			 (int)uio->uio_offset, uio->uio_resid, vp->v_lastr, retval, 0);
	    return(retval);
	  }

	while (uio->uio_resid && uio->uio_offset < filesize && retval == 0)
	  {
	    /* we know we have a resid, so this is safe */
	    iov = uio->uio_iov;
	    while (iov->iov_len == 0) {
	      uio->uio_iov++;
	      uio->uio_iovcnt--;
	      iov = uio->uio_iov;
	    }

	    /*
	     * We check every vector target and if it is physically 
	     * contiguous space, we skip the sanity checks.
	     */

            upl_offset = (vm_offset_t)iov->iov_base & ~PAGE_MASK;
            upl_size = (upl_offset + PAGE_SIZE +(PAGE_SIZE -1)) & ~PAGE_MASK;
            pages_in_pl = 0;
            upl_flags = UPL_QUERY_OBJECT_TYPE;
            if((vm_map_get_upl(current_map(),
			       (vm_offset_t)iov->iov_base & ~PAGE_MASK,
                               &upl_size, &upl, NULL, &pages_in_pl, &upl_flags, 0)) != KERN_SUCCESS)
              {
		/*
		 * the user app must have passed in an invalid address
		 */
		return (EFAULT);
              }

	    if (upl_flags & UPL_PHYS_CONTIG)
	      {
		retval = cluster_phys_read(vp, uio, filesize, devblocksize, flags);
	      }
	    else if (uio->uio_resid < 4 * PAGE_SIZE)
	      {
		/*
		 * We set a threshhold of 4 pages to decide if the nocopy
		 * read loop is worth the trouble...
		 */
		retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_END,
			     (int)uio->uio_offset, uio->uio_resid, vp->v_lastr, retval, 0);
		return(retval);
	      }
	    else if (uio->uio_offset & PAGE_MASK_64)
	      {
		/* Bring the file offset read up to a pagesize boundary */
		clip_size = (PAGE_SIZE - (int)(uio->uio_offset & PAGE_MASK_64));
		if (uio->uio_resid < clip_size)
		  clip_size = uio->uio_resid;
		/* 
		 * Fake the resid going into the cluster_read_x call
		 * and restore it on the way out.
		 */
		prev_resid = uio->uio_resid;
		uio->uio_resid = clip_size;
		retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
		uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
	      }
	    else if ((int)iov->iov_base & PAGE_MASK_64)
	      {
		clip_size = iov->iov_len;
		prev_resid = uio->uio_resid;
		uio->uio_resid = clip_size;
		retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
		uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
	      }
	    else
	      {
		/* 
		 * If we come in here, we know the offset into
		 * the file is on a pagesize boundary
		 */

		max_io_size = filesize - uio->uio_offset;
		clip_size = uio->uio_resid;
		if (iov->iov_len < clip_size)
		  clip_size = iov->iov_len;
		if (max_io_size < clip_size)
		  clip_size = (int)max_io_size;

		if (clip_size < PAGE_SIZE)
		  {
		    /*
		     * Take care of the tail end of the read in this vector.
		     */
		    prev_resid = uio->uio_resid;
		    uio->uio_resid = clip_size;
		    retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
		    uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
		  }
		else
		  {
		    /* round clip_size down to a multiple of pagesize */
		    clip_size = clip_size & ~(PAGE_MASK);
		    prev_resid = uio->uio_resid;
		    uio->uio_resid = clip_size;
		    retval = cluster_nocopy_read(vp, uio, filesize, devblocksize, flags);
		    if ((retval==0) && uio->uio_resid)
		      retval = cluster_read_x(vp, uio, filesize, devblocksize, flags);
		    uio->uio_resid = prev_resid - (clip_size - uio->uio_resid);
		  }
	      } /* end else */
	  } /* end while */

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_END,
		     (int)uio->uio_offset, uio->uio_resid, vp->v_lastr, retval, 0);

	return(retval);
}


static int
cluster_read_x(vp, uio, filesize, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         filesize;
	int           devblocksize;
	int           flags;
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	int              upl_size;
	off_t 	         upl_f_offset;
	int		 start_offset;
	int	         start_pg;
	int		 last_pg;
	int              uio_last;
	int              pages_in_upl;
	off_t            max_size;
	int              io_size;
	vm_offset_t      io_address;
	kern_return_t    kret;
	int              segflg;
	int              error  = 0;
	int              retval = 0;
	int              b_lblkno;
	int              e_lblkno;

	b_lblkno = (int)(uio->uio_offset / PAGE_SIZE_64);

	while (uio->uio_resid && uio->uio_offset < filesize && retval == 0) {
		/*
		 * compute the size of the upl needed to encompass
		 * the requested read... limit each call to cluster_io
		 * to the maximum UPL size... cluster_io will clip if
		 * this exceeds the maximum io_size for the device,
		 * make sure to account for 
		 * a starting offset that's not page aligned
		 */
		start_offset = (int)(uio->uio_offset & PAGE_MASK_64);
		upl_f_offset = uio->uio_offset - (off_t)start_offset;
		max_size     = filesize - uio->uio_offset;

		if ((off_t)((unsigned int)uio->uio_resid) < max_size)
		        io_size = uio->uio_resid;
		else
		        io_size = max_size;

		if (uio->uio_segflg == UIO_USERSPACE && !(vp->v_flag & VNOCACHE_DATA)) {
		        segflg = uio->uio_segflg;

			uio->uio_segflg = UIO_PHYS_USERSPACE;

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_START,
				     (int)uio->uio_offset, io_size, uio->uio_resid, 0, 0);

			while (io_size && retval == 0) {
			        int         xsize;
				vm_offset_t paddr;

				if (ubc_page_op(vp,
						upl_f_offset,
						UPL_POP_SET | UPL_POP_BUSY,
						&paddr, 0) != KERN_SUCCESS)
				        break;

				xsize = PAGE_SIZE - start_offset;
 			
				if (xsize > io_size)
				        xsize = io_size;

				retval = uiomove((caddr_t)(paddr + start_offset), xsize, uio);

				ubc_page_op(vp, upl_f_offset,
					    UPL_POP_CLR | UPL_POP_BUSY, 0, 0);

				io_size     -= xsize;
				start_offset = (int)
					(uio->uio_offset & PAGE_MASK_64);
				upl_f_offset = uio->uio_offset - start_offset;
			}
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_END,
				     (int)uio->uio_offset, io_size, uio->uio_resid, 0, 0);

			uio->uio_segflg = segflg;
			
			if (retval)
			        break;

			if (io_size == 0) {
			        /*
				 * we're already finished with this read request
				 * let's see if we should do a read-ahead
				 */
			        e_lblkno = (int)
					((uio->uio_offset - 1) / PAGE_SIZE_64);

			        if (!(vp->v_flag & VRAOFF))
				        /*
					 * let's try to read ahead if we're in 
					 * a sequential access pattern
					 */
				        cluster_rd_ahead(vp, b_lblkno, e_lblkno, filesize, devblocksize);
				vp->v_lastr = e_lblkno;

			        break;
			}
			max_size = filesize - uio->uio_offset;
		}
		upl_size = (start_offset + io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;
	        if (upl_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        upl_size = MAX_UPL_TRANSFER * PAGE_SIZE;
		pages_in_upl = upl_size / PAGE_SIZE;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 33)) | DBG_FUNC_START,
			     (int)upl, (int)upl_f_offset, upl_size, start_offset, 0);

		kret = ubc_create_upl(vp, 
						upl_f_offset,
						upl_size,
						&upl,
						&pl,
						UPL_FLAGS_NONE);
		if (kret != KERN_SUCCESS)
			panic("cluster_read: failed to get pagelist");

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 33)) | DBG_FUNC_END,
			     (int)upl, (int)upl_f_offset, upl_size, start_offset, 0);

		/*
		 * scan from the beginning of the upl looking for the first
		 * non-valid page.... this will become the first page in
		 * the request we're going to make to 'cluster_io'... if all
		 * of the pages are valid, we won't call through to 'cluster_io'
		 */
		for (start_pg = 0; start_pg < pages_in_upl; start_pg++) {
			if (!upl_valid_page(pl, start_pg))
				break;
		}

		/*
		 * scan from the starting invalid page looking for a valid
		 * page before the end of the upl is reached, if we 
		 * find one, then it will be the last page of the request to
		 * 'cluster_io'
		 */
		for (last_pg = start_pg; last_pg < pages_in_upl; last_pg++) {
			if (upl_valid_page(pl, last_pg))
				break;
		}

		if (start_pg < last_pg) {		
		        /*
			 * we found a range of 'invalid' pages that must be filled
			 * if the last page in this range is the last page of the file
			 * we may have to clip the size of it to keep from reading past
			 * the end of the last physical block associated with the file
			 */
			upl_offset = start_pg * PAGE_SIZE;
			io_size    = (last_pg - start_pg) * PAGE_SIZE;

			if ((upl_f_offset + upl_offset + io_size) > filesize)
			        io_size = filesize - (upl_f_offset + upl_offset);

			/*
			 * issue a synchronous read to cluster_io
			 */

			error = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset,
					   io_size, devblocksize, CL_READ, (struct buf *)0, (struct clios *)0);
		}
		if (error == 0) {
		        /*
			 * if the read completed successfully, or there was no I/O request
			 * issued, than map the upl into kernel address space and
			 * move the data into user land.... we'll first add on any 'valid'
			 * pages that were present in the upl when we acquired it.
			 */
			u_int  val_size;
			u_int  size_of_prefetch;

		        for (uio_last = last_pg; uio_last < pages_in_upl; uio_last++) {
			        if (!upl_valid_page(pl, uio_last))
				        break;
			}
			/*
			 * compute size to transfer this round,  if uio->uio_resid is
			 * still non-zero after this uiomove, we'll loop around and
			 * set up for another I/O.
			 */
			val_size = (uio_last * PAGE_SIZE) - start_offset;
		
			if (max_size < val_size)
			        val_size = max_size;

			if (uio->uio_resid < val_size)
			        val_size = uio->uio_resid;

			e_lblkno = (int)((uio->uio_offset + ((off_t)val_size - 1)) / PAGE_SIZE_64);

			if (size_of_prefetch = (uio->uio_resid - val_size)) {
			        /*
				 * if there's still I/O left to do for this request, then issue a
				 * pre-fetch I/O... the I/O wait time will overlap
				 * with the copying of the data
				 */
     				cluster_rd_prefetch(vp, uio->uio_offset + val_size, size_of_prefetch, filesize, devblocksize);
			} else {
			        if (!(vp->v_flag & VRAOFF) && !(vp->v_flag & VNOCACHE_DATA))
				        /*
					 * let's try to read ahead if we're in 
					 * a sequential access pattern
					 */
				        cluster_rd_ahead(vp, b_lblkno, e_lblkno, filesize, devblocksize);
				vp->v_lastr = e_lblkno;
			}
			if (uio->uio_segflg == UIO_USERSPACE) {
				int       offset;

			        segflg = uio->uio_segflg;

				uio->uio_segflg = UIO_PHYS_USERSPACE;


				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_START,
					     (int)uio->uio_offset, val_size, uio->uio_resid, 0, 0);

				offset = start_offset;

				while (val_size && retval == 0) {
	 				int   	  csize;
					int       i;
					caddr_t   paddr;

					i = offset / PAGE_SIZE;
					csize = min(PAGE_SIZE - start_offset, val_size);

				        paddr = (caddr_t)upl_phys_page(pl, i) + start_offset;

					retval = uiomove(paddr, csize, uio);

					val_size    -= csize;
					offset      += csize;
					start_offset = offset & PAGE_MASK;
				}
				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_END,
					     (int)uio->uio_offset, val_size, uio->uio_resid, 0, 0);

				uio->uio_segflg = segflg;
			}
			else
			{
			        if ((kret = ubc_upl_map(upl, &io_address)) != KERN_SUCCESS)
				        panic("cluster_read: ubc_upl_map() failed\n");

				retval = uiomove((caddr_t)(io_address + start_offset), val_size, uio);

			        if ((kret = ubc_upl_unmap(upl)) != KERN_SUCCESS)
				        panic("cluster_read: ubc_upl_unmap() failed\n");
			}
		}
		if (start_pg < last_pg) {
		        /*
			 * compute the range of pages that we actually issued an I/O for
			 * and either commit them as valid if the I/O succeeded
			 * or abort them if the I/O failed
			 */
		        io_size = (last_pg - start_pg) * PAGE_SIZE;

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 35)) | DBG_FUNC_START,
				     (int)upl, start_pg * PAGE_SIZE, io_size, error, 0);

			if (error || (vp->v_flag & VNOCACHE_DATA))
			        ubc_upl_abort_range(upl, start_pg * PAGE_SIZE, io_size,
						UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);
			else
			        ubc_upl_commit_range(upl, start_pg * PAGE_SIZE, io_size, 
						UPL_COMMIT_CLEAR_DIRTY
						| UPL_COMMIT_FREE_ON_EMPTY 
						| UPL_COMMIT_INACTIVATE);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 35)) | DBG_FUNC_END,
				     (int)upl, start_pg * PAGE_SIZE, io_size, error, 0);
		}
		if ((last_pg - start_pg) < pages_in_upl) {
		        int cur_pg;
			int commit_flags;

		        /*
			 * the set of pages that we issued an I/O for did not encompass
			 * the entire upl... so just release these without modifying
			 * there state
			 */
			if (error)
				ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);
			else {
				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 35)) | DBG_FUNC_START,
					     (int)upl, -1, pages_in_upl - (last_pg - start_pg), 0, 0);

				if (start_pg) {
					/*
					 * we found some already valid pages at the beginning of
					 * the upl commit these back to the inactive list with
					 * reference cleared
					 */
					for (cur_pg = 0; cur_pg < start_pg; cur_pg++) {
						commit_flags = UPL_COMMIT_FREE_ON_EMPTY 
							           | UPL_COMMIT_INACTIVATE;
						
						if (upl_dirty_page(pl, cur_pg))
							commit_flags |= UPL_COMMIT_SET_DIRTY;
						
						if ( !(commit_flags & UPL_COMMIT_SET_DIRTY) && (vp->v_flag & VNOCACHE_DATA))
							ubc_upl_abort_range(upl, cur_pg * PAGE_SIZE, PAGE_SIZE,
								UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);
						else
							ubc_upl_commit_range(upl, cur_pg * PAGE_SIZE, 
								PAGE_SIZE, commit_flags);
					}
				}
				if (last_pg < uio_last) {
					/*
					 * we found some already valid pages immediately after the
					 * pages we issued I/O for, commit these back to the
					 * inactive list with reference cleared
					 */
					for (cur_pg = last_pg; cur_pg < uio_last; cur_pg++) {
						commit_flags =  UPL_COMMIT_FREE_ON_EMPTY 
										| UPL_COMMIT_INACTIVATE;

						if (upl_dirty_page(pl, cur_pg))
							commit_flags |= UPL_COMMIT_SET_DIRTY;
						
						if ( !(commit_flags & UPL_COMMIT_SET_DIRTY) && (vp->v_flag & VNOCACHE_DATA))
							ubc_upl_abort_range(upl, cur_pg * PAGE_SIZE, PAGE_SIZE,
								UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);
						else
							ubc_upl_commit_range(upl, cur_pg * PAGE_SIZE, 
								PAGE_SIZE, commit_flags);
					}
				}
				if (uio_last < pages_in_upl) {
					/*
					 * there were some invalid pages beyond the valid pages
					 * that we didn't issue an I/O for, just release them
					 * unchanged
					 */
				        ubc_upl_abort_range(upl, uio_last * PAGE_SIZE,
							    (pages_in_upl - uio_last) * PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);
				}

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 35)) | DBG_FUNC_END,
					(int)upl, -1, -1, 0, 0);
			}
		}
		if (retval == 0)
		        retval = error;
	}

	return (retval);
}


static int
cluster_nocopy_read(vp, uio, filesize, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t         filesize;
	int           devblocksize;
	int           flags;
{
	upl_t            upl;
	upl_page_info_t  *pl;
	off_t 	         upl_f_offset;
	vm_offset_t      upl_offset;
	off_t            start_upl_f_offset;
	off_t            max_io_size;
	int              io_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	vm_offset_t      paddr;
	int              upl_flags;
	kern_return_t    kret;
	int              segflg;
	struct iovec     *iov;
	int              i;
	int              force_data_sync;
	int              retval = 0;
	int              first = 1;
	struct clios     iostate;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 70)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio->uio_resid, (int)filesize, devblocksize, 0);

	/*
	 * When we enter this routine, we know
	 *  -- the offset into the file is on a pagesize boundary
	 *  -- the resid is a page multiple
	 *  -- the resid will not exceed iov_len
	 */

	iostate.io_completed = 0;
	iostate.io_issued = 0;
	iostate.io_error = 0;
	iostate.io_wanted = 0;

	iov = uio->uio_iov;

	while (uio->uio_resid && uio->uio_offset < filesize && retval == 0) {

	        max_io_size = filesize - uio->uio_offset;

		if (max_io_size < (off_t)((unsigned int)uio->uio_resid))
		        io_size = max_io_size;
		else
		        io_size = uio->uio_resid;

		/*
		 * We don't come into this routine unless
		 * UIO_USERSPACE is set.
		 */
		segflg = uio->uio_segflg;

		uio->uio_segflg = UIO_PHYS_USERSPACE;

		/*
		 * First look for pages already in the cache
		 * and move them to user space.
		 */
		while (io_size && (retval == 0)) {
		        upl_f_offset = uio->uio_offset;

			/*
			 * If this call fails, it means the page is not
			 * in the page cache.
			 */
			if (ubc_page_op(vp, upl_f_offset,
					UPL_POP_SET | UPL_POP_BUSY, &paddr, 0) != KERN_SUCCESS)
			        break;

			retval = uiomove((caddr_t)(paddr), PAGE_SIZE, uio);
				
			ubc_page_op(vp, upl_f_offset, 
				    UPL_POP_CLR | UPL_POP_BUSY, 0, 0);
		  
			io_size -= PAGE_SIZE;
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 71)) | DBG_FUNC_NONE,
				     (int)uio->uio_offset, io_size, uio->uio_resid, 0, 0);
		}
		uio->uio_segflg = segflg;
			
		if (retval) {
			/*
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_reads;
		}
		/*
		 * If we are already finished with this read, then return
		 */
		if (io_size == 0) {
			/*
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_reads;
		}
		max_io_size = io_size;

		if (max_io_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        max_io_size = MAX_UPL_TRANSFER * PAGE_SIZE;
		if (first) {
	                if (max_io_size > (MAX_UPL_TRANSFER * PAGE_SIZE) / 4)
		                max_io_size = (MAX_UPL_TRANSFER * PAGE_SIZE) / 8;
			first = 0;
		}
		start_upl_f_offset = uio->uio_offset;   /* this is page aligned in the file */
		upl_f_offset = start_upl_f_offset;
		io_size = 0;

		while (io_size < max_io_size) {
		        if (ubc_page_op(vp, upl_f_offset,
					UPL_POP_SET | UPL_POP_BUSY, &paddr, 0) == KERN_SUCCESS) {
			        ubc_page_op(vp, upl_f_offset,
					    UPL_POP_CLR | UPL_POP_BUSY, 0, 0);
				break;
			}
			/*
			 * Build up the io request parameters.
			 */
			io_size += PAGE_SIZE_64;
			upl_f_offset += PAGE_SIZE_64;
		}
		if (io_size == 0)
			/*
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_reads;

		upl_offset = (vm_offset_t)iov->iov_base & PAGE_MASK_64;
		upl_needed_size = (upl_offset + io_size + (PAGE_SIZE -1)) & ~PAGE_MASK;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 72)) | DBG_FUNC_START,
			     (int)upl_offset, upl_needed_size, (int)iov->iov_base, io_size, 0);

		for (force_data_sync = 0; force_data_sync < 3; force_data_sync++) {
		        pages_in_pl = 0;
			upl_size = upl_needed_size;
			upl_flags = UPL_FILE_IO | UPL_NO_SYNC | UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL;

			kret = vm_map_get_upl(current_map(),
					      (vm_offset_t)iov->iov_base & ~PAGE_MASK,
					      &upl_size, &upl, NULL, &pages_in_pl, &upl_flags, force_data_sync);

			if (kret != KERN_SUCCESS) {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 72)) | DBG_FUNC_END,
					     (int)upl_offset, upl_size, io_size, kret, 0);
		  
				/*
				 * cluster_nocopy_read: failed to get pagelist
				 *
				 * we may have already spun some portion of this request
				 * off as async requests... we need to wait for the I/O
				 * to complete before returning
				 */
				goto wait_for_reads;
			}
			pages_in_pl = upl_size / PAGE_SIZE;
			pl = UPL_GET_INTERNAL_PAGE_LIST(upl);

			for (i = 0; i < pages_in_pl; i++) {
			        if (!upl_valid_page(pl, i))
				        break;		  
			}
			if (i == pages_in_pl)
			        break;

			ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);
		}
		if (force_data_sync >= 3) {
		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 72)) | DBG_FUNC_END,
				     (int)upl_offset, upl_size, io_size, kret, 0);
		  
			goto wait_for_reads;
		}
		/*
		 * Consider the possibility that upl_size wasn't satisfied.
		 */
		if (upl_size != upl_needed_size)
		        io_size = (upl_size - (int)upl_offset) & ~PAGE_MASK;

		if (io_size == 0) {
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);
			goto wait_for_reads;
		}
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 72)) | DBG_FUNC_END,
			     (int)upl_offset, upl_size, io_size, kret, 0);

		/*
		 * request asynchronously so that we can overlap
		 * the preparation of the next I/O
		 * if there are already too many outstanding reads
		 * wait until some have completed before issuing the next read
		 */
		while ((iostate.io_issued - iostate.io_completed) > (2 * MAX_UPL_TRANSFER * PAGE_SIZE)) {
	                iostate.io_wanted = 1;
			tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_nocopy_read", 0);
		}	
		if (iostate.io_error) {
		        /*
			 * one of the earlier reads we issued ran into a hard error
			 * don't issue any more reads, cleanup the UPL
			 * that was just created but not used, then
			 * go wait for any other reads to complete before
			 * returning the error to the caller
			 */
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, 
					    UPL_ABORT_FREE_ON_EMPTY);

		        goto wait_for_reads;
	        }
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 73)) | DBG_FUNC_START,
			     (int)upl, (int)upl_offset, (int)start_upl_f_offset, io_size, 0);

		retval = cluster_io(vp, upl, upl_offset, start_upl_f_offset,
				   io_size, devblocksize,
				   CL_PRESERVE | CL_COMMIT | CL_READ | CL_ASYNC | CL_NOZERO,
				   (struct buf *)0, &iostate);

		/*
		 * update the uio structure
		 */
		iov->iov_base   += io_size;
		iov->iov_len    -= io_size;
		uio->uio_resid  -= io_size;
		uio->uio_offset += io_size;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 73)) | DBG_FUNC_END,
			     (int)upl, (int)uio->uio_offset, (int)uio->uio_resid, retval, 0);

	} /* end while */

wait_for_reads:
	/*
	 * make sure all async reads that are part of this stream
	 * have completed before we return
	 */
	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_nocopy_read", 0);
	}	
	if (iostate.io_error)
		retval = iostate.io_error;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 70)) | DBG_FUNC_END,
		     (int)uio->uio_offset, (int)uio->uio_resid, 6, retval, 0);

	return (retval);
}


static int
cluster_phys_read(vp, uio, filesize, devblocksize, flags)
	struct vnode *vp;
	struct uio   *uio;
	off_t        filesize;
	int          devblocksize;
	int          flags;
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	vm_offset_t      dst_paddr;
	off_t            max_size;
	int              io_size;
	int              tail_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	struct iovec     *iov;
	struct clios     iostate;
	int              error;

	/*
	 * When we enter this routine, we know
	 *  -- the resid will not exceed iov_len
	 *  -- the target address is physically contiguous
	 */

	iov = uio->uio_iov;

	max_size = filesize - uio->uio_offset;

	if (max_size > (off_t)((unsigned int)iov->iov_len))
	        io_size = iov->iov_len;
	else
	        io_size = max_size;

	upl_offset = (vm_offset_t)iov->iov_base & PAGE_MASK_64;
	upl_needed_size = upl_offset + io_size;

	error       = 0;
	pages_in_pl = 0;
	upl_size = upl_needed_size;
	upl_flags = UPL_FILE_IO | UPL_NO_SYNC | UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL;

	kret = vm_map_get_upl(current_map(),
			      (vm_offset_t)iov->iov_base & ~PAGE_MASK,
			      &upl_size, &upl, NULL, &pages_in_pl, &upl_flags, 0);

	if (kret != KERN_SUCCESS) {
	        /*
		 * cluster_phys_read: failed to get pagelist
		 */
	        return(EINVAL);
	}
	if (upl_size < upl_needed_size) {
	        /*
		 * The upl_size wasn't satisfied.
		 */
	        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

		return(EINVAL);
	}
	pl = ubc_upl_pageinfo(upl);

	dst_paddr = (vm_offset_t)upl_phys_page(pl, 0) + ((vm_offset_t)iov->iov_base & PAGE_MASK);

	while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
	        int   head_size;

		head_size = devblocksize - (int)(uio->uio_offset & (devblocksize - 1));

		if (head_size > io_size)
		        head_size = io_size;

		error = cluster_align_phys_io(vp, uio, dst_paddr, head_size, devblocksize, CL_READ);

		if (error) {
		        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

			return(EINVAL);
		}
		upl_offset += head_size;
		dst_paddr  += head_size;
		io_size    -= head_size;
	}
	tail_size = io_size & (devblocksize - 1);
	io_size  -= tail_size;

	iostate.io_completed = 0;
	iostate.io_issued = 0;
	iostate.io_error = 0;
	iostate.io_wanted = 0;

	while (io_size && error == 0) {
	        int  xsize;

		if (io_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        xsize = MAX_UPL_TRANSFER * PAGE_SIZE;
		else
		        xsize = io_size;
		/*
		 * request asynchronously so that we can overlap
		 * the preparation of the next I/O... we'll do
		 * the commit after all the I/O has completed
		 * since its all issued against the same UPL
		 * if there are already too many outstanding reads
		 * wait until some have completed before issuing the next
		 */
		while ((iostate.io_issued - iostate.io_completed) > (2 * MAX_UPL_TRANSFER * PAGE_SIZE)) {
	                iostate.io_wanted = 1;
			tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_phys_read", 0);
		}	

	        error = cluster_io(vp, upl, upl_offset, uio->uio_offset, xsize, 0, 
				   CL_READ | CL_NOZERO | CL_DEV_MEMORY | CL_ASYNC,
				   (struct buf *)0, &iostate);
	        /*
		 * The cluster_io read was issued successfully,
		 * update the uio structure
		 */
		if (error == 0) {
		        uio->uio_resid  -= xsize;
			iov->iov_len    -= xsize;
			iov->iov_base   += xsize;
			uio->uio_offset += xsize;
			dst_paddr       += xsize;
			upl_offset      += xsize;
			io_size         -= xsize;
		}
	}
	/*
	 * make sure all async reads that are part of this stream
	 * have completed before we proceed
	 */
	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		tsleep((caddr_t)&iostate.io_wanted, PRIBIO + 1, "cluster_phys_read", 0);
	}	
	if (iostate.io_error) {
	        error = iostate.io_error;
	}
	if (error == 0 && tail_size)
	        error = cluster_align_phys_io(vp, uio, dst_paddr, tail_size, devblocksize, CL_READ);

	/*
	 * just release our hold on the physically contiguous
	 * region without changing any state
	 */
	ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);
	
	return (error);
}


/*
 * generate advisory I/O's in the largest chunks possible
 * the completed pages will be released into the VM cache
 */
int
advisory_read(vp, filesize, f_offset, resid, devblocksize)
	struct vnode *vp;
	off_t         filesize;
	off_t         f_offset;
	int           resid;
	int           devblocksize;
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	int              upl_size;
	off_t 	         upl_f_offset;
	int		 start_offset;
	int	         start_pg;
	int		 last_pg;
	int              pages_in_upl;
	off_t            max_size;
	int              io_size;
	kern_return_t    kret;
	int              retval = 0;
	int              issued_io;

	if (!UBCINFOEXISTS(vp))
		return(EINVAL);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 60)) | DBG_FUNC_START,
		     (int)f_offset, resid, (int)filesize, devblocksize, 0);

	while (resid && f_offset < filesize && retval == 0) {
		/*
		 * compute the size of the upl needed to encompass
		 * the requested read... limit each call to cluster_io
		 * to the maximum UPL size... cluster_io will clip if
		 * this exceeds the maximum io_size for the device,
		 * make sure to account for 
		 * a starting offset that's not page aligned
		 */
		start_offset = (int)(f_offset & PAGE_MASK_64);
		upl_f_offset = f_offset - (off_t)start_offset;
		max_size     = filesize - f_offset;

		if (resid < max_size)
		        io_size = resid;
		else
		        io_size = max_size;

		upl_size = (start_offset + io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;
	        if (upl_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        upl_size = MAX_UPL_TRANSFER * PAGE_SIZE;
		pages_in_upl = upl_size / PAGE_SIZE;

		kret = ubc_create_upl(vp, 
						upl_f_offset,
						upl_size,
						&upl,
						&pl,
						UPL_RET_ONLY_ABSENT);
		if (kret != KERN_SUCCESS)
		        return(retval);
		issued_io = 0;

		/*
		 * before we start marching forward, we must make sure we end on 
		 * a present page, otherwise we will be working with a freed
		 * upl
		 */
		for (last_pg = pages_in_upl - 1; last_pg >= 0; last_pg--) {
		        if (upl_page_present(pl, last_pg))
			        break;
		}
		pages_in_upl = last_pg + 1;


		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 61)) | DBG_FUNC_NONE,
			     (int)upl, (int)upl_f_offset, upl_size, start_offset, 0);


		for (last_pg = 0; last_pg < pages_in_upl; ) {
		        /*
			 * scan from the beginning of the upl looking for the first
			 * page that is present.... this will become the first page in
			 * the request we're going to make to 'cluster_io'... if all
			 * of the pages are absent, we won't call through to 'cluster_io'
			 */
		        for (start_pg = last_pg; start_pg < pages_in_upl; start_pg++) {
			        if (upl_page_present(pl, start_pg))
				        break;
			}

			/*
			 * scan from the starting present page looking for an absent
			 * page before the end of the upl is reached, if we 
			 * find one, then it will terminate the range of pages being
			 * presented to 'cluster_io'
			 */
			for (last_pg = start_pg; last_pg < pages_in_upl; last_pg++) {
			        if (!upl_page_present(pl, last_pg))
				        break;
			}

			if (last_pg > start_pg) {		
			        /*
				 * we found a range of pages that must be filled
				 * if the last page in this range is the last page of the file
				 * we may have to clip the size of it to keep from reading past
				 * the end of the last physical block associated with the file
				 */
			        upl_offset = start_pg * PAGE_SIZE;
				io_size    = (last_pg - start_pg) * PAGE_SIZE;

				if ((upl_f_offset + upl_offset + io_size) > filesize)
				        io_size = filesize - (upl_f_offset + upl_offset);

				/*
				 * issue an asynchronous read to cluster_io
				 */
				retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, io_size, devblocksize,
						    CL_ASYNC | CL_READ | CL_COMMIT | CL_AGE, (struct buf *)0, (struct clios *)0);

				issued_io = 1;
			}
		}
		if (issued_io == 0)
		        ubc_upl_abort(upl, 0);

		io_size = upl_size - start_offset;
		
		if (io_size > resid)
		        io_size = resid;
		f_offset += io_size;
		resid    -= io_size;
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 60)) | DBG_FUNC_END,
		     (int)f_offset, resid, retval, 0, 0);

	return(retval);
}


int
cluster_push(vp)
        struct vnode *vp;
{
        int  retval;

	if (!UBCINFOEXISTS(vp) || vp->v_clen == 0) {
		vp->v_flag &= ~VHASDIRTY;
		return(0);
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_START,
		     vp->v_flag & VHASDIRTY, vp->v_clen, 0, 0, 0);

	if (vp->v_flag & VHASDIRTY) {
	        daddr_t start_pg;
	        daddr_t last_pg;
		daddr_t end_pg;

		start_pg = vp->v_cstart;
		end_pg   = vp->v_lastw;

		vp->v_flag &= ~VHASDIRTY;
		vp->v_clen = 0;

		while (start_pg < end_pg) {
			last_pg = start_pg + MAX_UPL_TRANSFER;

			if (last_pg > end_pg)
			        last_pg = end_pg;

			cluster_push_x(vp, ubc_getsize(vp), start_pg, last_pg, 0);

			start_pg = last_pg;
		}
		return (1);
	}
	retval = cluster_try_push(vp, ubc_getsize(vp), 0, 1);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_END,
		     vp->v_flag & VHASDIRTY, vp->v_clen, retval, 0, 0);

	return (retval);
}


static int
cluster_try_push(vp, EOF, can_delay, push_all)
        struct vnode *vp;
	off_t  EOF;
	int    can_delay;
	int    push_all;
{
        int cl_index;
	int cl_index1;
	int min_index;
        int cl_len;
	int cl_total;
	int cl_pushed;
	struct v_cluster l_clusters[MAX_CLUSTERS];

	/*
	 * make a local 'sorted' copy of the clusters
	 * and clear vp->v_clen so that new clusters can
	 * be developed
	 */
	for (cl_index = 0; cl_index < vp->v_clen; cl_index++) {
	        for (min_index = -1, cl_index1 = 0; cl_index1 < vp->v_clen; cl_index1++) {
		        if (vp->v_clusters[cl_index1].start_pg == vp->v_clusters[cl_index1].last_pg)
			        continue;
			if (min_index == -1)
			        min_index = cl_index1;
			else if (vp->v_clusters[cl_index1].start_pg < vp->v_clusters[min_index].start_pg)
			        min_index = cl_index1;
		}
		if (min_index == -1)
		        break;
	        l_clusters[cl_index].start_pg = vp->v_clusters[min_index].start_pg;
		l_clusters[cl_index].last_pg  = vp->v_clusters[min_index].last_pg;

	        vp->v_clusters[min_index].start_pg = vp->v_clusters[min_index].last_pg;
	}
	cl_len     = cl_index;
	vp->v_clen = 0;

	for (cl_pushed = 0, cl_index = 0; cl_index < cl_len; cl_index++) {
	        /*
		 * try to push each cluster in turn...  cluster_push_x may not
		 * push the cluster if can_delay is TRUE and the cluster doesn't
		 * meet the critera for an immediate push
		 */
	        if (cluster_push_x(vp, EOF, l_clusters[cl_index].start_pg, l_clusters[cl_index].last_pg, can_delay)) {
		        l_clusters[cl_index].start_pg = 0;
			l_clusters[cl_index].last_pg  = 0;

		        cl_pushed++;

			if (push_all == 0)
			        break;
		}
	}
	if (cl_len > cl_pushed) {
	       /*
		* we didn't push all of the clusters, so
		* lets try to merge them back in to the vnode
		*/
	        if ((MAX_CLUSTERS - vp->v_clen) < (cl_len - cl_pushed)) {
		        /*
			 * we picked up some new clusters while we were trying to
			 * push the old ones (I don't think this can happen because
			 * I'm holding the lock, but just in case)... the sum of the
			 * leftovers plus the new cluster count exceeds our ability
			 * to represent them, so fall back to the VHASDIRTY mechanism
			 */
		        for (cl_index = 0; cl_index < cl_len; cl_index++) {
			        if (l_clusters[cl_index].start_pg == l_clusters[cl_index].last_pg)
				        continue;

				if (l_clusters[cl_index].start_pg < vp->v_cstart)
				        vp->v_cstart = l_clusters[cl_index].start_pg;
				if (l_clusters[cl_index].last_pg > vp->v_lastw)
				        vp->v_lastw = l_clusters[cl_index].last_pg;
			}
		        vp->v_flag |= VHASDIRTY;
		} else {
		        /*
			 * we've got room to merge the leftovers back in
			 * just append them starting at the next 'hole'
			 * represented by vp->v_clen
			 */
		        for (cl_index = 0, cl_index1 = vp->v_clen; cl_index < cl_len; cl_index++) {
			        if (l_clusters[cl_index].start_pg == l_clusters[cl_index].last_pg)
				        continue;

			        vp->v_clusters[cl_index1].start_pg = l_clusters[cl_index].start_pg;
				vp->v_clusters[cl_index1].last_pg  = l_clusters[cl_index].last_pg;

				if (cl_index1 == 0) {
				        vp->v_cstart = l_clusters[cl_index].start_pg;
					vp->v_lastw  = l_clusters[cl_index].last_pg;
				} else {
				        if (l_clusters[cl_index].start_pg < vp->v_cstart)
					        vp->v_cstart = l_clusters[cl_index].start_pg;
					if (l_clusters[cl_index].last_pg > vp->v_lastw)
					        vp->v_lastw = l_clusters[cl_index].last_pg;
				}
				cl_index1++;
			}
			/*
			 * update the cluster count
			 */
			vp->v_clen = cl_index1;
		}
	}
	return(MAX_CLUSTERS - vp->v_clen);
}



static int
cluster_push_x(vp, EOF, first, last, can_delay)
        struct vnode *vp;
	off_t  EOF;
	daddr_t first;
	daddr_t last;
	int    can_delay;
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	int              upl_size;
	off_t 	         upl_f_offset;
        int              pages_in_upl;
	int              start_pg;
	int              last_pg;
	int              io_size;
	int              io_flags;
	int              size;
	kern_return_t    kret;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_START,
		     vp->v_clen, first, last, EOF, 0);

	if ((pages_in_upl = last - first) == 0) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 0, 0, 0, 0);

	        return (1);
	}
	upl_size = pages_in_upl * PAGE_SIZE;
	upl_f_offset = ((off_t)first) * PAGE_SIZE_64;

	if (upl_f_offset + upl_size >= EOF) {

	        if (upl_f_offset >= EOF) {
		        /*
			 * must have truncated the file and missed 
			 * clearing a dangling cluster (i.e. it's completely
			 * beyond the new EOF
			 */
		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 1, 0, 0, 0);

		        return(1);
		}
		size = EOF - upl_f_offset;

		upl_size = (size + (PAGE_SIZE - 1) ) & ~(PAGE_SIZE - 1);
		pages_in_upl = upl_size / PAGE_SIZE;
	} else {
	        if (can_delay && (pages_in_upl < (MAX_UPL_TRANSFER - (MAX_UPL_TRANSFER / 2))))
		        return(0);
	        size = upl_size;
	}
	kret = ubc_create_upl(vp, 
			      	upl_f_offset,
			      	upl_size,
			      	&upl,
			        &pl,
			        UPL_RET_ONLY_DIRTY);
	if (kret != KERN_SUCCESS)
	        panic("cluster_push: failed to get pagelist");

	if (can_delay) {
	        int  num_of_dirty;
	
		for (num_of_dirty = 0, start_pg = 0; start_pg < pages_in_upl; start_pg++) {
		        if (upl_valid_page(pl, start_pg) && upl_dirty_page(pl, start_pg))
			        num_of_dirty++;
		}
		if (num_of_dirty < pages_in_upl / 2) {
		        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 0, 2, num_of_dirty, (pages_in_upl / 2), 0);

			return(0);
		}
	}
	last_pg = 0;

	while (size) {

		for (start_pg = last_pg; start_pg < pages_in_upl; start_pg++) {
			if (upl_valid_page(pl, start_pg) && upl_dirty_page(pl, start_pg))
				break;
		}
		if (start_pg > last_pg) {
			io_size = (start_pg - last_pg) * PAGE_SIZE;

			ubc_upl_abort_range(upl, last_pg * PAGE_SIZE, io_size,
					UPL_ABORT_FREE_ON_EMPTY);

			if (io_size < size)
			        size -= io_size;
			else
			        break;
		}
		for (last_pg = start_pg; last_pg < pages_in_upl; last_pg++) {
			if (!upl_valid_page(pl, last_pg) || !upl_dirty_page(pl, last_pg))
				break;
		}
		upl_offset = start_pg * PAGE_SIZE;

		io_size = min(size, (last_pg - start_pg) * PAGE_SIZE);

		if (vp->v_flag & VNOCACHE_DATA)
		        io_flags = CL_COMMIT | CL_AGE | CL_ASYNC | CL_DUMP;
		else
		        io_flags = CL_COMMIT | CL_AGE | CL_ASYNC;

		while (vp->v_numoutput >= ASYNC_THROTTLE) {
		        vp->v_flag |= VTHROTTLED;
			tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "cluster_push", 0);
		}
		cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, io_size, vp->v_ciosiz, io_flags, (struct buf *)0, (struct clios *)0);

		size -= io_size;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 3, 0, 0, 0);

	return(1);
}



static int
cluster_align_phys_io(struct vnode *vp, struct uio *uio, vm_offset_t usr_paddr, int xsize, int devblocksize, int flags)
{
        struct iovec     *iov;
        upl_page_info_t  *pl;
        upl_t            upl;
        vm_offset_t      ubc_paddr;
        kern_return_t    kret;
        int              error = 0;

        iov = uio->uio_iov;

        kret = ubc_create_upl(vp,
                              uio->uio_offset & ~PAGE_MASK_64,
                              PAGE_SIZE,
                              &upl,
                              &pl,
                              UPL_FLAGS_NONE);

        if (kret != KERN_SUCCESS)
                return(EINVAL);

        if (!upl_valid_page(pl, 0)) {
                /*
                 * issue a synchronous read to cluster_io
                 */
                error = cluster_io(vp, upl, 0, uio->uio_offset & ~PAGE_MASK_64, PAGE_SIZE, devblocksize,
				   CL_READ, (struct buf *)0, (struct clios *)0);
                if (error) {
                          ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);

                          return(error);
                }
        }
        ubc_paddr = (vm_offset_t)upl_phys_page(pl, 0) + (int)(uio->uio_offset & PAGE_MASK_64);

	if (flags & CL_READ)
	        copyp2p(ubc_paddr, usr_paddr, xsize, 2);
	else
	        copyp2p(usr_paddr, ubc_paddr, xsize, 1);

	if ( !(flags & CL_READ) || upl_dirty_page(pl, 0)) {
                /*
                 * issue a synchronous write to cluster_io
                 */
                error = cluster_io(vp, upl, 0, uio->uio_offset & ~PAGE_MASK_64, PAGE_SIZE, devblocksize,
				   0, (struct buf *)0, (struct clios *)0);
	}
	if (error == 0) {
	        uio->uio_offset += xsize;
		iov->iov_base   += xsize;
		iov->iov_len    -= xsize;
		uio->uio_resid  -= xsize;
	}
	ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);

        return (error);
}
