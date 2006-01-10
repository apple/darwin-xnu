/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#include <sys/proc_internal.h>
#include <sys/buf_internal.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/trace.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/resourcevar.h>
#include <sys/uio_internal.h>
#include <libkern/libkern.h>
#include <machine/machine_routines.h>

#include <sys/ubc_internal.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/vm_map.h>
#include <mach/upl.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
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
#define CL_THROTTLE   0x800
#define CL_KEEPCACHED 0x1000


struct clios {
        u_int  io_completed;       /* amount of io that has currently completed */
        u_int  io_issued;          /* amount of io that was successfully issued */
        int    io_error;           /* error code of first error encountered */
        int    io_wanted;          /* someone is sleeping waiting for a change in state */
};

static lck_grp_t	*cl_mtx_grp;
static lck_attr_t	*cl_mtx_attr;
static lck_grp_attr_t   *cl_mtx_grp_attr;
static lck_mtx_t	*cl_mtxp;


static int cluster_io(vnode_t vp, upl_t upl, vm_offset_t upl_offset, off_t f_offset, int non_rounded_size,
		      int flags, buf_t real_bp, struct clios *iostate);
static int cluster_iodone(buf_t bp, void *dummy);
static int cluster_rd_prefetch(vnode_t vp, off_t f_offset, u_int size, off_t filesize);
static int cluster_hard_throttle_on(vnode_t vp);

static int cluster_read_x(vnode_t vp, struct uio *uio, off_t filesize, int flags);
static int cluster_write_x(vnode_t vp, struct uio *uio, off_t oldEOF, off_t newEOF,
			   off_t headOff, off_t tailOff, int flags);
static int cluster_nocopy_read(vnode_t vp, struct uio *uio, off_t filesize);
static int cluster_nocopy_write(vnode_t vp, struct uio *uio, off_t newEOF);
static int cluster_phys_read(vnode_t vp, struct uio *uio, off_t filesize);
static int cluster_phys_write(vnode_t vp, struct uio *uio, off_t newEOF);
static int cluster_align_phys_io(vnode_t vp, struct uio *uio, addr64_t usr_paddr, int xsize, int flags);

static void	cluster_rd_ahead(vnode_t vp, struct cl_extent *extent, off_t filesize, struct cl_readahead *ra);

static int	cluster_push_x(vnode_t vp, struct cl_extent *, off_t EOF, int flags);
static void	cluster_push_EOF(vnode_t vp, off_t EOF);

static int	cluster_try_push(struct cl_writebehind *, vnode_t vp, off_t EOF, int can_delay, int push_all);

static void	sparse_cluster_switch(struct cl_writebehind *, vnode_t vp, off_t EOF);
static void	sparse_cluster_push(struct cl_writebehind *, vnode_t vp, off_t EOF, int push_all);
static void	sparse_cluster_add(struct cl_writebehind *, vnode_t vp, struct cl_extent *, off_t EOF);

static kern_return_t vfs_drt_mark_pages(void **cmapp, off_t offset, u_int length, int *setcountp);
static kern_return_t vfs_drt_get_cluster(void **cmapp, off_t *offsetp, u_int *lengthp);
static kern_return_t vfs_drt_control(void **cmapp, int op_type);

int	is_file_clean(vnode_t, off_t);

/*
 * throttle the number of async writes that
 * can be outstanding on a single vnode
 * before we issue a synchronous write 
 */
#define HARD_THROTTLE_MAXCNT	0
#define HARD_THROTTLE_MAXSIZE	(64 * 1024)

int hard_throttle_on_root = 0;
struct timeval priority_IO_timestamp_for_root;


void
cluster_init(void) {
        /*
	 * allocate lock group attribute and group
	 */
        cl_mtx_grp_attr = lck_grp_attr_alloc_init();
	//lck_grp_attr_setstat(cl_mtx_grp_attr);
	cl_mtx_grp = lck_grp_alloc_init("cluster I/O", cl_mtx_grp_attr);
		
	/*
	 * allocate the lock attribute
	 */
	cl_mtx_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(clf_mtx_attr);

	/*
	 * allocate and initialize mutex's used to protect updates and waits
	 * on the cluster_io context
	 */
	cl_mtxp	= lck_mtx_alloc_init(cl_mtx_grp, cl_mtx_attr);

	if (cl_mtxp == NULL)
	        panic("cluster_init: failed to allocate cl_mtxp");
}



#define CLW_ALLOCATE		0x01
#define CLW_RETURNLOCKED	0x02
/*
 * if the read ahead context doesn't yet exist,
 * allocate and initialize it...
 * the vnode lock serializes multiple callers
 * during the actual assignment... first one
 * to grab the lock wins... the other callers
 * will release the now unnecessary storage
 * 
 * once the context is present, try to grab (but don't block on)
 * the lock associated with it... if someone
 * else currently owns it, than the read
 * will run without read-ahead.  this allows
 * multiple readers to run in parallel and
 * since there's only 1 read ahead context,
 * there's no real loss in only allowing 1
 * reader to have read-ahead enabled.
 */
static struct cl_readahead *
cluster_get_rap(vnode_t vp)
{
        struct ubc_info		*ubc;
	struct cl_readahead	*rap;

	ubc = vp->v_ubcinfo;

        if ((rap = ubc->cl_rahead) == NULL) {
	        MALLOC_ZONE(rap, struct cl_readahead *, sizeof *rap, M_CLRDAHEAD, M_WAITOK);

		bzero(rap, sizeof *rap);
		rap->cl_lastr = -1;
		lck_mtx_init(&rap->cl_lockr, cl_mtx_grp, cl_mtx_attr);

		vnode_lock(vp);
		
		if (ubc->cl_rahead == NULL)
		        ubc->cl_rahead = rap;
		else {
		        lck_mtx_destroy(&rap->cl_lockr, cl_mtx_grp);
		        FREE_ZONE((void *)rap, sizeof *rap, M_CLRDAHEAD);
				rap = ubc->cl_rahead;
		}
		vnode_unlock(vp);
	}
	if (lck_mtx_try_lock(&rap->cl_lockr) == TRUE)
	        return(rap);
	
	return ((struct cl_readahead *)NULL);
}


/*
 * if the write behind context doesn't yet exist,
 * and CLW_ALLOCATE is specified, allocate and initialize it...
 * the vnode lock serializes multiple callers
 * during the actual assignment... first one
 * to grab the lock wins... the other callers
 * will release the now unnecessary storage
 * 
 * if CLW_RETURNLOCKED is set, grab (blocking if necessary)
 * the lock associated with the write behind context before
 * returning
 */

static struct cl_writebehind *
cluster_get_wbp(vnode_t vp, int flags)
{
        struct ubc_info *ubc;
	struct cl_writebehind *wbp;

	ubc = vp->v_ubcinfo;

        if ((wbp = ubc->cl_wbehind) == NULL) {

	        if ( !(flags & CLW_ALLOCATE))
		        return ((struct cl_writebehind *)NULL);
	  
	        MALLOC_ZONE(wbp, struct cl_writebehind *, sizeof *wbp, M_CLWRBEHIND, M_WAITOK);

		bzero(wbp, sizeof *wbp);
		lck_mtx_init(&wbp->cl_lockw, cl_mtx_grp, cl_mtx_attr);

		vnode_lock(vp);
		
		if (ubc->cl_wbehind == NULL)
		        ubc->cl_wbehind = wbp;
		else {
		        lck_mtx_destroy(&wbp->cl_lockw, cl_mtx_grp);
		        FREE_ZONE((void *)wbp, sizeof *wbp, M_CLWRBEHIND);
				wbp = ubc->cl_wbehind;
		}
		vnode_unlock(vp);
	}
	if (flags & CLW_RETURNLOCKED)
	        lck_mtx_lock(&wbp->cl_lockw);

	return (wbp);
}


static int 
cluster_hard_throttle_on(vnode_t vp)
{
        static struct timeval hard_throttle_maxelapsed = { 0, 200000 };

	if (vp->v_mount->mnt_kern_flag & MNTK_ROOTDEV) {
	        struct timeval elapsed;

		if (hard_throttle_on_root)
		        return(1);

		microuptime(&elapsed);
		timevalsub(&elapsed, &priority_IO_timestamp_for_root);

		if (timevalcmp(&elapsed, &hard_throttle_maxelapsed, <))
		        return(1);
	}
	return(0);
}


static int
cluster_iodone(buf_t bp, __unused void *dummy)
{
        int	b_flags;
        int	error;
	int	total_size;
	int	total_resid;
	int	upl_offset;
	int	zero_offset;
	upl_t	upl;
	buf_t	cbp;
	buf_t	cbp_head;
	buf_t	cbp_next;
	buf_t	real_bp;
	struct	clios *iostate;
	int	commit_size;
	int	pg_offset;

	cbp_head = (buf_t)(bp->b_trans_head);

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
	upl        = cbp->b_upl;
	b_flags    = cbp->b_flags;
	real_bp    = cbp->b_real_bp;
	zero_offset= cbp->b_validend;
	iostate    = (struct clios *)cbp->b_iostate;

	if (real_bp)
	        real_bp->b_dev = cbp->b_dev;

	while (cbp) {
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

	if (iostate) {
	        int need_wakeup = 0;

	        /*
		 * someone has issued multiple I/Os asynchrounsly
		 * and is waiting for them to complete (streaming)
		 */
		lck_mtx_lock(cl_mtxp);

	        if (error && iostate->io_error == 0)
		        iostate->io_error = error;

		iostate->io_completed += total_size;

		if (iostate->io_wanted) {
		        /*
		         * someone is waiting for the state of
			 * this io stream to change
			 */
		        iostate->io_wanted = 0;
			need_wakeup = 1;
		}
		lck_mtx_unlock(cl_mtxp);

		if (need_wakeup)
		        wakeup((caddr_t)&iostate->io_wanted);
	}
	if ((b_flags & B_NEED_IODONE) && real_bp) {
		if (error) {
		        real_bp->b_flags |= B_ERROR;
			real_bp->b_error = error;
		}
		real_bp->b_resid = total_resid;

		buf_biodone(real_bp);
	}
	if (error == 0 && total_resid)
	        error = EIO;

	if (b_flags & B_COMMIT_UPL) {
	        pg_offset   = upl_offset & PAGE_MASK;
		commit_size = (pg_offset + total_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

		if (error || (b_flags & B_NOCACHE)) {
		        int upl_abort_code;
			int page_in  = 0;
			int page_out = 0;

		        if (b_flags & B_PAGEIO) {
			        if (b_flags & B_READ)
				        page_in  = 1;
				else
				        page_out = 1;
			}
			if (b_flags & B_CACHE)		/* leave pages in the cache unchanged on error */
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if (page_out && (error != ENXIO)) /* transient error */
			        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
			else if (page_in)
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

			if ((b_flags & B_PHYS) && (b_flags & B_READ)) 
			        upl_commit_flags |= UPL_COMMIT_SET_DIRTY;

			if (b_flags & B_AGE)
			        upl_commit_flags |= UPL_COMMIT_INACTIVATE;

			ubc_upl_commit_range(upl, upl_offset - pg_offset, commit_size,
					upl_commit_flags);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
				     (int)upl, upl_offset - pg_offset, commit_size,
				     upl_commit_flags, 0);
		}
	} else {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 20)) | DBG_FUNC_END,
			     (int)upl, upl_offset, 0, error, 0);
	}

	return (error);
}


void
cluster_zero(upl_t upl, vm_offset_t upl_offset, int size, buf_t bp)
{
	upl_page_info_t *pl;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 23)) | DBG_FUNC_START,
		     upl_offset, size, (int)bp, 0, 0);

	if (bp == NULL || bp->b_datap == 0) {

	        pl = ubc_upl_pageinfo(upl);

	        while (size) {
		        int           page_offset;
			int           page_index;
			addr64_t      zero_addr;
			int           zero_cnt;

			page_index  = upl_offset / PAGE_SIZE;
			page_offset = upl_offset & PAGE_MASK;

			zero_addr = ((addr64_t)upl_phys_page(pl, page_index) << 12) + page_offset;
			zero_cnt  = min(PAGE_SIZE - page_offset, size);

			bzero_phys(zero_addr, zero_cnt);

			size       -= zero_cnt;
			upl_offset += zero_cnt;
		}
	} else
		bzero((caddr_t)((vm_offset_t)bp->b_datap + upl_offset), size);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 23)) | DBG_FUNC_END,
		     upl_offset, size, 0, 0, 0);
}


static int
cluster_io(vnode_t vp, upl_t upl, vm_offset_t upl_offset, off_t f_offset, int non_rounded_size,
	   int flags, buf_t real_bp, struct clios *iostate)
{
	buf_t	cbp;
	u_int	size;
	u_int	io_size;
	int	io_flags;
	int	bmap_flags;
	int	error = 0;
	int	retval = 0;
	buf_t	cbp_head = NULL;
	buf_t	cbp_tail = NULL;
	int	trans_count = 0;
	u_int	pg_count;
	int	pg_offset;
	u_int	max_iosize;
	u_int	max_vectors;
	int	priv;
	int	zero_offset = 0;
	int	async_throttle = 0;
	mount_t	mp;

	mp = vp->v_mount;

	if (mp->mnt_devblocksize > 1) {
	        /*
		 * round the requested size up so that this I/O ends on a
		 * page boundary in case this is a 'write'... if the filesystem
		 * has blocks allocated to back the page beyond the EOF, we want to
		 * make sure to write out the zero's that are sitting beyond the EOF
		 * so that in case the filesystem doesn't explicitly zero this area
		 * if a hole is created via a lseek/write beyond the current EOF,
		 * it will return zeros when it's read back from the disk.  If the
		 * physical allocation doesn't extend for the whole page, we'll
		 * only write/read from the disk up to the end of this allocation
		 * via the extent info returned from the VNOP_BLOCKMAP call.
		 */
	        pg_offset = upl_offset & PAGE_MASK;

		size = (((non_rounded_size + pg_offset) + (PAGE_SIZE - 1)) & ~PAGE_MASK) - pg_offset;
	} else {
	        /*
		 * anyone advertising a blocksize of 1 byte probably
		 * can't deal with us rounding up the request size
		 * AFP is one such filesystem/device
		 */
	        size = non_rounded_size;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 22)) | DBG_FUNC_START,
		     (int)f_offset, size, upl_offset, flags, 0);

	if (flags & CL_READ) {
	        io_flags = (B_READ);
		bmap_flags = VNODE_READ;

		max_iosize  = mp->mnt_maxreadcnt;
		max_vectors = mp->mnt_segreadcnt;
	} else {
	        io_flags = 0;
		bmap_flags = VNODE_WRITE;

		max_iosize  = mp->mnt_maxwritecnt;
		max_vectors = mp->mnt_segwritecnt;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 22)) | DBG_FUNC_NONE, max_iosize, max_vectors, mp->mnt_devblocksize, 0, 0);

	/*
	 * make sure the maximum iosize is a
	 * multiple of the page size
	 */
	max_iosize  &= ~PAGE_MASK;

	if (flags & CL_THROTTLE) {
	        if ( !(flags & CL_PAGEOUT) && cluster_hard_throttle_on(vp)) {
		        if (max_iosize > HARD_THROTTLE_MAXSIZE)
			        max_iosize = HARD_THROTTLE_MAXSIZE;
			async_throttle = HARD_THROTTLE_MAXCNT;
		} else
		        async_throttle = VNODE_ASYNC_THROTTLE;
	}
	if (flags & CL_AGE)
	        io_flags |= B_AGE;
	if (flags & CL_DUMP)
	        io_flags |= B_NOCACHE;
	if (flags & (CL_PAGEIN | CL_PAGEOUT))
		io_flags |= B_PAGEIO;
	if (flags & CL_COMMIT)
	        io_flags |= B_COMMIT_UPL;
	if (flags & CL_PRESERVE)
	        io_flags |= B_PHYS;
	if (flags & CL_KEEPCACHED)
	        io_flags |= B_CACHE;

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
		int	pg_resid;
		daddr64_t blkno;
		daddr64_t lblkno;

		if (size > max_iosize)
		        io_size = max_iosize;
		else
		        io_size = size;
		
		if ((error = VNOP_BLOCKMAP(vp, f_offset, io_size, &blkno, (size_t *)&io_size, NULL, bmap_flags, NULL))) {
			break;
		}
		if (real_bp && (real_bp->b_blkno == real_bp->b_lblkno))
		        real_bp->b_blkno = blkno;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 24)) | DBG_FUNC_NONE,
			     (int)f_offset, (int)blkno, io_size, zero_offset, 0);

		if (io_size == 0) {
		        /*
			 * vnop_blockmap didn't return an error... however, it did
			 * return an extent size of 0 which means we can't
			 * make forward progress on this I/O... a hole in the
			 * file would be returned as a blkno of -1 with a non-zero io_size
			 * a real extent is returned with a blkno != -1 and a non-zero io_size
			 */
	        	error = EINVAL;
			break;
		}
		if ( !(flags & CL_READ) && blkno == -1) {
		        off_t e_offset;

		        /*
			 * we're writing into a 'hole'
			 */
			if (flags & CL_PAGEOUT) {
			        /*
				 * if we got here via cluster_pageout 
				 * then just error the request and return
				 * the 'hole' should already have been covered
				 */
		        	error = EINVAL;
				break;
			}
			if ( !(flags & CL_COMMIT)) {
			        /*
				 * currently writes always request the commit to happen
				 * as part of the io completion... however, if the CL_COMMIT
				 * flag isn't specified, than we can't issue the abort_range
				 * since the call site is going to abort or commit the same upl..
				 * in this case we can only return an error
				 */
		        	error = EINVAL;
				break;
			}
			/*
			 * we can get here if the cluster code happens to 
			 * pick up a page that was dirtied via mmap vs
			 * a 'write' and the page targets a 'hole'...
			 * i.e. the writes to the cluster were sparse
			 * and the file was being written for the first time
			 *
			 * we can also get here if the filesystem supports
			 * 'holes' that are less than PAGE_SIZE.... because
			 * we can't know if the range in the page that covers
			 * the 'hole' has been dirtied via an mmap or not,
			 * we have to assume the worst and try to push the
			 * entire page to storage.
			 *
			 * Try paging out the page individually before
			 * giving up entirely and dumping it (the pageout
			 * path will insure that the zero extent accounting
			 * has been taken care of before we get back into cluster_io)
			 */
			ubc_upl_abort_range(upl, trunc_page(upl_offset), PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);

			e_offset = round_page_64(f_offset + 1);

			if (ubc_sync_range(vp, f_offset, e_offset, UBC_PUSHDIRTY) == 0) {
			        error = EINVAL;
			 	break;
			}
			io_size = e_offset - f_offset;

			f_offset   += io_size;
			upl_offset += io_size;

			if (size >= io_size)
			        size -= io_size;
			else
			        size = 0;
			/*
			 * keep track of how much of the original request
			 * that we've actually completed... non_rounded_size
			 * may go negative due to us rounding the request
			 * to a page size multiple (i.e.  size > non_rounded_size)
			 */
			non_rounded_size -= io_size;

			if (non_rounded_size <= 0) {
			        /*
				 * we've transferred all of the data in the original
				 * request, but we were unable to complete the tail
				 * of the last page because the file didn't have
				 * an allocation to back that portion... this is ok.
				 */
			        size = 0;
			}
			continue;
		}
		lblkno = (daddr64_t)(f_offset / PAGE_SIZE_64);
		/*
		 * we have now figured out how much I/O we can do - this is in 'io_size'
		 * pg_offset is the starting point in the first page for the I/O
		 * pg_count is the number of full and partial pages that 'io_size' encompasses
		 */
		pg_offset = upl_offset & PAGE_MASK;

		if (flags & CL_DEV_MEMORY) {
		        /*
			 * currently, can't deal with reading 'holes' in file
			 */
		        if (blkno == -1) {
			        error = EINVAL;
				break;
			}
			/*
			 * treat physical requests as one 'giant' page
			 */
			pg_count = 1;
		} else
		        pg_count  = (io_size + pg_offset + (PAGE_SIZE - 1)) / PAGE_SIZE;

		if ((flags & CL_READ) && blkno == -1) {
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
				 * if the 'hole' returned by vnop_blockmap extends all the way to the eof
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
			/*
			 * keep track of how much of the original request
			 * that we've actually completed... non_rounded_size
			 * may go negative due to us rounding the request
			 * to a page size multiple (i.e.  size > non_rounded_size)
			 */
			non_rounded_size -= io_size;

			if (non_rounded_size <= 0) {
			        /*
				 * we've transferred all of the data in the original
				 * request, but we were unable to complete the tail
				 * of the last page because the file didn't have
				 * an allocation to back that portion... this is ok.
				 */
			        size = 0;
			}
			if (cbp_head && pg_count) 
			        goto start_io;
			continue;

		}
		if (pg_count > max_vectors) {
		        if (((pg_count - max_vectors) * PAGE_SIZE) > io_size) {
			        io_size = PAGE_SIZE - pg_offset;
				pg_count = 1;
			} else {
			        io_size -= (pg_count - max_vectors) * PAGE_SIZE;
			        pg_count = max_vectors;
			}
		}

		if ( !(mp->mnt_kern_flag & MNTK_VIRTUALDEV))
		        /*
			 * if we're not targeting a virtual device i.e. a disk image
			 * it's safe to dip into the reserve pool since real devices
			 * can complete this I/O request without requiring additional
			 * bufs from the alloc_io_buf pool
			 */
			priv = 1;
		else if ((flags & CL_ASYNC) && !(flags & CL_PAGEOUT))
		        /*
			 * Throttle the speculative IO
			 */
			priv = 0;
		else
			priv = 1;

		cbp = alloc_io_buf(vp, priv);

		if (flags & CL_PAGEOUT) {
		        u_int i;

		        for (i = 0; i < pg_count; i++) {
			        if (buf_invalblkno(vp, lblkno + i, 0) == EBUSY)
				        panic("BUSY bp found in cluster_io");
			}
		}
		if (flags & CL_ASYNC) {
		        if (buf_setcallback(cbp, (void *)cluster_iodone, NULL))
			        panic("buf_setcallback failed\n");
		}
		cbp->b_flags |= io_flags;

		cbp->b_lblkno = lblkno;
		cbp->b_blkno  = blkno;
		cbp->b_bcount = io_size;

		if (buf_setupl(cbp, upl, upl_offset))
		        panic("buf_setupl failed\n");

		cbp->b_trans_next = (buf_t)NULL;

		if ((cbp->b_iostate = (void *)iostate))
		        /*
			 * caller wants to track the state of this
			 * io... bump the amount issued against this stream
			 */
		        iostate->io_issued += io_size;

		if (flags & CL_READ) {
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 26)) | DBG_FUNC_NONE,
				     (int)cbp->b_lblkno, (int)cbp->b_blkno, upl_offset, io_size, 0);
		}
		else {
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 27)) | DBG_FUNC_NONE,
				     (int)cbp->b_lblkno, (int)cbp->b_blkno, upl_offset, io_size, 0);
		}

		if (cbp_head) {
		        cbp_tail->b_trans_next = cbp;
			cbp_tail = cbp;
		} else {
		        cbp_head = cbp;
			cbp_tail = cbp;
		}
		(buf_t)(cbp->b_trans_head) = cbp_head;
		trans_count++;

		upl_offset += io_size;
		f_offset   += io_size;
		size       -= io_size;
		/*
		 * keep track of how much of the original request
		 * that we've actually completed... non_rounded_size
		 * may go negative due to us rounding the request
		 * to a page size multiple (i.e.  size > non_rounded_size)
		 */
		non_rounded_size -= io_size;

		if (non_rounded_size <= 0) {
		        /*
			 * we've transferred all of the data in the original
			 * request, but we were unable to complete the tail
			 * of the last page because the file didn't have
			 * an allocation to back that portion... this is ok.
			 */
		        size = 0;
		}
		if ( (!(upl_offset & PAGE_MASK) && !(flags & CL_DEV_MEMORY) && ((flags & CL_ASYNC) || trans_count > 8)) || size == 0) {
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
			        cbp_head->b_real_bp = (buf_t)NULL;

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
			  
			if (flags & CL_THROTTLE)
			        (void)vnode_waitforwrites(vp, async_throttle, 0, 0, (char *)"cluster_io");
			  
		        for (cbp = cbp_head; cbp;) {
				buf_t	cbp_next;

			        if ( !(io_flags & B_READ))
				        vnode_startwrite(vp);

				cbp_next = cbp->b_trans_next;
				
				(void) VNOP_STRATEGY(cbp);
				cbp = cbp_next;
			}
			if ( !(flags & CL_ASYNC)) {
			        int dummy;

			        for (cbp = cbp_head; cbp; cbp = cbp->b_trans_next)
				        buf_biowait(cbp);

				if ((error = cluster_iodone(cbp_head, (void *)&dummy))) {
				        if (((flags & (CL_PAGEOUT | CL_KEEPCACHED)) == CL_PAGEOUT) && (error == ENXIO))
						error = 0;	/* drop the error */
					else {
					        if (retval == 0)
						        retval = error;
						error = 0;
					}
				}
			}
			cbp_head = (buf_t)NULL;
			cbp_tail = (buf_t)NULL;

			trans_count = 0;
		}
	}
	if (error) {
	        int abort_size;

		io_size = 0;
		
	        for (cbp = cbp_head; cbp;) {
			buf_t	cbp_next;
 
			upl_offset -= cbp->b_bcount;
			size       += cbp->b_bcount;
			io_size    += cbp->b_bcount;

			cbp_next = cbp->b_trans_next;
			free_io_buf(cbp);
			cbp = cbp_next;
		}
		if (iostate) {
		        int need_wakeup = 0;

		        /*
			 * update the error condition for this stream
			 * since we never really issued the io
			 * just go ahead and adjust it back
			 */
		        lck_mtx_lock(cl_mtxp);

		        if (iostate->io_error == 0)
			        iostate->io_error = error;
			iostate->io_issued -= io_size;

			if (iostate->io_wanted) {
			        /*
				 * someone is waiting for the state of
				 * this io stream to change
				 */
			        iostate->io_wanted = 0;
				need_wakeup = 0;
			}
		        lck_mtx_unlock(cl_mtxp);

			if (need_wakeup)
			        wakeup((caddr_t)&iostate->io_wanted);
		}
		pg_offset  = upl_offset & PAGE_MASK;
		abort_size = (size + pg_offset + (PAGE_SIZE - 1)) & ~PAGE_MASK;

		if (flags & CL_COMMIT) {
		        int upl_abort_code;

			if (flags & CL_PRESERVE) {
			        ubc_upl_commit_range(upl, upl_offset - pg_offset, abort_size,
						     UPL_COMMIT_FREE_ON_EMPTY);
			} else {
			        if ((flags & CL_PAGEOUT) && (error != ENXIO)) /* transient error */
				        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY;
				else if (flags & CL_PAGEIN)
				        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR;
				else
				        upl_abort_code = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_DUMP_PAGES;

				ubc_upl_abort_range(upl, upl_offset - pg_offset, abort_size,
						upl_abort_code);
			}
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 28)) | DBG_FUNC_NONE,
				     (int)upl, upl_offset - pg_offset, abort_size, error, 0);
		}
		if (real_bp) {
		        real_bp->b_flags |= B_ERROR;
			real_bp->b_error  = error;

			buf_biodone(real_bp);
		}
		if (retval == 0)
		        retval = error;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 22)) | DBG_FUNC_END,
		     (int)f_offset, size, upl_offset, retval, 0);

	return (retval);
}


static int
cluster_rd_prefetch(vnode_t vp, off_t f_offset, u_int size, off_t filesize)
{
	int           pages_in_prefetch;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_START,
		     (int)f_offset, size, (int)filesize, 0, 0);

	if (f_offset >= filesize) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_END,
			     (int)f_offset, 0, 0, 0, 0);
	        return(0);
	}
	if (size > (MAX_UPL_TRANSFER * PAGE_SIZE))
	        size = (MAX_UPL_TRANSFER * PAGE_SIZE);
	else
	        size = (size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

        if ((off_t)size > (filesize - f_offset))
                size = filesize - f_offset;
	pages_in_prefetch = (size + (PAGE_SIZE - 1)) / PAGE_SIZE;

	advisory_read(vp, filesize, f_offset, size);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 49)) | DBG_FUNC_END,
		     (int)f_offset + size, pages_in_prefetch, 0, 1, 0);

	return (pages_in_prefetch);
}



static void
cluster_rd_ahead(vnode_t vp, struct cl_extent *extent, off_t filesize, struct cl_readahead *rap)
{
	daddr64_t	r_addr;
	off_t		f_offset;
	int		size_of_prefetch;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_START,
		     (int)extent->b_addr, (int)extent->e_addr, (int)rap->cl_lastr, 0, 0);

	if (extent->b_addr == rap->cl_lastr && extent->b_addr == extent->e_addr) {
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
			     rap->cl_ralen, (int)rap->cl_maxra, (int)rap->cl_lastr, 0, 0);
		return;
	}
	if (rap->cl_lastr == -1 || (extent->b_addr != rap->cl_lastr && extent->b_addr != (rap->cl_lastr + 1) &&
				   (extent->b_addr != (rap->cl_maxra + 1) || rap->cl_ralen == 0))) {
	        rap->cl_ralen = 0;
		rap->cl_maxra = 0;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
			     rap->cl_ralen, (int)rap->cl_maxra, (int)rap->cl_lastr, 1, 0);

		return;
	}
	if (extent->e_addr < rap->cl_maxra) {
	        if ((rap->cl_maxra - extent->e_addr) > (MAX_UPL_TRANSFER / 4)) {

		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
				     rap->cl_ralen, (int)rap->cl_maxra, (int)rap->cl_lastr, 2, 0);
			return;
		}
	}
	r_addr = max(extent->e_addr, rap->cl_maxra) + 1;
	f_offset = (off_t)(r_addr * PAGE_SIZE_64);

        size_of_prefetch = 0;

	ubc_range_op(vp, f_offset, f_offset + PAGE_SIZE_64, UPL_ROP_PRESENT, &size_of_prefetch);

	if (size_of_prefetch) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
			     rap->cl_ralen, (int)rap->cl_maxra, (int)rap->cl_lastr, 3, 0);
		return;
	}
	if (f_offset < filesize) {
	        daddr64_t read_size;

	        rap->cl_ralen = rap->cl_ralen ? min(MAX_UPL_TRANSFER, rap->cl_ralen << 1) : 1;

		read_size = (extent->e_addr + 1) - extent->b_addr;

		if (read_size > rap->cl_ralen) {
		        if (read_size > MAX_UPL_TRANSFER)
			        rap->cl_ralen = MAX_UPL_TRANSFER;
			else
			        rap->cl_ralen = read_size;
		}
		size_of_prefetch = cluster_rd_prefetch(vp, f_offset, rap->cl_ralen * PAGE_SIZE, filesize);

		if (size_of_prefetch)
		        rap->cl_maxra = (r_addr + size_of_prefetch) - 1;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 48)) | DBG_FUNC_END,
		     rap->cl_ralen, (int)rap->cl_maxra, (int)rap->cl_lastr, 4, 0);
}

int
cluster_pageout(vnode_t vp, upl_t upl, vm_offset_t upl_offset, off_t f_offset,
		int size, off_t filesize, int flags)
{
	int           io_size;
	int           rounded_size;
        off_t         max_size;
	int           local_flags;
	struct cl_writebehind *wbp;

	if (vp->v_mount->mnt_kern_flag & MNTK_VIRTUALDEV)
	        /*
		 * if we know we're issuing this I/O to a virtual device (i.e. disk image)
		 * then we don't want to enforce this throttle... if we do, we can 
		 * potentially deadlock since we're stalling the pageout thread at a time
		 * when the disk image might need additional memory (which won't be available
		 * if the pageout thread can't run)... instead we'll just depend on the throttle
		 * that the pageout thread now has in place to deal with external files
		 */
	        local_flags = CL_PAGEOUT;
	else
	        local_flags = CL_PAGEOUT | CL_THROTTLE;

	if ((flags & UPL_IOSYNC) == 0) 
		local_flags |= CL_ASYNC;
	if ((flags & UPL_NOCOMMIT) == 0) 
		local_flags |= CL_COMMIT;
	if ((flags & UPL_KEEPCACHED))
	        local_flags |= CL_KEEPCACHED;


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

	rounded_size = (io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	if (size > rounded_size) {
		if (local_flags & CL_COMMIT)
			ubc_upl_abort_range(upl, upl_offset + rounded_size, size - rounded_size,
					UPL_ABORT_FREE_ON_EMPTY);
	}
	if ((wbp = cluster_get_wbp(vp, 0)) != NULL)
	        wbp->cl_hasbeenpaged = 1;

	return (cluster_io(vp, upl, upl_offset, f_offset, io_size,
			   local_flags, (buf_t)NULL, (struct clios *)NULL));
}

int
cluster_pagein(vnode_t vp, upl_t upl, vm_offset_t upl_offset, off_t f_offset,
	       int size, off_t filesize, int flags)
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
				    size - rounded_size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
	
	retval = cluster_io(vp, upl, upl_offset, f_offset, io_size,
			   local_flags | CL_READ | CL_PAGEIN, (buf_t)NULL, (struct clios *)NULL);

	if (retval == 0 && !(flags & UPL_NORDAHEAD) && !(vp->v_flag & VRAOFF)) {
		struct cl_readahead *rap;

		rap = cluster_get_rap(vp);

		if (rap != NULL) {
		        struct cl_extent extent;

		        extent.b_addr = (daddr64_t)(f_offset / PAGE_SIZE_64);
			extent.e_addr = (daddr64_t)((f_offset + ((off_t)io_size - 1)) / PAGE_SIZE_64);

			if (rounded_size == PAGE_SIZE) {
			        /*
				 * we haven't read the last page in of the file yet
				 * so let's try to read ahead if we're in 
				 * a sequential access pattern
				 */
			        cluster_rd_ahead(vp, &extent, filesize, rap);
			}
			rap->cl_lastr = extent.e_addr;

			lck_mtx_unlock(&rap->cl_lockr);
		}
	}
	return (retval);
}

int
cluster_bp(buf_t bp)
{
        off_t  f_offset;
	int    flags;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 19)) | DBG_FUNC_START,
		     (int)bp, (int)bp->b_lblkno, bp->b_bcount, bp->b_flags, 0);

	if (bp->b_flags & B_READ)
	        flags = CL_ASYNC | CL_READ;
	else
	        flags = CL_ASYNC;

	f_offset = ubc_blktooff(bp->b_vp, bp->b_lblkno);

        return (cluster_io(bp->b_vp, bp->b_upl, 0, f_offset, bp->b_bcount, flags, bp, (struct clios *)NULL));
}

int
cluster_write(vnode_t vp, struct uio *uio, off_t oldEOF, off_t newEOF, off_t headOff, off_t tailOff, int xflags)
{
	int           prev_resid;
	u_int         clip_size;
	off_t         max_io_size;
	int           upl_size;
	int           upl_flags;
	upl_t         upl;
	int           retval = 0;
	int	      flags;

	flags = xflags;

	if (vp->v_flag & VNOCACHE_DATA)
	        flags |= IO_NOCACHE;

	if ( (!(flags & IO_NOCACHE)) || (!uio) || (!UIO_SEG_IS_USER_SPACE(uio->uio_segflg))) {
	        /*
		 * go do a write through the cache if one of the following is true....
		 *   NOCACHE is not true
		 *   there is no uio structure or it doesn't target USERSPACE
		 */
	        return (cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags));
	}

#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */
	
	while (uio_resid(uio) && uio->uio_offset < newEOF && retval == 0) {
	  	user_size_t	iov_len;
	  	user_addr_t	iov_base;

		/*
		 * we know we have a resid, so this is safe
		 * skip over any emtpy vectors
		 */
		uio_update(uio, (user_size_t)0);

		iov_len  = uio_curriovlen(uio);
		iov_base = uio_curriovbase(uio);

		upl_size  = PAGE_SIZE;
		upl_flags = UPL_QUERY_OBJECT_TYPE;

		// LP64todo - fix this!
		if ((vm_map_get_upl(current_map(),
				    (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
				    &upl_size, &upl, NULL, NULL, &upl_flags, 0)) != KERN_SUCCESS) {
		        /*
			 * the user app must have passed in an invalid address
			 */
		        return (EFAULT);
		}	      

		/*
		 * We check every vector target but if it is physically
		 * contiguous space, we skip the sanity checks.
		 */
		if (upl_flags & UPL_PHYS_CONTIG) {
		        int zflags;

			zflags = flags & ~IO_TAILZEROFILL;
			zflags |= IO_HEADZEROFILL;

		        if (flags & IO_HEADZEROFILL) {
			        /*
				 * in case we have additional vectors, we don't want to do this again
				 */
			        flags &= ~IO_HEADZEROFILL;

				if ((retval = cluster_write_x(vp, (struct uio *)0, 0, uio->uio_offset, headOff, 0, zflags)))
				        return(retval);
			}
			retval = cluster_phys_write(vp, uio, newEOF);

			if (uio_resid(uio) == 0 && (flags & IO_TAILZEROFILL)) {
			        return (cluster_write_x(vp, (struct uio *)0, 0, tailOff, uio->uio_offset, 0, zflags));
			}
		}
		else if ((uio_resid(uio) < PAGE_SIZE) || (flags & (IO_TAILZEROFILL | IO_HEADZEROFILL))) {
		        /*
			 * we're here because we're don't have a physically contiguous target buffer
			 * go do a write through the cache if one of the following is true....
			 *   the total xfer size is less than a page...
			 *   we're being asked to ZEROFILL either the head or the tail of the I/O...
			 */
		        return (cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags));
		}
		// LP64todo - fix this!
		else if (((int)uio->uio_offset & PAGE_MASK) || (CAST_DOWN(int, iov_base) & PAGE_MASK)) {
		        if (((int)uio->uio_offset & PAGE_MASK) == (CAST_DOWN(int, iov_base) & PAGE_MASK)) {
			        /*
				 * Bring the file offset write up to a pagesize boundary
				 * this will also bring the base address to a page boundary
				 * since they both are currently on the same offset within a page
				 * note: if we get here, uio->uio_resid is greater than PAGE_SIZE
				 * so the computed clip_size must always be less than the current uio_resid
				 */
			        clip_size = (PAGE_SIZE - (uio->uio_offset & PAGE_MASK_64));

				/* 
				 * Fake the resid going into the cluster_write_x call
				 * and restore it on the way out.
				 */
				// LP64todo - fix this
				prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			} else {
			        /*
				 * can't get both the file offset and the buffer offset aligned to a page boundary
				 * so fire an I/O through the cache for this entire vector
				 */
			        // LP64todo - fix this
			        clip_size = iov_len;
				// LP64todo - fix this
				prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			}
		} else {
		        /* 
			 * If we come in here, we know the offset into
			 * the file is on a pagesize boundary and the
			 * target buffer address is also on a page boundary
			 */
		        max_io_size = newEOF - uio->uio_offset;
			// LP64todo - fix this
			clip_size = uio_resid(uio);
			if (iov_len < clip_size)
			        // LP64todo - fix this!
			        clip_size = iov_len;
			if (max_io_size < clip_size)
			        clip_size = max_io_size;

			if (clip_size < PAGE_SIZE) {
			        /*
				 * Take care of tail end of write in this vector
				 */
			        // LP64todo - fix this
			        prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			} else {
			        /* round clip_size down to a multiple of pagesize */
			        clip_size = clip_size & ~(PAGE_MASK);
				// LP64todo - fix this
				prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_nocopy_write(vp, uio, newEOF);

				if ((retval == 0) && uio_resid(uio))
				        retval = cluster_write_x(vp, uio, oldEOF, newEOF, headOff, tailOff, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			}
		} /* end else */
	} /* end while */

	return(retval);
}


static int
cluster_nocopy_write(vnode_t vp, struct uio *uio, off_t newEOF)
{
	upl_t            upl;
	upl_page_info_t  *pl;
	vm_offset_t      upl_offset;
	int              io_size;
	int              io_flag;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	int              i;
	int              force_data_sync;
	int              error  = 0;
	struct clios     iostate;
	struct cl_writebehind *wbp;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 75)) | DBG_FUNC_START,
		     (int)uio->uio_offset, (int)uio_resid(uio), 
		     (int)newEOF, 0, 0);

	/*
	 * When we enter this routine, we know
	 *  -- the offset into the file is on a pagesize boundary
	 *  -- the resid is a page multiple
	 *  -- the resid will not exceed iov_len
	 */
	
	if ((wbp = cluster_get_wbp(vp, CLW_RETURNLOCKED)) != NULL) {

		cluster_try_push(wbp, vp, newEOF, 0, 1);

	        lck_mtx_unlock(&wbp->cl_lockw);
	}
	iostate.io_completed = 0;
	iostate.io_issued = 0;
	iostate.io_error = 0;
	iostate.io_wanted = 0;

	while (uio_resid(uio) && uio->uio_offset < newEOF && error == 0) {
	  	user_addr_t	iov_base;

	        io_size = uio_resid(uio);

		if (io_size > (MAX_UPL_TRANSFER * PAGE_SIZE))
		        io_size = MAX_UPL_TRANSFER * PAGE_SIZE;

		iov_base = uio_curriovbase(uio);

		// LP64todo - fix this!
		upl_offset = CAST_DOWN(vm_offset_t, iov_base) & PAGE_MASK;
		
		upl_needed_size = (upl_offset + io_size + (PAGE_SIZE -1)) & ~PAGE_MASK;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 76)) | DBG_FUNC_START,
			     (int)upl_offset, upl_needed_size, (int)iov_base, io_size, 0);

		for (force_data_sync = 0; force_data_sync < 3; force_data_sync++) {
		        pages_in_pl = 0;
			upl_size = upl_needed_size;
			upl_flags = UPL_FILE_IO | UPL_COPYOUT_FROM | UPL_NO_SYNC |
		                    UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;

			// LP64todo - fix this!
			kret = vm_map_get_upl(current_map(),
					      (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
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
			     (int)upl_offset, upl_size, (int)iov_base, io_size, 0);		       

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
		 * uio->uio_offset is page aligned within the file
		 * io_size is a multiple of PAGE_SIZE
		 */
		ubc_range_op(vp, uio->uio_offset, uio->uio_offset + io_size, UPL_ROP_DUMP, NULL);

		/*
		 * we want push out these writes asynchronously so that we can overlap
		 * the preparation of the next I/O
		 * if there are already too many outstanding writes
		 * wait until some complete before issuing the next
		 */
		lck_mtx_lock(cl_mtxp);

		while ((iostate.io_issued - iostate.io_completed) > (2 * MAX_UPL_TRANSFER * PAGE_SIZE)) {
	                iostate.io_wanted = 1;
			msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_nocopy_write", 0);
		}	
		lck_mtx_unlock(cl_mtxp);

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
		io_flag = CL_ASYNC | CL_PRESERVE | CL_COMMIT | CL_THROTTLE;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 77)) | DBG_FUNC_START,
			     (int)upl_offset, (int)uio->uio_offset, io_size, io_flag, 0);

		error = cluster_io(vp, upl, upl_offset, uio->uio_offset,
				   io_size, io_flag, (buf_t)NULL, &iostate);

		uio_update(uio, (user_size_t)io_size);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 77)) | DBG_FUNC_END,
			     (int)upl_offset, (int)uio->uio_offset, (int)uio_resid(uio), error, 0);

	} /* end while */

wait_for_writes:
	/*
	 * make sure all async writes issued as part of this stream
	 * have completed before we return
	 */
	lck_mtx_lock(cl_mtxp);

	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_nocopy_write", 0);
	}	
	lck_mtx_unlock(cl_mtxp);

	if (iostate.io_error)
		error = iostate.io_error;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 75)) | DBG_FUNC_END,
		     (int)uio->uio_offset, (int)uio->uio_resid, error, 4, 0);

	return (error);
}


static int
cluster_phys_write(vnode_t vp, struct uio *uio, off_t newEOF)
{
	upl_page_info_t *pl;
	addr64_t	 src_paddr;
 	upl_t            upl;
	vm_offset_t      upl_offset;
	int              tail_size;
	int              io_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	int              error  = 0;
	user_addr_t	 iov_base;
	int		 devblocksize;
	struct cl_writebehind *wbp;

	devblocksize = vp->v_mount->mnt_devblocksize;
	/*
	 * When we enter this routine, we know
	 *  -- the resid will not exceed iov_len
	 *  -- the vector target address is physcially contiguous
	 */
	if ((wbp = cluster_get_wbp(vp, CLW_RETURNLOCKED)) != NULL) {

		cluster_try_push(wbp, vp, newEOF, 0, 1);

	        lck_mtx_unlock(&wbp->cl_lockw);
	}
#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	// LP64todo - fix this!
	io_size = (int)uio_curriovlen(uio);
	iov_base = uio_curriovbase(uio);

	upl_offset = CAST_DOWN(upl_offset_t, iov_base) & PAGE_MASK;
	upl_needed_size = upl_offset + io_size;

	pages_in_pl = 0;
	upl_size = upl_needed_size;
	upl_flags = UPL_FILE_IO | UPL_COPYOUT_FROM | UPL_NO_SYNC | 
	            UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;

	// LP64todo - fix this!
	kret = vm_map_get_upl(current_map(),
			      (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
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
	        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);
		return(EINVAL);
	}
	pl = ubc_upl_pageinfo(upl);

	src_paddr = ((addr64_t)upl_phys_page(pl, 0) << 12) + (addr64_t)upl_offset;

	while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
	        int   head_size;

		head_size = devblocksize - (int)(uio->uio_offset & (devblocksize - 1));

		if (head_size > io_size)
		        head_size = io_size;

		error = cluster_align_phys_io(vp, uio, src_paddr, head_size, 0);

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
				   io_size, CL_DEV_MEMORY, (buf_t)NULL, (struct clios *)NULL);
	}
	if (error == 0) {
	        /*
		 * The cluster_io write completed successfully,
		 * update the uio structure
		 */
	        uio_update(uio, (user_size_t)io_size);

		src_paddr += io_size;

		if (tail_size)
		        error = cluster_align_phys_io(vp, uio, src_paddr, tail_size, 0);
	}
	/*
	 * just release our hold on the physically contiguous
	 * region without changing any state
	 */
	ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

	return (error);
}


static int
cluster_write_x(vnode_t vp, struct uio *uio, off_t oldEOF, off_t newEOF, off_t headOff, off_t tailOff, int flags)
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset = 0;
	int              upl_size;
	off_t 	         upl_f_offset;
	int              pages_in_upl;
	int		 start_offset;
	int              xfer_resid;
	int              io_size;
	int              io_offset;
	int              bytes_to_zero;
	int              bytes_to_move;
	kern_return_t    kret;
	int              retval = 0;
	int              io_resid;
	long long        total_size;
	long long        zero_cnt;
	off_t            zero_off;
	long long        zero_cnt1;
	off_t            zero_off1;
	struct cl_extent cl;
        int              intersection;
	struct cl_writebehind *wbp;

	if ((wbp = cluster_get_wbp(vp, 0)) != NULL)
	{
	        if (wbp->cl_hasbeenpaged) {
		        /*
			 * this vnode had pages cleaned to it by
			 * the pager which indicates that either
			 * it's not very 'hot', or the system is
			 * being overwhelmed by a lot of dirty 
			 * data being delayed in the VM cache...
			 * in either event, we'll push our remaining
			 * delayed data at this point...  this will
			 * be more efficient than paging out 1 page at 
			 * a time, and will also act as a throttle
			 * by delaying this client from writing any
			 * more data until all his delayed data has
			 * at least been queued to the uderlying driver.
			 */
		        if (wbp->cl_number || wbp->cl_scmap)
			        cluster_push_EOF(vp, newEOF);

			wbp->cl_hasbeenpaged = 0;
		}
	}
	if (uio) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_START,
			     (int)uio->uio_offset, uio_resid(uio), (int)oldEOF, (int)newEOF, 0);

		// LP64todo - fix this
	        io_resid = uio_resid(uio);
	} else {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_START,
			     0, 0, (int)oldEOF, (int)newEOF, 0);

	        io_resid = 0;
	}
	zero_cnt  = 0;
	zero_cnt1 = 0;
	zero_off  = 0;
	zero_off1 = 0;

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
		        // LP64todo - fix this
		        zero_off1 = uio->uio_offset + uio_resid(uio);

			if (zero_off1 < tailOff)
			        zero_cnt1 = tailOff - zero_off1;
		}	
	}
	if (zero_cnt == 0 && uio == (struct uio *) 0) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_END,
			     retval, 0, 0, 0, 0);
		return (0);
	}

	while ((total_size = (io_resid + zero_cnt + zero_cnt1)) && retval == 0) {
	        /*
		 * for this iteration of the loop, figure out where our starting point is
		 */
	        if (zero_cnt) {
		        start_offset = (int)(zero_off & PAGE_MASK_64);
			upl_f_offset = zero_off - start_offset;
		} else if (io_resid) {
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

		cl.b_addr = (daddr64_t)(upl_f_offset / PAGE_SIZE_64);
		
		if (uio && ((flags & (IO_NOCACHE | IO_SYNC | IO_HEADZEROFILL | IO_TAILZEROFILL)) == 0)) {
		        /*
			 * assumption... total_size <= io_resid
			 * because IO_HEADZEROFILL and IO_TAILZEROFILL not set
			 */
		        if ((start_offset + total_size) > (MAX_UPL_TRANSFER * PAGE_SIZE))
			        total_size -= start_offset;
		        xfer_resid = total_size;

		        retval = cluster_copy_ubc_data(vp, uio, &xfer_resid, 1);
			
			if (retval)
			        break;

			io_resid   -= (total_size - xfer_resid);
			total_size   = xfer_resid;
			start_offset = (int)(uio->uio_offset & PAGE_MASK_64);
			upl_f_offset = uio->uio_offset - start_offset;

			if (total_size == 0) {
			        if (start_offset) {
				        /*
					 * the write did not finish on a page boundary
					 * which will leave upl_f_offset pointing to the
					 * beginning of the last page written instead of
					 * the page beyond it... bump it in this case
					 * so that the cluster code records the last page
					 * written as dirty
					 */
				        upl_f_offset += PAGE_SIZE_64;
				}
			        upl_size = 0;
				
			        goto check_cluster;
			}
		}
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

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 41)) | DBG_FUNC_START, upl_size, io_size, total_size, 0, 0);
			

		/*
		 * Gather the pages from the buffer cache.
		 * The UPL_WILL_MODIFY flag lets the UPL subsystem know
		 * that we intend to modify these pages.
		 */
		kret = ubc_create_upl(vp, 
				      upl_f_offset,
				      upl_size,
				      &upl,
				      &pl,
				      UPL_SET_LITE | UPL_WILL_MODIFY);
		if (kret != KERN_SUCCESS)
			panic("cluster_write: failed to get pagelist");

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 41)) | DBG_FUNC_END,
			(int)upl, (int)upl_f_offset, start_offset, 0, 0);

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

		        retval = cluster_io(vp, upl, 0, upl_f_offset, read_size,
					    CL_READ, (buf_t)NULL, (struct clios *)NULL);
			if (retval) {
				/*
				 * we had an error during the read which causes us to abort
				 * the current cluster_write request... before we do, we need
				 * to release the rest of the pages in the upl without modifying
				 * there state and mark the failed page in error
				 */
				ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_DUMP_PAGES);

				if (upl_size > PAGE_SIZE)
				        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

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

			        retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, read_size,
						    CL_READ, (buf_t)NULL, (struct clios *)NULL);
				if (retval) {
					/*
					 * we had an error during the read which causes us to abort
					 * the current cluster_write request... before we do, we
					 * need to release the rest of the pages in the upl without
					 * modifying there state and mark the failed page in error
					 */
					ubc_upl_abort_range(upl, upl_offset, PAGE_SIZE, UPL_ABORT_DUMP_PAGES);

					if (upl_size > PAGE_SIZE)
					        ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY);

					KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 45)) | DBG_FUNC_NONE,
						     (int)upl, 0, 0, retval, 0);
					break;
				}
			}
		}
		xfer_resid = io_size;
		io_offset = start_offset;

		while (zero_cnt && xfer_resid) {

		        if (zero_cnt < (long long)xfer_resid)
			        bytes_to_zero = zero_cnt;
			else
			        bytes_to_zero = xfer_resid;

		        if ( !(flags & (IO_NOZEROVALID | IO_NOZERODIRTY))) {
				cluster_zero(upl, io_offset, bytes_to_zero, NULL);
			} else {
			        int zero_pg_index;

			        bytes_to_zero = min(bytes_to_zero, PAGE_SIZE - (int)(zero_off & PAGE_MASK_64));
				zero_pg_index = (int)((zero_off - upl_f_offset) / PAGE_SIZE_64);

				if ( !upl_valid_page(pl, zero_pg_index)) {
				        cluster_zero(upl, io_offset, bytes_to_zero, NULL); 

				} else if ((flags & (IO_NOZERODIRTY | IO_NOZEROVALID)) == IO_NOZERODIRTY &&
					   !upl_dirty_page(pl, zero_pg_index)) {
				        cluster_zero(upl, io_offset, bytes_to_zero, NULL); 
				}
			}
			xfer_resid -= bytes_to_zero;
			zero_cnt   -= bytes_to_zero;
			zero_off   += bytes_to_zero;
			io_offset  += bytes_to_zero;
		}
		if (xfer_resid && io_resid) {
			bytes_to_move = min(io_resid, xfer_resid);

			retval = cluster_copy_upl_data(uio, upl, io_offset, bytes_to_move);

			if (retval) {

				ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 45)) | DBG_FUNC_NONE,
					     (int)upl, 0, 0, retval, 0);
			} else {
			        io_resid  -= bytes_to_move;
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
			        cluster_zero(upl, io_offset, bytes_to_zero, NULL); 
			} else {
			        int zero_pg_index;
			
			        bytes_to_zero = min(bytes_to_zero, PAGE_SIZE - (int)(zero_off1 & PAGE_MASK_64));
				zero_pg_index = (int)((zero_off1 - upl_f_offset) / PAGE_SIZE_64);

				if ( !upl_valid_page(pl, zero_pg_index)) {
				        cluster_zero(upl, io_offset, bytes_to_zero, NULL); 
				} else if ((flags & (IO_NOZERODIRTY | IO_NOZEROVALID)) == IO_NOZERODIRTY &&
					   !upl_dirty_page(pl, zero_pg_index)) {
				        cluster_zero(upl, io_offset, bytes_to_zero, NULL); 
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
			        cluster_zero(upl, io_size, upl_size - io_size, NULL); 
			}
			if (flags & IO_SYNC)
			        /*
				 * if the IO_SYNC flag is set than we need to 
				 * bypass any clusters and immediately issue
				 * the I/O
				 */
			        goto issue_io;
check_cluster:
			/*
			 * take the lock to protect our accesses
			 * of the writebehind and sparse cluster state
			 */
			wbp = cluster_get_wbp(vp, CLW_ALLOCATE | CLW_RETURNLOCKED);

			/*
			 * calculate the last logical block number 
			 * that this delayed I/O encompassed
			 */
			cl.e_addr = (daddr64_t)((upl_f_offset + (off_t)upl_size) / PAGE_SIZE_64);

			if (wbp->cl_scmap) {

			        if ( !(flags & IO_NOCACHE)) {
				        /*
					 * we've fallen into the sparse
					 * cluster method of delaying dirty pages
					 * first, we need to release the upl if we hold one
					 * since pages in it may be present in the sparse cluster map
					 * and may span 2 separate buckets there... if they do and 
					 * we happen to have to flush a bucket to make room and it intersects
					 * this upl, a deadlock may result on page BUSY
					 */
				        if (upl_size)
					        ubc_upl_commit_range(upl, 0, upl_size,
								     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);

					sparse_cluster_add(wbp, vp, &cl, newEOF);

					lck_mtx_unlock(&wbp->cl_lockw);

					continue;
				}
				/*
				 * must have done cached writes that fell into
				 * the sparse cluster mechanism... we've switched
				 * to uncached writes on the file, so go ahead
				 * and push whatever's in the sparse map
				 * and switch back to normal clustering
				 *
				 * see the comment above concerning a possible deadlock...
				 */
			        if (upl_size) {
				        ubc_upl_commit_range(upl, 0, upl_size,
							     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
					/*
					 * setting upl_size to 0 keeps us from committing a
					 * second time in the start_new_cluster path
					 */
					upl_size = 0;
				}
				sparse_cluster_push(wbp, vp, newEOF, 1);

				wbp->cl_number = 0;
				/*
				 * no clusters of either type present at this point
				 * so just go directly to start_new_cluster since
				 * we know we need to delay this I/O since we've
				 * already released the pages back into the cache
				 * to avoid the deadlock with sparse_cluster_push
				 */
				goto start_new_cluster;
			}		    
			upl_offset = 0;

			if (wbp->cl_number == 0)
			        /*
				 * no clusters currently present
				 */
			        goto start_new_cluster;

			for (cl_index = 0; cl_index < wbp->cl_number; cl_index++) {
			        /*
				 * check each cluster that we currently hold
				 * try to merge some or all of this write into
				 * one or more of the existing clusters... if
				 * any portion of the write remains, start a
				 * new cluster
				 */
			        if (cl.b_addr >= wbp->cl_clusters[cl_index].b_addr) {
				        /*
					 * the current write starts at or after the current cluster
					 */
				        if (cl.e_addr <= (wbp->cl_clusters[cl_index].b_addr + MAX_UPL_TRANSFER)) {
					        /*
						 * we have a write that fits entirely
						 * within the existing cluster limits
						 */
					        if (cl.e_addr > wbp->cl_clusters[cl_index].e_addr)
						        /*
							 * update our idea of where the cluster ends
							 */
						        wbp->cl_clusters[cl_index].e_addr = cl.e_addr;
						break;
					}
					if (cl.b_addr < (wbp->cl_clusters[cl_index].b_addr + MAX_UPL_TRANSFER)) {
					        /*
						 * we have a write that starts in the middle of the current cluster
						 * but extends beyond the cluster's limit... we know this because
						 * of the previous checks
						 * we'll extend the current cluster to the max
						 * and update the b_addr for the current write to reflect that
						 * the head of it was absorbed into this cluster...
						 * note that we'll always have a leftover tail in this case since
						 * full absorbtion would have occurred in the clause above
						 */
					        wbp->cl_clusters[cl_index].e_addr = wbp->cl_clusters[cl_index].b_addr + MAX_UPL_TRANSFER;

						if (upl_size) {
						        daddr64_t start_pg_in_upl;

							start_pg_in_upl = (daddr64_t)(upl_f_offset / PAGE_SIZE_64);
							
							if (start_pg_in_upl < wbp->cl_clusters[cl_index].e_addr) {
							        intersection = (int)((wbp->cl_clusters[cl_index].e_addr - start_pg_in_upl) * PAGE_SIZE);

								ubc_upl_commit_range(upl, upl_offset, intersection,
										     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
								upl_f_offset += intersection;
								upl_offset   += intersection;
								upl_size     -= intersection;
							}
						}
						cl.b_addr = wbp->cl_clusters[cl_index].e_addr;
					}
					/*
					 * we come here for the case where the current write starts
					 * beyond the limit of the existing cluster or we have a leftover
					 * tail after a partial absorbtion
					 *
					 * in either case, we'll check the remaining clusters before 
					 * starting a new one
					 */
				} else {
				        /*
					 * the current write starts in front of the cluster we're currently considering
					 */
				        if ((wbp->cl_clusters[cl_index].e_addr - cl.b_addr) <= MAX_UPL_TRANSFER) {
					        /*
						 * we can just merge the new request into
						 * this cluster and leave it in the cache
						 * since the resulting cluster is still 
						 * less than the maximum allowable size
						 */
					        wbp->cl_clusters[cl_index].b_addr = cl.b_addr;

						if (cl.e_addr > wbp->cl_clusters[cl_index].e_addr) {
						        /*
							 * the current write completely
							 * envelops the existing cluster and since
							 * each write is limited to at most MAX_UPL_TRANSFER bytes
							 * we can just use the start and last blocknos of the write
							 * to generate the cluster limits
							 */
						        wbp->cl_clusters[cl_index].e_addr = cl.e_addr;
						}
						break;
					}

					/*
					 * if we were to combine this write with the current cluster
					 * we would exceed the cluster size limit.... so,
					 * let's see if there's any overlap of the new I/O with
					 * the cluster we're currently considering... in fact, we'll
					 * stretch the cluster out to it's full limit and see if we
					 * get an intersection with the current write
					 * 
					 */
					if (cl.e_addr > wbp->cl_clusters[cl_index].e_addr - MAX_UPL_TRANSFER) {
					        /*
						 * the current write extends into the proposed cluster
						 * clip the length of the current write after first combining it's
						 * tail with the newly shaped cluster
						 */
					        wbp->cl_clusters[cl_index].b_addr = wbp->cl_clusters[cl_index].e_addr - MAX_UPL_TRANSFER;

						if (upl_size) {
						        intersection = (int)((cl.e_addr - wbp->cl_clusters[cl_index].b_addr) * PAGE_SIZE);

							if (intersection > upl_size)
							        /*
								 * because the current write may consist of a number of pages found in the cache
								 * which are not part of the UPL, we may have an intersection that exceeds
								 * the size of the UPL that is also part of this write
								 */
							        intersection = upl_size;

						        ubc_upl_commit_range(upl, upl_offset + (upl_size - intersection), intersection,
									     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
							upl_size -= intersection;
						}
						cl.e_addr = wbp->cl_clusters[cl_index].b_addr;
					}
					/*
					 * if we get here, there was no way to merge
					 * any portion of this write with this cluster 
					 * or we could only merge part of it which 
					 * will leave a tail...
					 * we'll check the remaining clusters before starting a new one
					 */
				}
			}
			if (cl_index < wbp->cl_number)
			        /*
				 * we found an existing cluster(s) that we
				 * could entirely merge this I/O into
				 */
			        goto delay_io;

			if (wbp->cl_number < MAX_CLUSTERS && !(flags & IO_NOCACHE))
			        /*
				 * we didn't find an existing cluster to
				 * merge into, but there's room to start
				 * a new one
				 */
			        goto start_new_cluster;

			/*
			 * no exisitng cluster to merge with and no
			 * room to start a new one... we'll try 
			 * pushing one of the existing ones... if none of
			 * them are able to be pushed, we'll switch
			 * to the sparse cluster mechanism
			 * cluster_try_push updates cl_number to the
			 * number of remaining clusters... and
			 * returns the number of currently unused clusters
			 */
			int ret_cluster_try_push = 0;
			/* if writes are not deferred, call cluster push immediately */
			if (!((unsigned int)vfs_flags(vp->v_mount) & MNT_DEFWRITE)) {
				if (flags & IO_NOCACHE)
			        	can_delay = 0;
				else
			        	can_delay = 1;
				
				ret_cluster_try_push = cluster_try_push(wbp, vp, newEOF, can_delay, 0);
			}

			/* execute following regardless writes are deferred or not */
			if (ret_cluster_try_push == 0) {
			        /*
				 * no more room in the normal cluster mechanism
				 * so let's switch to the more expansive but expensive
				 * sparse mechanism....
				 * first, we need to release the upl if we hold one
				 * since pages in it may be present in the sparse cluster map (after the cluster_switch)
				 * and may span 2 separate buckets there... if they do and 
				 * we happen to have to flush a bucket to make room and it intersects
				 * this upl, a deadlock may result on page BUSY
				 */
			        if (upl_size)
				        ubc_upl_commit_range(upl, upl_offset, upl_size,
							     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);

			        sparse_cluster_switch(wbp, vp, newEOF);
				sparse_cluster_add(wbp, vp, &cl, newEOF);

				lck_mtx_unlock(&wbp->cl_lockw);

				continue;
			}
			/*
			 * we pushed one cluster successfully, so we must be sequentially writing this file
			 * otherwise, we would have failed and fallen into the sparse cluster support
			 * so let's take the opportunity to push out additional clusters as long as we
			 * remain below the throttle... this will give us better I/O locality if we're
			 * in a copy loop (i.e.  we won't jump back and forth between the read and write points
			 * however, we don't want to push so much out that the write throttle kicks in and
			 * hangs this thread up until some of the I/O completes...
			 */
			if (!((unsigned int)vfs_flags(vp->v_mount) & MNT_DEFWRITE)) {
				while (wbp->cl_number && (vp->v_numoutput <= (VNODE_ASYNC_THROTTLE / 2)))
			        	cluster_try_push(wbp, vp, newEOF, 0, 0);
			}

start_new_cluster:
			wbp->cl_clusters[wbp->cl_number].b_addr = cl.b_addr;
			wbp->cl_clusters[wbp->cl_number].e_addr = cl.e_addr;

			if (flags & IO_NOCACHE)
			        wbp->cl_clusters[wbp->cl_number].io_nocache = 1;
			else
			        wbp->cl_clusters[wbp->cl_number].io_nocache = 0;
			wbp->cl_number++;
delay_io:
			if (upl_size)
			        ubc_upl_commit_range(upl, upl_offset, upl_size,
						     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);

			lck_mtx_unlock(&wbp->cl_lockw);

			continue;
issue_io:
			/*
			 * we don't hold the vnode lock at this point
			 *
			 * because we had to ask for a UPL that provides currenty non-present pages, the
			 * UPL has been automatically set to clear the dirty flags (both software and hardware)
			 * upon committing it... this is not the behavior we want since it's possible for
			 * pages currently present as part of a mapped file to be dirtied while the I/O is in flight.
			 * in order to maintain some semblance of coherency with mapped writes
			 * we need to drop the current upl and pick it back up with COPYOUT_FROM set
			 * so that we correctly deal with a change in state of the hardware modify bit...
			 * we do this via cluster_push_x... by passing along the IO_SYNC flag, we force
			 * cluster_push_x to wait until all the I/Os have completed... cluster_push_x is also
			 * responsible for generating the correct sized I/O(s)
			 */
		        ubc_upl_commit_range(upl, 0, upl_size,
						     UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);

			cl.e_addr = (upl_f_offset + (off_t)upl_size) / PAGE_SIZE_64;

			retval = cluster_push_x(vp, &cl, newEOF, flags);
		}
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 40)) | DBG_FUNC_END,
		     retval, 0, io_resid, 0, 0);

	return (retval);
}

int
cluster_read(vnode_t vp, struct uio *uio, off_t filesize, int xflags)
{
	int           prev_resid;
	u_int         clip_size;
	off_t         max_io_size;
	int           upl_size;
	int           upl_flags;
	upl_t         upl;
	int           retval = 0;
	int	      flags;

	flags = xflags;

	if (vp->v_flag & VNOCACHE_DATA)
	        flags |= IO_NOCACHE;
	if (vp->v_flag & VRAOFF)
	        flags |= IO_RAOFF;

	if (!((flags & IO_NOCACHE) && UIO_SEG_IS_USER_SPACE(uio->uio_segflg))) {
	        /*
		 * go do a read through the cache if one of the following is true....
		 *   NOCACHE is not true
		 *   the uio request doesn't target USERSPACE
		 */
	        return (cluster_read_x(vp, uio, filesize, flags));
	}

#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	while (uio_resid(uio) && uio->uio_offset < filesize && retval == 0) {
	  	user_size_t	iov_len;
	  	user_addr_t	iov_base;

		/*
		 * we know we have a resid, so this is safe
		 * skip over any emtpy vectors
		 */
		uio_update(uio, (user_size_t)0);

		iov_len  = uio_curriovlen(uio);
		iov_base = uio_curriovbase(uio);

		upl_size  = PAGE_SIZE;
		upl_flags = UPL_QUERY_OBJECT_TYPE;
  
		// LP64todo - fix this!
		if ((vm_map_get_upl(current_map(),
				    (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
				    &upl_size, &upl, NULL, NULL, &upl_flags, 0)) != KERN_SUCCESS) {
		        /*
			 * the user app must have passed in an invalid address
			 */
		        return (EFAULT);
		}

		/*
		 * We check every vector target but if it is physically 
		 * contiguous space, we skip the sanity checks.
		 */
		if (upl_flags & UPL_PHYS_CONTIG) {
		        retval = cluster_phys_read(vp, uio, filesize);
		}
		else if (uio_resid(uio) < PAGE_SIZE) {
		        /*
			 * we're here because we're don't have a physically contiguous target buffer
			 * go do a read through the cache if
			 *   the total xfer size is less than a page...
			 */
		        return (cluster_read_x(vp, uio, filesize, flags));
		}
		// LP64todo - fix this!
		else if (((int)uio->uio_offset & PAGE_MASK) || (CAST_DOWN(int, iov_base) & PAGE_MASK)) {
		       if (((int)uio->uio_offset & PAGE_MASK) == (CAST_DOWN(int, iov_base) & PAGE_MASK)) {
			       /*
				* Bring the file offset read up to a pagesize boundary
				* this will also bring the base address to a page boundary
				* since they both are currently on the same offset within a page
				* note: if we get here, uio->uio_resid is greater than PAGE_SIZE
				* so the computed clip_size must always be less than the current uio_resid
				*/
			       clip_size = (PAGE_SIZE - (int)(uio->uio_offset & PAGE_MASK_64));

			       /* 
				* Fake the resid going into the cluster_read_x call
				* and restore it on the way out.
				*/
			       prev_resid = uio_resid(uio);
			       // LP64todo - fix this
			       uio_setresid(uio, clip_size);

			       retval = cluster_read_x(vp, uio, filesize, flags);

			       uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
		       } else {
			       /*
				* can't get both the file offset and the buffer offset aligned to a page boundary
				* so fire an I/O through the cache for this entire vector
				*/
			       // LP64todo - fix this!
			       clip_size = iov_len;
			       prev_resid = uio_resid(uio);
			       uio_setresid(uio, clip_size);

			       retval = cluster_read_x(vp, uio, filesize, flags);

			       uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
		       }
		} else {
		        /* 
			 * If we come in here, we know the offset into
			 * the file is on a pagesize boundary
			 */
		        max_io_size = filesize - uio->uio_offset;
			// LP64todo - fix this
			clip_size = uio_resid(uio);
			if (iov_len < clip_size)
			        clip_size = iov_len;
			if (max_io_size < clip_size)
			        clip_size = (int)max_io_size;

			if (clip_size < PAGE_SIZE) {
			        /*
				 * Take care of the tail end of the read in this vector.
				 */
			        // LP64todo - fix this
			        prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_read_x(vp, uio, filesize, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			} else {
			        /* round clip_size down to a multiple of pagesize */
			        clip_size = clip_size & ~(PAGE_MASK);
				// LP64todo - fix this
				prev_resid = uio_resid(uio);
				uio_setresid(uio, clip_size);

				retval = cluster_nocopy_read(vp, uio, filesize);

				if ((retval==0) && uio_resid(uio))
				        retval = cluster_read_x(vp, uio, filesize, flags);

				uio_setresid(uio, prev_resid - (clip_size - uio_resid(uio)));
			}
		} /* end else */
	} /* end while */

	return(retval);
}

static int
cluster_read_x(vnode_t vp, struct uio *uio, off_t filesize, int flags)
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	int              upl_size;
	off_t 	         upl_f_offset;
	int		 start_offset;
	int	         start_pg;
	int		 last_pg;
	int              uio_last = 0;
	int              pages_in_upl;
	off_t            max_size;
	off_t            last_ioread_offset;
	off_t            last_request_offset;
	u_int            size_of_prefetch;
	u_int            io_size;
	kern_return_t    kret;
	int              error  = 0;
	int              retval = 0;
	u_int            max_rd_size = MAX_UPL_TRANSFER * PAGE_SIZE;
	u_int            rd_ahead_enabled = 1;
	u_int            prefetch_enabled = 1;
	struct cl_readahead *	rap;
	struct clios		iostate;
	struct cl_extent	extent;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio_resid(uio), (int)filesize, 0, 0);
			 
	// LP64todo - fix this
	last_request_offset = uio->uio_offset + uio_resid(uio);

	if ((flags & (IO_RAOFF|IO_NOCACHE)) ||
		((last_request_offset & ~PAGE_MASK_64) == (uio->uio_offset & ~PAGE_MASK_64))) {
	        rd_ahead_enabled = 0;
		rap = NULL;
	} else {
	        if (cluster_hard_throttle_on(vp)) {
		        rd_ahead_enabled = 0;
			prefetch_enabled = 0;

			max_rd_size = HARD_THROTTLE_MAXSIZE;
		}
	        if ((rap = cluster_get_rap(vp)) == NULL)
		        rd_ahead_enabled = 0;
	}
	if (last_request_offset > filesize)
	        last_request_offset = filesize;
	extent.b_addr = uio->uio_offset / PAGE_SIZE_64;
        extent.e_addr = (last_request_offset - 1) / PAGE_SIZE_64;

	if (rap != NULL && rap->cl_ralen && (rap->cl_lastr == extent.b_addr || (rap->cl_lastr + 1) == extent.b_addr)) {
	        /*
		 * determine if we already have a read-ahead in the pipe courtesy of the
		 * last read systemcall that was issued...
		 * if so, pick up it's extent to determine where we should start
		 * with respect to any read-ahead that might be necessary to 
		 * garner all the data needed to complete this read systemcall
		 */
	        last_ioread_offset = (rap->cl_maxra * PAGE_SIZE_64) + PAGE_SIZE_64;

		if (last_ioread_offset < uio->uio_offset)
		        last_ioread_offset = (off_t)0;
		else if (last_ioread_offset > last_request_offset)
		        last_ioread_offset = last_request_offset;
	} else
	        last_ioread_offset = (off_t)0;

	while (uio_resid(uio) && uio->uio_offset < filesize && retval == 0) {
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

	// LP64todo - fix this!
		if ((off_t)((unsigned int)uio_resid(uio)) < max_size)
		        io_size = uio_resid(uio);
		else
		        io_size = max_size;

		if (!(flags & IO_NOCACHE)) {

		        while (io_size) {
			        u_int io_resid;
				u_int io_requested;

				/*
				 * if we keep finding the pages we need already in the cache, then
				 * don't bother to call cluster_rd_prefetch since it costs CPU cycles
				 * to determine that we have all the pages we need... once we miss in
				 * the cache and have issued an I/O, than we'll assume that we're likely
				 * to continue to miss in the cache and it's to our advantage to try and prefetch
				 */
				if (last_request_offset && last_ioread_offset && (size_of_prefetch = (last_request_offset - last_ioread_offset))) {
				        if ((last_ioread_offset - uio->uio_offset) <= max_rd_size && prefetch_enabled) {
					        /*
						 * we've already issued I/O for this request and
						 * there's still work to do and
						 * our prefetch stream is running dry, so issue a
						 * pre-fetch I/O... the I/O latency will overlap
						 * with the copying of the data
						 */
					        if (size_of_prefetch > max_rd_size)
						        size_of_prefetch = max_rd_size;

					        size_of_prefetch = cluster_rd_prefetch(vp, last_ioread_offset, size_of_prefetch, filesize);

						last_ioread_offset += (off_t)(size_of_prefetch * PAGE_SIZE);
				
						if (last_ioread_offset > last_request_offset)
						        last_ioread_offset = last_request_offset;
					}
				}
				/*
				 * limit the size of the copy we're about to do so that 
				 * we can notice that our I/O pipe is running dry and 
				 * get the next I/O issued before it does go dry
				 */
				if (last_ioread_offset && io_size > ((MAX_UPL_TRANSFER * PAGE_SIZE) / 4))
				        io_resid = ((MAX_UPL_TRANSFER * PAGE_SIZE) / 4);
				else
				        io_resid = io_size;

				io_requested = io_resid;

			        retval = cluster_copy_ubc_data(vp, uio, &io_resid, 0);

				io_size -= (io_requested - io_resid);

				if (retval || io_resid)
				        /*
					 * if we run into a real error or
					 * a page that is not in the cache
					 * we need to leave streaming mode
					 */
				        break;
				
				if ((io_size == 0 || last_ioread_offset == last_request_offset) && rd_ahead_enabled) {
				        /*
					 * we're already finished the I/O for this read request
					 * let's see if we should do a read-ahead
					 */
				        cluster_rd_ahead(vp, &extent, filesize, rap);
				}
			}
			if (retval)
			        break;
			if (io_size == 0) {
				if (rap != NULL) {
				        if (extent.e_addr < rap->cl_lastr)
					        rap->cl_maxra = 0;
					rap->cl_lastr = extent.e_addr;
				}
			        break;
			}
			start_offset = (int)(uio->uio_offset & PAGE_MASK_64);
			upl_f_offset = uio->uio_offset - (off_t)start_offset;
			max_size     = filesize - uio->uio_offset;
		}
	        if (io_size > max_rd_size)
		        io_size = max_rd_size;

		upl_size = (start_offset + io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	        if (upl_size > (MAX_UPL_TRANSFER * PAGE_SIZE) / 4)
		        upl_size = (MAX_UPL_TRANSFER * PAGE_SIZE) / 4;
		pages_in_upl = upl_size / PAGE_SIZE;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 33)) | DBG_FUNC_START,
			     (int)upl, (int)upl_f_offset, upl_size, start_offset, 0);

		kret = ubc_create_upl(vp, 
				      upl_f_offset,
				      upl_size,
				      &upl,
				      &pl,
				      UPL_SET_LITE);
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
		iostate.io_completed = 0;
		iostate.io_issued = 0;
		iostate.io_error = 0;
		iostate.io_wanted = 0;

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
			 * issue an asynchronous read to cluster_io
			 */

			error = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset,
					   io_size, CL_READ | CL_ASYNC, (buf_t)NULL, &iostate);
		}
		if (error == 0) {
		        /*
			 * if the read completed successfully, or there was no I/O request
			 * issued, than copy the data into user land via 'cluster_upl_copy_data'
			 * we'll first add on any 'valid'
			 * pages that were present in the upl when we acquired it.
			 */
			u_int  val_size;

		        for (uio_last = last_pg; uio_last < pages_in_upl; uio_last++) {
			        if (!upl_valid_page(pl, uio_last))
				        break;
			}
			/*
			 * compute size to transfer this round,  if uio->uio_resid is
			 * still non-zero after this attempt, we'll loop around and
			 * set up for another I/O.
			 */
			val_size = (uio_last * PAGE_SIZE) - start_offset;
		
			if (val_size > max_size)
			        val_size = max_size;

			if (val_size > uio_resid(uio))
	// LP64todo - fix this
			        val_size = uio_resid(uio);

			if (last_ioread_offset == 0)
			        last_ioread_offset = uio->uio_offset + val_size;

			if ((size_of_prefetch = (last_request_offset - last_ioread_offset)) && prefetch_enabled) {
			        /*
				 * if there's still I/O left to do for this request, and...
				 * we're not in hard throttle mode, then issue a
				 * pre-fetch I/O... the I/O latency will overlap
				 * with the copying of the data
				 */
     				size_of_prefetch = cluster_rd_prefetch(vp, last_ioread_offset, size_of_prefetch, filesize);

				last_ioread_offset += (off_t)(size_of_prefetch * PAGE_SIZE);
				
				if (last_ioread_offset > last_request_offset)
				        last_ioread_offset = last_request_offset;

			} else if ((uio->uio_offset + val_size) == last_request_offset) {
			        /*
				 * this transfer will finish this request, so...
				 * let's try to read ahead if we're in 
				 * a sequential access pattern and we haven't
				 * explicitly disabled it
				 */
			        if (rd_ahead_enabled)
				        cluster_rd_ahead(vp, &extent, filesize, rap);
					
				if (rap != NULL) {
				        if (extent.e_addr < rap->cl_lastr)
					        rap->cl_maxra = 0;
					rap->cl_lastr = extent.e_addr;
				}
			}
			lck_mtx_lock(cl_mtxp);

			while (iostate.io_issued != iostate.io_completed) {
			        iostate.io_wanted = 1;
				msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_read_x", 0);
			}	
			lck_mtx_unlock(cl_mtxp);

			if (iostate.io_error)
			        error = iostate.io_error;
			else
			        retval = cluster_copy_upl_data(uio, upl, start_offset, val_size);
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

			if (error || (flags & IO_NOCACHE))
			        ubc_upl_abort_range(upl, start_pg * PAGE_SIZE, io_size,
						UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);
			else
			        ubc_upl_commit_range(upl, start_pg * PAGE_SIZE, io_size, 
						     UPL_COMMIT_CLEAR_DIRTY |
						     UPL_COMMIT_FREE_ON_EMPTY | 
						     UPL_COMMIT_INACTIVATE);

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 35)) | DBG_FUNC_END,
				     (int)upl, start_pg * PAGE_SIZE, io_size, error, 0);
		}
		if ((last_pg - start_pg) < pages_in_upl) {
		        int cur_pg;
			int commit_flags;

		        /*
			 * the set of pages that we issued an I/O for did not encompass
			 * the entire upl... so just release these without modifying
			 * their state
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
						
						if ( !(commit_flags & UPL_COMMIT_SET_DIRTY) && (flags & IO_NOCACHE))
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
						
						if ( !(commit_flags & UPL_COMMIT_SET_DIRTY) && (flags & IO_NOCACHE))
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

		if ( uio_resid(uio) ) {
		        if (cluster_hard_throttle_on(vp)) {
			        rd_ahead_enabled = 0;
				prefetch_enabled = 0;

				max_rd_size = HARD_THROTTLE_MAXSIZE;
			} else {
				if (rap != NULL)
				        rd_ahead_enabled = 1;
				prefetch_enabled = 1;

			        max_rd_size = MAX_UPL_TRANSFER * PAGE_SIZE;
			}
		}
	}
	if (rap != NULL) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_END,
			     (int)uio->uio_offset, uio_resid(uio), rap->cl_lastr, retval, 0);

	        lck_mtx_unlock(&rap->cl_lockr);
	} else {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 32)) | DBG_FUNC_END,
			     (int)uio->uio_offset, uio_resid(uio), 0, retval, 0);
	}

	return (retval);
}


static int
cluster_nocopy_read(vnode_t vp, struct uio *uio, off_t filesize)
{
	upl_t            upl;
	upl_page_info_t  *pl;
	vm_offset_t      upl_offset;
	off_t            max_io_size;
	int              io_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	int              i;
	int              force_data_sync;
	int              retval = 0;
	int		 no_zero_fill = 0;
	int		 abort_flag = 0;
	struct clios     iostate;
	u_int            max_rd_size  = MAX_UPL_TRANSFER * PAGE_SIZE;
	u_int            max_rd_ahead = MAX_UPL_TRANSFER * PAGE_SIZE * 2;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 70)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio_resid(uio), (int)filesize, 0, 0);

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

	while (uio_resid(uio) && uio->uio_offset < filesize && retval == 0) {
	  	user_addr_t	iov_base;

	        if (cluster_hard_throttle_on(vp)) {
		        max_rd_size  = HARD_THROTTLE_MAXSIZE;
			max_rd_ahead = HARD_THROTTLE_MAXSIZE - 1;
		} else {
		        max_rd_size  = MAX_UPL_TRANSFER * PAGE_SIZE;
			max_rd_ahead = MAX_UPL_TRANSFER * PAGE_SIZE * 8;
		}
	        max_io_size = filesize - uio->uio_offset;

	// LP64todo - fix this
		if (max_io_size < (off_t)((unsigned int)uio_resid(uio)))
		        io_size = max_io_size;
		else
		        io_size = uio_resid(uio);

		/*
		 * First look for pages already in the cache
		 * and move them to user space.
		 */
		retval = cluster_copy_ubc_data(vp, uio, &io_size, 0);
			
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

		if (max_io_size > max_rd_size)
		        max_io_size = max_rd_size;

		io_size = 0;

		ubc_range_op(vp, uio->uio_offset, uio->uio_offset + max_io_size, UPL_ROP_ABSENT, &io_size);

		if (io_size == 0)
			/*
			 * we may have already spun some portion of this request
			 * off as async requests... we need to wait for the I/O
			 * to complete before returning
			 */
			goto wait_for_reads;
		
		iov_base = uio_curriovbase(uio);

		// LP64todo - fix this!
		upl_offset = CAST_DOWN(vm_offset_t, iov_base) & PAGE_MASK;
		upl_needed_size = (upl_offset + io_size + (PAGE_SIZE -1)) & ~PAGE_MASK;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 72)) | DBG_FUNC_START,
			     (int)upl_offset, upl_needed_size, (int)iov_base, io_size, 0);

		if (upl_offset == 0 && ((io_size & PAGE_MASK) == 0)) {
		        no_zero_fill = 1;
			abort_flag = UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY;
		} else {
		        no_zero_fill = 0;
		        abort_flag = UPL_ABORT_FREE_ON_EMPTY;
		}
		for (force_data_sync = 0; force_data_sync < 3; force_data_sync++) {
		        pages_in_pl = 0;
			upl_size = upl_needed_size;
			upl_flags = UPL_FILE_IO | UPL_NO_SYNC | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;

			if (no_zero_fill)
			        upl_flags |= UPL_NOZEROFILL;
			if (force_data_sync)
			        upl_flags |= UPL_FORCE_DATA_SYNC;

			// LP64todo - fix this!
			kret = vm_map_create_upl(current_map(),
						 (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
						 &upl_size, &upl, NULL, &pages_in_pl, &upl_flags);

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

			ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, abort_flag);
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
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, abort_flag);
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
		lck_mtx_lock(cl_mtxp);

		while ((iostate.io_issued - iostate.io_completed) > max_rd_ahead) {
	                iostate.io_wanted = 1;
			msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_nocopy_read", 0);
		}	
		lck_mtx_unlock(cl_mtxp);
			
		if (iostate.io_error) {
		        /*
			 * one of the earlier reads we issued ran into a hard error
			 * don't issue any more reads, cleanup the UPL
			 * that was just created but not used, then
			 * go wait for any other reads to complete before
			 * returning the error to the caller
			 */
		        ubc_upl_abort_range(upl, (upl_offset & ~PAGE_MASK), upl_size, abort_flag);

		        goto wait_for_reads;
	        }
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 73)) | DBG_FUNC_START,
			     (int)upl, (int)upl_offset, (int)uio->uio_offset, io_size, 0);

		retval = cluster_io(vp, upl, upl_offset, uio->uio_offset, io_size,
				   CL_PRESERVE | CL_COMMIT | CL_READ | CL_ASYNC | CL_NOZERO,
				   (buf_t)NULL, &iostate);

		/*
		 * update the uio structure
		 */
		uio_update(uio, (user_size_t)io_size);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 73)) | DBG_FUNC_END,
			     (int)upl, (int)uio->uio_offset, (int)uio_resid(uio), retval, 0);

	} /* end while */

wait_for_reads:
	/*
	 * make sure all async reads that are part of this stream
	 * have completed before we return
	 */
	lck_mtx_lock(cl_mtxp);

	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_nocopy_read", 0);
	}	
	lck_mtx_unlock(cl_mtxp);

	if (iostate.io_error)
		retval = iostate.io_error;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 70)) | DBG_FUNC_END,
		     (int)uio->uio_offset, (int)uio_resid(uio), 6, retval, 0);

	return (retval);
}


static int
cluster_phys_read(vnode_t vp, struct uio *uio, off_t filesize)
{
	upl_page_info_t *pl;
	upl_t            upl;
	vm_offset_t      upl_offset;
	addr64_t	 dst_paddr;
	off_t            max_size;
	int		 io_size;
	user_size_t	 iov_len;
	user_addr_t	 iov_base;
	int              tail_size;
	int              upl_size;
	int              upl_needed_size;
	int              pages_in_pl;
	int              upl_flags;
	kern_return_t    kret;
	struct clios     iostate;
	int              error;
	int		 devblocksize;

	devblocksize = vp->v_mount->mnt_devblocksize;
	/*
	 * When we enter this routine, we know
	 *  -- the resid will not exceed iov_len
	 *  -- the target address is physically contiguous
	 */

#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	iov_len = uio_curriovlen(uio);
	iov_base = uio_curriovbase(uio);

	max_size = filesize - uio->uio_offset;

	// LP64todo - fix this!
	if (max_size < 0 || (u_int64_t)max_size > iov_len)
	        io_size = iov_len;
	else
	        io_size = max_size;

	// LP64todo - fix this!
	upl_offset = CAST_DOWN(vm_offset_t, iov_base) & PAGE_MASK;
	upl_needed_size = upl_offset + io_size;

	error       = 0;
	pages_in_pl = 0;
	upl_size = upl_needed_size;
	upl_flags = UPL_FILE_IO | UPL_NO_SYNC | UPL_CLEAN_IN_PLACE | UPL_SET_INTERNAL | UPL_SET_LITE | UPL_SET_IO_WIRE;

	kret = vm_map_get_upl(current_map(),
			      (vm_map_offset_t)(iov_base & ~((user_addr_t)PAGE_MASK)),
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

	dst_paddr = ((addr64_t)upl_phys_page(pl, 0) << 12) + (addr64_t)upl_offset;

	while (((uio->uio_offset & (devblocksize - 1)) || io_size < devblocksize) && io_size) {
	        int   head_size;

		head_size = devblocksize - (int)(uio->uio_offset & (devblocksize - 1));

		if (head_size > io_size)
		        head_size = io_size;

		error = cluster_align_phys_io(vp, uio, dst_paddr, head_size, CL_READ);

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
		lck_mtx_lock(cl_mtxp);

		while ((iostate.io_issued - iostate.io_completed) > (8 * MAX_UPL_TRANSFER * PAGE_SIZE)) {
	                iostate.io_wanted = 1;
			msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_phys_read", 0);
		}	
		lck_mtx_unlock(cl_mtxp);

	        error = cluster_io(vp, upl, upl_offset, uio->uio_offset, xsize, 
				   CL_READ | CL_NOZERO | CL_DEV_MEMORY | CL_ASYNC,
				   (buf_t)NULL, &iostate);
	        /*
		 * The cluster_io read was issued successfully,
		 * update the uio structure
		 */
		if (error == 0) {
		        uio_update(uio, (user_size_t)xsize);

			dst_paddr  += xsize;
			upl_offset += xsize;
			io_size    -= xsize;
		}
	}
	/*
	 * make sure all async reads that are part of this stream
	 * have completed before we proceed
	 */
	lck_mtx_lock(cl_mtxp);

	while (iostate.io_issued != iostate.io_completed) {
	        iostate.io_wanted = 1;
		msleep((caddr_t)&iostate.io_wanted, cl_mtxp, PRIBIO + 1, "cluster_phys_read", 0);
	}	
	lck_mtx_unlock(cl_mtxp);

	if (iostate.io_error)
	        error = iostate.io_error;

	if (error == 0 && tail_size)
	        error = cluster_align_phys_io(vp, uio, dst_paddr, tail_size, CL_READ);

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
advisory_read(vnode_t vp, off_t filesize, off_t f_offset, int resid)
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
	int              skip_range;

	if ( !UBCINFOEXISTS(vp))
		return(EINVAL);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 60)) | DBG_FUNC_START,
		     (int)f_offset, resid, (int)filesize, 0, 0);

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

		skip_range = 0;
		/*
		 * return the number of contiguously present pages in the cache
		 * starting at upl_f_offset within the file
		 */
		ubc_range_op(vp, upl_f_offset, upl_f_offset + upl_size, UPL_ROP_PRESENT, &skip_range);

		if (skip_range) {
		        /*
			 * skip over pages already present in the cache
			 */
		        io_size = skip_range - start_offset;

		        f_offset += io_size;
			resid    -= io_size;

			if (skip_range == upl_size)
			        continue;
			/*
			 * have to issue some real I/O
			 * at this point, we know it's starting on a page boundary
			 * because we've skipped over at least the first page in the request
			 */
			start_offset = 0;
			upl_f_offset += skip_range;
			upl_size     -= skip_range;
		}
		pages_in_upl = upl_size / PAGE_SIZE;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 61)) | DBG_FUNC_START,
			     (int)upl, (int)upl_f_offset, upl_size, start_offset, 0);

		kret = ubc_create_upl(vp, 
				      upl_f_offset,
				      upl_size,
				      &upl,
				      &pl,
				      UPL_RET_ONLY_ABSENT | UPL_SET_LITE);
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


		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 61)) | DBG_FUNC_END,
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
				retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, io_size,
						    CL_ASYNC | CL_READ | CL_COMMIT | CL_AGE, (buf_t)NULL, (struct clios *)NULL);

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
cluster_push(vnode_t vp, int flags)
{
        int	retval;
	struct	cl_writebehind *wbp;

	if ( !UBCINFOEXISTS(vp)) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_NONE, (int)vp, flags, 0, -1, 0);
	        return (0);
	}
	/* return if deferred write is set */
	if (((unsigned int)vfs_flags(vp->v_mount) & MNT_DEFWRITE) && (flags & IO_DEFWRITE)) {
		return (0);
	}
	if ((wbp = cluster_get_wbp(vp, CLW_RETURNLOCKED)) == NULL) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_NONE, (int)vp, flags, 0, -2, 0);
	        return (0);
	}
	if (wbp->cl_number == 0 && wbp->cl_scmap == NULL) {
	        lck_mtx_unlock(&wbp->cl_lockw);

	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_NONE, (int)vp, flags, 0, -3, 0);
		return(0);
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_START,
		     (int)wbp->cl_scmap, wbp->cl_number, flags, 0, 0);

	if (wbp->cl_scmap) {
	        sparse_cluster_push(wbp, vp, ubc_getsize(vp), 1);

		retval = 1;
	} else 
	        retval = cluster_try_push(wbp, vp, ubc_getsize(vp), 0, 1);

	lck_mtx_unlock(&wbp->cl_lockw);

	if (flags & IO_SYNC)
	        (void)vnode_waitforwrites(vp, 0, 0, 0, (char *)"cluster_push");

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_END,
		     (int)wbp->cl_scmap, wbp->cl_number, retval, 0, 0);

	return (retval);
}


__private_extern__ void
cluster_release(struct ubc_info *ubc)
{
        struct cl_writebehind *wbp;
	struct cl_readahead   *rap;

	if ((wbp = ubc->cl_wbehind)) {

	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 81)) | DBG_FUNC_START, (int)ubc, (int)wbp->cl_scmap, wbp->cl_scdirty, 0, 0);

		if (wbp->cl_scmap)
		        vfs_drt_control(&(wbp->cl_scmap), 0);
	} else {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 81)) | DBG_FUNC_START, (int)ubc, 0, 0, 0, 0);
	}

	rap = ubc->cl_rahead;

	if (wbp != NULL) {
	        lck_mtx_destroy(&wbp->cl_lockw, cl_mtx_grp);
	        FREE_ZONE((void *)wbp, sizeof *wbp, M_CLWRBEHIND);
	}
	if ((rap = ubc->cl_rahead)) {
	        lck_mtx_destroy(&rap->cl_lockr, cl_mtx_grp);
	        FREE_ZONE((void *)rap, sizeof *rap, M_CLRDAHEAD);
	}
	ubc->cl_rahead  = NULL;
	ubc->cl_wbehind = NULL;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 81)) | DBG_FUNC_END, (int)ubc, (int)rap, (int)wbp, 0, 0);
}


static void
cluster_push_EOF(vnode_t vp, off_t EOF)
{
        struct cl_writebehind *wbp;

	wbp = cluster_get_wbp(vp, CLW_ALLOCATE | CLW_RETURNLOCKED);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_START,
		     (int)wbp->cl_scmap, wbp->cl_number, (int)EOF, 0, 0);

	if (wbp->cl_scmap)
	        sparse_cluster_push(wbp, vp, EOF, 1);
	else 
	        cluster_try_push(wbp, vp, EOF, 0, 1);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 53)) | DBG_FUNC_END,
		     (int)wbp->cl_scmap, wbp->cl_number, 0, 0, 0);

	lck_mtx_unlock(&wbp->cl_lockw);
}


static int
cluster_try_push(struct cl_writebehind *wbp, vnode_t vp, off_t EOF, int can_delay, int push_all)
{
        int cl_index;
	int cl_index1;
	int min_index;
        int cl_len;
	int cl_pushed = 0;
	struct cl_wextent l_clusters[MAX_CLUSTERS];

	/*
	 * the write behind context exists and has
	 * already been locked...
	 *
	 * make a local 'sorted' copy of the clusters
	 * and clear wbp->cl_number so that new clusters can
	 * be developed
	 */
	for (cl_index = 0; cl_index < wbp->cl_number; cl_index++) {
	        for (min_index = -1, cl_index1 = 0; cl_index1 < wbp->cl_number; cl_index1++) {
		        if (wbp->cl_clusters[cl_index1].b_addr == wbp->cl_clusters[cl_index1].e_addr)
			        continue;
			if (min_index == -1)
			        min_index = cl_index1;
			else if (wbp->cl_clusters[cl_index1].b_addr < wbp->cl_clusters[min_index].b_addr)
			        min_index = cl_index1;
		}
		if (min_index == -1)
		        break;
	        l_clusters[cl_index].b_addr = wbp->cl_clusters[min_index].b_addr;
		l_clusters[cl_index].e_addr = wbp->cl_clusters[min_index].e_addr;
		l_clusters[cl_index].io_nocache = wbp->cl_clusters[min_index].io_nocache;

	        wbp->cl_clusters[min_index].b_addr = wbp->cl_clusters[min_index].e_addr;
	}
	wbp->cl_number = 0;

	cl_len = cl_index;

	if (can_delay && cl_len == MAX_CLUSTERS) {
		int   i;
		
		/*
		 * determine if we appear to be writing the file sequentially
		 * if not, by returning without having pushed any clusters
		 * we will cause this vnode to be pushed into the sparse cluster mechanism
		 * used for managing more random I/O patterns
		 *
		 * we know that we've got all clusters currently in use and the next write doesn't fit into one of them...
		 * that's why we're in try_push with can_delay true...
		 *
		 * check to make sure that all the clusters except the last one are 'full'... and that each cluster
		 * is adjacent to the next (i.e. we're looking for sequential writes) they were sorted above
		 * so we can just make a simple pass through, up to, but not including the last one...
		 * note that e_addr is not inclusive, so it will be equal to the b_addr of the next cluster if they
		 * are sequential
		 * 
		 * we let the last one be partial as long as it was adjacent to the previous one...
		 * we need to do this to deal with multi-threaded servers that might write an I/O or 2 out
		 * of order... if this occurs at the tail of the last cluster, we don't want to fall into the sparse cluster world...
		 */
		for (i = 0; i < MAX_CLUSTERS - 1; i++) {
		        if ((l_clusters[i].e_addr - l_clusters[i].b_addr) != MAX_UPL_TRANSFER)
			        goto dont_try;
			if (l_clusters[i].e_addr != l_clusters[i+1].b_addr)
		                goto dont_try;
		}
	}
	/*
	 * drop the lock while we're firing off the I/Os...
	 * this is safe since I'm working off of a private sorted copy
	 * of the clusters, and I'm going to re-evaluate the public
	 * state after I retake the lock
	 */
	lck_mtx_unlock(&wbp->cl_lockw);

	for (cl_index = 0; cl_index < cl_len; cl_index++) {
	        int flags;
		struct cl_extent cl;

	        /*
		 * try to push each cluster in turn...
		 */
		if (l_clusters[cl_index].io_nocache)
		        flags = IO_NOCACHE;
		else
		        flags = 0;
		cl.b_addr = l_clusters[cl_index].b_addr;
		cl.e_addr = l_clusters[cl_index].e_addr;

	        cluster_push_x(vp, &cl, EOF, flags);

		l_clusters[cl_index].b_addr = 0;
		l_clusters[cl_index].e_addr = 0;

		cl_pushed++;

		if (push_all == 0)
		        break;
	}
	lck_mtx_lock(&wbp->cl_lockw);

dont_try:
	if (cl_len > cl_pushed) {
	       /*
		* we didn't push all of the clusters, so
		* lets try to merge them back in to the vnode
		*/
	        if ((MAX_CLUSTERS - wbp->cl_number) < (cl_len - cl_pushed)) {
		        /*
			 * we picked up some new clusters while we were trying to
			 * push the old ones... this can happen because I've dropped
			 * the vnode lock... the sum of the
			 * leftovers plus the new cluster count exceeds our ability
			 * to represent them, so switch to the sparse cluster mechanism
			 *
			 * collect the active public clusters...
			 */
		        sparse_cluster_switch(wbp, vp, EOF);

		        for (cl_index = 0, cl_index1 = 0; cl_index < cl_len; cl_index++) {
			        if (l_clusters[cl_index].b_addr == l_clusters[cl_index].e_addr)
				        continue;
			        wbp->cl_clusters[cl_index1].b_addr = l_clusters[cl_index].b_addr;
				wbp->cl_clusters[cl_index1].e_addr = l_clusters[cl_index].e_addr;
				wbp->cl_clusters[cl_index1].io_nocache = l_clusters[cl_index].io_nocache;

				cl_index1++;
			}
			/*
			 * update the cluster count
			 */
			wbp->cl_number = cl_index1;

		        /*
			 * and collect the original clusters that were moved into the 
			 * local storage for sorting purposes
			 */
		        sparse_cluster_switch(wbp, vp, EOF);

		} else {
		        /*
			 * we've got room to merge the leftovers back in
			 * just append them starting at the next 'hole'
			 * represented by wbp->cl_number
			 */
		        for (cl_index = 0, cl_index1 = wbp->cl_number; cl_index < cl_len; cl_index++) {
			        if (l_clusters[cl_index].b_addr == l_clusters[cl_index].e_addr)
				        continue;

			        wbp->cl_clusters[cl_index1].b_addr = l_clusters[cl_index].b_addr;
				wbp->cl_clusters[cl_index1].e_addr = l_clusters[cl_index].e_addr;
				wbp->cl_clusters[cl_index1].io_nocache = l_clusters[cl_index].io_nocache;

				cl_index1++;
			}
			/*
			 * update the cluster count
			 */
			wbp->cl_number = cl_index1;
		}
	}
	return(MAX_CLUSTERS - wbp->cl_number);
}



static int
cluster_push_x(vnode_t vp, struct cl_extent *cl, off_t EOF, int flags)
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
	int              upl_flags;
	int              size;
	int              error = 0;
	int              retval;
	kern_return_t    kret;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_START,
		     (int)cl->b_addr, (int)cl->e_addr, (int)EOF, flags, 0);

	if ((pages_in_upl = (int)(cl->e_addr - cl->b_addr)) == 0) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 0, 0, 0, 0);

	        return (0);
	}
	upl_size = pages_in_upl * PAGE_SIZE;
	upl_f_offset = (off_t)(cl->b_addr * PAGE_SIZE_64);

	if (upl_f_offset + upl_size >= EOF) {

	        if (upl_f_offset >= EOF) {
		        /*
			 * must have truncated the file and missed 
			 * clearing a dangling cluster (i.e. it's completely
			 * beyond the new EOF
			 */
		        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 1, 0, 0, 0);

		        return(0);
		}
		size = EOF - upl_f_offset;

		upl_size = (size + (PAGE_SIZE - 1)) & ~PAGE_MASK;
		pages_in_upl = upl_size / PAGE_SIZE;
	} else
	        size = upl_size;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 41)) | DBG_FUNC_START, upl_size, size, 0, 0, 0);

	/*
	 * by asking for UPL_COPYOUT_FROM and UPL_RET_ONLY_DIRTY, we get the following desirable behavior
	 * 
	 * - only pages that are currently dirty are returned... these are the ones we need to clean
	 * - the hardware dirty bit is cleared when the page is gathered into the UPL... the software dirty bit is set
	 * - if we have to abort the I/O for some reason, the software dirty bit is left set since we didn't clean the page
	 * - when we commit the page, the software dirty bit is cleared... the hardware dirty bit is untouched so that if 
	 *   someone dirties this page while the I/O is in progress, we don't lose track of the new state
	 *
	 * when the I/O completes, we no longer ask for an explicit clear of the DIRTY state (either soft or hard)
	 */

	if ((vp->v_flag & VNOCACHE_DATA) || (flags & IO_NOCACHE))
	        upl_flags = UPL_COPYOUT_FROM | UPL_RET_ONLY_DIRTY | UPL_SET_LITE | UPL_WILL_BE_DUMPED;
	else
	        upl_flags = UPL_COPYOUT_FROM | UPL_RET_ONLY_DIRTY | UPL_SET_LITE;

	kret = ubc_create_upl(vp, 
			      	upl_f_offset,
			      	upl_size,
			      	&upl,
			        &pl,
			        upl_flags);
	if (kret != KERN_SUCCESS)
	        panic("cluster_push: failed to get pagelist");

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 41)) | DBG_FUNC_END, (int)upl, upl_f_offset, 0, 0, 0);

	/*
	 * since we only asked for the dirty pages back
	 * it's possible that we may only get a few or even none, so...
	 * before we start marching forward, we must make sure we know
	 * where the last present page is in the UPL, otherwise we could
	 * end up working with a freed upl due to the FREE_ON_EMPTY semantics
	 * employed by commit_range and abort_range.
	 */
	for (last_pg = pages_in_upl - 1; last_pg >= 0; last_pg--) {
	        if (upl_page_present(pl, last_pg))
		        break;
	}
	pages_in_upl = last_pg + 1;

	if (pages_in_upl == 0) {
	        ubc_upl_abort(upl, 0);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 2, 0, 0, 0);
		return(0);
	}	  

	for (last_pg = 0; last_pg < pages_in_upl; ) {
	        /*
		 * find the next dirty page in the UPL
		 * this will become the first page in the 
		 * next I/O to generate
		 */
		for (start_pg = last_pg; start_pg < pages_in_upl; start_pg++) {
			if (upl_dirty_page(pl, start_pg))
				break;
			if (upl_page_present(pl, start_pg))
			        /*
				 * RET_ONLY_DIRTY will return non-dirty 'precious' pages
				 * just release these unchanged since we're not going
				 * to steal them or change their state
				 */
			        ubc_upl_abort_range(upl, start_pg * PAGE_SIZE, PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);
		}
		if (start_pg >= pages_in_upl)
		        /*
			 * done... no more dirty pages to push
			 */
		        break;
		if (start_pg > last_pg)
		        /*
			 * skipped over some non-dirty pages
			 */
			size -= ((start_pg - last_pg) * PAGE_SIZE);

		/*
		 * find a range of dirty pages to write
		 */
		for (last_pg = start_pg; last_pg < pages_in_upl; last_pg++) {
			if (!upl_dirty_page(pl, last_pg))
				break;
		}
		upl_offset = start_pg * PAGE_SIZE;

		io_size = min(size, (last_pg - start_pg) * PAGE_SIZE);

		io_flags = CL_THROTTLE | CL_COMMIT;

		if ( !(flags & IO_SYNC))
		        io_flags |= CL_ASYNC;

		retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, io_size,
				    io_flags, (buf_t)NULL, (struct clios *)NULL);

		if (error == 0 && retval)
		        error = retval;

		size -= io_size;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 51)) | DBG_FUNC_END, 1, 3, 0, 0, 0);

	return(error);
}


/*
 * sparse_cluster_switch is called with the write behind lock held
 */
static void
sparse_cluster_switch(struct cl_writebehind *wbp, vnode_t vp, off_t EOF)
{
        int	cl_index;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 78)) | DBG_FUNC_START, (int)vp, (int)wbp->cl_scmap, wbp->cl_scdirty, 0, 0);

	if (wbp->cl_scmap == NULL)
	        wbp->cl_scdirty = 0;

	for (cl_index = 0; cl_index < wbp->cl_number; cl_index++) {
	        int	  flags;
		struct cl_extent cl;

	        for (cl.b_addr = wbp->cl_clusters[cl_index].b_addr; cl.b_addr < wbp->cl_clusters[cl_index].e_addr; cl.b_addr++) {

		        if (ubc_page_op(vp, (off_t)(cl.b_addr * PAGE_SIZE_64), 0, 0, &flags) == KERN_SUCCESS) {
			        if (flags & UPL_POP_DIRTY) {
				        cl.e_addr = cl.b_addr + 1;

				        sparse_cluster_add(wbp, vp, &cl, EOF);
				}
			}
		}
	}
	wbp->cl_number = 0;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 78)) | DBG_FUNC_END, (int)vp, (int)wbp->cl_scmap, wbp->cl_scdirty, 0, 0);
}


/*
 * sparse_cluster_push is called with the write behind lock held
 */
static void
sparse_cluster_push(struct cl_writebehind *wbp, vnode_t vp, off_t EOF, int push_all)
{
        struct cl_extent cl;
        off_t		offset;
	u_int		length;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 79)) | DBG_FUNC_START, (int)vp, (int)wbp->cl_scmap, wbp->cl_scdirty, push_all, 0);

	if (push_all)
	        vfs_drt_control(&(wbp->cl_scmap), 1);

	for (;;) {
	        if (vfs_drt_get_cluster(&(wbp->cl_scmap), &offset, &length) != KERN_SUCCESS)
			break;

		cl.b_addr = (daddr64_t)(offset / PAGE_SIZE_64);
		cl.e_addr = (daddr64_t)((offset + length) / PAGE_SIZE_64);

		wbp->cl_scdirty -= (int)(cl.e_addr - cl.b_addr);

		cluster_push_x(vp, &cl, EOF, 0);

		if (push_all == 0)
		        break;
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 79)) | DBG_FUNC_END, (int)vp, (int)wbp->cl_scmap, wbp->cl_scdirty, 0, 0);
}


/*
 * sparse_cluster_add is called with the write behind lock held
 */
static void
sparse_cluster_add(struct cl_writebehind *wbp, vnode_t vp, struct cl_extent *cl, off_t EOF)
{
        u_int	new_dirty;
	u_int	length;
	off_t	offset;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 80)) | DBG_FUNC_START, (int)wbp->cl_scmap, wbp->cl_scdirty, (int)cl->b_addr, (int)cl->e_addr, 0);

	offset = (off_t)(cl->b_addr * PAGE_SIZE_64);
	length = ((u_int)(cl->e_addr - cl->b_addr)) * PAGE_SIZE;

	while (vfs_drt_mark_pages(&(wbp->cl_scmap), offset, length, &new_dirty) != KERN_SUCCESS) {
	        /*
		 * no room left in the map
		 * only a partial update was done
		 * push out some pages and try again
		 */
	        wbp->cl_scdirty += new_dirty;

	        sparse_cluster_push(wbp, vp, EOF, 0);

		offset += (new_dirty * PAGE_SIZE_64);
		length -= (new_dirty * PAGE_SIZE);
	}
	wbp->cl_scdirty += new_dirty;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 80)) | DBG_FUNC_END, (int)vp, (int)wbp->cl_scmap, wbp->cl_scdirty, 0, 0);
}


static int
cluster_align_phys_io(vnode_t vp, struct uio *uio, addr64_t usr_paddr, int xsize, int flags)
{
        upl_page_info_t  *pl;
        upl_t            upl;
        addr64_t	 ubc_paddr;
        kern_return_t    kret;
        int              error = 0;
	int		 did_read = 0;
	int		 abort_flags;
	int		 upl_flags;

	upl_flags = UPL_SET_LITE;
	if (! (flags & CL_READ)) {
		/*
		 * "write" operation:  let the UPL subsystem know
		 * that we intend to modify the buffer cache pages
		 * we're gathering.
		 */
		upl_flags |= UPL_WILL_MODIFY;
	}

        kret = ubc_create_upl(vp,
                              uio->uio_offset & ~PAGE_MASK_64,
                              PAGE_SIZE,
                              &upl,
                              &pl,
                              upl_flags);

        if (kret != KERN_SUCCESS)
                return(EINVAL);

        if (!upl_valid_page(pl, 0)) {
                /*
                 * issue a synchronous read to cluster_io
                 */
                error = cluster_io(vp, upl, 0, uio->uio_offset & ~PAGE_MASK_64, PAGE_SIZE,
				   CL_READ, (buf_t)NULL, (struct clios *)NULL);
                if (error) {
                          ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_DUMP_PAGES | UPL_ABORT_FREE_ON_EMPTY);

                          return(error);
                }
		did_read = 1;
        }
        ubc_paddr = ((addr64_t)upl_phys_page(pl, 0) << 12) + (addr64_t)(uio->uio_offset & PAGE_MASK_64);

/*
 *	NOTE:  There is no prototype for the following in BSD. It, and the definitions
 *	of the defines for cppvPsrc, cppvPsnk, cppvFsnk, and cppvFsrc will be found in
 *	osfmk/ppc/mappings.h.  They are not included here because there appears to be no
 *	way to do so without exporting them to kexts as well.
 */
	if (flags & CL_READ)
//		copypv(ubc_paddr, usr_paddr, xsize, cppvPsrc | cppvPsnk | cppvFsnk);	/* Copy physical to physical and flush the destination */
		copypv(ubc_paddr, usr_paddr, xsize,        2 |        1 |        4);	/* Copy physical to physical and flush the destination */
	else
//		copypv(usr_paddr, ubc_paddr, xsize, cppvPsrc | cppvPsnk | cppvFsrc);	/* Copy physical to physical and flush the source */
		copypv(usr_paddr, ubc_paddr, xsize,        2 |        1 |        8);	/* Copy physical to physical and flush the source */
	
	if ( !(flags & CL_READ) || (upl_valid_page(pl, 0) && upl_dirty_page(pl, 0))) {
	        /*
		 * issue a synchronous write to cluster_io
		 */
		error = cluster_io(vp, upl, 0, uio->uio_offset & ~PAGE_MASK_64, PAGE_SIZE,
					0, (buf_t)NULL, (struct clios *)NULL);
	}
	if (error == 0)
	        uio_update(uio, (user_size_t)xsize);

	if (did_read)
	        abort_flags = UPL_ABORT_FREE_ON_EMPTY;
	else
	        abort_flags = UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_DUMP_PAGES;

	ubc_upl_abort_range(upl, 0, PAGE_SIZE, abort_flags);
	
	return (error);
}



int
cluster_copy_upl_data(struct uio *uio, upl_t upl, int upl_offset, int xsize)
{
        int       pg_offset;
	int       pg_index;
        int   	  csize;
	int       segflg;
	int       retval = 0;
	upl_page_info_t *pl;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio_resid(uio), upl_offset, xsize, 0);

	segflg = uio->uio_segflg;

	switch(segflg) {

	  case UIO_USERSPACE32:
	  case UIO_USERISPACE32:
		uio->uio_segflg = UIO_PHYS_USERSPACE32;
		break;

	  case UIO_USERSPACE:
	  case UIO_USERISPACE:
		uio->uio_segflg = UIO_PHYS_USERSPACE;
		break;

	  case UIO_USERSPACE64:
	  case UIO_USERISPACE64:
		uio->uio_segflg = UIO_PHYS_USERSPACE64;
		break;

	  case UIO_SYSSPACE32:
		uio->uio_segflg = UIO_PHYS_SYSSPACE32;
		break;

	  case UIO_SYSSPACE:
		uio->uio_segflg = UIO_PHYS_SYSSPACE;
		break;

	  case UIO_SYSSPACE64:
		uio->uio_segflg = UIO_PHYS_SYSSPACE64;
		break;
	}
	pl = ubc_upl_pageinfo(upl);

	pg_index  = upl_offset / PAGE_SIZE;
	pg_offset = upl_offset & PAGE_MASK;
	csize     = min(PAGE_SIZE - pg_offset, xsize);

	while (xsize && retval == 0) {
	        addr64_t  paddr;

		paddr = ((addr64_t)upl_phys_page(pl, pg_index) << 12) + pg_offset;

		retval = uiomove64(paddr, csize, uio);

		pg_index += 1;
		pg_offset = 0;
		xsize    -= csize;
		csize     = min(PAGE_SIZE, xsize);
	}
	uio->uio_segflg = segflg;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_END,
		     (int)uio->uio_offset, uio_resid(uio), retval, segflg, 0);

	return (retval);
}


int
cluster_copy_ubc_data(vnode_t vp, struct uio *uio, int *io_resid, int mark_dirty)
{
	int       segflg;
	int       io_size;
	int       xsize;
	int       start_offset;
	int       retval = 0;
	memory_object_control_t	 control;


	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_START,
		     (int)uio->uio_offset, uio_resid(uio), 0, *io_resid, 0);

	control = ubc_getobject(vp, UBC_FLAGS_NONE);
	if (control == MEMORY_OBJECT_CONTROL_NULL) {
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_END,
			     (int)uio->uio_offset, uio_resid(uio), retval, 3, 0);

		return(0);
	}
	segflg = uio->uio_segflg;

	switch(segflg) {

	  case UIO_USERSPACE32:
	  case UIO_USERISPACE32:
		uio->uio_segflg = UIO_PHYS_USERSPACE32;
		break;

	  case UIO_USERSPACE64:
	  case UIO_USERISPACE64:
		uio->uio_segflg = UIO_PHYS_USERSPACE64;
		break;

	  case UIO_SYSSPACE32:
		uio->uio_segflg = UIO_PHYS_SYSSPACE32;
		break;

	  case UIO_SYSSPACE64:
		uio->uio_segflg = UIO_PHYS_SYSSPACE64;
		break;

	  case UIO_USERSPACE:
	  case UIO_USERISPACE:
		uio->uio_segflg = UIO_PHYS_USERSPACE;
		break;

	  case UIO_SYSSPACE:
		uio->uio_segflg = UIO_PHYS_SYSSPACE;
		break;
	}

	if ( (io_size = *io_resid) ) {
	        start_offset = (int)(uio->uio_offset & PAGE_MASK_64);
		xsize = uio_resid(uio);

		retval = memory_object_control_uiomove(control, uio->uio_offset - start_offset,
						       uio, start_offset, io_size, mark_dirty);
		xsize -= uio_resid(uio);
		io_size -= xsize;
	}
	uio->uio_segflg = segflg;
	*io_resid       = io_size;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 34)) | DBG_FUNC_END,
		     (int)uio->uio_offset, uio_resid(uio), retval, 0x80000000 | segflg, 0);

	return(retval);
}


int
is_file_clean(vnode_t vp, off_t filesize)
{
        off_t f_offset;
	int   flags;
	int   total_dirty = 0;

	for (f_offset = 0; f_offset < filesize; f_offset += PAGE_SIZE_64) {
	        if (ubc_page_op(vp, f_offset, 0, 0, &flags) == KERN_SUCCESS) {
		        if (flags & UPL_POP_DIRTY) {
			        total_dirty++;
			}
		}
	}
	if (total_dirty)
	        return(EINVAL);

	return (0);
}



/*
 * Dirty region tracking/clustering mechanism.
 *
 * This code (vfs_drt_*) provides a mechanism for tracking and clustering
 * dirty regions within a larger space (file).  It is primarily intended to
 * support clustering in large files with many dirty areas.
 *
 * The implementation assumes that the dirty regions are pages.
 *
 * To represent dirty pages within the file, we store bit vectors in a
 * variable-size circular hash.
 */

/*
 * Bitvector size.  This determines the number of pages we group in a
 * single hashtable entry.  Each hashtable entry is aligned to this
 * size within the file.
 */
#define DRT_BITVECTOR_PAGES		256

/*
 * File offset handling.
 *
 * DRT_ADDRESS_MASK is dependent on DRT_BITVECTOR_PAGES;
 * the correct formula is  (~(DRT_BITVECTOR_PAGES * PAGE_SIZE) - 1)
 */
#define DRT_ADDRESS_MASK		(~((1 << 20) - 1))
#define DRT_ALIGN_ADDRESS(addr)		((addr) & DRT_ADDRESS_MASK)

/*
 * Hashtable address field handling.
 *
 * The low-order bits of the hashtable address are used to conserve
 * space.
 *
 * DRT_HASH_COUNT_MASK must be large enough to store the range
 * 0-DRT_BITVECTOR_PAGES inclusive, as well as have one value
 * to indicate that the bucket is actually unoccupied.
 */
#define DRT_HASH_GET_ADDRESS(scm, i)	((scm)->scm_hashtable[(i)].dhe_control & DRT_ADDRESS_MASK)
#define DRT_HASH_SET_ADDRESS(scm, i, a)									\
	do {												\
		(scm)->scm_hashtable[(i)].dhe_control =							\
		    ((scm)->scm_hashtable[(i)].dhe_control & ~DRT_ADDRESS_MASK) | DRT_ALIGN_ADDRESS(a);	\
	} while (0)
#define DRT_HASH_COUNT_MASK		0x1ff
#define DRT_HASH_GET_COUNT(scm, i)	((scm)->scm_hashtable[(i)].dhe_control & DRT_HASH_COUNT_MASK)
#define DRT_HASH_SET_COUNT(scm, i, c)											\
	do {														\
		(scm)->scm_hashtable[(i)].dhe_control =									\
		    ((scm)->scm_hashtable[(i)].dhe_control & ~DRT_HASH_COUNT_MASK) | ((c) & DRT_HASH_COUNT_MASK);	\
	} while (0)
#define DRT_HASH_CLEAR(scm, i)                                                                                          \
	do {														\
		(scm)->scm_hashtable[(i)].dhe_control =	0;								\
	} while (0)
#define DRT_HASH_VACATE(scm, i)		DRT_HASH_SET_COUNT((scm), (i), DRT_HASH_COUNT_MASK)
#define DRT_HASH_VACANT(scm, i)		(DRT_HASH_GET_COUNT((scm), (i)) == DRT_HASH_COUNT_MASK)
#define DRT_HASH_COPY(oscm, oi, scm, i)									\
	do {												\
		(scm)->scm_hashtable[(i)].dhe_control = (oscm)->scm_hashtable[(oi)].dhe_control;	\
		DRT_BITVECTOR_COPY(oscm, oi, scm, i);							\
	} while(0);


/*
 * Hash table moduli.
 *
 * Since the hashtable entry's size is dependent on the size of
 * the bitvector, and since the hashtable size is constrained to
 * both being prime and fitting within the desired allocation
 * size, these values need to be manually determined.
 *
 * For DRT_BITVECTOR_SIZE = 256, the entry size is 40 bytes.
 *
 * The small hashtable allocation is 1024 bytes, so the modulus is 23.
 * The large hashtable allocation is 16384 bytes, so the modulus is 401.
 */
#define DRT_HASH_SMALL_MODULUS	23
#define DRT_HASH_LARGE_MODULUS	401

#define DRT_SMALL_ALLOCATION	1024	/* 104 bytes spare */
#define DRT_LARGE_ALLOCATION	16384	/* 344 bytes spare */

/* *** nothing below here has secret dependencies on DRT_BITVECTOR_PAGES *** */

/*
 * Hashtable bitvector handling.
 *
 * Bitvector fields are 32 bits long.
 */

#define DRT_HASH_SET_BIT(scm, i, bit)				\
	(scm)->scm_hashtable[(i)].dhe_bitvector[(bit) / 32] |= (1 << ((bit) % 32))

#define DRT_HASH_CLEAR_BIT(scm, i, bit)				\
	(scm)->scm_hashtable[(i)].dhe_bitvector[(bit) / 32] &= ~(1 << ((bit) % 32))
    
#define DRT_HASH_TEST_BIT(scm, i, bit) 				\
	((scm)->scm_hashtable[(i)].dhe_bitvector[(bit) / 32] & (1 << ((bit) % 32)))
    
#define DRT_BITVECTOR_CLEAR(scm, i) 				\
	bzero(&(scm)->scm_hashtable[(i)].dhe_bitvector[0], (DRT_BITVECTOR_PAGES / 32) * sizeof(u_int32_t))

#define DRT_BITVECTOR_COPY(oscm, oi, scm, i)			\
	bcopy(&(oscm)->scm_hashtable[(oi)].dhe_bitvector[0],	\
	    &(scm)->scm_hashtable[(i)].dhe_bitvector[0],	\
	    (DRT_BITVECTOR_PAGES / 32) * sizeof(u_int32_t))


 
/*
 * Hashtable entry.
 */
struct vfs_drt_hashentry {
	u_int64_t	dhe_control;
	u_int32_t	dhe_bitvector[DRT_BITVECTOR_PAGES / 32];
};

/*
 * Dirty Region Tracking structure.
 *
 * The hashtable is allocated entirely inside the DRT structure.
 *
 * The hash is a simple circular prime modulus arrangement, the structure
 * is resized from small to large if it overflows.
 */

struct vfs_drt_clustermap {
	u_int32_t		scm_magic;	/* sanity/detection */
#define DRT_SCM_MAGIC		0x12020003
	u_int32_t		scm_modulus;	/* current ring size */
	u_int32_t		scm_buckets;	/* number of occupied buckets */
	u_int32_t		scm_lastclean;	/* last entry we cleaned */
	u_int32_t		scm_iskips;	/* number of slot skips */

	struct vfs_drt_hashentry scm_hashtable[0];
};


#define DRT_HASH(scm, addr)		((addr) % (scm)->scm_modulus)
#define DRT_HASH_NEXT(scm, addr)	(((addr) + 1) % (scm)->scm_modulus)

/*
 * Debugging codes and arguments.
 */
#define DRT_DEBUG_EMPTYFREE	(FSDBG_CODE(DBG_FSRW, 82)) /* nil */
#define DRT_DEBUG_RETCLUSTER	(FSDBG_CODE(DBG_FSRW, 83)) /* offset, length */
#define DRT_DEBUG_ALLOC		(FSDBG_CODE(DBG_FSRW, 84)) /* copycount */
#define DRT_DEBUG_INSERT	(FSDBG_CODE(DBG_FSRW, 85)) /* offset, iskip */
#define DRT_DEBUG_MARK		(FSDBG_CODE(DBG_FSRW, 86)) /* offset, length,
							    * dirty */
							   /* 0, setcount */
							   /* 1 (clean, no map) */
							   /* 2 (map alloc fail) */
							   /* 3, resid (partial) */
#define DRT_DEBUG_6		(FSDBG_CODE(DBG_FSRW, 87))
#define DRT_DEBUG_SCMDATA	(FSDBG_CODE(DBG_FSRW, 88)) /* modulus, buckets,
							    * lastclean, iskips */


static kern_return_t	vfs_drt_alloc_map(struct vfs_drt_clustermap **cmapp);
static kern_return_t	vfs_drt_free_map(struct vfs_drt_clustermap *cmap);
static kern_return_t	vfs_drt_search_index(struct vfs_drt_clustermap *cmap,
	u_int64_t offset, int *indexp);
static kern_return_t	vfs_drt_get_index(struct vfs_drt_clustermap **cmapp,
	u_int64_t offset,
	int *indexp,
	int recursed);
static kern_return_t	vfs_drt_do_mark_pages(
	void		**cmapp,
	u_int64_t	offset,
	u_int    	length,
	int		*setcountp,
	int		dirty);
static void		vfs_drt_trace(
	struct vfs_drt_clustermap *cmap,
	int code,
	int arg1,
	int arg2,
	int arg3,
	int arg4);


/*
 * Allocate and initialise a sparse cluster map.
 *
 * Will allocate a new map, resize or compact an existing map.
 *
 * XXX we should probably have at least one intermediate map size,
 * as the 1:16 ratio seems a bit drastic.
 */
static kern_return_t
vfs_drt_alloc_map(struct vfs_drt_clustermap **cmapp)
{
	struct vfs_drt_clustermap *cmap, *ocmap;
	kern_return_t	kret;
	u_int64_t	offset;
	int		nsize, i, active_buckets, index, copycount;

	ocmap = NULL;
	if (cmapp != NULL)
		ocmap = *cmapp;
	
	/*
	 * Decide on the size of the new map.
	 */
	if (ocmap == NULL) {
		nsize = DRT_HASH_SMALL_MODULUS;
	} else {
		/* count the number of active buckets in the old map */
		active_buckets = 0;
		for (i = 0; i < ocmap->scm_modulus; i++) {
			if (!DRT_HASH_VACANT(ocmap, i) &&
			    (DRT_HASH_GET_COUNT(ocmap, i) != 0))
				active_buckets++;
		}
		/*
		 * If we're currently using the small allocation, check to
		 * see whether we should grow to the large one.
		 */
		if (ocmap->scm_modulus == DRT_HASH_SMALL_MODULUS) {
			/* if the ring is nearly full */
			if (active_buckets > (DRT_HASH_SMALL_MODULUS - 5)) {
				nsize = DRT_HASH_LARGE_MODULUS;
			} else {
				nsize = DRT_HASH_SMALL_MODULUS;
			}
		} else {
			/* already using the large modulus */
			nsize = DRT_HASH_LARGE_MODULUS;
			/*
			 * If the ring is completely full, there's
			 * nothing useful for us to do.  Behave as
			 * though we had compacted into the new
			 * array and return.
			 */
			if (active_buckets >= DRT_HASH_LARGE_MODULUS)
				return(KERN_SUCCESS);
		}
	}

	/*
	 * Allocate and initialise the new map.
	 */

	kret = kmem_alloc(kernel_map, (vm_offset_t *)&cmap,
	    (nsize == DRT_HASH_SMALL_MODULUS) ? DRT_SMALL_ALLOCATION : DRT_LARGE_ALLOCATION);
	if (kret != KERN_SUCCESS)
		return(kret);
	cmap->scm_magic = DRT_SCM_MAGIC;
	cmap->scm_modulus = nsize;
	cmap->scm_buckets = 0;
	cmap->scm_lastclean = 0;
	cmap->scm_iskips = 0;
	for (i = 0; i < cmap->scm_modulus; i++) {
	        DRT_HASH_CLEAR(cmap, i);
		DRT_HASH_VACATE(cmap, i);
		DRT_BITVECTOR_CLEAR(cmap, i);
	}

	/*
	 * If there's an old map, re-hash entries from it into the new map.
	 */
	copycount = 0;
	if (ocmap != NULL) {
		for (i = 0; i < ocmap->scm_modulus; i++) {
			/* skip empty buckets */
			if (DRT_HASH_VACANT(ocmap, i) ||
			    (DRT_HASH_GET_COUNT(ocmap, i) == 0))
				continue;
			/* get new index */
			offset = DRT_HASH_GET_ADDRESS(ocmap, i);
			kret = vfs_drt_get_index(&cmap, offset, &index, 1);
			if (kret != KERN_SUCCESS) {
				/* XXX need to bail out gracefully here */
				panic("vfs_drt: new cluster map mysteriously too small");
			}
			/* copy */
			DRT_HASH_COPY(ocmap, i, cmap, index);
			copycount++;
		}
	}

	/* log what we've done */
	vfs_drt_trace(cmap, DRT_DEBUG_ALLOC, copycount, 0, 0, 0);
	
	/*
	 * It's important to ensure that *cmapp always points to 
	 * a valid map, so we must overwrite it before freeing
	 * the old map.
	 */
	*cmapp = cmap;
	if (ocmap != NULL) {
		/* emit stats into trace buffer */
		vfs_drt_trace(ocmap, DRT_DEBUG_SCMDATA,
			      ocmap->scm_modulus,
			      ocmap->scm_buckets,
			      ocmap->scm_lastclean,
			      ocmap->scm_iskips);

		vfs_drt_free_map(ocmap);
	}
	return(KERN_SUCCESS);
}


/*
 * Free a sparse cluster map.
 */
static kern_return_t
vfs_drt_free_map(struct vfs_drt_clustermap *cmap)
{
	kmem_free(kernel_map, (vm_offset_t)cmap, 
		  (cmap->scm_modulus == DRT_HASH_SMALL_MODULUS) ? DRT_SMALL_ALLOCATION : DRT_LARGE_ALLOCATION);
	return(KERN_SUCCESS);
}


/*
 * Find the hashtable slot currently occupied by an entry for the supplied offset.
 */
static kern_return_t
vfs_drt_search_index(struct vfs_drt_clustermap *cmap, u_int64_t offset, int *indexp)
{
	int		index, i;

	offset = DRT_ALIGN_ADDRESS(offset);
	index = DRT_HASH(cmap, offset);

	/* traverse the hashtable */
	for (i = 0; i < cmap->scm_modulus; i++) {

		/*
		 * If the slot is vacant, we can stop.
		 */
		if (DRT_HASH_VACANT(cmap, index))
			break;

		/*
		 * If the address matches our offset, we have success.
		 */
		if (DRT_HASH_GET_ADDRESS(cmap, index) == offset) {
			*indexp = index;
			return(KERN_SUCCESS);
		}

		/*
		 * Move to the next slot, try again.
		 */
		index = DRT_HASH_NEXT(cmap, index);
	}
	/*
	 * It's not there.
	 */
	return(KERN_FAILURE);
}

/*
 * Find the hashtable slot for the supplied offset.  If we haven't allocated
 * one yet, allocate one and populate the address field.  Note that it will
 * not have a nonzero page count and thus will still technically be free, so
 * in the case where we are called to clean pages, the slot will remain free.
 */
static kern_return_t
vfs_drt_get_index(struct vfs_drt_clustermap **cmapp, u_int64_t offset, int *indexp, int recursed)
{
	struct vfs_drt_clustermap *cmap;
	kern_return_t	kret;
	int		index, i;

	cmap = *cmapp;

	/* look for an existing entry */
	kret = vfs_drt_search_index(cmap, offset, indexp);
	if (kret == KERN_SUCCESS)
		return(kret);

	/* need to allocate an entry */
	offset = DRT_ALIGN_ADDRESS(offset);
	index = DRT_HASH(cmap, offset);

	/* scan from the index forwards looking for a vacant slot */
	for (i = 0; i < cmap->scm_modulus; i++) {
		/* slot vacant? */
		if (DRT_HASH_VACANT(cmap, index) || DRT_HASH_GET_COUNT(cmap,index) == 0) {
			cmap->scm_buckets++;
			if (index < cmap->scm_lastclean)
				cmap->scm_lastclean = index;
			DRT_HASH_SET_ADDRESS(cmap, index, offset);
			DRT_HASH_SET_COUNT(cmap, index, 0);
			DRT_BITVECTOR_CLEAR(cmap, index);
			*indexp = index;
			vfs_drt_trace(cmap, DRT_DEBUG_INSERT, (int)offset, i, 0, 0);
			return(KERN_SUCCESS);
		}
		cmap->scm_iskips += i;
		index = DRT_HASH_NEXT(cmap, index);
	}

	/*
	 * We haven't found a vacant slot, so the map is full.  If we're not
	 * already recursed, try reallocating/compacting it.
	 */
	if (recursed)
		return(KERN_FAILURE);
	kret = vfs_drt_alloc_map(cmapp);
	if (kret == KERN_SUCCESS) {
		/* now try to insert again */
		kret = vfs_drt_get_index(cmapp, offset, indexp, 1);
	}
	return(kret);
}

/*
 * Implementation of set dirty/clean.
 *
 * In the 'clean' case, not finding a map is OK.
 */
static kern_return_t
vfs_drt_do_mark_pages(
	void		**private,
	u_int64_t	offset,
	u_int    	length,
	int		*setcountp,
	int		dirty)
{
	struct vfs_drt_clustermap *cmap, **cmapp;
	kern_return_t	kret;
	int		i, index, pgoff, pgcount, setcount, ecount;

	cmapp = (struct vfs_drt_clustermap **)private;
	cmap = *cmapp;

	vfs_drt_trace(cmap, DRT_DEBUG_MARK | DBG_FUNC_START, (int)offset, (int)length, dirty, 0);

	if (setcountp != NULL)
	        *setcountp = 0;
	
	/* allocate a cluster map if we don't already have one */
	if (cmap == NULL) {
		/* no cluster map, nothing to clean */
		if (!dirty) {
			vfs_drt_trace(cmap, DRT_DEBUG_MARK | DBG_FUNC_END, 1, 0, 0, 0);
			return(KERN_SUCCESS);
		}
		kret = vfs_drt_alloc_map(cmapp);
		if (kret != KERN_SUCCESS) {
			vfs_drt_trace(cmap, DRT_DEBUG_MARK | DBG_FUNC_END, 2, 0, 0, 0);
			return(kret);
		}
	}
	setcount = 0;

	/*
	 * Iterate over the length of the region.
	 */
	while (length > 0) {
		/*
		 * Get the hashtable index for this offset.
		 *
		 * XXX this will add blank entries if we are clearing a range
		 * that hasn't been dirtied.
		 */
		kret = vfs_drt_get_index(cmapp, offset, &index, 0);
		cmap = *cmapp;	/* may have changed! */
		/* this may be a partial-success return */
		if (kret != KERN_SUCCESS) {
		        if (setcountp != NULL)
			        *setcountp = setcount;
			vfs_drt_trace(cmap, DRT_DEBUG_MARK | DBG_FUNC_END, 3, (int)length, 0, 0);

			return(kret);
		}

		/*
		 * Work out how many pages we're modifying in this
		 * hashtable entry.
		 */
		pgoff = (offset - DRT_ALIGN_ADDRESS(offset)) / PAGE_SIZE;
		pgcount = min((length / PAGE_SIZE), (DRT_BITVECTOR_PAGES - pgoff));

		/*
		 * Iterate over pages, dirty/clearing as we go.
		 */
		ecount = DRT_HASH_GET_COUNT(cmap, index);
		for (i = 0; i < pgcount; i++) {
			if (dirty) {
				if (!DRT_HASH_TEST_BIT(cmap, index, pgoff + i)) {
					DRT_HASH_SET_BIT(cmap, index, pgoff + i);
					ecount++;
					setcount++;
				}
			} else {
				if (DRT_HASH_TEST_BIT(cmap, index, pgoff + i)) {
					DRT_HASH_CLEAR_BIT(cmap, index, pgoff + i);
					ecount--;
					setcount++;
				}
			}
		}
		DRT_HASH_SET_COUNT(cmap, index, ecount);

		offset += pgcount * PAGE_SIZE;
		length -= pgcount * PAGE_SIZE;
	}
	if (setcountp != NULL)
		*setcountp = setcount;

	vfs_drt_trace(cmap, DRT_DEBUG_MARK | DBG_FUNC_END, 0, setcount, 0, 0);

	return(KERN_SUCCESS);
}

/*
 * Mark a set of pages as dirty/clean.
 *
 * This is a public interface.
 *
 * cmapp
 *	Pointer to storage suitable for holding a pointer.  Note that
 *	this must either be NULL or a value set by this function.
 *
 * size
 *	Current file size in bytes.
 *
 * offset
 *	Offset of the first page to be marked as dirty, in bytes.  Must be
 *	page-aligned.
 *
 * length
 *	Length of dirty region, in bytes.  Must be a multiple of PAGE_SIZE.
 *
 * setcountp
 *	Number of pages newly marked dirty by this call (optional).
 *
 * Returns KERN_SUCCESS if all the pages were successfully marked.
 */
static kern_return_t
vfs_drt_mark_pages(void **cmapp, off_t offset, u_int length, int *setcountp)
{
	/* XXX size unused, drop from interface */
	return(vfs_drt_do_mark_pages(cmapp, offset, length, setcountp, 1));
}

#if 0
static kern_return_t
vfs_drt_unmark_pages(void **cmapp, off_t offset, u_int length)
{
	return(vfs_drt_do_mark_pages(cmapp, offset, length, NULL, 0));
}
#endif

/*
 * Get a cluster of dirty pages.
 *
 * This is a public interface.
 *
 * cmapp
 *	Pointer to storage managed by drt_mark_pages.  Note that this must
 *	be NULL or a value set by drt_mark_pages.
 *
 * offsetp
 *	Returns the byte offset into the file of the first page in the cluster.
 *
 * lengthp
 *	Returns the length in bytes of the cluster of dirty pages.
 *
 * Returns success if a cluster was found.  If KERN_FAILURE is returned, there
 * are no dirty pages meeting the minmum size criteria.  Private storage will
 * be released if there are no more dirty pages left in the map
 *
 */
static kern_return_t
vfs_drt_get_cluster(void **cmapp, off_t *offsetp, u_int *lengthp)
{
	struct vfs_drt_clustermap *cmap;
	u_int64_t	offset;
	u_int		length;
	int		index, i, j, fs, ls;

	/* sanity */
	if ((cmapp == NULL) || (*cmapp == NULL))
		return(KERN_FAILURE);
	cmap = *cmapp;

	/* walk the hashtable */
	for (offset = 0, j = 0; j < cmap->scm_modulus; offset += (DRT_BITVECTOR_PAGES * PAGE_SIZE), j++) {
	        index = DRT_HASH(cmap, offset);

	        if (DRT_HASH_VACANT(cmap, index) || (DRT_HASH_GET_COUNT(cmap, index) == 0))
			continue;

		/* scan the bitfield for a string of bits */
		fs = -1;

		for (i = 0; i < DRT_BITVECTOR_PAGES; i++) {
		        if (DRT_HASH_TEST_BIT(cmap, index, i)) {
			        fs = i;
				break;
			}
		}
		if (fs == -1) {
		        /*  didn't find any bits set */
		        panic("vfs_drt: entry summary count > 0 but no bits set in map");
		}
		for (ls = 0; i < DRT_BITVECTOR_PAGES; i++, ls++) {
			if (!DRT_HASH_TEST_BIT(cmap, index, i))
			        break;
		}
		
		/* compute offset and length, mark pages clean */
		offset = DRT_HASH_GET_ADDRESS(cmap, index) + (PAGE_SIZE * fs);
		length = ls * PAGE_SIZE;
		vfs_drt_do_mark_pages(cmapp, offset, length, NULL, 0);
		cmap->scm_lastclean = index;

		/* return successful */
		*offsetp = (off_t)offset;
		*lengthp = length;

		vfs_drt_trace(cmap, DRT_DEBUG_RETCLUSTER, (int)offset, (int)length, 0, 0);
		return(KERN_SUCCESS);
	}
	/*
	 * We didn't find anything... hashtable is empty
	 * emit stats into trace buffer and
	 * then free it
	 */
	vfs_drt_trace(cmap, DRT_DEBUG_SCMDATA,
		      cmap->scm_modulus,
		      cmap->scm_buckets,
		      cmap->scm_lastclean,
		      cmap->scm_iskips);
	
	vfs_drt_free_map(cmap);
	*cmapp = NULL;

	return(KERN_FAILURE);
}


static kern_return_t
vfs_drt_control(void **cmapp, int op_type)
{
	struct vfs_drt_clustermap *cmap;

	/* sanity */
	if ((cmapp == NULL) || (*cmapp == NULL))
		return(KERN_FAILURE);
	cmap = *cmapp;

	switch (op_type) {
	case 0:
		/* emit stats into trace buffer */
		vfs_drt_trace(cmap, DRT_DEBUG_SCMDATA,
			      cmap->scm_modulus,
			      cmap->scm_buckets,
			      cmap->scm_lastclean,
			      cmap->scm_iskips);

		vfs_drt_free_map(cmap);
		*cmapp = NULL;
	        break;

	case 1:
	        cmap->scm_lastclean = 0;
	        break;
	}
	return(KERN_SUCCESS);
}



/*
 * Emit a summary of the state of the clustermap into the trace buffer
 * along with some caller-provided data.
 */
#if KDEBUG
static void
vfs_drt_trace(__unused struct vfs_drt_clustermap *cmap, int code, int arg1, int arg2, int arg3, int arg4)
{
	KERNEL_DEBUG(code, arg1, arg2, arg3, arg4, 0);
}
#else
static void
vfs_drt_trace(__unused struct vfs_drt_clustermap *cmap, __unused int code, 
			  __unused int arg1, __unused int arg2, __unused int arg3, 
			  __unused int arg4)
{
}
#endif 

#if 0
/*
 * Perform basic sanity check on the hash entry summary count
 * vs. the actual bits set in the entry.
 */
static void
vfs_drt_sanity(struct vfs_drt_clustermap *cmap)
{
        int index, i;
	int bits_on;
	
	for (index = 0; index < cmap->scm_modulus; index++) {
	        if (DRT_HASH_VACANT(cmap, index))
		        continue;

		for (bits_on = 0, i = 0; i < DRT_BITVECTOR_PAGES; i++) {
			if (DRT_HASH_TEST_BIT(cmap, index, i))
			        bits_on++;
		}
		if (bits_on != DRT_HASH_GET_COUNT(cmap, index))
		        panic("bits_on = %d,  index = %d\n", bits_on, index);
	}		
}
#endif
