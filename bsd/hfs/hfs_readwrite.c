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
/*	@(#)hfs_readwrite.c	1.0
 *
 *	(c) 1990, 1992 NeXT Computer, Inc.  All Rights Reserved
 *	(c) 1998       Apple Computer, Inc.  All Rights Reserved
 *	
 *
 *	hfs_readwrite.c -- vnode operations to deal with reading and writing files.
 *
 *	MODIFICATION HISTORY:
 *	 9-Nov-1999	Scott Roberts	hfs_allocate now returns sizes based on allocation block boundaries (#2398794)
 *	 3-Feb-1999	Pat Dirks		Merged in Joe's change to hfs_truncate to skip vinvalbuf if LEOF isn't changing (#2302796)
 *								Removed superfluous (and potentially dangerous) second call to vinvalbuf() in hfs_truncate.
 *	 2-Dec-1998	Pat Dirks		Added support for read/write bootstrap ioctls.
 *	10-Nov-1998	Pat Dirks		Changed read/write/truncate logic to optimize block sizes for first extents of a file.
 *                              Changed hfs_strategy to correct I/O sizes from cluser code I/O requests in light of
 *                              different block sizing.  Changed bexpand to handle RELEASE_BUFFER flag.
 *	22-Sep-1998	Don Brady		Changed truncate zero-fill to use bwrite after several bawrites have been queued.
 *	11-Sep-1998	Pat Dirks		Fixed buffering logic to not rely on B_CACHE, which is set for empty buffers that
 *								have been pre-read by cluster_read (use b_validend > 0 instead).
 *  27-Aug-1998	Pat Dirks		Changed hfs_truncate to use cluster_write in place of bawrite where possible.
 *	25-Aug-1998	Pat Dirks		Changed hfs_write to do small device-block aligned writes into buffers without doing
 *								read-ahead of the buffer.  Added bexpand to deal with incomplete [dirty] buffers.
 *								Fixed can_cluster macro to use MAXPHYSIO instead of MAXBSIZE.
 *	19-Aug-1998	Don Brady		Remove optimization in hfs_truncate that prevented extra physical blocks from
 *								being truncated (radar #2265750). Also set fcb->fcbEOF before calling vinvalbuf.
 *	 7-Jul-1998	Pat Dirks		Added code to honor IO_NOZEROFILL in hfs_truncate.
 *	16-Jul-1998	Don Brady		In hfs_bmap use MAXPHYSIO instead of MAXBSIZE when calling MapFileBlockC (radar #2263753).
 *	16-Jul-1998	Don Brady		Fix error handling in hfs_allocate (radar #2252265).
 *	04-Jul-1998	chw				Synchronized options in hfs_allocate with flags in call to ExtendFileC
 *	25-Jun-1998	Don Brady		Add missing blockNo incrementing to zero fill loop in hfs_truncate.
 *	22-Jun-1998	Don Brady		Add bp = NULL assignment after brelse in hfs_read.
 *	 4-Jun-1998	Pat Dirks		Split off from hfs_vnodeops.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
//#include <mach/machine/vm_types.h>
#include <sys/vnode.h>
#include <sys/uio.h>

#include <miscfs/specfs/specdev.h>

#include <sys/ubc.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#include	"hfs.h"
#include	"hfs_dbg.h"
#include	"hfs_endian.h"
#include	"hfscommon/headers/FileMgrInternal.h"
#include	"hfscommon/headers/BTreesInternal.h"


#define can_cluster(size) ((((size & (4096-1))) == 0) && (size <= (MAXPHYSIO/2)))

enum {
	MAXHFSFILESIZE = 0x7FFFFFFF		/* this needs to go in the mount structure */
};

extern u_int32_t GetLogicalBlockSize(struct vnode *vp);

#if DBG_VOP_TEST_LOCKS
extern void DbgVopTest(int maxSlots, int retval, VopDbgStoreRec *VopDbgStore, char *funcname);
#endif

#if HFS_DIAGNOSTIC
void debug_check_blocksizes(struct vnode *vp);
#endif

/*****************************************************************************
*
*	Operations on vnodes
*
*****************************************************************************/

/*
#% read		vp	L L L
#
 vop_read {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN int ioflag;
     IN struct ucred *cred;

     */

int
hfs_read(ap)
struct vop_read_args /* {
    struct vnode *a_vp;
    struct uio *a_uio;
    int a_ioflag;
    struct ucred *a_cred;
} */ *ap;
{
    register struct vnode 	*vp;
    struct hfsnode 			*hp;
    register struct uio 	*uio;
    struct buf 				*bp;
    daddr_t 				logBlockNo;
    u_long					fragSize, moveSize, startOffset, ioxfersize;
    int						devBlockSize = 0;
    off_t 					bytesRemaining;
    int 					retval;
    u_short 				mode;
    FCB						*fcb;

    DBG_FUNC_NAME("hfs_read");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    vp = ap->a_vp;
    hp = VTOH(vp);
    fcb = HTOFCB(hp);
    mode = hp->h_meta->h_mode;
    uio = ap->a_uio;

#if HFS_DIAGNOSTIC
    if (uio->uio_rw != UIO_READ)
        panic("%s: mode", funcname);
#endif

    /* Can only read files */
    if (ap->a_vp->v_type != VREG && ap->a_vp->v_type != VLNK) {
        DBG_VOP_LOCKS_TEST(EISDIR);
        return (EISDIR);
    }
    DBG_RW(("\tfile size Ox%X\n", (u_int)fcb->fcbEOF));
    DBG_RW(("\tstarting at offset Ox%X of file, length Ox%X\n", (u_int)uio->uio_offset, (u_int)uio->uio_resid));

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(vp);
#endif

    /*
     * If they didn't ask for any data, then we are done.
     */
    if (uio->uio_resid == 0) {
        DBG_VOP_LOCKS_TEST(E_NONE);
        return (E_NONE);
    }

    /* cant read from a negative offset */
    if (uio->uio_offset < 0) {
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
    }

    if (uio->uio_offset > fcb->fcbEOF) {
        if ( (!ISHFSPLUS(VTOVCB(vp))) && (uio->uio_offset > (off_t)MAXHFSFILESIZE))
            retval = EFBIG;
        else
            retval = E_NONE;

        DBG_VOP_LOCKS_TEST(retval);
        return (retval);
    }

    VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_START,
                 (int)uio->uio_offset, uio->uio_resid, (int)fcb->fcbEOF,  (int)fcb->fcbPLen, 0);

    if (UBCISVALID(vp))
        retval = cluster_read(vp, uio, (off_t)fcb->fcbEOF, devBlockSize, 0);
    else {

        for (retval = 0, bp = NULL; uio->uio_resid > 0; bp = NULL) {

            if ((bytesRemaining = (fcb->fcbEOF - uio->uio_offset)) <= 0)
                break;

            logBlockNo  = (daddr_t)(uio->uio_offset / PAGE_SIZE_64);
            startOffset = (u_long) (uio->uio_offset & PAGE_MASK_64);
            fragSize    = PAGE_SIZE;

            if (((logBlockNo * PAGE_SIZE) + fragSize) < fcb->fcbEOF)
                ioxfersize = fragSize;
            else {
                ioxfersize = fcb->fcbEOF - (logBlockNo * PAGE_SIZE);
                ioxfersize = (ioxfersize + (devBlockSize - 1)) & ~(devBlockSize - 1);
            }
            DBG_RW(("\tat logBlockNo Ox%X, with Ox%lX left to read\n", logBlockNo, (UInt32)uio->uio_resid));
            moveSize = ioxfersize;
            DBG_RW(("\tmoveSize = Ox%lX; ioxfersize = Ox%lX; startOffset = Ox%lX.\n",
                    moveSize, ioxfersize, startOffset));
            DBG_ASSERT(moveSize >= startOffset);
            moveSize -= startOffset;

            if (bytesRemaining < moveSize)
                moveSize = bytesRemaining;

            if (uio->uio_resid < moveSize) {
                moveSize = uio->uio_resid;
                DBG_RW(("\treducing moveSize to Ox%lX (uio->uio_resid).\n", moveSize));
            };
            if (moveSize == 0) {
                break;
            };

            DBG_RW(("\tat logBlockNo Ox%X, extent of Ox%lX, xfer of Ox%lX; moveSize = Ox%lX\n", logBlockNo, fragSize, ioxfersize, moveSize));

            if (( uio->uio_offset + fragSize) >= fcb->fcbEOF) {
                retval = bread(vp, logBlockNo, ioxfersize, NOCRED, &bp);

            } else if (logBlockNo - 1 == vp->v_lastr && !(vp->v_flag & VRAOFF)) {
                daddr_t nextLogBlockNo = logBlockNo + 1;
                int nextsize;

                if (((nextLogBlockNo * PAGE_SIZE) +
                     (daddr_t)fragSize) < fcb->fcbEOF)
                    nextsize = fragSize;
                else {
                    nextsize = fcb->fcbEOF - (nextLogBlockNo * PAGE_SIZE);
                    nextsize = (nextsize + (devBlockSize - 1)) & ~(devBlockSize - 1);
                }
                retval = breadn(vp, logBlockNo, ioxfersize, &nextLogBlockNo, &nextsize, 1, NOCRED, &bp);
            } else {
                retval = bread(vp, logBlockNo, ioxfersize, NOCRED, &bp);
            };

            if (retval != E_NONE) {
                if (bp) {
                    brelse(bp);
                    bp = NULL;
                }
                break;
            };
            vp->v_lastr = logBlockNo;

            /*
             * We should only get non-zero b_resid when an I/O retval
             * has occurred, which should cause us to break above.
             * However, if the short read did not cause an retval,
             * then we want to ensure that we do not uiomove bad
             * or uninitialized data.
             */
            ioxfersize -= bp->b_resid;

            if (ioxfersize < moveSize) {			/* XXX PPD This should take the offset into account, too! */
                if (ioxfersize == 0)
                    break;
                moveSize = ioxfersize;
            }
            if ((startOffset + moveSize) > bp->b_bcount)
                panic("hfs_read: bad startOffset or moveSize\n");

            DBG_RW(("\tcopying Ox%lX bytes from %lX; resid = Ox%lX...\n", moveSize, (char *)bp->b_data + startOffset, bp->b_resid));

            if ((retval = uiomove((caddr_t)bp->b_data + startOffset, (int)moveSize, uio)))
                break;

            if (S_ISREG(mode) &&
                (((startOffset + moveSize) == fragSize) || (uio->uio_offset == fcb->fcbEOF))) {
                bp->b_flags |= B_AGE;
            };

            DBG_ASSERT(bp->b_bcount == bp->b_validend);

            brelse(bp);
            /* Start of loop resets bp to NULL before reaching outside this block... */
        }

        if (bp != NULL) {
            DBG_ASSERT(bp->b_bcount == bp->b_validend);
            brelse(bp);
        };
    }

    if (HTOVCB(hp)->vcbSigWord == kHFSPlusSigWord)
        hp->h_nodeflags |= IN_ACCESS;

    DBG_VOP_LOCKS_TEST(retval);

    #if HFS_DIAGNOSTIC
        debug_check_blocksizes(vp);
    #endif

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_END,
                (int)uio->uio_offset, uio->uio_resid, (int)fcb->fcbEOF,  (int)fcb->fcbPLen, 0);

    return (retval);
}

/*
 * Write data to a file or directory.
#% write	vp	L L L
#
 vop_write {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN int ioflag;
     IN struct ucred *cred;

     */
int
hfs_write(ap)
struct vop_write_args /* {
    struct vnode *a_vp;
    struct uio *a_uio;
    int a_ioflag;
    struct ucred *a_cred;
} */ *ap;
{
    struct hfsnode 		*hp = VTOH(ap->a_vp);
    struct uio 			*uio = ap->a_uio;
    struct vnode 		*vp = ap->a_vp ;
    struct vnode 		*dev;
    struct buf 			*bp;
    struct proc 		*p, *cp;
    struct timeval tv;
    FCB					*fcb = HTOFCB(hp);
    ExtendedVCB			*vcb = HTOVCB(hp);
    int					devBlockSize = 0;
    daddr_t 			logBlockNo;
    long				fragSize;
    off_t 				origFileSize, currOffset, writelimit, bytesToAdd;
    off_t				actualBytesAdded;
    u_long				blkoffset, resid, xfersize, clearSize;
    int					flags, ioflag;
    int 				retval;
    DBG_FUNC_NAME("hfs_write");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_RW(("\thfsnode 0x%x (%s)\n", (u_int)hp, H_NAME(hp)));
    DBG_RW(("\tstarting at offset Ox%lX of file, length Ox%lX\n", (UInt32)uio->uio_offset, (UInt32)uio->uio_resid));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    dev = hp->h_meta->h_devvp;

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(vp);
#endif

    if (uio->uio_offset < 0) {
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
    }

    if (uio->uio_resid == 0) {
        DBG_VOP_LOCKS_TEST(E_NONE);
        return (E_NONE);
    }

    if (ap->a_vp->v_type != VREG && ap->a_vp->v_type != VLNK) {		/* Can only write files */
        DBG_VOP_LOCKS_TEST(EISDIR);
        return (EISDIR);
    };

#if HFS_DIAGNOSTIC
	if (uio->uio_rw != UIO_WRITE)
		panic("%s: mode", funcname);
#endif

    ioflag = ap->a_ioflag;
    uio = ap->a_uio;
    vp = ap->a_vp;

    if (ioflag & IO_APPEND) uio->uio_offset = fcb->fcbEOF;
    if ((hp->h_meta->h_pflags & APPEND) && uio->uio_offset != fcb->fcbEOF)
    	return (EPERM);

	writelimit = uio->uio_offset + uio->uio_resid;

    /*
    * Maybe this should be above the vnode op call, but so long as
    * file servers have no limits, I don't think it matters.
    */
    p = uio->uio_procp;
    if (vp->v_type == VREG && p &&
        writelimit > p->p_rlimit[RLIMIT_FSIZE].rlim_cur) {
        psignal(p, SIGXFSZ);
        return (EFBIG);
    };
    VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

    resid = uio->uio_resid;
    origFileSize = fcb->fcbEOF;
    flags = ioflag & IO_SYNC ? B_SYNC : 0;

    DBG_RW(("\tLEOF is 0x%lX, PEOF is 0x%lX.\n", fcb->fcbEOF, fcb->fcbPLen));

    /*
    NOTE:	In the following loop there are two positions tracked:
    currOffset is the current I/O starting offset.  currOffset is never >LEOF; the
    LEOF is nudged along with currOffset as data is zeroed or written.
    uio->uio_offset is the start of the current I/O operation.  It may be arbitrarily
    beyond currOffset.

    The following is true at all times:

    currOffset <= LEOF <= uio->uio_offset <= writelimit
    */
    currOffset = MIN(uio->uio_offset, fcb->fcbEOF);

    DBG_RW(("\tstarting I/O loop at 0x%lX.\n", (u_long)currOffset));

    cp = current_proc();

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_START,
                (int)uio->uio_offset, uio->uio_resid, (int)fcb->fcbEOF,  (int)fcb->fcbPLen, 0);
    retval = 0;

    /* Now test if we need to extend the file */
    /* Doing so will adjust the fcbPLen for us */

    while (writelimit > (off_t)fcb->fcbPLen) {
	
        bytesToAdd = writelimit - fcb->fcbPLen;
        DBG_RW(("\textending file by 0x%lX bytes; 0x%lX blocks free",
                (unsigned long)bytesToAdd, (unsigned long)vcb->freeBlocks));

        /* lock extents b-tree (also protects volume bitmap) */
        retval = hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_EXCLUSIVE, cp);
        if (retval != E_NONE)
            break;

        retval = MacToVFSError(
                            ExtendFileC (vcb,
                                            fcb,
                                            bytesToAdd,
                                            0,
                                            kEFContigBit,
                                            &actualBytesAdded));

        (void) hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_RELEASE, cp);
        DBG_VOP_CONT(("\tactual bytes added = 0x%lX bytes, retval = %d...\n", actualBytesAdded, retval));
        if ((actualBytesAdded == 0) && (retval == E_NONE)) retval = ENOSPC;
        if (retval != E_NONE) break;

        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_NONE,
                    (int)uio->uio_offset, uio->uio_resid, (int)fcb->fcbEOF,  (int)fcb->fcbPLen, 0);
    };

	if (UBCISVALID(vp) && retval == E_NONE) {
		off_t filesize;
		off_t zero_off;
		off_t tail_off;
		off_t inval_start;
		off_t inval_end;
		off_t io_start, io_end;
		int lflag;
		struct rl_entry *invalid_range;

		if (writelimit > fcb->fcbEOF)
			filesize = writelimit;
		else
			filesize = fcb->fcbEOF;

		lflag = (ioflag & IO_SYNC);

		if (uio->uio_offset <= fcb->fcbEOF) {
			zero_off = uio->uio_offset & ~PAGE_MASK_64;
			
			/* Check to see whether the area between the zero_offset and the start
			   of the transfer to see whether is invalid and should be zero-filled
			   as part of the transfer:
			 */
			if (rl_scan(&hp->h_invalidranges, zero_off, uio->uio_offset - 1, &invalid_range) != RL_NOOVERLAP) {
				lflag |= IO_HEADZEROFILL;
			};
		} else {
			off_t eof_page_base = fcb->fcbEOF & ~PAGE_MASK_64;
			
			/* The bytes between fcb->fcbEOF and uio->uio_offset must never be
			   read without being zeroed.  The current last block is filled with zeroes
			   if it holds valid data but in all cases merely do a little bookkeeping
			   to track the area from the end of the current last page to the start of
			   the area actually written.  For the same reason only the bytes up to the
			   start of the page where this write will start is invalidated; any remainder
			   before uio->uio_offset is explicitly zeroed as part of the cluster_write.
			   
			   Note that inval_start, the start of the page after the current EOF,
			   may be past the start of the write, in which case the zeroing
			   will be handled by the cluser_write of the actual data.
			 */
			inval_start = (fcb->fcbEOF + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
			inval_end = uio->uio_offset & ~PAGE_MASK_64;
			zero_off = fcb->fcbEOF;
			
			if ((fcb->fcbEOF & PAGE_MASK_64) &&
				(rl_scan(&hp->h_invalidranges,
							eof_page_base,
							fcb->fcbEOF - 1,
							&invalid_range) != RL_NOOVERLAP)) {
				/* The page containing the EOF is not valid, so the
				   entire page must be made inaccessible now.  If the write
				   starts on a page beyond the page containing the eof
				   (inval_end > eof_page_base), add the
				   whole page to the range to be invalidated.  Otherwise
				   (i.e. if the write starts on the same page), zero-fill
				   the entire page explicitly now:
				 */
				if (inval_end > eof_page_base) {
					inval_start = eof_page_base;
				} else {
					zero_off = eof_page_base;
				};
			};
			
			if (inval_start < inval_end) {
				/* There's some range of data that's going to be marked invalid */
				
				if (zero_off < inval_start) {
					/* The pages between inval_start and inval_end are going to be invalidated,
					   and the actual write will start on a page past inval_end.  Now's the last
					   chance to zero-fill the page containing the EOF:
					 */
					retval = cluster_write(vp, (struct uio *) 0, fcb->fcbEOF, inval_start,
											zero_off, (off_t)0, devBlockSize, lflag | IO_HEADZEROFILL);
					if (retval) goto ioerr_exit;
				};
				
				/* Mark the remaining area of the newly allocated space as invalid: */
				rl_add(inval_start, inval_end - 1 , &hp->h_invalidranges);
				zero_off = fcb->fcbEOF = inval_end;
			};
			
			if (uio->uio_offset > zero_off) lflag |= IO_HEADZEROFILL;
		};

		/* Check to see whether the area between the end of the write and the end of
		   the page it falls in is invalid and should be zero-filled as part of the transfer:
		 */
		tail_off = (writelimit + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
		if (tail_off > filesize) tail_off = filesize;
		if (tail_off > writelimit) {
			if (rl_scan(&hp->h_invalidranges, writelimit, tail_off - 1, &invalid_range) != RL_NOOVERLAP) {
				lflag |= IO_TAILZEROFILL;
			};
		};
		
		/*
		 * if the write starts beyond the current EOF (possibly advanced in the
		 * zeroing of the last block, above), then we'll zero fill from the current EOF
		 * to where the write begins:
		 *
		 * NOTE: If (and ONLY if) the portion of the file about to be written is
		 *       before the current EOF it might be marked as invalid now and must be
		 *       made readable (removed from the invalid ranges) before cluster_write
		 *       tries to write it:
		 */
		io_start = (lflag & IO_HEADZEROFILL) ? zero_off : uio->uio_offset;
		io_end = (lflag & IO_TAILZEROFILL) ? tail_off : writelimit;
		if (io_start < fcb->fcbEOF) {
			rl_remove(io_start, io_end - 1, &hp->h_invalidranges);
		};
		retval = cluster_write(vp, uio, fcb->fcbEOF, filesize, zero_off, tail_off, devBlockSize, lflag);
				
		if (uio->uio_offset > fcb->fcbEOF) {
			fcb->fcbEOF = uio->uio_offset;

			ubc_setsize(vp, (off_t)fcb->fcbEOF);       /* XXX check errors */
		}
		if (resid > uio->uio_resid) hp->h_nodeflags |= IN_CHANGE | IN_UPDATE;

    } else {

        while (retval == E_NONE && uio->uio_resid > 0) {
            logBlockNo = currOffset / PAGE_SIZE;
            blkoffset  = currOffset & PAGE_MASK;

            if (((off_t)(fcb->fcbPLen) - currOffset) < PAGE_SIZE_64)
                fragSize = (off_t)(fcb->fcbPLen) - ((off_t)logBlockNo * PAGE_SIZE_64);
            else
                fragSize = PAGE_SIZE;
            xfersize = fragSize - blkoffset;

            DBG_RW(("\tcurrOffset = Ox%lX, logBlockNo = Ox%X, blkoffset = Ox%lX, xfersize = Ox%lX, fragSize = Ox%lX.\n",
                    (unsigned long)currOffset, logBlockNo, blkoffset, xfersize, fragSize));

            /* Make any adjustments for boundary conditions */
            if (currOffset + (off_t)xfersize > writelimit) {
                xfersize = writelimit - currOffset;
                DBG_RW(("\ttrimming xfersize to 0x%lX to match writelimit (uio_resid)...\n", xfersize));
            };

            /*
            * There is no need to read into bp if:
            * We start on a block boundary and will overwrite the whole block
            *
            *						OR
            */
            if ((blkoffset == 0) && (xfersize >= fragSize)) {
                DBG_RW(("\tRequesting %ld-byte block Ox%lX w/o read...\n", fragSize, (long)logBlockNo));

                bp = getblk(vp, logBlockNo, fragSize, 0, 0, BLK_READ);
                retval = 0;

                if (bp->b_blkno == -1) {
                    brelse(bp);
                    retval = EIO;		/* XXX */
                    break;
                }
            } else {

                if (currOffset == fcb->fcbEOF && blkoffset == 0) {
                    bp = getblk(vp, logBlockNo, fragSize, 0, 0, BLK_READ);
                    retval = 0;

                    if (bp->b_blkno == -1) {
                        brelse(bp);
                        retval = EIO;		/* XXX */
                        break;
                    }

                } else {
                    /*
                    * This I/O transfer is not sufficiently aligned, so read the affected block into a buffer:
                    */
                    DBG_VOP(("\tRequesting block Ox%X, size = 0x%08lX...\n", logBlockNo, fragSize));
                    retval = bread(vp, logBlockNo, fragSize, ap->a_cred, &bp);

                    if (retval != E_NONE) {
                        if (bp)
                            brelse(bp);
                        break;
                    }
                }
            }

            /* See if we are starting to write within file boundaries:
                If not, then we need to present a "hole" for the area between
                the current EOF and the start of the current I/O operation:

                Note that currOffset is only less than uio_offset if uio_offset > LEOF...
                */
            if (uio->uio_offset > currOffset) {
                clearSize = MIN(uio->uio_offset - currOffset, xfersize);
                DBG_RW(("\tzeroing Ox%lX bytes Ox%lX bytes into block Ox%X...\n", clearSize, blkoffset, logBlockNo));
                bzero(bp->b_data + blkoffset, clearSize);
                currOffset += clearSize;
                blkoffset += clearSize;
                xfersize -= clearSize;
            };

            if (xfersize > 0) {
                DBG_RW(("\tCopying Ox%lX bytes Ox%lX bytes into block Ox%X... ioflag == 0x%X\n",
                        xfersize, blkoffset, logBlockNo, ioflag));
                retval = uiomove((caddr_t)bp->b_data + blkoffset, (int)xfersize, uio);
                currOffset += xfersize;
            };
            DBG_ASSERT((bp->b_bcount % devBlockSize) == 0);

            if (ioflag & IO_SYNC) {
                (void)VOP_BWRITE(bp);
                //DBG_RW(("\tissuing bwrite\n"));
            } else if ((xfersize + blkoffset) == fragSize) {
                //DBG_RW(("\tissuing bawrite\n"));
                bp->b_flags |= B_AGE;
                bawrite(bp);
            } else {
                //DBG_RW(("\tissuing bdwrite\n"));
                bdwrite(bp);
            };

            /* Update the EOF if we just extended the file
                (the PEOF has already been moved out and the block mapping table has been updated): */
            if (currOffset > fcb->fcbEOF) {
                DBG_VOP(("\textending EOF to 0x%lX...\n", (UInt32)fcb->fcbEOF));
                fcb->fcbEOF = currOffset;

                if (UBCISVALID(vp))
                    ubc_setsize(vp, (off_t)fcb->fcbEOF); /* XXX check errors */
            };

            if (retval || (resid == 0))
                break;
            hp->h_nodeflags |= IN_CHANGE | IN_UPDATE;
        };
    };

ioerr_exit:
    /*
	 * If we successfully wrote any data, and we are not the superuser
     * we clear the setuid and setgid bits as a precaution against
     * tampering.
     */
    if (resid > uio->uio_resid && ap->a_cred && ap->a_cred->cr_uid != 0)
    hp->h_meta->h_mode &= ~(ISUID | ISGID);

    if (retval) {
        if (ioflag & IO_UNIT) {
            (void)VOP_TRUNCATE(vp, origFileSize,
                            ioflag & IO_SYNC, ap->a_cred, uio->uio_procp);
            uio->uio_offset -= resid - uio->uio_resid;
            uio->uio_resid = resid;
        }
    } else if (resid > uio->uio_resid && (ioflag & IO_SYNC)) {
        tv = time;
        retval = VOP_UPDATE(vp, &tv, &tv, 1);
    }

    #if HFS_DIAGNOSTIC
    debug_check_blocksizes(vp);
    #endif

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_END,
                (int)uio->uio_offset, uio->uio_resid, (int)fcb->fcbEOF, (int)fcb->fcbPLen, 0);

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}


/*

#% ioctl	vp	U U U
#
 vop_ioctl {
     IN struct vnode *vp;
     IN u_long command;
     IN caddr_t data;
     IN int fflag;
     IN struct ucred *cred;
     IN struct proc *p;

     */


/* ARGSUSED */
int
hfs_ioctl(ap)
struct vop_ioctl_args /* {
    struct vnode *a_vp;
    int  a_command;
    caddr_t  a_data;
    int  a_fflag;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    DBG_FUNC_NAME("hfs_ioctl");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);

    switch (ap->a_command) {
	
        case 1:
    {   register struct hfsnode *hp;
            register struct vnode *vp;
	register struct radvisory *ra;
	FCB *fcb;
	int devBlockSize = 0;
	int error;

	vp = ap->a_vp;

	VOP_LEASE(vp, ap->a_p, ap->a_cred, LEASE_READ);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, ap->a_p);

	ra = (struct radvisory *)(ap->a_data);
	hp = VTOH(vp);

	fcb = HTOFCB(hp);

	if (ra->ra_offset >= fcb->fcbEOF) {
	    VOP_UNLOCK(vp, 0, ap->a_p);
	    DBG_VOP_LOCKS_TEST(EFBIG);
	    return (EFBIG);
	}
	VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

	error = advisory_read(vp, fcb->fcbEOF, ra->ra_offset, ra->ra_count, devBlockSize);
	VOP_UNLOCK(vp, 0, ap->a_p);

	DBG_VOP_LOCKS_TEST(error);
	return (error);
            }

        case 2: /* F_READBOOTBLOCKS */
        case 3: /* F_WRITEBOOTBLOCKS */
            {
	    struct vnode *vp = ap->a_vp;
	    struct hfsnode *hp = VTOH(vp);
	    struct fbootstraptransfer *btd = (struct fbootstraptransfer *)ap->a_data;
	    int devBlockSize;
	    int error;
	    struct iovec aiov;
	    struct uio auio;
	    u_long blockNumber;
	    u_long blockOffset;
	    u_long xfersize;
	    struct buf *bp;

            if ((vp->v_flag & VROOT) == 0) return EINVAL;
            if (btd->fbt_offset + btd->fbt_length > 1024) return EINVAL;
	    
	    aiov.iov_base = btd->fbt_buffer;
	    aiov.iov_len = btd->fbt_length;
	    
	    auio.uio_iov = &aiov;
	    auio.uio_iovcnt = 1;
	    auio.uio_offset = btd->fbt_offset;
	    auio.uio_resid = btd->fbt_length;
	    auio.uio_segflg = UIO_USERSPACE;
	    auio.uio_rw = (ap->a_command == 3) ? UIO_WRITE : UIO_READ; /* F_WRITEBOOTSTRAP / F_READBOOTSTRAP */
	    auio.uio_procp = ap->a_p;

	    VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

	    while (auio.uio_resid > 0) {
	      blockNumber = auio.uio_offset / devBlockSize;
	      error = bread(hp->h_meta->h_devvp, blockNumber, devBlockSize, ap->a_cred, &bp);
	      if (error) {
                  if (bp) brelse(bp);
                  return error;
                };

                blockOffset = auio.uio_offset % devBlockSize;
	      xfersize = devBlockSize - blockOffset;
	      error = uiomove((caddr_t)bp->b_data + blockOffset, (int)xfersize, &auio);
                if (error) {
                  brelse(bp);
                  return error;
                };
                if (auio.uio_rw == UIO_WRITE) {
                  error = VOP_BWRITE(bp);
                  if (error) return error;
                } else {
                  brelse(bp);
                };
            };
        };
        return 0;

        case _IOC(IOC_OUT,'h', 4, 0):     /* Create date in local time */
            {
            *(time_t *)(ap->a_data) = to_bsd_time(VTOVCB(ap->a_vp)->localCreateDate);
            return 0;
            }

        default:
            DBG_VOP_LOCKS_TEST(ENOTTY);
            return (ENOTTY);
    }

    /* Should never get here */
	return 0;
}

/* ARGSUSED */
int
hfs_select(ap)
struct vop_select_args /* {
    struct vnode *a_vp;
    int  a_which;
    int  a_fflags;
    struct ucred *a_cred;
	void *a_wql;
    struct proc *a_p;
} */ *ap;
{
    DBG_FUNC_NAME("hfs_select");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);

    /*
     * We should really check to see if I/O is possible.
     */
    DBG_VOP_LOCKS_TEST(1);
    return (1);
}



/*
 * Mmap a file
 *
 * NB Currently unsupported.
# XXX - not used
#
 vop_mmap {
     IN struct vnode *vp;
     IN int fflags;
     IN struct ucred *cred;
     IN struct proc *p;

     */

/* ARGSUSED */

int
hfs_mmap(ap)
struct vop_mmap_args /* {
    struct vnode *a_vp;
    int  a_fflags;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    DBG_FUNC_NAME("hfs_mmap");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);

    DBG_VOP_LOCKS_TEST(EINVAL);
    return (EINVAL);
}



/*
 * Seek on a file
 *
 * Nothing to do, so just return.
# XXX - not used
# Needs work: Is newoff right?  What's it mean?
#
 vop_seek {
     IN struct vnode *vp;
     IN off_t oldoff;
     IN off_t newoff;
     IN struct ucred *cred;
     */
/* ARGSUSED */
int
hfs_seek(ap)
struct vop_seek_args /* {
    struct vnode *a_vp;
    off_t  a_oldoff;
    off_t  a_newoff;
    struct ucred *a_cred;
} */ *ap;
{
    DBG_FUNC_NAME("hfs_seek");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);

    DBG_VOP_LOCKS_TEST(E_NONE);
    return (E_NONE);
}


/*
 * Bmap converts a the logical block number of a file to its physical block
 * number on the disk.
 */

/*
 * vp  - address of vnode file the file
 * bn  - which logical block to convert to a physical block number.
 * vpp - returns the vnode for the block special file holding the filesystem
 *	 containing the file of interest
 * bnp - address of where to return the filesystem physical block number
#% bmap		vp	L L L
#% bmap		vpp	- U -
#
 vop_bmap {
     IN struct vnode *vp;
     IN daddr_t bn;
     OUT struct vnode **vpp;
     IN daddr_t *bnp;
     OUT int *runp;
     */
/*
 * Converts a logical block number to a physical block, and optionally returns
 * the amount of remaining blocks in a run. The logical block is based on hfsNode.logBlockSize.
 * The physical block number is based on the device block size, currently its 512.
 * The block run is returned in logical blocks, and is the REMAINING amount of blocks
 */

int
hfs_bmap(ap)
struct vop_bmap_args /* {
    struct vnode *a_vp;
    daddr_t a_bn;
    struct vnode **a_vpp;
    daddr_t *a_bnp;
    int *a_runp;
} */ *ap;
{
    struct hfsnode 		*hp = VTOH(ap->a_vp);
    struct hfsmount 	*hfsmp = VTOHFS(ap->a_vp);
    int					retval = E_NONE;
    daddr_t				logBlockSize;
    size_t				bytesContAvail = 0;
    off_t blockposition;
    struct proc			*p = NULL;
    int					lockExtBtree;
    struct rl_entry *invalid_range;
    enum rl_overlaptype overlaptype;

#define DEBUG_BMAP 0
#if DEBUG_BMAP
    DBG_FUNC_NAME("hfs_bmap");
    DBG_VOP_LOCKS_DECL(2);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
    if (ap->a_vpp != NULL) {
        DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_UNLOCKED, VOPDBG_IGNORE, VOPDBG_POS);
    } else {
        DBG_VOP_LOCKS_INIT(1,NULL, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);
	};
#endif

	DBG_IO(("\tMapped blk %d --> ", ap->a_bn));
    /*
     * Check for underlying vnode requests and ensure that logical
     * to physical mapping is requested.
     */
    if (ap->a_vpp != NULL)
        *ap->a_vpp = VTOH(ap->a_vp)->h_meta->h_devvp;
    if (ap->a_bnp == NULL)
        return (0);

    logBlockSize = GetLogicalBlockSize(ap->a_vp);
    blockposition = (off_t)(ap->a_bn * logBlockSize);
        
    lockExtBtree = hasOverflowExtents(hp);
    if (lockExtBtree)
    {
        p = current_proc();
        retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE | LK_CANRECURSE, p);
        if (retval)
            return (retval);
    }

    retval = MacToVFSError(
                            MapFileBlockC (HFSTOVCB(hfsmp),
                                            HTOFCB(hp),
                                            MAXPHYSIO,
                                            blockposition,
                                            ap->a_bnp,
                                            &bytesContAvail));

    if (lockExtBtree) (void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);

    if (retval == E_NONE) {
        /* Adjust the mapping information for invalid file ranges: */
        overlaptype = rl_scan(&hp->h_invalidranges,
                            blockposition,
                            blockposition + MAXPHYSIO - 1,
                            &invalid_range);
        if (overlaptype != RL_NOOVERLAP) {
            switch(overlaptype) {
                case RL_MATCHINGOVERLAP:
                case RL_OVERLAPCONTAINSRANGE:
                case RL_OVERLAPSTARTSBEFORE:
                    /* There's no valid block for this byte offset: */
                    *ap->a_bnp = (daddr_t)-1;
                    bytesContAvail = invalid_range->rl_end + 1 - blockposition;
                    break;
                
                case RL_OVERLAPISCONTAINED:
                case RL_OVERLAPENDSAFTER:
                    /* The range of interest hits an invalid block before the end: */
                    if (invalid_range->rl_start == blockposition) {
                    	/* There's actually no valid information to be had starting here: */
                    	*ap->a_bnp = (daddr_t)-1;
						if ((HTOFCB(hp)->fcbEOF > (invalid_range->rl_end + 1)) &&
							(invalid_range->rl_end + 1 - blockposition < bytesContAvail)) {
                    		bytesContAvail = invalid_range->rl_end + 1 - blockposition;
                    	};
                    } else {
                    	bytesContAvail = invalid_range->rl_start - blockposition;
                    };
                    break;
            };
			if (bytesContAvail > MAXPHYSIO) bytesContAvail = MAXPHYSIO;
        };
        
        /* Figure out how many read ahead blocks there are */
        if (ap->a_runp != NULL) {
            if (can_cluster(logBlockSize)) {
                /* Make sure this result never goes negative: */
                *ap->a_runp = (bytesContAvail < logBlockSize) ? 0 : (bytesContAvail / logBlockSize) - 1;
            } else {
                *ap->a_runp = 0;
            };
        };
    };

    DBG_IO(("%d:%d.\n", *ap->a_bnp, (bytesContAvail < logBlockSize) ? 0 : (bytesContAvail / logBlockSize) - 1));

#if DEBUG_BMAP

    DBG_VOP_LOCKS_TEST(retval);
#endif

    if (ap->a_runp) {
        DBG_ASSERT((*ap->a_runp * logBlockSize) < bytesContAvail);							/* At least *ap->a_runp blocks left and ... */
        if (can_cluster(logBlockSize)) {
            DBG_ASSERT(bytesContAvail - (*ap->a_runp * logBlockSize) < (2*logBlockSize));	/* ... at most 1 logical block accounted for by current block */
                                                                                            /* ... plus some sub-logical block sized piece */
        };
    };

    return (retval);
}

/* blktooff converts logical block number to file offset */

int
hfs_blktooff(ap)
struct vop_blktooff_args /* {
    struct vnode *a_vp;
    daddr_t a_lblkno;  
    off_t *a_offset;
} */ *ap;
{	
	if (ap->a_vp == NULL)
		return (EINVAL);
	*ap->a_offset = (off_t)ap->a_lblkno * PAGE_SIZE_64;

	return(0);
}

int
hfs_offtoblk(ap)
struct vop_offtoblk_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	daddr_t *a_lblkno;
} */ *ap;
{	
	long lbsize, boff;

	if (ap->a_vp == NULL)
		return (EINVAL);
	*ap->a_lblkno = ap->a_offset / PAGE_SIZE_64;

	return(0);
}

int
hfs_cmap(ap)
struct vop_cmap_args /* {
	struct vnode *a_vp;
	off_t a_foffset;    
	size_t a_size;
	daddr_t *a_bpn;
	size_t *a_run;
	void *a_poff;
} */ *ap;
{
    struct hfsnode 	*hp = VTOH(ap->a_vp);
    struct hfsmount 	*hfsmp = VTOHFS(ap->a_vp);
    FCB					*fcb = HTOFCB(hp);
    size_t				bytesContAvail = 0;
    int			retval = E_NONE;
    int					lockExtBtree;
    struct proc		*p = NULL;
    struct rl_entry *invalid_range;
    enum rl_overlaptype overlaptype;
    off_t limit;

#define DEBUG_CMAP 0
#if DEBUG_CMAP
    DBG_FUNC_NAME("hfs_cmap");
    DBG_VOP_LOCKS_DECL(2);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);

    DBG_VOP_LOCKS_INIT(0, ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
#endif

    DBG_IO(("\tMapped offset %qx --> ", ap->a_foffset));
    /*
     * Check for underlying vnode requests and ensure that logical
     * to physical mapping is requested.
     */
    if (ap->a_bpn == NULL) {
        return (0);
    };

    if (lockExtBtree = hasOverflowExtents(hp))
    {
        p = current_proc();
        if (retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE | LK_CANRECURSE, p)) {
            return (retval);
        };
    }
    retval = MacToVFSError(
			   MapFileBlockC (HFSTOVCB(hfsmp),
					  fcb,
					  ap->a_size,
					  ap->a_foffset,
					  ap->a_bpn,
					  &bytesContAvail));

    if (lockExtBtree) (void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);

    if (retval == E_NONE) {
        /* Adjust the mapping information for invalid file ranges: */
        overlaptype = rl_scan(&hp->h_invalidranges,
                            ap->a_foffset,
                            ap->a_foffset + (off_t)bytesContAvail - 1,
                            &invalid_range);
        if (overlaptype != RL_NOOVERLAP) {
            switch(overlaptype) {
                case RL_MATCHINGOVERLAP:
                case RL_OVERLAPCONTAINSRANGE:
                case RL_OVERLAPSTARTSBEFORE:
                    /* There's no valid block for this byte offset: */
                    *ap->a_bpn = (daddr_t)-1;
                    
                    /* There's no point limiting the amount to be returned if the
                       invalid range that was hit extends all the way to the EOF
                       (i.e. there's no valid bytes between the end of this range
                       and the file's EOF):
                     */
                    if ((fcb->fcbEOF > (invalid_range->rl_end + 1)) &&
        				(invalid_range->rl_end + 1 - ap->a_foffset < bytesContAvail)) {
                    	bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
                    };
                    break;
                
                case RL_OVERLAPISCONTAINED:
                case RL_OVERLAPENDSAFTER:
                    /* The range of interest hits an invalid block before the end: */
                    if (invalid_range->rl_start == ap->a_foffset) {
                    	/* There's actually no valid information to be had starting here: */
                    	*ap->a_bpn = (daddr_t)-1;
						if ((fcb->fcbEOF > (invalid_range->rl_end + 1)) &&
							(invalid_range->rl_end + 1 - ap->a_foffset < bytesContAvail)) {
                    		bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
                    	};
                    } else {
                    	bytesContAvail = invalid_range->rl_start - ap->a_foffset;
                    };
                    break;
            };
            if (bytesContAvail > ap->a_size) bytesContAvail = ap->a_size;
        };
        
        if (ap->a_run) *ap->a_run = bytesContAvail;
    };

    if (ap->a_poff) *(int *)ap->a_poff = 0;

    DBG_IO(("%d:%d.\n", *ap->a_bpn, bytesContAvail));

#if DEBUG_BMAP

    DBG_VOP_LOCKS_TEST(retval);
#endif

    return (retval);

}

/*
 * Calculate the logical to physical mapping if not done already,
 * then call the device strategy routine.
#
#vop_strategy {
#	IN struct buf *bp;
    */
int
hfs_strategy(ap)
struct vop_strategy_args /* {
    struct buf *a_bp;
} */ *ap;
{
    register struct buf *bp = ap->a_bp;
    register struct vnode *vp = bp->b_vp;
    register struct hfsnode *hp;
    int retval = 0;

	DBG_FUNC_NAME("hfs_strategy");

//	DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\n"));

    hp = VTOH(vp);

    if ( !(bp->b_flags & B_VECTORLIST)) {

        if (vp->v_type == VBLK || vp->v_type == VCHR)
	    panic("hfs_strategy: device vnode passed!");

	if (bp->b_flags & B_PAGELIST) {
	    /*
	     * if we have a page list associated with this bp,
	     * then go through cluster_bp since it knows how to 
	     * deal with a page request that might span non-contiguous
	     * physical blocks on the disk...
	     */
	    retval = cluster_bp(bp);
	    vp = hp->h_meta->h_devvp;
	    bp->b_dev = vp->v_rdev;

	    return (retval);
	}
	/*
	 * If we don't already know the filesystem relative block number
	 * then get it using VOP_BMAP().  If VOP_BMAP() returns the block
	 * number as -1 then we've got a hole in the file.  Although HFS
         * filesystems don't create files with holes, invalidating of
         * subranges of the file (lazy zero filling) may create such a
         * situation.
	 */
	if (bp->b_blkno == bp->b_lblkno) {
	    if ((retval = VOP_BMAP(vp, bp->b_lblkno, NULL, &bp->b_blkno, NULL))) {
	        bp->b_error = retval;
		bp->b_flags |= B_ERROR;
		biodone(bp);
		return (retval);
	    }
	    if ((long)bp->b_blkno == -1)
	        clrbuf(bp);
	}
	if ((long)bp->b_blkno == -1) {
	    biodone(bp);
	    return (0);
	}
	if (bp->b_validend == 0) {
	    /* Record the exact size of the I/O transfer about to be made: */
	    DBG_ASSERT(bp->b_validoff == 0);
	    bp->b_validend = bp->b_bcount;
	    DBG_ASSERT(bp->b_dirtyoff == 0);
	};
    }
    vp = hp->h_meta->h_devvp;
    bp->b_dev = vp->v_rdev;
    DBG_IO(("\t\t>>>%s: continuing w/ vp: 0x%x with logBlk Ox%X and phyBlk Ox%X\n", funcname, (u_int)vp, bp->b_lblkno, bp->b_blkno));

    return VOCALL (vp->v_op, VOFFSET(vop_strategy), ap);
}


/*
#% reallocblks	vp	L L L
#
 vop_reallocblks {
     IN struct vnode *vp;
     IN struct cluster_save *buflist;

     */

int
hfs_reallocblks(ap)
struct vop_reallocblks_args /* {
    struct vnode *a_vp;
    struct cluster_save *a_buflist;
} */ *ap;
{
    DBG_FUNC_NAME("hfs_reallocblks");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    /* Currently no support for clustering */		/* XXX */
    DBG_VOP_LOCKS_TEST(ENOSPC);
    return (ENOSPC);
}



/*
#
#% truncate	vp	L L L
#
vop_truncate {
    IN struct vnode *vp;
    IN off_t length;
    IN int flags;	(IO_SYNC)
    IN struct ucred *cred;
    IN struct proc *p;
};
 * Truncate the hfsnode hp to at most length size, freeing (or adding) the
 * disk blocks.
 */
int hfs_truncate(ap)
    struct vop_truncate_args /* {
        struct vnode *a_vp;
        off_t a_length;
        int a_flags;
        struct ucred *a_cred;
        struct proc *a_p;
    } */ *ap;
{
    register struct vnode *vp = ap->a_vp;
    register struct hfsnode *hp = VTOH(vp);
    off_t length = ap->a_length;
    long vflags;
    struct timeval tv;
    int retval;
    FCB *fcb;
    off_t bytesToAdd;
    off_t actualBytesAdded;
    DBG_FUNC_NAME("hfs_truncate");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(ap->a_vp);
#endif

    fcb = HTOFCB(hp);

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_START,
		 (int)length, fcb->fcbEOF, fcb->fcbPLen, 0, 0);

    if (length < 0) {
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
    }

    if ((!ISHFSPLUS(VTOVCB(vp))) && (length > (off_t)MAXHFSFILESIZE)) {	
        DBG_VOP_LOCKS_TEST(EFBIG);
	return (EFBIG);
    }

    if (vp->v_type != VREG && vp->v_type != VLNK) {		
        DBG_VOP_LOCKS_TEST(EISDIR);
        return (EISDIR);		/* hfs doesn't support truncating of directories */
    }

    tv = time;
    retval = E_NONE;
	
    DBG_RW(("%s: truncate from Ox%lX to Ox%X bytes\n", funcname, fcb->fcbPLen, length));

    /* 
     * we cannot just check if fcb->fcbEOF == length (as an optimization)
     * since there may be extra physical blocks that also need truncation
     */

    /*
     * Lengthen the size of the file. We must ensure that the
     * last byte of the file is allocated. Since the smallest
     * value of fcbEOF is 0, length will be at least 1.
     */
    if (length > fcb->fcbEOF) {
		off_t filePosition;
		daddr_t logBlockNo;
		long logBlockSize;
		long blkOffset;
		off_t bytestoclear;
		int blockZeroCount;
		struct buf *bp=NULL;

	/*
	 * If we don't have enough physical space then
	 * we need to extend the physical size.
	 */
	if (length > fcb->fcbPLen) {
	    /* lock extents b-tree (also protects volume bitmap) */
	    retval = hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
	    if (retval)
	        goto Err_Exit;

	    while ((length > fcb->fcbPLen) && (retval == E_NONE)) {
	        bytesToAdd = length - fcb->fcbPLen;
		retval = MacToVFSError(
                                       ExtendFileC (HTOVCB(hp),
                                                    fcb,
                                                    bytesToAdd,
                                                    0,
                                                    kEFAllMask,	/* allocate all requested bytes or none */
                                                    &actualBytesAdded));

		if (actualBytesAdded == 0 && retval == E_NONE) {
		    if (length > fcb->fcbPLen)
		        length = fcb->fcbPLen;
		    break;
		}
	    } 
	    (void) hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);
	    if (retval)
	        goto Err_Exit;

	    DBG_ASSERT(length <= fcb->fcbPLen);
	    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_NONE,
			 (int)length, fcb->fcbEOF, fcb->fcbPLen, 0, 0);
	}
 
	if (! (ap->a_flags & IO_NOZEROFILL)) {

	    if (UBCISVALID(vp) && retval == E_NONE) {
			struct rl_entry *invalid_range;
	        int devBlockSize;
			off_t zero_limit;
			
			zero_limit = (fcb->fcbEOF + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
			if (length < zero_limit) zero_limit = length;

			if (length > fcb->fcbEOF) {
		   		/* Extending the file: time to fill out the current last page w. zeroes? */
		   		if ((fcb->fcbEOF & PAGE_MASK_64) &&
		   			(rl_scan(&hp->h_invalidranges,
							 fcb->fcbEOF & ~PAGE_MASK_64,
							 fcb->fcbEOF - 1,
							 &invalid_range) == RL_NOOVERLAP)) {
		   				
						/* There's some valid data at the start of the (current) last page
						   of the file, so zero out the remainder of that page to ensure the
						   entire page contains valid data.  Since there is no invalid range
						   possible past the (current) eof, there's no need to remove anything
						   from the invalid range list before calling cluster_write():						 */
						VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);
						retval = cluster_write(vp, (struct uio *) 0, fcb->fcbEOF, zero_limit,
												fcb->fcbEOF, (off_t)0, devBlockSize, (ap->a_flags & IO_SYNC) | IO_HEADZEROFILL);
						if (retval) goto Err_Exit;
						
						/* Merely invalidate the remaining area, if necessary: */
						if (length > zero_limit) rl_add(zero_limit, length - 1, &hp->h_invalidranges);
		   		} else {
					/* The page containing the (current) eof is invalid: just add the
					   remainder of the page to the invalid list, along with the area
					   being newly allocated:
					 */
					rl_add(fcb->fcbEOF, length - 1, &hp->h_invalidranges);
				};
			}
	    } else {

#if 0
		    /*
		     * zero out any new logical space...
		     */
		    bytestoclear = length - fcb->fcbEOF;
		    filePosition = fcb->fcbEOF;

		    while (bytestoclear > 0) {
		        logBlockNo   = (daddr_t)(filePosition / PAGE_SIZE_64);
			blkOffset    = (long)(filePosition & PAGE_MASK_64);  

			if (((off_t)(fcb->fcbPLen) - ((off_t)logBlockNo * (off_t)PAGE_SIZE)) < PAGE_SIZE_64)
			    logBlockSize = (off_t)(fcb->fcbPLen) - ((off_t)logBlockNo * PAGE_SIZE_64);
			else
			    logBlockSize = PAGE_SIZE;
			
			if (logBlockSize < blkOffset)
			    panic("hfs_truncate: bad logBlockSize computed\n");
			        
			blockZeroCount = MIN(bytestoclear, logBlockSize - blkOffset);

			if (blkOffset == 0 && ((bytestoclear >= logBlockSize) || filePosition >= fcb->fcbEOF)) {
			    bp = getblk(vp, logBlockNo, logBlockSize, 0, 0, BLK_WRITE);
			    retval = 0;

			} else {
			    retval = bread(vp, logBlockNo, logBlockSize, ap->a_cred, &bp);
			    if (retval) {
			        brelse(bp);
				goto Err_Exit;
			    }
			}
			bzero((char *)bp->b_data + blkOffset, blockZeroCount);
					
			bp->b_flags |= B_DIRTY | B_AGE;

			if (ap->a_flags & IO_SYNC)
			    VOP_BWRITE(bp);
			else if (logBlockNo % 32)
			    bawrite(bp);
			else
			    VOP_BWRITE(bp);	/* wait after we issue 32 requests */

			bytestoclear -= blockZeroCount;
			filePosition += blockZeroCount;
		    }
#else
			panic("hfs_truncate: invoked on non-UBC object?!");
#endif
	    };
	}
	fcb->fcbEOF = length;

	if (UBCISVALID(vp))
	        ubc_setsize(vp, (off_t)fcb->fcbEOF); /* XXX check errors */

    } else { /* Shorten the size of the file */

        if (fcb->fcbEOF > length) {
	    /*
	     * Any buffers that are past the truncation point need to be
	     * invalidated (to maintain buffer cache consistency).  For
	     * simplicity, we invalidate all the buffers by calling vinvalbuf.
	     */
	    if (UBCISVALID(vp))
	        ubc_setsize(vp, (off_t)length); /* XXX check errors */

	    vflags = ((length > 0) ? V_SAVE : 0)  | V_SAVEMETA;	
	    retval = vinvalbuf(vp, vflags, ap->a_cred, ap->a_p, 0, 0);
	    
	    /* Any space previously marked as invalid is now irrelevant: */
	    rl_remove(length, fcb->fcbEOF - 1, &hp->h_invalidranges);
	}

	/*
	 * For a TBE process the deallocation of the file blocks is
	 * delayed until the file is closed.  And hfs_close calls
	 * truncate with the IO_NDELAY flag set.  So when IO_NDELAY
	 * isn't set, we make sure this isn't a TBE process.
	 */
	if ((ap->a_flags & IO_NDELAY) || (!ISSET(ap->a_p->p_flag, P_TBE))) {

	    /* lock extents b-tree (also protects volume bitmap) */
	    retval = hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
	    if (retval)
	        goto Err_Exit;
	    retval = MacToVFSError(
                               TruncateFileC(	
                                             HTOVCB(hp),
                                             fcb,
                                             length,
                                             false));
	    (void) hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);
	    if (retval)
	        goto Err_Exit;
	}
	fcb->fcbEOF = length;

	if (fcb->fcbFlags & fcbModifiedMask)
	    hp->h_nodeflags |= IN_MODIFIED;
    }
    hp->h_nodeflags |= IN_CHANGE | IN_UPDATE;
    retval = VOP_UPDATE(vp, &tv, &tv, MNT_WAIT);
    if (retval) {
        DBG_ERR(("Could not update truncate"));
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_NONE,
		     -1, -1, -1, retval, 0);
    }
Err_Exit:;

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(ap->a_vp);
#endif

    KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_END,
		 (int)length, fcb->fcbEOF, fcb->fcbPLen, retval, 0);

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}



/*
#
#% allocate	vp	L L L
#
vop_allocate {
	IN struct vnode *vp;
	IN off_t length;
	IN int flags;
	OUT off_t *bytesallocated;
	IN off_t offset;
	IN struct ucred *cred;
	IN struct proc *p;
};
 * allocate the hfsnode hp to at most length size
 */
int hfs_allocate(ap)
    struct vop_allocate_args /* {
        struct vnode *a_vp;
        off_t a_length;
        u_int32_t  a_flags;
        off_t *a_bytesallocated;
        off_t a_offset;
        struct ucred *a_cred;
        struct proc *a_p;
    } */ *ap;
{
    register struct vnode *vp = ap->a_vp;
    register struct hfsnode *hp = VTOH(vp);
    off_t	length = ap->a_length;
    off_t	startingPEOF;
    off_t	moreBytesRequested;
    off_t	actualBytesAdded;
    long vflags;
    struct timeval tv;
    int retval, retval2;
    FCB *fcb;
    UInt32 blockHint;
    UInt32 extendFlags =0;   /* For call to ExtendFileC */
    DBG_FUNC_NAME("hfs_allocate");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    /* Set the number of bytes allocated to 0 so that the caller will know that we
       did nothing.  ExtendFileC will fill this in for us if we actually allocate space */

    *(ap->a_bytesallocated) = 0; 
    fcb = HTOFCB(hp);

    /* Now for some error checking */

    if (length < (off_t)0) {
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
    }

    if (vp->v_type != VREG && vp->v_type != VLNK) {
        DBG_VOP_LOCKS_TEST(EISDIR);
        return (EISDIR);        /* hfs doesn't support truncating of directories */
    }

    if ((ap->a_flags & ALLOCATEFROMVOL) && (length <= fcb->fcbPLen))
        return (EINVAL);

    /* Fill in the flags word for the call to Extend the file */

	if (ap->a_flags & ALLOCATECONTIG) {
		extendFlags |= kEFContigMask;
	}

    if (ap->a_flags & ALLOCATEALL) {
		extendFlags |= kEFAllMask;
	}

    tv = time;
    retval = E_NONE;
    blockHint = 0;
    startingPEOF = fcb->fcbPLen;

    if (ap->a_flags & ALLOCATEFROMPEOF) {
		length += fcb->fcbPLen;
	}

	if (ap->a_flags & ALLOCATEFROMVOL)
		blockHint = ap->a_offset / HTOVCB(hp)->blockSize;

    /* If no changes are necesary, then we're done */
    if (fcb->fcbPLen == length)
    	goto Std_Exit;

    /*
    * Lengthen the size of the file. We must ensure that the
    * last byte of the file is allocated. Since the smallest
    * value of fcbPLen is 0, length will be at least 1.
    */
    if (length > fcb->fcbPLen) {
		moreBytesRequested = length - fcb->fcbPLen;
		
		/* lock extents b-tree (also protects volume bitmap) */
		retval = hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
		if (retval) goto Err_Exit;

		retval = MacToVFSError(
								ExtendFileC(HTOVCB(hp),
											fcb,
											moreBytesRequested,
											blockHint,
											extendFlags,
											&actualBytesAdded));

		*(ap->a_bytesallocated) = actualBytesAdded;

		(void) hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

		DBG_ASSERT(length <= fcb->fcbPLen);

		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the VOP_UPDATE to reflect the changes
		 */
        if (retval && (startingPEOF == fcb->fcbPLen)) goto Err_Exit;
        
        /*
         * Adjust actualBytesAdded to be allocation block aligned, not
         * clump size aligned.
         * NOTE: So what we are reporting does not affect reality
         * until the file is closed, when we truncate the file to allocation
         * block size.
         */

		if ((actualBytesAdded != 0) && (moreBytesRequested < actualBytesAdded))
			*(ap->a_bytesallocated) =
				roundup(moreBytesRequested, (off_t)VTOVCB(vp)->blockSize);

    } else { /* Shorten the size of the file */

    	if (fcb->fcbEOF > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).  For
			 * simplicity, we invalidate all the buffers by calling vinvalbuf.
			 */
			vflags = ((length > 0) ? V_SAVE : 0) | V_SAVEMETA;
			(void) vinvalbuf(vp, vflags, ap->a_cred, ap->a_p, 0, 0);
		}

       /* lock extents b-tree (also protects volume bitmap) */
        retval = hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
        if (retval) goto Err_Exit;

        retval = MacToVFSError(
                            TruncateFileC(
                                            HTOVCB(hp),
                                            fcb,
                                            length,
                                            false));
        (void) hfs_metafilelocking(HTOHFS(hp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the VOP_UPDATE to reflect the changes
		 */
		if (retval && (startingPEOF == fcb->fcbPLen)) goto Err_Exit;
        if (fcb->fcbFlags & fcbModifiedMask)
           hp->h_nodeflags |= IN_MODIFIED;

        DBG_ASSERT(length <= fcb->fcbPLen)  // DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG

        if (fcb->fcbEOF > fcb->fcbPLen) {
			fcb->fcbEOF = fcb->fcbPLen;

			if (UBCISVALID(vp))
				ubc_setsize(vp, (off_t)fcb->fcbEOF); /* XXX check errors */
        }
    }

Std_Exit:
    hp->h_nodeflags |= IN_CHANGE | IN_UPDATE;
	retval2 = VOP_UPDATE(vp, &tv, &tv, MNT_WAIT);

    if (retval == 0) retval = retval2;

Err_Exit:
    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}




/* pagein for HFS filesystem, similar to hfs_read(), but without cluster_read() */
int
hfs_pagein(ap)
	struct vop_pagein_args /* {
	   	struct vnode *a_vp,
	   	upl_t 	      a_pl,
		vm_offset_t   a_pl_offset,
		off_t         a_f_offset,
		size_t        a_size,
		struct ucred *a_cred,
		int           a_flags
	} */ *ap;
{
    register struct vnode *vp;
    struct hfsnode 	  *hp;
    FCB			  *fcb;
    int				devBlockSize = 0;
    int 		   retval;

    DBG_FUNC_NAME("hfs_pagein");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    vp  = ap->a_vp;
    hp  = VTOH(vp);
    fcb = HTOFCB(hp);

    if (vp->v_type != VREG && vp->v_type != VLNK)
	panic("hfs_pagein: vp not UBC type\n");

    DBG_VOP(("\tfile size Ox%X\n", (u_int)fcb->fcbEOF));
    DBG_VOP(("\tstarting at offset Ox%X of file, length Ox%X\n", (u_int)ap->a_f_offset, (u_int)ap->a_size));

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(vp);
#endif

    VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

    retval = cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
			 ap->a_size, (off_t)fcb->fcbEOF, devBlockSize,
			 ap->a_flags);

#if HFS_DIAGNOSTIC
    debug_check_blocksizes(vp);
#endif
    DBG_VOP_LOCKS_TEST(retval);

    return (retval);
}

/* 
 * pageout for HFS filesystem.
 */
int
hfs_pageout(ap)
	struct vop_pageout_args /* {
	   struct vnode *a_vp,
	   upl_t         a_pl,
	   vm_offset_t   a_pl_offset,
	   off_t         a_f_offset,
	   size_t        a_size,
	   struct ucred *a_cred,
	   int           a_flags
	} */ *ap;
{
	struct vnode	*vp = ap->a_vp;
	struct hfsnode	*hp =  VTOH(vp);
	FCB	        *fcb = HTOFCB(hp);
	int              retval;
	int              devBlockSize = 0;
	off_t            end_of_range;

	DBG_FUNC_NAME("hfs_pageout");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(vp);DBG_VOP_CONT(("\n"));
	DBG_VOP(("\thfsnode 0x%x (%s)\n", (u_int)hp, H_NAME(hp)));
	DBG_VOP(("\tstarting at offset Ox%lX of file, length Ox%lX\n", 
		(UInt32)ap->a_f_offset, (UInt32)ap->a_size));

	DBG_VOP_LOCKS_INIT(0, vp, VOPDBG_LOCKED, 
		VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

#if HFS_DIAGNOSTIC
	debug_check_blocksizes(vp);
#endif

	if (UBCINVALID(vp))
		panic("hfs_pageout: Not a  VREG: vp=%x", vp);

	VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);

	end_of_range = ap->a_f_offset + ap->a_size - 1;

	if (end_of_range >= (off_t)fcb->fcbEOF)
	        end_of_range = (off_t)(fcb->fcbEOF - 1);

	if (ap->a_f_offset < (off_t)fcb->fcbEOF)
	        rl_remove(ap->a_f_offset, end_of_range, &hp->h_invalidranges);

	retval = cluster_pageout(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size,
				 (off_t)fcb->fcbEOF, devBlockSize, ap->a_flags);

	/*
	 * If we successfully wrote any data, and we are not the superuser
	 * we clear the setuid and setgid bits as a precaution against
	 * tampering.
	 */
	if (retval == 0 && ap->a_cred && ap->a_cred->cr_uid != 0)
		hp->h_meta->h_mode &= ~(ISUID | ISGID);

#if HFS_DIAGNOSTIC
	debug_check_blocksizes(vp);
#endif

	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}

/*
 * Intercept B-Tree node writes to unswap them if necessary.
#
#vop_bwrite {
#	IN struct buf *bp;
 */
int
hfs_bwrite(ap)
struct vop_bwrite_args /* {
    struct buf *a_bp;
} */ *ap;
{
    register struct buf *bp = ap->a_bp;
    register struct vnode *vp = bp->b_vp;
    BlockDescriptor block;
    int retval = 0;

	DBG_FUNC_NAME("hfs_bwrite");

#if BYTE_ORDER == LITTLE_ENDIAN
    /* Trap B-Tree writes */
    if ((H_FILEID(VTOH(vp)) == kHFSExtentsFileID) ||
        (H_FILEID(VTOH(vp)) == kHFSCatalogFileID)) {

        /* Swap if the B-Tree node is in native byte order */
        if (((UInt16 *)((char *)bp->b_data + bp->b_bcount - 2))[0] == 0x000e) {
            /* Prepare the block pointer */
            block.blockHeader = bp;
            block.buffer = bp->b_data + IOBYTEOFFSETFORBLK(bp->b_blkno, VTOHFS(vp)->hfs_phys_block_size);
            block.blockReadFromDisk = (bp->b_flags & B_CACHE) == 0;	/* not found in cache ==> came from disk */
            block.blockSize = bp->b_bcount;
    
            /* Endian un-swap B-Tree node */
            SWAP_BT_NODE (&block, ISHFSPLUS (VTOVCB(vp)), H_FILEID(VTOH(vp)), 1);
        }

        /* We don't check to make sure that it's 0x0e00 because it could be all zeros */
    }
#endif

    retval = vn_bwrite (ap);

    return (retval);
}
