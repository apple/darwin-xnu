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
/*	@(#)hfs_readwrite.c	1.0
 *
 *	(c) 1998-2001 Apple Computer, Inc.  All Rights Reserved
 *	
 *	hfs_readwrite.c -- vnode operations to deal with reading and writing files.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/uio.h>

#include <miscfs/specfs/specdev.h>

#include <sys/ubc.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#include	"hfs.h"
#include	"hfs_endian.h"
#include	"hfs_quota.h"
#include	"hfscommon/headers/FileMgrInternal.h"
#include	"hfscommon/headers/BTreesInternal.h"
#include	"hfs_cnode.h"
#include	"hfs_dbg.h"

extern int overflow_extents(struct filefork *fp);

#define can_cluster(size) ((((size & (4096-1))) == 0) && (size <= (MAXPHYSIO/2)))

enum {
	MAXHFSFILESIZE = 0x7FFFFFFF		/* this needs to go in the mount structure */
};

extern u_int32_t GetLogicalBlockSize(struct vnode *vp);


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
	register struct uio *uio = ap->a_uio;
	register struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	struct buf *bp;
	daddr_t logBlockNo;
	u_long fragSize, moveSize, startOffset, ioxfersize;
	int devBlockSize = 0;
	off_t bytesRemaining;
	int retval = 0;
    	off_t filesize;
    	off_t filebytes;

	/* Preflight checks */
	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EISDIR);	/* HFS can only read files */
	if (uio->uio_resid == 0)
		return (0);		/* Nothing left to do */
	if (uio->uio_offset < 0)
		return (EINVAL);	/* cant read from a negative offset */

	cp = VTOC(vp);
	fp = VTOF(vp);
	filesize = fp->ff_size;
	filebytes = (off_t)fp->ff_blocks * (off_t)VTOVCB(vp)->blockSize;
	if (uio->uio_offset > filesize) {
		if ((!ISHFSPLUS(VTOVCB(vp))) && (uio->uio_offset > (off_t)MAXHFSFILESIZE))
			return (EFBIG);
		else
			return (0);
	}

	VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_START,
		(int)uio->uio_offset, uio->uio_resid, (int)filesize, (int)filebytes, 0);

	if (UBCISVALID(vp)) {
		retval = cluster_read(vp, uio, filesize, devBlockSize, 0);
	} else {

		for (retval = 0, bp = NULL; uio->uio_resid > 0; bp = NULL) {

            if ((bytesRemaining = (filesize - uio->uio_offset)) <= 0)
                break;

            logBlockNo  = (daddr_t)(uio->uio_offset / PAGE_SIZE_64);
            startOffset = (u_long) (uio->uio_offset & PAGE_MASK_64);
            fragSize    = PAGE_SIZE;

            if (((logBlockNo * PAGE_SIZE) + fragSize) < filesize)
                ioxfersize = fragSize;
            else {
                ioxfersize = filesize - (logBlockNo * PAGE_SIZE);
                ioxfersize = (ioxfersize + (devBlockSize - 1)) & ~(devBlockSize - 1);
            }
		moveSize = ioxfersize;
		moveSize -= startOffset;

            if (bytesRemaining < moveSize)
                moveSize = bytesRemaining;

            if (uio->uio_resid < moveSize) {
                moveSize = uio->uio_resid;
            };
            if (moveSize == 0) {
                break;
            };

            if (( uio->uio_offset + fragSize) >= filesize) {
                retval = bread(vp, logBlockNo, ioxfersize, NOCRED, &bp);

            } else if (logBlockNo - 1 == vp->v_lastr && !(vp->v_flag & VRAOFF)) {
                daddr_t nextLogBlockNo = logBlockNo + 1;
                int nextsize;

                if (((nextLogBlockNo * PAGE_SIZE) +
                     (daddr_t)fragSize) < filesize)
                    nextsize = fragSize;
                else {
                    nextsize = filesize - (nextLogBlockNo * PAGE_SIZE);
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

            if ((retval = uiomove((caddr_t)bp->b_data + startOffset, (int)moveSize, uio)))
                break;

            if (S_ISREG(cp->c_mode) &&
                (((startOffset + moveSize) == fragSize) || (uio->uio_offset == filesize))) {
                bp->b_flags |= B_AGE;
            };

            brelse(bp);
            /* Start of loop resets bp to NULL before reaching outside this block... */
        }

		if (bp != NULL) {
			brelse(bp);
		}
	}

	cp->c_flag |= C_ACCESS;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_END,
		(int)uio->uio_offset, uio->uio_resid, (int)filesize,  (int)filebytes, 0);

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
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct cnode *cp;
	struct filefork *fp;
	struct buf *bp;
	struct proc *p;
	struct timeval tv;
	ExtendedVCB *vcb;
    int					devBlockSize = 0;
    daddr_t 			logBlockNo;
    long				fragSize;
    off_t 				origFileSize, currOffset, writelimit, bytesToAdd;
    off_t				actualBytesAdded;
    u_long				blkoffset, resid, xfersize, clearSize;
    int					eflags, ioflag;
    int 				retval;
	off_t filebytes;
	u_long fileblocks;
	struct hfsmount *hfsmp;
	int started_tr = 0, grabbed_lock = 0;

	ioflag = ap->a_ioflag;

	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (E_NONE);
	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EISDIR);	/* Can only write files */

	cp = VTOC(vp);
	fp = VTOF(vp);
	vcb = VTOVCB(vp);
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)vcb->blockSize;

	if (ioflag & IO_APPEND)
		uio->uio_offset = fp->ff_size;
	if ((cp->c_flags & APPEND) && uio->uio_offset != fp->ff_size)
		return (EPERM);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (VTOHFS(vp)->jnl && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_data.cf_extents[0];
		if (extd->startBlock == VTOVCB(vp)->vcbJinfoBlock || extd->startBlock == VTOHFS(vp)->jnl_start) {
			return EPERM;
		}
	}

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
	}
	p = current_proc();

	VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);

	resid = uio->uio_resid;
	origFileSize = fp->ff_size;
	eflags = kEFDeferMask;	/* defer file block allocations */
	filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

	/*
	 * NOTE: In the following loop there are two positions tracked:
	 * currOffset is the current I/O starting offset.  currOffset
	 * is never >LEOF; the LEOF is nudged along with currOffset as
	 * data is zeroed or written. uio->uio_offset is the start of
	 * the current I/O operation.  It may be arbitrarily beyond
	 * currOffset.
	 *
	 * The following is true at all times:
	 *   currOffset <= LEOF <= uio->uio_offset <= writelimit
	 */
	currOffset = MIN(uio->uio_offset, fp->ff_size);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_START,
		(int)uio->uio_offset, uio->uio_resid, (int)fp->ff_size, (int)filebytes, 0);
	retval = 0;

	/* Now test if we need to extend the file */
	/* Doing so will adjust the filebytes for us */

#if QUOTA
	if(writelimit > filebytes) {
		bytesToAdd = writelimit - filebytes;

		retval = hfs_chkdq(cp, (int64_t)(roundup(bytesToAdd, vcb->blockSize)), 
				   ap->a_cred, 0);
		if (retval)
			return (retval);
	}
#endif /* QUOTA */

	hfsmp = VTOHFS(vp);
	if (writelimit > filebytes) {
		hfs_global_shared_lock_acquire(hfsmp);
		grabbed_lock = 1;
	}
	if (hfsmp->jnl && (writelimit > filebytes)) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			return EINVAL;
		}
		started_tr = 1;
	}

	while (writelimit > filebytes) {
	
		bytesToAdd = writelimit - filebytes;
		if (suser(ap->a_cred, NULL) != 0)
			eflags |= kEFReserveMask;

		/* lock extents b-tree (also protects volume bitmap) */
		retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, current_proc());
		if (retval != E_NONE)
			break;

		retval = MacToVFSError(ExtendFileC (vcb, (FCB*)fp, bytesToAdd,
				0, eflags, &actualBytesAdded));

		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);
		if ((actualBytesAdded == 0) && (retval == E_NONE))
			retval = ENOSPC;
		if (retval != E_NONE)
			break;
		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_NONE,
			(int)uio->uio_offset, uio->uio_resid, (int)fp->ff_size,  (int)filebytes, 0);
	}

	// XXXdbg
	if (started_tr) {
		hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
		journal_end_transaction(hfsmp->jnl);
		started_tr = 0;
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
		grabbed_lock = 0;
	}

	if (UBCISVALID(vp) && retval == E_NONE) {
		off_t filesize;
		off_t zero_off;
		off_t tail_off;
		off_t inval_start;
		off_t inval_end;
		off_t io_start, io_end;
		int lflag;
		struct rl_entry *invalid_range;

		if (writelimit > fp->ff_size)
			filesize = writelimit;
		else
			filesize = fp->ff_size;

		lflag = (ioflag & IO_SYNC);

		if (uio->uio_offset <= fp->ff_size) {
			zero_off = uio->uio_offset & ~PAGE_MASK_64;
			
			/* Check to see whether the area between the zero_offset and the start
			   of the transfer to see whether is invalid and should be zero-filled
			   as part of the transfer:
			 */
			if (rl_scan(&fp->ff_invalidranges, zero_off, uio->uio_offset - 1, &invalid_range) != RL_NOOVERLAP)
				lflag |= IO_HEADZEROFILL;
		} else {
			off_t eof_page_base = fp->ff_size & ~PAGE_MASK_64;
			
			/* The bytes between fp->ff_size and uio->uio_offset must never be
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
			inval_start = (fp->ff_size + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
			inval_end = uio->uio_offset & ~PAGE_MASK_64;
			zero_off = fp->ff_size;
			
			if ((fp->ff_size & PAGE_MASK_64) &&
				(rl_scan(&fp->ff_invalidranges,
							eof_page_base,
							fp->ff_size - 1,
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
					retval = cluster_write(vp, (struct uio *) 0,
							fp->ff_size, inval_start,
							zero_off, (off_t)0, devBlockSize,
							lflag | IO_HEADZEROFILL | IO_NOZERODIRTY);
					if (retval) goto ioerr_exit;
				};
				
				/* Mark the remaining area of the newly allocated space as invalid: */
				rl_add(inval_start, inval_end - 1 , &fp->ff_invalidranges);
				cp->c_zftimeout = time.tv_sec + ZFTIMELIMIT;
				zero_off = fp->ff_size = inval_end;
			};
			
			if (uio->uio_offset > zero_off) lflag |= IO_HEADZEROFILL;
		};

		/* Check to see whether the area between the end of the write and the end of
		   the page it falls in is invalid and should be zero-filled as part of the transfer:
		 */
		tail_off = (writelimit + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
		if (tail_off > filesize) tail_off = filesize;
		if (tail_off > writelimit) {
			if (rl_scan(&fp->ff_invalidranges, writelimit, tail_off - 1, &invalid_range) != RL_NOOVERLAP) {
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
		if (io_start < fp->ff_size) {
			rl_remove(io_start, io_end - 1, &fp->ff_invalidranges);
		};
		retval = cluster_write(vp, uio, fp->ff_size, filesize, zero_off,
				tail_off, devBlockSize, lflag | IO_NOZERODIRTY);
				
		if (uio->uio_offset > fp->ff_size) {
			fp->ff_size = uio->uio_offset;

			ubc_setsize(vp, fp->ff_size);       /* XXX check errors */
		}
		if (resid > uio->uio_resid)
			cp->c_flag |= C_CHANGE | C_UPDATE;
	} else {
		while (retval == E_NONE && uio->uio_resid > 0) {
			logBlockNo = currOffset / PAGE_SIZE;
			blkoffset  = currOffset & PAGE_MASK;

			if ((filebytes - currOffset) < PAGE_SIZE_64)
				fragSize = filebytes - ((off_t)logBlockNo * PAGE_SIZE_64);
			else
				fragSize = PAGE_SIZE;
			xfersize = fragSize - blkoffset;
	
			/* Make any adjustments for boundary conditions */
			if (currOffset + (off_t)xfersize > writelimit)
				xfersize = writelimit - currOffset;
	 
			/*
			 * There is no need to read into bp if:
			 * We start on a block boundary and will overwrite the whole block
			 *
			 *						OR
			 */
			if ((blkoffset == 0) && (xfersize >= fragSize)) {
				bp = getblk(vp, logBlockNo, fragSize, 0, 0, BLK_READ);
				retval = 0;
	
				if (bp->b_blkno == -1) {
					brelse(bp);
					retval = EIO;		/* XXX */
					break;
				}
			} else {
	
				if (currOffset == fp->ff_size && blkoffset == 0) {
					bp = getblk(vp, logBlockNo, fragSize, 0, 0, BLK_READ);
					retval = 0;
					if (bp->b_blkno == -1) {
						brelse(bp);
						retval = EIO;		/* XXX */
						break;
					}
				} else {
					/*
					 * This I/O transfer is not sufficiently aligned,
					 * so read the affected block into a buffer:
					 */
					retval = bread(vp, logBlockNo, fragSize, ap->a_cred, &bp);
					if (retval != E_NONE) {
						if (bp)
						brelse(bp);
						break;
					}
				}
			}
	
			/* See if we are starting to write within file boundaries:
			 * If not, then we need to present a "hole" for the area
			 * between the current EOF and the start of the current
			 * I/O operation:
			 *
			 * Note that currOffset is only less than uio_offset if
			 * uio_offset > LEOF...
			 */
			if (uio->uio_offset > currOffset) {
				clearSize = MIN(uio->uio_offset - currOffset, xfersize);
				bzero(bp->b_data + blkoffset, clearSize);
				currOffset += clearSize;
				blkoffset += clearSize;
				xfersize -= clearSize;
			}
	
			if (xfersize > 0) {
				retval = uiomove((caddr_t)bp->b_data + blkoffset, (int)xfersize, uio);
				currOffset += xfersize;
			}
	
			if (ioflag & IO_SYNC) {
				(void)VOP_BWRITE(bp);
			} else if ((xfersize + blkoffset) == fragSize) {
				bp->b_flags |= B_AGE;
				bawrite(bp);
			} else {
				bdwrite(bp);
			}
	
			/* Update the EOF if we just extended the file
			 * (the PEOF has already been moved out and the
			 * block mapping table has been updated):
			 */
			if (currOffset > fp->ff_size) {
				fp->ff_size = currOffset;
				if (UBCISVALID(vp))
					ubc_setsize(vp, fp->ff_size); /* XXX check errors */
			}
			if (retval || (resid == 0))
				break;
			cp->c_flag |= C_CHANGE | C_UPDATE;
		} /* endwhile */
	}

ioerr_exit:
	/*
	 * If we successfully wrote any data, and we are not the superuser
	 * we clear the setuid and setgid bits as a precaution against
	 * tampering.
	 */
	if (resid > uio->uio_resid && ap->a_cred && ap->a_cred->cr_uid != 0)
		cp->c_mode &= ~(S_ISUID | S_ISGID);

	if (retval) {
		if (ioflag & IO_UNIT) {
			(void)VOP_TRUNCATE(vp, origFileSize,
				ioflag & IO_SYNC, ap->a_cred, uio->uio_procp);
			uio->uio_offset -= resid - uio->uio_resid;
			uio->uio_resid = resid;
			filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;
		}
	} else if (resid > uio->uio_resid && (ioflag & IO_SYNC)) {
		tv = time;
		retval = VOP_UPDATE(vp, &tv, &tv, 1);
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_END,
		(int)uio->uio_offset, uio->uio_resid, (int)fp->ff_size, (int)filebytes, 0);

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
	switch (ap->a_command) {
	case 1: {
		register struct cnode *cp;
		register struct vnode *vp;
		register struct radvisory *ra;
		struct filefork *fp;
		int devBlockSize = 0;
		int error;

		vp = ap->a_vp;

		if (vp->v_type != VREG)
			return EINVAL;
 
		VOP_LEASE(vp, ap->a_p, ap->a_cred, LEASE_READ);
		error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, ap->a_p);
		if (error)
			return (error);

		ra = (struct radvisory *)(ap->a_data);
		cp = VTOC(vp);
		fp = VTOF(vp);

		if (ra->ra_offset >= fp->ff_size) {
			VOP_UNLOCK(vp, 0, ap->a_p);
			return (EFBIG);
		}
		VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);

		error = advisory_read(vp, fp->ff_size, ra->ra_offset, ra->ra_count, devBlockSize);
		VOP_UNLOCK(vp, 0, ap->a_p);

		return (error);
	}

        case 2: /* F_READBOOTBLOCKS */
        case 3: /* F_WRITEBOOTBLOCKS */
            {
	    struct vnode *vp = ap->a_vp;
	    struct vnode *devvp = NULL;
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
	    
	    devvp = VTOHFS(vp)->hfs_devvp;
	    aiov.iov_base = btd->fbt_buffer;
	    aiov.iov_len = btd->fbt_length;
	    
	    auio.uio_iov = &aiov;
	    auio.uio_iovcnt = 1;
	    auio.uio_offset = btd->fbt_offset;
	    auio.uio_resid = btd->fbt_length;
	    auio.uio_segflg = UIO_USERSPACE;
	    auio.uio_rw = (ap->a_command == 3) ? UIO_WRITE : UIO_READ; /* F_WRITEBOOTSTRAP / F_READBOOTSTRAP */
	    auio.uio_procp = ap->a_p;

	    VOP_DEVBLOCKSIZE(devvp, &devBlockSize);

	    while (auio.uio_resid > 0) {
	      blockNumber = auio.uio_offset / devBlockSize;
	      error = bread(devvp, blockNumber, devBlockSize, ap->a_cred, &bp);
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
	/*
	 * We should really check to see if I/O is possible.
	 */
	return (1);
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
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = VTOF(vp);
	struct hfsmount *hfsmp = VTOHFS(vp);
   int					retval = E_NONE;
    daddr_t				logBlockSize;
    size_t				bytesContAvail = 0;
    off_t blockposition;
    struct proc			*p = NULL;
    int					lockExtBtree;
    struct rl_entry *invalid_range;
    enum rl_overlaptype overlaptype;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = cp->c_devvp;
	if (ap->a_bnp == NULL)
		return (0);

	/* Only clustered I/O should have delayed allocations. */
	DBG_ASSERT(fp->ff_unallocblocks == 0);

	logBlockSize = GetLogicalBlockSize(vp);
	blockposition = (off_t)ap->a_bn * (off_t)logBlockSize;

	lockExtBtree = overflow_extents(fp);
	if (lockExtBtree) {
		p = current_proc();
		retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID,
				LK_EXCLUSIVE | LK_CANRECURSE, p);
		if (retval)
			return (retval);
	}

	retval = MacToVFSError(
                            MapFileBlockC (HFSTOVCB(hfsmp),
                                            (FCB*)fp,
                                            MAXPHYSIO,
                                            blockposition,
                                            ap->a_bnp,
                                            &bytesContAvail));

    if (lockExtBtree) (void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);

    if (retval == E_NONE) {
        /* Adjust the mapping information for invalid file ranges: */
        overlaptype = rl_scan(&fp->ff_invalidranges,
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
						if ((fp->ff_size > (invalid_range->rl_end + 1)) &&
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
    struct hfsmount *hfsmp = VTOHFS(ap->a_vp);
    struct filefork *fp = VTOF(ap->a_vp);
    size_t				bytesContAvail = 0;
    int			retval = E_NONE;
    int lockExtBtree = 0;
    struct proc		*p = NULL;
    struct rl_entry *invalid_range;
    enum rl_overlaptype overlaptype;
    int started_tr = 0, grabbed_lock = 0;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_bpn == NULL)
		return (0);

	p = current_proc();
  retry:
	if (fp->ff_unallocblocks) {
		lockExtBtree = 1;

		// XXXdbg
		hfs_global_shared_lock_acquire(hfsmp);
		grabbed_lock = 1;

		if (hfsmp->jnl) {
			if (journal_start_transaction(hfsmp->jnl) != 0) {
				hfs_global_shared_lock_release(hfsmp);
				return EINVAL;
			} else {
				started_tr = 1;
			}
		} 

		if (retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE | LK_CANRECURSE, p)) {
			if (started_tr) {
				journal_end_transaction(hfsmp->jnl);
			}
			if (grabbed_lock) {
				hfs_global_shared_lock_release(hfsmp);
			}
			return (retval);
		}
	} else if (overflow_extents(fp)) {
		lockExtBtree = 1;
		if (retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE | LK_CANRECURSE, p)) {
			return retval;
		}
	}

	/*
	 * Check for any delayed allocations.
	 */
	if (fp->ff_unallocblocks) {
		SInt64 reqbytes, actbytes;

		//
		// Make sure we have a transaction.  It's possible
		// that we came in and fp->ff_unallocblocks was zero
		// but during the time we blocked acquiring the extents
		// btree, ff_unallocblocks became non-zero and so we
		// will need to start a transaction.
		//
		if (hfsmp->jnl && started_tr == 0) {
		    if (lockExtBtree) {
			(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);
			lockExtBtree = 0;
		    }
    
		    goto retry;
		}

		reqbytes = (SInt64)fp->ff_unallocblocks *
		             (SInt64)HFSTOVCB(hfsmp)->blockSize;
		/*
		 * Release the blocks on loan and aquire some real ones.
		 * Note that we can race someone else for these blocks
		 * (and lose) so cmap needs to handle a failure here.
		 * Currently this race can't occur because all allocations
		 * are protected by an exclusive lock on the  Extents
		 * Overflow file.
		 */
		HFSTOVCB(hfsmp)->loanedBlocks -= fp->ff_unallocblocks;
		FTOC(fp)->c_blocks            -= fp->ff_unallocblocks;
		fp->ff_blocks                 -= fp->ff_unallocblocks;
		fp->ff_unallocblocks           = 0;

		while (retval == 0 && reqbytes > 0) {
			retval = MacToVFSError(ExtendFileC(HFSTOVCB(hfsmp),
					(FCB*)fp, reqbytes, 0,
					kEFAllMask | kEFNoClumpMask, &actbytes));
			if (retval == 0 && actbytes == 0)
				retval = ENOSPC;

			if (retval) {
				fp->ff_unallocblocks =
					reqbytes / HFSTOVCB(hfsmp)->blockSize;
				HFSTOVCB(hfsmp)->loanedBlocks += fp->ff_unallocblocks;
				FTOC(fp)->c_blocks            += fp->ff_unallocblocks;
				fp->ff_blocks                 += fp->ff_unallocblocks;
			}
			reqbytes -= actbytes;
		}

		if (retval) {
			(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);
			if (started_tr) {
				hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
				journal_end_transaction(hfsmp->jnl);
			}
			if (grabbed_lock) {
				hfs_global_shared_lock_release(hfsmp);
			}
			return (retval);
		}
		VTOC(ap->a_vp)->c_flag |= C_MODIFIED;
	}

	retval = MacToVFSError(
			   MapFileBlockC (HFSTOVCB(hfsmp),
					  (FCB *)fp,
					  ap->a_size,
					  ap->a_foffset,
					  ap->a_bpn,
					  &bytesContAvail));

	if (lockExtBtree)
    		(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);

	// XXXdbg
	if (started_tr) {
		hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
		journal_end_transaction(hfsmp->jnl);
		started_tr = 0;
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
		grabbed_lock = 0;
	}
			
    if (retval == E_NONE) {
        /* Adjust the mapping information for invalid file ranges: */
        overlaptype = rl_scan(&fp->ff_invalidranges,
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
                    if ((fp->ff_size > (invalid_range->rl_end + 1)) &&
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
						if ((fp->ff_size > (invalid_range->rl_end + 1)) &&
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

	if (ap->a_poff)
		*(int *)ap->a_poff = 0;

	return (retval);
}


/*
 * Read or write a buffer that is not contiguous on disk.  We loop over
 * each device block, copying to or from caller's buffer.
 *
 * We could be a bit more efficient by transferring as much data as is
 * contiguous.  But since this routine should rarely be called, and that
 * would be more complicated; best to keep it simple.
 */
static int
hfs_strategy_fragmented(struct buf *bp)
{
	register struct vnode *vp = bp->b_vp;
	register struct cnode *cp = VTOC(vp);
	register struct vnode *devvp = cp->c_devvp;
	caddr_t ioaddr;		/* Address of fragment within bp  */
	struct buf *frag = NULL; /* For reading or writing a single block */
	int retval = 0;
	long remaining;		/* Bytes (in bp) left to transfer */
	off_t offset;		/* Logical offset of current fragment in vp */
	u_long block_size;	/* Size of one device block (and one I/O) */
	
	/* Make sure we redo this mapping for the next I/O */
	bp->b_blkno = bp->b_lblkno;
	
	/* Set up the logical position and number of bytes to read/write */
	offset = (off_t) bp->b_lblkno * (off_t) GetLogicalBlockSize(vp);
	block_size = VTOHFS(vp)->hfs_phys_block_size;
	
	/* Get an empty buffer to do the deblocking */
	frag = geteblk(block_size);
	if (ISSET(bp->b_flags, B_READ))
		SET(frag->b_flags, B_READ);

	for (ioaddr = bp->b_data, remaining = bp->b_bcount; remaining != 0;
	    ioaddr += block_size, offset += block_size,
	    remaining -= block_size) {
		frag->b_resid = frag->b_bcount;
		CLR(frag->b_flags, B_DONE);

		/* Map the current position to a physical block number */
		retval = VOP_CMAP(vp, offset, block_size, &frag->b_lblkno,
		    NULL, NULL);
		if (retval != 0)
			break;

		/*
		 * Did we try to read a hole?
		 * (Should never happen for metadata!)
		 */
		if ((long)frag->b_lblkno == -1) {
			bzero(ioaddr, block_size);
			continue;
		}
		
		/* If writing, copy before I/O */
		if (!ISSET(bp->b_flags, B_READ))
			bcopy(ioaddr, frag->b_data, block_size);

		/* Call the device to do the I/O and wait for it */
		frag->b_blkno = frag->b_lblkno;
		frag->b_vp = devvp;  /* Used to dispatch via VOP_STRATEGY */
		frag->b_dev = devvp->v_rdev;
		retval = VOP_STRATEGY(frag);
		frag->b_vp = NULL;
		if (retval != 0)
			break;
		retval = biowait(frag);
		if (retval != 0)
			break;
		
		/* If reading, copy after the I/O */
		if (ISSET(bp->b_flags, B_READ))
			bcopy(frag->b_data, ioaddr, block_size);
	}
	
	frag->b_vp = NULL;
	//
	// XXXdbg - in the case that this is a meta-data block, it won't affect
	//          the journal because this bp is for a physical disk block,
	//          not a logical block that is part of the catalog or extents
	//          files.
	SET(frag->b_flags, B_INVAL);
	brelse(frag);
	
	if ((bp->b_error = retval) != 0)
		SET(bp->b_flags, B_ERROR);
	
	biodone(bp);	/* This I/O is now complete */
	return retval;
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
	register struct cnode *cp = VTOC(vp);
	int retval = 0;
	off_t offset;
	size_t bytes_contig;
	
	if ( !(bp->b_flags & B_VECTORLIST)) {
		if (vp->v_type == VBLK || vp->v_type == VCHR)
			panic("hfs_strategy: device vnode passed!");

		if (bp->b_flags & B_PAGELIST) {
			/*
			 * If we have a page list associated with this bp,
			 * then go through cluster_bp since it knows how to 
			 * deal with a page request that might span non-
			 * contiguous physical blocks on the disk...
			 */
			retval = cluster_bp(bp);
			vp = cp->c_devvp;
			bp->b_dev = vp->v_rdev;

			return (retval);
		}
		
		/*
		 * If we don't already know the filesystem relative block
		 * number then get it using VOP_BMAP().  If VOP_BMAP()
		 * returns the block number as -1 then we've got a hole in
		 * the file.  Although HFS filesystems don't create files with
		 * holes, invalidating of subranges of the file (lazy zero
		 * filling) may create such a situation.
		 */
		if (bp->b_blkno == bp->b_lblkno) {
			offset = (off_t) bp->b_lblkno *
			    (off_t) GetLogicalBlockSize(vp);

			if ((retval = VOP_CMAP(vp, offset, bp->b_bcount,
			    &bp->b_blkno, &bytes_contig, NULL))) {
				bp->b_error = retval;
				bp->b_flags |= B_ERROR;
				biodone(bp);
				return (retval);
			}
			if (bytes_contig < bp->b_bcount)
			{
				/*
				 * We were asked to read a block that wasn't
				 * contiguous, so we have to read each of the
				 * pieces and copy them into the buffer.
				 * Since ordinary file I/O goes through
				 * cluster_io (which won't ask us for
				 * discontiguous data), this is probably an
				 * attempt to read or write metadata.
				 */
				return hfs_strategy_fragmented(bp);
			}
			if ((long)bp->b_blkno == -1)
				clrbuf(bp);
		}
		if ((long)bp->b_blkno == -1) {
			biodone(bp);
			return (0);
		}
		if (bp->b_validend == 0) {
			/*
			 * Record the exact size of the I/O transfer about to
			 * be made:
			 */
			bp->b_validend = bp->b_bcount;
		}
	}
	vp = cp->c_devvp;
	bp->b_dev = vp->v_rdev;

	return VOCALL (vp->v_op, VOFFSET(vop_strategy), ap);
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
 * Truncate a cnode to at most length size, freeing (or adding) the
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
	register struct cnode *cp = VTOC(vp);
    	struct filefork *fp = VTOF(vp);
	off_t length;
	long vflags;
	struct timeval tv;
	int retval;
	off_t bytesToAdd;
	off_t actualBytesAdded;
	off_t filebytes;
	u_long fileblocks;
	int blksize;
	struct hfsmount *hfsmp;

	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EISDIR);	/* cannot truncate an HFS directory! */

	length = ap->a_length;
	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_START,
		 (int)length, (int)fp->ff_size, (int)filebytes, 0, 0);

	if (length < 0)
		return (EINVAL);

	if ((!ISHFSPLUS(VTOVCB(vp))) && (length > (off_t)MAXHFSFILESIZE))
		return (EFBIG);

	hfsmp = VTOHFS(vp);

	tv = time;
	retval = E_NONE;

	/* 
	 * We cannot just check if fp->ff_size == length (as an optimization)
	 * since there may be extra physical blocks that also need truncation.
	 */
#if QUOTA
	if (retval = hfs_getinoquota(cp))
		return(retval);
#endif /* QUOTA */

	/*
	 * Lengthen the size of the file. We must ensure that the
	 * last byte of the file is allocated. Since the smallest
	 * value of ff_size is 0, length will be at least 1.
	 */
	if (length > fp->ff_size) {
#if QUOTA
		retval = hfs_chkdq(cp, (int64_t)(roundup(length - filebytes, blksize)),
				ap->a_cred, 0);
		if (retval)
			goto Err_Exit;
#endif /* QUOTA */
		/*
		 * If we don't have enough physical space then
		 * we need to extend the physical size.
		 */
		if (length > filebytes) {
			int eflags;

			/* All or nothing and don't round up to clumpsize. */
			eflags = kEFAllMask | kEFNoClumpMask;

			if (suser(ap->a_cred, NULL) != 0)
				eflags |= kEFReserveMask;  /* keep a reserve */

			// XXXdbg
			hfs_global_shared_lock_acquire(hfsmp);
			if (hfsmp->jnl) {
				if (journal_start_transaction(hfsmp->jnl) != 0) {
					retval = EINVAL;
					goto Err_Exit;
				}
			}

			/* lock extents b-tree (also protects volume bitmap) */
			retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
			if (retval) {
				if (hfsmp->jnl) {
					journal_end_transaction(hfsmp->jnl);
				} 
				hfs_global_shared_lock_release(hfsmp);

				goto Err_Exit;
			}

			while ((length > filebytes) && (retval == E_NONE)) {
				bytesToAdd = length - filebytes;
				retval = MacToVFSError(ExtendFileC(VTOVCB(vp),
                                                    (FCB*)fp,
                                                    bytesToAdd,
                                                    0,
                                                    eflags,
                                                    &actualBytesAdded));

				filebytes = (off_t)fp->ff_blocks * (off_t)blksize;
				if (actualBytesAdded == 0 && retval == E_NONE) {
					if (length > filebytes)
						length = filebytes;
					break;
				}
			} /* endwhile */

			(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

			// XXXdbg
			if (hfsmp->jnl) {
				hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
				journal_end_transaction(hfsmp->jnl);
			} 
			hfs_global_shared_lock_release(hfsmp);

			if (retval)
				goto Err_Exit;

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_NONE,
				(int)length, (int)fp->ff_size, (int)filebytes, 0, 0);
		}
 
		if (!(ap->a_flags & IO_NOZEROFILL)) {
			if (UBCINFOEXISTS(vp) && retval == E_NONE) {
				struct rl_entry *invalid_range;
				int devBlockSize;
				off_t zero_limit;
			
				zero_limit = (fp->ff_size + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
				if (length < zero_limit) zero_limit = length;

				if (length > fp->ff_size) {
		   			/* Extending the file: time to fill out the current last page w. zeroes? */
		   			if ((fp->ff_size & PAGE_MASK_64) &&
					    (rl_scan(&fp->ff_invalidranges, fp->ff_size & ~PAGE_MASK_64,
					    fp->ff_size - 1, &invalid_range) == RL_NOOVERLAP)) {
		   				
						/* There's some valid data at the start of the (current) last page
						   of the file, so zero out the remainder of that page to ensure the
						   entire page contains valid data.  Since there is no invalid range
						   possible past the (current) eof, there's no need to remove anything
						   from the invalid range list before calling cluster_write():						 */
						VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);
						retval = cluster_write(vp, (struct uio *) 0, fp->ff_size, zero_limit,
								fp->ff_size, (off_t)0, devBlockSize,
								(ap->a_flags & IO_SYNC) | IO_HEADZEROFILL | IO_NOZERODIRTY);
						if (retval) goto Err_Exit;
						
						/* Merely invalidate the remaining area, if necessary: */
						if (length > zero_limit) {
							rl_add(zero_limit, length - 1, &fp->ff_invalidranges);
							cp->c_zftimeout = time.tv_sec + ZFTIMELIMIT;
						}
		   			} else {
					/* The page containing the (current) eof is invalid: just add the
					   remainder of the page to the invalid list, along with the area
					   being newly allocated:
					 */
					rl_add(fp->ff_size, length - 1, &fp->ff_invalidranges);
					cp->c_zftimeout = time.tv_sec + ZFTIMELIMIT;
					};
				}
			} else {
					panic("hfs_truncate: invoked on non-UBC object?!");
			};
		}
		cp->c_flag |= C_UPDATE;
		fp->ff_size = length;

		if (UBCISVALID(vp))
			ubc_setsize(vp, fp->ff_size);	/* XXX check errors */

	} else { /* Shorten the size of the file */

		if (fp->ff_size > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).  For
			 * simplicity, we invalidate all the buffers by calling vinvalbuf.
			 */
			if (UBCISVALID(vp))
				ubc_setsize(vp, length); /* XXX check errors */

			vflags = ((length > 0) ? V_SAVE : 0)  | V_SAVEMETA;	
			retval = vinvalbuf(vp, vflags, ap->a_cred, ap->a_p, 0, 0);
	    
			/* Any space previously marked as invalid is now irrelevant: */
			rl_remove(length, fp->ff_size - 1, &fp->ff_invalidranges);
		}

		/* 
		 * Account for any unmapped blocks. Note that the new
		 * file length can still end up with unmapped blocks.
		 */
		if (fp->ff_unallocblocks > 0) {
			u_int32_t finalblks;

			/* lock extents b-tree */
			retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID,
					LK_EXCLUSIVE, ap->a_p);
			if (retval)
				goto Err_Exit;

			VTOVCB(vp)->loanedBlocks -= fp->ff_unallocblocks;
			cp->c_blocks             -= fp->ff_unallocblocks;
			fp->ff_blocks            -= fp->ff_unallocblocks;
			fp->ff_unallocblocks      = 0;

			finalblks = (length + blksize - 1) / blksize;
			if (finalblks > fp->ff_blocks) {
				/* calculate required unmapped blocks */
				fp->ff_unallocblocks      = finalblks - fp->ff_blocks;
				VTOVCB(vp)->loanedBlocks += fp->ff_unallocblocks;
				cp->c_blocks             += fp->ff_unallocblocks;
				fp->ff_blocks            += fp->ff_unallocblocks;
			}
			(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID,
					LK_RELEASE, ap->a_p);
		}

		/*
		 * For a TBE process the deallocation of the file blocks is
		 * delayed until the file is closed.  And hfs_close calls
		 * truncate with the IO_NDELAY flag set.  So when IO_NDELAY
		 * isn't set, we make sure this isn't a TBE process.
		 */
		if ((ap->a_flags & IO_NDELAY) || (!ISSET(ap->a_p->p_flag, P_TBE))) {
#if QUOTA
		  off_t savedbytes = ((off_t)fp->ff_blocks * (off_t)blksize);
#endif /* QUOTA */
		  // XXXdbg
		  hfs_global_shared_lock_acquire(hfsmp);
			if (hfsmp->jnl) {
				if (journal_start_transaction(hfsmp->jnl) != 0) {
					retval = EINVAL;
					goto Err_Exit;
				}
			}

			/* lock extents b-tree (also protects volume bitmap) */
			retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
			if (retval) {
				if (hfsmp->jnl) {
					journal_end_transaction(hfsmp->jnl);
				}
				hfs_global_shared_lock_release(hfsmp);
				goto Err_Exit;
			}
			
			if (fp->ff_unallocblocks == 0)
				retval = MacToVFSError(TruncateFileC(VTOVCB(vp),
						(FCB*)fp, length, false));

			(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

			// XXXdbg
			if (hfsmp->jnl) {
				hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
				journal_end_transaction(hfsmp->jnl);
			}
			hfs_global_shared_lock_release(hfsmp);

			filebytes = (off_t)fp->ff_blocks * (off_t)blksize;
			if (retval)
				goto Err_Exit;
#if QUOTA
			/* These are bytesreleased */
			(void) hfs_chkdq(cp, (int64_t)-(savedbytes - filebytes), NOCRED, 0);
#endif /* QUOTA */
		}
		/* Only set update flag if the logical length changes */
		if (fp->ff_size != length)
			cp->c_flag |= C_UPDATE;
		fp->ff_size = length;
	}
	cp->c_flag |= C_CHANGE;
	retval = VOP_UPDATE(vp, &tv, &tv, MNT_WAIT);
	if (retval) {
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_NONE,
		     -1, -1, -1, retval, 0);
	}

Err_Exit:

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_END,
		 (int)length, (int)fp->ff_size, (int)filebytes, retval, 0);

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
 * allocate a cnode to at most length size
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
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = VTOF(vp);
	off_t length = ap->a_length;
	off_t startingPEOF;
	off_t moreBytesRequested;
	off_t actualBytesAdded;
	off_t filebytes;
	u_long fileblocks;
	long vflags;
	struct timeval tv;
	int retval, retval2;
	UInt32 blockHint;
	UInt32 extendFlags =0;   /* For call to ExtendFileC */
	struct hfsmount *hfsmp;

	hfsmp = VTOHFS(vp);

	*(ap->a_bytesallocated) = 0;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)VTOVCB(vp)->blockSize;

	if (length < (off_t)0)
		return (EINVAL);
	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EISDIR);
	if ((ap->a_flags & ALLOCATEFROMVOL) && (length <= filebytes))
		return (EINVAL);

	/* Fill in the flags word for the call to Extend the file */

	if (ap->a_flags & ALLOCATECONTIG) 
		extendFlags |= kEFContigMask;

	if (ap->a_flags & ALLOCATEALL)
		extendFlags |= kEFAllMask;

	if (suser(ap->a_cred, NULL) != 0)
		extendFlags |= kEFReserveMask;

	tv = time;
	retval = E_NONE;
	blockHint = 0;
	startingPEOF = filebytes;

	if (ap->a_flags & ALLOCATEFROMPEOF)
		length += filebytes;
	else if (ap->a_flags & ALLOCATEFROMVOL)
		blockHint = ap->a_offset / VTOVCB(vp)->blockSize;

	/* If no changes are necesary, then we're done */
	if (filebytes == length)
		goto Std_Exit;

	/*
	 * Lengthen the size of the file. We must ensure that the
	 * last byte of the file is allocated. Since the smallest
	 * value of filebytes is 0, length will be at least 1.
	 */
	if (length > filebytes) {
		moreBytesRequested = length - filebytes;
		
#if QUOTA
		retval = hfs_chkdq(cp,
				(int64_t)(roundup(moreBytesRequested, VTOVCB(vp)->blockSize)), 
				ap->a_cred, 0);
		if (retval)
			return (retval);

#endif /* QUOTA */
		// XXXdbg
		hfs_global_shared_lock_acquire(hfsmp);
		if (hfsmp->jnl) {
			if (journal_start_transaction(hfsmp->jnl) != 0) {
				retval = EINVAL;
				goto Err_Exit;
			}
		}

		/* lock extents b-tree (also protects volume bitmap) */
		retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
		if (retval) {
			if (hfsmp->jnl) {
				journal_end_transaction(hfsmp->jnl);
			}
			hfs_global_shared_lock_release(hfsmp);
			goto Err_Exit;
		}

		retval = MacToVFSError(ExtendFileC(VTOVCB(vp),
						(FCB*)fp,
						moreBytesRequested,
						blockHint,
						extendFlags,
						&actualBytesAdded));

		*(ap->a_bytesallocated) = actualBytesAdded;
		filebytes = (off_t)fp->ff_blocks * (off_t)VTOVCB(vp)->blockSize;

		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

		// XXXdbg
		if (hfsmp->jnl) {
			hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
			journal_end_transaction(hfsmp->jnl);
		}
		hfs_global_shared_lock_release(hfsmp);

		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the VOP_UPDATE to reflect the changes
		 */
		if (retval && (startingPEOF == filebytes))
			goto Err_Exit;
        
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

		if (fp->ff_size > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).  For
			 * simplicity, we invalidate all the buffers by calling vinvalbuf.
			 */
			vflags = ((length > 0) ? V_SAVE : 0) | V_SAVEMETA;
			(void) vinvalbuf(vp, vflags, ap->a_cred, ap->a_p, 0, 0);
		}

		// XXXdbg
		hfs_global_shared_lock_acquire(hfsmp);
		if (hfsmp->jnl) {
			if (journal_start_transaction(hfsmp->jnl) != 0) {
				retval = EINVAL;
				goto Err_Exit;
			}
		}

		/* lock extents b-tree (also protects volume bitmap) */
		retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
		if (retval) {
			if (hfsmp->jnl) {
				journal_end_transaction(hfsmp->jnl);
			}
			hfs_global_shared_lock_release(hfsmp);

			goto Err_Exit;
		}			

		retval = MacToVFSError(
                            TruncateFileC(
                                            VTOVCB(vp),
                                            (FCB*)fp,
                                            length,
                                            false));
		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);
		filebytes = (off_t)fp->ff_blocks * (off_t)VTOVCB(vp)->blockSize;

		if (hfsmp->jnl) {
			hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
			journal_end_transaction(hfsmp->jnl);
		}
		hfs_global_shared_lock_release(hfsmp);
		

		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the VOP_UPDATE to reflect the changes
		 */
		if (retval && (startingPEOF == filebytes)) goto Err_Exit;
#if QUOTA
		/* These are  bytesreleased */
		(void) hfs_chkdq(cp, (int64_t)-((startingPEOF - filebytes)), NOCRED,0);
#endif /* QUOTA */

		if (fp->ff_size > filebytes) {
			fp->ff_size = filebytes;

			if (UBCISVALID(vp))
				ubc_setsize(vp, fp->ff_size); /* XXX check errors */
		}
	}

Std_Exit:
	cp->c_flag |= C_CHANGE | C_UPDATE;
	retval2 = VOP_UPDATE(vp, &tv, &tv, MNT_WAIT);

	if (retval == 0)
		retval = retval2;
Err_Exit:
	return (retval);
}


/*
 * pagein for HFS filesystem
 */
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
	register struct vnode *vp = ap->a_vp;
	int devBlockSize = 0;
	int error;

	if (vp->v_type != VREG && vp->v_type != VLNK)
		panic("hfs_pagein: vp not UBC type\n");

	VOP_DEVBLOCKSIZE(VTOC(vp)->c_devvp, &devBlockSize);

	error = cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
	                        ap->a_size, (off_t)VTOF(vp)->ff_size, devBlockSize,
	                        ap->a_flags);
	return (error);
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
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = VTOF(vp);
	int retval;
	int devBlockSize = 0;
	off_t end_of_range;
	off_t filesize;

	if (UBCINVALID(vp))
		panic("hfs_pageout: Not a  VREG: vp=%x", vp);

	VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);
	filesize = fp->ff_size;
	end_of_range = ap->a_f_offset + ap->a_size - 1;

	if (end_of_range >= filesize)
	        end_of_range = (off_t)(filesize - 1);
	if (ap->a_f_offset < filesize)
	        rl_remove(ap->a_f_offset, end_of_range, &fp->ff_invalidranges);

	retval = cluster_pageout(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size,
				 filesize, devBlockSize, ap->a_flags);

	/*
	 * If we successfully wrote any data, and we are not the superuser
	 * we clear the setuid and setgid bits as a precaution against
	 * tampering.
	 */
	if (retval == 0 && ap->a_cred && ap->a_cred->cr_uid != 0)
		cp->c_mode &= ~(S_ISUID | S_ISGID);

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
	int retval = 0;
	register struct buf *bp = ap->a_bp;
	register struct vnode *vp = bp->b_vp;
#if BYTE_ORDER == LITTLE_ENDIAN
	BlockDescriptor block;

	/* Trap B-Tree writes */
	if ((VTOC(vp)->c_fileid == kHFSExtentsFileID) ||
	    (VTOC(vp)->c_fileid == kHFSCatalogFileID)) {

		/* Swap if the B-Tree node is in native byte order */
		if (((UInt16 *)((char *)bp->b_data + bp->b_bcount - 2))[0] == 0x000e) {
			/* Prepare the block pointer */
			block.blockHeader = bp;
			block.buffer = bp->b_data;
			/* not found in cache ==> came from disk */
			block.blockReadFromDisk = (bp->b_flags & B_CACHE) == 0;
			block.blockSize = bp->b_bcount;
    
			/* Endian un-swap B-Tree node */
			SWAP_BT_NODE (&block, ISHFSPLUS (VTOVCB(vp)), VTOC(vp)->c_fileid, 1);
		}

		/* We don't check to make sure that it's 0x0e00 because it could be all zeros */
	}
#endif
	/* This buffer shouldn't be locked anymore but if it is clear it */
	if (ISSET(bp->b_flags, B_LOCKED)) {
	    // XXXdbg
	    if (VTOHFS(vp)->jnl) {
			panic("hfs: CLEARING the lock bit on bp 0x%x\n", bp);
	    }
		CLR(bp->b_flags, B_LOCKED);
		printf("hfs_bwrite: called with lock bit set\n");
	}
	retval = vn_bwrite (ap);

	return (retval);
}
