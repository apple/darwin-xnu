/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/filedesc.h>
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

static int  hfs_clonelink(struct vnode *, int, struct ucred *, struct proc *);
static int  hfs_clonefile(struct vnode *, int, int, int,  struct ucred *, struct proc *);
static int  hfs_clonesysfile(struct vnode *, int, int, int, struct ucred *, struct proc *);


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
	int devBlockSize = 0;
	int retval = 0;
    	off_t filesize;
    	off_t filebytes;
	off_t start_resid = uio->uio_resid;


	/* Preflight checks */
	if ((vp->v_type != VREG) || !UBCINFOEXISTS(vp))
		return (EPERM);		/* can only read regular files */
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

	retval = cluster_read(vp, uio, filesize, devBlockSize, 0);

	cp->c_flag |= C_ACCESS;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_END,
		(int)uio->uio_offset, uio->uio_resid, (int)filesize,  (int)filebytes, 0);

	/*
	 * Keep track blocks read
	 */
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING && retval == 0) {
		/*
		 * If this file hasn't been seen since the start of
		 * the current sampling period then start over.
		 */
		if (cp->c_atime < VTOHFS(vp)->hfc_timebase) {
			fp->ff_bytesread = start_resid - uio->uio_resid;
			cp->c_atime = time.tv_sec;
		} else {
			fp->ff_bytesread += start_resid - uio->uio_resid;
		}
	}

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
	struct proc *p;
	struct timeval tv;
	ExtendedVCB *vcb;
	int devBlockSize = 0;
	off_t origFileSize, writelimit, bytesToAdd;
	off_t actualBytesAdded;
	u_long resid;
	int eflags, ioflag;
	int retval;
	off_t filebytes;
	struct hfsmount *hfsmp;
	int started_tr = 0, grabbed_lock = 0;


	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (E_NONE);
	if ((vp->v_type != VREG) || !UBCINFOEXISTS(vp))
		return (EPERM);		/* Can only write regular files */

	ioflag = ap->a_ioflag;
	cp = VTOC(vp);
	fp = VTOF(vp);
	vcb = VTOVCB(vp);
	filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

	if (ioflag & IO_APPEND)
		uio->uio_offset = fp->ff_size;
	if ((cp->c_flags & APPEND) && uio->uio_offset != fp->ff_size)
		return (EPERM);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (VTOHFS(vp)->jnl && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_extents[0];
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

#ifdef HFS_SPARSE_DEV
	/* 
	 * When the underlying device is sparse and space
	 * is low (< 8MB), stop doing delayed allocations
	 * and begin doing synchronous I/O.
	 */
	if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) &&
	    (hfs_freeblks(hfsmp, 0) < 2048)) {
		eflags &= ~kEFDeferMask;
		ioflag |= IO_SYNC;
	}
#endif /* HFS_SPARSE_DEV */

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
		if (ap->a_cred && suser(ap->a_cred, NULL) != 0)
			eflags |= kEFReserveMask;

		/* lock extents b-tree (also protects volume bitmap) */
		retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, current_proc());
		if (retval != E_NONE)
			break;
	
		/* Files that are changing size are not hot file candidates. */
		if (hfsmp->hfc_stage == HFC_RECORDING) {
			fp->ff_bytesread = 0;
		}
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
		tv = time;
		VOP_UPDATE(vp, &tv, &tv, 1);

		hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
		journal_end_transaction(hfsmp->jnl);
		started_tr = 0;
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
		grabbed_lock = 0;
	}

	if (retval == E_NONE) {
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
			if (uio->uio_offset > zero_off) {
			        if (rl_scan(&fp->ff_invalidranges, zero_off, uio->uio_offset - 1, &invalid_range) != RL_NOOVERLAP)
				        lflag |= IO_HEADZEROFILL;
			}
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
	}

	HFS_KNOTE(vp, NOTE_WRITE);

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
	vcb->vcbWrCnt++;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_END,
		(int)uio->uio_offset, uio->uio_resid, (int)fp->ff_size, (int)filebytes, 0);

	return (retval);
}


#ifdef HFS_SPARSE_DEV
struct hfs_backingstoreinfo {
	int  signature;   /* == 3419115 */
	int  version;     /* version of this struct (1) */
	int  backingfd;   /* disk image file (on backing fs) */
	int  bandsize;    /* sparse disk image band size */
};

#define HFSIOC_SETBACKINGSTOREINFO   _IOW('h', 7, struct hfs_backingstoreinfo)
#define HFSIOC_CLRBACKINGSTOREINFO   _IO('h', 8)

#define HFS_SETBACKINGSTOREINFO  IOCBASECMD(HFSIOC_SETBACKINGSTOREINFO)
#define HFS_CLRBACKINGSTOREINFO  IOCBASECMD(HFSIOC_CLRBACKINGSTOREINFO)

#endif /* HFS_SPARSE_DEV */

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

#ifdef HFS_SPARSE_DEV
	case HFS_SETBACKINGSTOREINFO: {
		struct hfsmount * hfsmp;
		struct vnode * bsfs_rootvp;
		struct vnode * di_vp;
		struct file * di_fp;
		struct hfs_backingstoreinfo *bsdata;
		int error = 0;
		
		hfsmp = VTOHFS(ap->a_vp);
		if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			return (EALREADY);
		}
		if (ap->a_p->p_ucred->cr_uid != 0 &&
			ap->a_p->p_ucred->cr_uid != (HFSTOVFS(hfsmp))->mnt_stat.f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		bsdata = (struct hfs_backingstoreinfo *)ap->a_data;
		if (bsdata == NULL) {
			return (EINVAL);
		}
		if (error = fdgetf(ap->a_p, bsdata->backingfd, &di_fp)) {
			return (error);
		}
		if (fref(di_fp) == -1) {
			return (EBADF);
		}
		if (di_fp->f_type != DTYPE_VNODE) {
			frele(di_fp);
			return (EINVAL);
		}
		di_vp = (struct vnode *)di_fp->f_data;
		if (ap->a_vp->v_mount == di_vp->v_mount) {
			frele(di_fp);
			return (EINVAL);
		}

		/*
		 * Obtain the backing fs root vnode and keep a reference
		 * on it.  This reference will be dropped in hfs_unmount.
		 */
		error = VFS_ROOT(di_vp->v_mount, &bsfs_rootvp);
		if (error) {
			frele(di_fp);
			return (error);
		}
        	VOP_UNLOCK(bsfs_rootvp, 0, ap->a_p);  /* Hold on to the reference */

		hfsmp->hfs_backingfs_rootvp = bsfs_rootvp;
		hfsmp->hfs_flags |= HFS_HAS_SPARSE_DEVICE;
		hfsmp->hfs_sparsebandblks = bsdata->bandsize / HFSTOVCB(hfsmp)->blockSize;
		hfsmp->hfs_sparsebandblks *= 4;

		frele(di_fp);
		return (0);
	}
	case HFS_CLRBACKINGSTOREINFO: {
		struct hfsmount * hfsmp;
		struct vnode * tmpvp;

		hfsmp = VTOHFS(ap->a_vp);
		if (ap->a_p->p_ucred->cr_uid != 0 &&
			ap->a_p->p_ucred->cr_uid != (HFSTOVFS(hfsmp))->mnt_stat.f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) &&
		    hfsmp->hfs_backingfs_rootvp) {

			hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
			tmpvp = hfsmp->hfs_backingfs_rootvp;
			hfsmp->hfs_backingfs_rootvp = NULLVP;
			hfsmp->hfs_sparsebandblks = 0;
			vrele(tmpvp);
		}
		return (0);
	}
#endif /* HFS_SPARSE_DEV */

	case 6: {
		int error;

		ap->a_vp->v_flag |= VFULLFSYNC;
		error = VOP_FSYNC(ap->a_vp, ap->a_cred, MNT_NOWAIT, ap->a_p);
		ap->a_vp->v_flag &= ~VFULLFSYNC;

		return error;
	}
	case 5: {
		register struct vnode *vp;
		register struct cnode *cp;
		struct filefork *fp;
		int error;

		vp = ap->a_vp;
		cp = VTOC(vp);
		fp = VTOF(vp);

		if (vp->v_type != VREG)
			return EINVAL;
 
		VOP_LEASE(vp, ap->a_p, ap->a_cred, LEASE_READ);
		error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, ap->a_p);
		if (error)
			return (error);

	        /*
		 * used by regression test to determine if 
		 * all the dirty pages (via write) have been cleaned
		 * after a call to 'fsysnc'.
		 */
		error = is_file_clean(vp, fp->ff_size);
		VOP_UNLOCK(vp, 0, ap->a_p);

		return (error);
	}

	case 1: {
		register struct vnode *vp;
		register struct radvisory *ra;
		register struct cnode *cp;
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
	struct timeval tv;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_bpn == NULL)
		return (0);

	p = current_proc();

	if (ISSET(VTOC(ap->a_vp)->c_flag, C_NOBLKMAP)) {
		/*
		 * File blocks are getting remapped. Wait until its finished.
		 */
		SET(VTOC(ap->a_vp)->c_flag, C_WBLKMAP);
		(void) tsleep((caddr_t)VTOC(ap->a_vp), PINOD, "hfs_cmap", 0);
		if (ISSET(VTOC(ap->a_vp)->c_flag, C_NOBLKMAP))
			panic("hfs_cmap: no mappable blocks");
	}	

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

		/* Files that are changing size are not hot file candidates. */
		if (hfsmp->hfc_stage == HFC_RECORDING) {
			fp->ff_bytesread = 0;
		}
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
			VTOC(ap->a_vp)->c_flag |= C_MODIFIED;
			if (started_tr) {
				tv = time;
				VOP_UPDATE(ap->a_vp, &tv, &tv, 1);

				hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
				journal_end_transaction(hfsmp->jnl);
			}
			if (grabbed_lock) {
				hfs_global_shared_lock_release(hfsmp);
			}
			return (retval);
		}
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
		tv = time;
		retval = VOP_UPDATE(ap->a_vp, &tv, &tv, 1);

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


static int do_hfs_truncate(ap)
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

	/* Files that are changing size are not hot file candidates. */
	if (hfsmp->hfc_stage == HFC_RECORDING) {
		fp->ff_bytesread = 0;
	}

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
			u_long blockHint = 0;

			/* All or nothing and don't round up to clumpsize. */
			eflags = kEFAllMask | kEFNoClumpMask;

			if (ap->a_cred && suser(ap->a_cred, NULL) != 0)
				eflags |= kEFReserveMask;  /* keep a reserve */

			/*
			 * Allocate Journal and Quota files in metadata zone.
			 */
			if (filebytes == 0 &&
			    hfsmp->hfs_flags & HFS_METADATA_ZONE &&
			    hfs_virtualmetafile(cp)) {
				eflags |= kEFMetadataMask;
				blockHint = hfsmp->hfs_metazone_start;
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

			while ((length > filebytes) && (retval == E_NONE)) {
				bytesToAdd = length - filebytes;
				retval = MacToVFSError(ExtendFileC(VTOVCB(vp),
                                                    (FCB*)fp,
                                                    bytesToAdd,
                                                    blockHint,
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
				tv = time;
				VOP_UPDATE(vp, &tv, &tv, 1);

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
				tv = time;
				VOP_UPDATE(vp, &tv, &tv, 1);

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
	off_t filebytes;
	u_long fileblocks;
	int blksize, error;
	u_int64_t nsize;

	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EISDIR);	/* cannot truncate an HFS directory! */

	length = ap->a_length;
	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	// have to loop truncating or growing files that are
	// really big because otherwise transactions can get
	// enormous and consume too many kernel resources.
	if (length < filebytes && (filebytes - length) > HFS_BIGFILE_SIZE) {
	    while (filebytes > length) {
		if ((filebytes - length) > HFS_BIGFILE_SIZE) {
		    filebytes -= HFS_BIGFILE_SIZE;
		} else {
		    filebytes = length;
		}

		ap->a_length = filebytes;
		error = do_hfs_truncate(ap);
		if (error)
		    break;
	    }
	} else if (length > filebytes && (length - filebytes) > HFS_BIGFILE_SIZE) {
	    while (filebytes < length) {
		if ((length - filebytes) > HFS_BIGFILE_SIZE) {
		    filebytes += HFS_BIGFILE_SIZE;
		} else {
		    filebytes = (length - filebytes);
		}

		ap->a_length = filebytes;
		error = do_hfs_truncate(ap);
		if (error)
		    break;
	    }
	} else {
	    error = do_hfs_truncate(ap);
	}

	return error;
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
	ExtendedVCB *vcb = VTOVCB(vp);
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
	UInt32 extendFlags;   /* For call to ExtendFileC */
	struct hfsmount *hfsmp;

	hfsmp = VTOHFS(vp);

	*(ap->a_bytesallocated) = 0;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)vcb->blockSize;

	if (length < (off_t)0)
		return (EINVAL);
	if (vp->v_type != VREG)
		return (EISDIR);
	if ((ap->a_flags & ALLOCATEFROMVOL) && (length < filebytes))
		return (EINVAL);

	/* Fill in the flags word for the call to Extend the file */

	extendFlags = kEFNoClumpMask;
	if (ap->a_flags & ALLOCATECONTIG) 
		extendFlags |= kEFContigMask;
	if (ap->a_flags & ALLOCATEALL)
		extendFlags |= kEFAllMask;
	if (ap->a_cred && suser(ap->a_cred, NULL) != 0)
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
				(int64_t)(roundup(moreBytesRequested, vcb->blockSize)), 
				ap->a_cred, 0);
		if (retval)
			return (retval);

#endif /* QUOTA */
		/*
		 * Metadata zone checks.
		 */
		if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
			/*
			 * Allocate Journal and Quota files in metadata zone.
			 */
			if (hfs_virtualmetafile(cp)) {
				extendFlags |= kEFMetadataMask;
				blockHint = hfsmp->hfs_metazone_start;
			} else if ((blockHint >= hfsmp->hfs_metazone_start) &&
				   (blockHint <= hfsmp->hfs_metazone_end)) {
				/*
				 * Move blockHint outside metadata zone.
				 */
				blockHint = hfsmp->hfs_metazone_end + 1;
			}
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

		retval = MacToVFSError(ExtendFileC(vcb,
						(FCB*)fp,
						moreBytesRequested,
						blockHint,
						extendFlags,
						&actualBytesAdded));

		*(ap->a_bytesallocated) = actualBytesAdded;
		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);

		// XXXdbg
		if (hfsmp->jnl) {
			tv = time;
			VOP_UPDATE(vp, &tv, &tv, 1);

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
				roundup(moreBytesRequested, (off_t)vcb->blockSize);

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
                                            vcb,
                                            (FCB*)fp,
                                            length,
                                            false));
		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, ap->a_p);
		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

		if (hfsmp->jnl) {
			tv = time;
			VOP_UPDATE(vp, &tv, &tv, 1);

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

	if (vp->v_type != VREG)
		panic("hfs_pagein: vp not UBC type\n");

	VOP_DEVBLOCKSIZE(VTOC(vp)->c_devvp, &devBlockSize);

	error = cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
	                        ap->a_size, (off_t)VTOF(vp)->ff_size, devBlockSize,
	                        ap->a_flags);
	/*
	 * Keep track blocks read
	 */
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING && error == 0) {
		struct cnode *cp;
		
		cp = VTOC(vp);		
		/*
		 * If this file hasn't been seen since the start of
		 * the current sampling period then start over.
		 */
		if (cp->c_atime < VTOHFS(vp)->hfc_timebase)
			VTOF(vp)->ff_bytesread = ap->a_size;
		else
			VTOF(vp)->ff_bytesread += ap->a_size;

		cp->c_flag |= C_ACCESS;
	}

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

	if (cp->c_flag & C_RELOCATING) {
		if (end_of_range < (filesize / 2)) {
			return (EBUSY);
		}
	}

	if (end_of_range >= filesize)
	        end_of_range = (off_t)(filesize - 1);
	if (ap->a_f_offset < filesize) {
	        rl_remove(ap->a_f_offset, end_of_range, &fp->ff_invalidranges);
	        cp->c_flag |= C_MODIFIED;  /* leof is dirty */
	}

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

/*
 * Relocate a file to a new location on disk
 *  cnode must be locked on entry
 *
 * Relocation occurs by cloning the file's data from its
 * current set of blocks to a new set of blocks. During
 * the relocation all of the blocks (old and new) are
 * owned by the file.
 *
 * -----------------
 * |///////////////|
 * -----------------
 * 0               N (file offset)
 *
 * -----------------     -----------------
 * |///////////////|     |               |     STEP 1 (aquire new blocks)
 * -----------------     -----------------
 * 0               N     N+1             2N
 *
 * -----------------     -----------------
 * |///////////////|     |///////////////|     STEP 2 (clone data)
 * -----------------     -----------------
 * 0               N     N+1             2N
 *
 *                       -----------------
 *                       |///////////////|     STEP 3 (head truncate blocks)
 *                       -----------------
 *                       0               N
 *
 * During steps 2 and 3 page-outs to file offsets less
 * than or equal to N are suspended.
 *
 * During step 3 page-ins to the file get supended.
 */
__private_extern__
int
hfs_relocate(vp, blockHint, cred, p)
	struct  vnode *vp;
	u_int32_t  blockHint;
	struct  ucred *cred;
	struct  proc *p;
{
	struct  filefork *fp;
	struct  hfsmount *hfsmp;
	ExtendedVCB *vcb;

	u_int32_t  headblks;
	u_int32_t  datablks;
	u_int32_t  blksize;
	u_int32_t  realsize;
	u_int32_t  growsize;
	u_int32_t  nextallocsave;
	u_int32_t  sector_a;
	u_int32_t  sector_b;
	int eflags;
	u_int32_t  oldstart;  /* debug only */
	off_t  newbytes;
	int  retval;

	if (vp->v_type != VREG && vp->v_type != VLNK) {
		return (EPERM);
	}
	
	hfsmp = VTOHFS(vp);
	if (hfsmp->hfs_flags & HFS_FRAGMENTED_FREESPACE) {
		return (ENOSPC);
	}

	fp = VTOF(vp);
	if (fp->ff_unallocblocks)
		return (EINVAL);
	vcb = VTOVCB(vp);
	blksize = vcb->blockSize;
	if (blockHint == 0)
		blockHint = vcb->nextAllocation;

	if ((fp->ff_size > (u_int64_t)0x7fffffff) ||
	    (vp->v_type == VLNK && fp->ff_size > blksize)) {
		return (EFBIG);
	}

	headblks = fp->ff_blocks;
	datablks = howmany(fp->ff_size, blksize);
	growsize = datablks * blksize;
	realsize = fp->ff_size;
	eflags = kEFContigMask | kEFAllMask | kEFNoClumpMask;
	if (blockHint >= hfsmp->hfs_metazone_start &&
	    blockHint <= hfsmp->hfs_metazone_end)
		eflags |= kEFMetadataMask;

	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			return (EINVAL);
		}
	}

	/* Lock extents b-tree (also protects volume bitmap) */
	retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, p);
	if (retval)
		goto out2;

	retval = MapFileBlockC(vcb, (FCB *)fp, 1, growsize - 1, &sector_a, NULL);
	if (retval) {
		retval = MacToVFSError(retval);
		goto out;
	}

	/*
	 * STEP 1 - aquire new allocation blocks.
	 */
	nextallocsave = vcb->nextAllocation;
	retval = ExtendFileC(vcb, (FCB*)fp, growsize, blockHint, eflags, &newbytes);
	if (eflags & kEFMetadataMask)                   
		vcb->nextAllocation = nextallocsave;

	retval = MacToVFSError(retval);
	if (retval == 0) {
		VTOC(vp)->c_flag |= C_MODIFIED;
		if (newbytes < growsize) {
			retval = ENOSPC;
			goto restore;
		} else if (fp->ff_blocks < (headblks + datablks)) {
			printf("hfs_relocate: allocation failed");
			retval = ENOSPC;
			goto restore;
		}

		retval = MapFileBlockC(vcb, (FCB *)fp, 1, growsize, &sector_b, NULL);
		if (retval) {
			retval = MacToVFSError(retval);
		} else if ((sector_a + 1) == sector_b) {
			retval = ENOSPC;
			goto restore;
		} else if ((eflags & kEFMetadataMask) &&
		           ((((u_int64_t)sector_b * hfsmp->hfs_phys_block_size) / blksize) >
		              hfsmp->hfs_metazone_end)) {
			printf("hfs_relocate: didn't move into metadata zone\n");
			retval = ENOSPC;
			goto restore;
		}
	}
	if (retval) {
		/*
		 * Check to see if failure is due to excessive fragmentation.
		 */
		if (retval == ENOSPC &&
		    hfs_freeblks(hfsmp, 0) > (datablks * 2)) {
			hfsmp->hfs_flags |= HFS_FRAGMENTED_FREESPACE;
		}
		goto out;
	}

	fp->ff_size = fp->ff_blocks * blksize;
	if (UBCISVALID(vp))
		(void) ubc_setsize(vp, fp->ff_size);

	/*
	 * STEP 2 - clone data into the new allocation blocks.
	 */

	if (vp->v_type == VLNK)
		retval = hfs_clonelink(vp, blksize, cred, p);
	else if (vp->v_flag & VSYSTEM)
		retval = hfs_clonesysfile(vp, headblks, datablks, blksize, cred, p);
	else
		retval = hfs_clonefile(vp, headblks, datablks, blksize, cred, p);

	if (retval)
		goto restore;
	
	oldstart = fp->ff_extents[0].startBlock;

	/*
	 * STEP 3 - switch to clone and remove old blocks.
	 */
	SET(VTOC(vp)->c_flag, C_NOBLKMAP);   /* suspend page-ins */

	retval = HeadTruncateFile(vcb, (FCB*)fp, headblks);

	CLR(VTOC(vp)->c_flag, C_NOBLKMAP);   /* resume page-ins */
	if (ISSET(VTOC(vp)->c_flag, C_WBLKMAP))
		wakeup(VTOC(vp));
	if (retval)
		goto restore;

	fp->ff_size = realsize;
	if (UBCISVALID(vp)) {
		(void) ubc_setsize(vp, realsize);
		(void) vinvalbuf(vp, V_SAVE, cred, p, 0, 0);
	}

	CLR(VTOC(vp)->c_flag, C_RELOCATING);  /* Resume page-outs for this file. */
out:
	(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);

	retval = VOP_FSYNC(vp, cred, MNT_WAIT, p);
out2:
	if (hfsmp->jnl) {
		if (VTOC(vp)->c_cnid < kHFSFirstUserCatalogNodeID)
			(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
		else
			(void) hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

	return (retval);

restore:
	/*
	 * Give back any newly allocated space.
	 */
	if (fp->ff_size != realsize)
		fp->ff_size = realsize;
	(void) TruncateFileC(vcb, (FCB*)fp, fp->ff_size, false);
	if (UBCISVALID(vp))
		(void) ubc_setsize(vp, fp->ff_size);
	CLR(VTOC(vp)->c_flag, C_RELOCATING);
	goto out;
}


/*
 * Clone a symlink.
 *
 */
static int
hfs_clonelink(struct vnode *vp, int blksize, struct ucred *cred, struct proc *p)
{
	struct buf *head_bp = NULL;
	struct buf *tail_bp = NULL;
	int error;


	error = meta_bread(vp, 0, blksize, cred, &head_bp);
	if (error)
		goto out;

	tail_bp = getblk(vp, 1, blksize, 0, 0, BLK_META);
	if (tail_bp == NULL) {
		error = EIO;
		goto out;
	}
	bcopy(head_bp->b_data, tail_bp->b_data, blksize);
	error = bwrite(tail_bp);
out:
	if (head_bp) {
		head_bp->b_flags |= B_INVAL;
		brelse(head_bp);
	}	
	(void) vinvalbuf(vp, V_SAVE, cred, p, 0, 0);

	return (error);
}

/*
 * Clone a file's data within the file.
 *
 */
static int
hfs_clonefile(struct vnode *vp, int blkstart, int blkcnt, int blksize,
              struct ucred *cred, struct proc *p)
{
	caddr_t  bufp;
	size_t  writebase;
	size_t  bufsize;
	size_t  copysize;
        size_t  iosize;
	size_t  filesize;
	size_t  offset;
	struct uio auio;
	struct iovec aiov;
	int  devblocksize;
	int  didhold;
	int  error;


	if ((error = vinvalbuf(vp, V_SAVE, cred, p, 0, 0))) {
		printf("hfs_clonefile: vinvalbuf failed - %d\n", error);
		return (error);
	}

	if (!ubc_clean(vp, 1)) {
		printf("hfs_clonefile: not ubc_clean\n");
		return (EIO);  /* XXX error code */
	}

  	/*
  	 * Suspend page-outs for this file.
  	 */
	SET(VTOC(vp)->c_flag, C_RELOCATING);

	filesize = VTOF(vp)->ff_size;
	writebase = blkstart * blksize;
	copysize = blkcnt * blksize;
	iosize = bufsize = MIN(copysize, 4096 * 16);
	offset = 0;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize)) {
		return (ENOMEM);
	}	

	VOP_DEVBLOCKSIZE(VTOC(vp)->c_devvp, &devblocksize);

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = p;

	while (offset < copysize) {
		iosize = MIN(copysize - offset, iosize);

		aiov.iov_base = bufp;
		aiov.iov_len = iosize;
		auio.uio_resid = iosize;
		auio.uio_offset = offset;
		auio.uio_rw = UIO_READ;

		error = cluster_read(vp, &auio, copysize, devblocksize, 0);
		if (error) {
			printf("hfs_clonefile: cluster_read failed - %d\n", error);
			break;
		}
		if (auio.uio_resid != 0) {
			printf("clonedata: cluster_read: uio_resid = %d\n", (int)auio.uio_resid);
			error = EIO;		
			break;
		}


		aiov.iov_base = bufp;
		aiov.iov_len = iosize;
		auio.uio_resid = iosize;
		auio.uio_offset = writebase + offset;
		auio.uio_rw = UIO_WRITE;

		error = cluster_write(vp, &auio, filesize + offset,
		                      filesize + offset + iosize,
		                      auio.uio_offset, 0, devblocksize, 0);
		if (error) {
			printf("hfs_clonefile: cluster_write failed - %d\n", error);
			break;
		}
		if (auio.uio_resid != 0) {
			printf("hfs_clonefile: cluster_write failed - uio_resid not zero\n");
			error = EIO;		
			break;
		}	
		offset += iosize;
	}
	if (error == 0) {
		/* Clean the pages in VM. */
		didhold = ubc_hold(vp);
		if (didhold)
			(void) ubc_clean(vp, 1);
	
		/*
		 * Clean out all associated buffers.
		 */
		(void) vinvalbuf(vp, V_SAVE, cred, p, 0, 0);
	
		if (didhold)
			ubc_rele(vp);
	}
	kmem_free(kernel_map, (vm_offset_t)bufp, bufsize);
	
	return (error);
}

/*
 * Clone a system (metadata) file.
 *
 */
static int
hfs_clonesysfile(struct vnode *vp, int blkstart, int blkcnt, int blksize,
                 struct ucred *cred, struct proc *p)
{
	caddr_t  bufp;
	char * offset;
	size_t  bufsize;
	size_t  iosize;
	struct buf *bp = NULL;
	daddr_t  blkno;
 	daddr_t  blk;
	int  breadcnt;
        int  i;
	int  error = 0;


	iosize = GetLogicalBlockSize(vp);
	bufsize = MIN(blkcnt * blksize, 1024 * 1024) & ~(iosize - 1);
	breadcnt = bufsize / iosize;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize)) {
		return (ENOMEM);
	}	
	blkstart = (blkstart * blksize) / iosize;
	blkcnt = (blkcnt * blksize) / iosize;
	blkno = 0;

	while (blkno < blkcnt) {
		/*
		 * Read up to a megabyte
		 */
		offset = bufp;
		for (i = 0, blk = blkno; (i < breadcnt) && (blk < blkcnt); ++i, ++blk) {
			error = meta_bread(vp, blk, iosize, cred, &bp);
			if (error) {
				printf("hfs_clonesysfile: meta_bread error %d\n", error);
				goto out;
			}
			if (bp->b_bcount != iosize) {
				printf("hfs_clonesysfile: b_bcount is only %d\n", bp->b_bcount);
				goto out;
			}
	
			bcopy(bp->b_data, offset, iosize);
			bp->b_flags |= B_INVAL;
			brelse(bp);
			bp = NULL;
			offset += iosize;
		}
	
		/*
		 * Write up to a megabyte
		 */
		offset = bufp;
		for (i = 0; (i < breadcnt) && (blkno < blkcnt); ++i, ++blkno) {
			bp = getblk(vp, blkstart + blkno, iosize, 0, 0, BLK_META);
			if (bp == NULL) {
				printf("hfs_clonesysfile: getblk failed on blk %d\n", blkstart + blkno);
				error = EIO;
				goto out;
			}
			bcopy(offset, bp->b_data, iosize);
			error = bwrite(bp);
			bp = NULL;
			if (error)
				goto out;
			offset += iosize;
		}
	}
out:
	if (bp) {
		brelse(bp);
	}

	kmem_free(kernel_map, (vm_offset_t)bufp, bufsize);

	error = VOP_FSYNC(vp, cred, MNT_WAIT, p);

	return (error);
}

