/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
#include <sys/buf_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/uio.h>
#include <sys/vfs_context.h>
#include <sys/fsevents.h>
#include <kern/kalloc.h>
#include <sys/disk.h>
#include <sys/sysctl.h>
#include <sys/fsctl.h>
#include <sys/mount_internal.h>
#include <sys/file_internal.h>

#include <libkern/OSDebug.h>

#include <miscfs/specfs/specdev.h>

#include <sys/ubc.h>
#include <sys/ubc_internal.h>

#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>

#include <IOKit/IOBSD.h>

#include <sys/kdebug.h>

#include	"hfs.h"
#include	"hfs_attrlist.h"
#include	"hfs_endian.h"
#include  	"hfs_fsctl.h"
#include	"hfs_quota.h"
#include	"hfscommon/headers/FileMgrInternal.h"
#include	"hfscommon/headers/BTreesInternal.h"
#include	"hfs_cnode.h"
#include	"hfs_dbg.h"


#define can_cluster(size) ((((size & (4096-1))) == 0) && (size <= (MAXPHYSIO/2)))

enum {
	MAXHFSFILESIZE = 0x7FFFFFFF		/* this needs to go in the mount structure */
};

/* from bsd/hfs/hfs_vfsops.c */
extern int hfs_vfs_vget (struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);

/* from hfs_hotfiles.c */
extern int hfs_pin_overflow_extents (struct hfsmount *hfsmp, uint32_t fileid,
		                              uint8_t forktype, uint32_t *pinned);

static int  hfs_clonefile(struct vnode *, int, int, int);
static int  hfs_clonesysfile(struct vnode *, int, int, int, kauth_cred_t, struct proc *);
static int  do_hfs_truncate(struct vnode *vp, off_t length, int flags, int skip, vfs_context_t context);

/* from bsd/hfs/hfs_vnops.c */
extern decmpfs_cnode* hfs_lazy_init_decmpfs_cnode (struct cnode *cp);



int flush_cache_on_write = 0;
SYSCTL_INT (_kern, OID_AUTO, flush_cache_on_write, CTLFLAG_RW | CTLFLAG_LOCKED, &flush_cache_on_write, 0, "always flush the drive cache on writes to uncached files");

/*
 * Read data from a file.
 */
int
hfs_vnop_read(struct vnop_read_args *ap)
{
	/*
	   struct vnop_read_args {
	   struct vnodeop_desc *a_desc;
	   vnode_t a_vp;
	   struct uio *a_uio;
	   int a_ioflag;
	   vfs_context_t a_context;
	   };
	 */

	uio_t uio = ap->a_uio;
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	struct hfsmount *hfsmp;
	off_t filesize;
	off_t filebytes;
	off_t start_resid = uio_resid(uio);
	off_t offset = uio_offset(uio);
	int retval = 0;
	int took_truncate_lock = 0;
	int io_throttle = 0;
	int throttled_count = 0;

	/* Preflight checks */
	if (!vnode_isreg(vp)) {
		/* can only read regular files */
		if (vnode_isdir(vp))
			return (EISDIR);
		else
			return (EPERM);
	}
	if (start_resid == 0)
		return (0);		/* Nothing left to do */
	if (offset < 0)
		return (EINVAL);	/* cant read from a negative offset */

#if SECURE_KERNEL
	if ((ap->a_ioflag & (IO_SKIP_ENCRYPTION|IO_SYSCALL_DISPATCH)) ==
						(IO_SKIP_ENCRYPTION|IO_SYSCALL_DISPATCH)) {
		/* Don't allow unencrypted io request from user space */
		return EPERM;
	}
#endif

#if HFS_COMPRESSION
	if (VNODE_IS_RSRC(vp)) {
		if (hfs_hides_rsrc(ap->a_context, VTOC(vp), 1)) { /* 1 == don't take the cnode lock */
			return 0;
		}
		/* otherwise read the resource fork normally */
	} else {
		int compressed = hfs_file_is_compressed(VTOC(vp), 1); /* 1 == don't take the cnode lock */
		if (compressed) {
			retval = decmpfs_read_compressed(ap, &compressed, VTOCMP(vp));
			if (retval == 0 && !(ap->a_ioflag & IO_EVTONLY) && vnode_isfastdevicecandidate(vp)) {
				(void) hfs_addhotfile(vp);
			}
			if (compressed) {
				if (retval == 0) {
					/* successful read, update the access time */
					VTOC(vp)->c_touch_acctime = TRUE;
					
					//
					// compressed files are not traditional hot file candidates
					// but they may be for CF (which ignores the ff_bytesread
					// field)
					//
					if (VTOHFS(vp)->hfc_stage == HFC_RECORDING) {
						VTOF(vp)->ff_bytesread = 0;
					}
				}
				return retval;
			}
			/* otherwise the file was converted back to a regular file while we were reading it */
			retval = 0;
		} else if ((VTOC(vp)->c_bsdflags & UF_COMPRESSED)) {
			int error;
			
			error = check_for_dataless_file(vp, NAMESPACE_HANDLER_READ_OP);
			if (error) {
				return error;
			}

		}
	}
#endif /* HFS_COMPRESSION */

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);

#if CONFIG_PROTECT
	if ((retval = cp_handle_vnop (vp, CP_READ_ACCESS, ap->a_ioflag)) != 0) {
		goto exit;
	}

#endif // CONFIG_PROTECT

	/* 
	 * If this read request originated from a syscall (as opposed to 
	 * an in-kernel page fault or something), then set it up for 
	 * throttle checks
	 */
	if (ap->a_ioflag & IO_SYSCALL_DISPATCH) {
		io_throttle = IO_RETURN_ON_THROTTLE;
	}

read_again:

	/* Protect against a size change. */
	hfs_lock_truncate(cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT);
	took_truncate_lock = 1;

	filesize = fp->ff_size;
	filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;

	/*
	 * Check the file size. Note that per POSIX spec, we return 0 at 
	 * file EOF, so attempting a read at an offset that is too big
	 * should just return 0 on HFS+. Since the return value was initialized
	 * to 0 above, we just jump to exit.  HFS Standard has its own behavior.
	 */
	if (offset > filesize) {
		if ((hfsmp->hfs_flags & HFS_STANDARD) &&
		    (offset > (off_t)MAXHFSFILESIZE)) {
			retval = EFBIG;
		}
		goto exit;
	}

	KERNEL_DEBUG(HFSDBG_READ | DBG_FUNC_START,
		(int)uio_offset(uio), uio_resid(uio), (int)filesize, (int)filebytes, 0);

	retval = cluster_read(vp, uio, filesize, ap->a_ioflag |io_throttle);

	cp->c_touch_acctime = TRUE;

	KERNEL_DEBUG(HFSDBG_READ | DBG_FUNC_END,
		(int)uio_offset(uio), uio_resid(uio), (int)filesize,  (int)filebytes, 0);

	/*
	 * Keep track blocks read
	 */
	if (hfsmp->hfc_stage == HFC_RECORDING && retval == 0) {
		int took_cnode_lock = 0;
		off_t bytesread;

		bytesread = start_resid - uio_resid(uio);

		/* When ff_bytesread exceeds 32-bits, update it behind the cnode lock. */
		if ((fp->ff_bytesread + bytesread) > 0x00000000ffffffff) {
			hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
			took_cnode_lock = 1;
		}
		/*
		 * If this file hasn't been seen since the start of
		 * the current sampling period then start over.
		 */
		if (cp->c_atime < hfsmp->hfc_timebase) {
			struct timeval tv;

			fp->ff_bytesread = bytesread;
			microtime(&tv);
			cp->c_atime = tv.tv_sec;
		} else {
			fp->ff_bytesread += bytesread;
		}

		if (!(ap->a_ioflag & IO_EVTONLY) && vnode_isfastdevicecandidate(vp)) {
			//
			// We don't add hotfiles for processes doing IO_EVTONLY I/O
			// on the assumption that they're system processes such as
			// mdworker which scan everything in the system (and thus
			// do not represent user-initiated access to files)
			//
			(void) hfs_addhotfile(vp);
		}
		if (took_cnode_lock)
			hfs_unlock(cp);
	}
exit:
	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	}
	if (retval == EAGAIN) {
		throttle_lowpri_io(1);
		throttled_count++;

		retval = 0;
		goto read_again;
	}
	if (throttled_count) {
		throttle_info_reset_window((uthread_t)get_bsdthread_info(current_thread()));
	}
	return (retval);
}

/*
 * Ideally, this wouldn't be necessary; the cluster code should be
 * able to handle this on the read-side.  See <rdar://20420068>.
 */
static errno_t hfs_zero_eof_page(vnode_t vp, off_t zero_up_to)
{
	assert(VTOC(vp)->c_lockowner != current_thread());
	assert(VTOC(vp)->c_truncatelockowner == current_thread());

	struct filefork *fp = VTOF(vp);

	if (!(fp->ff_size & PAGE_MASK_64) || zero_up_to <= fp->ff_size) {
		// Nothing to do
		return 0;
	}

	zero_up_to = MIN(zero_up_to, (off_t)round_page_64(fp->ff_size));

	/* N.B. At present, @zero_up_to is not important because the cluster
	   code will always zero up to the end of the page anyway. */
	return cluster_write(vp, NULL, fp->ff_size, zero_up_to,
						 fp->ff_size, 0, IO_HEADZEROFILL);
}

/*
 * Write data to a file.
 */
int
hfs_vnop_write(struct vnop_write_args *ap)
{
	uio_t uio = ap->a_uio;
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	struct hfsmount *hfsmp;
	kauth_cred_t cred = NULL;
	off_t origFileSize;
	off_t writelimit;
	off_t bytesToAdd = 0;
	off_t actualBytesAdded;
	off_t filebytes;
	off_t offset;
	ssize_t resid;
	int eflags;
	int ioflag = ap->a_ioflag;
	int retval = 0;
	int lockflags;
	int cnode_locked = 0;
	int partialwrite = 0;
	int do_snapshot = 1;
	time_t orig_ctime=VTOC(vp)->c_ctime;
	int took_truncate_lock = 0;
	int io_return_on_throttle = 0;
	int throttled_count = 0;

#if HFS_COMPRESSION
	if ( hfs_file_is_compressed(VTOC(vp), 1) ) { /* 1 == don't take the cnode lock */
		int state = decmpfs_cnode_get_vnode_state(VTOCMP(vp));
		switch(state) {
			case FILE_IS_COMPRESSED:
				return EACCES;
			case FILE_IS_CONVERTING:
				/* if FILE_IS_CONVERTING, we allow writes but do not
				   bother with snapshots or else we will deadlock.
				*/
				do_snapshot = 0;
				break;
			default:
				printf("invalid state %d for compressed file\n", state);
				/* fall through */
		}
	} else if ((VTOC(vp)->c_bsdflags & UF_COMPRESSED)) {
		int error;
		
		error = check_for_dataless_file(vp, NAMESPACE_HANDLER_WRITE_OP);
		if (error != 0) {
			return error;
		}
	}

	if (do_snapshot) {
		check_for_tracked_file(vp, orig_ctime, NAMESPACE_HANDLER_WRITE_OP, uio);
	}

#endif

#if SECURE_KERNEL
	if ((ioflag & (IO_SKIP_ENCRYPTION|IO_SYSCALL_DISPATCH)) ==
						(IO_SKIP_ENCRYPTION|IO_SYSCALL_DISPATCH)) {
		/* Don't allow unencrypted io request from user space */
		return EPERM;
	}
#endif

	resid = uio_resid(uio);
	offset = uio_offset(uio);

	if (offset < 0)
		return (EINVAL);
	if (resid == 0)
		return (E_NONE);
	if (!vnode_isreg(vp))
		return (EPERM);  /* Can only write regular files */

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);

#if CONFIG_PROTECT
	if ((retval = cp_handle_vnop (vp, CP_WRITE_ACCESS, 0)) != 0) {
		goto exit;
	}
#endif

	eflags = kEFDeferMask;	/* defer file block allocations */
#if HFS_SPARSE_DEV
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

	if ((ioflag & (IO_SINGLE_WRITER | IO_SYSCALL_DISPATCH)) == 
			(IO_SINGLE_WRITER | IO_SYSCALL_DISPATCH)) {
		io_return_on_throttle = IO_RETURN_ON_THROTTLE;
	}

again:
	/*
	 * Protect against a size change.
	 *
	 * Note: If took_truncate_lock is true, then we previously got the lock shared
	 * but needed to upgrade to exclusive.  So try getting it exclusive from the
	 * start.
	 */
	if (ioflag & IO_APPEND || took_truncate_lock) {
		hfs_lock_truncate(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	}	
	else {
		hfs_lock_truncate(cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT);
	}
	took_truncate_lock = 1;

	/* Update UIO */
	if (ioflag & IO_APPEND) {
		uio_setoffset(uio, fp->ff_size);
		offset = fp->ff_size;
	}
	if ((cp->c_bsdflags & APPEND) && offset != fp->ff_size) {
		retval = EPERM;
		goto exit;
	}

	cred = vfs_context_ucred(ap->a_context);
	if (cred && suser(cred, NULL) != 0)
		eflags |= kEFReserveMask;

	origFileSize = fp->ff_size;
	writelimit = offset + resid;

	/*
	 * We may need an exclusive truncate lock for several reasons, all
	 * of which are because we may be writing to a (portion of a) block
	 * for the first time, and we need to make sure no readers see the
	 * prior, uninitialized contents of the block.  The cases are:
	 *
	 * 1. We have unallocated (delayed allocation) blocks.  We may be
	 *    allocating new blocks to the file and writing to them.
	 *    (A more precise check would be whether the range we're writing
	 *    to contains delayed allocation blocks.)
	 * 2. We need to extend the file.  The bytes between the old EOF
	 *    and the new EOF are not yet initialized.  This is important
	 *    even if we're not allocating new blocks to the file.  If the
	 *    old EOF and new EOF are in the same block, we still need to
	 *    protect that range of bytes until they are written for the
	 *    first time.
	 *
	 * If we had a shared lock with the above cases, we need to try to upgrade
	 * to an exclusive lock.  If the upgrade fails, we will lose the shared
	 * lock, and will need to take the truncate lock again; the took_truncate_lock
	 * flag will still be set, causing us to try for an exclusive lock next time.
	 */
	if ((cp->c_truncatelockowner == HFS_SHARED_OWNER) &&
	    ((fp->ff_unallocblocks != 0) ||
	     (writelimit > origFileSize))) {
		if (lck_rw_lock_shared_to_exclusive(&cp->c_truncatelock) == FALSE) {
			/*
			 * Lock upgrade failed and we lost our shared lock, try again.
			 * Note: we do not set took_truncate_lock=0 here.  Leaving it
			 * set to 1 will cause us to try to get the lock exclusive.
			 */
			goto again;
		} 
		else {
			/* Store the owner in the c_truncatelockowner field if we successfully upgrade */
			cp->c_truncatelockowner = current_thread();  
		}
	}

	if ( (retval = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
		goto exit;
	}
	cnode_locked = 1;

	filebytes = hfs_blk_to_bytes(fp->ff_blocks, hfsmp->blockSize);

	if (offset > filebytes
		&& (hfs_blk_to_bytes(hfs_freeblks(hfsmp, ISSET(eflags, kEFReserveMask)),
							 hfsmp->blockSize) < offset - filebytes)) {
		retval = ENOSPC;
		goto exit;
	}

	KERNEL_DEBUG(HFSDBG_WRITE | DBG_FUNC_START,
		     (int)offset, uio_resid(uio), (int)fp->ff_size,
		     (int)filebytes, 0);

	/* Check if we do not need to extend the file */
	if (writelimit <= filebytes) {
		goto sizeok;
	}

	bytesToAdd = writelimit - filebytes;

#if QUOTA
	retval = hfs_chkdq(cp, (int64_t)(roundup(bytesToAdd, hfsmp->blockSize)), 
			   cred, 0);
	if (retval)
		goto exit;
#endif /* QUOTA */

	if (hfs_start_transaction(hfsmp) != 0) {
		retval = EINVAL;
		goto exit;
	}

	while (writelimit > filebytes) {
		bytesToAdd = writelimit - filebytes;

		/* Protect extents b-tree and allocation bitmap */
		lockflags = SFL_BITMAP;
		if (overflow_extents(fp))
			lockflags |= SFL_EXTENTS;
		lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
	
		/* Files that are changing size are not hot file candidates. */
		if (hfsmp->hfc_stage == HFC_RECORDING) {
			fp->ff_bytesread = 0;
		}
		retval = MacToVFSError(ExtendFileC (hfsmp, (FCB*)fp, bytesToAdd,
				0, eflags, &actualBytesAdded));

		hfs_systemfile_unlock(hfsmp, lockflags);

		if ((actualBytesAdded == 0) && (retval == E_NONE))
			retval = ENOSPC;
		if (retval != E_NONE)
			break;
		filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;
		KERNEL_DEBUG(HFSDBG_WRITE | DBG_FUNC_NONE,
			(int)offset, uio_resid(uio), (int)fp->ff_size,  (int)filebytes, 0);
	}
	(void) hfs_update(vp, 0);
	(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
	(void) hfs_end_transaction(hfsmp);

	/*
	 * If we didn't grow the file enough try a partial write.
	 * POSIX expects this behavior.
	 */
	if ((retval == ENOSPC) && (filebytes > offset)) {
		retval = 0;
		partialwrite = 1;
		uio_setresid(uio, (uio_resid(uio) - bytesToAdd));
		resid -= bytesToAdd;
		writelimit = filebytes;
	}
sizeok:
	if (retval == E_NONE) {
		off_t filesize;
		off_t head_off;
		int lflag;

		if (writelimit > fp->ff_size) {
			filesize = writelimit;
			struct timeval tv;
			rl_add(fp->ff_size, writelimit - 1 , &fp->ff_invalidranges);
			microuptime(&tv);
			cp->c_zftimeout = tv.tv_sec + ZFTIMELIMIT;
		} else
			filesize = fp->ff_size;

		lflag = ioflag & ~(IO_TAILZEROFILL | IO_HEADZEROFILL | IO_NOZEROVALID | IO_NOZERODIRTY);

		/*
		 * We no longer use IO_HEADZEROFILL or IO_TAILZEROFILL (except
		 * for one case below).  For the regions that lie before the
		 * beginning and after the end of this write that are in the
		 * same page, we let the cluster code handle zeroing that out
		 * if necessary.  If those areas are not cached, the cluster
		 * code will try and read those areas in, and in the case
		 * where those regions have never been written to,
		 * hfs_vnop_blockmap will consult the invalid ranges and then
		 * indicate that.  The cluster code will zero out those areas.
		 */

		head_off = trunc_page_64(offset);

		if (head_off < offset && head_off >= fp->ff_size) {
			/*
			 * The first page is beyond current EOF, so as an
			 * optimisation, we can pass IO_HEADZEROFILL.
			 */
			lflag |= IO_HEADZEROFILL;
		}

		hfs_unlock(cp);
		cnode_locked = 0;

		/*
		 * We need to tell UBC the fork's new size BEFORE calling
		 * cluster_write, in case any of the new pages need to be
		 * paged out before cluster_write completes (which does happen
		 * in embedded systems due to extreme memory pressure).
		 * Similarly, we need to tell hfs_vnop_pageout what the new EOF
		 * will be, so that it can pass that on to cluster_pageout, and
		 * allow those pageouts.
		 *
		 * We don't update ff_size yet since we don't want pageins to
		 * be able to see uninitialized data between the old and new
		 * EOF, until cluster_write has completed and initialized that
		 * part of the file.
		 *
		 * The vnode pager relies on the file size last given to UBC via
		 * ubc_setsize.  hfs_vnop_pageout relies on fp->ff_new_size or
		 * ff_size (whichever is larger).  NOTE: ff_new_size is always
		 * zero, unless we are extending the file via write.
		 */
		if (filesize > fp->ff_size) {
			retval = hfs_zero_eof_page(vp, offset);
			if (retval)
				goto exit;
			fp->ff_new_size = filesize;
			ubc_setsize(vp, filesize);
		}
		retval = cluster_write(vp, uio, fp->ff_size, filesize, head_off,
							   0, lflag | IO_NOZERODIRTY | io_return_on_throttle);
		if (retval) {
			fp->ff_new_size = 0;	/* no longer extending; use ff_size */
			
			if (retval == EAGAIN) {
				/*
				 * EAGAIN indicates that we still have I/O to do, but
				 * that we now need to be throttled
				 */
				if (resid != uio_resid(uio)) {
					/*
					 * did manage to do some I/O before returning EAGAIN
					 */
					resid = uio_resid(uio);
					offset = uio_offset(uio);

					cp->c_touch_chgtime = TRUE;
					cp->c_touch_modtime = TRUE;
					hfs_incr_gencount(cp);
				}
				if (filesize > fp->ff_size) {
					/*
					 * we called ubc_setsize before the call to
					 * cluster_write... since we only partially
					 * completed the I/O, we need to 
					 * re-adjust our idea of the filesize based
					 * on our interim EOF
					 */
					ubc_setsize(vp, offset);

					fp->ff_size = offset;
				}
				goto exit;
			}
			if (filesize > origFileSize) {
				ubc_setsize(vp, origFileSize);
			}
			goto ioerr_exit;
		}
		
		if (filesize > origFileSize) {
			fp->ff_size = filesize;
			
			/* Files that are changing size are not hot file candidates. */
			if (hfsmp->hfc_stage == HFC_RECORDING) {
				fp->ff_bytesread = 0;
			}
		}
		fp->ff_new_size = 0;	/* ff_size now has the correct size */		
	}
	if (partialwrite) {
		uio_setresid(uio, (uio_resid(uio) + bytesToAdd));
		resid += bytesToAdd;
	}

	// XXXdbg - see radar 4871353 for more info
	{
	    if (flush_cache_on_write && ((ioflag & IO_NOCACHE) || vnode_isnocache(vp))) {
			hfs_flush(hfsmp, HFS_FLUSH_CACHE);
	    }
	}

ioerr_exit:
	if (!cnode_locked) {
		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		cnode_locked = 1;
	}

	if (resid > uio_resid(uio)) {
		cp->c_touch_chgtime = TRUE;
		cp->c_touch_modtime = TRUE;
		hfs_incr_gencount(cp);

		/*
		 * If we successfully wrote any data, and we are not the superuser
		 * we clear the setuid and setgid bits as a precaution against
		 * tampering.
		 */
		if (cp->c_mode & (S_ISUID | S_ISGID)) {
			cred = vfs_context_ucred(ap->a_context);
			if (cred && suser(cred, NULL)) {
				cp->c_mode &= ~(S_ISUID | S_ISGID);
			}
		}
	}
	if (retval) {
		if (ioflag & IO_UNIT) {
			(void)hfs_truncate(vp, origFileSize, ioflag & IO_SYNC,
			                   0, ap->a_context);
			uio_setoffset(uio, (uio_offset(uio) - (resid - uio_resid(uio))));
			uio_setresid(uio, resid);
			filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;
		}
	} else if ((ioflag & IO_SYNC) && (resid > uio_resid(uio)))
		retval = hfs_update(vp, 0);

	/* Updating vcbWrCnt doesn't need to be atomic. */
	hfsmp->vcbWrCnt++;

	KERNEL_DEBUG(HFSDBG_WRITE | DBG_FUNC_END,
		(int)uio_offset(uio), uio_resid(uio), (int)fp->ff_size, (int)filebytes, 0);
exit:
	if (retval && took_truncate_lock
		&& cp->c_truncatelockowner == current_thread()) {
		fp->ff_new_size = 0;
		rl_remove(fp->ff_size, RL_INFINITY, &fp->ff_invalidranges);
	}

	if (cnode_locked)
		hfs_unlock(cp);

	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	}
	if (retval == EAGAIN) {
		throttle_lowpri_io(1);
		throttled_count++;

		retval = 0;
		goto again;
	}
	if (throttled_count) {
		throttle_info_reset_window((uthread_t)get_bsdthread_info(current_thread()));
	}
	return (retval);
}

/* support for the "bulk-access" fcntl */

#define CACHE_LEVELS 16
#define NUM_CACHE_ENTRIES (64*16)
#define PARENT_IDS_FLAG 0x100

struct access_cache {
       int numcached;
       int cachehits; /* these two for statistics gathering */
       int lookups;
       unsigned int *acache;
       unsigned char *haveaccess;
};

struct access_t {
	uid_t     uid;              /* IN: effective user id */
	short     flags;            /* IN: access requested (i.e. R_OK) */
	short     num_groups;       /* IN: number of groups user belongs to */
	int       num_files;        /* IN: number of files to process */
	int       *file_ids;        /* IN: array of file ids */
	gid_t     *groups;          /* IN: array of groups */
	short     *access;          /* OUT: access info for each file (0 for 'has access') */
} __attribute__((unavailable)); // this structure is for reference purposes only

struct user32_access_t {
	uid_t     uid;              /* IN: effective user id */
	short     flags;            /* IN: access requested (i.e. R_OK) */
	short     num_groups;       /* IN: number of groups user belongs to */
	int       num_files;        /* IN: number of files to process */
	user32_addr_t      file_ids;        /* IN: array of file ids */
	user32_addr_t      groups;          /* IN: array of groups */
	user32_addr_t      access;          /* OUT: access info for each file (0 for 'has access') */
};

struct user64_access_t {
	uid_t		uid;			/* IN: effective user id */
	short		flags;			/* IN: access requested (i.e. R_OK) */
	short		num_groups;		/* IN: number of groups user belongs to */
	int		num_files;		/* IN: number of files to process */
	user64_addr_t	file_ids;		/* IN: array of file ids */
	user64_addr_t	groups;			/* IN: array of groups */
	user64_addr_t	access;			/* OUT: access info for each file (0 for 'has access') */
};


// these are the "extended" versions of the above structures
// note that it is crucial that they be different sized than
// the regular version
struct ext_access_t {
	uint32_t   flags;           /* IN: access requested (i.e. R_OK) */
	uint32_t   num_files;       /* IN: number of files to process */
	uint32_t   map_size;        /* IN: size of the bit map */
	uint32_t  *file_ids;        /* IN: Array of file ids */
	char      *bitmap;          /* OUT: hash-bitmap of interesting directory ids */
	short     *access;          /* OUT: access info for each file (0 for 'has access') */
	uint32_t   num_parents;   /* future use */
	cnid_t      *parents;   /* future use */
} __attribute__((unavailable)); // this structure is for reference purposes only

struct user32_ext_access_t {
	uint32_t   flags;           /* IN: access requested (i.e. R_OK) */
	uint32_t   num_files;       /* IN: number of files to process */
	uint32_t   map_size;        /* IN: size of the bit map */
	user32_addr_t  file_ids;        /* IN: Array of file ids */
	user32_addr_t     bitmap;          /* OUT: hash-bitmap of interesting directory ids */
	user32_addr_t access;          /* OUT: access info for each file (0 for 'has access') */
	uint32_t   num_parents;   /* future use */
	user32_addr_t parents;   /* future use */
};

struct user64_ext_access_t {
	uint32_t      flags;        /* IN: access requested (i.e. R_OK) */
	uint32_t      num_files;    /* IN: number of files to process */
	uint32_t      map_size;     /* IN: size of the bit map */
	user64_addr_t   file_ids;     /* IN: array of file ids */
	user64_addr_t   bitmap;       /* IN: array of groups */
	user64_addr_t   access;       /* OUT: access info for each file (0 for 'has access') */
	uint32_t      num_parents;/* future use */
	user64_addr_t   parents;/* future use */
};


/*
 * Perform a binary search for the given parent_id. Return value is 
 * the index if there is a match.  If no_match_indexp is non-NULL it
 * will be assigned with the index to insert the item (even if it was
 * not found).
 */
static int cache_binSearch(cnid_t *array, unsigned int hi, cnid_t parent_id, int *no_match_indexp)
{
    int index=-1;
    unsigned int lo=0;
	
    do {
	unsigned int mid = ((hi - lo)/2) + lo;
	unsigned int this_id = array[mid];
		
	if (parent_id == this_id) {
	    hi = mid;
	    break;
	}
		
	if (parent_id < this_id) {
	    hi = mid;
	    continue;
	}
		
	if (parent_id > this_id) {
	    lo = mid + 1;
	    continue;
	}
    } while(lo < hi);

    /* check if lo and hi converged on the match */
    if (parent_id == array[hi]) {
	index = hi;
    }
	
    if (no_match_indexp) {
	*no_match_indexp = hi;
    }

    return index;
}
 
 
static int
lookup_bucket(struct access_cache *cache, int *indexp, cnid_t parent_id)
{
    unsigned int hi;
    int matches = 0;
    int index, no_match_index;
	
    if (cache->numcached == 0) {
	*indexp = 0;
	return 0; // table is empty, so insert at index=0 and report no match
    }
	
    if (cache->numcached > NUM_CACHE_ENTRIES) {
	cache->numcached = NUM_CACHE_ENTRIES;
    }
	
    hi = cache->numcached - 1;
	
    index = cache_binSearch(cache->acache, hi, parent_id, &no_match_index);

    /* if no existing entry found, find index for new one */
    if (index == -1) {
	index = no_match_index;
	matches = 0;
    } else {
	matches = 1;
    }
	
    *indexp = index;
    return matches;
}

/*
 * Add a node to the access_cache at the given index (or do a lookup first
 * to find the index if -1 is passed in). We currently do a replace rather
 * than an insert if the cache is full.
 */
static void
add_node(struct access_cache *cache, int index, cnid_t nodeID, int access)
{
    int lookup_index = -1;

    /* need to do a lookup first if -1 passed for index */
    if (index == -1) {
	if (lookup_bucket(cache, &lookup_index, nodeID)) {
	    if (cache->haveaccess[lookup_index] != access && cache->haveaccess[lookup_index] == ESRCH) {
		// only update an entry if the previous access was ESRCH (i.e. a scope checking error)
		cache->haveaccess[lookup_index] = access;
	    }

	    /* mission accomplished */
	    return;
	} else {
	    index = lookup_index;
	}

    }

    /* if the cache is full, do a replace rather than an insert */
    if (cache->numcached >= NUM_CACHE_ENTRIES) {
	cache->numcached = NUM_CACHE_ENTRIES-1;

	if (index > cache->numcached) {
	    index = cache->numcached;
	}
    }

    if (index < cache->numcached && index < NUM_CACHE_ENTRIES && nodeID > cache->acache[index]) {
	index++;
    }

    if (index >= 0 && index < cache->numcached) {
	/* only do bcopy if we're inserting */
	bcopy( cache->acache+index, cache->acache+(index+1), (cache->numcached - index)*sizeof(int) );
	bcopy( cache->haveaccess+index, cache->haveaccess+(index+1), (cache->numcached - index)*sizeof(unsigned char) );
    }

    cache->acache[index] = nodeID;
    cache->haveaccess[index] = access;
    cache->numcached++;
}


struct cinfo {
    uid_t   uid;
    gid_t   gid;
    mode_t  mode;
    cnid_t  parentcnid;
    u_int16_t recflags;
};

static int
snoop_callback(const cnode_t *cp, void *arg)
{
    struct cinfo *cip = arg;

    cip->uid = cp->c_uid;
    cip->gid = cp->c_gid;
    cip->mode = cp->c_mode;
    cip->parentcnid = cp->c_parentcnid;
    cip->recflags = cp->c_attr.ca_recflags;
	
    return (0);
}

/*
 * Lookup the cnid's attr info (uid, gid, and mode) as well as its parent id. If the item
 * isn't incore, then go to the catalog.
 */ 
static int
do_attr_lookup(struct hfsmount *hfsmp, struct access_cache *cache, cnid_t cnid, 
    struct cnode *skip_cp, CatalogKey *keyp, struct cat_attr *cnattrp)
{
    int error = 0;

    /* if this id matches the one the fsctl was called with, skip the lookup */
    if (cnid == skip_cp->c_cnid) {
		cnattrp->ca_uid = skip_cp->c_uid;
		cnattrp->ca_gid = skip_cp->c_gid;
		cnattrp->ca_mode = skip_cp->c_mode;
		cnattrp->ca_recflags = skip_cp->c_attr.ca_recflags;
		keyp->hfsPlus.parentID = skip_cp->c_parentcnid;
    } else {
		struct cinfo c_info;

		/* otherwise, check the cnode hash incase the file/dir is incore */
		error = hfs_chash_snoop(hfsmp, cnid, 0, snoop_callback, &c_info);

		if (error == EACCES) {
			// File is deleted
			return ENOENT;
		} else if (!error) {
			cnattrp->ca_uid = c_info.uid;
			cnattrp->ca_gid = c_info.gid;
			cnattrp->ca_mode = c_info.mode;
			cnattrp->ca_recflags = c_info.recflags;
			keyp->hfsPlus.parentID = c_info.parentcnid;
		} else {
			int lockflags;

			if (throttle_io_will_be_throttled(-1, HFSTOVFS(hfsmp)))
				throttle_lowpri_io(1);

			lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

			/* lookup this cnid in the catalog */
			error = cat_getkeyplusattr(hfsmp, cnid, keyp, cnattrp);
			
			hfs_systemfile_unlock(hfsmp, lockflags);
			
			cache->lookups++;
		}
    }
	
    return (error);
}


/*
 * Compute whether we have access to the given directory (nodeID) and all its parents. Cache
 * up to CACHE_LEVELS as we progress towards the root.
 */
static int 
do_access_check(struct hfsmount *hfsmp, int *err, struct access_cache *cache, HFSCatalogNodeID nodeID, 
    struct cnode *skip_cp, struct proc *theProcPtr, kauth_cred_t myp_ucred,
    struct vfs_context *my_context,
    char *bitmap,
    uint32_t map_size,
    cnid_t* parents,
    uint32_t num_parents)
{
    int                     myErr = 0;
    int                     myResult;
    HFSCatalogNodeID        thisNodeID;
    unsigned int            myPerms;
    struct cat_attr         cnattr;
    int                     cache_index = -1, scope_index = -1, scope_idx_start = -1;
    CatalogKey              catkey;

    int i = 0, ids_to_cache = 0;
    int parent_ids[CACHE_LEVELS];

    thisNodeID = nodeID;
    while (thisNodeID >=  kRootDirID) {
	myResult = 0;   /* default to "no access" */
	       
	/* check the cache before resorting to hitting the catalog */

	/* ASSUMPTION: access info of cached entries is "final"... i.e. no need
	 * to look any further after hitting cached dir */

	if (lookup_bucket(cache, &cache_index, thisNodeID)) {
	    cache->cachehits++;
	    myErr = cache->haveaccess[cache_index];
	    if (scope_index != -1) {
		if (myErr == ESRCH) {
		    myErr = 0;
		}
	    } else {
		scope_index = 0;   // so we'll just use the cache result 
		scope_idx_start = ids_to_cache;
	    }
	    myResult = (myErr == 0) ? 1 : 0;
	    goto ExitThisRoutine;
	}


	if (parents) {
	    int tmp;
	    tmp = cache_binSearch(parents, num_parents-1, thisNodeID, NULL);
	    if (scope_index == -1)
		scope_index = tmp;
	    if (tmp != -1 && scope_idx_start == -1 && ids_to_cache < CACHE_LEVELS) {
		scope_idx_start = ids_to_cache;
	    }
	}	   

	/* remember which parents we want to cache */
	if (ids_to_cache < CACHE_LEVELS) {
	    parent_ids[ids_to_cache] = thisNodeID;
	    ids_to_cache++;
	}
	// Inefficient (using modulo) and we might want to use a hash function, not rely on the node id to be "nice"...
	if (bitmap && map_size) {
	    bitmap[(thisNodeID/8)%(map_size)]|=(1<<(thisNodeID&7));	       
	}
	       

	/* do the lookup (checks the cnode hash, then the catalog) */
	myErr = do_attr_lookup(hfsmp, cache, thisNodeID, skip_cp, &catkey, &cnattr);
	if (myErr) {
	    goto ExitThisRoutine; /* no access */
	}

	/* Root always gets access. */
	if (suser(myp_ucred, NULL) == 0) {
		thisNodeID = catkey.hfsPlus.parentID;
		myResult = 1;
		continue;
	}

	// if the thing has acl's, do the full permission check
	if ((cnattr.ca_recflags & kHFSHasSecurityMask) != 0) {
	    struct vnode *vp;

	    /* get the vnode for this cnid */
	    myErr = hfs_vget(hfsmp, thisNodeID, &vp, 0, 0);
	    if ( myErr ) {
		myResult = 0;
		goto ExitThisRoutine;
	    }

	    thisNodeID = VTOC(vp)->c_parentcnid;

	    hfs_unlock(VTOC(vp));

	    if (vnode_vtype(vp) == VDIR) {
		myErr = vnode_authorize(vp, NULL, (KAUTH_VNODE_SEARCH | KAUTH_VNODE_LIST_DIRECTORY), my_context);
	    } else {
		myErr = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, my_context);
	    }

	    vnode_put(vp);
	    if (myErr) {
		myResult = 0;
		goto ExitThisRoutine;
	    }
	} else {
	    unsigned int flags;
		int mode = cnattr.ca_mode & S_IFMT;   
		myPerms = DerivePermissionSummary(cnattr.ca_uid, cnattr.ca_gid, cnattr.ca_mode, hfsmp->hfs_mp,myp_ucred, theProcPtr);

		if (mode == S_IFDIR) {
			flags = R_OK | X_OK;
		} else {
			flags = R_OK;
		}
		if ( (myPerms & flags) != flags) {
			myResult = 0;
			myErr = EACCES;
			goto ExitThisRoutine;   /* no access */
		}

	    /* up the hierarchy we go */
	    thisNodeID = catkey.hfsPlus.parentID;
	}
    }

    /* if here, we have access to this node */
    myResult = 1;

  ExitThisRoutine:
    if (parents && myErr == 0 && scope_index == -1) {
	myErr = ESRCH;
    }
				
    if (myErr) {
	myResult = 0;
    }
    *err = myErr;

    /* cache the parent directory(ies) */
    for (i = 0; i < ids_to_cache; i++) {
	if (myErr == 0 && parents && (scope_idx_start == -1 || i > scope_idx_start)) {
	    add_node(cache, -1, parent_ids[i], ESRCH);
	} else {
	    add_node(cache, -1, parent_ids[i], myErr);
	}
    }

    return (myResult);
}

static int
do_bulk_access_check(struct hfsmount *hfsmp, struct vnode *vp,
    struct vnop_ioctl_args *ap, int arg_size, vfs_context_t context)
{
    boolean_t is64bit;

    /*
     * NOTE: on entry, the vnode has an io_ref. In case this vnode
     * happens to be in our list of file_ids, we'll note it
     * avoid calling hfs_chashget_nowait() on that id as that
     * will cause a "locking against myself" panic.
     */
    Boolean check_leaf = true;
		
    struct user64_ext_access_t *user_access_structp;
    struct user64_ext_access_t tmp_user_access;
    struct access_cache cache;
		
    int error = 0, prev_parent_check_ok=1;
    unsigned int i;
		
    short flags;
    unsigned int num_files = 0;
    int map_size = 0;
    int num_parents = 0;
    int *file_ids=NULL;
    short *access=NULL;
    char *bitmap=NULL;
    cnid_t *parents=NULL;
    int leaf_index;
	
    cnid_t cnid;
    cnid_t prevParent_cnid = 0;
    unsigned int myPerms;
    short myaccess = 0;
    struct cat_attr cnattr;
    CatalogKey catkey;
    struct cnode *skip_cp = VTOC(vp);
    kauth_cred_t cred = vfs_context_ucred(context);
    proc_t p = vfs_context_proc(context);

    is64bit = proc_is64bit(p);

    /* initialize the local cache and buffers */
    cache.numcached = 0;
    cache.cachehits = 0;
    cache.lookups = 0;
    cache.acache = NULL;
    cache.haveaccess = NULL;
		
    /* struct copyin done during dispatch... need to copy file_id array separately */
    if (ap->a_data == NULL) {
	error = EINVAL;
	goto err_exit_bulk_access;
    }

    if (is64bit) {
	if (arg_size != sizeof(struct user64_ext_access_t)) {
	    error = EINVAL;
	    goto err_exit_bulk_access;
	}

	user_access_structp = (struct user64_ext_access_t *)ap->a_data;

    } else if (arg_size == sizeof(struct user32_access_t)) {
	struct user32_access_t *accessp = (struct user32_access_t *)ap->a_data;

	// convert an old style bulk-access struct to the new style
	tmp_user_access.flags     = accessp->flags;
	tmp_user_access.num_files = accessp->num_files;
	tmp_user_access.map_size  = 0;
	tmp_user_access.file_ids  = CAST_USER_ADDR_T(accessp->file_ids);
	tmp_user_access.bitmap    = USER_ADDR_NULL;
	tmp_user_access.access    = CAST_USER_ADDR_T(accessp->access);
	tmp_user_access.num_parents = 0;
	user_access_structp = &tmp_user_access;

    } else if (arg_size == sizeof(struct user32_ext_access_t)) {
	struct user32_ext_access_t *accessp = (struct user32_ext_access_t *)ap->a_data;

	// up-cast from a 32-bit version of the struct
	tmp_user_access.flags     = accessp->flags;
	tmp_user_access.num_files = accessp->num_files;
	tmp_user_access.map_size  = accessp->map_size;
	tmp_user_access.num_parents  = accessp->num_parents;

	tmp_user_access.file_ids  = CAST_USER_ADDR_T(accessp->file_ids);
	tmp_user_access.bitmap    = CAST_USER_ADDR_T(accessp->bitmap);
	tmp_user_access.access    = CAST_USER_ADDR_T(accessp->access);
	tmp_user_access.parents    = CAST_USER_ADDR_T(accessp->parents);

	user_access_structp = &tmp_user_access;
    } else {
	error = EINVAL;
	goto err_exit_bulk_access;
    }
		
    map_size = user_access_structp->map_size;

    num_files = user_access_structp->num_files;

    num_parents= user_access_structp->num_parents;

    if (num_files < 1) {
	goto err_exit_bulk_access;
    }
    if (num_files > 1024) {
	error = EINVAL;
	goto err_exit_bulk_access;
    }

    if (num_parents > 1024) {
	error = EINVAL;
	goto err_exit_bulk_access;
    }
		
    file_ids = (int *) kalloc(sizeof(int) * num_files);
    access = (short *) kalloc(sizeof(short) * num_files);
    if (map_size) {
	bitmap = (char *) kalloc(sizeof(char) * map_size);
    }

    if (num_parents) {
	parents = (cnid_t *) kalloc(sizeof(cnid_t) * num_parents);
    }

    cache.acache = (unsigned int *) kalloc(sizeof(int) * NUM_CACHE_ENTRIES);
    cache.haveaccess = (unsigned char *) kalloc(sizeof(unsigned char) * NUM_CACHE_ENTRIES);
		
    if (file_ids == NULL || access == NULL || (map_size != 0 && bitmap == NULL) || cache.acache == NULL || cache.haveaccess == NULL) {
	if (file_ids) {
	    kfree(file_ids, sizeof(int) * num_files);
	}
	if (bitmap) {
	    kfree(bitmap, sizeof(char) * map_size);
	}
	if (access) {
	    kfree(access, sizeof(short) * num_files);
	}
	if (cache.acache) {
	    kfree(cache.acache, sizeof(int) * NUM_CACHE_ENTRIES);
	}
	if (cache.haveaccess) {
	    kfree(cache.haveaccess, sizeof(unsigned char) * NUM_CACHE_ENTRIES);
	}
	if (parents) {
	    kfree(parents, sizeof(cnid_t) * num_parents);
	}			
	return ENOMEM;
    }
		
    // make sure the bitmap is zero'ed out...
    if (bitmap) {
	bzero(bitmap, (sizeof(char) * map_size));
    }

    if ((error = copyin(user_access_structp->file_ids, (caddr_t)file_ids,
		num_files * sizeof(int)))) {
	goto err_exit_bulk_access;
    }
	
    if (num_parents) {
	if ((error = copyin(user_access_structp->parents, (caddr_t)parents,
		    num_parents * sizeof(cnid_t)))) {
	    goto err_exit_bulk_access;
	}
    }
	
    flags = user_access_structp->flags;
    if ((flags & (F_OK | R_OK | W_OK | X_OK)) == 0) {
	flags = R_OK;
    }
		
    /* check if we've been passed leaf node ids or parent ids */
    if (flags & PARENT_IDS_FLAG) {
	check_leaf = false;
    }
		
    /* Check access to each file_id passed in */
    for (i = 0; i < num_files; i++) {
	leaf_index=-1;
	cnid = (cnid_t) file_ids[i];
			
	/* root always has access */
	if ((!parents) && (!suser(cred, NULL))) {
	    access[i] = 0;
	    continue;
	}
			
	if (check_leaf) {
	    /* do the lookup (checks the cnode hash, then the catalog) */
	    error = do_attr_lookup(hfsmp, &cache, cnid, skip_cp, &catkey, &cnattr);
	    if (error) {
		access[i] = (short) error;
		continue;
	    }
	    
	    if (parents) {
		// Check if the leaf matches one of the parent scopes
		leaf_index = cache_binSearch(parents, num_parents-1, cnid, NULL);
 		if (leaf_index >= 0 && parents[leaf_index] == cnid)
 		    prev_parent_check_ok = 0;
 		else if (leaf_index >= 0)
 		    prev_parent_check_ok = 1;
	    }

	    // if the thing has acl's, do the full permission check
	    if ((cnattr.ca_recflags & kHFSHasSecurityMask) != 0) {
		struct vnode *cvp;
		int myErr = 0;
		/* get the vnode for this cnid */
		myErr = hfs_vget(hfsmp, cnid, &cvp, 0, 0);
		if ( myErr ) {
		    access[i] = myErr;
		    continue;
		}
		
		hfs_unlock(VTOC(cvp));
		
		if (vnode_vtype(cvp) == VDIR) {
		    myErr = vnode_authorize(cvp, NULL, (KAUTH_VNODE_SEARCH | KAUTH_VNODE_LIST_DIRECTORY), context);
		} else {
		    myErr = vnode_authorize(cvp, NULL, KAUTH_VNODE_READ_DATA, context);
		}
		
		vnode_put(cvp);
		if (myErr) {
		    access[i] = myErr;
		    continue;
		}
	    } else {
		/* before calling CheckAccess(), check the target file for read access */
		myPerms = DerivePermissionSummary(cnattr.ca_uid, cnattr.ca_gid,
		    cnattr.ca_mode, hfsmp->hfs_mp, cred, p);
		
		/* fail fast if no access */ 
		if ((myPerms & flags) == 0) {
		    access[i] = EACCES;
		    continue;
		}		  					
	    }
	} else {
	    /* we were passed an array of parent ids */
	    catkey.hfsPlus.parentID = cnid;
	}
			
	/* if the last guy had the same parent and had access, we're done */
 	if (i > 0 && catkey.hfsPlus.parentID == prevParent_cnid && access[i-1] == 0 && prev_parent_check_ok) {
	    cache.cachehits++;
	    access[i] = 0;
	    continue;
	}
	
	myaccess = do_access_check(hfsmp, &error, &cache, catkey.hfsPlus.parentID, 
	    skip_cp, p, cred, context,bitmap, map_size, parents, num_parents);
			
	if (myaccess || (error == ESRCH && leaf_index != -1)) {
	    access[i] = 0; // have access.. no errors to report
	} else {
	    access[i] = (error != 0 ? (short) error : EACCES);
	}
			
	prevParent_cnid = catkey.hfsPlus.parentID;
    }
		
    /* copyout the access array */
    if ((error = copyout((caddr_t)access, user_access_structp->access, 
		num_files * sizeof (short)))) {
	goto err_exit_bulk_access;
    }
    if (map_size && bitmap) {
	if ((error = copyout((caddr_t)bitmap, user_access_structp->bitmap, 
		    map_size * sizeof (char)))) {
	    goto err_exit_bulk_access;
	}
    }
	
		
  err_exit_bulk_access:
		
    if (file_ids) 
	kfree(file_ids, sizeof(int) * num_files);
    if (parents) 
	kfree(parents, sizeof(cnid_t) * num_parents);
    if (bitmap) 
	kfree(bitmap, sizeof(char) * map_size);
    if (access)
	kfree(access, sizeof(short) * num_files);
    if (cache.acache)
	kfree(cache.acache, sizeof(int) * NUM_CACHE_ENTRIES);
    if (cache.haveaccess)
	kfree(cache.haveaccess, sizeof(unsigned char) * NUM_CACHE_ENTRIES);
		
    return (error);
}


/* end "bulk-access" support */


/*
 * Control filesystem operating characteristics.
 */
int
hfs_vnop_ioctl( struct vnop_ioctl_args /* {
		vnode_t a_vp;
		long  a_command;
		caddr_t  a_data;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode * vp = ap->a_vp;
	struct hfsmount *hfsmp = VTOHFS(vp);
	vfs_context_t context = ap->a_context;
	kauth_cred_t cred = vfs_context_ucred(context);
	proc_t p = vfs_context_proc(context);
	struct vfsstatfs *vfsp;
	boolean_t is64bit;
	off_t jnl_start, jnl_size;
	struct hfs_journal_info *jip;
#if HFS_COMPRESSION
	int compressed = 0;
	off_t uncompressed_size = -1;
	int decmpfs_error = 0;
	
	if (ap->a_command == F_RDADVISE) {
		/* we need to inspect the decmpfs state of the file as early as possible */
		compressed = hfs_file_is_compressed(VTOC(vp), 0);
		if (compressed) {
			if (VNODE_IS_RSRC(vp)) {
				/* if this is the resource fork, treat it as if it were empty */
				uncompressed_size = 0;
			} else {
				decmpfs_error = hfs_uncompressed_size_of_compressed_file(NULL, vp, 0, &uncompressed_size, 0);
				if (decmpfs_error != 0) {
					/* failed to get the uncompressed size, we'll check for this later */
					uncompressed_size = -1;
				}
			}
		}
	}
#endif /* HFS_COMPRESSION */

	is64bit = proc_is64bit(p);

#if CONFIG_PROTECT
	{
		int error = 0;
		if ((error = cp_handle_vnop(vp, CP_WRITE_ACCESS, 0)) != 0) {
			return error;
		}
	}
#endif /* CONFIG_PROTECT */

	switch (ap->a_command) {

	case HFS_GETPATH:
	{
		struct vnode *file_vp;
		cnid_t  cnid;
		int  outlen;
		char *bufptr;
		int error;
		int flags = 0;

		/* Caller must be owner of file system. */
		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES);
		}
		/* Target vnode must be file system's root. */
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		bufptr = (char *)ap->a_data;
		cnid = strtoul(bufptr, NULL, 10);
		if (ap->a_fflag & HFS_GETPATH_VOLUME_RELATIVE) {
			flags |= BUILDPATH_VOLUME_RELATIVE; 
		}

		/* We need to call hfs_vfs_vget to leverage the code that will
		 * fix the origin list for us if needed, as opposed to calling
		 * hfs_vget, since we will need the parent for build_path call.
		 */

		if ((error = hfs_vfs_vget(HFSTOVFS(hfsmp), cnid, &file_vp, context))) {
			return (error);
		}
		error = build_path(file_vp, bufptr, sizeof(pathname_t), &outlen, flags, context);
		vnode_put(file_vp);

		return (error);
	}

	case HFS_TRANSFER_DOCUMENT_ID:
	{
		struct cnode *cp = NULL;
		int error;
		u_int32_t to_fd = *(u_int32_t *)ap->a_data;
		struct fileproc *to_fp;
		struct vnode *to_vp;
		struct cnode *to_cp;

		cp = VTOC(vp);

		if ((error = fp_getfvp(p, to_fd, &to_fp, &to_vp)) != 0) {
			//printf("could not get the vnode for fd %d (err %d)\n", to_fd, error);
			return error;
		}
		if ( (error = vnode_getwithref(to_vp)) ) {
			file_drop(to_fd);
			return error;
		}

		if (VTOHFS(to_vp) != hfsmp) {
			error = EXDEV;
			goto transfer_cleanup;
		}

		int need_unlock = 1;
		to_cp = VTOC(to_vp);
		error = hfs_lockpair(cp, to_cp, HFS_EXCLUSIVE_LOCK);
		if (error != 0) {
			//printf("could not lock the pair of cnodes (error %d)\n", error);
			goto transfer_cleanup;
		}
			
		if (!(cp->c_bsdflags & UF_TRACKED)) {
			error = EINVAL;
		} else if (to_cp->c_bsdflags & UF_TRACKED) {
			//
			// if the destination is already tracked, return an error
			// as otherwise it's a silent deletion of the target's
			// document-id
			//
			error = EEXIST;
		} else if (S_ISDIR(cp->c_attr.ca_mode) || S_ISREG(cp->c_attr.ca_mode) || S_ISLNK(cp->c_attr.ca_mode)) {
			//
			// we can use the FndrExtendedFileInfo because the doc-id is the first
			// thing in both it and the ExtendedDirInfo struct which is fixed in
			// format and can not change layout
			//
			struct FndrExtendedFileInfo *f_extinfo = (struct FndrExtendedFileInfo *)((u_int8_t*)cp->c_finderinfo + 16);
			struct FndrExtendedFileInfo *to_extinfo = (struct FndrExtendedFileInfo *)((u_int8_t*)to_cp->c_finderinfo + 16);

			if (f_extinfo->document_id == 0) {
				uint32_t new_id;

				hfs_unlockpair(cp, to_cp);  // have to unlock to be able to get a new-id
				
				if ((error = hfs_generate_document_id(hfsmp, &new_id)) == 0) {
					//
					// re-lock the pair now that we have the document-id
					//
					hfs_lockpair(cp, to_cp, HFS_EXCLUSIVE_LOCK);
					f_extinfo->document_id = new_id;
				} else {
					goto transfer_cleanup;
				}
			}
					
			to_extinfo->document_id = f_extinfo->document_id;
			f_extinfo->document_id = 0;
			//printf("TRANSFERRING: doc-id %d from ino %d to ino %d\n", to_extinfo->document_id, cp->c_fileid, to_cp->c_fileid);

			// make sure the destination is also UF_TRACKED
			to_cp->c_bsdflags |= UF_TRACKED;
			cp->c_bsdflags &= ~UF_TRACKED;

			// mark the cnodes dirty
			cp->c_flag |= C_MODIFIED;
			to_cp->c_flag |= C_MODIFIED;

			int lockflags;
			if ((error = hfs_start_transaction(hfsmp)) == 0) {

				lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

				(void) cat_update(hfsmp, &cp->c_desc, &cp->c_attr, NULL, NULL);
				(void) cat_update(hfsmp, &to_cp->c_desc, &to_cp->c_attr, NULL, NULL);

				hfs_systemfile_unlock (hfsmp, lockflags);
				(void) hfs_end_transaction(hfsmp);
			}

#if CONFIG_FSE
			add_fsevent(FSE_DOCID_CHANGED, context,
				    FSE_ARG_DEV,   hfsmp->hfs_raw_dev,
				    FSE_ARG_INO,   (ino64_t)cp->c_fileid,       // src inode #
				    FSE_ARG_INO,   (ino64_t)to_cp->c_fileid,    // dst inode #
				    FSE_ARG_INT32, to_extinfo->document_id,
				    FSE_ARG_DONE);

			hfs_unlockpair(cp, to_cp);    // unlock this so we can send the fsevents
			need_unlock = 0;

			if (need_fsevent(FSE_STAT_CHANGED, vp)) {
				add_fsevent(FSE_STAT_CHANGED, context, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
			}
			if (need_fsevent(FSE_STAT_CHANGED, to_vp)) {
				add_fsevent(FSE_STAT_CHANGED, context, FSE_ARG_VNODE, to_vp, FSE_ARG_DONE);
			}
#else
			hfs_unlockpair(cp, to_cp);    // unlock this so we can send the fsevents
			need_unlock = 0;
#endif
		}
		
		if (need_unlock) {
			hfs_unlockpair(cp, to_cp);
		}

	transfer_cleanup:
		vnode_put(to_vp);
		file_drop(to_fd);

		return error;
	}



	case HFS_PREV_LINK:
	case HFS_NEXT_LINK:
	{
		cnid_t linkfileid;
		cnid_t nextlinkid;
		cnid_t prevlinkid;
		int error;

		/* Caller must be owner of file system. */
		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES);
		}
		/* Target vnode must be file system's root. */
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		linkfileid = *(cnid_t *)ap->a_data;
		if (linkfileid < kHFSFirstUserCatalogNodeID) {
			return (EINVAL);
		}
		if ((error = hfs_lookup_siblinglinks(hfsmp, linkfileid, &prevlinkid, &nextlinkid))) {
			return (error);
		}
		if (ap->a_command == HFS_NEXT_LINK) {
			*(cnid_t *)ap->a_data = nextlinkid;
		} else {
			*(cnid_t *)ap->a_data = prevlinkid;
		}
		return (0);
	}

	case HFS_RESIZE_PROGRESS: {

		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		/* file system must not be mounted read-only */
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}

		return hfs_resize_progress(hfsmp, (u_int32_t *)ap->a_data);
	}

	case HFS_RESIZE_VOLUME: {
		u_int64_t newsize;
		u_int64_t cursize;
		int ret;

		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		
		/* filesystem must not be mounted read only */
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		newsize = *(u_int64_t *)ap->a_data;
		cursize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;

		if (newsize == cursize) {
			return (0);
		}
		IOBSDMountChange(hfsmp->hfs_mp, kIOMountChangeWillResize);
		if (newsize > cursize) {
			ret = hfs_extendfs(hfsmp, *(u_int64_t *)ap->a_data, context);
		} else {
			ret = hfs_truncatefs(hfsmp, *(u_int64_t *)ap->a_data, context);
		}
		IOBSDMountChange(hfsmp->hfs_mp, kIOMountChangeDidResize);
		return (ret);
	}
	case HFS_CHANGE_NEXT_ALLOCATION: {
		int error = 0;		/* Assume success */
		u_int32_t location;

		if (vnode_vfsisrdonly(vp)) {
			return (EROFS);
		}
		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		hfs_lock_mount(hfsmp);
		location = *(u_int32_t *)ap->a_data;
		if ((location >= hfsmp->allocLimit) &&
			(location != HFS_NO_UPDATE_NEXT_ALLOCATION)) {
			error = EINVAL;
			goto fail_change_next_allocation;
		}
		/* Return previous value. */
		*(u_int32_t *)ap->a_data = hfsmp->nextAllocation;
		if (location == HFS_NO_UPDATE_NEXT_ALLOCATION) {
			/* On magic value for location, set nextAllocation to next block
			 * after metadata zone and set flag in mount structure to indicate 
			 * that nextAllocation should not be updated again.
			 */
			if (hfsmp->hfs_metazone_end != 0) {
				HFS_UPDATE_NEXT_ALLOCATION(hfsmp, hfsmp->hfs_metazone_end + 1);
			}
			hfsmp->hfs_flags |= HFS_SKIP_UPDATE_NEXT_ALLOCATION; 
		} else {
			hfsmp->hfs_flags &= ~HFS_SKIP_UPDATE_NEXT_ALLOCATION; 
			HFS_UPDATE_NEXT_ALLOCATION(hfsmp, location);
		}
		MarkVCBDirty(hfsmp);
fail_change_next_allocation:
		hfs_unlock_mount(hfsmp);
		return (error);
	}

#if HFS_SPARSE_DEV
	case HFS_SETBACKINGSTOREINFO: {
		struct vnode * bsfs_rootvp;
		struct vnode * di_vp;
		struct hfs_backingstoreinfo *bsdata;
		int error = 0;
		
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			return (EALREADY);
		}
		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		bsdata = (struct hfs_backingstoreinfo *)ap->a_data;
		if (bsdata == NULL) {
			return (EINVAL);
		}
		if ((error = file_vnode(bsdata->backingfd, &di_vp))) {
			return (error);
		}
		if ((error = vnode_getwithref(di_vp))) {
			file_drop(bsdata->backingfd);
			return(error);
		}

		if (vnode_mount(vp) == vnode_mount(di_vp)) {
			(void)vnode_put(di_vp);
			file_drop(bsdata->backingfd);
			return (EINVAL);
		}

		/*
		 * Obtain the backing fs root vnode and keep a reference
		 * on it.  This reference will be dropped in hfs_unmount.
		 */
		error = VFS_ROOT(vnode_mount(di_vp), &bsfs_rootvp, NULL); /* XXX use context! */
		if (error) {
			(void)vnode_put(di_vp);
			file_drop(bsdata->backingfd);
			return (error);
		}
		vnode_ref(bsfs_rootvp);
		vnode_put(bsfs_rootvp);

		hfs_lock_mount(hfsmp);
		hfsmp->hfs_backingfs_rootvp = bsfs_rootvp;
		hfsmp->hfs_flags |= HFS_HAS_SPARSE_DEVICE;
		hfsmp->hfs_sparsebandblks = bsdata->bandsize / hfsmp->blockSize * 4;
		hfs_unlock_mount(hfsmp);

		/* We check the MNTK_VIRTUALDEV bit instead of marking the dependent process */

		/*
		 * If the sparse image is on a sparse image file (as opposed to a sparse
		 * bundle), then we may need to limit the free space to the maximum size
		 * of a file on that volume.  So we query (using pathconf), and if we get
		 * a meaningful result, we cache the number of blocks for later use in
		 * hfs_freeblks().
		 */
		hfsmp->hfs_backingfs_maxblocks = 0;
		if (vnode_vtype(di_vp) == VREG) {
			int terr;
			int hostbits;
			terr = vn_pathconf(di_vp, _PC_FILESIZEBITS, &hostbits, context);
			if (terr == 0 && hostbits != 0 && hostbits < 64) {
				u_int64_t hostfilesizemax = ((u_int64_t)1) << hostbits;
				
				hfsmp->hfs_backingfs_maxblocks = hostfilesizemax / hfsmp->blockSize;
			}
		}
				
		/* The free extent cache is managed differently for sparse devices.  
		 * There is a window between which the volume is mounted and the 
		 * device is marked as sparse, so the free extent cache for this 
		 * volume is currently initialized as normal volume (sorted by block 
		 * count).  Reset the cache so that it will be rebuilt again 
		 * for sparse device (sorted by start block).
		 */
		ResetVCBFreeExtCache(hfsmp);

		(void)vnode_put(di_vp);
		file_drop(bsdata->backingfd);
		return (0);
	}
	case HFS_CLRBACKINGSTOREINFO: {
		struct vnode * tmpvp;

		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}

		if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) &&
		    hfsmp->hfs_backingfs_rootvp) {

			hfs_lock_mount(hfsmp);
			hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
			tmpvp = hfsmp->hfs_backingfs_rootvp;
			hfsmp->hfs_backingfs_rootvp = NULLVP;
			hfsmp->hfs_sparsebandblks = 0;
			hfs_unlock_mount(hfsmp);

			vnode_rele(tmpvp);
		}
		return (0);
	}
#endif /* HFS_SPARSE_DEV */

	/* Change the next CNID stored in the VH */
	case HFS_CHANGE_NEXTCNID: {
		int error = 0;		/* Assume success */
		u_int32_t fileid;
		int wraparound = 0;
		int lockflags = 0;

		if (vnode_vfsisrdonly(vp)) {
			return (EROFS);
		}
		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		
		fileid = *(u_int32_t *)ap->a_data;

		/* Must have catalog lock excl. to advance the CNID pointer */
		lockflags = hfs_systemfile_lock (hfsmp, SFL_CATALOG , HFS_EXCLUSIVE_LOCK);

		hfs_lock_mount(hfsmp);

		/* If it is less than the current next CNID, force the wraparound bit to be set */
		if (fileid < hfsmp->vcbNxtCNID) {
			wraparound=1;
		}

		/* Return previous value. */
		*(u_int32_t *)ap->a_data = hfsmp->vcbNxtCNID;

		hfsmp->vcbNxtCNID = fileid;

		if (wraparound) {
			hfsmp->vcbAtrb |= kHFSCatalogNodeIDsReusedMask;
		}
		
		MarkVCBDirty(hfsmp);
		hfs_unlock_mount(hfsmp);
		hfs_systemfile_unlock (hfsmp, lockflags);

		return (error);
	}
	
	case F_FREEZE_FS: {
		struct mount *mp;
 
		mp = vnode_mount(vp);
		hfsmp = VFSTOHFS(mp);

		if (!(hfsmp->jnl))
			return (ENOTSUP);

		vfsp = vfs_statfs(mp);
	
		if (kauth_cred_getuid(cred) != vfsp->f_owner &&
			!kauth_cred_issuser(cred))
			return (EACCES);

		return hfs_freeze(hfsmp);
	}

	case F_THAW_FS: {
		vfsp = vfs_statfs(vnode_mount(vp));
		if (kauth_cred_getuid(cred) != vfsp->f_owner &&
			!kauth_cred_issuser(cred))
			return (EACCES);

		return hfs_thaw(hfsmp, current_proc());
	}

	case HFS_EXT_BULKACCESS_FSCTL: {
	    int size;
	    
	    if (hfsmp->hfs_flags & HFS_STANDARD) {
		return EINVAL;
	    }

	    if (is64bit) {
		size = sizeof(struct user64_ext_access_t);
	    } else {
		size = sizeof(struct user32_ext_access_t);
	    }
	    
	    return do_bulk_access_check(hfsmp, vp, ap, size, context);
	} 

	case HFS_SET_XATTREXTENTS_STATE: {
		int state;

		if (ap->a_data == NULL) {
			return (EINVAL);
		}

		state = *(int *)ap->a_data;
		
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}

		/* Super-user can enable or disable extent-based extended 
		 * attribute support on a volume 
		 * Note: Starting Mac OS X 10.7, extent-based extended attributes
		 * are enabled by default, so any change will be transient only 
		 * till the volume is remounted.
		 */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return (EPERM);
		}
		if (state == 0 || state == 1)
			return hfs_set_volxattr(hfsmp, HFS_SET_XATTREXTENTS_STATE, state);
		else
			return (EINVAL);	
	}

	case F_SETSTATICCONTENT: {
		int error;
		int enable_static = 0;
		struct cnode *cp = NULL;
		/* 
		 * lock the cnode, decorate the cnode flag, and bail out.
		 * VFS should have already authenticated the caller for us.
		 */

		if (ap->a_data) {
			/* 
			 * Note that even though ap->a_data is of type caddr_t,
			 * the fcntl layer at the syscall handler will pass in NULL
			 * or 1 depending on what the argument supplied to the fcntl
			 * was.  So it is in fact correct to check the ap->a_data 
			 * argument for zero or non-zero value when deciding whether or not
			 * to enable the static bit in the cnode.
			 */
			enable_static = 1;
		}
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return EROFS;
		}
		cp = VTOC(vp);

		error = hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			if (enable_static) {
				cp->c_flag |= C_SSD_STATIC;
			}
			else {
				cp->c_flag &= ~C_SSD_STATIC;
			}
			hfs_unlock (cp);
		}
		return error;
	}

	case F_SET_GREEDY_MODE: {
		int error;
		int enable_greedy_mode = 0;
		struct cnode *cp = NULL;
		/* 
		 * lock the cnode, decorate the cnode flag, and bail out.
		 * VFS should have already authenticated the caller for us.
		 */

		if (ap->a_data) {
			/* 
			 * Note that even though ap->a_data is of type caddr_t,
			 * the fcntl layer at the syscall handler will pass in NULL
			 * or 1 depending on what the argument supplied to the fcntl
			 * was.  So it is in fact correct to check the ap->a_data 
			 * argument for zero or non-zero value when deciding whether or not
			 * to enable the greedy mode bit in the cnode.
			 */
			enable_greedy_mode = 1;
		}
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return EROFS;
		}
		cp = VTOC(vp);

		error = hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			if (enable_greedy_mode) {
				cp->c_flag |= C_SSD_GREEDY_MODE;
			}
			else {
				cp->c_flag &= ~C_SSD_GREEDY_MODE;
			}
			hfs_unlock (cp);
		}
		return error;
	}

	case F_SETIOTYPE: {
		int error;
		uint32_t iotypeflag = 0;
		
		struct cnode *cp = NULL;
		/* 
		 * lock the cnode, decorate the cnode flag, and bail out.
		 * VFS should have already authenticated the caller for us.
		 */

		if (ap->a_data == NULL) {
			return EINVAL;
		}

		/* 
		 * Note that even though ap->a_data is of type caddr_t, we
		 * can only use 32 bits of flag values.
		 */
		iotypeflag = (uint32_t) ap->a_data;
		switch (iotypeflag) {
			case F_IOTYPE_ISOCHRONOUS:
				break;
			default:
				return EINVAL;
		}


		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return EROFS;
		}
		cp = VTOC(vp);

		error = hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			switch (iotypeflag) {
				case F_IOTYPE_ISOCHRONOUS:
					cp->c_flag |= C_IO_ISOCHRONOUS;
					break;
				default:
					break;
			}
			hfs_unlock (cp);
		}
		return error;
	}

	case F_MAKECOMPRESSED: {
		int error = 0;
		uint32_t gen_counter;
		struct cnode *cp = NULL;
		int reset_decmp = 0;

		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return EROFS;
		}

		/* 
		 * acquire & lock the cnode.
		 * VFS should have already authenticated the caller for us.
		 */

		if (ap->a_data) {
			/* 
			 * Cast the pointer into a uint32_t so we can extract the 
			 * supplied generation counter.
			 */
			gen_counter = *((uint32_t*)ap->a_data);
		}
		else {
			return EINVAL;
		}

#if HFS_COMPRESSION
		cp = VTOC(vp);
		/* Grab truncate lock first; we may truncate the file */
		hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);

		error = hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error) {
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
			return error;
		}

		/* Are there any other usecounts/FDs? */
		if (vnode_isinuse(vp, 1)) {
			hfs_unlock(cp);
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
			return EBUSY;
		}

		/* now we have the cnode locked down; Validate arguments */
		if (cp->c_attr.ca_flags & (UF_IMMUTABLE | UF_COMPRESSED)) {
			/* EINVAL if you are trying to manipulate an IMMUTABLE file */
			hfs_unlock(cp);
			hfs_unlock_truncate (cp, HFS_LOCK_DEFAULT);
			return EINVAL;
		}

		if ((hfs_get_gencount (cp)) == gen_counter) {
			/* 
			 * OK, the gen_counter matched.  Go for it:
			 * Toggle state bits, truncate file, and suppress mtime update 
			 */
			reset_decmp = 1;
			cp->c_bsdflags |= UF_COMPRESSED;				

			error = hfs_truncate(vp, 0, IO_NDELAY, HFS_TRUNCATE_SKIPTIMES,
								 ap->a_context);
		}
		else {
			error = ESTALE;
		}

		/* Unlock cnode before executing decmpfs ; they may need to get an EA */
		hfs_unlock(cp);

		/*
		 * Reset the decmp state while still holding the truncate lock. We need to 
		 * serialize here against a listxattr on this node which may occur at any 
		 * time. 
		 * 
		 * Even if '0/skiplock' is passed in 2nd argument to hfs_file_is_compressed,
		 * that will still potentially require getting the com.apple.decmpfs EA. If the 
	 	 * EA is required, then we can't hold the cnode lock, because the getxattr call is
		 * generic(through VFS), and can't pass along any info telling it that we're already
		 * holding it (the lock). If we don't serialize, then we risk listxattr stopping
		 * and trying to fill in the hfs_file_is_compressed info during the callback
		 * operation, which will result in deadlock against the b-tree node.
		 * 
		 * So, to serialize against listxattr (which will grab buf_t meta references on
		 * the b-tree blocks), we hold the truncate lock as we're manipulating the 
		 * decmpfs payload. 
		 */
		if ((reset_decmp) && (error == 0)) {
			decmpfs_cnode *dp = VTOCMP (vp);
			if (dp != NULL) {
				decmpfs_cnode_set_vnode_state(dp, FILE_TYPE_UNKNOWN, 0);
			}

			/* Initialize the decmpfs node as needed */
			(void) hfs_file_is_compressed (cp, 0); /* ok to take lock */
		}

		hfs_unlock_truncate (cp, HFS_LOCK_DEFAULT);

#endif
		return error;
	}

	case F_SETBACKINGSTORE: {

		int error = 0;

		/* 
		 * See comment in F_SETSTATICCONTENT re: using
	     * a null check for a_data
  		 */
		if (ap->a_data) {
			error = hfs_set_backingstore (vp, 1);
		}
		else {
			error = hfs_set_backingstore (vp, 0);
		}		

		return error;
	}

	case F_GETPATH_MTMINFO: {
		int error = 0;

		int *data = (int*) ap->a_data;	

		/* Ask if this is a backingstore vnode */
		error = hfs_is_backingstore (vp, data);

		return error;
	}

	case F_FULLFSYNC: {
		int error;
		
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			error = hfs_fsync(vp, MNT_WAIT, HFS_FSYNC_FULL, p);
			hfs_unlock(VTOC(vp));
		}

		return error;
	}

	case F_BARRIERFSYNC: {
		int error;

		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			error = hfs_fsync(vp, MNT_WAIT, HFS_FSYNC_BARRIER, p);
			hfs_unlock(VTOC(vp));
		}

		return error;
	}

	case F_CHKCLEAN: {
		register struct cnode *cp;
		int error;

		if (!vnode_isreg(vp))
			return EINVAL;
 
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error == 0) {
			cp = VTOC(vp);
			/*
			 * used by regression test to determine if 
			 * all the dirty pages (via write) have been cleaned
			 * after a call to 'fsysnc'.
			 */
			error = is_file_clean(vp, VTOF(vp)->ff_size);
			hfs_unlock(cp);
		}
		return (error);
	}

	case F_RDADVISE: {
		register struct radvisory *ra;
		struct filefork *fp;
		int error;

		if (!vnode_isreg(vp))
			return EINVAL;
 
		ra = (struct radvisory *)(ap->a_data);
		fp = VTOF(vp);

		/* Protect against a size change. */
		hfs_lock_truncate(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);

#if HFS_COMPRESSION
		if (compressed && (uncompressed_size == -1)) {
			/* fetching the uncompressed size failed above, so return the error */
			error = decmpfs_error;
		} else if ((compressed && (ra->ra_offset >= uncompressed_size)) ||
				   (!compressed && (ra->ra_offset >= fp->ff_size))) {
			error = EFBIG;
		}
#else /* HFS_COMPRESSION */
		if (ra->ra_offset >= fp->ff_size) {
			error = EFBIG;
		}
#endif /* HFS_COMPRESSION */
		else {
			error = advisory_read(vp, fp->ff_size, ra->ra_offset, ra->ra_count);
		}

		hfs_unlock_truncate(VTOC(vp), HFS_LOCK_DEFAULT);
		return (error);
	}

	case _IOC(IOC_OUT,'h', 4, 0):     /* Create date in local time */
	{
		if (is64bit) {
			*(user_time_t *)(ap->a_data) = (user_time_t) (to_bsd_time(VTOVCB(vp)->localCreateDate));
		}
		else {
			*(user32_time_t *)(ap->a_data) = (user32_time_t) (to_bsd_time(VTOVCB(vp)->localCreateDate));
		}
		return 0;
	}

	case SPOTLIGHT_FSCTL_GET_MOUNT_TIME:
	    *(uint32_t *)ap->a_data = hfsmp->hfs_mount_time;
	    break;

	case SPOTLIGHT_FSCTL_GET_LAST_MTIME:
	    *(uint32_t *)ap->a_data = hfsmp->hfs_last_mounted_mtime;
	    break;

	case HFS_FSCTL_GET_VERY_LOW_DISK:
	    *(uint32_t*)ap->a_data = hfsmp->hfs_freespace_notify_dangerlimit;
	    break;

	case HFS_FSCTL_SET_VERY_LOW_DISK:
	    if (*(uint32_t *)ap->a_data >= hfsmp->hfs_freespace_notify_warninglimit) {
		return EINVAL;
	    }

	    hfsmp->hfs_freespace_notify_dangerlimit = *(uint32_t *)ap->a_data;
	    break;

	case HFS_FSCTL_GET_LOW_DISK:
	    *(uint32_t*)ap->a_data = hfsmp->hfs_freespace_notify_warninglimit;
	    break;

	case HFS_FSCTL_SET_LOW_DISK:
	    if (   *(uint32_t *)ap->a_data >= hfsmp->hfs_freespace_notify_desiredlevel
		|| *(uint32_t *)ap->a_data <= hfsmp->hfs_freespace_notify_dangerlimit) {

		return EINVAL;
	    }

	    hfsmp->hfs_freespace_notify_warninglimit = *(uint32_t *)ap->a_data;
	    break;

	case HFS_FSCTL_GET_DESIRED_DISK:
	    *(uint32_t*)ap->a_data = hfsmp->hfs_freespace_notify_desiredlevel;
	    break;

	case HFS_FSCTL_SET_DESIRED_DISK:
	    if (*(uint32_t *)ap->a_data <= hfsmp->hfs_freespace_notify_warninglimit) {
		return EINVAL;
	    }

	    hfsmp->hfs_freespace_notify_desiredlevel = *(uint32_t *)ap->a_data;
	    break;

	case HFS_VOLUME_STATUS:
	    *(uint32_t *)ap->a_data = hfsmp->hfs_notification_conditions;
	    break;

	case HFS_SET_BOOT_INFO:
		if (!vnode_isvroot(vp))
			return(EINVAL);
		if (!kauth_cred_issuser(cred) && (kauth_cred_getuid(cred) != vfs_statfs(HFSTOVFS(hfsmp))->f_owner))
			return(EACCES);	/* must be superuser or owner of filesystem */
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		hfs_lock_mount (hfsmp);
		bcopy(ap->a_data, &hfsmp->vcbFndrInfo, sizeof(hfsmp->vcbFndrInfo));
		hfs_unlock_mount (hfsmp);
		(void) hfs_flushvolumeheader(hfsmp, HFS_FVH_WAIT);
		break;
		
	case HFS_GET_BOOT_INFO:
		if (!vnode_isvroot(vp))
			return(EINVAL);
		hfs_lock_mount (hfsmp);
		bcopy(&hfsmp->vcbFndrInfo, ap->a_data, sizeof(hfsmp->vcbFndrInfo));
		hfs_unlock_mount(hfsmp);
		break;

	case HFS_MARK_BOOT_CORRUPT:
		/* Mark the boot volume corrupt by setting 
		 * kHFSVolumeInconsistentBit in the volume header.  This will 
		 * force fsck_hfs on next mount.
		 */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EACCES;
		}
			
		/* Allowed only on the root vnode of the boot volume */
		if (!(vfs_flags(HFSTOVFS(hfsmp)) & MNT_ROOTFS) || 
		    !vnode_isvroot(vp)) {
			return EINVAL;
		}
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}
		printf ("hfs_vnop_ioctl: Marking the boot volume corrupt.\n");
		hfs_mark_inconsistent(hfsmp, HFS_FSCK_FORCED);
		break;

	case HFS_FSCTL_GET_JOURNAL_INFO:
		jip = (struct hfs_journal_info*)ap->a_data;

		if (vp == NULLVP)
		        return EINVAL;

	    if (hfsmp->jnl == NULL) {
			jnl_start = 0;
			jnl_size  = 0;
	    } else {
			jnl_start = hfs_blk_to_bytes(hfsmp->jnl_start, hfsmp->blockSize) + hfsmp->hfsPlusIOPosOffset;
			jnl_size  = hfsmp->jnl_size;
	    }

		jip->jstart = jnl_start;
		jip->jsize = jnl_size;
		break;

	case HFS_SET_ALWAYS_ZEROFILL: {
	    struct cnode *cp = VTOC(vp);

	    if (*(int *)ap->a_data) {
		cp->c_flag |= C_ALWAYS_ZEROFILL;
	    } else {
		cp->c_flag &= ~C_ALWAYS_ZEROFILL;
	    }
	    break;
	}    

	case HFS_DISABLE_METAZONE: {
		/* Only root can disable metadata zone */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EACCES;
		}
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return (EROFS);
		}

		/* Disable metadata zone now */
		(void) hfs_metadatazone_init(hfsmp, true);
		printf ("hfs: Disabling metadata zone on %s\n", hfsmp->vcbVN);
		break;
	}


	case HFS_FSINFO_METADATA_BLOCKS: {
		int error;
		struct hfsinfo_metadata *hinfo;

		hinfo = (struct hfsinfo_metadata *)ap->a_data;

		/* Get information about number of metadata blocks */
		error = hfs_getinfo_metadata_blocks(hfsmp, hinfo);
		if (error) {
			return error;
		}

		break;
	}

	case HFS_GET_FSINFO: {
		hfs_fsinfo *fsinfo = (hfs_fsinfo *)ap->a_data;

		/* Only root is allowed to get fsinfo */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EACCES;
		}

		/*
		 * Make sure that the caller's version number matches with
		 * the kernel's version number.  This will make sure that
		 * if the structures being read/written into are changed
		 * by the kernel, the caller will not read incorrect data.
		 *
		 * The first three fields --- request_type, version and
		 * flags are same for all the hfs_fsinfo structures, so
		 * we can access the version number by assuming any
		 * structure for now.
		 */
		if (fsinfo->header.version != HFS_FSINFO_VERSION) {
			return ENOTSUP;
		}

		/* Make sure that the current file system is not marked inconsistent */
		if (hfsmp->vcbAtrb & kHFSVolumeInconsistentMask) {
			return EIO;
		}

		return hfs_get_fsinfo(hfsmp, ap->a_data);
	}

	case HFS_CS_FREESPACE_TRIM: {
		int error = 0;
		int lockflags = 0;

		/* Only root allowed */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EACCES;
		}

		/* 
		 * This core functionality is similar to hfs_scan_blocks().  
		 * The main difference is that hfs_scan_blocks() is called 
		 * as part of mount where we are assured that the journal is 
		 * empty to start with.  This fcntl() can be called on a 
		 * mounted volume, therefore it has to flush the content of 
		 * the journal as well as ensure the state of summary table. 
		 * 
		 * This fcntl scans over the entire allocation bitmap,
		 * creates list of all the free blocks, and issues TRIM 
		 * down to the underlying device.  This can take long time 
		 * as it can generate up to 512MB of read I/O.
		 */

		if ((hfsmp->hfs_flags & HFS_SUMMARY_TABLE) == 0) {
			error = hfs_init_summary(hfsmp);
			if (error) {
				printf("hfs: fsctl() could not initialize summary table for %s\n", hfsmp->vcbVN);
				return error;
			}
		}

		/* 
		 * The journal maintains list of recently deallocated blocks to 
		 * issue DKIOCUNMAPs when the corresponding journal transaction is 
		 * flushed to the disk.  To avoid any race conditions, we only 
		 * want one active trim list and only one thread issuing DKIOCUNMAPs.
		 * Therefore we make sure that the journal trim list is sync'ed, 
		 * empty, and not modifiable for the duration of our scan.
		 * 
		 * Take the journal lock before flushing the journal to the disk. 
		 * We will keep on holding the journal lock till we don't get the 
		 * bitmap lock to make sure that no new journal transactions can 
		 * start.  This will make sure that the journal trim list is not 
		 * modified after the journal flush and before getting bitmap lock.
		 * We can release the journal lock after we acquire the bitmap 
		 * lock as it will prevent any further block deallocations.
		 */
		hfs_journal_lock(hfsmp);

		/* Flush the journal and wait for all I/Os to finish up */
		error = hfs_flush(hfsmp, HFS_FLUSH_JOURNAL_META);
		if (error) {
			hfs_journal_unlock(hfsmp);
			return error;
		}

		/* Take bitmap lock to ensure it is not being modified */
		lockflags = hfs_systemfile_lock(hfsmp, SFL_BITMAP, HFS_EXCLUSIVE_LOCK);

		/* Release the journal lock */
		hfs_journal_unlock(hfsmp);

		/* 
		 * ScanUnmapBlocks reads the bitmap in large block size 
		 * (up to 1MB) unlike the runtime which reads the bitmap 
		 * in the 4K block size.  This can cause buf_t collisions 
		 * and potential data corruption.  To avoid this, we 
		 * invalidate all the existing buffers associated with 
		 * the bitmap vnode before scanning it.
		 *
		 * Note: ScanUnmapBlock() cleans up all the buffers 
		 * after itself, so there won't be any large buffers left 
		 * for us to clean up after it returns.
		 */
		error = buf_invalidateblks(hfsmp->hfs_allocation_vp, 0, 0, 0);
		if (error) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			return error;
		}

		/* Traverse bitmap and issue DKIOCUNMAPs */
		error = ScanUnmapBlocks(hfsmp);
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error) {
			return error;
		}

		break;
	}

	case HFS_SET_HOTFILE_STATE: {
		int error;
		struct cnode *cp = VTOC(vp);
		uint32_t hf_state = *((uint32_t*)ap->a_data);
		uint32_t num_unpinned = 0;
		
		error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error) {
			return error;
		}

		// printf("hfs: setting hotfile state %d on %s\n", hf_state, vp->v_name);
		if (hf_state == HFS_MARK_FASTDEVCANDIDATE) {
			vnode_setfastdevicecandidate(vp);

			cp->c_attr.ca_recflags |= kHFSFastDevCandidateMask;
			cp->c_attr.ca_recflags &= ~kHFSDoNotFastDevPinMask;
			cp->c_flag |= C_MODIFIED;
		} else if (hf_state == HFS_UNMARK_FASTDEVCANDIDATE || hf_state == HFS_NEVER_FASTDEVCANDIDATE) {
			vnode_clearfastdevicecandidate(vp);
			hfs_removehotfile(vp);

			if (cp->c_attr.ca_recflags & kHFSFastDevPinnedMask) {
				hfs_pin_vnode(hfsmp, vp, HFS_UNPIN_IT, &num_unpinned, ap->a_context);
			}
				
			if (hf_state == HFS_NEVER_FASTDEVCANDIDATE) {
				cp->c_attr.ca_recflags |= kHFSDoNotFastDevPinMask;
			}
			cp->c_attr.ca_recflags &= ~(kHFSFastDevCandidateMask|kHFSFastDevPinnedMask);
			cp->c_flag |= C_MODIFIED;

		} else {
			error = EINVAL;
		}

		if (num_unpinned != 0) {
			lck_mtx_lock(&hfsmp->hfc_mutex);
			hfsmp->hfs_hotfile_freeblks += num_unpinned;
			lck_mtx_unlock(&hfsmp->hfc_mutex);
		}

		hfs_unlock(cp);
		return error;
		break;
	}

	case HFS_REPIN_HOTFILE_STATE: {
		int error=0;
		uint32_t repin_what = *((uint32_t*)ap->a_data);

		/* Only root allowed */
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EACCES;
		}

		if (!(hfsmp->hfs_flags & (HFS_CS_METADATA_PIN | HFS_CS_HOTFILE_PIN))) {
			// this system is neither regular Fusion or Cooperative Fusion
			// so this fsctl makes no sense.
			return EINVAL;
		}

		//
		// After a converting a CoreStorage volume to be encrypted, the
		// extents could have moved around underneath us.  This call
		// allows corestoraged to re-pin everything that should be
		// pinned (it would happen on the next reboot too but that could
		// be a long time away).
		//
		if ((repin_what & HFS_REPIN_METADATA) && (hfsmp->hfs_flags & HFS_CS_METADATA_PIN)) {
			hfs_pin_fs_metadata(hfsmp);
		}
		if ((repin_what & HFS_REPIN_USERDATA) && (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN)) {
			hfs_repin_hotfiles(hfsmp);
		}
		if ((repin_what & HFS_REPIN_USERDATA) && (hfsmp->hfs_flags & HFS_CS_SWAPFILE_PIN)) {
			//XXX Swapfiles (marked SWAP_PINNED) may have moved too.
			//XXX Do we care? They have a more transient/dynamic nature/lifetime.
		}

		return error;
		break;
	}		


	default:
		return (ENOTTY);
	}

	return 0;
}

/*
 * select
 */
int
hfs_vnop_select(__unused struct vnop_select_args *ap)
/*
	struct vnop_select_args {
		vnode_t a_vp;
		int  a_which;
		int  a_fflags;
		void *a_wql;
		vfs_context_t a_context;
	};
*/
{
	/*
	 * We should really check to see if I/O is possible.
	 */
	return (1);
}

/*
 * Converts a logical block number to a physical block, and optionally returns
 * the amount of remaining blocks in a run. The logical block is based on hfsNode.logBlockSize.
 * The physical block number is based on the device block size, currently its 512.
 * The block run is returned in logical blocks, and is the REMAINING amount of blocks
 */
int
hfs_bmap(struct vnode *vp, daddr_t bn, struct vnode **vpp, daddr64_t *bnp, unsigned int *runp)
{
	struct filefork *fp = VTOF(vp);
	struct hfsmount *hfsmp = VTOHFS(vp);
	int  retval = E_NONE;
	u_int32_t  logBlockSize;
	size_t  bytesContAvail = 0;
	off_t  blockposition;
	int lockExtBtree;
	int lockflags = 0;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (vpp != NULL)
		*vpp = hfsmp->hfs_devvp;
	if (bnp == NULL)
		return (0);

	logBlockSize = GetLogicalBlockSize(vp);
	blockposition = (off_t)bn * logBlockSize;

	lockExtBtree = overflow_extents(fp);

	if (lockExtBtree)
		lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

	retval = MacToVFSError(
                            MapFileBlockC (HFSTOVCB(hfsmp),
                                            (FCB*)fp,
                                            MAXPHYSIO,
                                            blockposition,
                                            bnp,
                                            &bytesContAvail));

	if (lockExtBtree)
		hfs_systemfile_unlock(hfsmp, lockflags);

	if (retval == E_NONE) {
		/* Figure out how many read ahead blocks there are */
		if (runp != NULL) {
			if (can_cluster(logBlockSize)) {
				/* Make sure this result never goes negative: */
				*runp = (bytesContAvail < logBlockSize) ? 0 : (bytesContAvail / logBlockSize) - 1;
			} else {
				*runp = 0;
			}
		}
	}
	return (retval);
}

/*
 * Convert logical block number to file offset.
 */
int
hfs_vnop_blktooff(struct vnop_blktooff_args *ap)
/*
	struct vnop_blktooff_args {
		vnode_t a_vp;
		daddr64_t a_lblkno;  
		off_t *a_offset;
	};
*/
{	
	if (ap->a_vp == NULL)
		return (EINVAL);
	*ap->a_offset = (off_t)ap->a_lblkno * (off_t)GetLogicalBlockSize(ap->a_vp);

	return(0);
}

/*
 * Convert file offset to logical block number.
 */
int
hfs_vnop_offtoblk(struct vnop_offtoblk_args *ap)
/*
	struct vnop_offtoblk_args {
		vnode_t a_vp;
		off_t a_offset;    
		daddr64_t *a_lblkno;
	};
*/
{	
	if (ap->a_vp == NULL)
		return (EINVAL);
	*ap->a_lblkno = (daddr64_t)(ap->a_offset / (off_t)GetLogicalBlockSize(ap->a_vp));

	return(0);
}

/*
 * Map file offset to physical block number.
 *
 * If this function is called for write operation, and if the file
 * had virtual blocks allocated (delayed allocation), real blocks
 * are allocated by calling ExtendFileC().
 * 
 * If this function is called for read operation, and if the file
 * had virtual blocks allocated (delayed allocation), no change 
 * to the size of file is done, and if required, rangelist is 
 * searched for mapping.
 *
 * System file cnodes are expected to be locked (shared or exclusive).
 *
 * -- INVALID RANGES --
 *
 * Invalid ranges are used to keep track of where we have extended a
 * file, but have not yet written that data to disk.  In the past we
 * would clear up the invalid ranges as we wrote to those areas, but
 * before data was actually flushed to disk.  The problem with that
 * approach is that the data can be left in the cache and is therefore
 * still not valid on disk.  So now we clear up the ranges here, when
 * the flags field has VNODE_WRITE set, indicating a write is about to
 * occur.  This isn't ideal (ideally we want to clear them up when
 * know the data has been successfully written), but it's the best we
 * can do.
 *
 * For reads, we use the invalid ranges here in block map to indicate
 * to the caller that the data should be zeroed (a_bpn == -1).  We
 * have to be careful about what ranges we return to the cluster code.
 * Currently the cluster code can only handle non-rounded values for
 * the EOF; it cannot handle funny sized ranges in the middle of the
 * file (the main problem is that it sends down odd sized I/Os to the
 * disk).  Our code currently works because whilst the very first
 * offset and the last offset in the invalid ranges are not aligned,
 * gaps in the invalid ranges between the first and last, have to be
 * aligned (because we always write page sized blocks).  For example,
 * consider this arrangement:
 *
 *         +-------------+-----+-------+------+
 *         |             |XXXXX|       |XXXXXX|
 *         +-------------+-----+-------+------+
 *                       a     b       c      d
 *
 * This shows two invalid ranges <a, b> and <c, d>.  Whilst a and d
 * are not necessarily aligned, b and c *must* be.
 *
 * Zero-filling occurs in a number of ways:
 *
 *   1. When a read occurs and we return with a_bpn == -1.
 *
 *   2. When hfs_fsync or hfs_filedone calls hfs_flush_invalid_ranges
 *      which will cause us to iterate over the ranges bringing in
 *      pages that are not present in the cache and zeroing them.  Any
 *      pages that are already in the cache are left untouched.  Note
 *      that hfs_fsync does not always flush invalid ranges.
 *
 *   3. When we extend a file we zero out from the old EOF to the end
 *      of the page.  It would be nice if we didn't have to do this if
 *      the page wasn't present (and could defer it), but because of
 *      the problem described above, we have to.
 *
 * The invalid ranges are also used to restrict the size that we write
 * out on disk: see hfs_prepare_fork_for_update.
 *
 * Note that invalid ranges are ignored when neither the VNODE_READ or
 * the VNODE_WRITE flag is specified.  This is useful for the
 * F_LOG2PHYS* fcntls which are not interested in invalid ranges: they
 * just want to know whether blocks are physically allocated or not.
 */
int
hfs_vnop_blockmap(struct vnop_blockmap_args *ap)
/*
	struct vnop_blockmap_args {
		vnode_t a_vp;
		off_t a_foffset;    
		size_t a_size;
		daddr64_t *a_bpn;
		size_t *a_run;
		void *a_poff;
		int a_flags;
		vfs_context_t a_context;
	};
*/
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	struct hfsmount *hfsmp;
	size_t bytesContAvail = ap->a_size;
	int retval = E_NONE;
	int syslocks = 0;
	int lockflags = 0;
	struct rl_entry *invalid_range;
	enum rl_overlaptype overlaptype;
	int started_tr = 0;
	int tooklock = 0;

#if HFS_COMPRESSION
	if (VNODE_IS_RSRC(vp)) {
		/* allow blockmaps to the resource fork */
	} else {
		if ( hfs_file_is_compressed(VTOC(vp), 1) ) { /* 1 == don't take the cnode lock */
			int state = decmpfs_cnode_get_vnode_state(VTOCMP(vp));
			switch(state) {
				case FILE_IS_COMPRESSED:
					return ENOTSUP;
				case FILE_IS_CONVERTING:
					/* if FILE_IS_CONVERTING, we allow blockmap */
					break;
				default:
					printf("invalid state %d for compressed file\n", state);
					/* fall through */
			}
		}
	}
#endif /* HFS_COMPRESSION */

	/* Do not allow blockmap operation on a directory */
	if (vnode_isdir(vp)) {
		return (ENOTSUP);
	}

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_bpn == NULL)
		return (0);

	hfsmp = VTOHFS(vp);
	cp = VTOC(vp);
	fp = VTOF(vp);

	if ( !vnode_issystem(vp) && !vnode_islnk(vp) && !vnode_isswap(vp)) {
		if (cp->c_lockowner != current_thread()) {
			hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
			tooklock = 1;
		}

		// For reads, check the invalid ranges
		if (ISSET(ap->a_flags, VNODE_READ)) {
			if (ap->a_foffset >= fp->ff_size) {
				retval = ERANGE;
				goto exit;
			}

			overlaptype = rl_scan(&fp->ff_invalidranges, ap->a_foffset,
								  ap->a_foffset + (off_t)bytesContAvail - 1,
								  &invalid_range);
			switch(overlaptype) {
				case RL_MATCHINGOVERLAP:
				case RL_OVERLAPCONTAINSRANGE:
				case RL_OVERLAPSTARTSBEFORE:
					/* There's no valid block for this byte offset */
					*ap->a_bpn = (daddr64_t)-1;
					/* There's no point limiting the amount to be returned
					 * if the invalid range that was hit extends all the way
					 * to the EOF (i.e. there's no valid bytes between the
					 * end of this range and the file's EOF):
					 */
					if (((off_t)fp->ff_size > (invalid_range->rl_end + 1)) &&
						((size_t)(invalid_range->rl_end + 1 - ap->a_foffset) < bytesContAvail)) {
						bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
					}

					retval = 0;
					goto exit;

				case RL_OVERLAPISCONTAINED:
				case RL_OVERLAPENDSAFTER:
					/* The range of interest hits an invalid block before the end: */
					if (invalid_range->rl_start == ap->a_foffset) {
						/* There's actually no valid information to be had starting here: */
						*ap->a_bpn = (daddr64_t)-1;
						if (((off_t)fp->ff_size > (invalid_range->rl_end + 1)) &&
							((size_t)(invalid_range->rl_end + 1 - ap->a_foffset) < bytesContAvail)) {
							bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
						}

						retval = 0;
						goto exit;
					} else {
						/*
						 * Sadly, the lower layers don't like us to
						 * return unaligned ranges, so we skip over
						 * any invalid ranges here that are less than
						 * a page: zeroing of those bits is not our
						 * responsibility (it's dealt with elsewhere).
						 */
						do {
							off_t rounded_start = round_page_64(invalid_range->rl_start);
							if ((off_t)bytesContAvail < rounded_start - ap->a_foffset)
								break;
							if (rounded_start < invalid_range->rl_end + 1) {
								bytesContAvail = rounded_start - ap->a_foffset;
								break;
							}
						} while ((invalid_range = TAILQ_NEXT(invalid_range,
															 rl_link)));
					}
					break;

				case RL_NOOVERLAP:
					break;
			} // switch
		}
	}

#if CONFIG_PROTECT
	if (cp->c_cpentry) {
		const int direction = (ISSET(ap->a_flags, VNODE_WRITE)
							   ? VNODE_WRITE : VNODE_READ);

		cp_io_params_t io_params;
		cp_io_params(hfsmp, cp->c_cpentry,
					 off_rsrc_make(ap->a_foffset, VNODE_IS_RSRC(vp)),
					 direction, &io_params);

		if (io_params.max_len < (off_t)bytesContAvail)
			bytesContAvail = io_params.max_len;

		if (io_params.phys_offset != -1) {
			*ap->a_bpn = ((io_params.phys_offset + hfsmp->hfsPlusIOPosOffset)
						  / hfsmp->hfs_logical_block_size);

			retval = 0;
			goto exit;
		}
	}
#endif

retry:

	/* Check virtual blocks only when performing write operation */
	if ((ap->a_flags & VNODE_WRITE) && (fp->ff_unallocblocks != 0)) {
		if (hfs_start_transaction(hfsmp) != 0) {
			retval = EINVAL;
			goto exit;
		} else {
			started_tr = 1;
		}
		syslocks = SFL_EXTENTS | SFL_BITMAP;
		
	} else if (overflow_extents(fp)) {
		syslocks = SFL_EXTENTS;
	}
	
	if (syslocks)
		lockflags = hfs_systemfile_lock(hfsmp, syslocks, HFS_EXCLUSIVE_LOCK);

	/*
	 * Check for any delayed allocations.
	 */
	if ((ap->a_flags & VNODE_WRITE) && (fp->ff_unallocblocks != 0)) {
		int64_t actbytes;
		u_int32_t loanedBlocks;

		// 
		// Make sure we have a transaction.  It's possible
		// that we came in and fp->ff_unallocblocks was zero
		// but during the time we blocked acquiring the extents
		// btree, ff_unallocblocks became non-zero and so we
		// will need to start a transaction.
		//
		if (started_tr == 0) {
			if (syslocks) {
				hfs_systemfile_unlock(hfsmp, lockflags);
				syslocks = 0;
			}
			goto retry;
		}

		/*
		 * Note: ExtendFileC will Release any blocks on loan and
		 * aquire real blocks.  So we ask to extend by zero bytes
		 * since ExtendFileC will account for the virtual blocks.
		 */

		loanedBlocks = fp->ff_unallocblocks;
		retval = ExtendFileC(hfsmp, (FCB*)fp, 0, 0,
				     kEFAllMask | kEFNoClumpMask, &actbytes);

		if (retval) {
			fp->ff_unallocblocks = loanedBlocks;
			cp->c_blocks += loanedBlocks;
			fp->ff_blocks += loanedBlocks;

			hfs_lock_mount (hfsmp);
			hfsmp->loanedBlocks += loanedBlocks;
			hfs_unlock_mount (hfsmp);

			hfs_systemfile_unlock(hfsmp, lockflags);
			cp->c_flag |= C_MODIFIED;
			if (started_tr) {
				(void) hfs_update(vp, 0);
				(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);

				hfs_end_transaction(hfsmp);
				started_tr = 0;
			}
			goto exit;
		}
	}

	retval = MapFileBlockC(hfsmp, (FCB *)fp, bytesContAvail, ap->a_foffset,
	                       ap->a_bpn, &bytesContAvail);
	if (syslocks) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		syslocks = 0;
	}

	if (retval) {
		/* On write, always return error because virtual blocks, if any, 
		 * should have been allocated in ExtendFileC().  We do not 
		 * allocate virtual blocks on read, therefore return error 
		 * only if no virtual blocks are allocated.  Otherwise we search
		 * rangelist for zero-fills
		 */
		if ((MacToVFSError(retval) != ERANGE) ||
		    (ap->a_flags & VNODE_WRITE) ||
		    ((ap->a_flags & VNODE_READ) && (fp->ff_unallocblocks == 0))) {
			goto exit;
		}

		/* Validate if the start offset is within logical file size */
		if (ap->a_foffset >= fp->ff_size) {
			goto exit;
		}

		/*
		 * At this point, we have encountered a failure during
		 * MapFileBlockC that resulted in ERANGE, and we are not
		 * servicing a write, and there are borrowed blocks.
		 *
		 * However, the cluster layer will not call blockmap for
		 * blocks that are borrowed and in-cache.  We have to assume
		 * that because we observed ERANGE being emitted from
		 * MapFileBlockC, this extent range is not valid on-disk.  So
		 * we treat this as a mapping that needs to be zero-filled
		 * prior to reading.
		 */

		if (fp->ff_size - ap->a_foffset < (off_t)bytesContAvail)
			bytesContAvail = fp->ff_size - ap->a_foffset;

		*ap->a_bpn = (daddr64_t) -1;
		retval = 0;

		goto exit;
	}

exit:
	if (retval == 0) {
		if (ISSET(ap->a_flags, VNODE_WRITE)) {
			struct rl_entry *r = TAILQ_FIRST(&fp->ff_invalidranges);

			// See if we might be overlapping invalid ranges...
			if (r && (ap->a_foffset + (off_t)bytesContAvail) > r->rl_start) {
				/*
				 * Mark the file as needing an update if we think the
				 * on-disk EOF has changed.
				 */
				if (ap->a_foffset <= r->rl_start)
					SET(cp->c_flag, C_MODIFIED);

				/*
				 * This isn't the ideal place to put this.  Ideally, we
				 * should do something *after* we have successfully
				 * written to the range, but that's difficult to do
				 * because we cannot take locks in the callback.  At
				 * present, the cluster code will call us with VNODE_WRITE
				 * set just before it's about to write the data so we know
				 * that data is about to be written.  If we get an I/O
				 * error at this point then chances are the metadata
				 * update to follow will also have an I/O error so the
				 * risk here is small.
				 */
				rl_remove(ap->a_foffset, ap->a_foffset + bytesContAvail - 1,
						  &fp->ff_invalidranges);

				if (!TAILQ_FIRST(&fp->ff_invalidranges)) {
					cp->c_flag &= ~C_ZFWANTSYNC;
					cp->c_zftimeout = 0;
				}
			}
		}

		if (ap->a_run)
			*ap->a_run = bytesContAvail;

		if (ap->a_poff)
			*(int *)ap->a_poff = 0;
	}

	if (started_tr) {
		hfs_update(vp, TRUE);
		hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		hfs_end_transaction(hfsmp);
		started_tr = 0;
	}

	if (tooklock)
		hfs_unlock(cp);

	return (MacToVFSError(retval));
}

/*
 * prepare and issue the I/O
 * buf_strategy knows how to deal
 * with requests that require 
 * fragmented I/Os
 */
int
hfs_vnop_strategy(struct vnop_strategy_args *ap)
{
	buf_t	bp = ap->a_bp;
	vnode_t	vp = buf_vnode(bp);
	int error = 0;
	
	/* Mark buffer as containing static data if cnode flag set */
	if (VTOC(vp)->c_flag & C_SSD_STATIC) {
		buf_markstatic(bp);
	}
	
	/* Mark buffer as containing static data if cnode flag set */
	if (VTOC(vp)->c_flag & C_SSD_GREEDY_MODE) {
		bufattr_markgreedymode(&bp->b_attr);
	}

	/* mark buffer as containing burst mode data if cnode flag set */
	if (VTOC(vp)->c_flag & C_IO_ISOCHRONOUS) {
		bufattr_markisochronous(&bp->b_attr);
	}
	
#if CONFIG_PROTECT
	error = cp_handle_strategy(bp);

	if (error)
		return error;
#endif
	
	error = buf_strategy(VTOHFS(vp)->hfs_devvp, ap);
	
	return error;
}

int
do_hfs_truncate(struct vnode *vp, off_t length, int flags, int truncateflags, vfs_context_t context)
{
	register struct cnode *cp = VTOC(vp);
    	struct filefork *fp = VTOF(vp);
	kauth_cred_t cred = vfs_context_ucred(context);
	int retval;
	off_t bytesToAdd;
	off_t actualBytesAdded;
	off_t filebytes;
	u_int32_t fileblocks;
	int blksize;
	struct hfsmount *hfsmp;
	int lockflags;
	int suppress_times = (truncateflags & HFS_TRUNCATE_SKIPTIMES);

	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	KERNEL_DEBUG(HFSDBG_TRUNCATE | DBG_FUNC_START,
		 (int)length, (int)fp->ff_size, (int)filebytes, 0, 0);

	if (length < 0)
		return (EINVAL);

	/* This should only happen with a corrupt filesystem */
	if ((off_t)fp->ff_size < 0)
		return (EINVAL);

	if ((!ISHFSPLUS(VTOVCB(vp))) && (length > (off_t)MAXHFSFILESIZE))
		return (EFBIG);

	hfsmp = VTOHFS(vp);

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
	if ((retval = hfs_getinoquota(cp)))
		return(retval);
#endif /* QUOTA */

	/*
	 * Lengthen the size of the file. We must ensure that the
	 * last byte of the file is allocated. Since the smallest
	 * value of ff_size is 0, length will be at least 1.
	 */
	if (length > (off_t)fp->ff_size) {
#if QUOTA
		retval = hfs_chkdq(cp, (int64_t)(roundup(length - filebytes, blksize)),
				   cred, 0);
		if (retval)
			goto Err_Exit;
#endif /* QUOTA */
		/*
		 * If we don't have enough physical space then
		 * we need to extend the physical size.
		 */
		if (length > filebytes) {
			int eflags;
			u_int32_t blockHint = 0;

			/* All or nothing and don't round up to clumpsize. */
			eflags = kEFAllMask | kEFNoClumpMask;

			if (cred && (suser(cred, NULL) != 0)) {
				eflags |= kEFReserveMask;  /* keep a reserve */
			}

			/*
			 * Allocate Journal and Quota files in metadata zone.
			 */
			if (filebytes == 0 &&
			    hfsmp->hfs_flags & HFS_METADATA_ZONE &&
			    hfs_virtualmetafile(cp)) {
				eflags |= kEFMetadataMask;
				blockHint = hfsmp->hfs_metazone_start;
			}
			if (hfs_start_transaction(hfsmp) != 0) {
			    retval = EINVAL;
			    goto Err_Exit;
			}

			/* Protect extents b-tree and allocation bitmap */
			lockflags = SFL_BITMAP;
			if (overflow_extents(fp))
				lockflags |= SFL_EXTENTS;
			lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

			/* 
			 * Keep growing the file as long as the current EOF is
			 * less than the desired value.
			 */
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

			hfs_systemfile_unlock(hfsmp, lockflags);

			if (hfsmp->jnl) {
				hfs_update(vp, 0);
				hfs_volupdate(hfsmp, VOL_UPDATE, 0);
			}

			hfs_end_transaction(hfsmp);

			if (retval)
				goto Err_Exit;

			KERNEL_DEBUG(HFSDBG_TRUNCATE | DBG_FUNC_NONE,
				(int)length, (int)fp->ff_size, (int)filebytes, 0, 0);
		}
 
		if (ISSET(flags, IO_NOZEROFILL)) {
			// An optimisation for the hibernation file
			if (vnode_isswap(vp))
				rl_remove_all(&fp->ff_invalidranges);
		} else {
			if (UBCINFOEXISTS(vp)  && (vnode_issystem(vp) == 0) && retval == E_NONE) {
				if (length > (off_t)fp->ff_size) {
					struct timeval tv;

		   			/* Extending the file: time to fill out the current last page w. zeroes? */
					if (fp->ff_size & PAGE_MASK_64) {
						/* There might be some valid data at the start of the (current) last page
						   of the file, so zero out the remainder of that page to ensure the
						   entire page contains valid data. */
						hfs_unlock(cp);
						retval = hfs_zero_eof_page(vp, length);
						hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
						if (retval) goto Err_Exit;
					}
					microuptime(&tv);
					rl_add(fp->ff_size, length - 1, &fp->ff_invalidranges);
					cp->c_zftimeout = tv.tv_sec + ZFTIMELIMIT;
				}
			} else {
					panic("hfs_truncate: invoked on non-UBC object?!");
			};
		}
		if (suppress_times == 0) {
			cp->c_touch_modtime = TRUE;
		}
		fp->ff_size = length;

	} else { /* Shorten the size of the file */

		// An optimisation for the hibernation file
		if (ISSET(flags, IO_NOZEROFILL) && vnode_isswap(vp)) {
			rl_remove_all(&fp->ff_invalidranges);
		} else if ((off_t)fp->ff_size > length) {
			/* Any space previously marked as invalid is now irrelevant: */
			rl_remove(length, fp->ff_size - 1, &fp->ff_invalidranges);
		}

		/* 
		 * Account for any unmapped blocks. Note that the new
		 * file length can still end up with unmapped blocks.
		 */
		if (fp->ff_unallocblocks > 0) {
			u_int32_t finalblks;
			u_int32_t loanedBlocks;

			hfs_lock_mount(hfsmp);
			loanedBlocks = fp->ff_unallocblocks;
			cp->c_blocks -= loanedBlocks;
			fp->ff_blocks -= loanedBlocks;
			fp->ff_unallocblocks = 0;

			hfsmp->loanedBlocks -= loanedBlocks;

			finalblks = (length + blksize - 1) / blksize;
			if (finalblks > fp->ff_blocks) {
				/* calculate required unmapped blocks */
				loanedBlocks = finalblks - fp->ff_blocks;
				hfsmp->loanedBlocks += loanedBlocks;

				fp->ff_unallocblocks = loanedBlocks;
				cp->c_blocks += loanedBlocks;
				fp->ff_blocks += loanedBlocks;
			}
			hfs_unlock_mount (hfsmp);
		}

		off_t savedbytes = ((off_t)fp->ff_blocks * (off_t)blksize);
		if (hfs_start_transaction(hfsmp) != 0) {
			retval = EINVAL;
			goto Err_Exit;
		}

		if (fp->ff_unallocblocks == 0) {
			/* Protect extents b-tree and allocation bitmap */
			lockflags = SFL_BITMAP;
			if (overflow_extents(fp))
				lockflags |= SFL_EXTENTS;
			lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

			retval = MacToVFSError(TruncateFileC(VTOVCB(vp), (FCB*)fp, length, 0, 
												 FORK_IS_RSRC (fp), FTOC(fp)->c_fileid, false));

			hfs_systemfile_unlock(hfsmp, lockflags);
		}
		if (hfsmp->jnl) {
			if (retval == 0) {
				fp->ff_size = length;
			}
			hfs_update(vp, 0);
			hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		}
		hfs_end_transaction(hfsmp);

		filebytes = (off_t)fp->ff_blocks * (off_t)blksize;
		if (retval)
			goto Err_Exit;
#if QUOTA
		/* These are bytesreleased */
		(void) hfs_chkdq(cp, (int64_t)-(savedbytes - filebytes), NOCRED, 0);
#endif /* QUOTA */

		//
		// Unlike when growing a file, we adjust the hotfile block count here
		// instead of deeper down in the block allocation code because we do
		// not necessarily have a vnode or "fcb" at the time we're deleting
		// the file and so we wouldn't know if it was hotfile cached or not
		//
		hfs_hotfile_adjust_blocks(vp, (int64_t)((savedbytes - filebytes) / blksize));


		/* 
		 * Only set update flag if the logical length changes & we aren't
		 * suppressing modtime updates.
		 */
		if (((off_t)fp->ff_size != length) && (suppress_times == 0)) {
			cp->c_touch_modtime = TRUE;
		}
		fp->ff_size = length;
	}
	if (cp->c_mode & (S_ISUID | S_ISGID)) {
		if (!vfs_context_issuser(context))
			cp->c_mode &= ~(S_ISUID | S_ISGID);
	}
	cp->c_flag |= C_MODIFIED;
	cp->c_touch_chgtime = TRUE;	/* status changed */
	if (suppress_times == 0) {
		cp->c_touch_modtime = TRUE;	/* file data was modified */

		/*
		 * If we are not suppressing the modtime update, then
		 * update the gen count as well.
		 */
		if (S_ISREG(cp->c_attr.ca_mode) || S_ISLNK (cp->c_attr.ca_mode)) {
			hfs_incr_gencount(cp);
		}
	}

	retval = hfs_update(vp, 0);
	if (retval) {
		KERNEL_DEBUG(HFSDBG_TRUNCATE | DBG_FUNC_NONE,
		     -1, -1, -1, retval, 0);
	}

Err_Exit:

	KERNEL_DEBUG(HFSDBG_TRUNCATE | DBG_FUNC_END,
		 (int)length, (int)fp->ff_size, (int)filebytes, retval, 0);

	return (retval);
}

/*
 * Preparation which must be done prior to deleting the catalog record
 * of a file or directory.  In order to make the on-disk as safe as possible,
 * we remove the catalog entry before releasing the bitmap blocks and the 
 * overflow extent records.  However, some work must be done prior to deleting
 * the catalog record.
 * 
 * When calling this function, the cnode must exist both in memory and on-disk.
 * If there are both resource fork and data fork vnodes, this function should
 * be called on both.  
 */

int
hfs_prepare_release_storage (struct hfsmount *hfsmp, struct vnode *vp) {
	
	struct filefork *fp = VTOF(vp);
	struct cnode *cp = VTOC(vp);
#if QUOTA
	int retval = 0;
#endif /* QUOTA */
	
	/* Cannot truncate an HFS directory! */
	if (vnode_isdir(vp)) {
		return (EISDIR);
	}
	
	/* 
	 * See the comment below in hfs_truncate for why we need to call 
	 * setsize here.  Essentially we want to avoid pending IO if we 
	 * already know that the blocks are going to be released here.
	 * This function is only called when totally removing all storage for a file, so
	 * we can take a shortcut and immediately setsize (0);
	 */
	ubc_setsize(vp, 0);
	
	/* This should only happen with a corrupt filesystem */
	if ((off_t)fp->ff_size < 0)
		return (EINVAL);
	
	/* 
	 * We cannot just check if fp->ff_size == length (as an optimization)
	 * since there may be extra physical blocks that also need truncation.
	 */
#if QUOTA
	if ((retval = hfs_getinoquota(cp))) {
		return(retval);
	}
#endif /* QUOTA */
	
	/* Wipe out any invalid ranges which have yet to be backed by disk */
	rl_remove(0, fp->ff_size - 1, &fp->ff_invalidranges);
	
	/* 
	 * Account for any unmapped blocks. Since we're deleting the 
	 * entire file, we don't have to worry about just shrinking
	 * to a smaller number of borrowed blocks.
	 */
	if (fp->ff_unallocblocks > 0) {
		u_int32_t loanedBlocks;
		
		hfs_lock_mount (hfsmp);
		loanedBlocks = fp->ff_unallocblocks;
		cp->c_blocks -= loanedBlocks;
		fp->ff_blocks -= loanedBlocks;
		fp->ff_unallocblocks = 0;
		
		hfsmp->loanedBlocks -= loanedBlocks;
		
		hfs_unlock_mount (hfsmp);
	}
	
	return 0;
}


/*
 * Special wrapper around calling TruncateFileC.  This function is useable
 * even when the catalog record does not exist any longer, making it ideal
 * for use when deleting a file.  The simplification here is that we know 
 * that we are releasing all blocks.
 *
 * Note that this function may be called when there is no vnode backing
 * the file fork in question.  We may call this from hfs_vnop_inactive
 * to clear out resource fork data (and may not want to clear out the data 
 * fork yet).  As a result, we pointer-check both sets of inputs before 
 * doing anything with them.
 *
 * The caller is responsible for saving off a copy of the filefork(s)
 * embedded within the cnode prior to calling this function.  The pointers
 * supplied as arguments must be valid even if the cnode is no longer valid.
 */

int 
hfs_release_storage (struct hfsmount *hfsmp, struct filefork *datafork, 
					 struct filefork *rsrcfork, u_int32_t fileid) {
	
	off_t filebytes;
	u_int32_t fileblocks;
	int blksize = 0;
	int error = 0;
	int lockflags;
	
	blksize = hfsmp->blockSize;
	
	/* Data Fork */
	if (datafork) {
		off_t prev_filebytes;
		datafork->ff_size = 0;

		fileblocks = datafork->ff_blocks;
		filebytes = (off_t)fileblocks * (off_t)blksize;
		prev_filebytes = filebytes;
		
		/* We killed invalid ranges and loaned blocks before we removed the catalog entry */
		
		while (filebytes > 0) {
			if (filebytes > HFS_BIGFILE_SIZE) {
				filebytes -= HFS_BIGFILE_SIZE;
			} else {
				filebytes = 0;
			}
			
			/* Start a transaction, and wipe out as many blocks as we can in this iteration */
			if (hfs_start_transaction(hfsmp) != 0) {
				error = EINVAL;
				break;
			}
			
			if (datafork->ff_unallocblocks == 0) {
				/* Protect extents b-tree and allocation bitmap */
				lockflags = SFL_BITMAP;
				if (overflow_extents(datafork))
					lockflags |= SFL_EXTENTS;
				lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
				
				error = MacToVFSError(TruncateFileC(HFSTOVCB(hfsmp), datafork, filebytes, 1, 0, fileid, false));
				
				hfs_systemfile_unlock(hfsmp, lockflags);
			}
			(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
			
			struct cnode *cp = datafork ? FTOC(datafork) : NULL;
			struct vnode *vp;
			vp = cp ? CTOV(cp, 0) : NULL;
			hfs_hotfile_adjust_blocks(vp, (int64_t)((prev_filebytes - filebytes) / blksize));
			prev_filebytes = filebytes;
			
			/* Finish the transaction and start over if necessary */
			hfs_end_transaction(hfsmp);
			
			if (error) {
				break;
			}
		}
	}
	
	/* Resource fork */
	if (error == 0 && rsrcfork) {
		rsrcfork->ff_size = 0;

		fileblocks = rsrcfork->ff_blocks;
		filebytes = (off_t)fileblocks * (off_t)blksize;
		
		/* We killed invalid ranges and loaned blocks before we removed the catalog entry */
		
		while (filebytes > 0) {
			if (filebytes > HFS_BIGFILE_SIZE) {
				filebytes -= HFS_BIGFILE_SIZE;
			} else {
				filebytes = 0;
			}
			
			/* Start a transaction, and wipe out as many blocks as we can in this iteration */
			if (hfs_start_transaction(hfsmp) != 0) {
				error = EINVAL;
				break;
			}
			
			if (rsrcfork->ff_unallocblocks == 0) {
				/* Protect extents b-tree and allocation bitmap */
				lockflags = SFL_BITMAP;
				if (overflow_extents(rsrcfork))
					lockflags |= SFL_EXTENTS;
				lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
				
				error = MacToVFSError(TruncateFileC(HFSTOVCB(hfsmp), rsrcfork, filebytes, 1, 1, fileid, false));
				
				hfs_systemfile_unlock(hfsmp, lockflags);
			}
			(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
			
			/* Finish the transaction and start over if necessary */
			hfs_end_transaction(hfsmp);			
			
			if (error) {
				break;
			}
		}
	}
	
	return error;
}

errno_t hfs_ubc_setsize(vnode_t vp, off_t len, bool have_cnode_lock)
{
	errno_t error;

	/*
	 * Call ubc_setsize to give the VM subsystem a chance to do
	 * whatever it needs to with existing pages before we delete
	 * blocks.  Note that symlinks don't use the UBC so we'll
	 * get back ENOENT in that case.
	 */
	if (have_cnode_lock) {
		error = ubc_setsize_ex(vp, len, UBC_SETSIZE_NO_FS_REENTRY);
		if (error == EAGAIN) {
			cnode_t *cp = VTOC(vp);

			if (cp->c_truncatelockowner != current_thread()) {
#if DEVELOPMENT || DEBUG
				panic("hfs: hfs_ubc_setsize called without exclusive truncate lock!");
#else
				printf("hfs: hfs_ubc_setsize called without exclusive truncate lock!\n");
#endif
			}

			hfs_unlock(cp);
			error = ubc_setsize_ex(vp, len, 0);
			hfs_lock_always(cp, HFS_EXCLUSIVE_LOCK);
		}
	} else
		error = ubc_setsize_ex(vp, len, 0);

	return error == ENOENT ? 0 : error;
}

/*
 * Truncate a cnode to at most length size, freeing (or adding) the
 * disk blocks.
 */
int
hfs_truncate(struct vnode *vp, off_t length, int flags,
			 int truncateflags, vfs_context_t context)
{
	struct filefork *fp = VTOF(vp);
	off_t filebytes;
	u_int32_t fileblocks;
	int blksize;
	errno_t error = 0;
	struct cnode *cp = VTOC(vp);
	hfsmount_t *hfsmp = VTOHFS(vp);

	/* Cannot truncate an HFS directory! */
	if (vnode_isdir(vp)) {
		return (EISDIR);
	}
	/* A swap file cannot change size. */
	if (vnode_isswap(vp) && length && !ISSET(flags, IO_NOAUTH)) {
		return (EPERM);
	}

	blksize = hfsmp->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	bool caller_has_cnode_lock = (cp->c_lockowner == current_thread());

	error = hfs_ubc_setsize(vp, length, caller_has_cnode_lock);
	if (error)
		return error;

	if (!caller_has_cnode_lock) {
		error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		if (error)
			return error;
	}

	// have to loop truncating or growing files that are
	// really big because otherwise transactions can get
	// enormous and consume too many kernel resources.

	if (length < filebytes) {
		while (filebytes > length) {
			if ((filebytes - length) > HFS_BIGFILE_SIZE) {
		    		filebytes -= HFS_BIGFILE_SIZE;
			} else {
		    		filebytes = length;
			}
			error = do_hfs_truncate(vp, filebytes, flags, truncateflags, context);
			if (error)
				break;
		}
	} else if (length > filebytes) {
		kauth_cred_t cred = vfs_context_ucred(context);
		const bool keep_reserve = cred && suser(cred, NULL) != 0;

		if (hfs_freeblks(hfsmp, keep_reserve)
			< howmany(length - filebytes, blksize)) {
			error = ENOSPC;
		} else {
			while (filebytes < length) {
				if ((length - filebytes) > HFS_BIGFILE_SIZE) {
					filebytes += HFS_BIGFILE_SIZE;
				} else {
					filebytes = length;
				}
				error = do_hfs_truncate(vp, filebytes, flags, truncateflags, context);
				if (error)
					break;
			}
		}
	} else /* Same logical size */ {

		error = do_hfs_truncate(vp, length, flags, truncateflags, context);
	}
	/* Files that are changing size are not hot file candidates. */
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING) {
		fp->ff_bytesread = 0;
	}


	if (!caller_has_cnode_lock)
		hfs_unlock(cp);

	// Make sure UBC's size matches up (in case we didn't completely succeed)
	errno_t err2 = hfs_ubc_setsize(vp, fp->ff_size, caller_has_cnode_lock);
	if (!error)
		error = err2;

	return error;
}


/*
 * Preallocate file storage space.
 */
int
hfs_vnop_allocate(struct vnop_allocate_args /* {
		vnode_t a_vp;
		off_t a_length;
		u_int32_t  a_flags;
		off_t *a_bytesallocated;
		off_t a_offset;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	ExtendedVCB *vcb;
	off_t length = ap->a_length;
	off_t startingPEOF;
	off_t moreBytesRequested;
	off_t actualBytesAdded;
	off_t filebytes;
	u_int32_t fileblocks;
	int retval, retval2;
	u_int32_t blockHint;
	u_int32_t extendFlags;   /* For call to ExtendFileC */
	struct hfsmount *hfsmp;
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	int lockflags;
	time_t orig_ctime;

	*(ap->a_bytesallocated) = 0;

	if (!vnode_isreg(vp))
		return (EISDIR);
	if (length < (off_t)0)
		return (EINVAL);
	
	cp = VTOC(vp);

	orig_ctime = VTOC(vp)->c_ctime;

	check_for_tracked_file(vp, orig_ctime, ap->a_length == 0 ? NAMESPACE_HANDLER_TRUNCATE_OP|NAMESPACE_HANDLER_DELETE_OP : NAMESPACE_HANDLER_TRUNCATE_OP, NULL);

	hfs_lock_truncate(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);

	if ((retval = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
		goto Err_Exit;
	}
	
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);
	vcb = VTOVCB(vp);

	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)vcb->blockSize;

	if ((ap->a_flags & ALLOCATEFROMVOL) && (length < filebytes)) {
		retval = EINVAL;
		goto Err_Exit;
	}

	/* Fill in the flags word for the call to Extend the file */

	extendFlags = kEFNoClumpMask;
	if (ap->a_flags & ALLOCATECONTIG) 
		extendFlags |= kEFContigMask;
	if (ap->a_flags & ALLOCATEALL)
		extendFlags |= kEFAllMask;
	if (cred && suser(cred, NULL) != 0)
		extendFlags |= kEFReserveMask;
	if (hfs_virtualmetafile(cp))
		extendFlags |= kEFMetadataMask;

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
		if (ISSET(extendFlags, kEFAllMask)
			&& (hfs_freeblks(hfsmp, ISSET(extendFlags, kEFReserveMask))
				< howmany(length - filebytes, hfsmp->blockSize))) {
			retval = ENOSPC;
			goto Err_Exit;
		}

		off_t total_bytes_added = 0, orig_request_size;

		orig_request_size = moreBytesRequested = length - filebytes;
		
#if QUOTA
		retval = hfs_chkdq(cp,
				(int64_t)(roundup(moreBytesRequested, vcb->blockSize)), 
				cred, 0);
		if (retval)
			goto Err_Exit;

#endif /* QUOTA */
		/*
		 * Metadata zone checks.
		 */
		if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
			/*
			 * Allocate Journal and Quota files in metadata zone.
			 */
			if (hfs_virtualmetafile(cp)) {
				blockHint = hfsmp->hfs_metazone_start;
			} else if ((blockHint >= hfsmp->hfs_metazone_start) &&
				   (blockHint <= hfsmp->hfs_metazone_end)) {
				/*
				 * Move blockHint outside metadata zone.
				 */
				blockHint = hfsmp->hfs_metazone_end + 1;
			}
		}


		while ((length > filebytes) && (retval == E_NONE)) {
		    off_t bytesRequested;
		    
		    if (hfs_start_transaction(hfsmp) != 0) {
			retval = EINVAL;
			goto Err_Exit;
		    }

		    /* Protect extents b-tree and allocation bitmap */
		    lockflags = SFL_BITMAP;
		    if (overflow_extents(fp))
				lockflags |= SFL_EXTENTS;
		    lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

		    if (moreBytesRequested >= HFS_BIGFILE_SIZE) {
				bytesRequested = HFS_BIGFILE_SIZE;
		    } else {
				bytesRequested = moreBytesRequested;
		    }

		    if (extendFlags & kEFContigMask) {
			    // if we're on a sparse device, this will force it to do a
			    // full scan to find the space needed.
			    hfsmp->hfs_flags &= ~HFS_DID_CONTIG_SCAN;
		    }

		    retval = MacToVFSError(ExtendFileC(vcb,
						(FCB*)fp,
						bytesRequested,
						blockHint,
						extendFlags,
						&actualBytesAdded));

		    if (retval == E_NONE) {
			*(ap->a_bytesallocated) += actualBytesAdded;
			total_bytes_added += actualBytesAdded;
			moreBytesRequested -= actualBytesAdded;
			if (blockHint != 0) {
			    blockHint += actualBytesAdded / vcb->blockSize;
			}
		    }
		    filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;
		    
		    hfs_systemfile_unlock(hfsmp, lockflags);

		    if (hfsmp->jnl) {
			(void) hfs_update(vp, 0);
			(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		    }

		    hfs_end_transaction(hfsmp);
		}


		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the hfs_update to reflect the changes
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
		if (total_bytes_added != 0 && orig_request_size < total_bytes_added)
			*(ap->a_bytesallocated) =
				roundup(orig_request_size, (off_t)vcb->blockSize);

	} else { /* Shorten the size of the file */

		/*
		 * N.B. At present, this code is never called.  If and when we
		 * do start using it, it looks like there might be slightly
		 * strange semantics with the file size: it's possible for the
		 * file size to *increase* e.g. if current file size is 5,
		 * length is 1024 and filebytes is 4096, the file size will
		 * end up being 1024 bytes.  This isn't necessarily a problem
		 * but it's not consistent with the code above which doesn't
		 * change the file size.
		 */

		retval = hfs_truncate(vp, length, 0, 0, ap->a_context);
		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

		/*
		 * if we get an error and no changes were made then exit
		 * otherwise we must do the hfs_update to reflect the changes
		 */
		if (retval && (startingPEOF == filebytes)) goto Err_Exit;
#if QUOTA
		/* These are  bytesreleased */
		(void) hfs_chkdq(cp, (int64_t)-((startingPEOF - filebytes)), NOCRED,0);
#endif /* QUOTA */

		if (fp->ff_size > filebytes) {
			fp->ff_size = filebytes;

			hfs_ubc_setsize(vp, fp->ff_size, true);
		}
	}

Std_Exit:
	cp->c_flag |= C_MODIFIED;
	cp->c_touch_chgtime = TRUE;
	cp->c_touch_modtime = TRUE;
	retval2 = hfs_update(vp, 0);

	if (retval == 0)
		retval = retval2;
Err_Exit:
	hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	hfs_unlock(cp);
	return (retval);
}


/*
 * Pagein for HFS filesystem
 */
int
hfs_vnop_pagein(struct vnop_pagein_args *ap)
/*
	struct vnop_pagein_args {
	   	vnode_t a_vp,
	   	upl_t 	      a_pl,
		vm_offset_t   a_pl_offset,
		off_t         a_f_offset,
		size_t        a_size,
		int           a_flags
		vfs_context_t a_context;
	};
*/
{
	vnode_t 	vp;
	struct cnode	*cp;
	struct filefork *fp;
	int		error = 0;
	upl_t 		upl;
	upl_page_info_t	*pl;
	off_t		f_offset;
	off_t		page_needed_f_offset;
	int		offset;
	int		isize; 
	int		upl_size; 
	int		pg_index;
	boolean_t	truncate_lock_held = FALSE;
	boolean_t 	file_converted = FALSE;
	kern_return_t	kret;
	
	vp = ap->a_vp;
	cp = VTOC(vp);
	fp = VTOF(vp);

#if CONFIG_PROTECT
	if ((error = cp_handle_vnop(vp, CP_READ_ACCESS | CP_WRITE_ACCESS, 0)) != 0) {
		/* 
		 * If we errored here, then this means that one of two things occurred:
		 * 1. there was a problem with the decryption of the key.
		 * 2. the device is locked and we are not allowed to access this particular file.
		 * 
		 * Either way, this means that we need to shut down this upl now.  As long as 
		 * the pl pointer is NULL (meaning that we're supposed to create the UPL ourselves)
		 * then we create a upl and immediately abort it.
		 */
		if (ap->a_pl == NULL) {
			/* create the upl */
			ubc_create_upl (vp, ap->a_f_offset, ap->a_size, &upl, &pl, 
					UPL_UBC_PAGEIN | UPL_RET_ONLY_ABSENT);
			/* mark the range as needed so it doesn't immediately get discarded upon abort */
			ubc_upl_range_needed (upl, ap->a_pl_offset / PAGE_SIZE, 1);
	
			/* Abort the range */
			ubc_upl_abort_range (upl, 0, ap->a_size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
		}

	
		return error;
	}
#endif /* CONFIG_PROTECT */

	if (ap->a_pl != NULL) {
		/*
		 * this can only happen for swap files now that
		 * we're asking for V2 paging behavior...
		 * so don't need to worry about decompression, or
		 * keeping track of blocks read or taking the truncate lock
		 */
		error = cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
				       ap->a_size, (off_t)fp->ff_size, ap->a_flags);
		goto pagein_done;
	}

	page_needed_f_offset = ap->a_f_offset + ap->a_pl_offset;

retry_pagein:
	/*
	 * take truncate lock (shared/recursive) to guard against 
	 * zero-fill thru fsync interfering, but only for v2
	 *
	 * the HFS_RECURSE_TRUNCLOCK arg indicates that we want the 
	 * lock shared and we are allowed to recurse 1 level if this thread already
	 * owns the lock exclusively... this can legally occur
	 * if we are doing a shrinking ftruncate against a file
	 * that is mapped private, and the pages being truncated
	 * do not currently exist in the cache... in that case
	 * we will have to page-in the missing pages in order
	 * to provide them to the private mapping... we must
	 * also call hfs_unlock_truncate with a postive been_recursed 
	 * arg to indicate that if we have recursed, there is no need to drop
	 * the lock.  Allowing this simple recursion is necessary
	 * in order to avoid a certain deadlock... since the ftruncate
	 * already holds the truncate lock exclusively, if we try
	 * to acquire it shared to protect the pagein path, we will
	 * hang this thread
	 *
	 * NOTE: The if () block below is a workaround in order to prevent a 
	 * VM deadlock. See rdar://7853471.
	 * 
	 * If we are in a forced unmount, then launchd will still have the 
	 * dyld_shared_cache file mapped as it is trying to reboot.  If we 
	 * take the truncate lock here to service a page fault, then our 
	 * thread could deadlock with the forced-unmount.  The forced unmount 
	 * thread will try to reclaim the dyld_shared_cache vnode, but since it's 
	 * marked C_DELETED, it will call ubc_setsize(0).  As a result, the unmount 
	 * thread will think it needs to copy all of the data out of the file 
	 * and into a VM copy object.  If we hold the cnode lock here, then that 
	 * VM operation will not be able to proceed, because we'll set a busy page 
	 * before attempting to grab the lock.  Note that this isn't as simple as "don't
	 * call ubc_setsize" because doing that would just shift the problem to the
	 * ubc_msync done before the vnode is reclaimed.
	 *
	 * So, if a forced unmount on this volume is in flight AND the cnode is 
	 * marked C_DELETED, then just go ahead and do the page in without taking 
	 * the lock (thus suspending pagein_v2 semantics temporarily).  Since it's on a file
	 * that is not going to be available on the next mount, this seems like a 
	 * OK solution from a correctness point of view, even though it is hacky.
	 */
	if (vfs_isforce(vp->v_mount)) {
		if (cp->c_flag & C_DELETED) {
			/* If we don't get it, then just go ahead and operate without the lock */
			truncate_lock_held = hfs_try_trunclock(cp, HFS_SHARED_LOCK, HFS_LOCK_SKIP_IF_EXCLUSIVE);
		}
	}
	else {
		hfs_lock_truncate(cp, HFS_SHARED_LOCK, HFS_LOCK_SKIP_IF_EXCLUSIVE);
		truncate_lock_held = TRUE;
	}

	kret = ubc_create_upl(vp, ap->a_f_offset, ap->a_size, &upl, &pl, UPL_UBC_PAGEIN | UPL_RET_ONLY_ABSENT); 

	if ((kret != KERN_SUCCESS) || (upl == (upl_t) NULL)) {
		error = EINVAL;
		goto pagein_done;
	}
	ubc_upl_range_needed(upl, ap->a_pl_offset / PAGE_SIZE, 1);

	upl_size = isize = ap->a_size;

	/*
	 * Scan from the back to find the last page in the UPL, so that we 
	 * aren't looking at a UPL that may have already been freed by the
	 * preceding aborts/completions.
	 */ 
	for (pg_index = ((isize) / PAGE_SIZE); pg_index > 0;) {
		if (upl_page_present(pl, --pg_index))
			break;
		if (pg_index == 0) {
			/*
			 * no absent pages were found in the range specified
			 * just abort the UPL to get rid of it and then we're done
			 */
			ubc_upl_abort_range(upl, 0, isize, UPL_ABORT_FREE_ON_EMPTY);
			goto pagein_done;
		}
	}
	/* 
	 * initialize the offset variables before we touch the UPL.
	 * f_offset is the position into the file, in bytes
	 * offset is the position into the UPL, in bytes
	 * pg_index is the pg# of the UPL we're operating on
	 * isize is the offset into the UPL of the last page that is present. 
	 */
	isize = ((pg_index + 1) * PAGE_SIZE);	
	pg_index = 0;
	offset = 0;
	f_offset = ap->a_f_offset;

	while (isize) {
		int  xsize;
		int  num_of_pages;

		if ( !upl_page_present(pl, pg_index)) {
			/*
			 * we asked for RET_ONLY_ABSENT, so it's possible
			 * to get back empty slots in the UPL.
			 * just skip over them
			 */
			f_offset += PAGE_SIZE;
			offset   += PAGE_SIZE;
			isize    -= PAGE_SIZE;
			pg_index++;

			continue;
		}
		/* 
		 * We know that we have at least one absent page.
		 * Now checking to see how many in a row we have
		 */
		num_of_pages = 1;
		xsize = isize - PAGE_SIZE;

		while (xsize) {
			if ( !upl_page_present(pl, pg_index + num_of_pages))
				break;
			num_of_pages++;
			xsize -= PAGE_SIZE;
		}
		xsize = num_of_pages * PAGE_SIZE;

#if HFS_COMPRESSION
		if (VNODE_IS_RSRC(vp)) {
			/* allow pageins of the resource fork */
		} else {
			int compressed = hfs_file_is_compressed(VTOC(vp), 1); /* 1 == don't take the cnode lock */

			if (compressed) {

				if (truncate_lock_held) {
					/*
					 * can't hold the truncate lock when calling into the decmpfs layer
					 * since it calls back into this layer... even though we're only
					 * holding the lock in shared mode, and the re-entrant path only
					 * takes the lock shared, we can deadlock if some other thread
					 * tries to grab the lock exclusively in between.
					 */
					hfs_unlock_truncate(cp, HFS_LOCK_SKIP_IF_EXCLUSIVE);
					truncate_lock_held = FALSE;
				}
				ap->a_pl = upl;
				ap->a_pl_offset = offset;
				ap->a_f_offset = f_offset;
				ap->a_size = xsize;

				error = decmpfs_pagein_compressed(ap, &compressed, VTOCMP(vp));
				/*
				 * note that decpfs_pagein_compressed can change the state of
				 * 'compressed'... it will set it to 0 if the file is no longer
				 * compressed once the compression lock is successfully taken
				 * i.e. we would block on that lock while the file is being inflated
				 */
				if (error == 0 && vnode_isfastdevicecandidate(vp)) {
					(void) hfs_addhotfile(vp);
				}
				if (compressed) {
					if (error == 0) {
						/* successful page-in, update the access time */
						VTOC(vp)->c_touch_acctime = TRUE;
					
						//
						// compressed files are not traditional hot file candidates
						// but they may be for CF (which ignores the ff_bytesread
						// field)
						//
						if (VTOHFS(vp)->hfc_stage == HFC_RECORDING) {
							fp->ff_bytesread = 0;
						}
					} else if (error == EAGAIN) {
						/*
						 * EAGAIN indicates someone else already holds the compression lock...
						 * to avoid deadlocking, we'll abort this range of pages with an
						 * indication that the pagein needs to be redriven
						 */
			        		ubc_upl_abort_range(upl, (upl_offset_t) offset, xsize, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_RESTART);
					} else if (error == ENOSPC) {

						if (upl_size == PAGE_SIZE)
							panic("decmpfs_pagein_compressed: couldn't ubc_upl_map a single page\n");

						ubc_upl_abort_range(upl, (upl_offset_t) offset, isize, UPL_ABORT_FREE_ON_EMPTY);

						ap->a_size = PAGE_SIZE;
						ap->a_pl = NULL;
						ap->a_pl_offset = 0;
						ap->a_f_offset = page_needed_f_offset;

						goto retry_pagein;
					}
					goto pagein_next_range;
				}
				else {
					/* 
					 * Set file_converted only if the file became decompressed while we were
					 * paging in.  If it were still compressed, we would re-start the loop using the goto
					 * in the above block.  This avoid us overloading truncate_lock_held as our retry_pagein
					 * condition below, since we could have avoided taking the truncate lock to prevent
					 * a deadlock in the force unmount case.
					 */
					file_converted = TRUE;
				}
			}
			if (file_converted == TRUE) {
				/*
				 * the file was converted back to a regular file after we first saw it as compressed
				 * we need to abort the upl, retake the truncate lock, recreate the UPL and start over
				 * reset a_size so that we consider what remains of the original request
				 * and null out a_upl and a_pl_offset.
				 *
				 * We should only be able to get into this block if the decmpfs_pagein_compressed 
				 * successfully decompressed the range in question for this file.
				 */
				ubc_upl_abort_range(upl, (upl_offset_t) offset, isize, UPL_ABORT_FREE_ON_EMPTY);

				ap->a_size = isize;
				ap->a_pl = NULL;
				ap->a_pl_offset = 0;

				/* Reset file_converted back to false so that we don't infinite-loop. */
				file_converted = FALSE;
				goto retry_pagein;
			}
		}
#endif
		error = cluster_pagein(vp, upl, offset, f_offset, xsize, (off_t)fp->ff_size, ap->a_flags);

		/*
		 * Keep track of blocks read.
		 */
		if ( !vnode_isswap(vp) && VTOHFS(vp)->hfc_stage == HFC_RECORDING && error == 0) {
			int bytesread;
			int took_cnode_lock = 0;
		
			if (ap->a_f_offset == 0 && fp->ff_size < PAGE_SIZE)
				bytesread = fp->ff_size;
			else
				bytesread = xsize;

			/* When ff_bytesread exceeds 32-bits, update it behind the cnode lock. */
			if ((fp->ff_bytesread + bytesread) > 0x00000000ffffffff && cp->c_lockowner != current_thread()) {
				hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
				took_cnode_lock = 1;
			}
			/*
			 * If this file hasn't been seen since the start of
			 * the current sampling period then start over.
			 */
			if (cp->c_atime < VTOHFS(vp)->hfc_timebase) {
				struct timeval tv;

				fp->ff_bytesread = bytesread;
				microtime(&tv);
				cp->c_atime = tv.tv_sec;
			} else {
				fp->ff_bytesread += bytesread;
			}
			cp->c_touch_acctime = TRUE;

			if (vnode_isfastdevicecandidate(vp)) {
				(void) hfs_addhotfile(vp);
			}
			if (took_cnode_lock)
				hfs_unlock(cp);
		}
pagein_next_range:
		f_offset += xsize;
		offset   += xsize;
		isize    -= xsize;
		pg_index += num_of_pages;

		error = 0;
	}

pagein_done:
	if (truncate_lock_held == TRUE) {
		/* Note 1 is passed to hfs_unlock_truncate in been_recursed argument */
		hfs_unlock_truncate(cp, HFS_LOCK_SKIP_IF_EXCLUSIVE);
	}

	return (error);
}

/* 
 * Pageout for HFS filesystem.
 */
int
hfs_vnop_pageout(struct vnop_pageout_args *ap)
/*
	struct vnop_pageout_args {
	   vnode_t a_vp,
	   upl_t         a_pl,
	   vm_offset_t   a_pl_offset,
	   off_t         a_f_offset,
	   size_t        a_size,
	   int           a_flags
	   vfs_context_t a_context;
	};
*/
{
	vnode_t vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	int retval = 0;
	off_t filesize;
	upl_t 		upl;
	upl_page_info_t* pl;
	vm_offset_t	a_pl_offset;
	int		a_flags;
	int is_pageoutv2 = 0;
	kern_return_t kret;

	cp = VTOC(vp);
	fp = VTOF(vp);
	
	a_flags = ap->a_flags;
	a_pl_offset = ap->a_pl_offset;

	/*
	 * we can tell if we're getting the new or old behavior from the UPL
	 */
	if ((upl = ap->a_pl) == NULL) {
		int request_flags; 

		is_pageoutv2 = 1;
		/*
		 * we're in control of any UPL we commit
		 * make sure someone hasn't accidentally passed in UPL_NOCOMMIT 
		 */
		a_flags &= ~UPL_NOCOMMIT;
		a_pl_offset = 0;

		/*
		 * For V2 semantics, we want to take the cnode truncate lock
		 * shared to guard against the file size changing via zero-filling.
		 * 
		 * However, we have to be careful because we may be invoked 
		 * via the ubc_msync path to write out dirty mmap'd pages
		 * in response to a lock event on a content-protected
		 * filesystem (e.g. to write out class A files).
		 * As a result, we want to take the truncate lock 'SHARED' with 
		 * the mini-recursion locktype so that we don't deadlock/panic 
		 * because we may be already holding the truncate lock exclusive to force any other
		 * IOs to have blocked behind us. 
		 */
		hfs_lock_truncate(cp, HFS_SHARED_LOCK, HFS_LOCK_SKIP_IF_EXCLUSIVE);

		if (a_flags & UPL_MSYNC) {
			request_flags = UPL_UBC_MSYNC | UPL_RET_ONLY_DIRTY;
		}
		else {
			request_flags = UPL_UBC_PAGEOUT | UPL_RET_ONLY_DIRTY;
		}
		
		kret = ubc_create_upl(vp, ap->a_f_offset, ap->a_size, &upl, &pl, request_flags); 

		if ((kret != KERN_SUCCESS) || (upl == (upl_t) NULL)) {
			retval = EINVAL;
			goto pageout_done;
		}
	}
	/*
	 * from this point forward upl points at the UPL we're working with
	 * it was either passed in or we succesfully created it
	 */

	/*
	 * Figure out where the file ends, for pageout purposes.  If
	 * ff_new_size > ff_size, then we're in the middle of extending the
	 * file via a write, so it is safe (and necessary) that we be able
	 * to pageout up to that point.
	 */
	filesize = fp->ff_size;
	if (fp->ff_new_size > filesize)
		filesize = fp->ff_new_size;

	/* 
	 * Now that HFS is opting into VFC_VFSVNOP_PAGEOUTV2, we may need to operate on our own  
	 * UPL instead of relying on the UPL passed into us.  We go ahead and do that here,
	 * scanning for dirty ranges.  We'll issue our own N cluster_pageout calls, for
	 * N dirty ranges in the UPL.  Note that this is almost a direct copy of the 
	 * logic in vnode_pageout except that we need to do it after grabbing the truncate 
	 * lock in HFS so that we don't lock invert ourselves.  
	 * 
	 * Note that we can still get into this function on behalf of the default pager with
	 * non-V2 behavior (swapfiles).  However in that case, we did not grab locks above 
	 * since fsync and other writing threads will grab the locks, then mark the 
	 * relevant pages as busy.  But the pageout codepath marks the pages as busy, 
	 * and THEN would attempt to grab the truncate lock, which would result in deadlock.  So
	 * we do not try to grab anything for the pre-V2 case, which should only be accessed
	 * by the paging/VM system.
	 */

	if (is_pageoutv2) {
		off_t f_offset;
		int offset;
		int isize; 
		int pg_index;
		int error;
		int error_ret = 0;

		isize = ap->a_size;
		f_offset = ap->a_f_offset;

		/* 
		 * Scan from the back to find the last page in the UPL, so that we 
		 * aren't looking at a UPL that may have already been freed by the
		 * preceding aborts/completions.
		 */ 
		for (pg_index = ((isize) / PAGE_SIZE); pg_index > 0;) {
			if (upl_page_present(pl, --pg_index))
				break;
			if (pg_index == 0) {
				ubc_upl_abort_range(upl, 0, isize, UPL_ABORT_FREE_ON_EMPTY);
				goto pageout_done;
			}
		}

		/* 
		 * initialize the offset variables before we touch the UPL.
		 * a_f_offset is the position into the file, in bytes
		 * offset is the position into the UPL, in bytes
		 * pg_index is the pg# of the UPL we're operating on.
		 * isize is the offset into the UPL of the last non-clean page. 
		 */
		isize = ((pg_index + 1) * PAGE_SIZE);	

		offset = 0;
		pg_index = 0;

		while (isize) {
			int  xsize;
			int  num_of_pages;

			if ( !upl_page_present(pl, pg_index)) {
				/*
				 * we asked for RET_ONLY_DIRTY, so it's possible
				 * to get back empty slots in the UPL.
				 * just skip over them
				 */
				f_offset += PAGE_SIZE;
				offset   += PAGE_SIZE;
				isize    -= PAGE_SIZE;
				pg_index++;

				continue;
			}
			if ( !upl_dirty_page(pl, pg_index)) {
				panic ("hfs_vnop_pageout: unforeseen clean page @ index %d for UPL %p\n", pg_index, upl);
			}

			/* 
			 * We know that we have at least one dirty page.
			 * Now checking to see how many in a row we have
			 */
			num_of_pages = 1;
			xsize = isize - PAGE_SIZE;

			while (xsize) {
				if ( !upl_dirty_page(pl, pg_index + num_of_pages))
					break;
				num_of_pages++;
				xsize -= PAGE_SIZE;
			}
			xsize = num_of_pages * PAGE_SIZE;

			if ((error = cluster_pageout(vp, upl, offset, f_offset,
							xsize, filesize, a_flags))) {
				if (error_ret == 0)
					error_ret = error;
			}
			f_offset += xsize;
			offset   += xsize;
			isize    -= xsize;
			pg_index += num_of_pages;
		}
		/* capture errnos bubbled out of cluster_pageout if they occurred */
		if (error_ret != 0) {
			retval = error_ret;
		}
	} /* end block for v2 pageout behavior */
	else {
		/* 
		 * just call cluster_pageout for old pre-v2 behavior
		 */
		retval = cluster_pageout(vp, upl, a_pl_offset, ap->a_f_offset,
				ap->a_size, filesize, a_flags);		
	}

	/*
	 * If data was written, update the modification time of the file
	 * but only if it's mapped writable; we will have touched the
	 * modifcation time for direct writes.
	 */
	if (retval == 0 && (ubc_is_mapped_writable(vp)
						|| ISSET(cp->c_flag, C_MIGHT_BE_DIRTY_FROM_MAPPING))) {
		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

		// Check again with lock
		bool mapped_writable = ubc_is_mapped_writable(vp);
		if (mapped_writable
			|| ISSET(cp->c_flag, C_MIGHT_BE_DIRTY_FROM_MAPPING)) {
			cp->c_touch_modtime = TRUE;
			cp->c_touch_chgtime = TRUE;

			/*
			 * We only need to increment the generation counter if
			 * it's currently mapped writable because we incremented
			 * the counter in hfs_vnop_mnomap.
			 */
			if (mapped_writable)
				hfs_incr_gencount(VTOC(vp));

			/*
			 * If setuid or setgid bits are set and this process is
			 * not the superuser then clear the setuid and setgid bits
			 * as a precaution against tampering.
			 */
			if ((cp->c_mode & (S_ISUID | S_ISGID)) &&
				(vfs_context_suser(ap->a_context) != 0)) {
				cp->c_mode &= ~(S_ISUID | S_ISGID);
			}
		}

		hfs_unlock(cp);
	}

pageout_done:
	if (is_pageoutv2) {
		/* 
		 * Release the truncate lock.  Note that because 
		 * we may have taken the lock recursively by 
		 * being invoked via ubc_msync due to lockdown,
		 * we should release it recursively, too.
		 */
		hfs_unlock_truncate(cp, HFS_LOCK_SKIP_IF_EXCLUSIVE);
	}
	return (retval);
}

/*
 * Intercept B-Tree node writes to unswap them if necessary.
 */
int
hfs_vnop_bwrite(struct vnop_bwrite_args *ap)
{
	int retval = 0;
	register struct buf *bp = ap->a_bp;
	register struct vnode *vp = buf_vnode(bp);
	BlockDescriptor block;

	/* Trap B-Tree writes */
	if ((VTOC(vp)->c_fileid == kHFSExtentsFileID) ||
	    (VTOC(vp)->c_fileid == kHFSCatalogFileID) ||
	    (VTOC(vp)->c_fileid == kHFSAttributesFileID) ||
	    (vp == VTOHFS(vp)->hfc_filevp)) {

		/* 
		 * Swap and validate the node if it is in native byte order.
		 * This is always be true on big endian, so we always validate
		 * before writing here.  On little endian, the node typically has
		 * been swapped and validated when it was written to the journal,
		 * so we won't do anything here.
		 */
		if (((u_int16_t *)((char *)buf_dataptr(bp) + buf_count(bp) - 2))[0] == 0x000e) {
			/* Prepare the block pointer */
			block.blockHeader = bp;
			block.buffer = (char *)buf_dataptr(bp);
			block.blockNum = buf_lblkno(bp);
			/* not found in cache ==> came from disk */
			block.blockReadFromDisk = (buf_fromcache(bp) == 0);
			block.blockSize = buf_count(bp);
    
			/* Endian un-swap B-Tree node */
			retval = hfs_swap_BTNode (&block, vp, kSwapBTNodeHostToBig, false);
			if (retval)
				panic("hfs_vnop_bwrite: about to write corrupt node!\n");
		}
	}

	/* This buffer shouldn't be locked anymore but if it is clear it */
	if ((buf_flags(bp) & B_LOCKED)) {
	        // XXXdbg
	        if (VTOHFS(vp)->jnl) {
		        panic("hfs: CLEARING the lock bit on bp %p\n", bp);
		}
		buf_clearflags(bp, B_LOCKED);
	}
	retval = vn_bwrite (ap);

	return (retval);
}


int
hfs_pin_block_range(struct hfsmount *hfsmp, int pin_state, uint32_t start_block, uint32_t nblocks, vfs_context_t ctx)
{
	_dk_cs_pin_t pin;
	unsigned ioc;
	int err;

	memset(&pin, 0, sizeof(pin));
	pin.cp_extent.offset = ((uint64_t)start_block) * HFSTOVCB(hfsmp)->blockSize;
	pin.cp_extent.length = ((uint64_t)nblocks) * HFSTOVCB(hfsmp)->blockSize;
	switch (pin_state) {
	case HFS_PIN_IT:
		ioc = _DKIOCCSPINEXTENT;
		pin.cp_flags = _DKIOCCSPINTOFASTMEDIA;
		break;
	case HFS_PIN_IT | HFS_TEMP_PIN:
		ioc = _DKIOCCSPINEXTENT;
		pin.cp_flags = _DKIOCCSPINTOFASTMEDIA | _DKIOCCSTEMPORARYPIN;
		break;
	case HFS_PIN_IT | HFS_DATALESS_PIN:
		ioc = _DKIOCCSPINEXTENT;
		pin.cp_flags = _DKIOCCSPINTOFASTMEDIA | _DKIOCCSPINFORSWAPFILE;
		break;
	case HFS_UNPIN_IT:
		ioc = _DKIOCCSUNPINEXTENT;
		pin.cp_flags = 0;
		break;
	case HFS_UNPIN_IT | HFS_EVICT_PIN:
		ioc = _DKIOCCSPINEXTENT;
		pin.cp_flags = _DKIOCCSPINTOSLOWMEDIA;
		break;
	default:
		return EINVAL;
	}
	err = VNOP_IOCTL(hfsmp->hfs_devvp, ioc, (caddr_t)&pin, 0, ctx);
	return err;
}

//
// The cnode lock should already be held on entry to this function
//
int
hfs_pin_vnode(struct hfsmount *hfsmp, struct vnode *vp, int pin_state, uint32_t *num_blocks_pinned, vfs_context_t ctx)
{
	struct filefork *fp = VTOF(vp);
	int i, err=0, need_put=0;
	struct vnode *rsrc_vp=NULL;
	uint32_t npinned = 0;
	off_t               offset;

	if (num_blocks_pinned) {
		*num_blocks_pinned = 0;
	}
	
	if (vnode_vtype(vp) != VREG) {
		/* Not allowed to pin directories or symlinks */
		printf("hfs: can't pin vnode of type %d\n", vnode_vtype(vp));
		return (EPERM);
	}
	
	if (fp->ff_unallocblocks) {
		printf("hfs: can't pin a vnode w/unalloced blocks (%d)\n", fp->ff_unallocblocks);
		return (EINVAL);
	}

	/*
	 * It is possible that if the caller unlocked/re-locked the cnode after checking
	 * for C_NOEXISTS|C_DELETED that the file could have been deleted while the
	 * cnode was unlocked.  So check the condition again and return ENOENT so that
	 * the caller knows why we failed to pin the vnode. 
	 */
	if (VTOC(vp)->c_flag & (C_NOEXISTS|C_DELETED)) {
		// makes no sense to pin something that's pending deletion
		return ENOENT;
	}

	if (fp->ff_blocks == 0 && (VTOC(vp)->c_bsdflags & UF_COMPRESSED)) {
		if (!VNODE_IS_RSRC(vp) && hfs_vgetrsrc(hfsmp, vp, &rsrc_vp) == 0) {
			//printf("hfs: fileid %d resource fork nblocks: %d / size: %lld\n", VTOC(vp)->c_fileid,
			//       VTOC(rsrc_vp)->c_rsrcfork->ff_blocks,VTOC(rsrc_vp)->c_rsrcfork->ff_size);

			fp = VTOC(rsrc_vp)->c_rsrcfork;
			need_put = 1;
		}
	}
	if (fp->ff_blocks == 0) {
		if (need_put) {
			//
			// use a distinct error code for a compressed file that has no resource fork;
			// we return EALREADY to indicate that the data is already probably hot file
			// cached because it's in an EA and the attributes btree is on the ssd
			// 
			err = EALREADY;
		} else {
			err = EINVAL;
		}
		goto out;
	}

	offset = 0;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		if (fp->ff_extents[i].startBlock == 0) {
			break;
		}

		err = hfs_pin_block_range(hfsmp, pin_state, fp->ff_extents[i].startBlock, fp->ff_extents[i].blockCount, ctx);
		if (err) {
			break;
		} else {
			npinned += fp->ff_extents[i].blockCount;			
		}
	}
	
	if (err || npinned == 0) {
		goto out;
	}

	if (fp->ff_extents[kHFSPlusExtentDensity-1].startBlock) {
		uint32_t pblocks;
		uint8_t forktype = 0;

		if (fp == VTOC(vp)->c_rsrcfork) {
			forktype = 0xff;
		}
		/*
		 * The file could have overflow extents, better pin them.
		 *
		 * We assume that since we are holding the cnode lock for this cnode,
		 * the files extents cannot be manipulated, but the tree could, so we
		 * need to ensure that it doesn't change behind our back as we iterate it.
		 */
		int lockflags = hfs_systemfile_lock (hfsmp, SFL_EXTENTS, HFS_SHARED_LOCK);
		err = hfs_pin_overflow_extents(hfsmp, VTOC(vp)->c_fileid, forktype, &pblocks);
		hfs_systemfile_unlock (hfsmp, lockflags);

		if (err) {
			goto out;
		}
		npinned += pblocks;
	}

out:
	if (num_blocks_pinned) {
		*num_blocks_pinned = npinned;
	}
	
	if (need_put && rsrc_vp) {
		//
		// have to unlock the cnode since it's shared between the
		// resource fork vnode and the data fork vnode (and the
		// vnode_put() may need to re-acquire the cnode lock to
		// reclaim the resource fork vnode)
		//
		hfs_unlock(VTOC(vp));
		vnode_put(rsrc_vp);
		hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
	}
	return err;
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
 * |///////////////|     |               |     STEP 1 (acquire new blocks)
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
 * During step 3 page-ins to the file get suspended.
 */
int
hfs_relocate(struct  vnode *vp, u_int32_t  blockHint, kauth_cred_t cred,
	struct  proc *p)
{
	struct  cnode *cp;
	struct  filefork *fp;
	struct  hfsmount *hfsmp;
	u_int32_t  headblks;
	u_int32_t  datablks;
	u_int32_t  blksize;
	u_int32_t  growsize;
	u_int32_t  nextallocsave;
	daddr64_t  sector_a,  sector_b;
	int eflags;
	off_t  newbytes;
	int  retval;
	int lockflags = 0;
	int took_trunc_lock = 0;
	int started_tr = 0;
	enum vtype vnodetype;

	vnodetype = vnode_vtype(vp);
	if (vnodetype != VREG) {
		/* Not allowed to move symlinks. */
		return (EPERM);
	}
	
	hfsmp = VTOHFS(vp);
	if (hfsmp->hfs_flags & HFS_FRAGMENTED_FREESPACE) {
		return (ENOSPC);
	}

	cp = VTOC(vp);
	fp = VTOF(vp);
	if (fp->ff_unallocblocks)
		return (EINVAL);

#if CONFIG_PROTECT
	/* 
	 * <rdar://problem/9118426>
	 * Disable HFS file relocation on content-protected filesystems
	 */
	if (cp_fs_protected (hfsmp->hfs_mp)) {
		return EINVAL;
	}
#endif
	/* If it's an SSD, also disable HFS relocation */
	if (hfsmp->hfs_flags & HFS_SSD) {
		return EINVAL;
	}


	blksize = hfsmp->blockSize;
	if (blockHint == 0)
		blockHint = hfsmp->nextAllocation;

	if (fp->ff_size > 0x7fffffff) {
		return (EFBIG);
	}

	//
	// We do not believe that this call to hfs_fsync() is
	// necessary and it causes a journal transaction
	// deadlock so we are removing it.
	//
	//if (vnodetype == VREG && !vnode_issystem(vp)) {
	//	retval = hfs_fsync(vp, MNT_WAIT, 0, p);
	//	if (retval)
	//		return (retval);
	//}

	if (!vnode_issystem(vp) && (vnodetype != VLNK)) {
		hfs_unlock(cp);
		hfs_lock_truncate(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		/* Force lock since callers expects lock to be held. */
		if ((retval = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS))) {
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
			return (retval);
		}
		/* No need to continue if file was removed. */
		if (cp->c_flag & C_NOEXISTS) {
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
			return (ENOENT);
		}
		took_trunc_lock = 1;
	}
	headblks = fp->ff_blocks;
	datablks = howmany(fp->ff_size, blksize);
	growsize = datablks * blksize;
	eflags = kEFContigMask | kEFAllMask | kEFNoClumpMask;
	if (blockHint >= hfsmp->hfs_metazone_start &&
	    blockHint <= hfsmp->hfs_metazone_end)
		eflags |= kEFMetadataMask;

	if (hfs_start_transaction(hfsmp) != 0) {
		if (took_trunc_lock)
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	    return (EINVAL);
	}
	started_tr = 1;
	/*
	 * Protect the extents b-tree and the allocation bitmap
	 * during MapFileBlockC and ExtendFileC operations.
	 */
	lockflags = SFL_BITMAP;
	if (overflow_extents(fp))
		lockflags |= SFL_EXTENTS;
	lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

	retval = MapFileBlockC(hfsmp, (FCB *)fp, 1, growsize - 1, &sector_a, NULL);
	if (retval) {
		retval = MacToVFSError(retval);
		goto out;
	}

	/*
	 * STEP 1 - acquire new allocation blocks.
	 */
	nextallocsave = hfsmp->nextAllocation;
	retval = ExtendFileC(hfsmp, (FCB*)fp, growsize, blockHint, eflags, &newbytes);
	if (eflags & kEFMetadataMask) {
		hfs_lock_mount(hfsmp);
		HFS_UPDATE_NEXT_ALLOCATION(hfsmp, nextallocsave);
		MarkVCBDirty(hfsmp);
		hfs_unlock_mount(hfsmp);
	}

	retval = MacToVFSError(retval);
	if (retval == 0) {
		cp->c_flag |= C_MODIFIED;
		if (newbytes < growsize) {
			retval = ENOSPC;
			goto restore;
		} else if (fp->ff_blocks < (headblks + datablks)) {
			printf("hfs_relocate: allocation failed id=%u, vol=%s\n", cp->c_cnid, hfsmp->vcbVN);
			retval = ENOSPC;
			goto restore;
		}

		retval = MapFileBlockC(hfsmp, (FCB *)fp, 1, growsize, &sector_b, NULL);
		if (retval) {
			retval = MacToVFSError(retval);
		} else if ((sector_a + 1) == sector_b) {
			retval = ENOSPC;
			goto restore;
		} else if ((eflags & kEFMetadataMask) &&
		           ((((u_int64_t)sector_b * hfsmp->hfs_logical_block_size) / blksize) >
		              hfsmp->hfs_metazone_end)) {
#if 0
			const char * filestr;
			char emptystr = '\0';

			if (cp->c_desc.cd_nameptr != NULL) {
				filestr = (const char *)&cp->c_desc.cd_nameptr[0];
			} else if (vnode_name(vp) != NULL) {
				filestr = vnode_name(vp);
			} else {
				filestr = &emptystr;
			}
#endif
			retval = ENOSPC;
			goto restore;
		}
	}
	/* Done with system locks and journal for now. */
	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;
	hfs_end_transaction(hfsmp);
	started_tr = 0;

	if (retval) {
		/*
		 * Check to see if failure is due to excessive fragmentation.
		 */
		if ((retval == ENOSPC) &&
		    (hfs_freeblks(hfsmp, 0) > (datablks * 2))) {
			hfsmp->hfs_flags |= HFS_FRAGMENTED_FREESPACE;
		}
		goto out;
	}
	/*
	 * STEP 2 - clone file data into the new allocation blocks.
	 */

	if (vnodetype == VLNK)
		retval = EPERM;
	else if (vnode_issystem(vp))
		retval = hfs_clonesysfile(vp, headblks, datablks, blksize, cred, p);
	else
		retval = hfs_clonefile(vp, headblks, datablks, blksize);

	/* Start transaction for step 3 or for a restore. */
	if (hfs_start_transaction(hfsmp) != 0) {
		retval = EINVAL;
		goto out;
	}
	started_tr = 1;
	if (retval)
		goto restore;

	/*
	 * STEP 3 - switch to cloned data and remove old blocks.
	 */
	lockflags = SFL_BITMAP;
	if (overflow_extents(fp))
		lockflags |= SFL_EXTENTS;
	lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

	retval = HeadTruncateFile(hfsmp, (FCB*)fp, headblks);

	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;
	if (retval)
		goto restore;
out:
	if (took_trunc_lock)
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);

	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		lockflags = 0;
	}

	/* Push cnode's new extent data to disk. */
	if (retval == 0) {
		hfs_update(vp, 0);
	}
	if (hfsmp->jnl) {
		if (cp->c_cnid < kHFSFirstUserCatalogNodeID)
			(void) hfs_flushvolumeheader(hfsmp, HFS_FVH_WAIT | HFS_FVH_WRITE_ALT);
		else
			(void) hfs_flushvolumeheader(hfsmp, 0);
	}
exit:
	if (started_tr)
		hfs_end_transaction(hfsmp);

	return (retval);

restore:
	if (fp->ff_blocks == headblks) {
		if (took_trunc_lock)
			hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
		goto exit;
	}
	/*
	 * Give back any newly allocated space.
	 */
	if (lockflags == 0) {
		lockflags = SFL_BITMAP;
		if (overflow_extents(fp))
			lockflags |= SFL_EXTENTS;
		lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
	}

	(void) TruncateFileC(hfsmp, (FCB*)fp, fp->ff_size, 0, FORK_IS_RSRC(fp), 
						 FTOC(fp)->c_fileid, false);

	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;

	if (took_trunc_lock)
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	goto exit;
}


/*
 * Clone a file's data within the file.
 *
 */
static int
hfs_clonefile(struct vnode *vp, int blkstart, int blkcnt, int blksize)
{
	caddr_t  bufp;
	size_t  bufsize;
	size_t  copysize;
        size_t  iosize;
	size_t  offset;
	off_t	writebase;
	uio_t auio;
	int  error = 0;

	writebase = blkstart * blksize;
	copysize = blkcnt * blksize;
	iosize = bufsize = MIN(copysize, 128 * 1024);
	offset = 0;

	hfs_unlock(VTOC(vp));

#if CONFIG_PROTECT
	if ((error = cp_handle_vnop(vp, CP_WRITE_ACCESS, 0)) != 0) {
		hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);	
		return (error);
	}
#endif /* CONFIG_PROTECT */

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize, VM_KERN_MEMORY_FILE)) {
		hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		return (ENOMEM);
	}

	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);

	while (offset < copysize) {
		iosize = MIN(copysize - offset, iosize);

		uio_reset(auio, offset, UIO_SYSSPACE, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufp, iosize);

		error = cluster_read(vp, auio, copysize, IO_NOCACHE);
		if (error) {
			printf("hfs_clonefile: cluster_read failed - %d\n", error);
			break;
		}
		if (uio_resid(auio) != 0) {
			printf("hfs_clonefile: cluster_read: uio_resid = %lld\n", (int64_t)uio_resid(auio));
			error = EIO;		
			break;
		}

		uio_reset(auio, writebase + offset, UIO_SYSSPACE, UIO_WRITE);
		uio_addiov(auio, (uintptr_t)bufp, iosize);

		error = cluster_write(vp, auio, writebase + offset,
		                      writebase + offset + iosize,
		                      uio_offset(auio), 0, IO_NOCACHE | IO_SYNC);
		if (error) {
			printf("hfs_clonefile: cluster_write failed - %d\n", error);
			break;
		}
		if (uio_resid(auio) != 0) {
			printf("hfs_clonefile: cluster_write failed - uio_resid not zero\n");
			error = EIO;		
			break;
		}	
		offset += iosize;
	}
	uio_free(auio);

	if ((blksize & PAGE_MASK)) {
		/*
		 * since the copy may not have started on a PAGE
		 * boundary (or may not have ended on one), we 
		 * may have pages left in the cache since NOCACHE
		 * will let partially written pages linger...
		 * lets just flush the entire range to make sure
		 * we don't have any pages left that are beyond
		 * (or intersect) the real LEOF of this file
		 */
		ubc_msync(vp, writebase, writebase + offset, NULL, UBC_INVALIDATE | UBC_PUSHDIRTY);
	} else {
		/*
		 * No need to call ubc_msync or hfs_invalbuf
		 * since the file was copied using IO_NOCACHE and
		 * the copy was done starting and ending on a page
		 * boundary in the file.
		 */
	}
	kmem_free(kernel_map, (vm_offset_t)bufp, bufsize);

	hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);	
	return (error);
}

/*
 * Clone a system (metadata) file.
 *
 */
static int
hfs_clonesysfile(struct vnode *vp, int blkstart, int blkcnt, int blksize,
                 kauth_cred_t cred, struct proc *p)
{
	caddr_t  bufp;
	char * offset;
	size_t  bufsize;
	size_t  iosize;
	struct buf *bp = NULL;
	daddr64_t  blkno;
 	daddr64_t  blk;
	daddr64_t  start_blk;
	daddr64_t  last_blk;
	int  breadcnt;
        int  i;
	int  error = 0;


	iosize = GetLogicalBlockSize(vp);
	bufsize = MIN(blkcnt * blksize, 1024 * 1024) & ~(iosize - 1);
	breadcnt = bufsize / iosize;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize, VM_KERN_MEMORY_FILE)) {
		return (ENOMEM);
	}	
	start_blk = ((daddr64_t)blkstart * blksize) / iosize;
	last_blk  = ((daddr64_t)blkcnt * blksize) / iosize;
	blkno = 0;

	while (blkno < last_blk) {
		/*
		 * Read up to a megabyte
		 */
		offset = bufp;
		for (i = 0, blk = blkno; (i < breadcnt) && (blk < last_blk); ++i, ++blk) {
			error = (int)buf_meta_bread(vp, blk, iosize, cred, &bp);
			if (error) {
				printf("hfs_clonesysfile: meta_bread error %d\n", error);
				goto out;
			}
			if (buf_count(bp) != iosize) {
				printf("hfs_clonesysfile: b_bcount is only %d\n", buf_count(bp));
				goto out;
			}
			bcopy((char *)buf_dataptr(bp), offset, iosize);

			buf_markinvalid(bp);
			buf_brelse(bp);
			bp = NULL;

			offset += iosize;
		}
	
		/*
		 * Write up to a megabyte
		 */
		offset = bufp;
		for (i = 0; (i < breadcnt) && (blkno < last_blk); ++i, ++blkno) {
			bp = buf_getblk(vp, start_blk + blkno, iosize, 0, 0, BLK_META);
			if (bp == NULL) {
				printf("hfs_clonesysfile: getblk failed on blk %qd\n", start_blk + blkno);
				error = EIO;
				goto out;
			}
			bcopy(offset, (char *)buf_dataptr(bp), iosize);
			error = (int)buf_bwrite(bp);
			bp = NULL;
			if (error)
				goto out;
			offset += iosize;
		}
	}
out:
	if (bp) {
		buf_brelse(bp);
	}

	kmem_free(kernel_map, (vm_offset_t)bufp, bufsize);

	error = hfs_fsync(vp, MNT_WAIT, 0, p);

	return (error);
}

errno_t hfs_flush_invalid_ranges(vnode_t vp)
{
	cnode_t *cp = VTOC(vp);

	assert(cp->c_lockowner == current_thread());
	assert(cp->c_truncatelockowner == current_thread());

	if (!ISSET(cp->c_flag, C_ZFWANTSYNC) && !cp->c_zftimeout)
		return 0;

	filefork_t *fp = VTOF(vp);

	/*
	 * We can't hold the cnode lock whilst we call cluster_write so we
	 * need to copy the extents into a local buffer.
	 */
	int max_exts = 16;
	struct ext {
		off_t start, end;
	} exts_buf[max_exts];		// 256 bytes
	struct ext *exts = exts_buf;
	int ext_count = 0;
	errno_t ret;

	struct rl_entry *r = TAILQ_FIRST(&fp->ff_invalidranges);

	while (r) {
		/* If we have more than can fit in our stack buffer, switch
		   to a heap buffer. */
		if (exts == exts_buf && ext_count == max_exts) {
			max_exts = 256;
			MALLOC(exts, struct ext *, sizeof(struct ext) * max_exts,
				   M_TEMP, M_WAITOK);
			memcpy(exts, exts_buf, ext_count * sizeof(struct ext));
		}

		struct rl_entry *next = TAILQ_NEXT(r, rl_link);

		exts[ext_count++] = (struct ext){ r->rl_start, r->rl_end };

		if (!next || (ext_count == max_exts && exts != exts_buf)) {
			hfs_unlock(cp);
			for (int i = 0; i < ext_count; ++i) {
				ret = cluster_write(vp, NULL, fp->ff_size, exts[i].end + 1,
									exts[i].start, 0,
									IO_HEADZEROFILL | IO_NOZERODIRTY | IO_NOCACHE);
				if (ret) {
					hfs_lock_always(cp, HFS_EXCLUSIVE_LOCK);
					goto exit;
				}
			}

			if (!next) {
				hfs_lock_always(cp, HFS_EXCLUSIVE_LOCK);
				break;
			}

			/* Push any existing clusters which should clean up our invalid
			   ranges as they go through hfs_vnop_blockmap. */
			cluster_push(vp, 0);

			hfs_lock_always(cp, HFS_EXCLUSIVE_LOCK);

			/*
			 * Get back to where we were (given we dropped the lock).
			 * This shouldn't be many because we pushed above.
			 */
			TAILQ_FOREACH(r, &fp->ff_invalidranges, rl_link) {
				if (r->rl_end > exts[ext_count - 1].end)
					break;
			}

			ext_count = 0;
		} else
			r = next;
	}

	ret = 0;

exit:

	if (exts != exts_buf)
		FREE(exts, M_TEMP);

	return ret;
}
