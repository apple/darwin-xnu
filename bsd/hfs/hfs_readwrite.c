/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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

#include <miscfs/specfs/specdev.h>

#include <sys/ubc.h>
#include <sys/ubc_internal.h>

#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>

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

/* from bsd/vfs/vfs_cluster.c */
extern int is_file_clean(vnode_t vp, off_t filesize);
/* from bsd/hfs/hfs_vfsops.c */
extern int hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);

static int  hfs_clonelink(struct vnode *, int, kauth_cred_t, struct proc *);
static int  hfs_clonefile(struct vnode *, int, int, int);
static int  hfs_clonesysfile(struct vnode *, int, int, int, kauth_cred_t, struct proc *);

int flush_cache_on_write = 0;
SYSCTL_INT (_kern, OID_AUTO, flush_cache_on_write, CTLFLAG_RW, &flush_cache_on_write, 0, "always flush the drive cache on writes to uncached files");


/*
 * Read data from a file.
 */
int
hfs_vnop_read(struct vnop_read_args *ap)
{
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

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);

	/* Protect against a size change. */
	hfs_lock_truncate(cp, 0);

	filesize = fp->ff_size;
	filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;
	if (offset > filesize) {
		if ((hfsmp->hfs_flags & HFS_STANDARD) &&
		    (offset > (off_t)MAXHFSFILESIZE)) {
			retval = EFBIG;
		}
		goto exit;
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_START,
		(int)uio_offset(uio), uio_resid(uio), (int)filesize, (int)filebytes, 0);

	retval = cluster_read(vp, uio, filesize, ap->a_ioflag);

	cp->c_touch_acctime = TRUE;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_END,
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
			hfs_lock(cp, HFS_FORCE_LOCK);
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
		if (took_cnode_lock)
			hfs_unlock(cp);
	}
exit:
	hfs_unlock_truncate(cp, 0);
	return (retval);
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
	size_t resid;
	int eflags;
	int ioflag = ap->a_ioflag;
	int retval = 0;
	int lockflags;
	int cnode_locked = 0;
	int partialwrite = 0;
	int exclusive_lock = 0;

	// LP64todo - fix this! uio_resid may be 64-bit value
	resid = uio_resid(uio);
	offset = uio_offset(uio);

	if (ioflag & IO_APPEND) {
	    exclusive_lock = 1;
	}
	
	if (offset < 0)
		return (EINVAL);
	if (resid == 0)
		return (E_NONE);
	if (!vnode_isreg(vp))
		return (EPERM);  /* Can only write regular files */

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);

	eflags = kEFDeferMask;	/* defer file block allocations */
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

again:
	/* Protect against a size change. */
	hfs_lock_truncate(cp, exclusive_lock);

	if (ioflag & IO_APPEND) {
		uio_setoffset(uio, fp->ff_size);
		offset = fp->ff_size;
	}
	if ((cp->c_flags & APPEND) && offset != fp->ff_size) {
		retval = EPERM;
		goto exit;
	}

	origFileSize = fp->ff_size;
	writelimit = offset + resid;
	filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;

	/* If the truncate lock is shared, and if we either have virtual 
	 * blocks or will need to extend the file, upgrade the truncate 
	 * to exclusive lock.  If upgrade fails, we lose the lock and 
	 * have to get exclusive lock again 
	 */
	if ((exclusive_lock == 0) && 
	    ((fp->ff_unallocblocks != 0) || (writelimit > filebytes))) {
	    	exclusive_lock = 1;
		/* Lock upgrade failed and we lost our shared lock, try again */
		if (lck_rw_lock_shared_to_exclusive(&cp->c_truncatelock) == FALSE) {
			goto again;
		} 
	}

	if ( (retval = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
		goto exit;
	}
	cnode_locked = 1;
	
	if (!exclusive_lock) {
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_START,
		             (int)offset, uio_resid(uio), (int)fp->ff_size,
		             (int)filebytes, 0);
	}

	/* Check if we do not need to extend the file */
	if (writelimit <= filebytes) {
		goto sizeok;
	}

	cred = vfs_context_ucred(ap->a_context);
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
		if (cred && suser(cred, NULL) != 0)
			eflags |= kEFReserveMask;

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
		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_NONE,
			(int)offset, uio_resid(uio), (int)fp->ff_size,  (int)filebytes, 0);
	}
	(void) hfs_update(vp, TRUE);
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
		off_t zero_off;
		off_t tail_off;
		off_t inval_start;
		off_t inval_end;
		off_t io_start;
		int lflag;
		struct rl_entry *invalid_range;

		if (writelimit > fp->ff_size)
			filesize = writelimit;
		else
			filesize = fp->ff_size;

		lflag = ioflag & ~(IO_TAILZEROFILL | IO_HEADZEROFILL | IO_NOZEROVALID | IO_NOZERODIRTY);

		if (offset <= fp->ff_size) {
			zero_off = offset & ~PAGE_MASK_64;
			
			/* Check to see whether the area between the zero_offset and the start
			   of the transfer to see whether is invalid and should be zero-filled
			   as part of the transfer:
			 */
			if (offset > zero_off) {
			        if (rl_scan(&fp->ff_invalidranges, zero_off, offset - 1, &invalid_range) != RL_NOOVERLAP)
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
			inval_end = offset & ~PAGE_MASK_64;
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
				struct timeval tv;
				/* There's some range of data that's going to be marked invalid */
				
				if (zero_off < inval_start) {
					/* The pages between inval_start and inval_end are going to be invalidated,
					   and the actual write will start on a page past inval_end.  Now's the last
					   chance to zero-fill the page containing the EOF:
					 */
					hfs_unlock(cp);
					cnode_locked = 0;
					retval = cluster_write(vp, (uio_t) 0,
							fp->ff_size, inval_start,
							zero_off, (off_t)0,
							lflag | IO_HEADZEROFILL | IO_NOZERODIRTY);
					hfs_lock(cp, HFS_FORCE_LOCK);
					cnode_locked = 1;
					if (retval) goto ioerr_exit;
					offset = uio_offset(uio);
				};
				
				/* Mark the remaining area of the newly allocated space as invalid: */
				rl_add(inval_start, inval_end - 1 , &fp->ff_invalidranges);
				microuptime(&tv);
				cp->c_zftimeout = tv.tv_sec + ZFTIMELIMIT;
				zero_off = fp->ff_size = inval_end;
			};
			
			if (offset > zero_off) lflag |= IO_HEADZEROFILL;
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
		io_start = (lflag & IO_HEADZEROFILL) ? zero_off : offset;
		if (io_start < fp->ff_size) {
			off_t io_end;

			io_end = (lflag & IO_TAILZEROFILL) ? tail_off : writelimit;
			rl_remove(io_start, io_end - 1, &fp->ff_invalidranges);
		};

		hfs_unlock(cp);
		cnode_locked = 0;
		retval = cluster_write(vp, uio, fp->ff_size, filesize, zero_off,
				tail_off, lflag | IO_NOZERODIRTY);
		if (retval) {
			goto ioerr_exit;
		}
		offset = uio_offset(uio);
		if (offset > fp->ff_size) {
			fp->ff_size = offset;

			ubc_setsize(vp, fp->ff_size);       /* XXX check errors */
			/* Files that are changing size are not hot file candidates. */
			if (hfsmp->hfc_stage == HFC_RECORDING)
				fp->ff_bytesread = 0;
		}
		if (resid > uio_resid(uio)) {
			cp->c_touch_chgtime = TRUE;
			cp->c_touch_modtime = TRUE;
		}
	}
	if (partialwrite) {
		uio_setresid(uio, (uio_resid(uio) + bytesToAdd));
		resid += bytesToAdd;
	}

	// XXXdbg - see radar 4871353 for more info
	{
	    if (flush_cache_on_write && ((ioflag & IO_NOCACHE) || vnode_isnocache(vp))) {
		VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, NULL);
	    }
	}
	HFS_KNOTE(vp, NOTE_WRITE);

ioerr_exit:
	/*
	 * If we successfully wrote any data, and we are not the superuser
	 * we clear the setuid and setgid bits as a precaution against
	 * tampering.
	 */
	if (cp->c_mode & (S_ISUID | S_ISGID)) {
		cred = vfs_context_ucred(ap->a_context);
		if (resid > uio_resid(uio) && cred && suser(cred, NULL)) {
			if (!cnode_locked) {
				hfs_lock(cp, HFS_FORCE_LOCK);
				cnode_locked = 1;
			}
			cp->c_mode &= ~(S_ISUID | S_ISGID);
		}
	}
	if (retval) {
		if (ioflag & IO_UNIT) {
			if (!cnode_locked) {
				hfs_lock(cp, HFS_FORCE_LOCK);
				cnode_locked = 1;
			}
			(void)hfs_truncate(vp, origFileSize, ioflag & IO_SYNC,
			                   0, ap->a_context);
			// LP64todo - fix this!  resid needs to by user_ssize_t
			uio_setoffset(uio, (uio_offset(uio) - (resid - uio_resid(uio))));
			uio_setresid(uio, resid);
			filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;
		}
	} else if ((ioflag & IO_SYNC) && (resid > uio_resid(uio))) {
		if (!cnode_locked) {
			hfs_lock(cp, HFS_FORCE_LOCK);
			cnode_locked = 1;
		}
		retval = hfs_update(vp, TRUE);
	}
	/* Updating vcbWrCnt doesn't need to be atomic. */
	hfsmp->vcbWrCnt++;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_END,
		(int)uio_offset(uio), uio_resid(uio), (int)fp->ff_size, (int)filebytes, 0);
exit:
	if (cnode_locked)
		hfs_unlock(cp);
	hfs_unlock_truncate(cp, exclusive_lock);
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
};

struct user_access_t {
	uid_t		uid;			/* IN: effective user id */
	short		flags;			/* IN: access requested (i.e. R_OK) */
	short		num_groups;		/* IN: number of groups user belongs to */
	int		num_files;		/* IN: number of files to process */
	user_addr_t	file_ids;		/* IN: array of file ids */
	user_addr_t	groups;			/* IN: array of groups */
	user_addr_t	access;			/* OUT: access info for each file (0 for 'has access') */
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
};

struct ext_user_access_t {
	uint32_t      flags;        /* IN: access requested (i.e. R_OK) */
	uint32_t      num_files;    /* IN: number of files to process */
	uint32_t      map_size;     /* IN: size of the bit map */
	user_addr_t   file_ids;     /* IN: array of file ids */
	user_addr_t   bitmap;       /* IN: array of groups */
	user_addr_t   access;       /* OUT: access info for each file (0 for 'has access') */
	uint32_t      num_parents;/* future use */
	user_addr_t   parents;/* future use */
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
	/*printf("EGAD! numcached is %d... cut our losses and trim to %d\n",
	  cache->numcached, NUM_CACHE_ENTRIES);*/
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
	//printf("cache is full (%d). replace at index %d\n", cache->numcached, index);
	cache->numcached = NUM_CACHE_ENTRIES-1;

	if (index > cache->numcached) {
	    //    printf("index %d pinned to %d\n", index, cache->numcached);
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
snoop_callback(const struct cat_desc *descp, const struct cat_attr *attrp, void * arg)
{
    struct cinfo *cip = (struct cinfo *)arg;

    cip->uid = attrp->ca_uid;
    cip->gid = attrp->ca_gid;
    cip->mode = attrp->ca_mode;
    cip->parentcnid = descp->cd_parentcnid;
    cip->recflags = attrp->ca_recflags;
	
    return (0);
}

/*
 * Lookup the cnid's attr info (uid, gid, and mode) as well as its parent id. If the item
 * isn't incore, then go to the catalog.
 */ 
static int
do_attr_lookup(struct hfsmount *hfsmp, struct access_cache *cache, dev_t dev, cnid_t cnid, 
    struct cnode *skip_cp, CatalogKey *keyp, struct cat_attr *cnattrp)
{
    int error = 0;

    /* if this id matches the one the fsctl was called with, skip the lookup */
    if (cnid == skip_cp->c_cnid) {
	cnattrp->ca_uid = skip_cp->c_uid;
	cnattrp->ca_gid = skip_cp->c_gid;
	cnattrp->ca_mode = skip_cp->c_mode;
	keyp->hfsPlus.parentID = skip_cp->c_parentcnid;
    } else {
	struct cinfo c_info;

	/* otherwise, check the cnode hash incase the file/dir is incore */
	if (hfs_chash_snoop(dev, cnid, snoop_callback, &c_info) == 0) {
	    cnattrp->ca_uid = c_info.uid;
	    cnattrp->ca_gid = c_info.gid;
	    cnattrp->ca_mode = c_info.mode;
	    cnattrp->ca_recflags = c_info.recflags;
	    keyp->hfsPlus.parentID = c_info.parentcnid;
	} else {
	    int lockflags;
			
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
    struct cnode *skip_cp, struct proc *theProcPtr, kauth_cred_t myp_ucred, dev_t dev,
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
	myErr = do_attr_lookup(hfsmp, cache, dev, thisNodeID, skip_cp, &catkey, &cnattr);
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
	    myErr = hfs_vget(hfsmp, thisNodeID, &vp, 0);
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
		   
	    myPerms = DerivePermissionSummary(cnattr.ca_uid, cnattr.ca_gid,
		cnattr.ca_mode, hfsmp->hfs_mp,
		myp_ucred, theProcPtr);

	    if (cnattr.ca_mode & S_IFDIR) {
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
     * NOTE: on entry, the vnode is locked. Incase this vnode
     * happens to be in our list of file_ids, we'll note it
     * avoid calling hfs_chashget_nowait() on that id as that
     * will cause a "locking against myself" panic.
     */
    Boolean check_leaf = true;
		
    struct ext_user_access_t *user_access_structp;
    struct ext_user_access_t tmp_user_access;
    struct access_cache cache;
		
    int error = 0;
    unsigned int i;
		
    dev_t dev = VTOC(vp)->c_dev;
		
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
	if (arg_size != sizeof(struct ext_user_access_t)) {
	    error = EINVAL;
	    goto err_exit_bulk_access;
	}

	user_access_structp = (struct ext_user_access_t *)ap->a_data;

    } else if (arg_size == sizeof(struct access_t)) {
	struct access_t *accessp = (struct access_t *)ap->a_data;

	// convert an old style bulk-access struct to the new style
	tmp_user_access.flags     = accessp->flags;
	tmp_user_access.num_files = accessp->num_files;
	tmp_user_access.map_size  = 0;
	tmp_user_access.file_ids  = CAST_USER_ADDR_T(accessp->file_ids);
	tmp_user_access.bitmap    = USER_ADDR_NULL;
	tmp_user_access.access    = CAST_USER_ADDR_T(accessp->access);
	tmp_user_access.num_parents = 0;
	user_access_structp = &tmp_user_access;

    } else if (arg_size == sizeof(struct ext_access_t)) {
	struct ext_access_t *accessp = (struct ext_access_t *)ap->a_data;

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
	    error = do_attr_lookup(hfsmp, &cache, dev, cnid, skip_cp, &catkey, &cnattr);
	    if (error) {
		access[i] = (short) error;
		continue;
	    }
	    
	    if (parents) {
		// Check if the leaf matches one of the parent scopes
		leaf_index = cache_binSearch(parents, num_parents-1, cnid, NULL);
	    }

	    // if the thing has acl's, do the full permission check
	    if ((cnattr.ca_recflags & kHFSHasSecurityMask) != 0) {
		struct vnode *cvp;
		int myErr = 0;
		/* get the vnode for this cnid */
		myErr = hfs_vget(hfsmp, cnid, &cvp, 0);
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
	if (i > 0 && catkey.hfsPlus.parentID == prevParent_cnid && access[i-1] == 0) {
	    cache.cachehits++;
	    access[i] = 0;
	    continue;
	}
			
	myaccess = do_access_check(hfsmp, &error, &cache, catkey.hfsPlus.parentID, 
	    skip_cp, p, cred, dev, context,bitmap, map_size, parents, num_parents);
			
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
		
    //printf("on exit (err %d), numfiles/numcached/cachehits/lookups is %d/%d/%d/%d\n", error, num_files, cache.numcached, cache.cachehits, cache.lookups);
		
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
 * Callback for use with freeze ioctl.
 */
static int
hfs_freezewrite_callback(struct vnode *vp, __unused void *cargs)
{
	vnode_waitforwrites(vp, 0, 0, 0, "hfs freeze");

	return 0;
}

/*
 * Control filesystem operating characteristics.
 */
int
hfs_vnop_ioctl( struct vnop_ioctl_args /* {
		vnode_t a_vp;
		int  a_command;
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

	is64bit = proc_is64bit(p);

	switch (ap->a_command) {

	case HFS_GETPATH:
	{
		struct vnode *file_vp;
		cnid_t  cnid;
		int  outlen;
		char *bufptr;
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
		bufptr = (char *)ap->a_data;
		cnid = strtoul(bufptr, NULL, 10);

		/* We need to call hfs_vfs_vget to leverage the code that will fix the
		 * origin list for us if needed, as opposed to calling hfs_vget, since
		 * we will need it for the subsequent build_path call.  
		 */
		if ((error = hfs_vfs_vget(HFSTOVFS(hfsmp), cnid, &file_vp, context))) {
			return (error);
		}
		error = build_path(file_vp, bufptr, sizeof(pathname_t), &outlen, 0, context);
		vnode_put(file_vp);

		return (error);
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
		if ((error = hfs_lookuplink(hfsmp, linkfileid, &prevlinkid, &nextlinkid))) {
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
		return hfs_resize_progress(hfsmp, (u_int32_t *)ap->a_data);
	}

	case HFS_RESIZE_VOLUME: {
		u_int64_t newsize;
		u_int64_t cursize;

		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		if (suser(cred, NULL) &&
			kauth_cred_getuid(cred) != vfsp->f_owner) {
			return (EACCES); /* must be owner of file system */
		}
		if (!vnode_isvroot(vp)) {
			return (EINVAL);
		}
		newsize = *(u_int64_t *)ap->a_data;
		cursize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;
		
		if (newsize > cursize) {
			return hfs_extendfs(hfsmp, *(u_int64_t *)ap->a_data, context);
		} else if (newsize < cursize) {
			return hfs_truncatefs(hfsmp, *(u_int64_t *)ap->a_data, context);
		} else {
			return (0);
		}
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
		HFS_MOUNT_LOCK(hfsmp, TRUE);
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
			HFS_UPDATE_NEXT_ALLOCATION(hfsmp, hfsmp->hfs_metazone_end + 1);
			hfsmp->hfs_flags |= HFS_SKIP_UPDATE_NEXT_ALLOCATION; 
		} else {
			hfsmp->hfs_flags &= ~HFS_SKIP_UPDATE_NEXT_ALLOCATION; 
			HFS_UPDATE_NEXT_ALLOCATION(hfsmp, location);
		}
		MarkVCBDirty(hfsmp);
fail_change_next_allocation:
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		return (error);
	}

#ifdef HFS_SPARSE_DEV
	case HFS_SETBACKINGSTOREINFO: {
		struct vnode * bsfs_rootvp;
		struct vnode * di_vp;
		struct hfs_backingstoreinfo *bsdata;
		int error = 0;
		
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

		hfsmp->hfs_backingfs_rootvp = bsfs_rootvp;
		hfsmp->hfs_flags |= HFS_HAS_SPARSE_DEVICE;
		hfsmp->hfs_sparsebandblks = bsdata->bandsize / HFSTOVCB(hfsmp)->blockSize;
		hfsmp->hfs_sparsebandblks *= 4;

		vfs_markdependency(hfsmp->hfs_mp);

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
		if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) &&
		    hfsmp->hfs_backingfs_rootvp) {

			hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
			tmpvp = hfsmp->hfs_backingfs_rootvp;
			hfsmp->hfs_backingfs_rootvp = NULLVP;
			hfsmp->hfs_sparsebandblks = 0;
			vnode_rele(tmpvp);
		}
		return (0);
	}
#endif /* HFS_SPARSE_DEV */

	case F_FREEZE_FS: {
		struct mount *mp;
 
		if (!is_suser())
			return (EACCES);

		mp = vnode_mount(vp);
		hfsmp = VFSTOHFS(mp);

		if (!(hfsmp->jnl))
			return (ENOTSUP);

		lck_rw_lock_exclusive(&hfsmp->hfs_insync);
 
		// flush things before we get started to try and prevent
		// dirty data from being paged out while we're frozen.
		// note: can't do this after taking the lock as it will
		// deadlock against ourselves.
		vnode_iterate(mp, 0, hfs_freezewrite_callback, NULL);
		hfs_global_exclusive_lock_acquire(hfsmp);
		journal_flush(hfsmp->jnl);

		// don't need to iterate on all vnodes, we just need to
		// wait for writes to the system files and the device vnode
		if (HFSTOVCB(hfsmp)->extentsRefNum)
		    vnode_waitforwrites(HFSTOVCB(hfsmp)->extentsRefNum, 0, 0, 0, "hfs freeze");
		if (HFSTOVCB(hfsmp)->catalogRefNum)
		    vnode_waitforwrites(HFSTOVCB(hfsmp)->catalogRefNum, 0, 0, 0, "hfs freeze");
		if (HFSTOVCB(hfsmp)->allocationsRefNum)
		    vnode_waitforwrites(HFSTOVCB(hfsmp)->allocationsRefNum, 0, 0, 0, "hfs freeze");
		if (hfsmp->hfs_attribute_vp)
		    vnode_waitforwrites(hfsmp->hfs_attribute_vp, 0, 0, 0, "hfs freeze");
		vnode_waitforwrites(hfsmp->hfs_devvp, 0, 0, 0, "hfs freeze");

		hfsmp->hfs_freezing_proc = current_proc();

		return (0);
	}

	case F_THAW_FS: {
		if (!is_suser())
			return (EACCES);

		// if we're not the one who froze the fs then we
		// can't thaw it.
		if (hfsmp->hfs_freezing_proc != current_proc()) {
		    return EPERM;
		}

		// NOTE: if you add code here, also go check the
		//       code that "thaws" the fs in hfs_vnop_close()
		//
		hfsmp->hfs_freezing_proc = NULL;
		hfs_global_exclusive_lock_release(hfsmp);
		lck_rw_unlock_exclusive(&hfsmp->hfs_insync);

		return (0);
	}

	case HFS_BULKACCESS_FSCTL: {
	    int size;
	    
	    if (hfsmp->hfs_flags & HFS_STANDARD) {
		return EINVAL;
	    }

	    if (is64bit) {
		size = sizeof(struct user_access_t);
	    } else {
		size = sizeof(struct access_t);
	    }
	    
	    return do_bulk_access_check(hfsmp, vp, ap, size, context);
	} 

	case HFS_EXT_BULKACCESS_FSCTL: {
	    int size;
	    
	    if (hfsmp->hfs_flags & HFS_STANDARD) {
		return EINVAL;
	    }

	    if (is64bit) {
		size = sizeof(struct ext_user_access_t);
	    } else {
		size = sizeof(struct ext_access_t);
	    }
	    
	    return do_bulk_access_check(hfsmp, vp, ap, size, context);
	} 

	case HFS_SETACLSTATE: {
		int state;

		if (ap->a_data == NULL) {
			return (EINVAL);
		}

		vfsp = vfs_statfs(HFSTOVFS(hfsmp));
		state = *(int *)ap->a_data;

		// super-user can enable or disable acl's on a volume.
		// the volume owner can only enable acl's
		if (!is_suser() && (state == 0 || kauth_cred_getuid(cred) != vfsp->f_owner)) {
			return (EPERM);
		}
		if (state == 0 || state == 1)
			return hfs_set_volxattr(hfsmp, HFS_SETACLSTATE, state);
		else
			return (EINVAL);	
	}

	case HFS_SET_XATTREXTENTS_STATE: {
		int state;

		if (ap->a_data == NULL) {
			return (EINVAL);
		}

		state = *(int *)ap->a_data;

		/* Super-user can enable or disable extent-based extended 
		 * attribute support on a volume 
		 */
		if (!is_suser()) {
			return (EPERM);
		}
		if (state == 0 || state == 1)
			return hfs_set_volxattr(hfsmp, HFS_SET_XATTREXTENTS_STATE, state);
		else
			return (EINVAL);	
	}

	case F_FULLFSYNC: {
		int error;

		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
		if (error == 0) {
			error = hfs_fsync(vp, MNT_WAIT, TRUE, p);
			hfs_unlock(VTOC(vp));
		}

		return error;
	}

	case F_CHKCLEAN: {
		register struct cnode *cp;
		int error;

		if (!vnode_isreg(vp))
			return EINVAL;
 
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
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
		hfs_lock_truncate(VTOC(vp), TRUE);

		if (ra->ra_offset >= fp->ff_size) {
			error = EFBIG;
		} else {
			error = advisory_read(vp, fp->ff_size, ra->ra_offset, ra->ra_count);
		}

		hfs_unlock_truncate(VTOC(vp), TRUE);
		return (error);
	}

	case F_READBOOTSTRAP:
	case F_WRITEBOOTSTRAP:
	{
	    struct vnode *devvp = NULL;
	    user_fbootstraptransfer_t *user_bootstrapp;
	    int devBlockSize;
	    int error;
	    uio_t auio;
	    daddr64_t blockNumber;
	    u_long blockOffset;
	    u_long xfersize;
	    struct buf *bp;
	    user_fbootstraptransfer_t user_bootstrap;

		if (!vnode_isvroot(vp))
			return (EINVAL);
		/* LP64 - when caller is a 64 bit process then we are passed a pointer 
		 * to a user_fbootstraptransfer_t else we get a pointer to a 
		 * fbootstraptransfer_t which we munge into a user_fbootstraptransfer_t
		 */
		if (is64bit) {
			user_bootstrapp = (user_fbootstraptransfer_t *)ap->a_data;
		}
		else {
	    	fbootstraptransfer_t *bootstrapp = (fbootstraptransfer_t *)ap->a_data;
			user_bootstrapp = &user_bootstrap;
			user_bootstrap.fbt_offset = bootstrapp->fbt_offset;
			user_bootstrap.fbt_length = bootstrapp->fbt_length;
			user_bootstrap.fbt_buffer = CAST_USER_ADDR_T(bootstrapp->fbt_buffer);
		}
		if (user_bootstrapp->fbt_offset + user_bootstrapp->fbt_length > 1024) 
			return EINVAL;
	    
	    devvp = VTOHFS(vp)->hfs_devvp;
		auio = uio_create(1, user_bootstrapp->fbt_offset, 
						  is64bit ? UIO_USERSPACE64 : UIO_USERSPACE32,
						  (ap->a_command == F_WRITEBOOTSTRAP) ? UIO_WRITE : UIO_READ);
		uio_addiov(auio, user_bootstrapp->fbt_buffer, user_bootstrapp->fbt_length);

	    devBlockSize = vfs_devblocksize(vnode_mount(vp));

	    while (uio_resid(auio) > 0) {
			blockNumber = uio_offset(auio) / devBlockSize;
			error = (int)buf_bread(devvp, blockNumber, devBlockSize, cred, &bp);
			if (error) {
				if (bp) buf_brelse(bp);
				uio_free(auio);
				return error;
			};

			blockOffset = uio_offset(auio) % devBlockSize;
			xfersize = devBlockSize - blockOffset;
			error = uiomove((caddr_t)buf_dataptr(bp) + blockOffset, (int)xfersize, auio);
			if (error) {
				buf_brelse(bp);
				uio_free(auio);
				return error;
			};
			if (uio_rw(auio) == UIO_WRITE) {
				error = VNOP_BWRITE(bp);
				if (error) {
					uio_free(auio);
                  	return error;
				}
			} else {
				buf_brelse(bp);
			};
		};
		uio_free(auio);
	};
	return 0;

	case _IOC(IOC_OUT,'h', 4, 0):     /* Create date in local time */
	{
		if (is64bit) {
			*(user_time_t *)(ap->a_data) = (user_time_t) (to_bsd_time(VTOVCB(vp)->localCreateDate));
		}
		else {
			*(time_t *)(ap->a_data) = to_bsd_time(VTOVCB(vp)->localCreateDate);
		}
		return 0;
	}

	case HFS_GET_MOUNT_TIME:
	    return copyout(&hfsmp->hfs_mount_time, CAST_USER_ADDR_T(ap->a_data), sizeof(hfsmp->hfs_mount_time));
	    break;

	case HFS_GET_LAST_MTIME:
	    return copyout(&hfsmp->hfs_last_mounted_mtime, CAST_USER_ADDR_T(ap->a_data), sizeof(hfsmp->hfs_last_mounted_mtime));
	    break;

	case HFS_SET_BOOT_INFO:
		if (!vnode_isvroot(vp))
			return(EINVAL);
		if (!kauth_cred_issuser(cred) && (kauth_cred_getuid(cred) != vfs_statfs(HFSTOVFS(hfsmp))->f_owner))
			return(EACCES);	/* must be superuser or owner of filesystem */
		HFS_MOUNT_LOCK(hfsmp, TRUE);
		bcopy(ap->a_data, &hfsmp->vcbFndrInfo, sizeof(hfsmp->vcbFndrInfo));
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
		break;
		
	case HFS_GET_BOOT_INFO:
		if (!vnode_isvroot(vp))
			return(EINVAL);
		HFS_MOUNT_LOCK(hfsmp, TRUE);
		bcopy(&hfsmp->vcbFndrInfo, ap->a_data, sizeof(hfsmp->vcbFndrInfo));
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		break;

	case HFS_MARK_BOOT_CORRUPT:
		/* Mark the boot volume corrupt by setting 
		 * kHFSVolumeInconsistentBit in the volume header.  This will 
		 * force fsck_hfs on next mount.
		 */
		if (!is_suser()) {
			return EACCES;
		}
		
		/* Allowed only on the root vnode of the boot volume */
		if (!(vfs_flags(HFSTOVFS(hfsmp)) & MNT_ROOTFS) || 
		    !vnode_isvroot(vp)) {
			return EINVAL;
		}

		printf ("hfs_vnop_ioctl: Marking the boot volume corrupt.\n");
		hfs_mark_volume_inconsistent(hfsmp);
		break;

	default:
		return (ENOTTY);
	}

    /* Should never get here */
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
	size_t bytesContAvail = 0;
	int retval = E_NONE;
	int syslocks = 0;
	int lockflags = 0;
	struct rl_entry *invalid_range;
	enum rl_overlaptype overlaptype;
	int started_tr = 0;
	int tooklock = 0;

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

	if ( !vnode_issystem(vp) && !vnode_islnk(vp) && !vnode_isswap(vp)) {
		if (VTOC(vp)->c_lockowner != current_thread()) {
			hfs_lock(VTOC(vp), HFS_FORCE_LOCK);
			tooklock = 1;
		}
	}
	hfsmp = VTOHFS(vp);
	cp = VTOC(vp);
	fp = VTOF(vp);

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

			HFS_MOUNT_LOCK(hfsmp, TRUE);
			hfsmp->loanedBlocks += loanedBlocks;
			HFS_MOUNT_UNLOCK(hfsmp, TRUE);

			hfs_systemfile_unlock(hfsmp, lockflags);
			cp->c_flag |= C_MODIFIED;
			if (started_tr) {
				(void) hfs_update(vp, TRUE);
				(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);

				hfs_end_transaction(hfsmp);
				started_tr = 0;
			}
			goto exit;
		}
	}

	retval = MapFileBlockC(hfsmp, (FCB *)fp, ap->a_size, ap->a_foffset,
	                       ap->a_bpn, &bytesContAvail);
	if (syslocks) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		syslocks = 0;
	}

	if (started_tr) {
		(void) hfs_update(vp, TRUE);
		(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		hfs_end_transaction(hfsmp);
		started_tr = 0;
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
		if (ap->a_foffset > fp->ff_size) {
		    	goto exit;
		}

		/* Searching file extents has failed for read operation, therefore 
		 * search rangelist for any uncommitted holes in the file. 
		 */
		overlaptype = rl_scan(&fp->ff_invalidranges, ap->a_foffset,
	        	              ap->a_foffset + (off_t)(ap->a_size - 1),
	                	      &invalid_range);
		switch(overlaptype) {
		case RL_OVERLAPISCONTAINED:
			/* start_offset <= rl_start, end_offset >= rl_end */
			if (ap->a_foffset != invalid_range->rl_start) {
				break;
			}
		case RL_MATCHINGOVERLAP:
			/* start_offset = rl_start, end_offset = rl_end */
		case RL_OVERLAPCONTAINSRANGE:
			/* start_offset >= rl_start, end_offset <= rl_end */
		case RL_OVERLAPSTARTSBEFORE:
			/* start_offset > rl_start, end_offset >= rl_start */
			if ((off_t)fp->ff_size > (invalid_range->rl_end + 1)) {
				bytesContAvail = (invalid_range->rl_end + 1) - ap->a_foffset;
			} else {
				bytesContAvail = fp->ff_size - ap->a_foffset;
			}
			if (bytesContAvail > ap->a_size) {
				bytesContAvail = ap->a_size;
			}
			*ap->a_bpn = (daddr64_t)-1;
			retval = 0;
			break;
		case RL_OVERLAPENDSAFTER:
			/* start_offset < rl_start, end_offset < rl_end */
		case RL_NOOVERLAP:
			break;
		}
		goto exit;
	}

	/* MapFileC() found a valid extent in the filefork.  Search the 
	 * mapping information further for invalid file ranges 
	 */
	overlaptype = rl_scan(&fp->ff_invalidranges, ap->a_foffset,
	                      ap->a_foffset + (off_t)bytesContAvail - 1,
	                      &invalid_range);
	if (overlaptype != RL_NOOVERLAP) {
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
			    (invalid_range->rl_end + 1 - ap->a_foffset < bytesContAvail)) {
				bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
			}
			break;
	
		case RL_OVERLAPISCONTAINED:
		case RL_OVERLAPENDSAFTER:
			/* The range of interest hits an invalid block before the end: */
			if (invalid_range->rl_start == ap->a_foffset) {
				/* There's actually no valid information to be had starting here: */
				*ap->a_bpn = (daddr64_t)-1;
				if (((off_t)fp->ff_size > (invalid_range->rl_end + 1)) &&
				    (invalid_range->rl_end + 1 - ap->a_foffset < bytesContAvail)) {
					bytesContAvail = invalid_range->rl_end + 1 - ap->a_foffset;
				}
			} else {
				bytesContAvail = invalid_range->rl_start - ap->a_foffset;
			}
			break;

		case RL_NOOVERLAP:
			break;
		} /* end switch */
		if (bytesContAvail > ap->a_size)
			bytesContAvail = ap->a_size;
	} 
		
exit:
	if (retval == 0) {
		if (ap->a_run)
			*ap->a_run = bytesContAvail;

		if (ap->a_poff)
			*(int *)ap->a_poff = 0;
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

	return (buf_strategy(VTOHFS(vp)->hfs_devvp, ap));
}


static int
do_hfs_truncate(struct vnode *vp, off_t length, int flags, vfs_context_t context)
{
	register struct cnode *cp = VTOC(vp);
    	struct filefork *fp = VTOF(vp);
	struct proc *p = vfs_context_proc(context);;
	kauth_cred_t cred = vfs_context_ucred(context);
	int retval;
	off_t bytesToAdd;
	off_t actualBytesAdded;
	off_t filebytes;
	u_long fileblocks;
	int blksize;
	struct hfsmount *hfsmp;
	int lockflags;

	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_START,
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
			u_long blockHint = 0;

			/* All or nothing and don't round up to clumpsize. */
			eflags = kEFAllMask | kEFNoClumpMask;

			if (cred && suser(cred, NULL) != 0)
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
			if (hfs_start_transaction(hfsmp) != 0) {
			    retval = EINVAL;
			    goto Err_Exit;
			}

			/* Protect extents b-tree and allocation bitmap */
			lockflags = SFL_BITMAP;
			if (overflow_extents(fp))
				lockflags |= SFL_EXTENTS;
			lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

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
			    (void) hfs_update(vp, TRUE);
			    (void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
			}

			hfs_end_transaction(hfsmp);

			if (retval)
				goto Err_Exit;

			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_NONE,
				(int)length, (int)fp->ff_size, (int)filebytes, 0, 0);
		}
 
		if (!(flags & IO_NOZEROFILL)) {
			if (UBCINFOEXISTS(vp)  && (vnode_issystem(vp) == 0) && retval == E_NONE) {
				struct rl_entry *invalid_range;
				off_t zero_limit;
			
				zero_limit = (fp->ff_size + (PAGE_SIZE_64 - 1)) & ~PAGE_MASK_64;
				if (length < zero_limit) zero_limit = length;

				if (length > (off_t)fp->ff_size) {
					struct timeval tv;

		   			/* Extending the file: time to fill out the current last page w. zeroes? */
		   			if ((fp->ff_size & PAGE_MASK_64) &&
					    (rl_scan(&fp->ff_invalidranges, fp->ff_size & ~PAGE_MASK_64,
					    fp->ff_size - 1, &invalid_range) == RL_NOOVERLAP)) {
		   				
						/* There's some valid data at the start of the (current) last page
						   of the file, so zero out the remainder of that page to ensure the
						   entire page contains valid data.  Since there is no invalid range
						   possible past the (current) eof, there's no need to remove anything
						   from the invalid range list before calling cluster_write():	*/
						hfs_unlock(cp);
						retval = cluster_write(vp, (struct uio *) 0, fp->ff_size, zero_limit,
								fp->ff_size, (off_t)0,
								(flags & IO_SYNC) | IO_HEADZEROFILL | IO_NOZERODIRTY);
						hfs_lock(cp, HFS_FORCE_LOCK);
						if (retval) goto Err_Exit;
						
						/* Merely invalidate the remaining area, if necessary: */
						if (length > zero_limit) {
							microuptime(&tv);
							rl_add(zero_limit, length - 1, &fp->ff_invalidranges);
							cp->c_zftimeout = tv.tv_sec + ZFTIMELIMIT;
						}
		   			} else {
					/* The page containing the (current) eof is invalid: just add the
					   remainder of the page to the invalid list, along with the area
					   being newly allocated:
					 */
					microuptime(&tv);
					rl_add(fp->ff_size, length - 1, &fp->ff_invalidranges);
					cp->c_zftimeout = tv.tv_sec + ZFTIMELIMIT;
					};
				}
			} else {
					panic("hfs_truncate: invoked on non-UBC object?!");
			};
		}
		cp->c_touch_modtime = TRUE;
		fp->ff_size = length;

	} else { /* Shorten the size of the file */

		if ((off_t)fp->ff_size > length) {
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

			HFS_MOUNT_LOCK(hfsmp, TRUE);

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
			HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		}

		/*
		 * For a TBE process the deallocation of the file blocks is
		 * delayed until the file is closed.  And hfs_close calls
		 * truncate with the IO_NDELAY flag set.  So when IO_NDELAY
		 * isn't set, we make sure this isn't a TBE process.
		 */
		if ((flags & IO_NDELAY) || (proc_tbe(p) == 0)) {
#if QUOTA
		  off_t savedbytes = ((off_t)fp->ff_blocks * (off_t)blksize);
#endif /* QUOTA */
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

				retval = MacToVFSError(TruncateFileC(VTOVCB(vp),
						(FCB*)fp, length, false));

				hfs_systemfile_unlock(hfsmp, lockflags);
			}
			if (hfsmp->jnl) {
				if (retval == 0) {
					fp->ff_size = length;
				}
				(void) hfs_update(vp, TRUE);
				(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
			}

			hfs_end_transaction(hfsmp);

			filebytes = (off_t)fp->ff_blocks * (off_t)blksize;
			if (retval)
				goto Err_Exit;
#if QUOTA
			/* These are bytesreleased */
			(void) hfs_chkdq(cp, (int64_t)-(savedbytes - filebytes), NOCRED, 0);
#endif /* QUOTA */
		}
		/* Only set update flag if the logical length changes */
		if ((off_t)fp->ff_size != length)
			cp->c_touch_modtime = TRUE;
		fp->ff_size = length;
	}
	cp->c_touch_chgtime = TRUE;	/* status changed */
	cp->c_touch_modtime = TRUE;	/* file data was modified */
	retval = hfs_update(vp, MNT_WAIT);
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
 * Truncate a cnode to at most length size, freeing (or adding) the
 * disk blocks.
 */
__private_extern__
int
hfs_truncate(struct vnode *vp, off_t length, int flags, int skipsetsize,
             vfs_context_t context)
{
    	struct filefork *fp = VTOF(vp);
	off_t filebytes;
	u_long fileblocks;
	int blksize, error = 0;
	struct cnode *cp = VTOC(vp);

	/* Cannot truncate an HFS directory! */
	if (vnode_isdir(vp)) {
		return (EISDIR);
	}
	/* A swap file cannot change size. */
	if (vnode_isswap(vp) && (length != 0)) {
		return (EPERM);
	}

	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

	//
	// Have to do this here so that we don't wind up with
	// i/o pending for blocks that are about to be released
	// if we truncate the file.
	//
	// If skipsetsize is set, then the caller is responsible
	// for the ubc_setsize.
	//
	if (!skipsetsize)
		ubc_setsize(vp, length);

	// have to loop truncating or growing files that are
	// really big because otherwise transactions can get
	// enormous and consume too many kernel resources.

	if (length < filebytes) {
		while (filebytes > length) {
			if ((filebytes - length) > HFS_BIGFILE_SIZE && overflow_extents(fp)) {
		    		filebytes -= HFS_BIGFILE_SIZE;
			} else {
		    		filebytes = length;
			}
			cp->c_flag |= C_FORCEUPDATE;
			error = do_hfs_truncate(vp, filebytes, flags, context);
			if (error)
				break;
		}
	} else if (length > filebytes) {
		while (filebytes < length) {
			if ((length - filebytes) > HFS_BIGFILE_SIZE && overflow_extents(fp)) {
				filebytes += HFS_BIGFILE_SIZE;
			} else {
				filebytes = length;
			}
			cp->c_flag |= C_FORCEUPDATE;
			error = do_hfs_truncate(vp, filebytes, flags, context);
			if (error)
				break;
		}
	} else /* Same logical size */ {

		error = do_hfs_truncate(vp, length, flags, context);
	}
	/* Files that are changing size are not hot file candidates. */
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING) {
		fp->ff_bytesread = 0;
	}

	return (error);
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
	u_long fileblocks;
	int retval, retval2;
	u_int32_t blockHint;
	u_int32_t extendFlags;   /* For call to ExtendFileC */
	struct hfsmount *hfsmp;
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	int lockflags;

	*(ap->a_bytesallocated) = 0;

	if (!vnode_isreg(vp))
		return (EISDIR);
	if (length < (off_t)0)
		return (EINVAL);
	
	cp = VTOC(vp);

	hfs_lock_truncate(cp, TRUE);

	if ((retval = hfs_lock(cp, HFS_EXCLUSIVE_LOCK))) {
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
			(void) hfs_update(vp, TRUE);
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

		if (fp->ff_size > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).
			 */
		}

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

			hfs_unlock(cp);
			ubc_setsize(vp, fp->ff_size);
			hfs_lock(cp, HFS_FORCE_LOCK);
		}
	}

Std_Exit:
	cp->c_touch_chgtime = TRUE;
	cp->c_touch_modtime = TRUE;
	retval2 = hfs_update(vp, MNT_WAIT);

	if (retval == 0)
		retval = retval2;
Err_Exit:
	hfs_unlock_truncate(cp, TRUE);
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
	vnode_t vp = ap->a_vp;
	int error;

	error = cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
	                       ap->a_size, (off_t)VTOF(vp)->ff_size, ap->a_flags);
	/*
	 * Keep track of blocks read.
	 */
	if (!vnode_isswap(vp) && VTOHFS(vp)->hfc_stage == HFC_RECORDING && error == 0) {
		struct cnode *cp;
		struct filefork *fp;
		int bytesread;
		int took_cnode_lock = 0;
		
		cp = VTOC(vp);
		fp = VTOF(vp);

		if (ap->a_f_offset == 0 && fp->ff_size < PAGE_SIZE)
			bytesread = fp->ff_size;
		else
			bytesread = ap->a_size;

		/* When ff_bytesread exceeds 32-bits, update it behind the cnode lock. */
		if ((fp->ff_bytesread + bytesread) > 0x00000000ffffffff && cp->c_lockowner != current_thread()) {
			hfs_lock(cp, HFS_FORCE_LOCK);
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
		if (took_cnode_lock)
			hfs_unlock(cp);
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
	int retval;
	off_t filesize;

	cp = VTOC(vp);
	fp = VTOF(vp);
	
	if (vnode_isswap(vp)) {
		filesize = fp->ff_size;
	} else {
		off_t end_of_range;
		int tooklock = 0;

		if (cp->c_lockowner != current_thread()) {
		    if ( (retval = hfs_lock(cp, HFS_EXCLUSIVE_LOCK))) {
			if (!(ap->a_flags & UPL_NOCOMMIT)) {
				ubc_upl_abort_range(ap->a_pl,
						    ap->a_pl_offset,
						    ap->a_size,
						    UPL_ABORT_FREE_ON_EMPTY);
			}
			return (retval);
		    }
		    tooklock = 1;
		}
	
		filesize = fp->ff_size;
		end_of_range = ap->a_f_offset + ap->a_size - 1;
	
		if (end_of_range >= filesize) {
			end_of_range = (off_t)(filesize - 1);
		}
		if (ap->a_f_offset < filesize) {
			rl_remove(ap->a_f_offset, end_of_range, &fp->ff_invalidranges);
			cp->c_flag |= C_MODIFIED;  /* leof is dirty */
		}

		if (tooklock) {
		    hfs_unlock(cp);
		}
	}

	retval = cluster_pageout(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset,
	                         ap->a_size, filesize, ap->a_flags);

	/*
	 * If data was written, and setuid or setgid bits are set and
	 * this process is not the superuser then clear the setuid and
	 * setgid bits as a precaution against tampering.
	 */
	if ((retval == 0) &&
	    (cp->c_mode & (S_ISUID | S_ISGID)) &&
	    (vfs_context_suser(ap->a_context) != 0)) {
		hfs_lock(cp, HFS_FORCE_LOCK);
		cp->c_mode &= ~(S_ISUID | S_ISGID);
		cp->c_touch_chgtime = TRUE;
		hfs_unlock(cp);
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
__private_extern__
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
	if (vnodetype != VREG && vnodetype != VLNK) {
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
	blksize = hfsmp->blockSize;
	if (blockHint == 0)
		blockHint = hfsmp->nextAllocation;

	if ((fp->ff_size > 0x7fffffff) ||
	    ((fp->ff_size > blksize) && vnodetype == VLNK)) {
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
		hfs_lock_truncate(cp, TRUE);
		/* Force lock since callers expects lock to be held. */
		if ((retval = hfs_lock(cp, HFS_FORCE_LOCK))) {
			hfs_unlock_truncate(cp, TRUE);
			return (retval);
		}
		/* No need to continue if file was removed. */
		if (cp->c_flag & C_NOEXISTS) {
			hfs_unlock_truncate(cp, TRUE);
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
			hfs_unlock_truncate(cp, TRUE);
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
		HFS_MOUNT_LOCK(hfsmp, TRUE);
		HFS_UPDATE_NEXT_ALLOCATION(hfsmp, nextallocsave);
		MarkVCBDirty(hfsmp);
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
	}

	retval = MacToVFSError(retval);
	if (retval == 0) {
		cp->c_flag |= C_MODIFIED;
		if (newbytes < growsize) {
			retval = ENOSPC;
			goto restore;
		} else if (fp->ff_blocks < (headblks + datablks)) {
			printf("hfs_relocate: allocation failed");
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
		           ((((u_int64_t)sector_b * hfsmp->hfs_phys_block_size) / blksize) >
		              hfsmp->hfs_metazone_end)) {
			const char * filestr;
			char emptystr = '\0';

			if (cp->c_desc.cd_nameptr != NULL) {
				filestr = (const char *)&cp->c_desc.cd_nameptr[0];
			} else if (vnode_name(vp) != NULL) {
				filestr = vnode_name(vp);
			} else {
				filestr = &emptystr;
			}
			printf("hfs_relocate: %s didn't move into MDZ (%d blks)\n", filestr, fp->ff_blocks);
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
		retval = hfs_clonelink(vp, blksize, cred, p);
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
		hfs_unlock_truncate(cp, TRUE);

	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		lockflags = 0;
	}

	/* Push cnode's new extent data to disk. */
	if (retval == 0) {
		(void) hfs_update(vp, MNT_WAIT);
	}
	if (hfsmp->jnl) {
		if (cp->c_cnid < kHFSFirstUserCatalogNodeID)
			(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
		else
			(void) hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
	}
exit:
	if (started_tr)
		hfs_end_transaction(hfsmp);

	return (retval);

restore:
	if (fp->ff_blocks == headblks) {
		if (took_trunc_lock)
			hfs_unlock_truncate(cp, TRUE);
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

	(void) TruncateFileC(hfsmp, (FCB*)fp, fp->ff_size, false);

	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;

	if (took_trunc_lock)
		hfs_unlock_truncate(cp, TRUE);
	goto exit;
}


/*
 * Clone a symlink.
 *
 */
static int
hfs_clonelink(struct vnode *vp, int blksize, kauth_cred_t cred, __unused struct proc *p)
{
	struct buf *head_bp = NULL;
	struct buf *tail_bp = NULL;
	int error;


	error = (int)buf_meta_bread(vp, (daddr64_t)0, blksize, cred, &head_bp);
	if (error)
		goto out;

	tail_bp = buf_getblk(vp, (daddr64_t)1, blksize, 0, 0, BLK_META);
	if (tail_bp == NULL) {
		error = EIO;
		goto out;
	}
	bcopy((char *)buf_dataptr(head_bp), (char *)buf_dataptr(tail_bp), blksize);
	error = (int)buf_bwrite(tail_bp);
out:
	if (head_bp) {
	        buf_markinvalid(head_bp);
		buf_brelse(head_bp);
	}	
	(void) buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0);

	return (error);
}

/*
 * Clone a file's data within the file.
 *
 */
static int
hfs_clonefile(struct vnode *vp, int blkstart, int blkcnt, int blksize)
{
	caddr_t  bufp;
	size_t  writebase;
	size_t  bufsize;
	size_t  copysize;
        size_t  iosize;
	off_t	filesize;
	size_t  offset;
	uio_t auio;
	int  error = 0;

	filesize = VTOF(vp)->ff_blocks * blksize;  /* virtual file size */
	writebase = blkstart * blksize;
	copysize = blkcnt * blksize;
	iosize = bufsize = MIN(copysize, 128 * 1024);
	offset = 0;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize)) {
		return (ENOMEM);
	}	
	hfs_unlock(VTOC(vp));

	auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);

	while (offset < copysize) {
		iosize = MIN(copysize - offset, iosize);

		uio_reset(auio, offset, UIO_SYSSPACE32, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufp, iosize);

		error = cluster_read(vp, auio, copysize, IO_NOCACHE);
		if (error) {
			printf("hfs_clonefile: cluster_read failed - %d\n", error);
			break;
		}
		if (uio_resid(auio) != 0) {
			printf("clonedata: cluster_read: uio_resid = %lld\n", uio_resid(auio));
			error = EIO;		
			break;
		}

		uio_reset(auio, writebase + offset, UIO_SYSSPACE32, UIO_WRITE);
		uio_addiov(auio, (uintptr_t)bufp, iosize);

		error = cluster_write(vp, auio, filesize + offset,
		                      filesize + offset + iosize,
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

	/*
	 * No need to call ubc_sync_range or hfs_invalbuf
	 * since the file was copied using IO_NOCACHE.
	 */

	kmem_free(kernel_map, (vm_offset_t)bufp, bufsize);

	hfs_lock(VTOC(vp), HFS_FORCE_LOCK);	
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

	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufp, bufsize)) {
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
