/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/vfs_context.h>

#include <miscfs/specfs/specdev.h>

#include <sys/ubc.h>
#include <vm/vm_pageout.h>
#include <vm/vm_kern.h>

#include <sys/kdebug.h>

#include	"hfs.h"
#include	"hfs_endian.h"
#include  "hfs_fsctl.h"
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

extern int  hfs_setextendedsecurity(struct hfsmount *, int);


static int  hfs_clonelink(struct vnode *, int, kauth_cred_t, struct proc *);
static int  hfs_clonefile(struct vnode *, int, int, int);
static int  hfs_clonesysfile(struct vnode *, int, int, int, kauth_cred_t, struct proc *);


/*****************************************************************************
*
*	I/O Operations on vnodes
*
*****************************************************************************/
int  hfs_vnop_read(struct vnop_read_args *);
int  hfs_vnop_write(struct vnop_write_args *);
int  hfs_vnop_ioctl(struct vnop_ioctl_args *);
int  hfs_vnop_select(struct vnop_select_args *);
int  hfs_vnop_blktooff(struct vnop_blktooff_args *);
int  hfs_vnop_offtoblk(struct vnop_offtoblk_args *);
int  hfs_vnop_blockmap(struct vnop_blockmap_args *);
int  hfs_vnop_strategy(struct vnop_strategy_args *);
int  hfs_vnop_allocate(struct vnop_allocate_args *);
int  hfs_vnop_pagein(struct vnop_pagein_args *);
int  hfs_vnop_pageout(struct vnop_pageout_args *);
int  hfs_vnop_bwrite(struct vnop_bwrite_args *);


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

	retval = cluster_read(vp, uio, filesize, 0);

	cp->c_touch_acctime = TRUE;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 12)) | DBG_FUNC_END,
		(int)uio_offset(uio), uio_resid(uio), (int)filesize,  (int)filebytes, 0);

	/*
	 * Keep track blocks read
	 */
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING && retval == 0) {
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
		if (cp->c_atime < VTOHFS(vp)->hfc_timebase) {
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
	hfs_unlock_truncate(cp);
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
	off_t bytesToAdd;
	off_t actualBytesAdded;
	off_t filebytes;
	off_t offset;
	size_t resid;
	int eflags;
	int ioflag = ap->a_ioflag;
	int retval = 0;
	int lockflags;
	int cnode_locked = 0;

	// LP64todo - fix this! uio_resid may be 64-bit value
	resid = uio_resid(uio);
	offset = uio_offset(uio);

	if (offset < 0)
		return (EINVAL);
	if (resid == 0)
		return (E_NONE);
	if (!vnode_isreg(vp))
		return (EPERM);  /* Can only write regular files */

	/* Protect against a size change. */
	hfs_lock_truncate(VTOC(vp), TRUE);

	if ( (retval = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
		hfs_unlock_truncate(VTOC(vp));
		return (retval);
	}
	cnode_locked = 1;
	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);
	filebytes = (off_t)fp->ff_blocks * (off_t)hfsmp->blockSize;

	if (ioflag & IO_APPEND) {
		uio_setoffset(uio, fp->ff_size);
		offset = fp->ff_size;
	}
	if ((cp->c_flags & APPEND) && offset != fp->ff_size) {
		retval = EPERM;
		goto exit;
	}

	origFileSize = fp->ff_size;
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

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 0)) | DBG_FUNC_START,
		(int)offset, uio_resid(uio), (int)fp->ff_size, (int)filebytes, 0);

	/* Now test if we need to extend the file */
	/* Doing so will adjust the filebytes for us */

	writelimit = offset + resid;
	if (writelimit <= filebytes)
		goto sizeok;

	cred = vfs_context_ucred(ap->a_context);
#if QUOTA
	bytesToAdd = writelimit - filebytes;
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

		lflag = (ioflag & IO_SYNC);

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
	hfs_unlock_truncate(cp);
	return (retval);
}

/* support for the "bulk-access" fcntl */

#define CACHE_ELEMS 64
#define CACHE_LEVELS 16
#define PARENT_IDS_FLAG 0x100

/* from hfs_attrlist.c */
extern unsigned long DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid,
			mode_t obj_mode, struct mount *mp,
			kauth_cred_t cred, struct proc *p);

/* from vfs/vfs_fsevents.c */
extern char *get_pathbuff(void);
extern void release_pathbuff(char *buff);

struct access_cache {
       int numcached;
       int cachehits; /* these two for statistics gathering */
       int lookups;
       unsigned int *acache;
       Boolean *haveaccess;
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
	int			num_files;		/* IN: number of files to process */
	user_addr_t	file_ids;		/* IN: array of file ids */
	user_addr_t	groups;			/* IN: array of groups */
	user_addr_t	access;			/* OUT: access info for each file (0 for 'has access') */
};

/*
 * Perform a binary search for the given parent_id. Return value is 
 * found/not found boolean, and indexp will be the index of the item 
 * or the index at which to insert the item if it's not found.
 */
static int
lookup_bucket(struct access_cache *cache, int *indexp, cnid_t parent_id)
{
	unsigned int lo, hi;
	int index, matches = 0;
	
	if (cache->numcached == 0) {
		*indexp = 0;
		return 0; // table is empty, so insert at index=0 and report no match
	}
	
	if (cache->numcached > CACHE_ELEMS) {
		/*printf("EGAD! numcached is %d... cut our losses and trim to %d\n",
		  cache->numcached, CACHE_ELEMS);*/
		cache->numcached = CACHE_ELEMS;
	}
	
	lo = 0;
	hi = cache->numcached - 1;
	index = -1;
	
	/* perform binary search for parent_id */
	do {
		unsigned int mid = (hi - lo)/2 + lo;
		unsigned int this_id = cache->acache[mid];
		
		if (parent_id == this_id) {
			index = mid;
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
	if (parent_id == cache->acache[hi]) {
		index = hi;
	}
	
	/* if no existing entry found, find index for new one */
	if (index == -1) {
		index = (parent_id < cache->acache[hi]) ? hi : hi + 1;
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
                       if (cache->haveaccess[lookup_index] != access) {
                               /* change access info for existing entry... should never happen */
			       cache->haveaccess[lookup_index] = access;
                       }

		       /* mission accomplished */
                       return;
               } else {
                       index = lookup_index;
               }

       }

       /* if the cache is full, do a replace rather than an insert */
       if (cache->numcached >= CACHE_ELEMS) {
               //printf("cache is full (%d). replace at index %d\n", cache->numcached, index);
               cache->numcached = CACHE_ELEMS-1;

               if (index > cache->numcached) {
                 //    printf("index %d pinned to %d\n", index, cache->numcached);
                       index = cache->numcached;
               }
       } else if (index >= 0 && index < cache->numcached) {
               /* only do bcopy if we're inserting */
               bcopy( cache->acache+index, cache->acache+(index+1), (cache->numcached - index)*sizeof(int) );
               bcopy( cache->haveaccess+index, cache->haveaccess+(index+1), (cache->numcached - index)*sizeof(Boolean) );
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
};

static int
snoop_callback(const struct cat_desc *descp, const struct cat_attr *attrp, void * arg)
{
	struct cinfo *cip = (struct cinfo *)arg;

	cip->uid = attrp->ca_uid;
	cip->gid = attrp->ca_gid;
	cip->mode = attrp->ca_mode;
	cip->parentcnid = descp->cd_parentcnid;
	
	return (0);
}

/*
 * Lookup the cnid's attr info (uid, gid, and mode) as well as its parent id. If the item
 * isn't incore, then go to the catalog.
 */ 
static int
do_attr_lookup(struct hfsmount *hfsmp, struct access_cache *cache, dev_t dev, cnid_t cnid, 
	       struct cnode *skip_cp, CatalogKey *keyp, struct cat_attr *cnattrp, struct proc *p)
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
		struct cnode *skip_cp, struct proc *theProcPtr, kauth_cred_t myp_ucred, dev_t dev )
{
       int                     myErr = 0;
       int                     myResult;
       HFSCatalogNodeID        thisNodeID;
       unsigned long           myPerms;
       struct cat_attr         cnattr;
       int                     cache_index = -1;
       CatalogKey              catkey;

       int i = 0, ids_to_cache = 0;
       int parent_ids[CACHE_LEVELS];

       /* root always has access */
       if (!suser(myp_ucred, NULL)) {
               return (1);
       }

       thisNodeID = nodeID;
       while (thisNodeID >=  kRootDirID) {
               myResult = 0;   /* default to "no access" */
       
               /* check the cache before resorting to hitting the catalog */

               /* ASSUMPTION: access info of cached entries is "final"... i.e. no need
                * to look any further after hitting cached dir */

               if (lookup_bucket(cache, &cache_index, thisNodeID)) {
                       cache->cachehits++;
                       myResult = cache->haveaccess[cache_index];
                       goto ExitThisRoutine;
               }

               /* remember which parents we want to cache */
               if (ids_to_cache < CACHE_LEVELS) {
                       parent_ids[ids_to_cache] = thisNodeID;
                       ids_to_cache++;
               }
	       
	       /* do the lookup (checks the cnode hash, then the catalog) */
	       myErr = do_attr_lookup(hfsmp, cache, dev, thisNodeID, skip_cp, &catkey, &cnattr, theProcPtr);
	       if (myErr) {
		       goto ExitThisRoutine; /* no access */
	       }

               myPerms = DerivePermissionSummary(cnattr.ca_uid, cnattr.ca_gid,
                                                 cnattr.ca_mode, hfsmp->hfs_mp,
                                                 myp_ucred, theProcPtr);

               if ( (myPerms & X_OK) == 0 ) {
		       myResult = 0;
                       goto ExitThisRoutine;   /* no access */
	       } 

               /* up the hierarchy we go */
               thisNodeID = catkey.hfsPlus.parentID;
       }

       /* if here, we have access to this node */
       myResult = 1;

 ExitThisRoutine:
       if (myErr) {
	       //printf("*** error %d from catalog looking up parent %d/%d!\n", myErr, dev, thisNodeID);
               myResult = 0;
       }
       *err = myErr;

       /* cache the parent directory(ies) */
       for (i = 0; i < ids_to_cache; i++) {
               /* small optimization: get rid of double-lookup for all these */
	       // printf("adding %d to cache with result: %d\n", parent_ids[i], myResult);
               add_node(cache, -1, parent_ids[i], myResult);
       }

       return (myResult);
}
/* end "bulk-access" support */



/*
 * Callback for use with freeze ioctl.
 */
static int
hfs_freezewrite_callback(struct vnode *vp, void *cargs)
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
		location = *(u_int32_t *)ap->a_data;
		if (location > hfsmp->totalBlocks - 1) {
			return (EINVAL);
		}
		/* Return previous value. */
		*(u_int32_t *)ap->a_data = hfsmp->nextAllocation;
		HFS_MOUNT_LOCK(hfsmp, TRUE);
		hfsmp->nextAllocation = location;
		hfsmp->vcbFlags |= 0xFF00;
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		return (0);
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
		task_t task;
 
		if (!is_suser())
			return (EACCES);

		mp = vnode_mount(vp);
		hfsmp = VFSTOHFS(mp);

		if (!(hfsmp->jnl))
			return (ENOTSUP);

		lck_rw_lock_exclusive(&hfsmp->hfs_insync);
 
		task = current_task();
		task_working_set_disable(task);

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

#define HFSIOC_BULKACCESS _IOW('h', 9, struct access_t)
#define HFS_BULKACCESS_FSCTL IOCBASECMD(HFSIOC_BULKACCESS)

	case HFS_BULKACCESS_FSCTL:
	case HFS_BULKACCESS: {
		/*
		 * NOTE: on entry, the vnode is locked. Incase this vnode
		 * happens to be in our list of file_ids, we'll note it
		 * avoid calling hfs_chashget_nowait() on that id as that
		 * will cause a "locking against myself" panic.
		 */
		Boolean check_leaf = true;
		
		struct user_access_t *user_access_structp;
		struct user_access_t tmp_user_access_t;
		struct access_cache cache;
		
		int error = 0, i;
		
		dev_t dev = VTOC(vp)->c_dev;
		
		short flags;
		struct ucred myucred;	/* XXX ILLEGAL */
		int num_files;
		int *file_ids = NULL;
		short *access = NULL;
		
		cnid_t cnid;
		cnid_t prevParent_cnid = 0;
		unsigned long myPerms;
		short myaccess = 0;
		struct cat_attr cnattr;
		CatalogKey catkey;
		struct cnode *skip_cp = VTOC(vp);
		struct vfs_context	my_context;

		/* first, return error if not run as root */
		if (cred->cr_ruid != 0) {
			return EPERM;
		}
		
		/* initialize the local cache and buffers */
		cache.numcached = 0;
		cache.cachehits = 0;
		cache.lookups = 0;
		
		file_ids = (int *) get_pathbuff();
		access = (short *) get_pathbuff();
		cache.acache = (int *) get_pathbuff();
		cache.haveaccess = (Boolean *) get_pathbuff();
		
		if (file_ids == NULL || access == NULL || cache.acache == NULL || cache.haveaccess == NULL) {
			release_pathbuff((char *) file_ids);
			release_pathbuff((char *) access);
			release_pathbuff((char *) cache.acache);
			release_pathbuff((char *) cache.haveaccess);
			
			return ENOMEM;
		}
		
		/* struct copyin done during dispatch... need to copy file_id array separately */
		if (ap->a_data == NULL) {
			error = EINVAL;
			goto err_exit_bulk_access;
		}

		if (is64bit) {
			user_access_structp = (struct user_access_t *)ap->a_data;
		}
		else {
			struct access_t *       accessp = (struct access_t *)ap->a_data;
			tmp_user_access_t.uid = accessp->uid;
			tmp_user_access_t.flags = accessp->flags;
			tmp_user_access_t.num_groups = accessp->num_groups;
			tmp_user_access_t.num_files = accessp->num_files;
			tmp_user_access_t.file_ids = CAST_USER_ADDR_T(accessp->file_ids);
			tmp_user_access_t.groups = CAST_USER_ADDR_T(accessp->groups);
			tmp_user_access_t.access = CAST_USER_ADDR_T(accessp->access);
			user_access_structp = &tmp_user_access_t;
		}
		
		num_files = user_access_structp->num_files;
		if (num_files < 1) {
			goto err_exit_bulk_access;
		}
		if (num_files > 256) {
			error = EINVAL;
			goto err_exit_bulk_access;
		}
		
		if ((error = copyin(user_access_structp->file_ids, (caddr_t)file_ids,
							num_files * sizeof(int)))) {
			goto err_exit_bulk_access;
		}
		
		/* fill in the ucred structure */
		flags = user_access_structp->flags;
		if ((flags & (F_OK | R_OK | W_OK | X_OK)) == 0) {
			flags = R_OK;
		}
		
		/* check if we've been passed leaf node ids or parent ids */
		if (flags & PARENT_IDS_FLAG) {
			check_leaf = false;
		}
		
		memset(&myucred, 0, sizeof(myucred));
		myucred.cr_ref = 1;
		myucred.cr_uid = myucred.cr_ruid = myucred.cr_svuid = user_access_structp->uid;
		myucred.cr_ngroups = user_access_structp->num_groups;
		if (myucred.cr_ngroups < 1 || myucred.cr_ngroups > 16) {
			myucred.cr_ngroups = 0;
		} else if ((error = copyin(user_access_structp->groups, (caddr_t)myucred.cr_groups,
					  myucred.cr_ngroups * sizeof(gid_t)))) {
			goto err_exit_bulk_access;
		}
		myucred.cr_rgid = myucred.cr_svgid = myucred.cr_groups[0];
		myucred.cr_gmuid = myucred.cr_uid;
		
		my_context.vc_proc = p;
		my_context.vc_ucred = &myucred;

		/* Check access to each file_id passed in */
		for (i = 0; i < num_files; i++) {
#if 0
			cnid = (cnid_t) file_ids[i];
			
			/* root always has access */
			if (!suser(&myucred, NULL)) {
				access[i] = 0;
				continue;
			}
			
			if (check_leaf) {
				
				/* do the lookup (checks the cnode hash, then the catalog) */
				error = do_attr_lookup(hfsmp, &cache, dev, cnid, skip_cp, &catkey, &cnattr, p);
				if (error) {
					access[i] = (short) error;
					continue;
				}
							
				/* before calling CheckAccess(), check the target file for read access */
				myPerms = DerivePermissionSummary(cnattr.ca_uid, cnattr.ca_gid,
								  cnattr.ca_mode, hfsmp->hfs_mp, &myucred, p  );
				
				
				/* fail fast if no access */ 
				if ((myPerms & flags) == 0) {
					access[i] = EACCES;
					continue;
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
						   skip_cp, p, &myucred, dev);
			
			if ( myaccess ) {
				access[i] = 0; // have access.. no errors to report
			} else {
				access[i] = (error != 0 ? (short) error : EACCES);
			}
			
			prevParent_cnid = catkey.hfsPlus.parentID;
#else
			int myErr;
			
			cnid = (cnid_t)file_ids[i];
			
			while (cnid >= kRootDirID) {
			    /* get the vnode for this cnid */
			    myErr = hfs_vget(hfsmp, cnid, &vp, 0);
			    if ( myErr ) {
				access[i] = EACCES;
				break;
			    }

			    cnid = VTOC(vp)->c_parentcnid;

			    hfs_unlock(VTOC(vp));
			    if (vnode_vtype(vp) == VDIR) {
				myErr = vnode_authorize(vp, NULL, (KAUTH_VNODE_SEARCH | KAUTH_VNODE_LIST_DIRECTORY), &my_context);
			    } else {
				myErr = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, &my_context);
			    }
			    vnode_put(vp);
			    access[i] = myErr;
			    if (myErr) {
				break;
			    }
			}
#endif			
		}
		
		/* copyout the access array */
		if ((error = copyout((caddr_t)access, user_access_structp->access, 
				     num_files * sizeof (short)))) {
			goto err_exit_bulk_access;
		}
		
	err_exit_bulk_access:
		
		//printf("on exit (err %d), numfiles/numcached/cachehits/lookups is %d/%d/%d/%d\n", error, num_files, cache.numcached, cache.cachehits, cache.lookups);
		
		release_pathbuff((char *) cache.acache);
		release_pathbuff((char *) cache.haveaccess);
		release_pathbuff((char *) file_ids);
		release_pathbuff((char *) access);
		
		return (error);
	} /* HFS_BULKACCESS */

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
			return hfs_setextendedsecurity(hfsmp, state);
		else
			return (EINVAL);	
	}

	case F_FULLFSYNC: {
		int error;

		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
		if (error == 0) {
			error = hfs_fsync(vp, MNT_NOWAIT, TRUE, p);
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

		hfs_unlock_truncate(VTOC(vp));
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
hfs_bmap(struct vnode *vp, daddr_t bn, struct vnode **vpp, daddr64_t *bnp, int *runp)
{
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = VTOF(vp);
	struct hfsmount *hfsmp = VTOHFS(vp);
	int  retval = E_NONE;
	daddr_t  logBlockSize;
	size_t  bytesContAvail = 0;
	off_t  blockposition;
	int lockExtBtree;
	int lockflags = 0;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (vpp != NULL)
		*vpp = cp->c_devvp;
	if (bnp == NULL)
		return (0);

	logBlockSize = GetLogicalBlockSize(vp);
	blockposition = (off_t)bn * (off_t)logBlockSize;

	lockExtBtree = overflow_extents(fp);

	if (lockExtBtree)
		lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS, HFS_SHARED_LOCK);

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

	if ( !vnode_issystem(vp) && !vnode_islnk(vp)) {
		if (VTOC(vp)->c_lockowner != current_thread()) {
			hfs_lock(VTOC(vp), HFS_FORCE_LOCK);
			tooklock = 1;
		} else {
			cp = VTOC(vp);
			panic("blockmap: %s cnode lock already held!\n",
				cp->c_desc.cd_nameptr ? cp->c_desc.cd_nameptr : "");
		}
	}
	hfsmp = VTOHFS(vp);
	cp = VTOC(vp);
	fp = VTOF(vp);

retry:
	if (fp->ff_unallocblocks) {
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
	if (fp->ff_unallocblocks) {
		SInt64 actbytes;
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
		}

		if (retval) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			cp->c_flag |= C_MODIFIED;
			if (started_tr) {
				(void) hfs_update(vp, TRUE);
				(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);

				hfs_end_transaction(hfsmp);
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
		goto exit;
	}

	/* Adjust the mapping information for invalid file ranges: */
	overlaptype = rl_scan(&fp->ff_invalidranges, ap->a_foffset,
	                      ap->a_foffset + (off_t)bytesContAvail - 1,
	                      &invalid_range);
	if (overlaptype != RL_NOOVERLAP) {
		switch(overlaptype) {
		case RL_MATCHINGOVERLAP:
		case RL_OVERLAPCONTAINSRANGE:
		case RL_OVERLAPSTARTSBEFORE:
			/* There's no valid block for this byte offset: */
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
	if (ap->a_run)
		*ap->a_run = bytesContAvail;

	if (ap->a_poff)
		*(int *)ap->a_poff = 0;
exit:
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
	struct cnode *cp = VTOC(vp);

	return (buf_strategy(cp->c_devvp, ap));
}


static int
do_hfs_truncate(struct vnode *vp, off_t length, int flags, int skipsetsize, vfs_context_t context)
{
	register struct cnode *cp = VTOC(vp);
    	struct filefork *fp = VTOF(vp);
	struct proc *p = vfs_context_proc(context);;
	kauth_cred_t cred = vfs_context_ucred(context);
	int retval;
	off_t bytesToAdd;
	off_t actualBytesAdded;
	off_t filebytes;
	u_int64_t old_filesize;
	u_long fileblocks;
	int blksize;
	struct hfsmount *hfsmp;
	int lockflags;

	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;
	old_filesize = fp->ff_size;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 7)) | DBG_FUNC_START,
		 (int)length, (int)fp->ff_size, (int)filebytes, 0, 0);

	if (length < 0)
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
			if (UBCINFOEXISTS(vp) && retval == E_NONE) {
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

		/* Nested transactions will do their own ubc_setsize. */
		if (!skipsetsize) {
			/*
			 * ubc_setsize can cause a pagein here 
			 * so we need to drop cnode lock. 
			 */
			hfs_unlock(cp);
			ubc_setsize(vp, length);
			hfs_lock(cp, HFS_FORCE_LOCK);
		}

	} else { /* Shorten the size of the file */

		if ((off_t)fp->ff_size > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).
			 */

		         /* Nested transactions will do their own ubc_setsize. */
		         if (!skipsetsize) {
		         	/*
		         	 * ubc_setsize can cause a pageout here 
		         	 * so we need to drop cnode lock. 
		         	 */
				hfs_unlock(cp);
				ubc_setsize(vp, length);
				hfs_lock(cp, HFS_FORCE_LOCK);
			}
	    
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
		if (old_filesize != length)
			cp->c_touch_modtime = TRUE;
		fp->ff_size = length;
	}
	cp->c_touch_chgtime = TRUE;
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

	if (vnode_isdir(vp))
		return (EISDIR);	/* cannot truncate an HFS directory! */

	blksize = VTOVCB(vp)->blockSize;
	fileblocks = fp->ff_blocks;
	filebytes = (off_t)fileblocks * (off_t)blksize;

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
			cp->c_flag |= C_FORCEUPDATE;
			error = do_hfs_truncate(vp, filebytes, flags, skipsetsize, context);
			if (error)
				break;
		}
	} else if (length > filebytes) {
		while (filebytes < length) {
			if ((length - filebytes) > HFS_BIGFILE_SIZE) {
				filebytes += HFS_BIGFILE_SIZE;
			} else {
				filebytes = length;
			}
			cp->c_flag |= C_FORCEUPDATE;
			error = do_hfs_truncate(vp, filebytes, flags, skipsetsize, context);
			if (error)
				break;
		}
	} else /* Same logical size */ {

		error = do_hfs_truncate(vp, length, flags, skipsetsize, context);
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
	UInt32 blockHint;
	UInt32 extendFlags;   /* For call to ExtendFileC */
	struct hfsmount *hfsmp;
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	int lockflags;

	*(ap->a_bytesallocated) = 0;

	if (!vnode_isreg(vp))
		return (EISDIR);
	if (length < (off_t)0)
		return (EINVAL);

	if ((retval = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
		return (retval);
	cp = VTOC(vp);
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
		moreBytesRequested = length - filebytes;
		
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

		if (hfs_start_transaction(hfsmp) != 0) {
		    retval = EINVAL;
		    goto Err_Exit;
		}

		/* Protect extents b-tree and allocation bitmap */
		lockflags = SFL_BITMAP;
		if (overflow_extents(fp))
			lockflags |= SFL_EXTENTS;
		lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

		retval = MacToVFSError(ExtendFileC(vcb,
						(FCB*)fp,
						moreBytesRequested,
						blockHint,
						extendFlags,
						&actualBytesAdded));

		*(ap->a_bytesallocated) = actualBytesAdded;
		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

		hfs_systemfile_unlock(hfsmp, lockflags);

		if (hfsmp->jnl) {
			(void) hfs_update(vp, TRUE);
			(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		}

		hfs_end_transaction(hfsmp);

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
		if ((actualBytesAdded != 0) && (moreBytesRequested < actualBytesAdded))
			*(ap->a_bytesallocated) =
				roundup(moreBytesRequested, (off_t)vcb->blockSize);

	} else { /* Shorten the size of the file */

		if (fp->ff_size > length) {
			/*
			 * Any buffers that are past the truncation point need to be
			 * invalidated (to maintain buffer cache consistency).
			 */
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

		retval = MacToVFSError(TruncateFileC(vcb, (FCB*)fp, length, false));

		hfs_systemfile_unlock(hfsmp, lockflags);

		filebytes = (off_t)fp->ff_blocks * (off_t)vcb->blockSize;

		if (hfsmp->jnl) {
			(void) hfs_update(vp, TRUE);
			(void) hfs_volupdate(hfsmp, VOL_UPDATE, 0);
		}

		hfs_end_transaction(hfsmp);
		

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
	if (VTOHFS(vp)->hfc_stage == HFC_RECORDING && error == 0) {
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
		if ((fp->ff_bytesread + bytesread) > 0x00000000ffffffff) {
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
	off_t end_of_range;
	off_t filesize;

	cp = VTOC(vp);
	if (cp->c_lockowner == current_thread()) {
		panic("pageout: %s cnode lock already held!\n",
		      cp->c_desc.cd_nameptr ? cp->c_desc.cd_nameptr : "");
	}
	if ( (retval = hfs_lock(cp, HFS_EXCLUSIVE_LOCK))) {
		if (!(ap->a_flags & UPL_NOCOMMIT)) {
		        ubc_upl_abort_range(ap->a_pl,
					    ap->a_pl_offset,
					    ap->a_size,
					    UPL_ABORT_FREE_ON_EMPTY);
		}
		return (retval);
	}
	fp = VTOF(vp);

	filesize = fp->ff_size;
	end_of_range = ap->a_f_offset + ap->a_size - 1;

	if (end_of_range >= filesize) {
	        end_of_range = (off_t)(filesize - 1);
	}
	if (ap->a_f_offset < filesize) {
	        rl_remove(ap->a_f_offset, end_of_range, &fp->ff_invalidranges);
	        cp->c_flag |= C_MODIFIED;  /* leof is dirty */
	}
	hfs_unlock(cp);

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
		 * been swapped and validatated when it was written to the journal,
		 * so we won't do anything here.
		 */
		if (((UInt16 *)((char *)buf_dataptr(bp) + buf_count(bp) - 2))[0] == 0x000e) {
			/* Prepare the block pointer */
			block.blockHeader = bp;
			block.buffer = (char *)buf_dataptr(bp);
			block.blockNum = buf_lblkno(bp);
			/* not found in cache ==> came from disk */
			block.blockReadFromDisk = (buf_fromcache(bp) == 0);
			block.blockSize = buf_count(bp);
    
			/* Endian un-swap B-Tree node */
			retval = hfs_swap_BTNode (&block, vp, kSwapBTNodeHostToBig);
			if (retval)
				panic("hfs_vnop_bwrite: about to write corrupt node!\n");
		}
	}

	/* This buffer shouldn't be locked anymore but if it is clear it */
	if ((buf_flags(bp) & B_LOCKED)) {
	        // XXXdbg
	        if (VTOHFS(vp)->jnl) {
		        panic("hfs: CLEARING the lock bit on bp 0x%x\n", bp);
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
	int disabled_caching = 0;
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

	if ((fp->ff_size > (u_int64_t)0x7fffffff) ||
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
		if ((retval = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
			hfs_unlock_truncate(cp);
			return (retval);
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
	    		hfs_unlock_truncate(cp);
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
	 * STEP 1 - aquire new allocation blocks.
	 */
	if (!vnode_isnocache(vp)) {
		vnode_setnocache(vp);
		disabled_caching = 1;

	}
	nextallocsave = hfsmp->nextAllocation;
	retval = ExtendFileC(hfsmp, (FCB*)fp, growsize, blockHint, eflags, &newbytes);
	if (eflags & kEFMetadataMask) {
		HFS_MOUNT_LOCK(hfsmp, TRUE);
		hfsmp->nextAllocation = nextallocsave;
		hfsmp->vcbFlags |= 0xFF00;
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
			printf("hfs_relocate: didn't move into metadata zone\n");
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
		hfs_unlock_truncate(cp);

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
	if (disabled_caching) {
		vnode_clearnocache(vp);
	}
	if (started_tr)
		hfs_end_transaction(hfsmp);

	return (retval);

restore:
	if (fp->ff_blocks == headblks)
		goto exit;
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
		hfs_unlock_truncate(cp);
	goto exit;
}


/*
 * Clone a symlink.
 *
 */
static int
hfs_clonelink(struct vnode *vp, int blksize, kauth_cred_t cred, struct proc *p)
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

		error = cluster_read(vp, auio, copysize, 0);
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
