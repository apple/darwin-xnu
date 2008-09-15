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

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/file_internal.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode_if.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/ubc_internal.h>
#include <sys/paths.h>
#include <sys/quota.h>
#include <sys/time.h>
#include <sys/disk.h>
#include <sys/kauth.h>
#include <sys/uio_internal.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>
#include <vfs/vfs_support.h>
#include <machine/spl.h>

#include <sys/kdebug.h>
#include <sys/sysctl.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_quota.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/FileMgrInternal.h"


#define KNDETACH_VNLOCKED 0x00000001

#define CARBON_TEMP_DIR_NAME	"Cleanup At Startup"


/* Global vfs data structures for hfs */

/* Always F_FULLFSYNC? 1=yes,0=no (default due to "various" reasons is 'no') */
int always_do_fullfsync = 0;
SYSCTL_INT (_kern, OID_AUTO, always_do_fullfsync, CTLFLAG_RW, &always_do_fullfsync, 0, "always F_FULLFSYNC when fsync is called");

static int hfs_makenode(struct vnode *dvp, struct vnode **vpp,
                        struct componentname *cnp, struct vnode_attr *vap,
                        vfs_context_t ctx);

static int hfs_metasync(struct hfsmount *hfsmp, daddr64_t node, __unused struct proc *p);
static int hfs_metasync_all(struct hfsmount *hfsmp);

static int hfs_removedir(struct vnode *, struct vnode *, struct componentname *,
                         int);

static int hfs_removefile(struct vnode *, struct vnode *, struct componentname *,
                          int, int, int);

#if FIFO
static int hfsfifo_read(struct vnop_read_args *);
static int hfsfifo_write(struct vnop_write_args *);
static int hfsfifo_close(struct vnop_close_args *);
static int hfsfifo_kqfilt_add(struct vnop_kqfilt_add_args *);
static int hfsfifo_kqfilt_remove(struct vnop_kqfilt_remove_args *);

extern int (**fifo_vnodeop_p)(void *);
#endif /* FIFO */

static int hfs_vnop_close(struct vnop_close_args*);
static int hfs_vnop_create(struct vnop_create_args*);
static int hfs_vnop_exchange(struct vnop_exchange_args*);
static int hfs_vnop_fsync(struct vnop_fsync_args*);
static int hfs_vnop_mkdir(struct vnop_mkdir_args*);
static int hfs_vnop_mknod(struct vnop_mknod_args*);
static int hfs_vnop_getattr(struct vnop_getattr_args*);
static int hfs_vnop_open(struct vnop_open_args*);
static int hfs_vnop_readdir(struct vnop_readdir_args*);
static int hfs_vnop_remove(struct vnop_remove_args*);
static int hfs_vnop_rename(struct vnop_rename_args*);
static int hfs_vnop_rmdir(struct vnop_rmdir_args*);
static int hfs_vnop_symlink(struct vnop_symlink_args*);
static int hfs_vnop_setattr(struct vnop_setattr_args*);
static int hfs_vnop_readlink(struct vnop_readlink_args *);
static int hfs_vnop_pathconf(struct vnop_pathconf_args *);
static int hfs_vnop_kqfiltremove(struct vnop_kqfilt_remove_args *);
static int hfs_vnop_whiteout(struct vnop_whiteout_args *);
static int hfsspec_read(struct vnop_read_args *);
static int hfsspec_write(struct vnop_write_args *);
static int hfsspec_close(struct vnop_close_args *);

/* Options for hfs_removedir and hfs_removefile */
#define HFSRM_SKIP_RESERVE  0x01




/*****************************************************************************
*
* Common Operations on vnodes
*
*****************************************************************************/

/*
 * Create a regular file.
 */
static int
hfs_vnop_create(struct vnop_create_args *ap)
{
	int error;

again:
	error = hfs_makenode(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context);

	/*
	 * We speculatively skipped the original lookup of the leaf
	 * for CREATE.  Since it exists, go get it as long as they
	 * didn't want an exclusive create.
	 */
	if ((error == EEXIST) && !(ap->a_vap->va_vaflags & VA_EXCLUSIVE)) {
		struct vnop_lookup_args args;

		args.a_desc = &vnop_lookup_desc;
		args.a_dvp = ap->a_dvp;
		args.a_vpp = ap->a_vpp;
		args.a_cnp = ap->a_cnp;
		args.a_context = ap->a_context;
		args.a_cnp->cn_nameiop = LOOKUP;
		error = hfs_vnop_lookup(&args);
		/*
		 * We can also race with remove for this file.
		 */
		if (error == ENOENT) {
			goto again;
		}

		/* Make sure it was file. */
		if ((error == 0) && !vnode_isreg(*args.a_vpp)) {
			vnode_put(*args.a_vpp);
			error = EEXIST;
		}
		args.a_cnp->cn_nameiop = CREATE;
	}
	return (error);
}

/*
 * Make device special file.
 */
static int
hfs_vnop_mknod(struct vnop_mknod_args *ap)
{
	struct vnode_attr *vap = ap->a_vap;
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct cnode *cp;
	int error;

	if (VTOVCB(dvp)->vcbSigWord != kHFSPlusSigWord) {
		return (ENOTSUP);
	}

	/* Create the vnode */
	error = hfs_makenode(dvp, vpp, ap->a_cnp, vap, ap->a_context);
	if (error)
		return (error);

	cp = VTOC(*vpp);
	cp->c_touch_acctime = TRUE;
	cp->c_touch_chgtime = TRUE;
	cp->c_touch_modtime = TRUE;

	if ((vap->va_rdev != VNOVAL) &&
	    (vap->va_type == VBLK || vap->va_type == VCHR))
		cp->c_rdev = vap->va_rdev;

	return (0);
}

/*
 * Open a file/directory.
 */
static int
hfs_vnop_open(struct vnop_open_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct filefork *fp;
	struct timeval tv;
	int error;

	/*
	 * Files marked append-only must be opened for appending.
	 */
	if ((VTOC(vp)->c_flags & APPEND) && !vnode_isdir(vp) &&
	    (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
		return (EPERM);

	if (vnode_isreg(vp) && !UBCINFOEXISTS(vp))
		return (EBUSY);  /* file is in use by the kernel */

	/* Don't allow journal file to be opened externally. */
	if (VTOC(vp)->c_fileid == VTOHFS(vp)->hfs_jnlfileid)
		return (EPERM);
	/*
	 * On the first (non-busy) open of a fragmented
	 * file attempt to de-frag it (if its less than 20MB).
	 */
	if ((VTOHFS(vp)->hfs_flags & HFS_READ_ONLY) ||
	    (VTOHFS(vp)->jnl == NULL) ||
#if NAMEDSTREAMS
	    !vnode_isreg(vp) || vnode_isinuse(vp, 0) || vnode_isnamedstream(vp)) {
#else
	    !vnode_isreg(vp) || vnode_isinuse(vp, 0)) {
#endif
		return (0);
	}

	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
		return (error);
	fp = VTOF(vp);
	if (fp->ff_blocks &&
	    fp->ff_extents[7].blockCount != 0 &&
	    fp->ff_size <= (20 * 1024 * 1024)) {
		struct timeval now;
		struct cnode *cp = VTOC(vp);
		/* 
		 * Wait until system bootup is done (3 min).
		 * And don't relocate a file that's been modified
		 * within the past minute -- this can lead to
		 * system thrashing.
		 */
		microuptime(&tv);
		microtime(&now);
		if (tv.tv_sec > (60 * 3) &&
		   ((now.tv_sec - cp->c_mtime) > 60)) {
			(void) hfs_relocate(vp, VTOVCB(vp)->nextAllocation + 4096,
			                    vfs_context_ucred(ap->a_context),
			                    vfs_context_proc(ap->a_context));
		}
	}
	hfs_unlock(VTOC(vp));

	return (0);
}


/*
 * Close a file/directory.
 */
static int
hfs_vnop_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
 	register struct cnode *cp;
	struct proc *p = vfs_context_proc(ap->a_context);
	struct hfsmount *hfsmp;
	int busy;
	int knownrefs = 0;
	int tooktrunclock = 0;

	if ( hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) != 0)
		return (0);
	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/*
	 * If the rsrc fork is a named stream, it holds a usecount on 
	 * the data fork, which prevents the data fork from getting recycled, which
	 * then prevents the de-allocation of its extra blocks.  
	 * Do checks for truncation on close. Purge extra extents if they
	 * exist.  Make sure the vp is not a directory, that it has a resource
	 * fork, and that rsrc fork is a named stream.
	 */
	
	if ((vp->v_type == VREG) && (cp->c_rsrc_vp)
			&& (vnode_isnamedstream(cp->c_rsrc_vp))) {
		uint32_t blks;

		blks = howmany(VTOF(vp)->ff_size, VTOVCB(vp)->blockSize);
		/*
		 *  If there are any extra blocks and there are only 2 refs on 
		 *  this vp (ourselves + rsrc fork holding ref on us), go ahead
		 *  and try to truncate the extra blocks away.
		 */
		if ((blks < VTOF(vp)->ff_blocks) && (!vnode_isinuse(vp, 2))) {
			// release cnode lock ; must acquire truncate lock BEFORE cnode lock
			hfs_unlock (cp);

			hfs_lock_truncate(cp, TRUE);
			tooktrunclock = 1;
			
			if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) != 0) {
				hfs_unlock_truncate(cp, TRUE);
				return (0);			
			}

			//now re-test to make sure it's still valid.
			if (cp->c_rsrc_vp) {
				knownrefs = 1 + vnode_isnamedstream(cp->c_rsrc_vp);
				if (!vnode_isinuse(vp, knownrefs)) {
					blks = howmany(VTOF(vp)->ff_size, VTOVCB(vp)->blockSize);
					if (blks < VTOF(vp)->ff_blocks) {
						(void) hfs_truncate(vp, VTOF(vp)->ff_size, IO_NDELAY, 0, ap->a_context);
					}
				}
			}
		}
	}

	// if we froze the fs and we're exiting, then "thaw" the fs 
	if (hfsmp->hfs_freezing_proc == p && proc_exiting(p)) {
	    hfsmp->hfs_freezing_proc = NULL;
	    hfs_global_exclusive_lock_release(hfsmp);
	    lck_rw_unlock_exclusive(&hfsmp->hfs_insync);
	}

	busy = vnode_isinuse(vp, 1);

	if (busy) {
		hfs_touchtimes(VTOHFS(vp), cp);	
	}
	if (vnode_isdir(vp)) {
		hfs_reldirhints(cp, busy);
	} else if (vnode_issystem(vp) && !busy) {
		vnode_recycle(vp);
	}
	if (tooktrunclock) {
		hfs_unlock_truncate(cp, TRUE);
	}
	
	hfs_unlock(cp);
	return (0);
}

/*
 * Get basic attributes.
 */
static int
hfs_vnop_getattr(struct vnop_getattr_args *ap)
{
#define VNODE_ATTR_TIMES  \
	(VNODE_ATTR_va_access_time|VNODE_ATTR_va_change_time|VNODE_ATTR_va_modify_time)
#define VNODE_ATTR_AUTH  \
	(VNODE_ATTR_va_mode | VNODE_ATTR_va_uid | VNODE_ATTR_va_gid | \
         VNODE_ATTR_va_flags | VNODE_ATTR_va_acl)

	struct vnode *vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	struct vnode *rvp = NULLVP;
	struct hfsmount *hfsmp;
	struct cnode *cp;
	uint64_t data_size;
	enum vtype v_type;
	int error = 0;

	cp = VTOC(vp);

	/*
	 * Shortcut for vnode_authorize path.  Each of the attributes
	 * in this set is updated atomically so we don't need to take
	 * the cnode lock to access them.
	 */
	if ((vap->va_active & ~VNODE_ATTR_AUTH) == 0) {
		/* Make sure file still exists. */
		if (cp->c_flag & C_NOEXISTS)
			return (ENOENT);

		vap->va_uid = cp->c_uid;
		vap->va_gid = cp->c_gid;
		vap->va_mode = cp->c_mode;
		vap->va_flags = cp->c_flags;
		vap->va_supported |= VNODE_ATTR_AUTH & ~VNODE_ATTR_va_acl;

		if ((cp->c_attr.ca_recflags & kHFSHasSecurityMask) == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
			VATTR_SET_SUPPORTED(vap, va_acl);
		}
		return (0);
	}
	hfsmp = VTOHFS(vp);
	v_type = vnode_vtype(vp);

	/*
	 * If time attributes are requested and we have cnode times
	 * that require updating, then acquire an exclusive lock on
	 * the cnode before updating the times.  Otherwise we can
	 * just acquire a shared lock.
	 */
	if ((vap->va_active & VNODE_ATTR_TIMES) &&
	    (cp->c_touch_acctime || cp->c_touch_chgtime || cp->c_touch_modtime)) {
		if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK)))
			return (error);
		hfs_touchtimes(hfsmp, cp);
	} else {
		if ((error = hfs_lock(cp, HFS_SHARED_LOCK)))
			return (error);
	}

	if (v_type == VDIR) {
		data_size = (cp->c_entries + 2) * AVERAGE_HFSDIRENTRY_SIZE;

		if (VATTR_IS_ACTIVE(vap, va_nlink)) {
			int nlink;
	
			/*
			 * For directories, the va_nlink is esentially a count
			 * of the ".." references to a directory plus the "."
			 * reference and the directory itself. So for HFS+ this
			 * becomes the sub-directory count plus two.
			 *
			 * In the absence of a sub-directory count we use the
			 * directory's item count.  This will be too high in
			 * most cases since it also includes files.
			 */
			if ((hfsmp->hfs_flags & HFS_FOLDERCOUNT) && 
			    (cp->c_attr.ca_recflags & kHFSHasFolderCountMask))
				nlink = cp->c_attr.ca_dircount;  /* implied ".." entries */
			else
				nlink = cp->c_entries;

			/* Account for ourself and our "." entry */
			nlink += 2;  
			 /* Hide our private directories. */
			if (cp->c_cnid == kHFSRootFolderID) {
				if (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid != 0) {
					--nlink;    
				}
				if (hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid != 0) {
					--nlink;
				}
			}
			VATTR_RETURN(vap, va_nlink, (u_int64_t)nlink);
		}		
		if (VATTR_IS_ACTIVE(vap, va_nchildren)) {
			int entries;
	
			entries = cp->c_entries;
			/* Hide our private files and directories. */
			if (cp->c_cnid == kHFSRootFolderID) {
				if (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid != 0)
					--entries;
				if (hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid != 0)
					--entries;
				if (hfsmp->jnl || ((hfsmp->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY)))
					entries -= 2;   /* hide the journal files */
			}
			VATTR_RETURN(vap, va_nchildren, entries);
		}
		/*
		 * The va_dirlinkcount is the count of real directory hard links.
		 * (i.e. its not the sum of the implied "." and ".." references)
		 */
		if (VATTR_IS_ACTIVE(vap, va_dirlinkcount)) {
			VATTR_RETURN(vap, va_dirlinkcount, (uint32_t)cp->c_linkcount);
		}
	} else /* !VDIR */ {
		data_size = VCTOF(vp, cp)->ff_size;

		VATTR_RETURN(vap, va_nlink, (u_int64_t)cp->c_linkcount);
		if (VATTR_IS_ACTIVE(vap, va_data_alloc)) {
			u_int64_t blocks;
	
			blocks = VCTOF(vp, cp)->ff_blocks;
			VATTR_RETURN(vap, va_data_alloc, blocks * (u_int64_t)hfsmp->blockSize);
		}
	}

	/* conditional because 64-bit arithmetic can be expensive */
	if (VATTR_IS_ACTIVE(vap, va_total_size)) {
		if (v_type == VDIR) {
			VATTR_RETURN(vap, va_total_size, (cp->c_entries + 2) * AVERAGE_HFSDIRENTRY_SIZE);
		} else {
			u_int64_t total_size = 0;
			struct cnode *rcp;
			
			if (cp->c_datafork) {
				total_size = cp->c_datafork->ff_size;
			}

			if (cp->c_blocks - VTOF(vp)->ff_blocks) {
				/* We deal with resource fork vnode iocount at the end of the function */
				error = hfs_vgetrsrc(hfsmp, vp, &rvp, TRUE);
				if (error) {
					goto out;
				}
				rcp = VTOC(rvp);
				if (rcp && rcp->c_rsrcfork) {
					total_size += rcp->c_rsrcfork->ff_size;
				}
			}

			VATTR_RETURN(vap, va_total_size, total_size);
		}
	}
	if (VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		if (v_type == VDIR) {
			VATTR_RETURN(vap, va_total_alloc, 0);
		} else {
			VATTR_RETURN(vap, va_total_alloc, (u_int64_t)cp->c_blocks * (u_int64_t)hfsmp->blockSize);
		}
	}

	/*
	 * If the VFS wants extended security data, and we know that we
	 * don't have any (because it never told us it was setting any)
	 * then we can return the supported bit and no data.  If we do
	 * have extended security, we can just leave the bit alone and
	 * the VFS will use the fallback path to fetch it.
	 */
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if ((cp->c_attr.ca_recflags & kHFSHasSecurityMask) == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
			VATTR_SET_SUPPORTED(vap, va_acl);
		}
	}
	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		/* Access times are lazily updated, get current time if needed */
		if (cp->c_touch_acctime) {
			struct timeval tv;
	
			microtime(&tv);
			vap->va_access_time.tv_sec = tv.tv_sec;
		} else {
			vap->va_access_time.tv_sec = cp->c_atime;
		}
		vap->va_access_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	vap->va_create_time.tv_sec = cp->c_itime;
	vap->va_create_time.tv_nsec = 0;
	vap->va_modify_time.tv_sec = cp->c_mtime;
	vap->va_modify_time.tv_nsec = 0;
	vap->va_change_time.tv_sec = cp->c_ctime;
	vap->va_change_time.tv_nsec = 0;
	vap->va_backup_time.tv_sec = cp->c_btime;
	vap->va_backup_time.tv_nsec = 0;	

	/* XXX is this really a good 'optimal I/O size'? */
	vap->va_iosize = hfsmp->hfs_logBlockSize;
	vap->va_uid = cp->c_uid;
	vap->va_gid = cp->c_gid;
	vap->va_mode = cp->c_mode;
	vap->va_flags = cp->c_flags;

	/*
	 * Exporting file IDs from HFS Plus:
	 *
	 * For "normal" files the c_fileid is the same value as the
	 * c_cnid.  But for hard link files, they are different - the
	 * c_cnid belongs to the active directory entry (ie the link)
	 * and the c_fileid is for the actual inode (ie the data file).
	 *
	 * The stat call (getattr) uses va_fileid and the Carbon APIs,
	 * which are hardlink-ignorant, will ask for va_linkid.
	 */
	vap->va_fileid = (u_int64_t)cp->c_fileid;
	/* 
	 * We need to use the origin cache for both hardlinked files 
	 * and directories. Hardlinked directories have multiple cnids 
	 * and parents (one per link). Hardlinked files also have their 
	 * own parents and link IDs separate from the indirect inode number. 
	 * If we don't use the cache, we could end up vending the wrong ID 
	 * because the cnode will only reflect the link that was looked up most recently.
	 */
	if (cp->c_flag & C_HARDLINK) {
		vap->va_linkid = (u_int64_t)hfs_currentcnid(cp);
		vap->va_parentid = (u_int64_t)hfs_currentparent(cp);
	} else {
		vap->va_linkid = (u_int64_t)cp->c_cnid;
		vap->va_parentid = (u_int64_t)cp->c_parentcnid;
	}
	vap->va_fsid = cp->c_dev;
	vap->va_filerev = 0;
	vap->va_encoding = cp->c_encoding;
	vap->va_rdev = (v_type == VBLK || v_type == VCHR) ? cp->c_rdev : 0;
	vap->va_data_size = data_size;

	/* Mark them all at once instead of individual VATTR_SET_SUPPORTED calls. */
	vap->va_supported |= VNODE_ATTR_va_create_time | VNODE_ATTR_va_modify_time |
	                     VNODE_ATTR_va_change_time| VNODE_ATTR_va_backup_time |
	                     VNODE_ATTR_va_iosize | VNODE_ATTR_va_uid |
	                     VNODE_ATTR_va_gid | VNODE_ATTR_va_mode |
	                     VNODE_ATTR_va_flags |VNODE_ATTR_va_fileid |
	                     VNODE_ATTR_va_linkid | VNODE_ATTR_va_parentid |
	                     VNODE_ATTR_va_fsid | VNODE_ATTR_va_filerev |
	                     VNODE_ATTR_va_encoding | VNODE_ATTR_va_rdev |
	                     VNODE_ATTR_va_data_size;

	/* If this is the root, let VFS to find out the mount name, which may be different from the real name.
	 * Otherwise, we need to just take care for hardlinked files, which need to be looked up, if necessary
	 */
	if (VATTR_IS_ACTIVE(vap, va_name) && (cp->c_cnid != kHFSRootFolderID)) {
		struct cat_desc linkdesc;
		int lockflags;
		int uselinkdesc = 0;
		cnid_t nextlinkid = 0;
		cnid_t prevlinkid = 0;	

		/* Get the name for ATTR_CMN_NAME.  We need to take special care for hardlinks      
		 * here because the info. for the link ID requested by getattrlist may be
		 * different than what's currently in the cnode.  This is because the cnode     
		 * will be filled in with the information for the most recent link ID that went
		 * through namei/lookup().  If there are competing lookups for hardlinks that point 
		 * to the same inode, one (or more) getattrlists could be vended incorrect name information.
		 * Also, we need to beware of open-unlinked files which could have a namelen of 0.  Note
		 * that if another hardlink sibling of this file is being unlinked, that could also thrash
		 * the name fields but it should *not* be treated like an open-unlinked file here.
		 */
		if ((cp->c_flag & C_HARDLINK) &&
				((cp->c_desc.cd_namelen == 0) || (vap->va_linkid != cp->c_cnid))) {
			/* If we have no name and our linkID is the raw inode number, then we may
			 * have an open-unlinked file.  Go to the next link in this case. 
			 */
			if ((cp->c_desc.cd_namelen == 0) && (vap->va_linkid == cp->c_fileid)) {
				if ((error = hfs_lookuplink(hfsmp, vap->va_linkid, &prevlinkid, &nextlinkid))) {
					goto out;
				}
			}
			else {
				nextlinkid = vap->va_linkid;
			}
			/* Now probe the catalog for the linkID.  Note that we don't know if we have
			 * the exclusive lock here for the cnode, so we can't just update the descriptor.  
			 * Instead, we should just store the descriptor's value locally and then use it to pass
			 * out the name value as needed below.
			 */
			if (nextlinkid) {
				lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
				error = cat_findname(hfsmp, nextlinkid, &linkdesc);	
				hfs_systemfile_unlock(hfsmp, lockflags);
				if (error == 0) {
					uselinkdesc = 1;
				}
			}
		}
		
		/* By this point, we either patched the name above, and the c_desc points 
		 * to correct data, or it already did, in which case we just proceed by copying
		 * the name into the VAP.  Note that we will never set va_name to supported if
		 * nextlinkid is never initialized.  This could happen in the degenerate case above
		 * involving the raw inode number, where it has no nextlinkid.  In this case, we will
		 * simply not export the name as supported.
		 */
		if (uselinkdesc) {
			strlcpy(vap->va_name, (const char *)linkdesc.cd_nameptr, MAXPATHLEN);
			VATTR_SET_SUPPORTED(vap, va_name);
			cat_releasedesc(&linkdesc);	
		}
		else if (cp->c_desc.cd_namelen) {
			strlcpy(vap->va_name, (const char *)cp->c_desc.cd_nameptr, MAXPATHLEN);
			VATTR_SET_SUPPORTED(vap, va_name);
		}
	}

out:
	hfs_unlock(cp);
	/* 
	 * We need to drop the iocount on the rsrc fork vnode only *after* we've 
	 * released the cnode lock, since vnode_put can trigger an inactive call, which
	 * will go back into the HFS and try to acquire a cnode lock.  	 
	 */
	if (rvp) {
		vnode_put(rvp);
	}
	return (error);
}

static int
hfs_vnop_setattr(ap)
	struct vnop_setattr_args /* {
		struct vnode *a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode_attr *vap = ap->a_vap;
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = NULL;
	struct hfsmount *hfsmp;
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	struct proc *p = vfs_context_proc(ap->a_context);
	int error = 0;
	uid_t nuid;
	gid_t ngid;

	hfsmp = VTOHFS(vp);

	/* Don't allow modification of the journal file. */
	if (hfsmp->hfs_jnlfileid == VTOC(vp)->c_fileid) {
		return (EPERM);
	}

	/*
	 * File size change request.
	 * We are guaranteed that this is not a directory, and that
	 * the filesystem object is writeable.
	 */
	VATTR_SET_SUPPORTED(vap, va_data_size);
	if (VATTR_IS_ACTIVE(vap, va_data_size) && !vnode_islnk(vp)) {

		/* Take truncate lock before taking cnode lock. */
		hfs_lock_truncate(VTOC(vp), TRUE);
		
		/* Perform the ubc_setsize before taking the cnode lock. */
		ubc_setsize(vp, vap->va_data_size);

		if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
			hfs_unlock_truncate(VTOC(vp), TRUE);
			return (error);
		}
		cp = VTOC(vp);

		error = hfs_truncate(vp, vap->va_data_size, vap->va_vaflags & 0xffff, 1, ap->a_context);

		hfs_unlock_truncate(cp, TRUE);
		if (error)
			goto out;
	}
	if (cp == NULL) {
		if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
			return (error);
		cp = VTOC(vp);
	}

	/*
	 * If it is just an access time update request by itself
	 * we know the request is from kernel level code, and we
	 * can delay it without being as worried about consistency.
	 * This change speeds up mmaps, in the rare case that they
	 * get caught behind a sync.
	 */

	if (vap->va_active == VNODE_ATTR_va_access_time) {
		cp->c_touch_acctime=TRUE;
		goto out;
	}



	/*
	 * Owner/group change request.
	 * We are guaranteed that the new owner/group is valid and legal.
	 */
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	nuid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : (uid_t)VNOVAL;
	ngid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : (gid_t)VNOVAL;
	if (((nuid != (uid_t)VNOVAL) || (ngid != (gid_t)VNOVAL)) &&
	    ((error = hfs_chown(vp, nuid, ngid, cred, p)) != 0))
		goto out;

	/*
	 * Mode change request.
	 * We are guaranteed that the mode value is valid and that in
	 * conjunction with the owner and group, this change is legal.
	 */
	VATTR_SET_SUPPORTED(vap, va_mode);
	if (VATTR_IS_ACTIVE(vap, va_mode) &&
	    ((error = hfs_chmod(vp, (int)vap->va_mode, cred, p)) != 0))
	    goto out;

	/*
	 * File flags change.
	 * We are guaranteed that only flags allowed to change given the
	 * current securelevel are being changed.
	 */
	VATTR_SET_SUPPORTED(vap, va_flags);
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		u_int16_t *fdFlags;

		cp->c_flags = vap->va_flags;
		cp->c_touch_chgtime = TRUE;
		
		/*
		 * Mirror the UF_HIDDEN flag to the invisible bit of the Finder Info.
		 *
		 * The fdFlags for files and frFlags for folders are both 8 bytes
		 * into the userInfo (the first 16 bytes of the Finder Info).  They
		 * are both 16-bit fields.
		 */
		fdFlags = (u_int16_t *) &cp->c_finderinfo[8];
		if (vap->va_flags & UF_HIDDEN)
			*fdFlags |= OSSwapHostToBigConstInt16(kFinderInvisibleMask);
		else
			*fdFlags &= ~OSSwapHostToBigConstInt16(kFinderInvisibleMask);
	}

	/*
	 * Timestamp updates.
	 */
	VATTR_SET_SUPPORTED(vap, va_create_time);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	VATTR_SET_SUPPORTED(vap, va_backup_time);
	VATTR_SET_SUPPORTED(vap, va_change_time);
	if (VATTR_IS_ACTIVE(vap, va_create_time) ||
	    VATTR_IS_ACTIVE(vap, va_access_time) ||
	    VATTR_IS_ACTIVE(vap, va_modify_time) ||
	    VATTR_IS_ACTIVE(vap, va_backup_time)) {
		if (VATTR_IS_ACTIVE(vap, va_create_time))
			cp->c_itime = vap->va_create_time.tv_sec;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			cp->c_atime = vap->va_access_time.tv_sec;
			cp->c_touch_acctime = FALSE;
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			cp->c_mtime = vap->va_modify_time.tv_sec;
			cp->c_touch_modtime = FALSE;
			cp->c_touch_chgtime = TRUE;

			/*
			 * The utimes system call can reset the modification
			 * time but it doesn't know about HFS create times.
			 * So we need to ensure that the creation time is
			 * always at least as old as the modification time.
			 */
			if ((VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) &&
			    (cp->c_cnid != kHFSRootFolderID) &&
			    (cp->c_mtime < cp->c_itime)) {
				cp->c_itime = cp->c_mtime;
			}
		}
		if (VATTR_IS_ACTIVE(vap, va_backup_time))
			cp->c_btime = vap->va_backup_time.tv_sec;
		cp->c_flag |= C_MODIFIED;
	}
	
	/*
	 * Set name encoding.
	 */
	VATTR_SET_SUPPORTED(vap, va_encoding);
	if (VATTR_IS_ACTIVE(vap, va_encoding)) {
		cp->c_encoding = vap->va_encoding;
		hfs_setencodingbits(hfsmp, cp->c_encoding);
	}

	if ((error = hfs_update(vp, TRUE)) != 0)
		goto out;
	HFS_KNOTE(vp, NOTE_ATTRIB);
out:
	if (cp)
		hfs_unlock(cp);
	return (error);
}


/*
 * Change the mode on a file.
 * cnode must be locked before calling.
 */
__private_extern__
int
hfs_chmod(struct vnode *vp, int mode, __unused kauth_cred_t cred, __unused struct proc *p)
{
	register struct cnode *cp = VTOC(vp);

	if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
		return (0);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (VTOHFS(vp)->jnl && cp && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_extents[0];
		if (extd->startBlock == VTOVCB(vp)->vcbJinfoBlock || extd->startBlock == VTOHFS(vp)->jnl_start) {
			return EPERM;
		}
	}

#if OVERRIDE_UNKNOWN_PERMISSIONS
	if (((unsigned int)vfs_flags(VTOVFS(vp))) & MNT_UNKNOWNPERMISSIONS) {
		return (0);
	};
#endif
	cp->c_mode &= ~ALLPERMS;
	cp->c_mode |= (mode & ALLPERMS);
	cp->c_touch_chgtime = TRUE;
	return (0);
}


__private_extern__
int
hfs_write_access(struct vnode *vp, kauth_cred_t cred, struct proc *p, Boolean considerFlags)
{
	struct cnode *cp = VTOC(vp);
	int retval = 0;
	int is_member;

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	switch (vnode_vtype(vp)) {
	case VDIR:
 	case VLNK:
	case VREG:
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		break;
	default:
		break;
 	}
 
	/* If immutable bit set, nobody gets to write it. */
	if (considerFlags && (cp->c_flags & IMMUTABLE))
		return (EPERM);

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL))
		return (0);

	/* Otherwise, check the owner. */
	if ((retval = hfs_owner_rights(VTOHFS(vp), cp->c_uid, cred, p, false)) == 0)
		return ((cp->c_mode & S_IWUSR) == S_IWUSR ? 0 : EACCES);
 
	/* Otherwise, check the groups. */
	if (kauth_cred_ismember_gid(cred, cp->c_gid, &is_member) == 0 && is_member) {
		return ((cp->c_mode & S_IWGRP) == S_IWGRP ? 0 : EACCES);
 	}
 
	/* Otherwise, check everyone else. */
	return ((cp->c_mode & S_IWOTH) == S_IWOTH ? 0 : EACCES);
}


/*
 * Perform chown operation on cnode cp;
 * code must be locked prior to call.
 */
__private_extern__
int
#if !QUOTA
hfs_chown(struct vnode *vp, uid_t uid, gid_t gid, __unused kauth_cred_t cred,
	__unused struct proc *p)
#else 
hfs_chown(struct vnode *vp, uid_t uid, gid_t gid, kauth_cred_t cred,
	__unused struct proc *p)
#endif
{
	register struct cnode *cp = VTOC(vp);
	uid_t ouid;
	gid_t ogid;
#if QUOTA
	int error = 0;
	register int i;
	int64_t change;
#endif /* QUOTA */

	if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
		return (ENOTSUP);

	if (((unsigned int)vfs_flags(VTOVFS(vp))) & MNT_UNKNOWNPERMISSIONS)
		return (0);
	
	if (uid == (uid_t)VNOVAL)
		uid = cp->c_uid;
	if (gid == (gid_t)VNOVAL)
		gid = cp->c_gid;

#if 0	/* we are guaranteed that this is already the case */
	/*
	 * If we don't own the file, are trying to change the owner
	 * of the file, or are not a member of the target group,
	 * the caller must be superuser or the call fails.
	 */
	if ((kauth_cred_getuid(cred) != cp->c_uid || uid != cp->c_uid ||
	    (gid != cp->c_gid &&
	     (kauth_cred_ismember_gid(cred, gid, &is_member) || !is_member))) &&
	    (error = suser(cred, 0)))
		return (error);
#endif

	ogid = cp->c_gid;
	ouid = cp->c_uid;
#if QUOTA
	if ((error = hfs_getinoquota(cp)))
		return (error);
	if (ouid == uid) {
		dqrele(cp->c_dquot[USRQUOTA]);
		cp->c_dquot[USRQUOTA] = NODQUOT;
	}
	if (ogid == gid) {
		dqrele(cp->c_dquot[GRPQUOTA]);
		cp->c_dquot[GRPQUOTA] = NODQUOT;
	}

	/*
	 * Eventually need to account for (fake) a block per directory
	 * if (vnode_isdir(vp))
	 *     change = VTOHFS(vp)->blockSize;
	 * else
	 */

	change = (int64_t)(cp->c_blocks) * (int64_t)VTOVCB(vp)->blockSize;
	(void) hfs_chkdq(cp, -change, cred, CHOWN);
	(void) hfs_chkiq(cp, -1, cred, CHOWN);
	for (i = 0; i < MAXQUOTAS; i++) {
		dqrele(cp->c_dquot[i]);
		cp->c_dquot[i] = NODQUOT;
	}
#endif /* QUOTA */
	cp->c_gid = gid;
	cp->c_uid = uid;
#if QUOTA
	if ((error = hfs_getinoquota(cp)) == 0) {
		if (ouid == uid) {
			dqrele(cp->c_dquot[USRQUOTA]);
			cp->c_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(cp->c_dquot[GRPQUOTA]);
			cp->c_dquot[GRPQUOTA] = NODQUOT;
		}
		if ((error = hfs_chkdq(cp, change, cred, CHOWN)) == 0) {
			if ((error = hfs_chkiq(cp, 1, cred, CHOWN)) == 0)
				goto good;
			else
				(void) hfs_chkdq(cp, -change, cred, CHOWN|FORCE);
		}
		for (i = 0; i < MAXQUOTAS; i++) {
			dqrele(cp->c_dquot[i]);
			cp->c_dquot[i] = NODQUOT;
		}
	}
	cp->c_gid = ogid;
	cp->c_uid = ouid;
	if (hfs_getinoquota(cp) == 0) {
		if (ouid == uid) {
			dqrele(cp->c_dquot[USRQUOTA]);
			cp->c_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(cp->c_dquot[GRPQUOTA]);
			cp->c_dquot[GRPQUOTA] = NODQUOT;
		}
		(void) hfs_chkdq(cp, change, cred, FORCE|CHOWN);
		(void) hfs_chkiq(cp, 1, cred, FORCE|CHOWN);
		(void) hfs_getinoquota(cp);
	}
	return (error);
good:
	if (hfs_getinoquota(cp))
		panic("hfs_chown: lost quota");
#endif /* QUOTA */


	/*
	  According to the SUSv3 Standard, chown() shall mark
	  for update the st_ctime field of the file.
	  (No exceptions mentioned)
	*/
		cp->c_touch_chgtime = TRUE;
	return (0);
}


/*
 * The hfs_exchange routine swaps the fork data in two files by
 * exchanging some of the information in the cnode.  It is used
 * to preserve the file ID when updating an existing file, in
 * case the file is being tracked through its file ID. Typically
 * its used after creating a new file during a safe-save.
 */
static int
hfs_vnop_exchange(ap)
	struct vnop_exchange_args /* {
		struct vnode *a_fvp;
		struct vnode *a_tvp;
		int a_options;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *from_vp = ap->a_fvp;
	struct vnode *to_vp = ap->a_tvp;
	struct cnode *from_cp;
	struct cnode *to_cp;
	struct hfsmount *hfsmp;
	struct cat_desc tempdesc;
	struct cat_attr tempattr;
	const unsigned char *from_nameptr;
	const unsigned char *to_nameptr;
	char from_iname[32];
	char to_iname[32];
	u_int32_t tempflag;
	cnid_t  from_parid;
	cnid_t  to_parid;
	int lockflags;
	int error = 0, started_tr = 0, got_cookie = 0;
	cat_cookie_t cookie;

	/* The files must be on the same volume. */
	if (vnode_mount(from_vp) != vnode_mount(to_vp))
		return (EXDEV);

	if (from_vp == to_vp)
		return (EINVAL);

	if ((error = hfs_lockpair(VTOC(from_vp), VTOC(to_vp), HFS_EXCLUSIVE_LOCK)))
		return (error);

	from_cp = VTOC(from_vp);
	to_cp = VTOC(to_vp);
	hfsmp = VTOHFS(from_vp);

	/* Only normal files can be exchanged. */
	if (!vnode_isreg(from_vp) || !vnode_isreg(to_vp) ||
	    VNODE_IS_RSRC(from_vp) || VNODE_IS_RSRC(to_vp)) {
		error = EINVAL;
		goto exit;
	}

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (hfsmp->jnl) {
		struct HFSPlusExtentDescriptor *extd;

		if (from_cp->c_datafork) {
			extd = &from_cp->c_datafork->ff_extents[0];
			if (extd->startBlock == VTOVCB(from_vp)->vcbJinfoBlock || extd->startBlock == hfsmp->jnl_start) {
				error = EPERM;
				goto exit;
			}
		}

		if (to_cp->c_datafork) {
			extd = &to_cp->c_datafork->ff_extents[0];
			if (extd->startBlock == VTOVCB(to_vp)->vcbJinfoBlock || extd->startBlock == hfsmp->jnl_start) {
				error = EPERM;
				goto exit;
			}
		}
	}

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto exit;
	}
	started_tr = 1;
	
	/*
	 * Reserve some space in the Catalog file.
	 */
	if ((error = cat_preflight(hfsmp, CAT_EXCHANGE, &cookie, vfs_context_proc(ap->a_context)))) {
		goto exit;
	}
	got_cookie = 1;

	/* The backend code always tries to delete the virtual
	 * extent id for exchanging files so we need to lock
	 * the extents b-tree.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_EXTENTS | SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	/* Account for the location of the catalog objects. */
	if (from_cp->c_flag & C_HARDLINK) {
		MAKE_INODE_NAME(from_iname, sizeof(from_iname),
				from_cp->c_attr.ca_linkref);
		from_nameptr = (unsigned char *)from_iname;
		from_parid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
		from_cp->c_hint = 0;
	} else {
		from_nameptr = from_cp->c_desc.cd_nameptr;
		from_parid = from_cp->c_parentcnid;
	}
	if (to_cp->c_flag & C_HARDLINK) {
		MAKE_INODE_NAME(to_iname, sizeof(to_iname),
				to_cp->c_attr.ca_linkref);
		to_nameptr = (unsigned char *)to_iname;
		to_parid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
		to_cp->c_hint = 0;
	} else {
		to_nameptr = to_cp->c_desc.cd_nameptr;
		to_parid = to_cp->c_parentcnid;
	}

	/* Do the exchange */
	error = ExchangeFileIDs(hfsmp, from_nameptr, to_nameptr, from_parid,
	                        to_parid, from_cp->c_hint, to_cp->c_hint);
	hfs_systemfile_unlock(hfsmp, lockflags);

	/*
	 * Note that we don't need to exchange any extended attributes
	 * since the attributes are keyed by file ID.
	 */

	if (error != E_NONE) {
		error = MacToVFSError(error);
		goto exit;
	}

	/* Purge the vnodes from the name cache */
 	if (from_vp)
		cache_purge(from_vp);
	if (to_vp)
		cache_purge(to_vp);

	/* Save a copy of from attributes before swapping. */
	bcopy(&from_cp->c_desc, &tempdesc, sizeof(struct cat_desc));
	bcopy(&from_cp->c_attr, &tempattr, sizeof(struct cat_attr));
	tempflag = from_cp->c_flag & (C_HARDLINK | C_HASXATTRS);

	/*
	 * Swap the descriptors and all non-fork related attributes.
	 * (except the modify date)
	 */
	bcopy(&to_cp->c_desc, &from_cp->c_desc, sizeof(struct cat_desc));

	from_cp->c_hint = 0;
	from_cp->c_fileid = from_cp->c_cnid;
	from_cp->c_itime = to_cp->c_itime;
	from_cp->c_btime = to_cp->c_btime;
	from_cp->c_atime = to_cp->c_atime;
	from_cp->c_ctime = to_cp->c_ctime;
	from_cp->c_gid = to_cp->c_gid;
	from_cp->c_uid = to_cp->c_uid;
	from_cp->c_flags = to_cp->c_flags;
	from_cp->c_mode = to_cp->c_mode;
	from_cp->c_linkcount = to_cp->c_linkcount;
	from_cp->c_flag = to_cp->c_flag & (C_HARDLINK | C_HASXATTRS);
	from_cp->c_attr.ca_recflags = to_cp->c_attr.ca_recflags;
	bcopy(to_cp->c_finderinfo, from_cp->c_finderinfo, 32);

	bcopy(&tempdesc, &to_cp->c_desc, sizeof(struct cat_desc));
	to_cp->c_hint = 0;
	to_cp->c_fileid = to_cp->c_cnid;
	to_cp->c_itime = tempattr.ca_itime;
	to_cp->c_btime = tempattr.ca_btime;
	to_cp->c_atime = tempattr.ca_atime;
	to_cp->c_ctime = tempattr.ca_ctime;
	to_cp->c_gid = tempattr.ca_gid;
	to_cp->c_uid = tempattr.ca_uid;
	to_cp->c_flags = tempattr.ca_flags;
	to_cp->c_mode = tempattr.ca_mode;
	to_cp->c_linkcount = tempattr.ca_linkcount;
	to_cp->c_flag = tempflag;
	to_cp->c_attr.ca_recflags = tempattr.ca_recflags;
	bcopy(tempattr.ca_finderinfo, to_cp->c_finderinfo, 32);

	/* Rehash the cnodes using their new file IDs */
	hfs_chash_rehash(from_cp, to_cp);

	/*
	 * When a file moves out of "Cleanup At Startup"
	 * we can drop its NODUMP status.
	 */
	if ((from_cp->c_flags & UF_NODUMP) &&
	    (from_cp->c_parentcnid != to_cp->c_parentcnid)) {
		from_cp->c_flags &= ~UF_NODUMP;
		from_cp->c_touch_chgtime = TRUE;
	}
	if ((to_cp->c_flags & UF_NODUMP) &&
	    (to_cp->c_parentcnid != from_cp->c_parentcnid)) {
		to_cp->c_flags &= ~UF_NODUMP;
		to_cp->c_touch_chgtime = TRUE;
	}

	HFS_KNOTE(from_vp, NOTE_ATTRIB);
	HFS_KNOTE(to_vp, NOTE_ATTRIB);

exit:
	if (got_cookie) {
	        cat_postflight(hfsmp, &cookie, vfs_context_proc(ap->a_context));
	}
	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	}

	hfs_unlockpair(from_cp, to_cp);
	return (error);
}


/*
 *  cnode must be locked
 */
__private_extern__
int
hfs_fsync(struct vnode *vp, int waitfor, int fullsync, struct proc *p)
{
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = NULL;
	int retval = 0;
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct timeval tv;
	int wait;
	int lockflag;
	int took_trunc_lock = 0;

	wait = (waitfor == MNT_WAIT);
	if (always_do_fullfsync)
		fullsync = 1;
	
	/* HFS directories don't have any data blocks. */
	if (vnode_isdir(vp))
		goto metasync;

	/*
	 * For system files flush the B-tree header and
	 * for regular files write out any clusters
	 */
	if (vnode_issystem(vp)) {
	    if (VTOF(vp)->fcbBTCBPtr != NULL) {
			// XXXdbg
			if (hfsmp->jnl == NULL) {
				BTFlushPath(VTOF(vp));
			}
	    }
	} else if (UBCINFOEXISTS(vp)) {
		hfs_unlock(cp);
		hfs_lock_truncate(cp, TRUE);
		took_trunc_lock = 1;

		/* Don't hold cnode lock when calling into cluster layer. */
		(void) cluster_push(vp, wait ? IO_SYNC : 0);

		hfs_lock(cp, HFS_FORCE_LOCK);
	}
	/*
	 * When MNT_WAIT is requested and the zero fill timeout
	 * has expired then we must explicitly zero out any areas
	 * that are currently marked invalid (holes).
	 *
	 * Files with NODUMP can bypass zero filling here.
	 */
	if ((wait || (cp->c_flag & C_ZFWANTSYNC)) &&
	    ((cp->c_flags & UF_NODUMP) == 0) &&
	    UBCINFOEXISTS(vp) && (vnode_issystem(vp) ==0) && (fp = VTOF(vp)) &&
	    cp->c_zftimeout != 0) {
		microuptime(&tv);
		if (!fullsync && tv.tv_sec < (long)cp->c_zftimeout) {
			/* Remember that a force sync was requested. */
			cp->c_flag |= C_ZFWANTSYNC;
			goto datasync;
		}
		if (!took_trunc_lock) {
			hfs_unlock(cp);
			hfs_lock_truncate(cp, TRUE);
			hfs_lock(cp, HFS_FORCE_LOCK);
			took_trunc_lock = 1;
		}

		while (!CIRCLEQ_EMPTY(&fp->ff_invalidranges)) {
			struct rl_entry *invalid_range = CIRCLEQ_FIRST(&fp->ff_invalidranges);
			off_t start = invalid_range->rl_start;
			off_t end = invalid_range->rl_end;
    		
			/* The range about to be written must be validated
			 * first, so that VNOP_BLOCKMAP() will return the
			 * appropriate mapping for the cluster code:
			 */
			rl_remove(start, end, &fp->ff_invalidranges);

			/* Don't hold cnode lock when calling into cluster layer. */
			hfs_unlock(cp);
			(void) cluster_write(vp, (struct uio *) 0,
					fp->ff_size, end + 1, start, (off_t)0,
					IO_HEADZEROFILL | IO_NOZERODIRTY | IO_NOCACHE);
			hfs_lock(cp, HFS_FORCE_LOCK);
			cp->c_flag |= C_MODIFIED;
		}
		hfs_unlock(cp);
		(void) cluster_push(vp, wait ? IO_SYNC : 0);
		hfs_lock(cp, HFS_FORCE_LOCK);

		cp->c_flag &= ~C_ZFWANTSYNC;
		cp->c_zftimeout = 0;
	}
datasync:
	if (took_trunc_lock)
		hfs_unlock_truncate(cp, TRUE);
	
	/*
	 * if we have a journal and if journal_active() returns != 0 then the
	 * we shouldn't do anything to a locked block (because it is part 
	 * of a transaction).  otherwise we'll just go through the normal 
	 * code path and flush the buffer.  note journal_active() can return
	 * -1 if the journal is invalid -- however we still need to skip any 
	 * locked blocks as they get cleaned up when we finish the transaction
	 * or close the journal.
	 */
	// if (hfsmp->jnl && journal_active(hfsmp->jnl) >= 0)
	if (hfsmp->jnl)
	        lockflag = BUF_SKIP_LOCKED;
	else
	        lockflag = 0;

	/*
	 * Flush all dirty buffers associated with a vnode.
	 */
	buf_flushdirtyblks(vp, wait, lockflag, "hfs_fsync");

metasync:
	if (vnode_isreg(vp) && vnode_issystem(vp)) {
		if (VTOF(vp)->fcbBTCBPtr != NULL) {
			microuptime(&tv);
			BTSetLastSync(VTOF(vp), tv.tv_sec);
		}
		cp->c_touch_acctime = FALSE;
		cp->c_touch_chgtime = FALSE;
		cp->c_touch_modtime = FALSE;
	} else if ( !(vp->v_flag & VSWAP) ) /* User file */ {
		retval = hfs_update(vp, wait);

		/*
		 * When MNT_WAIT is requested push out the catalog record for
		 * this file.  If they asked for a full fsync, we can skip this
		 * because the journal_flush or hfs_metasync_all will push out
		 * all of the metadata changes.
		 */
   		if ((retval == 0) && wait && !fullsync && cp->c_hint &&
   		    !ISSET(cp->c_flag, C_DELETED | C_NOEXISTS)) {
   			hfs_metasync(VTOHFS(vp), (daddr64_t)cp->c_hint, p);
		}

		/*
		 * If this was a full fsync, make sure all metadata
		 * changes get to stable storage.
		 */
		if (fullsync) {
		    if (hfsmp->jnl) {
			journal_flush(hfsmp->jnl);
		    } else {
			retval = hfs_metasync_all(hfsmp);
		    	/* XXX need to pass context! */
			VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, NULL);
		    }
		}
	}

	return (retval);
}


/* Sync an hfs catalog b-tree node */
static int
hfs_metasync(struct hfsmount *hfsmp, daddr64_t node, __unused struct proc *p)
{
	vnode_t	vp;
	buf_t	bp;
	int lockflags;

	vp = HFSTOVCB(hfsmp)->catalogRefNum;

	// XXXdbg - don't need to do this on a journaled volume
	if (hfsmp->jnl) {
		return 0;
	}

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	/*
	 * Look for a matching node that has been delayed
	 * but is not part of a set (B_LOCKED).
	 *
	 * BLK_ONLYVALID causes buf_getblk to return a
	 * buf_t for the daddr64_t specified only if it's
	 * currently resident in the cache... the size
	 * parameter to buf_getblk is ignored when this flag
	 * is set
	 */
	bp = buf_getblk(vp, node, 0, 0, 0, BLK_META | BLK_ONLYVALID);

	if (bp) {
	        if ((buf_flags(bp) & (B_LOCKED | B_DELWRI)) == B_DELWRI)
		        (void) VNOP_BWRITE(bp);
		else
		        buf_brelse(bp);
	}

	hfs_systemfile_unlock(hfsmp, lockflags);

	return (0);
}


/*
 * Sync all hfs B-trees.  Use this instead of journal_flush for a volume
 * without a journal.  Note that the volume bitmap does not get written;
 * we rely on fsck_hfs to fix that up (which it can do without any loss
 * of data).
 */
static int
hfs_metasync_all(struct hfsmount *hfsmp)
{
	int lockflags;

	/* Lock all of the B-trees so we get a mutually consistent state */
	lockflags = hfs_systemfile_lock(hfsmp,
		SFL_CATALOG|SFL_EXTENTS|SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	/* Sync each of the B-trees */
	if (hfsmp->hfs_catalog_vp)
		hfs_btsync(hfsmp->hfs_catalog_vp, 0);
	if (hfsmp->hfs_extents_vp)
		hfs_btsync(hfsmp->hfs_extents_vp, 0);
	if (hfsmp->hfs_attribute_vp)
		hfs_btsync(hfsmp->hfs_attribute_vp, 0);
	
	/* Wait for all of the writes to complete */
	if (hfsmp->hfs_catalog_vp)
		vnode_waitforwrites(hfsmp->hfs_catalog_vp, 0, 0, 0, "hfs_metasync_all");
	if (hfsmp->hfs_extents_vp)
		vnode_waitforwrites(hfsmp->hfs_extents_vp, 0, 0, 0, "hfs_metasync_all");
	if (hfsmp->hfs_attribute_vp)
		vnode_waitforwrites(hfsmp->hfs_attribute_vp, 0, 0, 0, "hfs_metasync_all");

	hfs_systemfile_unlock(hfsmp, lockflags);
	
	return 0;
}


/*ARGSUSED 1*/
static int
hfs_btsync_callback(struct buf *bp, __unused void *dummy)
{
	buf_clearflags(bp, B_LOCKED);
	(void) buf_bawrite(bp);

	return(BUF_CLAIMED);
}


__private_extern__
int
hfs_btsync(struct vnode *vp, int sync_transaction)
{
	struct cnode *cp = VTOC(vp);
	struct timeval tv;
	int    flags = 0;

	if (sync_transaction)
	        flags |= BUF_SKIP_NONLOCKED;
	/*
	 * Flush all dirty buffers associated with b-tree.
	 */
	buf_iterate(vp, hfs_btsync_callback, flags, 0);

	microuptime(&tv);
	if (vnode_issystem(vp) && (VTOF(vp)->fcbBTCBPtr != NULL))
		(void) BTSetLastSync(VTOF(vp), tv.tv_sec);
	cp->c_touch_acctime = FALSE;
	cp->c_touch_chgtime = FALSE;
	cp->c_touch_modtime = FALSE;

	return 0;
}

/*
 * Remove a directory.
 */
static int
hfs_vnop_rmdir(ap)
	struct vnop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct cnode *dcp = VTOC(dvp);
	struct cnode *cp = VTOC(vp);
	int error;

	if (!S_ISDIR(cp->c_mode)) {
		return (ENOTDIR);
	}
	if (dvp == vp) {
		return (EINVAL);
	}
	if ((error = hfs_lockpair(dcp, cp, HFS_EXCLUSIVE_LOCK))) {
		return (error);
	}
	error = hfs_removedir(dvp, vp, ap->a_cnp, 0);
	hfs_unlockpair(dcp, cp);

	return (error);
}

/*
 * Remove a directory
 *
 * Both dvp and vp cnodes are locked
 */
static int
hfs_removedir(struct vnode *dvp, struct vnode *vp, struct componentname *cnp,
              int skip_reserve)
{
	struct cnode *cp;
	struct cnode *dcp;
	struct hfsmount * hfsmp;
	struct cat_desc desc;
	int lockflags;
	int error = 0, started_tr = 0;

	cp = VTOC(vp);
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(vp);

	if (dcp == cp) {
		return (EINVAL);	/* cannot remove "." */
	}
	if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
		return (0);
	}
	if (cp->c_entries != 0) {
		return (ENOTEMPTY);
	}

	/* Check if we're removing the last link to an empty directory. */
	if (cp->c_flag & C_HARDLINK) {
		/* We could also return EBUSY here */
		return hfs_unlink(hfsmp, dvp, vp, cnp, skip_reserve);
	}

	if ((hfsmp->hfs_attribute_vp != NULL) &&
	    (cp->c_attr.ca_recflags & kHFSHasAttributesMask) != 0) {

	    return hfs_removefile(dvp, vp, cnp, 0, 0, 1);
	}

	dcp->c_flag |= C_DIR_MODIFICATION;

#if QUOTA
	if (hfsmp->hfs_flags & HFS_QUOTAS)
		(void)hfs_getinoquota(cp);
#endif
	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto out;
	}
	started_tr = 1;

	/*
	 * Verify the directory is empty (and valid).
	 * (Rmdir ".." won't be valid since
	 *  ".." will contain a reference to
	 *  the current directory and thus be
	 *  non-empty.)
	 */
	if ((dcp->c_flags & APPEND) || (cp->c_flags & (IMMUTABLE | APPEND))) {
		error = EPERM;
		goto out;
	}

	/* Remove the entry from the namei cache: */
	cache_purge(vp);

	/* 
	 * Protect against a race with rename by using the component
	 * name passed in and parent id from dvp (instead of using 
	 * the cp->c_desc which may have changed).
	 */
	desc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	desc.cd_namelen = cnp->cn_namelen;
	desc.cd_parentcnid = dcp->c_fileid;
	desc.cd_cnid = cp->c_cnid;
	desc.cd_flags = CD_ISDIR;
	desc.cd_encoding = cp->c_encoding;
	desc.cd_hint = 0;

	if (!hfs_valid_cnode(hfsmp, dvp, cnp, cp->c_fileid)) {
	    error = 0;
	    goto out;
	}

	/* Remove entry from catalog */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);

	if (!skip_reserve) {
		/*
		 * Reserve some space in the Catalog file.
		 */
		if ((error = cat_preflight(hfsmp, CAT_DELETE, NULL, 0))) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			goto out;
		}
	}

	error = cat_delete(hfsmp, &desc, &cp->c_attr);
	if (error == 0) {
		/* The parent lost a child */
		if (dcp->c_entries > 0)
			dcp->c_entries--;
		DEC_FOLDERCOUNT(hfsmp, dcp->c_attr);
		dcp->c_dirchangecnt++;
		dcp->c_touch_chgtime = TRUE;
		dcp->c_touch_modtime = TRUE;
		hfs_touchtimes(hfsmp, cp);
		(void) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);
		cp->c_flag &= ~(C_MODIFIED | C_FORCEUPDATE);
	}

	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error)
		goto out;

#if QUOTA
	if (hfsmp->hfs_flags & HFS_QUOTAS)
		(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */

	HFS_KNOTE(dvp, NOTE_WRITE | NOTE_LINK | NOTE_ATTRIB);

	hfs_volupdate(hfsmp, VOL_RMDIR, (dcp->c_cnid == kHFSRootFolderID));

	/*
	 * directory open or in use (e.g. opendir() or current working
	 * directory for some process); wait for inactive to actually
	 * remove catalog entry
	 */
	if (vnode_isinuse(vp, 0)) {
		cp->c_flag |= C_DELETED;
	} else {
		cp->c_mode = 0;  /* Makes the vnode go away...see inactive */
		cp->c_flag |= C_NOEXISTS;
	}
out:
	dcp->c_flag &= ~C_DIR_MODIFICATION;
	wakeup((caddr_t)&dcp->c_flag);

	HFS_KNOTE(vp, NOTE_DELETE);

	if (started_tr) { 
	    hfs_end_transaction(hfsmp);
	}

	return (error);
}


/*
 * Remove a file or link.
 */
static int
hfs_vnop_remove(ap)
	struct vnop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct cnode *dcp = VTOC(dvp);
	struct cnode *cp = VTOC(vp);
	struct vnode *rvp = cp->c_rsrc_vp;
	int error=0, recycle_rsrc=0, rvid=0;

	if (dvp == vp) {
		return (EINVAL);
	}

	hfs_lock_truncate(cp, TRUE);

	if ((error = hfs_lockpair(dcp, cp, HFS_EXCLUSIVE_LOCK))) {
		hfs_unlock_truncate(cp, TRUE);
		return (error);
	}
	error = hfs_removefile(dvp, vp, ap->a_cnp, ap->a_flags, 0, 0);

	//
	// If the remove succeeded and it's an open-unlinked file that has
	// a resource fork vnode that's not in use, we will want to recycle
	// the rvp *after* we're done unlocking everything.  Otherwise the
	// resource vnode will keep a v_parent reference on this vnode which
	// prevents it from going through inactive/reclaim which means that
	// the disk space associated with this file won't get free'd until
	// something forces the resource vnode to get recycled (and that can
	// take a very long time).
	//
	if (error == 0 && (cp->c_flag & C_DELETED) && rvp && !vnode_isinuse(rvp, 0)) {
	    rvid = vnode_vid(rvp);
	    recycle_rsrc = 1;
	}

	/*
	 * Drop the truncate lock before unlocking the cnode
	 * (which can potentially perform a vnode_put and
	 * recycle the vnode which in turn might require the
	 * truncate lock)
	 */
	hfs_unlock_truncate(cp, TRUE);
	hfs_unlockpair(dcp, cp);

	if (recycle_rsrc && vnode_getwithvid(rvp, rvid) == 0) {
		vnode_ref(rvp);
		vnode_rele(rvp);
		vnode_recycle(rvp);
		vnode_put(rvp);
	} 
	
	return (error);
}


static int
hfs_removefile_callback(struct buf *bp, void *hfsmp) {

        if ( !(buf_flags(bp) & B_META))
	        panic("hfs: symlink bp @ %p is not marked meta-data!\n", bp);
	/*
	 * it's part of the current transaction, kill it.
	 */
	journal_kill_block(((struct hfsmount *)hfsmp)->jnl, bp);

	return (BUF_CLAIMED);
}

/*
 * hfs_removefile
 *
 * Similar to hfs_vnop_remove except there are additional options.
 *
 * Requires cnode and truncate locks to be held.
 */
static int
hfs_removefile(struct vnode *dvp, struct vnode *vp, struct componentname *cnp,
               int flags, int skip_reserve, int allow_dirs)
{
	struct vnode *rvp = NULL;
	struct cnode *cp;
	struct cnode *dcp;
	struct hfsmount *hfsmp;
	struct cat_desc desc;
	struct timeval tv;
	vfs_context_t ctx = cnp->cn_context;
	int dataforkbusy = 0;
	int rsrcforkbusy = 0;
	int truncated = 0;
	int lockflags;
	int error = 0;
	int started_tr = 0;
	int isbigfile = 0, defer_remove=0, isdir=0;

	cp = VTOC(vp);
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(vp);

	/* Check if we lost a race post lookup. */
	if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
		return (0);
	}

	if (!hfs_valid_cnode(hfsmp, dvp, cnp, cp->c_fileid)) {
	    return 0;
	}

	/* Make sure a remove is permitted */
	if (VNODE_IS_RSRC(vp)) {
		return (EPERM);
	}
	/* Don't allow deleting the journal or journal_info_block. */
	if (hfsmp->jnl &&
	    (cp->c_fileid == hfsmp->hfs_jnlfileid || cp->c_fileid == hfsmp->hfs_jnlinfoblkid)) {
		return (EPERM);
	}
	/*
	 * Hard links require special handling.
	 */
	if (cp->c_flag & C_HARDLINK) {
		if ((flags & VNODE_REMOVE_NODELETEBUSY) && vnode_isinuse(vp, 0)) {
			return (EBUSY);
		} else {
			/* A directory hard link with a link count of one is 
			 * treated as a regular directory.  Therefore it should 
			 * only be removed using rmdir().
			 */
			if ((vnode_isdir(vp) == 1) && (cp->c_linkcount == 1) && 
			    (allow_dirs == 0)) {
			    	return (EPERM);
			}
			return hfs_unlink(hfsmp, dvp, vp, cnp, skip_reserve);
		}
	}
	/* Directories should call hfs_rmdir! (unless they have a lot of attributes) */
	if (vnode_isdir(vp)) {
		if (allow_dirs == 0)
			return (EPERM);  /* POSIX */
		isdir = 1;
	}
	/* Sanity check the parent ids. */
	if ((cp->c_parentcnid != hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) &&
	    (cp->c_parentcnid != dcp->c_fileid)) {
		return (EINVAL);
	}

	dcp->c_flag |= C_DIR_MODIFICATION;

	// this guy is going away so mark him as such
	cp->c_flag |= C_DELETED;


	/* Remove our entry from the namei cache. */
	cache_purge(vp);

	/*
	 * Acquire a vnode for a non-empty resource fork.
	 * (needed for hfs_truncate)
	 */
	if (isdir == 0 && (cp->c_blocks - VTOF(vp)->ff_blocks)) {
		/*
		 * We must avoid calling hfs_vgetrsrc() when we have
		 * an active resource fork vnode to avoid deadlocks
		 * when that vnode is in the VL_TERMINATE state. We
		 * can defer removing the file and its resource fork
		 * until the call to hfs_vnop_inactive() occurs.
		 */
		if (cp->c_rsrc_vp) {
			defer_remove = 1;
		} else {
			error = hfs_vgetrsrc(hfsmp, vp, &rvp, FALSE);
			if (error)
				goto out;
			/* Defer the vnode_put on rvp until the hfs_unlock(). */
			cp->c_flag |= C_NEED_RVNODE_PUT;
		}
	}
	/* Check if this file is being used. */
	if (isdir == 0) {
		dataforkbusy = vnode_isinuse(vp, 0);
		rsrcforkbusy = rvp ? vnode_isinuse(rvp, 0) : 0;
	}
	
	/* Check if we have to break the deletion into multiple pieces. */
	if (isdir == 0) {
		isbigfile = ((cp->c_datafork->ff_size >= HFS_BIGFILE_SIZE) && overflow_extents(VTOF(vp)));
	}

	/* Check if the file has xattrs.  If it does we'll have to delete them in
	   individual transactions in case there are too many */
	if ((hfsmp->hfs_attribute_vp != NULL) &&
	    (cp->c_attr.ca_recflags & kHFSHasAttributesMask) != 0) {
	    defer_remove = 1;
	}

	/*
	 * Carbon semantics prohibit deleting busy files.
	 * (enforced when VNODE_REMOVE_NODELETEBUSY is requested)
	 */
	if (dataforkbusy || rsrcforkbusy) {
		if ((flags & VNODE_REMOVE_NODELETEBUSY) ||
		    (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid == 0)) {
			error = EBUSY;
			goto out;
		}
	}

#if QUOTA
	if (hfsmp->hfs_flags & HFS_QUOTAS)
		(void)hfs_getinoquota(cp);
#endif /* QUOTA */

	/* Check if we need a ubc_setsize. */
	if (isdir == 0 && (!dataforkbusy || !rsrcforkbusy)) {
		/*
		 * A ubc_setsize can cause a pagein so defer it
		 * until after the cnode lock is dropped.  The
		 * cnode lock cannot be dropped/reacquired here
		 * since we might already hold the journal lock.
		 */
		if (!dataforkbusy && cp->c_datafork->ff_blocks && !isbigfile) {
			cp->c_flag |= C_NEED_DATA_SETSIZE;
		}
		if (!rsrcforkbusy && rvp) {
			cp->c_flag |= C_NEED_RSRC_SETSIZE;
		}
	}

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto out;
	}
	started_tr = 1;

	// XXXdbg - if we're journaled, kill any dirty symlink buffers 
	if (hfsmp->jnl && vnode_islnk(vp))
	        buf_iterate(vp, hfs_removefile_callback, BUF_SKIP_NONLOCKED, (void *)hfsmp);

	/*
	 * Truncate any non-busy forks.  Busy forks will
	 * get truncated when their vnode goes inactive.
	 *
	 * Since we're already inside a transaction,
	 * tell hfs_truncate to skip the ubc_setsize.
	 */
	if (isdir == 0) {
		int mode = cp->c_mode;

		if (!dataforkbusy && !isbigfile && cp->c_datafork->ff_blocks != 0) {
			cp->c_mode = 0;  /* Suppress hfs_update */
			error = hfs_truncate(vp, (off_t)0, IO_NDELAY, 1, ctx);
			cp->c_mode = mode;
			if (error)
				goto out;
			truncated = 1;
		}
		if (!rsrcforkbusy && rvp) {
			cp->c_mode = 0;  /* Suppress hfs_update */
			error = hfs_truncate(rvp, (off_t)0, IO_NDELAY, 1, ctx);
			cp->c_mode = mode;
			if (error)
				goto out;
			truncated = 1;
		}
	}

	/* 
	 * Protect against a race with rename by using the component
	 * name passed in and parent id from dvp (instead of using 
	 * the cp->c_desc which may have changed).  
	 */
	desc.cd_flags = 0;
	desc.cd_encoding = cp->c_desc.cd_encoding;
	desc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	desc.cd_namelen = cnp->cn_namelen;
	desc.cd_parentcnid = dcp->c_fileid;
	desc.cd_hint = cp->c_desc.cd_hint;
	desc.cd_cnid = cp->c_cnid;
	microtime(&tv);

	/*
	 * There are two cases to consider:
	 *  1. File is busy/big/defer_remove ==> move/rename the file
	 *  2. File is not in use ==> remove the file
	 */
	if (dataforkbusy || rsrcforkbusy || isbigfile || defer_remove) {
		char delname[32];
		struct cat_desc to_desc;
		struct cat_desc todir_desc;

		/*
		 * Orphan this file (move to hidden directory).
		 */
		bzero(&todir_desc, sizeof(todir_desc));
		todir_desc.cd_parentcnid = 2;

		MAKE_DELETED_NAME(delname, sizeof(delname), cp->c_fileid);
		bzero(&to_desc, sizeof(to_desc));
		to_desc.cd_nameptr = (const u_int8_t *)delname;
		to_desc.cd_namelen = strlen(delname);
		to_desc.cd_parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
		to_desc.cd_flags = 0;
		to_desc.cd_cnid = cp->c_cnid;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
		if (!skip_reserve) {
			if ((error = cat_preflight(hfsmp, CAT_RENAME, NULL, 0))) {
				hfs_systemfile_unlock(hfsmp, lockflags);
				goto out;
			}
		}

		error = cat_rename(hfsmp, &desc, &todir_desc,
				&to_desc, (struct cat_desc *)NULL);

		if (error == 0) {
			hfsmp->hfs_private_attr[FILE_HARDLINKS].ca_entries++;
			if (isdir == 1) {
				INC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[FILE_HARDLINKS]);
			}
			(void) cat_update(hfsmp, &hfsmp->hfs_private_desc[FILE_HARDLINKS],
			                  &hfsmp->hfs_private_attr[FILE_HARDLINKS], NULL, NULL);

			/* Update the parent directory */
			if (dcp->c_entries > 0)
				dcp->c_entries--;
			if (isdir == 1) {
				DEC_FOLDERCOUNT(hfsmp, dcp->c_attr);
			}
			dcp->c_dirchangecnt++;
			dcp->c_ctime = tv.tv_sec;
			dcp->c_mtime = tv.tv_sec;
			(void) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);

			/* Update the file's state */
			cp->c_flag |= C_DELETED;
			cp->c_ctime = tv.tv_sec;
			--cp->c_linkcount;
			(void) cat_update(hfsmp, &to_desc, &cp->c_attr, NULL, NULL);
		}
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error)
			goto out;

	} else /* Not busy */ {

		if (cp->c_blocks > 0) {
			printf("hfs_remove: attempting to delete a non-empty file %s\n",
				cp->c_desc.cd_nameptr);
			error = EBUSY;
			goto out;
		}

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
		if (!skip_reserve) {
			if ((error = cat_preflight(hfsmp, CAT_DELETE, NULL, 0))) {
				hfs_systemfile_unlock(hfsmp, lockflags);
				goto out;
			}
		}

		error = cat_delete(hfsmp, &desc, &cp->c_attr);

		if (error && error != ENXIO && error != ENOENT && truncated) {
			if ((cp->c_datafork && cp->c_datafork->ff_size != 0) ||
				(cp->c_rsrcfork && cp->c_rsrcfork->ff_size != 0)) {
				panic("hfs: remove: couldn't delete a truncated file! (%d, data sz %lld; rsrc sz %lld)",
					  error, cp->c_datafork->ff_size, cp->c_rsrcfork->ff_size);
			} else {
				printf("hfs: remove: strangely enough, deleting truncated file %s (%d) got err %d\n",
					   cp->c_desc.cd_nameptr, cp->c_attr.ca_fileid, error);
			}
		}
		if (error == 0) {
			/* Update the parent directory */
			if (dcp->c_entries > 0)
				dcp->c_entries--;
			dcp->c_dirchangecnt++;
			dcp->c_ctime = tv.tv_sec;
			dcp->c_mtime = tv.tv_sec;
			(void) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);
		}
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error)
			goto out;

#if QUOTA
		if (hfsmp->hfs_flags & HFS_QUOTAS)
			(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */

		cp->c_mode = 0;
		truncated  = 0;    // because the catalog entry is gone
		cp->c_flag |= C_NOEXISTS;
		cp->c_flag &= ~C_DELETED;
		cp->c_touch_chgtime = TRUE;   /* XXX needed ? */
		--cp->c_linkcount;

		hfs_volupdate(hfsmp, VOL_RMFILE, (dcp->c_cnid == kHFSRootFolderID));
	}

	/*
	 * All done with this cnode's descriptor...
	 *
	 * Note: all future catalog calls for this cnode must be by
	 * fileid only.  This is OK for HFS (which doesn't have file
	 * thread records) since HFS doesn't support the removal of
	 * busy files.
	 */
	cat_releasedesc(&cp->c_desc);

	HFS_KNOTE(dvp, NOTE_WRITE);

out:
	if (error) {
	    cp->c_flag &= ~C_DELETED;
	}

	/* Commit the truncation to the catalog record */
	if (truncated) {
	    cp->c_flag |= C_FORCEUPDATE;
	    cp->c_touch_chgtime = TRUE;
	    cp->c_touch_modtime = TRUE;
	    (void) hfs_update(vp, 0);
	}

	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	}

	dcp->c_flag &= ~C_DIR_MODIFICATION;
	wakeup((caddr_t)&dcp->c_flag);

	HFS_KNOTE(vp, NOTE_DELETE);
	if (rvp) {
		HFS_KNOTE(rvp, NOTE_DELETE);
	}

	return (error);
}


__private_extern__ void
replace_desc(struct cnode *cp, struct cat_desc *cdp)
{
	// fixes 4348457 and 4463138
	if (&cp->c_desc == cdp) {
	    return;
	}

	/* First release allocated name buffer */
	if (cp->c_desc.cd_flags & CD_HASBUF && cp->c_desc.cd_nameptr != 0) {
		const u_int8_t *name = cp->c_desc.cd_nameptr;

		cp->c_desc.cd_nameptr = 0;
		cp->c_desc.cd_namelen = 0;
		cp->c_desc.cd_flags &= ~CD_HASBUF;
		vfs_removename((const char *)name);
	}
	bcopy(cdp, &cp->c_desc, sizeof(cp->c_desc));

	/* Cnode now owns the name buffer */
	cdp->cd_nameptr = 0;
	cdp->cd_namelen = 0;
	cdp->cd_flags &= ~CD_HASBUF;
}


/*
 * Rename a cnode.
 *
 * The VFS layer guarantees that:
 *   - source and destination will either both be directories, or
 *     both not be directories.
 *   - all the vnodes are from the same file system
 *
 * When the target is a directory, HFS must ensure that its empty.
 */
static int
hfs_vnop_rename(ap)
	struct vnop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *rvp = NULLVP;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	struct proc *p = vfs_context_proc(ap->a_context);
	struct cnode *fcp;
	struct cnode *fdcp;
	struct cnode *tdcp;
	struct cnode *tcp;
	struct cat_desc from_desc;
	struct cat_desc to_desc;
	struct cat_desc out_desc;
	struct hfsmount *hfsmp;
	cat_cookie_t cookie;
	int tvp_deleted = 0;
	int started_tr = 0, got_cookie = 0;
	int took_trunc_lock = 0;
	int lockflags;
	int error;
	int rsrc_vid = 0;
	int recycle_rsrc = 0;
	
	/* When tvp exist, take the truncate lock for the hfs_removefile(). */
	if (tvp && (vnode_isreg(tvp) || vnode_islnk(tvp))) {
		hfs_lock_truncate(VTOC(tvp), TRUE);
		took_trunc_lock = 1;
	}

  retry:
	error = hfs_lockfour(VTOC(fdvp), VTOC(fvp), VTOC(tdvp), tvp ? VTOC(tvp) : NULL,
	                     HFS_EXCLUSIVE_LOCK);
	if (error) {
		if (took_trunc_lock)
			hfs_unlock_truncate(VTOC(tvp), TRUE);	
		return (error);
	}

	fdcp = VTOC(fdvp);
	fcp = VTOC(fvp);
	tdcp = VTOC(tdvp);
	tcp = tvp ? VTOC(tvp) : NULL;
	hfsmp = VTOHFS(tdvp);

	/* Check for a race against unlink. */
	if ((fcp->c_flag & (C_NOEXISTS | C_DELETED)) || !hfs_valid_cnode(hfsmp, fdvp, fcnp, fcp->c_fileid)) {
		error = ENOENT;
		goto out;
	}

	if (tcp && ((tcp->c_flag & (C_NOEXISTS | C_DELETED)) || !hfs_valid_cnode(hfsmp, tdvp, tcnp, tcp->c_fileid))) {
	    //
	    // hmm, the destination vnode isn't valid any more.
	    // in this case we can just drop him and pretend he
	    // never existed in the first place.
	    //
	    if (took_trunc_lock) {
		hfs_unlock_truncate(VTOC(tvp), TRUE);
		took_trunc_lock = 0;
	    }

	    hfs_unlockfour(fdcp, fcp, tdcp, tcp);

	    tcp = NULL;
	    tvp = NULL;
	    
	    // retry the locking with tvp null'ed out
	    goto retry;
	}

	fdcp->c_flag |= C_DIR_MODIFICATION;
	if (fdvp != tdvp) {
	    tdcp->c_flag |= C_DIR_MODIFICATION;
	}

	/*
	 * Disallow renaming of a directory hard link if the source and 
	 * destination parent directories are different, or a directory whose 
	 * descendant is a directory hard link and the one of the ancestors
	 * of the destination directory is a directory hard link.
	 */
	if (vnode_isdir(fvp) && (fdvp != tdvp)) {
		if (fcp->c_flag & C_HARDLINK) {
			error = EPERM;
			goto out;
		}
		if (fcp->c_attr.ca_recflags & kHFSHasChildLinkMask) {
		    lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		    if (cat_check_link_ancestry(hfsmp, tdcp->c_fileid, 0)) {
				error = EPERM;
				hfs_systemfile_unlock(hfsmp, lockflags);
				goto out;
			}
			hfs_systemfile_unlock(hfsmp, lockflags);
		}
	}

	/*
	 * The following edge case is caught here:
	 * (to cannot be a descendent of from)
	 *
	 *       o fdvp
	 *      /
	 *     /
	 *    o fvp
	 *     \
	 *      \
	 *       o tdvp
	 *      /
	 *     /
	 *    o tvp
	 */
	if (tdcp->c_parentcnid == fcp->c_fileid) {
		error = EINVAL;
		goto out;
	}

	/*
	 * The following two edge cases are caught here:
	 * (note tvp is not empty)
	 *
	 *       o tdvp               o tdvp
	 *      /                    /
	 *     /                    /
	 *    o tvp            tvp o fdvp
	 *     \                    \
	 *      \                    \
	 *       o fdvp               o fvp
	 *      /
	 *     /
	 *    o fvp
	 */
	if (tvp && vnode_isdir(tvp) && (tcp->c_entries != 0) && fvp != tvp) {
		error = ENOTEMPTY;
		goto out;
	}

	/*
	 * The following edge case is caught here:
	 * (the from child and parent are the same)
	 *
	 *          o tdvp
	 *         /
	 *        /
	 *  fdvp o fvp
	 */
	if (fdvp == fvp) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Make sure "from" vnode and its parent are changeable.
	 */
	if ((fcp->c_flags & (IMMUTABLE | APPEND)) || (fdcp->c_flags & APPEND)) {
		error = EPERM;
		goto out;
	}

	/*
	 * If the destination parent directory is "sticky", then the
	 * user must own the parent directory, or the destination of
	 * the rename, otherwise the destination may not be changed
	 * (except by root). This implements append-only directories.
	 *
	 * Note that checks for immutable and write access are done
	 * by the call to hfs_removefile.
	 */
	if (tvp && (tdcp->c_mode & S_ISTXT) &&
	    (suser(vfs_context_ucred(tcnp->cn_context), NULL)) &&
	    (kauth_cred_getuid(vfs_context_ucred(tcnp->cn_context)) != tdcp->c_uid) &&
	    (hfs_owner_rights(hfsmp, tcp->c_uid, vfs_context_ucred(tcnp->cn_context), p, false)) ) {
		error = EPERM;
		goto out;
	}

#if QUOTA
	if (tvp)
		(void)hfs_getinoquota(tcp);
#endif
	/* Preflighting done, take fvp out of the name space. */
	cache_purge(fvp);

	/*
	 * When a file moves out of "Cleanup At Startup"
	 * we can drop its NODUMP status.
	 */
	if ((fcp->c_flags & UF_NODUMP) &&
	    vnode_isreg(fvp) &&
	    (fdvp != tdvp) &&
	    (fdcp->c_desc.cd_nameptr != NULL) &&
	    (strncmp((const char *)fdcp->c_desc.cd_nameptr,
		     CARBON_TEMP_DIR_NAME,
		     sizeof(CARBON_TEMP_DIR_NAME)) == 0)) {
		fcp->c_flags &= ~UF_NODUMP;
		fcp->c_touch_chgtime = TRUE;
		(void) hfs_update(fvp, 0);
	}

	bzero(&from_desc, sizeof(from_desc));
	from_desc.cd_nameptr = (const u_int8_t *)fcnp->cn_nameptr;
	from_desc.cd_namelen = fcnp->cn_namelen;
	from_desc.cd_parentcnid = fdcp->c_fileid;
	from_desc.cd_flags = fcp->c_desc.cd_flags & ~(CD_HASBUF | CD_DECOMPOSED);
	from_desc.cd_cnid = fcp->c_cnid;

	bzero(&to_desc, sizeof(to_desc));
	to_desc.cd_nameptr = (const u_int8_t *)tcnp->cn_nameptr;
	to_desc.cd_namelen = tcnp->cn_namelen;
	to_desc.cd_parentcnid = tdcp->c_fileid;
	to_desc.cd_flags = fcp->c_desc.cd_flags & ~(CD_HASBUF | CD_DECOMPOSED);
	to_desc.cd_cnid = fcp->c_cnid;

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto out;
	}
	started_tr = 1;

	/* hfs_vnop_link() and hfs_vnop_rename() set kHFSHasChildLinkMask 
	 * inside a journal transaction and without holding a cnode lock.  
	 * As setting of this bit depends on being in journal transaction for 
	 * concurrency, check this bit again after we start journal transaction for rename
	 * to ensure that this directory does not have any descendant that
	 * is a directory hard link. 
	 */
	if (vnode_isdir(fvp) && (fdvp != tdvp)) {
		if (fcp->c_attr.ca_recflags & kHFSHasChildLinkMask) {
		    lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		    if (cat_check_link_ancestry(hfsmp, tdcp->c_fileid, 0)) {
				error = EPERM;
				hfs_systemfile_unlock(hfsmp, lockflags);
				goto out;
			}
			hfs_systemfile_unlock(hfsmp, lockflags);
		}
	}

	// if it's a hardlink then re-lookup the name so
	// that we get the correct cnid in from_desc (see
	// the comment in hfs_removefile for more details)
	//
	if (fcp->c_flag & C_HARDLINK) {
	    struct cat_desc tmpdesc;
	    cnid_t real_cnid;

	    tmpdesc.cd_nameptr = (const u_int8_t *)fcnp->cn_nameptr;
	    tmpdesc.cd_namelen = fcnp->cn_namelen;
	    tmpdesc.cd_parentcnid = fdcp->c_fileid;
	    tmpdesc.cd_hint = fdcp->c_childhint;
	    tmpdesc.cd_flags = fcp->c_desc.cd_flags & CD_ISDIR;
	    tmpdesc.cd_encoding = 0;
	    
	    lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	    if (cat_lookup(hfsmp, &tmpdesc, 0, NULL, NULL, NULL, &real_cnid) != 0) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		goto out;
	    }

	    // use the real cnid instead of whatever happened to be there
	    from_desc.cd_cnid = real_cnid;
	    hfs_systemfile_unlock(hfsmp, lockflags);
	}

	/*
	 * Reserve some space in the Catalog file.
	 */
	if ((error = cat_preflight(hfsmp, CAT_RENAME + CAT_DELETE, &cookie, p))) {
		goto out;
	}
	got_cookie = 1;

	/*
	 * If the destination exists then it may need to be removed.
	 */
	if (tvp) {
		/*
		 * When fvp matches tvp they could be case variants
		 * or matching hard links.
		 */
		if (fvp == tvp) {
			if (!(fcp->c_flag & C_HARDLINK)) {
				goto skip_rm;  /* simple case variant */

			} else if ((fdvp != tdvp) ||
			           (hfsmp->hfs_flags & HFS_CASE_SENSITIVE)) {
				goto out;  /* matching hardlinks, nothing to do */

			} else if (hfs_namecmp((const u_int8_t *)fcnp->cn_nameptr, fcnp->cn_namelen,
			                       (const u_int8_t *)tcnp->cn_nameptr, tcnp->cn_namelen) == 0) {
				goto skip_rm;  /* case-variant hardlink in the same dir */
			} else {
				goto out;  /* matching hardlink, nothing to do */
			}
		}

		if (vnode_isdir(tvp))
			error = hfs_removedir(tdvp, tvp, tcnp, HFSRM_SKIP_RESERVE);
		else {
			if (tcp){
				rvp = tcp->c_rsrc_vp;
			}
			error = hfs_removefile(tdvp, tvp, tcnp, 0, HFSRM_SKIP_RESERVE, 0);
				
			/* If the destination file had a resource fork vnode, we couldn't do 
			 * anything about it in hfs_removefile because we didn't have a reference on it.  
			 * We need to take action here to prevent it from leaking blocks.  If removefile 
			 * succeeded, then squirrel away the vid of the resource fork vnode and force a 
			 * recycle after dropping all of the locks. The vid is guaranteed not to change 
			 * at this point because we still hold the cnode lock.
			 */
			if ((error == 0) && (tcp->c_flag & C_DELETED) && rvp && !vnode_isinuse(rvp, 0)) {
				rsrc_vid = vnode_vid(rvp);	
				recycle_rsrc = 1;
			}
		}

		if (error)
			goto out;
		tvp_deleted = 1;
	}
skip_rm:
	/*
	 * All done with tvp and fvp
	 */

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	error = cat_rename(hfsmp, &from_desc, &tdcp->c_desc, &to_desc, &out_desc);
	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error) {
		goto out;
	}

	/* Invalidate negative cache entries in the destination directory */
	if (tdcp->c_flag & C_NEG_ENTRIES) {
		cache_purge_negatives(tdvp);
		tdcp->c_flag &= ~C_NEG_ENTRIES;
	}

	/* Update cnode's catalog descriptor */
	replace_desc(fcp, &out_desc);
	fcp->c_parentcnid = tdcp->c_fileid;
	fcp->c_hint = 0;

	hfs_volupdate(hfsmp, vnode_isdir(fvp) ? VOL_RMDIR : VOL_RMFILE,
	              (fdcp->c_cnid == kHFSRootFolderID));
	hfs_volupdate(hfsmp, vnode_isdir(fvp) ? VOL_MKDIR : VOL_MKFILE,
	              (tdcp->c_cnid == kHFSRootFolderID));

	/* Update both parent directories. */
	if (fdvp != tdvp) {
		if (vnode_isdir(fvp)) {
			/* If the source directory has directory hard link 
			 * descendants, set the kHFSHasChildLinkBit in the 
			 * destination parent hierarchy 
			 */
			if ((fcp->c_attr.ca_recflags & kHFSHasChildLinkMask) && 
			    !(tdcp->c_attr.ca_recflags & kHFSHasChildLinkMask)) {

				tdcp->c_attr.ca_recflags |= kHFSHasChildLinkMask;

				error = cat_set_childlinkbit(hfsmp, tdcp->c_parentcnid);
				if (error) {
					printf ("hfs_vnop_rename: error updating parent chain for %u\n", tdcp->c_cnid);
					error = 0;
				}
			}
			INC_FOLDERCOUNT(hfsmp, tdcp->c_attr);
			DEC_FOLDERCOUNT(hfsmp, fdcp->c_attr);
		}
		tdcp->c_entries++;
		tdcp->c_dirchangecnt++;
		if (fdcp->c_entries > 0)
			fdcp->c_entries--;
		fdcp->c_dirchangecnt++;
		fdcp->c_touch_chgtime = TRUE;
		fdcp->c_touch_modtime = TRUE;

		fdcp->c_flag |= C_FORCEUPDATE;  // XXXdbg - force it out!
		(void) hfs_update(fdvp, 0);
	}
	tdcp->c_childhint = out_desc.cd_hint;	/* Cache directory's location */
	tdcp->c_touch_chgtime = TRUE;
	tdcp->c_touch_modtime = TRUE;

	tdcp->c_flag |= C_FORCEUPDATE;  // XXXdbg - force it out!
	(void) hfs_update(tdvp, 0);
out:
	if (got_cookie) {
		cat_postflight(hfsmp, &cookie, p);
	}
	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	}

	/* Note that if hfs_removedir or hfs_removefile was invoked above they will already have
	   generated a NOTE_WRITE for tdvp and a NOTE_DELETE for tvp.
	 */
	if (error == 0) {
		HFS_KNOTE(fvp, NOTE_RENAME);
		HFS_KNOTE(fdvp, NOTE_WRITE);
		if (tdvp != fdvp) HFS_KNOTE(tdvp, NOTE_WRITE);
	};

	fdcp->c_flag &= ~C_DIR_MODIFICATION;
	wakeup((caddr_t)&fdcp->c_flag);
	if (fdvp != tdvp) {
	    tdcp->c_flag &= ~C_DIR_MODIFICATION;
	    wakeup((caddr_t)&tdcp->c_flag);
	}

	if (took_trunc_lock)
		hfs_unlock_truncate(VTOC(tvp), TRUE);	

	hfs_unlockfour(fdcp, fcp, tdcp, tcp);

	/* Now that we've dropped locks, see if we need to force recycle on the old
	 * destination's rsrc fork, preventing a leak of the rsrc fork's blocks.  Note that
	 * doing the ref/rele is in order to twiddle the VL_INACTIVE bit to the vnode's flags
	 * so that on the last vnode_put for this vnode, we will force vnop_inactive to be triggered.
	 */
	if ((recycle_rsrc) && (vnode_getwithvid(rvp, rsrc_vid) == 0)) {		
		vnode_ref(rvp);
		vnode_rele(rvp);
		vnode_recycle(rvp);
		vnode_put (rvp);
	}


	/* After tvp is removed the only acceptable error is EIO */
	if (error && tvp_deleted)
		error = EIO;

	return (error);
}


/*
 * Make a directory.
 */
static int
hfs_vnop_mkdir(struct vnop_mkdir_args *ap)
{
	/***** HACK ALERT ********/
	ap->a_cnp->cn_flags |= MAKEENTRY;
	return hfs_makenode(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap, ap->a_context);
}


/*
 * Create a symbolic link.
 */
static int
hfs_vnop_symlink(struct vnop_symlink_args *ap)
{
	struct vnode **vpp = ap->a_vpp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = NULL;
	struct cnode *cp = NULL;
	struct hfsmount *hfsmp;
	struct filefork *fp;
	struct buf *bp = NULL;
	char *datap;
	int started_tr = 0;
	u_int32_t len;
	int error;

	/* HFS standard disks don't support symbolic links */
	if (VTOVCB(dvp)->vcbSigWord != kHFSPlusSigWord)
		return (ENOTSUP);

	/* Check for empty target name */
	if (ap->a_target[0] == 0)
		return (EINVAL);

	hfsmp = VTOHFS(dvp);
	len = strlen(ap->a_target);

	/* Check for free space */
	if (((u_int64_t)hfs_freeblks(hfsmp, 0) * (u_int64_t)hfsmp->blockSize) < len) {
		return (ENOSPC);
	}

	/* Create the vnode */
	ap->a_vap->va_mode |= S_IFLNK;
	if ((error = hfs_makenode(dvp, vpp, ap->a_cnp, ap->a_vap, ap->a_context))) {
		goto out;
	}
	vp = *vpp;
	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
		goto out;
	}
	cp = VTOC(vp);
	fp = VTOF(vp);

	if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
	    goto out;
	}

#if QUOTA
	(void)hfs_getinoquota(cp);
#endif /* QUOTA */

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto out;
	}
	started_tr = 1;

	/*
	 * Allocate space for the link.
	 *
	 * Since we're already inside a transaction,
	 * tell hfs_truncate to skip the ubc_setsize.
	 *
	 * Don't need truncate lock since a symlink is treated as a system file.
	 */
	error = hfs_truncate(vp, len, IO_NOZEROFILL, 1, ap->a_context);

	/* On errors, remove the symlink file */
	if (error) {
		/*
		 * End the transaction so we don't re-take the cnode lock
		 * below while inside a transaction (lock order violation).
		 */
		hfs_end_transaction(hfsmp);

		/* hfs_removefile() requires holding the truncate lock */
		hfs_unlock(cp);
		hfs_lock_truncate(cp, TRUE);
		hfs_lock(cp, HFS_FORCE_LOCK);

		if (hfs_start_transaction(hfsmp) != 0) {
			started_tr = 0;
			hfs_unlock_truncate(cp, TRUE);
			goto out;
		}
		
		(void) hfs_removefile(dvp, vp, ap->a_cnp, 0, 0, 0);
		hfs_unlock_truncate(cp, TRUE);
		goto out;	
	}

	/* Write the link to disk */
	bp = buf_getblk(vp, (daddr64_t)0, roundup((int)fp->ff_size, VTOHFS(vp)->hfs_phys_block_size),
			0, 0, BLK_META);
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}
	datap = (char *)buf_dataptr(bp);
	bzero(datap, buf_size(bp));
	bcopy(ap->a_target, datap, len);

	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp, NULL, NULL);
	} else {
		buf_bawrite(bp);
	}
	/*
	 * We defered the ubc_setsize for hfs_truncate
	 * since we were inside a transaction.
	 *
	 * We don't need to drop the cnode lock here
	 * since this is a symlink.
	 */
	ubc_setsize(vp, len);
out:
	if (started_tr)
	    hfs_end_transaction(hfsmp);
	if ((cp != NULL) && (vp != NULL)) {
		hfs_unlock(cp);
	}
	if (error) {
		if (vp) {
			vnode_put(vp);
		}
		*vpp = NULL;
	}
	return (error);
}


/* structures to hold a "." or ".." directory entry */
struct hfs_stddotentry {
	u_int32_t	d_fileno;   /* unique file number */
	u_int16_t	d_reclen;   /* length of this structure */
	u_int8_t	d_type;     /* dirent file type */
	u_int8_t	d_namlen;   /* len of filename */
	char		d_name[4];  /* "." or ".." */
};

struct hfs_extdotentry {
	u_int64_t  d_fileno;   /* unique file number */
	u_int64_t  d_seekoff;  /* seek offset (optional, used by servers) */
	u_int16_t  d_reclen;   /* length of this structure */
	u_int16_t  d_namlen;   /* len of filename */
	u_int8_t   d_type;     /* dirent file type */
	u_char     d_name[3];  /* "." or ".." */
};

typedef union {
	struct hfs_stddotentry  std;
	struct hfs_extdotentry  ext;
} hfs_dotentry_t;

/*
 *  hfs_vnop_readdir reads directory entries into the buffer pointed
 *  to by uio, in a filesystem independent format.  Up to uio_resid
 *  bytes of data can be transferred.  The data in the buffer is a
 *  series of packed dirent structures where each one contains the
 *  following entries:
 *
 *	u_int32_t   d_fileno;              // file number of entry
 *	u_int16_t   d_reclen;              // length of this record
 *	u_int8_t    d_type;                // file type
 *	u_int8_t    d_namlen;              // length of string in d_name
 *	char        d_name[MAXNAMELEN+1];  // null terminated file name
 *
 *  The current position (uio_offset) refers to the next block of
 *  entries.  The offset can only be set to a value previously
 *  returned by hfs_vnop_readdir or zero.  This offset does not have
 *  to match the number of bytes returned (in uio_resid).
 *
 *  In fact, the offset used by HFS is essentially an index (26 bits)
 *  with a tag (6 bits).  The tag is for associating the next request
 *  with the current request.  This enables us to have multiple threads
 *  reading the directory while the directory is also being modified.
 *
 *  Each tag/index pair is tied to a unique directory hint.  The hint
 *  contains information (filename) needed to build the catalog b-tree
 *  key for finding the next set of entries.
 *
 * If the directory is marked as deleted-but-in-use (cp->c_flag & C_DELETED),
 * do NOT synthesize entries for "." and "..".
 */
static int
hfs_vnop_readdir(ap)
	struct vnop_readdir_args /* {
		vnode_t a_vp;
		uio_t a_uio;
		int a_flags;
		int *a_eofflag;
		int *a_numdirent;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	uio_t uio = ap->a_uio;
	struct cnode *cp;
	struct hfsmount *hfsmp;
	directoryhint_t *dirhint = NULL;
	directoryhint_t localhint;
	off_t offset;
	off_t startoffset;
	int error = 0;
	int eofflag = 0;
	user_addr_t user_start = 0;
	user_size_t user_len = 0;
	int index;
	unsigned int tag;
	int items;
	int lockflags;
	int extended;
	int nfs_cookies;
	caddr_t bufstart;
	cnid_t cnid_hint = 0;

	items = 0;
	startoffset = offset = uio_offset(uio);
	bufstart = CAST_DOWN(caddr_t, uio_iov_base(uio));
	extended = (ap->a_flags & VNODE_READDIR_EXTENDED);
	nfs_cookies = extended && (ap->a_flags & VNODE_READDIR_REQSEEKOFF);

	/* Sanity check the uio data. */
	if ((uio_iovcnt(uio) > 1) ||
	    (uio_resid(uio) < (int)sizeof(struct dirent))) {
		return (EINVAL);
	}
	/* Note that the dirhint calls require an exclusive lock. */
	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
		return (error);
	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/* Pick up cnid hint (if any). */
	if (nfs_cookies) {
		cnid_hint = (cnid_t)(uio_offset(uio) >> 32);
		uio_setoffset(uio, uio_offset(uio) & 0x00000000ffffffffLL);
		if (cnid_hint == INT_MAX) { /* searching pass the last item */
			eofflag = 1;
			goto out;
		}
	}
	/*
	 * Synthesize entries for "." and "..", unless the directory has
	 * been deleted, but not closed yet (lazy delete in progress).
	 */
	if (offset == 0 && !(cp->c_flag & C_DELETED)) {
		hfs_dotentry_t  dotentry[2];
		size_t  uiosize;

		if (extended) {
			struct hfs_extdotentry *entry = &dotentry[0].ext;

			entry->d_fileno = cp->c_cnid;
			entry->d_reclen = sizeof(struct hfs_extdotentry);
			entry->d_type = DT_DIR;
			entry->d_namlen = 1;
			entry->d_name[0] = '.';
			entry->d_name[1] = '\0';
			entry->d_name[2] = '\0';
			entry->d_seekoff = 1;

			++entry;
			entry->d_fileno = cp->c_parentcnid;
			entry->d_reclen = sizeof(struct hfs_extdotentry);
			entry->d_type = DT_DIR;
			entry->d_namlen = 2;
			entry->d_name[0] = '.';
			entry->d_name[1] = '.';
			entry->d_name[2] = '\0';
			entry->d_seekoff = 2;
			uiosize = 2 * sizeof(struct hfs_extdotentry);
		} else {
			struct hfs_stddotentry *entry = &dotentry[0].std;

			entry->d_fileno = cp->c_cnid;
			entry->d_reclen = sizeof(struct hfs_stddotentry);
			entry->d_type = DT_DIR;
			entry->d_namlen = 1;
			*(int *)&entry->d_name[0] = 0;
			entry->d_name[0] = '.';

			++entry;
			entry->d_fileno = cp->c_parentcnid;
			entry->d_reclen = sizeof(struct hfs_stddotentry);
			entry->d_type = DT_DIR;
			entry->d_namlen = 2;
			*(int *)&entry->d_name[0] = 0;
			entry->d_name[0] = '.';
			entry->d_name[1] = '.';
			uiosize = 2 * sizeof(struct hfs_stddotentry);
		}
		if ((error = uiomove((caddr_t)&dotentry, uiosize, uio))) {
			goto out;
		}
		offset += 2;
	}

	/* If there are no real entries then we're done. */
	if (cp->c_entries == 0) {
		error = 0;
		eofflag = 1;
		uio_setoffset(uio, offset);
		goto seekoffcalc;
	}

	//
	// We have to lock the user's buffer here so that we won't
	// fault on it after we've acquired a shared lock on the
	// catalog file.  The issue is that you can get a 3-way
	// deadlock if someone else starts a transaction and then
	// tries to lock the catalog file but can't because we're
	// here and we can't service our page fault because VM is
	// blocked trying to start a transaction as a result of
	// trying to free up pages for our page fault.  It's messy
	// but it does happen on dual-processors that are paging
	// heavily (see radar 3082639 for more info).  By locking
	// the buffer up-front we prevent ourselves from faulting
	// while holding the shared catalog file lock.
	//
	// Fortunately this and hfs_search() are the only two places
	// currently (10/30/02) that can fault on user data with a
	// shared lock on the catalog file.
	//
	if (hfsmp->jnl && uio_isuserspace(uio)) {
		user_start = uio_curriovbase(uio);
		user_len = uio_curriovlen(uio);

		if ((error = vslock(user_start, user_len)) != 0) {
			user_start = 0;
			goto out;
		}
	}
	/* Convert offset into a catalog directory index. */
	index = (offset & HFS_INDEX_MASK) - 2;
	tag = offset & ~HFS_INDEX_MASK;

	/* Lock catalog during cat_findname and cat_getdirentries. */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	/* When called from NFS, try and resolve a cnid hint. */
	if (nfs_cookies && cnid_hint != 0) {
		if (cat_findname(hfsmp, cnid_hint, &localhint.dh_desc) == 0) {
			if ( localhint.dh_desc.cd_parentcnid == cp->c_fileid) {
				localhint.dh_index = index - 1;
				localhint.dh_time = 0;
				bzero(&localhint.dh_link, sizeof(localhint.dh_link));
				dirhint = &localhint;  /* don't forget to release the descriptor */
			} else {
				cat_releasedesc(&localhint.dh_desc);
			}
		}
	}

	/* Get a directory hint (cnode must be locked exclusive) */
	if (dirhint == NULL) {
		dirhint = hfs_getdirhint(cp, ((index - 1) & HFS_INDEX_MASK) | tag, 0);

		/* Hide tag from catalog layer. */
		dirhint->dh_index &= HFS_INDEX_MASK;
		if (dirhint->dh_index == HFS_INDEX_MASK) {
			dirhint->dh_index = -1;
		}
	}
	
	if (index == 0) {
		dirhint->dh_threadhint = cp->c_dirthreadhint;
	}

	/* Pack the buffer with dirent entries. */
	error = cat_getdirentries(hfsmp, cp->c_entries, dirhint, uio, extended, &items, &eofflag);

	if (index == 0 && error == 0) {
		cp->c_dirthreadhint = dirhint->dh_threadhint;
	}

	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error != 0) {
		goto out;
	}
	
	/* Get index to the next item */
	index += items;
	
	if (items >= (int)cp->c_entries) {
		eofflag = 1;
	}

	/* Convert catalog directory index back into an offset. */
	while (tag == 0)
		tag = (++cp->c_dirhinttag) << HFS_INDEX_BITS;	
	uio_setoffset(uio, (index + 2) | tag);
	dirhint->dh_index |= tag;

seekoffcalc:
	cp->c_touch_acctime = TRUE;

	if (ap->a_numdirent) {
		if (startoffset == 0)
			items += 2;
		*ap->a_numdirent = items;
	}

out:
	if (hfsmp->jnl && user_start) {
		vsunlock(user_start, user_len, TRUE);
	}
	/* If we didn't do anything then go ahead and dump the hint. */
	if ((dirhint != NULL) &&
	    (dirhint != &localhint) &&
	    (uio_offset(uio) == startoffset)) {
		hfs_reldirhint(cp, dirhint);
		eofflag = 1;
	}
	if (ap->a_eofflag) {
		*ap->a_eofflag = eofflag;
	}
	if (dirhint == &localhint) {
		cat_releasedesc(&localhint.dh_desc);
	}
	hfs_unlock(cp);
	return (error);
}


/*
 * Read contents of a symbolic link.
 */
static int
hfs_vnop_readlink(ap)
	struct vnop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;
	int error;

	if (!vnode_islnk(vp))
		return (EINVAL);
 
	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
		return (error);
	cp = VTOC(vp);
	fp = VTOF(vp);
   
	/* Zero length sym links are not allowed */
	if (fp->ff_size == 0 || fp->ff_size > MAXPATHLEN) {
		printf("hfs: zero length symlink on fileid %d\n", cp->c_fileid);
		error = EINVAL;
		goto exit;
	}
    
	/* Cache the path so we don't waste buffer cache resources */
	if (fp->ff_symlinkptr == NULL) {
		struct buf *bp = NULL;

		MALLOC(fp->ff_symlinkptr, char *, fp->ff_size, M_TEMP, M_WAITOK);
		error = (int)buf_meta_bread(vp, (daddr64_t)0,
		                            roundup((int)fp->ff_size,
		                            VTOHFS(vp)->hfs_phys_block_size),
		                            vfs_context_ucred(ap->a_context), &bp);
		if (error) {
			if (bp)
				buf_brelse(bp);
			if (fp->ff_symlinkptr) {
				FREE(fp->ff_symlinkptr, M_TEMP);
				fp->ff_symlinkptr = NULL;
			}
			goto exit;
		}
		bcopy((char *)buf_dataptr(bp), fp->ff_symlinkptr, (size_t)fp->ff_size);

		if (VTOHFS(vp)->jnl && (buf_flags(bp) & B_LOCKED) == 0) {
		        buf_markinvalid(bp);		/* data no longer needed */
		}
		buf_brelse(bp);
	}
	error = uiomove((caddr_t)fp->ff_symlinkptr, (int)fp->ff_size, ap->a_uio);

	/*
	 * Keep track blocks read
	 */
	if ((VTOHFS(vp)->hfc_stage == HFC_RECORDING) && (error == 0)) {
		
		/*
		 * If this file hasn't been seen since the start of
		 * the current sampling period then start over.
		 */
		if (cp->c_atime < VTOHFS(vp)->hfc_timebase)
			VTOF(vp)->ff_bytesread = fp->ff_size;
		else
			VTOF(vp)->ff_bytesread += fp->ff_size;
		
	//	if (VTOF(vp)->ff_bytesread > fp->ff_size)
	//		cp->c_touch_acctime = TRUE;
	}

exit:
	hfs_unlock(cp);
	return (error);
}


/*
 * Get configurable pathname variables.
 */
static int
hfs_vnop_pathconf(ap)
	struct vnop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
		vfs_context_t a_context;
	} */ *ap;
{
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		if (VTOHFS(ap->a_vp)->hfs_flags & HFS_STANDARD)
			*ap->a_retval = 1;
		else
			*ap->a_retval = HFS_LINK_MAX;
		break;
	case _PC_NAME_MAX:
		if (VTOHFS(ap->a_vp)->hfs_flags & HFS_STANDARD)
			*ap->a_retval = kHFSMaxFileNameChars;  /* 255 */
		else
			*ap->a_retval = kHFSPlusMaxFileNameChars;  /* 31 */
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;  /* 1024 */
		break;
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 200112;		/* _POSIX_CHOWN_RESTRICTED */
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 200112;		/* _POSIX_NO_TRUNC */
		break;
	case _PC_NAME_CHARS_MAX:
		*ap->a_retval = kHFSPlusMaxFileNameChars;
		break;
	case _PC_CASE_SENSITIVE:
		if (VTOHFS(ap->a_vp)->hfs_flags & HFS_CASE_SENSITIVE)
			*ap->a_retval = 1;
		else
			*ap->a_retval = 0;
		break;
	case _PC_CASE_PRESERVING:
		*ap->a_retval = 1;
		break;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;	/* number of bits to store max file size */
		break;
	default:
		return (EINVAL);
	}

	return (0);
}


/*
 * Update a cnode's on-disk metadata.
 *
 * If waitfor is set, then wait for the disk write of
 * the node to complete.
 *
 * The cnode must be locked exclusive
 */
__private_extern__
int
hfs_update(struct vnode *vp, __unused int waitfor)
{
	struct cnode *cp = VTOC(vp);
	struct proc *p;
	struct cat_fork *dataforkp = NULL;
	struct cat_fork *rsrcforkp = NULL;
	struct cat_fork datafork;
	struct cat_fork rsrcfork;
	struct hfsmount *hfsmp;
	int lockflags;
	int error;

	p = current_proc();
	hfsmp = VTOHFS(vp);

	if (((vnode_issystem(vp) && (cp->c_cnid < kHFSFirstUserCatalogNodeID))) || 
	   	hfsmp->hfs_catalog_vp == NULL){
		return (0);
	}
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) || (cp->c_mode == 0)) {
		cp->c_flag &= ~C_MODIFIED;
		cp->c_touch_acctime = 0;
		cp->c_touch_chgtime = 0;
		cp->c_touch_modtime = 0;
		return (0);
	}

	hfs_touchtimes(hfsmp, cp);

	/* Nothing to update. */
	if ((cp->c_flag & (C_MODIFIED | C_FORCEUPDATE)) == 0) {
		return (0);
	}
	
	if (cp->c_datafork)
		dataforkp = &cp->c_datafork->ff_data;
	if (cp->c_rsrcfork)
		rsrcforkp = &cp->c_rsrcfork->ff_data;

	/*
	 * For delayed allocations updates are
	 * postponed until an fsync or the file
	 * gets written to disk.
	 *
	 * Deleted files can defer meta data updates until inactive.
	 *
	 * If we're ever called with the C_FORCEUPDATE flag though
	 * we have to do the update.
	 */
	if (ISSET(cp->c_flag, C_FORCEUPDATE) == 0 &&
	    (ISSET(cp->c_flag, C_DELETED) || 
	    (dataforkp && cp->c_datafork->ff_unallocblocks) ||
	    (rsrcforkp && cp->c_rsrcfork->ff_unallocblocks))) {
	//	cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_UPDATE);
		cp->c_flag |= C_MODIFIED;

		HFS_KNOTE(vp, NOTE_ATTRIB);

		return (0);
	}

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    return error;
	}

	/*
	 * For files with invalid ranges (holes) the on-disk
	 * field representing the size of the file (cf_size)
	 * must be no larger than the start of the first hole.
	 */
	if (dataforkp && !CIRCLEQ_EMPTY(&cp->c_datafork->ff_invalidranges)) {
		bcopy(dataforkp, &datafork, sizeof(datafork));
		datafork.cf_size = CIRCLEQ_FIRST(&cp->c_datafork->ff_invalidranges)->rl_start;
		dataforkp = &datafork;
	} else if (dataforkp && (cp->c_datafork->ff_unallocblocks != 0)) {
		// always make sure the block count and the size 
		// of the file match the number of blocks actually
		// allocated to the file on disk
		bcopy(dataforkp, &datafork, sizeof(datafork));
		// make sure that we don't assign a negative block count
		if (cp->c_datafork->ff_blocks < cp->c_datafork->ff_unallocblocks) {
		    panic("hfs: ff_blocks %d is less than unalloc blocks %d\n",
			  cp->c_datafork->ff_blocks, cp->c_datafork->ff_unallocblocks);
		}
		datafork.cf_blocks = (cp->c_datafork->ff_blocks - cp->c_datafork->ff_unallocblocks);
		datafork.cf_size   = datafork.cf_blocks * HFSTOVCB(hfsmp)->blockSize;
		dataforkp = &datafork;
	}

	/*
	 * For resource forks with delayed allocations, make sure
	 * the block count and file size match the number of blocks
	 * actually allocated to the file on disk.
	 */
	if (rsrcforkp && (cp->c_rsrcfork->ff_unallocblocks != 0)) {
		bcopy(rsrcforkp, &rsrcfork, sizeof(rsrcfork));
		rsrcfork.cf_blocks = (cp->c_rsrcfork->ff_blocks - cp->c_rsrcfork->ff_unallocblocks);
		rsrcfork.cf_size   = rsrcfork.cf_blocks * HFSTOVCB(hfsmp)->blockSize;
		rsrcforkp = &rsrcfork;
	}

	/*
	 * Lock the Catalog b-tree file.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

	/* XXX - waitfor is not enforced */
	error = cat_update(hfsmp, &cp->c_desc, &cp->c_attr, dataforkp, rsrcforkp);

	hfs_systemfile_unlock(hfsmp, lockflags);

	/* After the updates are finished, clear the flags */
	cp->c_flag &= ~(C_MODIFIED | C_FORCEUPDATE);

	hfs_end_transaction(hfsmp);

	HFS_KNOTE(vp, NOTE_ATTRIB);
	
	return (error);
}

/*
 * Allocate a new node
 * Note - Function does not create and return a vnode for whiteout creation.
 */
static int
hfs_makenode(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp,
             struct vnode_attr *vap, vfs_context_t ctx)
{
	struct cnode *cp = NULL;
	struct cnode *dcp;
	struct vnode *tvp;
	struct hfsmount *hfsmp;
	struct cat_desc in_desc, out_desc;
	struct cat_attr attr;
	struct timeval tv;
	int lockflags;
	int error, started_tr = 0;
	enum vtype vnodetype;
	int mode;

	dcp = VTOC(dvp);
	if ((error = hfs_lock(dcp, HFS_EXCLUSIVE_LOCK)))
		return (error);

	dcp->c_flag |= C_DIR_MODIFICATION;
	
	hfsmp = VTOHFS(dvp);
	*vpp = NULL;
	tvp = NULL;
	out_desc.cd_flags = 0;
	out_desc.cd_nameptr = NULL;

	vnodetype = vap->va_type;
	if (vnodetype == VNON)
		vnodetype = VREG;
	mode = MAKEIMODE(vnodetype, vap->va_mode);

	/* Check if were out of usable disk space. */
	if ((hfs_freeblks(hfsmp, 1) == 0) && (vfs_context_suser(ctx) != 0)) {
		error = ENOSPC;
		goto exit;
	}

	microtime(&tv);

	/* Setup the default attributes */
	bzero(&attr, sizeof(attr));
	attr.ca_mode = mode;
	attr.ca_linkcount = 1;
	if (VATTR_IS_ACTIVE(vap, va_rdev)) {
		attr.ca_rdev = vap->va_rdev;
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		VATTR_SET_SUPPORTED(vap, va_create_time);
		attr.ca_itime = vap->va_create_time.tv_sec;
	} else {
		attr.ca_itime = tv.tv_sec;
	}
	if ((hfsmp->hfs_flags & HFS_STANDARD) && gTimeZone.tz_dsttime) {
		attr.ca_itime += 3600;	/* Same as what hfs_update does */
	}
	attr.ca_atime = attr.ca_ctime = attr.ca_mtime = attr.ca_itime;
	attr.ca_atimeondisk = attr.ca_atime;
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		VATTR_SET_SUPPORTED(vap, va_flags);
		attr.ca_flags = vap->va_flags;
	}
	
	/* 
	 * HFS+ only: all files get ThreadExists
	 * HFSX only: dirs get HasFolderCount
	 */
	if (!(hfsmp->hfs_flags & HFS_STANDARD)) {
		if (vnodetype == VDIR) {
			if (hfsmp->hfs_flags & HFS_FOLDERCOUNT)
				attr.ca_recflags = kHFSHasFolderCountMask;
		} else {
			attr.ca_recflags = kHFSThreadExistsMask;
		}
	}

	attr.ca_uid = vap->va_uid;
	attr.ca_gid = vap->va_gid;
	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);

	/* Tag symlinks with a type and creator. */
	if (vnodetype == VLNK) {
		struct FndrFileInfo *fip;

		fip = (struct FndrFileInfo *)&attr.ca_finderinfo;
		fip->fdType    = SWAP_BE32(kSymLinkFileType);
		fip->fdCreator = SWAP_BE32(kSymLinkCreator);
	}
	if (cnp->cn_flags & ISWHITEOUT)
		attr.ca_flags |= UF_OPAQUE;

	/* Setup the descriptor */
	in_desc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	in_desc.cd_namelen = cnp->cn_namelen;
	in_desc.cd_parentcnid = dcp->c_fileid;
	in_desc.cd_flags = S_ISDIR(mode) ? CD_ISDIR : 0;
	in_desc.cd_hint = dcp->c_childhint;
	in_desc.cd_encoding = 0;

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
	    goto exit;
	}
	started_tr = 1;

	// have to also lock the attribute file because cat_create() needs
	// to check that any fileID it wants to use does not have orphaned
	// attributes in it.
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	/* Reserve some space in the Catalog file. */
	if ((error = cat_preflight(hfsmp, CAT_CREATE, NULL, 0))) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		goto exit;
	}
	error = cat_create(hfsmp, &in_desc, &attr, &out_desc);
	if (error == 0) {
		/* Update the parent directory */
		dcp->c_childhint = out_desc.cd_hint;	/* Cache directory's location */
		dcp->c_entries++;
		if (vnodetype == VDIR) {
			INC_FOLDERCOUNT(hfsmp, dcp->c_attr);
		}
		dcp->c_dirchangecnt++;
		dcp->c_ctime = tv.tv_sec;
		dcp->c_mtime = tv.tv_sec;
		(void) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);
		HFS_KNOTE(dvp, NOTE_ATTRIB);
	}
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (error)
		goto exit;
	
	/* Invalidate negative cache entries in the directory */
	if (dcp->c_flag & C_NEG_ENTRIES) {
		cache_purge_negatives(dvp);
		dcp->c_flag &= ~C_NEG_ENTRIES;
	}

	if (vnodetype == VDIR) {
		HFS_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
	} else {
		HFS_KNOTE(dvp, NOTE_WRITE);
	};

	hfs_volupdate(hfsmp, vnodetype == VDIR ? VOL_MKDIR : VOL_MKFILE,
		(dcp->c_cnid == kHFSRootFolderID));

	// XXXdbg
	// have to end the transaction here before we call hfs_getnewvnode()
	// because that can cause us to try and reclaim a vnode on a different
	// file system which could cause us to start a transaction which can
	// deadlock with someone on that other file system (since we could be
	// holding two transaction locks as well as various vnodes and we did
	// not obtain the locks on them in the proper order).
	//
	// NOTE: this means that if the quota check fails or we have to update
	//       the change time on a block-special device that those changes
	//       will happen as part of independent transactions.
	//
	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	    started_tr = 0;
	}

	/* Do not create vnode for whiteouts */
	if (S_ISWHT(mode)) {
		goto exit;
	}

	/*
	 * Create a vnode for the object just created.
	 *
	 * The cnode is locked on successful return.
	 */
	error = hfs_getnewvnode(hfsmp, dvp, cnp, &out_desc, GNV_CREATE, &attr, NULL, &tvp);
	if (error)
		goto exit;

	cp = VTOC(tvp);
#if QUOTA
	/* 
	 * We call hfs_chkiq with FORCE flag so that if we
	 * fall through to the rmdir we actually have 
	 * accounted for the inode
	*/
	if (hfsmp->hfs_flags & HFS_QUOTAS) {
		if ((error = hfs_getinoquota(cp)) ||
		    (error = hfs_chkiq(cp, 1, vfs_context_ucred(ctx), FORCE))) {
	
			if (vnode_isdir(tvp))
				(void) hfs_removedir(dvp, tvp, cnp, 0);
			else {
				hfs_unlock(cp);
				hfs_lock_truncate(cp, TRUE);
				hfs_lock(cp, HFS_FORCE_LOCK);
				(void) hfs_removefile(dvp, tvp, cnp, 0, 0, 0);
				hfs_unlock_truncate(cp, TRUE);
			}
			/*
			 * we successfully allocated a new vnode, but
			 * the quota check is telling us we're beyond
			 * our limit, so we need to dump our lock + reference
			 */
			hfs_unlock(cp);
			vnode_put(tvp);
	
			goto exit;
		}
	}
#endif /* QUOTA */

	*vpp = tvp;
exit:
	cat_releasedesc(&out_desc);

	/*
	 * Check if a file is located in the "Cleanup At Startup"
	 * directory.  If it is then tag it as NODUMP so that we
	 * can be lazy about zero filling data holes.
	 */
	if ((error == 0) && dvp && (vnodetype == VREG) &&
	    (dcp->c_desc.cd_nameptr != NULL) &&
	    (strncmp((const char *)dcp->c_desc.cd_nameptr,
		     CARBON_TEMP_DIR_NAME,
		     sizeof(CARBON_TEMP_DIR_NAME)) == 0)) {
	   	struct vnode *ddvp;

		dcp->c_flag &= ~C_DIR_MODIFICATION;
		wakeup((caddr_t)&dcp->c_flag);

		hfs_unlock(dcp);
		dvp = NULL;

		/*
		 * The parent of "Cleanup At Startup" should
		 * have the ASCII name of the userid.
		 */
		if (hfs_vget(hfsmp, dcp->c_parentcnid, &ddvp, 0) == 0) {
			if (VTOC(ddvp)->c_desc.cd_nameptr) {
				uid_t uid;

				uid = strtoul((const char *)VTOC(ddvp)->c_desc.cd_nameptr, 0, 0);
				if ((uid == cp->c_uid) ||
				    (uid == vfs_context_ucred(ctx)->cr_uid)) {
					cp->c_flags |= UF_NODUMP;
					cp->c_touch_chgtime = TRUE;
				}
			}
			hfs_unlock(VTOC(ddvp));
			vnode_put(ddvp);
		}
	}
	if (dvp) {
		dcp->c_flag &= ~C_DIR_MODIFICATION;
		wakeup((caddr_t)&dcp->c_flag);
		
		hfs_unlock(dcp);
	}
	if (error == 0 && cp != NULL) {
		hfs_unlock(cp);
	}
	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	    started_tr = 0;
	}

	return (error);
}


/*
 * Return a referenced vnode for the resource fork
 *
 * cnode for vnode vp must already be locked.
 *
 * can_drop_lock is true if its safe to temporally drop/re-acquire the cnode lock
 */
__private_extern__
int
hfs_vgetrsrc(struct hfsmount *hfsmp, struct vnode *vp, struct vnode **rvpp, int can_drop_lock)
{
	struct vnode *rvp;
	struct vnode *dvp = NULLVP;
	struct cnode *cp = VTOC(vp);
	int error;
	int vid;

restart:
	/* Attempt to use exising vnode */
	if ((rvp = cp->c_rsrc_vp)) {
	        vid = vnode_vid(rvp);

		/*
		 * It is not safe to hold the cnode lock when calling vnode_getwithvid()
		 * for the alternate fork -- vnode_getwithvid() could deadlock waiting
		 * for a VL_WANTTERM while another thread has an iocount on the alternate
		 * fork vnode and is attempting to acquire the common cnode lock.
		 *
		 * But it's also not safe to drop the cnode lock when we're holding
		 * multiple cnode locks, like during a hfs_removefile() operation
		 * since we could lock out of order when re-acquiring the cnode lock.
		 *
		 * So we can only drop the lock here if its safe to drop it -- which is
		 * most of the time with the exception being hfs_removefile().
		 */
		if (can_drop_lock)
			hfs_unlock(cp);

		error = vnode_getwithvid(rvp, vid);

		if (can_drop_lock) {
			(void) hfs_lock(cp, HFS_FORCE_LOCK);
			/*
			 * When our lock was relinquished, the resource fork
			 * could have been recycled.  Check for this and try
			 * again.
			 */
			if (error == ENOENT)
				goto restart;
		}
		if (error) {
			const char * name = (const char *)VTOC(vp)->c_desc.cd_nameptr;

			if (name)
				printf("hfs_vgetrsrc: couldn't get resource"
				       " fork for %s, err %d\n", name, error);
			return (error);
		}
	} else {
		struct cat_fork rsrcfork;
		struct componentname cn;
		int lockflags;

		/*
		 * Make sure cnode lock is exclusive, if not upgrade it.
		 *
		 * We assume that we were called from a read-only VNOP (getattr)
		 * and that its safe to have the cnode lock dropped and reacquired.
		 */
		if (cp->c_lockowner != current_thread()) {
			if (!can_drop_lock)
				return (EINVAL);
			/*
			 * If the upgrade fails we loose the lock and
			 * have to take the exclusive lock on our own.
			 */
			if (lck_rw_lock_shared_to_exclusive(&cp->c_rwlock) == FALSE)
				lck_rw_lock_exclusive(&cp->c_rwlock);
			cp->c_lockowner = current_thread();
		}

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

		/* Get resource fork data */
		error = cat_lookup(hfsmp, &cp->c_desc, 1, (struct cat_desc *)0,
				(struct cat_attr *)0, &rsrcfork, NULL);

		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error)
			return (error);
		
		/*
		 * Supply hfs_getnewvnode with a component name. 
		 */
		cn.cn_pnbuf = NULL;
		if (cp->c_desc.cd_nameptr) {
			MALLOC_ZONE(cn.cn_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			cn.cn_nameiop = LOOKUP;
			cn.cn_flags = ISLASTCN | HASBUF;
			cn.cn_context = NULL;
			cn.cn_pnlen = MAXPATHLEN;
			cn.cn_nameptr = cn.cn_pnbuf;
			cn.cn_hash = 0;
			cn.cn_consume = 0;
			cn.cn_namelen = snprintf(cn.cn_nameptr, MAXPATHLEN,
						 "%s%s", cp->c_desc.cd_nameptr,
						 _PATH_RSRCFORKSPEC);
		}
		dvp = vnode_getparent(vp);
		error = hfs_getnewvnode(hfsmp, dvp, cn.cn_pnbuf ? &cn : NULL,
		                        &cp->c_desc, GNV_WANTRSRC | GNV_SKIPLOCK, &cp->c_attr,
		                        &rsrcfork, &rvp);
		if (dvp)
			vnode_put(dvp);
		if (cn.cn_pnbuf)
			FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
		if (error)
			return (error);
	}

	*rvpp = rvp;
	return (0);
}


static void
filt_hfsdetach(struct knote *kn)
{
	struct vnode *vp;
	
	vp = (struct vnode *)kn->kn_hook;
	if (vnode_getwithvid(vp, kn->kn_hookid))
		return;

	if (1) {  /* ! KNDETACH_VNLOCKED */
		if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) == 0) {
			(void) KNOTE_DETACH(&VTOC(vp)->c_knotes, kn);
			hfs_unlock(VTOC(vp));
		}
	}

	vnode_put(vp);
}

/*ARGSUSED*/
static int
filt_hfsread(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;
	int dropvp = 0;

	if (hint == 0)  {
		if ((vnode_getwithvid(vp, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else 
			dropvp = 1;
	}
	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}

	/* poll(2) semantics dictate always saying there is data */
	if (!(kn->kn_flags & EV_POLL)) {
		off_t amount;
 
		amount = VTOF(vp)->ff_size - kn->kn_fp->f_fglob->fg_offset;
		if (amount > (off_t)INTPTR_MAX)
			kn->kn_data = INTPTR_MAX;
		else if (amount < (off_t)INTPTR_MIN)
			kn->kn_data = INTPTR_MIN;
		else
			kn->kn_data = (intptr_t)amount;
	} else {
		kn->kn_data = 1;
	}

	if  (dropvp)
		vnode_put(vp);

	return (kn->kn_data != 0);
}

/*ARGSUSED*/
static int
filt_hfswrite(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;

	if (hint == 0)  {
		if ((vnode_getwithvid(vp, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else 
			vnode_put(vp);
	}
	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_data = 0;
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}
	kn->kn_data = 0;
	return (1);
}

static int
filt_hfsvnode(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;

	if (hint == 0)  {
		if ((vnode_getwithvid(vp, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else
			vnode_put(vp);
	}
	if (kn->kn_sfflags & hint)
		kn->kn_fflags |= hint;
	if ((hint == NOTE_REVOKE)) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}
	
	return (kn->kn_fflags != 0);
}

static struct filterops hfsread_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfsread };
static struct filterops hfswrite_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfswrite };
static struct filterops hfsvnode_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfsvnode };

/*
 * Add a kqueue filter.
 */
static int
hfs_vnop_kqfiltadd(
	struct vnop_kqfilt_add_args /* {
		struct vnode *a_vp;
		struct knote *a_kn;
		struct proc *p;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode *vp = ap->a_vp;
	struct knote *kn = ap->a_kn;
	int error;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (vnode_isreg(vp)) {
			kn->kn_fop = &hfsread_filtops;
		} else {
			return EINVAL;
		};
		break;
	case EVFILT_WRITE:
		if (vnode_isreg(vp)) {
			kn->kn_fop = &hfswrite_filtops;
		} else {
			return EINVAL;
		};
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &hfsvnode_filtops;
		break;
	default:
		return (1);
	}

	kn->kn_hook = (caddr_t)vp;
	kn->kn_hookid = vnode_vid(vp);

	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK)))
		return (error);
	KNOTE_ATTACH(&VTOC(vp)->c_knotes, kn);
	hfs_unlock(VTOC(vp));

	return (0);
}

/*
 * Remove a kqueue filter
 */
static int
hfs_vnop_kqfiltremove(ap)
	struct vnop_kqfilt_remove_args /* {
		struct vnode *a_vp;
		uintptr_t ident;
		vfs_context_t a_context;
	} */__unused *ap;
{
	int result;

	result = ENOTSUP; /* XXX */
	
	return (result);
}

/*
 * Wrapper for special device reads
 */
static int
hfsspec_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	/*
	 * Set access flag.
	 */
	VTOC(ap->a_vp)->c_touch_acctime = TRUE;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Wrapper for special device writes
 */
static int
hfsspec_write(ap)
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	/*
	 * Set update and change flags.
	 */
	VTOC(ap->a_vp)->c_touch_chgtime = TRUE;
	VTOC(ap->a_vp)->c_touch_modtime = TRUE;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Wrapper for special device close
 *
 * Update the times on the cnode then do device close.
 */
static int
hfsspec_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;

	if (vnode_isinuse(ap->a_vp, 1)) {
		if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) == 0) {
			cp = VTOC(vp);
			hfs_touchtimes(VTOHFS(vp), cp);
			hfs_unlock(cp);
		}
	}
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_close), ap));
}

#if FIFO
/*
 * Wrapper for fifo reads
 */
static int
hfsfifo_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	/*
	 * Set access flag.
	 */
	VTOC(ap->a_vp)->c_touch_acctime = TRUE;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Wrapper for fifo writes
 */
static int
hfsfifo_write(ap)
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	/*
	 * Set update and change flags.
	 */
	VTOC(ap->a_vp)->c_touch_chgtime = TRUE;
	VTOC(ap->a_vp)->c_touch_modtime = TRUE;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Wrapper for fifo close
 *
 * Update the times on the cnode then do device close.
 */
static int
hfsfifo_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;

	if (vnode_isinuse(ap->a_vp, 1)) {
		if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) == 0) {
			cp = VTOC(vp);
			hfs_touchtimes(VTOHFS(vp), cp);
			hfs_unlock(cp);
		}
	}
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_close), ap));
}

/*
 * kqfilt_add wrapper for fifos.
 *
 * Fall through to hfs kqfilt_add routines if needed 
 */
int
hfsfifo_kqfilt_add(ap)
	struct vnop_kqfilt_add_args *ap;
{
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vnop_kqfilt_add), ap);
	if (error)
		error = hfs_vnop_kqfiltadd(ap);
	return (error);
}

/*
 * kqfilt_remove wrapper for fifos.
 *
 * Fall through to hfs kqfilt_remove routines if needed 
 */
int
hfsfifo_kqfilt_remove(ap)
	struct vnop_kqfilt_remove_args *ap;
{
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vnop_kqfilt_remove), ap);
	if (error)
		error = hfs_vnop_kqfiltremove(ap);
	return (error);
}

#endif /* FIFO */

/*
 * Synchronize a file's in-core state with that on disk.
 */
static int
hfs_vnop_fsync(ap)
	struct vnop_fsync_args /* {
		struct vnode *a_vp;
		int a_waitfor;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode* vp = ap->a_vp;
	int error;

	/*
	 * We need to allow ENOENT lock errors since unlink
	 * systenm call can call VNOP_FSYNC during vclean.
	 */
	error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
	if (error)
		return (0);

	error = hfs_fsync(vp, ap->a_waitfor, 0, vfs_context_proc(ap->a_context));

	hfs_unlock(VTOC(vp));
	return (error);
}


static int
hfs_vnop_whiteout(ap) 
	struct vnop_whiteout_args /* {
		struct vnode *a_dvp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	int error = 0;
	struct vnode *vp = NULL;
	struct vnode_attr va;
	struct vnop_lookup_args lookup_args;
	struct vnop_remove_args remove_args;
	struct hfsmount *hfsmp;

	hfsmp = VTOHFS(ap->a_dvp);
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		error = ENOTSUP;
		goto exit;
	}

	switch (ap->a_flags) {
		case LOOKUP:
			error = 0;
			break;

		case CREATE: 
			VATTR_INIT(&va);
			VATTR_SET(&va, va_type, VREG);
			VATTR_SET(&va, va_mode, S_IFWHT);
			VATTR_SET(&va, va_uid, 0);
			VATTR_SET(&va, va_gid, 0);
			
			error = hfs_makenode(ap->a_dvp, &vp, ap->a_cnp, &va, ap->a_context);
			/* No need to release the vnode as no vnode is created for whiteouts */
			break;

		case DELETE:
			lookup_args.a_dvp = ap->a_dvp;
			lookup_args.a_vpp = &vp;
			lookup_args.a_cnp = ap->a_cnp;
			lookup_args.a_context = ap->a_context;

			error = hfs_vnop_lookup(&lookup_args);
			if (error) {
				break;
			}
			
			remove_args.a_dvp = ap->a_dvp;
			remove_args.a_vp = vp;
			remove_args.a_cnp = ap->a_cnp;
			remove_args.a_flags = 0;
			remove_args.a_context = ap->a_context;

			error = hfs_vnop_remove(&remove_args);
			vnode_put(vp);
			break;

		default:
			panic("hfs_vnop_whiteout: unknown operation (flag = %x)\n", ap->a_flags);
	};
	
exit:
	return (error);
}

int (**hfs_vnodeop_p)(void *);

#define VOPFUNC int (*)(void *)

struct vnodeopv_entry_desc hfs_vnodeop_entries[] = {
    { &vnop_default_desc, (VOPFUNC)vn_default_error },
    { &vnop_lookup_desc, (VOPFUNC)hfs_vnop_lookup },		/* lookup */
    { &vnop_create_desc, (VOPFUNC)hfs_vnop_create },		/* create */
    { &vnop_mknod_desc, (VOPFUNC)hfs_vnop_mknod },             /* mknod */
    { &vnop_open_desc, (VOPFUNC)hfs_vnop_open },			/* open */
    { &vnop_close_desc, (VOPFUNC)hfs_vnop_close },		/* close */
    { &vnop_getattr_desc, (VOPFUNC)hfs_vnop_getattr },		/* getattr */
    { &vnop_setattr_desc, (VOPFUNC)hfs_vnop_setattr },		/* setattr */
    { &vnop_read_desc, (VOPFUNC)hfs_vnop_read },			/* read */
    { &vnop_write_desc, (VOPFUNC)hfs_vnop_write },		/* write */
    { &vnop_ioctl_desc, (VOPFUNC)hfs_vnop_ioctl },		/* ioctl */
    { &vnop_select_desc, (VOPFUNC)hfs_vnop_select },		/* select */
    { &vnop_revoke_desc, (VOPFUNC)nop_revoke },			/* revoke */
    { &vnop_exchange_desc, (VOPFUNC)hfs_vnop_exchange },		/* exchange */
    { &vnop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
    { &vnop_fsync_desc, (VOPFUNC)hfs_vnop_fsync },		/* fsync */
    { &vnop_remove_desc, (VOPFUNC)hfs_vnop_remove },		/* remove */
    { &vnop_link_desc, (VOPFUNC)hfs_vnop_link },			/* link */
    { &vnop_rename_desc, (VOPFUNC)hfs_vnop_rename },		/* rename */
    { &vnop_mkdir_desc, (VOPFUNC)hfs_vnop_mkdir },             /* mkdir */
    { &vnop_rmdir_desc, (VOPFUNC)hfs_vnop_rmdir },		/* rmdir */
    { &vnop_symlink_desc, (VOPFUNC)hfs_vnop_symlink },         /* symlink */
    { &vnop_readdir_desc, (VOPFUNC)hfs_vnop_readdir },		/* readdir */
    { &vnop_readdirattr_desc, (VOPFUNC)hfs_vnop_readdirattr },	/* readdirattr */
    { &vnop_readlink_desc, (VOPFUNC)hfs_vnop_readlink },		/* readlink */
    { &vnop_inactive_desc, (VOPFUNC)hfs_vnop_inactive },		/* inactive */
    { &vnop_reclaim_desc, (VOPFUNC)hfs_vnop_reclaim },		/* reclaim */
    { &vnop_strategy_desc, (VOPFUNC)hfs_vnop_strategy },		/* strategy */
    { &vnop_pathconf_desc, (VOPFUNC)hfs_vnop_pathconf },		/* pathconf */
    { &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
    { &vnop_allocate_desc, (VOPFUNC)hfs_vnop_allocate },		/* allocate */
    { &vnop_searchfs_desc, (VOPFUNC)hfs_vnop_search },		/* search fs */
    { &vnop_bwrite_desc, (VOPFUNC)hfs_vnop_bwrite },		/* bwrite */
    { &vnop_pagein_desc, (VOPFUNC)hfs_vnop_pagein },		/* pagein */
    { &vnop_pageout_desc,(VOPFUNC) hfs_vnop_pageout },		/* pageout */
    { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
    { &vnop_blktooff_desc, (VOPFUNC)hfs_vnop_blktooff },		/* blktooff */
    { &vnop_offtoblk_desc, (VOPFUNC)hfs_vnop_offtoblk },		/* offtoblk */
    { &vnop_blockmap_desc, (VOPFUNC)hfs_vnop_blockmap },			/* blockmap */
    { &vnop_kqfilt_add_desc, (VOPFUNC)hfs_vnop_kqfiltadd },		/* kqfilt_add */
    { &vnop_kqfilt_remove_desc, (VOPFUNC)hfs_vnop_kqfiltremove },		/* kqfilt_remove */
    { &vnop_getxattr_desc, (VOPFUNC)hfs_vnop_getxattr},
    { &vnop_setxattr_desc, (VOPFUNC)hfs_vnop_setxattr},
    { &vnop_removexattr_desc, (VOPFUNC)hfs_vnop_removexattr},
    { &vnop_listxattr_desc, (VOPFUNC)hfs_vnop_listxattr},
    { &vnop_whiteout_desc, (VOPFUNC)hfs_vnop_whiteout},
#if NAMEDSTREAMS
    { &vnop_getnamedstream_desc, (VOPFUNC)hfs_vnop_getnamedstream },
    { &vnop_makenamedstream_desc, (VOPFUNC)hfs_vnop_makenamedstream },
    { &vnop_removenamedstream_desc, (VOPFUNC)hfs_vnop_removenamedstream },
#endif
    { NULL, (VOPFUNC)NULL }
};

struct vnodeopv_desc hfs_vnodeop_opv_desc =
{ &hfs_vnodeop_p, hfs_vnodeop_entries };

int (**hfs_specop_p)(void *);
struct vnodeopv_entry_desc hfs_specop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)spec_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)hfsspec_close },		/* close */
	{ &vnop_getattr_desc, (VOPFUNC)hfs_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)hfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (VOPFUNC)hfsspec_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)hfsspec_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)hfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)spec_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)spec_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)spec_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)spec_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)hfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)hfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)hfs_vnop_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)hfs_vnop_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)hfs_vnop_pageout },	/* Pageout */
        { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)hfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)hfs_vnop_offtoblk },	/* offtoblk */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_specop_opv_desc =
	{ &hfs_specop_p, hfs_specop_entries };

#if FIFO
int (**hfs_fifoop_p)(void *);
struct vnodeopv_entry_desc hfs_fifoop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)hfsfifo_close },		/* close */
	{ &vnop_getattr_desc, (VOPFUNC)hfs_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)hfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (VOPFUNC)hfsfifo_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)hfsfifo_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)hfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)hfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)hfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)hfs_vnop_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)hfs_vnop_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)hfs_vnop_pageout },	/* Pageout */
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile }, 		/* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)hfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)hfs_vnop_offtoblk },	/* offtoblk */
  	{ &vnop_blockmap_desc, (VOPFUNC)hfs_vnop_blockmap },		/* blockmap */
	{ &vnop_kqfilt_add_desc, (VOPFUNC)hfsfifo_kqfilt_add },  /* kqfilt_add */
	{ &vnop_kqfilt_remove_desc, (VOPFUNC)hfsfifo_kqfilt_remove },  /* kqfilt_remove */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_fifoop_opv_desc =
	{ &hfs_fifoop_p, hfs_fifoop_entries };
#endif /* FIFO */



