/*
 * Copyright (c) 2002-2007 Apple Inc. All rights reserved.
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
#ifndef _HFS_CNODE_H_
#define _HFS_CNODE_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/quota.h>

#include <kern/locks.h>

#include <hfs/hfs_catalog.h>
#include <hfs/rangelist.h>


/*
 * The filefork is used to represent an HFS file fork (data or resource).
 * Reading or writing any of these fields requires holding cnode lock.
 */
struct filefork {
	struct cnode   *ff_cp;               /* cnode associated with this fork */
	struct rl_head  ff_invalidranges;    /* Areas of disk that should read back as zeroes */
	union {
	   void        *ffu_sysfileinfo;     /* additional info for system files */
	   char        *ffu_symlinkptr;      /* symbolic link pathname */
	} ff_union;
	struct cat_fork ff_data;             /* fork data (size, extents) */
};
typedef struct filefork filefork_t;

/* Aliases for common fields */
#define ff_size          ff_data.cf_size
#define ff_clumpsize     ff_data.cf_clump
#define ff_bytesread     ff_data.cf_bytesread
#define ff_blocks        ff_data.cf_blocks
#define ff_extents       ff_data.cf_extents
#define ff_unallocblocks ff_data.cf_vblocks

#define ff_symlinkptr    ff_union.ffu_symlinkptr
#define ff_sysfileinfo   ff_union.ffu_sysfileinfo


/* The btree code still needs these... */
#define fcbEOF           ff_size
#define fcbExtents       ff_extents
#define	fcbBTCBPtr       ff_sysfileinfo

typedef u_int8_t atomicflag_t;


/*
 * Hardlink Origin (for hardlinked directories).
 */
struct linkorigin {
	TAILQ_ENTRY(linkorigin)  lo_link;  /* chain */
	void *  lo_thread;      /* thread that performed the lookup */
	cnid_t  lo_cnid;        /* hardlink's cnid */
	cnid_t  lo_parentcnid;  /* hardlink's parent cnid */
};
typedef struct linkorigin linkorigin_t;

#define MAX_CACHED_ORIGINS  10


/*
 * The cnode is used to represent each active (or recently active)
 * file or directory in the HFS filesystem.
 *
 * Reading or writing any of these fields requires holding c_lock.
 */
struct cnode {
	lck_rw_t                c_rwlock;       /* cnode's lock */
	void *                  c_lockowner;    /* cnode's lock owner (exclusive case only) */
	lck_rw_t                c_truncatelock; /* protects file from truncation during read/write */
	LIST_ENTRY(cnode)	c_hash;		/* cnode's hash chain */
	u_int32_t		c_flag;		/* cnode's runtime flags */
	u_int32_t		c_hflag;	/* cnode's flags for maintaining hash - protected by global hash lock */
	struct vnode		*c_vp;		/* vnode for data fork or dir */
	struct vnode		*c_rsrc_vp;	/* vnode for resource fork */
	dev_t			c_dev;		/* cnode's device */
        struct dquot		*c_dquot[MAXQUOTAS]; /* cnode's quota info */
	struct klist		c_knotes;	/* knotes attached to this vnode */
	u_int32_t		c_childhint;	 /* catalog hint for children (small dirs only) */
	u_int32_t		c_dirthreadhint; /* catalog hint for directory's thread rec */
	struct cat_desc		c_desc;		/* cnode's descriptor */
	struct cat_attr		c_attr;		/* cnode's attributes */
	TAILQ_HEAD(hfs_originhead, linkorigin) c_originlist;  /* hardlink origin cache */
	TAILQ_HEAD(hfs_hinthead, directoryhint) c_hintlist;  /* readdir directory hint list */
  	int16_t			c_dirhinttag;	/* directory hint tag */
	union {
	    int16_t     cu_dirhintcnt;          /* directory hint count */
	    int16_t     cu_syslockcount;        /* system file use only */
	} c_union;
	u_int32_t		c_dirchangecnt; /* changes each insert/delete (in-core only) */
 	struct filefork		*c_datafork;	/* cnode's data fork */
	struct filefork		*c_rsrcfork;	/* cnode's rsrc fork */
	atomicflag_t	c_touch_acctime;
	atomicflag_t	c_touch_chgtime;
	atomicflag_t	c_touch_modtime;
};
typedef struct cnode cnode_t;

/* Aliases for common cnode fields */
#define c_cnid		c_desc.cd_cnid
#define c_hint		c_desc.cd_hint
#define c_parentcnid	c_desc.cd_parentcnid
#define c_encoding	c_desc.cd_encoding

#define c_fileid	c_attr.ca_fileid
#define c_mode		c_attr.ca_mode
#define c_linkcount	c_attr.ca_linkcount
#define c_uid		c_attr.ca_uid
#define c_gid		c_attr.ca_gid
#define c_rdev		c_attr.ca_union1.cau_rdev
#define c_atime		c_attr.ca_atime
#define c_mtime		c_attr.ca_mtime
#define c_ctime		c_attr.ca_ctime
#define c_itime		c_attr.ca_itime
#define c_btime		c_attr.ca_btime
#define c_flags		c_attr.ca_flags
#define c_finderinfo	c_attr.ca_finderinfo
#define c_blocks	c_attr.ca_union2.cau_blocks
#define c_entries	c_attr.ca_union2.cau_entries
#define c_zftimeout	c_childhint

#define c_dirhintcnt    c_union.cu_dirhintcnt
#define c_syslockcount  c_union.cu_syslockcount


/* hash maintenance flags kept in c_hflag and protected by hfs_chash_mutex */
#define H_ALLOC		0x00001	/* CNode is being allocated */
#define H_ATTACH	0x00002	/* CNode is being attached to by another vnode */
#define	H_TRANSIT	0x00004	/* CNode is getting recycled  */
#define H_WAITING	0x00008	/* CNode is being waited for */


/* Runtime cnode flags (kept in c_flag) */
#define C_NEED_RVNODE_PUT  0x00001  /* Need to do a vnode_put on c_rsrc_vp after the unlock */
#define C_NEED_DVNODE_PUT  0x00002  /* Need to do a vnode_put on c_vp after the unlock */
#define C_ZFWANTSYNC	   0x00004  /* fsync requested and file has holes */
#define C_FROMSYNC         0x00008  /* fsync was called from sync */ 

#define C_MODIFIED         0x00010  /* CNode has been modified */
#define C_NOEXISTS         0x00020  /* CNode has been deleted, catalog entry is gone */
#define C_DELETED          0x00040  /* CNode has been marked to be deleted */
#define C_HARDLINK         0x00080  /* CNode is a hard link (file or dir) */

#define C_FORCEUPDATE      0x00100  /* force the catalog entry update */
#define C_HASXATTRS        0x00200  /* cnode has extended attributes */
#define C_NEG_ENTRIES      0x00400  /* directory has negative name entries */
#define C_WARNED_RSRC      0x00800  /* cnode lookup warning has been issued */ 

#define C_NEED_DATA_SETSIZE  0x01000  /* Do a ubc_setsize(0) on c_rsrc_vp after the unlock */
#define C_NEED_RSRC_SETSIZE  0x02000  /* Do a ubc_setsize(0) on c_vp after the unlock */
#define C_DIR_MODIFICATION   0x04000  /* Directory is being modified, wait for lookups */

#define ZFTIMELIMIT	(5 * 60)

/*
 * The following is the "invisible" bit from the fdFlags field
 * in the FndrFileInfo.
 */
enum { kFinderInvisibleMask = 1 << 14 };


/*
 * Convert between cnode pointers and vnode pointers
 */
#define VTOC(vp)	((struct cnode *)vnode_fsnode((vp)))

#define CTOV(cp,rsrc)	(((rsrc) && S_ISREG((cp)->c_mode)) ? \
			(cp)->c_rsrc_vp : (cp)->c_vp)

/*
 * Convert between vnode pointers and file forks
 *
 * Note: no CTOF since that is ambiguous
 */

#define FTOC(fp)	((fp)->ff_cp)

#define VTOF(vp)	((vp) == VTOC((vp))->c_rsrc_vp ?	\
			 VTOC((vp))->c_rsrcfork :		\
			 VTOC((vp))->c_datafork)

#define VCTOF(vp, cp)	((vp) == (cp)->c_rsrc_vp ?	\
			 (cp)->c_rsrcfork :		\
			 (cp)->c_datafork)

#define FTOV(fp)	((fp) == FTOC(fp)->c_rsrcfork ?		\
			 FTOC(fp)->c_rsrc_vp :			\
			 FTOC(fp)->c_vp)


/*
 * Test for a resource fork
 */
#define FORK_IS_RSRC(fp)	((fp) == FTOC(fp)->c_rsrcfork)

#define VNODE_IS_RSRC(vp)	((vp) == VTOC((vp))->c_rsrc_vp)


#define ATIME_ONDISK_ACCURACY	300


/* This overlays the FileID portion of NFS file handles. */
struct hfsfid {
	u_int32_t hfsfid_cnid;	/* Catalog node ID. */
	u_int32_t hfsfid_gen;	/* Generation number (create date). */
};


/* Get new default vnode */
extern int hfs_getnewvnode(struct hfsmount *hfsmp, struct vnode *dvp, struct componentname *cnp,
                           struct cat_desc *descp, int flags, struct cat_attr *attrp,
                           struct cat_fork *forkp, struct vnode **vpp);


#define GNV_WANTRSRC   0x01  /* Request the resource fork vnode. */
#define GNV_SKIPLOCK   0x02  /* Skip taking the cnode lock (when getting resource fork). */
#define GNV_CREATE     0x04  /* The vnode is for a newly created item. */


/* Touch cnode times based on c_touch_xxx flags */
extern void hfs_touchtimes(struct hfsmount *, struct cnode *);

/*
 * HFS cnode hash functions.
 */
extern void  hfs_chashinit(void);
extern void  hfs_chashinit_finish(void);
extern void  hfs_chashinsert(struct cnode *cp);
extern int   hfs_chashremove(struct cnode *cp);
extern void  hfs_chash_abort(struct cnode *cp);
extern void  hfs_chash_rehash(struct cnode *cp1, struct cnode *cp2);
extern void  hfs_chashwakeup(struct cnode *cp, int flags);
extern void  hfs_chash_mark_in_transit(struct cnode *cp);

extern struct vnode * hfs_chash_getvnode(dev_t dev, ino_t inum, int wantrsrc, int skiplock);
extern struct cnode * hfs_chash_getcnode(dev_t dev, ino_t inum, struct vnode **vpp, int wantrsrc, int skiplock);
extern int hfs_chash_snoop(dev_t, ino_t, int (*)(const struct cat_desc *,
                            const struct cat_attr *, void *), void *);
extern int hfs_valid_cnode(struct hfsmount *hfsmp, struct vnode *dvp, struct componentname *cnp, cnid_t cnid);
				
extern int hfs_chash_set_childlinkbit(dev_t dev, cnid_t cnid);

/*
 * HFS cnode lock functions.
 *
 *  HFS Locking Order:
 *
 *  1. cnode truncate lock (if needed)
 *  2. cnode lock (in parent-child order if related, otherwise by address order)
 *  3. journal (if needed)
 *  4. system files (as needed)
 *       A. Catalog B-tree file
 *       B. Attributes B-tree file
 *       C. Startup file (if there is one)
 *       D. Allocation Bitmap file (always exclusive, supports recursion)
 *       E. Overflow Extents B-tree file (always exclusive, supports recursion)
 *  5. hfs mount point (always last)
 *
 */
enum hfslocktype  {HFS_SHARED_LOCK = 1, HFS_EXCLUSIVE_LOCK = 2, HFS_FORCE_LOCK = 3};
#define HFS_SHARED_OWNER  (void *)0xffffffff

extern int hfs_lock(struct cnode *, enum hfslocktype);
extern int hfs_lockpair(struct cnode *, struct cnode *, enum hfslocktype);
extern int hfs_lockfour(struct cnode *, struct cnode *, struct cnode *, struct cnode *,
                        enum hfslocktype);

extern void hfs_unlock(struct cnode *);
extern void hfs_unlockpair(struct cnode *, struct cnode *);
extern void hfs_unlockfour(struct cnode *, struct cnode *, struct cnode *, struct cnode *);

extern void hfs_lock_truncate(struct cnode *, int);
extern void hfs_unlock_truncate(struct cnode *, int);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */

#endif /* ! _HFS_CNODE_H_ */
