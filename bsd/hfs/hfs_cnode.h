/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
#ifndef _HFS_CNODE_H_
#define _HFS_CNODE_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/quota.h>

#include <hfs/hfs_catalog.h>
#include <hfs/rangelist.h>


/*
 * The filefork is used to represent an HFS file fork (data or resource).
 * Reading or writing any of these fields requires holding cnode lock.
 */
struct filefork {
	struct cnode	*ff_cp;		/* cnode associated with this fork */
	struct rl_head	ff_invalidranges; /* Areas of disk that should read back as zeroes */
	union {
	  struct hfslockf *ffu_lockf;	/* Head of byte-level lock list. */
	  void *ffu_sysdata;		/* private data for system files */
	  char *ffu_symlinkptr;		/* symbolic link pathname */
	} ff_un;
	struct cat_fork	ff_data;
	u_int32_t	ff_unallocblocks; /* unallocated blocks (until cmap) */
};

/* Aliases for common fields */
#define ff_size		ff_data.cf_size
#define ff_clumpsize	ff_data.cf_clump
#define ff_blocks	ff_data.cf_blocks
#define ff_extents	ff_data.cf_extents
#define ff_symlinkptr	ff_un.ffu_symlinkptr
#define	ff_lockf	ff_un.ffu_lockf


/* The btree code still needs these... */
#define fcbEOF		ff_size
#define fcbClmpSize	ff_clumpsize
#define fcbExtents	ff_extents
#define	fcbBTCBPtr	ff_un.ffu_sysdata


/*
 * Directory index entry
 */
struct	hfs_index {
	SLIST_ENTRY(hfs_index) hi_link;
	int	hi_index;
	void	*hi_thread;	/* thread that created index entry */
	char	hi_name[1];
};

/*
 * The cnode is used to represent each active (or recently active)
 * file or directory in the HFS filesystem.
 *
 * Reading or writing any of these fields requires holding c_lock.
 */
struct cnode {
	struct lock__bsd__	c_lock;		/* cnode's lock */
	LIST_ENTRY(cnode)	c_hash;		/* cnode's hash chain */
	u_int32_t		c_flag;		/* cnode's runtime flags */
	struct vnode		*c_vp;		/* vnode for data fork or dir */
	struct vnode		*c_rsrc_vp;	/* vnode for resource fork */
	struct vnode		*c_devvp;	/* vnode for block I/O */
	dev_t			c_dev;		/* cnode's device */
        struct dquot		*c_dquot[MAXQUOTAS]; /* cnode's quota info */
	cnid_t			c_childhint;	/* catalog hint for children */
	struct cat_desc		c_desc;		/* cnode's descriptor */
	struct cat_attr		c_attr;		/* cnode's attributes */
	SLIST_HEAD(hfs_indexhead, hfs_index) c_indexlist;  /* directory index list */
 	struct filefork		*c_datafork;	/* cnode's data fork */
	struct filefork		*c_rsrcfork;	/* cnode's rsrc fork */
};

/* Aliases for common cnode fields */
#define c_cnid		c_desc.cd_cnid
#define c_hint		c_desc.cd_hint
#define c_parentcnid	c_desc.cd_parentcnid
#define c_encoding	c_desc.cd_encoding

#define c_fileid	c_attr.ca_fileid
#define c_mode		c_attr.ca_mode
#define c_nlink		c_attr.ca_nlink
#define c_uid		c_attr.ca_uid
#define c_gid		c_attr.ca_gid
#define c_rdev		c_attr.ca_rdev
#define c_atime		c_attr.ca_atime
#define c_mtime		c_attr.ca_mtime
#define c_mtime_nsec	c_attr.ca_mtime_nsec
#define c_ctime		c_attr.ca_ctime
#define c_itime		c_attr.ca_itime
#define c_btime		c_attr.ca_btime
#define c_flags		c_attr.ca_flags
#define c_finderinfo	c_attr.ca_finderinfo
#define c_blocks	c_attr.ca_blocks
#define c_entries	c_attr.ca_entries
#define c_zftimeout	c_childhint


/* Runtime cnode flags (kept in c_flag) */
#define C_ACCESS	0x0001	/* Access time update request */
#define C_CHANGE	0x0002	/* Change time update request */
#define C_UPDATE	0x0004	/* Modification time update request */
#define C_MODIFIED 	0x0008	/* CNode has been modified */
#define C_ATIMEMOD	0x0010	/* Access time has been modified */

#define C_NOEXISTS	0x0020	/* CNode has been deleted, catalog entry is gone */
#define C_DELETED	0x0040	/* CNode has been marked to be deleted */
#define C_HARDLINK	0x0080	/* CNode is a hard link */

#define C_ALLOC		0x0100	/* CNode is being allocated */
#define C_WALLOC	0x0200	/* Waiting for allocation to finish */
#define	C_TRANSIT	0x0400	/* CNode is getting recycled  */
#define	C_WTRANSIT	0x0800	/* Waiting for cnode getting recycled  */

#define C_RENAME	0x1000	/* CNode is being renamed */
#define C_ZFWANTSYNC	0x2000	/* fsync requested and file has holes */


#define ZFTIMELIMIT	(5 * 60)

/*
 * Convert between cnode pointers and vnode pointers
 */
#define VTOC(vp)	((struct cnode *)(vp)->v_data)

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

#define FTOV(fp)	((fp) == FTOC(fp)->c_rsrcfork ?		\
			 FTOC(fp)->c_rsrc_vp :			\
			 FTOC(fp)->c_vp)

/*
 * Test for a resource fork
 */
#define FORK_IS_RSRC(fp)	((fp) == FTOC(fp)->c_rsrcfork)

#define VNODE_IS_RSRC(vp)	((vp) == VTOC((vp))->c_rsrc_vp)


/*
 * CTIMES should be an inline function...
 */
#define C_TIMEMASK	(C_ACCESS | C_CHANGE | C_UPDATE)

#define ATIME_ACCURACY	60

#define CTIMES(cp, t1, t2) {							\
	if ((cp)->c_flag & C_TIMEMASK) {					\
		/*								\
		 * If only the access time is changing then defer		\
		 * updating it on-disk util later (in hfs_inactive).		\
		 * If it was recently updated then skip the update.		\
		 */								\
		if (((cp)->c_flag & (C_TIMEMASK | C_MODIFIED)) == C_ACCESS) {	\
			if (((cp)->c_flag & C_ATIMEMOD) ||			\
			    (t1)->tv_sec > ((cp)->c_atime + ATIME_ACCURACY)) {	\
				(cp)->c_atime = (t1)->tv_sec;			\
				(cp)->c_flag |= C_ATIMEMOD;			\
			}							\
			(cp)->c_flag &= ~C_ACCESS;				\
		} else {							\
			if ((cp)->c_flag & C_ACCESS) {				\
				(cp)->c_atime = (t1)->tv_sec;			\
			}							\
			if ((cp)->c_flag & C_UPDATE) {				\
				(cp)->c_mtime = (t2)->tv_sec;			\
				(cp)->c_mtime_nsec = (t2)->tv_usec * 1000;	\
			}							\
			if ((cp)->c_flag & C_CHANGE) {				\
				(cp)->c_ctime = time.tv_sec;			\
			}							\
			(cp)->c_flag |= C_MODIFIED;				\
			(cp)->c_flag &= ~C_TIMEMASK;				\
		}								\
	}									\
}

/* This overlays the fid structure (see mount.h). */
struct hfsfid {
	u_int16_t hfsfid_len;	/* Length of structure. */
	u_int16_t hfsfid_pad;	/* Force 32-bit alignment. */
	/* The following data is filesystem-dependent, up to MAXFIDSZ (16) bytes: */
	u_int32_t hfsfid_cnid;	/* Catalog node ID. */
	u_int32_t hfsfid_gen;	/* Generation number (create date). */
};


/*
 * HFS cnode hash functions.
 */
extern void  hfs_chashinit(void);
extern void  hfs_chashinsert(struct cnode *cp);
extern void  hfs_chashremove(struct cnode *cp);
extern struct cnode * hfs_chashget(dev_t dev, ino_t inum, int wantrsrc,
				struct vnode **vpp, struct vnode **rvpp);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */

#endif /* ! _HFS_CNODE_H_ */
