/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1991, 1993
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
 *	@(#)mount.h	8.21 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef _SYS_MOUNT_INTERNAL_H_
#define	_SYS_MOUNT_INTERNAL_H_

#include <sys/appleapiopts.h>
#ifndef KERNEL
#include <sys/ucred.h>
#else
#include <sys/kernel_types.h>
#include <sys/namei.h>
#endif
#include <sys/queue.h>
#include <sys/lock.h>
#include <net/radix.h>
#include <sys/socket.h>		/* XXX for AF_MAX */
#include <sys/vfs_context.h>		/* XXX for AF_MAX */
#include <sys/mount.h>
#include <sys/cdefs.h>

struct label;

/*
 * Structure per mounted file system.  Each mounted file system has an
 * array of operations and an instance record.  The file systems are
 * put on a doubly linked list.
 */
TAILQ_HEAD(vnodelst, vnode);

struct mount {
	TAILQ_ENTRY(mount) mnt_list;		/* mount list */
	int32_t		mnt_count;		/* reference on the mount */
	lck_mtx_t	mnt_mlock;		/* mutex that protects mount point */
	struct vfsops	*mnt_op;		/* operations on fs */
	struct vfstable	*mnt_vtable;		/* configuration info */
	struct vnode	*mnt_vnodecovered;	/* vnode we mounted on */
	struct vnodelst	mnt_vnodelist;		/* list of vnodes this mount */
	struct vnodelst	mnt_workerqueue;		/* list of vnodes this mount */
	struct vnodelst	mnt_newvnodes;		/* list of vnodes this mount */
	int		mnt_flag;		/* flags */
	int		mnt_kern_flag;		/* kernel only flags */
	int		mnt_lflag;			/* mount life cycle flags */
	int		mnt_maxsymlinklen;	/* max size of short symlink */
	struct vfsstatfs	mnt_vfsstat;		/* cache of filesystem stats */
	qaddr_t		mnt_data;		/* private data */
	/* Cached values of the IO constraints for the device */
	u_int32_t	mnt_maxreadcnt;		/* Max. byte count for read */
	u_int32_t	mnt_maxwritecnt;	/* Max. byte count for write */
	u_int32_t	mnt_segreadcnt;		/* Max. segment count for read */
	u_int32_t	mnt_segwritecnt;	/* Max. segment count for write */
	u_int32_t	mnt_maxsegreadsize;	/* Max. segment read size  */
	u_int32_t	mnt_maxsegwritesize;	/* Max. segment write size */
        u_int32_t	mnt_alignmentmask;	/* Mask of bits that aren't addressable via DMA */
	u_int32_t	mnt_devblocksize;	/* the underlying device block size */
	u_int32_t	mnt_ioflags;		/* flags for  underlying device */
	lck_rw_t	mnt_rwlock;		/* mutex readwrite lock */
        lck_mtx_t	mnt_renamelock;		/* mutex that serializes renames that change shape of tree */
	vnode_t		mnt_devvp;		/* the device mounted on for local file systems */
	uint32_t	mnt_devbsdunit;		/* the BSD unit number of the device */
	int32_t		mnt_crossref;		/* refernces to cover lookups  crossing into mp */
	int32_t		mnt_iterref;		/* refernces to cover iterations; drained makes it -ve  */
 
 	/* XXX 3762912 hack to support HFS filesystem 'owner' */
 	uid_t		mnt_fsowner;
 	gid_t		mnt_fsgroup;

	struct label	*mnt_mntlabel;		/* MAC mount label */
	struct label	*mnt_fslabel;		/* MAC default fs label */

	/*
	 * cache the rootvp of the last mount point
	 * in the chain in the mount struct pointed
	 * to by the vnode sitting in '/'
	 * this cache is used to shortcircuit the
	 * mount chain traversal and allows us
	 * to traverse to the true underlying rootvp
	 * in 1 easy step inside of 'cache_lookup_path'
	 *
	 * make sure to validate against the cached vid
	 * in case the rootvp gets stolen away since
	 * we don't take an explicit long term reference
	 * on it when we mount it
	 */
	vnode_t		mnt_realrootvp;
        int		mnt_realrootvp_vid;
	/*
	 * bumped each time a mount or unmount
	 * occurs... its used to invalidate
	 * 'mnt_realrootvp' from the cache
	 */
        int             mnt_generation;
        /*
	 * if 'MNTK_AUTH_CACHE_TIMEOUT' is 
	 * set, then 'mnt_authcache_ttl' is
	 * the time-to-live for the per-vnode authentication cache
	 * on this mount... if zero, no cache is maintained...
	 * if 'MNTK_AUTH_CACHE_TIMEOUT' isn't set, its the
	 * time-to-live for the cached lookup right for
	 * volumes marked 'MNTK_AUTH_OPAQUE'.
	 */
	int		mnt_authcache_ttl;
	/*
	 * The proc structure pointer and process ID form a
	 * sufficiently unique duple identifying the process
	 * hosting this mount point. Set by vfs_markdependency()
	 * and utilized in new_vnode() to avoid reclaiming vnodes
	 * with this dependency (radar 5192010).
	 */
	pid_t		mnt_dependent_pid;
	void		*mnt_dependent_process;
};

/*
 * default number of seconds to keep cached lookup
 * rights valid on mounts marked MNTK_AUTH_OPAQUE
 */
#define CACHED_LOOKUP_RIGHT_TTL		2

/*
 * ioflags
 */
#define MNT_IOFLAGS_FUA_SUPPORTED	0x00000001

  
/* XXX 3762912 hack to support HFS filesystem 'owner' */
#define vfs_setowner(_mp, _uid, _gid)	do {(_mp)->mnt_fsowner = (_uid); (_mp)->mnt_fsgroup = (_gid); } while (0)


/* mount point to which dead vps point to */
extern struct mount * dead_mountp;

/*
 * Internal filesystem control flags stored in mnt_kern_flag.
 *
 * MNTK_UNMOUNT locks the mount entry so that name lookup cannot proceed
 * past the mount point.  This keeps the subtree stable during mounts
 * and unmounts.
 *
 * Note:	We are counting down on new bit assignments.  This is
 *		because the bits here were broken out from the high bits
 *		of the mount flags.
 */
#define MNTK_AUTH_CACHE_TTL	0x00008000      /* rights cache has TTL - TTL of 0 disables cache */
#define	MNTK_PATH_FROM_ID	0x00010000	/* mounted file system supports id-to-path lookups */
#define	MNTK_UNMOUNT_PREFLIGHT	0x00020000	/* mounted file system wants preflight check during unmount */
#define	MNTK_NAMED_STREAMS	0x00040000	/* mounted file system supports Named Streams VNOPs */
#define	MNTK_EXTENDED_ATTRS	0x00080000	/* mounted file system supports Extended Attributes VNOPs */
#define	MNTK_LOCK_LOCAL		0x00100000	/* advisory locking is done above the VFS itself */
#define MNTK_VIRTUALDEV 	0x00200000      /* mounted on a virtual device i.e. a disk image */
#define MNTK_ROOTDEV    	0x00400000      /* this filesystem resides on the same device as the root */
#define MNTK_UNMOUNT		0x01000000	/* unmount in progress */
#define	MNTK_MWAIT		0x02000000	/* waiting for unmount to finish */
#define MNTK_WANTRDWR		0x04000000	/* upgrade to read/write requested */
#if REV_ENDIAN_FS
#define MNT_REVEND		0x08000000	/* Reverse endian FS */
#endif /* REV_ENDIAN_FS */
#define MNTK_FRCUNMOUNT		0x10000000	/* Forced unmount wanted. */
#define MNTK_AUTH_OPAQUE        0x20000000      /* authorisation decisions are not made locally */
#define MNTK_AUTH_OPAQUE_ACCESS 0x40000000      /* VNOP_ACCESS is reliable for remote auth */
#define MNTK_EXTENDED_SECURITY	0x80000000	/* extended security supported */

#define	MNT_LBUSY		0x00000001	/* mount is busy */
#define MNT_LUNMOUNT		0x00000002	/* mount in unmount */
#define MNT_LFORCE		0x00000004	/* mount in forced unmount */
#define MNT_LDRAIN		0x00000008	/* mount in drain */
#define MNT_LITER		0x00000010	/* mount in iteration */
#define MNT_LNEWVN		0x00000020	/* mount has new vnodes created */
#define MNT_LWAIT		0x00000040	/* wait for unmount op */
#define MNT_LITERWAIT		0x00000080	/* mount in iteration */
#define MNT_LDEAD		0x00000100	/* mount already unmounted*/


/*
 * Generic file handle
 */
#define	NFS_MAX_FH_SIZE		NFSV4_MAX_FH_SIZE
#define	NFSV4_MAX_FH_SIZE	128
#define	NFSV3_MAX_FH_SIZE	64
#define	NFSV2_MAX_FH_SIZE	32
struct fhandle {
	int		fh_len;				/* length of file handle */
	unsigned char	fh_data[NFS_MAX_FH_SIZE];	/* file handle value */
};
typedef struct fhandle	fhandle_t;



/*
 * Filesystem configuration information. One of these exists for each
 * type of filesystem supported by the kernel. These are searched at
 * mount time to identify the requested filesystem.
 */
struct vfstable {
/* THE FOLLOWING SHOULD KEEP THE SAME FOR user compat with sysctl */
	struct	vfsops *vfc_vfsops;	/* filesystem operations vector */
	char	vfc_name[MFSNAMELEN];	/* filesystem type name */
	int	vfc_typenum;		/* historic filesystem type number */
	int	vfc_refcount;		/* number mounted of this type */
	int	vfc_flags;		/* permanent flags */
	int	(*vfc_mountroot)(mount_t, vnode_t, vfs_context_t);	/* if != NULL, routine to mount root */
	struct	vfstable *vfc_next;	/* next in list */
/* Till the above we SHOULD KEEP THE SAME FOR user compat with sysctl */
	int         vfc_threadsafe;     /* FS is thread & premeption safe */
	lck_mtx_t   vfc_lock;		/* for non-threaded file systems */
	int 		vfc_vfsflags;	/* for optional types */
	void *		vfc_descptr;	/* desc table allocated address */
	int			vfc_descsize;	/* size allocated for desc table */
	int 		vfc_64bitready;	/* The file system is ready for 64bit */
};

/* vfc_vfsflags: */
#define VFC_VFSLOCALARGS	0x02
#define	VFC_VFSGENERICARGS	0x04
#define	VFC_VFSNATIVEXATTR	0x10
#define	VFC_VFSDIRLINKS		0x20
#define	VFC_VFSPREFLIGHT	0x40
#define	VFC_VFSREADDIR_EXTENDED	0x80
#define	VFC_VFSNOMACLABEL	0x1000

extern int maxvfsconf;		/* highest defined filesystem type */
extern struct vfstable  *vfsconf;	/* head of list of filesystem types */
extern int maxvfsslots;		/* Maximum slots available to be used */
extern int numused_vfsslots;	/* number of slots already used */

/* the following two are xnu private */
struct vfstable *	vfstable_add(struct	vfstable *);
int	vfstable_del(struct vfstable *);


struct vfsmount_args {
	union {
		struct {
			char * mnt_fspec;
			void * mnt_fsdata;
		} mnt_localfs_args;
		struct {
			void *  mnt_fsdata;		/* FS specific */
		} mnt_remotefs_args;
	} mountfs_args;
};


/*
 * LP64 version of statfs structure.
 * NOTE - must be kept in sync with struct statfs in mount.h
 */
struct user_statfs {
	short		f_otype;		/* TEMPORARY SHADOW COPY OF f_type */
	short		f_oflags;		/* TEMPORARY SHADOW COPY OF f_flags */
	user_long_t	f_bsize __attribute((aligned(8)));		/* fundamental file system block size */
	user_long_t	f_iosize;		/* optimal transfer block size */
	user_long_t	f_blocks;		/* total data blocks in file system */
	user_long_t	f_bfree;		/* free blocks in fs */
	user_long_t	f_bavail;		/* free blocks avail to non-superuser */
	user_long_t	f_files;		/* total file nodes in file system */
	user_long_t	f_ffree;		/* free file nodes in fs */
	fsid_t		f_fsid;			/* file system id */
	uid_t		f_owner;		/* user that mounted the filesystem */
	short		f_reserved1;	/* spare for later */
	short		f_type;			/* type of filesystem */
    user_long_t	f_flags;		/* copy of mount exported flags */
	user_long_t f_reserved2[2];	/* reserved for future use */
	char		f_fstypename[MFSNAMELEN]; /* fs type name */
	char		f_mntonname[MNAMELEN];	/* directory on which mounted */
	char		f_mntfromname[MNAMELEN];/* mounted filesystem */
#if COMPAT_GETFSSTAT
	char		f_reserved3[0];	/* For alignment */
	user_long_t	f_reserved4[0];	/* For future use */
#else
	char		f_reserved3;	/* For alignment */
	user_long_t	f_reserved4[4] __attribute((aligned(8)));	/* For future use */
#endif
};

/*
 * throttle I/Os are affected only by normal I/Os happening on the same bsd device node.  For example, disk1s3 and
 * disk1s5 are the same device node, while disk1s3 and disk2 are not (although disk2 might be a mounted disk image file
 * and the disk image file resides on a partition in disk1).  The following constant defines the maximum number of
 * different bsd device nodes the algorithm can consider, and larger numbers are rounded by this maximum.  Since
 * throttled I/O is usually useful in non-server environment only, a small number 16 is enough in most cases
 */
#define LOWPRI_MAX_NUM_DEV 16

__BEGIN_DECLS

extern int mount_generation;
extern TAILQ_HEAD(mntlist, mount) mountlist;
void mount_list_lock(void);
void mount_list_unlock(void);
void mount_lock_init(mount_t);
void mount_lock_destroy(mount_t);
void mount_lock(mount_t);
void mount_unlock(mount_t);
void mount_lock_renames(mount_t);
void mount_unlock_renames(mount_t);
void mount_ref(mount_t, int);
void mount_drop(mount_t, int);
int  mount_refdrain(mount_t);

/* vfs_rootmountalloc should be kept as a private api */
errno_t vfs_rootmountalloc(const char *, const char *, mount_t *mpp);
errno_t	vfs_init_io_attributes(vnode_t, mount_t);

int	vfs_mountroot(void);
void	vfs_unmountall(void);
int	safedounmount(struct mount *, int, vfs_context_t);
int	dounmount(struct mount *, int, int, vfs_context_t);

/* xnuy internal api */
void  mount_dropcrossref(mount_t, vnode_t, int);
mount_t mount_lookupby_volfsid(int, int);
mount_t mount_list_lookupby_fsid(fsid_t *, int, int);
void mount_list_add(mount_t);
void mount_list_remove(mount_t);
int  mount_iterref(mount_t, int);
int  mount_isdrained(mount_t, int);
void mount_iterdrop(mount_t);
void mount_iterdrain(mount_t);
void mount_iterreset(mount_t);

/* throttled I/O api */
int throttle_get_io_policy(struct uthread **ut);
extern void throttle_lowpri_io(boolean_t ok_to_sleep);
int throttle_io_will_be_throttled(int lowpri_window_msecs, size_t devbsdunit);

__END_DECLS

#endif /* !_SYS_MOUNT_INTERNAL_H_ */
