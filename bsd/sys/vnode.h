/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
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
 *	@(#)vnode.h	8.17 (Berkeley) 5/20/95
 */
 
#ifndef _VNODE_H_
#define _VNODE_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
#ifdef KERNEL
#include <sys/kernel_types.h>
#include <sys/signal.h>
#endif

/*
 * The vnode is the focus of all file activity in UNIX.  There is a
 * unique vnode allocated for each active file, each current directory,
 * each mounted-on file, text file, and the root.
 */

/*
 * Vnode types.  VNON means no type.
 */
enum vtype	{ VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR,
			  VCPLX };

/*
 * Vnode tag types.
 * These are for the benefit of external programs only (e.g., pstat)
 * and should NEVER be inspected by the kernel.
 */
enum vtagtype	{
	VT_NON, VT_UFS, VT_NFS, VT_MFS, VT_MSDOSFS, VT_LFS, VT_LOFS, VT_FDESC,
	VT_PORTAL, VT_NULL, VT_UMAP, VT_KERNFS, VT_PROCFS, VT_AFS, VT_ISOFS,
	VT_UNION, VT_HFS, VT_VOLFS, VT_DEVFS, VT_WEBDAV, VT_UDF, VT_AFP,
	VT_CDDA, VT_CIFS,VT_OTHER};


/*
 * flags for VNOP_BLOCKMAP
 */
#define VNODE_READ	0x01
#define VNODE_WRITE	0x02



/* flags for VNOP_ALLOCATE */
#define	PREALLOCATE		0x00000001	/* preallocate allocation blocks */
#define	ALLOCATECONTIG	0x00000002	/* allocate contigious space */
#define	ALLOCATEALL		0x00000004	/* allocate all requested space */
									/* or no space at all */
#define	FREEREMAINDER	0x00000008	/* deallocate allocated but */
									/* unfilled blocks */
#define	ALLOCATEFROMPEOF	0x00000010	/* allocate from the physical eof */
#define	ALLOCATEFROMVOL		0x00000020	/* allocate from the volume offset */

/*
 * Token indicating no attribute value yet assigned. some user source uses this
 */
#define	VNOVAL	(-1)

#ifdef KERNEL

/*
 * Flags for ioflag.
 */
#define	IO_UNIT		0x0001		/* do I/O as atomic unit */
#define	IO_APPEND	0x0002		/* append write to end */
#define	IO_SYNC		0x0004		/* do I/O synchronously */
#define	IO_NODELOCKED	0x0008		/* underlying node already locked */
#define	IO_NDELAY	0x0010		/* FNDELAY flag set in file table */
#define	IO_NOZEROFILL	0x0020		/* F_SETSIZE fcntl uses to prevent zero filling */
#define	IO_TAILZEROFILL	0x0040		/* zero fills at the tail of write */
#define	IO_HEADZEROFILL	0x0080		/* zero fills at the head of write */
#define	IO_NOZEROVALID	0x0100		/* do not zero fill if valid page */
#define	IO_NOZERODIRTY	0x0200		/* do not zero fill if page is dirty */
#define IO_CLOSE	0x0400		/* I/O issued from close path */
#define IO_NOCACHE	0x0800		/* same effect as VNOCACHE_DATA, but only for this 1 I/O */
#define IO_RAOFF	0x1000		/* same effect as VRAOFF, but only for this 1 I/O */
#define IO_DEFWRITE	0x2000		/* defer write if vfs.defwrite is set */

/*
 * Component Name: this structure describes the pathname
 * information that is passed through the VNOP interface.
 */
struct componentname {
	/*
	 * Arguments to lookup.
	 */
	u_long	cn_nameiop;	/* lookup operation */
	u_long	cn_flags;	/* flags (see below) */
#ifdef BSD_KERNEL_PRIVATE
	vfs_context_t	cn_context;
	void * pad_obsolete2;

/* XXX use of these defines are deprecated */
#define	cn_proc		(cn_context->vc_proc + 0)	/* non-lvalue */
#define	cn_cred		(cn_context->vc_ucred + 0)	/* non-lvalue */

#else
	void * obsolete1;	/* use vfs_context_t */
	void * obsolete2;	/* use vfs_context_t */
#endif
	/*
	 * Shared between lookup and commit routines.
	 */
	char	*cn_pnbuf;	/* pathname buffer */
	long	cn_pnlen;	/* length of allocated buffer */
	char	*cn_nameptr;	/* pointer to looked up name */
	long	cn_namelen;	/* length of looked up component */
	u_long	cn_hash;	/* hash value of looked up name */
	long	cn_consume;	/* chars to consume in lookup() */
};

/*
 * component name operations (for VNOP_LOOKUP)
 */
#define	LOOKUP		0	/* perform name lookup only */
#define	CREATE		1	/* setup for file creation */
#define	DELETE		2	/* setup for file deletion */
#define	RENAME		3	/* setup for file renaming */
#define	OPMASK		3	/* mask for operation */

/*
 * component name operational modifier flags
 */
#define	FOLLOW		0x0040	/* follow symbolic links */

/*
 * component name parameter descriptors.
 */
#define	ISDOTDOT	0x002000 /* current component name is .. */
#define	MAKEENTRY	0x004000 /* entry is to be added to name cache */
#define	ISLASTCN	0x008000 /* this is last component of pathname */
#define	ISWHITEOUT	0x020000 /* found whiteout */
#define	DOWHITEOUT	0x040000 /* do whiteouts */



/* The following structure specifies a vnode for creation */
struct vnode_fsparam {
	struct mount * vnfs_mp;		/* mount point to which this vnode_t is part of */
	enum vtype	vnfs_vtype;		/* vnode type */
	const char * vnfs_str;		/* File system Debug aid */
	struct vnode * vnfs_dvp;			/* The parent vnode */
	void * vnfs_fsnode;			/* inode */
	int (**vnfs_vops)(void *);		/* vnode dispatch table */
	int vnfs_markroot;			/* is this a root vnode in FS (not a system wide one) */
	int vnfs_marksystem;		/* is  a system vnode */
	dev_t vnfs_rdev;			/* dev_t  for block or char vnodes */
	off_t vnfs_filesize;		/* that way no need for getattr in UBC */
	struct componentname * vnfs_cnp; /* component name to add to namecache */
	uint32_t vnfs_flags;		/* flags */
};

#define	VNFS_NOCACHE	0x01	/* do not add to name cache at this time */
#define	VNFS_CANTCACHE	0x02	/* never add this instance to the name cache */

#define VNCREATE_FLAVOR	0
#define VCREATESIZE sizeof(struct vnode_fsparam)

/*
 * Vnode attributes, new-style.
 *
 * The vnode_attr structure is used to transact attribute changes and queries
 * with the filesystem.
 *
 * Note that this structure may be extended, but existing fields must not move.
 */

#define VATTR_INIT(v)			do {(v)->va_supported = (v)->va_active = 0ll; (v)->va_vaflags = 0;} while(0)
#define VATTR_SET_ACTIVE(v, a)		((v)->va_active |= VNODE_ATTR_ ## a)
#define VATTR_SET_SUPPORTED(v, a)	((v)->va_supported |= VNODE_ATTR_ ## a)
#define VATTR_IS_SUPPORTED(v, a)	((v)->va_supported & VNODE_ATTR_ ## a)
#define VATTR_CLEAR_ACTIVE(v, a)	((v)->va_active &= ~VNODE_ATTR_ ## a)
#define VATTR_CLEAR_SUPPORTED(v, a)	((v)->va_supported &= ~VNODE_ATTR_ ## a)
#define VATTR_IS_ACTIVE(v, a)		((v)->va_active & VNODE_ATTR_ ## a)
#define VATTR_ALL_SUPPORTED(v)		(((v)->va_active & (v)->va_supported) == (v)->va_active)
#define VATTR_INACTIVE_SUPPORTED(v)	do {(v)->va_active &= ~(v)->va_supported; (v)->va_supported = 0;} while(0)
#define VATTR_SET(v, a, x)		do { (v)-> a = (x); VATTR_SET_ACTIVE(v, a);} while(0)
#define VATTR_WANTED(v, a)		VATTR_SET_ACTIVE(v, a)
#define VATTR_RETURN(v, a, x)		do { (v)-> a = (x); VATTR_SET_SUPPORTED(v, a);} while(0)
#define VATTR_NOT_RETURNED(v, a)	(VATTR_IS_ACTIVE(v, a) && !VATTR_IS_SUPPORTED(v, a))

/*
 * Two macros to simplify conditional checking in kernel code.
 */
#define VATTR_IS(v, a, x)		(VATTR_IS_SUPPORTED(v, a) && (v)-> a == (x))
#define VATTR_IS_NOT(v, a, x)		(VATTR_IS_SUPPORTED(v, a) && (v)-> a != (x))

#define VNODE_ATTR_va_rdev		(1LL<< 0)	/* 00000001 */
#define VNODE_ATTR_va_nlink		(1LL<< 1)	/* 00000002 */
#define VNODE_ATTR_va_total_size	(1LL<< 2)	/* 00000004 */
#define VNODE_ATTR_va_total_alloc	(1LL<< 3)	/* 00000008 */
#define VNODE_ATTR_va_data_size		(1LL<< 4)	/* 00000010 */
#define VNODE_ATTR_va_data_alloc	(1LL<< 5)	/* 00000020 */
#define VNODE_ATTR_va_iosize		(1LL<< 6)	/* 00000040 */
#define VNODE_ATTR_va_uid		(1LL<< 7)	/* 00000080 */
#define VNODE_ATTR_va_gid		(1LL<< 8)	/* 00000100 */
#define VNODE_ATTR_va_mode		(1LL<< 9)	/* 00000200 */
#define VNODE_ATTR_va_flags		(1LL<<10)	/* 00000400 */
#define VNODE_ATTR_va_acl		(1LL<<11)	/* 00000800 */
#define VNODE_ATTR_va_create_time	(1LL<<12)	/* 00001000 */
#define VNODE_ATTR_va_access_time	(1LL<<13)	/* 00002000 */
#define VNODE_ATTR_va_modify_time	(1LL<<14)	/* 00004000 */
#define VNODE_ATTR_va_change_time	(1LL<<15)	/* 00008000 */
#define VNODE_ATTR_va_backup_time	(1LL<<16)	/* 00010000 */
#define VNODE_ATTR_va_fileid		(1LL<<17)	/* 00020000 */
#define VNODE_ATTR_va_linkid		(1LL<<18)	/* 00040000 */
#define VNODE_ATTR_va_parentid		(1LL<<19)	/* 00080000 */
#define VNODE_ATTR_va_fsid		(1LL<<20)	/* 00100000 */
#define VNODE_ATTR_va_filerev		(1LL<<21)	/* 00200000 */
#define VNODE_ATTR_va_gen		(1LL<<22)	/* 00400000 */
#define VNODE_ATTR_va_encoding		(1LL<<23)	/* 00800000 */
#define VNODE_ATTR_va_type		(1LL<<24)	/* 01000000 */
#define VNODE_ATTR_va_name		(1LL<<25)       /* 02000000 */
#define VNODE_ATTR_va_uuuid		(1LL<<26)	/* 04000000 */
#define VNODE_ATTR_va_guuid		(1LL<<27)	/* 08000000 */
#define VNODE_ATTR_va_nchildren		(1LL<<28)       /* 10000000 */

#define VNODE_ATTR_BIT(n)	(VNODE_ATTR_ ## n)
/*
 * Read-only attributes.
 */
#define VNODE_ATTR_RDONLY	(VNODE_ATTR_BIT(va_rdev) |		\
				VNODE_ATTR_BIT(va_nlink) |		\
				VNODE_ATTR_BIT(va_total_size) |		\
				VNODE_ATTR_BIT(va_total_alloc) |	\
				VNODE_ATTR_BIT(va_data_alloc) |		\
				VNODE_ATTR_BIT(va_iosize) |		\
				VNODE_ATTR_BIT(va_fileid) |		\
				VNODE_ATTR_BIT(va_linkid) |		\
				VNODE_ATTR_BIT(va_parentid) |		\
				VNODE_ATTR_BIT(va_fsid) |		\
				VNODE_ATTR_BIT(va_filerev) |		\
				VNODE_ATTR_BIT(va_gen) |		\
				VNODE_ATTR_BIT(va_name) |		\
				VNODE_ATTR_BIT(va_type) |		\
				VNODE_ATTR_BIT(va_nchildren))
/*
 * Attributes that can be applied to a new file object.
 */
#define VNODE_ATTR_NEWOBJ	(VNODE_ATTR_BIT(va_rdev) |		\
				VNODE_ATTR_BIT(va_uid)	|		\
				VNODE_ATTR_BIT(va_gid) |		\
				VNODE_ATTR_BIT(va_mode) |		\
				VNODE_ATTR_BIT(va_flags) |		\
				VNODE_ATTR_BIT(va_acl) |		\
				VNODE_ATTR_BIT(va_create_time) |	\
				VNODE_ATTR_BIT(va_modify_time) |	\
				VNODE_ATTR_BIT(va_change_time) |	\
				VNODE_ATTR_BIT(va_encoding) |		\
				VNODE_ATTR_BIT(va_type) |		\
				VNODE_ATTR_BIT(va_uuuid) |		\
				VNODE_ATTR_BIT(va_guuid))

struct vnode_attr {
	/* bitfields */
	uint64_t	va_supported;
	uint64_t	va_active;

	/*
	 * Control flags.  The low 16 bits are reserved for the
	 * ioflags being passed for truncation operations.
	 */
	int		va_vaflags;
	
	/* traditional stat(2) parameter fields */
	dev_t		va_rdev;	/* device id (device nodes only) */
	uint64_t	va_nlink;	/* number of references to this file */
	uint64_t	va_total_size;	/* size in bytes of all forks */
	uint64_t	va_total_alloc;	/* disk space used by all forks */
	uint64_t	va_data_size;	/* size in bytes of the main(data) fork */
	uint64_t	va_data_alloc;	/* disk space used by the main(data) fork */
	uint32_t	va_iosize;	/* optimal I/O blocksize */

	/* file security information */
	uid_t		va_uid;		/* owner UID */
	gid_t		va_gid;		/* owner GID */
	mode_t		va_mode;	/* posix permissions */
	uint32_t	va_flags;	/* file flags */
	struct kauth_acl *va_acl;	/* access control list */

	/* timestamps */
	struct timespec	va_create_time;	/* time of creation */
	struct timespec	va_access_time;	/* time of last access */
	struct timespec	va_modify_time;	/* time of last data modification */
	struct timespec	va_change_time;	/* time of last metadata change */
	struct timespec	va_backup_time;	/* time of last backup */
	
	/* file parameters */
	uint64_t	va_fileid;	/* file unique ID in filesystem */
	uint64_t	va_linkid;	/* file link unique ID */
	uint64_t	va_parentid;	/* parent ID */
	uint32_t	va_fsid;	/* filesystem ID */
	uint64_t	va_filerev;	/* file revision counter */	/* XXX */
	uint32_t	va_gen;		/* file generation count */	/* XXX - relationship of
									* these two? */
	/* misc parameters */
	uint32_t	va_encoding;	/* filename encoding script */

	enum vtype	va_type;	/* file type (create only) */
	char *		va_name;	/* Name for ATTR_CMN_NAME; MAXPATHLEN bytes */
	guid_t		va_uuuid;	/* file owner UUID */
	guid_t		va_guuid;	/* file group UUID */
	
	uint64_t	va_nchildren;	/* Number of items in a directory */
					/* Meaningful for directories only */

	/* add new fields here only */
};

/*
 * Flags for va_vaflags.
 */
#define	VA_UTIMES_NULL	0x010000	/* utimes argument was NULL */
#define VA_EXCLUSIVE	0x020000	/* exclusive create request */



/*
 *  Modes.  Some values same as Ixxx entries from inode.h for now.
 */
#define	VSUID	0x800 /*04000*/	/* set user id on execution */
#define	VSGID	0x400 /*02000*/	/* set group id on execution */
#define	VSVTX	0x200 /*01000*/	/* save swapped text even after use */
#define	VREAD	0x100 /*00400*/	/* read, write, execute permissions */
#define	VWRITE	0x080 /*00200*/
#define	VEXEC	0x040 /*00100*/


/*
 * Convert between vnode types and inode formats (since POSIX.1
 * defines mode word of stat structure in terms of inode formats).
 */
extern enum vtype	iftovt_tab[];
extern int		vttoif_tab[];
#define IFTOVT(mode)	(iftovt_tab[((mode) & S_IFMT) >> 12])
#define VTTOIF(indx)	(vttoif_tab[(int)(indx)])
#define MAKEIMODE(indx, mode)	(int)(VTTOIF(indx) | (mode))


/*
 * Flags to various vnode functions.
 */
#define	SKIPSYSTEM	0x0001		/* vflush: skip vnodes marked VSYSTEM */
#define	FORCECLOSE	0x0002		/* vflush: force file closeure */
#define	WRITECLOSE	0x0004		/* vflush: only close writeable files */
#define SKIPSWAP	0x0008		/* vflush: skip vnodes marked VSWAP */
#define SKIPROOT	0x0010		/* vflush: skip root vnodes marked VROOT */

#define	DOCLOSE		0x0008		/* vclean: close active files */

#define	V_SAVE		0x0001		/* vinvalbuf: sync file first */
#define	V_SAVEMETA	0x0002		/* vinvalbuf: leave indirect blocks */

#define	REVOKEALL	0x0001		/* vnop_revoke: revoke all aliases */

/* VNOP_REMOVE: do not delete busy files (Carbon remove file semantics) */
#define VNODE_REMOVE_NODELETEBUSY  0x0001  

/* VNOP_READDIR flags: */
#define VNODE_READDIR_EXTENDED    0x0001   /* use extended directory entries */
#define VNODE_READDIR_REQSEEKOFF  0x0002   /* requires seek offset (cookies) */
#define VNODE_READDIR_SEEKOFF32   0x0004   /* seek offset values should fit in 32 bits */


#define	NULLVP	((struct vnode *)NULL)

/*
 * Macro/function to check for client cache inconsistency w.r.t. leasing.
 */
#define	LEASE_READ	0x1		/* Check lease for readers */
#define	LEASE_WRITE	0x2		/* Check lease for modifiers */


#ifndef BSD_KERNEL_PRIVATE
struct vnodeop_desc;
#endif

extern	int desiredvnodes;		/* number of vnodes desired */


/*
 * This structure is used to configure the new vnodeops vector.
 */
struct vnodeopv_entry_desc {
	struct vnodeop_desc *opve_op;   /* which operation this is */
	int (*opve_impl)(void *);		/* code implementing this operation */
};
struct vnodeopv_desc {
			/* ptr to the ptr to the vector where op should go */
	int (***opv_desc_vector_p)(void *);
	struct vnodeopv_entry_desc *opv_desc_ops;   /* null terminated list */
};

/*
 * A default routine which just returns an error.
 */
int vn_default_error(void);

/*
 * A generic structure.
 * This can be used by bypass routines to identify generic arguments.
 */
struct vnop_generic_args {
	struct vnodeop_desc *a_desc;
	/* other random data follows, presumably */
};

#ifndef _KAUTH_ACTION_T
typedef int kauth_action_t;
# define _KAUTH_ACTION_T
#endif

#include <sys/vnode_if.h>

__BEGIN_DECLS

errno_t	vnode_create(int, size_t, void  *, vnode_t *);
int	vnode_addfsref(vnode_t);
int	vnode_removefsref(vnode_t);

int	vnode_hasdirtyblks(vnode_t);
int	vnode_hascleanblks(vnode_t);
#define	VNODE_ASYNC_THROTTLE	18
/* timeout is in 10 msecs and not hz tick based */
int	vnode_waitforwrites(vnode_t, int, int, int, char *);
void	vnode_startwrite(vnode_t);
void	vnode_writedone(vnode_t);

enum vtype	vnode_vtype(vnode_t);
uint32_t	vnode_vid(vnode_t);
mount_t	vnode_mountedhere(vnode_t vp);
mount_t	vnode_mount(vnode_t);
dev_t	vnode_specrdev(vnode_t);
void *	vnode_fsnode(vnode_t);
void	vnode_clearfsnode(vnode_t);

int	vnode_isvroot(vnode_t);
int	vnode_issystem(vnode_t);
int	vnode_ismount(vnode_t);
int	vnode_isreg(vnode_t);
int	vnode_isdir(vnode_t);
int	vnode_islnk(vnode_t);
int	vnode_isfifo(vnode_t);
int	vnode_isblk(vnode_t);
int	vnode_ischr(vnode_t);

int	vnode_ismountedon(vnode_t);
void	vnode_setmountedon(vnode_t);
void	vnode_clearmountedon(vnode_t);

int	vnode_isnocache(vnode_t);
void	vnode_setnocache(vnode_t);
void	vnode_clearnocache(vnode_t);
int	vnode_isnoreadahead(vnode_t);
void	vnode_setnoreadahead(vnode_t);
void	vnode_clearnoreadahead(vnode_t);
/* left only for compat reasons as User code depends on this from getattrlist, for ex */
void	vnode_settag(vnode_t, int);
int	vnode_tag(vnode_t);
int	vnode_getattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx);
int	vnode_setattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx);

#ifdef BSD_KERNEL_PRIVATE

/*
 * Indicate that a file has multiple hard links.  VFS will always call
 * VNOP_LOOKUP on this vnode.  Volfs will always ask for it's parent
 * object ID (instead of using the v_parent pointer).
 */
void	vnode_set_hard_link(vnode_t vp);

vnode_t vnode_parent(vnode_t);
void vnode_setparent(vnode_t, vnode_t);
char * vnode_name(vnode_t);
void vnode_setname(vnode_t, char *);
int vnode_isnoflush(vnode_t);
void vnode_setnoflush(vnode_t);
void vnode_clearnoflush(vnode_t);
#endif

uint32_t  vnode_vfsmaxsymlen(vnode_t);
int	vnode_vfsisrdonly(vnode_t);
int	vnode_vfstypenum(vnode_t);
void	vnode_vfsname(vnode_t, char *);
int 	vnode_vfs64bitready(vnode_t);

proc_t	vfs_context_proc(vfs_context_t);
ucred_t	vfs_context_ucred(vfs_context_t);
int	vfs_context_issuser(vfs_context_t);
int	vfs_context_pid(vfs_context_t);
int	vfs_context_issignal(vfs_context_t, sigset_t);
int	vfs_context_suser(vfs_context_t);
int	vfs_context_is64bit(vfs_context_t);
vfs_context_t vfs_context_create(vfs_context_t);
int vfs_context_rele(vfs_context_t);


int	vflush(struct mount *mp, struct vnode *skipvp, int flags);
int 	vnode_get(vnode_t);
int 	vnode_getwithvid(vnode_t, int);
int 	vnode_put(vnode_t);
int 	vnode_ref(vnode_t);
void 	vnode_rele(vnode_t);
int 	vnode_isinuse(vnode_t, int);
void 	vnode_lock(vnode_t);
void 	vnode_unlock(vnode_t);
int		vnode_recycle(vnode_t);
void	vnode_reclaim(vnode_t);

#define	VNODE_UPDATE_PARENT	0x01
#define	VNODE_UPDATE_NAME	0x02
#define	VNODE_UPDATE_CACHE	0x04
void	vnode_update_identity(vnode_t vp, vnode_t dvp, char *name, int name_len, int name_hashval, int flags);

int	vn_bwrite(struct vnop_bwrite_args *ap);

int	vnode_authorize(vnode_t /*vp*/, vnode_t /*dvp*/, kauth_action_t, vfs_context_t);
int	vnode_authattr(vnode_t, struct vnode_attr *, kauth_action_t *, vfs_context_t);
int	vnode_authattr_new(vnode_t /*dvp*/, struct vnode_attr *, int /*noauth*/, vfs_context_t);
errno_t vnode_close(vnode_t, int, vfs_context_t);

int vn_getpath(struct vnode *vp, char *pathbuf, int *len);

/*
 * Flags for the vnode_lookup and vnode_open
 */
#define VNODE_LOOKUP_NOFOLLOW		0x01
#define	VNODE_LOOKUP_NOCROSSMOUNT	0x02
#define VNODE_LOOKUP_DOWHITEOUT		0x04

errno_t vnode_lookup(const char *, int, vnode_t *, vfs_context_t);
errno_t vnode_open(const char *, int, int, int, vnode_t *, vfs_context_t);

/*
 * exported vnode operations
 */

int	vnode_iterate(struct mount *, int, int (*)(struct vnode *, void *), void *);
/*
 * flags passed into vnode_iterate
 */
#define VNODE_RELOAD			0x01
#define VNODE_WAIT				0x02
#define VNODE_WRITEABLE 		0x04
#define VNODE_WITHID			0x08
#define VNODE_NOLOCK_INTERNAL	0x10
#define VNODE_NODEAD			0x20
#define VNODE_NOSUSPEND			0x40
#define VNODE_ITERATE_ALL 		0x80
#define VNODE_ITERATE_ACTIVE 	0x100
#define VNODE_ITERATE_INACTIVE	0x200

/*
 * return values from callback
 */
#define VNODE_RETURNED		0	/* done with vnode, reference can be dropped */
#define VNODE_RETURNED_DONE	1	/* done with vnode, reference can be dropped, terminate iteration */
#define VNODE_CLAIMED		2	/* don't drop reference */
#define VNODE_CLAIMED_DONE	3	/* don't drop reference, terminate iteration */


struct stat;
int	vn_stat(struct vnode *vp, struct stat *sb, kauth_filesec_t *xsec, vfs_context_t ctx);
int	vn_stat_noauth(struct vnode *vp, struct stat *sb, kauth_filesec_t *xsec, vfs_context_t ctx);
int	vn_revoke(vnode_t vp, int flags, vfs_context_t);
/* XXX BOGUS */
int	vaccess(mode_t file_mode, uid_t uid, gid_t gid,
	  		mode_t acc_mode, struct ucred *cred);


/* namecache function prototypes */
int	cache_lookup(vnode_t dvp, vnode_t *vpp,	struct componentname *cnp);
void	cache_enter(vnode_t dvp, vnode_t vp, struct componentname *cnp);
void	cache_purge(vnode_t vp);
void	cache_purge_negatives(vnode_t vp);

/*
 * Global string-cache routines.  You can pass zero for nc_hash
 * if you don't know it (add_name() will then compute the hash).
 * There are no flags for now but maybe someday.
 */
char *vfs_addname(const char *name, size_t len, u_int nc_hash, u_int flags);
int   vfs_removename(const char *name);

__END_DECLS

#endif /* KERNEL */

#endif /* !_VNODE_H_ */
