/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/queue.h>
#include <sys/lock.h>

#include <sys/time.h>
#include <sys/uio.h>

#include <sys/vm.h>
#ifdef KERNEL
#include <sys/systm.h>
#include <vm/vm_pageout.h>
#endif /* KERNEL */

#ifdef __APPLE_API_PRIVATE
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
 * Each underlying filesystem allocates its own private area and hangs
 * it from v_data.  If non-null, this area is freed in getnewvnode().
 */
LIST_HEAD(buflists, buf);

#define MAX_CLUSTERS 4	/* maximum number of vfs clusters per vnode */

struct v_cluster {
	unsigned int	start_pg;
	unsigned int	last_pg;
};

struct v_padded_clusters {
	long	v_pad;
	struct v_cluster	v_c[MAX_CLUSTERS];
};

/*
 * Reading or writing any of these items requires holding the appropriate lock.
 * v_freelist is locked by the global vnode_free_list simple lock.
 * v_mntvnodes is locked by the global mntvnodes simple lock.
 * v_flag, v_usecount, v_holdcount and v_writecount are
 * locked by the v_interlock simple lock.
 */
struct vnode {
	u_long	v_flag;				/* vnode flags (see below) */
	long	v_usecount;			/* reference count of users */
	long	v_holdcnt;			/* page & buffer references */
	daddr_t	v_lastr;			/* last read (read-ahead) */
	u_long	v_id;				/* capability identifier */
	struct	mount *v_mount;			/* ptr to vfs we are in */
	int 	(**v_op)(void *);		/* vnode operations vector */
	TAILQ_ENTRY(vnode) v_freelist;		/* vnode freelist */
	LIST_ENTRY(vnode) v_mntvnodes;		/* vnodes for mount point */
	struct	buflists v_cleanblkhd;		/* clean blocklist head */
	struct	buflists v_dirtyblkhd;		/* dirty blocklist head */
	long	v_numoutput;			/* num of writes in progress */
	enum	vtype v_type;			/* vnode type */
	union {
		struct mount	*vu_mountedhere;/* ptr to mounted vfs (VDIR) */
		struct socket	*vu_socket;	/* unix ipc (VSOCK) */
		struct specinfo	*vu_specinfo;	/* device (VCHR, VBLK) */
		struct fifoinfo	*vu_fifoinfo;	/* fifo (VFIFO) */
	} v_un;
	struct ubc_info *v_ubcinfo;	/* valid for (VREG) */
	struct	nqlease *v_lease;		/* Soft reference to lease */
	daddr_t	v_lastw;			/* last write (write cluster) */
	daddr_t	v_cstart;			/* start block of cluster */
	daddr_t	v_ciosiz;			/* real size of I/O for cluster */
	int	v_clen;				/* length of current cluster */
	int	v_ralen;			/* Read-ahead length */
	daddr_t	v_maxra;			/* last readahead block */
	union {
		simple_lock_data_t v_ilk;	/* lock on usecount and flag */
		struct v_padded_clusters v_cl;	/* vfs cluster IO */
	} v_un1;
#define	v_clusters v_un1.v_cl.v_c
#define	v_interlock v_un1.v_ilk

	struct	lock__bsd__ *v_vnlock;		/* used for non-locking fs's */
	long	v_writecount;			/* reference count of writers */
	enum	vtagtype v_tag;			/* type of underlying data */
	void 	*v_data;			/* private data for fs */
};
#define	v_mountedhere	v_un.vu_mountedhere
#define	v_socket	v_un.vu_socket
#define	v_specinfo	v_un.vu_specinfo
#define	v_fifoinfo	v_un.vu_fifoinfo

/*
 * Vnode flags.
 */
#define	VROOT		0x000001	/* root of its file system */
#define	VTEXT		0x000002	/* vnode is a pure text prototype */
#define	VSYSTEM		0x000004	/* vnode being used by kernel */
#define	VISTTY		0x000008	/* vnode represents a tty */
#define	VWASMAPPED	0x000010	/* vnode was mapped before */
#define	VTERMINATE	0x000020	/* terminating memory object */
#define	VTERMWANT	0x000040	/* wating for memory object death */
#define	VMOUNT		0x000080	/* mount operation in progress */
#define	VXLOCK		0x000100	/* vnode is locked to change underlying type */
#define	VXWANT		0x000200	/* process is waiting for vnode */
#define	VBWAIT		0x000400	/* waiting for output to complete */
#define	VALIASED	0x000800	/* vnode has an alias */
#define	VORECLAIM	0x001000	/* vm object is being reclaimed */
#define	VNOCACHE_DATA	0x002000	/* don't keep data cached once it's been consumed */
#define	VSTANDARD	0x004000	/* vnode obtained from common pool */
#define	VAGE		0x008000	/* Insert vnode at head of free list */
#define	VRAOFF		0x010000	/* read ahead disabled */
#define	VUINIT		0x020000	/* ubc_info being initialized */
#define	VUWANT		0x040000	/* process is wating for VUINIT */
#define	VUINACTIVE	0x080000	/* UBC vnode is on inactive list */
#define	VHASDIRTY	0x100000	/* UBC vnode may have 1 or more */
		/* delayed dirty pages that need to be flushed at the next 'sync' */
#define	VSWAP		0x200000	/* vnode is being used as swapfile */
#define	VTHROTTLED	0x400000	/* writes or pageouts have been throttled */
		/* wakeup tasks waiting when count falls below threshold */
#define	VNOFLUSH	0x800000	/* don't vflush() if SKIPSYSTEM */


/*
 * Vnode attributes.  A field value of VNOVAL represents a field whose value
 * is unavailable (getattr) or which is not to be changed (setattr).
 */
struct vattr {
	enum vtype	va_type;	/* vnode type (for create) */
	u_short		va_mode;	/* files access mode and type */
	short		va_nlink;	/* number of references to file */
	uid_t		va_uid;		/* owner user id */
	gid_t		va_gid;		/* owner group id */
	long		va_fsid;	/* file system id (dev for now) */
	long		va_fileid;	/* file id */
	u_quad_t	va_size;	/* file size in bytes */
	long		va_blocksize;	/* blocksize preferred for i/o */
	struct timespec	va_atime;	/* time of last access */
	struct timespec	va_mtime;	/* time of last modification */
	struct timespec	va_ctime;	/* time file changed */
	u_long		va_gen;		/* generation number of file */
	u_long		va_flags;	/* flags defined for file */
	dev_t		va_rdev;	/* device the special file represents */
	u_quad_t	va_bytes;	/* bytes of disk space held by file */
	u_quad_t	va_filerev;	/* file modification number */
	u_int		va_vaflags;	/* operations flags, see below */
	long		va_spare;	/* remain quad aligned */
};

/*
 * Flags for va_vaflags.
 */
#define	VA_UTIMES_NULL	0x01		/* utimes argument was NULL */
#define VA_EXCLUSIVE	0x02		/* exclusive create request */

/*
 * Flags for ioflag.
 */
#define	IO_UNIT		0x01		/* do I/O as atomic unit */
#define	IO_APPEND	0x02		/* append write to end */
#define	IO_SYNC		0x04		/* do I/O synchronously */
#define	IO_NODELOCKED	0x08		/* underlying node already locked */
#define	IO_NDELAY	0x10		/* FNDELAY flag set in file table */
#define	IO_NOZEROFILL	0x20		/* F_SETSIZE fcntl uses to prevent zero filling */
#define	IO_TAILZEROFILL	0x40		/* zero fills at the tail of write */
#define	IO_HEADZEROFILL	0x80		/* zero fills at the head of write */
#define	IO_NOZEROVALID	0x100		/* do not zero fill if valid page */
#define	IO_NOZERODIRTY	0x200		/* do not zero fill if page is dirty */

/*
 *  Modes.  Some values same as Ixxx entries from inode.h for now.
 */
#define	VSUID	04000		/* set user id on execution */
#define	VSGID	02000		/* set group id on execution */
#define	VSVTX	01000		/* save swapped text even after use */
#define	VREAD	00400		/* read, write, execute permissions */
#define	VWRITE	00200
#define	VEXEC	00100

/*
 * Token indicating no attribute value yet assigned.
 */
#define	VNOVAL	(-1)

#ifdef KERNEL
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

#define	DOCLOSE		0x0008		/* vclean: close active files */

#define	V_SAVE		0x0001		/* vinvalbuf: sync file first */
#define	V_SAVEMETA	0x0002		/* vinvalbuf: leave indirect blocks */

#define	REVOKEALL	0x0001		/* vop_revoke: revoke all aliases */

/* flags for vop_allocate */
#define	PREALLOCATE		0x00000001	/* preallocate allocation blocks */
#define	ALLOCATECONTIG	0x00000002	/* allocate contigious space */
#define	ALLOCATEALL		0x00000004	/* allocate all requested space */
									/* or no space at all */
#define	FREEREMAINDER	0x00000008	/* deallocate allocated but */
									/* unfilled blocks */
#define	ALLOCATEFROMPEOF	0x00000010	/* allocate from the physical eof */
#define	ALLOCATEFROMVOL		0x00000020	/* allocate from the volume offset */

#if DIAGNOSTIC
#define	VATTR_NULL(vap)	vattr_null(vap)
#define	HOLDRELE(vp)	holdrele(vp)
#define	VHOLD(vp)	vhold(vp)

void	holdrele __P((struct vnode *));
void	vattr_null __P((struct vattr *));
void	vhold __P((struct vnode *));
#else
#define	VATTR_NULL(vap)	(*(vap) = va_null)	/* initialize a vattr */
#define	HOLDRELE(vp)	holdrele(vp)		/* decrease buf or page ref */
extern __inline void holdrele(struct vnode *vp)
{
	simple_lock(&vp->v_interlock);
	vp->v_holdcnt--;
	simple_unlock(&vp->v_interlock);
}
#define	VHOLD(vp)	vhold(vp)		/* increase buf or page ref */
extern __inline void vhold(struct vnode *vp)
{
	simple_lock(&vp->v_interlock);
	if (++vp->v_holdcnt <= 0)
		panic("vhold: v_holdcnt");
	simple_unlock(&vp->v_interlock);
}
#endif /* DIAGNOSTIC */

#define	VREF(vp)	vref(vp)
void	vref __P((struct vnode *));
#define	NULLVP	((struct vnode *)NULL)

/*
 * Global vnode data.
 */
extern	struct vnode *rootvnode;	/* root (i.e. "/") vnode */
extern	int desiredvnodes;		/* number of vnodes desired */
extern	struct vattr va_null;		/* predefined null vattr structure */

/*
 * Macro/function to check for client cache inconsistency w.r.t. leasing.
 */
#define	LEASE_READ	0x1		/* Check lease for readers */
#define	LEASE_WRITE	0x2		/* Check lease for modifiers */
#endif /* KERNEL */

/*
 * Mods for exensibility.
 */

/*
 * Flags for vdesc_flags:
 */
#define VDESC_MAX_VPS		16
/* Low order 16 flag bits are reserved for willrele flags for vp arguments. */
#define VDESC_VP0_WILLRELE	0x0001
#define VDESC_VP1_WILLRELE	0x0002
#define VDESC_VP2_WILLRELE	0x0004
#define VDESC_VP3_WILLRELE	0x0008
#define VDESC_NOMAP_VPP		0x0100
#define VDESC_VPP_WILLRELE	0x0200

/*
 * VDESC_NO_OFFSET is used to identify the end of the offset list
 * and in places where no such field exists.
 */
#define VDESC_NO_OFFSET -1

/*
 * This structure describes the vnode operation taking place.
 */
struct vnodeop_desc {
	int	vdesc_offset;		/* offset in vector--first for speed */
	char    *vdesc_name;		/* a readable name for debugging */
	int	vdesc_flags;		/* VDESC_* flags */

	/*
	 * These ops are used by bypass routines to map and locate arguments.
	 * Creds and procs are not needed in bypass routines, but sometimes
	 * they are useful to (for example) transport layers.
	 * Nameidata is useful because it has a cred in it.
	 */
	int	*vdesc_vp_offsets;	/* list ended by VDESC_NO_OFFSET */
	int	vdesc_vpp_offset;	/* return vpp location */
	int	vdesc_cred_offset;	/* cred location, if any */
	int	vdesc_proc_offset;	/* proc location, if any */
	int	vdesc_componentname_offset; /* if any */
	/*
	 * Finally, we've got a list of private data (about each operation)
	 * for each transport layer.  (Support to manage this list is not
	 * yet part of BSD.)
	 */
	caddr_t	*vdesc_transports;
};

#endif /* __APPLE_API_PRIVATE */

#ifdef KERNEL

#ifdef __APPLE_API_PRIVATE
/*
 * A list of all the operation descs.
 */
extern struct vnodeop_desc *vnodeop_descs[];

/*
 * Interlock for scanning list of vnodes attached to a mountpoint
 */
extern struct slock mntvnode_slock;

/*
 * This macro is very helpful in defining those offsets in the vdesc struct.
 *
 * This is stolen from X11R4.  I ingored all the fancy stuff for
 * Crays, so if you decide to port this to such a serious machine,
 * you might want to consult Intrisics.h's XtOffset{,Of,To}.
 */
#define VOPARG_OFFSET(p_type,field) \
        ((int) (((char *) (&(((p_type)NULL)->field))) - ((char *) NULL)))
#define VOPARG_OFFSETOF(s_type,field) \
	VOPARG_OFFSET(s_type*,field)
#define VOPARG_OFFSETTO(S_TYPE,S_OFFSET,STRUCT_P) \
	((S_TYPE)(((char*)(STRUCT_P))+(S_OFFSET)))


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
int vn_default_error __P((void));

/*
 * A generic structure.
 * This can be used by bypass routines to identify generic arguments.
 */
struct vop_generic_args {
	struct vnodeop_desc *a_desc;
	/* other random data follows, presumably */
};

/*
 * VOCALL calls an op given an ops vector.  We break it out because BSD's
 * vclean changes the ops vector and then wants to call ops with the old
 * vector.
 */
#define VOCALL(OPSV,OFF,AP) (( *((OPSV)[(OFF)])) (AP))

/*
 * This call works for vnodes in the kernel.
 */
#define VCALL(VP,OFF,AP) VOCALL((VP)->v_op,(OFF),(AP))
#define VDESC(OP) (& __CONCAT(OP,_desc))
#define VOFFSET(OP) (VDESC(OP)->vdesc_offset)

#endif /* __APPLE_API_PRIVATE */

/*
 * Finally, include the default set of vnode operations.
 */
#include <sys/vnode_if.h>

/*
 * vnode manipulation functions.
 */
struct file;
struct mount;
struct nameidata;
struct ostat;
struct proc;
struct stat;
struct ucred;
struct uio;
struct vattr;
struct vnode;
struct vop_bwrite_args;

#ifdef __APPLE_API_EVOLVING
int 	bdevvp __P((dev_t dev, struct vnode **vpp));
void	cvtstat __P((struct stat *st, struct ostat *ost));
int 	getnewvnode __P((enum vtagtype tag,
	    struct mount *mp, int (**vops)(void *), struct vnode **vpp));
void	insmntque __P((struct vnode *vp, struct mount *mp));
void 	vattr_null __P((struct vattr *vap));
int 	vcount __P((struct vnode *vp));
int	vflush __P((struct mount *mp, struct vnode *skipvp, int flags));
int 	vget __P((struct vnode *vp, int lockflag, struct proc *p));
void 	vgone __P((struct vnode *vp));
int	vinvalbuf __P((struct vnode *vp, int save, struct ucred *cred,
	    struct proc *p, int slpflag, int slptimeo));
void	vprint __P((char *label, struct vnode *vp));
int	vrecycle __P((struct vnode *vp, struct slock *inter_lkp,
	    struct proc *p));
int	vn_bwrite __P((struct vop_bwrite_args *ap));
int 	vn_close __P((struct vnode *vp,
	    int flags, struct ucred *cred, struct proc *p));
int	vn_lock __P((struct vnode *vp, int flags, struct proc *p));
int 	vn_open __P((struct nameidata *ndp, int fmode, int cmode));
int 	vn_rdwr __P((enum uio_rw rw, struct vnode *vp, caddr_t base,
	    int len, off_t offset, enum uio_seg segflg, int ioflg,
	    struct ucred *cred, int *aresid, struct proc *p));
int	vn_stat __P((struct vnode *vp, struct stat *sb, struct proc *p));
int	vop_noislocked __P((struct vop_islocked_args *));
int	vop_nolock __P((struct vop_lock_args *));
int	vop_nounlock __P((struct vop_unlock_args *));
int	vop_revoke __P((struct vop_revoke_args *));
struct vnode *
	checkalias __P((struct vnode *vp, dev_t nvp_rdev, struct mount *mp));
void 	vput __P((struct vnode *vp));
void 	vrele __P((struct vnode *vp));
int	vaccess __P((mode_t file_mode, uid_t uid, gid_t gid,
	    mode_t acc_mode, struct ucred *cred));
int	getvnode __P((struct proc *p, int fd, struct file **fpp));
#endif __APPLE_API_EVOLVING

#endif /* KERNEL */

#endif /* !_VNODE_H_ */
