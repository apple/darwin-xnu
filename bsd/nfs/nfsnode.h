/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfsnode.h	8.9 (Berkeley) 5/14/95
 * FreeBSD-Id: nfsnode.h,v 1.24 1997/10/28 14:06:25 bde Exp $
 */


#ifndef _NFS_NFSNODE_H_
#define _NFS_NFSNODE_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#ifndef _NFS_NFS_H_
#include <nfs/nfs.h>
#endif

/*
 * Silly rename structure that hangs off the nfsnode until the name
 * can be removed by nfs_inactive()
 */
struct sillyrename {
	struct	ucred *s_cred;
	vnode_t	s_dvp;
	long	s_namlen;
	char	s_name[20];
};

/*
 * This structure is used to save the logical directory offset to
 * NFS cookie mappings.
 * The mappings are stored in a list headed
 * by n_cookies, as required.
 * There is one mapping for each NFS_DIRBLKSIZ bytes of directory information
 * stored in increasing logical offset byte order.
 */
#define NFSNUMCOOKIES		31

struct nfsdmap {
	LIST_ENTRY(nfsdmap)	ndm_list;
	int			ndm_eocookie;
	nfsuint64		ndm_cookies[NFSNUMCOOKIES];
};

/*
 * The nfsbuf is the nfs equivalent to a struct buf.
 */
struct nfsbuf {
	LIST_ENTRY(nfsbuf)	nb_hash;	/* hash chain */
	LIST_ENTRY(nfsbuf)	nb_vnbufs;	/* vnode's nfsbuf chain */
	TAILQ_ENTRY(nfsbuf)	nb_free;	/* free list position if not active. */
	volatile long		nb_flags;	/* NB_* flags. */
	volatile long		nb_lflags;	/* NBL_* flags. */
	volatile long		nb_refs;	/* outstanding references. */
	long			nb_bufsize;	/* buffer size */
	daddr64_t		nb_lblkno;	/* logical block number. */
	uint64_t		nb_verf;	/* V3 write verifier */
	time_t			nb_timestamp;	/* buffer timestamp */
	int			nb_error;	/* errno value. */
	u_int32_t		nb_valid;	/* valid pages in buf */
	u_int32_t		nb_dirty;	/* dirty pages in buf */
	int			nb_validoff;	/* offset in buffer of valid region. */
	int			nb_validend;	/* offset of end of valid region. */
	int			nb_dirtyoff;	/* offset in buffer of dirty region. */
	int			nb_dirtyend;	/* offset of end of dirty region. */
	caddr_t			nb_data;	/* mapped buffer */
	vnode_t			nb_vp;		/* device vnode */
	proc_t			nb_proc;	/* associated proc; NULL if kernel. */
	struct ucred *		nb_rcred;	/* read credentials reference */
	struct ucred *		nb_wcred;	/* write credentials reference */
	void *			nb_pagelist;	/* upl */
};

/*
 * These flags are kept in b_lflags... 
 * nfs_buf_mutex must be held before examining/updating
 */
#define	NBL_BUSY	0x00000001	/* I/O in progress. */
#define	NBL_WANTED	0x00000002	/* Process wants this buffer. */

/*
 * These flags are kept in nb_flags and they're (purposefully)
 * very similar to the B_* flags for struct buf.
 * nfs_buf_mutex is not needed to examine/update these.
 */
#define	NB_NEEDCOMMIT	0x00000002	/* Append-write in progress. */
#define	NB_ASYNC	0x00000004	/* Start I/O, do not wait. */
#define	NB_CACHE	0x00000020	/* Bread found us in the cache. */
#define	NB_STABLE	0x00000040	/* write FILESYNC not UNSTABLE. */
#define	NB_DELWRI	0x00000080	/* Delay I/O until buffer reused. */
#define	NB_DONE		0x00000200	/* I/O completed. */
#define	NB_EINTR	0x00000400	/* I/O was interrupted */
#define	NB_ERROR	0x00000800	/* I/O error occurred. */
#define	NB_WASDIRTY	0x00001000	/* page was found dirty in the VM cache */
#define	NB_INVAL	0x00002000	/* Does not contain valid info. */
#define	NB_NOCACHE	0x00008000	/* Do not cache block after use. */
#define	NB_READ		0x00100000	/* Read buffer. */
#define	NB_PAGELIST	0x00400000	/* Buffer describes pagelist I/O. */
#define	NB_WRITE	0x00000000	/* Write buffer (pseudo flag). */
#define	NB_WRITEINPROG	0x01000000	/* Write in progress. */
#define	NB_META		0x40000000	/* buffer contains meta-data. */
#define	NB_IOD		0x80000000	/* buffer being handled by nfsiod. */

/* Flags for operation type in nfs_buf_get() */
#define	NBLK_READ	0x00000001	/* buffer for read */
#define	NBLK_WRITE	0x00000002	/* buffer for write */
#define	NBLK_META	0x00000004	/* buffer for metadata */
#define	NBLK_OPMASK	0x00000007	/* operation mask */
/* modifiers for above flags... */
#define NBLK_NOWAIT	0x40000000	/* don't wait on busy buffer */
#define NBLK_ONLYVALID	0x80000000	/* only return cached buffer */

/* These flags are used for nfsbuf iterating */
#define NBI_ITER		0x01	/* iteration in progress */
#define NBI_ITERWANT		0x02	/* waiting to iterate */
#define NBI_CLEAN		0x04	/* requesting clean buffers */
#define NBI_DIRTY		0x08	/* requesting dirty buffers */
#define NBI_NOWAIT		0x10	/* don't block on NBI_ITER */

/* Flags for nfs_buf_acquire */
#define NBAC_NOWAIT		0x01	/* Don't wait if buffer is busy */
#define NBAC_REMOVE		0x02	/* Remove from free list once buffer is acquired */

/* some convenience macros...  */
#define NBOFF(BP)			((off_t)(BP)->nb_lblkno * (off_t)(BP)->nb_bufsize)
#define NBPGVALID(BP,P)			(((BP)->nb_valid >> (P)) & 0x1)
#define NBPGDIRTY(BP,P)			(((BP)->nb_dirty >> (P)) & 0x1)
#define NBPGVALID_SET(BP,P)		((BP)->nb_valid |= (1 << (P)))
#define NBPGDIRTY_SET(BP,P)		((BP)->nb_dirty |= (1 << (P)))

#define NBUFSTAMPVALID(BP)		((BP)->nb_timestamp != ~0)
#define NBUFSTAMPINVALIDATE(BP)		((BP)->nb_timestamp = ~0)

#define NFS_BUF_MAP(BP) \
	do { \
		if (!(BP)->nb_data && nfs_buf_map(BP)) \
			panic("nfs_buf_map failed"); \
	} while (0)

LIST_HEAD(nfsbuflists, nfsbuf);
TAILQ_HEAD(nfsbuffreehead, nfsbuf);

#define NFSNOLIST ((struct nfsbuf *)0xdeadbeef)

extern lck_mtx_t *nfs_buf_mutex;
extern int nfsbufcnt, nfsbufmin, nfsbufmax, nfsbufmetacnt, nfsbufmetamax;
extern int nfsbuffreecnt, nfsbuffreemetacnt, nfsbufdelwricnt, nfsneedbuffer;
extern int nfs_nbdwrite;
extern struct nfsbuffreehead nfsbuffree, nfsbufdelwri;
extern time_t nfsbuffreeuptimestamp;

#define NFSBUFCNTCHK(locked) \
	do { \
	if (!locked) lck_mtx_lock(nfs_buf_mutex); \
	if (	(nfsbufcnt < 0) || \
		(nfsbufcnt > nfsbufmax) || \
		(nfsbufmetacnt < 0) || \
		(nfsbufmetacnt > nfsbufmetamax) || \
		(nfsbufmetacnt > nfsbufcnt) || \
		(nfsbuffreecnt < 0) || \
		(nfsbuffreecnt > nfsbufmax) || \
		(nfsbuffreecnt > nfsbufcnt) || \
		(nfsbuffreemetacnt < 0) || \
		(nfsbuffreemetacnt > nfsbufmax) || \
		(nfsbuffreemetacnt > nfsbufcnt) || \
		(nfsbuffreemetacnt > nfsbufmetamax) || \
		(nfsbuffreemetacnt > nfsbufmetacnt) || \
		(nfsbufdelwricnt < 0) || \
		(nfsbufdelwricnt > nfsbufmax) || \
		(nfsbufdelwricnt > nfsbufcnt) || \
		(nfs_nbdwrite < 0) || \
		(nfs_nbdwrite > nfsbufcnt) || \
		0) \
		panic("nfsbuf count error: max %d meta %d cnt %d meta %d free %d meta %d delwr %d bdw %d\n", \
			nfsbufmax, nfsbufmetamax, nfsbufcnt, nfsbufmetacnt, nfsbuffreecnt, nfsbuffreemetacnt, \
			nfsbufdelwricnt, nfs_nbdwrite); \
	if (!locked) lck_mtx_unlock(nfs_buf_mutex); \
	} while (0)

struct nfs_vattr {
	enum vtype	nva_type;	/* vnode type (for create) */
	u_short		nva_mode;	/* files access mode and type */ 
	dev_t		nva_rdev;	/* device the special file represents */
	uid_t		nva_uid;	/* owner user id */
	gid_t		nva_gid;	/* owner group id */
	uint32_t	nva_fsid;	/* file system id (dev for now) */
	uint64_t	nva_nlink;	/* number of references to file */ 
	uint64_t	nva_fileid;	/* file id */
	uint64_t	nva_size;	/* file size in bytes */
	uint64_t	nva_bytes;	/* bytes of disk space held by file */
	uint32_t	nva_blocksize;	/* blocksize preferred for i/o */
	struct timespec	nva_atime;	/* time of last access */
	struct timespec	nva_mtime;	/* time of last modification */
	struct timespec	nva_ctime;	/* time file changed */
};

/*
 * The nfsnode is the nfs equivalent to ufs's inode. Any similarity
 * is purely coincidental.
 * There is a unique nfsnode allocated for each active file,
 * each current directory, each mounted-on file, text file, and the root.
 * An nfsnode is 'named' by its file handle. (nget/nfs_node.c)
 * If this structure exceeds 256 bytes (it is currently 256 using 4.4BSD-Lite
 * type definitions), file handles of > 32 bytes should probably be split out
 * into a separate MALLOC()'d data structure. (Reduce the size of nfsnode.n_fh
 * by changing the definition in nfsproto.h of NFS_SMALLFH.)
 * NB: Hopefully the current order of the fields is such that everything will
 *     be well aligned and, therefore, tightly packed.
 */
struct nfsnode {
	LIST_ENTRY(nfsnode)	n_hash;		/* Hash chain */
	u_quad_t		n_size;		/* Current size of file */
	struct nfs_vattr	n_vattr;	/* Vnode attribute cache */
	time_t			n_attrstamp;	/* Attr. cache timestamp */
        u_int32_t               n_mode;         /* ACCESS mode cache */
        uid_t                   n_modeuid;      /* credentials having mode */
        time_t                  n_modestamp;    /* mode cache timestamp */
	struct timespec		n_mtime;	/* Prev modify time. */
	struct timespec		n_ncmtime;	/* namecache modify time. */
	u_char			*n_fhp;		/* NFS File Handle */
	union {
		vnode_t		n_vp;		/* associated vnode */
		mount_t		n_mp;		/* associated mount (NINIT) */
	} n_un0;
	struct lockf		*n_lockf;	/* Locking record of file */
	int			n_error;	/* Save write error value */
	union {
		struct timespec	nf_atim;	/* Special file times */
		nfsuint64	nd_cookieverf;	/* Cookie verifier (dir only) */
	} n_un1;
	union {
		struct timespec	nf_mtim;
		off_t		nd_direof;	/* Dir. EOF offset cache */
	} n_un2;
	union {
		struct sillyrename *nf_silly;	/* Ptr to silly rename struct */
		LIST_HEAD(, nfsdmap) nd_cook;	/* cookies */
	} n_un3;
	short			n_fhsize;	/* size in bytes, of fh */
	short			n_flag;		/* Flag for locking.. */
	u_char			n_fh[NFS_SMALLFH];/* Small File Handle */
	u_int64_t		n_xid;		/* last xid to loadattr */
	struct nfsbuflists	n_cleanblkhd;	/* clean blocklist head */
	struct nfsbuflists	n_dirtyblkhd;	/* dirty blocklist head */
	int			n_needcommitcnt;/* # bufs that need committing */
	int			n_bufiterflags;	/* buf iterator flags */
};

#define nfstimespeccmp(tvp, uvp, cmp)		\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?	\
	 ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :	\
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#define CHECK_NEEDCOMMITCNT(np) \
	do { \
		if ((np)->n_needcommitcnt < 0) { \
			printf("nfs: n_needcommitcnt negative\n"); \
			(np)->n_needcommitcnt = 0; \
		} \
	} while (0)

#define n_vnode		n_un0.n_vp
#define n_mount		n_un0.n_mp
#define n_atim		n_un1.nf_atim
#define n_mtim		n_un2.nf_mtim
#define n_sillyrename	n_un3.nf_silly
#define n_cookieverf	n_un1.nd_cookieverf
#define n_direofoffset	n_un2.nd_direof
#define n_cookies	n_un3.nd_cook

/*
 * Flags for n_flag
 */
#define	NFLUSHWANT	0x0001	/* Want wakeup from a flush in prog. */
#define	NFLUSHINPROG	0x0002	/* Avoid multiple calls to vinvalbuf() */
#define	NMODIFIED	0x0004	/* Might have a modified buffer in bio */
#define	NWRITEERR	0x0008	/* Flag write errors so close will know */
#define	NNEEDINVALIDATE	0x0010	/* need to call vinvalbuf() */
#define	NNOCACHE	0x0020	/* all bufs are uncached */
#define	NWRBUSY		0x0040	/* node in write/fsync */
#define	NACC		0x0100	/* Special file accessed */
#define	NUPD		0x0200	/* Special file updated */
#define	NCHG		0x0400	/* Special file times changed */
#define NHASHED		0x1000  /* someone wants to lock */
#define NINIT		0x2000  /* node is being initialized */
#define NWINIT		0x4000  /* someone waiting for init to complete */

#define NATTRVALID(np)		((np)->n_attrstamp != ~0)
#define NATTRINVALIDATE(np)	((np)->n_attrstamp = ~0)
#define NMODEVALID(np)		((np)->n_modestamp != ~0)
#define NMODEINVALIDATE(np)	((np)->n_modestamp = ~0)

#define NVALIDBUFS(np)	(!LIST_EMPTY(&(np)->n_dirtyblkhd) || \
 			 !LIST_EMPTY(&(np)->n_cleanblkhd))

/*
 * NFS-specific flags for nfs_vinvalbuf/nfs_flush
 */
#define V_IGNORE_WRITEERR	0x8000

/*
 * Flags for nfs_nget()
 */
#define	NG_MARKROOT	0x0001	/* mark vnode as root of FS */
#define	NG_MAKEENTRY	0x0002	/* add name cache entry for vnode */

/*
 * Convert between nfsnode pointers and vnode pointers
 */
#define VTONFS(vp)	((struct nfsnode *)vnode_fsnode(vp))
#define NFSTOV(np)	((np)->n_vnode)

/* nfsnode hash table mutex */
extern lck_mtx_t *nfs_node_hash_mutex;

/*
 * nfsiod structures
 */
extern proc_t nfs_iodwant[NFS_MAXASYNCDAEMON];
extern struct nfsmount *nfs_iodmount[NFS_MAXASYNCDAEMON];
extern lck_grp_t *nfs_iod_lck_grp;
extern lck_grp_attr_t *nfs_iod_lck_grp_attr;
extern lck_attr_t *nfs_iod_lck_attr;
extern lck_mtx_t *nfs_iod_mutex;

#if defined(KERNEL)

typedef int     vnop_t(void *);
extern	vnop_t	**fifo_nfsv2nodeop_p;
extern	vnop_t	**nfsv2_vnodeop_p;
extern	vnop_t	**spec_nfsv2nodeop_p;

/*
 * Prototypes for NFS vnode operations
 */
int	nfs_write(struct vnop_write_args *);
#define nfs_revoke nop_revoke
#define nfs_seek ((int (*)(struct  vnop_seek_args *))nullop) //XXXdead?
int	nfs_inactive(struct vnop_inactive_args *);
int	nfs_reclaim(struct vnop_reclaim_args *);


/* other stuff */
int	nfs_removeit(struct sillyrename *);
int	nfs_nget(mount_t,vnode_t,struct componentname *,u_char *,int,struct nfs_vattr *,u_int64_t *,int,struct nfsnode **);
nfsuint64 *nfs_getcookie(struct nfsnode *, off_t, int);
void nfs_invaldir(vnode_t);

/* nfsbuf functions */
void nfs_nbinit(void);
void nfs_buf_remfree(struct nfsbuf *);
boolean_t nfs_buf_is_incore(vnode_t, daddr64_t);
struct nfsbuf * nfs_buf_incore(vnode_t, daddr64_t);
int nfs_buf_get(vnode_t, daddr64_t, int, proc_t, int, struct nfsbuf **);
int nfs_buf_upl_setup(struct nfsbuf *bp);
void nfs_buf_upl_check(struct nfsbuf *bp);
void nfs_buf_release(struct nfsbuf *, int);
int nfs_buf_iowait(struct nfsbuf *);
void nfs_buf_iodone(struct nfsbuf *);
void nfs_buf_write_delayed(struct nfsbuf *, proc_t);
void nfs_buf_check_write_verifier(struct nfsnode *, struct nfsbuf *);
void nfs_buf_freeup(int);
void nfs_buf_refget(struct nfsbuf *bp);
void nfs_buf_refrele(struct nfsbuf *bp);
void nfs_buf_drop(struct nfsbuf *);
errno_t nfs_buf_acquire(struct nfsbuf *, int, int, int);
int nfs_buf_iterprepare(struct nfsnode *, struct nfsbuflists *, int);
void nfs_buf_itercomplete(struct nfsnode *, struct nfsbuflists *, int);

#endif /* KERNEL */

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSNODE_H_ */
