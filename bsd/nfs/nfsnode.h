/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/lock.h>


/*
 * Silly rename structure that hangs off the nfsnode until the name
 * can be removed by nfs_inactive()
 */
struct sillyrename {
	struct	ucred *s_cred;
	struct	vnode *s_dvp;
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
	long			nb_bufsize;	/* buffer size */
	daddr_t			nb_lblkno;	/* logical block number. */
	int			nb_error;	/* errno value. */
	u_int32_t		nb_valid;	/* valid pages in buf */
	u_int32_t		nb_dirty;	/* dirty pages in buf */
	int			nb_validoff;	/* offset in buffer of valid region. */
	int			nb_validend;	/* offset of end of valid region. */
	int			nb_dirtyoff;	/* offset in buffer of dirty region. */
	int			nb_dirtyend;	/* offset of end of dirty region. */
	caddr_t			nb_data;	/* mapped buffer */
	struct vnode *		nb_vp;		/* device vnode */
	struct proc *		nb_proc;	/* associated proc; NULL if kernel. */
	struct ucred *		nb_rcred;	/* read credentials reference */
	struct ucred *		nb_wcred;	/* write credentials reference */
	void *			nb_pagelist;	/* upl */
};

/*
 * These flags are kept in nb_flags and they're (purposefully)
 * very similar to the B_* flags for struct buf.
 */
#define	NB_NEEDCOMMIT	0x00000002	/* Append-write in progress. */
#define	NB_ASYNC	0x00000004	/* Start I/O, do not wait. */
#define	NB_BUSY		0x00000010	/* I/O in progress. */
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
#define	NB_WANTED	0x00800000	/* Process wants this buffer. */
#define	NB_WRITE	0x00000000	/* Write buffer (pseudo flag). */
#define	NB_WRITEINPROG	0x01000000	/* Write in progress. */
#define	NB_META		0x40000000	/* buffer contains meta-data. */
#define	NB_IOD		0x80000000	/* buffer being handled by nfsiod. */


#define NBOFF(BP)			((off_t)(BP)->nb_lblkno * (off_t)(BP)->nb_bufsize)
#define NBPGVALID(BP,P)			(((BP)->nb_valid >> (P)) & 0x1)
#define NBPGDIRTY(BP,P)			(((BP)->nb_dirty >> (P)) & 0x1)
#define NBPGVALID_SET(BP,P)		((BP)->nb_valid |= (1 << (P)))
#define NBPGDIRTY_SET(BP,P)		((BP)->nb_dirty |= (1 << (P)))

#define NFS_BUF_MAP(BP) \
	do { \
		if (!(BP)->nb_data && nfs_buf_map(BP)) \
			panic("nfs_buf_map failed"); \
	} while (0)

LIST_HEAD(nfsbuflists, nfsbuf);
TAILQ_HEAD(nfsbuffreehead, nfsbuf);

#define NFSNOLIST ((struct nfsbuf *)0xdeadbeef)

extern int nfsbufhashlock, nfsbufcnt, nfsbufmin, nfsbufmax;
extern int nfsbuffreecnt, nfsbufdelwricnt, nfsneedbuffer;
extern int nfs_nbdwrite;
extern struct nfsbuffreehead nfsbuffree, nfsbufdelwri;

#define NFSBUFCNTCHK() \
	do { \
	if (	(nfsbufcnt < 0) || \
		(nfsbufcnt > nfsbufmax) || \
		(nfsbuffreecnt < 0) || \
		(nfsbuffreecnt > nfsbufmax) || \
		(nfsbuffreecnt > nfsbufcnt) || \
		(nfsbufdelwricnt < 0) || \
		(nfsbufdelwricnt > nfsbufmax) || \
		(nfsbufdelwricnt > nfsbufcnt) || \
		(nfs_nbdwrite < 0) || \
		(nfs_nbdwrite > nfsbufcnt) || \
		0) \
		panic("nfsbuf count error: max %d cnt %d free %d delwr %d bdw %d\n", \
			nfsbufmax, nfsbufcnt, nfsbuffreecnt, \
			nfsbufdelwricnt, nfs_nbdwrite); \
	} while (0)

/*
 * The nfsnode is the nfs equivalent to ufs's inode. Any similarity
 * is purely coincidental.
 * There is a unique nfsnode allocated for each active file,
 * each current directory, each mounted-on file, text file, and the root.
 * An nfsnode is 'named' by its file handle. (nget/nfs_node.c)
 * If this structure exceeds 256 bytes (it is currently 256 using 4.4BSD-Lite
 * type definitions), file handles of > 32 bytes should probably be split out
 * into a separate MALLOC()'d data structure. (Reduce the size of nfsfh_t by
 * changing the definition in sys/mount.h of NFS_SMALLFH.)
 * NB: Hopefully the current order of the fields is such that everything will
 *     be well aligned and, therefore, tightly packed.
 */
struct nfsnode {
	struct lock__bsd__	n_lock;	/* the vnode lock */
	LIST_ENTRY(nfsnode)	n_hash;		/* Hash chain */
	CIRCLEQ_ENTRY(nfsnode)	n_timer;	/* Nqnfs timer chain */
	u_quad_t		n_size;		/* Current size of file */
	u_quad_t		n_brev;		/* Modify rev when cached */
	u_quad_t		n_lrev;		/* Modify rev for lease */
	struct vattr		n_vattr;	/* Vnode attribute cache */
	time_t			n_attrstamp;	/* Attr. cache timestamp */
        u_int32_t               n_mode;         /* ACCESS mode cache */
        uid_t                   n_modeuid;      /* credentials having mode */
        time_t                  n_modestamp;    /* mode cache timestamp */
	time_t			n_mtime;	/* Prev modify time. */
	time_t			n_ctime;	/* Prev create time. */
	time_t			n_expiry;	/* Lease expiry time */
	nfsfh_t			*n_fhp;		/* NFS File Handle */
	union {
		struct vnode	*n_vp;		/* associated vnode */
		struct mount	*n_mp;		/* associated mount (NINIT) */
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
	nfsfh_t			n_fh;		/* Small File Handle */
	u_int64_t		n_xid;		/* last xid to loadattr */
	struct nfsbuflists	n_cleanblkhd;	/* clean blocklist head */
	struct nfsbuflists	n_dirtyblkhd;	/* dirty blocklist head */
	int			n_needcommitcnt;/* # bufs that need committing */
};

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
#define	NQNFSNONCACHE	0x0020	/* Non-cachable lease */
#define	NQNFSWRITE	0x0040	/* Write lease */
#define	NQNFSEVICTED	0x0080	/* Has been evicted */
#define	NACC		0x0100	/* Special file accessed */
#define	NUPD		0x0200	/* Special file updated */
#define	NCHG		0x0400	/* Special file times changed */
#define NHASHED		0x1000  /* someone wants to lock */
#define NINIT		0x2000  /* node is being initialized */
#define NWINIT		0x4000  /* someone waiting for init to complete */

/*
 * Convert between nfsnode pointers and vnode pointers
 */
#define VTONFS(vp)	((struct nfsnode *)(vp)->v_data)
#define NFSTOV(np)	((struct vnode *)(np)->n_vnode)

/*
 * Queue head for nfsiod's
 */
extern TAILQ_HEAD(nfs_bufq, buf) nfs_bufq;
extern struct proc *nfs_iodwant[NFS_MAXASYNCDAEMON];
extern struct nfsmount *nfs_iodmount[NFS_MAXASYNCDAEMON];

#if defined(KERNEL)

typedef int     vop_t __P((void *));
extern	vop_t	**fifo_nfsv2nodeop_p;
extern	vop_t	**nfsv2_vnodeop_p;
extern	vop_t	**spec_nfsv2nodeop_p;

/*
 * Prototypes for NFS vnode operations
 */
int	nfs_write __P((struct vop_write_args *));
#define	nfs_lease_check ((int (*) __P((struct  vop_lease_args *)))nullop)
#define nqnfs_vop_lease_check	lease_check
int	nqnfs_vop_lease_check __P((struct vop_lease_args *));
#define nfs_revoke vop_revoke
#define nfs_seek ((int (*) __P((struct  vop_seek_args *)))nullop)
int	nfs_inactive __P((struct vop_inactive_args *));
int	nfs_reclaim __P((struct vop_reclaim_args *));
int nfs_lock __P((struct vop_lock_args *));
int nfs_unlock __P((struct vop_unlock_args *));
int nfs_islocked __P((struct vop_islocked_args *));

#define nfs_reallocblks \
	((int (*) __P((struct  vop_reallocblks_args *)))eopnotsupp)

/* other stuff */
int	nfs_removeit __P((struct sillyrename *));
int	nfs_nget __P((struct mount *,nfsfh_t *,int,struct nfsnode **));
nfsuint64 *nfs_getcookie __P((struct nfsnode *, off_t, int));
void nfs_invaldir __P((struct vnode *));

#define nqnfs_lease_updatetime	lease_updatetime

/* nfsbuf functions */
void nfs_nbinit(void);
void nfs_buf_remfree(struct nfsbuf *);
struct nfsbuf * nfs_buf_incore(struct vnode *, daddr_t);
struct nfsbuf * nfs_buf_get(struct vnode *, daddr_t, int, struct proc *, int);
int nfs_buf_upl_setup(struct nfsbuf *bp);
void nfs_buf_upl_check(struct nfsbuf *bp);
void nfs_buf_release(struct nfsbuf *);
int nfs_buf_iowait(struct nfsbuf *);
void nfs_buf_iodone(struct nfsbuf *);
void nfs_buf_write_delayed(struct nfsbuf *);

#endif /* KERNEL */

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSNODE_H_ */
