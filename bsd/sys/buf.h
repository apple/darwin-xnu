/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)buf.h	8.9 (Berkeley) 3/30/95
 */

#ifndef _SYS_BUF_H_
#define	_SYS_BUF_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#include <sys/queue.h>
#include <sys/errno.h>
#include <sys/vm.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_PRIVATE

#define NOLIST ((struct buf *)0x87654321)

/*
 * The buffer header describes an I/O operation in the kernel.
 */
struct buf {
	LIST_ENTRY(buf) b_hash;		/* Hash chain. */
	LIST_ENTRY(buf) b_vnbufs;	/* Buffer's associated vnode. */
	TAILQ_ENTRY(buf) b_freelist;	/* Free list position if not active. */
	struct  proc *b_proc;		/* Associated proc; NULL if kernel. */
	volatile long	b_flags;	/* B_* flags. */
	int	b_error;		/* Errno value. */
	long	b_bufsize;		/* Allocated buffer size. */
	long	b_bcount;		/* Valid bytes in buffer. */
	long	b_resid;		/* Remaining I/O. */
	dev_t	b_dev;			/* Device associated with buffer. */
	struct {
		caddr_t	b_addr;		/* Memory, superblocks, indirect etc.*/
	} b_un;
	void	*b_saveaddr;		/* Original b_addr for physio. */
	daddr_t	b_lblkno;		/* Logical block number. */
	daddr_t	b_blkno;		/* Underlying physical block number. */
					/* Function to call upon completion. */
	void	(*b_iodone) __P((struct buf *));
	struct	vnode *b_vp;		/* Device vnode. */
	int	b_dirtyoff;		/* Offset in buffer of dirty region. */
	int	b_dirtyend;		/* Offset of end of dirty region. */
	int	b_validoff;		/* Offset in buffer of valid region. */
	int	b_validend;		/* Offset of end of valid region. */
	struct	ucred *b_rcred;		/* Read credentials reference. */
	struct	ucred *b_wcred;		/* Write credentials reference. */
	int	b_timestamp;		/* timestamp for queuing operation */
	long	b_vectorcount;	/* number of vectors in b_vectorlist */
	void	*b_vectorlist;	/* vector list for I/O */
	void	*b_pagelist;	/* to save pagelist info */
	long	b_vects[2];		/* vectorlist when b_vectorcount is 1 */
	long	b_whichq;		/* the free list the buffer belongs to */
	TAILQ_ENTRY(buf)	b_act;	/* Device driver queue when active */
	void	*b_drvdata;		/* Device driver private use */
};

/*
 * For portability with historic industry practice, the cylinder number has
 * to be maintained in the `b_resid' field.
 */
#define	b_cylinder b_resid		/* Cylinder number for disksort(). */

/* Device driver compatibility definitions. */
#define	b_active b_bcount		/* Driver queue head: drive active. */
#define	b_data	 b_un.b_addr		/* b_un.b_addr is not changeable. */
#define	b_errcnt b_resid		/* Retry count while I/O in progress. */
#define	iodone	 biodone		/* Old name for biodone. */
#define	iowait	 biowait		/* Old name for biowait. */

/* cluster_io definitions for use with io bufs */
#define b_uploffset  b_bufsize
#define b_trans_head b_freelist.tqe_prev
#define b_trans_next b_freelist.tqe_next
#define b_real_bp    b_saveaddr
#define b_iostate    b_rcred

/* journaling uses this cluster i/o field for its own
 * purposes because meta data buf's should never go
 * through the clustering code.
 */
#define b_transaction b_vectorlist

   

/*
 * These flags are kept in b_flags.
 */
#define	B_AGE		0x00000001	/* Move to age queue when I/O done. */
#define	B_NEEDCOMMIT	0x00000002	/* Append-write in progress. */
#define	B_ASYNC		0x00000004	/* Start I/O, do not wait. */
#define	B_BAD		0x00000008	/* Bad block revectoring in progress. */
#define	B_BUSY		0x00000010	/* I/O in progress. */
#define	B_CACHE		0x00000020	/* Bread found us in the cache. */
#define	B_CALL		0x00000040	/* Call b_iodone from biodone. */
#define	B_DELWRI	0x00000080	/* Delay I/O until buffer reused. */
#define	B_DIRTY		0x00000100	/* Dirty page to be pushed out async. */
#define	B_DONE		0x00000200	/* I/O completed. */
#define	B_EINTR		0x00000400	/* I/O was interrupted */
#define	B_ERROR		0x00000800	/* I/O error occurred. */
#define	B_WASDIRTY	0x00001000	/* page was found dirty in the VM cache */
#define	B_INVAL		0x00002000	/* Does not contain valid info. */
#define	B_LOCKED	0x00004000	/* Locked in core (not reusable). */
#define	B_NOCACHE	0x00008000	/* Do not cache block after use. */
#define	B_PAGEOUT	0x00010000	/* Page out indicator... */
#define	B_PGIN		0x00020000	/* Pagein op, so swap() can count it. */
#define	B_PHYS		0x00040000	/* I/O to user memory. */
#define	B_RAW		0x00080000	/* Set by physio for raw transfers. */
#define	B_READ		0x00100000	/* Read buffer. */
#define	B_TAPE		0x00200000	/* Magnetic tape I/O. */
#define	B_PAGELIST	0x00400000	/* Buffer describes pagelist I/O. */
#define	B_WANTED	0x00800000	/* Process wants this buffer. */
#define	B_WRITE		0x00000000	/* Write buffer (pseudo flag). */
#define	B_WRITEINPROG	0x01000000	/* Write in progress. */
#define	B_HDRALLOC	0x02000000	/* zone allocated buffer header */
#define	B_NORELSE	0x04000000	/* don't brelse() in bwrite() */
#define B_NEED_IODONE   0x08000000
								/* need to do a biodone on the */
								/* real_bp associated with a cluster_io */
#define B_COMMIT_UPL    0x10000000
								/* commit pages in upl when */
								/* I/O completes/fails */
#define	B_ZALLOC	0x20000000	/* b_data is zalloc()ed */
#define	B_META		0x40000000	/* buffer contains meta-data. */
#define	B_VECTORLIST	0x80000000	/* Used by device drivers. */


/*
 * Zero out the buffer's data area.
 */
#define	clrbuf(bp) {							\
	bzero((bp)->b_data, (u_int)(bp)->b_bcount);			\
	(bp)->b_resid = 0;						\
}

/* Flags to low-level allocation routines. */
#define B_CLRBUF	0x01	/* Request allocated buffer be cleared. */
#define B_SYNC		0x02	/* Do all allocations synchronously. */
#define B_NOBUFF	0x04	/* Do not allocate struct buf */

/* Flags for operation type in getblk() */
#define	BLK_READ	0x01	/* buffer for read */
#define	BLK_WRITE	0x02	/* buffer for write */
#define	BLK_PAGEIN	0x04	/* buffer for pagein */
#define	BLK_PAGEOUT	0x08	/* buffer for pageout */
#define	BLK_META	0x10	/* buffer for metadata */
#define	BLK_CLREAD	0x20	/* buffer for cluster read */
#define	BLK_CLWRITE	0x40	/* buffer for cluster write */

extern int nbuf;			/* The number of buffer headers */
extern struct buf *buf;		/* The buffer headers. */

#endif /* __APPLE_API_PRIVATE */


#ifdef __APPLE_API_UNSTABLE
/* Macros to clear/set/test flags. */
#define	SET(t, f)	(t) |= (f)
#define	CLR(t, f)	(t) &= ~(f)
#define	ISSET(t, f)	((t) & (f))
#endif /* __APPLE_API_UNSTABLE */

#ifdef __APPLE_API_PRIVATE
/*
 * Definitions for the buffer free lists.
 */
#define	BQUEUES		6		/* number of free buffer queues */

#define	BQ_LOCKED	0		/* super-blocks &c */
#define	BQ_LRU		1		/* lru, useful buffers */
#define	BQ_AGE		2		/* rubbish */
#define	BQ_EMPTY	3		/* buffer headers with no memory */
#define BQ_META		4		/* buffer containing metadata */
#define BQ_LAUNDRY	5		/* buffers that need cleaning */
#endif /* __APPLE_API_PRIVATE */

__BEGIN_DECLS
#ifdef __APPLE_API_UNSTABLE
int	allocbuf __P((struct buf *, int));
void	bawrite __P((struct buf *));
void	bdwrite __P((struct buf *));
void	biodone __P((struct buf *));
int	biowait __P((struct buf *));
int	bread __P((struct vnode *, daddr_t, int,
	    struct ucred *, struct buf **));
int	meta_bread __P((struct vnode *, daddr_t, int,
	    struct ucred *, struct buf **));
int	breada __P((struct vnode *, daddr_t, int, daddr_t, int,
	    struct ucred *, struct buf **));
int	breadn __P((struct vnode *, daddr_t, int, daddr_t *, int *, int,
	    struct ucred *, struct buf **));
void	brelse __P((struct buf *));
void	bremfree __P((struct buf *));
void	bufinit __P((void));
void	bwillwrite __P((void));
int	bwrite __P((struct buf *));
struct buf *getblk __P((struct vnode *, daddr_t, int, int, int, int));
struct buf *geteblk __P((int));
struct buf *incore __P((struct vnode *, daddr_t));
u_int	minphys __P((struct buf *bp));
int physio __P((void (*)(struct buf *), struct buf *, dev_t, int ,  u_int (*)(struct buf *), struct uio *, int ));
int count_busy_buffers __P((void));
struct buf *alloc_io_buf __P((struct vnode *, int));
void free_io_buf __P((struct buf *));
void reassignbuf __P((struct buf *, struct vnode *));
#endif /* __APPLE_API_UNSTABLE */
__END_DECLS

#ifdef __APPLE_API_PRIVATE
/*
 *	Stats on usefulness of the buffer cache
 */
struct bufstats {
	long	bufs_incore;		/* found incore */
	long	bufs_busyincore;	/* found incore. was busy */
	long	bufs_vmhits;		/* not incore. found in VM */
	long	bufs_miss;			/* not incore. not in VM */
	long	bufs_sleeps;		/* buffer starvation */
	long	bufs_eblk;			/* Calls to geteblk */
	long	bufs_iobufmax;		/* Max. number of IO buffers used */
	long	bufs_iobufinuse;	/* number of IO buffers in use */
	long	bufs_iobufsleeps;	/* IO buffer starvation */
};
#endif /* __APPLE_API_PRIVATE */

#endif /* KERNEL */
#endif /* !_SYS_BUF_H_ */
