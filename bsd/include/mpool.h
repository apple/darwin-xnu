/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)mpool.h	8.1 (Berkeley) 6/2/93
 */

/*
 * The memory pool scheme is a simple one.  Each in memory page is referenced
 * by a bucket which is threaded in three ways.  All active pages are threaded
 * on a hash chain (hashed by the page number) and an lru chain.  Inactive
 * pages are threaded on a free chain.  Each reference to a memory pool is
 * handed an MPOOL which is the opaque cookie passed to all of the memory
 * routines.
 */
#define	HASHSIZE	128
#define	HASHKEY(pgno)	((pgno - 1) % HASHSIZE)

/* The BKT structures are the elements of the lists. */
typedef struct BKT {
	struct BKT	*hnext;		/* next hash bucket */
	struct BKT	*hprev;		/* previous hash bucket */
	struct BKT	*cnext;		/* next free/lru bucket */
	struct BKT	*cprev;		/* previous free/lru bucket */
	void		*page;		/* page */
	pgno_t		pgno;		/* page number */

#define	MPOOL_DIRTY	0x01		/* page needs to be written */
#define	MPOOL_PINNED	0x02		/* page is pinned into memory */
	unsigned long	flags;		/* flags */
} BKT;

/* The BKTHDR structures are the heads of the lists. */
typedef struct BKTHDR {
	struct BKT	*hnext;		/* next hash bucket */
	struct BKT	*hprev;		/* previous hash bucket */
	struct BKT	*cnext;		/* next free/lru bucket */
	struct BKT	*cprev;		/* previous free/lru bucket */
} BKTHDR;

typedef struct MPOOL {
	BKTHDR	free;			/* The free list. */
	BKTHDR	lru;			/* The LRU list. */
	BKTHDR	hashtable[HASHSIZE];	/* Hashed list by page number. */
	pgno_t	curcache;		/* Current number of cached pages. */
	pgno_t	maxcache;		/* Max number of cached pages. */
	pgno_t	npages;			/* Number of pages in the file. */
	u_long	pagesize;		/* File page size. */
	int	fd;			/* File descriptor. */
					/* Page in conversion routine. */
	void    (*pgin) __P((void *, pgno_t, void *));
					/* Page out conversion routine. */
	void    (*pgout) __P((void *, pgno_t, void *));
	void	*pgcookie;		/* Cookie for page in/out routines. */
#ifdef STATISTICS
	unsigned long	cachehit;
	unsigned long	cachemiss;
	unsigned long	pagealloc;
	unsigned long	pageflush;
	unsigned long	pageget;
	unsigned long	pagenew;
	unsigned long	pageput;
	unsigned long	pageread;
	unsigned long	pagewrite;
#endif
} MPOOL;

#ifdef __MPOOLINTERFACE_PRIVATE
/* Macros to insert/delete into/from hash chain. */
#define rmhash(bp) { \
        (bp)->hprev->hnext = (bp)->hnext; \
        (bp)->hnext->hprev = (bp)->hprev; \
}
#define inshash(bp, pg) { \
	hp = &mp->hashtable[HASHKEY(pg)]; \
        (bp)->hnext = hp->hnext; \
        (bp)->hprev = (struct BKT *)hp; \
        hp->hnext->hprev = (bp); \
        hp->hnext = (bp); \
}

/* Macros to insert/delete into/from lru and free chains. */
#define	rmchain(bp) { \
        (bp)->cprev->cnext = (bp)->cnext; \
        (bp)->cnext->cprev = (bp)->cprev; \
}
#define inschain(bp, dp) { \
        (bp)->cnext = (dp)->cnext; \
        (bp)->cprev = (struct BKT *)(dp); \
        (dp)->cnext->cprev = (bp); \
        (dp)->cnext = (bp); \
}
#endif

__BEGIN_DECLS
MPOOL	*mpool_open __P((DBT *, int, pgno_t, pgno_t));
void	 mpool_filter __P((MPOOL *, void (*)(void *, pgno_t, void *),
	    void (*)(void *, pgno_t, void *), void *));
void	*mpool_new __P((MPOOL *, pgno_t *));
void	*mpool_get __P((MPOOL *, pgno_t, u_int));
int	 mpool_put __P((MPOOL *, void *, u_int));
int	 mpool_sync __P((MPOOL *));
int	 mpool_close __P((MPOOL *));
#ifdef STATISTICS
void	 mpool_stat __P((MPOOL *));
#endif
__END_DECLS
