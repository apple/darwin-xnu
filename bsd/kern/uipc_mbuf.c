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
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
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
 *	@(#)uipc_mbuf.c	8.2 (Berkeley) 1/4/94
 */
/* HISTORY
 *
 *	10/15/97 Annette DeSchon (deschon@apple.com)
 *		Fixed bug in which all cluster mbufs were broken up 
 *		into regular mbufs: Some clusters are now reserved.
 *		When a cluster is needed, regular mbufs are no longer
 *		used.  (Radar 1683621)
 *	20-May-95 Mac Gillon (mgillon) at NeXT
 *		New version based on 4.4
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/domain.h>

#include <kern/queue.h>
#include <kern/kern_types.h>
#include <kern/sched_prim.h>

#include <IOKit/IOMapper.h>

extern vm_offset_t kmem_mb_alloc(vm_map_t  , int );
extern boolean_t PE_parse_boot_arg(const char *, void *);

#define _MCLREF(p)       (++mclrefcnt[mtocl(p)])
#define _MCLUNREF(p)     (--mclrefcnt[mtocl(p)] == 0)
#define _M_CLEAR_PKTHDR(mbuf_ptr)	(mbuf_ptr)->m_pkthdr.rcvif = NULL; \
									(mbuf_ptr)->m_pkthdr.len = 0; \
									(mbuf_ptr)->m_pkthdr.header = NULL; \
									(mbuf_ptr)->m_pkthdr.csum_flags = 0; \
									(mbuf_ptr)->m_pkthdr.csum_data = 0; \
									(mbuf_ptr)->m_pkthdr.aux = (struct mbuf*)NULL; \
									(mbuf_ptr)->m_pkthdr.vlan_tag = 0; \
									(mbuf_ptr)->m_pkthdr.socket_id = 0; \
									SLIST_INIT(&(mbuf_ptr)->m_pkthdr.tags);

/* kernel translater */
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

lck_mtx_t			* mbuf_mlock;
lck_grp_t			* mbuf_mlock_grp;
lck_grp_attr_t	* mbuf_mlock_grp_attr;
lck_attr_t 		* mbuf_mlock_attr;
extern lck_mtx_t 	*domain_proto_mtx;

struct mbuf 	*mfree;		/* mbuf free list */
struct	mbuf *mfreelater;	/* mbuf deallocation list */
extern vm_map_t mb_map;		/* special map */
int		m_want;		/* sleepers on mbufs */
short		*mclrefcnt; 	/* mapped cluster reference counts */
int             *mcl_paddr;
static ppnum_t mcl_paddr_base;	/* Handle returned by IOMapper::iovmAlloc() */
union mcluster 	*mclfree;	/* mapped cluster free list */
union mbigcluster 	*mbigfree;	/* mapped cluster free list */
int		max_linkhdr;	/* largest link-level header */
int		max_protohdr;	/* largest protocol header */
int		max_hdr;	/* largest link+protocol header */
int		max_datalen;	/* MHLEN - max_hdr */
struct mbstat 	mbstat;		/* statistics */
union mcluster 	*mbutl;		/* first mapped cluster address */
union mcluster  *embutl;	/* ending virtual address of mclusters */

static int 	nclpp;		/* # clusters per physical page */

static int m_howmany(int, size_t );
void m_reclaim(void);
static int m_clalloc(const int , const int, const size_t, int);
int do_reclaim = 0;

#define MF_NOWAIT	0x1
#define MF_BIG		0x2

/* The number of cluster mbufs that are allocated, to start. */
#define MINCL	max(16, 2)

static int mbuf_expand_thread_wakeup = 0;
static int mbuf_expand_mcl = 0;
static int mbuf_expand_big = 0;
static int mbuf_expand_thread_initialized = 0;

static void mbuf_expand_thread_init(void);
static void mbuf_expand_thread(void);
static int m_expand(int );
static caddr_t m_bigalloc(int );
static void m_bigfree(caddr_t ,  u_int ,  caddr_t );
static struct mbuf * m_mbigget(struct mbuf *, int );
void mbinit(void);
static void m_range_check(void *addr);


#if 0
static int mfree_munge = 0;
#if 0
#define _MFREE_MUNGE(m) {                                               \
    if (mfree_munge)                                                    \
        {   int i;                                                      \
            vm_offset_t *element = (vm_offset_t *)(m);                  \
            for (i = 0;                                                 \
                 i < sizeof(struct mbuf)/sizeof(vm_offset_t);           \
                 i++)                                                   \
                    (element)[i] = 0xdeadbeef;                          \
        }                                                               \
}
#else
void
munge_mbuf(struct mbuf *m)
{
    int i;
    vm_offset_t *element = (vm_offset_t *)(m);
    for (i = 0;
            i < sizeof(struct mbuf)/sizeof(vm_offset_t);
            i++)
            (element)[i] = 0xdeadbeef;
}
#define _MFREE_MUNGE(m) {  \
    if (mfree_munge)       \
        munge_mbuf(m);     \
}
#endif
#else
#define _MFREE_MUNGE(m)
#endif


#define _MINTGET(m, type) { 						\
	MBUF_LOCK();							\
	if (((m) = mfree) != 0) {					\
		MCHECK(m);                                              \
		++mclrefcnt[mtocl(m)]; 					\
		mbstat.m_mtypes[MT_FREE]--;				\
		mbstat.m_mtypes[(type)]++;				\
		mfree = (m)->m_next;					\
	}								\
	MBUF_UNLOCK();							\
}
	

static void
m_range_check(void *addr)
{
	if (addr && (addr < (void *)mbutl || addr >= (void *)embutl))
		panic("mbuf address out of range 0x%x", addr);
}

__private_extern__ void
mbinit(void)
{
	int m;
	int initmcl = 32;
	int mcl_pages;

	if (nclpp)
		return;
	nclpp = round_page_32(MCLBYTES) / MCLBYTES;	/* see mbufgc() */
	if (nclpp < 1) nclpp = 1;
	mbuf_mlock_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(mbuf_mlock_grp_attr);

	mbuf_mlock_grp = lck_grp_alloc_init("mbuf", mbuf_mlock_grp_attr);
	mbuf_mlock_attr = lck_attr_alloc_init();
	lck_attr_setdefault(mbuf_mlock_attr);

	mbuf_mlock = lck_mtx_alloc_init(mbuf_mlock_grp, mbuf_mlock_attr);

	mbstat.m_msize = MSIZE;
	mbstat.m_mclbytes = MCLBYTES;
	mbstat.m_minclsize = MINCLSIZE;
	mbstat.m_mlen = MLEN;
	mbstat.m_mhlen = MHLEN;
	mbstat.m_bigmclbytes = NBPG;

	if (nmbclusters == 0)
		nmbclusters = NMBCLUSTERS;
	MALLOC(mclrefcnt, short *, nmbclusters * sizeof (short),
					M_TEMP, M_WAITOK);
	if (mclrefcnt == 0)
		panic("mbinit");
	for (m = 0; m < nmbclusters; m++)
		mclrefcnt[m] = -1;

	/* Calculate the number of pages assigned to the cluster pool */
	mcl_pages = nmbclusters/(NBPG/CLBYTES);
	MALLOC(mcl_paddr, int *, mcl_pages * sizeof(int), M_TEMP, M_WAITOK);
	if (mcl_paddr == 0)
		panic("mbinit1");
	/* Register with the I/O Bus mapper */
	mcl_paddr_base = IOMapperIOVMAlloc(mcl_pages);
	bzero((char *)mcl_paddr, mcl_pages * sizeof(int));

	embutl = (union mcluster *)((unsigned char *)mbutl + (nmbclusters * MCLBYTES));

	PE_parse_boot_arg("initmcl", &initmcl);
	
	if (m_clalloc(max(NBPG/CLBYTES, 1) * initmcl, M_WAIT, MCLBYTES, 0) == 0)
		goto bad;
	MBUF_UNLOCK();

    (void) kernel_thread(kernel_task, mbuf_expand_thread_init);

	return;
bad:
		panic("mbinit");
}

/*
 * Allocate some number of mbuf clusters
 * and place on cluster free list.
 * Take the mbuf lock (if not already locked) and do not release it
 */
/* ARGSUSED */
static int
m_clalloc(
	const int num,
	const int nowait,
	const size_t bufsize,
	int locked)
{
	int i;
	vm_size_t size = 0;
	int numpages = 0;
	vm_offset_t page = 0;

	if (locked == 0)
		MBUF_LOCK();
	/*
	 * Honor the caller's wish to block or not block.
	 * We have a way to grow the pool asynchronously,
	 * by kicking the dlil_input_thread.
	 */
	i = m_howmany(num, bufsize);
	if (i == 0 || nowait == M_DONTWAIT)
		goto out;

	MBUF_UNLOCK();	
	size = round_page_32(i * bufsize);
	page = kmem_mb_alloc(mb_map, size);

	if (page == 0) {
		size = NBPG; /* Try for 1 if failed */
		page = kmem_mb_alloc(mb_map, size);
	}
	MBUF_LOCK();

	if (page) {
		numpages = size / NBPG;
		for (i = 0; i < numpages; i++, page += NBPG) {
			if (((int)page & PGOFSET) == 0) {
				ppnum_t offset = ((char *)page - (char *)mbutl)/NBPG;
				ppnum_t new_page = pmap_find_phys(kernel_pmap, (vm_address_t) page);
				
				/*
				 * In the case of no mapper being available
				 * the following code nops and returns the
				 * input page, if there is a mapper the I/O
				 * page appropriate is returned.
				 */
				new_page = IOMapperInsertPage(mcl_paddr_base, offset, new_page);
				mcl_paddr[offset] = new_page << 12;
			}
			if (bufsize == MCLBYTES) {
				union mcluster *mcl = (union mcluster *)page;

				if (++mclrefcnt[mtocl(mcl)] != 0)
					panic("m_clalloc already there");
				mcl->mcl_next = mclfree;
				mclfree = mcl++;
				if (++mclrefcnt[mtocl(mcl)] != 0)
					panic("m_clalloc already there");
				mcl->mcl_next = mclfree;
				mclfree = mcl++;
			} else {
				union mbigcluster *mbc = (union mbigcluster *)page;

				if (++mclrefcnt[mtocl(mbc)] != 0)
					panic("m_clalloc already there");
				if (++mclrefcnt[mtocl(mbc) + 1] != 0)
					panic("m_clalloc already there");

				mbc->mbc_next = mbigfree;
				mbigfree = mbc;
			}
		}
		if (bufsize == MCLBYTES) {
			int numcl = numpages << 1;
			mbstat.m_clfree += numcl;
			mbstat.m_clusters += numcl;
			return (numcl);
		} else {
			mbstat.m_bigclfree += numpages;
			mbstat.m_bigclusters += numpages;
			return (numpages);
		}
	} /* else ... */
out:
	/* 
	 * When non-blocking we kick a thread if we havve to grow the 
	 * pool or if the number of free clusters is less than requested.
	 */
	if (bufsize == MCLBYTES) {
		if (i > 0) {
			/* Remember total number of clusters needed at this time */
			i += mbstat.m_clusters;
			if (i > mbuf_expand_mcl) {
				mbuf_expand_mcl = i;
				if (mbuf_expand_thread_initialized)
					wakeup((caddr_t)&mbuf_expand_thread_wakeup);
			}
		}
	
		if (mbstat.m_clfree >= num) 
			 return 1;
	} else {
		if (i > 0) {
			/* Remember total number of 4KB clusters needed at this time */
			i += mbstat.m_bigclusters;
			if (i > mbuf_expand_big) {
				mbuf_expand_big = i; 
				if (mbuf_expand_thread_initialized)
					wakeup((caddr_t)&mbuf_expand_thread_wakeup);
			}
		}
	
		if (mbstat.m_bigclfree >= num) 
			 return 1;
	}
	return 0;
}

/*
 * Add more free mbufs by cutting up a cluster.
 */
static int
m_expand(int canwait)
{
	caddr_t mcl;

	if (mbstat.m_clfree < (mbstat.m_clusters >> 4)) {
		/* 
		 * 1/16th of the total number of cluster mbufs allocated is
		 * reserved for large packets.  The number reserved must
		 * always be < 1/2, or future allocation will be prevented.
		 */
		(void)m_clalloc(1, canwait, MCLBYTES, 0);
		MBUF_UNLOCK();
		if (mbstat.m_clfree < (mbstat.m_clusters >> 4))
			return 0;
	}

	MCLALLOC(mcl, canwait);
	if (mcl) {
		struct mbuf *m = (struct mbuf *)mcl;
		int i = NMBPCL;
		MBUF_LOCK();
		mbstat.m_mtypes[MT_FREE] += i;
		mbstat.m_mbufs += i;
		while (i--) {
			_MFREE_MUNGE(m);
			m->m_type = MT_FREE;
			m->m_next = mfree;
			mfree = m++;
		}
		i = m_want;
		m_want = 0;
		MBUF_UNLOCK();
		if (i) wakeup((caddr_t)&mfree);
		return 1;
	}
	return 0;
}

/*
 * When MGET failes, ask protocols to free space when short of memory,
 * then re-attempt to allocate an mbuf.
 */
struct mbuf *
m_retry(
	int canwait, 
	int type)
{
	struct mbuf *m;
	int wait;

	for (;;) {
		(void) m_expand(canwait);
        	_MINTGET(m, type);
        	if (m) {
                	(m)->m_next = (m)->m_nextpkt = 0;
                	(m)->m_type = (type);
                	(m)->m_data = (m)->m_dat;
                	(m)->m_flags = 0;
                	(m)->m_len = 0;
        	}
		if (m || canwait == M_DONTWAIT)
			break;
		MBUF_LOCK();
		wait = m_want++;
		mbuf_expand_mcl++;
		if (wait == 0)
			mbstat.m_drain++;
		else
			mbstat.m_wait++;
		MBUF_UNLOCK();
        
		if (mbuf_expand_thread_initialized)
			wakeup((caddr_t)&mbuf_expand_thread_wakeup);

		if (wait == 0) {
			m_reclaim();
		} else {
			struct timespec ts;
			ts.tv_sec = 1;
			ts.tv_nsec = 0;
			(void) msleep((caddr_t)&mfree, 0, (PZERO-1) | PDROP, "m_retry", &ts);
		}
	}
	if (m == 0)
		mbstat.m_drops++;
	return (m);
}

/*
 * As above; retry an MGETHDR.
 */
struct mbuf *
m_retryhdr(
	int canwait, 
	int type)
{
	struct mbuf *m;

	if ((m = m_retry(canwait, type))) {
		m->m_next = m->m_nextpkt = 0;
		m->m_flags |= M_PKTHDR;
		m->m_data = m->m_pktdat;
		_M_CLEAR_PKTHDR(m);
	}
	return (m);
}

void
m_reclaim(void)
{
	do_reclaim = 1;	/* drain is performed in pfslowtimo(), to avoid deadlocks */
	mbstat.m_drain++;
}

/*
 * Space allocation routines.
 * These are also available as macros
 * for critical paths.
 */
struct mbuf *
m_get(
	int nowait, 
	int type)
{
	struct mbuf *m;

	m_range_check(mfree);
	m_range_check(mclfree);
	m_range_check(mbigfree);

	_MINTGET(m, type);
	if (m) {
		m->m_next = m->m_nextpkt = 0;
		m->m_type = type;
		m->m_data = m->m_dat;
		m->m_flags = 0;
		m->m_len = 0;
	} else
		(m) = m_retry(nowait, type);

	m_range_check(mfree);
	m_range_check(mclfree);
	m_range_check(mbigfree);


	return (m);
}

struct mbuf *
m_gethdr(
	int nowait, 
	int type)
{
	struct mbuf *m;

	m_range_check(mfree);
	m_range_check(mclfree);
	m_range_check(mbigfree);


	_MINTGET(m, type);
	if (m) {
		m->m_next = m->m_nextpkt = 0;
		m->m_type = type;
		m->m_data = m->m_pktdat;
		m->m_flags = M_PKTHDR;
		m->m_len = 0;
		_M_CLEAR_PKTHDR(m)
	} else
		m = m_retryhdr(nowait, type);

	m_range_check(mfree);
	m_range_check(mclfree);
	m_range_check(mbigfree);


	return m;
}

struct mbuf *
m_getclr(
	int nowait, 
	int type)
{
	struct mbuf *m;

	MGET(m, nowait, type);
	if (m == 0)
		return (0);
	bzero(mtod(m, caddr_t), MLEN);
	return (m);
}

struct mbuf *
m_free(
	struct mbuf *m)
{
	struct mbuf *n = m->m_next;
	int i;

	m_range_check(m);
	m_range_check(mfree);
	m_range_check(mclfree);

	if (m->m_type == MT_FREE)
		panic("freeing free mbuf");

	/* Free the aux data if there is any */
	if ((m->m_flags & M_PKTHDR) && m->m_pkthdr.aux)
	{
		m_freem(m->m_pkthdr.aux);
	}
	if ((m->m_flags & M_PKTHDR) != 0)
		m_tag_delete_chain(m, NULL);

	MBUF_LOCK();
	if ((m->m_flags & M_EXT)) 
    {
		if (MCLHASREFERENCE(m)) {
			remque((queue_t)&m->m_ext.ext_refs);
		} else if (m->m_ext.ext_free == NULL) {
			union mcluster *mcl= (union mcluster *)m->m_ext.ext_buf;
			
			m_range_check(mcl);
			
			if (_MCLUNREF(mcl)) {
				mcl->mcl_next = mclfree;
				mclfree = mcl;
				++mbstat.m_clfree;
			} 
#ifdef COMMENT_OUT
/* *** Since m_split() increments "mclrefcnt[mtocl(m->m_ext.ext_buf)]", 
       and AppleTalk ADSP uses m_split(), this incorrect sanity check
       caused a panic.  
*** */
			else	/* sanity check - not referenced this way */
				panic("m_free m_ext cluster not free");
#endif
		} else {
			(*(m->m_ext.ext_free))(m->m_ext.ext_buf,
			    m->m_ext.ext_size, m->m_ext.ext_arg);
		}
	}
	mbstat.m_mtypes[m->m_type]--;
	(void) _MCLUNREF(m);
	_MFREE_MUNGE(m);
	m->m_type = MT_FREE;
	mbstat.m_mtypes[m->m_type]++;
	m->m_flags = 0;
	m->m_next = mfree;
	m->m_len = 0;
	mfree = m;
	i = m_want;
	m_want = 0;
	MBUF_UNLOCK();
	if (i) wakeup((caddr_t)&mfree);
	return (n);
}

/* m_mclget() add an mbuf cluster to a normal mbuf */
struct mbuf *
m_mclget(
        struct mbuf *m,
        int nowait)
{
	MCLALLOC(m->m_ext.ext_buf, nowait);
	if (m->m_ext.ext_buf) {
		m->m_data = m->m_ext.ext_buf;
		m->m_flags |= M_EXT;
		m->m_ext.ext_size = MCLBYTES;
		m->m_ext.ext_free = 0;
		m->m_ext.ext_refs.forward = m->m_ext.ext_refs.backward =
			&m->m_ext.ext_refs;
	}
        
    return m;
}

/* m_mclalloc() allocate an mbuf cluster */
caddr_t
m_mclalloc(
    int nowait)
{
    caddr_t p;
        
	(void)m_clalloc(1, nowait, MCLBYTES, 0);
	if ((p = (caddr_t)mclfree)) {
		++mclrefcnt[mtocl(p)];
		mbstat.m_clfree--;
		mclfree = ((union mcluster *)p)->mcl_next;
	} else {
		mbstat.m_drops++;
	}
	MBUF_UNLOCK();
        
    return p;
}

/* m_mclfree() releases a reference to a cluster allocated by MCLALLOC,
 * freeing the cluster if the reference count has reached 0. */
void
m_mclfree(
    caddr_t p)
{
	MBUF_LOCK();

	m_range_check(p);

	if (--mclrefcnt[mtocl(p)] == 0) {
		((union mcluster *)(p))->mcl_next = mclfree;
		mclfree = (union mcluster *)(p);
		mbstat.m_clfree++;
	}
	MBUF_UNLOCK();
}

/* mcl_hasreference() checks if a cluster of an mbuf is referenced by another mbuf */
int
m_mclhasreference(
    struct mbuf *m)
{
    return (m->m_ext.ext_refs.forward != &(m->m_ext.ext_refs));
}

__private_extern__ caddr_t
m_bigalloc(int nowait)
{
    caddr_t p;
        
	(void)m_clalloc(1, nowait, NBPG, 0);
	if ((p = (caddr_t)mbigfree)) {
		if (mclrefcnt[mtocl(p)] != mclrefcnt[mtocl(p) + 1])
			panic("m_bigalloc mclrefcnt %x mismatch %d != %d",  
				p, mclrefcnt[mtocl(p)],  mclrefcnt[mtocl(p) + 1]);
		if (mclrefcnt[mtocl(p)] || mclrefcnt[mtocl(p) + 1])
			panic("m_bigalloc mclrefcnt %x not null %d != %d",  
				p, mclrefcnt[mtocl(p)],  mclrefcnt[mtocl(p) + 1]);
		++mclrefcnt[mtocl(p)];
		++mclrefcnt[mtocl(p) + 1];
		mbstat.m_bigclfree--;
		mbigfree = ((union mbigcluster *)p)->mbc_next;
	} else {
		mbstat.m_drops++;
	}
	MBUF_UNLOCK();
	return p;
}

__private_extern__ void
m_bigfree(caddr_t p, __unused u_int size, __unused caddr_t arg)
{
	m_range_check(p);
	
	if (mclrefcnt[mtocl(p)] != mclrefcnt[mtocl(p) + 1])
		panic("m_bigfree mclrefcnt %x mismatch %d != %d",  
			p, mclrefcnt[mtocl(p)],  mclrefcnt[mtocl(p) + 1]);
	--mclrefcnt[mtocl(p)];
	--mclrefcnt[mtocl(p) + 1];
	if (mclrefcnt[mtocl(p)] == 0) {
		((union mbigcluster *)(p))->mbc_next = mbigfree;
		mbigfree = (union mbigcluster *)(p);
		mbstat.m_bigclfree++;
	}
}

/* m_mbigget() add an 4KB mbuf cluster to a normal mbuf */
__private_extern__ struct mbuf *
m_mbigget(struct mbuf *m, int nowait)
{
	m->m_ext.ext_buf =  m_bigalloc(nowait);
	if (m->m_ext.ext_buf) {
		m->m_data = m->m_ext.ext_buf;
		m->m_flags |= M_EXT;
		m->m_ext.ext_size = NBPG;
		m->m_ext.ext_free = m_bigfree;
		m->m_ext.ext_arg = 0;
		m->m_ext.ext_refs.forward = m->m_ext.ext_refs.backward =
			&m->m_ext.ext_refs;
	}
        
    return m;
}


/* */
void
m_copy_pkthdr(
    struct mbuf *to, 
    struct mbuf *from)
{
	to->m_pkthdr = from->m_pkthdr;
	from->m_pkthdr.aux = (struct mbuf *)NULL;
	SLIST_INIT(&from->m_pkthdr.tags);       /* purge tags from src */
	to->m_flags = from->m_flags & M_COPYFLAGS;
	to->m_data = (to)->m_pktdat;
}

/*
 * "Move" mbuf pkthdr from "from" to "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 */
#ifndef __APPLE__
void
m_move_pkthdr(struct mbuf *to, struct mbuf *from)
{
        KASSERT((to->m_flags & M_EXT) == 0, ("m_move_pkthdr: to has cluster"));

        to->m_flags = from->m_flags & M_COPYFLAGS;
        to->m_data = to->m_pktdat;
        to->m_pkthdr = from->m_pkthdr;          /* especially tags */
        SLIST_INIT(&from->m_pkthdr.tags);       /* purge tags from src */
        from->m_flags &= ~M_PKTHDR;
}
#endif

/*
 * Duplicate "from"'s mbuf pkthdr in "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 * In particular, this does a deep copy of the packet tags.
 */
static int
m_dup_pkthdr(struct mbuf *to, struct mbuf *from, int how)
{
        to->m_flags = (from->m_flags & M_COPYFLAGS) | (to->m_flags & M_EXT);
        if ((to->m_flags & M_EXT) == 0)
                to->m_data = to->m_pktdat;
        to->m_pkthdr = from->m_pkthdr;
        SLIST_INIT(&to->m_pkthdr.tags);
        return (m_tag_copy_chain(to, from, how));
}

/*
 * return a list of mbuf hdrs that point to clusters...
 * try for num_needed, if wantall is not set, return whatever
 * number were available... set up the first num_with_pkthdrs
 * with mbuf hdrs configured as packet headers... these are
 * chained on the m_nextpkt field... any packets requested beyond
 * this are chained onto the last packet header's m_next field.
 * The size of the cluster is controlled by the paramter bufsize.
 */
__private_extern__ struct mbuf *
m_getpackets_internal(unsigned int *num_needed, int num_with_pkthdrs, int how, int wantall, size_t bufsize)
{
	struct mbuf *m;
	struct mbuf **np, *top;
	unsigned int num, needed = *num_needed;
	
	if (bufsize != MCLBYTES && bufsize != NBPG)
		return 0;
	
	top = NULL;
	np = &top;
	
	(void)m_clalloc(needed, how, bufsize, 0);		/* takes the MBUF_LOCK, but doesn't release it... */
	
	for (num = 0; num < needed; num++) {
		m_range_check(mfree);
		m_range_check(mclfree);
		m_range_check(mbigfree);
		
		if (mfree && ((bufsize == NBPG && mbigfree) || (bufsize == MCLBYTES && mclfree))) {
			/* mbuf + cluster are available */
			m = mfree;
			MCHECK(m);
			mfree = m->m_next;
			++mclrefcnt[mtocl(m)];
			mbstat.m_mtypes[MT_FREE]--;
			mbstat.m_mtypes[MT_DATA]++;
			if (bufsize == NBPG) {
				m->m_ext.ext_buf = (caddr_t)mbigfree; /* get the big cluster */
				++mclrefcnt[mtocl(m->m_ext.ext_buf)];
				++mclrefcnt[mtocl(m->m_ext.ext_buf) + 1];
				mbstat.m_bigclfree--;
				mbigfree = ((union mbigcluster *)(m->m_ext.ext_buf))->mbc_next;
				m->m_ext.ext_free = m_bigfree;
				m->m_ext.ext_size = NBPG;
			} else {
				m->m_ext.ext_buf = (caddr_t)mclfree; /* get the cluster */
				++mclrefcnt[mtocl(m->m_ext.ext_buf)];
				mbstat.m_clfree--;
				mclfree = ((union mcluster *)(m->m_ext.ext_buf))->mcl_next;
				m->m_ext.ext_free = 0;
				m->m_ext.ext_size = MCLBYTES;
			}
			m->m_ext.ext_arg = 0;
			m->m_ext.ext_refs.forward = m->m_ext.ext_refs.backward = &m->m_ext.ext_refs;
			m->m_next = m->m_nextpkt = 0;
			m->m_type = MT_DATA;
			m->m_data = m->m_ext.ext_buf;
			m->m_len = 0;

			if (num_with_pkthdrs == 0)
				m->m_flags = M_EXT;
			else {
				m->m_flags = M_PKTHDR | M_EXT;
				_M_CLEAR_PKTHDR(m);
			
				num_with_pkthdrs--;
			}
		} else {
			MBUF_UNLOCK();
			
			if (num_with_pkthdrs == 0) {
				MGET(m, how, MT_DATA );
			} else {
				MGETHDR(m, how, MT_DATA);
			
				num_with_pkthdrs--;
			}
			if (m == 0)
				goto fail;
			
			if (bufsize == NBPG)
				m = m_mbigget(m, how);
			else
				m = m_mclget(m, how);
			if ((m->m_flags & M_EXT) == 0) {
				m_free(m);
				goto fail;
			}
			MBUF_LOCK();
		}
		*np = m; 
		
		if (num_with_pkthdrs)
			np = &m->m_nextpkt;
		else
			np = &m->m_next;
	}
	MBUF_UNLOCK();
	
	*num_needed = num;
	return (top);
fail:
	if (wantall && top) {
		m_freem(top);
		return 0;
	}
	return top;
}


/*
 * Return list of mbuf linked by m_nextpkt
 * Try for num_needed, and if wantall is not set, return whatever
 * number were available
 * The size of each mbuf in the list is controlled by the parameter packetlen.
 * Each mbuf of the list may have a chain of mbufs linked by m_next. Each mbuf in 
 * the chain is called a segment.
 * If maxsegments is not null and the value pointed to is not null, this specify 
 * the maximum number of segments for a chain of mbufs.
 * If maxsegments is zero or the value pointed to is zero the 
 * caller does not have any restriction on the number of segments. 
 * The actual  number of segments of a mbuf chain is return in the value pointed 
 * to by maxsegments.
 * When possible the allocation is done under a single lock.
 */

__private_extern__ struct mbuf *
m_allocpacket_internal(unsigned int *num_needed, size_t packetlen, unsigned int * maxsegments, 
			int how, int wantall, size_t wantsize)
{
	struct mbuf **np, *top;
	size_t bufsize;
	unsigned int num;
	unsigned int numchunks = 0;

	top = NULL;
	np = &top;
	
	if (wantsize == 0) {
		if (packetlen <= MINCLSIZE)
			bufsize = packetlen;
		else if (packetlen > MCLBYTES)
			bufsize = NBPG;
		else
			bufsize = MCLBYTES;
	} else if (wantsize == MCLBYTES || wantsize == NBPG)
		bufsize = wantsize;
	else
		return 0;

	if (bufsize <= MHLEN) {
			numchunks = 1;
	} else if (bufsize <= MINCLSIZE) {
		if (maxsegments != NULL && *maxsegments == 1) {
			bufsize = MCLBYTES;
			numchunks = 1;
		} else {
			numchunks = 2;
		}
	} else if (bufsize == NBPG) {
		numchunks = ((packetlen - 1) >> PGSHIFT) + 1;
	} else {
		numchunks = ((packetlen - 1) >> MCLSHIFT) + 1;
	}
	if (maxsegments != NULL) {
	 	if (*maxsegments && numchunks > *maxsegments) {
			*maxsegments = numchunks;
			return 0;
		}
		*maxsegments = numchunks;
	}
	/* m_clalloc takes the MBUF_LOCK, but do not release it */	
	(void)m_clalloc(numchunks, how, (bufsize == NBPG) ? NBPG : MCLBYTES, 0);
	for (num = 0; num < *num_needed; num++) {
		struct mbuf **nm, *pkt = 0;
		size_t len;

		nm = &pkt;

		m_range_check(mfree);
		m_range_check(mclfree);
		m_range_check(mbigfree);

		for (len = 0; len < packetlen; ) {
			struct mbuf *m = NULL;

			if (wantsize == 0 && packetlen > MINCLSIZE) {
				if (packetlen - len > MCLBYTES)
					bufsize = NBPG;
				else
					bufsize = MCLBYTES;
			}
			len += bufsize;
			
			if (mfree && ((bufsize == NBPG && mbigfree) || (bufsize == MCLBYTES && mclfree))) {
				/* mbuf + cluster are available */
				m = mfree;
				MCHECK(m);
				mfree = m->m_next;
				++mclrefcnt[mtocl(m)];
				mbstat.m_mtypes[MT_FREE]--;
				mbstat.m_mtypes[MT_DATA]++;
				if (bufsize == NBPG) {
					m->m_ext.ext_buf = (caddr_t)mbigfree; /* get the big cluster */
					++mclrefcnt[mtocl(m->m_ext.ext_buf)];
					++mclrefcnt[mtocl(m->m_ext.ext_buf) + 1];
					mbstat.m_bigclfree--;
					mbigfree = ((union mbigcluster *)(m->m_ext.ext_buf))->mbc_next;
					m->m_ext.ext_free = m_bigfree;
					m->m_ext.ext_size = NBPG;
				} else {
					m->m_ext.ext_buf = (caddr_t)mclfree; /* get the cluster */
					++mclrefcnt[mtocl(m->m_ext.ext_buf)];
					mbstat.m_clfree--;
					mclfree = ((union mcluster *)(m->m_ext.ext_buf))->mcl_next;
					m->m_ext.ext_free = 0;
					m->m_ext.ext_size = MCLBYTES;
				}
				m->m_ext.ext_arg = 0;
				m->m_ext.ext_refs.forward = m->m_ext.ext_refs.backward = &m->m_ext.ext_refs;
				m->m_next = m->m_nextpkt = 0;
				m->m_type = MT_DATA;
				m->m_data = m->m_ext.ext_buf;
				m->m_len = 0;
	
				if (pkt == 0) {
					pkt = m;
					m->m_flags = M_PKTHDR | M_EXT;
					_M_CLEAR_PKTHDR(m);
				} else {
					m->m_flags = M_EXT;
				}
			} else {
				MBUF_UNLOCK();
				
				if (pkt == 0) {
					MGETHDR(m, how, MT_DATA);
				} else {
					MGET(m, how, MT_DATA );
				}
				if (m == 0) {
					m_freem(pkt);
					goto fail;
				}
				if (bufsize <= MINCLSIZE) {
					if (bufsize > MHLEN) {
						MGET(m->m_next, how, MT_DATA);
						if (m->m_next == 0) {
							m_free(m);
							m_freem(pkt);
							goto fail;
						}
					}
				} else {
					if (bufsize == NBPG)
						m = m_mbigget(m, how);
					else
						m = m_mclget(m, how);
					if ((m->m_flags & M_EXT) == 0) {
						m_free(m);
						m_freem(pkt);
						goto fail;
					}
				}
				MBUF_LOCK();
			}
			*nm = m;
			nm = &m->m_next;
		}
		*np = pkt; 		
		np = &pkt->m_nextpkt;
	}
	MBUF_UNLOCK();
	*num_needed = num;
	
	return top;
fail:
	if (wantall && top) {
		m_freem(top);
		return 0;
	}
	*num_needed = num;
	
	return top;
}


/* Best effort to get a mbuf cluster + pkthdr under one lock.
 * If we don't have them avail, just bail out and use the regular
 * path.
 * Used by drivers to allocated packets on receive ring.
 */
__private_extern__ struct mbuf *
m_getpacket_how(int how)
{
	unsigned int num_needed = 1;
	
	return m_getpackets_internal(&num_needed, 1, how, 1, MCLBYTES);
}

/* Best effort to get a mbuf cluster + pkthdr under one lock.
 * If we don't have them avail, just bail out and use the regular
 * path.
 * Used by drivers to allocated packets on receive ring.
 */
struct mbuf *
m_getpacket(void)
{
	unsigned int num_needed = 1;

	return m_getpackets_internal(&num_needed, 1, M_WAITOK, 1, MCLBYTES);
}


/*
 * return a list of mbuf hdrs that point to clusters...
 * try for num_needed, if this can't be met, return whatever
 * number were available... set up the first num_with_pkthdrs
 * with mbuf hdrs configured as packet headers... these are
 * chained on the m_nextpkt field... any packets requested beyond
 * this are chained onto the last packet header's m_next field.
 */
struct mbuf *
m_getpackets(int num_needed, int num_with_pkthdrs, int how)
{
	unsigned int n = num_needed;
	
	return m_getpackets_internal(&n, num_with_pkthdrs, how, 0, MCLBYTES);
}


/*
 * return a list of mbuf hdrs set up as packet hdrs
 * chained together on the m_nextpkt field
 */
struct mbuf *
m_getpackethdrs(int num_needed, int how)
{
	struct mbuf *m;
	struct mbuf **np, *top;

	top = NULL;
	np = &top;

	MBUF_LOCK();

	while (num_needed--) {
		m_range_check(mfree);
		m_range_check(mclfree);
		m_range_check(mbigfree);

	    if ((m = mfree)) {	/* mbufs are available */
                MCHECK(m);
                mfree = m->m_next;
                ++mclrefcnt[mtocl(m)];
                mbstat.m_mtypes[MT_FREE]--;
                mbstat.m_mtypes[MT_DATA]++;

                m->m_next = m->m_nextpkt = 0;
                m->m_type = MT_DATA;
                m->m_flags = M_PKTHDR;
                m->m_len = 0;
                m->m_data = m->m_pktdat;
                _M_CLEAR_PKTHDR(m);

	    } else {

			MBUF_UNLOCK();
			m = m_retryhdr(how, MT_DATA);
			if (m == 0)
				return(top);
			MBUF_LOCK();
	    }
	    *np = m; 
	    np = &m->m_nextpkt;
	}
	MBUF_UNLOCK();

	return (top);
}


/* free and mbuf list (m_nextpkt) while following m_next under one lock.
 * returns the count for mbufs packets freed. Used by the drivers.
 */
int 
m_freem_list(
	struct mbuf *m)
{
	struct mbuf *nextpkt;
	int i, count=0;

	MBUF_LOCK();

	while (m) {
		if (m) 
		        nextpkt = m->m_nextpkt; /* chain of linked mbufs from driver */
		else 
		        nextpkt = 0;

		count++;

		while (m) { /* free the mbuf chain (like mfreem) */
			
			struct mbuf *n;

			m_range_check(m);
			m_range_check(mfree);
			m_range_check(mclfree);
			m_range_check(mbigfree);
	

			/* Free the aux data if there is any */
			if ((m->m_flags & M_PKTHDR) && m->m_pkthdr.aux) {
				/*
				 * Treat the current m as the nextpkt and set m
				 * to the aux data. Preserve nextpkt in m->m_nextpkt.
				 * This lets us free the aux data in this loop
				 * without having to call m_freem recursively,
				 * which wouldn't work because we've still got
				 * the lock.
				 */
				m->m_nextpkt = nextpkt;
				nextpkt = m;
				m = nextpkt->m_pkthdr.aux;
				nextpkt->m_pkthdr.aux = NULL;
			}
			
			if ((m->m_flags & M_PKTHDR) != 0 && !SLIST_EMPTY(&m->m_pkthdr.tags)) {
				/* A quick (albeit inefficient) expedient */
				MBUF_UNLOCK();
				m_tag_delete_chain(m, NULL);
				MBUF_LOCK();
			}

			n = m->m_next;

			if (n && n->m_nextpkt)
				panic("m_freem_list: m_nextpkt of m_next != NULL");
			if (m->m_type == MT_FREE)
				panic("freeing free mbuf");

			if (m->m_flags & M_EXT) {
				if (MCLHASREFERENCE(m)) {
					remque((queue_t)&m->m_ext.ext_refs);
				} else if (m->m_ext.ext_free == NULL) {
					union mcluster *mcl= (union mcluster *)m->m_ext.ext_buf;
					
					m_range_check(mcl);

					if (_MCLUNREF(mcl)) {
						mcl->mcl_next = mclfree;
						mclfree = mcl;
						++mbstat.m_clfree;
					} 
				} else {
					(*(m->m_ext.ext_free))(m->m_ext.ext_buf,
					    m->m_ext.ext_size, m->m_ext.ext_arg);
				}
			}
			mbstat.m_mtypes[m->m_type]--;
			(void) _MCLUNREF(m);
              _MFREE_MUNGE(m);
			mbstat.m_mtypes[MT_FREE]++;
			m->m_type = MT_FREE;
			m->m_flags = 0;
			m->m_len = 0;
			m->m_next = mfree;
			mfree = m;
			m = n;
		}
		m = nextpkt; /* bump m with saved nextpkt if any */
	}
	if ((i = m_want))
		m_want = 0;

	MBUF_UNLOCK();

	if (i)
		wakeup((caddr_t)&mfree);

	return (count);
}

void
m_freem(
	struct mbuf *m)
{
	while (m)
		m = m_free(m);
}

/*
 * Mbuffer utility routines.
 */
/*
 * Compute the amount of space available
 * before the current start of data in an mbuf.
 */
int
m_leadingspace(
	struct mbuf *m)
{
	if (m->m_flags & M_EXT) {
		if (MCLHASREFERENCE(m))
			return(0);
		return (m->m_data - m->m_ext.ext_buf);
	}
	if (m->m_flags & M_PKTHDR)
		return (m->m_data - m->m_pktdat);
	return (m->m_data - m->m_dat);
}

/*
 * Compute the amount of space available
 * after the end of data in an mbuf.
 */
int
m_trailingspace(
	struct mbuf *m)
{
	if (m->m_flags & M_EXT) {
		if (MCLHASREFERENCE(m))
			return(0);
		return (m->m_ext.ext_buf + m->m_ext.ext_size -
			(m->m_data + m->m_len));
	}
	return (&m->m_dat[MLEN] - (m->m_data + m->m_len));
}

/*
 * Lesser-used path for M_PREPEND:
 * allocate new mbuf to prepend to chain,
 * copy junk along.
 * Does not adjust packet header length.
 */
struct mbuf *
m_prepend(
	struct mbuf *m,
	int len, 
	int how)
{
	struct mbuf *mn;

	MGET(mn, how, m->m_type);
	if (mn == (struct mbuf *)NULL) {
		m_freem(m);
		return ((struct mbuf *)NULL);
	}
	if (m->m_flags & M_PKTHDR) {
		M_COPY_PKTHDR(mn, m);
		m->m_flags &= ~M_PKTHDR;
	}
	mn->m_next = m;
	m = mn;
	if (len < MHLEN)
		MH_ALIGN(m, len);
	m->m_len = len;
	return (m);
}

/*
 * Replacement for old M_PREPEND macro:
 * allocate new mbuf to prepend to chain,
 * copy junk along, and adjust length.
 * 
 */
struct mbuf *
m_prepend_2(
        struct mbuf *m,
        int len,
        int how)
{
        if (M_LEADINGSPACE(m) >= len) {
                m->m_data -= len;
                m->m_len += len;
        } else {
		m = m_prepend(m, len, how);
        }
        if ((m) && (m->m_flags & M_PKTHDR))
                m->m_pkthdr.len += len;
        return (m);
}

/*
 * Make a copy of an mbuf chain starting "off0" bytes from the beginning,
 * continuing for "len" bytes.  If len is M_COPYALL, copy to end of mbuf.
 * The wait parameter is a choice of M_WAIT/M_DONTWAIT from caller.
 */
int MCFail;

struct mbuf *
m_copym(
	struct mbuf *m,
	int off0,
	int len,
	int wait)
{
	struct mbuf *n, **np;
	int off = off0;
	struct mbuf *top;
	int copyhdr = 0;

	if (off < 0 || len < 0)
		panic("m_copym");
	if (off == 0 && m->m_flags & M_PKTHDR)
		copyhdr = 1;

	while (off >= m->m_len) {
		if (m == 0)
			panic("m_copym");
		off -= m->m_len;
		m = m->m_next;
	}
	np = &top;
	top = 0;

	MBUF_LOCK();

	while (len > 0) {
		m_range_check(mfree);
		m_range_check(mclfree);
		m_range_check(mbigfree);

		if (m == 0) {
			if (len != M_COPYALL)
				panic("m_copym");
			break;
		}
		if ((n = mfree)) {
			MCHECK(n);
			++mclrefcnt[mtocl(n)];
			mbstat.m_mtypes[MT_FREE]--;
			mbstat.m_mtypes[m->m_type]++;
			mfree = n->m_next;
			n->m_next = n->m_nextpkt = 0;
			n->m_type = m->m_type;
			n->m_data = n->m_dat;
			n->m_flags = 0;
		} else {
		        MBUF_UNLOCK();
		        n = m_retry(wait, m->m_type);
		        MBUF_LOCK();
		}
		*np = n;

		if (n == 0)
			goto nospace;
		if (copyhdr) {
			M_COPY_PKTHDR(n, m);
			if (len == M_COPYALL)
				n->m_pkthdr.len -= off0;
			else
				n->m_pkthdr.len = len;
			copyhdr = 0;
		}
		if (len == M_COPYALL) {
		    if (min(len, (m->m_len - off)) == len) {
			printf("m->m_len %d - off %d = %d, %d\n", 
			       m->m_len, off, m->m_len - off,
			       min(len, (m->m_len - off)));
		    }
		}
		n->m_len = min(len, (m->m_len - off));
		if (n->m_len == M_COPYALL) {
		    printf("n->m_len == M_COPYALL, fixing\n");
		    n->m_len = MHLEN;
		}
		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			insque((queue_t)&n->m_ext.ext_refs, (queue_t)&m->m_ext.ext_refs);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			bcopy(mtod(m, caddr_t)+off, mtod(n, caddr_t),
			    (unsigned)n->m_len);
		}
		if (len != M_COPYALL)
			len -= n->m_len;
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}
	MBUF_UNLOCK();

	if (top == 0)
		MCFail++;

	return (top);
nospace:
	MBUF_UNLOCK();

	m_freem(top);
	MCFail++;
	return (0);
}


/*
 * equivilent to m_copym except that all necessary
 * mbuf hdrs are allocated within this routine
 * also, the last mbuf and offset accessed are passed
 * out and can be passed back in to avoid having to
 * rescan the entire mbuf list (normally hung off of the socket)
 */
struct mbuf *
m_copym_with_hdrs(
	struct mbuf *m,
	int off0, 
	int len,
	int wait,
	struct mbuf **m_last,
	int *m_off)
{
	struct mbuf *n, **np = 0;
	int off = off0;
	struct mbuf *top = 0;
	int copyhdr = 0;
	int type;

	if (off == 0 && m->m_flags & M_PKTHDR)
		copyhdr = 1;

	if (*m_last) {
	        m   = *m_last;
		off = *m_off;
	} else {
	        while (off >= m->m_len) {
		        off -= m->m_len;
			m = m->m_next;
		}
	}

	MBUF_LOCK();

	while (len > 0) {
		m_range_check(mfree);
		m_range_check(mclfree);
		m_range_check(mbigfree);

		if (top == 0)
		        type = MT_HEADER;
		else {
		        if (m == 0)
			        panic("m_gethdr_and_copym");
		        type = m->m_type;
		}
		if ((n = mfree)) {
		        MCHECK(n);
		        ++mclrefcnt[mtocl(n)];
			mbstat.m_mtypes[MT_FREE]--;
			mbstat.m_mtypes[type]++;
			mfree = n->m_next;
			n->m_next = n->m_nextpkt = 0;
			n->m_type = type;

			if (top) {
			        n->m_data = n->m_dat;
				n->m_flags = 0;
			} else {
			        n->m_data = n->m_pktdat;
				n->m_flags = M_PKTHDR;
				_M_CLEAR_PKTHDR(n);
			}
		} else {
		        MBUF_UNLOCK();
			if (top)
			        n = m_retry(wait, type);
			else
			        n = m_retryhdr(wait, type);
		        MBUF_LOCK();
		}
		if (n == 0)
			goto nospace;
		if (top == 0) {
		        top = n;
			np = &top->m_next;
			continue;
		} else
		        *np = n;

		if (copyhdr) {
			M_COPY_PKTHDR(n, m);
			n->m_pkthdr.len = len;
			copyhdr = 0;
		}
		n->m_len = min(len, (m->m_len - off));

		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			insque((queue_t)&n->m_ext.ext_refs, (queue_t)&m->m_ext.ext_refs);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			bcopy(mtod(m, caddr_t)+off, mtod(n, caddr_t),
			    (unsigned)n->m_len);
		}
		len -= n->m_len;
		
		if (len == 0) {
		        if ((off + n->m_len) == m->m_len) {
			       *m_last = m->m_next;
			       *m_off  = 0;
			} else {
			       *m_last = m;
			       *m_off  = off + n->m_len;
			}
		        break;
		}
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}
	MBUF_UNLOCK();

	return (top);
nospace:
	MBUF_UNLOCK();

	if (top)
	        m_freem(top);
	MCFail++;
	return (0);
}


/*
 * Copy data from an mbuf chain starting "off" bytes from the beginning,
 * continuing for "len" bytes, into the indicated buffer.
 */
void m_copydata(
	struct mbuf *m,
	int off,
	int len,
	caddr_t cp)
{
	unsigned count;

	if (off < 0 || len < 0)
		panic("m_copydata");
	while (off > 0) {
		if (m == 0)
			panic("m_copydata");
		if (off < m->m_len)
			break;
		off -= m->m_len;
		m = m->m_next;
	}
	while (len > 0) {
		if (m == 0)
			panic("m_copydata");
		count = min(m->m_len - off, len);
		bcopy(mtod(m, caddr_t) + off, cp, count);
		len -= count;
		cp += count;
		off = 0;
		m = m->m_next;
	}
}

/*
 * Concatenate mbuf chain n to m.
 * Both chains must be of the same type (e.g. MT_DATA).
 * Any m_pkthdr is not updated.
 */
void m_cat(
	struct mbuf *m, struct mbuf *n)
{
	while (m->m_next)
		m = m->m_next;
	while (n) {
		if (m->m_flags & M_EXT ||
		    m->m_data + m->m_len + n->m_len >= &m->m_dat[MLEN]) {
			/* just join the two chains */
			m->m_next = n;
			return;
		}
		/* splat the data from one into the other */
		bcopy(mtod(n, caddr_t), mtod(m, caddr_t) + m->m_len,
		    (u_int)n->m_len);
		m->m_len += n->m_len;
		n = m_free(n);
	}
}

void
m_adj(
	struct mbuf *mp,
	int req_len)
{
	int len = req_len;
	struct mbuf *m;
	int count;

	if ((m = mp) == NULL)
		return;
	if (len >= 0) {
		/*
		 * Trim from head.
		 */
		while (m != NULL && len > 0) {
			if (m->m_len <= len) {
				len -= m->m_len;
				m->m_len = 0;
				m = m->m_next;
			} else {
				m->m_len -= len;
				m->m_data += len;
				len = 0;
			}
		}
		m = mp;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= (req_len - len);
	} else {
		/*
		 * Trim from tail.  Scan the mbuf chain,
		 * calculating its length and finding the last mbuf.
		 * If the adjustment only affects this mbuf, then just
		 * adjust and return.  Otherwise, rescan and truncate
		 * after the remaining size.
		 */
		len = -len;
		count = 0;
		for (;;) {
			count += m->m_len;
			if (m->m_next == (struct mbuf *)0)
				break;
			m = m->m_next;
		}
		if (m->m_len >= len) {
			m->m_len -= len;
			m = mp;
			if (m->m_flags & M_PKTHDR)
				m->m_pkthdr.len -= len;
			return;
		}
		count -= len;
		if (count < 0)
			count = 0;
		/*
		 * Correct length for chain is "count".
		 * Find the mbuf with last data, adjust its length,
		 * and toss data from remaining mbufs on chain.
		 */
		m = mp;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len = count;
		for (; m; m = m->m_next) {
			if (m->m_len >= count) {
				m->m_len = count;
				break;
			}
			count -= m->m_len;
		}
		while ((m = m->m_next))
			m->m_len = 0;
	}
}

/*
 * Rearange an mbuf chain so that len bytes are contiguous
 * and in the data area of an mbuf (so that mtod and dtom
 * will work for a structure of size len).  Returns the resulting
 * mbuf chain on success, frees it and returns null on failure.
 * If there is room, it will add up to max_protohdr-len extra bytes to the
 * contiguous region in an attempt to avoid being called next time.
 */
int MPFail;

struct mbuf *
m_pullup(
	struct mbuf *n,
	int len)
{
	struct mbuf *m;
	int count;
	int space;

	/*
	 * If first mbuf has no cluster, and has room for len bytes
	 * without shifting current data, pullup into it,
	 * otherwise allocate a new mbuf to prepend to the chain.
	 */
	if ((n->m_flags & M_EXT) == 0 &&
	    n->m_data + len < &n->m_dat[MLEN] && n->m_next) {
		if (n->m_len >= len)
			return (n);
		m = n;
		n = n->m_next;
		len -= m->m_len;
	} else {
		if (len > MHLEN)
			goto bad;
		MGET(m, M_DONTWAIT, n->m_type);
		if (m == 0)
			goto bad;
		m->m_len = 0;
		if (n->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(m, n);
			n->m_flags &= ~M_PKTHDR;
		}
	}
	space = &m->m_dat[MLEN] - (m->m_data + m->m_len);
	do {
		count = min(min(max(len, max_protohdr), space), n->m_len);
		bcopy(mtod(n, caddr_t), mtod(m, caddr_t) + m->m_len,
		  (unsigned)count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len)
			n->m_data += count;
		else
			n = m_free(n);
	} while (len > 0 && n);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return (m);
bad:
	m_freem(n);
	MPFail++;
	return (0);
}

/*
 * Partition an mbuf chain in two pieces, returning the tail --
 * all but the first len0 bytes.  In case of failure, it returns NULL and
 * attempts to restore the chain to its original state.
 */
struct mbuf *
m_split(
	struct mbuf *m0,
	int len0, 
	int wait)
{
	struct mbuf *m, *n;
	unsigned len = len0, remain;

	for (m = m0; m && len > m->m_len; m = m->m_next)
		len -= m->m_len;
	if (m == 0)
		return (0);
	remain = m->m_len - len;
	if (m0->m_flags & M_PKTHDR) {
		MGETHDR(n, wait, m0->m_type);
		if (n == 0)
			return (0);
		n->m_pkthdr.rcvif = m0->m_pkthdr.rcvif;
		n->m_pkthdr.len = m0->m_pkthdr.len - len0;
		m0->m_pkthdr.len = len0;
		if (m->m_flags & M_EXT)
			goto extpacket;
		if (remain > MHLEN) {
			/* m can't be the lead packet */
			MH_ALIGN(n, 0);
			n->m_next = m_split(m, len, wait);
			if (n->m_next == 0) {
				(void) m_free(n);
				return (0);
			} else
				return (n);
		} else
			MH_ALIGN(n, remain);
	} else if (remain == 0) {
		n = m->m_next;
		m->m_next = 0;
		return (n);
	} else {
		MGET(n, wait, m->m_type);
		if (n == 0)
			return (0);
		M_ALIGN(n, remain);
	}
extpacket:
	if (m->m_flags & M_EXT) {
		n->m_flags |= M_EXT;
		MBUF_LOCK();
		n->m_ext = m->m_ext;
                insque((queue_t)&n->m_ext.ext_refs, (queue_t)&m->m_ext.ext_refs);
		MBUF_UNLOCK();
		n->m_data = m->m_data + len;
	} else {
		bcopy(mtod(m, caddr_t) + len, mtod(n, caddr_t), remain);
	}
	n->m_len = remain;
	m->m_len = len;
	n->m_next = m->m_next;
	m->m_next = 0;
	return (n);
}
/*
 * Routine to copy from device local memory into mbufs.
 */
struct mbuf *
m_devget(
	char *buf,
	int totlen, 
	int off0,
	struct ifnet *ifp,
	void (*copy)(const void *, void *, size_t))
{
	struct mbuf *m;
	struct mbuf *top = 0, **mp = &top;
	int off = off0, len;
	char *cp;
	char *epkt;

	cp = buf;
	epkt = cp + totlen;
	if (off) {
		/*
		 * If 'off' is non-zero, packet is trailer-encapsulated,
		 * so we have to skip the type and length fields.
		 */
		cp += off + 2 * sizeof(u_int16_t);
		totlen -= 2 * sizeof(u_int16_t);
	}
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == 0)
		return (0);
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = totlen;
	m->m_len = MHLEN;

	while (totlen > 0) {
		if (top) {
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m == 0) {
				m_freem(top);
				return (0);
			}
			m->m_len = MLEN;
		}
		len = min(totlen, epkt - cp);
		if (len >= MINCLSIZE) {
			MCLGET(m, M_DONTWAIT);
			if (m->m_flags & M_EXT)
				m->m_len = len = min(len, MCLBYTES);
			else {
			  	/* give up when it's out of cluster mbufs */
			        if (top)
				   m_freem(top);
				m_freem(m);
				return (0);
			}
		} else {
			/*
			 * Place initial small packet/header at end of mbuf.
			 */
			if (len < m->m_len) {
				if (top == 0 && len + max_linkhdr <= m->m_len)
					m->m_data += max_linkhdr;
				m->m_len = len;
			} else
				len = m->m_len;
		}
		if (copy)
			copy(cp, mtod(m, caddr_t), (unsigned)len);
		else
			bcopy(cp, mtod(m, caddr_t), (unsigned)len);
		cp += len;
		*mp = m;
		mp = &m->m_next;
		totlen -= len;
		if (cp == epkt)
			cp = buf;
	}
	return (top);
}

/*
 * Cluster freelist allocation check. The mbuf lock  must be held.
 * Ensure hysteresis between hi/lo.
 */
static int
m_howmany(int num, size_t bufsize)
{
	int i = 0;
	
	/* Bail if we've maxed out the mbuf memory map */
	if (mbstat.m_clusters + (mbstat.m_bigclusters << 1) < nmbclusters) {
		int j = 0;
		
		if (bufsize == MCLBYTES) {
			/* Under minimum */
			if (mbstat.m_clusters < MINCL)
				return (MINCL - mbstat.m_clusters);
			/* Too few (free < 1/2 total) and not over maximum */
			if (mbstat.m_clusters < (nmbclusters >> 1)) {
				if (num >= mbstat.m_clfree)
					i = num - mbstat.m_clfree;
				if (((mbstat.m_clusters + num) >> 1) > mbstat.m_clfree)
					j = ((mbstat.m_clusters + num) >> 1) - mbstat.m_clfree;
				i = max(i, j);
				if (i + mbstat.m_clusters >= (nmbclusters >> 1))
					i = (nmbclusters >> 1) - mbstat.m_clusters;
			}
		} else {
			/* Under minimum */
			if (mbstat.m_bigclusters < MINCL)
				return (MINCL - mbstat.m_bigclusters);
			/* Too few (free < 1/2 total) and not over maximum */
			if (mbstat.m_bigclusters < (nmbclusters >> 2)) {
				if (num >= mbstat.m_bigclfree)
					i = num - mbstat.m_bigclfree;
				if (((mbstat.m_bigclusters + num) >> 1) > mbstat.m_bigclfree)
					j = ((mbstat.m_bigclusters + num) >> 1) - mbstat.m_bigclfree;
				i = max(i, j);
				if (i + mbstat.m_bigclusters >= (nmbclusters >> 2))
					i = (nmbclusters >> 2) - mbstat.m_bigclusters;
			}
		}
	}
	return i;
}

/*
 * Copy data from a buffer back into the indicated mbuf chain,
 * starting "off" bytes from the beginning, extending the mbuf
 * chain if necessary.
 */
void
m_copyback(
	struct	mbuf *m0,
	int off,
	int len,
	caddr_t cp)
{
	int mlen;
	struct mbuf *m = m0, *n;
	int totlen = 0;

	if (m0 == 0)
		return;
	while (off > (mlen = m->m_len)) {
		off -= mlen;
		totlen += mlen;
		if (m->m_next == 0) {
			n = m_getclr(M_DONTWAIT, m->m_type);
			if (n == 0)
				goto out;
			n->m_len = min(MLEN, len + off);
			m->m_next = n;
		}
		m = m->m_next;
	}
	while (len > 0) {
		mlen = min (m->m_len - off, len);
		bcopy(cp, off + mtod(m, caddr_t), (unsigned)mlen);
		cp += mlen;
		len -= mlen;
		mlen += off;
		off = 0;
		totlen += mlen;
		if (len == 0)
			break;
		if (m->m_next == 0) {
			n = m_get(M_DONTWAIT, m->m_type);
			if (n == 0)
				break;
			n->m_len = min(MLEN, len);
			m->m_next = n;
		}
		m = m->m_next;
	}
out:	if (((m = m0)->m_flags & M_PKTHDR) && (m->m_pkthdr.len < totlen))
		m->m_pkthdr.len = totlen;
}


char *mcl_to_paddr(char *addr) {
        int base_phys;
  
	if (addr < (char *)mbutl || addr >= (char *)embutl)
	        return (0);
	base_phys = mcl_paddr[(addr - (char *)mbutl) >> PGSHIFT];

	if (base_phys == 0)
	        return (0);
	return ((char *)((int)base_phys | ((int)addr & PGOFSET)));
}

/*
 * Dup the mbuf chain passed in.  The whole thing.  No cute additional cruft.
 * And really copy the thing.  That way, we don't "precompute" checksums
 *  for unsuspecting consumers.
 * Assumption: m->m_nextpkt == 0.
 * Trick: for small packets, don't dup into a cluster.  That way received
 *  packets don't take up too much room in the sockbuf (cf. sbspace()).
 */
int MDFail;

struct mbuf *
m_dup(struct mbuf *m, int how)
{	
	struct mbuf *n, **np;
	struct mbuf *top;
	int copyhdr = 0;

	np = &top;
	top = 0;
	if (m->m_flags & M_PKTHDR)
		copyhdr = 1;

	/*
	 * Quick check: if we have one mbuf and its data fits in an
	 *  mbuf with packet header, just copy and go.
	 */
	if (m->m_next == NULL)
	{	/* Then just move the data into an mbuf and be done... */
		if (copyhdr)
		{	if (m->m_pkthdr.len <= MHLEN)
			{	if ((n = m_gethdr(how, m->m_type)) == NULL)
					return(NULL);
				n->m_len = m->m_len;
				m_dup_pkthdr(n, m, how);
				bcopy(m->m_data, n->m_data, m->m_len);
				return(n);
			}
		} else if (m->m_len <= MLEN)
		{	if ((n = m_get(how, m->m_type)) == NULL)
				return(NULL);
			bcopy(m->m_data, n->m_data, m->m_len);
			n->m_len = m->m_len;
			return(n);
		}
	}
	while (m)
	{
#if BLUE_DEBUG
		kprintf("<%x: %x, %x, %x\n", m, m->m_flags, m->m_len,
			m->m_data);
#endif
		if (copyhdr)
			n = m_gethdr(how, m->m_type);
		else
			n = m_get(how, m->m_type);
		if (n == 0)
			goto nospace;
		if (m->m_flags & M_EXT)
		{	MCLGET(n, how);
			if ((n->m_flags & M_EXT) == 0)
				goto nospace;
		}
		*np = n;
		if (copyhdr)
		{	/* Don't use M_COPY_PKTHDR: preserve m_data */
			m_dup_pkthdr(n, m, how);
			copyhdr = 0;
			if ((n->m_flags & M_EXT) == 0)
				n->m_data = n->m_pktdat;
		}
		n->m_len = m->m_len;
		/*
		 * Get the dup on the same bdry as the original
		 * Assume that the two mbufs have the same offset to data area
		 *  (up to word bdries)
		 */
		bcopy(mtod(m, caddr_t), mtod(n, caddr_t), (unsigned)n->m_len);
		m = m->m_next;
		np = &n->m_next;
#if BLUE_DEBUG
		kprintf(">%x: %x, %x, %x\n", n, n->m_flags, n->m_len,
			n->m_data);
#endif
	}

	if (top == 0)
		MDFail++;
	return (top);
 nospace:
	m_freem(top);
	MDFail++;
	return (0);
}

int
m_mclref(struct mbuf *p)
{
	return (_MCLREF(p));
}

int
m_mclunref(struct mbuf *p)
{
	return (_MCLUNREF(p));
}

/* change mbuf to new type */
void
m_mchtype(struct mbuf *m, int t)
{
        MBUF_LOCK();
        mbstat.m_mtypes[(m)->m_type]--;
        mbstat.m_mtypes[t]++;
        (m)->m_type = t;
        MBUF_UNLOCK();
}

void *m_mtod(struct mbuf *m)
{
	return ((m)->m_data);
}

struct mbuf *m_dtom(void *x)
{
	return ((struct mbuf *)((u_long)(x) & ~(MSIZE-1)));
}

int m_mtocl(void *x)
{
	return (((char *)(x) - (char *)mbutl) / sizeof(union mcluster));
}

union mcluster *m_cltom(int x)
{
	return ((union mcluster *)(mbutl + (x)));
}


void m_mcheck(struct mbuf *m)
{
	if (m->m_type != MT_FREE) 
		panic("mget MCHECK: m_type=%x m=%x", m->m_type, m);
}

static void
mbuf_expand_thread(void)
{
	while (1) {
		MBUF_LOCK();
		if (mbuf_expand_mcl) {
			int n;
		        
		    /* Adjust to the current number of cluster in use */
			n = mbuf_expand_mcl - (mbstat.m_clusters - mbstat.m_clfree);
			mbuf_expand_mcl = 0;
		    
		    if (n > 0)
				(void)m_clalloc(n, M_WAIT, MCLBYTES, 1);
		}
		if (mbuf_expand_big) {
			int n;
		        
		    /* Adjust to the current number of 4 KB cluster in use */
			n = mbuf_expand_big - (mbstat.m_bigclusters - mbstat.m_bigclfree);
			mbuf_expand_big = 0;
		        
		    if (n > 0)
				(void)m_clalloc(n, M_WAIT, NBPG, 1);
        }
		MBUF_UNLOCK();
		/* 
		 * Because we can run out of memory before filling the mbuf map, we 
		 * should not allocate more clusters than they are mbufs -- otherwise
		 * we could have a large number of useless clusters allocated.
		 */
		while (mbstat.m_mbufs < mbstat.m_bigclusters + mbstat.m_clusters) {
			if (m_expand(M_WAIT) == 0)
				break;
		}
	
		assert_wait(&mbuf_expand_thread_wakeup, THREAD_UNINT);
		(void) thread_block((thread_continue_t)mbuf_expand_thread);
	}
}

static void
mbuf_expand_thread_init(void)
{
	mbuf_expand_thread_initialized++;
	mbuf_expand_thread();
}

SYSCTL_DECL(_kern_ipc);
SYSCTL_STRUCT(_kern_ipc, KIPC_MBSTAT, mbstat, CTLFLAG_RW, &mbstat, mbstat, "");

