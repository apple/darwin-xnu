/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/* 
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * Copyright (c) 1994 NeXT Computer, Inc. All rights reserved.
 *
 * Copyright (c) 1982, 1986, 1988 Regents of the University of California.
 * All rights reserved.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *	@(#)mbuf.h	8.3 (Berkeley) 1/21/94
 **********************************************************************
 * HISTORY
 * 20-May-95  Mac Gillon (mgillon) at NeXT
 *	New version based on 4.4
 *	Purged old history
 */

#ifndef	_SYS_MBUF_H_
#define	_SYS_MBUF_H_

#include <sys/cdefs.h>
#include <sys/appleapiopts.h>

#ifdef KERNEL_PRIVATE

#include <sys/lock.h>
#include <sys/queue.h>

/*
 * Mbufs are of a single size, MSIZE (machine/param.h), which
 * includes overhead.  An mbuf may add a single "mbuf cluster" of size
 * MCLBYTES (also in machine/param.h), which has no additional overhead
 * and is used instead of the internal data area; this is done when
 * at least MINCLSIZE of data must be stored.
 */

#define	MLEN		(MSIZE - sizeof(struct m_hdr))	/* normal data len */
#define	MHLEN		(MLEN - sizeof(struct pkthdr))	/* data len w/pkthdr */

#define	MINCLSIZE	(MHLEN + MLEN)	/* smallest amount to put in cluster */
#define	M_MAXCOMPRESS	(MHLEN / 2)	/* max amount to copy for compression */

#define NMBPCL		(sizeof(union mcluster) / sizeof(struct mbuf))

/*
 * Macros for type conversion
 * mtod(m,t) -	convert mbuf pointer to data pointer of correct type
 * dtom(x) -	convert data pointer within mbuf to mbuf pointer (XXX)
 * mtocl(x) -	convert pointer within cluster to cluster index #
 * cltom(x) -	convert cluster # to ptr to beginning of cluster
 */
#define mtod(m,t)       ((t)m_mtod(m))
#define dtom(x)         m_dtom(x)
#define mtocl(x)        m_mtocl(x)
#define cltom(x)        m_cltom(x)

#define MCLREF(p)       m_mclref(p)
#define MCLUNREF(p)     m_mclunref(p)

/* header at beginning of each mbuf: */
struct m_hdr {
	struct	mbuf *mh_next;		/* next buffer in chain */
	struct	mbuf *mh_nextpkt;	/* next chain in queue/record */
	long	mh_len;			/* amount of data in this mbuf */
	caddr_t	mh_data;		/* location of data */
	short	mh_type;		/* type of data in this mbuf */
	short	mh_flags;		/* flags; see below */
};

/*
 * Packet tag structure (see below for details).
 */
struct m_tag {
	SLIST_ENTRY(m_tag)	m_tag_link;	/* List of packet tags */
	u_int16_t			m_tag_type;	/* Module specific type */
	u_int16_t			m_tag_len;	/* Length of data */
	u_int32_t			m_tag_id;	/* Module ID */
};

/* record/packet header in first mbuf of chain; valid if M_PKTHDR set */
struct	pkthdr {
	int	len;			/* total packet length */
	struct	ifnet *rcvif;		/* rcv interface */

	/* variables for ip and tcp reassembly */
	void	*header;		/* pointer to packet header */
        /* variables for hardware checksum */
#ifdef KERNEL_PRIVATE
    	/* Note: csum_flags is used for hardware checksum and VLAN */
#endif KERNEL_PRIVATE
        int     csum_flags;             /* flags regarding checksum */       
        int     csum_data;              /* data field used by csum routines */
	struct mbuf *aux;		/* extra data buffer; ipsec/others */
#ifdef KERNEL_PRIVATE
	u_short	vlan_tag;		/* VLAN tag, host byte order */
	u_short socket_id;		/* socket id */
#else KERNEL_PRIVATE
	u_int	reserved1;		/* for future use */
#endif KERNEL_PRIVATE
        SLIST_HEAD(packet_tags, m_tag) tags; /* list of packet tags */
};


/* description of external storage mapped into mbuf, valid if M_EXT set */
struct m_ext {
	caddr_t	ext_buf;		/* start of buffer */
	void	(*ext_free)(caddr_t , u_int, caddr_t);	/* free routine if not the usual */
	u_int	ext_size;		/* size of buffer, for ext_free */
	caddr_t	ext_arg;		/* additional ext_free argument */
	struct	ext_refsq {		/* references held */
		struct ext_refsq *forward, *backward;
	} ext_refs;
};

struct mbuf {
	struct	m_hdr m_hdr;
	union {
		struct {
			struct	pkthdr MH_pkthdr;	/* M_PKTHDR set */
			union {
				struct	m_ext MH_ext;	/* M_EXT set */
				char	MH_databuf[MHLEN];
			} MH_dat;
		} MH;
		char	M_databuf[MLEN];		/* !M_PKTHDR, !M_EXT */
	} M_dat;
};

#define	m_next		m_hdr.mh_next
#define	m_len		m_hdr.mh_len
#define	m_data		m_hdr.mh_data
#define	m_type		m_hdr.mh_type
#define	m_flags		m_hdr.mh_flags
#define	m_nextpkt	m_hdr.mh_nextpkt
#define	m_act		m_nextpkt
#define	m_pkthdr	M_dat.MH.MH_pkthdr
#define	m_ext		M_dat.MH.MH_dat.MH_ext
#define	m_pktdat	M_dat.MH.MH_dat.MH_databuf
#define	m_dat		M_dat.M_databuf

/* mbuf flags */
#define	M_EXT		0x0001	/* has associated external storage */
#define	M_PKTHDR	0x0002	/* start of record */
#define	M_EOR		0x0004	/* end of record */
#define	M_PROTO1	0x0008	/* protocol-specific */
#define	M_PROTO2	0x0010	/* protocol-specific */
#define	M_PROTO3	0x0020	/* protocol-specific */
#define	M_PROTO4	0x0040	/* protocol-specific */
#define	M_PROTO5	0x0080	/* protocol-specific */

/* mbuf pkthdr flags, also in m_flags */
#define	M_BCAST		0x0100	/* send/received as link-level broadcast */
#define	M_MCAST		0x0200	/* send/received as link-level multicast */
#define	M_FRAG		0x0400	/* packet is a fragment of a larger packet */
#define	M_FIRSTFRAG	0x0800	/* packet is first fragment */
#define	M_LASTFRAG	0x1000	/* packet is last fragment */
#define	M_PROMISC	0x2000	/* packet is promiscuous (shouldn't go to stack) */

/* flags copied when copying m_pkthdr */
#define M_COPYFLAGS     (M_PKTHDR|M_EOR|M_PROTO1|M_PROTO2|M_PROTO3 | \
                            M_PROTO4|M_PROTO5|M_BCAST|M_MCAST|M_FRAG | \
                            M_FIRSTFRAG|M_LASTFRAG|M_PROMISC)

/* flags indicating hw checksum support and sw checksum requirements [freebsd4.1]*/
#define CSUM_IP                 0x0001          /* will csum IP */
#define CSUM_TCP                0x0002          /* will csum TCP */
#define CSUM_UDP                0x0004          /* will csum UDP */
#define CSUM_IP_FRAGS           0x0008          /* will csum IP fragments */
#define CSUM_FRAGMENT           0x0010          /* will do IP fragmentation */
        
#define CSUM_IP_CHECKED         0x0100          /* did csum IP */
#define CSUM_IP_VALID           0x0200          /*   ... the csum is valid */
#define CSUM_DATA_VALID         0x0400          /* csum_data field is valid */
#define CSUM_PSEUDO_HDR         0x0800          /* csum_data has pseudo hdr */
#define CSUM_TCP_SUM16          0x1000          /* simple TCP Sum16 computation */
 
#define CSUM_DELAY_DATA         (CSUM_TCP | CSUM_UDP)
#define CSUM_DELAY_IP           (CSUM_IP)       /* XXX add ipv6 here too? */
/*
 * Note: see also IF_HWASSIST_CSUM defined in <net/if_var.h>
 */
/* bottom 16 bits reserved for hardware checksum */
#define CSUM_CHECKSUM_MASK	0xffff

/* VLAN tag present */
#define CSUM_VLAN_TAG_VALID	0x10000		/* vlan_tag field is valid */
#endif KERNEL_PRIVATE


/* mbuf types */
#define	MT_FREE		0	/* should be on free list */
#define	MT_DATA		1	/* dynamic (data) allocation */
#define	MT_HEADER	2	/* packet header */
#define	MT_SOCKET	3	/* socket structure */
#define	MT_PCB		4	/* protocol control block */
#define	MT_RTABLE	5	/* routing tables */
#define	MT_HTABLE	6	/* IMP host tables */
#define	MT_ATABLE	7	/* address resolution tables */
#define	MT_SONAME	8	/* socket name */
#define	MT_SOOPTS	10	/* socket options */
#define	MT_FTABLE	11	/* fragment reassembly header */
#define	MT_RIGHTS	12	/* access rights */
#define	MT_IFADDR	13	/* interface address */
#define MT_CONTROL	14	/* extra-data protocol message */
#define MT_OOBDATA	15	/* expedited data  */
#define MT_TAG          16      /* volatile metadata associated to pkts */
#define MT_MAX		32	/* enough? */

#ifdef KERNEL_PRIVATE

/* flags to m_get/MGET */
/* Need to include malloc.h to get right options for malloc  */
#include	<sys/malloc.h>

#define	M_DONTWAIT	M_NOWAIT
#define	M_WAIT		M_WAITOK

/*
 * mbuf utility macros:
 *
 *	MBUFLOCK(code)
 * prevents a section of code from from being interrupted by network
 * drivers.
 */

#ifdef _KERN_LOCKS_H_
extern lck_mtx_t * mbuf_mlock;
#else
extern void * mbuf_mlock;
#endif

#define MBUF_LOCK()	lck_mtx_lock(mbuf_mlock);
#define MBUF_UNLOCK()	lck_mtx_unlock(mbuf_mlock);

/*
 * mbuf allocation/deallocation macros:
 *
 *	MGET(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain internal data.
 *
 *	MGETHDR(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain a packet header
 * and internal data.
 */

#if 1
#define MCHECK(m) m_mcheck(m)
#else
#define MCHECK(m)
#endif

extern struct mbuf *mfree;				/* mbuf free list */

#define	MGET(m, how, type) ((m) = m_get((how), (type)))

#define	MGETHDR(m, how, type)	((m) = m_gethdr((how), (type)))

/*
 * Mbuf cluster macros.
 * MCLALLOC(caddr_t p, int how) allocates an mbuf cluster.
 * MCLGET adds such clusters to a normal mbuf;
 * the flag M_EXT is set upon success.
 * MCLFREE releases a reference to a cluster allocated by MCLALLOC,
 * freeing the cluster if the reference count has reached 0.
 *
 * Normal mbuf clusters are normally treated as character arrays
 * after allocation, but use the first word of the buffer as a free list
 * pointer while on the free list.
 */
union mcluster {
	union	mcluster *mcl_next;
	char	mcl_buf[MCLBYTES];
};

#define	MCLALLOC(p, how)	((p) = m_mclalloc(how))

#define	MCLFREE(p)	m_mclfree(p)

#define	MCLGET(m, how) 	((m) = m_mclget(m, how))

/*
 * Mbuf big cluster
 */

union mbigcluster {
	union mbigcluster	*mbc_next;
	char 			mbc_buf[NBPG];
};


#define MCLHASREFERENCE(m) m_mclhasreference(m)

/*
 * MFREE(struct mbuf *m, struct mbuf *n)
 * Free a single mbuf and associated external storage.
 * Place the successor, if any, in n.
 */

#define	MFREE(m, n) ((n) = m_free(m))

/*
 * Copy mbuf pkthdr from from to to.
 * from must have M_PKTHDR set, and to must be empty.
 * aux pointer will be moved to `to'.
 */
#define	M_COPY_PKTHDR(to, from)		m_copy_pkthdr(to, from)

/*
 * Set the m_data pointer of a newly-allocated mbuf (m_get/MGET) to place
 * an object of the specified size at the end of the mbuf, longword aligned.
 */
#define	M_ALIGN(m, len)				\
	{ (m)->m_data += (MLEN - (len)) &~ (sizeof(long) - 1); }
/*
 * As above, for mbufs allocated with m_gethdr/MGETHDR
 * or initialized by M_COPY_PKTHDR.
 */
#define	MH_ALIGN(m, len) \
	{ (m)->m_data += (MHLEN - (len)) &~ (sizeof(long) - 1); }

/*
 * Compute the amount of space available
 * before the current start of data in an mbuf.
 * Subroutine - data not available if certain references.
 */
#define	M_LEADINGSPACE(m)	m_leadingspace(m)

/*
 * Compute the amount of space available
 * after the end of data in an mbuf.
 * Subroutine - data not available if certain references.
 */
#define	M_TRAILINGSPACE(m)	m_trailingspace(m)

/*
 * Arrange to prepend space of size plen to mbuf m.
 * If a new mbuf must be allocated, how specifies whether to wait.
 * If how is M_DONTWAIT and allocation fails, the original mbuf chain
 * is freed and m is set to NULL.
 */
#define	M_PREPEND(m, plen, how) 	((m) = m_prepend_2((m), (plen), (how)))

/* change mbuf to new type */
#define MCHTYPE(m, t) 		m_mchtype(m, t)

/* length to m_copy to copy all */
#define	M_COPYALL	1000000000

/* compatiblity with 4.3 */
#define  m_copy(m, o, l)	m_copym((m), (o), (l), M_DONTWAIT)

#endif /* KERNEL_PRIVATE */

/*
 * Mbuf statistics.
 */
/* LP64todo - not 64-bit safe */
struct mbstat {
	u_long  m_mbufs;        /* mbufs obtained from page pool */
	u_long  m_clusters;     /* clusters obtained from page pool */
	u_long  m_spare;        /* spare field */
	u_long  m_clfree;       /* free clusters */
	u_long  m_drops;        /* times failed to find space */
	u_long  m_wait;         /* times waited for space */
	u_long  m_drain;        /* times drained protocols for space */
	u_short m_mtypes[256];  /* type specific mbuf allocations */
	u_long  m_mcfail;       /* times m_copym failed */
	u_long  m_mpfail;       /* times m_pullup failed */
	u_long  m_msize;        /* length of an mbuf */
	u_long  m_mclbytes;     /* length of an mbuf cluster */
	u_long  m_minclsize;    /* min length of data to allocate a cluster */
	u_long  m_mlen;         /* length of data in an mbuf */
	u_long  m_mhlen;        /* length of data in a header mbuf */
	u_long  m_bigclusters;     /* clusters obtained from page pool */
	u_long  m_bigclfree;       /* free clusters */
	u_long  m_bigmclbytes;     /* length of an mbuf cluster */
};

/* Compatibillity with 10.3 */
struct ombstat {
	u_long	m_mbufs;	/* mbufs obtained from page pool */
	u_long	m_clusters;	/* clusters obtained from page pool */
	u_long	m_spare;	/* spare field */
	u_long	m_clfree;	/* free clusters */
	u_long	m_drops;	/* times failed to find space */
	u_long	m_wait;		/* times waited for space */
	u_long	m_drain;	/* times drained protocols for space */
	u_short	m_mtypes[256];	/* type specific mbuf allocations */
	u_long	m_mcfail;	/* times m_copym failed */
	u_long	m_mpfail;	/* times m_pullup failed */
	u_long	m_msize;	/* length of an mbuf */
	u_long	m_mclbytes;	/* length of an mbuf cluster */
	u_long	m_minclsize;	/* min length of data to allocate a cluster */
	u_long	m_mlen;		/* length of data in an mbuf */
	u_long	m_mhlen;	/* length of data in a header mbuf */
};
#ifdef KERNEL_PRIVATE

/*
 * pkthdr.aux type tags.
 */
struct mauxtag {
	int af;
	int type;
};

#ifdef	KERNEL
extern union 	mcluster *mbutl;	/* virtual address of mclusters */
extern union 	mcluster *embutl;	/* ending virtual address of mclusters */
extern short 	*mclrefcnt;		/* cluster reference counts */
extern int 	*mcl_paddr;		/* physical addresses of clusters */
extern struct 	mbstat mbstat;		/* statistics */
extern int 	nmbclusters;		/* number of mapped clusters */
extern union 	mcluster *mclfree;	/* free mapped cluster list */
extern int	max_linkhdr;		/* largest link-level header */
extern int	max_protohdr;		/* largest protocol header */
extern int	max_hdr;		/* largest link+protocol header */
extern int	max_datalen;		/* MHLEN - max_hdr */

__BEGIN_DECLS
struct	mbuf *m_copym(struct mbuf *, int, int, int);
struct	mbuf *m_split(struct mbuf *, int, int);
struct	mbuf *m_free(struct mbuf *);
struct	mbuf *m_get(int, int);
struct	mbuf *m_getpacket(void);
struct	mbuf *m_getclr(int, int);
struct	mbuf *m_gethdr(int, int);
struct	mbuf *m_prepend(struct mbuf *, int, int);
struct  mbuf *m_prepend_2(struct mbuf *, int, int);
struct	mbuf *m_pullup(struct mbuf *, int);
struct	mbuf *m_retry(int, int);
struct	mbuf *m_retryhdr(int, int);
void m_adj(struct mbuf *, int);
void m_freem(struct mbuf *);
int m_freem_list(struct mbuf *);
struct	mbuf *m_devget(char *, int, int, struct ifnet *, void (*)(const void *, void *, size_t));
char   *mcl_to_paddr(char *);
struct mbuf *m_pulldown(struct mbuf*, int, int, int*);
struct mbuf *m_aux_add(struct mbuf *, int, int);
struct mbuf *m_aux_find(struct mbuf *, int, int);
void m_aux_delete(struct mbuf *, struct mbuf *);

struct mbuf *m_mclget(struct mbuf *, int);
caddr_t m_mclalloc(int);
void m_mclfree(caddr_t p);
int m_mclhasreference(struct mbuf *);
void m_copy_pkthdr(struct mbuf *, struct mbuf*);

int m_mclref(struct mbuf *);
int m_mclunref(struct mbuf *);

void *          m_mtod(struct mbuf *);
struct mbuf *   m_dtom(void *);
int             m_mtocl(void *);
union mcluster *m_cltom(int );

int m_trailingspace(struct mbuf *);
int m_leadingspace(struct mbuf *);

void m_mchtype(struct mbuf *m, int t);
void m_mcheck(struct mbuf*);

void m_copyback(struct mbuf *, int , int , caddr_t);
void m_copydata(struct mbuf *, int , int , caddr_t);
struct mbuf* m_dup(struct mbuf *m, int how);
void m_cat(struct mbuf *, struct mbuf *);
struct  mbuf *m_copym_with_hdrs(struct mbuf*, int, int, int, struct mbuf**, int*);
struct mbuf *m_getpackets(int, int, int);
struct mbuf * m_getpackethdrs(int , int );
struct mbuf* m_getpacket_how(int );
struct mbuf * m_getpackets_internal(unsigned int *, int , int , int , size_t);
struct mbuf * m_allocpacket_internal(unsigned int * , size_t , unsigned int *, int , int , size_t );

__END_DECLS

/*
 Packets may have annotations attached by affixing a list of "packet
 tags" to the pkthdr structure.  Packet tags are dynamically allocated
 semi-opaque data structures that have a fixed header (struct m_tag)
 that specifies the size of the memory block and an <id,type> pair that
 identifies it. The id identifies the module and the type identifies the
 type of data for that module. The id of zero is reserved for the kernel.
 
 Note that the packet tag returned by m_tag_allocate has the default
 memory alignment implemented by malloc.  To reference private data one
 can use a construct like:
 
      struct m_tag *mtag = m_tag_allocate(...);
      struct foo *p = (struct foo *)(mtag+1);
 
 if the alignment of struct m_tag is sufficient for referencing members
 of struct foo.  Otherwise it is necessary to embed struct m_tag within
 the private data structure to insure proper alignment; e.g.
 
      struct foo {
              struct m_tag    tag;
              ...
      };
      struct foo *p = (struct foo *) m_tag_allocate(...);
      struct m_tag *mtag = &p->tag;
 */

#define KERNEL_MODULE_TAG_ID	0

enum {
	KERNEL_TAG_TYPE_NONE			= 0,
	KERNEL_TAG_TYPE_DUMMYNET		= 1,
	KERNEL_TAG_TYPE_DIVERT			= 2,
	KERNEL_TAG_TYPE_IPFORWARD		= 3,
	KERNEL_TAG_TYPE_IPFILT			= 4
};

/*
 * As a temporary and low impact solution to replace the even uglier
 * approach used so far in some parts of the network stack (which relies
 * on global variables), packet tag-like annotations are stored in MT_TAG
 * mbufs (or lookalikes) prepended to the actual mbuf chain.
 *
 *      m_type  = MT_TAG
 *      m_flags = m_tag_id
 *      m_next  = next buffer in chain.
 *
 * BE VERY CAREFUL not to pass these blocks to the mbuf handling routines.
 */
#define _m_tag_id       m_hdr.mh_flags

__BEGIN_DECLS

/* Packet tag routines */
struct  m_tag   *m_tag_alloc(u_int32_t id, u_int16_t type, int len, int wait);
void             m_tag_free(struct m_tag *);
void             m_tag_prepend(struct mbuf *, struct m_tag *);
void             m_tag_unlink(struct mbuf *, struct m_tag *);
void             m_tag_delete(struct mbuf *, struct m_tag *);
void             m_tag_delete_chain(struct mbuf *, struct m_tag *);
struct  m_tag   *m_tag_locate(struct mbuf *,u_int32_t id, u_int16_t type,
							  struct m_tag *);
struct  m_tag   *m_tag_copy(struct m_tag *, int wait);
int              m_tag_copy_chain(struct mbuf *to, struct mbuf *from, int wait);
void             m_tag_init(struct mbuf *);
struct  m_tag   *m_tag_first(struct mbuf *);
struct  m_tag   *m_tag_next(struct mbuf *, struct m_tag *);

__END_DECLS

#endif /* KERNEL */

#endif /* KERNEL_PRIVATE */
#ifdef KERNEL
#include <sys/kpi_mbuf.h>
#endif
#endif	/* !_SYS_MBUF_H_ */
