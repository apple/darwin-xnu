/*	$KAME: natpt_defs.h,v 1.7 2000/03/25 07:23:54 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define	SAME		(0)

#define	NATPT_MAXHASH	(397)
#define	MAXTSLOTENTRY	(4096)

#define	SZSIN6		sizeof(struct sockaddr_in6)
#define	SZSIN		sizeof(struct sockaddr_in)

#define	CAR(p)		((p)->car)
#define	CDR(p)		((p)->cdr)
#define	CAAR(p)		(CAR(CAR(p)))
#define	CADR(p)		(CAR(CDR(p)))
#define	CDAR(p)		(CDR(CAR(p)))
#define	CDDR(p)		(CDR(CDR(p)))

#ifndef TCP6
#define	tcp6hdr		tcphdr
#endif


#if defined(NATPT_ASSERT) && (NATPT_ASSERT != 0)
# if defined(__STDC__)
#  define	ASSERT(e)	((e) ? (void)0 : natpt_assert(__FILE__, __LINE__, #e))
# else	/* PCC */
#  define	ASSERT(e)	((e) ? (void)0 : natpt_assert(__FILE__, __LINE__, "e"))
# endif
#else
# undef NATPT_ASSERT
# define	ASSERT(e)	((void)0)
#endif


#define	IN4_ARE_ADDR_EQUAL(a, b)					\
	((a)->s_addr == (b)->s_addr)


#define	ReturnEnobufs(m)	if (m == NULL) { errno = ENOBUFS; return (NULL); }


#if (defined(KERNEL)) || (defined(_KERNEL))

#define	isDebug(d)	(natpt_debug & (d))
#define	isDump(d)	(natpt_dump  & (d))

#define	D_DIVEIN4			0x00000001
#define	D_PEEKOUTGOINGV4		0x00000002
#define	D_TRANSLATINGIPV4		0x00000010
#define	D_TRANSLATEDIPV4		0x00001000

#define	D_DIVEIN6			0x00010000
#define	D_IN6REJECT			0x00020000
#define	D_IN6ACCEPT			0x00040000
#define	D_PEEKOUTGOINGV6		0x00080000
#define	D_TRANSLATINGIPV6		0x00100000
#define	D_TRANSLATEDIPV6		0x01000000

#define	fixSuMiReICMPBug	(1)

#ifdef fixSuMiReICMPBug
#define	IPDST		(0xc48db2cb)		/* == 203.178.141.196	XXX	*/
#define	ICMPSRC		(0x02c410ac)		/* == 172.16.196.2	XXX	*/
#endif

#endif	/* defined(KERNEL)			*/

/*
 *	OS dependencies
 */

#ifdef KERNEL

#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#define	rcb_list		list
#endif

#ifdef __NetBSD__
/*
 * Macros for type conversion
 * dtom(x) -	convert data pointer within mbuf to mbuf pointer (XXX)
 */
#define	dtom(x)		((struct mbuf *)((long)(x) & ~(MSIZE-1)))
#endif

#endif	/* _KERNEL	*/


/*
 *	Structure definitions.
 */

typedef	struct	_cell
{
    struct  _cell   *car;
    struct  _cell   *cdr;
}   Cell;


/* Interface Box structure						*/

struct ifBox
{
    int			 side;
#define	noSide			(0)
#define	inSide			(1)
#define	outSide			(2)
    char		 ifName[IFNAMSIZ];
    struct ifnet	*ifnet;
};


/* IP ...								*/

struct _cv						/* 28[byte]	*/
{
    u_char	 ip_p;			/* IPPROTO_(ICMP[46]|TCP|UDP)	*/
    u_char	 ip_payload;		/* IPPROTO_(ICMP|TCP|UDP)	*/

    u_char	 inout;
/*	#define	NATPT_UNSPEC		(0)				*/
/*	#define	NATPT_INBOUND		(1)				*/
/*	#define	NATPT_OUTBOUND		(2)				*/

    u_char	 flags;
#define		NATPT_TRACEROUTE	(0x01)
#define		NATPT_NEEDFRAGMENT	(0x02)

    int		 poff;			/* payload offset		*/
    int		 plen;			/* payload length		*/

    struct mbuf		*m;
    struct _tSlot	*ats;
    union
    {
	struct ip	*_ip4;
	struct ip6_hdr	*_ip6;
    }		 _ip;
    union
    {
	caddr_t		  _caddr;
	struct icmp	 *_icmp4;
	struct icmp6_hdr *_icmp6;
	struct tcphdr	 *_tcp4;
	struct tcp6hdr	 *_tcp6;
	struct udphdr	 *_udp;
    }		 _payload;
};


/* IP address structure							*/

union inaddr					/* sizeof():  16[byte]	*/
{
    struct in_addr	in4;
    struct in6_addr	in6;
};


struct pAddr					/* sizeof():  44[byte]	*/
{
    u_char		ip_p;		/* protocol family (within struct _tSlot)	*/
    u_char		sa_family;	/* address family  (within struct _cSlot)	*/

    u_short		port[2];
#define	_port0			port[0]
#define	_port1			port[1]

#define	_sport			port[0]
#define	_dport			port[1]
#define	_eport			port[1]

    union inaddr	addr[2];

#define	in4src			addr[0].in4
#define	in4dst			addr[1].in4
#define	in4Addr			addr[0].in4
#define	in4Mask			addr[1].in4
#define	in4RangeStart		addr[0].in4
#define	in4RangeEnd		addr[1].in4

#define	in6src			addr[0].in6
#define	in6dst			addr[1].in6
#define	in6Addr			addr[0].in6
#define	in6Mask			addr[1].in6

    struct
    {
	u_char		type;
#define	ADDR_ANY		(0)
#define	ADDR_SINGLE		(1)
#define	ADDR_MASK		(2)
#define	ADDR_RANGE		(3)
#define	ADDR_FAITH		(4)

	u_char		prefix;
    }			ad;
};


/* Configuration slot entry						*/

struct	_cSlot					/* sizeof(): 100[byte]	*/
{
    u_char		 flags;
#define	NATPT_STATIC		(1)	/* Rule was set statically	*/
#define	NATPT_DYNAMIC		(2)	/* Rule was set dynamically	*/
#define NATPT_FAITH		(3)

    u_char		 dir;
#define	NATPT_UNSPEC		(0)
#define	NATPT_INBOUND		(1)
#define	NATPT_OUTBOUND		(2)

    u_char		 map;
#define	NATPT_PORT_MAP		(0x01)	/* Mapping dest port		   */
#define	NATPT_PORT_MAP_DYNAMIC	(0x02)	/* Mapping dest port dynamically */
#define	NATPT_ADDR_MAP		(0x04)	/* Mapping dest addr		   */
#define	NATPT_ADDR_MAP_DYNAMIC	(0x08)	/* Mapping dest addr dynamically */

    u_char		 proto;

    u_short		 prefix;
    u_short		 cport;		/* current port			*/

    struct pAddr	 local, remote;
    struct _cSlotAux	*aux;		/* place holder			*/
};


#if	0
/* Configuration slot auxiliary entry					*/
/* currently not used							*/

struct	_cSlotAux				/* sizeof():   0[byte]	*/
{
};
#endif


/* Translation slot entry						*/

struct	_tSlot					/* sizeof(): 104[byte]	*/
{
    u_char	ip_payload;

    u_char	session;
/* #define	NATPT_UNSPEC		(0)		*/
/* #define	NATPT_INBOUND		(1)		*/
/* #define	NATPT_OUTBOUND		(2)		*/

    u_char	remap;
/* #define	NATPT_PORT_REMAP	(0x01)		*/
/* #define	NATPT_ADDR_REMAP	(0x02)		*/

/* #define NATPT_STATIC		(0x1)			 */
/* #define NATPT_DYNAMIC	(0x2)			 */
/* #define NATPT_FAITH		(0x3)			 */

    struct pAddr	local;
    struct pAddr	remote;
    time_t		tstamp;
    int			lcount;

    union
    {
	struct _idseq
	{
	    n_short		 icd_id;
	    n_short		 icd_seq;
	}			 ih_idseq;
	struct _tcpstate	*tcp;
    }				 suit;
};


struct _tcpstate				/* sizeof():  28[byte]	*/
{
    short	_state;
    short	_session;
    u_long	_ip_id[2];	/* IP packet Identification			*/
				/*    [0]: current packet			*/
				/*    [1]: just before packet			*/
    u_short	_port[2];	/* [0]:outGoing srcPort, [1]:inComing dstPort	*/
/*  u_long	_iss;			initial send sequence number		*/
    u_long	_delta[3];	/* Sequence delta				*/
				/*    [0]: current     (cumulative)		*/
				/*    [1]: just before (cumulative)		*/
				/*    [2]: (this time)				*/
};
