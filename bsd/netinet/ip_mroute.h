/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1989 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *	@(#)ip_mroute.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IP_MROUTE_H_
#define _NETINET_IP_MROUTE_H_
#include <sys/appleapiopts.h>

/*
 * Definitions for IP multicast forwarding.
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Ajit Thyagarajan, PARC, August 1993.
 * Modified by Ajit Thyagarajan, PARC, August 1994.
 *
 * MROUTING Revision: 3.3.1.3
 */


/*
 * Multicast Routing set/getsockopt commands.
 */
#define	MRT_INIT	100	/* initialize forwarder */
#define	MRT_DONE	101	/* shut down forwarder */
#define	MRT_ADD_VIF	102	/* create virtual interface */
#define	MRT_DEL_VIF	103	/* delete virtual interface */
#define MRT_ADD_MFC	104	/* insert forwarding cache entry */
#define MRT_DEL_MFC	105	/* delete forwarding cache entry */
#define MRT_VERSION	106	/* get kernel version number */
#define MRT_ASSERT      107     /* enable PIM assert processing */


#ifdef KERNEL_PRIVATE
#define GET_TIME(t)	microtime(&t)
#endif KERNEL_PRIVATE

/*
 * Types and macros for handling bitmaps with one bit per virtual interface.
 */
#define	MAXVIFS 32
typedef u_long vifbitmap_t;
typedef u_short vifi_t;		/* type of a vif index */
#define ALL_VIFS (vifi_t)-1

#define	VIFM_SET(n, m)		((m) |= (1 << (n)))
#define	VIFM_CLR(n, m)		((m) &= ~(1 << (n)))
#define	VIFM_ISSET(n, m)	((m) & (1 << (n)))
#define	VIFM_CLRALL(m)		((m) = 0x00000000)
#define	VIFM_COPY(mfrom, mto)	((mto) = (mfrom))
#define	VIFM_SAME(m1, m2)	((m1) == (m2))


/*
 * Argument structure for MRT_ADD_VIF.
 * (MRT_DEL_VIF takes a single vifi_t argument.)
 */
struct vifctl {
	vifi_t	vifc_vifi;	    	/* the index of the vif to be added */
	u_char	vifc_flags;     	/* VIFF_ flags defined below */
	u_char	vifc_threshold; 	/* min ttl required to forward on vif */
	u_int	vifc_rate_limit;	/* max rate */
	struct	in_addr vifc_lcl_addr;	/* local interface address */
	struct	in_addr vifc_rmt_addr;	/* remote address (tunnels only) */
};

#define	VIFF_TUNNEL	0x1		/* vif represents a tunnel end-point */
#define VIFF_SRCRT	0x2		/* tunnel uses IP source routing */

/*
 * Argument structure for MRT_ADD_MFC and MRT_DEL_MFC
 * (mfcc_tos to be added at a future point)
 */
struct mfcctl {
    struct in_addr  mfcc_origin;		/* ip origin of mcasts       */
    struct in_addr  mfcc_mcastgrp; 		/* multicast group associated*/
    vifi_t	    mfcc_parent;   		/* incoming vif              */
    u_char	    mfcc_ttls[MAXVIFS]; 	/* forwarding ttls on vifs   */
};

/*
 * The kernel's multicast routing statistics.
 */
struct mrtstat {
    u_long	mrts_mfc_lookups;	/* # forw. cache hash table hits   */
    u_long	mrts_mfc_misses;	/* # forw. cache hash table misses */
    u_long	mrts_upcalls;		/* # calls to mrouted              */
    u_long	mrts_no_route;		/* no route for packet's origin    */
    u_long	mrts_bad_tunnel;	/* malformed tunnel options        */
    u_long	mrts_cant_tunnel;	/* no room for tunnel options      */
    u_long	mrts_wrong_if;		/* arrived on wrong interface	   */
    u_long	mrts_upq_ovflw;		/* upcall Q overflow		   */
    u_long	mrts_cache_cleanups;	/* # entries with no upcalls 	   */
    u_long  	mrts_drop_sel;     	/* pkts dropped selectively        */
    u_long  	mrts_q_overflow;    	/* pkts dropped - Q overflow       */
    u_long  	mrts_pkt2large;     	/* pkts dropped - size > BKT SIZE  */
    u_long	mrts_upq_sockfull;	/* upcalls dropped - socket full */
};

/*
 * Argument structure used by mrouted to get src-grp pkt counts
 */
struct sioc_sg_req {
    struct in_addr src;
    struct in_addr grp;
    u_long pktcnt;
    u_long bytecnt;
    u_long wrong_if;
};

/*
 * Argument structure used by mrouted to get vif pkt counts
 */
struct sioc_vif_req {
    vifi_t vifi;		/* vif number				*/
    u_long icount;		/* Input packet count on vif		*/
    u_long ocount;		/* Output packet count on vif		*/
    u_long ibytes;		/* Input byte count on vif		*/
    u_long obytes;		/* Output byte count on vif		*/
};

#ifdef PRIVATE
/*
 * The kernel's virtual-interface structure.
 */
struct tbf;
struct ifnet;
struct socket;
struct vif {
    u_char   		v_flags;     	/* VIFF_ flags defined above         */
    u_char   		v_threshold;	/* min ttl required to forward on vif*/
    u_int      		v_rate_limit; 	/* max rate			     */
    struct tbf 	       *v_tbf;       	/* token bucket structure at intf.   */
    struct in_addr 	v_lcl_addr;   	/* local interface address           */
    struct in_addr 	v_rmt_addr;   	/* remote address (tunnels only)     */
    struct ifnet       *v_ifp;	     	/* pointer to interface              */
    u_long		v_pkt_in;	/* # pkts in on interface            */
    u_long		v_pkt_out;	/* # pkts out on interface           */
    u_long		v_bytes_in;	/* # bytes in on interface	     */
    u_long		v_bytes_out;	/* # bytes out on interface	     */
    struct route	v_route;	/* cached route if this is a tunnel */
    u_int		v_rsvp_on;	/* RSVP listening on this vif */
    struct socket      *v_rsvpd;	/* RSVP daemon socket */
};
#endif

/*
 * The kernel's multicast forwarding cache entry structure 
 * (A field for the type of service (mfc_tos) is to be added 
 * at a future point)
 */
struct mfc {
    struct in_addr  mfc_origin;	 		/* IP origin of mcasts   */
    struct in_addr  mfc_mcastgrp;  		/* multicast group associated*/
    vifi_t	    mfc_parent; 		/* incoming vif              */
    u_char	    mfc_ttls[MAXVIFS]; 		/* forwarding ttls on vifs   */
    u_long	    mfc_pkt_cnt;		/* pkt count for src-grp     */
    u_long	    mfc_byte_cnt;		/* byte count for src-grp    */
    u_long	    mfc_wrong_if;		/* wrong if for src-grp	     */
    int		    mfc_expire;			/* time to clean entry up    */
    struct timeval  mfc_last_assert;		/* last time I sent an assert*/
    struct rtdetq  *mfc_stall;			/* q of packets awaiting mfc */
    struct mfc     *mfc_next;			/* next mfc entry            */
};

/*
 * Struct used to communicate from kernel to multicast router
 * note the convenient similarity to an IP packet
 */
struct igmpmsg {
    u_long	    unused1;
    u_long	    unused2;
    u_char	    im_msgtype;			/* what type of message	    */
#define IGMPMSG_NOCACHE		1
#define IGMPMSG_WRONGVIF	2
    u_char	    im_mbz;			/* must be zero		    */
    u_char	    im_vif;			/* vif rec'd on		    */
    u_char	    unused3;
    struct in_addr  im_src, im_dst;
};
#define MFCTBLSIZ       256

#ifdef KERNEL_PRIVATE
/*
 * Argument structure used for pkt info. while upcall is made
 */
struct rtdetq {
    struct mbuf 	*m;		/* A copy of the packet		    */
    struct ifnet	*ifp;		/* Interface pkt came in on	    */
    vifi_t		xmt_vif;	/* Saved copy of imo_multicast_vif  */
#if UPCALL_TIMING
    struct timeval	t;		/* Timestamp */
#endif /* UPCALL_TIMING */
    struct rtdetq	*next;		/* Next in list of packets          */
};

#if (MFCTBLSIZ & (MFCTBLSIZ - 1)) == 0	  /* from sys:route.h */
#define MFCHASHMOD(h)	((h) & (MFCTBLSIZ - 1))
#else
#define MFCHASHMOD(h)	((h) % MFCTBLSIZ)
#endif

#define MAX_UPQ	4		/* max. no of pkts in upcall Q */

/*
 * Token Bucket filter code 
 */
#define MAX_BKT_SIZE    10000             /* 10K bytes size 		*/
#define MAXQSIZE        10                /* max # of pkts in queue 	*/

/*
 * the token bucket filter at each vif
 */
struct tbf
{
    struct timeval tbf_last_pkt_t; /* arr. time of last pkt 	*/
    u_long tbf_n_tok;      	/* no of tokens in bucket 	*/
    u_long tbf_q_len;    	/* length of queue at this vif	*/
    u_long tbf_max_q_len;	/* max. queue length		*/
    struct mbuf *tbf_q;		/* Packet queue			*/
    struct mbuf *tbf_t;		/* tail-insertion pointer	*/
};


struct sockopt;

extern int	(*ip_mrouter_set)(struct socket *, struct sockopt *);
extern int	(*ip_mrouter_get)(struct socket *, struct sockopt *);
extern int	(*ip_mrouter_done)(void);
#if MROUTING
extern int	(*mrt_ioctl)(int, caddr_t);
#else
extern int	(*mrt_ioctl)(int, caddr_t, struct proc *);
#endif

#endif KERNEL_PRIVATE
#endif /* _NETINET_IP_MROUTE_H_ */
