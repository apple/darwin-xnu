/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Defines for synchronous PPP/Cisco link level subroutines.
 *
 * Copyright (C) 1994 Cronyx Ltd.
 * Author: Serge Vakulenko, <vak@cronyx.ru>
 *
 * Heavily revamped to conform to RFC 1661.
 * Copyright (C) 1997, Joerg Wunsch.
 *
 * This software is distributed with NO WARRANTIES, not even the implied
 * warranties for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Authors grant any other persons or organizations permission to use
 * or modify this software as long as this message is kept with the software,
 * all derivative works or modified versions.
 *
 * From: Version 2.0, Fri Oct  6 20:39:21 MSK 1995
 *
 */

#ifndef _NET_IF_SPPP_H_
#define _NET_IF_SPPP_H_ 1
#include <sys/appleapiopts.h>

#ifndef DONT_WARN_OBSOLETE
#warning if_sppp.h is not used by the darwin kernel
#endif

#define IDX_LCP 0		/* idx into state table */

struct slcp {
	u_long	opts;		/* LCP options to send (bitfield) */
	u_long  magic;          /* local magic number */
	u_long	mru;		/* our max receive unit */
	u_long	their_mru;	/* their max receive unit */
	u_long	protos;		/* bitmask of protos that are started */
	u_char  echoid;         /* id of last keepalive echo request */
	/* restart max values, see RFC 1661 */
	int	timeout;
	int	max_terminate;
	int	max_configure;
	int	max_failure;
};

#define IDX_IPCP 1		/* idx into state table */

struct sipcp {
	u_long	opts;		/* IPCP options to send (bitfield) */
	u_int	flags;
#define IPCP_HISADDR_SEEN 1	/* have seen his address already */
#define IPCP_MYADDR_DYN   2	/* my address is dynamically assigned */
#define IPCP_MYADDR_SEEN  4	/* have seen his address already */
};

#define AUTHNAMELEN	32
#define AUTHKEYLEN	16

struct sauth {
	u_short	proto;			/* authentication protocol to use */
	u_short	flags;
#define AUTHFLAG_NOCALLOUT	1	/* do not require authentication on */
					/* callouts */
#define AUTHFLAG_NORECHALLENGE	2	/* do not re-challenge CHAP */
	u_char	name[AUTHNAMELEN];	/* system identification name */
	u_char	secret[AUTHKEYLEN];	/* secret password */
	u_char	challenge[AUTHKEYLEN];	/* random challenge */
};

#define IDX_PAP		2
#define IDX_CHAP	3

#define IDX_COUNT (IDX_CHAP + 1) /* bump this when adding cp's! */

/*
 * Don't change the order of this.  Ordering the phases this way allows
 * for a comparision of ``pp_phase >= PHASE_AUTHENTICATE'' in order to
 * know whether LCP is up.
 */
enum ppp_phase {
	PHASE_DEAD, PHASE_ESTABLISH, PHASE_TERMINATE,
	PHASE_AUTHENTICATE, PHASE_NETWORK
};

#ifdef __APPLE_API_PRIVATE
struct sppp {
	/* NB: pp_if _must_ be first */
	struct  ifnet pp_if;    /* network interface data */
	struct  ifqueue pp_fastq; /* fast output queue */
	struct	ifqueue pp_cpq;	/* PPP control protocol queue */
	struct  sppp *pp_next;  /* next interface in keepalive list */
	u_int   pp_flags;       /* use Cisco protocol instead of PPP */
	u_short pp_alivecnt;    /* keepalive packets counter */
	u_short pp_loopcnt;     /* loopback detection counter */
	u_long  pp_seq;         /* local sequence number */
	u_long  pp_rseq;        /* remote sequence number */
	enum ppp_phase pp_phase;	/* phase we're currently in */
	int	state[IDX_COUNT];	/* state machine */
	u_char  confid[IDX_COUNT];	/* id of last configuration request */
	int	rst_counter[IDX_COUNT];	/* restart counter */
	int	fail_counter[IDX_COUNT]; /* negotiation failure counter */
	struct callout_handle ch[IDX_COUNT]; /* per-proto and if callouts */
	struct callout_handle pap_my_to_ch; /* PAP needs one more... */
	struct slcp lcp;		/* LCP params */
	struct sipcp ipcp;		/* IPCP params */
	struct sauth myauth;		/* auth params, i'm peer */
	struct sauth hisauth;		/* auth params, i'm authenticator */
	/*
	 * These functions are filled in by sppp_attach(), and are
	 * expected to be used by the lower layer (hardware) drivers
	 * in order to communicate the (un)availability of the
	 * communication link.  Lower layer drivers that are always
	 * ready to communicate (like hardware HDLC) can shortcut
	 * pp_up from pp_tls, and pp_down from pp_tlf.
	 */
	void	(*pp_up)(struct sppp *sp);
	void	(*pp_down)(struct sppp *sp);
	/*
	 * These functions need to be filled in by the lower layer
	 * (hardware) drivers if they request notification from the
	 * PPP layer whether the link is actually required.  They
	 * correspond to the tls and tlf actions.
	 */
	void	(*pp_tls)(struct sppp *sp);
	void	(*pp_tlf)(struct sppp *sp);
	/*
	 * These (optional) functions may be filled by the hardware
	 * driver if any notification of established connections
	 * (currently: IPCP up) is desired (pp_con) or any internal
	 * state change of the interface state machine should be
	 * signaled for monitoring purposes (pp_chg).
	 */
	void	(*pp_con)(struct sppp *sp);
	void	(*pp_chg)(struct sppp *sp, int new_state);
	/* These two fields are for use by the lower layer */
	void    *pp_lowerp;
	int     pp_loweri;
};

#endif /* __APPLE_API_PRIVATE */

#define PP_KEEPALIVE    0x01    /* use keepalive protocol */
#define PP_CISCO        0x02    /* use Cisco protocol instead of PPP */
				/* 0x04 was PP_TIMO */
#define PP_CALLIN	0x08	/* we are being called */
#define PP_NEEDAUTH	0x10	/* remote requested authentication */


#define PP_MTU          1500    /* default/minimal MRU */
#define PP_MAX_MRU	2048	/* maximal MRU we want to negotiate */

/*
 * Definitions to pass struct sppp data down into the kernel using the
 * SIOC[SG]IFGENERIC ioctl interface.
 *
 * In order to use this, create a struct spppreq, fill in the cmd
 * field with SPPPIOGDEFS, and put the address of this structure into
 * the ifr_data portion of a struct ifreq.  Pass this struct to a
 * SIOCGIFGENERIC ioctl.  Then replace the cmd field by SPPPIOCDEFS,
 * modify the defs field as desired, and pass the struct ifreq now
 * to a SIOCSIFGENERIC ioctl.
 */

#define SPPPIOGDEFS  ((caddr_t)(('S' << 24) + (1 << 16) + sizeof(struct sppp)))
#define SPPPIOSDEFS  ((caddr_t)(('S' << 24) + (2 << 16) + sizeof(struct sppp)))

struct spppreq {
	int	cmd;
	struct sppp defs;
};

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
void sppp_attach (struct ifnet *ifp);
void sppp_detach (struct ifnet *ifp);
void sppp_input (struct ifnet *ifp, struct mbuf *m);
int sppp_ioctl (struct ifnet *ifp, u_long cmd, void *data);
struct mbuf *sppp_dequeue (struct ifnet *ifp);
struct mbuf *sppp_pick(struct ifnet *ifp);
int sppp_isempty (struct ifnet *ifp);
void sppp_flush (struct ifnet *ifp);
#endif /* __APPLE_API_PRIVATE */
#endif

#endif /* _NET_IF_SPPP_H_ */
