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
 *	@(#)iso.h	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */

#ifndef __ISO__
#define __ISO__

/*
 *	Return true if this is a multicast address
 *	This assumes that the bit transmission is lsb first. This 
 *	assumption is valid for 802.3 but not 802.5. There is a
 *	kludge to get around this for 802.5 -- see if_lan.c
 *	where subnetwork header is setup.
 */
#define	IS_MULTICAST(snpa)\
	((snpa)[0] & 0x01)
	
/*
 * Protocols
 */
#define	ISOPROTO_TCP	6		/* IETF experiment */
#define	ISOPROTO_UDP	17		/* IETF experiment */
#define	ISOPROTO_TP0	25		/* connection oriented transport protocol */
#define	ISOPROTO_TP1	26		/* not implemented */
#define	ISOPROTO_TP2	27		/* not implemented */
#define	ISOPROTO_TP3	28		/* not implemented */
#define	ISOPROTO_TP4	29		/* connection oriented transport protocol */
#define	ISOPROTO_TP		ISOPROTO_TP4	 /* tp-4 with negotiation */
#define	ISOPROTO_CLTP	30		/* connectionless transport (not yet impl.) */
#define	ISOPROTO_CLNP	31		/* connectionless internetworking protocol */
#define	ISOPROTO_X25	32		/* cons */
#define	ISOPROTO_INACT_NL	33	/* inactive network layer! */
#define	ISOPROTO_ESIS	34		/* ES-IS protocol */
#define	ISOPROTO_INTRAISIS	35		/* IS-IS protocol */
#define	ISOPROTO_IDRP	36		/* Interdomain Routing Protocol */

#define	ISOPROTO_RAW	255		/* raw clnp */
#define	ISOPROTO_MAX	256

#define	ISO_PORT_RESERVED		1024
#define	ISO_PORT_USERRESERVED	5000
/*
 * Port/socket numbers: standard network functions
 * NOT PRESENTLY USED
 */
#define	ISO_PORT_MAINT		501
#define	ISO_PORT_ECHO		507
#define	ISO_PORT_DISCARD	509
#define	ISO_PORT_SYSTAT		511
#define	ISO_PORT_NETSTAT	515
/*
 * Port/socket numbers: non-standard application functions
 */
#define ISO_PORT_LOGIN		513
/*
 * Port/socket numbers: public use
 */
#define ISO_PORT_PUBLIC		1024		/* high bit set --> public */

/*
 *	Network layer protocol identifiers
 */
#define ISO8473_CLNP	0x81
#define	ISO9542_ESIS	0x82
#define ISO9542X25_ESIS	0x8a
#define ISO10589_ISIS		0x83
#define ISO8878A_CONS		0x84
#define ISO10747_IDRP		0x85


#ifndef IN_CLASSA_NET
#include <netinet/in.h>
#endif /* IN_CLASSA_NET */



/* The following looks like a sockaddr
 * to facilitate using tree lookup routines */
struct iso_addr {
	u_char	isoa_len;						/* length (in bytes) */
	char	isoa_genaddr[20];				/* general opaque address */
};

struct sockaddr_iso {
	u_char	 			siso_len;			/* length */
	u_char	 			siso_family;		/* family */
	u_char				siso_plen;			/* presentation selector length */
	u_char				siso_slen;			/* session selector length */
	u_char				siso_tlen;			/* transport selector length */
	struct 	iso_addr	siso_addr;			/* network address */
	u_char				siso_pad[6];		/* space for gosip v2 sels */
											/* makes struct 32 bytes long */
};
#define siso_nlen siso_addr.isoa_len
#define siso_data siso_addr.isoa_genaddr

#define TSEL(s) ((caddr_t)((s)->siso_data + (s)->siso_nlen))

#define SAME_ISOADDR(a, b) \
	(bcmp((a)->siso_data, (b)->siso_data, (unsigned)(a)->siso_nlen)==0)
/*
 * The following are specific values for siso->siso_data[0],
 * otherwise known as the AFI:
 */
#define	AFI_37		0x37	/* bcd of "37" */
#define AFI_OSINET	0x47	/* bcd of "47" */
#define AFI_RFC986	0x47	/* bcd of "47" */
#define	AFI_SNA		0x00	/* SubNetwork Address; invalid really...*/

#ifdef KERNEL

extern int iso_netmatch();
extern int iso_hash(); 
extern int iso_addrmatch();
extern struct iso_ifaddr *iso_iaonnetof();
extern	struct domain isodomain;
extern	struct protosw isosw[];

#else
/* user utilities definitions from the iso library */

#include <sys/cdefs.h>

__BEGIN_DECLS
struct iso_addr *iso_addr __P((const char *));
char *iso_ntoa __P((const struct iso_addr *));

/* THESE DON'T EXIST YET */
struct hostent *iso_gethostbyname(), *iso_gethostbyaddr();
__END_DECLS

#endif /* KERNEL */

#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
#endif /* __ISO__ */
