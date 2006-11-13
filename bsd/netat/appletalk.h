/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *
 * ORIGINS: 82
 *
 * (C) COPYRIGHT Apple Computer, Inc. 1992-1996
 * All Rights Reserved
 *
 */                                                                   

/* Miscellaneous definitions for AppleTalk used by all protocol 
 * modules.
 */

#ifndef _NETAT_APPLETALK_H_
#define _NETAT_APPLETALK_H_
#include <sys/appleapiopts.h>

#include <sys/types.h>
#include <sys/uio.h>

#ifdef __APPLE_API_OBSOLETE

/* 
   Non-aligned types are used in packet headers. 
*/

/* New fundemental types: non-aligned variations of u_short and u_long */
typedef u_char ua_short[2];		/* Unaligned short */
typedef u_char ua_long[4];		/* Unaligned long */

/* Two at_net typedefs; the first is aligned the other isn't */
typedef u_short at_net_al;		/* Aligned AppleTalk network number */
typedef ua_short at_net_unal;		/* Unaligned AppleTalk network number */

/* Miscellaneous types */
typedef u_char	at_node;		/* AppleTalk node number */
typedef u_char  at_socket;		/* AppleTalk socket number */

typedef at_net_unal at_net;	/* Default: Unaligned AppleTalk network number */
struct atalk_addr {
	u_char	atalk_unused;
	at_net	atalk_net;
	at_node	atalk_node;
};

/* Macros to manipulate unaligned fields */
#define	UAS_ASSIGN(x,s)	*(unsigned short *) &(x[0]) = (unsigned short) (s)
#define	UAS_UAS(x,y)	*(unsigned short *) &(x[0]) = *(unsigned short *) &(y[0])
#define	UAS_VALUE(x)	(*(unsigned short *) &(x[0]))
#define	UAL_ASSIGN(x,l)	*(unsigned long *) &(x[0]) = (unsigned long) (l)
#define	UAL_UAL(x,y)	*(unsigned long *) &(x[0]) = *(unsigned long *) &(y[0])
#define	UAL_VALUE(x)	(*(unsigned long *) &(x[0]))

/* Macros to manipulate at_net variables */
#define	NET_ASSIGN(x,s)	*(unsigned short *)&(x[0]) = (unsigned short)(s)
#define	NET_NET(x, y)	*(unsigned short *)&(x[0]) = *(unsigned short *)&(y[0])
#define	NET_VALUE(x)	(*(unsigned short *) &(x[0]))
#define ATALK_ASSIGN(a, net, node, unused ) \
  a.atalk_unused = unused; a.atalk_node = node; NET_ASSIGN(a.atalk_net, net)

#define NET_EQUAL(a, b)	(NET_VALUE(a) == NET_VALUE(b))
#define NET_NOTEQ(a, b)	(NET_VALUE(a) != NET_VALUE(b))
#define NET_EQUAL0(a)	(NET_VALUE(a) == 0)
#define NET_NOTEQ0(a)	(NET_VALUE(a) != 0)


/* 
   AppleTalk Internet Address 
*/

typedef struct at_inet {
	u_short	net;			/* Network Address */
	u_char	node;			/* Node number */
	u_char	socket;			/* Socket number */
} at_inet_t;

/*
   DDP Address for OT
*/

typedef struct ddp_addr {
	at_inet_t	inet;
	u_short		ddptype;
} ddp_addr_t;

/*
  AppleTalk address
*/

struct at_addr {
	u_short     s_net;		/* 16-bit network address */
	u_char      s_node;		/* 8-bit node # (1-0xfd) */
};

/*
  Appletalk sockaddr definition
*/
struct sockaddr_at {
	u_char  	sat_len;        /* total length */
	u_char  	sat_family;     /* address family (AF_APPLETALK) */
	u_char  	sat_port;	/* 8-bit "socket number" */
	struct at_addr 	sat_addr;	/* 16-bit "net" and 8-bit "node */
	char		sat_zero[8];	/* used for netrange in netatalk */
};

#define ATADDR_ANYNET	(u_short)0x0000
#define ATADDR_ANYNODE	(u_char)0x00
#define ATADDR_ANYPORT	(u_char)0x00

#define ATADDR_BCASTNODE (u_char)0xff	/* There is no BCAST for NET */

/* make sure the net, node and socket numbers are in legal range :
 *
 * Net#		0		Local Net
 *		1 - 0xfffe	Legal net nos
 *		0xffff		Reserved by Apple for future use.
 * Node#	0		Illegal
 *		1 - 0x7f	Legal (user node id's)
 *		0x80 - 0xfe	Legal (server node id's; 0xfe illegal in
 *				Phase II nodes)
 *		0xff		Broadcast
 * Socket#	0		Illegal
 *		1 - 0xfe	Legal
 *		0xff		Illegal
 */
#define valid_at_addr(addr) \
	((!(addr) || (addr)->net == 0xffff || (addr)->node == 0 || \
	  (addr)->socket == 0 || (addr)->socket == 0xff)? 0: 1)

/*** * ETHERTYPE_ definitions are in netinet/if_ether.h *** */
#define ETHERTYPE_AT    0x809B          /* AppleTalk protocol */
#define ETHERTYPE_AARP  0x80F3          /* AppleTalk ARP */

/* 
   DDP protocol types 
*/

#define DDP_RTMP          0x01
#define DDP_NBP           0x02
#define DDP_ATP           0x03
#define DDP_ECHO          0x04
#define DDP_RTMP_REQ      0x05
#define DDP_ZIP           0x06
#define DDP_ADSP          0x07

/* 
   Protocols for the socket API 
*/

#define ATPROTO_NONE  	0		/* no corresponding DDP type exists */

#define ATPROTO_ATP	DDP_ATP		/* must match DDP type */
#define ATPROTO_ADSP    DDP_ADSP	/* must match DDP type */

#define ATPROTO_DDP	249		/* *** to be eliminated eventually *** */
#define ATPROTO_LAP   	250 		/* *** to be eliminated eventually *** */

#define ATPROTO_AURP  	251		/* no corresponding DDP type exists */
#define ATPROTO_ASP	252		/* no corresponding DDP type exists */
#define ATPROTO_AFP	253		/* no corresponding DDP type exists */

#define ATPROTO_RAW	255		/* no corresponding DDP type exists */

/*
  Options for use with [gs]etsockopt at the DDP level.
  First word of comment is data type; bool is stored in int.
*/
#define DDP_CHKSUM_ON	1	/* int; default = FALSE;
				   DDP checksums should be used */
#define DDP_HDRINCL	2	/* int; default = FALSE;
				   header is included with data */
#define DDP_GETSOCKNAME	3	/* used to get ddp_addr_t */
#define DDP_SLFSND_ON	4	/* int; default = FALSE;
				   packets sent to the cable-multicast address
				   on this socket will be looped back */
#define DDP_STRIPHDR	5	/* int; default = FALSE;
				   drop DDP header on receive (raw) */

/* 
   AppleTalk protocol retry and timeout 
*/

typedef struct at_retry {
    short	interval;		/* Retry interval in seconds */
    short	retries;		/* Maximum number of retries */
    u_char      backoff;                /* Retry backoff, must be 1 through 4 */
} at_retry_t;

/* 
   Basic NBP Definitions needed for AppleTalk framework
*/

#define MAX_ZONES 50

#define NBP_NVE_STR_SIZE	32	/* Maximum NBP tuple string size */
typedef struct at_nvestr {
	u_char		len;
	u_char		str[NBP_NVE_STR_SIZE];
} at_nvestr_t;

/* Entity Name */
typedef struct at_entity {
	at_nvestr_t	object;
	at_nvestr_t	type;
	at_nvestr_t	zone;
} at_entity_t;

#define NBP_TUPLE_SIZE	((3*NBP_NVE_STR_SIZE)+3) 
			/* 3 for field lengths + 3*32 for three names */
typedef struct at_nbptuple {
	at_inet_t	enu_addr;
	u_char		enu_enum;
	at_entity_t 	enu_entity;
} at_nbptuple_t;

/* 
   Basic ATP Definitions needed for LibcAT 
*/

#define ATP_TRESP_MAX       8	/* Maximum number of Tresp pkts */

/* Response buffer structure for atp_sendreq() and atp_sendrsp() */
typedef	struct	at_resp {
	u_char	bitmap;				/* Bitmap of responses */
	u_char	filler[3];			/* Force 68K to RISC alignment */
	struct	iovec resp[ATP_TRESP_MAX];	/* Buffer for response data */
	long	userdata[ATP_TRESP_MAX];	/* Buffer for response user data */
} at_resp_t;

/* 
   Needed for ASP and ADSP 
*/

typedef struct {
	int  maxlen; /* max buffer length */
	int  len;    /* length of data */
	char *buf;   /* pointer to buffer */
} strbuf_t;

#define	IFID_HOME	1 		/* home port in ifID_table */

#define	ATALK_VALUE(a)		((*(u_long *) &(a))&0x00ffffff)
#define	ATALK_EQUAL(a, b)	(ATALK_VALUE(a) == ATALK_VALUE(b))

#define VERSION_LENGTH		80	/* length of version string */

/* struture containing general information regarding the state of
 * the Appletalk networking 
 */
typedef struct at_state {
	unsigned int	flags;		/* various init flags */
} at_state_t;

/*  at_state_t 'flags' defines */
#define AT_ST_STARTED		0x0001	/* set if protocol is fully enabled */
#define AT_ST_STARTING		0x0002	/* set if interfaces are configured */
#define AT_ST_MULTIHOME		0x0080	/* set if multihome mode */
#define AT_ST_ROUTER		0x0100	/* set if we are a router */
#define AT_ST_IF_CHANGED	0x0200	/* set when state of any I/F 
					   changes (for SNMP) */
#define AT_ST_RT_CHANGED	0x0400  /* route table changed (for SNMP)*/
#define AT_ST_ZT_CHANGED 	0x0800  /* zone table changed (for SNMP) */
#define AT_ST_NBP_CHANGED	0x1000  /* if nbp table changed (for SNMP)*/

#ifdef KERNEL_PRIVATE
extern at_state_t at_state;		/* global state of AT network */

#define ROUTING_MODE	(at_state.flags & AT_ST_ROUTER)
#define MULTIHOME_MODE	(at_state.flags & AT_ST_MULTIHOME)
#define MULTIPORT_MODE (ROUTING_MODE || MULTIHOME_MODE)
#endif /* KERNEL_PRIVATE */

/* defines originally from h/at_elap.h */
#define AT_ADDR			0
#define ET_ADDR			1
#define AT_ADDR_NO_LOOP		2	/* disables packets from looping back */

#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_APPLETALK_H_ */
