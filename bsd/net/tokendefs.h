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
/* 	Copyright (c) 1991 NeXT Computer, Inc.  All rights reserved. 
 *
 * tokendefs.h - Token-Ring MAC header definitions.  
 *
 * HISTORY
 * 8-Oct-92  Joel Greenblatt at NeXT
 * 	created 
 */
#ifndef _NET_TOKENDEFS_H_
#define _NET_TOKENDEFS_H_


#include <sys/errno.h>

/*
 * Token ring address - 6 octets
 */
#define NUM_TR_ADDR_BYTES	6

struct token_addr {
	u_char	token_addr_octet[NUM_TR_ADDR_BYTES];
};

#define ta_byte token_addr_octet

typedef struct token_addr token_addr_t;

/*
 * MAC header size
 */
#define MAC_HDR_MIN	(1+1+6+6)		/* MAC hdr size w/o ri field */
#define MAC_HDR_MAX	(MAC_HDR_MIN + RISIZE) 	/* MAC hdr size w/max ri */

/*
 * The maximum size of the MAC information field as spec'd by ISO 8802/5.
 */
#define MAC_INFO_4MB	4472	/* max size of mac info field -- 4 Mbs */
#define MAC_INFO_16MB	17800	/* max size of mac info field -- 16 Mbs */

/*
 * Maximum DMA packet sizes for 4 & 16 Mbit assuming no CRC.
 */ 
#define MAC_DMA_MAX_4MB	  (MAC_HDR_MAX + MAC_INFO_4MB)
#define MAC_DMA_MAX_16MB  (MAC_HDR_MAX + MAC_INFO_16MB)

/* 
 * Routing control field.
 */
typedef struct	{

#if	__BIG_ENDIAN__
	   unsigned char bcast  : 3,		/* broadcast */
	   		 len    : 5;		/* length */
	   unsigned char dir    : 1,		/* direction */
	   		 longf  : 3,		/* longest frame */
	   		 rsrvd  : 4;		/* reserved */

#elif	__LITTLE_ENDIAN__
	  unsigned char  len    : 5,		/* length */
	   	         bcast  : 3;		/* broadcast */
	  unsigned char  rsrvd  : 4,		/* reserved */
	   		 longf  : 3,		/* longest frame */
	   		 dir    : 1;		/* direction */
#else
   error
#endif
} routing_ctl_t;		

/* bcast field ... */
#define  BI_SPECIFIC	0	/* b'0xx': non-broadcast (specific route) */
#define  BI_AR_BCAST	4	/* b'10x': all-routes broadcast */
#define  BI_SR_BCAST 	6	/* b'11x': single-route broadcast */

/* 
 * longf field 
 */
#define  LF_S516	0
#define  LF_S1500	1
#define  LF_S2052	2
#define  LF_S4472	3
#define  LF_S8144	4
#define  LF_S11407	5
#define  LF_S17800	6
#define  LF_BCAST	7	/* All-routes broadcast */

#define LFB_4MB		LF_S4472	/* encoded max info -- 4 Mb */
#define LFB_16MB	LF_S17800	/* encoded max info -- 16 Mb */

/*
 * Source Routing field (2-18 bytes, must be even)
 */

#define RISIZE         18	/* max size (bytes) of 802.5 routing field */

typedef	struct	{
	routing_ctl_t	rc;			 
	u_char 		sn[RISIZE-sizeof(routing_ctl_t)];   
} sroute_t;

/*
 * Token Ring MAC header  (IEEE 802.5, ISO 8802/5)
 */

#define TR_DA_SIZE	6

typedef	struct	{
	u_char	 	ac;		/* PPPTMRRR;  PPP = token priority */
	u_char	 	fc;		/* FFrrZZZZ;  FF = frame type */
#define	TR_FC_MASK 	0xc0		/* mask for frame-type */
#define	TR_FC_MAC 	0x00		/* frame-type = mac frame */
#define	TR_FC_DATA 	0x40		/* frame-type = non-mac (data frame) */
	u_char	 	da[TR_DA_SIZE];	/* destination address */
	u_char	 	sa[TR_DA_SIZE];	/* source address */
#define TR_RII		0x80		/* routing info indicator bit */
	sroute_t 	ri;		/* routing information field */
} tokenHeader_t;

/*
 * token-ring netif definitions
 */
#define IFTYPE_TOKENRING	"4/16Mb Token-Ring"	/* netif type-string */

/*
 * Error codes
 */
#define	TRINGDOWN	ENETDOWN 	/* interface down */
#define TNOBUFS		ENOBUFS 	/* transmit queue full error */
#define TBADDA		EINVAL 		/* bad dest addr */
#define TBADFSIZE	EMSGSIZE 	/* bad frame size */

#endif /* ! _NET_TOKENDEFS_H_ */
