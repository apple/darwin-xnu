/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *
 * ORIGINS: 82
 *
 * (C) COPYRIGHT Apple Computer, Inc. 1992-1996
 * All Rights Reserved
 *
 */                                                                   
/*
 *	Copyright (c) 1988, 1989 Apple Computer, Inc. 
 *
 *	The information contained herein is subject to change without
 *	notice and  should not be  construed as a commitment by Apple
 *	Computer, Inc. Apple Computer, Inc. assumes no responsibility
 *	for any errors that may appear.
 *
 *	Confidential and Proprietary to Apple Computer, Inc.
 */
/*
 * Title:	nbp.h
 *
 * Facility:	Include file for NBP kernel module.
 *
 * Author:	Kumar Vora, Creation Date: May-1-1989
 *
 * History:
 * X01-001	Kumar Vora	May-1-1989
 *	 	Initial Creation.
 */

#ifndef _NETAT_NBP_H_
#define _NETAT_NBP_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

/* NBP packet types */

#define NBP_BRRQ		0x01  	/* Broadcast request */
#define NBP_LKUP    		0x02  	/* Lookup */
#define NBP_LKUP_REPLY		0x03  	/* Lookup reply */
#define NBP_FWDRQ		0x04	/* Forward Request (router only) */

/* *** the following may be discontinued in the near future *** */

#define NBP_CONFIRM   		0x09	/* Confirm, not sent on wire */

#ifdef NOT_USED
#define NBP_REGISTER    	0x07	/* Register a name */
#define NBP_DELETE      	0x08	/* Delete a name */
#define NBP_STATUS_REPLY	0x0a	/* Status on register/delete */
#define	NBP_CLOSE_NOTE		0x0b	/* Close notification from DDP */
#endif

/* *** **************************************************** *** */

/* Protocol defaults */

#define NBP_RETRY_COUNT		8	/* Maximum repeats */
#define NBP_RETRY_INTERVAL	1	/* Retry timeout */

/* Special (partial) wildcard character */
#define	NBP_SPL_WILDCARD	0xC5
#define	NBP_ORD_WILDCARD	'='

/* Packet definitions */

#define NBP_TUPLE_MAX	15	/* Maximum number of tuples in one DDP packet */
#define	NBP_HDR_SIZE	2

typedef struct at_nbp {
#if BYTE_ORDER == BIG_ENDIAN
        unsigned      	
        	control : 4,
        	tuple_count : 4;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
		unsigned
			tuple_count : 4,
			control : 4;
#endif
	u_char		at_nbp_id;
	at_nbptuple_t	tuple[NBP_TUPLE_MAX];
} at_nbp_t;

#define DEFAULT_ZONE(zone) (!(zone)->len || ((zone)->len == 1 && (zone)->str[0] == '*'))

#ifdef KERNEL_PRIVATE

/* Struct for name registry */
typedef struct _nve_ {
	TAILQ_ENTRY(_nve_) nve_link; /* tailq macro glue */
	gbuf_t		*tag;		/*pointer to the parent gbuf_t*/
					/* *** there's no reason why tag has to
					   be an mbuf *** */
	at_nvestr_t	zone;
	u_int		zone_hash;
	at_nvestr_t	object;
	u_int		object_hash;
	at_nvestr_t	type;
	u_int		type_hash;
	at_inet_t	address;
	u_char		ddptype;
	u_char		enumerator;
	int		pid;
	long		unique_nbp_id;	/* long to be compatible with OT */
} nve_entry_t;

#define	NBP_WILD_OBJECT	0x01
#define	NBP_WILD_TYPE	0x02
#define	NBP_WILD_MASK	0x03

struct nbp_req;
typedef	struct nbp_req nbp_req_t;
struct nbp_req	{
	int		(*func)(nbp_req_t *, nve_entry_t *);
	gbuf_t		*response;	/* the response datagram	*/
	int		space_unused;	/* Space available in the resp	*/
					/* packet.			*/
	gbuf_t		*request;	/* The request datagram		*/
					/* Saved for return address	*/
	nve_entry_t	nve;
	u_char		flags;		/* Flags to indicate whether or	*/
					/* not the request tuple has	*/
					/* wildcards in it		*/
};

extern int	nbp_insert_entry(nve_entry_t *);
extern u_int	nbp_strhash (at_nvestr_t *);
extern nve_entry_t *nbp_find_nve(nve_entry_t *);
extern int	nbp_fillin_nve(at_entity_t *, nve_entry_t *);

extern at_nvestr_t *getSPLocalZone(int);
extern at_nvestr_t *getLocalZone(int);

#endif /* KERNEL_PRIVATE */
#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_NBP_H_ */
