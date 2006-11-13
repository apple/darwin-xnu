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

#ifndef _NETAT_ZIP_H_
#define	_NETAT_ZIP_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

/* Definitions for ZIP, per AppleTalk Zone Information Protocol
 * documentation from `Inside AppleTalk', July 14, 1986.
 */

/* ZIP packet types */

#define ZIP_QUERY         	1  	/* ZIP zone query packet */
#define ZIP_REPLY           	2  	/* ZIP query reply packet */
#define ZIP_TAKEDOWN        	3  	/* ZIP takedown packet */
#define ZIP_BRINGUP        	4  	/* ZIP bringup packet */
#define ZIP_GETNETINFO		5	/* ZIP DDP get net info packet */
#define	ZIP_NETINFO_REPLY	6	/* ZIP GetNetInfo Reply */
#define ZIP_NOTIFY		7	/* Notification of zone name change */
#define ZIP_EXTENDED_REPLY	8	/* ZIP extended query reply packet */ 

#define ZIP_GETMYZONE    	7  	/* ZIP ATP get my zone packet */
#define ZIP_GETZONELIST    	8  	/* ZIP ATP get zone list packet */
#define	ZIP_GETLOCALZONES	9	/* ZIP ATP get cable list packet*/

#define ZIP_HDR_SIZE		2
#define	ZIP_DATA_SIZE		584


#define ZIP_MAX_ZONE_LENGTH	32	/* Max length for a Zone Name */

typedef	struct at_zip {
	u_char	command;
	u_char	flags;
	char	data[ZIP_DATA_SIZE];
} at_zip_t;

#define	 ZIP_ZIP(c)	((at_zip_t *)(&((at_ddp_t *)(c))->data[0]))

typedef struct {
	char		command;
	char		flags;
	at_net		cable_range_start;
	at_net		cable_range_end;
	u_char		data[1];
} at_x_zip_t;

#define	ZIP_X_HDR_SIZE	6

/* flags for ZipNetInfoReply packet */
#define	ZIP_ZONENAME_INVALID	0x80
#define	ZIP_USE_BROADCAST	0x40
#define	ZIP_ONE_ZONE		0x20

#define	ZIP_NETINFO_RETRIES	3
#define	ZIP_TIMER_INT		HZ	/* HZ defined in param.h */

/* ZIP control codes */
#define	ZIP_ONLINE		1
#define ZIP_LATE_ROUTER		2
#define	ZIP_NO_ROUTER		3

#define ZIP_RE_AARP		-1

#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_ZIP_H_ */
