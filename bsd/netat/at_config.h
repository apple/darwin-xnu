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
 *        Copyright (c) 1988-1993 Apple Computer, Inc.
 */

#ifndef _NETAT_AT_CONFIG_H_
#define	_NETAT_AT_CONFIG_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

/* originally from if_cnt.h
 *
 * defines for if_stat struct. 
 * note: set IF_TYPE_CNT to number of types supported and make sure 
 * 	that defines for those type  are LESS than this value
 */

#define IF_TYPENO_CNT	1	/* number of different types we support */
				/* *** this value was 5, but for now, let's
				   just start with ethernet *** */

/* maximum number of I/F's allowed */
/* *** "17" corresponds to Shiner *** */
#define IF_TOTAL_MAX	17	/* max count of any combination of I/F's */

typedef struct if_types {
	int 	iftype,
		max_interfaces;
} if_types_t;

	/* GET_ZONES defines */
#define GET_ALL_ZONES 			0
#define GET_LOCAL_ZONES_ONLY	 	1

typedef struct if_zone_info {
	at_nvestr_t	zone_name;		/* the zone name & len */
	unsigned	zone_ifs[IF_TYPENO_CNT]; /* bitmapped I/F usage for zone */
	unsigned	zone_home;		/* TRUE for home zone */
} if_zone_info_t;

typedef union if_zone_nve {
	at_nvestr_t	ifnve;
	int		zone;
} if_zone_nve_t;

/* this struct used to obtain local zones for specific
   ifID's from the kernel  and to set default zones for
   specific ifID numbers */
typedef struct if_zone {
	if_zone_nve_t	ifzn;
	char		usage[IF_TOTAL_MAX];	/* I/F usage (1 set if
						   I/F in this zone */
	int		index;			/* zone index in ZT_table */
} if_zone_t;


#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_AT_CONFIG_H_ */
