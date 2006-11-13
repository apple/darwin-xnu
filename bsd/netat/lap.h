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
 *	Copyright (c) 1988, 1989 Apple Computer, Inc. 
 */

/* Definitions for generic access to AppleTalk link level protocols.
 */

#ifndef _NETAT_LAP_H_
#define _NETAT_LAP_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_OBSOLETE

#define	AT_MID_ELAP	202

/* elap ioctl's */ 

#define	ELAP_IOC_MYIOCTL(i)	((i>>8) == AT_MID_ELAP)
#define	ELAP_IOC_GET_STATS	((AT_MID_ELAP<<8) | 2)

#define	AT_MID_LAP	214

/* Generic LAP ioctl's.  Each LAP may implement other ioctl's specific to
 * its functionality.
 */
#define	LAP_IOC_MYIOCTL(i)	  	((i>>8) == AT_MID_LAP)
#define	LAP_IOC_ADD_ROUTE	   	((AT_MID_LAP<<8) | 9)
#define	LAP_IOC_GET_ZONE		((AT_MID_LAP<<8) | 12)
#define	LAP_IOC_GET_ROUTE		((AT_MID_LAP<<8) | 13)
#define LAP_IOC_SNMP_GET_CFG		((AT_MID_LAP<<8) | 21)
#define LAP_IOC_SNMP_GET_AARP  		((AT_MID_LAP<<8) | 22)
#define LAP_IOC_SNMP_GET_RTMP		((AT_MID_LAP<<8) | 23)
#define LAP_IOC_SNMP_GET_ZIP		((AT_MID_LAP<<8) | 24)
#define LAP_IOC_SNMP_GET_DDP		((AT_MID_LAP<<8) | 25)
#define LAP_IOC_SNMP_GET_NBP		((AT_MID_LAP<<8) | 26)
#define LAP_IOC_SNMP_GET_PORTS		((AT_MID_LAP<<8) | 27)

#ifdef NOT_USED

#define	ELAP_IOC_GET_CFG	((AT_MID_ELAP<<8) | 1)	/* not used */
#define	ELAP_IOC_SET_CFG	((AT_MID_ELAP<<8) | 3)	/* not used */
#define	ELAP_IOC_SET_ZONE	((AT_MID_ELAP<<8) | 4)	/* not used */
#define	ELAP_IOC_SWITCHZONE	((AT_MID_ELAP<<8) | 5)	/* not used */

#define	LAP_IOC_ONLINE		  	((AT_MID_LAP<<8) | 1) /* not used */
#define	LAP_IOC_OFFLINE		  	((AT_MID_LAP<<8) | 2) /* not used */
#define	LAP_IOC_GET_IFS_STAT	  	((AT_MID_LAP<<8) | 3) /* not used */
#define	LAP_IOC_ADD_ZONE  	  	((AT_MID_LAP<<8) | 4) /* not used */
#define	LAP_IOC_ROUTER_START 		((AT_MID_LAP<<8) | 5) /* not used */
#define	LAP_IOC_ROUTER_SHUTDOWN 	((AT_MID_LAP<<8) | 6) /* not used */
#define	LAP_IOC_ROUTER_INIT     	((AT_MID_LAP<<8) | 7) /* not used */
#define	LAP_IOC_GET_IFID		((AT_MID_LAP<<8) | 8) /* not used */
#define	LAP_IOC_GET_DBG			((AT_MID_LAP<<8) | 10) /* not used */
#define	LAP_IOC_SET_DBG			((AT_MID_LAP<<8) | 11) /* not used */
#define	LAP_IOC_ADD_IFNAME		((AT_MID_LAP<<8) | 14) /* not used */
#define	LAP_IOC_DO_DEFER		((AT_MID_LAP<<8) | 15) /* not used */
#define	LAP_IOC_DO_DELAY		((AT_MID_LAP<<8) | 16) /* not used */
#define	LAP_IOC_SHUT_DOWN		((AT_MID_LAP<<8) | 17) /* not used */
#define	LAP_IOC_CHECK_STATE		((AT_MID_LAP<<8) | 18) /* not used */
#define	LAP_IOC_DEL_IFNAME		((AT_MID_LAP<<8) | 19) /* not used */
#define	LAP_IOC_SET_MIX			((AT_MID_LAP<<8) | 20) /* not used */
#define LAP_IOC_SET_LOCAL_ZONES		((AT_MID_LAP<<8) | 28) /* not used */
#define LAP_IOC_GET_LOCAL_ZONE		((AT_MID_LAP<<8) | 29) /* not used */
#define LAP_IOC_IS_ZONE_LOCAL		((AT_MID_LAP<<8) | 30) /* not used */
#define LAP_IOC_GET_MODE		((AT_MID_LAP<<8) | 31) /* not used */
#define LAP_IOC_GET_IF_NAMES		((AT_MID_LAP<<8) | 32) /* not used */
#define LAP_IOC_GET_DEFAULT_ZONE	((AT_MID_LAP<<8) | 33) /* not used */
#define LAP_IOC_SET_DEFAULT_ZONES	((AT_MID_LAP<<8) | 34) /* not used */

#endif /* NOT_USED */

#endif /* __APPLE_API_OBSOLETE */
#endif /*  _NETAT_LAP_H_ */

