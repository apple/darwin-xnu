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
 * @OSF_COPYRIGHT@
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:35  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.9.2  1995/10/09  17:13:48  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:34:10  joe]
 *
 * Revision 1.1.6.1  1995/05/11  20:57:18  burke
 * 	Update ETAP changes.
 * 	[1995/05/09  17:15:03  burke]
 * 
 * Revision 1.1.9.1  1995/09/18  19:13:34  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:34:10  joe]
 * 
 * Revision 1.1.6.1  1995/05/11  20:57:18  burke
 * 	Update ETAP changes.
 * 	[1995/05/09  17:15:03  burke]
 * 
 * Revision 1.1.3.1  1994/12/14  18:55:51  joe
 * 	ETAP nswc merge
 * 	[1994/12/14  17:07:33  joe]
 * 
 * Revision 1.1.1.2  1994/12/12  15:34:48  joe
 * 	Initial check-in
 * 
 * $EndLog$
 */
/*
 *  ETAP build options are selected using the config.debug configuration file.
 *
 *  ETAP options are:
 *	ETAP_LOCK_ACCUMULATE	- Cumulative lock tracing
 *	ETAP_LOCK_MONITOR	- Monitor lock behavior
 *	ETAP_EVENT_MONITOR	- Monitor general events
 *
 * Derived options are:
 *	ETAP_LOCK_TRACE		- Equals one if either cumulative or monitored
 *				  lock tracing is configured (zero otherwise).
 *	ETAP_MONITOR		- Equals one if either lock or event monitoring
 *				  is configured (zero otherwise).
 */

#ifndef	_KERN_ETAP_OPTIONS_H_
#define _KERN_ETAP_OPTIONS_H_

#ifdef ETAP_DYNAMIC_OPTIONS
#include <etap.h>
#include <etap_lock_monitor.h>
#include <etap_lock_accumulate.h>
#include <etap_event_monitor.h>
#else
#define ETAP 0
#define ETAP_LOCK_MONITOR 0
#define ETAP_LOCK_ACCUMULATE 0
#define ETAP_EVENT_MONITOR 0
#endif

#if	ETAP_LOCK_MONITOR || ETAP_LOCK_ACCUMULATE
#define	ETAP_LOCK_TRACE		1
#else	/* ETAP_LOCK_MONITOR || ETAP_LOCK_ACCUMULATE */
#define	ETAP_LOCK_TRACE		0		
#endif  /* ETAP_LOCK_MONITOR || ETAP_LOCK_ACCUMULATE */

#if	ETAP_LOCK_MONITOR || ETAP_EVENT_MONITOR
#define ETAP_MONITOR		1
#else	/* ETAP_LOCK_MONITOR || ETAP_EVENT_MONITOR */
#define ETAP_MONITOR		0
#endif	/* ETAP_LOCK_MONITOR || ETAP_EVENT_MONITOR */

#endif	/* _KERN_ETAP_OPTIONS_H_ */
