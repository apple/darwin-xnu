/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

/*
 * ieee8023ad.h
 */

/* 
 * Modification History
 *
 * May 14, 2004	Dieter Siegmund (dieter@apple.com)
 * - created
 */


#ifndef _NET_IEEE8023AD_H_
#define	_NET_IEEE8023AD_H_

#include <sys/types.h>

#define IEEE8023AD_SLOW_PROTO_ETHERTYPE				0x8809
#define IEEE8023AD_SLOW_PROTO_MULTICAST { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 }

#define IEEE8023AD_SLOW_PROTO_SUBTYPE_LACP			1
#define IEEE8023AD_SLOW_PROTO_SUBTYPE_LA_MARKER_PROTOCOL	2
#define IEEE8023AD_SLOW_PROTO_SUBTYPE_RESERVED_START		3
#define IEEE8023AD_SLOW_PROTO_SUBTYPE_RESERVED_END		10
#endif _NET_IEEE8023AD_H_
