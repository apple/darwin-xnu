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

/*
 *	Copyright (c) 1988, 1989 Apple Computer, Inc. 
 */

#ifndef _NETAT_AT_PAT_H_
#define _NETAT_AT_PAT_H_
#include <sys/appleapiopts.h>

/* This is header for the PAT module. This contains a table of pointers that 
 * should get initialized with the BNET stuff and the ethernet driver. The 
 * number of interfaces supported should be communicated. Should include
 * mbuf.h, if.h, socket.h
 *
 * Author: R. C. Venkatraman
 * Date  : 2/29/88 
 */

typedef struct {
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short len;
} enet_header_t;

typedef struct {
	unsigned char dst_sap;
	unsigned char src_sap;
	unsigned char control;
	unsigned char protocol[5];
} llc_header_t;

#define ENET_LLC_SIZE (sizeof(enet_header_t)+sizeof(llc_header_t))
#define SNAP_UI		0x03  /* bits 11000000 reversed!! */
#define SNAP_AT_SAP	0xaa
#define SNAP_PROTO_AT	{0x08, 0x00, 0x07, 0x80, 0x9B}
#define SNAP_PROTO_AARP	{0x00, 0x00, 0x00, 0x80, 0xF3}
#define SNAP_HDR_AT	{SNAP_AT_SAP, SNAP_AT_SAP, SNAP_UI, SNAP_PROTO_AT}
#define SNAP_HDR_AARP	{SNAP_AT_SAP, SNAP_AT_SAP, SNAP_UI, SNAP_PROTO_AARP}

#define LLC_PROTO_EQUAL(a1, a2)                                         \
        ((*((unsigned long *)(a1)) == *((unsigned long *)(a2))) &&      \
	 (a1[4] == a2[4])				                \
	)
#endif /* _NETAT_AT_PAT_H_ */
