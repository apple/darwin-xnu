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
#ifndef	_IODVDTYPES_H
#define	_IODVDTYPES_H

#include <IOKit/IOTypes.h>

    enum DVDKeyFormat {
        kCSSAGID		= 0x00,
        kChallengeKey		= 0x01,
        kKey1			= 0x02,
        kKey2			= 0x03,
        kTitleKey		= 0x04,
        kASF			= 0x05,
        kSetRegion		= 0x06,
        kRPCState		= 0x08,
        kCSS2AGID		= 0x10,
        kCPRMAGID		= 0x11,
        kInvalidateAGID		= 0x3f
    };

    enum DVDKeyClass {
        kCSS_CSS2_CPRM		= 0x00,
        kRSSA			= 0x01
    };

    enum DVDMediaType {
        kDVDMediaTypeUnknown   = 0x0200,
        kDVDMediaTypeROM       = 0x0202, /* DVD-ROM */
        kDVDMediaTypeRAM       = 0x0203, /* DVD-RAM */
        kDVDMediaTypeR         = 0x0204, /* DVD-R   */
        kDVDMediaTypeRW        = 0x0205, /* DVD-RW  */
        kDVDMediaTypePlusRW    = 0x0206, /* DVD+RW  */

        kDVDMediaTypeMin       = 0x0200,
        kDVDMediaTypeMax       = 0x02FF
    };
    
#endif
