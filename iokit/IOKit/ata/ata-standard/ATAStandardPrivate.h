/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 *
 *    ATAPrivate.h
 *
 */

typedef struct EndianTable
{
    UInt32	size;
    UInt32	type;
} EndianTable;

enum 
{
    identifyWords_54to58_Valid 		= 0x0001,
    identifyWords_64to70_Valid 		= 0x0002,
    identifyWords_88to88_Valid 		= 0x0004,

    advPIOModes_Mode3_Supported 	= 0x0001,
    advPIOModes_Mode4_Supported 	= 0x0002,
 
    dmaModes_Mode0_Supported 		= 0x0001,
    dmaModes_Mode1_Supported 		= 0x0002,
    dmaModes_Mode2_Supported 		= 0x0004,
    dmaModes_Supported 			= 0x0007,

    ultraDMAModes_Mode0_Supported	= 0x0001,
    ultraDMAModes_Mode1_Supported	= 0x0002,
    ultraDMAModes_Mode2_Supported	= 0x0004,
    ultraDMAModes_Supported		= 0x001f,

    commandSetsSupported2_ValidMask	= 0xC000,
    commandSetsSupported2_Valid		= 0x4000,
     
    commandSetsSupported2_DMAQueued	= 0x0002,

    commandSetsSupported3_ValidMask	= 0xC000,
    commandSetsSupported3_Valid		= 0x4000,

    commandSetsEnabled2_DMAQueued	= 0x0002,
};

enum 
{
    kATAPIPktProtocolMask		= 0x0060,
    kATAPIPktProtocolSlowDRQ		= 0x0000,
    kATAPIPktProtocolIntDRQ		= 0x0020,
    kATAPIPktProtocolFastDRQ		= 0x0040,
};

typedef struct
{
    UInt32		minDataAccess;
    UInt32		minDataCycle;

} ATAModeTable;

