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
 *    IOATAData.cpp
 *
 */

#include <IOKit/ata/IOATAStandardInterface.h>
#include <IOKit/ata/ata-standard/ATAStandardPrivate.h>

static void  *x;
#define id ((ATAIdentify *)x)

EndianTable  AppleIdentifyEndianTable[] =
{
    { sizeof(id->generalConfiguration), 		sizeof(UInt16)	},
    { sizeof(id->logicalCylinders), 			sizeof(UInt16)	},
    { sizeof(id->reserved_1), 				sizeof(UInt16)	},
    { sizeof(id->logicalHeads), 			sizeof(UInt16)	},
    { sizeof(id->reserved_2), 				sizeof(UInt16)	},
    { sizeof(id->logicalSectorsPerTrack), 		sizeof(UInt16)	},
    { sizeof(id->reserved_3), 				sizeof(UInt16)	},
    { sizeof(id->serialNumber), 			sizeof(UInt8)	},
    { sizeof(id->reserved_4), 				sizeof(UInt16)	},
    { sizeof(id->firmwareRevision), 			sizeof(UInt8)	},
    { sizeof(id->modelNumber), 				sizeof(UInt8)	},
    { sizeof(id->multipleModeSectors), 			sizeof(UInt16)	},
    { sizeof(id->reserved_5), 				sizeof(UInt16)	},
    { sizeof(id->capabilities1), 			sizeof(UInt16)	},
    { sizeof(id->capabilities2), 			sizeof(UInt16)	},
    { sizeof(id->pioMode), 				sizeof(UInt16)	},
    { sizeof(id->reserved_6), 				sizeof(UInt16)	},
    { sizeof(id->validFields), 				sizeof(UInt16)	},
    { sizeof(id->currentLogicalCylinders), 		sizeof(UInt16)	},
    { sizeof(id->currentLogicalHeads), 			sizeof(UInt16)	},
    { sizeof(id->currentLogicalSectorsPerTrack), 	sizeof(UInt16)	},
    { sizeof(id->currentAddressableSectors), 		sizeof(UInt32)	},
    { sizeof(id->currentMultipleModeSectors), 		sizeof(UInt16)	},
    { sizeof(id->userAddressableSectors), 		sizeof(UInt32)	},
    { sizeof(id->reserved_7), 				sizeof(UInt16)	},
    { sizeof(id->dmaModes), 				sizeof(UInt16)	},
    { sizeof(id->advancedPIOModes), 			sizeof(UInt16)	},
    { sizeof(id->minDMACycleTime), 			sizeof(UInt16)	},
    { sizeof(id->recDMACycleTime), 			sizeof(UInt16)	},
    { sizeof(id->minPIOCycleTimeNoIORDY), 		sizeof(UInt16)	},
    { sizeof(id->minPIOCyclcTimeIORDY), 		sizeof(UInt16)	},
    { sizeof(id->reserved_8), 				sizeof(UInt16)	},
    { sizeof(id->busReleaseLatency), 			sizeof(UInt16)	},
    { sizeof(id->serviceLatency), 			sizeof(UInt16)	},
    { sizeof(id->reserved_9), 				sizeof(UInt16)	},
    { sizeof(id->queueDepth), 				sizeof(UInt16)	},
    { sizeof(id->reserved_10), 				sizeof(UInt16)	},
    { sizeof(id->versionMajor),		 		sizeof(UInt16)	},
    { sizeof(id->versionMinor), 			sizeof(UInt16)	},
    { sizeof(id->commandSetsSupported1), 		sizeof(UInt16)	},
    { sizeof(id->commandSetsSupported2), 		sizeof(UInt16)	},
    { sizeof(id->commandSetsSupported3), 		sizeof(UInt16)	},
    { sizeof(id->commandSetsEnabled1), 			sizeof(UInt16)	},
    { sizeof(id->commandSetsEnabled2), 			sizeof(UInt16)	},
    { sizeof(id-> commandSetsDefault), 			sizeof(UInt16)	},
    { sizeof(id->ultraDMAModes), 			sizeof(UInt16)	},
    { sizeof(id->securityEraseTime), 			sizeof(UInt16)	},
    { sizeof(id-> securityEnhancedEraseTime), 		sizeof(UInt16)	},
    { sizeof(id-> currentAdvPowerMgtValue), 		sizeof(UInt16)	},
    { sizeof(id->reserved_11),				sizeof(UInt16)	},
    { sizeof(id->removableMediaSupported),		sizeof(UInt16)	},
    { sizeof(id->securityStatus),			sizeof(UInt16)	},
    { sizeof(id->reserved_12),				sizeof(UInt16)	},
    { 0,						0 		}
};    

ATAModeTable ApplePIOModes[] =
{
    { 165,    600 },	/* Mode 0 */
    { 125,    383 },	/*      1 */ 
    { 100,    240 },	/*      2 */
    {  80,    180 },	/*      3 */
    {  70,    120 }	/*      4 */
};
UInt32 AppleNumPIOModes = (sizeof(ApplePIOModes)/sizeof(ATAModeTable));

ATAModeTable AppleDMAModes[] =
{
    { 215,    480 },	/* Mode 0 */
    {  80,    150 },	/*      1 */
    {  70,    120 }	/*      2 */
};
UInt32 AppleNumDMAModes = (sizeof(AppleDMAModes)/sizeof(ATAModeTable));

ATAModeTable AppleUltraModes[] =
{
    {   0,    114 },	/* Mode 0 */
    {   0,     75 },	/*      1 */
    {   0,     55 },	/*      2 */
    {   100,   45 },	/*      3 */
    {   100,   25 }	/*      4 */
};
UInt32 AppleNumUltraModes = (sizeof(AppleUltraModes)/sizeof(ATAModeTable));

