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
 * ATADevice.h
 *
 */

#ifndef _ATADEVICE_H
#define _ATADEVICE_H

#define kDefaultInquirySize	255

typedef UInt32 ATAUnit;

    
enum ATADeviceTimeouts
{
    kATATimerIntervalmS 	= 500,
    kATAProbeTimeoutmS	 	= 5000,
    kATAResetIntervalmS 	= 3000,
    kATAAbortTimeoutmS  	= 5000,
    kATAReqSenseTimeoutmS	= 5000,
    kATADisableTimeoutmS	= 5000,
    kATAResetPollIntervalmS     = 50,
    kATAResetTimeoutmS		= 25000,
    kATABusyTimeoutmS		= 10,
    kATADRQTimeoutmS		= 10,
};

enum ATAClientMessage
{
    kATAClientMsgNone	 		=  0x00005000,
    kATAClientMsgDeviceAbort,
    kATAClientMsgDeviceReset,
    kATAClientMsgBusReset,
    kATAClientMsgSelectTiming,		

    kATAClientMsgDone			= 0x80000000,
};

enum ATAQueueType
{
    kATAQTypeNormalQ		= 0,
    kATAQTypeBypassQ		= 1,
};

enum ATAQueuePosition
{
    kATAQPositionTail		= 0,
    kATAQPositionHead		= 1,
};


#define kATAPropertyProtocol		"ATA Protocol"			/* IOCString */
#define kATAPropertyDeviceNumber 	"ATA Device Number"    		/* OSNumber  */
#define kATAPropertyDeviceType		"ATA Device Type"		/* IOCString */
#define kATAPropertyDeviceId		"ATA Device Id"			/* OSNumber  */
#define kATAPropertyModelNumber		"ATA Device Model Number"	/* IOCString */
#define kATAPropertyFirmwareRev		"ATA Device Firmware Revision"  /* IOCString */
#define kATAPropertyVendorName		"ATA Device Vendor Name"	/* IOCString */
#define kATAPropertyProductName		"ATA Device Product Name"	/* IOCString */
#define kATAPropertyProductRevision	"ATA Device Product Revision"	/* IOCString */
#define kATAPropertyLocation		"IOUnit"			/* OSNumber  */

#define kATAMaxProperties		9

#define kATAPropertyProtocolATA		"ATA"
#define kATAPropertyProtocolATAPI	"ATAPI"

#define kATADeviceTypeDisk		"Disk"
#define kATADeviceTypeTape		"Tape"
#define kATADeviceTypeCDRom		"CDRom"
#define kATADeviceTypeScanner		"Scanner"
#define kATADeviceTypeOther		"Other"

#endif
