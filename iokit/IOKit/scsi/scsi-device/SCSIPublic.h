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
 *	SCSIPublic.h
 *
 */

#ifndef _SCSIPUBLIC_H
#define _SCSIPUBLIC_H

typedef struct _SCSIInquiry
{
    unsigned char   devType;		/*	0 Device type,		*/
    unsigned char   devTypeMod;		/*	1 Device type modifier	*/
    unsigned char   version;		/*	2 ISO/ECMA/ANSI version */
    unsigned char   format;		/*	3 Response data format	*/
    unsigned char   length;		/*	4 Additional Length	*/
    unsigned char   reserved5;		/*	5 Reserved		*/
    unsigned char   reserved6;		/*	6 Reserved		*/
    unsigned char   flags;		/*	7 Capability flags	*/
    unsigned char   vendorName[8];	/*	8-15 Vendor-specific	*/
    unsigned char   productName[16];	/* 16-31 Product id		*/
    unsigned char   productRevision[4];	/* 32-35 Product revision	*/
    unsigned char   vendorSpecific[20];	/* 36-55 Vendor stuff		*/
    unsigned char   scsi3Options;       /*    56 SCSI-3 options         */
    unsigned char   moreReserved[39];	/* 57-95 Reserved		*/
} SCSIInquiry;

/*
 * These are device type qualifiers. We need them to distinguish between "unknown"
 * and "missing" devices.
 */
enum 
{
    kSCSIDevTypeQualifierConnected  	= 0x00, /* Exists and is connected	*/
    kSCSIDevTypeQualifierNotConnected 	= 0x20, /* Logical unit exists	*/
    kSCSIDevTypeQualifierReserved   	= 0x40,
    kSCSIDevTypeQualifierMissing    	= 0x60, /* No such logical unit	*/
    kSCSIDevTypeQualifierVendorSpecific = 0x80, /* Non-standardized	*/
    kSCSIDevTypeQualifierMask	    	= 0xE0,
};

enum
{
    kSCSIDevTypeModRemovable		= 0x80, /* Device has removable media */
};

enum _SCSIDevFlags 
{
    kSCSIDevCapRelAdr			= 0x80,
    kSCSIDevCapWBus32			= 0x40,
    kSCSIDevCapWBus16			= 0x20,
    kSCSIDevCapSync			= 0x10,
    kSCSIDevCapLinked			= 0x08,
    kSCSIDevCapCmdQue			= 0x02,
    kSCSIDevCapSftRe			= 0x01,
};

typedef struct _SCSISenseData
{
    unsigned char   errorCode;		    /*     0 Result validity	*/
    unsigned char   segmentNumber;	    /*     1 Segment number	*/
    unsigned char   senseKey;		    /*     2 Sense code, flags	*/
    unsigned char   info[4];		    /*   3-6 Sense-key specific	*/
    unsigned char   additionalSenseLength;  /*     7 Sense length info	*/
    unsigned char   reservedForCopy[4];	    /*  8-11 Sense-key specific	*/
    unsigned char   additionalSenseCode;    /*    12 What kind of error	*/
    unsigned char   additionalSenseQualifier; /*  13 More error info	*/
    unsigned char   fruCode;		    /*    14 Field replacable	*/
    unsigned char   senseKeySpecific[2];    /* 15-16 Additional info	*/
    unsigned char   additional[101];	    /* 17-26 Additional info	*/
} SCSISenseData;

/*
 * The high-bit of errorCode signals whether there is a logical
 * block. The low value signals whether there is a valid sense
 */
enum _SCSIErrorCode
{
    kSCSISenseHasLBN			= 0x80,	/* Logical block number set	*/
    kSCSISenseInfoValid	 		= 0x70,	/* Is sense key valid?		*/
    kSCSISenseInfoMask			= 0x70,	/* Mask for sense info		*/
    kSCSISenseCurrentErr		= 0x70,	/* Error code (byte 0 & 0x7F	*/
    kSCSISenseDeferredErr		= 0x71,	/* Error code (byte 0 & 0x7F	*/
};

/*
 * These bits may be set in the sense key
 */
enum _SCSISenseKeyMasks
{
    kSCSISenseKeyMask			= 0x0F,
    kSCSISenseILI			= 0x20,	/* Illegal logical Length	*/
    kSCSISenseEOM			= 0x40,	/* End of media			*/
    kSCSISenseFileMark			= 0x80,	/* End of file mark		*/
};
/*
 * SCSI sense codes. (Returned after request sense).
 */
enum _SCSISenseKeys
{
    kSCSISenseNone			= 0x00,	/* No error			*/
    kSCSISenseRecoveredErr		= 0x01, /* Warning			*/
    kSCSISenseNotReady			= 0x02,	/* Device not ready		*/
    kSCSISenseMediumErr			= 0x03, /* Device medium error		*/
    kSCSISenseHardwareErr		= 0x04, /* Device hardware error	*/
    kSCSISenseIllegalReq		= 0x05, /* Illegal request for dev.	*/
    kSCSISenseUnitAtn			= 0x06,	/* Unit attention (not err)	*/
    kSCSISenseDataProtect		= 0x07, /* Data protection		*/
    kSCSISenseBlankCheck		= 0x08, /* Tape-specific error		*/
    kSCSISenseVendorSpecific 		= 0x09,	/* Vendor-specific error	*/
    kSCSISenseCopyAborted		= 0x0a, /* Copy request cancelled	*/
    kSCSISenseAbortedCmd		= 0x0b, /* Initiator aborted cmd.	*/
    kSCSISenseEqual			= 0x0c,	/* Comparison equal		*/
    kSCSISenseVolumeOverflow 		= 0x0d,	/* Write past end mark		*/
    kSCSISenseMiscompare		= 0x0e, /* Comparison failed		*/
};

enum _SCSIStatus
{
    kSCSIStatusGood			= 0x00,
    kSCSIStatusCheckCondition		= 0x02,
    kSCSIStatusConditionMet		= 0x04,
    kSCSIStatusBusy			= 0x08,
    kSCSIStatusIntermediate		= 0x10,
    kSCSIStatusIntermediateMet		= 0x0a,
    kSCSIStatusReservationConfict	= 0x18,
    kSCSIStatusCommandTerminated	= 0x22,
    kSCSIStatusQueueFull		= 0x28,
};


enum _SCSIDevTypes
{
    kSCSIDevTypeDirect			= 0,	/* Hard disk (not CD-ROM)	*/
    kSCSIDevTypeSequential,			/* Magtape or DAT		*/
    kSCSIDevTypePrinter,			/* Printer			*/
    kSCSIDevTypeProcessor,			/* Attached processor		*/
    kSCSIDevTypeWorm,				/* Write-once, read multiple	*/
    kSCSIDevTypeCDROM,				/* CD-ROM			*/
    kSCSIDevTypeScanner,			/* Scanner			*/
    kSCSIDevTypeOptical,			/* Optical disk			*/
    kSCSIDevTypeChanger,			/* Jukebox			*/
    kSCSIDevTypeComm,				/* Communication link		*/
    kSCSIDevTypeGraphicArts0A,
    kSCSIDevTypeGraphicArts0B,
    kSCSIDevTypeFirstReserved,			/* Reserved sequence start	*/
    kSCSIDevTypeUnknownOrMissing 	= 0x1F,
    kSCSIDevTypeMask			= 0x1F,
};

enum _SCSIInqVersion
{
    kSCSIInqVersionSCSI3		= 0x03,
};

enum _SCSI3Options
{
    kSCSI3InqOptionIUS			= 0x01,
    kSCSI3InqOptionQAS			= 0x02,
    kSCSI3InqOptionClockDT		= 0x04,
};


/*
 * SCSI command codes. Commands defined as ...6, ...10, ...12, are
 * six-byte, ten-byte, and twelve-byte variants of the indicated command.
 */

/*
 * These commands are supported for all devices.
 */
enum _SCSICmds
{
     kSCSICmdChangeDefinition    	= 0x40,
     kSCSICmdCompare		    	= 0x39,
     kSCSICmdCopy		    	= 0x18,
     kSCSICmdCopyAndVerify	    	= 0x3a,
     kSCSICmdInquiry		    	= 0x12,
     kSCSICmdLogSelect	    		= 0x4c,
     kSCSICmdLogSense	    		= 0x4d,
     kSCSICmdModeSelect12	    	= 0x55,
     kSCSICmdModeSelect6	    	= 0x15,
     kSCSICmdModeSense12	    	= 0x5a,
     kSCSICmdModeSense6	    		= 0x1a,
     kSCSICmdReadBuffer	    		= 0x3c,
     kSCSICmdRecvDiagResult	    	= 0x1c,
     kSCSICmdRequestSense	    	= 0x03,
     kSCSICmdSendDiagnostic	    	= 0x1d,
     kSCSICmdTestUnitReady	    	= 0x00,
     kSCSICmdWriteBuffer	    	= 0x3b,

/*
 * These commands are supported by direct-access devices only.
 */
     kSCSICmdFormatUnit	    		= 0x04,
     kSCSICmdLockUnlockCache	   	= 0x36,
     kSCSICmdPrefetch	    	    	= 0x34,
     kSCSICmdPreventAllowRemoval  	= 0x1e,
     kSCSICmdRead6		    	= 0x08,
     kSCSICmdRead10		    	= 0x28,
     kSCSICmdReadCapacity	    	= 0x25,
     kSCSICmdReadDefectData	    	= 0x37,
     kSCSICmdReadLong	            	= 0x3e,
     kSCSICmdReassignBlocks	    	= 0x07,
     kSCSICmdRelease		    	= 0x17,
     kSCSICmdReserve		    	= 0x16,
     kSCSICmdRezeroUnit	    		= 0x01,
     kSCSICmdSearchDataEql	    	= 0x31,
     kSCSICmdSearchDataHigh	    	= 0x30,
     kSCSICmdSearchDataLow	    	= 0x32,
     kSCSICmdSeek6		    	= 0x0b,
     kSCSICmdSeek10		    	= 0x2b,
     kSCSICmdSetLimits	    		= 0x33,
     kSCSICmdStartStopUnit	    	= 0x1b,
     kSCSICmdSynchronizeCache     	= 0x35,
     kSCSICmdVerify		    	= 0x2f,
     kSCSICmdWrite6		    	= 0x0a,
     kSCSICmdWrite10		    	= 0x2a,
     kSCSICmdWriteAndVerify	    	= 0x2e,
     kSCSICmdWriteLong	    		= 0x3f,
     kSCSICmdWriteSame	    		= 0x41,

/*
 * These commands are supported by sequential devices.
 */
     kSCSICmdRewind		    	= 0x01,
     kSCSICmdWriteFilemarks	    	= 0x10,
     kSCSICmdSpace		    	= 0x11,
     kSCSICmdLoadUnload	    		= 0x1B,
/*
 * ANSI SCSI-II for CD-ROM devices.
 */
     kSCSICmdReadCDTableOfContents	= 0x43,
};

/*
 * Message codes (for Msg In and Msg Out phases).
 */
enum _SCSIMsgs
{
    kSCSIMsgAbort		    	= 0x06,
    kSCSIMsgAbortTag	    		= 0x0d,
    kSCSIMsgBusDeviceReset	    	= 0x0c,
    kSCSIMsgClearQueue	     		= 0x0e,
    kSCSIMsgCmdComplete	    		= 0x00,
    kSCSIMsgDisconnect	    		= 0x04,
    kSCSIMsgIdentify	    		= 0x80,
    kSCSIMsgIgnoreWideResdue    	= 0x23,
    kSCSIMsgInitiateRecovery    	= 0x0f,
    kSCSIMsgInitiatorDetectedErr 	= 0x05,
    kSCSIMsgLinkedCmdComplete    	= 0x0a,
    kSCSIMsgLinkedCmdCompleteFlag 	= 0x0b,
    kSCSIMsgParityErr	     		= 0x09,
    kSCSIMsgRejectMsg	     		= 0x07,
    kSCSIMsgModifyDataPtr	    	= 0x00, /* Extended msg	*/
    kSCSIMsgNop		     		= 0x08,
    kSCSIMsgHeadOfQueueTag	    	= 0x21, /* Two byte msg	*/
    kSCSIMsgOrderedQueueTag	     	= 0x22, /* Two byte msg	*/
    kSCSIMsgSimpleQueueTag	   	= 0x20, /* Two byte msg	*/
    kSCSIMsgReleaseRecovery	     	= 0x10,
    kSCSIMsgRestorePointers	   	= 0x03,
    kSCSIMsgSaveDataPointers     	= 0x02,
    kSCSIMsgSyncXferReq	     		= 0x01, /* Extended msg	*/
    kSCSIMsgWideDataXferReq	  	= 0x03, /* Extended msg	*/
    kSCSIMsgTerminateIOP	     	= 0x11,
    kSCSIMsgExtended	     		= 0x01,
    kSCSIMsgEnableDisconnectMask  	= 0x40,
};

#endif
