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
 *	ATAPublic.h
 *
 */

#ifndef _ATAPUBLIC_H
#define _ATAPUBLIC_H

typedef struct ATAIdentify
{
    UInt16	generalConfiguration;
    UInt16	logicalCylinders;
    UInt16	reserved_1[1];
    UInt16	logicalHeads;
    UInt16	reserved_2[2];
    UInt16	logicalSectorsPerTrack;    
    UInt16	reserved_3[3];
    char	serialNumber[20];
    UInt16	reserved_4[3];
    char        firmwareRevision[8];
    char	modelNumber[40];
    UInt16	multipleModeSectors;
    UInt16	reserved_5[1];
    UInt16	capabilities1;
    UInt16	capabilities2;
    UInt16	pioMode;
    UInt16	reserved_6[1];
    UInt16	validFields;
    UInt16	currentLogicalCylinders;
    UInt16	currentLogicalHeads;
    UInt16	currentLogicalSectorsPerTrack;
    UInt16	currentAddressableSectors[2];
    UInt16	currentMultipleModeSectors;
    UInt16	userAddressableSectors[2];
    UInt16	reserved_7[1];
    UInt16	dmaModes;
    UInt16	advancedPIOModes;
    UInt16	minDMACycleTime;
    UInt16	recDMACycleTime;
    UInt16	minPIOCycleTimeNoIORDY;
    UInt16	minPIOCyclcTimeIORDY;
    UInt16	reserved_8[2];
    UInt16	busReleaseLatency;
    UInt16	serviceLatency;
    UInt16	reserved_9[2];
    UInt16	queueDepth;
    UInt16	reserved_10[4];
    UInt16	versionMajor;
    UInt16	versionMinor;
    UInt16	commandSetsSupported1;
    UInt16	commandSetsSupported2;
    UInt16	commandSetsSupported3;
    UInt16	commandSetsEnabled1;
    UInt16	commandSetsEnabled2;
    UInt16	commandSetsDefault;
    UInt16	ultraDMAModes;
    UInt16	securityEraseTime;
    UInt16	securityEnhancedEraseTime;
    UInt16	currentAdvPowerMgtValue;
    UInt16	reserved_11[35];
    UInt16	removableMediaSupported;
    UInt16	securityStatus;
    UInt16      reserved_12[127];
} ATAIdentify;



typedef struct ATAPIInquiry
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
    unsigned char   moreReserved[40];	/* 56-95 Reserved		*/
} ATAInquiry;

/*
 * These are device type qualifiers. We need them to distinguish between "unknown"
 * and "missing" devices.
 */
enum 
{
    kATAPIDevTypeQualifierConnected  	= 0x00, /* Exists and is connected	*/
    kATAPIDevTypeQualifierNotConnected 	= 0x20, /* Logical unit exists	*/
    kATAPIDevTypeQualifierReserved   	= 0x40,
    kATAPIDevTypeQualifierMissing    	= 0x60, /* No such logical unit	*/
    kATAPIDevTypeQualifierVendorSpecific = 0x80, /* Non-standardized	*/
    kATAPIDevTypeQualifierMask	    	= 0xE0,
};

enum ATAPIDevFlags 
{
    kATAPIDevCapRelAdr			= 0x80,
    kATAPIDevCapWBus32			= 0x40,
    kATAPIDevCapWBus16			= 0x20,
    kATAPIDevCapSync			= 0x10,
    kATAPIDevCapLinked			= 0x08,
    kATAPIDevCapCmdQue			= 0x02,
    kATAPIDevCapSftRe			= 0x01,
};

typedef struct ATAPISenseData
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
} ATASenseData;

/*
 * The high-bit of errorCode signals whether there is a logical
 * block. The low value signals whether there is a valid sense
 */
enum ATAErrorCode
{
    kATAPISenseHasLBN			= 0x80,	/* Logical block number set	*/
    kATAPISenseInfoValid	 	= 0x70,	/* Is sense key valid?		*/
    kATAPISenseInfoMask			= 0x70,	/* Mask for sense info		*/
    kATAPISenseCurrentErr		= 0x70,	/* Error code (byte 0 & 0x7F	*/
    kATAPISenseDeferredErr		= 0x71,	/* Error code (byte 0 & 0x7F	*/
};

/*
 * These bits may be set in the sense key
 */
enum ATAPISenseKeyMasks
{
    kATAPISenseKeyMask			= 0x0F,
    kATAPISenseILI			= 0x20,	/* Illegal logical Length	*/
    kATAPISenseEOM			= 0x40,	/* End of media			*/
    kATAPISenseFileMark			= 0x80,	/* End of file mark		*/
};
/*
 * ATA sense codes. (Returned after request sense).
 */
enum ATAPISenseKeys
{
    kATAPISenseNone			= 0x00,	/* No error			*/
    kATAPISenseRecoveredErr		= 0x01, /* Warning			*/
    kATAPISenseNotReady			= 0x02,	/* Device not ready		*/
    kATAPISenseMediumErr		= 0x03, /* Device medium error		*/
    kATAPISenseHardwareErr		= 0x04, /* Device hardware error	*/
    kATAPISenseIllegalReq		= 0x05, /* Illegal request for dev.	*/
    kATAPISenseUnitAtn			= 0x06,	/* Unit attention (not err)	*/
    kATAPISenseDataProtect		= 0x07, /* Data protection		*/
    kATAPISenseBlankCheck		= 0x08, /* Tape-specific error		*/
    kATAPISenseVendorSpecific 		= 0x09,	/* Vendor-specific error	*/
    kATAPISenseCopyAborted		= 0x0a, /* Copy request cancelled	*/
    kATAPISenseAbortedCmd		= 0x0b, /* Initiator aborted cmd.	*/
    kATAPISenseEqual			= 0x0c,	/* Comparison equal		*/
    kATAPISenseVolumeOverflow 		= 0x0d,	/* Write past end mark		*/
    kATAPISenseMiscompare		= 0x0e, /* Comparison failed		*/
};

enum ATAPIStatus
{
    kATAPIStatusGood			= 0x00,
    kATAPIStatusCheckCondition		= 0x02,
    kATAPIStatusConditionMet		= 0x04,
    kATAPIStatusBusy			= 0x08,
    kATAPIStatusIntermediate		= 0x10,
    kATAPIStatusIntermediateMet		= 0x0a,
    kATAPIStatusReservationConfict	= 0x18,
    kATAPIStatusCommandTerminated	= 0x22,
    kATAPIStatusQueueFull		= 0x28,
};


enum ATAPIDevTypes
{
    kATAPIDevTypeDirect		= 0,	/* Hard disk (not CD-ROM)	*/
    kATAPIDevTypeSequential,		/* Magtape or DAT		*/
    kATAPIDevTypePrinter,		/* Printer			*/
    kATAPIDevTypeProcessor,		/* Attached processor		*/
    kATAPIDevTypeWorm,			/* Write-once, read multiple	*/
    kATAPIDevTypeCDROM,			/* CD-ROM			*/
    kATAPIDevTypeScanner,		/* Scanner			*/
    kATAPIDevTypeOptical,		/* Optical disk			*/
    kATAPIDevTypeChanger,		/* Jukebox			*/
    kATAPIDevTypeComm,			/* Communication link		*/
    kATAPIDevTypeGraphicArts0A,
    kATAPIDevTypeGraphicArts0B,
    kATAPIDevTypeFirstReserved,		/* Reserved sequence start	*/
    kATAPIDevTypeUnknownOrMissing = 0x1F,
    kATAPIDevTypeMask		= 0x1F,
};


/*
 * ATA command codes. Commands defined as ...6, ...10, ...12, are
 * six-byte, ten-byte, and twelve-byte variants of the indicated command.
 */

/*
 * These commands are supported for all devices.
 */
enum ATAPICmds
{
     kATAPICmdChangeDefinition    	= 0x40,
     kATAPICmdCompare		    	= 0x39,
     kATAPICmdCopy		    	= 0x18,
     kATAPICmdCopyAndVerify	    	= 0x3a,
     kATAPICmdInquiry		    	= 0x12,
     kATAPICmdLogSelect	    		= 0x4c,
     kATAPICmdLogSense	    		= 0x4d,
     kATAPICmdModeSelect12	    	= 0x55,
     kATAPICmdModeSelect6	    	= 0x15,
     kATAPICmdModeSense12	    	= 0x5a,
     kATAPICmdModeSense6	    	= 0x1a,
     kATAPICmdReadBuffer	    	= 0x3c,
     kATAPICmdRecvDiagResult	    	= 0x1c,
     kATAPICmdRequestSense	    	= 0x03,
     kATAPICmdSendDiagnostic	    	= 0x1d,
     kATAPICmdTestUnitReady	    	= 0x00,
     kATAPICmdWriteBuffer	    	= 0x3b,

/*
 * These commands are supported by direct-access devices only.
 */
     kATAPICmdFormatUnit	    	= 0x04,
     kATAPICmdLockUnlockCache	   	= 0x36,
     kATAPICmdPrefetch	    	    	= 0x34,
     kATAPICmdPreventAllowRemoval  	= 0x1e,
     kATAPICmdRead6		    	= 0x08,
     kATAPICmdRead10		    	= 0x28,
     kATAPICmdReadCapacity	    	= 0x25,
     kATAPICmdReadDefectData	    	= 0x37,
     kATAPICmdReadLong	            	= 0x3e,
     kATAPICmdReassignBlocks	    	= 0x07,
     kATAPICmdRelease		    	= 0x17,
     kATAPICmdReserve		    	= 0x16,
     kATAPICmdRezeroUnit	    	= 0x01,
     kATAPICmdSearchDataEql	    	= 0x31,
     kATAPICmdSearchDataHigh	    	= 0x30,
     kATAPICmdSearchDataLow	    	= 0x32,
     kATAPICmdSeek6		    	= 0x0b,
     kATAPICmdSeek10		    	= 0x2b,
     kATAPICmdSetLimits	    		= 0x33,
     kATAPICmdStartStopUnit	    	= 0x1b,
     kATAPICmdSynchronizeCache     	= 0x35,
     kATAPICmdVerify		    	= 0x2f,
     kATAPICmdWrite6		    	= 0x0a,
     kATAPICmdWrite10		    	= 0x2a,
     kATAPICmdWriteAndVerify	    	= 0x2e,
     kATAPICmdWriteLong	    		= 0x3f,
     kATAPICmdWriteSame	    		= 0x41,

/*
 * These commands are supported by sequential devices.
 */
     kATAPICmdRewind		    	= 0x01,
     kATAPICmdWriteFilemarks	    	= 0x10,
     kATAPICmdSpace		    	= 0x11,
     kATAPICmdLoadUnload	    	= 0x1B,
/*
 * ANSI ATA-II for CD-ROM devices.
 */
     kATAPICmdReadCDTableOfContents	= 0x43,
};


enum ATARegs
{
    /*
     * ATA Register ordinals
     */
    kATARegData			= 0x00,		
    kATARegFeatures		= 0x01,		
    kATARegSectorCount		= 0x02,		
    kATARegSectorNumber		= 0x03,		
    kATARegCylinderLow		= 0x04,		
    kATARegCylinderHigh		= 0x05,
    kATARegDriveHead		= 0x06,
    kATARegCommand		= 0x07,

    kATARegError		= 0x01,
    kATARegStatus		= 0x07,

    kATARegDeviceControl	= 0x08,

    kATARegAltStatus		= 0x08,

    /*
     * ATAPI Register ordinals
     */
    kATARegATAPIData		= 0x00,
    kATARegATAPIFeatures	= 0x01,
    kATARegATAPIIntReason	= 0x02,
    kATARegATAPIByteCountLow	= 0x04,
    kATARegATAPIByteCountHigh	= 0x05,
    kATARegATAPIDeviceSelect	= 0x06,
    kATARegATAPICommand		= 0x07,

    kATARegATAPIError		= 0x01,
    kATARegATAPIStatus		= 0x07,

    kATARegATAPIDeviceControl	= 0x08,

    kATARegATAPIAlternateStatus	= 0x08,

    kMaxATARegs			= 12,
};

enum ATASectorCountQDMA
{
    kATATagBit			= 0x08,
};


enum ATAPIIntReason
{
    kATAPIIntReasonCD		= 0x01,
    kATAPIIntReasonIO		= 0x02,
    kATAPIIntReasonREL		= 0x04,
    kATAPIIntReasonTagBit	= 0x08,
    kATAPIIntReasonTagMask	= 0xf8,
};

enum ATACommand
{
    kATAModeCHS			= 0xa0, 
    kATAModeLBA			= 0xe0,
 
    kATACommandSetFeatures	= 0xef,

    kATACommandIdentify		= 0xec,

    kATACommandReadSector	= 0x20,

    kATACommandService		= 0xa2,

    kATACommandATAPIReset	= 0x08,
    kATACommandATAPIPacket	= 0xa0,
    kATACommandATAPIIdentify	= 0xa1,
};

enum ATAFeatures
{
    kATAFeatureTransferMode		= 0x03,	
        kATATransferModePIODefault	= 0x00,		// SectorCount settings (or'd w/Mode)	
        kATATransferModePIOwFC		= 0x08,		
        kATATransferModeDMA		= 0x20,
        kATATransferModeUltraDMA33	= 0x40,
        kATATransferModeMask		= 0x07,
};


enum ATAStatus
{
    kATAStatusERR		= 0x01,
    kATAStatusIDX		= 0x02,
    kATAStatusECC		= 0x04,
    kATAStatusDRQ		= 0x08,
    kATAStatusSC		= 0x10,
    kATAStatusDF		= 0x20,
    kATAStatusDRDY		= 0x40,
    kATAStatusBSY		= 0x80,

    kATAStatusSERV		= 0x10,
    kATAStatusREL		= 0x20,

    kATAPIStatusCHK		= 0x01,
    kATAPIStatusDRQ		= 0x08,
    kATAPIStatusSERV		= 0x10,
    kATAPIStatusDMRD		= 0x20,
    kATAPIStatusDRDY		= 0x40,
    kATAPIStatusBSY		= 0x80,
};

enum ATAError
{
   kATAErrorNM			= 0x02,
   kATAErrorABRT		= 0x04,
   kATAErrorMCR			= 0x08,
   kATAErrorIDNF		= 0x10,
   kATAErrorMC			= 0x20,
   kATAErrorWP			= 0x40,

   kATAPIErrorILI		= 0x01,
   kATAPIErrorEOM		= 0x02,
   kATAPIErrorABRT		= 0x04,
   kATAPIErrorSenseKeyBit	= 0x10,
   kATAPIErrorSenseKeyMask	= 0xf0,
};

enum ATADeviceControl
{
    kATADevControlnIEN		= 0x02,
    kATADevControlSRST		= 0x04,
};

enum ATASignatures
{
    kATASignatureSectorCount	= 0x01,
    kATASignatureSectorNumber	= 0x01,
    kATASignatureCylinderLow	= 0x00,
    kATASignatureCylinderHigh	= 0x00,

    kATAPISignatureCylinderLow	= 0x14,
    kATAPISignatureCylinderHigh = 0xeb,
};


#endif
