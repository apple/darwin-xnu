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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  21 July 98 - start IOKit
 */

/*
    File:       Types.h
 
    Contains:   Basic Macintosh data types.
 
    Version:    Technology: PowerSurge 1.0.2.
                Package:    Universal Interfaces 2.1.2 on ETO #20
 
    Copyright:  © 1984-1995 by Apple Computer, Inc.
                All rights reserved.
 
    Bugs?:      If you find a problem with this file, use the Apple Bug Reporter
                stack.  Include the file and version information (from above)
                in the problem description and send to:
                    Internet:   apple.bugs@applelink.apple.com
                    AppleLink:  APPLE.BUGS
 
*/

#ifndef _IOKIT_IOMACOSTYPES_H
#define _IOKIT_IOMACOSTYPES_H
#ifndef __MACTYPES__

#include <IOKit/IOTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma options align=mac68k

#ifndef NULL
#if !defined(__cplusplus) && (defined(__SC__) || defined(THINK_C))
#define NULL ((void *) 0)
#else
#define NULL 0
#endif
#endif

enum {
    noErr                       = 0
};

typedef unsigned long KernelProcessID;
typedef unsigned long AddressSpaceID;

#if 0
#ifndef __cplusplus
enum { false, true };
#endif
#endif

typedef unsigned char Byte;

typedef signed char SignedByte;

typedef UInt16 UniChar;

typedef char *Ptr;

typedef Ptr *Handle;

typedef long Fixed;

typedef Fixed *FixedPtr;

typedef long Fract;

typedef Fract *FractPtr;

struct _extended80 {
    short                           exp;
    short                           man[4];
};
struct _extended96 {
    short                           exp[2];
    short                           man[4];
};
typedef struct wide				*WidePtr;

typedef struct UnsignedWide		*UnsignedWidePtr;


/*
enum {
    false,
    true
};
#if !__option(bool)
    #ifndef true
        #define true            1
    #endif
    #ifndef false
        #define false           0
    #endif
#endif

typedef unsigned char Boolean;
*/


typedef short OSErr;

typedef unsigned int FourCharCode;

typedef FourCharCode OSType;

typedef FourCharCode ResType;

typedef OSType *OSTypePtr;

typedef ResType *ResTypePtr;

struct Rect {
    short                           top;
    short                           left;
    short                           bottom;
    short                           right;
};
typedef struct Rect Rect;

typedef Rect *RectPtr;

// Quickdraw.i

/*
    kVariableLengthArray is used in array bounds to specify a variable length array.
    It is ususally used in variable length structs when the last field is an array
    of any size.  Before ANSI C, we used zero as the bounds of variable length 
    array, but that is illegal in ANSI C.  Example:
    
        struct FooList 
        {
            short   listLength;
            Foo     elements[kVariableLengthArray];
        };
*/

enum {
    kVariableLengthArray        = 1
};

/* Numeric version part of 'vers' resource */
struct NumVersion {
    UInt8                           majorRev;                   /*1st part of version number in BCD*/
    UInt8                           minorAndBugRev;             /*2nd & 3rd part of version number share a byte*/
    UInt8                           stage;                      /*stage code: dev, alpha, beta, final*/
    UInt8                           nonRelRev;                  /*revision level of non-released version*/
};
typedef struct NumVersion NumVersion;

typedef struct OpaqueRef *KernelID;

typedef UInt8 *BytePtr;

typedef UInt32 ByteCount;

typedef UInt32 ItemCount;

typedef void *LogicalAddress;

typedef void *PhysicalAddress;

typedef UInt32 PBVersion;

typedef SInt32 Duration;

#define kInvalidID 0

enum {
    kNilOptions                 = 0
};


typedef unsigned char Str31[32];


/*
From:
	File:		DriverFamilyMatching.i <18>
	Copyright:	© 1995-1996 by Apple Computer, Inc., all rights reserved.
*/

//##############################################
// Well known properties in the Name Registry
//##############################################

#define kPropertyName					"name"
#define kPropertyCompatible				"compatible"
#define	kPropertyDriverPtr				"driver-ptr"
#define kPropertyDriverDesc				"driver-description"
#define kPropertyReg					"reg"
#define kPropertyAAPLAddress				"AAPL,address"
#define kPropertyMatching				"matching"


//#########################################################
// Descriptor for Drivers and NDRVs
//#########################################################
/* Driver Typing Information Used to Match Drivers With Devices */
struct DriverType {
	Str31							nameInfoStr;				/* Driver Name/Info String*/
	NumVersion						version;					/* Driver Version Number*/
};
typedef struct DriverType			DriverType;
typedef DriverType *				DriverTypePtr;

/* OS Runtime Information Used to Setup and Maintain a Driver's Runtime Environment */
typedef OptionBits RuntimeOptions;


enum {
	kDriverIsLoadedUponDiscovery = 0x00000001,					/* auto-load driver when discovered*/
	kDriverIsOpenedUponLoad		=  0x00000002,					/* auto-open driver when loaded*/
	kDriverIsUnderExpertControl	=  0x00000004,					/* I/O expert handles loads/opens*/
	kDriverIsConcurrent			=  0x00000008,					/* supports concurrent requests*/
	kDriverQueuesIOPB			=  0x00000010,					/* device manager doesn't queue IOPB*/
	kDriverIsLoadedAtBoot		=  0x00000020,					/* Driver is loaded at the boot time */
	kDriverIsForVirtualDevice	=  0x00000040,					/* Driver is for a virtual Device */ 
	kDriverSupportDMSuspendAndResume = 0x00000080				/* Driver supports Device Manager Suspend and Resume command */
};

struct DriverOSRuntime {
	RuntimeOptions					driverRuntime;				/* Options for OS Runtime*/
	Str31							driverName;					/* Driver's name to the OS*/
	UInt32							driverDescReserved[8];		/* Reserved area*/
};
typedef struct DriverOSRuntime		DriverOSRuntime;
typedef DriverOSRuntime *			DriverOSRuntimePtr;

/* OS Service Information Used To Declare What APIs a Driver Supports */
typedef UInt32 ServiceCount;

struct DriverServiceInfo {
	OSType							serviceCategory;			/* Service Category Name*/
	OSType							serviceType;				/* Type within Category*/
	NumVersion						serviceVersion;				/* Version of service*/
};
typedef struct DriverServiceInfo	DriverServiceInfo;
typedef DriverServiceInfo *			DriverServiceInfoPtr;

struct DriverOSService {
	ServiceCount					nServices;					/* Number of Services Supported*/
	DriverServiceInfo				service[1];					/* The List of Services (at least one)*/
};
typedef struct DriverOSService		DriverOSService;
typedef DriverOSService *			DriverOSServicePtr;

/* Categories */

enum {
	kServiceCategoryDisplay			= 'disp',						/* Display Manager*/
	kServiceCategoryOpenTransport 	= 'otan',						/* Open Transport*/
	kServiceCategoryBlockStorage	= 'blok',						/* Block Storage*/
	kServiceCategoryNdrvDriver		= 'ndrv',						/* Generic Native Driver*/
	kServiceCategoryScsiSIM			= 'scsi',						/* SCSI */
	kServiceCategoryFileManager		= 'file',						/* File Manager */
	kServiceCategoryIDE				= 'ide-',						/* ide */
	kServiceCategoryADB				= 'adb-',						/* adb */
	kServiceCategoryPCI				= 'pci-',						/* pci bus */
																	/* Nu Bus */
	kServiceCategoryDFM				= 'dfm-',						/* DFM */
	kServiceCategoryMotherBoard		= 'mrbd',						/* mother Board */
	kServiceCategoryKeyboard		= 'kybd',						/* Keyboard */
	kServiceCategoryPointing		= 'poit',						/* Pointing */
	kServiceCategoryRTC				= 'rtc-',						/* RTC */
	kServiceCategoryNVRAM			= 'nram',						/* NVRAM */
	kServiceCategorySound			= 'sond',						/* Sound (1/3/96 MCS) */
	kServiceCategoryPowerMgt		= 'pgmt',						/* Power Management */
	kServiceCategoryGeneric			= 'genr'						/* Generic Service Category to receive general Events */
};

/* Ndrv ServiceCategory Types */
enum {
	kNdrvTypeIsGeneric			= 'genr',						/* generic*/
	kNdrvTypeIsVideo			= 'vido',						/* video*/
	kNdrvTypeIsBlockStorage		= 'blok',						/* block storage*/
	kNdrvTypeIsNetworking		= 'netw',						/* networking*/
	kNdrvTypeIsSerial			= 'serl',						/* serial*/
	kNdrvTypeIsParallel			= 'parl',						/* parallel */
	kNdrvTypeIsSound			= 'sond',						/* sound*/
	kNdrvTypeIsBusBridge		= 'brdg'
};

typedef UInt32 DriverDescVersion;

/*	The Driver Description */
enum {
	kInitialDriverDescriptor	= 0,
	kVersionOneDriverDescriptor	= 1
};

enum {
	kTheDescriptionSignature	= 'mtej',
	kDriverDescriptionSignature	= 'pdes'						
};


struct DriverDescription {
	OSType							driverDescSignature;		/* Signature field of this structure*/
	DriverDescVersion				driverDescVersion;			/* Version of this data structure*/
	DriverType						driverType;					/* Type of Driver*/
	DriverOSRuntime					driverOSRuntimeInfo;		/* OS Runtime Requirements of Driver*/
	DriverOSService					driverServices;				/* Apple Service API Membership*/
};
typedef struct DriverDescription	DriverDescription;
typedef DriverDescription *			DriverDescriptionPtr;


#pragma options align=reset

#ifdef __cplusplus
}
#endif

#endif /* __MACTYPES__ */

#ifndef __QUICKDRAW__

#ifdef __cplusplus
extern "C" {
#endif

#pragma options align=mac68k

struct RGBColor {
 unsigned short red;                /*magnitude of red component*/
 unsigned short green;              /*magnitude of green component*/
 unsigned short blue;               /*magnitude of blue component*/
};
typedef struct RGBColor     RGBColor;
typedef RGBColor            *RGBColorPtr;
typedef RGBColorPtr         *RGBColorHdl;

struct ColorSpec {
 short value;                       /*index or other value*/
 RGBColor rgb;                      /*true color*/
};

typedef struct ColorSpec    ColorSpec;
typedef ColorSpec           *ColorSpecPtr;

struct GammaTbl {
 short gVersion;                    /*gamma version number*/
 short gType;                       /*gamma data type*/
 short gFormulaSize;                /*Formula data size*/
 short gChanCnt;                    /*number of channels of data*/
 short gDataCnt;                    /*number of values/channel*/
 short gDataWidth;                  /*bits/corrected value (data packed to next larger byte size)*/
 short gFormulaData[1];             /*data for formulas followed by gamma values*/
};
typedef struct GammaTbl     GammaTbl;
typedef GammaTbl            *GammaTblPtr;

#pragma options align=reset

#ifdef __cplusplus
}
#endif

#endif /* __QUICKDRAW__ */

#endif /* _IOKIT_IOMACOSTYPES_H */
