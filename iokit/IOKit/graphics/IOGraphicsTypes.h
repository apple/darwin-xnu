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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOGRAPHICSTYPES_H
#define _IOKIT_IOGRAPHICSTYPES_H


#include <IOKit/IOTypes.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef SInt32	IOIndex;
typedef UInt32	IOSelect;
typedef UInt32	IOFixed1616;
typedef SInt32	IODisplayModeID;
typedef UInt32	IODisplayVendorID;
typedef UInt32	IODisplayProductID;

enum {
    kIOMaxPixelBits 	= 64
};
typedef char IOPixelEncoding[ kIOMaxPixelBits ];

// Common Apple pixel formats

#define IO1BitIndexedPixels	"P"
#define IO2BitIndexedPixels	"PP"
#define IO4BitIndexedPixels	"PPPP"
#define IO8BitIndexedPixels	"PPPPPPPP"
#define IO16BitDirectPixels	"-RRRRRGGGGGBBBBB"
#define IO32BitDirectPixels	"--------RRRRRRRRGGGGGGGGBBBBBBBB"

// other possible pixel formats

#define IOYUV422Pixels		"Y4U2V2"
#define IO8BitOverlayPixels	"O8"
// page flipping
#define IOPagedPixels		"Page1"

#define IO_SampleTypeAlpha	'A'
#define IO_SampleTypeSkip	'-'

// Info about a pixel format
enum {
    kIOCLUTPixels		= 0,
    kIOFixedCLUTPixels		= 1,
    kIORGBDirectPixels 		= 2,
    kIOMonoDirectPixels 	= 3,
    kIOMonoInverseDirectPixels	= 4,
};

struct IOPixelInformation {
    IOByteCount			bytesPerRow;
    IOByteCount			bytesPerPlane;
    UInt32			bitsPerPixel;
    UInt32			pixelType;
    UInt32			componentCount;
    UInt32			bitsPerComponent;
    UInt32			componentMasks[ 8 * 2 ];
    IOPixelEncoding		pixelFormat;
    UInt32			flags;
    UInt32			activeWidth;
    UInt32			activeHeight;
    UInt32			reserved[ 2 ];
};
typedef struct IOPixelInformation IOPixelInformation;

// Info about a display mode
typedef UInt32  IOAppleTimingID;

struct IODisplayModeInformation {
    UInt32			nominalWidth;
    UInt32			nominalHeight;
    IOFixed1616			refreshRate;
    IOIndex			maxDepthIndex;
    UInt32			flags;
    UInt32			reserved[ 4 ];
};
typedef struct IODisplayModeInformation IODisplayModeInformation;

// flags
enum {
    kDisplayModeSafetyFlags	= 0x00000007,

    kDisplayModeAlwaysShowFlag	= 0x00000008,
    kDisplayModeNeverShowFlag	= 0x00000080,
    kDisplayModeNotResizeFlag	= 0x00000010,
    kDisplayModeRequiresPanFlag	= 0x00000020,

    kDisplayModeInterlacedFlag	= 0x00000040,

    kDisplayModeSimulscanFlag	= 0x00000100,
    kDisplayModeBuiltInFlag	= 0x00000400,
    kDisplayModeNotPresetFlag	= 0x00000200,
    kDisplayModeStretchedFlag	= 0x00000800
};
enum {
    kDisplayModeValidFlag	= 0x00000001,
    kDisplayModeSafeFlag	= 0x00000002,
    kDisplayModeDefaultFlag	= 0x00000004,
};

// Framebuffer info

struct IOFramebufferInformation {
    IOPhysicalAddress		baseAddress;
    UInt32			activeWidth;
    UInt32			activeHeight;
    IOByteCount			bytesPerRow;
    IOByteCount			bytesPerPlane;
    UInt32			bitsPerPixel;
    UInt32			pixelType;
    UInt32			flags;
    UInt32			reserved[ 4 ];
};
typedef struct IOFramebufferInformation IOFramebufferInformation;

// flags
enum {
    kFramebufferSupportsCopybackCache	= 0x00010000,
    kFramebufferSupportsWritethruCache	= 0x00020000,
    kFramebufferSupportsGammaCorrection	= 0x00040000,
    kFramebufferDisableAltivecAccess	= 0x00080000,
};

// Aperture is an index into supported pixel formats for a mode & depth
typedef IOIndex IOPixelAperture;
enum {
    kIOFBSystemAperture	= 0
};

//// CLUTs

typedef UInt16 IOColorComponent;

struct IOColorEntry {
    UInt16	   		index;
    IOColorComponent   		red;
    IOColorComponent   		green;
    IOColorComponent   		blue;
};
typedef struct IOColorEntry IOColorEntry;

// options (masks)
enum {
    kSetCLUTByValue		= 0x00000001,		// else at index
    kSetCLUTImmediately		= 0x00000002,		// else at VBL
    kSetCLUTWithLuminance	= 0x00000004		// else RGB
};

//// Controller attributes

enum {
    kIOPowerAttribute			= 'powr',
    kIOHardwareCursorAttribute		= 'crsr'
};

//// Display mode timing information

struct IODetailedTimingInformation {
    // from EDID defn
    UInt32			pixelClock;		// Hertz
    UInt32			horizontalActive;	// pixels
    UInt32			horizontalBlanking;	// pixels
    UInt32			horizontalBorder;	// pixels
    UInt32			horizontalSyncOffset;	// pixels
    UInt32			horizontalSyncWidth;	// pixels
    UInt32			verticalActive;		// lines
    UInt32			verticalBlanking;	// lines
    UInt32			verticalBorder;		// lines
    UInt32			verticalSyncOffset;	// lines
    UInt32			verticalSyncWidth;	// lines
};
typedef struct IODetailedTimingInformation IODetailedTimingInformation;

struct IOTimingInformation {
    IOAppleTimingID		appleTimingID;		// appleTimingXXX const
    UInt32			flags;
    IODetailedTimingInformation detailedInfo;
};
typedef struct IOTimingInformation IOTimingInformation;

enum {
    // b0-7 from EDID flags
    kIODetailedTimingValid	= 0x80000000
};

//// Connections

enum {
    kOrConnections			= 0xffffffe,
    kAndConnections			= 0xffffffd
};

enum {
    kConnectionEnable			= 'enab',
    kConnectionSyncEnable		= 'sync',
    kConnectionSyncFlags		= 'sycf',
    kConnectionSupportsAppleSense	= 'asns',
    kConnectionSupportsLLDDCSense	= 'lddc',
    kConnectionSupportsHLDDCSense	= 'hddc'
};

// kConnectionSyncControl values
enum {
    kIOHSyncDisable			= 0x00000001,
    kIOVSyncDisable			= 0x00000002,
    kIOCSyncDisable			= 0x00000004,
    kIONoSeparateSyncControl		= 0x00000040,
    kIOTriStateSyncs			= 0x00000080,
    kIOSyncOnBlue			= 0x00000008,
    kIOSyncOnGreen			= 0x00000010,
    kIOSyncOnRed			= 0x00000020
};


#define IO_DISPLAY_CAN_FILL		0x00000040
#define IO_DISPLAY_CAN_BLIT		0x00000020

#define IO_24BPP_TRANSFER_TABLE_SIZE	256
#define IO_15BPP_TRANSFER_TABLE_SIZE	256
#define IO_8BPP_TRANSFER_TABLE_SIZE	256
#define IO_12BPP_TRANSFER_TABLE_SIZE	256
#define IO_2BPP_TRANSFER_TABLE_SIZE	256

#define STDFB_BM256_TO_BM38_MAP_SIZE	256
#define STDFB_BM38_TO_BM256_MAP_SIZE	256
#define STDFB_BM38_TO_256_WITH_LOGICAL_SIZE	\
	(STDFB_BM38_TO_BM256_MAP_SIZE + (256/sizeof(int)))

#define STDFB_4BPS_TO_5BPS_MAP_SIZE	16
#define STDFB_5BPS_TO_4BPS_MAP_SIZE	32

enum {
    // connection types for IOServiceOpen
    kIOFBServerConnectType		= 0,
    kIOFBSharedConnectType		= 1,
    kIOFBEngineControllerConnectType	= 20,
    kIOFBEngineConnectType		= 21
};

struct IOGPoint {
    SInt16	x;
    SInt16	y;
};
typedef struct IOGPoint IOGPoint;

struct IOGSize {
    SInt16	width;
    SInt16	height;
};
typedef struct IOGSize IOGSize;

struct IOGBounds {
    SInt16	minx;
    SInt16	maxx;
    SInt16	miny;
    SInt16	maxy;
};
typedef struct IOGBounds IOGBounds;

#if !defined(__Point__) && !defined(BINTREE_H) && !defined(__MACTYPES__)
#define __Point__
typedef IOGPoint Point;
#endif

#if !defined(__Bounds__) && !defined(BINTREE_H) && !defined(__MACTYPES__)
#define __Bounds__
typedef IOGBounds Bounds;
#endif

// interrupt types

enum {
    kIOFBVBLInterruptType		= 'vbl ',
    kIOFBHBLInterruptType		= 'hbl ',
    kIOFBFrameInterruptType		= 'fram',
    kIOFBConnectInterruptType		= 'dci '
};

// property keys

#define kIOFramebufferInfoKey		"IOFramebufferInformation"

#define kIOFBWidthKey			"IOFBWidth"
#define kIOFBHeightKey			"IOFBHeight"
#define kIOFBRefreshRateKey		"IOFBRefreshRate"
#define kIOFBFlagsKey			"IOFBFlags"
#define kIOFBBytesPerRowKey		"IOFBBytesPerRow"
#define kIOFBBytesPerPlaneKey		"IOFBBytesPerPlane"
#define kIOFBBitsPerPixelKey		"IOFBBitsPerPixel"
#define kIOFBComponentCountKey		"IOFBComponentCount"
#define kIOFBBitsPerComponentKey	"IOFBBitsPerComponent"

#define kIOFBDetailedTimingsKey		"IOFBDetailedTimings"
#define kIOFBTimingRangeKey		"IOFBTimingRange"

#define kIOFBHostAccessFlagsKey		"IOFBHostAccessFlags"

#define kIODisplayEDIDKey		"IODisplayEDID"
#define kIODisplayLocationKey		"IODisplayLocation"

enum {
    kDisplayVendorIDUnknown	= 'unkn',
    kDisplayProductIDGeneric	= 0x717
};

#define kDisplayVendorID		"DisplayVendorID"	 // CFNumber
#define kDisplayProductID		"DisplayProductID"	 // CFNumber
#define kDisplaySerialNumber		"DisplaySerialNumber"	 // CFNumber
#define kDisplaySerialString		"DisplaySerialString"	 // CFString
#define kDisplayWeekOfManufacture	"DisplayWeekManufacture" // CFNumber
#define kDisplayYearOfManufacture	"DisplayYearManufacture" // CFNumber

// CFDictionary of language-locale keys, name values
// eg. "en"="Color LCD", "en-GB"="Colour LCD"
#define kDisplayProductName		"DisplayProductName"

// all CFNumber or CFArray of CFNumber (floats)
#define kDisplayWhitePointX		"DisplayWhitePointX"
#define kDisplayWhitePointY		"DisplayWhitePointY"
#define kDisplayRedPointX		"DisplayRedPointX"
#define kDisplayRedPointY		"DisplayRedPointY"
#define kDisplayGreenPointX		"DisplayGreenPointX"
#define kDisplayGreenPointY		"DisplayGreenPointY"
#define kDisplayBluePointX		"DisplayBluePointX"
#define kDisplayBluePointY		"DisplayBluePointY"
#define kDisplayWhiteGamma		"DisplayWhiteGamma"
#define kDisplayRedGamma		"DisplayRedGamma"
#define kDisplayGreenGamma		"DisplayGreenGamma"
#define kDisplayBlueGamma		"DisplayBlueGamma"

// CFData
#define kDisplayCSProfile		"DisplayCSProfile"

// CFNumber
#define kDisplayHorizontalImageSize	"DisplayHorizontalImageSize"
#define kDisplayVerticalImageSize	"DisplayVerticalImageSize"

// Display parameters

#define kIODisplayParametersKey		"IODisplayParameters"
#define kIODisplayGUIDKey		"IODisplayGUID"

#define kIODisplayValueKey		"value"
#define kIODisplayMinValueKey		"min"
#define kIODisplayMaxValueKey		"max"

#define kIODisplayBrightnessKey		"brightness"
#define kIODisplayContrastKey		"contrast"
#define kIODisplayHorizontalPositionKey	"horizontal-position"
#define kIODisplayHorizontalSizeKey	"horizontal-size"
#define kIODisplayVerticalPositionKey	"vertical-position"
#define kIODisplayVerticalSizeKey	"vertical-size"
#define kIODisplayTrapezoidKey		"trapezoid"
#define kIODisplayPincushionKey		"pincushion"
#define kIODisplayParallelogramKey	"parallelogram"
#define kIODisplayRotationKey		"rotation"
#define kIODisplayTheatreModeKey	"theatre-mode"

#define kIODisplayParametersCommitKey	"commit"
#define kIODisplayParametersDefaultKey	"defaults"

#ifdef __cplusplus
}
#endif

#endif /* ! _IOKIT_IOGRAPHICSTYPES_H */
