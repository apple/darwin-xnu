/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#ifndef __HFS_MACOS_TYPES__
#define __HFS_MACOS_TYPES__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#include <sys/param.h>
	#ifdef KERNEL
	#include <libkern/libkern.h>
	#include <sys/systm.h>
	#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/proc.h>


#define TARGET_OS_MAC			0
#define TARGET_OS_WIN32			0
#define TARGET_OS_UNIX			0

#define PRAGMA_IMPORT			0
#define PRAGMA_STRUCT_ALIGN		1
#define PRAGMA_ONCE			0
#define PRAGMA_STRUCT_PACK		0
#define PRAGMA_STRUCT_PACKPUSH		0

#if __GNUC__ >= 2
	#define TYPE_LONGLONG		1
#else
	#define TYPE_LONGLONG		0
#endif
#ifdef __cplusplus
	#define TYPE_BOOL		1
#else
	#define TYPE_BOOL		0
#endif

#define EXTERN_API(_type)		extern _type
#define EXTERN_API_C(_type)		extern _type

#define CALLBACK_API_C(_type, _name)	_type ( * _name)

#define TARGET_API_MACOS_X 1
#define TARGET_API_MAC_OS8 0
#define TARGET_API_MAC_CARBON 0
	
	

/****** START OF MACOSTYPES *********/


/*
   4.4BSD's sys/types.h defines size_t without defining __size_t__:
   Things are a lot clearer from here on if we define __size_t__ now.
 */
#define __size_t__

/*
	Convert kernel's diagnostic flag to MacOS's
*/
#if HFS_DIAGNOSTIC
    #define DEBUG_BUILD 1
#else
    #define DEBUG_BUILD 0
#endif	/* DIAGNOSTIC */

/********************************************************************************

	Special values in C
	
		NULL		The C standard for an impossible pointer value
		nil			A carry over from pascal, NULL is prefered for C
		
*********************************************************************************/
#ifndef NULL
	#define	NULL 0
#endif

#ifndef nil
	#define nil NULL
#endif


typedef u_int8_t 		UInt8;
typedef int8_t		 	SInt8;
typedef u_int16_t 		UInt16;
typedef int16_t 		SInt16;
typedef u_int32_t 		UInt32;
typedef int32_t 		SInt32;
typedef u_int64_t  		UInt64;
typedef int64_t 		SInt64;

typedef char *			Ptr;
typedef long 			Size;

typedef SInt16 			OSErr;
typedef SInt32 			OSStatus;
typedef UInt32 			ItemCount;
typedef void *			LogicalAddress;
typedef UInt32 			ByteCount;
typedef UInt8 *			BytePtr;
typedef UInt32 			ByteOffset;
typedef UInt32 			OptionBits;
typedef unsigned long 		FourCharCode;
typedef FourCharCode 		OSType;

typedef UInt16 			UniChar;
typedef unsigned char 		Str255[256];
typedef unsigned char 		Str31[32];
typedef unsigned char *		StringPtr;
typedef const unsigned char *	ConstStr255Param;
typedef const unsigned char *	ConstStr31Param;
typedef const unsigned char *	ConstUTF8Param;

typedef UInt8 			Byte;

typedef UInt32 			TextEncoding;
typedef UniChar *		UniCharArrayPtr;
typedef const UniChar *		ConstUniCharArrayPtr;


/********************************************************************************

	Boolean types and values
	
		Boolean			A one byte value, holds "false" (0) or "true" (1)
		false			The Boolean value of zero (0)
		true			The Boolean value of one (1)
		
*********************************************************************************/
/*
	The identifiers "true" and "false" are becoming keywords in C++
	and work with the new built-in type "bool"
	"Boolean" will remain an unsigned char for compatibility with source
	code written before "bool" existed.
*/
#if !TYPE_BOOL

enum {
	false						= 0,
	true						= 1
};

#endif  /*  !TYPE_BOOL */

typedef unsigned char 				Boolean;




EXTERN_API( void ) DebugStr(ConstStr255Param debuggerMsg);

/*********************************************************************************

	Added types for HFSPlus MacOS X functionality. Needs to be incorporated to
	other places
		
*********************************************************************************/

typedef struct vnode* FileReference;


/***** START OF MACOSSTUBS ********/


/*
	SizeTDef.h -- Common definitions
	
	size_t - this type is defined by several ANSI headers.
*/
#if ! defined (__size_t__)
	#define __size_t__
        #if defined (__xlc) || defined (__xlC) || defined (__xlC__) || defined (__MWERKS__)
		typedef unsigned long size_t;
        #else	/* __xlC */
		typedef unsigned int size_t;
	#endif	/* __xlC */
#endif	/* __size_t__ */


/*
 	File:		Errors.h
 
*/
enum {
	noErr			= 0,
	dskFulErr		= -34,		/*disk full*/
	bdNamErr		= -37,		/*there may be no bad names in the final system!*/
	paramErr		= -50,		/*error in user parameter list*/
	memFullErr		= -108,		/*Not enough room in heap zone*/
	fileBoundsErr		= -1309,	/*file's EOF, offset, mark or size is too big*/
	kTECUsedFallbacksStatus	= -8783,

};


enum {
	/* Finder Flags */
	kHasBeenInited		= 0x0100,
	kHasCustomIcon		= 0x0400,
	kIsStationery		= 0x0800,
	kNameLocked		= 0x1000,
	kHasBundle		= 0x2000,
	kIsInvisible		= 0x4000,
	kIsAlias		= 0x8000
};

enum {
	fsRtParID	= 1,
	fsRtDirID	= 2
};


enum {
	/* Mac OS encodings*/
	kTextEncodingMacRoman		= 0L,
	kTextEncodingMacJapanese	= 1,
	kTextEncodingMacChineseTrad	= 2,
	kTextEncodingMacKorean		= 3,
	kTextEncodingMacArabic		= 4,
	kTextEncodingMacHebrew		= 5,
	kTextEncodingMacGreek		= 6,
	kTextEncodingMacCyrillic	= 7,
	kTextEncodingMacDevanagari	= 9,
	kTextEncodingMacGurmukhi	= 10,
	kTextEncodingMacGujarati	= 11,
	kTextEncodingMacOriya		= 12,
	kTextEncodingMacBengali		= 13,
	kTextEncodingMacTamil		= 14,
	kTextEncodingMacTelugu		= 15,
	kTextEncodingMacKannada		= 16,
	kTextEncodingMacMalayalam	= 17,
	kTextEncodingMacSinhalese	= 18,
	kTextEncodingMacBurmese		= 19,
	kTextEncodingMacKhmer		= 20,
	kTextEncodingMacThai		= 21,
	kTextEncodingMacLaotian		= 22,
	kTextEncodingMacGeorgian	= 23,
	kTextEncodingMacArmenian	= 24,
	kTextEncodingMacChineseSimp	= 25,
	kTextEncodingMacTibetan		= 26,
	kTextEncodingMacMongolian	= 27,
	kTextEncodingMacEthiopic	= 28,
	kTextEncodingMacCentralEurRoman = 29,
	kTextEncodingMacVietnamese	= 30,
	kTextEncodingMacExtArabic	= 31,	/* The following use script code 0, smRoman*/
	kTextEncodingMacSymbol		= 33,
	kTextEncodingMacDingbats	= 34,
	kTextEncodingMacTurkish		= 35,
	kTextEncodingMacCroatian	= 36,
	kTextEncodingMacIcelandic	= 37,
	kTextEncodingMacRomanian	= 38,					
	kTextEncodingMacUnicode		= 0x7E,

	kTextEncodingMacFarsi		= 0x8C,	/* Like MacArabic but uses Farsi digits */														/* The following use script code 7, smCyrillic */
	kTextEncodingMacUkrainian	= 0x98,	/* The following use script code 32, smUnimplemented */
};


/* PROTOTYPES */

#if HFS_DIAGNOSTIC
	extern void RequireFileLock(FileReference vp, int shareable);
	#define REQUIRE_FILE_LOCK(vp,s) RequireFileLock((vp),(s))
#else
	#define REQUIRE_FILE_LOCK(vp,s)
#endif


EXTERN_API( void )
BlockMoveData(const void * srcPtr, void * destPtr, Size byteCount);

#define BlockMoveData(src, dest, len)	bcopy((src), (dest), (len))

EXTERN_API_C( void )
ClearMemory(void * start, UInt32 length);

#define ClearMemory(start, length)	bzero((start), (size_t)(length));


EXTERN_API( Ptr )
NewPtr(Size byteCount);

EXTERN_API( Ptr )
NewPtrSysClear(Size byteCount);

EXTERN_API( void )
DisposePtr(Ptr p);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif	/* __HFS_MACOS_TYPES__ */
