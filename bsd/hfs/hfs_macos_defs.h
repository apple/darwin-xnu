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
 	File:		hfs_macos_types.h
 
 	Contains:	Basic Macintosh OS data types.
 
 	Version:	System 7.5
 
 	DRI:		Nick Kledzik
 
 	History:
 	12-Aug-1999	Scott Roberts	Created from ConditionalMacros.h, MacOSStubs.h, MacOSTypes.h

 
 
*/


#ifndef __hfs_macos_types__
#define __hfs_macos_types__


#include <sys/param.h>
	#ifdef KERNEL
	#include <libkern/libkern.h>
	#include <sys/systm.h>
	#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/lock.h>

/****** START OF CONDITIONALMACROS *********/

	#if defined(__ppc__) || defined(powerpc) || defined(ppc)
		#define TARGET_CPU_PPC			1
		#define TARGET_CPU_68K			0
		#define TARGET_CPU_X86			0
		#define TARGET_CPU_MIPS			0
		#define TARGET_CPU_SPARC		0   
		#define TARGET_CPU_ALPHA		0
		#define TARGET_RT_MAC_CFM		0
		#define TARGET_RT_MAC_MACHO		1
		#define TARGET_RT_MAC_68881		0
		#define TARGET_RT_LITTLE_ENDIAN	0
		#define TARGET_RT_BIG_ENDIAN	1
	#elif defined(m68k)
		#define TARGET_CPU_PPC			0
		#define TARGET_CPU_68K			1
		#define TARGET_CPU_X86			0
		#define TARGET_CPU_MIPS			0
		#define TARGET_CPU_SPARC		0   
		#define TARGET_CPU_ALPHA		0
		#define TARGET_RT_MAC_CFM		0
		#define TARGET_RT_MAC_MACHO		1
		#define TARGET_RT_MAC_68881		0
		#define TARGET_RT_LITTLE_ENDIAN 0
		#define TARGET_RT_BIG_ENDIAN	1
	#elif defined(sparc)
		#define TARGET_CPU_PPC			0
		#define TARGET_CPU_68K			0
		#define TARGET_CPU_X86			0
		#define TARGET_CPU_MIPS			0
		#define TARGET_CPU_SPARC		1
		#define TARGET_CPU_ALPHA		0
		#define TARGET_RT_MAC_CFM		0
		#define TARGET_RT_MAC_MACHO		1
		#define TARGET_RT_MAC_68881		0
		#define TARGET_RT_LITTLE_ENDIAN	0
		#define TARGET_RT_BIG_ENDIAN	1
	#elif defined(__i386__) || defined(i386) || defined(intel)
		#define TARGET_CPU_PPC			0
		#define TARGET_CPU_68K			0
		#define TARGET_CPU_X86			1
		#define TARGET_CPU_MIPS			0
		#define TARGET_CPU_SPARC		0
		#define TARGET_CPU_ALPHA		0
		#define TARGET_RT_MAC_CFM		0
		#define TARGET_RT_MAC_MACHO		1
		#define TARGET_RT_MAC_68881		0
		#define TARGET_RT_LITTLE_ENDIAN	1
		#define TARGET_RT_BIG_ENDIAN	0
	#else
		#error unrecognized GNU C compiler
	#endif


	#define TARGET_OS_MAC				0
	#define TARGET_OS_WIN32				0
	#define TARGET_OS_UNIX				0

	#define PRAGMA_IMPORT				0
	#define PRAGMA_STRUCT_ALIGN			1
	#define PRAGMA_ONCE					0
	#define PRAGMA_STRUCT_PACK			0
	#define PRAGMA_STRUCT_PACKPUSH		0
	#define PRAGMA_ENUM_PACK			0
	#define PRAGMA_ENUM_ALWAYSINT		0
	#define PRAGMA_ENUM_OPTIONS			0
	#define FOUR_CHAR_CODE(x)			(x)

	#define TYPE_EXTENDED				0
	#if __GNUC__ >= 2
		#define TYPE_LONGLONG			1
	#else
		#define TYPE_LONGLONG			0
	#endif
	#ifdef __cplusplus
		#define TYPE_BOOL				1
	#else
		#define TYPE_BOOL				0
	#endif
	
	#define FUNCTION_PASCAL				0
	#define FUNCTION_DECLSPEC			0
	#define FUNCTION_WIN32CC			0			


	#define EXTERN_API(_type)						extern _type
	#define EXTERN_API_C(_type)						extern _type
	#define EXTERN_API_STDCALL(_type)				extern _type
	#define EXTERN_API_C_STDCALL(_type)				extern _type
	
	#define DEFINE_API(_type)						_type
	#define DEFINE_API_C(_type)						_type
	#define DEFINE_API_STDCALL(_type)				_type
	#define DEFINE_API_C_STDCALL(_type)				_type

	#define CALLBACK_API(_type, _name)				_type ( * _name)
	#define CALLBACK_API_C(_type, _name)			_type ( * _name)
	#define CALLBACK_API_STDCALL(_type, _name)		_type ( * _name)
	#define CALLBACK_API_C_STDCALL(_type, _name)	_type ( * _name)
	
	#define TARGET_API_MACOS_X 1
	#define TARGET_API_MAC_OS8 0
	#define TARGET_API_MAC_CARBON 0
	
	#define ONEWORDINLINE(w1)
	#define TWOWORDINLINE(w1,w2)
	#define THREEWORDINLINE(w1,w2,w3)
	#define FOURWORDINLINE(w1,w2,w3,w4)
	#define FIVEWORDINLINE(w1,w2,w3,w4,w5)
	#define SIXWORDINLINE(w1,w2,w3,w4,w5,w6)
	#define SEVENWORDINLINE(w1,w2,w3,w4,w5,w6,w7)
	#define EIGHTWORDINLINE(w1,w2,w3,w4,w5,w6,w7,w8)
	#define NINEWORDINLINE(w1,w2,w3,w4,w5,w6,w7,w8,w9)
	#define TENWORDINLINE(w1,w2,w3,w4,w5,w6,w7,w8,w9,w10)
	#define ELEVENWORDINLINE(w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11)
	#define TWELVEWORDINLINE(w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12)
	

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


/********************************************************************************

	Base integer types for all target OS's and CPU's
	
		UInt8			 8-bit unsigned integer	
		SInt8			 8-bit signed integer
		UInt16			16-bit unsigned integer	
		SInt16			16-bit signed integer			
		UInt32			32-bit unsigned integer	
		SInt32			32-bit signed integer	
		UInt64			64-bit unsigned integer	
		SInt64			64-bit signed integer	

*********************************************************************************/
typedef u_int8_t 					UInt8;
typedef int8_t		 				SInt8;
typedef u_int16_t 					UInt16;
typedef int16_t 					SInt16;
typedef u_int32_t 					UInt32;
typedef int32_t 					SInt32;
typedef u_int64_t  					UInt64;
typedef int64_t 					SInt64;



/********************************************************************************

	Base floating point types 
	
		Float32			32 bit IEEE float:  1 sign bit, 8 exponent bits, 23 fraction bits
		Float64			64 bit IEEE float:  1 sign bit, 11 exponent bits, 52 fraction bits	
		Float80			80 bit MacOS float: 1 sign bit, 15 exponent bits, 1 integer bit, 63 fraction bits
		Float96			96 bit 68881 float: 1 sign bit, 15 exponent bits, 16 pad bits, 1 integer bit, 63 fraction bits
		
	Note: These are fixed size floating point types, useful when writing a floating
		  point value to disk.  If your compiler does not support a particular size 
		  float, a struct is used instead.
		  Use of of the NCEG types (e.g. double_t) or an ANSI C type (e.g. double) if
		  you want a floating point representation that is natural for any given
		  compiler, but might be a different size on different compilers.

*********************************************************************************/
typedef float				Float32;
typedef double				Float64;

struct Float80 {
	SInt16 	exp;
	UInt16 	man[4];
};
typedef struct Float80 Float80;

struct Float96 {
	SInt16 	exp[2];		/* the second 16-bits is always zero */
	UInt16 	man[4];
};
typedef struct Float96 Float96;



/********************************************************************************

	MacOS Memory Manager types
	
		Ptr				Pointer to a non-relocatable block
		Handle			Pointer to a master pointer to a relocatable block
		Size			The number of bytes in a block (signed for historical reasons)
		
*********************************************************************************/
typedef char *							Ptr;
typedef Ptr *							Handle;
typedef long 							Size;
/********************************************************************************

	Higher level basic types
	
		OSErr					16-bit result error code
		OSStatus				32-bit result error code
		LogicalAddress			Address in the clients virtual address space
		ConstLogicalAddress		Address in the clients virtual address space that will only be read
		PhysicalAddress			Real address as used on the hardware bus
		BytePtr					Pointer to an array of bytes
		ByteCount				The size of an array of bytes
		ByteOffset				An offset into an array of bytes
		ItemCount				32-bit iteration count
		OptionBits				Standard 32-bit set of bit flags
		PBVersion				?
		Duration				32-bit millisecond timer for drivers
		AbsoluteTime			64-bit clock
		ScriptCode				The coarse features of a written language (e.g. Roman vs Cyrillic)
		LangCode				A particular language (e.g. English)
		RegionCode				A variation of a language (British vs American English)
		FourCharCode			A 32-bit value made by packing four 1 byte characters together
		OSType					A FourCharCode used in the OS and file system (e.g. creator)
		ResType					A FourCharCode used to tag resources (e.g. 'DLOG')
		
*********************************************************************************/
typedef SInt16 							OSErr;
typedef SInt32 							OSStatus;
typedef void *							LogicalAddress;
typedef const void *					ConstLogicalAddress;
typedef void *							PhysicalAddress;
typedef UInt8 *							BytePtr;
typedef UInt32 							ByteCount;
typedef UInt32 							ByteOffset;
typedef SInt32 							Duration;
typedef UInt64		 					AbsoluteTime;
typedef UInt32 							OptionBits;
typedef UInt32 							ItemCount;
typedef UInt32 							PBVersion;
typedef SInt16 							ScriptCode;
typedef SInt16 							LangCode;
typedef SInt16 							RegionCode;
typedef unsigned long 					FourCharCode;
typedef FourCharCode 					OSType;
typedef FourCharCode 					ResType;
typedef OSType *						OSTypePtr;
typedef ResType *						ResTypePtr;


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

typedef unsigned char 					Boolean;


/********************************************************************************

	Function Pointer Types
	
		ProcPtr					Generic pointer to a function
		Register68kProcPtr		Pointer to a 68K function that expects parameters in registers
		UniversalProcPtr		Pointer to classic 68K code or a RoutineDescriptor
		
		ProcHandle				Pointer to a ProcPtr
		UniversalProcHandle		Pointer to a UniversalProcPtr
		
*********************************************************************************/
typedef long (*ProcPtr)();
typedef void (*Register68kProcPtr)();

typedef ProcPtr 						UniversalProcPtr;

typedef ProcPtr *						ProcHandle;
typedef UniversalProcPtr *				UniversalProcHandle;

/********************************************************************************

	Quickdraw Types
	
		Point				2D Quickdraw coordinate, range: -32K to +32K
		Rect				Rectangluar Quickdraw area
		Style				Quickdraw font rendering styles
		StyleParameter		Style when used as a parameter (historical 68K convention)
		StyleField			Style when used as a field (historical 68K convention)
		CharParameter		Char when used as a parameter (historical 68K convention)
		
	Note:   The original Macintosh toolbox in 68K Pascal defined Style as a SET.  
			Both Style and CHAR occupy 8-bits in packed records or 16-bits when 
			used as fields in non-packed records or as parameters. 
		
*********************************************************************************/
struct Point {
	short 							v;
	short 							h;
};
typedef struct Point Point;

typedef Point *							PointPtr;
struct Rect {
	short 							top;
	short 							left;
	short 							bottom;
	short 							right;
};
typedef struct Rect Rect;

typedef Rect *							RectPtr;
typedef short 							CharParameter;

enum {
	normal						= 0,
	bold						= 1,
	italic						= 2,
	underline					= 4,
	outline						= 8,
	shadow						= 0x10,
	condense					= 0x20,
	extend						= 0x40
};

typedef unsigned char 					Style;
typedef short 							StyleParameter;
typedef Style 							StyleField;


/********************************************************************************

	Common Constants
	
		noErr					OSErr: function performed properly - no error
		kNilOptions				OptionBits: all flags false
		kInvalidID				KernelID: NULL is for pointers as kInvalidID is for ID's
		kVariableLengthArray	array bounds: variable length array

	Note: kVariableLengthArray is used in array bounds to specify a variable length array.
		  It is ususally used in variable length structs when the last field is an array
		  of any size.  Before ANSI C, we used zero as the bounds of variable length 
		  array, but zero length array are illegal in ANSI C.  Example usage:
	
		struct FooList 
		{
			short 	listLength;
			Foo		elements[kVariableLengthArray];
		};
		
*********************************************************************************/

enum {
	noErr						= 0
};


enum {
	kNilOptions					= 0
};

#define kInvalidID	 0

enum {
	kVariableLengthArray		= 1
};



/********************************************************************************

	String Types
	
		UniChar					A single UniCode character (16-bits)

		StrNNN					Pascal string holding up to NNN bytes
		StringPtr				Pointer to a pascal string
		StringHandle			Pointer to a StringPtr
		ConstStrNNNParam		For function parameters only - means string is const
		
		CStringPtr				Pointer to a C string       (same as:  char*)
		ConstCStringPtr			Pointer to a const C string (same as:  const char*)
		
	Note: The length of a pascal string is stored in the first byte.
		  A pascal string does not have a termination byte and can be at most 255 bytes long.
		  The first character in a pascal string is offset one byte from the start of the string. 
		  
		  A C string is terminated with a byte of value zero.  
		  A C string has no length limitation.
		  The first character in a C string is the first byte of the string. 
		  
		
*********************************************************************************/
typedef UInt16 							UniChar;
typedef unsigned char 					Str255[256];
typedef unsigned char 					Str63[64];
typedef unsigned char 					Str32[33];
typedef unsigned char 					Str31[32];
typedef unsigned char 					Str27[28];
typedef unsigned char 					Str15[16];
/*
	The type Str32 is used in many AppleTalk based data structures.
	It holds up to 32 one byte chars.  The problem is that with the
	length byte it is 33 bytes long.  This can cause weird alignment
	problems in structures.  To fix this the type "Str32Field" has
	been created.  It should only be used to hold 32 chars, but
	it is 34 bytes long so that there are no alignment problems.
*/
typedef unsigned char 					Str32Field[34];
typedef unsigned char *					StringPtr;
typedef StringPtr *						StringHandle;
typedef const unsigned char *			ConstStr255Param;
typedef const unsigned char *			ConstStr63Param;
typedef const unsigned char *			ConstStr32Param;
typedef const unsigned char *			ConstStr31Param;
typedef const unsigned char *			ConstStr27Param;
typedef const unsigned char *			ConstStr15Param;
#ifdef __cplusplus
inline unsigned char StrLength(ConstStr255Param string) { return (*string); }
#else
#define StrLength(string) (*(unsigned char *)(string))
#endif  /*  defined(__cplusplus)  */

typedef const unsigned char *			ConstUTF8Param;

/*********************************************************************************

	Old names for types
		
*********************************************************************************/
typedef UInt8 							Byte;
typedef SInt8 							SignedByte;
typedef SInt64 *						WidePtr;
typedef UInt64 *						UnsignedWidePtr;
typedef Float80 						extended80;
typedef Float96 						extended96;
typedef SInt8 							VHSelect;


EXTERN_API( void )
DebugStr						(ConstStr255Param 		debuggerMsg);

/*********************************************************************************

	Added types for HFSPlus MacOS X functionality. Needs to be incorporated to
	other places
		
*********************************************************************************/

    typedef struct vnode* FileReference;
    #define kNoFileReference NULL


#define HFSInstrumentation 0


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
	StdDef.h -- Common definitions
	
*/

#define offsetof(structure,field) ((size_t)&((structure *) 0)->field)



/*
 	File:		Errors.h
 
*/
enum {
	paramErr					= -50,							/*error in user parameter list*/
	noHardwareErr				= -200,							/*Sound Manager Error Returns*/
	notEnoughHardwareErr		= -201,							/*Sound Manager Error Returns*/
	userCanceledErr				= -128,
	qErr						= -1,							/*queue element not found during deletion*/
	vTypErr						= -2,							/*invalid queue element*/
	corErr						= -3,							/*core routine number out of range*/
	unimpErr					= -4,							/*unimplemented core routine*/
	SlpTypeErr					= -5,							/*invalid queue element*/
	seNoDB						= -8,							/*no debugger installed to handle debugger command*/
	controlErr					= -17,							/*I/O System Errors*/
	statusErr					= -18,							/*I/O System Errors*/
	readErr						= -19,							/*I/O System Errors*/
	writErr						= -20,							/*I/O System Errors*/
	badUnitErr					= -21,							/*I/O System Errors*/
	unitEmptyErr				= -22,							/*I/O System Errors*/
	openErr						= -23,							/*I/O System Errors*/
	closErr						= -24,							/*I/O System Errors*/
	dRemovErr					= -25,							/*tried to remove an open driver*/
	dInstErr					= -26							/*DrvrInstall couldn't find driver in resources*/
};

enum {																/* Printing Errors */
	iMemFullErr					= -108,
	iIOAbort					= -27,							/*Scrap Manager errors*/
	noScrapErr					= -100,							/*No scrap exists error*/
	noTypeErr					= -102,							/*No object of that type in scrap*/
	memROZWarn					= -99,							/*soft error in ROZ*/
	memROZError					= -99,							/*hard error in ROZ*/
	memROZErr					= -99,							/*hard error in ROZ*/
	memFullErr					= -108,							/*Not enough room in heap zone*/
	nilHandleErr				= -109,							/*Master Pointer was NIL in HandleZone or other*/
	memWZErr					= -111,							/*WhichZone failed (applied to free block)*/
	memPurErr					= -112,							/*trying to purge a locked or non-purgeable block*/
	memAdrErr					= -110							/*address was odd; or out of range*/
};



enum {
	abortErr					= -27,							/*IO call aborted by KillIO*/
	iIOAbortErr					= -27,							/*IO abort error (Printing Manager)*/
	notOpenErr					= -28,							/*Couldn't rd/wr/ctl/sts cause driver not opened*/
	unitTblFullErr				= -29,							/*unit table has no more entries*/
	dceExtErr					= -30,							/*dce extension error*/
	slotNumErr					= -360,							/*invalid slot # error*/
	gcrOnMFMErr					= -400,							/*gcr format on high density media error*/
	dirFulErr					= -33,							/*Directory full*/
	dskFulErr					= -34,							/*disk full*/
	nsvErr						= -35,							/*no such volume*/
	ioErr						= -36,							/*I/O error (bummers)*/
	bdNamErr					= -37,							/*there may be no bad names in the final system!*/
	fnOpnErr					= -38,							/*File not open*/
	eofErr						= -39,							/*End of file*/
	posErr						= -40,							/*tried to position to before start of file (r/w)*/
	mFulErr						= -41,							/*memory full (open) or file won't fit (load)*/
	tmfoErr						= -42,							/*too many files open*/
	fnfErr						= -43,							/*File not found*/
	wPrErr						= -44,							/*diskette is write protected.*/
	fLckdErr					= -45							/*file is locked*/
};


enum {
	vLckdErr					= -46,							/*volume is locked*/
	fBsyErr						= -47,							/*File is busy (delete)*/
	dupFNErr					= -48,							/*duplicate filename (rename)*/
	opWrErr						= -49,							/*file already open with with write permission*/
	rfNumErr					= -51,							/*refnum error*/
	gfpErr						= -52,							/*get file position error*/
	volOffLinErr				= -53,							/*volume not on line error (was Ejected)*/
	permErr						= -54,							/*permissions error (on file open)*/
	volOnLinErr					= -55,							/*drive volume already on-line at MountVol*/
	nsDrvErr					= -56,							/*no such drive (tried to mount a bad drive num)*/
	noMacDskErr					= -57,							/*not a mac diskette (sig bytes are wrong)*/
	extFSErr					= -58,							/*volume in question belongs to an external fs*/
	fsRnErr						= -59,							/*file system internal error:during rename the old entry was deleted but could not be restored.*/
	badMDBErr					= -60,							/*bad master directory block*/
	wrPermErr					= -61,							/*write permissions error*/
	dirNFErr					= -120,							/*Directory not found*/
	tmwdoErr					= -121,							/*No free WDCB available*/
	badMovErr					= -122,							/*Move into offspring error*/
	wrgVolTypErr				= -123,							/*Wrong volume type error [operation not supported for MFS]*/
	volGoneErr					= -124							/*Server volume has been disconnected.*/
};

enum {
																/*Dictionary Manager errors*/
	notBTree					= -410,							/*The file is not a dictionary.*/
	btNoSpace					= -413,							/*Can't allocate disk space.*/
	btDupRecErr					= -414,							/*Record already exists.*/
	btRecNotFnd					= -415,							/*Record cannot be found.*/
	btKeyLenErr					= -416,							/*Maximum key length is too long or equal to zero.*/
	btKeyAttrErr				= -417,							/*There is no such a key attribute.*/
	unknownInsertModeErr		= -20000,						/*There is no such an insert mode.*/
	recordDataTooBigErr			= -20001,						/*The record data is bigger than buffer size (1024 bytes).*/
	invalidIndexErr				= -20002						/*The recordIndex parameter is not valid.*/
};


enum {
	fidNotFound					= -1300,						/*no file thread exists.*/
	fidExists					= -1301,						/*file id already exists*/
	notAFileErr					= -1302,						/*directory specified*/
	diffVolErr					= -1303,						/*files on different volumes*/
	catChangedErr				= -1304,						/*the catalog has been modified*/
	desktopDamagedErr			= -1305,						/*desktop database files are corrupted*/
	sameFileErr					= -1306,						/*can't exchange a file with itself*/
	badFidErr					= -1307,						/*file id is dangling or doesn't match with the file number*/
	notARemountErr				= -1308,						/*when _Mount allows only remounts and doesn't get one*/
	fileBoundsErr				= -1309,						/*file's EOF, offset, mark or size is too big*/
	fsDataTooBigErr				= -1310,						/*file or volume is too big for system*/
	volVMBusyErr				= -1311,						/*can't eject because volume is in use by VM*/
	envNotPresent				= -5500,						/*returned by glue.*/
	envBadVers					= -5501,						/*Version non-positive*/
	envVersTooBig				= -5502,						/*Version bigger than call can handle*/
	fontDecError				= -64,							/*error during font declaration*/
	fontNotDeclared				= -65,							/*font not declared*/
	fontSubErr					= -66,							/*font substitution occured*/
	fontNotOutlineErr			= -32615,						/*bitmap font passed to routine that does outlines only*/
	firstDskErr					= -84,							/*I/O System Errors*/
	lastDskErr					= -64,							/*I/O System Errors*/
	noDriveErr					= -64,							/*drive not installed*/
	offLinErr					= -65,							/*r/w requested for an off-line drive*/
	noNybErr					= -66							/*couldn't find 5 nybbles in 200 tries*/
};

enum {
																/* general text errors*/
	kTextUnsupportedEncodingErr	= -8738,						/* specified encoding not supported for this operation*/
	kTextMalformedInputErr		= -8739,						/* in DBCS, for example, high byte followed by invalid low byte*/
	kTextUndefinedElementErr	= -8740,						/* text conversion errors*/
	kTECMissingTableErr			= -8745,
	kTECTableChecksumErr		= -8746,
	kTECTableFormatErr			= -8747,
	kTECCorruptConverterErr		= -8748,						/* invalid converter object reference*/
	kTECNoConversionPathErr		= -8749,
	kTECBufferBelowMinimumSizeErr = -8750,						/* output buffer too small to allow processing of first input text element*/
	kTECArrayFullErr			= -8751,						/* supplied name buffer or TextRun, TextEncoding, or UnicodeMapping array is too small*/
	kTECBadTextRunErr			= -8752,
	kTECPartialCharErr			= -8753,						/* input buffer ends in the middle of a multibyte character, conversion stopped*/
	kTECUnmappableElementErr	= -8754,
	kTECIncompleteElementErr	= -8755,						/* text element may be incomplete or is too long for internal buffers*/
	kTECDirectionErr			= -8756,						/* direction stack overflow, etc.*/
	kTECGlobalsUnavailableErr	= -8770,						/* globals have already been deallocated (premature TERM)*/
	kTECItemUnavailableErr		= -8771,						/* item (e.g. name) not available for specified region (& encoding if relevant)*/
																/* text conversion status codes*/
	kTECUsedFallbacksStatus		= -8783,
	kTECNeedFlushStatus			= -8784,
	kTECOutputBufferFullStatus	= -8785,						/* output buffer has no room for conversion of next input text element (partial conversion)*/
																/* deprecated error & status codes for low-level converter*/
	unicodeChecksumErr			= -8769,
	unicodeNoTableErr			= -8768,
	unicodeVariantErr			= -8767,
	unicodeFallbacksErr			= -8766,
	unicodePartConvertErr		= -8765,
	unicodeBufErr				= -8764,
	unicodeCharErr				= -8763,
	unicodeElementErr			= -8762,
	unicodeNotFoundErr			= -8761,
	unicodeTableFormatErr		= -8760,
	unicodeDirectionErr			= -8759,
	unicodeContextualErr		= -8758,
	unicodeTextEncodingDataErr	= -8757
};


/*
 	File:		MacMemory.h
 
 
*/


/*
 	File:		MixedMode.h
 
*/

/* Calling Conventions */
typedef unsigned short 					CallingConventionType;

enum {
	kPascalStackBased			= 0,
	kCStackBased				= 1,
	kRegisterBased				= 2,
	kD0DispatchedPascalStackBased = 8,
	kD1DispatchedPascalStackBased = 12,
	kD0DispatchedCStackBased	= 9,
	kStackDispatchedPascalStackBased = 14,
	kThinkCStackBased			= 5
};


	#define STACK_UPP_TYPE(name) 	name
	#define REGISTER_UPP_TYPE(name) name


/*
 	File:		OSUtils.h
 
*/
typedef struct QElem QElem;

typedef QElem *							QElemPtr;
struct QHdr {
	short 							qFlags;
	QElemPtr 						qHead;
	QElemPtr 						qTail;
};
typedef struct QHdr QHdr;

typedef QHdr *							QHdrPtr;

typedef CALLBACK_API( void , DeferredTaskProcPtr )(long dtParam);
/*
	WARNING: DeferredTaskProcPtr uses register based parameters under classic 68k
			 and cannot be written in a high-level language without 
			 the help of mixed mode or assembly glue.
*/
typedef REGISTER_UPP_TYPE(DeferredTaskProcPtr) 					DeferredTaskUPP;
enum { uppDeferredTaskProcInfo = 0x0000B802 }; 					/* register no_return_value Func(4_bytes:A1) */
#define NewDeferredTaskProc(userRoutine) 						(DeferredTaskUPP)NewRoutineDescriptor((ProcPtr)(userRoutine), uppDeferredTaskProcInfo, GetCurrentArchitecture())
#define CallDeferredTaskProc(userRoutine, dtParam) 			CALL_ONE_PARAMETER_UPP((userRoutine), uppDeferredTaskProcInfo, (dtParam))
struct DeferredTask {
	QElemPtr 						qLink;
	short 							qType;
	short 							dtFlags;
	DeferredTaskUPP 				dtAddr;
	long 							dtParam;
	long 							dtReserved;
};
typedef struct DeferredTask DeferredTask;

typedef DeferredTask *					DeferredTaskPtr;

/*
 	File:		Finder.h
 
 
*/

/*	
	The following declerations used to be in Files.‰, 
	but are Finder specific and were moved here.
*/

enum {
                                                                /* Finder Flags */
    kIsOnDesk					= 0x0001,
    kColor						= 0x000E,
    kIsShared					= 0x0040,						/* bit 0x0080 is hasNoINITS */
    kHasBeenInited				= 0x0100,						/* bit 0x0200 was the letter bit for AOCE, but is now reserved for future use */
    kHasCustomIcon				= 0x0400,
    kIsStationery				= 0x0800,
    kNameLocked					= 0x1000,
    kHasBundle					= 0x2000,
    kIsInvisible				= 0x4000,
    kIsAlias					= 0x8000
};


enum {
																/* Finder Constants */
	fOnDesk						= 1,
	fHasBundle					= 8192,
	fTrash						= -3,
	fDesktop					= -2,
	fDisk						= 0
};

#if PRAGMA_STRUCT_ALIGN
	#pragma options align=mac68k
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(push, 2)
#elif PRAGMA_STRUCT_PACK
	#pragma pack(2)
#endif


struct FInfo {
	OSType 							fdType;						/*the type of the file*/
	OSType 							fdCreator;					/*file's creator*/
	unsigned short 					fdFlags;					/*flags ex. hasbundle,invisible,locked, etc.*/
	Point 							fdLocation;					/*file's location in folder*/
	short 							fdFldr;						/*folder containing file*/
};
typedef struct FInfo FInfo;

struct FXInfo {
	short 							fdIconID;					/*Icon ID*/
	short 							fdUnused[3];				/*unused but reserved 6 bytes*/
	SInt8 							fdScript;					/*Script flag and number*/
	SInt8 							fdXFlags;					/*More flag bits*/
	short 							fdComment;					/*Comment ID*/
	long 							fdPutAway;					/*Home Dir ID*/
};
typedef struct FXInfo FXInfo;

struct DInfo {
	Rect 							frRect;						/*folder rect*/
	unsigned short 					frFlags;					/*Flags*/
	Point 							frLocation;					/*folder location*/
	short 							frView;						/*folder view*/
};
typedef struct DInfo DInfo;

struct DXInfo {
	Point 							frScroll;					/*scroll position*/
	long 							frOpenChain;				/*DirID chain of open folders*/
	SInt8 							frScript;					/*Script flag and number*/
	SInt8 							frXFlags;					/*More flag bits*/
	short 							frComment;					/*comment*/
	long 							frPutAway;					/*DirID*/
};
typedef struct DXInfo DXInfo;

#if PRAGMA_STRUCT_ALIGN
	#pragma options align=reset
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(pop)
#elif PRAGMA_STRUCT_PACK
	#pragma pack()
#endif


enum {
	fsRtParID					= 1,
	fsRtDirID					= 2
};



#if PRAGMA_STRUCT_ALIGN
	#pragma options align=mac68k
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(push, 2)
#elif PRAGMA_STRUCT_PACK
	#pragma pack(2)
#endif


#if PRAGMA_STRUCT_ALIGN
	#pragma options align=reset
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(pop)
#elif PRAGMA_STRUCT_PACK
	#pragma pack()
#endif


/*
 * UTGetBlock options
 */

enum {
	gbDefault					= 0,							/* default value - read if not found */
																/*	bits and masks */
	gbReadBit					= 0,							/* read block from disk (forced read) */
	gbReadMask					= 0x0001,
	gbExistBit					= 1,							/* get existing cache block */
	gbExistMask					= 0x0002,
	gbNoReadBit					= 2,							/* don't read block from disk if not found in cache */
	gbNoReadMask				= 0x0004,
	gbReleaseBit				= 3,							/* release block immediately after GetBlock */
	gbReleaseMask				= 0x0008
};


/*
 * UTReleaseBlock options
 */

enum {
	rbDefault					= 0,							/* default value - just mark the buffer not in-use */
																/*	bits and masks */
	rbWriteBit					= 0,							/* force write buffer to disk */
	rbWriteMask					= 0x0001,
	rbTrashBit					= 1,							/* trash buffer contents after release */
	rbTrashMask					= 0x0002,
	rbDirtyBit					= 2,							/* mark buffer dirty */
	rbDirtyMask					= 0x0004,
	rbFreeBit					= 3,							/* free the buffer (save in the hash) */
	rbFreeMask					= 0x000A						/* rbFreeMask (rbFreeBit + rbTrashBit) works as rbTrash on < System 7.0 RamCache; on >= System 7.0, rbfreeMask overrides rbTrash */
};

/*
 * UTFlushCache options
 */

enum {
	fcDefault					= 0,							/* default value - pass this fcOption to just flush any dirty buffers */
																/*	bits and masks */
	fcTrashBit					= 0,							/* (don't pass this as fcOption, use only for testing bit) */
	fcTrashMask					= 0x0001,						/* pass this fcOption value to flush and trash cache blocks */
	fcFreeBit					= 1,							/* (don't pass this as fcOption, use only for testing bit) */
	fcFreeMask					= 0x0003						/* pass this fcOption to flush and free cache blocks (Note: both fcTrash and fcFree bits are set) */
};



/*
 * FCBRec.fcbFlags bits
 */

enum {
	fcbWriteBit					= 0,							/* Data can be written to this file */
	fcbWriteMask				= 0x01,
	fcbResourceBit				= 1,							/* This file is a resource fork */
	fcbResourceMask				= 0x02,
	fcbWriteLockedBit			= 2,							/* File has a locked byte range */
	fcbWriteLockedMask			= 0x04,
	fcbSharedWriteBit			= 4,							/* File is open for shared write access */
	fcbSharedWriteMask			= 0x10,
	fcbFileLockedBit			= 5,							/* File is locked (write-protected) */
	fcbFileLockedMask			= 0x20,
	fcbOwnClumpBit				= 6,							/* File has clump size specified in FCB */
	fcbOwnClumpMask				= 0x40,
	fcbModifiedBit				= 7,							/* File has changed since it was last flushed */
	fcbModifiedMask				= 0x80
};


/*
 	File:		TextCommon.h
 
*/

/* LocaleIdentifier is an obsolete Copland typedef, will be removed soon*/
typedef UInt32 							LocaleIdentifier;
/* TextEncodingBase type & values */
/* (values 0-32 correspond to the Script Codes defined in Inside Macintosh: Text pages 6-52 and 6-53 */
typedef UInt32 							TextEncodingBase;

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
	kTextEncodingMacExtArabic	= 31,							/* The following use script code 0, smRoman*/
	kTextEncodingMacSymbol		= 33,
	kTextEncodingMacDingbats	= 34,
	kTextEncodingMacTurkish		= 35,
	kTextEncodingMacCroatian	= 36,
	kTextEncodingMacIcelandic	= 37,
	kTextEncodingMacRomanian	= 38,							/* The following use script code 4, smArabic*/
	kTextEncodingMacFarsi		= 0x8C,							/* Like MacArabic but uses Farsi digits*/
																/* The following use script code 7, smCyrillic*/
	kTextEncodingMacUkrainian	= 0x98,							/* The following use script code 32, smUnimplemented*/
	kTextEncodingMacVT100		= 0xFC,							/* VT100/102 font from Comm Toolbox: Latin-1 repertoire + box drawing etc*/
																/* Special Mac OS encodings*/
	kTextEncodingMacHFS			= 0xFF,							/* Meta-value, should never appear in a table.*/
																/* Unicode & ISO UCS encodings begin at 0x100*/
	kTextEncodingUnicodeDefault	= 0x0100,						/* Meta-value, should never appear in a table.*/
	kTextEncodingUnicodeV1_1	= 0x0101,
	kTextEncodingISO10646_1993	= 0x0101,						/* Code points identical to Unicode 1.1*/
	kTextEncodingUnicodeV2_0	= 0x0103,						/* New location for Korean Hangul*/
																/* ISO 8-bit and 7-bit encodings begin at 0x200*/
	kTextEncodingISOLatin1		= 0x0201,						/* ISO 8859-1*/
	kTextEncodingISOLatin2		= 0x0202,						/* ISO 8859-2*/
	kTextEncodingISOLatinCyrillic = 0x0205,						/* ISO 8859-5*/
	kTextEncodingISOLatinArabic	= 0x0206,						/* ISO 8859-6, = ASMO 708, =DOS CP 708*/
	kTextEncodingISOLatinGreek	= 0x0207,						/* ISO 8859-7*/
	kTextEncodingISOLatinHebrew	= 0x0208,						/* ISO 8859-8*/
	kTextEncodingISOLatin5		= 0x0209,						/* ISO 8859-9*/
																/* MS-DOS & Windows encodings begin at 0x400*/
	kTextEncodingDOSLatinUS		= 0x0400,						/* code page 437*/
	kTextEncodingDOSGreek		= 0x0405,						/* code page 737 (formerly code page 437G)*/
	kTextEncodingDOSBalticRim	= 0x0406,						/* code page 775*/
	kTextEncodingDOSLatin1		= 0x0410,						/* code page 850, "Multilingual"*/
	kTextEncodingDOSGreek1		= 0x0411,						/* code page 851*/
	kTextEncodingDOSLatin2		= 0x0412,						/* code page 852, Slavic*/
	kTextEncodingDOSCyrillic	= 0x0413,						/* code page 855, IBM Cyrillic*/
	kTextEncodingDOSTurkish		= 0x0414,						/* code page 857, IBM Turkish*/
	kTextEncodingDOSPortuguese	= 0x0415,						/* code page 860*/
	kTextEncodingDOSIcelandic	= 0x0416,						/* code page 861*/
	kTextEncodingDOSHebrew		= 0x0417,						/* code page 862*/
	kTextEncodingDOSCanadianFrench = 0x0418,					/* code page 863*/
	kTextEncodingDOSArabic		= 0x0419,						/* code page 864*/
	kTextEncodingDOSNordic		= 0x041A,						/* code page 865*/
	kTextEncodingDOSRussian		= 0x041B,						/* code page 866*/
	kTextEncodingDOSGreek2		= 0x041C,						/* code page 869, IBM Modern Greek*/
	kTextEncodingDOSThai		= 0x041D,						/* code page 874, also for Windows*/
	kTextEncodingDOSJapanese	= 0x0420,						/* code page 932, also for Windows*/
	kTextEncodingDOSChineseSimplif = 0x0421,					/* code page 936, also for Windows*/
	kTextEncodingDOSKorean		= 0x0422,						/* code page 949, also for Windows; Unified Hangul Code*/
	kTextEncodingDOSChineseTrad	= 0x0423,						/* code page 950, also for Windows*/
	kTextEncodingWindowsLatin1	= 0x0500,						/* code page 1252*/
	kTextEncodingWindowsANSI	= 0x0500,						/* code page 1252 (alternate name)*/
	kTextEncodingWindowsLatin2	= 0x0501,						/* code page 1250, Central Europe*/
	kTextEncodingWindowsCyrillic = 0x0502,						/* code page 1251, Slavic Cyrillic*/
	kTextEncodingWindowsGreek	= 0x0503,						/* code page 1253*/
	kTextEncodingWindowsLatin5	= 0x0504,						/* code page 1254, Turkish*/
	kTextEncodingWindowsHebrew	= 0x0505,						/* code page 1255*/
	kTextEncodingWindowsArabic	= 0x0506,						/* code page 1256*/
	kTextEncodingWindowsBalticRim = 0x0507,						/* code page 1257*/
	kTextEncodingWindowsKoreanJohab = 0x0510,					/* code page 1361, for Windows NT*/
																/* Various national standards begin at 0x600*/
	kTextEncodingUS_ASCII		= 0x0600,
	kTextEncodingJIS_X0201_76	= 0x0620,
	kTextEncodingJIS_X0208_83	= 0x0621,
	kTextEncodingJIS_X0208_90	= 0x0622,
	kTextEncodingJIS_X0212_90	= 0x0623,
	kTextEncodingJIS_C6226_78	= 0x0624,
	kTextEncodingGB_2312_80		= 0x0630,
	kTextEncodingGBK_95			= 0x0631,						/* annex to GB 13000-93; for Windows 95*/
	kTextEncodingKSC_5601_87	= 0x0640,						/* same as KSC 5601-92 without Johab annex*/
	kTextEncodingKSC_5601_92_Johab = 0x0641,					/* KSC 5601-92 Johab annex*/
	kTextEncodingCNS_11643_92_P1 = 0x0651,						/* CNS 11643-1992 plane 1*/
	kTextEncodingCNS_11643_92_P2 = 0x0652,						/* CNS 11643-1992 plane 2*/
	kTextEncodingCNS_11643_92_P3 = 0x0653,						/* CNS 11643-1992 plane 3 (was plane 14 in 1986 version)*/
																/* ISO 2022 collections begin at 0x800*/
	kTextEncodingISO_2022_JP	= 0x0820,
	kTextEncodingISO_2022_JP_2	= 0x0821,
	kTextEncodingISO_2022_CN	= 0x0830,
	kTextEncodingISO_2022_CN_EXT = 0x0831,
	kTextEncodingISO_2022_KR	= 0x0840,						/* EUC collections begin at 0x900*/
	kTextEncodingEUC_JP			= 0x0920,						/* ISO 646, 1-byte katakana, JIS 208, JIS 212*/
	kTextEncodingEUC_CN			= 0x0930,						/* ISO 646, GB 2312-80*/
	kTextEncodingEUC_TW			= 0x0931,						/* ISO 646, CNS 11643-1992 Planes 1-16*/
	kTextEncodingEUC_KR			= 0x0940,						/* ISO 646, KS C 5601-1987*/
																/* Misc standards begin at 0xA00*/
	kTextEncodingShiftJIS		= 0x0A01,						/* plain Shift-JIS*/
	kTextEncodingKOI8_R			= 0x0A02,						/* Russian internet standard*/
	kTextEncodingBig5			= 0x0A03,						/* Big-5 (has variants)*/
	kTextEncodingMacRomanLatin1	= 0x0A04,						/* Mac OS Roman permuted to align with ISO Latin-1*/
	kTextEncodingHZ_GB_2312		= 0x0A05,						/* HZ (RFC 1842, for Chinese mail & news)*/
																/* Other platform encodings*/
	kTextEncodingNextStepLatin	= 0x0B01,						/* NextStep encoding*/
																/* EBCDIC & IBM host encodings begin at 0xC00*/
	kTextEncodingEBCDIC_US		= 0x0C01,						/* basic EBCDIC-US*/
	kTextEncodingEBCDIC_CP037	= 0x0C02,						/* code page 037, extended EBCDIC (Latin-1 set) for US,Canada...*/
																/* Special value*/
	kTextEncodingMultiRun		= 0x0FFF,						/* Multi-encoding text with external run info*/
																/* The following are older names for backward compatibility*/
	kTextEncodingMacTradChinese	= 2,
	kTextEncodingMacRSymbol		= 8,
	kTextEncodingMacSimpChinese	= 25,
	kTextEncodingMacGeez		= 28,
	kTextEncodingMacEastEurRoman = 29,
	kTextEncodingMacUninterp	= 32
};

/* TextEncodingVariant type & values */
typedef UInt32 							TextEncodingVariant;

enum {
																/* Default TextEncodingVariant, for any TextEncodingBase*/
	kTextEncodingDefaultVariant	= 0,							/* Variants of kTextEncodingMacIcelandic													*/
	kMacIcelandicStandardVariant = 0,							/* 0xBB & 0xBC are fem./masc. ordinal indicators*/
	kMacIcelandicTrueTypeVariant = 1,							/* 0xBB & 0xBC are fi/fl ligatures*/
																/* Variants of kTextEncodingMacJapanese*/
	kMacJapaneseStandardVariant	= 0,
	kMacJapaneseStdNoVerticalsVariant = 1,
	kMacJapaneseBasicVariant	= 2,
	kMacJapanesePostScriptScrnVariant = 3,
	kMacJapanesePostScriptPrintVariant = 4,
	kMacJapaneseVertAtKuPlusTenVariant = 5,						/* Variant options for most Japanese encodings (MacJapanese, ShiftJIS, EUC-JP, ISO 2022-JP)	*/
																/* These can be OR-ed into the variant value in any combination*/
	kJapaneseNoOneByteKanaOption = 0x20,
	kJapaneseUseAsciiBackslashOption = 0x40,					/* Variants of kTextEncodingMacArabic*/
	kMacArabicStandardVariant	= 0,							/* 0xC0 is 8-spoke asterisk, 0x2A & 0xAA are asterisk (e.g. Cairo)*/
	kMacArabicTrueTypeVariant	= 1,							/* 0xC0 is asterisk, 0x2A & 0xAA are multiply signs (e.g. Baghdad)*/
	kMacArabicThuluthVariant	= 2,							/* 0xC0 is Arabic five-point star, 0x2A & 0xAA are multiply signs*/
	kMacArabicAlBayanVariant	= 3,							/* 8-spoke asterisk, multiply sign, Koranic ligatures & parens*/
																/* Variants of kTextEncodingMacFarsi*/
	kMacFarsiStandardVariant	= 0,							/* 0xC0 is 8-spoke asterisk, 0x2A & 0xAA are asterisk (e.g. Tehran)*/
	kMacFarsiTrueTypeVariant	= 1,							/* asterisk, multiply signs, Koranic ligatures, geometric shapes*/
																/* Variants of kTextEncodingMacHebrew*/
	kMacHebrewStandardVariant	= 0,
	kMacHebrewFigureSpaceVariant = 1,							/* Variants of Unicode & ISO 10646 encodings*/
	kUnicodeNoSubset			= 0,
	kUnicodeNoCompatibilityVariant = 1,
	kUnicodeMaxDecomposedVariant = 2,
	kUnicodeNoComposedVariant	= 3,
	kUnicodeNoCorporateVariant	= 4,							/* Variants of Big-5 encoding*/
	kBig5_BasicVariant			= 0,
	kBig5_StandardVariant		= 1,							/* 0xC6A1-0xC7FC: kana, Cyrillic, enclosed numerics*/
	kBig5_ETenVariant			= 2,							/* adds kana, Cyrillic, radicals, etc with hi bytes C6-C8,F9*/
																/* The following are older names for backward compatibility*/
	kJapaneseStandardVariant	= 0,
	kJapaneseStdNoVerticalsVariant = 1,
	kJapaneseBasicVariant		= 2,
	kJapanesePostScriptScrnVariant = 3,
	kJapanesePostScriptPrintVariant = 4,
	kJapaneseVertAtKuPlusTenVariant = 5,						/* kJapaneseStdNoOneByteKanaVariant = 6,	// replaced by kJapaneseNoOneByteKanaOption*/
																/* kJapaneseBasicNoOneByteKanaVariant = 7,	// replaced by kJapaneseNoOneByteKanaOption	*/
	kHebrewStandardVariant		= 0,
	kHebrewFigureSpaceVariant	= 1
};

/* TextEncodingFormat type & values */
typedef UInt32 							TextEncodingFormat;

enum {
																/* Default TextEncodingFormat for any TextEncodingBase*/
	kTextEncodingDefaultFormat	= 0,							/* Formats for Unicode & ISO 10646*/
	kUnicode16BitFormat			= 0,
	kUnicodeUTF7Format			= 1,
	kUnicodeUTF8Format			= 2,
	kUnicode32BitFormat			= 3
};

/* TextEncoding type */
typedef UInt32 							TextEncoding;
/* name part selector for GetTextEncodingName*/
typedef UInt32 							TextEncodingNameSelector;

enum {
	kTextEncodingFullName		= 0,
	kTextEncodingBaseName		= 1,
	kTextEncodingVariantName	= 2,
	kTextEncodingFormatName		= 3
};

/* Types used in conversion */
struct TextEncodingRun {
	ByteOffset 						offset;
	TextEncoding 					textEncoding;
};
typedef struct TextEncodingRun TextEncodingRun;

typedef TextEncodingRun *				TextEncodingRunPtr;
typedef const TextEncodingRun *			ConstTextEncodingRunPtr;
struct ScriptCodeRun {
	ByteOffset 						offset;
	ScriptCode 						script;
};
typedef struct ScriptCodeRun ScriptCodeRun;

typedef ScriptCodeRun *					ScriptCodeRunPtr;
typedef const ScriptCodeRun *			ConstScriptCodeRunPtr;
typedef UInt8 *							TextPtr;
typedef const UInt8 *					ConstTextPtr;
/* Basic types for Unicode characters and strings: */
typedef UniChar *						UniCharArrayPtr;
typedef const UniChar *					ConstUniCharArrayPtr;
/* enums for TextEncoding Conversion routines*/

enum {
	kTextScriptDontCare			= -128,
	kTextLanguageDontCare		= -128,
	kTextRegionDontCare			= -128
};



/*
 	File:		UnicodeConverter.h
 
 
*/

/* Unicode conversion contexts: */
typedef struct OpaqueTextToUnicodeInfo*  TextToUnicodeInfo;
typedef struct OpaqueUnicodeToTextInfo*  UnicodeToTextInfo;
typedef struct OpaqueUnicodeToTextRunInfo*  UnicodeToTextRunInfo;
typedef const TextToUnicodeInfo 		ConstTextToUnicodeInfo;
typedef const UnicodeToTextInfo 		ConstUnicodeToTextInfo;
/* UnicodeMapVersion type & values */
typedef SInt32 							UnicodeMapVersion;

enum {
	kUnicodeUseLatestMapping	= -1,
	kUnicodeUseHFSPlusMapping	= 4
};

/* Types used in conversion */
struct UnicodeMapping {
	TextEncoding 					unicodeEncoding;
	TextEncoding 					otherEncoding;
	UnicodeMapVersion 				mappingVersion;
};
typedef struct UnicodeMapping UnicodeMapping;

typedef UnicodeMapping *				UnicodeMappingPtr;
typedef const UnicodeMapping *			ConstUnicodeMappingPtr;
/* Control flags for ConvertFromUnicodeToText and ConvertFromTextToUnicode */

enum {
	kUnicodeUseFallbacksBit		= 0,
	kUnicodeKeepInfoBit			= 1,
	kUnicodeDirectionalityBits	= 2,
	kUnicodeVerticalFormBit		= 4,
	kUnicodeLooseMappingsBit	= 5,
	kUnicodeStringUnterminatedBit = 6,
	kUnicodeTextRunBit			= 7,
	kUnicodeKeepSameEncodingBit	= 8
};


enum {
	kUnicodeUseFallbacksMask	= 1L << kUnicodeUseFallbacksBit,
	kUnicodeKeepInfoMask		= 1L << kUnicodeKeepInfoBit,
	kUnicodeDirectionalityMask	= 3L << kUnicodeDirectionalityBits,
	kUnicodeVerticalFormMask	= 1L << kUnicodeVerticalFormBit,
	kUnicodeLooseMappingsMask	= 1L << kUnicodeLooseMappingsBit,
	kUnicodeStringUnterminatedMask = 1L << kUnicodeStringUnterminatedBit,
	kUnicodeTextRunMask			= 1L << kUnicodeTextRunBit,
	kUnicodeKeepSameEncodingMask = 1L << kUnicodeKeepSameEncodingBit
};

/* Values for kUnicodeDirectionality field */

enum {
	kUnicodeDefaultDirection	= 0,
	kUnicodeLeftToRight			= 1,
	kUnicodeRightToLeft			= 2
};

/* Directionality masks for control flags */

enum {
	kUnicodeDefaultDirectionMask = kUnicodeDefaultDirection << kUnicodeDirectionalityBits,
	kUnicodeLeftToRightMask		= kUnicodeLeftToRight << kUnicodeDirectionalityBits,
	kUnicodeRightToLeftMask		= kUnicodeRightToLeft << kUnicodeDirectionalityBits
};

/* Control flags for TruncateForUnicodeToText: */
/*
   Now TruncateForUnicodeToText uses control flags from the same set as used by
   ConvertFromTextToUnicode, ConvertFromUnicodeToText, etc., but only
   kUnicodeStringUnterminatedMask is meaningful for TruncateForUnicodeToText.
   
   Previously two special control flags were defined for TruncateForUnicodeToText:
  		kUnicodeTextElementSafeBit = 0
  		kUnicodeRestartSafeBit = 1
   However, neither of these was implemented.
   Instead of implementing kUnicodeTextElementSafeBit, we now use
   kUnicodeStringUnterminatedMask since it accomplishes the same thing and avoids
   having special flags just for TruncateForUnicodeToText
   Also, kUnicodeRestartSafeBit is unnecessary, since restart-safeness is handled by
   setting kUnicodeKeepInfoBit with ConvertFromUnicodeToText.
   If TruncateForUnicodeToText is called with one or both of the old special control
   flags set (bits 0 or 1), it will not generate a paramErr, but the old bits have no
   effect on its operation.
*/

/* Filter bits for filter field in QueryUnicodeMappings and CountUnicodeMappings: */

enum {
	kUnicodeMatchUnicodeBaseBit	= 0,
	kUnicodeMatchUnicodeVariantBit = 1,
	kUnicodeMatchUnicodeFormatBit = 2,
	kUnicodeMatchOtherBaseBit	= 3,
	kUnicodeMatchOtherVariantBit = 4,
	kUnicodeMatchOtherFormatBit	= 5
};


enum {
	kUnicodeMatchUnicodeBaseMask = 1L << kUnicodeMatchUnicodeBaseBit,
	kUnicodeMatchUnicodeVariantMask = 1L << kUnicodeMatchUnicodeVariantBit,
	kUnicodeMatchUnicodeFormatMask = 1L << kUnicodeMatchUnicodeFormatBit,
	kUnicodeMatchOtherBaseMask	= 1L << kUnicodeMatchOtherBaseBit,
	kUnicodeMatchOtherVariantMask = 1L << kUnicodeMatchOtherVariantBit,
	kUnicodeMatchOtherFormatMask = 1L << kUnicodeMatchOtherFormatBit
};

/* Control flags for SetFallbackUnicodeToText */

enum {
	kUnicodeFallbackSequencingBits = 0
};


enum {
	kUnicodeFallbackSequencingMask = 3L << kUnicodeFallbackSequencingBits
};

/* values for kUnicodeFallbackSequencing field */

enum {
	kUnicodeFallbackDefaultOnly	= 0L,
	kUnicodeFallbackCustomOnly	= 1L,
	kUnicodeFallbackDefaultFirst = 2L,
	kUnicodeFallbackCustomFirst	= 3L
};



/*
 	File:		Timer.h
 
 
*/


enum {
																/* high bit of qType is set if task is active */
	kTMTaskActive				= (1L << 15)
};

typedef struct TMTask 					TMTask;
typedef TMTask *						TMTaskPtr;
typedef CALLBACK_API( void , TimerProcPtr )(TMTaskPtr tmTaskPtr);
/*
	WARNING: TimerProcPtr uses register based parameters under classic 68k
			 and cannot be written in a high-level language without 
			 the help of mixed mode or assembly glue.
*/
typedef REGISTER_UPP_TYPE(TimerProcPtr) 						TimerUPP;
struct TMTask {
	QElemPtr 						qLink;
	short 							qType;
	TimerUPP 						tmAddr;
	long 							tmCount;
	long 							tmWakeUp;
	long 							tmReserved;
};


/*
 	File:		TextCommonPriv.h
 
 
*/


/*
   -----------------------------------------------------------------------------------------------------------
   TextEncoding creation & extraction macros.
   Current packed format:
  		31 30 29    26 25                 16 15                             0
  		|pack| format |       variant       |              base              |
  		|vers|        |                     |                                |
  		|2bit| 4 bits |       10 bits       |            16 bits             |
   Unpacked elements
  		base                                 15                             0
  		|                0                  |            16 bits             |
  		variant                                              9              0
  		|                0                                  |      10 bits   |
  		format                                                       3      0
  		|                0                                          | 4 bits |
   -----------------------------------------------------------------------------------------------------------
*/

enum {
	kTextEncodingVersion		= 0
};


enum {
	kTextEncodingBaseShiftBits	= 0,							/*	<13>*/
	kTextEncodingVariantShiftBits = 16,							/*	<13>*/
	kTextEncodingFormatShiftBits = 26,							/*	<13><16>*/
	kTextEncodingVersionShiftBits = 30
};



enum {
	kTextEncodingBaseSourceMask	= 0x0000FFFF,					/*	16 bits <13>*/
	kTextEncodingVariantSourceMask = 0x000003FF,				/*	10 bits <13><16>*/
	kTextEncodingFormatSourceMask = 0x0000000F,					/*	 4 bits <13><16>*/
	kTextEncodingVersionSourceMask = 0x00000003					/*	 2 bits*/
};


enum {
	kTextEncodingBaseMask		= kTextEncodingBaseSourceMask << kTextEncodingBaseShiftBits,
	kTextEncodingVariantMask	= kTextEncodingVariantSourceMask << kTextEncodingVariantShiftBits,
	kTextEncodingFormatMask		= kTextEncodingFormatSourceMask << kTextEncodingFormatShiftBits,
	kTextEncodingVersionMask	= kTextEncodingVersionSourceMask << kTextEncodingVersionShiftBits
};


enum {
	kTextEncodingVersionShifted	= (kTextEncodingVersion & kTextEncodingVersionSourceMask) << kTextEncodingVersionShiftBits
};


#define CreateTextEncodingPriv(base,variant,format) \
				( ((base & kTextEncodingBaseSourceMask) << kTextEncodingBaseShiftBits) \
				| ((variant & kTextEncodingVariantSourceMask) << kTextEncodingVariantShiftBits) \
				| ((format & kTextEncodingFormatSourceMask) << kTextEncodingFormatShiftBits) \
				| (kTextEncodingVersionShifted) )
#define GetTextEncodingBasePriv(encoding) \
				((encoding & kTextEncodingBaseMask) >> kTextEncodingBaseShiftBits)
#define GetTextEncodingVariantPriv(encoding) \
				((encoding & kTextEncodingVariantMask) >> kTextEncodingVariantShiftBits)
#define GetTextEncodingFormatPriv(encoding) \
				((encoding & kTextEncodingFormatMask) >> kTextEncodingFormatShiftBits)
#define IsMacTextEncoding(encoding) ((encoding & 0x0000FF00L) == 0x00000000L)
#define IsUnicodeTextEncoding(encoding) ((encoding & 0x0000FF00L) == 0x00000100L)
/* TextEncoding used by HFS*/

enum {
	kMacHFSTextEncoding			= 0x000000FF
};


/*
	File:		Instrumentation.h


*/
/*******************************************************************/
/*                        Types				                       */
/*******************************************************************/
/* Reference to an instrumentation class */
typedef struct InstOpaqueClassRef* InstClassRef;

/* Aliases to the generic instrumentation class for each type of class */
typedef InstClassRef InstPathClassRef;
typedef InstClassRef InstTraceClassRef;
typedef InstClassRef InstHistogramClassRef;
typedef InstClassRef InstSplitHistogramClassRef;
typedef InstClassRef InstMagnitudeClassRef;
typedef InstClassRef InstGrowthClassRef;
typedef InstClassRef InstTallyClassRef;

/* Reference to a data descriptor */
typedef struct InstOpaqueDataDescriptorRef* InstDataDescriptorRef;


/*******************************************************************/
/*            Constant Definitions                                 */
/*******************************************************************/

/* Reference to the root of the class hierarchy */
#define kInstRootClassRef	 ( (InstClassRef) -1)

/* Options used for creating classes */
typedef OptionBits InstClassOptions;


enum {
	kInstDisableClassMask			= 0x00,			/* Create the class disabled */
	kInstEnableClassMask			= 0x01,			/* Create the class enabled */

	kInstSummaryTraceClassMask		= 0x20			/* Create a summary trace class instead of a regular one */
};

								

EXTERN_API( Boolean )
EqualString						(ConstStr255Param 		str1,
								 ConstStr255Param 		str2,
								 Boolean 				caseSensitive,
								 Boolean 				diacSensitive);

								 


/*
 	File:		LowMemPriv.h
 
 
*/

/* The following replace storage used in low-mem on MacOS: */
extern struct FSVarsRec * gFSMVars;


#define LMGetFSMVars() gFSMVars



EXTERN_API( void )
InsTime							(QElemPtr 				tmTaskPtr);
EXTERN_API( void )
PrimeTime						(QElemPtr 				tmTaskPtr,
								 long 					count);
EXTERN_API( void )
RmvTime							(QElemPtr 				tmTaskPtr);


								 

/* PROTOTYPES */

#if HFS_DIAGNOSTIC
	extern void RequireFileLock(FileReference vp, int shareable);
	#define REQUIRE_FILE_LOCK(vp,s) RequireFileLock((vp),(s))
#else
	#define REQUIRE_FILE_LOCK(vp,s)
#endif


EXTERN_API( void )
BlockMove						(const void *			srcPtr,
								 void *					destPtr,
								 Size 					byteCount);
EXTERN_API( void )
BlockMoveData					(const void *			srcPtr,
								 void *					destPtr,
								 Size 					byteCount);

EXTERN_API_C( void )
BlockMoveUncached				(const void *			srcPtr,
								 void *					destPtr,
								 Size 					byteCount);

EXTERN_API_C( void )
BlockMoveDataUncached			(const void *			srcPtr,
								 void *					destPtr,
								 Size 					byteCount);

EXTERN_API_C( void )
BlockZero						(void *					destPtr,
								 Size 					byteCount);

EXTERN_API_C( void )
BlockZeroUncached				(void *					destPtr,
								 Size 					byteCount);

EXTERN_API( Ptr )
NewPtr							(Size 					byteCount);

EXTERN_API( Ptr )
NewPtrSys						(Size 					byteCount);

EXTERN_API( Ptr )
NewPtrClear						(Size 					byteCount);

EXTERN_API( Ptr )
NewPtrSysClear					(Size 					byteCount);

EXTERN_API( OSErr )
MemError						(void);

EXTERN_API( void )
DisposePtr						(Ptr 					p);

EXTERN_API( Size )
GetPtrSize						(Ptr 					p);

EXTERN_API( void )
SetPtrSize						(Ptr 					p,
								 Size 					newSize);
								 
EXTERN_API( void )
DisposeHandle					(Handle 				h);

EXTERN_API( void )
SetHandleSize					(Handle 				h,
								 Size 					newSize);

/*
 	File:		DateTimeUtils.h
 
 
*/
EXTERN_API( void )
GetDateTime						(unsigned long *		secs);



#endif	/* __hfs_macos_types__ */
