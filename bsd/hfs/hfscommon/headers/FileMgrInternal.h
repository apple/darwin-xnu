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
	File:		FilesInternal.h

	Contains:	IPI for File Manager (HFS Plus)

	Version:	HFS Plus 1.0

	Copyright:	© 1996-1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contacts:		Mark Day, Deric horn, Jim Luther

		Technology:			File Systems

	Writers:

		(JL)	Jim Luther
		(msd)	Mark Day
		(djb)	Don Brady
		(DSH)	Deric Horn

	Change History (most recent first):
	  <MOSXS>	 9/12/99	ser	Removed FCBs.
	  <MOSX>	  9/9/99	pwd	Fixed some VCB fields to be unsigned instead of signed to align
	  							the definitions with the MDB/volume header and actual use [#2355889].
 	  <MOSXS>	  9/3/99	ser	Added kUndefinedStrLen.
	  <MOSXS>	  6/3/99	djb	Removed unused/legacy vcb fields from ExtendedVCB.
	  <MOSXS>	11/20/98	djb	Add support for UTF-8 names.
	  <MOSXS>	 8/31/98	djb	Added boolean flag to GetTimeLocal prototype.
	  <MOSXS>	 6/30/98	djb	Add NodesAreContiguous prototype (for radar #2249539).
	  <MOSXS>	 6/22/98	djb	Add ERR_BASE to error codes to make them negative (for MacOS X only).
	  					Replace DeallocFile prototype with DeleteFile prototype.
	  <MOSXS>	  6/5/98	djb	Added CreateFileIDRef prototype;
	  <MOSXS>	  6/3/98	djb	Add MoveRenameCatalogNode prototype (replaces seperate Move and Rename).
	  <MOSXS>	 4/17/98	djb	Add VCB locking.
	  <MOSXS>	  4/6/98	djb	Removed CreateVolumeCatalogCache and DisposeVolumeCatalogCache (obsolete).
	  <MOSXS>	  4/2/98	djb	UpdateCatalogNode now takes parID and name as input.
	  <MOSXS>	 3/31/98	djb	Sync up with final HFSVolumes.h header file.
	  <MOSXS>	 3/17/98	djb	Fixed CreateCatalogNode interface to take kCatalogFolderNode and
	  					kCatalogFileNode as type input.

	  <CS30>	 1/29/98	DSH		Added TrashVolumeDiskCache prototype for TrashAllFSCaches API
									support.
	  <CS29>	12/10/97	DSH		2201501, Overload the NodeData valence field for over 2 Gig file
									support.
	  <CS28>	11/18/97	DSH		Conditionalize ou BlockCameFromDisk() macro for DFA
	  <CS27>	11/16/97	djb		LockMappingTable is now defined in UnicodeConverterPriv.i.
	  <CS26>	11/13/97	djb		Move CatalogIterator struct to CatalogPrivate.h. Include
									UnicodeConverter.i instead of Unicode.i.
	  <CS25>	 11/3/97	JL		#2001483 - changed UnMountVolume's prototype.
		<24>	10/31/97	DSH		Added consistencyStatus parameter to MountCheck.
	  <CS23>	10/21/97	DSH		Interfacer tweak
	  <CS22>	10/21/97	DSH		Conditionalize LMGetFCBTable, LMGetFSVars for DFA to call
									through DFAs LowMem accessors.
	  <CS21>	10/20/97	msd		Add a bytesMaximum parameter to BlockAllocate; removed fcb
									parameter.
	  <CS20>	10/19/97	msd		Bug 1684586. Remove the modifyDate field from CatalogNodeDate.
									GetCatInfo and SetCatInfo use only contentModDate.
	  <CS19>	10/16/97	djb		Add LMGetFSVars and LMGetFCBTable macros, add gBlockCacheDirty
									to FSVars, simplified HFS Stack swapping macros.
	  <CS18>	10/13/97	DSH		Added InitBTreeHeader prototype
	  <CS17>	10/13/97	djb		Add volumeNameEncodingHint to VCB, add textEncoding to
									CatalogNodeData, add gTextEncodingFontName to FSVars.
	  <CS16>	 10/1/97	DSH		Added CheckVolumeConsistency() for 1682475.
	  <CS15>	 10/1/97	djb		New Catalog iterators and Catalog node cache SPI.
	  <CS14>	 9/17/97	DSH		Moved prototype HFSBlocksFromTotalSectors() here for DFA
									wrapperless volume support.
	  <CS13>	 9/16/97	msd		Add a field to FSVarsRec to store old WriteXParam address.
	  <CS12>	 9/15/97	djb		Add gBootPToUTable to FSVars (used to bootstrap Unicode).
	  <CS11>	  9/7/97	djb		Add FlushBlockCache prototype.
	  <CS10>	  9/4/97	djb		Add cmParentNotFound error code and reportMissingParent bit.
	   <CS9>	  9/4/97	msd		Remove unused attributes calls. Rename PropertyCloseVolume to
									AttributesCloseVolume. In CatalogNodeData, replace
									attributeModDate with modifyDate. Remove macro LatestModDate.
	   <CS8>	 8/22/97	djb		Add readFromDisk flag to GetCacheBlock and BlockCameFromDisk
									macro.
	   <CS7>	 8/18/97	DSH		Override ASM cache accessing routines for DFA to use DFA cache.
	   <CS6>	 7/28/97	msd		Add prototypes for CacheReadInPlace, RemountWrappedVolumes.
	   <CS5>	 7/25/97	DSH		Added GenericMRUCache Routines
	   <CS4>	 7/22/97	msd		In CatalogNodeData, move attributeModDate after backupDate; this
									allows SetCatInfo to manipulate the rest of the dates in one
									block, the same as in the parameter block.
	   <CS3>	 7/21/97	djb		Add more instrumentation globals (CallProfile). Reallign FSVars.
	   <CS2>	 7/18/97	msd		Selector for PBCreateAttribute conflicts with PBGetXCatInfo. The
									attribute calls now have selectors in the range $65..$69.
	   <CS1>	 7/16/97	DSH		first checked in
	  <CS23>	  7/8/97	DSH		Added LockMappingTable() until its moved into the Unicode header
									files.
	  <CS22>	  7/7/97	DSH		Taking out changes made in HFS <45> for greater compatability
									with the Tempo installer.
	  <CS21>	 6/27/97	msd		Add PBLongRename SPI. Add prototype for
									RenameCatalogNodeUnicode.
	  <CS20>	 6/26/97	DSH		Conditionalized macro LocalToUTC to not look at FSVars for DFA.
	  <CS19>	 6/25/97	msd		Add prototype for HFSCommunicationProc.
	  <CS18>	 6/24/97	DSH		Adding runtime flags to deturmine unicode usage and installation
									status.
	  <CS17>	 6/24/97	djb		Add linkCount to CatalogNodeData. Add LinkCatalogNode prototype.
									Move Private Catalog Manager prototypes to CatalogPrivate.h.
	  <CS16>	 6/20/97	msd		Add prototype for CopyCatalogNodeData. In CatalogNodeData,
									replaced modifyDate with contentModDate and attributeModDate.
									Added a LatestModDate macro.
		<15>	 6/18/97	djb		Add mask to ConversionContext. Add encodingsBitmap to VCB (and
									reallign some fields). Add gInstalledEncodings to FSVars.
	  <CS14>	 6/17/97	msd		The conversions between local time and UTC have the sign of the
									offset backwards.
	  <CS13>	 6/13/97	djb		Removed PrepareOutputName. Changed parameters for
									DeleteCatalogNode, MoveCatalogNode, PrepareInputName. Add
									private catalog macros.
	  <CS12>	 6/12/97	msd		Export BlockAllocateAny and UpdateVCBFreeBlks.
	  <CS11>	 6/12/97	msd		Add a parameter block and prototype for an SPI to create very
									large files.
	  <CS10>	  6/9/97	msd		Add an offsetToUTC field to FSVarsRec. Add prototypes for
									GetTimeUTC and GetTimeLocal; add macros for LocalToUTC and
									UTCToLocal.
	   <CS9>	  6/5/97	msd		Add MapLogicalToPhysical (internal routine), PBMapFilePosition
									for external use.
	   <CS8>	  6/4/97	djb		More Unicode converter changes (support for non roman scripts).
	   <CS7>	  6/2/97	msd		Add prototype for AdjustEOF.
	   <CS6>	 5/28/97	msd		Add prototypes for attributes SPI, both internal routines and PB
									calls. Add FindFileNameGlueRec and FindFileName routine.
									Prototypes for FindFileControlBlock and AccessBTree disappeared,
									so added again.
	   <CS5>	 5/20/97	DSH		Including LowMemPriv.a in DFA compiles
	   <CS4>	 5/19/97	djb		Add uppLockMappingTable to FSVars.
	   <CS3>	 5/19/97	djb		Add CreateVolumeCatalogCache and DisposeVolumeCatalogCache
									prototypes. Remove private CatalogDataCache structure.
	   <CS2>	 5/16/97	msd		Use fixed-size integers for GetBlock_glue and RelBlock_glue so
									it will build with compilers other than MPW C and SC. Add
									prototype for FillHFSStack, UnMountVolume, and
									MakeVCBsExtendedVCBs from VolumeRequests.c. Add prototypes for
									CreateEmbeddedVolume and InitUnicodeConverter.
	   <CS1>	  5/9/97	djb		first checked in
	   <CS2>	  5/7/97	djb		Add summary trace data. Shrink FSVars.later to 4 longs.
	   <CS1>	 4/28/97	djb		first checked in

*/
#ifndef __FILEMGRINTERNAL__
#define __FILEMGRINTERNAL__

#include <sys/param.h>
#include <sys/vnode.h>

#include "../../hfs.h"
#include "../../hfs_macos_defs.h"
#include "../../hfs_format.h"


#if PRAGMA_ONCE
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if PRAGMA_IMPORT
#pragma import on
#endif

#if PRAGMA_STRUCT_ALIGN
	#pragma options align=mac68k
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(push, 2)
#elif PRAGMA_STRUCT_PACK
	#pragma pack(2)
#endif

/* CatalogNodeID is used to track catalog objects */
typedef UInt32		HFSCatalogNodeID;

/* internal error codes*/

#if TARGET_API_MACOS_X
  #define ERR_BASE	-32767
#else
  #define ERR_BASE	0
#endif

enum {
																/* FXM errors*/
	fxRangeErr					= ERR_BASE + 16,				/* file position beyond mapped range*/
	fxOvFlErr					= ERR_BASE + 17,				/* extents file overflow*/
																/* Unicode errors*/
	uniTooLongErr				= ERR_BASE + 24,				/* Unicode string too long to convert to Str31*/
	uniBufferTooSmallErr		= ERR_BASE + 25,				/* Unicode output buffer too small*/
	uniNotMappableErr			= ERR_BASE + 26,				/* Unicode string can't be mapped to given script*/
																/* BTree Manager errors*/
	btNotFound					= ERR_BASE + 32,				/* record not found*/
	btExists					= ERR_BASE + 33,				/* record already exists*/
	btNoSpaceAvail				= ERR_BASE + 34,				/* no available space*/
	btNoFit						= ERR_BASE + 35,				/* record doesn't fit in node */
	btBadNode					= ERR_BASE + 36,				/* bad node detected*/
	btBadHdr					= ERR_BASE + 37,				/* bad BTree header record detected*/
	dsBadRotate					= ERR_BASE + 64,				/* bad BTree rotate*/
																/* Catalog Manager errors*/
	cmNotFound					= ERR_BASE + 48,				/* CNode not found*/
	cmExists					= ERR_BASE + 49,				/* CNode already exists*/
	cmNotEmpty					= ERR_BASE + 50,				/* directory CNode not empty (valence = 0)*/
	cmRootCN					= ERR_BASE + 51,				/* invalid reference to root CNode*/
	cmBadNews					= ERR_BASE + 52,				/* detected bad catalog structure*/
	cmFThdDirErr				= ERR_BASE + 53,				/* thread belongs to a directory not a file*/
	cmFThdGone					= ERR_BASE + 54,				/* file thread doesn't exist*/
	cmParentNotFound			= ERR_BASE + 55,				/* CNode for parent ID does not exist*/
																/* TFS internal errors*/
	fsDSIntErr					= -127							/* Internal file system error*/
};


/* internal flags*/


enum {
																/* File System busy flag:*/
																/* Bit zero of FSBusy (lomem $360) is true when the file system is running.*/
																/* The word at $360 is cleared when the file system is exited. The*/
																/* bits defined here are for additional flags in the FSBusy word that are*/
																/* valid only when the file system is running.*/
	fsBusyBit					= 0,							/* file system is running; other FSBusy bits are valid*/
	fsSCSIDefer					= 1,							/* file system is waiting for SCSI transaction to complete*/
	fsIntMaskDefer				= 2,							/* file system is waiting until the interrupt mask is lowered*/
																/* Flag bits in HFSFlags byte:*/
	hfsReq						= 0,							/* Set if request is specific to HFS*/
	dirCN						= 1,							/* Set if a CNode is a directory*/
	reportMissingParent			= 4,							/* tell Catalog to report missing parents (used by MakeFSSpec)*/
	skipPMSP					= 5,							/* Set to skip PMSP setup (one-shot)*/
	noPMSP						= 6,							/* Set to disable PMSP completely (status flag)*/
	hfsContd					= 7,							/* Set if Async trap is continued*/
																/* fsFlags values*/
	fsNoAllocate				= 0,
	fsNoAllocateMask			= 0x01,							/* true when allocating memory is a very bad idea*/
	fsNeedFCBs					= 1,
	fsNeedFCBsMask				= 0x02,							/* true when a local FCB couldn't be found	*/
	fsNoFCBExpansion			= 2,
	fsNoFCBExpansionMask		= 0x04,							/* true if no FCB expansion logic is desired*/
																/*	ExtendFile option flags*/
																/*	extendFileAllBit			= 0,				|* allocate all requested bytes or none *|*/
																/*	extendFileAllMask			= 0x0001,*/
																/*	*/
																/*	extendFileContigBit			= 1,				|* force contiguous allocation *|*/
																/*	extendFileContigMask		= 0x0002*/
	kEFContigBit				= 1,							/*	force contiguous allocation*/
	kEFContigMask				= 0x02,
	kEFAllBit					= 0,							/*	allocate all requested bytes or none*/
	kEFAllMask					= 0x01,							/*	TruncateFile option flags*/
	kTFTrunExtBit				= 0,							/*	truncate to the extent containing new PEOF*/
	kTFTrunExtMask				= 1
};

enum {
	kUndefinedStrLen			= 0								/* Unknown string length */
};

enum {
	HFSStkLen					= 1792,							/* old stack size (pre HFS Plus)*/
	kFileSystemStackSlop		= 16,							/* additional temporary space*/
	kFileSystemStackSize		= 16384,						/* give us more breathing room*/
	kFileSystemVersion			= FOUR_CHAR_CODE('2.0A'),		/* current file system version*/
																/*	31744 = $7C00, a nice round number close to*/
																/*	(32767*1000)/1024, which is about the largest */
																/*	free space unsuspecting, decimal-K minded apps*/
																/*	might be expected to handle.*/
																/*	AlBlkLim*/
	kMaxHFSAllocationBlocks		= 31744,
	WDRfnMin					= -32767,						/* lowest assigned WD RefNum*/
	WDRfnMax					= -4096,						/* largest possible WDrefnum*/
	kFirstFileRefnum			= 2,							/* smallest FCB refnum*/
	kNoHint						= 0
};


/* Internal LowMem pointers*/

/*€€ The following should really be in LowMemPriv.i*/

enum {
	FSCallAsync					= 0x0342,						/*	ONE BYTE FREE*/
	NoEject						= 0x034B,						/* used by Eject and Offline*/
	CacheFlag					= 0x0377,
	SysBMCPtr					= 0x0378,						/* System-wide bitmap cache pointer*/
	SysCtlCPtr					= 0x0380,						/* System-wide control cache pointer*/
	HFSDSErr					= 0x0392,						/* Final gasp - error that caused IOErr.*/
	LMParamBlock				= 0x03A4,						/* LMGetParams() just gives us a copy of it*/
	FSVarsPtr					= 0x0BB8,						/* lomem that points to file system variable block*/
	CacheVars					= 0x0394,
	HFSStkPtr					= 0x036E,						/* Temporary location of HFS Stack pointer*/
	FSIOErr						= 0x03DE,						/* last I/O error (NEXT WORD FREE)*/
																/* file manager vectors not found in LowMemPriv.i*/
	JUpdAltMDB					= (0xED) * 4 + 0x0400,			/* ($A0ED) $0400 is n/OSTable*/
	JCkExtFS					= (0xEE) * 4 + 0x0400,			/* ($A0EE) $0400 is n/OSTable*/
	JBMChk						= (0xF0) * 4 + 0x0400,			/* ($A0F0) $0400 is n/OSTable*/
	JTstMod						= (0xF1) * 4 + 0x0400,			/* ($A0F1) $0400 is n/OSTable*/
	JLocCRec					= (0xF2) * 4 + 0x0400,			/* ($A0F2) $0400 is n/OSTable*/
	JTreeSearch					= (0xF3) * 4 + 0x0400,			/* ($A0F3) $0400 is n/OSTable*/
	JMapFBlock					= (0xF4) * 4 + 0x0400,			/* ($A0F4) $0400 is n/OSTable*/
	JXFSearch					= (0xF5) * 4 + 0x0400,			/* ($A0F5) $0400 is n/OSTable*/
	JReadBM						= (0xF6) * 4 + 0x0400			/* ($A0F6) $0400 is n/OSTable*/
};


/* Poor Man's Search Path*/

struct SearchPathHeader {
	Ptr 							PMSPHook;					/* Hook for PMSP modification*/
	short 							PMSPIndx;					/* Index to PMSP index from start of PMSP*/
};
typedef struct SearchPathHeader SearchPathHeader;

struct SearchPathEntry {
	short 							spVRefNum;					/* VRefNum in PMSP entry*/
	UInt32 							spDirID;					/* Directory ID in PMSP entry*/
};
typedef struct SearchPathEntry SearchPathEntry;


enum {
	kPoorMansSearchIndex		= -2,
	MaxDVCnt					= 8,							/* Leave room for 8 default VRefNums*/
	PMSPSize					= MaxDVCnt * sizeof(SearchPathEntry) + sizeof(SearchPathHeader) + 2
};



enum {
	fsWDCBExtendCount			= 8,							/* # of WDCB's to add when we run out*/
																/*	FileIDs variables*/
	kNumExtentsToCache			= 4								/*	just guessing for ExchangeFiles*/
};


enum {
	kInvalidMRUCacheKey			= -1L,							/* flag to denote current MRU cache key is invalid*/
	kDefaultNumMRUCacheBlocks	= 16							/* default number of blocks in each cache*/
};


/* Universal Extent Key */

union ExtentKey {
	HFSExtentKey 					hfs;
	HFSPlusExtentKey 				hfsPlus;
};
typedef union ExtentKey					ExtentKey;
/* Universal extent descriptor */

union ExtentDescriptor {
	HFSExtentDescriptor 			hfs;
	HFSPlusExtentDescriptor 		hfsPlus;
};
typedef union ExtentDescriptor			ExtentDescriptor;
/* Universal extent record */

union ExtentRecord {
	HFSExtentRecord 				hfs;
	HFSPlusExtentRecord 			hfsPlus;
};
typedef union ExtentRecord				ExtentRecord;
/* Universal catalog key */

union CatalogKey {
	HFSCatalogKey 					hfs;
	HFSPlusCatalogKey 				hfsPlus;
};
typedef union CatalogKey				CatalogKey;
/* Universal catalog data record */

union CatalogRecord {
	SInt16 							recordType;
	HFSCatalogFolder 				hfsFolder;
	HFSCatalogFile 					hfsFile;
	HFSCatalogThread 				hfsThread;
	HFSPlusCatalogFolder 			hfsPlusFolder;
	HFSPlusCatalogFile 				hfsPlusFile;
	HFSPlusCatalogThread 			hfsPlusThread;
};
typedef union CatalogRecord				CatalogRecord;


enum {
	CMMaxCName					= kHFSMaxFileNameChars
};


enum {
	vcbMaxNam					= 27,							/* volumes currently have a 27 byte max name length*/
																/* VCB flags*/
	vcbManualEjectMask			= 0x0001,						/* bit 0	manual-eject bit: set if volume is in a manual-eject drive*/
	vcbFlushCriticalInfoMask	= 0x0002,						/* bit 1	critical info bit: set if critical MDB information needs to flush*/
																/*	IoParam->ioVAtrb*/
	kDefaultVolumeMask			= 0x0020,
	kFilesOpenMask				= 0x0040
};


/* Catalog Node Data - universal data returned from the Catalog Manager*/


enum {
	xFFFilAttrLockMask			= 0x70
};

/*	valence is overloaded for files and used as additional flags. 2201501*/

enum {
	kLargeDataForkMask			= 0x00000001,
	kLargeRsrcForkMask			= 0x00000002
};

/* Universal catalog name*/

union CatalogName {
	Str31 							pstr;
	HFSUniStr255 					ustr;
};
typedef union CatalogName CatalogName;

/* Unicode Conversion*/


enum {
	kMacBaseEncodingCount		= 50,
	kTextEncodingUndefined		= 0x00007FFF
};

struct ConversionContext {
	TextToUnicodeInfo 				toUnicode;
	UnicodeToTextInfo 				fromUnicode;
};
typedef struct ConversionContext ConversionContext;

struct CallProfile {
	UInt16 							refCount;
	UInt16 							errCount;
	UInt32 							callCount;
	UInt32 							minTime;
	UInt32 							maxTime;
	UInt64 							totalTime;
	UInt64 							startBase;					/* in nanoseconds*/
};
typedef struct CallProfile CallProfile;


struct FSVarsRec {
	UInt32 							gDefaultBaseEncoding;
	ItemCount 						gInstalledEncodings;
	ConversionContext 				gConversionContext[50];
	Ptr 							gBootPToUTable;				/* used by boot code to find Extensions folder*/
	StringPtr 						gTextEncodingFontName;		/* points to font name (only used when no HFS Plus volumes have been mounted)*/
	Boolean 						gUseDynamicUnicodeConverters;
	Boolean 						gIsUnicodeInstalled;
};
typedef struct FSVarsRec FSVarsRec;



/*
 * MacOS accessor routines
 */
#define GetFileControlBlock(fref)			((FCB *)((fref)->v_data))
#define GetFileRefNumFromFCB(filePtr)		((filePtr)->h_vp)


EXTERN_API_C( Boolean )
BlockCameFromDisk				(void);

/*	The following macro marks a VCB as dirty by setting the upper 8 bits of the flags*/
EXTERN_API_C( void )
MarkVCBDirty					(ExtendedVCB *vcb);

EXTERN_API_C( void )
MarkVCBClean					(ExtendedVCB *vcb);

EXTERN_API_C( Boolean )
IsVCBDirty						(ExtendedVCB *vcb);


#define VCB_LOCK_INIT(vcb)		simple_lock_init(&vcb->vcbSimpleLock)
#define VCB_LOCK(vcb)			simple_lock(&vcb->vcbSimpleLock)
#define VCB_UNLOCK(vcb)			simple_unlock(&vcb->vcbSimpleLock)

#define	MarkVCBDirty(vcb)		{ VCB_LOCK((vcb)); ((vcb)->vcbFlags |= 0xFF00); VCB_UNLOCK((vcb)); }
#define	MarkVCBClean(vcb)		{ VCB_LOCK((vcb)); ((vcb)->vcbFlags &= 0x00FF); VCB_UNLOCK((vcb)); }
#define	IsVCBDirty(vcb)			((Boolean) ((vcb->vcbFlags & 0xFF00) != 0))


/*	Test for error and return if error occurred*/
EXTERN_API_C( void )
ReturnIfError					(OSErr 					result);

#define	ReturnIfError(result)					if ( (result) != noErr ) return (result); else ;
/*	Test for passed condition and return if true*/
EXTERN_API_C( void )
ReturnErrorIf					(Boolean 				condition,
								 OSErr 					result);

#define	ReturnErrorIf(condition, error)			if ( (condition) )	return( (error) );
/*	Exit function on error*/
EXTERN_API_C( void )
ExitOnError						(OSErr 					result);

#define	ExitOnError( result )					if ( ( result ) != noErr )	goto ErrorExit; else ;
/*	Return the low 16 bits of a 32 bit value, pinned if too large*/
EXTERN_API_C( UInt16 )
LongToShort						(UInt32 				l);

#define	LongToShort( l )	l <= (UInt32)0x0000FFFF ? ((UInt16) l) : ((UInt16) 0xFFFF)


/* Catalog Manager Routines (IPI)*/

EXTERN_API_C( OSErr )
CreateCatalogNode				(ExtendedVCB *			volume,
								 HFSCatalogNodeID 		parentID,
								 ConstUTF8Param	 		name,
								 UInt32 				nodeType,
								 HFSCatalogNodeID *		catalogNodeID,
								 UInt32 *				catalogHint);

EXTERN_API_C( OSErr )
DeleteCatalogNode				(ExtendedVCB *			volume,
								 HFSCatalogNodeID 		parentID,
								 ConstUTF8Param 		name,
								 UInt32 				hint);

EXTERN_API_C( OSErr )
GetCatalogNode					(ExtendedVCB *			volume,
								 HFSCatalogNodeID 		parentID,
								 ConstUTF8Param 		name,
                                 UInt32 				length,
                                 UInt32 				hint,
								 CatalogNodeData *		nodeData,
								 UInt32 *				newHint);

EXTERN_API_C( OSErr )
GetCatalogOffspring				(ExtendedVCB *			volume,
								 HFSCatalogNodeID 		folderID,
								 UInt16 				index,
								 CatalogNodeData *		nodeData,
								 HFSCatalogNodeID *		nodeID,
								 SInt16 *			nodeType);

EXTERN_API_C( OSErr )
MoveRenameCatalogNode			(ExtendedVCB *			volume,
								 HFSCatalogNodeID		srcParentID,
								 ConstUTF8Param			srcName,
					  			 UInt32					srcHint,
					  			 HFSCatalogNodeID		dstParentID,
					  			 ConstUTF8Param			dstName,
					  			 UInt32 *				newHint);

EXTERN_API_C( OSErr )
UpdateCatalogNode				(ExtendedVCB *			volume,
								 HFSCatalogNodeID		parentID,
								 ConstUTF8Param			name,
								 UInt32					catalogHint, 
								 const CatalogNodeData * nodeData);

EXTERN_API_C( OSErr )
CreateFileIDRef					(ExtendedVCB *			volume,
								 HFSCatalogNodeID		parentID,
								 ConstUTF8Param			name,
								 UInt32					hint,
								 HFSCatalogNodeID *		threadID);

EXTERN_API_C( OSErr )
ExchangeFileIDs					(ExtendedVCB *			volume,
								 ConstUTF8Param			srcName,
								 ConstUTF8Param			destName,
								 HFSCatalogNodeID		srcID,
								 HFSCatalogNodeID		destID,
								 UInt32					srcHint,
								 UInt32					destHint );

EXTERN_API_C( OSErr )
LinkCatalogNode					(ExtendedVCB *			volume,
								 HFSCatalogNodeID 		parentID,
								 ConstUTF8Param 		name,
								 HFSCatalogNodeID 		linkParentID,
								 ConstUTF8Param 		linkName);

EXTERN_API_C( SInt32 )
CompareCatalogKeys				(HFSCatalogKey *		searchKey,
								 HFSCatalogKey *		trialKey);

EXTERN_API_C( SInt32 )
CompareExtendedCatalogKeys		(HFSPlusCatalogKey *	searchKey,
								 HFSPlusCatalogKey *	trialKey);

EXTERN_API_C( OSErr )
InitCatalogCache				(void);

EXTERN_API_C( void )
InvalidateCatalogCache			(ExtendedVCB *			volume);


/* GenericMRUCache Routines*/
EXTERN_API_C( OSErr )
InitMRUCache					(UInt32 				bufferSize,
								 UInt32 				numCacheBlocks,
								 Ptr *					cachePtr);

EXTERN_API_C( OSErr )
DisposeMRUCache					(Ptr 					cachePtr);

EXTERN_API_C( void )
TrashMRUCache					(Ptr 					cachePtr);

EXTERN_API_C( OSErr )
GetMRUCacheBlock				(UInt32 				key,
								 Ptr 					cachePtr,
								 Ptr *					buffer);

EXTERN_API_C( void )
InvalidateMRUCacheBlock			(Ptr 					cachePtr,
								 Ptr 					buffer);

EXTERN_API_C( void )
InsertMRUCacheBlock				(Ptr 					cachePtr,
								 UInt32 				key,
								 Ptr 					buffer);

/* BTree Manager Routines*/

typedef CALLBACK_API_C( SInt32 , KeyCompareProcPtr )(void *a, void *b);


EXTERN_API_C( OSErr )
SearchBTreeRecord				(FileReference 				refNum,
								 const void *			key,
								 UInt32 				hint,
								 void *					foundKey,
								 void *					data,
								 UInt16 *				dataSize,
								 UInt32 *				newHint);

EXTERN_API_C( OSErr )
InsertBTreeRecord				(FileReference 				refNum,
								 void *					key,
								 void *					data,
								 UInt16 				dataSize,
								 UInt32 *				newHint);

EXTERN_API_C( OSErr )
DeleteBTreeRecord				(FileReference 				refNum,
								 void *					key);

EXTERN_API_C( OSErr )
ReplaceBTreeRecord				(FileReference 				refNum,
								 const void *			key,
								 UInt32 				hint,
								 void *					newData,
								 UInt16 				dataSize,
								 UInt32 *				newHint);

/*	From HFSVolumesInit.c*/
EXTERN_API_C( void )
InitBTreeHeader					(UInt32 				fileSize,
								 UInt32 				clumpSize,
								 UInt16 				nodeSize,
								 UInt16 				recordCount,
								 UInt16 				keySize,
								 UInt32 				attributes,
								 UInt32 *				mapNodes,
								 void *					buffer);

/*	Prototypes for big block cache*/

EXTERN_API_C( OSErr )
InitializeBlockCache			(UInt32 				blockSize,
								 UInt32 				blockCount);

EXTERN_API_C( OSErr )
FlushBlockCache					(void);

EXTERN_API_C( OSErr )
GetCacheBlock					(FileReference 				fileRefNum,
								 UInt32 				blockNumber,
								 UInt32 				blockSize,
								 UInt16 				options,
								 LogicalAddress *		buffer,
								 Boolean *				readFromDisk);

EXTERN_API_C( OSErr )
ReleaseCacheBlock				(LogicalAddress 		buffer,
								 UInt16 				options);

EXTERN_API_C( OSErr )
MarkCacheBlock					(LogicalAddress 		buffer);

EXTERN_API_C( OSErr )
TrashCacheBlocks				(FileReference 				fileRefNum);

/*	Prototypes for C->Asm glue*/
EXTERN_API_C( OSErr )
GetBlock_glue					(UInt16 				flags,
								 UInt32 				nodeNumber,
								 Ptr *					nodeBuffer,
                   						 FileReference 				refNum,
								 ExtendedVCB *			vcb);

EXTERN_API_C( OSErr )
RelBlock_glue					(Ptr 					nodeBuffer,
								 UInt16 				flags);

EXTERN_API_C( void )
MarkBlock_glue					(Ptr 					nodeBuffer);

EXTERN_API_C( OSErr )
C_FlushCache					(ExtendedVCB *			vcb,
								 UInt32 				flags,
                 						 FileReference 				refNum);


EXTERN_API_C( void )	TrashVolumeDiskCache(ExtendedVCB * vcb);

/*	Prototypes for exported routines in VolumeAllocation.c*/
EXTERN_API_C( OSErr )
BlockAllocate					(ExtendedVCB *			vcb,
								 UInt32 				startingBlock,
								 SInt64 				bytesRequested,
								 SInt64 				bytesMaximum,
								 Boolean 				forceContiguous,
								 UInt32 *				startBlock,
								 UInt32 *				actualBlocks);

EXTERN_API_C( OSErr )
BlockDeallocate					(ExtendedVCB *			vcb,
								 UInt32 				firstBlock,
								 UInt32 				numBlocks);

EXTERN_API_C( OSErr )
UpdateFreeCount					(ExtendedVCB *			vcb);


EXTERN_API_C( OSErr )
AllocateFreeSpace				(ExtendedVCB *			vcb,
								 UInt32 *				startBlock,
								 UInt32 *				actualBlocks);

EXTERN_API_C( UInt32 )
FileBytesToBlocks				(SInt64 				numerator,
								 UInt32 				denominator);

EXTERN_API_C( OSErr )
BlockAllocateAny				(ExtendedVCB *			vcb,
								 UInt32 				startingBlock,
								 UInt32 				endingBlock,
								 UInt32 				maxBlocks,
								 UInt32 *				actualStartBlock,
								 UInt32 *				actualNumBlocks);

EXTERN_API_C( void )
UpdateVCBFreeBlks				(ExtendedVCB *			vcb);

/*	File Extent Mapping routines*/
EXTERN_API_C( OSErr )
FlushExtentFile					(ExtendedVCB *			vcb);

EXTERN_API_C( SInt32 )
CompareExtentKeys				(const HFSExtentKey *	searchKey,
								 const HFSExtentKey *	trialKey);

EXTERN_API_C( SInt32 )
CompareExtentKeysPlus			(const HFSPlusExtentKey *searchKey,
								 const HFSPlusExtentKey *trialKey);

EXTERN_API_C( OSErr )
DeleteFile						(ExtendedVCB *			vcb,
								 HFSCatalogNodeID 		parDirID,
								 ConstUTF8Param 		catalogName,
								 UInt32					catalogHint);

EXTERN_API_C( OSErr )
TruncateFileC					(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 SInt64 				peof,
								 Boolean 				truncateToExtent);

EXTERN_API_C( OSErr )
ExtendFileC						(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 SInt64 				bytesToAdd,
								 UInt32 				flags,
								 SInt64 *				actualBytesAdded);

EXTERN_API_C( OSErr )
MapFileBlockC					(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 size_t 				numberOfBytes,
								 off_t 					offset,
								 daddr_t *				startBlock,
								 size_t *				availableBytes);

#if TARGET_API_MACOS_X
EXTERN_API_C( Boolean )
NodesAreContiguous				(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 UInt32					nodeSize);
#endif
EXTERN_API_C( void )
AdjustEOF						(FCB	 *			sourceFCB);

/*	Utility routines*/

EXTERN_API_C( void )
ClearMemory						(void *					start,
								 UInt32 				length);

EXTERN_API_C( Boolean )
UnicodeBinaryCompare			(ConstHFSUniStr255Param ustr1,
								 ConstHFSUniStr255Param ustr2);

EXTERN_API_C( Boolean )
PascalBinaryCompare				(ConstStr31Param 		pstr1,
								 ConstStr31Param 		pstr2);

EXTERN_API_C( OSErr )
VolumeWritable					(ExtendedVCB *	vcb);


/*	Get the current time in UTC (GMT)*/
EXTERN_API_C( UInt32 )
GetTimeUTC						(void);

/*	Get the current local time*/
EXTERN_API_C( UInt32 )
GetTimeLocal					(Boolean forHFS);

EXTERN_API_C( UInt32 )
LocalToUTC						(UInt32 				localTime);

EXTERN_API_C( UInt32 )
UTCToLocal						(UInt32 				utcTime);


/*	Volumes routines*/
EXTERN_API_C( OSErr )
FlushVolumeControlBlock			(ExtendedVCB *			vcb);

EXTERN_API_C( OSErr )
CheckVolumeOffLine				(ExtendedVCB *			vcb);

EXTERN_API_C( OSErr )
ValidVolumeHeader				(HFSPlusVolumeHeader *			volumeHeader);

EXTERN_API_C( void )
FillHFSStack					(void);


EXTERN_API_C( OSErr )
AccessBTree						(ExtendedVCB *			vcb,
                 						 FileReference 				refNum,
								 UInt32 				fileID,
								 UInt32 				fileClumpSize,
								 void *					CompareRoutine);

EXTERN_API_C( void )
RemountWrappedVolumes			(void);

EXTERN_API_C( OSErr )
CheckVolumeConsistency			(ExtendedVCB *			vcb);

EXTERN_API_C( void )
HFSBlocksFromTotalSectors		(UInt32 				totalSectors,
								 UInt32 *				blockSize,
								 UInt16 *				blockCount);




#if PRAGMA_STRUCT_ALIGN
	#pragma options align=reset
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(pop)
#elif PRAGMA_STRUCT_PACK
	#pragma pack()
#endif

#ifdef PRAGMA_IMPORT_OFF
#pragma import off
#elif PRAGMA_IMPORT
#pragma import reset
#endif

#ifdef __cplusplus
}
#endif

#endif /* __FILEMGRINTERNAL__ */

