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
    File:       zPEF.h

    Contains:   PEF format declarations.

    Version:    Maxwell

    Copyright:  © 1992-1996 by Apple Computer, Inc., all rights reserved.

    File Ownership:

        DRI:                Alan Lillich

        Other Contact:      <<unknown>>

        Technology:         Core Runtime

    Writers:

        (AWL)   Alan Lillich
        (ELE)   Erik Eidt

     Change History (most recent first):

         <7>     2/28/96    AWL     Adapt for new container handler model.
         <6>     4/12/95    AWL     Fix bit field problem.
         <5>     8/29/94    AWL     Remove "never" share mode.
         <4>     8/23/94    AWL     Update section sharing constants.
         <3>     4/28/94    AWL     Simplify cross address space use for booting.
         <2>     4/11/94    AWL     Use 68K alignment for the export symbol structure.
         <1>     2/15/94    AWL     Initial checkin for kernel based CFM.

         -------------------------------------------------------------------------------------

            <7>   8/26/93    AWL        Move CFTypes.h and CFLoader.h up with other Apple private headers.
            <5>     7/8/93   AWL        (&ELE) Fixed version field names in import file IDs
            <4>     6/9/93   JRG        ELE & AWL Changes:
            <4>  06/08/93    AWL        (&ELE) Added more standard section types and packed data opcodes.
            <3>   9/23/92    ELE        added precomputed hash table for improved runtime performance.

     Version 1.3 Erik Eidt 9/23/92  updated for new hash table capabilities
     Version 1.2 Erik Eidt 7/8/92   updated for new relocations and other loader section size optimizations
     Version 1.1 Cheryl Lins 5/27/92 updated for PEF 1.2 definition
     Version 1.0 Cheryl Lins 4/7/92 initial version
*/


#ifndef __IOPEFINTERNALS__
#define __IOPEFINTERNALS__ 1

#include "IOPEFLoader.h"


typedef signed int      PEF_SBits32;    // ! Can't use SInt32, it is "signed long".
typedef unsigned int    PEF_UBits32;    // ! Can't use UInt32, it is "unsigned long".


#pragma options align=mac68k

/*========== File Header ==========*/

typedef struct {
     UInt16 magic1;                 /* magic flag describing execution machine and environment */
     UInt16 magic2;                 /* magic flag describing execution machine and environment */
     OSType  fileTypeID;            /* OSType identifier = 'pef' */
     OSType  architectureID;        /* OSType identifier = 'pwpc' */
     UInt32  versionNumber;     /* version number of this file format */
     UInt32  dateTimeStamp;     /* Macintosh date/time stamp */
     UInt32  oldDefVersion;     /* old definition version number */
     UInt32  oldImpVersion;     /* old implementation version number */
     UInt32  currentVersion;        /* current version number */
     SInt16  numberSections;        /* number of sections */
     SInt16  loadableSections;  /* number of sections that are loadable for execution,
                                                    also the section # of first non-loadable section */
     BytePtr    memoryAddress;      /* the location this container was last loaded */
} FileHeader, *FileHeaderPtr;

#define kPEFVersion 1               /* current version number */
#define kPEFMagic1  0x4A6F          /* value of magic1 for PEF */
#define kPEFMagic2  0x7921          /* value of magic2 for PEF */
#define kPEFTypeID  0x70656666      /* value of fileTypeID for 'peff' */
#define kPowerPCID  0x70777063      /* value of architecture ID 'pwpc' */

/*========== Section Header ==========*/

typedef struct {
     ByteCount        sectionName;  /* offset into global string table for section name */
     BytePtr          sectionAddress; /* preferred base address for the section */
     ByteCount        execSize;         /* section size in bytes during execution in memory including zero initialization */
     ByteCount        initSize;         /* section size in bytes during execution in memory before zero initialization */
     ByteCount        rawSize;          /* section size in bytes in container before loading */
     ByteCount        containerOffset;/* container offest to section's raw data */
     UInt8  regionKind;     /* section/region classification */
     UInt8   shareKind;     /* sharing classification */
     UInt8    alignment;        /* execution alignment requirement (0=byte,1=half,2=word,3=doubleword,4=quadword..) */
     UInt8    reservedA;
} SectionHeader, *SectionHeaderPtr;

/* TCFLSectionKind */
#define kPEFCodeSection 0
#define kPEFDataSection 1
#define kPEFPIDataSection 2
#define kPEFConstantSection 3
#define kPEFLoaderSection 4
#define kPEFDebugSection 5
#define kPEFExecDataSection 6
#define kPEFExceptionSection 7
#define kPEFTracebackSection 8

/* TCFLShareKind */
#define kPEFContextShare 1
#define kPEFGlobalShare 4
#define kPEFProtectedShare 5

/* Defines for PIDataSections */
#define kPEFZero 0
#define kPEFBlock 1
#define kPEFRepeat 2
#define kPEFRepeatBlock 3
#define kPEFRepeatZero  4
#define kPEFNoOpcode 0x0fff
#define kPEFOpcodeShift 5
#define kPEFFirstOperandMask 31


/*========== Loader Header ==========*/

typedef struct {
     SInt32      entryPointSection;      /* section number containing entry point descriptor */
     ByteCount   entryPointOffset;       /* offset to entry point descriptor within section */

     SInt32      initPointSection;       /* section number containing entry point descriptor */
     ByteCount   initPointOffset;        /* offset to entry point descriptor within section */

     SInt32      termPointSection;       /* section number containing entry point descriptor */
     ByteCount   termPointOffset;        /* offset to entry point descriptor within section */

     ItemCount       numImportFiles;             /* number of import file id entries */
     ItemCount       numImportSyms;          /* number of import symbol table entries */
     ItemCount       numSections;                /* number of sections with load-time relocations */
     ByteCount   relocationsOffset;      /* offset to relocation descriptions table */

     ByteCount   stringsOffset;          /* offset to loader string table */

     ByteCount   hashSlotTable;          /* offset to hash slot table */
     ItemCount       hashSlotTabSize;        /* number of hash slot entries */
     ItemCount       numExportSyms;          /* number of export symbol table entries */
} LoaderHeader, *LoaderHeaderPtr;

/*========== Loader Section Header ==========*/

typedef struct {
     SInt16  sectionNumber;          /* reference to primary section number */
     SInt16  reservedA;                  /* if TSectNum were 16 bits, which it isn't */
     ItemCount       numRelocations;             /* number of loader relocations for this section */
     ByteCount   relocationsOffset;      /* offset to relocation descriptions for this section */
} LoaderRelExpHeader, *LoaderRelExpHeaderPtr;

/*========== Loader Import File ID's Entry ==========*/

typedef struct {
     ByteCount    fileNameOffset;         /* offset into loader string table for file name */
     UInt32       oldImpVersion;              /* oldest compatible implementation library */
     UInt32       linkedVersion;              /* current version at link time */
     ItemCount            numImports;                 /* number of imports from this file */
     ItemCount            impFirst;                   /* number of the first imports from this file (relative to all imports) */
     UInt8    options;                /* call this libraries initialization routine before mine */
     UInt8    reservedA;
     UInt16   reservedB;
} LoaderImportFileID, *LoaderImportFileIDPtr;

#define kPEFInitBeforeMask      0x80
#define kPEFWeakLibraryMask     0x40
#define kPEFDeferredBindMask    0x20

/*========== Loader Import Symbol Table Entry ==========*/

typedef struct {
     PEF_UBits32    symClass    :  8;   // Actually ot type TCFLSymbolClass.
     PEF_UBits32    nameOffset  : 24;
} LoaderImport, *LoaderImportPtr;

#define kPEFWeakSymbolMask  0x80

/*========== Loader Export Hash Slot Table Entry ==========*/

typedef struct {
    PEF_UBits32 chainCount : 14;
    PEF_UBits32 chainIndex : 18;
} HashSlotEntry, *HashSlotEntryPtr;

#define PEFHashHighBits(hashword,bitCount)  ((hashword) >> (bitCount))
#define PEFHashMaskBits(hashword,bitCount)  (((UInt32)(1) << (bitCount)) - 1)

#define GetPEFHashSlot(hashword,bitCount)   \
    ( (ItemCount) (((hashword) ^ PEFHashHighBits((hashword),(bitCount))) & PEFHashMaskBits((hashword),(bitCount))) )

/*========== Loader Export Hash Chain Table Entry ==========*/

typedef struct {
     UInt32  hashword;                        /* (hashword >> 16) == nameLength !! */
} HashChainEntry, *HashChainEntryPtr;

/*========== Loader Export Symbol Table Entry ==========*/

/*  Section number controls how 'address' is interpreted.
     >=0: section number exporting the symbol; 'address' is offset from start of the section to
            the symbol being exported (ie address of a routine or data item)
     -1:    value is absolute (non-relocatable)
     -2:    value is a physical address (non-relocatable)
     -3:    re-export imported symbol whose number is in 'address'
*/

/* this struct is stored in the file, non-aligned: size = 10 */
typedef struct {
     PEF_UBits32    symClass    :  8;   // Actually ot type TCFLSymbolClass.
     PEF_UBits32    nameOffset  : 24;
     ByteCount      offset;                                       /* offset into section to exported symbol */
     SInt16         sectionNumber;
} LoaderExport, *LoaderExportPtr;

#define SIZEOF_LoaderExport (sizeof (TUnsigned32)*2 + sizeof (SInt16))


#define kPEFAbsoluteExport -1
#define kPEFPhysicalExport -2
#define kPEFReExportImport -3

/*========== Loader Relocation Entry ==========*/

typedef UInt16 RelocInstr;

typedef union {
    struct { unsigned op:7, rest:9;                  } opcode;
    struct { unsigned op:2, delta_d4:8, cnt:6;   } deltadata;
    struct { unsigned op:7, cnt_m1:9;                } run;
    struct { unsigned op:7, idx:9;                   } glp;
    struct { unsigned op:4, delta_m1:12;             } delta;
    struct { unsigned op:4, icnt_m1:4, rcnt_m1:8; } rpt;
    struct { unsigned op:6, idx_top:10;              } large1;
    struct { unsigned op:6, cnt_m1:4, idx_top:6;  } large2;
    UInt16 instr;
    UInt16 bot;
} Relocation;

// opcode definitions which can be used with
// Relocation.opcode.op:7, if masked properly
// by the up coming table
// (NOTE: a half word of 0 is garunteed to be an unused relocation instruction)

#define krDDAT 0x00 // type deltadata

#define krCODE 0x20 // type run
#define krDATA 0x21 // type run
#define krDESC 0x22 // type run
#define krDSC2 0x23 // type run
#define krVTBL 0x24 // type run
#define krSYMR 0x25 // type run
//              0x26
//              0x2F

#define krSYMB 0x30 // type glp
#define krCDIS 0x31 // type glp
#define krDTIS 0x32 // type glp
#define krSECN 0x33 // type glp
//              0x34
//              0x3F

#define krDELT 0x40 // type delta
#define krRPT   0x48 // type rpt

#define krLABS 0x50 // type large1
#define krLSYM 0x52 // type large1
//              0x54
//              0x56

#define krLRPT 0x58 // type large2
#define krLSEC 0x5A // type large2
//              0x5C
//              0x5E

            // LSEC usage:
            // LSEC 0, n         -- Long SECN
            // LSEC 1, n         -- Long CDIS
            // LSEC 2, n         -- Long DTIS
            // LSEC 3, n         -- free
            // LSEC 15, n        -- free

// constants that indicate the maximum sizes of fields
// (before packing, ie: subtracting one, in some cases)

#define ksDELTA 4096        // delta max for DELTA from

#define ksDDDMAX 1023       // delta max for DELTA-DAT (DDAT) form
#define ksDDRMAX 63         // run max for DELTA-DAT (DDAT) form

#define ksCODE   512        // count max for CODE form
#define ksDATA   512        // count max for DATA form
#define ksDEMAX  512        // count max for DESC form
#define ksVTMAX  512        // count max for VTBL form
#define ksISMAX  512        // count max for IMPS form
#define ksRPTMAX 256        // count max for RPT form

#define IsLARG(op) (((op) & 0x70) == 0x50)

#define RELOPSHFT 9

#define ksDVDMAX 0          // (63) delta max for DELTA-VTBL (DVBL) form
#define ksDVRMAX 0          // (256)  run max for DELTA-VTBL (DVBL) form

#define krXXXX 0xff


/*
                From:               PEFBinaryFormat.i
                    Revision:       9
*/

enum {
                                                                /* The packed data opcodes. */
    kPEFPkDataZero              = 0,                            /* Zero fill "count" bytes. */
    kPEFPkDataBlock             = 1,                            /* Block copy "count" bytes. */
    kPEFPkDataRepeat            = 2,                            /* Repeat "count" bytes "count2"+1 times. */
    kPEFPkDataRepeatBlock       = 3,                            /* Interleaved repeated and unique data. */
    kPEFPkDataRepeatZero        = 4                             /* Interleaved zero and unique data. */
};


enum {
    kPEFPkDataOpcodeShift       = 5,
    kPEFPkDataCount5Mask        = 0x1F,
    kPEFPkDataMaxCount5         = 31,
    kPEFPkDataVCountShift       = 7,
    kPEFPkDataVCountMask        = 0x7F,
    kPEFPkDataVCountEndMask     = 0x80
};

#define PEFPkDataOpcode(byte) ( ((UInt8)(byte)) >> kPEFPkDataOpcodeShift )

#define PEFPkDataCount5(byte) ( ((UInt8)(byte)) & kPEFPkDataCount5Mask )

#define PEFPkDataComposeInstr(opcode,count5)        \
            ( (((UInt8)(opcode)) << kPEFPkDataOpcodeShift) | ((UInt8)(count5)) )





/*
    File:       CodeFragmentContainerPriv.h
 
    Contains:   Physical container routines of the ModernOS version of CFM.
 
    Version:    Maxwell
 
    DRI:        Alan Lillich
 
    Copyright:  © 1984-1996 by Apple Computer, Inc.
                All rights reserved.
 
    BuildInfo:  Built by:           Simon Douglas
                With Interfacer:    2.0d13   (PowerPC native)
                From:               CodeFragmentContainerPriv.i
                    Revision:       9
                    Dated:          10/9/96
                    Last change by: AWL
                    Last comment:   Remove special SMP sharing, using prepare option instead.
 
    Bugs:       Report bugs to Radar component ÒSystem InterfacesÓ, ÒLatestÓ
                List the version information (from above) in the Problem Description.
 
*/
/*
 -------------------------------------------------------------------------------------------
 This file contains what used to be called the CFLoader interface.  The name was changed to
 fit the newer convention of having CodeFragment as a common prefix, and to reduce pervasive
 confusion between the Code Fragment Manager and the Code Fragment Loaders, promulgated by
 the long history of the Segment Loader.  This file defines the abstract interface to the
 physical representation of code fragments.
 !!! This version has minimal comments, the main purpose is to get things compiled.
*/


/*
 ¤
 ===========================================================================================
 General Types and Constants
 ===========================
*/
typedef SInt32 CFContSignedIndex;
typedef UInt32 CFContStringHash;
#define CFContStringHashLength(hashValue)   ((hashValue) >> 16)
struct CFContHashedName {
    CFContStringHash                nameHash;                   /* ! Includes the name length.*/
    BytePtr                         nameText;
};
typedef struct CFContHashedName CFContHashedName;

/*
 ------------------------------------------
 Declarations for code fragment containers.
*/

enum {
    kCFContContainerInfoVersion = 0x00010001
};

struct CFContContainerInfo {
    CFContHashedName                cfragName;
    UInt32                          modDate;                    /* !!! Abstract type?*/
    OSType                          architecture;
    CFragVersionNumber              currentVersion;
    CFragVersionNumber              oldImpVersion;
    CFragVersionNumber              oldDefVersion;
    UInt32                          reservedA;
    void *                          reservedB;
};
typedef struct CFContContainerInfo CFContContainerInfo;

/*
 ----------------------------------------
 Declarations for code fragment sections.
*/
struct CFContLogicalLocation {
    CFContSignedIndex               section;                    /* "Real" sections use zero based indices, special ones are negative.*/
    ByteCount                       offset;
};
typedef struct CFContLogicalLocation CFContLogicalLocation;


enum {
    kCFContNoSectionIndex       = -1,
    kCFContAbsoluteSectionIndex = -2,
    kCFContReexportSectionIndex = -3
};

typedef UInt8 CFContSectionSharing;

enum {
    kCFContShareSectionInClosure = 0,                           /* ! Not supported at present!*/
    kCFContShareSectionInProcess = 1,
    kCFContShareSectionAcrossSystem = 4,
    kCFContShareSectionWithProtection = 5
};

typedef UInt8 CFContMemoryAccess;

enum {
    kCFContMemReadMask          = 0x01,                         /* Readable memory can also be executed.*/
    kCFContMemWriteMask         = 0x02,
    kCFContMemExecuteMask       = 0x04,                         /* ! Affects cache actions, not protection!*/
    kCFContReadOnlyData         = kCFContMemReadMask,
    kCFContWriteableData        = kCFContMemReadMask | kCFContMemWriteMask,
    kCFContNormalCode           = kCFContMemReadMask | kCFContMemExecuteMask,
    kCFContExcludedMemory       = 0
};

typedef UInt32 CFContSectionOptions;

enum {
                                                                /* Values for CFContSectionOptions.*/
    kPackedCFContSectionMask    = 0x01,                         /* Stored contents are compressed.*/
    kRelocatedCFContSectionMask = 0x02,                         /* Section contents have relocations.*/
    kEmptyFillCFContSectionMask = 0x04,                         /* The extension part may be left untouched.*/
    kResidentCFContSectionMask  = 0x08,
    kPrefaultCFContSectionMask  = 0x10
};


enum {
    kCFContSectionInfoVersion   = 0x00010001
};

struct CFContSectionInfo {
    CFContHashedName                sectionName;
    CFContMemoryAccess              access;
    CFContSectionSharing            sharing;
    UInt8                           alignment;                  /* ! The power of 2, a.k.a. number of low order zero bits.*/
    UInt8                           reservedA;
    CFContSectionOptions            options;
    ByteCount                       containerOffset;
    ByteCount                       containerLength;
    ByteCount                       unpackedLength;
    ByteCount                       totalLength;
    LogicalAddress                  defaultAddress;
    UInt32                          reservedB;
    void *                          reservedC;
};
typedef struct CFContSectionInfo CFContSectionInfo;

/*
 ----------------------------------
 Declarations for exported symbols.
*/
typedef UInt32 CFContExportedSymbolOptions;
/*
 ! enum {   // Values for CFContExportedSymbolOptions.
 !  // ! No options at present.
 ! };
*/

enum {
    kCFContExportedSymbolInfoVersion = 0x00010001
};

struct CFContExportedSymbolInfo {
    CFContHashedName                symbolName;
    CFContLogicalLocation           location;
    CFContExportedSymbolOptions     options;
    CFragSymbolClass                symbolClass;
    UInt8                           reservedA;
    UInt16                          reservedB;
    UInt32                          reservedC;
    void *                          reservedD;
};
typedef struct CFContExportedSymbolInfo CFContExportedSymbolInfo;

/*
 ------------------------------------------------
 Declarations for imported libraries and symbols.
*/
typedef UInt32 CFContImportedLibraryOptions;

enum {
                                                                /* Values for CFContImportedLibraryOptions.*/
    kCFContWeakLibraryMask      = 0x01,                         /* ! Same as kCFContWeakSymbolMask to reduce errors.*/
    kCFContInitBeforeMask       = 0x02,
    kCFContDeferredBindMask     = 0x04
};


enum {
    kCFContImportedLibraryInfoVersion = 0x00010001
};

struct CFContImportedLibraryInfo {
    CFContHashedName                libraryName;
    CFragVersionNumber              linkedVersion;
    CFragVersionNumber              oldImpVersion;
    CFContImportedLibraryOptions    options;
};
typedef struct CFContImportedLibraryInfo CFContImportedLibraryInfo;

typedef UInt32 CFContImportedSymbolOptions;

enum {
                                                                /* Values for CFContImportedSymbolOptions.*/
    kCFContWeakSymbolMask       = 0x01                          /* ! Same as kCFContWeakLibraryMask to reduce errors.*/
};


enum {
    kCFContImportedSymbolInfoVersion = 0x00010001
};

struct CFContImportedSymbolInfo {
    CFContHashedName                symbolName;
    ItemCount                       libraryIndex;
    CFContImportedSymbolOptions     options;
    CFragSymbolClass                symbolClass;
    UInt8                           reservedA;
    UInt16                          reservedB;
    UInt32                          reservedC;
    void *                          reservedD;
};
typedef struct CFContImportedSymbolInfo CFContImportedSymbolInfo;

/*
 -------------------------------------------------
 Declarations for dealing with container handlers.
*/
typedef UInt32 CFContOpenOptions;

enum {
                                                                /* Values for CFContOpenOptions.*/
    kCFContPrepareInPlaceMask   = 0x01,
    kCFContMinimalOpenMask      = 0x02
};

typedef UInt32 CFContCloseOptions;

enum {
                                                                /* Values for CFContCloseOptions.*/
    kCFContPartialCloseMask     = 0x01
};

typedef struct OpaqueCFContHandlerRef* CFContHandlerRef;
typedef struct CFContHandlerProcs CFContHandlerProcs;
typedef CFContHandlerProcs *CFContHandlerProcsPtr;
typedef LogicalAddress (*CFContAllocateMem)(ByteCount size);
typedef void (*CFContReleaseMem)(LogicalAddress address);
/*
 ¤
 ===========================================================================================
 Container Handler Routines
 ==========================
*/
typedef OSStatus (*CFCont_OpenContainer)(LogicalAddress mappedAddress, LogicalAddress runningAddress, ByteCount containerLength, KernelProcessID runningProcessID, const CFContHashedName *cfragName, CFContOpenOptions options, CFContAllocateMem Allocate, CFContReleaseMem Release, CFContHandlerRef *containerRef, CFContHandlerProcsPtr *handlerProcs);
typedef OSStatus (*CFCont_CloseContainer)(CFContHandlerRef containerRef, CFContCloseOptions options);
typedef OSStatus (*CFCont_GetContainerInfo)(CFContHandlerRef containerRef, PBVersion infoVersion, CFContContainerInfo *containerInfo);
/* -------------------------------------------------------------------------------------------*/
typedef OSStatus (*CFCont_GetSectionCount)(CFContHandlerRef containerRef, ItemCount *sectionCount);
typedef OSStatus (*CFCont_GetSectionInfo)(CFContHandlerRef containerRef, ItemCount sectionIndex, PBVersion infoVersion, CFContSectionInfo *sectionInfo);
typedef OSStatus (*CFCont_FindSectionInfo)(CFContHandlerRef containerRef, const CFContHashedName *sectionName, PBVersion infoVersion, ItemCount *sectionIndex, CFContSectionInfo *sectionInfo);
typedef OSStatus (*CFCont_SetSectionAddress)(CFContHandlerRef containerRef, ItemCount sectionIndex, LogicalAddress mappedAddress, LogicalAddress runningAddress);
/* -------------------------------------------------------------------------------------------*/
typedef OSStatus (*CFCont_GetAnonymousSymbolLocations)(CFContHandlerRef containerRef, CFContLogicalLocation *mainLocation, CFContLogicalLocation *initLocation, CFContLogicalLocation *termLocation);
/* -------------------------------------------------------------------------------------------*/
typedef OSStatus (*CFCont_GetExportedSymbolCount)(CFContHandlerRef containerRef, ItemCount *exportCount);
typedef OSStatus (*CFCont_GetExportedSymbolInfo)(CFContHandlerRef containerRef, CFContSignedIndex exportedIndex, PBVersion infoVersion, CFContExportedSymbolInfo *exportInfo);
typedef OSStatus (*CFCont_FindExportedSymbolInfo)(CFContHandlerRef containerRef, const CFContHashedName *exportName, PBVersion infoVersion, ItemCount *exportIndex, CFContExportedSymbolInfo *exportInfo);
/* -------------------------------------------------------------------------------------------*/
typedef OSStatus (*CFCont_GetImportCounts)(CFContHandlerRef containerRef, ItemCount *libraryCount, ItemCount *symbolCount);
typedef OSStatus (*CFCont_GetImportedLibraryInfo)(CFContHandlerRef containerRef, ItemCount libraryIndex, PBVersion infoVersion, CFContImportedLibraryInfo *libraryInfo);
typedef OSStatus (*CFCont_GetImportedSymbolInfo)(CFContHandlerRef containerRef, ItemCount symbolIndex, PBVersion infoVersion, CFContImportedSymbolInfo *symbolInfo);
typedef OSStatus (*CFCont_SetImportedSymbolAddress)(CFContHandlerRef containerRef, ItemCount symbolIndex, LogicalAddress symbolAddress);
/* -------------------------------------------------------------------------------------------*/
typedef OSStatus (*CFCont_UnpackSection)(CFContHandlerRef containerRef, ItemCount sectionIndex, ByteCount sectionOffset, LogicalAddress bufferAddress, ByteCount bufferLength);
typedef OSStatus (*CFCont_RelocateSection)(CFContHandlerRef containerRef, ItemCount sectionIndex);
typedef OSStatus (*CFCont_RelocateImportsOnly)(CFContHandlerRef containerRef, ItemCount sectionIndex, ItemCount libraryIndex);
typedef OSStatus (*CFCont_MakeSectionExecutable)(CFContHandlerRef containerRef, ItemCount sectionIndex);
typedef OSStatus (*CFCont_AllocateSection)(CFContHandlerRef containerRef, ItemCount sectionIndex, LogicalAddress *mappedAddress, LogicalAddress *runningAddress);
typedef OSStatus (*CFCont_ReleaseSection)(CFContHandlerRef containerRef, ItemCount sectionIndex);
/* -------------------------------------------------------------------------------------------*/

#if 0
struct CFContHandlerInfo {
    OrderedItemName                 orderedName;
    OrderRequirements               orderedReq;
    CFCont_OpenContainer            OpenHandler;
};
typedef struct CFContHandlerInfo CFContHandlerInfo;
#endif

struct CFContHandlerProcs {
    ItemCount                       procCount;
    CFragShortVersionPair           abiVersion;

    CFCont_OpenContainer            OpenContainer;              /*  1*/
    CFCont_CloseContainer           CloseContainer;             /*  2*/
    CFCont_GetContainerInfo         GetContainerInfo;           /*  3*/

    CFCont_GetSectionCount          GetSectionCount;            /*  4*/
    CFCont_GetSectionInfo           GetSectionInfo;             /*  5*/
    CFCont_FindSectionInfo          FindSectionInfo;            /*  6*/
    CFCont_SetSectionAddress        SetSectionAddress;          /*  7*/

    CFCont_GetAnonymousSymbolLocations  GetAnonymousSymbolLocations; /*  8*/

    CFCont_GetExportedSymbolCount   GetExportedSymbolCount;     /*  9*/
    CFCont_GetExportedSymbolInfo    GetExportedSymbolInfo;      /* 10*/
    CFCont_FindExportedSymbolInfo   FindExportedSymbolInfo;     /* 11*/

    CFCont_GetImportCounts          GetImportCounts;            /* 12*/
    CFCont_GetImportedLibraryInfo   GetImportedLibraryInfo;     /* 13*/
    CFCont_GetImportedSymbolInfo    GetImportedSymbolInfo;      /* 14*/
    CFCont_SetImportedSymbolAddress  SetImportedSymbolAddress;  /* 15*/

    CFCont_UnpackSection            UnpackSection;              /* 16*/
    CFCont_RelocateSection          RelocateSection;            /* 17*/
    CFCont_RelocateImportsOnly      RelocateImportsOnly;        /* 18*/
    CFCont_MakeSectionExecutable    MakeSectionExecutable;      /* 19   (Opt.)*/
    CFCont_AllocateSection          AllocateSection;            /* 20   (Opt.)*/
    CFCont_ReleaseSection           ReleaseSection;             /* 21   (Opt.)*/
};


enum {
    kCFContMinimumProcCount     = 18,
    kCFContCurrentProcCount     = 21,
    kCFContHandlerABIVersion    = 0x00010001
};

/*
 -----------------------------------------------------------------------------------------
 The ABI version is a pair of UInt16s used as simple counters.  The high order part is the
 current version number, the low order part is the oldest compatible definition version.
 number.  This pair is to be used by the specific container handlers to describe what
 version of the container handler ABI they support.
    0x00010001
    ----------
    The initial release of this ABI.  (The old CFLoader ABI does not count.)
 ¤
 ===========================================================================================
 General Routines
 ================
*/
extern CFContStringHash CFContHashName(BytePtr nameText, ByteCount nameLength);

#if 0

/* -------------------------------------------------------------------------------------------*/
extern OSStatus CFContOpenContainer(LogicalAddress mappedAddress, LogicalAddress runningAddress, ByteCount containerLength, KernelProcessID runningProcessID, const CFContHashedName *cfragName, CFContOpenOptions options, CFContAllocateMem Allocate, CFContReleaseMem Release, CFContHandlerRef *containerRef, CFContHandlerProcsPtr *handlerProcs);

/* -------------------------------------------------------------------------------------------*/
extern OSStatus CFContRegisterContainerHandler(const OrderedItemName *orderedName, const OrderRequirements *orderedReq, CFCont_OpenContainer OpenHandler, OrderedItemName *rejectingHandler);

extern OSStatus CFContUnregisterContainerHandler(const OrderedItemName *orderedName);

extern OSStatus CFContGetContainerHandlers(ItemCount requestedCount, ItemCount *totalCount, CFContHandlerInfo *handlers);

/* -------------------------------------------------------------------------------------------*/
#endif






/*
    File:       PEFLoader.h

    Contains:   PEF Loader Interface.

    Version:    Maxwell

    Copyright:  © 1992-1996 by Apple Computer, Inc., all rights reserved.

    File Ownership:

        DRI:                Alan Lillich

        Other Contact:      <<unknown>>

        Technology:         Core Runtime

    Writers:

        (AWL)   Alan Lillich
        (ELE)   Erik Eidt

     Change History (most recent first):

         <7>     8/23/96    AWL     (1379028) Propagate changes from CodeFragmentContainerPriv.
         <6>     2/28/96    AWL     Adapt for new container handler model.
         <5>     6/20/94    AWL     Move private PEF loader info struct here to be visible to the
                                    booting "wacky" PEF loader.
         <4>      6/8/94    AWL     Make all CFL routines visible for direct use in special cases
                                    such as booting.
         <3>     5/16/94    AWL     Fix typo.
         <2>     2/25/94    AWL     Update for Q&D solution to loading across address spaces.
         <1>     2/15/94    AWL     Initial checkin for kernel based CFM.
*/

// ===========================================================================================

enum {
    kBuiltinSectionArraySize    = 4
};

struct PEFPrivateInfo { // !!! Clean up field names, collapse Booleans, etc.
    CFContAllocateMem       Allocate;
    CFContReleaseMem        Release;
    BytePtr                 mappedContainer;
    BytePtr                 runningContainer;
    ItemCount               sectionCount;       // Just the instantiated sections.
    SectionHeader *         sections;
    BytePtr                 stringTable;
    ItemCount               ldrSectionNo;
    LoaderHeader *          ldrHeader;
    BytePtr                 ldrStringTable;
    LoaderRelExpHeader *    ldrSections;
    LoaderImportFileID *    ldrImportFiles;
    LoaderImport *          ldrImportSymbols;
    HashSlotEntry *         ldrHashSlot;
    HashChainEntry *        ldrHashChain;
    LoaderExport *          ldrExportSymbols;
    BytePtr                 ldrRelocations;
    BytePtr *               mappedOrigins;      // Mapped base address for each section.
    ByteCount *             runningOffsets;     // Running offset from presumed address.
    BytePtr *               imports;
    BytePtr                 originArray [kBuiltinSectionArraySize]; // ! Only used if big enough.
    ByteCount               offsetArray [kBuiltinSectionArraySize]; // ! Only used if big enough.
    Boolean                 loadInPlace;
    Boolean                 resolved;
};

typedef struct PEFPrivateInfo   PEFPrivateInfo;


// ===========================================================================================


extern OSStatus PEF_OpenContainer       ( LogicalAddress            mappedAddress,
                                          LogicalAddress            runningAddress,
                                          ByteCount                 containerLength,
                                          KernelProcessID           runningProcessID,
                                          const CFContHashedName *  cfragName,
                                          CFContOpenOptions         options,
                                          CFContAllocateMem         Allocate,
                                          CFContReleaseMem          Release,
                                          CFContHandlerRef *        containerRef_o,
                                          CFContHandlerProcs * *    handlerProcs_o );

extern OSStatus PEF_CloseContainer      ( CFContHandlerRef          containerRef,
                                          CFContCloseOptions        options );

extern OSStatus PEF_GetContainerInfo    ( CFContHandlerRef          containerRef,
                                          PBVersion                 infoVersion,
                                          CFContContainerInfo *     containerInfo );

// -------------------------------------------------------------------------------------------

extern OSStatus PEF_GetSectionCount     ( CFContHandlerRef          containerRef,
                                          ItemCount *               sectionCount );

extern OSStatus PEF_GetSectionInfo      ( CFContHandlerRef          containerRef,
                                          ItemCount                 sectionIndex,
                                          PBVersion                 infoVersion,
                                          CFContSectionInfo *       sectionInfo );

extern OSStatus PEF_FindSectionInfo     ( CFContHandlerRef          containerRef,
                                          const CFContHashedName *  sectionName,
                                          PBVersion                 infoVersion,
                                          ItemCount *               sectionIndex,   // May be null.
                                          CFContSectionInfo *       sectionInfo );  // May be null.

extern OSStatus PEF_SetSectionAddress   ( CFContHandlerRef          containerRef,
                                          ItemCount                 sectionIndex,
                                          LogicalAddress            mappedAddress,
                                          LogicalAddress            runningAddress );

// -------------------------------------------------------------------------------------------

extern OSStatus PEF_GetAnonymousSymbolLocations ( CFContHandlerRef          containerRef,
                                                  CFContLogicalLocation *   mainLocation,   // May be null.
                                                  CFContLogicalLocation *   initLocation,   // May be null.
                                                  CFContLogicalLocation *   termLocation ); // May be null.

// -------------------------------------------------------------------------------------------

extern OSStatus PEF_GetExportedSymbolCount  ( CFContHandlerRef              containerRef,
                                              ItemCount *                   exportCount );

extern OSStatus PEF_GetExportedSymbolInfo   ( CFContHandlerRef              containerRef,
                                              CFContSignedIndex             exportIndex,
                                              PBVersion                     infoVersion,
                                              CFContExportedSymbolInfo *    exportInfo );

extern OSStatus PEF_FindExportedSymbolInfo  ( CFContHandlerRef              containerRef,
                                              const CFContHashedName *      exportName,
                                              PBVersion                     infoVersion,
                                              ItemCount *                   exportIndex,    // May be null.
                                              CFContExportedSymbolInfo *    exportInfo );   // May be null.

// -------------------------------------------------------------------------------------------

extern OSStatus PEF_GetImportCounts             ( CFContHandlerRef              containerRef,
                                                  ItemCount *                   libraryCount,   // May be null.
                                                  ItemCount *                   symbolCount );  // May be null.

extern OSStatus PEF_GetImportedLibraryInfo      ( CFContHandlerRef              containerRef,
                                                  ItemCount                     libraryIndex,
                                                  PBVersion                     infoVersion,
                                                  CFContImportedLibraryInfo *   libraryInfo );

extern OSStatus PEF_GetImportedSymbolInfo       ( CFContHandlerRef              containerRef,
                                                  ItemCount                     symbolIndex,
                                                  PBVersion                     infoVersion,
                                                  CFContImportedSymbolInfo *    symbolInfo );

extern OSStatus PEF_SetImportedSymbolAddress    ( CFContHandlerRef              containerRef,
                                                  ItemCount                     symbolIndex,
                                                  LogicalAddress                symbolAddress );

// -------------------------------------------------------------------------------------------

extern OSStatus PEF_UnpackSection           ( CFContHandlerRef      containerRef,
                                              ItemCount             sectionIndex,
                                              ByteCount             sectionOffset,
                                              LogicalAddress        bufferAddress,
                                              ByteCount             bufferLength );

extern OSStatus PEF_RelocateSection         ( CFContHandlerRef      containerRef,
                                              ItemCount             sectionIndex );

extern OSStatus PEF_RelocateImportsOnly     ( CFContHandlerRef      containerRef,
                                              ItemCount             sectionIndex,
                                              ItemCount             libraryIndex );

struct CFragInitBlock {
	void *		contextID;
	void *		closureID;
	void *		connectionID;
	SInt32		where;			// locator rec
	LogicalAddress	address;
	ByteCount	length;
	Boolean		inPlace;
	UInt8		resvA;
	UInt16		resvB;
	char *		libName;
	UInt32		resvC;
};
typedef struct CFragInitBlock CFragInitBlock;

#pragma options align=reset

#endif  // __IOPEFINTERNALS__

