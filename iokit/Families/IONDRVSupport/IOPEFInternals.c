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
    File:       PEFLoader.c

    Contains:   PEF loader implementation.

    Version:    Maxwell

    Copyright:  © 1994-1996 by Apple Computer, Inc., all rights reserved.

    File Ownership:

        DRI:                Alan Lillich

        Other Contact:      <<unknown>>

        Technology:         Core Runtime

    Writers:

        (AWL)   Alan Lillich
        (ELE)   Erik Eidt

     Change History (most recent first):

        <26>     10/4/96    AWL     Disable partial unpacking tests.
        <25>     9/26/96    AWL     Fix assertions to have the right polarity.
        <24>     9/18/96    AWL     Simplify UnpackPartialSection.
        <23>     8/27/96    AWL     Support partial unpacking in PEF_UnpackSection.
        <22>     8/23/96    AWL     (1379028) Propagate changes from CodeFragmentContainerPriv.
        <21>     8/16/96    AWL     Isolate memory utilities to work with both CFM and ProtoCFM.
        <20>     4/18/96    AWL     (1342167) Fix problems with relocations for in-place sections.
        <19>      4/2/96    AWL     (1336962) Fix checks for missing optional parameters.
        <18>      3/7/96    AWL     Remove unused variable in PEF_UnpackSection.
        <17>     2/28/96    AWL     Adapt for new container handler model.
        <16>     1/19/96    AWL     Changes for D11.
        <15>    10/10/95    AWL     Minor cleanup for CodeWarrior's strict checking.
        <14>     6/14/95    AWL     Pick up flags from CFMWhere ASAP.
        <13>     5/23/95    AWL     Introduce temporary hack to workaround build problem for 68K
                                    ModernOS booting code. *** THIS BREAKS REAL 68K BUILDS! ***
        <12>      2/8/95    AWL     Update debug output calls.
        <11>    12/14/94    AWL     Changes for Maxwell D4 build.
        <10>     12/2/94    AWL     Disable reexported import optimization because of problems with
                                    missing weak libraries. It could be put back later with the
                                    addition of a "resolvedImports" bit vector.
         <9>      9/9/94    AWL     Switch to the "real" API and SPI headers.
         <8>      9/2/94    AWL     Error codes are now in Errors.h.
         <7>     7/28/94    AWL     Return cfragSymbolNotFound instead of paramErr from
                                    PLFindExportInfo. (#1177313)
         <6>     7/12/94    AWL     Fix load-in-place processing in SetRegionAddress.
         <5>     6/20/94    AWL     Allow the CFL info pointer to be NULL for a "get procs" call to
                                    OpenContainer.
         <4>      5/9/94    AWL     Change PLGetSpecialSectionInfo to handle some of the wierdness
                                    in nonloaded sections.
         <3>     4/28/94    AWL     Simplify cross address space use for booting. Fix problem with
                                    load in place, should not require SetRegionAddress.
         <2>     2/25/94    AWL     Update for Q&D solution to loading across address spaces.
                                    Fix problem in PLGetSpecialSectionInfo switch statement.
         <1>     2/15/94    AWL     Initial checkin for kernel based CFM.

          ------------------------------------------------------------------------------------

        <31>    09/15/93    AWL     (&ELE) Add CFL prefix to hash functions.
        <30>    09/08/93    ELE     (&AWL) Fix sneaky little typo that causes load failure.
        <29>    08/30/93    AWL     Add declaration so that 68K native CFM compiles.
        <28>    08/26/93    AWL     Move CFTypes.h and CFLoader.h up with other Apple private
                                    headers.
        <26>    07/08/93    AWL     (&ELE) Fixed version field names in import file IDs.
                                    Remove version < 0 checks as versions are unsigned.
        <25>    06/16/93    ELE     ELE & AWL Change to New Pool allocation.
        <24>    06/09/93    ELE     ELE & AWL Fix bug in GetSpecialSection for debugger.
        <23>    06/09/93    JRG     ELE & AWL Changes:
        <22>    06/08/93    ELE     (&AWL) Shift to allocation bottleneck.  Added support for
                                    packed data sections.  Switched to new CFLoader section
                                    attribute bits.
        <21>    02/15/93    ELE     Changed NewPtr->NewPtrSys
        <20>    02/03/93    ELE     Added architecture pass thru to GetVersion per CFL Spec.
        <19>    12/23/92    ELE     Fixed bug where init routine was being returned for the
                                    term routine.
        <17>    10/29/92    ELE     GetVersion - added dateStamp.
        <16>    10/01/92    ELE     fix bug in use in place, update of header!
        <15>    10/01/92    ELE     fix bug in use in place!
        <14>    09/28/92    ELE     needed to update field expIndex from Find/GetExportInfo.
        <13>    09/23/92    ELE     updated to new PEF format, updated to new CF Loader SPI.
        <12>    09/23/92    ELE     Latest version.

*/


#include "IOPEFInternals.h"

// ===========================================================================================

#define PEF_Assert(a)          if( !(a)) kprintf("PEF_Assert:")
#define PEF_BlockMove(src,dst,len) memcpy(dst,src,len)
#define PEF_BlockClear(dst,len)    memset(dst,0,len)
extern Boolean  PCFM_CompareBytes   ( const Byte *  left,
                              const Byte *  right,
                              ByteCount     count );
#define PEF_CompareBytes(a,b,c) PCFM_CompareBytes(a,b,c)

#define EnableCFMDebugging	0

// ===========================================================================================


enum {
    kPEFHandlerProcCount    = 18
};

static CFContHandlerProcs   PEFHandlerProcs = {
    kPEFHandlerProcCount,
    kCFContHandlerABIVersion,

    PEF_OpenContainer,                  //  1
    PEF_CloseContainer,                 //  2
    PEF_GetContainerInfo,               //  3

    PEF_GetSectionCount,                //  4
    PEF_GetSectionInfo,                 //  5
    PEF_FindSectionInfo,                //  6
    PEF_SetSectionAddress,              //  7

    PEF_GetAnonymousSymbolLocations,    //  8

    PEF_GetExportedSymbolCount,         //  9
    PEF_GetExportedSymbolInfo,          // 10
    PEF_FindExportedSymbolInfo,         // 11

    PEF_GetImportCounts,                // 12
    PEF_GetImportedLibraryInfo,         // 13
    PEF_GetImportedSymbolInfo,          // 14
    PEF_SetImportedSymbolAddress,       // 15

    PEF_UnpackSection,                  // 16
    PEF_RelocateSection,                // 17
    PEF_RelocateImportsOnly,            // 18
};


#if EnableCFMDebugging
    static char gDebugMessage [256];
#endif

// ===========================================================================================

const unsigned char opcode [128] = {
         krDDAT,krDDAT,krDDAT,krDDAT, krDDAT,krDDAT,krDDAT,krDDAT,
         krDDAT,krDDAT,krDDAT,krDDAT, krDDAT,krDDAT,krDDAT,krDDAT,
         krDDAT,krDDAT,krDDAT,krDDAT, krDDAT,krDDAT,krDDAT,krDDAT,
         krDDAT,krDDAT,krDDAT,krDDAT, krDDAT,krDDAT,krDDAT,krDDAT,

         krCODE,krDATA,krDESC,krDSC2, krVTBL,krSYMR,krXXXX,krXXXX,
         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,
         krSYMB,krCDIS,krDTIS,krSECN, krXXXX,krXXXX,krXXXX,krXXXX,
         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,

         krDELT,krDELT,krDELT,krDELT, krDELT,krDELT,krDELT,krDELT,
         krRPT ,krRPT ,krRPT ,krRPT , krRPT ,krRPT ,krRPT ,krRPT ,
         krLABS,krLABS,krLSYM,krLSYM, krXXXX,krXXXX,krXXXX,krXXXX,
         krLRPT,krLRPT,krLSEC,krLSEC, krXXXX,krXXXX,krXXXX,krXXXX,

         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,
         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,
         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,
         krXXXX,krXXXX,krXXXX,krXXXX, krXXXX,krXXXX,krXXXX,krXXXX,
};

// ¤
// ===========================================================================================
// GetNameLength ()
// ================


static ByteCount    GetNameLength   ( BytePtr nameStart )
{
    BytePtr nameEnd = nameStart;


    if ( nameStart != NULL ) {
        while ( *nameEnd != 0 ) nameEnd += 1;
    }

    return (nameEnd - nameStart);


}   // GetNameLength ()


// ¤
// ===========================================================================================
// FindRelocationInfo ()
// =====================


static LoaderRelExpHeader * FindRelocationInfo  ( PEFPrivateInfo *  pefPrivate,
                                                  ItemCount         sectionIndex )
{
    LoaderRelExpHeader *    relocInfo   = NULL;
    const ItemCount         loopLimit   = pefPrivate->ldrHeader->numSections;
    ItemCount               relocIndex;


    for ( relocIndex = 0; relocIndex < loopLimit; relocIndex += 1 ) {
        relocInfo = &pefPrivate->ldrSections[relocIndex];
        if ( sectionIndex == relocInfo->sectionNumber ) return relocInfo;
    }
    return NULL;


}   // FindRelocationInfo ()


// ¤
// ===========================================================================================
// GetSectionName ()
// =================


static void GetSectionName  ( PEFPrivateInfo *      pefPrivate,
                              SectionHeader *       sectionHeader,
                              CFContHashedName *    sectionName )
{
    CFContStringHash    nameHash    = 0;
    BytePtr             nameText    = NULL;
    ByteCount           nameLength;


    if ( sectionHeader->sectionName != -1 ) {
        nameText    = pefPrivate->stringTable + sectionHeader->sectionName;
        nameLength  = GetNameLength ( nameText );
        nameHash    = CFContHashName ( nameText, nameLength );
    }

    sectionName->nameHash   = nameHash;
    sectionName->nameText   = nameText;


}   // GetSectionName ()


// ¤
// ===========================================================================================
// PEF_OpenContainer ()
// ====================


OSStatus    PEF_OpenContainer   ( LogicalAddress            mappedAddress,
                                  LogicalAddress            runningAddress,
                                  ByteCount                 containerLength,
                                  KernelProcessID           runningProcessID,
                                  const CFContHashedName *  cfragName,
                                  CFContOpenOptions         options,
                                  CFContAllocateMem         Allocate,
                                  CFContReleaseMem          Release,
                                  CFContHandlerRef *        containerRef,
                                  CFContHandlerProcsPtr *   handlerProcs )
{
    #pragma unused ( containerLength )
    #pragma unused ( runningProcessID )
    #pragma unused ( cfragName )

    OSStatus                err             = -1;//cfragCFMInternalErr;
    FileHeader *            fileHeader      = (FileHeader *) mappedAddress;
    PEFPrivateInfo *        pefPrivate      = NULL;
    SectionHeader *         loaderSection   = NULL;
    SInt32                  sectionIndex;


    if ( (sizeof ( PEF_SBits32 ) != 4) | (sizeof ( PEF_UBits32 ) != 4) ) goto InternalError;    // ! Is "int" 32 bits?

    if ( (Allocate == NULL)     ||
         (Release == NULL)      ||
         (containerRef == NULL) ||
         (handlerProcs == NULL) ) goto ParameterError;

    *containerRef   = NULL;     // Clear for errors, only set on OK path.
    *handlerProcs   = NULL;


    // ---------------------------------------------------------------------------------
    // Allow the container address to be null as a special case to get the loader procs.
    // Otherwise validate the header as acceptable PEF.

    if ( mappedAddress == NULL ) goto OK;

    if ( (fileHeader->magic1 != kPEFMagic1)     ||
         (fileHeader->magic2 != kPEFMagic2)     ||
         (fileHeader->fileTypeID != kPEFTypeID) ||
         (fileHeader->versionNumber != kPEFVersion) )   goto FragmentFormatError;


    // -----------------------------------------------
    // Allocate and initialize the private info block.

    pefPrivate = (PEFPrivateInfo *) ((*Allocate) ( sizeof ( PEFPrivateInfo ) ));
    if ( pefPrivate == NULL ) goto PrivateMemoryError;

    PEF_BlockClear ( pefPrivate, sizeof ( *pefPrivate ) );

    pefPrivate->Allocate            = Allocate;
    pefPrivate->Release             = Release;
    pefPrivate->mappedContainer     = (BytePtr) mappedAddress;
    pefPrivate->runningContainer    = (BytePtr) runningAddress;
    pefPrivate->sectionCount        = fileHeader->loadableSections;
    pefPrivate->sections            = (SectionHeader *) (fileHeader + 1);
    pefPrivate->stringTable         = (BytePtr) (&pefPrivate->sections[fileHeader->numberSections]);
    pefPrivate->loadInPlace         = ((options & kCFContPrepareInPlaceMask) != 0);

    // -----------------------------------------------------
    // Find the loader section and extract important fields.

    for ( sectionIndex = 0; sectionIndex < fileHeader->numberSections; sectionIndex += 1 ) {
        loaderSection = & pefPrivate->sections[sectionIndex];
        if ( loaderSection->regionKind == kPEFLoaderSection ) break;
    }
    if ( sectionIndex == fileHeader->numberSections ) goto FragmentCorruptError;

    pefPrivate->ldrSectionNo        = sectionIndex;
    pefPrivate->ldrHeader           = (LoaderHeader *) ((BytePtr)mappedAddress + loaderSection->containerOffset);
    pefPrivate->ldrStringTable      = (BytePtr)pefPrivate->ldrHeader + pefPrivate->ldrHeader->stringsOffset;

    pefPrivate->ldrImportFiles      = (LoaderImportFileID *) (pefPrivate->ldrHeader + 1);
    pefPrivate->ldrImportSymbols    = (LoaderImport *) (pefPrivate->ldrImportFiles + pefPrivate->ldrHeader->numImportFiles);
    pefPrivate->ldrSections         = (LoaderRelExpHeader *) (pefPrivate->ldrImportSymbols + pefPrivate->ldrHeader->numImportSyms);
    pefPrivate->ldrRelocations      = (BytePtr)pefPrivate->ldrHeader + pefPrivate->ldrHeader->relocationsOffset;

    pefPrivate->ldrHashSlot         = (HashSlotEntry *) ((BytePtr)pefPrivate->ldrHeader + pefPrivate->ldrHeader->hashSlotTable);
    pefPrivate->ldrHashChain        = (HashChainEntry *) (pefPrivate->ldrHashSlot + (1 << pefPrivate->ldrHeader->hashSlotTabSize));
    pefPrivate->ldrExportSymbols    = (LoaderExport *) (pefPrivate->ldrHashChain + pefPrivate->ldrHeader->numExportSyms);

    // ----------------------------------------------------
    // Set up the array to store resolved import addresses.

    if ( pefPrivate->ldrHeader->numImportSyms > 0 ) {
        pefPrivate->imports = (BytePtr *) ((*Allocate) ( pefPrivate->ldrHeader->numImportSyms * sizeof ( BytePtr ) ));
        if ( pefPrivate->imports == NULL ) goto PrivateMemoryError;
    }

    // -----------------------------------------------------------------
    // Set up the pointers to the arrays of section origins and offsets.

    if (pefPrivate->sectionCount <= kBuiltinSectionArraySize) {
        pefPrivate->mappedOrigins   = & pefPrivate->originArray[0];
        pefPrivate->runningOffsets  = & pefPrivate->offsetArray[0];
    } else {
        pefPrivate->mappedOrigins   = (BytePtr *) ((*Allocate) ( pefPrivate->sectionCount * sizeof ( BytePtr ) ));
        if ( pefPrivate->mappedOrigins == NULL ) goto PrivateMemoryError;
        pefPrivate->runningOffsets = (ByteCount *) ((*Allocate) ( pefPrivate->sectionCount * sizeof ( ByteCount ) ));
        if ( pefPrivate->runningOffsets == NULL ) goto PrivateMemoryError;
    }

    // ---------------------------------------------------------------------------------------
    // Fill in the origin and offset arrays.  The origin array gives the base address of the
    // section instance as visible in the loader's address space.  I.e. it tells the loader
    // where it can access the loaded section contents.  The offset array tells what to add
    // for relocations refering to that section.  So it must be based on running addresses and
    // must "remove" the presumed running address.  If the section will be used in place we
    // must compute the final values here.  Otherwise SetRegionAddress will be called later to
    // provide the mapped and running addresses.  Validate load in place restrictions too.

    // ??? We really ought to consider getting rid of the preset for in-place usage and make
    // ??? that case as close as possible to the normal case.

    // ! Note that although the ByteCount type used in the offset arrays is unsigned, ignoring
    // ! overflow lets things work right for a full -4GB to +4GB offset range.

    for ( sectionIndex = 0; sectionIndex < pefPrivate->sectionCount; sectionIndex += 1 ) {

        SectionHeader * section = & pefPrivate->sections[sectionIndex];

        pefPrivate->mappedOrigins[sectionIndex]     = (BytePtr) -1; // ! Just a diagnostic tag.
        pefPrivate->runningOffsets[sectionIndex]    = - ((ByteCount) section->sectionAddress);  // Subtract the presumed address.

        if ( pefPrivate->loadInPlace ) {
            if ( (section->regionKind == kPEFPIDataSection) || (section->execSize != section->rawSize) ) goto FragmentUsageError;
            section->sectionAddress                     = pefPrivate->runningContainer + section->containerOffset;
            pefPrivate->mappedOrigins[sectionIndex]     = pefPrivate->mappedContainer + section->containerOffset;
            pefPrivate->runningOffsets[sectionIndex]    += (ByteCount) section->sectionAddress;     // Add in the new address.
        }

    }

    if ( options & kCFContPrepareInPlaceMask ) fileHeader->memoryAddress = runningAddress;


OK:
    err = noErr;
    *handlerProcs = &PEFHandlerProcs;
    *containerRef = (CFContHandlerRef) pefPrivate;

EXIT:
    return err;

ERROR:
    (void) PEF_CloseContainer ( (CFContHandlerRef) pefPrivate, kNilOptions );
    goto EXIT;

InternalError:
    err = cfragCFMInternalErr;
    goto ERROR;

ParameterError:
    err = paramErr;
    goto ERROR;

FragmentFormatError:
    err = cfragFragmentFormatErr;
    goto ERROR;

PrivateMemoryError:
    err = cfragNoPrivateMemErr;
    goto ERROR;

FragmentCorruptError:
    err = cfragFragmentCorruptErr;
    goto ERROR;

FragmentUsageError:
    err = cfragFragmentUsageErr;
    goto ERROR;


}   // PEF_OpenContainer ()


// ¤
// ===========================================================================================
// PEF_CloseContainer ()
// =====================


OSStatus    PEF_CloseContainer  ( CFContHandlerRef      containerRef,
                                  CFContCloseOptions    options )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;
    CFContReleaseMem    Release     = NULL;


    if ( pefPrivate == NULL ) goto OK;  // Simplifies error cleanup from PEF_OpenContainer.


    Release = pefPrivate->Release;

    if ( pefPrivate->sectionCount > kBuiltinSectionArraySize ) {
        if ( pefPrivate->mappedOrigins != NULL ) {
            (*Release) ( pefPrivate->mappedOrigins );
            pefPrivate->mappedOrigins = NULL;
        }
        if ( pefPrivate->runningOffsets != NULL ) {
            (*Release) ( pefPrivate->runningOffsets );
            pefPrivate->runningOffsets = NULL;
        }
    }

    if ( pefPrivate->imports != NULL ) {
        (*Release) ( pefPrivate->imports );
        pefPrivate->imports = NULL;
    }

    pefPrivate->resolved = 0;   // ! Disables reexported import optimization.

    if ( ! (options & kCFContPartialCloseMask) ) (*Release) ( pefPrivate );


OK:
    err = noErr;
    return err;

}   // PEF_CloseContainer ()


// ¤
// ===========================================================================================
// PEF_GetContainerInfo ()
// =======================


OSStatus    PEF_GetContainerInfo    ( CFContHandlerRef      containerRef,
                                      PBVersion             infoVersion,
                                      CFContContainerInfo * containerInfo )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;
    FileHeader *        fileHeader  = NULL;


    if ( (pefPrivate == NULL) || (containerInfo == NULL) ) goto ParameterError;
    if ( infoVersion != kCFContContainerInfoVersion ) goto ParameterError;


    fileHeader  = (FileHeader *) pefPrivate->mappedContainer;

    containerInfo->cfragName.nameHash   = 0;    // PEF does not have an embedded name.
    containerInfo->cfragName.nameText   = NULL;

    containerInfo->modDate          = fileHeader->dateTimeStamp;
    containerInfo->architecture     = fileHeader->architectureID;
    containerInfo->currentVersion   = fileHeader->currentVersion;
    containerInfo->oldImpVersion    = fileHeader->oldImpVersion;
    containerInfo->oldDefVersion    = fileHeader->oldDefVersion;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetContainerInfo ()


// ¤
// ===========================================================================================
// PEF_GetSectionCount ()
// ======================


OSStatus    PEF_GetSectionCount ( CFContHandlerRef  containerRef,
                                  ItemCount *       sectionCount )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;


    if ( (pefPrivate == NULL) || (sectionCount == NULL) ) goto ParameterError;

    *sectionCount = pefPrivate->sectionCount;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetSectionCount ()


// ¤
// ===========================================================================================
// PEF_GetSectionInfo ()
// =====================


OSStatus    PEF_GetSectionInfo  ( CFContHandlerRef      containerRef,
                                  ItemCount             sectionIndex,
                                  PBVersion             infoVersion,
                                  CFContSectionInfo *   sectionInfo )
{
    OSStatus            err             = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate      = (PEFPrivateInfo *) containerRef;
    SectionHeader *     sectionHeader   = NULL;


    if ( (pefPrivate == NULL) || (sectionInfo == NULL) ) goto ParameterError;
    if ( infoVersion != kCFContSectionInfoVersion ) goto ParameterError;
    if ( sectionIndex >= pefPrivate->sectionCount ) goto ParameterError;


    sectionHeader = &pefPrivate->sections[sectionIndex];

    GetSectionName ( pefPrivate, sectionHeader, &sectionInfo->sectionName );

    sectionInfo->sharing            = sectionHeader->shareKind;
    sectionInfo->alignment          = sectionHeader->alignment;
    sectionInfo->reservedA          = 0;
    sectionInfo->containerOffset    = sectionHeader->containerOffset;
    sectionInfo->containerLength    = sectionHeader->rawSize;
    sectionInfo->unpackedLength     = sectionHeader->initSize;
    sectionInfo->totalLength        = sectionHeader->execSize;
    sectionInfo->defaultAddress     = sectionHeader->sectionAddress;

    sectionInfo->options = kNilOptions;
    if ( FindRelocationInfo ( pefPrivate, sectionIndex ) != NULL ) sectionInfo->options |= kRelocatedCFContSectionMask;

    switch ( pefPrivate->sections[sectionIndex].regionKind ) {
        case kPEFCodeSection :
            sectionInfo->access = kCFContNormalCode;
            break;
        case kPEFDataSection :
            sectionInfo->access = kCFContWriteableData;
            break;
        case kPEFPIDataSection :
            sectionInfo->access = kCFContWriteableData;
            sectionInfo->options |= kPackedCFContSectionMask;
            break;
        case kPEFConstantSection :
            sectionInfo->access = kCFContReadOnlyData;
            break;
        case kPEFExecDataSection :
            sectionInfo->access = kCFContWriteableData | kCFContMemExecuteMask;
            break;
        default :
            sectionInfo->access = kCFContReadOnlyData;  // ! Not necessarily right, but safe.
            break;
    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetSectionInfo ()


// ¤
// ===========================================================================================
// PEF_FindSectionInfo ()
// ======================


OSStatus    PEF_FindSectionInfo ( CFContHandlerRef          containerRef,
                                  const CFContHashedName *  sectionName,
                                  PBVersion                 infoVersion,
                                  ItemCount *               sectionIndex,   // May be null.
                                  CFContSectionInfo *       sectionInfo )   // May be null.
{
    OSStatus            err             = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate      = (PEFPrivateInfo *) containerRef;
    SectionHeader *     sectionHeader   = NULL;
    CFContHashedName    hashedName;

    ItemCount           tempIndex;
    CFContSectionInfo   tempInfo;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( (sectionInfo != NULL) && (infoVersion != kCFContSectionInfoVersion) ) goto ParameterError;

    if ( sectionIndex == NULL ) sectionIndex = &tempIndex;
    if ( sectionInfo == NULL ) sectionInfo = &tempInfo;


    for ( tempIndex = 0; tempIndex < pefPrivate->sectionCount; tempIndex += 1 ) {
        sectionHeader = &pefPrivate->sections[tempIndex];
        GetSectionName ( pefPrivate, sectionHeader, &hashedName );
        if ( (hashedName.nameHash == sectionName->nameHash) &&
             (PEF_CompareBytes ( hashedName.nameText, sectionName->nameText, CFContStringHashLength ( hashedName.nameHash ) )) ) break;
    }
    if ( tempIndex == pefPrivate->sectionCount ) goto NoSectionError;
    *sectionIndex = tempIndex;

    err = PEF_GetSectionInfo ( containerRef, tempIndex, infoVersion, sectionInfo );
    if ( err != noErr ) goto ERROR;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;

NoSectionError:
    err = cfragNoSectionErr;
    goto ERROR;


}   // PEF_FindSectionInfo ()


// ¤
// ===========================================================================================
// PEF_SetSectionAddress ()
// ========================


OSStatus    PEF_SetSectionAddress   ( CFContHandlerRef  containerRef,
                                      ItemCount         sectionIndex,
                                      LogicalAddress    mappedAddress,
                                      LogicalAddress    runningAddress )
{
    OSErr               err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;
    SectionHeader *     section     = NULL;


    if ( (pefPrivate == NULL)   || (sectionIndex >= pefPrivate->sectionCount) ) goto ParameterError;


    // --------------------------------------------------------------------------------------
    // For a load in place usage we've already set the addresses, make sure these match.
    // Otherwise set both addresses.  Note that the "presumed" address is already subtracted.

    section = & pefPrivate->sections[sectionIndex];

    if ( ! pefPrivate->loadInPlace ) {

        pefPrivate->mappedOrigins[sectionIndex]     = (BytePtr) mappedAddress;
        pefPrivate->runningOffsets[sectionIndex]    += (ByteCount) runningAddress;

    } else {

        if ( (runningAddress != section->sectionAddress) ||
             (mappedAddress != pefPrivate->mappedOrigins[sectionIndex]) ) goto UsageError;

    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;

UsageError:
    err = cfragFragmentUsageErr;
    goto ERROR;


}   // PEF_SetSectionAddress ()


// ¤
// ===========================================================================================
// PEF_GetAnonymousSymbolLocations ()
// ==================================


extern OSStatus PEF_GetAnonymousSymbolLocations ( CFContHandlerRef          containerRef,
                                                  CFContLogicalLocation *   mainLocation,   // May be null.
                                                  CFContLogicalLocation *   initLocation,   // May be null.
                                                  CFContLogicalLocation *   termLocation )  // May be null.
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;
    LoaderHeader *      ldrHeader   = NULL;

    CFContLogicalLocation   tempLocation;


    if ( (pefPrivate == NULL) ) goto ParameterError;

    if ( mainLocation == NULL ) mainLocation    = &tempLocation;
    if ( initLocation == NULL ) initLocation    = &tempLocation;
    if ( termLocation == NULL ) termLocation    = &tempLocation;


    ldrHeader = pefPrivate->ldrHeader;

    mainLocation->section   = ldrHeader->entryPointSection;
    mainLocation->offset    = ldrHeader->entryPointOffset;

    initLocation->section   = ldrHeader->initPointSection;
    initLocation->offset    = ldrHeader->initPointOffset;

    termLocation->section   = ldrHeader->termPointSection;
    termLocation->offset    = ldrHeader->termPointOffset;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetAnonymousSymbolLocations ()


// ¤
// ===========================================================================================
// PEF_GetExportedSymbolCount ()
// =============================


extern OSStatus PEF_GetExportedSymbolCount  ( CFContHandlerRef  containerRef,
                                              ItemCount *       exportCount )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;


    if ( (pefPrivate == NULL) || (exportCount == NULL) ) goto ParameterError;

    *exportCount = pefPrivate->ldrHeader->numExportSyms;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetExportedSymbolCount ()


// ¤
// ===========================================================================================
// PEF_GetExportedSymbolInfo ()
// ============================


OSStatus    PEF_GetExportedSymbolInfo   ( CFContHandlerRef              containerRef,
                                          CFContSignedIndex             exportIndex,
                                          PBVersion                     infoVersion,
                                          CFContExportedSymbolInfo *    exportInfo )
{
    OSStatus            err             = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate      = (PEFPrivateInfo *) containerRef;
    LoaderExport *      exportedSymbol  = NULL;


    if ( (pefPrivate == NULL) || (exportInfo == NULL) ) goto ParameterError;
    if ( exportIndex >= pefPrivate->ldrHeader->numExportSyms ) goto ParameterError;
    if ( infoVersion != kCFContExportedSymbolInfoVersion ) goto ParameterError;


    if ( exportIndex >= 0 ) {

        exportedSymbol = &pefPrivate->ldrExportSymbols[exportIndex];

        exportInfo->symbolName.nameHash = pefPrivate->ldrHashChain[exportIndex].hashword;
        exportInfo->symbolName.nameText = &pefPrivate->ldrStringTable[exportedSymbol->nameOffset];

        exportInfo->symbolClass = exportedSymbol->symClass;
        exportInfo->reservedA   = 0;
        exportInfo->reservedB   = 0;
        exportInfo->options     = kNilOptions;

        exportInfo->location.section = exportedSymbol->sectionNumber;

        #if 1   // *** Disable the reexported import optimization.
            exportInfo->location.offset = exportedSymbol->offset;
        #else
            // This is the buggy optimization.  It has problems with missing weak libraries.
            // Addition of a "resolvedImports" bit vector is probably the way to fix it, but it
            // may not be much of an optimization then.
            if ( (! pefPrivate->resolved) || (exportedSymbol->sectionNumber != kReExportImport) ) {
                exportInfo->location.offset = exportedSymbol->address;
            } else {
                exportInfo->location.section    = kPhysicalExport;
                exportInfo->location.offset     = pefPrivate->imports[exportedSymbol->address];
            }
        #endif

    } else {

        CFContLogicalLocation   mainLocation;
        CFContLogicalLocation   initLocation;
        CFContLogicalLocation   termLocation;

        err = PEF_GetAnonymousSymbolLocations ( containerRef, &mainLocation, &initLocation, &termLocation );
        if ( err != noErr ) goto ERROR;

        switch ( exportIndex ) {
            case kMainCFragSymbolIndex  :
                exportInfo->location = mainLocation;
                exportInfo->symbolClass = 0xFF;     // !!! Ought to have a kUnknownCFragSymbol constant.
                break;
            case kInitCFragSymbolIndex  :
                exportInfo->location = initLocation;
                exportInfo->symbolClass = kTVectorCFragSymbol;  // ! Very well better be!
                break;
            case kTermCFragSymbolIndex  :
                exportInfo->location = termLocation;
                exportInfo->symbolClass = kTVectorCFragSymbol;  // ! Very well better be!
                break;
            default :
                goto ParameterError;
        }

        exportInfo->symbolName.nameHash = 0;
        exportInfo->symbolName.nameText = NULL;

        exportInfo->reservedA   = 0;
        exportInfo->reservedB   = 0;
        exportInfo->options     = kNilOptions;

    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetExportedSymbolInfo ()


// ¤
// ===========================================================================================
// PEF_FindExportedSymbolInfo ()
// =============================


OSStatus    PEF_FindExportedSymbolInfo  ( CFContHandlerRef              containerRef,
                                          const CFContHashedName *      exportName,
                                          PBVersion                     infoVersion,
                                          ItemCount *                   exportIndex_o,  // May be null.
                                          CFContExportedSymbolInfo *    exportInfo )    // May be null.
{
    OSStatus            err             = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate      = (PEFPrivateInfo *) containerRef;
    LoaderExport *      exportedSymbol  = NULL;
    CFContStringHash *  hashwordList    = NULL;
    CFContStringHash *  nextHashword    = NULL;
    HashSlotEntry *     hashSlot        = NULL;
    ByteCount           nameLength      = CFContStringHashLength ( exportName->nameHash );
    ItemCount           exportIndex;
    ItemCount           slotIndex;
    ItemCount           chainLimit;
    Boolean             nameMatch;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( infoVersion != kCFContExportedSymbolInfoVersion ) goto ParameterError;


    hashwordList    = &pefPrivate->ldrHashChain[0].hashword;

    slotIndex       = GetPEFHashSlot ( exportName->nameHash, pefPrivate->ldrHeader->hashSlotTabSize );
    hashSlot        = &pefPrivate->ldrHashSlot[slotIndex];

    exportIndex     = hashSlot->chainIndex;
    chainLimit      = exportIndex + hashSlot->chainCount;
    nextHashword    = &hashwordList[exportIndex];

    while ( exportIndex < chainLimit ) {

        if ( *nextHashword == exportName->nameHash ) {
            exportedSymbol = &pefPrivate->ldrExportSymbols[exportIndex];
            nameMatch = PEF_CompareBytes ( exportName->nameText,
                                           &pefPrivate->ldrStringTable[exportedSymbol->nameOffset],
                                           nameLength );
            if ( nameMatch ) goto Found;
        }

        exportIndex     += 1;
        nextHashword    += 1;   // ! Pointer arithmetic.
    }
    goto NotFoundError;

Found:
    if ( exportIndex_o != NULL ) *exportIndex_o = exportIndex;
    if ( exportInfo != NULL ) {
        err = PEF_GetExportedSymbolInfo ( containerRef, exportIndex, infoVersion, exportInfo );
        if ( err != noErr ) goto ERROR;
    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;

NotFoundError:
    err = cfragNoSymbolErr;
    goto ERROR;


}   // PEF_FindExportedSymbolInfo ()


// ¤
// ===========================================================================================
// PEF_GetImportCounts ()
// ======================


OSStatus    PEF_GetImportCounts ( CFContHandlerRef  containerRef,
                                  ItemCount *       libraryCount,   // May be null.
                                  ItemCount *       symbolCount )   // May be null.
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;


    if ( pefPrivate == NULL ) goto ParameterError;

    if ( libraryCount != NULL ) *libraryCount = pefPrivate->ldrHeader->numImportFiles;
    if ( symbolCount != NULL ) *symbolCount = pefPrivate->ldrHeader->numImportSyms;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetImportCounts ()


// ¤
// ===========================================================================================
// PEF_GetImportedLibraryInfo ()
// =============================


OSStatus    PEF_GetImportedLibraryInfo  ( CFContHandlerRef              containerRef,
                                          ItemCount                     libraryIndex,
                                          PBVersion                     infoVersion,
                                          CFContImportedLibraryInfo *   libraryInfo )
{
    OSStatus                err             = cfragCFMInternalErr;
    PEFPrivateInfo *        pefPrivate      = (PEFPrivateInfo *) containerRef;
    LoaderImportFileID *    importedLibrary = NULL;
    BytePtr                 nameText        = NULL;
    ByteCount               nameLength;


    if ( (pefPrivate == NULL) || (libraryInfo == NULL) ) goto ParameterError;
    if ( infoVersion != kCFContImportedLibraryInfoVersion ) goto ParameterError;
    if ( libraryIndex >= pefPrivate->ldrHeader->numImportFiles ) goto ParameterError;


    importedLibrary = &pefPrivate->ldrImportFiles[libraryIndex];

    nameText    = &pefPrivate->ldrStringTable[importedLibrary->fileNameOffset];
    nameLength  = GetNameLength ( nameText );

    libraryInfo->libraryName.nameHash   = CFContHashName ( nameText, nameLength );
    libraryInfo->libraryName.nameText   = nameText;

    libraryInfo->linkedVersion  = importedLibrary->linkedVersion;
    libraryInfo->oldImpVersion  = importedLibrary->oldImpVersion;
    libraryInfo->options        = kNilOptions;

    if ( importedLibrary->options & kPEFInitBeforeMask ) libraryInfo->options |= kCFContInitBeforeMask;
    if ( importedLibrary->options & kPEFWeakLibraryMask ) libraryInfo->options |= kCFContWeakLibraryMask;
    if ( importedLibrary->options & kPEFDeferredBindMask ) libraryInfo->options |= kCFContDeferredBindMask;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_GetImportedLibraryInfo ()


// ¤
// ===========================================================================================
// PEF_GetImportedSymbolInfo ()
// ============================


OSStatus    PEF_GetImportedSymbolInfo   ( CFContHandlerRef              containerRef,
                                          ItemCount                     symbolIndex,
                                          PBVersion                     infoVersion,
                                          CFContImportedSymbolInfo *    symbolInfo )
{
    OSStatus                err             = cfragCFMInternalErr;
    PEFPrivateInfo *        pefPrivate      = (PEFPrivateInfo *) containerRef;
    LoaderImport *          importedSymbol  = NULL;
    LoaderImportFileID *    importedLibrary = NULL;
    BytePtr                 nameText        = NULL;
    ByteCount               nameLength;
    ItemCount               libraryCount;
    ItemCount               libraryIndex;


    if ( (pefPrivate == NULL) || (symbolInfo == NULL) ) goto ParameterError;
    if ( infoVersion != kCFContImportedSymbolInfoVersion ) goto ParameterError;
    if ( symbolIndex >= pefPrivate->ldrHeader->numImportSyms ) goto ParameterError;


    importedSymbol  = &pefPrivate->ldrImportSymbols[symbolIndex];
    libraryCount    = pefPrivate->ldrHeader->numImportFiles;

    nameText    = &pefPrivate->ldrStringTable[importedSymbol->nameOffset];
    nameLength  = GetNameLength ( nameText );

    symbolInfo->symbolName.nameHash = CFContHashName ( nameText, nameLength );
    symbolInfo->symbolName.nameText = nameText;

    symbolInfo->symbolClass     = importedSymbol->symClass & 0x0F;
    symbolInfo->reservedA       = 0;
    symbolInfo->reservedB       = 0;
    symbolInfo->options         = 0;

    if ( importedSymbol->symClass & kPEFWeakSymbolMask ) symbolInfo->options |= kCFContWeakSymbolMask;

    for ( libraryIndex = 0; libraryIndex < libraryCount; libraryIndex += 1 ) {
        importedLibrary = &pefPrivate->ldrImportFiles[libraryIndex];
        if ( (importedLibrary->impFirst <= symbolIndex) &&
             (symbolIndex < (importedLibrary->impFirst + importedLibrary->numImports)) ) {
            break;
        }
    }
    if ( libraryIndex == libraryCount ) goto FragmentCorruptError;

    symbolInfo->libraryIndex = libraryIndex;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;

FragmentCorruptError:
    err = cfragFragmentCorruptErr;
    goto ERROR;


}   // PEF_GetImportedSymbolInfo ()


// ¤
// ===========================================================================================
// PEF_SetImportedSymbolAddress ()
// ===============================


OSStatus    PEF_SetImportedSymbolAddress    ( CFContHandlerRef              containerRef,
                                              ItemCount                     symbolIndex,
                                              LogicalAddress                symbolAddress )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( symbolIndex >= pefPrivate->ldrHeader->numImportSyms ) goto ParameterError;


    pefPrivate->imports[symbolIndex] = symbolAddress;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_SetImportedSymbolAddress ()


// ¤
// ===========================================================================================
// GetPackedDataCount ()
// =====================


static UInt32   GetPackedDataCount ( UInt8 * *  byteHandle )
{
    UInt32  count   = 0;
    UInt8 * bytePtr = *byteHandle;
    UInt8   currByte;


    do {
        currByte = *bytePtr++;
        count = (count << kPEFPkDataVCountShift) | (currByte & kPEFPkDataVCountMask);
    } while ( (currByte & kPEFPkDataVCountEndMask) != 0 );

    *byteHandle = bytePtr;

    return count;


}   // GetPackedDataCount ()


// ¤
// ===========================================================================================
// UnpackFullSection ()
// ====================


// ------------------------------------------------------------------------------------------
// This is the "normal" case from CFM, unpacking all of the packed portion.  Along the way we
// make sure we're not writing beyond the end of the unpacked data.  At the end we make sure
// that all we didn't read past the end of the packed data, and that all of the output was
// written.

// ! Note that the xyzEnd pointers are the actual end of the range, not one byte beyond.  This
// ! routine will work if the output end address is 0xFFFFFFFF, but not if the packed end is.

// ! Don't do range comparisons as "(lowAddr + length) > highAddr", because this might wrap
// ! the end high end of the address space.  Always do "(highAddr - lowAddr) > length".

// ??? We should gather some statistics on actual usage to see whether it is worthwhile to
// ??? have local customized code for common cases.  E.g. block fill of 1, 2, or 4 bytes, or
// ??? of interleaved repeats with 1/2/4 byte common or custom portions.


static OSStatus UnpackFullSection   ( BytePtr   packedBase,
                                      BytePtr   packedEnd,
                                      BytePtr   outputBase,
                                      BytePtr   outputEnd )
{
    OSStatus    err         = cfragCFMInternalErr;
    BytePtr     packedPos   = packedBase;
    BytePtr     outputPos   = outputBase;
    BytePtr     outPosLimit = outputEnd + 1;    // ! Might be zero if outputEnd is 0xFFFFFFFF.

    UInt8       currByte;
    UInt8       opcode;
    UInt32      count1;
    UInt32      count2;
    UInt32      count3;


    if ( (packedEnd + 1) == 0 ) goto FragmentUsageError;


    while ( packedPos <= packedEnd ) {


        currByte    = *packedPos++;
        opcode      = currByte >> kPEFPkDataOpcodeShift;
        count1      = currByte & kPEFPkDataCount5Mask;

        if ( count1 == 0 ) count1 = GetPackedDataCount ( &packedPos );


        switch ( opcode ) {


            case kPEFPkDataZero :

                if ( (outPosLimit - outputPos) < count1 ) goto FragmentCorruptError;

                PEF_BlockClear ( outputPos, count1 );
                outputPos += count1;

                break;


            case kPEFPkDataBlock :

                if ( (outPosLimit - outputPos) < count1 ) goto FragmentCorruptError;

                PEF_BlockMove ( packedPos, outputPos, count1 );
                packedPos   += count1;
                outputPos   += count1;

                break;


            case kPEFPkDataRepeat :     // ??? Need a BlockFill routine?

                count2 = GetPackedDataCount ( &packedPos ) + 1;     // ! Stored count is 1 less.

                if ( (outPosLimit - outputPos) < (count1 * count2) ) goto FragmentCorruptError;

                if ( count1 == 1 ) {    // ??? Is this worth the bother?  Other sizes?

                    currByte = *packedPos++;
                    for ( ; count2 != 0; count2 -= 1 ) *outputPos++ = currByte;

                } else {

                    for ( ; count2 != 0; count2 -= 1 ) {
                        PEF_BlockMove ( packedPos, outputPos, count1 );
                        outputPos += count1;
                    }
                    packedPos += count1;

                }

                break;


            case kPEFPkDataRepeatBlock :

                count2  = GetPackedDataCount ( &packedPos );
                count3  = GetPackedDataCount ( &packedPos );

                if ( (outPosLimit - outputPos) < (((count1 + count2) * count3) + count1) ) goto FragmentCorruptError;

                {
                    BytePtr commonPos   = packedPos;

                    packedPos += count1;    // Skip the common part.

                    for ( ; count3 != 0; count3 -= 1 ) {

                        PEF_BlockMove ( commonPos, outputPos, count1 );
                        outputPos += count1;

                        PEF_BlockMove ( packedPos, outputPos, count2 );
                        packedPos   += count2;
                        outputPos   += count2;

                    }

                    PEF_BlockMove ( commonPos, outputPos, count1 );
                    outputPos += count1;

                }

                break;


            case kPEFPkDataRepeatZero :

                count2 = GetPackedDataCount ( &packedPos );
                count3 = GetPackedDataCount ( &packedPos );

                if ( (outPosLimit - outputPos) < (((count1 + count2) * count3) + count1) ) goto FragmentCorruptError;

                PEF_BlockClear ( outputPos, count1 );
                outputPos += count1;

                for ( ; count3 != 0; count3 -= 1 ) {

                    PEF_BlockMove ( packedPos, outputPos, count2 );
                    packedPos   += count2;
                    outputPos   += count2;

                    PEF_BlockClear ( outputPos, count1 );
                    outputPos += count1;

                }

                break;


            default :
                goto FragmentCorruptError;

        }

    }


    if ( (packedPos != (packedEnd + 1)) || (outputPos != outPosLimit) ) goto FragmentCorruptError;

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;


FragmentUsageError:
    err = cfragFragmentUsageErr;
    goto ERROR;

FragmentCorruptError:
    err = cfragFragmentCorruptErr;
    goto ERROR;


}   // UnpackFullSection ()


// ¤
// ===========================================================================================
// UnpackPartialSection ()
// =======================


// -------------------------------------------------------------------------------------------
// This is the case where we want to extract some arbitrary portion of a section as it would
// be when instantiated but not relocated.  We have to interpret the packed part up to the
// desired output start, then continue begin unpacking for real.  If we run out of packed data
// before filling the output, we fill the rest of the output with zeroes.

// ! We have to be very careful in the skip logic because the current operation probably spans
// ! the skip/output boundary.  We have to be similarly careful at the output end because the
// ! current operation probably spans the tail of the output.  Don't forget that the partial
// ! output at the start could also fill the output and overflow the tail!

// ! Note that the xyzEnd pointers are the actual end of the range, not one byte beyond.  This
// ! routine might not work if outputEnd is 0xFFFFFFFF.  This is because outputPos points to
// ! the next byte to be written.  The loops that are controlled by "outputPos < outputBase"
// ! or "outputPos <= outputEnd" would fail in this case if outputPos were "outputEnd + 1",
// ! i.e. outputPos would be zero.

// ! Don't do range comparisons as "(lowAddr + length) > highAddr", because this might wrap
// ! the end high end of the address space.  Always do "(highAddr - lowAddr) > length".


// -------------------------------------------------------------------------------------------


static void PartialBlockClear   ( BytePtr   outputBase,
                                  ByteCount outputStartOffset,
                                  ByteCount outputEndOffset,
                                  ByteCount outputOffset,
                                  ByteCount count )
{

    if ( ((outputOffset + count) <= outputStartOffset) || (outputOffset > outputEndOffset) ) return;    // Nothing to output.

    if ( outputOffset < outputStartOffset ) {
        count -= (outputStartOffset - outputOffset);
        outputOffset = outputStartOffset;
    }

    if ( count > (outputEndOffset - outputOffset + 1) ) count = outputEndOffset - outputOffset + 1;

    PEF_BlockClear ( outputBase + (outputOffset - outputStartOffset), count );

}   // PartialBlockClear ();


// -------------------------------------------------------------------------------------------


static void PartialBlockMove    ( BytePtr   source,
                                  BytePtr   outputBase,
                                  ByteCount outputStartOffset,
                                  ByteCount outputEndOffset,
                                  ByteCount outputOffset,
                                  ByteCount count )
{

    if ( ((outputOffset + count) <= outputStartOffset) || (outputOffset > outputEndOffset) ) return;    // Nothing to output.

    if ( outputOffset < outputStartOffset ) {
        const ByteCount skipCount   = outputStartOffset - outputOffset;
        source  += skipCount;
        count   -= skipCount;
        outputOffset = outputStartOffset;
    }

    if ( count > (outputEndOffset - outputOffset + 1) ) count = outputEndOffset - outputOffset + 1;

    PEF_BlockMove ( source, outputBase + (outputOffset - outputStartOffset), count );

}   // PartialBlockClear ();


// -------------------------------------------------------------------------------------------


static OSStatus UnpackPartialSection    ( BytePtr   packedBase,
                                          BytePtr   packedEnd,
                                          BytePtr   outputBase,
                                          BytePtr   outputEnd,
                                          ByteCount outputStartOffset )
{
    OSStatus        err             = cfragCFMInternalErr;
    const ByteCount outputEndOffset = outputStartOffset + (outputEnd - outputBase);
    BytePtr         packedPos       = NULL;
    BytePtr         packedBoundary  = NULL;
    ByteCount       outputOffset;
    ByteCount       outputBoundary;

    UInt8           currByte;
    UInt8           opcode;
    UInt32          count1;
    UInt32          count2;
    UInt32          count3;


    if ( ((packedEnd + 1) == 0) || ((outputEnd + 1) == 0) ) goto FragmentUsageError;


    // --------------------------------------------------------------------------------------
    // Skip the packed data until we get within the output range.  We know there is something
    // to unpack, otherwise the zero fill of the output would be done by the caller.  This
    // loop sets outputOffset to the end of what would be unpacked, until the outputOffset is
    // beyond the outputStartOffset.  I.e. until we hit the first operation that would create
    // actual output.

    outputOffset    = 0;
    packedPos       = packedBase;

    do {

        packedBoundary  = packedPos;    // The start of the current operation.
        outputBoundary  = outputOffset;

        currByte        = *packedPos++;
        opcode          = currByte >> kPEFPkDataOpcodeShift;
        count1          = currByte & kPEFPkDataCount5Mask;

        if ( count1 == 0 ) count1 = GetPackedDataCount ( &packedPos );

        switch ( opcode ) {

            case kPEFPkDataZero :
                outputOffset += count1;
                break;

            case kPEFPkDataBlock :
                packedPos       += count1;
                outputOffset    += count1;
                break;

            case kPEFPkDataRepeat :
                count2 = GetPackedDataCount ( &packedPos ) + 1;     // ! Stored count is 1 less.
                packedPos       += count1;
                outputOffset    += count1 * count2;
                break;


            case kPEFPkDataRepeatBlock :
                count2  = GetPackedDataCount ( &packedPos );
                count3  = GetPackedDataCount ( &packedPos );
                packedPos       += count1 + (count2 * count3);
                outputOffset    += count1 + ((count1 + count2) * count3);
                break;


            case kPEFPkDataRepeatZero :
                count2 = GetPackedDataCount ( &packedPos );
                count3 = GetPackedDataCount ( &packedPos );
                packedPos       += count2 * count3;
                outputOffset    += count1 + ((count1 + count2) * count3);
                break;


            default :
                goto FragmentCorruptError;

        }

    } while ( outputOffset <= outputStartOffset );


    //----------------------------------------------------------------------------------------
    // Now do the actual unpacking.  This uses a copy of the full unpack logic with special
    // block copy/clear routines.  These special routines do the bounds checking, only writing
    // output where actually allowed.  This involves "unnecessary" checks for the "middle"
    // operations that are fully within the range, but vastly simplifies the boundary cases.

    packedPos       = packedBoundary;       // Reset to the operation that spans the output start.
    outputOffset    = outputBoundary;

    do {

        currByte    = *packedPos++;
        opcode      = currByte >> kPEFPkDataOpcodeShift;
        count1      = currByte & kPEFPkDataCount5Mask;

        if ( count1 == 0 ) count1 = GetPackedDataCount ( &packedPos );

        switch ( opcode ) {

            case kPEFPkDataZero :
                PartialBlockClear ( outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                outputOffset += count1;
                break;

            case kPEFPkDataBlock :
                PartialBlockMove ( packedPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                packedPos       += count1;
                outputOffset    += count1;
                break;

            case kPEFPkDataRepeat :     // ??? Need a BlockFill routine?
                count2 = GetPackedDataCount ( &packedPos ) + 1;     // ! Stored count is 1 less.
                for ( ; count2 != 0; count2 -= 1 ) {
                    PartialBlockMove ( packedPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                    outputOffset += count1;
                }
                packedPos += count1;
                break;

            case kPEFPkDataRepeatBlock :

                count2  = GetPackedDataCount ( &packedPos );
                count3  = GetPackedDataCount ( &packedPos );

                {
                    BytePtr commonPos   = packedPos;

                    packedPos += count1;    // Skip the common part.

                    for ( ; count3 != 0; count3 -= 1 ) {

                        PartialBlockMove ( commonPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                        outputOffset += count1;

                        PartialBlockMove ( packedPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count2 );
                        packedPos       += count2;
                        outputOffset    += count2;

                    }

                    PartialBlockMove ( commonPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                    outputOffset += count1;

                }

                break;

            case kPEFPkDataRepeatZero :

                count2 = GetPackedDataCount ( &packedPos );
                count3 = GetPackedDataCount ( &packedPos );

                PartialBlockClear ( outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                outputOffset += count1;

                for ( ; count3 != 0; count3 -= 1 ) {

                    PartialBlockMove ( packedPos, outputBase, outputStartOffset, outputEndOffset, outputOffset, count2 );
                    packedPos       += count2;
                    outputOffset    += count2;

                    PartialBlockClear ( outputBase, outputStartOffset, outputEndOffset, outputOffset, count1 );
                    outputOffset += count1;

                }

                break;

            default :
                goto FragmentCorruptError;

        }

    } while ( (outputOffset <= outputEndOffset) && (packedPos <= packedEnd) );


    // ------------------------------------------
    // Finally block clear anything that is left.

    if ( outputOffset <= outputEndOffset ) {
        PEF_BlockClear ( outputBase + (outputOffset - outputStartOffset), outputEndOffset - outputOffset + 1 );
    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;


FragmentUsageError:
    err = cfragFragmentUsageErr;
    goto ERROR;

FragmentCorruptError:
    err = cfragFragmentCorruptErr;
    goto ERROR;


}   // UnpackPartialSection ()


// ¤
// ===========================================================================================
// PEF_UnpackSection ()
// ====================


OSStatus    PEF_UnpackSection   ( CFContHandlerRef  containerRef,
                                  ItemCount         sectionIndex,
                                  ByteCount         sectionOffset,
                                  LogicalAddress    bufferAddress,
                                  ByteCount         bufferLength )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;
    SectionHeader *     section     = NULL;
    BytePtr             packedBase  = NULL;
    BytePtr             packedEnd   = NULL;
    BytePtr             outputBase  = bufferAddress;
    BytePtr             outputEnd   = outputBase + bufferLength - 1;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( sectionIndex >= pefPrivate->sectionCount ) goto ParameterError;
    if ( (bufferAddress == NULL) && (bufferLength != 0) ) goto ParameterError;

    section = &pefPrivate->sections[sectionIndex];
    if ( (sectionOffset + bufferLength) > section->execSize ) goto ParameterError;

    packedBase  = pefPrivate->mappedContainer + section->containerOffset;
    packedEnd   = packedBase + section->rawSize - 1;


    if ( (sectionOffset == 0) && (bufferLength == section->initSize) ) {

        err = UnpackFullSection ( packedBase, packedEnd, outputBase, outputEnd );
        if ( err != noErr ) goto ERROR;

        if ( false && EnableCFMDebugging && (section->execSize > 8) ) { // Force some tests of partial unpacking.

            UInt32  word;
            BytePtr  partContents   = (*pefPrivate->Allocate) ( section->execSize - 2 );

            PEF_Assert ( partContents != NULL );

            err = PEF_UnpackSection ( containerRef, sectionIndex, 1, &word, 4 );
            PEF_Assert ( err == noErr );

            err = PEF_UnpackSection ( containerRef, sectionIndex, section->execSize / 2, &word, 4 );
            PEF_Assert ( err == noErr );

            err = PEF_UnpackSection ( containerRef, sectionIndex, section->execSize - 5, &word, 4 );
            PEF_Assert ( err == noErr );

            err = PEF_UnpackSection ( containerRef, sectionIndex, 1, partContents, section->execSize - 2 );
            PEF_Assert ( err == noErr );

            (*pefPrivate->Release) ( partContents );
        }

    } else {

        if ( section->initSize < sectionOffset ) {
            PEF_BlockClear ( bufferAddress, bufferLength );
        } else {
            err = UnpackPartialSection ( packedBase, packedEnd, outputBase, outputEnd, sectionOffset );
            if ( err != noErr ) goto ERROR;
        }

        if ( EnableCFMDebugging ) {     // See if the partial output agrees with full output.

            BytePtr  fullContents   = (*pefPrivate->Allocate) ( section->execSize );

            PEF_Assert ( fullContents != NULL );
            PEF_BlockClear ( fullContents, section->execSize );

            err = UnpackFullSection ( packedBase, packedEnd, fullContents, fullContents + section->initSize - 1 );
            PEF_Assert ( err == noErr );

            PEF_Assert ( PEF_CompareBytes ( fullContents + sectionOffset, bufferAddress, bufferLength ) );

            (*pefPrivate->Release) ( fullContents );

        }

    }

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;


ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_UnpackSection ()


// ¤
// ===========================================================================================
// PEF_RelocateSection ()
// ======================


// *** This needs cleaning up.


OSStatus    PEF_RelocateSection ( CFContHandlerRef  containerRef,
                                  ItemCount         sectionIndex )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;

    BytePtr *   raddr;
    ByteCount dataA;
    int cnt;    // ! Must be signed.
    ByteCount codeA;
    LoaderRelExpHeader * ldRelHdr;
    Relocation *reloc, *rlend;
    Relocation r;
    long rpt;   // ! Must be signed.
    long secn;
    long rsymi;
    BytePtr *imports;
    ByteCount *regions;
    long i;
    long relNum;
    BytePtr regStart;
    SectionHeader * section;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( sectionIndex >= pefPrivate->sectionCount ) goto ParameterError;

    regStart = pefPrivate->mappedOrigins[sectionIndex];
    section = & pefPrivate->sections [sectionIndex];

    pefPrivate->resolved = 1;       // !!! Really means relocated, and should be set on exit.

    for (i = 0; ; i++) {
        if ( i >= pefPrivate->sectionCount ) return noErr;  // No relocations for this section.
        ldRelHdr = & pefPrivate->ldrSections [i];
        if ( ldRelHdr->sectionNumber == sectionIndex ) break;
    }

    regions = pefPrivate->runningOffsets;
    imports = pefPrivate->imports;

    reloc = (Relocation *) (pefPrivate->ldrRelocations + ldRelHdr->relocationsOffset);
    rlend = (Relocation *) ((RelocInstr *) reloc + ldRelHdr->numRelocations);
    raddr = (BytePtr *) regStart;   // ! Change the stride from 1 to 4.
    rsymi = 0;
    codeA = regions [0];
    dataA = regions [1];
    rpt = 0;

    #if 0
        sprintf ( gDebugMessage, "PLPrepareRegion: start @ %.8X\n", raddr );
        PutSerialMesssage ( gDebugMessage );
    #endif

    relNum = 0;
    while (reloc < rlend) {

        r = *reloc;
        reloc = (Relocation *) ((RelocInstr *) reloc + 1);

        switch ( opcode [r.opcode.op] ) {
            case krDDAT :
                raddr = (BytePtr *) ((BytePtr)raddr + (r.deltadata.delta_d4 * 4));  // ! Reduce stride to 1.
                cnt = r.deltadata.cnt;
                while (--cnt >= 0) {
                    *raddr++ += dataA;
                }
                break;

            case krCODE :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += codeA;
                }
                break;

            case krDATA :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += dataA;
                }
                break;

            case krDESC :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += codeA;
                    *raddr++ += dataA;
                    raddr++;
                }
                break;

            case krDSC2 :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += codeA;
                    *raddr++ += dataA;
                }
                break;

            case krVTBL :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += dataA;
                    raddr++;
                }
                break;

            case krSYMR :
                cnt = r.run.cnt_m1 + 1;
                while (--cnt >= 0) {
                    *raddr++ += (ByteCount) imports [rsymi++];
                }
                break;

            case krSYMB :
                rsymi = r.glp.idx;
                *raddr++ += (ByteCount) imports [rsymi++];
                break;

            case krCDIS :
                codeA = regions [r.glp.idx];
                break;

            case krDTIS :
                dataA = regions [r.glp.idx];
                break;

            case krSECN :
                *raddr++ += regions [r.glp.idx];
                break;

            case krDELT :
                raddr = (BytePtr *) ((BytePtr) raddr + r.delta.delta_m1 + 1);   // ! Reduce stride to 1.
                #if 0
                    sprintf ( gDebugMessage, "PLPrepareRegion: delta to %.8X\n", raddr );
                    PutSerialMesssage ( gDebugMessage );
                #endif
                break;

            case krRPT :
                if (--rpt == 0) break;  // count was 1 --> rpt done
                if (rpt < 0)                    // first time rpt encountered?
                    rpt = r.rpt.rcnt_m1 + 1; // yes- initialize rpt count
                cnt = r.rpt.icnt_m1 + 2;    // yes or no - back up cnt instrs
                reloc = (Relocation *) ((RelocInstr *) reloc - cnt);
                break;

            case krLABS :
                raddr = (BytePtr *) ((r.large1.idx_top << 16) + reloc->bot + regStart);
                reloc = (Relocation *) ((RelocInstr *) reloc + 1);
                #if 0
                    sprintf ( gDebugMessage, "PLPrepareRegion: abs to %.8X\n", raddr );
                    PutSerialMesssage ( gDebugMessage );
                #endif
                break;

            case krLSYM :
                rsymi = (r.large1.idx_top << 16) + reloc->bot;
                reloc = (Relocation *) ((RelocInstr *) reloc + 1);
                *raddr++ += (ByteCount) imports [rsymi++];
                break;

            case krLRPT :
                if (--rpt == 0) {
                    reloc = (Relocation *) ((RelocInstr *) reloc + 1);
                    break;
                }
                if (rpt < 0)
                    rpt = (r.large2.idx_top << 16) + reloc->bot;
                cnt = r.large2.cnt_m1 + 2;
                reloc = (Relocation *) ((RelocInstr *) reloc - cnt);
                break;

            case krLSEC :
                secn = (r.large2.idx_top << 16) + reloc->bot;
                switch (r.large2.cnt_m1) {
                    case 0 : *raddr++ += regions [secn]; break;
                    case 1 : codeA  = regions [secn]; break;
                    case 2 : dataA  = regions [secn]; break;
                }
                reloc = (Relocation *) ((RelocInstr *) reloc + 1);
                break;

            default :
                goto FragmentCorruptError;
        }
    }


    #if 0
        sprintf ( gDebugMessage, "PLPrepareRegion: end @ %.8X\n", raddr );
        PutSerialMesssage ( gDebugMessage );
    #endif

    err = noErr;

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;

FragmentCorruptError:
    err = cfragFragmentCorruptErr;
    goto ERROR;


}   // PEF_RelocateSection ()


// ¤
// ===========================================================================================
// PEF_RelocateImportsOnly ()
// ==========================


OSStatus    PEF_RelocateImportsOnly ( CFContHandlerRef  containerRef,
                                      ItemCount         sectionIndex,
                                      ItemCount         libraryIndex )
{
    OSStatus            err         = cfragCFMInternalErr;
    PEFPrivateInfo *    pefPrivate  = (PEFPrivateInfo *) containerRef;


    if ( pefPrivate == NULL ) goto ParameterError;
    if ( sectionIndex >= pefPrivate->sectionCount ) goto ParameterError;
    if ( libraryIndex >= pefPrivate->ldrHeader->numImportFiles ) goto ParameterError;


    if ( pefPrivate == NULL ) goto ParameterError;


    return unimpErr;    // !!! Fix this!

EXIT:
    return err;

ERROR:
    goto EXIT;

ParameterError:
    err = paramErr;
    goto ERROR;


}   // PEF_RelocateImportsOnly ()

