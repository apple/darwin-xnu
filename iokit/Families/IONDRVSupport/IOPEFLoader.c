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
 *	From pieces of ProtoCFM, Alan Lillich.
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  21 July 98 - start IOKit
 */


#include <IOKit/IOLib.h>
#include <IOKit/ndrvsupport/IONDRVSupport.h>

#include "IOPEFLibraries.h"
#include "IOPEFLoader.h"
#include "IOPEFInternals.h"



#define LOG	if(0)	IOLog
#define INFO	if(0)	IOLog

struct SectionVars {
    LogicalAddress          address;
    ByteCount		    allocSize;
    ByteCount               unpackedLength;
    Boolean                 isPacked;
};
typedef struct SectionVars SectionVars;

struct InstanceVars {
    BytePtr                 pef;            // container in memory  
    CFContHandlerRef        cRef;
    CFContHandlerProcs *    cProcs;
    ItemCount               numSections;
    SectionVars         *   sections;
    IONDRVUndefinedSymbolHandler undefinedHandler;
    void *		    undefHandlerSelf;
};
typedef struct InstanceVars InstanceVars;


static OSStatus LocationToAddress( InstanceVars * inst,
	CFContLogicalLocation * location, LogicalAddress * address );
static OSStatus SatisfyImports( InstanceVars * inst );
static OSStatus Instantiate( InstanceVars * inst );


#define PCFM_BlockCopy(src,dst,len) 	memcpy(dst,src,len)
#define PCFM_BlockClear(dst,len)    	memset(dst,0,len)
#define PCFM_MakeExecutable(addr,len)	flush_dcache((vm_offset_t)addr, len, 0);	\
					invalidate_icache((vm_offset_t)addr, len, 0)

extern OSStatus    CallTVector( 
	    void * p1, void * p2, void * p3, void * p4, void * p5, void * p6,
	    LogicalAddress entry );

// ¤
// ===========================================================================================
// CFContHashName ()
// =================


CFContStringHash    CFContHashName  ( BytePtr   nameText,
                                      ByteCount nameLength )
{
    BytePtr             currChar    = nameText;
    SInt32              hashValue   = 0;    // ! Signed to match old published PEF algorithm.
    ByteCount           length      = 0;
    ByteCount           limit;
    CFContStringHash    result;

    #define PseudoRotate(x)  ( ( (x) << 1 ) - ( (x) >> (16) ) )


    for ( limit = nameLength; limit > 0; limit -= 1 ) {
        if ( *currChar == NULL ) break;
        hashValue   = (PseudoRotate ( hashValue )) ^ *currChar;
        currChar    += 1;
        length      += 1;
    }

    result = (length << 16) | ((UInt16) ((hashValue ^ (hashValue >> 16)) & 0xFFFF));

    return result;


}   // CFContHashName ()


// ¤
// ===========================================================================================
// PCFM_CompareBytes ()
// ====================


Boolean PCFM_CompareBytes   ( const Byte *  left,
                              const Byte *  right,
                              ByteCount     count )
{
    // !!! Blechola!  Switch to a standard routine ASAP!

    UInt32 *    wLeft;
    UInt32 *    wRight;
    UInt8 *     bLeft;
    UInt8 *     bRight;

    ByteCount   leftMiss    = (UInt32)left & 0x00000003;
    ByteCount   rightMiss   = (UInt32)right & 0x00000003;


    bLeft   = (UInt8 *) left;
    bRight  = (UInt8 *) right;

    if ( (leftMiss != 0) && (rightMiss != 0) ) {
        ByteCount   align   = leftMiss;
        if ( align > count ) align = count;
        while ( align > 0 ) {
            if ( *bLeft++ != *bRight++ ) goto NoMatch;
            align -= 1;
            count -= 1;
        }
    }

    wLeft   = (UInt32 *) bLeft;
    wRight  = (UInt32 *) bRight;
    while ( count >= 4 ) {
        if ( *wLeft++ != *wRight++ ) goto NoMatch;
        count -= 4;
    }

    bLeft   = (UInt8 *) wLeft;
    bRight  = (UInt8 *) wRight;
    while ( count > 0 ) {
        if ( *bLeft++ != *bRight++ ) goto NoMatch;
        count -= 1;
    }

    return true;


NoMatch:
    return false;


}   // PCFM_CompareBytes ()

// ===========================================================================================

LogicalAddress PCodeAllocateMem( ByteCount size );
void  PCodeReleaseMem( LogicalAddress address );
extern void *kern_os_malloc(size_t size);
extern void kern_os_free(void * addr);

LogicalAddress
PCodeAllocateMem( ByteCount size )
{
    return( (LogicalAddress) kern_os_malloc( (size_t) size ));
}

void 
PCodeReleaseMem( LogicalAddress address )
{
    kern_os_free( (void *) address );
}

// ===========================================================================================

OSStatus
PCodeOpen( LogicalAddress container, ByteCount containerSize, PCodeInstance * instance )
{
    OSStatus            err;
    InstanceVars     *  inst;

    inst = PCodeAllocateMem( sizeof( InstanceVars));
    *instance = inst;

    inst->pef = (BytePtr) container;
                                            // procID, name, options
    err = PEF_OpenContainer( container, container, containerSize, 0, 0, 0,
			    PCodeAllocateMem, PCodeReleaseMem,
			    &inst->cRef, &inst->cProcs );
    if( err) LOG( "PEF_OpenContainer = %ld\n", err );

    return( err);
}

OSStatus
PCodeInstantiate( PCodeInstance instance,
                    IONDRVUndefinedSymbolHandler handler, void * self )
{
    OSStatus         	   err;
    InstanceVars     	*  inst = instance;
    CFContLogicalLocation  initLocation;
    LogicalAddress	   tv;
    CFragInitBlock	   initInfo;

    inst->undefinedHandler = handler;
    inst->undefHandlerSelf = self;

    do {
	err = Instantiate( inst );
	if( err)
	    continue;

	// call INIT
    	err = PEF_GetAnonymousSymbolLocations( inst->cRef, NULL, &initLocation, NULL );
	if( err)
	    continue;
	err = LocationToAddress( inst, &initLocation, &tv );
	if( err || (tv == NULL) )
	    continue;
	bzero( &initInfo, sizeof( initInfo));
	err = CallTVector( &initInfo, 0, 0, 0, 0, 0, tv );

    } while( false);

    return( err);
}


OSStatus
PCodeClose( PCodeInstance instance )
{
    OSStatus            err;
    InstanceVars     *  inst = instance;
    SectionVars      *  section;
    int			i;

    if( !inst)
	return( noErr);

    err = PEF_CloseContainer( inst->cRef, 0 );
    if( err) LOG( "PEF_CloseContainer = %ld\n", err );

    if( inst->sections ) {
        for( i = 0; i < inst->numSections; i++) {
            section = inst->sections + i;
	    if( section->allocSize)
		PCodeReleaseMem( section->address);
        }
        PCodeReleaseMem(inst->sections);
    }

    return( err);
}

OSStatus
PCodeFindExport( PCodeInstance instance, const char * symbolName, LogicalAddress * address, CFragSymbolClass * symbolClass )
{
    CFContExportedSymbolInfo        symInfo;
    CFContHashedName                hashName;
    OSStatus                        err;
    InstanceVars     		*   inst = instance;

    hashName.nameHash = CFContHashName( (UInt8 *) symbolName, strlen( symbolName) );
    hashName.nameText = (UInt8 *) symbolName;

    err = PEF_FindExportedSymbolInfo( inst->cRef, &hashName,
                                    kCFContExportedSymbolInfoVersion, (void *) 0, &symInfo );
    if( err) {
	LOG( "PEF_FindExportedSymbolInfo = %ld\n", err );
	return( err);
    }

    if( address);
	err = LocationToAddress( inst, &symInfo.location, address );
    if( symbolClass)
	*symbolClass = symInfo.symbolClass;

    return( err);
}

OSStatus
PCodeFindMain( PCodeInstance instance, LogicalAddress * mainAddress )
{
    InstanceVars     		*   inst = instance;
    CFContLogicalLocation           mainLocation;
    OSStatus                        err;

    err = PEF_GetAnonymousSymbolLocations( inst->cRef, &mainLocation, NULL, NULL );

    if( err == noErr)
	err = LocationToAddress( inst, &mainLocation, mainAddress );

    return( err);
}



// ===========================================================================================

static OSStatus
LocationToAddress( InstanceVars * inst, CFContLogicalLocation * location,
		LogicalAddress * address )
{
    BytePtr                 sectionBase;
    OSStatus                err = noErr;

    if ( location->section >= 0 ) {
        sectionBase = (BytePtr) (inst->sections + location->section)->address;
        *address = (LogicalAddress) (sectionBase + location->offset);

    } else if ( location->section == kCFContAbsoluteSectionIndex ) {
        *address = (LogicalAddress) location->offset;

    } else if ( location->section == kCFContNoSectionIndex ) {
        *address = (LogicalAddress) kUnresolvedCFragSymbolAddress;

    } else
        err = cfragFragmentFormatErr;

    return( err);
}


static OSStatus
Instantiate( InstanceVars * inst )
{
    CFContHandlerRef        cRef;
    ItemCount               numSects, sectionIndex;
    CFContSectionInfo       sectionInfo;
    CFContSectionInfo   *   section;
    OSStatus                err;

    cRef = inst->cRef;
            
    err = PEF_GetSectionCount( cRef, &numSects );
    if( err) LOG( "PEF_GetSectionCount = %ld\n", err );
    INFO( "Num sects = %ld\n", numSects );

    inst->numSections = numSects;
    inst->sections = PCodeAllocateMem( numSects * sizeof( SectionVars ));

    for( sectionIndex = 0; sectionIndex < numSects; sectionIndex++ )
    {
        Boolean                 isPacked, isMappable;
        Boolean                 needAlloc, needCopy, needClear;
        LogicalAddress          sectionAddress;
        SectionVars         *   sectionVars;

        sectionVars = inst->sections + sectionIndex;
        section = &sectionInfo;

        err = PEF_GetSectionInfo( cRef, sectionIndex, kCFContSectionInfoVersion, section );
        if( err) LOG( "PEF_GetSectionInfo = %ld\n", err );

#if 0
        if ( sectionInfo.sharing == kCFContShareSectionInClosure ) goto SectionSharingError;
        if ( (! (sectionInfo.access & kCFContMemWriteMask)) &&
             (sectionInfo.options & kRelocatedCFContSectionMask) ) goto SectionOptionsError;
#endif

        isPacked            = ((section->options & kPackedCFContSectionMask) != 0);
        isMappable          = (! isPacked) &&
                              (! (section->options & kRelocatedCFContSectionMask)) &&
                              (! (section->access & kCFContMemWriteMask));

        if ( ! isMappable ) {
            // ----------------------------------------------------------------------------------
            // Mappable really means "fully expanded in container", so sections that are not mappable
            // need to be allocated.  The loader will do the initialization copying.  This is the
            // standard case for packed PEF data sections.
            needAlloc   = true;
            needCopy    = (! isPacked);
            needClear   = (section->totalLength != section->unpackedLength);

        } else if ( ! (section->access & kCFContMemWriteMask)  ) {
            // -----------------------------------------------------------------------------------
            // A "mappable" read only section.  Make sure it is fully present, i.e. no zero filled
            // extension.  This is the standard case for code and literal sections.
            if ( section->totalLength != section->unpackedLength ) {
                err = cfragFragmentUsageErr;        // !!! Needs error label & message.
//              goto ERROR;
            }
            needAlloc   = false;
            needCopy    = false;
            needClear   = false;

        } else {
            // -----------------------------------------------------------------------------------
            // A "mappable", writeable, don't use in place section.  This is the standard case for
            // unpacked data sections.
            needAlloc   = true;
            needCopy    = true;
            needClear   = (section->totalLength != section->unpackedLength);
        }

        if ( needAlloc ) {
            // *** Should honor the container's alignment specifications.
            sectionAddress = PCodeAllocateMem( section->totalLength ); //, 4, allocMode );
        } else {
            sectionAddress  = inst->pef + section->containerOffset;
        }

        // --------------------------------------------------------------------------------------
        // !!! The copy/clear code should be moved to the loader as part of the split of the
        // !!! unpack/relocate operations.  It isn't clear at this point if both the read and
        // !!! write sides should be touched.  What if the write side pushes out pages brought in
        // !!! by the read side?  We should also have better advice to say all bytes are changed.

        if ( needCopy ) {
            BytePtr     source  = inst->pef + section->containerOffset;
            BytePtr     dest    = sectionAddress;
            ByteCount   length  = section->unpackedLength;

            PCFM_BlockCopy ( source, dest, length );
        }

        if ( needClear ) {
            BytePtr     dest    = (BytePtr) sectionAddress + section->unpackedLength;
            ByteCount   length  = section->totalLength - section->unpackedLength;

            PCFM_BlockClear ( dest, length );
        }

        // -------------------------------------------------------------------------------------
        // If CFM was responsible for bringing the container into memory then we have to get the
        // I&D caches in sync for the (read-only & use-in-place) code sections.

	if ( (section->access & kCFContMemExecuteMask)
	  && (! (section->access & kCFContMemWriteMask)) && isMappable ) {
	    PCFM_MakeExecutable ( sectionAddress, section->unpackedLength );
	}

        err = PEF_SetSectionAddress( cRef, sectionIndex, sectionAddress, sectionAddress );
        if( err) LOG( "PEF_SetSectionAddress = %ld\n", err );

        sectionVars->address = sectionAddress;
        sectionVars->unpackedLength = section->unpackedLength;
        sectionVars->isPacked = isPacked;
	if( needAlloc)
            sectionVars->allocSize = section->totalLength;
	else
            sectionVars->allocSize = 0;
    }

    // -------------------------------------------------------------------------------------

    err = SatisfyImports( inst );
    if( err) LOG( "SatisfyImports = %ld\n", err );

    // -------------------------------------------------------------------------------------

    for( sectionIndex = 0; sectionIndex < numSects; sectionIndex++ )
    {
        SectionVars         *   sectionVars;

        sectionVars = inst->sections + sectionIndex;

	INFO("Section[%ld] ", sectionIndex );

        if ( sectionVars->isPacked ) {
	INFO("unpacking...");
            err = PEF_UnpackSection(        cRef,
                                            sectionIndex,
                                            0,  // Unpack the whole section.
                                            sectionVars->address,
                                            sectionVars->unpackedLength );
            if( err) LOG( "PEF_UnpackSection = %ld\n", err );
        }

	INFO("reloc...");
        err = PEF_RelocateSection( cRef, sectionIndex );

	INFO(" address = 0x%08lx\n", (UInt32) sectionVars->address );
    }

    if( err) LOG( "Instantiate = %ld\n", err );

    return( err);
}

struct StubFunction {
    LogicalAddress	pc;
    LogicalAddress	toc;
    char		name[64];
};
typedef struct StubFunction StubFunction;

OSStatus IONDRVUnimplementedVector( UInt32 p1, UInt32 p2, UInt32 p3, UInt32 p4 )
{
    char * name = (char *) get_R2();

    LOG("-*- %s : %lx, %lx, %lx, %lx\n", name, p1, p2, p3, p4);

    set_R2( (UInt32) name);

    return( -53);
}

static OSStatus
SatisfyImports( InstanceVars * inst )
{
    CFContImportedSymbolInfo        symInfo;

    OSStatus                        err = 0;
    CFContHandlerRef                cRef;
    ItemCount                       numLibs, numSyms, index, i;
    struct CFLibInfo {
        CFContImportedLibraryInfo   info;
        LibraryEntry            *   found;
    };
    struct CFLibInfo            *   libInfo;
    struct CFLibInfo            *   curLib;
    FunctionEntry               *   funcs;
    const IOTVector             *   symAddr;
    StubFunction		*   stub;

    cRef = inst->cRef;
    err = PEF_GetImportCounts( cRef, &numLibs, &numSyms );
    if( err) LOG( "PEF_GetImportCounts = %ld\n", err );

    libInfo = PCodeAllocateMem( numLibs * sizeof( struct CFLibInfo));
    PCFM_BlockClear( libInfo, numLibs * sizeof( struct CFLibInfo));

    for( index = 0; index < numLibs; index++ )
    {
        curLib = libInfo + index;
        err = PEF_GetImportedLibraryInfo( cRef, index, kCFContImportedLibraryInfoVersion, &curLib->info);
        if( err) LOG( "PEF_GetImportCounts = %ld\n", err );

        for( i = 0; i < IONumNDRVLibraries; i++ ) {
            if( strcmp( (char *) curLib->info.libraryName.nameText,
			IONDRVLibraries[ i ].name) == 0) {
                curLib->found = &IONDRVLibraries[ i ];
                break;
            }
        }
    }

    for( index = 0; index < numSyms; index++ )
    {
        err = PEF_GetImportedSymbolInfo( cRef, index, kCFContImportedSymbolInfoVersion, &symInfo );
        if( err) LOG( "PEF_GetImportedSymbolInfo = %ld\n", err );

        curLib = libInfo + symInfo.libraryIndex;

        symAddr = NULL;
        if( curLib->found) {
            for( i = 0; i < curLib->found->numSyms; i++ ) {

                funcs = curLib->found->functions + i;
                if( strcmp( (char *) symInfo.symbolName.nameText, funcs->name ) == 0) {
                    symAddr = (IOTVector *) &funcs->address;
                    break;
                }
            }

        } else if( inst->undefinedHandler)
            symAddr = (*inst->undefinedHandler)(inst->undefHandlerSelf, 
                                                curLib->info.libraryName.nameText,
                                                symInfo.symbolName.nameText );
	if( symAddr == NULL) {

	    LOG("Undefined %s:%s ", curLib->info.libraryName.nameText, symInfo.symbolName.nameText );

	    stub = IOMalloc( sizeof( StubFunction));
	    symAddr = (IOTVector *) &stub->pc;
	    stub->pc = IONDRVUnimplementedVector;
	    stub->toc = &stub->name[0];
	    strncpy( stub->name, symInfo.symbolName.nameText, 60);
	}

        err = PEF_SetImportedSymbolAddress( cRef, index, (IOTVector *) symAddr );
        if( err) LOG( "PEF_SetImportedSymbolAddress = %ld\n", err );
    }

    PCodeReleaseMem( libInfo);

    return( err);
}




