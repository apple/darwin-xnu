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


#ifndef __IONDRV__
#define __IONDRV__

#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOInterruptEventSource.h>

#include <IOKit/ndrvsupport/IOMacOSTypes.h>
#include <IOKit/ndrvsupport/IONDRVSupport.h>

#pragma options align=mac68k

#ifdef __cplusplus
extern "C" {
#endif

typedef void * RegEntryID[4];

struct DriverInitInfo {
    UInt16                          refNum;
    RegEntryID                      deviceEntry;
};

#define MAKE_REG_ENTRY(regEntryID,obj) 			\
	regEntryID[ 0 ] = (void *) obj;			\
	regEntryID[ 1 ] = (void *) ~(UInt32)obj;	\
	regEntryID[ 2 ] = (void *) 0x53696d65;		\
	regEntryID[ 3 ] = (void *) 0x52756c7a;

#define REG_ENTRY_TO_OBJ(regEntryID,obj) 				\
	if( (UInt32)((obj = ((IORegistryEntry **)regEntryID)[ 0 ])) 	\
	 != ~((UInt32 *)regEntryID)[ 1 ] )				\
	    return( -2538);

#define REG_ENTRY_TO_OBJ_RET(regEntryID,obj,ret) 			\
	if( (UInt32)((obj = ((IORegistryEntry **)regEntryID)[ 0 ])) 	\
	 != ~((UInt32 *)regEntryID)[ 1 ] )				\
	    return( ret);

#define REG_ENTRY_TO_PT(regEntryID,obj) 				\
	IORegistryEntry * obj;						\
	if( (UInt32)((obj = ((IORegistryEntry **)regEntryID)[ 0 ])) 	\
	 != ~((UInt32 *)regEntryID)[ 1 ] )				\
	    return( -2538);

#define REG_ENTRY_TO_SERVICE(regEntryID,type,obj) 			\
	IORegistryEntry * regEntry;					\
	type		* obj;						\
	if( (UInt32)((regEntry = ((IORegistryEntry **)regEntryID)[ 0 ])) \
	 != ~((UInt32 *)regEntryID)[ 1 ] )				\
	    return( -2538);						\
	if( 0 == (obj = OSDynamicCast( type, regEntry))) 		\
	    return( -2542);

struct CntrlParam {
    void *                          qLink;
    short                           qType;
    short                           ioTrap;
    void *                          ioCmdAddr;
    void *                          ioCompletion;
    short                           ioResult;
    char *                          ioNamePtr;
    short                           ioVRefNum;
    short                           ioCRefNum;
    short                           csCode;
    void *                          csParams;
    short                           csParam[9];
};
typedef struct CntrlParam CntrlParam, *CntrlParamPtr;

#pragma options align=reset

enum {
    kOpenCommand                = 0,
    kCloseCommand               = 1,
    kReadCommand                = 2,
    kWriteCommand               = 3,
    kControlCommand             = 4,
    kStatusCommand              = 5,
    kKillIOCommand              = 6,
    kInitializeCommand          = 7,                            /* init driver and device*/
    kFinalizeCommand            = 8,                            /* shutdown driver and device*/
    kReplaceCommand             = 9,                            /* replace an old driver*/
    kSupersededCommand          = 10                            /* prepare to be replaced by a new driver*/
};
enum {
    kSynchronousIOCommandKind   = 0x00000001,
    kAsynchronousIOCommandKind  = 0x00000002,
    kImmediateIOCommandKind     = 0x00000004
};


extern OSStatus    CallTVector( 
	    void * p1, void * p2, void * p3, void * p4, void * p5, void * p6,
	    struct IOTVector * entry );

#ifdef __cplusplus
}
#endif

class IONDRV : public OSObject
{
    OSDeclareDefaultStructors(IONDRV)

private:
    void * 			pcInst;
    struct IOTVector *		fDoDriverIO;
    struct DriverDescription *	theDriverDesc;

public:
    static IONDRV * instantiate( IORegistryEntry * regEntry,
                                 IOLogicalAddress container,
                                 IOByteCount containerSize,
                                 IONDRVUndefinedSymbolHandler handler,
                                 void * self );

    static IONDRV * fromRegistryEntry( IORegistryEntry * regEntry,
                                        IONDRVUndefinedSymbolHandler handler,
                                        void * self);

    virtual void free( void );

    virtual IOReturn getSymbol( const char * symbolName,
				IOLogicalAddress * address );

    virtual const char * driverName( void );

    virtual IOReturn doDriverIO( UInt32 commandID, void * contents,
				UInt32 commandCode, UInt32 commandKind );

};

struct IONDRVInterruptSource {
    void *		refCon;
    struct IOTVector *	handler;
    struct IOTVector *	enabler;
    struct IOTVector *	disabler;
    bool		registered;
    bool		enabled;
};

class IONDRVInterruptSet : public OSObject {

    OSDeclareDefaultStructors(IONDRVInterruptSet)

public:
    IOService *			provider;
    IOOptionBits		options;
    UInt32			count;
    IONDRVInterruptSource *	sources;
    IONDRVInterruptSet *	child;

    static IONDRVInterruptSet * with(IOService * provider,
                                    IOOptionBits options, SInt32 count);
    void free();
};

#endif /* __IONDRV__ */

