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
 * Copyright (c) 1997-1998 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * sdouglas  22 Oct 97 - first checked in.
 * sdouglas  24 Jul 98 - start IOKit.
 * sdouglas  15 Dec 98 - cpp.
 *
 */

#ifndef _IOKIT_IONDRVFRAMEBUFFER_H
#define _IOKIT_IONDRVFRAMEBUFFER_H

#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/ndrvsupport/IOMacOSVideo.h>
#include <IOKit/ndrvsupport/IONDRVSupport.h>


#define kIONDRVDisableKey	"AAPL,disable-ndrv"


class IONDRVFramebuffer : public IOFramebuffer
{
    OSDeclareDefaultStructors(IONDRVFramebuffer)

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

protected:

    IOService *			nub;
    class IONDRV *		ndrv;

    // current configuration
    IODisplayModeID		currentDisplayMode;
    IOIndex			currentDepth;
    IOIndex			currentPage;
    bool			directMode;

    IOPhysicalAddress		physicalFramebuffer;
    IODeviceMemory	*	vramRange;

    UInt8			startAt8;
    UInt8			grayMode;
    UInt8			lastGrayMode;
    VDClutBehavior		lastClutSetting;
    UInt8			platformDeepSleep;

    bool			consoleDevice;
    UInt32			powerState;
    UInt32			ndrvState;
    SInt32			ndrvEnter;
    OSArray *			detailedTimings;
    UInt32			detailedTimingsSeed;
    UInt32 *			detailedTimingsCurrent;

    IODeviceMemory *		vramMemory;

    VDResolutionInfoRec		cachedVDResolution;

    struct _VSLService *	vslServices;

    UInt32			accessFlags;
    UInt8			shouldDoI2CPower;

    UInt8			__reservedB[3];
    UInt32			__reservedA[31];

private:
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 0);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 1);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 2);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 3);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 4);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 5);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 6);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 7);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 8);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 9);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 10);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 11);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 12);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 13);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 14);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 15);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 16);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 17);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 18);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 19);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 20);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 21);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 22);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 23);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 24);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 25);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 26);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 27);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 28);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 29);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 30);
    OSMetaClassDeclareReservedUnused(IONDRVFramebuffer, 31);

private:

    void initForPM ( void );
    IOReturn setPowerState( unsigned long, IOService* );
    unsigned long maxCapabilityForDomainState( IOPMPowerFlags );
    unsigned long initialPowerStateForDomainState( IOPMPowerFlags );
    unsigned long powerStateForDomainState( IOPMPowerFlags );

    virtual IOReturn checkDriver( void );
    virtual UInt32 iterateAllModes( IODisplayModeID * displayModeIDs );
    virtual IOReturn getResInfoForMode( IODisplayModeID modeID,
                                    IODisplayModeInformation * theInfo );
    virtual IOReturn getResInfoForArbMode( IODisplayModeID modeID,
                                    IODisplayModeInformation * theInfo );
    virtual IOReturn validateDisplayMode(
            IODisplayModeID mode, IOOptionBits flags,
            VDDetailedTimingRec ** detailed );
    virtual IOReturn setDetailedTiming(
            IODisplayModeID mode, IOOptionBits options,
            void * description, IOByteCount descripSize );
    virtual void getCurrentConfiguration( void );
    static const IOTVector * _undefinedSymbolHandler( void * self, 
                            const char * libraryName, const char * symbolName );
    void displayI2CPower( bool enable );

public:
    virtual IOReturn doControl( UInt32 code, void * params );
    virtual IOReturn doStatus( UInt32 code, void * params );

public:

    virtual IOService * probe(	IOService * 	provider,
				SInt32 *	score );

    virtual bool start( IOService * provider );

    virtual void free( void );

    virtual IOReturn setProperties( OSObject * properties );

    virtual IOReturn enableController( void );

    virtual IODeviceMemory * makeSubRange( IOPhysicalAddress start,
                                           IOPhysicalLength length );
    virtual IODeviceMemory * getApertureRange( IOPixelAperture aperture );
    virtual IODeviceMemory * getVRAMRange( void );

    virtual IODeviceMemory * findVRAM( void );

    virtual bool isConsoleDevice( void );

    virtual const IOTVector * undefinedSymbolHandler( const char * libraryName,
                                                      const char * symbolName );

    virtual const char * getPixelFormats( void );

    // Array of supported display modes
    virtual IOItemCount getDisplayModeCount( void );
    virtual IOReturn getDisplayModes( IODisplayModeID * allDisplayModes );

    // Info about a display mode
    virtual IOReturn getInformationForDisplayMode( IODisplayModeID displayMode,
                    IODisplayModeInformation * info );

    // Mask of pixel formats available in mode and depth
    virtual UInt64  getPixelFormatsForDisplayMode( IODisplayModeID displayMode,
                    IOIndex depth );

    virtual IOReturn getPixelInformation(
	IODisplayModeID displayMode, IOIndex depth,
	IOPixelAperture aperture, IOPixelInformation * pixelInfo );

    // Framebuffer info

    // Current display mode and depth
    virtual IOReturn getCurrentDisplayMode( IODisplayModeID * displayMode,
                            IOIndex * depth );

    // Set display mode and depth
    virtual IOReturn setDisplayMode( IODisplayModeID displayMode,
                            IOIndex depth );

    // For pages
    virtual IOReturn setApertureEnable( IOPixelAperture aperture,
		    IOOptionBits enable );

    virtual IOReturn setStartupDisplayMode( IODisplayModeID displayMode,
                            IOIndex depth );
    virtual IOReturn getStartupDisplayMode( IODisplayModeID * displayMode,
                            IOIndex * depth );

    //// CLUTs

    virtual IOReturn setCLUTWithEntries( IOColorEntry * colors, UInt32 index,
                UInt32 numEntries, IOOptionBits options );

    //// Gamma

    virtual IOReturn setGammaTable( UInt32 channelCount, UInt32 dataCount,
                    UInt32 dataWidth, void * data );

    //// Display mode timing information

    virtual IOReturn getTimingInfoForDisplayMode( IODisplayModeID displayMode,
                IOTimingInformation * info );

    //// Detailed timing information

    virtual IOReturn validateDetailedTiming(
                    void * description, IOByteCount descripSize );

    virtual IOReturn setDetailedTimings( OSArray * array );

    //// Controller attributes

    virtual IOReturn getAttribute( IOSelect attribute, UInt32 * value );

    //// Connections

    virtual IOItemCount getConnectionCount( void );

    virtual IOReturn getAttributeForConnection( IOIndex connectIndex,
                    IOSelect attribute, UInt32  * value );
    
    virtual IOReturn setAttributeForConnection( IOIndex connectIndex,
                    IOSelect attribute, UInt32  info );

    // Apple sensing

    virtual IOReturn getAppleSense( IOIndex connectIndex,
            UInt32 * senseType,
            UInt32 * primary,
            UInt32 * extended,
            UInt32 * displayType );

    virtual IOReturn connectFlags( IOIndex connectIndex,
                    IODisplayModeID displayMode, IOOptionBits * flags );

    //// IOHighLevelDDCSense

    virtual bool hasDDCConnect( IOIndex connectIndex );
    virtual IOReturn getDDCBlock( IOIndex connectIndex, UInt32 blockNumber,
                    IOSelect blockType, IOOptionBits options,
                    UInt8 * data, IOByteCount * length );

    //// Interrupts

    virtual IOReturn registerForInterruptType( IOSelect interruptType,
            	        IOFBInterruptProc proc, OSObject * target, void * ref,
			void ** interruptRef );
    virtual IOReturn unregisterInterrupt( void * interruptRef );
    virtual IOReturn setInterruptState( void * interruptRef, UInt32 state );

    //// HW Cursors

    virtual IOReturn setCursorImage( void * cursorImage );
    virtual IOReturn setCursorState( SInt32 x, SInt32 y, bool visible );

    //// VSL calls

    static OSStatus VSLNewInterruptService(
                            void * entryID,
                            UInt32 serviceType,
                            _VSLService ** serviceID );
    static OSStatus VSLDisposeInterruptService( _VSLService * serviceID );
    static OSStatus VSLDoInterruptService( _VSLService * serviceID );
    static Boolean  VSLPrepareCursorForHardwareCursor(
                            void * cursorRef,
                            IOHardwareCursorDescriptor * hwDesc,
                            IOHardwareCursorInfo * hwCursorInfo );
};

#endif /* ! _IOKIT_IONDRVFRAMEBUFFER_H */


