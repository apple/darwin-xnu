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
 * 30 Nov 98 sdouglas start cpp, from previous versions.
 */

#ifndef _IOKIT_IOFRAMEBUFFER_H
#define _IOKIT_IOFRAMEBUFFER_H

#include <IOKit/IOService.h>
#include <IOKit/graphics/IOGraphicsDevice.h>
#include <IOKit/graphics/IOFramebufferShared.h>
#include <IOKit/IOLib.h>

class IOFramebuffer;
class IOBufferMemoryDescriptor;

typedef void (*CursorBlitProc)(
                    IOFramebuffer * inst,
                    void * shmem,
                    volatile unsigned char *vramPtr,
                    unsigned int cursStart,
                    unsigned int vramRow,
                    unsigned int cursRow,
                    int width,
                    int height );

typedef void (*CursorRemoveProc)(
                    IOFramebuffer * inst,
                    void * shmem,
                    volatile unsigned char *vramPtr,
                    unsigned int vramRow,
                    int width,
                    int height );

enum {
   kTransparentEncoding 	= 0,
   kInvertingEncoding
};

enum {
   kTransparentEncodingShift	= (kTransparentEncoding << 1),
   kTransparentEncodedPixel	= (0x01 << kTransparentEncodingShift),

   kInvertingEncodingShift	= (kInvertingEncoding << 1),
   kInvertingEncodedPixel	= (0x01 << kInvertingEncodingShift),
};

enum {
   kHardwareCursorDescriptorMajorVersion	= 0x0001,
   kHardwareCursorDescriptorMinorVersion	= 0x0000
};

struct IOHardwareCursorDescriptor {
   UInt16		majorVersion;
   UInt16		minorVersion;
   UInt32		height;
   UInt32		width;
   UInt32		bitDepth;
   UInt32		maskBitDepth;
   UInt32		numColors;
   UInt32 *		colorEncodings;
   UInt32		flags;
   UInt32		supportedSpecialEncodings;
   UInt32		specialEncodings[16];
};
typedef struct IOHardwareCursorDescriptor IOHardwareCursorDescriptor;

enum {
   kHardwareCursorInfoMajorVersion		= 0x0001,
   kHardwareCursorInfoMinorVersion		= 0x0000
};

struct IOHardwareCursorInfo {
   UInt16		majorVersion;
   UInt16		minorVersion;
   UInt32		cursorHeight;
   UInt32		cursorWidth;
   // nil or big enough for hardware's max colors
   IOColorEntry *	colorMap;
   UInt8 *		hardwareCursorData;
   UInt32		reserved[6];
};
typedef struct IOHardwareCursorInfo IOHardwareCursorInfo;

// clock & data values
enum {
    kIODDCLow				= 0,
    kIODDCHigh				= 1,
    kIODDCTristate			= 2
};
// ddcBlockType constants
enum {
    // EDID block type.
    kIODDCBlockTypeEDID			= 0
};

// ddcFlags constants
enum {
    // Force a new read of the EDID.
    kIODDCForceRead			= 0x00000001,
};

enum {
    kDisabledInterruptState		= 0,
    kEnabledInterruptState		= 1
};

typedef void (*IOFBInterruptProc)( OSObject * target, void * ref );


typedef IOReturn (*IOFramebufferNotificationHandler)
	(OSObject * self, void * ref,
	IOFramebuffer * framebuffer, IOIndex event,
	void * info);

// IOFramebufferNotificationHandler events
enum {
    kIOFBNotifyDisplayModeWillChange	= 1,
    kIOFBNotifyDisplayModeDidChange,
    kIOFBNotifyWillSleep,
    kIOFBNotifyDidWake,
};


struct StdFBShmem_t;
class IOFramebufferUserClient;

class IOFramebuffer : public IOGraphicsDevice
{
    friend class IOFramebufferUserClient;
    friend class IOFramebufferSharedUserClient;
    friend class IOGraphicsEngineClient;

    OSDeclareDefaultStructors(IOFramebuffer)

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

private:

protected:
    StdFBShmem_t *			priv;
    int					shmemClientVersion;
    IOBufferMemoryDescriptor *		sharedCursor;

    union {
        struct {
            /* Mapping tables used in cursor drawing to 5-5-5 displays. */
            unsigned char *	_bm34To35SampleTable;
            unsigned char *	_bm35To34SampleTable;
            /* Mapping tables used in cursor drawing to 8-bit RGB displays. */
            unsigned int *	_bm256To38SampleTable;
            unsigned char *	_bm38To256SampleTable;
        } 				t;
        UInt8 *				tables[ 4 ];
    } 					colorConvert;
    
    /* cursor blitting vars */
    CursorBlitProc			cursorBlitProc;
    CursorRemoveProc			cursorRemoveProc;

    IOGSize				maxCursorSize;
    volatile unsigned char *		cursorImages[ kIOFBNumCursorFrames ];
    volatile unsigned char *		cursorMasks[ kIOFBNumCursorFrames ];
    volatile unsigned char *		cursorSave;
    unsigned int			white;

    Point				nextCursorLoc;
    int					nextCursorFrame;
    void *				vblInterrupt;
    semaphore_t				vblSemaphore;

    /* memory ranges */
    volatile unsigned char * 		frameBuffer;
    unsigned int			totalWidth;
    unsigned int			rowBytes;
    unsigned int			bytesPerPixel;

    IOMemoryMap *			vramMap;
    IOByteCount				vramMapOffset;
    OSArray *				userAccessRanges;
    OSArray *				engineAccessRanges;
    IOBufferMemoryDescriptor  * 	engineContext;
    OSSet *				fbNotifications;

    class IOFramebufferUserClient *		serverConnect;
    class IOFramebufferSharedUserClient *	sharedConnect;

    bool				opened;
    bool				closed;
    bool				clutValid;
    bool				currentMono;
    bool				needCursorService;
    bool				haveVBLService;
    bool				haveHWCursor;
    bool				hwCursorLoaded;

    void *				pmRef;

    /* Reserved for future expansion. */
    int 				_IOFramebuffer_reserved[7];

private:
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 0);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 1);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 2);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 3);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 4);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 5);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 6);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 7);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 8);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 9);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 10);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 11);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 12);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 13);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 14);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 15);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 16);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 17);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 18);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 19);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 20);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 21);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 22);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 23);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 24);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 25);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 26);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 27);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 28);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 29);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 30);
    OSMetaClassDeclareReservedUnused(IOFramebuffer, 31);


public:
    static void initialize();

    virtual IOReturn powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService* );
    virtual IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService* );
    virtual IOReturn setPowerState( unsigned long powerStateOrdinal, IOService * device);
    virtual IOReturn newUserClient( task_t		owningTask,
                                    void * 		security_id,
                                    UInt32  		type,
                                    IOUserClient **	handler );


    virtual void hideCursor( void );
    virtual void showCursor( Point * cursorLoc, int frame );
    virtual void moveCursor( Point * cursorLoc, int frame );
    // virtual
    void resetCursor( void );

    virtual void getVBLTime( AbsoluteTime * time, AbsoluteTime * delta );

    virtual void getBoundingRect ( Bounds ** bounds );

    virtual bool start( IOService * provider );

    virtual IOReturn open( void );
    
    virtual void close( void );

    virtual bool isConsoleDevice( void );

    virtual IOReturn setupForCurrentConfig( void );

    virtual bool serializeInfo( OSSerialize * s );
    virtual bool setNumber( OSDictionary * dict, const char * key,
				UInt32 number );

    IONotifier * addFramebufferNotification(
            IOFramebufferNotificationHandler handler,
            OSObject * self, void * ref);

    virtual IODeviceMemory * getApertureRange( IOPixelAperture aperture ) = 0;
    virtual IODeviceMemory * getVRAMRange( void );

protected:

    IOReturn deliverFramebufferNotification(
                    IOIndex event, void * info = 0 );

#ifdef IOFRAMEBUFFER_PRIVATE
#include <IOKit/graphics/IOFramebufferPrivate.h>
#endif

public:

    virtual IOReturn enableController( void );

    // List of pixel formats supported, null separated,
    //  doubly null terminated.
    virtual const char * getPixelFormats( void ) = 0;

    // Array of supported display modes
    virtual IOItemCount getDisplayModeCount( void ) = 0;
    virtual IOReturn getDisplayModes( IODisplayModeID * allDisplayModes ) = 0;

    // Info about a display mode
    virtual IOReturn getInformationForDisplayMode( IODisplayModeID displayMode,
                    IODisplayModeInformation * info ) = 0;

    // Mask of pixel formats available in mode and depth
    virtual UInt64  getPixelFormatsForDisplayMode( IODisplayModeID displayMode,
                    IOIndex depth ) = 0;

    virtual IOReturn getPixelInformation(
	IODisplayModeID displayMode, IOIndex depth,
	IOPixelAperture aperture, IOPixelInformation * pixelInfo ) = 0;

    // Framebuffer info

    // Current display mode and depth
    virtual IOReturn getCurrentDisplayMode( IODisplayModeID * displayMode,
                            IOIndex * depth ) = 0;

    // Set display mode and depth
    virtual IOReturn setDisplayMode( IODisplayModeID displayMode,
                            IOIndex depth );

    // For pages
    virtual IOReturn setApertureEnable( IOPixelAperture aperture,
		    IOOptionBits enable );

    // Display mode and depth for startup
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

    //// Controller attributes

    virtual IOReturn setAttribute( IOSelect attribute, UInt32 value );
    virtual IOReturn getAttribute( IOSelect attribute, UInt32 * value );

    //// Display mode timing information

    virtual IOReturn getTimingInfoForDisplayMode(
		IODisplayModeID displayMode, IOTimingInformation * info );

    //// Detailed timing information

    virtual IOReturn validateDetailedTiming(
                    void * description, IOByteCount descripSize );

    virtual IOReturn setDetailedTimings( OSArray * array );

    //// Connections

    virtual IOItemCount getConnectionCount( void );

    virtual IOReturn setAttributeForConnection( IOIndex connectIndex,
                    IOSelect attribute, UInt32 value );
    virtual IOReturn getAttributeForConnection( IOIndex connectIndex,
                    IOSelect attribute, UInt32  * value );

    //// HW Cursors

    virtual bool convertCursorImage( void * cursorImage,
		IOHardwareCursorDescriptor * description,
                IOHardwareCursorInfo * cursor );

    virtual IOReturn setCursorImage( void * cursorImage );
    virtual IOReturn setCursorState( SInt32 x, SInt32 y, bool visible );

    //// SW Cursors

    virtual void flushCursor( void );

    // Apple sensing

    virtual IOReturn getAppleSense( IOIndex connectIndex,
            UInt32 * senseType,
            UInt32 * primary,
            UInt32 * extended,
            UInt32 * displayType );

    virtual IOReturn connectFlags( IOIndex connectIndex,
                    IODisplayModeID displayMode, IOOptionBits * flags );

    //// IOLowLevelDDCSense

    virtual void setDDCClock( IOIndex connectIndex, UInt32 value );
    virtual void setDDCData( IOIndex connectIndex, UInt32 value );
    virtual bool readDDCClock( IOIndex connectIndex );
    virtual bool readDDCData( IOIndex connectIndex );
    virtual IOReturn enableDDCRaster( bool enable );

    //// IOHighLevelDDCSense

    virtual bool hasDDCConnect( IOIndex connectIndex );
    virtual IOReturn getDDCBlock( IOIndex connectIndex, UInt32 blockNumber,
                    IOSelect blockType, IOOptionBits options,
                    UInt8 * data, IOByteCount * length );

    //// Interrupts

    // This is driven in the opposite direction to ndrv's ie. the base class
    // registers a proc with the driver, and controls int generation with
    // setInterruptState. Clients ask for serviceType.

    virtual IOReturn registerForInterruptType( IOSelect interruptType,
            	    IOFBInterruptProc proc, OSObject * target, void * ref,
		    void ** interruptRef );
    virtual IOReturn unregisterInterrupt( void * interruptRef );
    virtual IOReturn setInterruptState( void * interruptRef, UInt32 state );

    virtual IOReturn getNotificationSemaphore( IOSelect interruptType,
                                               semaphore_t * semaphore );
};

#endif /* ! _IOKIT_IOFRAMEBUFFER_H */
