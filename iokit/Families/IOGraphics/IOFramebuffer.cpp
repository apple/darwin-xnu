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
 * 01 Sep 92	Portions from Joe Pasqua, Created. 
 */


#include <IOKit/IOLib.h>
#include <libkern/c++/OSContainers.h>

#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#define IOFRAMEBUFFER_PRIVATE
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/graphics/IODisplay.h>

#include "IOFramebufferUserClient.h"
#include "IODisplayWrangler.h"
#include "IOFramebufferReallyPrivate.h"
#include <IOKit/pwr_mgt/RootDomain.h>

#include <string.h>
#include <IOKit/assert.h>
#include <sys/kdebug.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOGraphicsDevice

OSDefineMetaClass( IOFramebuffer, IOGraphicsDevice )
OSDefineAbstractStructors( IOFramebuffer, IOGraphicsDevice )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define	GetShmem(instance)	((StdFBShmem_t *)(instance->priv))

#define CLEARSEMA(shmem)	ev_unlock(&shmem->cursorSema)
#define SETSEMA(shmem)		\
        if (!ev_try_lock(&shmem->cursorSema)) return;
#define TOUCHBOUNDS(one, two) \
        (((one.minx < two.maxx) && (two.minx < one.maxx)) && \
        ((one.miny < two.maxy) && (two.miny < one.maxy)))

/*
 * Cursor rendering
 */

#include "IOCursorBlits.h"

inline void IOFramebuffer::StdFBDisplayCursor( IOFramebuffer * inst )
{
    StdFBShmem_t *shmem;
    Bounds saveRect;
    volatile unsigned char *vramPtr;	/* screen data pointer */
    unsigned int cursStart;
    unsigned int cursorWidth;
    int width;
    int height;

    shmem = GetShmem(inst);
    saveRect = shmem->cursorRect;
    /* Clip saveRect vertical within screen bounds */
    if (saveRect.miny < shmem->screenBounds.miny)
        saveRect.miny = shmem->screenBounds.miny;
    if (saveRect.maxy > shmem->screenBounds.maxy)
        saveRect.maxy = shmem->screenBounds.maxy;
    if (saveRect.minx < shmem->screenBounds.minx)
        saveRect.minx = shmem->screenBounds.minx;
    if (saveRect.maxx > shmem->screenBounds.maxx)
        saveRect.maxx = shmem->screenBounds.maxx;
    shmem->saveRect = saveRect; /* Remember save rect for RemoveCursor */

    vramPtr = inst->frameBuffer +
        (inst->rowBytes * (saveRect.miny - shmem->screenBounds.miny)) +
        (inst->bytesPerPixel * (saveRect.minx - shmem->screenBounds.minx));

    width = saveRect.maxx - saveRect.minx;
    height = saveRect.maxy - saveRect.miny;
    cursorWidth = shmem->cursorSize[shmem->frame].width;

    cursStart = (saveRect.miny - shmem->cursorRect.miny) * cursorWidth +
                (saveRect.minx - shmem->cursorRect.minx);

    if( inst->cursorBlitProc)
        inst->cursorBlitProc( inst,
		    (void *) shmem,
                    vramPtr,
                    cursStart,
                    inst->totalWidth - width,   /* vramRow */
                    cursorWidth - width,	/* cursRow */
                    width,
                    height);
}

// Description:	RemoveCursor erases the cursor by replacing the background
//		image that was saved by the previous call to DisplayCursor.
//		If the frame buffer is cacheable, flush at the end of the
//		drawing operation.

inline void IOFramebuffer::StdFBRemoveCursor( IOFramebuffer * inst )
{
    StdFBShmem_t *shmem;
    volatile unsigned char *vramPtr;	/* screen data pointer */
    unsigned int vramRow;
    int width;
    int height;

    shmem = GetShmem(inst);
        
    vramRow = inst->totalWidth;	/* Scanline width in pixels */

    vramPtr = inst->frameBuffer +
        (inst->rowBytes * (shmem->saveRect.miny - shmem->screenBounds.miny))
	+ (inst->bytesPerPixel *
		(shmem->saveRect.minx - shmem->screenBounds.minx));

    width = shmem->saveRect.maxx - shmem->saveRect.minx;
    height = shmem->saveRect.maxy - shmem->saveRect.miny;
    vramRow -= width;

    if( inst->cursorRemoveProc)
        inst->cursorRemoveProc( inst, (void *)shmem,
				vramPtr, vramRow, width, height);
}

inline void IOFramebuffer::RemoveCursor( IOFramebuffer * inst )
{
    StdFBShmem_t *	shmem = GetShmem(inst);

    if( shmem->hardwareCursorActive ) {
        Point *		hs;

        hs = &shmem->hotSpot[shmem->frame];
	inst->setCursorState(
		shmem->cursorLoc.x - hs->x - shmem->screenBounds.minx,
		shmem->cursorLoc.y - hs->y - shmem->screenBounds.miny, false );
    } else
        StdFBRemoveCursor(inst);
}

inline void IOFramebuffer::DisplayCursor( IOFramebuffer * inst )
{
    Point 	 *	hs;
    StdFBShmem_t *	shmem = GetShmem(inst);
    SInt32		x, y;

    hs = &shmem->hotSpot[shmem->frame];
    x  = shmem->cursorLoc.x - hs->x;
    y  = shmem->cursorLoc.y - hs->y;

    if( shmem->hardwareCursorActive )
	inst->setCursorState( x - shmem->screenBounds.minx,
				y - shmem->screenBounds.miny, true );
    else {
        shmem->cursorRect.maxx = (shmem->cursorRect.minx = x)
		+ shmem->cursorSize[shmem->frame].width;
        shmem->cursorRect.maxy = (shmem->cursorRect.miny = y)
		+ shmem->cursorSize[shmem->frame].height;
        StdFBDisplayCursor(inst);
        shmem->oldCursorRect = shmem->cursorRect;
    }
}

inline void IOFramebuffer::SysHideCursor( IOFramebuffer * inst )
{
    if (!GetShmem(inst)->cursorShow++)
	RemoveCursor(inst);
}

inline void IOFramebuffer::SysShowCursor( IOFramebuffer * inst )
{
    StdFBShmem_t *shmem;
    
    shmem = GetShmem(inst);

    if (shmem->cursorShow)
	if (!--(shmem->cursorShow))
	    DisplayCursor(inst);
}

inline void IOFramebuffer::CheckShield( IOFramebuffer * inst )
{
    Point *		hs;
    int 		intersect;
    Bounds 		tempRect;
    StdFBShmem_t *	shmem = GetShmem(inst);
    
    /* Calculate temp cursorRect */
    hs = &shmem->hotSpot[shmem->frame];
    tempRect.maxx = (tempRect.minx = (shmem->cursorLoc).x - hs->x)
				   + shmem->cursorSize[shmem->frame].width;
    tempRect.maxy = (tempRect.miny = (shmem->cursorLoc).y - hs->y)
				   + shmem->cursorSize[shmem->frame].height;

    intersect = TOUCHBOUNDS(tempRect, shmem->shieldRect);
    if (intersect != shmem->shielded)
	(shmem->shielded = intersect) ?
	    SysHideCursor(inst) : SysShowCursor(inst);
}

/**
 ** external methods
 **/

void IOFramebuffer::setupCursor( IOPixelInformation * info )
{
    StdFBShmem_t *		shmem	= GetShmem(this);
    volatile unsigned char *	bits;
    IOByteCount			cursorImageBytes;

    rowBytes = info->bytesPerRow;
    totalWidth = (rowBytes * 8) / info->bitsPerPixel;
    bytesPerPixel = info->bitsPerPixel / 8;
    frameBuffer = (volatile unsigned char *) vramMap->getVirtualAddress();

    if( shmem) {
        if( (shmem->screenBounds.maxx == shmem->screenBounds.minx)
         || (shmem->screenBounds.maxy == shmem->screenBounds.miny)) {
            // a default if no one calls IOFBSetBounds()
            shmem->screenBounds.minx = 0;
            shmem->screenBounds.miny = 0;
            shmem->screenBounds.maxx = info->activeWidth;
            shmem->screenBounds.maxy = info->activeHeight;
        }

        cursorImageBytes = maxCursorSize.width * maxCursorSize.height
                            * bytesPerPixel;
        bits = shmem->cursor;
        for( int i = 0; i < kIOFBNumCursorFrames; i++ ) {
            cursorImages[i] = bits;
            bits += cursorImageBytes;
	    shmem->cursorSize[i] = maxCursorSize;
        }
        if( info->bitsPerPixel <= 8) {
            for( int i = 0; i < kIOFBNumCursorFrames; i++ ) {
                cursorMasks[i] = bits;
                bits += cursorImageBytes;
            }
        }
        cursorSave = bits;
    }

    switch( info->bitsPerPixel) {
        case 8:
            if( colorConvert.t._bm256To38SampleTable
             && colorConvert.t._bm38To256SampleTable) {
                cursorBlitProc = (CursorBlitProc) StdFBDisplayCursor8P;
                cursorRemoveProc = (CursorRemoveProc) StdFBRemoveCursor8;
            }
            break;
        case 16:
            if( colorConvert.t._bm34To35SampleTable
             && colorConvert.t._bm35To34SampleTable) {
                cursorBlitProc = (CursorBlitProc) StdFBDisplayCursor555;
                cursorRemoveProc = (CursorRemoveProc) StdFBRemoveCursor16;
            }
            break;
        case 32:
            if( colorConvert.t._bm256To38SampleTable
             && colorConvert.t._bm38To256SampleTable) {
                cursorBlitProc = (CursorBlitProc) StdFBDisplayCursor32Axxx;
                cursorRemoveProc = (CursorRemoveProc) StdFBRemoveCursor32;
            }
            break;
        default:
            IOLog("%s: can't do cursor at depth %ld\n",
		getName(), info->bitsPerPixel);
            cursorBlitProc = (CursorBlitProc) NULL;
            cursorRemoveProc = (CursorRemoveProc) NULL;
            break;
    }
}

void IOFramebuffer::stopCursor( void )
{
    cursorBlitProc = (CursorBlitProc) NULL;
    cursorRemoveProc = (CursorRemoveProc) NULL;
}

IOReturn IOFramebuffer::createSharedCursor(
		int shmemVersion, int maxWidth, int maxHeight )
{
    StdFBShmem_t *		shmem;
    IOByteCount			size, maxImageSize;

    kprintf("createSharedCursor vers = %d, %d x %d\n",
	shmemVersion, maxWidth, maxHeight);

    if( shmemVersion != kIOFBCurrentShmemVersion)
	return( kIOReturnUnsupported);

    shmemClientVersion = shmemVersion;
    maxImageSize = (maxWidth * maxHeight * kIOFBMaxCursorDepth) / 8;

    size = sizeof( StdFBShmem_t)
	 + ((kIOFBNumCursorFrames + 1) * maxImageSize);

    if( !sharedCursor || (size != sharedCursor->getLength())) {
        IOBufferMemoryDescriptor * newDesc;

        priv = 0;
        newDesc = IOBufferMemoryDescriptor::withOptions(
                kIODirectionNone | kIOMemoryKernelUserShared, size );
        if( !newDesc)
            return( kIOReturnNoMemory );
    
        if( sharedCursor)
            sharedCursor->release();
        sharedCursor = newDesc;
    }
    shmem = (StdFBShmem_t *) sharedCursor->getBytesNoCopy();
    priv = shmem;

    // Init shared memory area
    bzero( shmem, size );
    shmem->version = kIOFBCurrentShmemVersion;
    shmem->structSize = size;
    shmem->cursorShow = 1;
    shmem->hardwareCursorCapable = haveHWCursor;

    maxCursorSize.width = maxWidth;
    maxCursorSize.height = maxHeight;

    doSetup( false );

    return( kIOReturnSuccess);
}

IOReturn IOFramebuffer::setBoundingRect( Bounds * bounds )
{
    StdFBShmem_t *shmem;

    shmem = GetShmem(this);
    if( NULL == shmem)
	return( kIOReturnUnsupported);

    shmem->screenBounds = *bounds;

    return( kIOReturnSuccess);
}

/**
 ** IOUserClient methods
 **/

IOReturn IOFramebuffer::newUserClient(  task_t		owningTask,
                                        void * 		security_id,
                                        UInt32  	type,
                                        IOUserClient **	handler )

{
#if 0
    static UInt8 data[] = { 0x00, 0x03, 0x04, 0x07, 0x08, 0x0b, 0x0c, 0x0f,
                            0x10, 0x13, 0x14, 0x17, 0x18, 0x1b, 0x1c, 0x1f,

			    0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03,
			    0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07,
			    0x08, 0x08, 0x09, 0x09, 0x0a, 0x0a, 0x0b, 0x0b,
			    0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f };
    colorConvert.t._bm34To35SampleTable = data;
    colorConvert.t._bm35To34SampleTable = data + 16;
#endif

    IOReturn		err = kIOReturnSuccess;
    IOUserClient *	newConnect = 0;
    IOUserClient *	theConnect = 0;

    switch( type ) {

        case kIOFBServerConnectType:
            if( serverConnect)
                err = kIOReturnExclusiveAccess;
            else {

                if( isConsoleDevice())
                    getPlatform()->setConsoleInfo( 0, kPEReleaseScreen);

		err = IODisplayWrangler::clientStart( this );
		if( kIOReturnSuccess == err)
                    newConnect = IOFramebufferUserClient::withTask(owningTask);
	    }
	    break;

        case kIOFBSharedConnectType:
            if( sharedConnect) {
                theConnect = sharedConnect;
                theConnect->retain();
            } else if( serverConnect)
                newConnect = IOFramebufferSharedUserClient::withTask(owningTask);
            else
                err = kIOReturnNotOpen;
	    break;

        case kIOFBEngineControllerConnectType:
        case kIOFBEngineConnectType:
            newConnect = IOGraphicsEngineClient::withTask(owningTask);
	    break;

	default:
	    err = kIOReturnBadArgument;
    }

    if( newConnect) {
	if( (false == newConnect->attach( this ))
         || (false == newConnect->start( this ))) {
            newConnect->detach( this );
            newConnect->release();
        } else
            theConnect = newConnect;
    }

    *handler = theConnect;
    return( err );
}

IOReturn IOFramebuffer::extGetDisplayModeCount( IOItemCount * count )
{
    *count = getDisplayModeCount();
    return( kIOReturnSuccess);
}

IOReturn IOFramebuffer::extGetDisplayModes( IODisplayModeID * allModes, IOByteCount * size )
{
    IOReturn		err;
    IOByteCount		outSize;

    outSize = getDisplayModeCount() * sizeof( IODisplayModeID);

    if( *size < outSize)
	return( kIOReturnBadArgument);

    *size = outSize;
    err = getDisplayModes( allModes );

    return( err);
}

IOReturn IOFramebuffer::extGetVRAMMapOffset( IOPixelAperture /* aperture */, 
					IOByteCount * offset )
{
    *offset = vramMapOffset;

    return( kIOReturnSuccess );
}

IOReturn IOFramebuffer::extSetBounds( Bounds * bounds )
{
    StdFBShmem_t *shmem;

    shmem = GetShmem(this);
    if( shmem)
        shmem->screenBounds = *bounds;

    return( kIOReturnSuccess );
}

IOReturn IOFramebuffer::extValidateDetailedTiming(
                void * description, void * outDescription,
                IOByteCount inSize, IOByteCount * outSize )
{
    IOReturn	err;

    if( *outSize != inSize)
        return( kIOReturnBadArgument );

    err = validateDetailedTiming( description, inSize );

    if( kIOReturnSuccess == err)
        bcopy( description, outDescription, inSize );

    return( err );
}


IOReturn IOFramebuffer::extSetColorConvertTable( UInt32 select,
                                                 UInt8 * data, IOByteCount length )
{
    static const IOByteCount checkLength[] = {
        16 * sizeof( UInt8),
        32 * sizeof( UInt8),
        256 * sizeof( UInt32),
        5 * 256 * sizeof( UInt8) };

    UInt8 *		table;
    IODisplayModeID	mode;
    IOIndex		depth;
    IOPixelInformation	info;

    if( select > 3)
        return( kIOReturnBadArgument );

    if( length != checkLength[select])
        return( kIOReturnBadArgument );

    table = colorConvert.tables[select];
    if( 0 == table) {
        table = (UInt8 *) IOMalloc( length );
        colorConvert.tables[select] = table;
    }
    if( !table)
        return( kIOReturnNoMemory );

    bcopy( data, table, length );
    if( select == 3)
        white = data[data[255] + data[511] + data[767] + 1024];

    if( (NULL == cursorBlitProc)
      && colorConvert.tables[0] && colorConvert.tables[1]
      && colorConvert.tables[2] && colorConvert.tables[3]
      && vramMap
      && (kIOReturnSuccess == getCurrentDisplayMode( &mode, &depth ))
      && (kIOReturnSuccess == getPixelInformation( mode, depth, kIOFBSystemAperture, &info )))
        setupCursor( &info );

    return( kIOReturnSuccess );
}

IOReturn IOFramebuffer::extSetCLUTWithEntries( UInt32 index, IOOptionBits options,
                                        IOColorEntry * colors, IOByteCount inputCount )
{
    IOReturn	kr;

    kr = setCLUTWithEntries( colors, index,
                            inputCount / sizeof( IOColorEntry),
                            options );

    return( kr );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

//
// BEGIN:	Implementation of the evScreen protocol
//

void IOFramebuffer::hideCursor( void )
{
    StdFBShmem_t *shmem = GetShmem(this);

    SETSEMA(shmem);
    SysHideCursor(this);
    CLEARSEMA(shmem);
}

#if 0
void IOFramebuffer::free()
{
    if( vblSemaphore)
        semaphore_destroy(kernel_task, vblSemaphore);
    super::free();
}
#endif

void IOFramebuffer::deferredMoveCursor( IOFramebuffer * inst )
{
    StdFBShmem_t *	shmem = GetShmem(inst);
    IOReturn		err = kIOReturnSuccess;

    if( shmem->hardwareCursorActive && (0 == shmem->frame) ) {

        if (shmem->cursorObscured) {
            shmem->cursorObscured = 0;
            if (shmem->cursorShow)
                --shmem->cursorShow;
        }
	if (!shmem->cursorShow) {
            Point * hs;
            hs = &shmem->hotSpot[shmem->frame];
            err = inst->setCursorState(
		shmem->cursorLoc.x - hs->x - shmem->screenBounds.minx,
		shmem->cursorLoc.y - hs->y - shmem->screenBounds.miny, true );
	}

    } else {

        if (!shmem->cursorShow++)
            RemoveCursor(inst);
        if (shmem->cursorObscured) {
            shmem->cursorObscured = 0;
            if (shmem->cursorShow)
                --shmem->cursorShow;
        }
        if (shmem->shieldFlag) CheckShield(inst);
        if (shmem->cursorShow)
            if (!--shmem->cursorShow)
                DisplayCursor(inst);

	inst->flushCursor();
    }
    inst->needCursorService = (kIOReturnBusy == err);
}

void IOFramebuffer::moveCursor( Point * cursorLoc, int frame )
{
    nextCursorLoc = *cursorLoc;
    nextCursorFrame = frame;
    needCursorService  = true;

    StdFBShmem_t *shmem = GetShmem(this);

    SETSEMA(shmem);

    if( !haveVBLService) {
        shmem->cursorLoc = *cursorLoc;
        shmem->frame = frame;
        deferredMoveCursor( this );
    }

    CLEARSEMA(shmem);
}

void IOFramebuffer::handleVBL( IOFramebuffer * inst, void * ref )
{
    StdFBShmem_t *	shmem = GetShmem(inst);
    AbsoluteTime	now;

    if( !shmem)
        return;

    clock_get_uptime( &now );
    shmem->vblDelta = now;
    SUB_ABSOLUTETIME( &shmem->vblDelta, &shmem->vblTime );
    shmem->vblTime = now;

    KERNEL_DEBUG(0xc000030 | DBG_FUNC_NONE,
        shmem->vblDelta.hi, shmem->vblDelta.lo, 0, 0, 0);

    if( inst->vblSemaphore)
        semaphore_signal_all(inst->vblSemaphore);
    
    SETSEMA(shmem);

    if( inst->needCursorService) {
        shmem->cursorLoc = inst->nextCursorLoc;
        shmem->frame = inst->nextCursorFrame;
        deferredMoveCursor( inst );
    }

    CLEARSEMA(shmem);
}

void IOFramebuffer::showCursor( Point * cursorLoc, int frame )
{
    StdFBShmem_t *shmem;
    
    shmem = GetShmem(this);
    SETSEMA(shmem);
    shmem->frame = frame;
    shmem->hardwareCursorActive = hwCursorLoaded && (frame == 0);
    shmem->cursorLoc = *cursorLoc;
    if (shmem->shieldFlag) CheckShield(this);
    SysShowCursor(this);
    CLEARSEMA(shmem);
}

void IOFramebuffer::resetCursor( void )
{
    StdFBShmem_t *shmem;
    
    shmem = GetShmem(this);
    hwCursorLoaded = false;
    if( !shmem)
        return;
    hideCursor();
    shmem->hardwareCursorActive = false;
    showCursor( &shmem->cursorLoc, shmem->frame );
}

void IOFramebuffer::getVBLTime( AbsoluteTime * time, AbsoluteTime * delta ) 
{
    StdFBShmem_t *shmem;

    shmem = GetShmem(this);
    if( shmem) {
        *time = shmem->vblTime;
        *delta = shmem->vblDelta;
    } else
        time->hi = time->lo = 0;
}

void IOFramebuffer::getBoundingRect( Bounds ** bounds )
{
    StdFBShmem_t *shmem;

    shmem = GetShmem(this);
    if( NULL == shmem)
        *bounds = NULL;
    else
        *bounds = &shmem->screenBounds;
}

//
// END:		Implementation of the evScreen protocol
//

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOFramebuffer::getNotificationSemaphore(
                                  IOSelect interruptType, semaphore_t * semaphore )
{
    kern_return_t	kr;
    semaphore_t		sema;

    if( interruptType != kIOFBVBLInterruptType)
        return( kIOReturnUnsupported );

    if( !haveVBLService)
        return( kIOReturnNoResources );

    if( MACH_PORT_NULL == vblSemaphore) {
        kr = semaphore_create(kernel_task, &sema, SYNC_POLICY_FIFO, 0);
        if( kr == KERN_SUCCESS)
            vblSemaphore = sema;
    } else
        kr = KERN_SUCCESS;

    if( kr == KERN_SUCCESS)
        *semaphore = vblSemaphore;

    return( kr );
}

IOReturn IOFramebuffer::extSetCursorVisible( bool visible )
{
    IOReturn		err;
    Point *		hs;
    StdFBShmem_t *	shmem = GetShmem(this);

    if( shmem->hardwareCursorActive ) {
        hs = &shmem->hotSpot[shmem->frame];
	err = setCursorState(
		shmem->cursorLoc.x - hs->x - shmem->screenBounds.minx,
		shmem->cursorLoc.y - hs->y - shmem->screenBounds.miny,
		visible );
    } else
	err = kIOReturnBadArgument;

    return( err );
}

IOReturn IOFramebuffer::extSetCursorPosition( SInt32 x, SInt32 y )
{
    return( kIOReturnUnsupported );
}

IOReturn IOFramebuffer::extSetNewCursor( void * cursor, IOIndex frame,
					IOOptionBits options )
{
    StdFBShmem_t *	shmem = GetShmem(this);
    IOReturn		err;

    if( cursor || options || frame)
	err = kIOReturnBadArgument;
    else {

	if( (shmem->cursorSize[frame].width > maxCursorSize.width)
	 || (shmem->cursorSize[frame].height > maxCursorSize.height))
            err = kIOReturnBadArgument;

	else if( haveHWCursor)
            err = setCursorImage( (void *) frame );
        else
            err = kIOReturnUnsupported;
    }

    hwCursorLoaded = (kIOReturnSuccess == err);
    shmem->hardwareCursorActive = hwCursorLoaded && (shmem->frame == 0);
    
    return( err );
}

bool IOFramebuffer::convertCursorImage( void * cursorImage,
                                    IOHardwareCursorDescriptor * hwDesc,
                                    IOHardwareCursorInfo * hwCursorInfo )
{
    StdFBShmem_t *		shmem = GetShmem(this);
    UInt8 *			dataOut = hwCursorInfo->hardwareCursorData;
    IOColorEntry *		clut = hwCursorInfo->colorMap;
    UInt32			maxColors = hwDesc->numColors;
    int				frame = (int) cursorImage;

    volatile unsigned short *	cursPtr16;
    volatile unsigned int *	cursPtr32;
    SInt32 			x, y;
    UInt32			index, numColors = 0;
    UInt16			alpha, red, green, blue;
    UInt16			s16;
    UInt32			s32;
    UInt8			data = 0;
    UInt8			pixel = 0;
    bool			ok = true;

    assert( frame < kIOFBNumCursorFrames );

    if( bytesPerPixel == 4) {
        cursPtr32 = (volatile unsigned int *) cursorImages[ frame ];
        cursPtr16 = 0;
    } else if( bytesPerPixel == 2) {
        cursPtr32 = 0;
        cursPtr16 = (volatile unsigned short *) cursorImages[ frame ];
    } else
	return( false );

    x = shmem->cursorSize[frame].width;
    y = shmem->cursorSize[frame].height;

    if( (x > (SInt32) hwDesc->width) || (y > (SInt32) hwDesc->height))
	return( false );
#if 0
    hwCursorInfo->cursorWidth = x;
    hwCursorInfo->cursorHeight = y;
    while( (--y != -1) ) {
        x = shmem->cursorSize[frame].width;
        while( (--x != -1) ) {

	    if( cursPtr32) {
		s32 = *(cursPtr32++);
		alpha = (s32 >> 28) & 0xf;
                if( alpha && (alpha != 0xf))
                    *(cursPtr32 - 1) = 0x00ffffff;

	    } else {
		s16 = *(cursPtr16++);
		alpha = s16 & 0x000F;
                if( alpha && (alpha != 0xf))
                    *(cursPtr16 - 1) = 0xfff0;
            }
        }
    }
#endif

    hwCursorInfo->cursorWidth = x;
    hwCursorInfo->cursorHeight = y;

    while( ok && (--y != -1) ) {
        x = shmem->cursorSize[frame].width;
        while( ok && (--x != -1) ) {

	    if( cursPtr32) {
		s32 = *(cursPtr32++);
		alpha = (s32 >> 28) & 0xf;
		red = (s32 >> 16) & 0xff;
		red |= (red << 8);
		green = (s32 >> 8) & 0xff;
		green |= (green << 8);
		blue = (s32) & 0xff;
		blue |= (blue << 8);

	    } else {
#define RMASK16	0xF000
#define GMASK16	0x0F00
#define BMASK16	0x00F0
#define AMASK16	0x000F
		s16 = *(cursPtr16++);
		alpha = s16 & AMASK16;
                red = s16 & RMASK16;
		red |= (red >> 4) | (red >> 8) | (red >> 12);
		green = s16 & GMASK16;
		green |= (green << 4) | (green >> 4) | (green >> 8);
		blue = s16 & BMASK16;
		blue |= (blue << 8) | (blue << 4) | (blue >> 4);
	    }

            if( alpha == 0 ) {

                if( 0 == (red | green | blue)) {
                    /* Transparent black area.  Leave dst as is. */
                    if( kTransparentEncodedPixel
                            & hwDesc->supportedSpecialEncodings)
                        pixel = hwDesc->specialEncodings[kTransparentEncoding];
                    else
                        ok = false;
                } else if (0xffff == (red & green & blue)) {
                    /* Transparent white area.  Invert dst. */
                    if( kInvertingEncodedPixel
                            & hwDesc->supportedSpecialEncodings)
                        pixel = hwDesc->specialEncodings[kInvertingEncoding];
                    else
                        ok = false;
                } else
                    ok = false;

            } else if( alpha == 0xf ) {

		/* Opaque cursor pixel.  Mark it. */
		for( index = 0; index < numColors; index++ ) {
		    if( (red   == clut[ index ].red)
		     && (green == clut[ index ].green)
		     && (blue  == clut[ index ].blue) ) {

			pixel = clut[ index ].index;
			break;
		    }
		}
		if( index == numColors) {
		    ok = (numColors < maxColors);
		    if( ok) {
                        pixel = hwDesc->colorEncodings[ numColors++ ];
                        clut[ index ].red   = red;
                        clut[ index ].green = green;
                        clut[ index ].blue  = blue;
                        clut[ index ].index = pixel;
		    }
		}

            } else {
                /* Alpha is not 0 or 1.0.  Sover the cursor. */
                ok = false;
                break;
	    }

	    data <<= hwDesc->bitDepth;
	    data |= pixel;

	    if( 0 == (x & ((8 / hwDesc->bitDepth) - 1)))
		*dataOut++ = data;
	} /* x */
    } /* y */

//    if( !ok)	kprintf("Couldnt do a hw curs\n");

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOFramebuffer::initialize()
{
#if 0
static IOWorkLoop * gIOFramebufferWorkloop;
static IOLock * gIOFramebufferLock;

    gIOFramebufferLock = IOLockAlloc();

    gIOFramebufferWorkloop = IOWorkLoop::workLoop();

    assert( gIOFramebufferLock && gIOFramebufferWorkloop );
#endif
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if 0
static bool serializeInfoCB( void * target, void * ref, OSSerialize * s )
{
    return( ((IOFramebuffer *)target)->serializeInfo(s) );
}
#endif

static IOPMrootDomain * gIOPMRootDomain;

bool IOFramebuffer::start( IOService * provider )
{

    if( ! super::start( provider))
	return( false );

    userAccessRanges = OSArray::withCapacity( 1 );
    engineAccessRanges = OSArray::withCapacity( 1 );

#if 0
    OSSerializer * infoSerializer = OSSerializer::forTarget( (void *) this, &serializeInfoCB );
    if( !infoSerializer)
	return( false );

    setProperty( kIOFramebufferInfoKey, infoSerializer );
    infoSerializer->release();


    IOInterruptEventSource *	eventSrc;

    eventSrc = IOInterruptEventSource::interruptEventSource(
	this, autopollArrived);
    if (!eventSrc || 
	kIOReturnSuccess != workLoop->addEventSource(eventSrc) ) {
        kprintf("Start is bailing\n");
	return false;
    }
#endif

    closed = true;
    registerService();

    // initialize superclass power management variables
    PMinit();
    // attach into the power management hierarchy
    provider->joinPMtree(this);
    // clamp power on (the user client will change that when appropriate)
//    makeUsable();

    if( !gIOPMRootDomain)
        gIOPMRootDomain = (IOPMrootDomain *)
            IORegistryEntry::fromPath("/IOPowerConnection/IOPMrootDomain", gIOPowerPlane);
    if( gIOPMRootDomain)
        gIOPMRootDomain->registerInterestedDriver(this);

    return( true );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Apple standard 8-bit CLUT

UInt8 appleClut8[ 256 * 3 ] = {
// 00
	0xFF,0xFF,0xFF, 0xFF,0xFF,0xCC,	0xFF,0xFF,0x99,	0xFF,0xFF,0x66,
	0xFF,0xFF,0x33, 0xFF,0xFF,0x00,	0xFF,0xCC,0xFF,	0xFF,0xCC,0xCC,
	0xFF,0xCC,0x99, 0xFF,0xCC,0x66,	0xFF,0xCC,0x33,	0xFF,0xCC,0x00,
	0xFF,0x99,0xFF, 0xFF,0x99,0xCC,	0xFF,0x99,0x99,	0xFF,0x99,0x66,
// 10
	0xFF,0x99,0x33, 0xFF,0x99,0x00,	0xFF,0x66,0xFF,	0xFF,0x66,0xCC,
	0xFF,0x66,0x99, 0xFF,0x66,0x66,	0xFF,0x66,0x33,	0xFF,0x66,0x00,
	0xFF,0x33,0xFF, 0xFF,0x33,0xCC,	0xFF,0x33,0x99,	0xFF,0x33,0x66,
	0xFF,0x33,0x33, 0xFF,0x33,0x00,	0xFF,0x00,0xFF,	0xFF,0x00,0xCC,
// 20
	0xFF,0x00,0x99, 0xFF,0x00,0x66,	0xFF,0x00,0x33,	0xFF,0x00,0x00,
	0xCC,0xFF,0xFF, 0xCC,0xFF,0xCC,	0xCC,0xFF,0x99,	0xCC,0xFF,0x66,
	0xCC,0xFF,0x33, 0xCC,0xFF,0x00,	0xCC,0xCC,0xFF,	0xCC,0xCC,0xCC,
	0xCC,0xCC,0x99, 0xCC,0xCC,0x66,	0xCC,0xCC,0x33,	0xCC,0xCC,0x00,
// 30
	0xCC,0x99,0xFF, 0xCC,0x99,0xCC,	0xCC,0x99,0x99,	0xCC,0x99,0x66,
	0xCC,0x99,0x33, 0xCC,0x99,0x00,	0xCC,0x66,0xFF,	0xCC,0x66,0xCC,
	0xCC,0x66,0x99, 0xCC,0x66,0x66,	0xCC,0x66,0x33,	0xCC,0x66,0x00,
	0xCC,0x33,0xFF, 0xCC,0x33,0xCC,	0xCC,0x33,0x99,	0xCC,0x33,0x66,
// 40
	0xCC,0x33,0x33, 0xCC,0x33,0x00,	0xCC,0x00,0xFF,	0xCC,0x00,0xCC,
	0xCC,0x00,0x99, 0xCC,0x00,0x66,	0xCC,0x00,0x33,	0xCC,0x00,0x00,
	0x99,0xFF,0xFF, 0x99,0xFF,0xCC,	0x99,0xFF,0x99,	0x99,0xFF,0x66,
	0x99,0xFF,0x33, 0x99,0xFF,0x00,	0x99,0xCC,0xFF,	0x99,0xCC,0xCC,
// 50
	0x99,0xCC,0x99, 0x99,0xCC,0x66,	0x99,0xCC,0x33,	0x99,0xCC,0x00,
	0x99,0x99,0xFF, 0x99,0x99,0xCC,	0x99,0x99,0x99,	0x99,0x99,0x66,
	0x99,0x99,0x33, 0x99,0x99,0x00,	0x99,0x66,0xFF,	0x99,0x66,0xCC,
	0x99,0x66,0x99, 0x99,0x66,0x66,	0x99,0x66,0x33,	0x99,0x66,0x00,
// 60
	0x99,0x33,0xFF, 0x99,0x33,0xCC,	0x99,0x33,0x99,	0x99,0x33,0x66,
	0x99,0x33,0x33, 0x99,0x33,0x00,	0x99,0x00,0xFF,	0x99,0x00,0xCC,
	0x99,0x00,0x99, 0x99,0x00,0x66,	0x99,0x00,0x33,	0x99,0x00,0x00,
	0x66,0xFF,0xFF, 0x66,0xFF,0xCC,	0x66,0xFF,0x99,	0x66,0xFF,0x66,
// 70
	0x66,0xFF,0x33, 0x66,0xFF,0x00,	0x66,0xCC,0xFF,	0x66,0xCC,0xCC,
	0x66,0xCC,0x99, 0x66,0xCC,0x66,	0x66,0xCC,0x33,	0x66,0xCC,0x00,
	0x66,0x99,0xFF, 0x66,0x99,0xCC,	0x66,0x99,0x99,	0x66,0x99,0x66,
	0x66,0x99,0x33, 0x66,0x99,0x00,	0x66,0x66,0xFF,	0x66,0x66,0xCC,
// 80
	0x66,0x66,0x99, 0x66,0x66,0x66,	0x66,0x66,0x33,	0x66,0x66,0x00,
	0x66,0x33,0xFF, 0x66,0x33,0xCC,	0x66,0x33,0x99,	0x66,0x33,0x66,
	0x66,0x33,0x33, 0x66,0x33,0x00,	0x66,0x00,0xFF,	0x66,0x00,0xCC,
	0x66,0x00,0x99, 0x66,0x00,0x66,	0x66,0x00,0x33,	0x66,0x00,0x00,
// 90
	0x33,0xFF,0xFF, 0x33,0xFF,0xCC,	0x33,0xFF,0x99,	0x33,0xFF,0x66,
	0x33,0xFF,0x33, 0x33,0xFF,0x00,	0x33,0xCC,0xFF,	0x33,0xCC,0xCC,
	0x33,0xCC,0x99, 0x33,0xCC,0x66,	0x33,0xCC,0x33,	0x33,0xCC,0x00,
	0x33,0x99,0xFF, 0x33,0x99,0xCC,	0x33,0x99,0x99,	0x33,0x99,0x66,
// a0
	0x33,0x99,0x33, 0x33,0x99,0x00,	0x33,0x66,0xFF,	0x33,0x66,0xCC,
	0x33,0x66,0x99, 0x33,0x66,0x66,	0x33,0x66,0x33,	0x33,0x66,0x00,
	0x33,0x33,0xFF, 0x33,0x33,0xCC,	0x33,0x33,0x99,	0x33,0x33,0x66,
	0x33,0x33,0x33, 0x33,0x33,0x00,	0x33,0x00,0xFF,	0x33,0x00,0xCC,
// b0
	0x33,0x00,0x99, 0x33,0x00,0x66,	0x33,0x00,0x33,	0x33,0x00,0x00,
	0x00,0xFF,0xFF, 0x00,0xFF,0xCC,	0x00,0xFF,0x99,	0x00,0xFF,0x66,
	0x00,0xFF,0x33, 0x00,0xFF,0x00,	0x00,0xCC,0xFF,	0x00,0xCC,0xCC,
	0x00,0xCC,0x99, 0x00,0xCC,0x66,	0x00,0xCC,0x33,	0x00,0xCC,0x00,
// c0
	0x00,0x99,0xFF, 0x00,0x99,0xCC,	0x00,0x99,0x99,	0x00,0x99,0x66,
	0x00,0x99,0x33, 0x00,0x99,0x00,	0x00,0x66,0xFF,	0x00,0x66,0xCC,
	0x00,0x66,0x99, 0x00,0x66,0x66,	0x00,0x66,0x33,	0x00,0x66,0x00,
	0x00,0x33,0xFF, 0x00,0x33,0xCC,	0x00,0x33,0x99,	0x00,0x33,0x66,
// d0
	0x00,0x33,0x33, 0x00,0x33,0x00,	0x00,0x00,0xFF,	0x00,0x00,0xCC,
	0x00,0x00,0x99, 0x00,0x00,0x66,	0x00,0x00,0x33,	0xEE,0x00,0x00,
	0xDD,0x00,0x00, 0xBB,0x00,0x00,	0xAA,0x00,0x00,	0x88,0x00,0x00,
	0x77,0x00,0x00, 0x55,0x00,0x00,	0x44,0x00,0x00,	0x22,0x00,0x00,
// e0
	0x11,0x00,0x00, 0x00,0xEE,0x00,	0x00,0xDD,0x00,	0x00,0xBB,0x00,
	0x00,0xAA,0x00, 0x00,0x88,0x00,	0x00,0x77,0x00,	0x00,0x55,0x00,
	0x00,0x44,0x00, 0x00,0x22,0x00,	0x00,0x11,0x00,	0x00,0x00,0xEE,
	0x00,0x00,0xDD, 0x00,0x00,0xBB,	0x00,0x00,0xAA,	0x00,0x00,0x88,
// f0
	0x00,0x00,0x77, 0x00,0x00,0x55,	0x00,0x00,0x44,	0x00,0x00,0x22,
	0x00,0x00,0x11, 0xEE,0xEE,0xEE,	0xDD,0xDD,0xDD,	0xBB,0xBB,0xBB,
	0xAA,0xAA,0xAA, 0x88,0x88,0x88,	0x77,0x77,0x77,	0x55,0x55,0x55,
	0x44,0x44,0x44, 0x22,0x22,0x22,	0x11,0x11,0x11,	0x00,0x00,0x00
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifdef __ppc__
extern
#endif
int killprint;
extern "C" { int kmputc( int c ); }

IOReturn IOFramebuffer::setPowerState( unsigned long powerStateOrdinal,
						IOService * whichDevice )
{
    if( 0 == powerStateOrdinal ) {
        if( isConsoleDevice())
            killprint = 1;
        deliverFramebufferNotification( kIOFBNotifyWillSleep );

    } else {

        if( isConsoleDevice()) {
            killprint = 0;
            kmputc( 033 );
            kmputc( 'c' );
        }
        deliverFramebufferNotification( kIOFBNotifyDidWake );
    }

    return( IOPMAckImplied);
}

IOReturn IOFramebuffer::beginSystemSleep( void * ackRef )
{
    pmRef = ackRef;
    powerOverrideOnPriv();
    changePowerStateToPriv(0);

    return( kIOReturnSuccess );
}

IOReturn IOFramebuffer::powerStateWillChangeTo( IOPMPowerFlags flags,
                                                unsigned long, IOService * whatDevice )
{
    if( (whatDevice == gIOPMRootDomain) && (IOPMPowerOn & flags))
        // end system sleep
        powerOverrideOffPriv();

    return( IOPMAckImplied );
}

IOReturn IOFramebuffer::powerStateDidChangeTo( IOPMPowerFlags flags,
                                                unsigned long, IOService* whatDevice )
{
    if( (whatDevice == this) && pmRef && (0 == (IOPMDeviceUsable & flags))) {
        // root can proceed
        acknowledgeSleepWakeNotification(pmRef);
        pmRef = 0;
    }

    return( IOPMAckImplied );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IODeviceMemory * IOFramebuffer::getVRAMRange( void )
{
    return( getApertureRange( kIOFBSystemAperture ));
}

void  IOFramebuffer::close( void )	// called by the user client when
{					// the window server exits

}



IOReturn IOFramebuffer::open( void )
{
    IOReturn		err = kIOReturnSuccess;
    UInt32		value;

    do {
	if( opened)
	    continue;

        // tell the console if it's on this display, it's going away
	if( isConsoleDevice())
            getPlatform()->setConsoleInfo( 0, kPEDisableScreen);

        deliverFramebufferNotification( kIOFBNotifyDisplayModeWillChange );

	err = enableController();
	if( kIOReturnSuccess != err) {
            deliverFramebufferNotification( kIOFBNotifyDisplayModeDidChange );
	    continue;
	}
	err = registerForInterruptType( kIOFBVBLInterruptType, 
			(IOFBInterruptProc) &handleVBL, 
			this, priv, &vblInterrupt );
	haveVBLService = (err == kIOReturnSuccess );

	err = getAttribute( kIOHardwareCursorAttribute, &value );
	haveHWCursor = ((err == kIOReturnSuccess) && value);

	err = kIOReturnSuccess;
        opened = true;

    } while( false );

    return( err );
}

IOReturn IOFramebuffer::setUserRanges( void )
{
#if 1		/* print ranges */

    UInt32		i, numRanges;
    IODeviceMemory *	mem;

	numRanges = userAccessRanges->getCount();
	IOLog("%s: user ranges num:%ld", getName(), numRanges);
	for( i = 0; i < numRanges; i++) {
	    mem = (IODeviceMemory *) userAccessRanges->getObject( i );
	    if( 0 == mem)
		continue;
	    IOLog(" start:%lx size:%lx",
		mem->getPhysicalAddress(), mem->getLength() );
	}
        IOLog("\n");

#endif
    return( kIOReturnSuccess);
}

IOReturn IOFramebuffer::setupForCurrentConfig( void )
{
    return( doSetup( true ));
}

IOReturn IOFramebuffer::doSetup( bool full )
{
    IOReturn			err;
    IODisplayModeID		mode;
    IOIndex			depth;
    IOPixelInformation		info;
    IODisplayModeInformation	dmInfo;
    IODeviceMemory *		mem;
    IODeviceMemory *		fbRange;
    IOPhysicalAddress		base;
    PE_Video			newConsole;

    err = getCurrentDisplayMode( &mode, &depth );
    if( err)
        IOLog("%s: getCurrentDisplayMode %d\n", getName(), err);

    err = getPixelInformation( mode, depth, kIOFBSystemAperture, &info );
    if( err)
	IOLog("%s: getPixelInformation %d\n", getName(),  err);

    if( full && (clutValid == false) && (info.pixelType == kIOCLUTPixels)) {

	IOColorEntry	*	tempTable;
	int			i;

	tempTable = (IOColorEntry *) IOMalloc( 256 * sizeof( *tempTable));
	if( tempTable) {

	    for( i = 0; i < 256; i++) {
                if( currentMono) {
                    UInt32	lum;

		    lum = 0x0101 * i;
                    tempTable[ i ].red   = lum;
                    tempTable[ i ].green = lum;
                    tempTable[ i ].blue  = lum;
                } else {
                    tempTable[ i ].red   = (appleClut8[ i * 3 + 0 ] << 8)
					  | appleClut8[ i * 3 + 0 ];
                    tempTable[ i ].green = (appleClut8[ i * 3 + 1 ] << 8)
					  | appleClut8[ i * 3 + 1 ];
                    tempTable[ i ].blue  = (appleClut8[ i * 3 + 2 ] << 8)
					  | appleClut8[ i * 3 + 2 ];
		}
	    }
	    setCLUTWithEntries( tempTable, 0, 256, 1 * kSetCLUTImmediately );
	    IOFree( tempTable, 256 * sizeof( *tempTable));
	}
        clutValid = true;
    }

    fbRange = getApertureRange( kIOFBSystemAperture );

    if( full && fbRange) {

        userAccessRanges->removeObject( kIOFBSystemAperture );
        userAccessRanges->setObject( kIOFBSystemAperture, fbRange );
        err = setUserRanges();

	base = fbRange->getPhysicalAddress();
        if( (mem = getVRAMRange())) {
            vramMapOffset = base - mem->getPhysicalAddress();
            mem->release();
	}

	if( vramMap)
	    vramMap->release();
	vramMap = fbRange->map();
	assert( vramMap );
	if( vramMap)
	    base = vramMap->getVirtualAddress();

        // console now available
        if( info.activeWidth >= 128) {
            newConsole.v_baseAddr	= base;
            newConsole.v_rowBytes	= info.bytesPerRow;
            newConsole.v_width		= info.activeWidth;
            newConsole.v_height		= info.activeHeight;
            newConsole.v_depth		= info.bitsPerPixel;
            //	strcpy( consoleInfo->v_pixelFormat, "PPPPPPPP");
            getPlatform()->setConsoleInfo( &newConsole, kPEEnableScreen );
        }

        deliverFramebufferNotification( kIOFBNotifyDisplayModeDidChange, 0 );

        (void) getInformationForDisplayMode( mode, &dmInfo );
        IOLog( "%s: using (%ldx%ld@%ldHz,%ld bpp)\n", getName(),
                    info.activeWidth, info.activeHeight,
                    (dmInfo.refreshRate + 0x8000) >> 16, info.bitsPerPixel );
    }

    if( fbRange)
        fbRange->release();
    if( vramMap)
        setupCursor( &info );

    return( kIOReturnSuccess );
}

IOReturn IOFramebuffer::extSetDisplayMode( IODisplayModeID displayMode,
				IOIndex depth )
{
    IOReturn	err;

    stopCursor();

    if( isConsoleDevice())
        getPlatform()->setConsoleInfo( 0, kPEDisableScreen);

    deliverFramebufferNotification( kIOFBNotifyDisplayModeWillChange );

    err = setDisplayMode( displayMode, depth );

    clutValid = false;

    setupForCurrentConfig();

    return( err );
}

IOReturn IOFramebuffer::extGetInformationForDisplayMode(
		IODisplayModeID mode, IODisplayModeInformation * info )
{
    UInt32		flags = 0;
    IOReturn		err;
    IOTimingInformation timingInfo;

    err = getInformationForDisplayMode( mode, info );
    if( kIOReturnSuccess == err) {
	err = IODisplayWrangler::getFlagsForDisplayMode( this, mode, &flags);
	if( kIOReturnSuccess == err) {
	    info->flags &= ~kDisplayModeSafetyFlags;
	    info->flags |= flags;
	}
	if( kIOReturnSuccess == getTimingInfoForDisplayMode( mode, &timingInfo )) 
            info->reserved[0] = timingInfo.appleTimingID;

    }

    return( err );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOFramebuffer::setNumber( OSDictionary * dict, const char * key,
				UInt32 value )
{
    OSNumber *	num;
    bool	ok;

    num = OSNumber::withNumber( value, 32 );
    if( !num)
	return( false );

    ok = dict->setObject( key, num );
    num->release();

    return( ok );
}

bool IOFramebuffer::serializeInfo( OSSerialize * s )
{
    IOReturn			err;
    IODisplayModeInformation	info;
    IOPixelInformation		pixelInfo;
    IODisplayModeID *		modeIDs;
    IOItemCount			modeCount, modeNum, aperture;
    IOIndex			depthNum;
    OSDictionary *		infoDict;
    OSDictionary *		modeDict;
    OSDictionary *		pixelDict;
    char			keyBuf[12];
    bool			ok = true;

    modeCount = getDisplayModeCount();
    modeIDs = IONew( IODisplayModeID, modeCount );
    if( !modeIDs)
	return( false );

    err = getDisplayModes( modeIDs );
    if( err)
	return( false );

    infoDict = OSDictionary::withCapacity( 10 );
    if( !infoDict)
	return( false );

    for( modeNum = 0; modeNum < modeCount; modeNum++ ) {

	err = getInformationForDisplayMode( modeIDs[ modeNum ], &info );
	if( err)
	    continue;

	modeDict = OSDictionary::withCapacity( 10 );
	if( !modeDict)
	    break;

	ok = setNumber( modeDict, kIOFBWidthKey,
			info.nominalWidth )
	 && setNumber( modeDict, kIOFBHeightKey,
			info.nominalHeight )
	 && setNumber( modeDict, kIOFBRefreshRateKey,
			info.refreshRate )
	 && setNumber( modeDict, kIOFBFlagsKey,
			info.flags );
	if( !ok)
	    break;

	for( depthNum = 0; depthNum < info.maxDepthIndex; depthNum++ ) {
	    
	    for( aperture = 0; ; aperture++ ) {

		err = getPixelInformation( modeIDs[ modeNum ], depthNum,
					aperture, &pixelInfo );
		if( err)
		    break;

		pixelDict = OSDictionary::withCapacity( 10 );
		if( !pixelDict)
		    continue;

		ok = setNumber( pixelDict, kIOFBBytesPerRowKey,
				pixelInfo.bytesPerRow )
		  && setNumber( pixelDict, kIOFBBytesPerPlaneKey,
				pixelInfo.bytesPerPlane )
		  && setNumber( pixelDict, kIOFBBitsPerPixelKey,
				pixelInfo.bitsPerPixel )
		  && setNumber( pixelDict, kIOFBComponentCountKey,
				pixelInfo.componentCount )
		  && setNumber( pixelDict, kIOFBBitsPerComponentKey,
				pixelInfo.bitsPerComponent )
		  && setNumber( pixelDict, kIOFBFlagsKey,
				pixelInfo.flags )
		  && setNumber( pixelDict, kIOFBWidthKey,
				pixelInfo.activeWidth )
		  && setNumber( pixelDict, kIOFBHeightKey,
				pixelInfo.activeHeight );
		if( !ok)
		    break;

		sprintf( keyBuf, "%lx", depthNum + (aperture << 16) );
                modeDict->setObject( keyBuf, pixelDict );
		pixelDict->release();
	    }
	}

        sprintf( keyBuf, "%lx", modeIDs[ modeNum ] );
        infoDict->setObject( keyBuf, modeDict );
	modeDict->release();
    }

    IODelete( modeIDs, IODisplayModeID, modeCount );

    ok &= infoDict->serialize( s );
    infoDict->release();

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(_IOFramebufferNotifier, IONotifier)
#define LOCKNOTIFY()
#define UNLOCKNOTIFY()

void _IOFramebufferNotifier::remove()
{
    LOCKNOTIFY();

    if( whence) {
        whence->removeObject( (OSObject *) this );
        whence = 0;
    }

    fEnable = false;

    UNLOCKNOTIFY();
    
    release();
}

bool _IOFramebufferNotifier::disable()
{
    bool	ret;

    LOCKNOTIFY();
    ret = fEnable;
    fEnable = false;
    UNLOCKNOTIFY();

    return( ret );
}

void _IOFramebufferNotifier::enable( bool was )
{
    LOCKNOTIFY();
    fEnable = was;
    UNLOCKNOTIFY();
}

IONotifier * IOFramebuffer::addFramebufferNotification(
	IOFramebufferNotificationHandler handler,
	OSObject * self, void * ref)
{
    _IOFramebufferNotifier *	notify = 0;

    notify = new _IOFramebufferNotifier;
    if( notify && !notify->init()) {
        notify->release();
        notify = 0;
    }

    if( notify) {
        notify->handler = handler;
        notify->self = self;
        notify->ref = ref;
	notify->fEnable = true;

        if( 0 == fbNotifications)
            fbNotifications = OSSet::withCapacity(1);

        notify->whence = fbNotifications;
        if( fbNotifications)
            fbNotifications->setObject( notify );
    }

    return( notify );
}

IOReturn IOFramebuffer::deliverFramebufferNotification(
		IOIndex event, void * info = 0 )
{
    OSIterator *		iter;
    _IOFramebufferNotifier *	notify;
    IOReturn			ret = kIOReturnSuccess;
    IOReturn			r;

    LOCKNOTIFY();

    iter = OSCollectionIterator::withCollection( fbNotifications );

    if( iter) {
        while( (notify = (_IOFramebufferNotifier *) iter->getNextObject())) {

            if( notify->fEnable) {
		r = (*notify->handler)( notify->self, notify->ref, this,
					event, info );
		if( kIOReturnSuccess != ret)
		    ret = r;
	    }
        }
        iter->release();
    }

    UNLOCKNOTIFY();

    return( ret );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Some stubs

IOReturn IOFramebuffer::enableController ( void )
{
    return( kIOReturnSuccess );
}

bool IOFramebuffer::isConsoleDevice( void )
{
    return( false );
}

    // Set display mode and depth
IOReturn IOFramebuffer::setDisplayMode( IODisplayModeID /* displayMode */,
                            IOIndex /* depth */ )
{
    return( kIOReturnUnsupported);
}

// For pages
IOReturn IOFramebuffer::setApertureEnable(
		IOPixelAperture /* aperture */, IOOptionBits /* enable */ )
{
    return( kIOReturnUnsupported);
}

// Display mode and depth for startup
IOReturn IOFramebuffer::setStartupDisplayMode(
			IODisplayModeID /* displayMode */, IOIndex /* depth */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::getStartupDisplayMode(
		IODisplayModeID * /* displayMode */, IOIndex * /* depth */ )
{
    return( kIOReturnUnsupported);
}

//// CLUTs

IOReturn IOFramebuffer::setCLUTWithEntries(
	    IOColorEntry * /* colors */, UInt32 /* index */,
            UInt32 /* numEntries */, IOOptionBits /* options */ )
{
    return( kIOReturnUnsupported);
}

//// Gamma

IOReturn IOFramebuffer::setGammaTable( UInt32 /* channelCount */,
		UInt32 /* dataCount */, UInt32 /* dataWidth */, void * /* data */ )
{
    return( kIOReturnUnsupported);
}

//// Controller attributes

IOReturn IOFramebuffer::setAttribute( IOSelect /* attribute */, UInt32 /* value */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::getAttribute( IOSelect /* attribute */,
		UInt32 * /* value */ )
{
    return( kIOReturnUnsupported);
}

//// Display mode timing information

IOReturn IOFramebuffer::getTimingInfoForDisplayMode(
	    IODisplayModeID /* displayMode */,
            IOTimingInformation * /* info */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::validateDetailedTiming(
            void * description, IOByteCount descripSize )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::setDetailedTimings( OSArray * array )
{
    return( kIOReturnUnsupported);
}

//// Connections

IOItemCount IOFramebuffer::getConnectionCount( void )
{
    return( 1);
}

IOReturn IOFramebuffer::setAttributeForConnection( IOIndex /* connectIndex */,
                IOSelect /* attribute */, UInt32 /* value */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::getAttributeForConnection( IOIndex /* connectIndex */,
                IOSelect /* attribute */, UInt32  * /* value */ )
{
    return( kIOReturnUnsupported);
}

//// HW Cursors

IOReturn IOFramebuffer::setCursorImage( void * cursorImage )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::setCursorState( SInt32 x, SInt32 y, bool visible )
{
    return( kIOReturnUnsupported);
}

void IOFramebuffer::flushCursor( void )
{
}

//// Interrupts

IOReturn IOFramebuffer::registerForInterruptType( IOSelect interruptType,
            	    IOFBInterruptProc proc, OSObject * target, void * ref,
		    void ** interruptRef )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::unregisterInterrupt( void * interruptRef )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::setInterruptState( void * interruptRef, UInt32 state )
{
    return( kIOReturnUnsupported);
}

// Apple sensing

IOReturn IOFramebuffer::getAppleSense(
	    IOIndex  /* connectIndex */,
            UInt32 * /* senseType */,
            UInt32 * /* primary */,
            UInt32 * /* extended */,
            UInt32 * /* displayType */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::connectFlags( IOIndex /* connectIndex */,
                    IODisplayModeID /* displayMode */, IOOptionBits * /* flags */ )
{
    return( kIOReturnUnsupported);
}

//// IOLowLevelDDCSense

void IOFramebuffer::setDDCClock( IOIndex /* connectIndex */, UInt32 /* value */ )
{
}

void IOFramebuffer::setDDCData( IOIndex /* connectIndex */, UInt32 /* value */ )
{
}

bool IOFramebuffer::readDDCClock( IOIndex /* connectIndex */ )
{
    return( false);
}

bool IOFramebuffer::readDDCData( IOIndex /* connectIndex */ )
{
    return( false);
}

IOReturn IOFramebuffer::enableDDCRaster( bool /* enable */ )
{
    return( kIOReturnUnsupported);
}


//// IOHighLevelDDCSense

bool IOFramebuffer::hasDDCConnect( IOIndex /* connectIndex */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOFramebuffer::getDDCBlock( IOIndex /* connectIndex */, UInt32 /* blockNumber */,
                    IOSelect /* blockType */, IOOptionBits /* options */,
                    UInt8 * /* data */, IOByteCount * /* length */ )
{
    return( kIOReturnUnsupported);
}

OSMetaClassDefineReservedUnused(IOFramebuffer, 0);
OSMetaClassDefineReservedUnused(IOFramebuffer, 1);
OSMetaClassDefineReservedUnused(IOFramebuffer, 2);
OSMetaClassDefineReservedUnused(IOFramebuffer, 3);
OSMetaClassDefineReservedUnused(IOFramebuffer, 4);
OSMetaClassDefineReservedUnused(IOFramebuffer, 5);
OSMetaClassDefineReservedUnused(IOFramebuffer, 6);
OSMetaClassDefineReservedUnused(IOFramebuffer, 7);
OSMetaClassDefineReservedUnused(IOFramebuffer, 8);
OSMetaClassDefineReservedUnused(IOFramebuffer, 9);
OSMetaClassDefineReservedUnused(IOFramebuffer, 10);
OSMetaClassDefineReservedUnused(IOFramebuffer, 11);
OSMetaClassDefineReservedUnused(IOFramebuffer, 12);
OSMetaClassDefineReservedUnused(IOFramebuffer, 13);
OSMetaClassDefineReservedUnused(IOFramebuffer, 14);
OSMetaClassDefineReservedUnused(IOFramebuffer, 15);
OSMetaClassDefineReservedUnused(IOFramebuffer, 16);
OSMetaClassDefineReservedUnused(IOFramebuffer, 17);
OSMetaClassDefineReservedUnused(IOFramebuffer, 18);
OSMetaClassDefineReservedUnused(IOFramebuffer, 19);
OSMetaClassDefineReservedUnused(IOFramebuffer, 20);
OSMetaClassDefineReservedUnused(IOFramebuffer, 21);
OSMetaClassDefineReservedUnused(IOFramebuffer, 22);
OSMetaClassDefineReservedUnused(IOFramebuffer, 23);
OSMetaClassDefineReservedUnused(IOFramebuffer, 24);
OSMetaClassDefineReservedUnused(IOFramebuffer, 25);
OSMetaClassDefineReservedUnused(IOFramebuffer, 26);
OSMetaClassDefineReservedUnused(IOFramebuffer, 27);
OSMetaClassDefineReservedUnused(IOFramebuffer, 28);
OSMetaClassDefineReservedUnused(IOFramebuffer, 29);
OSMetaClassDefineReservedUnused(IOFramebuffer, 30);
OSMetaClassDefineReservedUnused(IOFramebuffer, 31);

