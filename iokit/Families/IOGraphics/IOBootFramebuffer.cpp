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
 * Boot video dumb frambuffer shim
 */

#include "IOBootFramebuffer.h"

enum { kTheDisplayMode	= 10 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOFramebuffer

OSDefineMetaClassAndStructors(IOBootFramebuffer, IOFramebuffer)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOService * IOBootFramebuffer::probe(	IOService * 	provider,
                                        SInt32 *	score )
{
    PE_Video		bootDisplay;
    IOService *		ret = 0;
    IOReturn		err;

    do {

        if( !provider->getProperty("AAPL,boot-display"))
	    continue;

        err = getPlatform()->getConsoleInfo( &bootDisplay );
	if( err || (bootDisplay.v_baseAddr == 0))
	    continue;

	if (false == super::probe( provider, score ))
	    continue;

	*score 		= 0;
	ret = this;			// Success

    } while( false);

    return( ret);
}


const char * IOBootFramebuffer::getPixelFormats( void )
{
    const char *	ret;
    PE_Video		bootDisplay;

    getPlatform()->getConsoleInfo( &bootDisplay);

    switch( bootDisplay.v_depth) {
      case 8:
      default:
	ret = IO8BitIndexedPixels;
	break;
      case 15:
      case 16:
	ret = IO16BitDirectPixels;
	break;
      case 24:
      case 32:
	ret = IO32BitDirectPixels;
	break;
    }

    return( ret);
}

IOItemCount IOBootFramebuffer::getDisplayModeCount( void )
{
    return( 1);
}

IOReturn IOBootFramebuffer::getDisplayModes(
			IODisplayModeID * allDisplayModes )
{

    *allDisplayModes = kTheDisplayMode;
    return( kIOReturnSuccess);
}

IOReturn IOBootFramebuffer::getInformationForDisplayMode(
		IODisplayModeID /* displayMode */,
		IODisplayModeInformation * info )
{
    PE_Video 	bootDisplay;

    getPlatform()->getConsoleInfo( &bootDisplay);

    bzero( info, sizeof( *info));

    info->maxDepthIndex	= 0;
    info->nominalWidth	= bootDisplay.v_width;
    info->nominalHeight	= bootDisplay.v_height;
    info->refreshRate	= 75 << 16;

    return( kIOReturnSuccess);
}

UInt64 IOBootFramebuffer::getPixelFormatsForDisplayMode( 
		IODisplayModeID /* displayMode */, IOIndex /* depth */ )
{
    return( 1);
}

IOReturn IOBootFramebuffer::getPixelInformation(
	IODisplayModeID displayMode, IOIndex depth,
	IOPixelAperture aperture, IOPixelInformation * info )
{
    PE_Video	bootDisplay;

    if( aperture || depth || (displayMode != kTheDisplayMode) )
        return( kIOReturnUnsupportedMode);

    getPlatform()->getConsoleInfo( &bootDisplay);

    bzero( info, sizeof( *info));

    info->activeWidth		= bootDisplay.v_width;
    info->activeHeight		= bootDisplay.v_height;
    info->bytesPerRow           = bootDisplay.v_rowBytes & 0x7fff;
    info->bytesPerPlane		= 0;

    switch( bootDisplay.v_depth ) {
      case 8:
      default:
        strcpy(info->pixelFormat, IO8BitIndexedPixels );
    info->pixelType 		= kIOCLUTPixels;
    info->componentMasks[0]	= 0xff;
    info->bitsPerPixel 		= 8;
    info->componentCount 	= 1;
    info->bitsPerComponent	= 8;
	break;
      case 15:
      case 16:
        strcpy(info->pixelFormat, IO16BitDirectPixels );
        info->pixelType 	= kIORGBDirectPixels;
        info->componentMasks[0] = 0x7c00;
        info->componentMasks[1] = 0x03e0;
        info->componentMasks[2] = 0x001f;
        info->bitsPerPixel 	= 16;
        info->componentCount 	= 3;
        info->bitsPerComponent	= 5;
	break;
      case 24:
      case 32:
        strcpy(info->pixelFormat, IO32BitDirectPixels );
        info->pixelType 	= kIORGBDirectPixels;
        info->componentMasks[0] = 0x00ff0000;
        info->componentMasks[1] = 0x0000ff00;
        info->componentMasks[2] = 0x000000ff;
        info->bitsPerPixel 	= 32;
        info->componentCount 	= 3;
        info->bitsPerComponent	= 8;
	break;
    }

    return( kIOReturnSuccess);
}

IOReturn IOBootFramebuffer::getCurrentDisplayMode( 
		IODisplayModeID * displayMode, IOIndex * depth )
{
    if( displayMode)
	*displayMode = kTheDisplayMode;
    if( depth)
	*depth = 0;

    return( kIOReturnSuccess);
}

IODeviceMemory * IOBootFramebuffer::getApertureRange( IOPixelAperture aper )
{
    IOReturn			err;
    IOPixelInformation		info;
    IOByteCount			bytes;
    PE_Video			bootDisplay;

    getPlatform()->getConsoleInfo( &bootDisplay);

    err = getPixelInformation( kTheDisplayMode, 0, aper,
                                &info );
    if( err)
	return( 0 );

    bytes = (info.bytesPerRow * info.activeHeight) + 128;

    return( IODeviceMemory::withRange( bootDisplay.v_baseAddr, bytes ));
}

bool IOBootFramebuffer::isConsoleDevice( void )
{
    return( (0 != getProvider()->getProperty("AAPL,boot-display")) );
}

IOReturn IOBootFramebuffer::setGammaTable( UInt32 channelCount,
                            UInt32 dataCount, UInt32 dataWidth, void * data )
{
    return( kIOReturnSuccess );
}

IOReturn IOBootFramebuffer::setCLUTWithEntries(
                    IOColorEntry * colors, UInt32 index, UInt32 numEntries,
                    IOOptionBits options )
{
    return( kIOReturnSuccess );
}
