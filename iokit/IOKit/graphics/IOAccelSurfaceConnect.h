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

#ifndef _IOACCEL_SURFACE_CONNECT_H
#define _IOACCEL_SURFACE_CONNECT_H

#include <IOKit/graphics/IOAccelTypes.h>
#include <IOKit/graphics/IOAccelClientConnect.h>


/*
** Surface visible region in device coordinates.
**
** num_rects:	The number of rectangles in the rect array.  If num_rects
**		is zero the bounds rectangle is used for the visible rectangle.
**		If num_rects is zero the surface must be completely contained
**		by the device.
**
** bounds:	The unclipped surface rectangle in device coords.  Extends
**		beyond the device bounds if the surface is not totally on
**		the device.
**
** rect[]:	An array of visible rectangles in device coords.  If num_rects
**		is non-zero only the region described by these rectangles is
**		copied to the frame buffer during a flush operation.
*/
typedef struct
{
        UInt32        num_rects;
        IOAccelBounds bounds;
        IOAccelBounds rect[0];
} IOAccelDeviceRegion;


/*
** Determine the size of a region.
*/
#define IOACCEL_SIZEOF_DEVICE_REGION(_rgn_) (sizeof(IOAccelDeviceRegion) + (_rgn_)->num_rects * sizeof(IOAccelBounds))


/*
** Surface client public memory types.  Private memory types start with
** kIOAccelNumSurfaceMemoryTypes.
*/
enum eIOAccelSurfaceMemoryTypes {
	kIOAccelNumSurfaceMemoryTypes,
};


/*
** Surface client public methods.  Private methods start with
** kIOAccelNumSurfaceMethods.
*/
enum eIOAccelSurfaceMethods {
	kIOAccelSurfaceSetIDMode,
	kIOAccelSurfaceSetShape,
	kIOAccelSurfaceGetState,
	kIOAccelSurfaceLock,
	kIOAccelSurfaceUnlock,
	kIOAccelSurfaceRead,
	kIOAccelSurfaceFlush,
	kIOAccelNumSurfaceMethods,
};


/*
** Option bits for IOAccelCreateSurface and the kIOAccelSurfaceSetIDMode method.
** The color depth field can take any value of the _CGSDepth enumeration.
*/
typedef enum {
        kIOAccelSurfaceModeColorDepthBits = 0x0000000F,
} eIOAccelSurfaceModeBits;


/*
** Options bits for IOAccelSetSurfaceShape and the kIOAccelSurfaceSetShape method.
*/
typedef enum {
        kIOAccelSurfaceShapeNone         = 0x00000000,
        kIOAccelSurfaceShapeBlockingBit  = 0x00000001,
        kIOAccelSurfaceShapeNonSimpleBit = 0x00000002,
} eIOAccelSurfaceShapeBits;


/*
** Return bits for the kIOAccelSurfaceGetState method.
*/
typedef enum {
	kIOAccelSurfaceStateNone    = 0x00000000,
	kIOAccelSurfaceStateIdleBit = 0x00000001,
} eIOAccelSurfaceStateBits;


#endif /* _IOACCEL_SURFACE_CONNECT_H */

