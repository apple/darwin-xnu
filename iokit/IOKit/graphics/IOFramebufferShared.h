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
/* Copyright (c) 1992, 1993 NeXT Computer, Inc.  All rights reserved. 
 *
 * IOFrameBufferShared.h - Definitions of objects and types shared between
 *   kernel level IOFrameBufferDisplay driver and PostScript level driver.
 *
 * HISTORY
 * 03 Sep 92	Joe Pasqua
 *      Created. 
 * 24 Jun 93	Derek B Clegg
 * 	Moved to driverkit.
 */

#ifndef _IOKIT_IOFRAMEBUFFERSHARED_H
#define _IOKIT_IOFRAMEBUFFERSHARED_H

#include <IOKit/hidsystem/IOHIDTypes.h>
#include <IOKit/graphics/IOGraphicsTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KERNEL
// CGS use optional
#define IOFB_ARBITRARY_SIZE_CURSOR
#endif

#define IOFB_SUPPORTS_XOR_CURSOR

//
// Cursor and Window Server state data, occupying a slice of shared memory
// between the kernel and WindowServer.
//

enum {
    kIOFBNumCursorFrames	= 4,
    kIOFBNumCursorFramesShift	= 2,
    kIOFBMaxCursorDepth		= 32
};

#ifndef IOFB_ARBITRARY_SIZE_CURSOR

#define CURSORWIDTH  16         /* width in pixels */
#define CURSORHEIGHT 16         /* height in pixels */

struct bm12Cursor {
    unsigned int image[4][16];
    unsigned int mask[4][16];
    unsigned int save[16];
};

struct bm18Cursor {
    unsigned char image[4][256];
    unsigned char mask[4][256];
    unsigned char save[256];
};

struct bm34Cursor {
    unsigned short image[4][256];
    unsigned short save[256];
};

struct bm38Cursor {
    unsigned int image[4][256];
    unsigned int save[256];
};

#endif /* IOFB_ARBITRARY_SIZE_CURSOR */

struct StdFBShmem_t {
    ev_lock_data_t cursorSema;	
    int frame;
    char cursorShow;
    char cursorObscured;
    char shieldFlag;
    char shielded;
    IOGBounds saveRect;
    IOGBounds shieldRect;
    IOGPoint cursorLoc;
    IOGBounds cursorRect;
    IOGBounds oldCursorRect;
    IOGBounds screenBounds;
    int version;
    int structSize;
    AbsoluteTime vblTime;
    AbsoluteTime vblDelta;
    unsigned int reservedC[30];
    unsigned char hardwareCursorCapable;
    unsigned char hardwareCursorActive;
    unsigned char reservedB[2];
    IOGSize cursorSize[kIOFBNumCursorFrames];
    IOGPoint hotSpot[kIOFBNumCursorFrames];
#ifndef IOFB_ARBITRARY_SIZE_CURSOR
    union {
	struct bm12Cursor bw;
	struct bm18Cursor bw8;
	struct bm34Cursor rgb;
	struct bm38Cursor rgb24;
    } cursor;
#else  /* IOFB_ARBITRARY_SIZE_CURSOR */
    unsigned char cursor[0];
#endif /* IOFB_ARBITRARY_SIZE_CURSOR */
};
#ifndef __cplusplus
typedef volatile struct StdFBShmem_t StdFBShmem_t;
#endif


enum {
    // version for IOFBCreateSharedCursor
    kIOFBCurrentShmemVersion	= 2,
    // memory types for IOConnectMapMemory.
    // 0..n are apertures
    kIOFBCursorMemory		= 100,
    kIOFBVRAMMemory		= 110
};

#define IOFRAMEBUFFER_CONFORMSTO	"IOFramebuffer"

#ifdef __cplusplus
}
#endif

#endif /* ! _IOKIT_IOFRAMEBUFFERSHARED_H */
