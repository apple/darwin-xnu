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

#define RBMASK	0xF0F0		/* Short, or 16 bit format */
#define GAMASK	0x0F0F		/* Short, or 16 bit format */
#define AMASK	0x000F		/* Short, or 16 bit format */

#if 1
#define short34to35WithGamma(x) 	\
	(  (((x) & 0xf000) >> 1)	\
	 | (((x) & 0x0f00) >> 2)  	\
	 | (((x) & 0x00f0) >> 3)	\
	 | (((x) & 0x8000) >> 5)  	\
	 | (((x) & 0x0800) >> 6)  	\
	 | (((x) & 0x0080) >> 7) )

#define short35to34WithGamma(x) 	\
	(  0x000F			\
	 | (((x) & 0x001e) << 3)	\
	 | (((x) & 0x03c0) << 2)	\
	 | (((x) & 0x7800) << 1) )
#else
#define short34to35WithGamma(x) \
	(  (_bm34To35SampleTable[((x) & 0x00F0) >> 4])		\
	 | (_bm34To35SampleTable[((x) & 0x0F00) >> 8] << 5)	\
	 | (_bm34To35SampleTable[(x) >> 12] << 10) )

#define short35to34WithGamma(x) \
	(  0x000F						\
	 | (_bm35To34SampleTable[x & 0x001F] << 4)		\
	 | (_bm35To34SampleTable[(x & 0x03E0) >> 5] << 8)	\
	 | (_bm35To34SampleTable[(x & 0x7C00) >> 10] << 12) )
#endif

void IOFramebuffer::StdFBDisplayCursor555(
                IOFramebuffer * inst,
		StdFBShmem_t *shmem,
                volatile unsigned short *vramPtr,
                unsigned int cursStart,
                unsigned int vramRow,
                unsigned int cursRow,
                int width,
                int height )
{
    int i, j;
    volatile unsigned short *cursPtr;
    volatile unsigned short *savePtr;
    unsigned short s, d, f;
    unsigned char *_bm34To35SampleTable;
    unsigned char *_bm35To34SampleTable;

    savePtr = (volatile unsigned short *) inst->cursorSave;
    cursPtr = (volatile unsigned short *) inst->cursorImages[ shmem->frame ];
    cursPtr += cursStart;

    _bm34To35SampleTable = inst->colorConvert.t._bm34To35SampleTable;
    _bm35To34SampleTable = inst->colorConvert.t._bm35To34SampleTable;
    
    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; ) {
            d = *savePtr++ = *vramPtr;
            if ( (s = *cursPtr++) == 0 )
            {	/* Transparent black area.  Leave dst as is. */
                ++vramPtr;
                continue;
            }
            if ( (f = (~s) & (unsigned int)AMASK) == 0 )
            {	/* Opaque cursor pixel.  Mark it. */
                *vramPtr++ = short34to35WithGamma(s);
                continue;
            }
            if ((f == AMASK))
            {	/* Transparent non black cursor pixel.  xor it. */
                *vramPtr++ = d ^ short34to35WithGamma(s);
                continue;
            }
            /* Alpha is not 0 or 1.0.  Sover the cursor. */
            d = short35to34WithGamma(d);
            d = s + (((((d & RBMASK)>>4)*f + GAMASK) & RBMASK)
                | ((((d & GAMASK)*f+GAMASK)>>4) & GAMASK));
            *vramPtr++ = short34to35WithGamma(d);
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        vramPtr += vramRow; /* starting point of next screen line */
    }
}

void IOFramebuffer::StdFBDisplayCursor444(
                IOFramebuffer * inst,
                StdFBShmem_t *shmem,
                volatile unsigned short *vramPtr,
                unsigned int cursStart,
                unsigned int vramRow,
                unsigned int cursRow,
                int width,
                int height )
{
    int i, j;
    volatile unsigned short *savePtr;	/* saved screen data pointer */
    volatile unsigned short *cursPtr;
    unsigned short s, d, f;

    savePtr = (volatile unsigned short *) inst->cursorSave;
    cursPtr = (volatile unsigned short *) inst->cursorImages[ shmem->frame ];
    cursPtr += cursStart;

    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; ) {
            d = *savePtr++ = *vramPtr;
            if ( (s = *cursPtr++) == 0 )
            {	/* Transparent black area.  Leave dst as is. */
                ++vramPtr;
                continue;
            }
            if ( (f = (~s) & (unsigned int)AMASK) == 0 )
            {	/* Opaque cursor pixel.  Mark it. */
                *vramPtr++ = s;
                continue;
            }
            if ((f == AMASK))
            {	/* Transparent non black cursor pixel.  xor it. */
                *vramPtr++ = d ^ s;
                continue;
            }
            /* Alpha is not 0 or 1.0.  Sover the cursor. */
            *vramPtr++ = s + (((((d & RBMASK)>>4)*f + GAMASK) & RBMASK)
                              | ((((d & GAMASK)*f+GAMASK)>>4) & GAMASK));
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        vramPtr += vramRow; /* starting point of next screen line */
    }
}

static inline unsigned int MUL32(unsigned int a, unsigned int b)
{
    unsigned int v, w;

    v  = ((a & 0xff00ff00) >> 8) * b;
    v += ((v & 0xff00ff00) >> 8) + 0x00010001;
    w  = (a & 0x00ff00ff) * b;
    w += ((w & 0xff00ff00) >> 8) + 0x00010001;

    return (v & 0xff00ff00) | ((w >> 8) & 0x00ff00ff);
}

static inline unsigned char map32to256( unsigned char *directToLogical, unsigned int s)
{
    unsigned char logicalValue;

    if ((s ^ (s>>8)) & 0x00ffff00) {
	logicalValue =  directToLogical[(s>>24)        + 0] +
			directToLogical[((s>>16)&0xff) + 256] +
			directToLogical[((s>>8)&0xff)  + 512];
    } else {
	logicalValue =  directToLogical[(s>>24)        + 768];
    }
    // final conversion to actual palette
    return( directToLogical[ logicalValue + 1024 ]);
}

void IOFramebuffer::StdFBDisplayCursor8P(
                IOFramebuffer * inst,
                StdFBShmem_t *shmem,
                volatile unsigned char *vramPtr,
                unsigned int cursStart,
                unsigned int vramRow,
                unsigned int cursRow,
                int width,
                int height )
{
    int i, j;
    volatile unsigned char *savePtr;	/* saved screen data pointer */
    volatile unsigned char *cursPtr;
    unsigned char dst, src, alpha, white;
    unsigned int rgb32val;
    volatile unsigned char *maskPtr;		/* cursor mask pointer */
    unsigned int *_bm256To38SampleTable
        = inst->colorConvert.t._bm256To38SampleTable;
    unsigned char *_bm38To256SampleTable
        = inst->colorConvert.t._bm38To256SampleTable;

    savePtr = (volatile unsigned char *) inst->cursorSave;
    cursPtr = (volatile unsigned char *) inst->cursorImages[ shmem->frame ];
    maskPtr = (volatile unsigned char *) inst->cursorMasks[ shmem->frame ];
    cursPtr += cursStart;
    maskPtr += cursStart;
    
    white = inst->white;
    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; savePtr++,maskPtr++,cursPtr++,vramPtr++) {
            dst = *savePtr = *vramPtr;
            src = *cursPtr;
            if ((alpha = *maskPtr)) {
                if ((alpha = ~alpha)) {
                    rgb32val = _bm256To38SampleTable[dst];
                    rgb32val = (_bm256To38SampleTable[src] & ~0xff) +
                                      MUL32(rgb32val, alpha);
                    *vramPtr = map32to256(_bm38To256SampleTable, rgb32val);
                } else
                    *vramPtr = src;
            } else if (src == white)
                *vramPtr = map32to256(_bm38To256SampleTable,
                                      _bm256To38SampleTable[dst] ^ 0xffffffff);
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        maskPtr += cursRow;
        vramPtr += vramRow; /* starting point of next screen line */
    }
}


void IOFramebuffer::StdFBDisplayCursor8G(
                                 IOFramebuffer * inst,
                                 StdFBShmem_t *shmem,
                                 volatile unsigned char *vramPtr,
                                 unsigned int cursStart,
                                 unsigned int vramRow,
                                 unsigned int cursRow,
                                 int width,
                                 int height )
{
    int i, j;
    volatile unsigned char *savePtr;	/* saved screen data pointer */
    unsigned short s, d, a;
    volatile unsigned char *cursPtr;
    volatile unsigned char *maskPtr;		/* cursor mask pointer */

    savePtr = (volatile unsigned char *) inst->cursorSave;
    cursPtr = (volatile unsigned char *) inst->cursorImages[ shmem->frame ];
    maskPtr = (volatile unsigned char *) inst->cursorMasks[ shmem->frame ];
    cursPtr += cursStart;
    maskPtr += cursStart;

    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; ) {
            int t;
            d = *savePtr++ = *vramPtr;
            s = *cursPtr++;
            a = *maskPtr++;
            if (a) {
                t = d * (255 - *maskPtr++);
                *vramPtr = s + ((t + (t >> 8) + 1) >> 8);
            } else if (s)
                *vramPtr = d ^ s;
            vramPtr++;
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        maskPtr += cursRow;
        vramPtr += vramRow; /* starting point of next screen line */
    }
}

void IOFramebuffer::StdFBDisplayCursor32Axxx(
                                 IOFramebuffer * inst,
                                 StdFBShmem_t *shmem,
                                 volatile unsigned int *vramPtr,
                                 unsigned int cursStart,
                                 unsigned int vramRow,
                                 unsigned int cursRow,
                                 int width,
                                 int height )
{
    int i, j;
    volatile unsigned int *savePtr;	/* saved screen data pointer */
    unsigned int s, d, f;
    volatile unsigned int *cursPtr;

    savePtr = (volatile unsigned int *) inst->cursorSave;
    cursPtr = (volatile unsigned int *) inst->cursorImages[ shmem->frame ];
    cursPtr += cursStart;

    /* Pixel format is Axxx */
    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; ) {
            d = *savePtr++ = *vramPtr;
            s = *cursPtr++;
            f = s >> 24;
            if (f) {
                if (f == 0xff)		// Opaque pixel
                    *vramPtr++ = s;
                else {			// SOVER the cursor pixel
                    s <<= 8;  d <<= 8;   /* Now pixels are xxxA */
                    f ^= 0xFF;
                    d = s+(((((d&0xFF00FF00)>>8)*f+0x00FF00FF)&0xFF00FF00)
                        | ((((d & 0x00FF00FF)*f+0x00FF00FF)>>8) &
                            0x00FF00FF));
                    *vramPtr++ = (d>>8) | 0xff000000;
                }
            } else if (s) {
                // Transparent non black cursor pixel.  xor it.
                *vramPtr++ = d ^ s;
                continue;
            } else			// Transparent cursor pixel
                vramPtr++;
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        vramPtr += vramRow; /* starting point of next screen line */
    }
}

void IOFramebuffer::StdFBDisplayCursor32xxxA(
                                            IOFramebuffer * inst,
                                            StdFBShmem_t *shmem,
                                            volatile unsigned int *vramPtr,
                                            unsigned int cursStart,
                                            unsigned int vramRow,
                                            unsigned int cursRow,
                                            int width,
                                            int height )
{
    int i, j;
    volatile unsigned int *savePtr;	/* saved screen data pointer */
    unsigned int s, d, f;
    volatile unsigned int *cursPtr;

    savePtr = (volatile unsigned int *) inst->cursorSave;
    cursPtr = (volatile unsigned int *) inst->cursorImages[ shmem->frame ];
    cursPtr += cursStart;

    /* Pixel format is xxxA */
    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; ) {
            d = *savePtr++ = *vramPtr;
            s = *cursPtr++;
            f = s & (unsigned int)0xFF;
            if (f) {
                if (f == 0xff)		// Opaque pixel
                    *vramPtr++ = s;
                else {			// SOVER the cursor pixel
                    f ^= 0xFF;
                    d = s+(((((d&0xFF00FF00)>>8)*f+0x00FF00FF)&0xFF00FF00)
                        | ((((d & 0x00FF00FF)*f+0x00FF00FF)>>8) &
                            0x00FF00FF));
                    *vramPtr++ = d;
                }
            } else if (s) {
                // Transparent non black cursor pixel.  xor it.
                *vramPtr++ = d ^ s;
                continue;
            } else			// Transparent cursor pixel
                vramPtr++;
        }
        cursPtr += cursRow; /* starting point of next cursor line */
        vramPtr += vramRow; /* starting point of next screen line */
    }
}

void IOFramebuffer::StdFBRemoveCursor16(
                                IOFramebuffer * inst,
                                StdFBShmem_t *shmem,
                                volatile unsigned short *vramPtr,
                                unsigned int vramRow,
                                int width,
                                int height )
{
    int i, j;
    volatile unsigned short *savePtr;

    savePtr = (volatile unsigned short *) inst->cursorSave;

    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; )
	    *vramPtr++ = *savePtr++;
	vramPtr += vramRow;
    }
}

void IOFramebuffer::StdFBRemoveCursor8(
                               IOFramebuffer * inst,
                               StdFBShmem_t *shmem,
                               volatile unsigned char *vramPtr,
                               unsigned int vramRow,
                               int width,
                               int height )
{
    int i, j;
    volatile unsigned char *savePtr;

    savePtr = (volatile unsigned char *) inst->cursorSave;

    for (i = height; --i >= 0; ) {
        for (j = width; --j >= 0; )
	    *vramPtr++ = *savePtr++;
	vramPtr += vramRow;
    }
}

void IOFramebuffer::StdFBRemoveCursor32(
                                IOFramebuffer * inst,
                                StdFBShmem_t *shmem,
                                volatile unsigned int *vramPtr,
                                unsigned int vramRow,
                                int width,
                                int height )
{
    int i, j;
    volatile unsigned int *savePtr;

    savePtr = (volatile unsigned int *) inst->cursorSave;

    for (i = height; --i >= 0; ) {
	for (j = width; --j >= 0; )
	    *vramPtr++ = *savePtr++;
	vramPtr += vramRow;
    }
}
