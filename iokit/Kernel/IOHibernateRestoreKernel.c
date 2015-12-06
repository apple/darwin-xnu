/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdint.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOLib.h>
#include <pexpert/boot.h>
#include <libkern/libkern.h>

#include <vm/WKdm_new.h>
#include "IOHibernateInternal.h"

#include <machine/pal_hibernate.h>

/*
This code is linked into the kernel but part of the "__HIB" section, which means
its used by code running in the special context of restoring the kernel text and data
from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
it calls or references needs to be careful to only touch memory also in the "__HIB" section.
*/

uint32_t gIOHibernateState;

uint32_t gIOHibernateDebugFlags;

static IOHibernateImageHeader _hibernateHeader;
IOHibernateImageHeader * gIOHibernateCurrentHeader = &_hibernateHeader;

ppnum_t gIOHibernateHandoffPages[64];
uint32_t gIOHibernateHandoffPageCount = sizeof(gIOHibernateHandoffPages) 
					/ sizeof(gIOHibernateHandoffPages[0]);

#if CONFIG_DEBUG
void hibprintf(const char *fmt, ...);
#else
#define hibprintf(x...)
#endif


#if CONFIG_SLEEP
#if defined(__i386__) || defined(__x86_64__)
extern void acpi_wake_prot_entry(void);
#endif
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(__i386__) || defined(__x86_64__)

#define rdtsc(lo,hi) \
    __asm__ volatile("lfence; rdtsc; lfence" : "=a" (lo), "=d" (hi))

static inline uint64_t rdtsc64(void)
{
    uint64_t lo, hi;
    rdtsc(lo, hi);
    return ((hi) << 32) | (lo);
}

#else

static inline uint64_t rdtsc64(void)
{
    return (0);
}

#endif /* defined(__i386__) || defined(__x86_64__) */

#if defined(__i386__) || defined(__x86_64__)

#define DBGLOG	1

#include <architecture/i386/pio.h>

/* standard port addresses */
enum {
    COM1_PORT_ADDR = 0x3f8,
    COM2_PORT_ADDR = 0x2f8
};

/* UART register offsets */
enum {
    UART_RBR = 0,  /* receive buffer Register   (R) */
    UART_THR = 0,  /* transmit holding register (W) */
    UART_DLL = 0,  /* DLAB = 1, divisor latch (LSB) */
    UART_IER = 1,  /* interrupt enable register     */
    UART_DLM = 1,  /* DLAB = 1, divisor latch (MSB) */
    UART_IIR = 2,  /* interrupt ident register (R)  */
    UART_FCR = 2,  /* fifo control register (W)     */
    UART_LCR = 3,  /* line control register         */
    UART_MCR = 4,  /* modem control register        */
    UART_LSR = 5,  /* line status register          */
    UART_MSR = 6,  /* modem status register         */
    UART_SCR = 7   /* scratch register              */
};

enum {
    UART_LCR_8BITS = 0x03,
    UART_LCR_DLAB  = 0x80
};

enum {
    UART_MCR_DTR   = 0x01,
    UART_MCR_RTS   = 0x02,
    UART_MCR_OUT1  = 0x04,
    UART_MCR_OUT2  = 0x08,
    UART_MCR_LOOP  = 0x10
};

enum {
    UART_LSR_DR    = 0x01,
    UART_LSR_OE    = 0x02,
    UART_LSR_PE    = 0x04,
    UART_LSR_FE    = 0x08,
    UART_LSR_THRE  = 0x20
};

static void uart_putc(char c)
{
    while (!(inb(COM1_PORT_ADDR + UART_LSR) & UART_LSR_THRE))
	{}
    outb(COM1_PORT_ADDR + UART_THR, c);
}

static int debug_probe( void )
{
    /* Verify that the Scratch Register is accessible */
    outb(COM1_PORT_ADDR + UART_SCR, 0x5a);
    if (inb(COM1_PORT_ADDR + UART_SCR) != 0x5a) return false;
    outb(COM1_PORT_ADDR + UART_SCR, 0xa5);
    if (inb(COM1_PORT_ADDR + UART_SCR) != 0xa5) return false;
    uart_putc('\n');
    return true;
}

static void uart_puthex(uint64_t num)
{
    int bit;
    char c;
    bool leading = true;

    for (bit = 60; bit >= 0; bit -= 4)
    {
	c = 0xf & (num >> bit);
	if (c)
	    leading = false;
	else if (leading && bit)
	    continue;
	if (c <= 9)
	    c += '0';
	else
	    c+= 'a' - 10;
	uart_putc(c);
    }
}

static void debug_code(uint32_t code, uint64_t value)
{
    int bit;
    char c;

    if (!(kIOHibernateDebugRestoreLogs & gIOHibernateDebugFlags))
	return;

    for (bit = 24; bit >= 0; bit -= 8)
    {
	c = 0xFF & (code >> bit);
	if (c)
	    uart_putc(c);
    }
    uart_putc('=');
    uart_puthex(value);
    uart_putc('\n');
    uart_putc('\r');
}

#endif /* defined(__i386__) || defined(__x86_64__) */

#if !defined(DBGLOG)
#define debug_probe()	    (false)
#define debug_code(c, v)    {}
#endif

enum
{
    kIOHibernateRestoreCodeImageStart	    = 'imgS',
    kIOHibernateRestoreCodeImageEnd	    = 'imgE',
    kIOHibernateRestoreCodePageIndexStart   = 'pgiS',
    kIOHibernateRestoreCodePageIndexEnd	    = 'pgiE',
    kIOHibernateRestoreCodeMapStart	    = 'mapS',
    kIOHibernateRestoreCodeMapEnd	    = 'mapE',
    kIOHibernateRestoreCodeWakeMapSize	    = 'wkms',
    kIOHibernateRestoreCodeConflictPage	    = 'cfpg',
    kIOHibernateRestoreCodeConflictSource   = 'cfsr',
    kIOHibernateRestoreCodeNoMemory         = 'nomm',
    kIOHibernateRestoreCodeTag              = 'tag ',
    kIOHibernateRestoreCodeSignature        = 'sign',
    kIOHibernateRestoreCodeMapVirt          = 'mapV',
    kIOHibernateRestoreCodeHandoffPages     = 'hand',
    kIOHibernateRestoreCodeHandoffCount     = 'hndc',
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


static void fatal(void)
{
#if defined(__i386__) || defined(__x86_64__)
    outb(0xcf9, 6);
#else
    while (true) {}
#endif
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

uint32_t
hibernate_sum_page(uint8_t *buf, uint32_t ppnum)
{
    return (((uint32_t *)buf)[((PAGE_SIZE >> 2) - 1) & ppnum]);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static hibernate_bitmap_t *
hibernate_page_bitmap(hibernate_page_list_t * list, uint32_t page)
{
    uint32_t             bank;
    hibernate_bitmap_t * bitmap = &list->bank_bitmap[0];

    for (bank = 0; bank < list->bank_count; bank++)
    {
	if ((page >= bitmap->first_page) && (page <= bitmap->last_page))
	    break;
	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }
    if (bank == list->bank_count)
	bitmap = NULL;
	
    return (bitmap);
}

hibernate_bitmap_t *
hibernate_page_bitmap_pin(hibernate_page_list_t * list, uint32_t * pPage)
{
    uint32_t             bank, page = *pPage;
    hibernate_bitmap_t * bitmap = &list->bank_bitmap[0];

    for (bank = 0; bank < list->bank_count; bank++)
    {
	if (page <= bitmap->first_page)
	{
	    *pPage = bitmap->first_page;
	    break;
	}
	if (page <= bitmap->last_page)
	    break;
	bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
    }
    if (bank == list->bank_count)
	bitmap = NULL;
	
    return (bitmap);
}

void 
hibernate_page_bitset(hibernate_page_list_t * list, boolean_t set, uint32_t page)
{
    hibernate_bitmap_t * bitmap;

    bitmap = hibernate_page_bitmap(list, page);
    if (bitmap)
    {
	page -= bitmap->first_page;
	if (set)
	    bitmap->bitmap[page >> 5] |= (0x80000000 >> (page & 31));
	    //setbit(page - bitmap->first_page, (int *) &bitmap->bitmap[0]);
	else
	    bitmap->bitmap[page >> 5] &= ~(0x80000000 >> (page & 31));
	    //clrbit(page - bitmap->first_page, (int *) &bitmap->bitmap[0]);
    }
}

boolean_t 
hibernate_page_bittst(hibernate_page_list_t * list, uint32_t page)
{
    boolean_t		 result = TRUE;
    hibernate_bitmap_t * bitmap;

    bitmap = hibernate_page_bitmap(list, page);
    if (bitmap)
    {
	page -= bitmap->first_page;
	result = (0 != (bitmap->bitmap[page >> 5] & (0x80000000 >> (page & 31))));
    }
    return (result);
}

// count bits clear or set (set == TRUE) starting at page.
uint32_t
hibernate_page_bitmap_count(hibernate_bitmap_t * bitmap, uint32_t set, uint32_t page)
{
    uint32_t index, bit, bits;
    uint32_t count;

    count = 0;

    index = (page - bitmap->first_page) >> 5;
    bit = (page - bitmap->first_page) & 31;

    bits = bitmap->bitmap[index];
    if (set)
	bits = ~bits;
    bits = (bits << bit);
    if (bits)
	count += __builtin_clz(bits);
    else
    {
	count += 32 - bit;
	while (++index < bitmap->bitmapwords)
	{
	    bits = bitmap->bitmap[index];
	    if (set)
		bits = ~bits;
	    if (bits)
	    {
		count += __builtin_clz(bits);
		break;
	    }
	    count += 32;
	}
    }

    if ((page + count) > (bitmap->last_page + 1)) count = (bitmap->last_page + 1) - page;

    return (count);
}

static ppnum_t
hibernate_page_list_grab(hibernate_page_list_t * list, uint32_t * pNextFree)
{
    uint32_t		 nextFree = *pNextFree;
    uint32_t		 nextFreeInBank;
    hibernate_bitmap_t * bitmap;

    nextFreeInBank = nextFree + 1;
    while ((bitmap = hibernate_page_bitmap_pin(list, &nextFreeInBank)))
    {
	nextFreeInBank += hibernate_page_bitmap_count(bitmap, FALSE, nextFreeInBank);
	if (nextFreeInBank <= bitmap->last_page)
	{
	    *pNextFree = nextFreeInBank;
	    break;
	}
    }

    if (!bitmap) 
    {
	debug_code(kIOHibernateRestoreCodeNoMemory, nextFree);
	fatal();
	nextFree = 0;
    }

    return (nextFree);
}

static uint32_t
store_one_page(uint32_t procFlags, uint32_t * src, uint32_t compressedSize, 
		uint32_t * buffer, uint32_t ppnum)
{
	uint64_t dst = ptoa_64(ppnum);
	uint8_t scratch[WKdm_SCRATCH_BUF_SIZE] __attribute__ ((aligned (16)));

	if (compressedSize != PAGE_SIZE)
	{
		dst = pal_hib_map(DEST_COPY_AREA, dst);
		if (compressedSize != 4) WKdm_decompress_new((WK_word*) src, (WK_word*)(uintptr_t)dst, (WK_word*) &scratch[0], compressedSize);
		else {
			int i;
			uint32_t *s, *d;
			
			s = src;
			d = (uint32_t *)(uintptr_t)dst;

			for (i = 0; i < (int)(PAGE_SIZE / sizeof(int32_t)); i++)
				*d++ = *s;
		}
	}
	else
	{
		dst = hibernate_restore_phys_page((uint64_t) (uintptr_t) src, dst, PAGE_SIZE, procFlags);
	}

	return hibernate_sum_page((uint8_t *)(uintptr_t)dst, ppnum);
}

long 
hibernate_kernel_entrypoint(uint32_t p1, 
                            uint32_t p2, uint32_t p3, uint32_t p4)
{
    uint64_t headerPhys;
    uint64_t mapPhys;
    uint64_t srcPhys;
    uint64_t imageReadPhys;
    uint64_t pageIndexPhys;
    uint32_t * pageIndexSource;
    hibernate_page_list_t * map;
    uint32_t stage;
    uint32_t count;
    uint32_t ppnum;
    uint32_t page;
    uint32_t conflictCount;
    uint32_t compressedSize;
    uint32_t uncompressedPages;
    uint32_t copyPageListHeadPage;
    uint32_t pageListPage;
    uint32_t * copyPageList;
    uint32_t * src;
    uint32_t copyPageIndex;
    uint32_t sum;
    uint32_t pageSum;
    uint32_t nextFree;
    uint32_t lastImagePage;
    uint32_t lastMapPage;
    uint32_t lastPageIndexPage;
    uint32_t handoffPages;
    uint32_t handoffPageCount;

    uint64_t timeStart;
    timeStart = rdtsc64();

    assert_static(sizeof(IOHibernateImageHeader) == 512);

    headerPhys = ptoa_64(p1);

    if ((kIOHibernateDebugRestoreLogs & gIOHibernateDebugFlags) && !debug_probe())
	gIOHibernateDebugFlags &= ~kIOHibernateDebugRestoreLogs;

    debug_code(kIOHibernateRestoreCodeImageStart, headerPhys);

    memcpy(gIOHibernateCurrentHeader,
	   (void *) pal_hib_map(IMAGE_AREA, headerPhys), 
	   sizeof(IOHibernateImageHeader));

    debug_code(kIOHibernateRestoreCodeSignature, gIOHibernateCurrentHeader->signature);

    mapPhys = headerPhys
             + (offsetof(IOHibernateImageHeader, fileExtentMap)
	     + gIOHibernateCurrentHeader->fileExtentMapSize 
	     + ptoa_32(gIOHibernateCurrentHeader->restore1PageCount)
	     + gIOHibernateCurrentHeader->previewSize);

    map = (hibernate_page_list_t *) pal_hib_map(BITMAP_AREA, mapPhys);

    lastImagePage = atop_64(headerPhys + gIOHibernateCurrentHeader->image1Size);
    lastMapPage = atop_64(mapPhys + gIOHibernateCurrentHeader->bitmapSize);

    handoffPages     = gIOHibernateCurrentHeader->handoffPages;
    handoffPageCount = gIOHibernateCurrentHeader->handoffPageCount;

    debug_code(kIOHibernateRestoreCodeImageEnd,       ptoa_64(lastImagePage));
    debug_code(kIOHibernateRestoreCodeMapStart,       mapPhys);
    debug_code(kIOHibernateRestoreCodeMapEnd,         ptoa_64(lastMapPage));

    debug_code(kIOHibernateRestoreCodeMapVirt, (uintptr_t) map);
    debug_code(kIOHibernateRestoreCodeHandoffPages, ptoa_64(handoffPages));
    debug_code(kIOHibernateRestoreCodeHandoffCount, handoffPageCount);

    // knock all the image pages to be used out of free map
    for (ppnum = atop_64(headerPhys); ppnum <= lastImagePage; ppnum++)
    {
	hibernate_page_bitset(map, FALSE, ppnum);
    }
    // knock all the handoff pages to be used out of free map
    for (ppnum = handoffPages; ppnum < (handoffPages + handoffPageCount); ppnum++)
    {
	hibernate_page_bitset(map, FALSE, ppnum);
    }

    nextFree = 0;
    hibernate_page_list_grab(map, &nextFree);

    sum = gIOHibernateCurrentHeader->actualRestore1Sum;
    gIOHibernateCurrentHeader->diag[0] = atop_64(headerPhys);
    gIOHibernateCurrentHeader->diag[1] = sum;
    gIOHibernateCurrentHeader->trampolineTime = 0;

    uncompressedPages    = 0;
    conflictCount        = 0;
    copyPageListHeadPage = 0;
    copyPageList         = 0;
    copyPageIndex        = PAGE_SIZE >> 2;

    compressedSize       = PAGE_SIZE;
    stage                = 2;
    count                = 0;
    srcPhys              = 0;

    if (gIOHibernateCurrentHeader->previewSize)
    {
	pageIndexPhys     = headerPhys
	                   + (offsetof(IOHibernateImageHeader, fileExtentMap)
			   + gIOHibernateCurrentHeader->fileExtentMapSize 
			   + ptoa_32(gIOHibernateCurrentHeader->restore1PageCount));
	imageReadPhys     = (pageIndexPhys + gIOHibernateCurrentHeader->previewPageListSize);
	lastPageIndexPage = atop_64(imageReadPhys);
	pageIndexSource   = (uint32_t *) pal_hib_map(IMAGE2_AREA, pageIndexPhys);
    }
    else
    {
	pageIndexPhys     = 0;
	lastPageIndexPage = 0;
	imageReadPhys     = (mapPhys + gIOHibernateCurrentHeader->bitmapSize);
    }

    debug_code(kIOHibernateRestoreCodePageIndexStart, pageIndexPhys);
    debug_code(kIOHibernateRestoreCodePageIndexEnd,   ptoa_64(lastPageIndexPage));

    while (1)
    {
	switch (stage)
	{
	    case 2:
		// copy handoff data
		count = srcPhys ? 0 : handoffPageCount;
		if (!count)
		    break;
		if (count > gIOHibernateHandoffPageCount) count = gIOHibernateHandoffPageCount;
		srcPhys = ptoa_64(handoffPages);
		break;
	
	    case 1:
		// copy pageIndexSource pages == preview image data
		if (!srcPhys)
		{
		    if (!pageIndexPhys) break;
		    srcPhys = imageReadPhys;
		}
		ppnum = pageIndexSource[0];
		count = pageIndexSource[1];
		pageIndexSource += 2;
		pageIndexPhys   += 2 * sizeof(pageIndexSource[0]);
		imageReadPhys = srcPhys;
		break;

	    case 0:
		// copy pages
		if (!srcPhys) srcPhys = (mapPhys + gIOHibernateCurrentHeader->bitmapSize);
		src = (uint32_t *) pal_hib_map(IMAGE_AREA, srcPhys);
		ppnum = src[0];
		count = src[1];
		srcPhys += 2 * sizeof(*src);
		imageReadPhys = srcPhys;
		break;
	}


	if (!count)
	{
	    if (!stage)
	        break;
	    stage--;
	    srcPhys = 0;
	    continue;
	}

	for (page = 0; page < count; page++, ppnum++)
	{
	    uint32_t tag;
	    int conflicts;

	    src = (uint32_t *) pal_hib_map(IMAGE_AREA, srcPhys);

	    if (2 == stage) ppnum = gIOHibernateHandoffPages[page];
	    else if (!stage)
	    {
		tag = *src++;
//		debug_code(kIOHibernateRestoreCodeTag, (uintptr_t) tag);
		srcPhys += sizeof(*src);
		compressedSize = kIOHibernateTagLength & tag;
	    }

	    conflicts = (ppnum >= atop_64(mapPhys)) && (ppnum <= lastMapPage);

	    conflicts |= ((ppnum >= atop_64(imageReadPhys)) && (ppnum <= lastImagePage));

	    if (stage >= 2)
 		conflicts |= ((ppnum >= atop_64(srcPhys)) && (ppnum <= (handoffPages + handoffPageCount - 1)));

	    if (stage >= 1)
 		conflicts |= ((ppnum >= atop_64(pageIndexPhys)) && (ppnum <= lastPageIndexPage));

	    if (!conflicts)
	    {
		pageSum = store_one_page(gIOHibernateCurrentHeader->processorFlags,
					 src, compressedSize, 0, ppnum);
		if (stage != 2)
		    sum += pageSum;
		uncompressedPages++;
	    }
	    else
	    {
		uint32_t   bufferPage = 0;
		uint32_t * dst;

//		debug_code(kIOHibernateRestoreCodeConflictPage,   ppnum);
//		debug_code(kIOHibernateRestoreCodeConflictSource, (uintptr_t) src);
		conflictCount++;
		if (compressedSize)
		{
		    // alloc new buffer page
		    bufferPage = hibernate_page_list_grab(map, &nextFree);
		    dst = (uint32_t *)pal_hib_map(DEST_COPY_AREA, ptoa_64(bufferPage));
		    memcpy(dst, src, compressedSize);
		}
		if (copyPageIndex > ((PAGE_SIZE >> 2) - 3))
		{
		    // alloc new copy list page
		    pageListPage = hibernate_page_list_grab(map, &nextFree);
		    // link to current
		    if (copyPageList) {
			    copyPageList[1] = pageListPage;
		    } else {
			    copyPageListHeadPage = pageListPage;
		    }
		    copyPageList = (uint32_t *)pal_hib_map(SRC_COPY_AREA, 
				    ptoa_64(pageListPage));
		    copyPageList[1] = 0;
		    copyPageIndex = 2;
		}
		copyPageList[copyPageIndex++] = ppnum;
		copyPageList[copyPageIndex++] = bufferPage;
		copyPageList[copyPageIndex++] = (compressedSize | (stage << 24));
		copyPageList[0] = copyPageIndex;
	    }
	    srcPhys += ((compressedSize + 3) & ~3);
	    src     += ((compressedSize + 3) >> 2);
	}
    }

    /* src points to the last page restored, so we need to skip over that */
    hibernateRestorePALState(src);

    // -- copy back conflicts

    pageListPage = copyPageListHeadPage;
    while (pageListPage)
    {
	copyPageList = (uint32_t *)pal_hib_map(COPY_PAGE_AREA, ptoa_64(pageListPage));
	for (copyPageIndex = 2; copyPageIndex < copyPageList[0]; copyPageIndex += 3)
	{
	    ppnum          = copyPageList[copyPageIndex + 0];
	    srcPhys        = ptoa_64(copyPageList[copyPageIndex + 1]);
	    src            = (uint32_t *) pal_hib_map(SRC_COPY_AREA, srcPhys);
	    compressedSize = copyPageList[copyPageIndex + 2];
	    stage 	   = compressedSize >> 24;
	    compressedSize &= 0x1FFF;
	    pageSum        = store_one_page(gIOHibernateCurrentHeader->processorFlags,
			    			src, compressedSize, 0, ppnum);
	    if (stage != 2)
	    	sum += pageSum;
	    uncompressedPages++;
	}
	pageListPage = copyPageList[1];
    }

    pal_hib_patchup();

    // -- image has been destroyed...

    gIOHibernateCurrentHeader->actualImage1Sum         = sum;
    gIOHibernateCurrentHeader->actualUncompressedPages = uncompressedPages;
    gIOHibernateCurrentHeader->conflictCount           = conflictCount;
    gIOHibernateCurrentHeader->nextFree                = nextFree;

    gIOHibernateState = kIOHibernateStateWakingFromHibernate;

    gIOHibernateCurrentHeader->trampolineTime = (((rdtsc64() - timeStart)) >> 8);

//  debug_code('done', 0);

#if CONFIG_SLEEP
#if defined(__i386__) || defined(__x86_64__)
    typedef void (*ResetProc)(void);
    ResetProc proc;
    proc = HIB_ENTRYPOINT;
    // flush caches
    __asm__("wbinvd");
    proc();
#else
// implement me
#endif
#endif

    return -1;
}

#if CONFIG_DEBUG
/* standalone printf implementation */
/*-
 * Copyright (c) 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)subr_prf.c	8.3 (Berkeley) 1/21/94
 */

typedef long ptrdiff_t;
char const hibhex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define hibhex2ascii(hex)  (hibhex2ascii_data[hex])
#define toupper(c)      ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
static size_t
hibstrlen(const char *s)
{
	size_t l = 0;
	while (*s++)
		l++;
	return l;
}

/* Max number conversion buffer length: a u_quad_t in base 2, plus NUL byte. */
#define MAXNBUF	(sizeof(intmax_t) * NBBY + 1)

/*
 * Put a NUL-terminated ASCII number (base <= 36) in a buffer in reverse
 * order; return an optional length and a pointer to the last character
 * written in the buffer (i.e., the first character of the string).
 * The buffer pointed to by `nbuf' must have length >= MAXNBUF.
 */
static char *
ksprintn(char *nbuf, uintmax_t num, int base, int *lenp, int upper)
{
	char *p, c;

	/* Truncate so we don't call umoddi3, which isn't in __HIB */
#if !defined(__LP64__)
	uint32_t num2 = (uint32_t) num;
#else
	uintmax_t num2 = num;
#endif

	p = nbuf;
	*p = '\0';
	do {
		c = hibhex2ascii(num2 % base);
		*++p = upper ? toupper(c) : c;
	} while (num2 /= base);
	if (lenp)
		*lenp = (int)(p - nbuf);
	return (p);
}

/*
 * Scaled down version of printf(3).
 *
 * Two additional formats:
 *
 * The format %b is supported to decode error registers.
 * Its usage is:
 *
 *	printf("reg=%b\n", regval, "*");
 *
 * where  is the output base expressed as a control character, e.g.
 * \10 gives octal; \20 gives hex.  Each arg is a sequence of characters,
 * the first of which gives the bit number to be inspected (origin 1), and
 * the next characters (up to a control character, i.e. a character <= 32),
 * give the name of the register.  Thus:
 *
 *	kvprintf("reg=%b\n", 3, "\10\2BITTWO\1BITONE\n");
 *
 * would produce output:
 *
 *	reg=3
 *
 * XXX:  %D  -- Hexdump, takes pointer and separator string:
 *		("%6D", ptr, ":")   -> XX:XX:XX:XX:XX:XX
 *		("%*D", len, ptr, " " -> XX XX XX XX ...
 */
static int
hibkvprintf(char const *fmt, void (*func)(int, void*), void *arg, int radix, va_list ap)
{
#define PCHAR(c) {int cc=(c); if (func) (*func)(cc,arg); else *d++ = cc; retval++; }
	char nbuf[MAXNBUF];
	char *d;
	const char *p, *percent, *q;
	u_char *up;
	int ch, n;
	uintmax_t num;
	int base, lflag, qflag, tmp, width, ladjust, sharpflag, neg, sign, dot;
	int cflag, hflag, jflag, tflag, zflag;
	int dwidth, upper;
	char padc;
	int stop = 0, retval = 0;

	num = 0;
	if (!func)
		d = (char *) arg;
	else
		d = NULL;

	if (fmt == NULL)
		fmt = "(fmt null)\n";

	if (radix < 2 || radix > 36)
		radix = 10;

	for (;;) {
		padc = ' ';
		width = 0;
		while ((ch = (u_char)*fmt++) != '%' || stop) {
			if (ch == '\0')
				return (retval);
			PCHAR(ch);
		}
		percent = fmt - 1;
		qflag = 0; lflag = 0; ladjust = 0; sharpflag = 0; neg = 0;
		sign = 0; dot = 0; dwidth = 0; upper = 0;
		cflag = 0; hflag = 0; jflag = 0; tflag = 0; zflag = 0;
reswitch:	switch (ch = (u_char)*fmt++) {
		case '.':
			dot = 1;
			goto reswitch;
		case '#':
			sharpflag = 1;
			goto reswitch;
		case '+':
			sign = 1;
			goto reswitch;
		case '-':
			ladjust = 1;
			goto reswitch;
		case '%':
			PCHAR(ch);
			break;
		case '*':
			if (!dot) {
				width = va_arg(ap, int);
				if (width < 0) {
					ladjust = !ladjust;
					width = -width;
				}
			} else {
				dwidth = va_arg(ap, int);
			}
			goto reswitch;
		case '0':
			if (!dot) {
				padc = '0';
				goto reswitch;
			}
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
				for (n = 0;; ++fmt) {
					n = n * 10 + ch - '0';
					ch = *fmt;
					if (ch < '0' || ch > '9')
						break;
				}
			if (dot)
				dwidth = n;
			else
				width = n;
			goto reswitch;
		case 'b':
			num = (u_int)va_arg(ap, int);
			p = va_arg(ap, char *);
			for (q = ksprintn(nbuf, num, *p++, NULL, 0); *q;)
				PCHAR(*q--);

			if (num == 0)
				break;

			for (tmp = 0; *p;) {
				n = *p++;
				if (num & (1 << (n - 1))) {
					PCHAR(tmp ? ',' : '<');
					for (; (n = *p) > ' '; ++p)
						PCHAR(n);
					tmp = 1;
				} else
					for (; *p > ' '; ++p)
						continue;
			}
			if (tmp)
				PCHAR('>');
			break;
		case 'c':
			PCHAR(va_arg(ap, int));
			break;
		case 'D':
			up = va_arg(ap, u_char *);
			p = va_arg(ap, char *);
			if (!width)
				width = 16;
			while(width--) {
				PCHAR(hibhex2ascii(*up >> 4));
				PCHAR(hibhex2ascii(*up & 0x0f));
				up++;
				if (width)
					for (q=p;*q;q++)
						PCHAR(*q);
			}
			break;
		case 'd':
		case 'i':
			base = 10;
			sign = 1;
			goto handle_sign;
		case 'h':
			if (hflag) {
				hflag = 0;
				cflag = 1;
			} else
				hflag = 1;
			goto reswitch;
		case 'j':
			jflag = 1;
			goto reswitch;
		case 'l':
			if (lflag) {
				lflag = 0;
				qflag = 1;
			} else
				lflag = 1;
			goto reswitch;
		case 'n':
			if (jflag)
				*(va_arg(ap, intmax_t *)) = retval;
			else if (qflag)
				*(va_arg(ap, quad_t *)) = retval;
			else if (lflag)
				*(va_arg(ap, long *)) = retval;
			else if (zflag)
				*(va_arg(ap, size_t *)) = retval;
			else if (hflag)
				*(va_arg(ap, short *)) = retval;
			else if (cflag)
				*(va_arg(ap, char *)) = retval;
			else
				*(va_arg(ap, int *)) = retval;
			break;
		case 'o':
			base = 8;
			goto handle_nosign;
		case 'p':
			base = 16;
			sharpflag = (width == 0);
			sign = 0;
			num = (uintptr_t)va_arg(ap, void *);
			goto number;
		case 'q':
			qflag = 1;
			goto reswitch;
		case 'r':
			base = radix;
			if (sign)
				goto handle_sign;
			goto handle_nosign;
		case 's':
			p = va_arg(ap, char *);
			if (p == NULL)
				p = "(null)";
			if (!dot)
				n = (typeof(n))hibstrlen (p);
			else
				for (n = 0; n < dwidth && p[n]; n++)
					continue;

			width -= n;

			if (!ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			while (n--)
				PCHAR(*p++);
			if (ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			break;
		case 't':
			tflag = 1;
			goto reswitch;
		case 'u':
			base = 10;
			goto handle_nosign;
		case 'X':
			upper = 1;
		case 'x':
			base = 16;
			goto handle_nosign;
		case 'y':
			base = 16;
			sign = 1;
			goto handle_sign;
		case 'z':
			zflag = 1;
			goto reswitch;
handle_nosign:
			sign = 0;
			if (jflag)
				num = va_arg(ap, uintmax_t);
			else if (qflag)
				num = va_arg(ap, u_quad_t);
			else if (tflag)
				num = va_arg(ap, ptrdiff_t);
			else if (lflag)
				num = va_arg(ap, u_long);
			else if (zflag)
				num = va_arg(ap, size_t);
			else if (hflag)
				num = (u_short)va_arg(ap, int);
			else if (cflag)
				num = (u_char)va_arg(ap, int);
			else
				num = va_arg(ap, u_int);
			goto number;
handle_sign:
			if (jflag)
				num = va_arg(ap, intmax_t);
			else if (qflag)
				num = va_arg(ap, quad_t);
			else if (tflag)
				num = va_arg(ap, ptrdiff_t);
			else if (lflag)
				num = va_arg(ap, long);
			else if (zflag)
				num = va_arg(ap, ssize_t);
			else if (hflag)
				num = (short)va_arg(ap, int);
			else if (cflag)
				num = (char)va_arg(ap, int);
			else
				num = va_arg(ap, int);
number:
			if (sign && (intmax_t)num < 0) {
				neg = 1;
				num = -(intmax_t)num;
			}
			p = ksprintn(nbuf, num, base, &tmp, upper);
			if (sharpflag && num != 0) {
				if (base == 8)
					tmp++;
				else if (base == 16)
					tmp += 2;
			}
			if (neg)
				tmp++;

			if (!ladjust && padc != '0' && width
			    && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);
			if (neg)
				PCHAR('-');
			if (sharpflag && num != 0) {
				if (base == 8) {
					PCHAR('0');
				} else if (base == 16) {
					PCHAR('0');
					PCHAR('x');
				}
			}
			if (!ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);

			while (*p)
				PCHAR(*p--);

			if (ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);

			break;
		default:
			while (percent < fmt)
				PCHAR(*percent++);
			/*
			 * Since we ignore an formatting argument it is no
			 * longer safe to obey the remaining formatting
			 * arguments as the arguments will no longer match
			 * the format specs.
			 */
			stop = 1;
			break;
		}
	}
#undef PCHAR
}


static void
putchar(int c, void *arg)
{
	(void)arg;
	uart_putc(c);
}

void
hibprintf(const char *fmt, ...)
{
	/* http://www.pagetable.com/?p=298 */
	va_list ap;

	va_start(ap, fmt);
	hibkvprintf(fmt, putchar, NULL, 10, ap);
	va_end(ap);
}
#endif /* CONFIG_DEBUG */

