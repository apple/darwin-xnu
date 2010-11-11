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
#include <crypto/aes.h>
#include <libkern/libkern.h>

#include "WKdm.h"
#include "IOHibernateInternal.h"

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

static hibernate_graphics_t _hibernateGraphics;
hibernate_graphics_t * gIOHibernateGraphicsInfo = &_hibernateGraphics;

static hibernate_cryptwakevars_t _cryptWakeVars;
hibernate_cryptwakevars_t * gIOHibernateCryptWakeVars = &_cryptWakeVars;

vm_offset_t gIOHibernateWakeMap;    	    // ppnum
vm_size_t   gIOHibernateWakeMapSize;


#if CONFIG_SLEEP
#if defined(__i386__) || defined(__x86_64__)
extern void acpi_wake_prot_entry(void);
#endif
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
	else if (leading)
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
    kIOHibernateRestoreCodeNoMemory         = 'nomm'
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

    return (count);
}

static vm_offset_t
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
    uint64_t dst;
    uint32_t sum;

    dst = ptoa_64(ppnum);
    if (ppnum < 0x00100000)
	buffer = (uint32_t *) (uintptr_t) dst;

    if (compressedSize != PAGE_SIZE)
    {
	WKdm_decompress((WK_word*) src, (WK_word*) buffer, PAGE_SIZE >> 2);
	src = buffer;
    }

    sum = hibernate_sum_page((uint8_t *) src, ppnum);

    if (((uint64_t) (uintptr_t) src) == dst)
	src = 0;

    hibernate_restore_phys_page((uint64_t) (uintptr_t) src, dst, PAGE_SIZE, procFlags);

    return (sum);
}

// used only for small struct copies
static void 
bcopy_internal(const void *src, void *dst, uint32_t len)
{
    const char *s = src;
    char       *d = dst;
    uint32_t   idx = 0;

    while (idx < len)
    {
        d[idx] = s[idx];
        idx++;
    }
}

#define C_ASSERT(e) typedef char    __C_ASSERT__[(e) ? 1 : -1]

long 
hibernate_kernel_entrypoint(IOHibernateImageHeader * header, 
                            void * p2, void * p3, void * p4)
{
    uint32_t idx;
    uint32_t * src;
    uint32_t * buffer;
    uint32_t * pageIndexSource;
    hibernate_page_list_t * map;
    uint32_t count;
    uint32_t ppnum;
    uint32_t page;
    uint32_t conflictCount;
    uint32_t compressedSize;
    uint32_t uncompressedPages;
    uint32_t copyPageListHead;
    uint32_t * copyPageList;
    uint32_t copyPageIndex;
    uint32_t sum;
    uint32_t nextFree;
    uint32_t lastImagePage;
    uint32_t lastMapPage;
    uint32_t lastPageIndexPage;

    C_ASSERT(sizeof(IOHibernateImageHeader) == 512);

    if ((kIOHibernateDebugRestoreLogs & gIOHibernateDebugFlags) && !debug_probe())
	gIOHibernateDebugFlags &= ~kIOHibernateDebugRestoreLogs;

    debug_code(kIOHibernateRestoreCodeImageStart, (uintptr_t) header);

    bcopy_internal(header, 
                gIOHibernateCurrentHeader, 
                sizeof(IOHibernateImageHeader));

    if (!p2)
    {
	count = header->graphicsInfoOffset;
	if (count)
	    p2 = (void *)(((uintptr_t) header) - count);
    }
    if (p2) 
        bcopy_internal(p2, 
                gIOHibernateGraphicsInfo, 
                sizeof(hibernate_graphics_t));
    else
        gIOHibernateGraphicsInfo->physicalAddress = gIOHibernateGraphicsInfo->depth = 0;

    if (!p3)
    {
	count = header->cryptVarsOffset;
	if (count)
	    p3 = (void *)(((uintptr_t) header) - count);
    }
    if (p3)
        bcopy_internal(p3, 
                gIOHibernateCryptWakeVars, 
                sizeof(hibernate_cryptwakevars_t));

    src = (uint32_t *)
                (((uintptr_t) &header->fileExtentMap[0]) 
                            + header->fileExtentMapSize 
                            + ptoa_32(header->restore1PageCount));

    if (header->previewSize)
    {
        pageIndexSource = src;
        map = (hibernate_page_list_t *)(((uintptr_t) pageIndexSource) + header->previewSize);
        src = (uint32_t *) (((uintptr_t) pageIndexSource) + header->previewPageListSize);
    }
    else
    {
        pageIndexSource = 0;
        map = (hibernate_page_list_t *) src;
        src = (uint32_t *) (((uintptr_t) map) + header->bitmapSize);
    }

    lastPageIndexPage = atop_32((uintptr_t) src);

    lastImagePage = atop_32(((uintptr_t) header) + header->image1Size);

    lastMapPage = atop_32(((uintptr_t) map) + header->bitmapSize);

    debug_code(kIOHibernateRestoreCodeImageEnd,       ptoa_64(lastImagePage));
    debug_code(kIOHibernateRestoreCodePageIndexStart, (uintptr_t) pageIndexSource);
    debug_code(kIOHibernateRestoreCodePageIndexEnd,   ptoa_64(lastPageIndexPage));
    debug_code(kIOHibernateRestoreCodeMapStart,       (uintptr_t) map);
    debug_code(kIOHibernateRestoreCodeMapEnd,         ptoa_64(lastMapPage));

    // knock all the image pages to be used out of free map
    for (ppnum = atop_32((uintptr_t) header); ppnum <= lastImagePage; ppnum++)
    {
	hibernate_page_bitset(map, FALSE, ppnum);
    }

    nextFree = 0;
    hibernate_page_list_grab(map, &nextFree);
    buffer = (uint32_t *) (uintptr_t) ptoa_32(hibernate_page_list_grab(map, &nextFree));

    if (header->memoryMapSize && (count = header->memoryMapOffset))
    {
	p4 = (void *)(((uintptr_t) header) - count);
	gIOHibernateWakeMap     = hibernate_page_list_grab(map, &nextFree);
	gIOHibernateWakeMapSize = header->memoryMapSize;
	debug_code(kIOHibernateRestoreCodeWakeMapSize, gIOHibernateWakeMapSize);
	if (gIOHibernateWakeMapSize > PAGE_SIZE)
	    fatal();
	bcopy_internal(p4, (void  *) (uintptr_t) ptoa_32(gIOHibernateWakeMap), gIOHibernateWakeMapSize);
    }
    else
	gIOHibernateWakeMapSize = 0;

    sum = gIOHibernateCurrentHeader->actualRestore1Sum;
    gIOHibernateCurrentHeader->diag[0] = (uint32_t)(uintptr_t) header;
    gIOHibernateCurrentHeader->diag[1] = sum;

    uncompressedPages = 0;
    conflictCount     = 0;
    copyPageListHead  = 0;
    copyPageList      = 0;
    copyPageIndex     = PAGE_SIZE >> 2;

    compressedSize    = PAGE_SIZE;

    while (1)
    {
        if (pageIndexSource)
        {
            ppnum = pageIndexSource[0];
            count = pageIndexSource[1];
            pageIndexSource += 2;
            if (!count)
            {
                pageIndexSource = 0;
                src =  (uint32_t *) (((uintptr_t) map) + gIOHibernateCurrentHeader->bitmapSize);
                ppnum = src[0];
                count = src[1];
                src += 2;
            } 
        }
        else
        {
            ppnum = src[0];
            count = src[1];
            if (!count)
                break;
            src += 2;
	}

	for (page = 0; page < count; page++, ppnum++)
	{
            uint32_t tag;
	    int conflicts;

            if (!pageIndexSource)
            {
                tag = *src++;
                compressedSize = kIOHibernateTagLength & tag;
            }

	    conflicts = (((ppnum >= atop_32((uintptr_t) map)) && (ppnum <= lastMapPage))
		      || ((ppnum >= atop_32((uintptr_t) src)) && (ppnum <= lastImagePage)));

            if (pageIndexSource)
                conflicts |= ((ppnum >= atop_32((uintptr_t) pageIndexSource)) && (ppnum <= lastPageIndexPage));

	    if (!conflicts)
	    {
		if (compressedSize)
		    sum += store_one_page(gIOHibernateCurrentHeader->processorFlags,
					    src, compressedSize, buffer, ppnum);
		uncompressedPages++;
	    }
	    else
	    {
		uint32_t   bufferPage;
		uint32_t * dst;

//		debug_code(kIOHibernateRestoreCodeConflictPage,   ppnum);
//		debug_code(kIOHibernateRestoreCodeConflictSource, (uintptr_t) src);

		conflictCount++;

		// alloc new buffer page
		bufferPage = hibernate_page_list_grab(map, &nextFree);

		if (copyPageIndex > ((PAGE_SIZE >> 2) - 3))
		{
		    // alloc new copy list page
		    uint32_t pageListPage = hibernate_page_list_grab(map, &nextFree);
		    // link to current
		    if (copyPageList)
			copyPageList[1] = pageListPage;
		    else
			copyPageListHead = pageListPage;
		    copyPageList = (uint32_t *) (uintptr_t) ptoa_32(pageListPage);
		    copyPageList[1] = 0;
		    copyPageIndex = 2;
		}

		copyPageList[copyPageIndex++] = ppnum;
		copyPageList[copyPageIndex++] = bufferPage;
		copyPageList[copyPageIndex++] = compressedSize;
		copyPageList[0] = copyPageIndex;

		dst = (uint32_t *) (uintptr_t) ptoa_32(bufferPage);
		for (idx = 0; idx < ((compressedSize + 3) >> 2); idx++)
		    dst[idx] = src[idx];
	    }
	    src += ((compressedSize + 3) >> 2);
	}
    }

    // -- copy back conflicts

    copyPageList = (uint32_t *)(uintptr_t) ptoa_32(copyPageListHead);
    while (copyPageList)
    {
	for (copyPageIndex = 2; copyPageIndex < copyPageList[0]; copyPageIndex += 3)
	{
	    ppnum	   =              copyPageList[copyPageIndex + 0];
	    src		   = (uint32_t *) (uintptr_t) ptoa_32(copyPageList[copyPageIndex + 1]);
	    compressedSize =              copyPageList[copyPageIndex + 2];

	    sum += store_one_page(gIOHibernateCurrentHeader->processorFlags,
				    src, compressedSize, buffer, ppnum);
	    uncompressedPages++;
	}
	copyPageList = (uint32_t *) (uintptr_t) ptoa_32(copyPageList[1]);
    }

    // -- image has been destroyed...

    gIOHibernateCurrentHeader->actualImage1Sum         = sum;
    gIOHibernateCurrentHeader->actualUncompressedPages = uncompressedPages;
    gIOHibernateCurrentHeader->conflictCount           = conflictCount;
    gIOHibernateCurrentHeader->nextFree                = nextFree;

    gIOHibernateState = kIOHibernateStateWakingFromHibernate;

#if CONFIG_SLEEP
#if defined(__ppc__)
    typedef void (*ResetProc)(void);
    ResetProc proc;
    proc = (ResetProc) 0x100;
    __asm__ volatile("ori 0, 0, 0" : : );
    proc();
#elif defined(__i386__) || defined(__x86_64__)
    typedef void (*ResetProc)(void);
    ResetProc proc;
    proc = (ResetProc) acpi_wake_prot_entry;
    // flush caches
    __asm__("wbinvd");
    proc();
#else
// implement me
#endif
#endif

    return -1;
}
