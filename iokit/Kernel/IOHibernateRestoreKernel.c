/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOLib.h>
#include <pexpert/boot.h>
#include <crypto/aes.h>

#include "WKdm.h"
#include "IOHibernateInternal.h"

/*
This code is linked into the kernel but part of the "__HIB" section, which means
its used by code running in the special context of restoring the kernel text and data
from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
it calls or references needs to be careful to only touch memory also in the "__HIB" section.
*/

uint32_t gIOHibernateState;

static IOHibernateImageHeader _hibernateHeader;
IOHibernateImageHeader * gIOHibernateCurrentHeader = &_hibernateHeader;

static hibernate_graphics_t _hibernateGraphics;
hibernate_graphics_t * gIOHibernateGraphicsInfo = &_hibernateGraphics;

static hibernate_cryptwakevars_t _cryptWakeVars;
hibernate_cryptwakevars_t * gIOHibernateCryptWakeVars = &_cryptWakeVars;

vm_offset_t gIOHibernateWakeMap;    	    // ppnum
vm_size_t   gIOHibernateWakeMapSize;

#if __i386__
extern void   acpi_wake_prot_entry(void);
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define BASE 65521L /* largest prime smaller than 65536 */
#define NMAX 5000  
// NMAX (was 5521) the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

uint32_t
hibernate_sum(uint8_t *buf, int32_t len)
{
    unsigned long s1 = 1; // adler & 0xffff;
    unsigned long s2 = 0; // (adler >> 16) & 0xffff;
    int k;

    while (len > 0) {
        k = len < NMAX ? len : NMAX;
        len -= k;
        while (k >= 16) {
            DO16(buf);
	    buf += 16;
            k -= 16;
        }
        if (k != 0) do {
            s1 += *buf++;
	    s2 += s1;
        } while (--k);
        s1 %= BASE;
        s2 %= BASE;
    }
    return (s2 << 16) | s1;
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
	bitmap = 0;
	
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
	bitmap = 0;
	
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
	IOPanic(__FUNCTION__);

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
	buffer = (uint32_t *) (uint32_t) dst;

    if (compressedSize != PAGE_SIZE)
    {
	WKdm_decompress((WK_word*) src, (WK_word*) buffer, PAGE_SIZE >> 2);
	src = buffer;
    }

    sum = hibernate_sum((uint8_t *) src, PAGE_SIZE);

    if (((uint64_t) (uint32_t) src) == dst)
	src = 0;

    hibernate_restore_phys_page((uint64_t) (uint32_t) src, dst, PAGE_SIZE, procFlags);

    return (sum);
}

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
    typedef void (*ResetProc)(void);
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
                sizeof(hibernate_cryptvars_t));

    src = (uint32_t *)
                (((uint32_t) &header->fileExtentMap[0]) 
                            + header->fileExtentMapSize 
                            + ptoa_32(header->restore1PageCount));

    if (header->previewSize)
    {
        pageIndexSource = src;
        map = (hibernate_page_list_t *)(((uint32_t) pageIndexSource) + header->previewSize);
        src = (uint32_t *) (((uint32_t) pageIndexSource) + header->previewPageListSize);
    }
    else
    {
        pageIndexSource = 0;
        map = (hibernate_page_list_t *) src;
        src = (uint32_t *) (((uint32_t) map) + header->bitmapSize);
    }

    lastPageIndexPage = atop_32(src);

    lastImagePage = atop_32(((uint32_t) header) + header->image1Size);

    lastMapPage = atop_32(((uint32_t) map) + header->bitmapSize);

    // knock all the image pages to be used out of free map
    for (ppnum = atop_32(header); ppnum <= lastImagePage; ppnum++)
    {
	hibernate_page_bitset(map, FALSE, ppnum);
    }

    nextFree = 0;
    hibernate_page_list_grab(map, &nextFree);
    buffer = (uint32_t *) ptoa_32(hibernate_page_list_grab(map, &nextFree));

    if (header->memoryMapSize && (count = header->memoryMapOffset))
    {
	p4 = (void *)(((uintptr_t) header) - count);
	gIOHibernateWakeMap     = hibernate_page_list_grab(map, &nextFree);
	gIOHibernateWakeMapSize = header->memoryMapSize;
	bcopy_internal(p4, (void  *) ptoa_32(gIOHibernateWakeMap), gIOHibernateWakeMapSize);
    }
    else
	gIOHibernateWakeMapSize = 0;

    sum = gIOHibernateCurrentHeader->actualRestore1Sum;
    gIOHibernateCurrentHeader->diag[0] = (uint32_t) header;
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
                src =  (uint32_t *) (((uint32_t) map) + gIOHibernateCurrentHeader->bitmapSize);
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

//    SINT(ppnum);

	    conflicts = (((ppnum >= atop_32(map)) && (ppnum <= lastMapPage))
		      || ((ppnum >= atop_32(src)) && (ppnum <= lastImagePage)));

            if (pageIndexSource)
                conflicts |= ((ppnum >= atop_32(pageIndexSource)) && (ppnum <= lastPageIndexPage));

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
		    copyPageList = (uint32_t *) ptoa_32(pageListPage);
		    copyPageList[1] = 0;
		    copyPageIndex = 2;
		}

		copyPageList[copyPageIndex++] = ppnum;
		copyPageList[copyPageIndex++] = bufferPage;
		copyPageList[copyPageIndex++] = compressedSize;
		copyPageList[0] = copyPageIndex;

		dst = (uint32_t *) ptoa_32(bufferPage);
		for (idx = 0; idx < ((compressedSize + 3) >> 2); idx++)
		    dst[idx] = src[idx];
	    }
	    src += ((compressedSize + 3) >> 2);
	}
    }

    // -- copy back conflicts

    copyPageList = (uint32_t *) ptoa_32(copyPageListHead);
    while (copyPageList)
    {
	for (copyPageIndex = 2; copyPageIndex < copyPageList[0]; copyPageIndex += 3)
	{
	    ppnum	   =              copyPageList[copyPageIndex + 0];
	    src		   = (uint32_t *) ptoa_32(copyPageList[copyPageIndex + 1]);
	    compressedSize =              copyPageList[copyPageIndex + 2];

	    sum += store_one_page(gIOHibernateCurrentHeader->processorFlags,
				    src, compressedSize, buffer, ppnum);
	    uncompressedPages++;
	}
	copyPageList = (uint32_t *) ptoa_32(copyPageList[1]);
    }

    // -- image has been destroyed...

    gIOHibernateCurrentHeader->actualImage1Sum         = sum;
    gIOHibernateCurrentHeader->actualUncompressedPages = uncompressedPages;
    gIOHibernateCurrentHeader->conflictCount           = conflictCount;
    gIOHibernateCurrentHeader->nextFree                = nextFree;

    gIOHibernateState = kIOHibernateStateWakingFromHibernate;

#if __ppc__
    ResetProc proc;
    proc = (ResetProc) 0x100;
    __asm__ volatile("ori 0, 0, 0" : : );
    proc();
#elif __i386__
    ResetProc proc;
    proc = (ResetProc) acpi_wake_prot_entry;
    // flush caches
    __asm__("wbinvd");
    proc();
#endif
  
    return -1;
}

