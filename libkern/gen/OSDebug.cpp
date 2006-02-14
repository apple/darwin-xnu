/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

// NOTE:  This file is only c++ so I can get static initialisers going
#include <libkern/OSDebug.h>

#include <sys/cdefs.h>

#include <stdarg.h>
#include <mach/mach_types.h>
#include <mach/kmod.h>
#include <kern/lock.h>

#include <libkern/libkern.h>	// From bsd's libkern directory

__BEGIN_DECLS
// From osmfk/kern/thread.h but considered to be private
extern vm_offset_t min_valid_stack_address(void);
extern vm_offset_t max_valid_stack_address(void);

// From osfmk/kmod.c
extern void kmod_dump_log(vm_offset_t *addr, unsigned int cnt);
__END_DECLS

static mutex_t *sOSReportLock = mutex_alloc(0);

/* Report a message with a 4 entry backtrace - very slow */
void
OSReportWithBacktrace(const char *str, ...)
{
    char buf[128];
    void *bt[9];
    const unsigned cnt = sizeof(bt) / sizeof(bt[0]);
    va_list listp;

    // Ignore the our and our callers stackframes, skipping frames 0 & 1
    (void) OSBacktrace(bt, cnt);

    va_start(listp, str);
    vsnprintf(buf, sizeof(buf), str, listp);
    va_end(listp);

    mutex_lock(sOSReportLock);
    {
	printf("%s\nBacktrace %p %p %p %p %p %p %p\n",
		buf, bt[2], bt[3], bt[4], bt[5], bt[6], bt[7], bt[8]);
	kmod_dump_log((vm_offset_t *) &bt[2], cnt - 2);
    }
    mutex_unlock(sOSReportLock);
}

static vm_offset_t minstackaddr = min_valid_stack_address();
static vm_offset_t maxstackaddr = max_valid_stack_address();

unsigned OSBacktrace(void **bt, unsigned maxAddrs)
{
    unsigned frame;

#if __ppc__
    vm_offset_t stackptr, stackptr_prev;
    const vm_offset_t * const mem = (vm_offset_t *) 0;
    unsigned i = 0;

    __asm__ volatile("mflr %0" : "=r" (stackptr)); 
    bt[i++] = (void *) stackptr;

    __asm__ volatile("mr %0,r1" : "=r" (stackptr)); 
    for ( ; i < maxAddrs; i++) {
	// Validate we have a reasonable stackptr
	if ( !(minstackaddr <= stackptr && stackptr < maxstackaddr)
	|| (stackptr & 3))
	    break;

	stackptr_prev = stackptr;
	stackptr = mem[stackptr_prev >> 2];
	if ((stackptr_prev ^ stackptr) > 8 * 1024)	// Sanity check
	    break;

	vm_offset_t addr = mem[(stackptr >> 2) + 2]; 
	if ((addr & 3) || (addr < 0x8000))	// More sanity checks
	    break;
	bt[i] = (void *) addr;
    }
    frame = i;

    for ( ; i < maxAddrs; i++)
	    bt[i] = (void *) 0;
#elif 0 && __i386__	// Note that this should be ported for i386
    // This function is not safe, we should get this code ported appropriately
    if (maxAddrs > 16) {
	for (frame = 16; frame < maxAddrs; frame++)
	    bt[frame] = __builtin_return_address(frame);
	maxAddrs = 16;
    }

    switch(maxAddrs) {
    case 15+1: bt[15] = __builtin_return_address(15);
    case 14+1: bt[14] = __builtin_return_address(14);
    case 13+1: bt[13] = __builtin_return_address(13);
    case 12+1: bt[12] = __builtin_return_address(12);
    case 11+1: bt[11] = __builtin_return_address(11);
    case 10+1: bt[10] = __builtin_return_address(10);
    case  9+1: bt[ 9] = __builtin_return_address( 9);
    case  8+1: bt[ 8] = __builtin_return_address( 8);
    case  7+1: bt[ 7] = __builtin_return_address( 7);
    case  6+1: bt[ 6] = __builtin_return_address( 6);
    case  5+1: bt[ 5] = __builtin_return_address( 5);
    case  4+1: bt[ 4] = __builtin_return_address( 4);
    case  3+1: bt[ 3] = __builtin_return_address( 3);
    case  2+1: bt[ 2] = __builtin_return_address( 2);
    case  1+1: bt[ 1] = __builtin_return_address( 1);
    case  0+1: bt[ 0] = __builtin_return_address( 0);
    case 0: default: break;
    }

    frame = maxAddrs;
#else
    // This function is not safe, we should get this code ported appropriately
    if (maxAddrs > 16) {
	for (frame = 16; frame < maxAddrs; frame++)
	    bt[frame] = 0;
	maxAddrs = 16;
    }

    switch (maxAddrs) {
    case 15+1: bt[15] = __builtin_return_address(15);
    case 14+1: bt[14] = __builtin_return_address(14);
    case 13+1: bt[13] = __builtin_return_address(13);
    case 12+1: bt[12] = __builtin_return_address(12);
    case 11+1: bt[11] = __builtin_return_address(11);
    case 10+1: bt[10] = __builtin_return_address(10);
    case  9+1: bt[ 9] = __builtin_return_address( 9);
    case  8+1: bt[ 8] = __builtin_return_address( 8);
    case  7+1: bt[ 7] = __builtin_return_address( 7);
    case  6+1: bt[ 6] = __builtin_return_address( 6);
    case  5+1: bt[ 5] = __builtin_return_address( 5);
    case  4+1: bt[ 4] = __builtin_return_address( 4);
    case  3+1: bt[ 3] = __builtin_return_address( 3);
    case  2+1: bt[ 2] = __builtin_return_address( 2);
    case  1+1: bt[ 1] = __builtin_return_address( 1);
    case  0+1: bt[ 0] = __builtin_return_address( 0);
    case    0:
    default  :
	break;
    }

    frame = maxAddrs;
#endif

    return frame;
}
