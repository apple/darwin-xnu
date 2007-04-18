/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

// NOTE:  This file is only c++ so I can get static initialisers going
#include <libkern/OSDebug.h>

#include <sys/cdefs.h>

#include <stdarg.h>
#include <mach/mach_types.h>
#include <mach/kmod.h>
#include <kern/lock.h>

#include <libkern/libkern.h>	// From bsd's libkern directory
#include <mach/vm_param.h>

__BEGIN_DECLS
// From osmfk/kern/thread.h but considered to be private
extern vm_offset_t min_valid_stack_address(void);
extern vm_offset_t max_valid_stack_address(void);

// From osfmk/kmod.c
extern void kmod_dump_log(vm_offset_t *addr, unsigned int cnt);

extern addr64_t kvtophys(vm_offset_t va);
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

#if __i386__
#define i386_RETURN_OFFSET 4

static unsigned int
i386_validate_stackptr(vm_offset_t stackptr)
{
	/* Existence and alignment check
	 */
	if (!stackptr || (stackptr & 0x3))
		return 0;
  
	/* Is a virtual->physical translation present?
	 */
	if (!kvtophys(stackptr))
		return 0;
  
	/* Check if the return address lies on the same page;
	 * If not, verify that a translation exists.
	 */
	if (((PAGE_SIZE - (stackptr & PAGE_MASK)) < i386_RETURN_OFFSET) &&
	    !kvtophys(stackptr + i386_RETURN_OFFSET))
		return 0;
	return 1;
}

static unsigned int
i386_validate_raddr(vm_offset_t raddr)
{
	return ((raddr > VM_MIN_KERNEL_ADDRESS) &&
	    (raddr < VM_MAX_KERNEL_ADDRESS));
}
#endif

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
#elif __i386__
#define SANE_i386_FRAME_SIZE 8*1024
    vm_offset_t stackptr, stackptr_prev, raddr;
    unsigned frame_index = 0;
/* Obtain current frame pointer */
    __asm__ volatile("movl %%ebp, %0" : "=m" (stackptr)); 

    if (!i386_validate_stackptr(stackptr))
	    goto pad;

    raddr = *((vm_offset_t *) (stackptr + i386_RETURN_OFFSET));

    if (!i386_validate_raddr(raddr))
	    goto pad;

    bt[frame_index++] = (void *) raddr;

    for ( ; frame_index < maxAddrs; frame_index++) {
	    stackptr_prev = stackptr;
	    stackptr = *((vm_offset_t *) stackptr_prev);

	    if (!i386_validate_stackptr(stackptr))
		    break;
	/* Stack grows downwards */
	    if (stackptr < stackptr_prev)
		    break;

	    if ((stackptr_prev ^ stackptr) > SANE_i386_FRAME_SIZE)
		    break;

	    raddr = *((vm_offset_t *) (stackptr + i386_RETURN_OFFSET));

	    if (!i386_validate_raddr(raddr))
		    break;

	    bt[frame_index] = (void *) raddr;
    }
pad:
    frame = frame_index;

    for ( ; frame_index < maxAddrs; frame_index++)
	    bt[frame_index] = (void *) 0;
#else
#error arch
#endif
    return frame;
}
