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
 */

#ifndef __IOKIT_IOLIB_H
#define __IOKIT_IOLIB_H

#ifndef KERNEL
#error IOLib.h is for kernel use only
#endif

#ifndef IOKIT_DEPRECATED
#define IOKIT_DEPRECATED	1
#endif

#include <IOKit/system.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOLocks.h>

#include <libkern/OSAtomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <kern/thread_call.h>
#include <kern/clock.h>
/*
 * min/max macros.
 */

#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

/*
 * These are opaque to the user.
 */
typedef thread_t IOThread;
typedef void (*IOThreadFunc)(void *argument);

/*
 * Memory allocation functions.
 */

/*! @function IOMalloc
    @abstract Allocates general purpose, wired memory in the kernel map.
    @discussion This is a general purpose utility to allocate memory in the kernel. There are no alignment guarantees given on the returned memory, and alignment may vary depending on the kernel configuration. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param size Size of the memory requested.
    @result Pointer to the allocated memory, or zero on failure. */

void * IOMalloc(vm_size_t size);

/*! @function IOFree
    @abstract Frees memory allocated with IOMalloc.
    @discussion This function frees memory allocated with IOMalloc, it may block and so should not be called from interrupt level or while a simple lock is held.
    @param address Pointer to the allocated memory.
    @param size Size of the memory allocated. */

void   IOFree(void * address, vm_size_t size);

/*! @function IOMallocAligned
    @abstract Allocates wired memory in the kernel map, with an alignment restriction.
    @discussion This is a utility to allocate memory in the kernel, with an alignment restriction which is specified as a byte count. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param size Size of the memory requested.
    @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bit 0-7 zero.
    @result Pointer to the allocated memory, or zero on failure. */

void * IOMallocAligned(vm_size_t size, vm_offset_t alignment);

/*! @function IOFreeAligned
    @abstract Frees memory allocated with IOMallocAligned.
    @discussion This function frees memory allocated with IOMallocAligned, it may block and so should not be called from interrupt level or while a simple lock is held.
    @param address Pointer to the allocated memory.
    @param size Size of the memory allocated. */

void   IOFreeAligned(void * address, vm_size_t size);

/*! @function IOMallocContiguous
    @abstract Allocates wired memory in the kernel map, with an alignment restriction and physically contiguous.
    @discussion This is a utility to allocate memory in the kernel, with an alignment restriction which is specified as a byte count, and will allocate only physically contiguous memory. The request may fail if memory is fragmented, and may cause large amounts of paging activity. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param size Size of the memory requested.
    @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
    @param physicalAddress IOMallocContiguous returns the physical address of the allocated memory here, if physicalAddress is a non-zero pointer.
    @result Virtual address of the allocated memory, or zero on failure. */

void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
			   IOPhysicalAddress * physicalAddress);

/*! @function IOFreeContiguous
    @abstract Frees memory allocated with IOMallocContiguous.
    @discussion This function frees memory allocated with IOMallocContiguous, it may block and so should not be called from interrupt level or while a simple lock is held.
    @param address Virtual address of the allocated memory.
    @param size Size of the memory allocated. */

void   IOFreeContiguous(void * address, vm_size_t size);


/*! @function IOMallocPageable
    @abstract Allocates pageable memory in the kernel map.
    @discussion This is a utility to allocate pageable memory in the kernel. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param size Size of the memory requested.
    @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
    @result Pointer to the allocated memory, or zero on failure. */

void * IOMallocPageable(vm_size_t size, vm_size_t alignment);

/*! @function IOFreePageable
    @abstract Frees memory allocated with IOMallocPageable.
    @discussion This function frees memory allocated with IOMallocPageable, it may block and so should not be called from interrupt level or while a simple lock is held.
    @param address Virtual address of the allocated memory.
    @param size Size of the memory allocated. */

void IOFreePageable(void * address, vm_size_t size);

/*
 * Typed memory allocation macros. Both may block.
 */
#define IONew(type,number)        (type*)IOMalloc(sizeof(type) * (number) )
#define IODelete(ptr,type,number) IOFree( (ptr) , sizeof(type) * (number) )

/*! @function IOSetProcessorCacheMode
    @abstract Sets the processor cache mode for mapped memory.
    @discussion This function sets the cache mode of an already mapped & wired memory range. Note this may not be supported on I/O mappings or shared memory - it is far preferable to set the cache mode as mappings are created with the IOMemoryDescriptor::map method.
    @param task Task the memory is mapped into.
    @param address Virtual address of the memory.
    @param length Length of the range to set.
    @param cacheMode A constant from IOTypes.h, <br>
	kIOMapDefaultCache to inhibit the cache in I/O areas, kIOMapCopybackCache in general purpose RAM.<br>
	kIOMapInhibitCache, kIOMapWriteThruCache, kIOMapCopybackCache to set the appropriate caching.<br> 
    @result An IOReturn code.*/

IOReturn IOSetProcessorCacheMode( task_t task, IOVirtualAddress address,
				  IOByteCount length, IOOptionBits cacheMode );

/*! @function IOFlushProcessorCache
    @abstract Flushes the processor cache for mapped memory.
    @discussion This function flushes the processor cache of an already mapped memory range. Note in most cases it is preferable to use IOMemoryDescriptor::prepare and complete to manage cache coherency since they are aware of the architecture's requirements. Flushing the processor cache is not required for coherency in most situations.
    @param task Task the memory is mapped into.
    @param address Virtual address of the memory.
    @param length Length of the range to set.
    @result An IOReturn code. */

IOReturn IOFlushProcessorCache( task_t task, IOVirtualAddress address,
				  IOByteCount length );

/*! @function IOThreadSelf
    @abstract Returns the osfmk identifier for the currently running thread.
    @discussion This function returns the current thread (a pointer to the currently active osfmk thread_shuttle). */

#define IOThreadSelf() (current_thread())

/*! @function IOCreateThread
    @abstract Create a kernel thread.
    @discussion This function creates a kernel thread, and passes the caller supplied argument to the new thread.
    @param function A C-function pointer where the thread will begin execution.
    @param argument Caller specified data to be passed to the new thread.
    @result An IOThread identifier for the new thread, equivalent to an osfmk thread_t. */

IOThread IOCreateThread(IOThreadFunc function, void *argument);

/*! @function IOExitThread
    @abstract Terminate exceution of current thread.
    @discussion This function destroys the currently running thread, and does not return. */

volatile void IOExitThread();

/*! @function IOSleep
    @abstract Sleep the calling thread for a number of milliseconds.
    @discussion This function blocks the calling thread for at least the number of specified milliseconds, giving time to other processes.
    @param milliseconds The integer number of milliseconds to wait. */

void IOSleep(unsigned milliseconds);

/*! @function IODelay
    @abstract Spin delay for a number of microseconds.
    @discussion This function spins to delay for at least the number of specified microseconds. Since the CPU is busy spinning no time is made available to other processes; this method of delay should be used only for short periods. Also, the AbsoluteTime based APIs of kern/clock.h provide finer grained and lower cost delays.
    @param microseconds The integer number of microseconds to spin wait. */

void IODelay(unsigned microseconds);

/*! @function IOLog
    @abstract Log a message to console in text mode, and /var/log/system.log.
    @discussion This function allows a driver to log diagnostic information to the screen during verbose boots, and to a log file found at /var/log/system.log. IOLog should not be called from interrupt context.
    @param format A printf() style format string (see printf() documentation).
    @param other arguments described by the format string. */

void IOLog(const char *format, ...)
__attribute__((format(printf, 1, 2)));

void kprintf(const char *format, ...);

/*
 * Convert a integer constant (typically a #define or enum) to a string
 * via an array of IONamedValue.
 */
const char *IOFindNameForValue(int value, 
	const IONamedValue *namedValueArray);

/*
 * Convert a string to an int via an array of IONamedValue. Returns
 * kIOReturnSuccess of string found, else returns kIOReturnBadArgument.
 */
IOReturn IOFindValueForName(const char *string, 
	const IONamedValue *regValueArray,
	int *value);				/* RETURNED */

/*! @function Debugger
    @abstract Enter the kernel debugger.
    @discussion This function freezes the kernel and enters the builtin debugger. It may not be possible to exit the debugger without a second machine.
    @param reason A C-string to describe why the debugger is being entered. */
 
void Debugger(const char * reason);

struct OSDictionary * IOBSDNameMatching( const char * name );
struct OSDictionary * IOOFPathMatching( const char * path, char * buf, int maxLen );

/*
 * Convert between size and a power-of-two alignment.
 */
IOAlignment IOSizeToAlignment(unsigned int size);
unsigned int IOAlignmentToSize(IOAlignment align);

/*
 * Multiply and divide routines for IOFixed datatype.
 */

static inline IOFixed IOFixedMultiply(IOFixed a, IOFixed b)
{
    return (IOFixed)((((SInt64) a) * ((SInt64) b)) >> 16);
}

static inline IOFixed IOFixedDivide(IOFixed a, IOFixed b)
{
    return (IOFixed)((((SInt64) a) << 16) / ((SInt64) b));
}

/*
 * IORound and IOTrunc convenience functions, in the spirit
 * of vm's round_page() and trunc_page().
 */
#define IORound(value,multiple) \
        ((((value) + (multiple) - 1) / (multiple)) * (multiple))

#define IOTrunc(value,multiple) \
        (((value) / (multiple)) * (multiple));


#if IOKIT_DEPRECATED

/* The following API is deprecated */

#undef eieio
#define eieio() \
    OSSynchronizeIO()

void IOPanic(const char *reason);

/* The AbsoluteTime clock API exported by kern/clock.h
   should be used for high resolution timing. */

void IOGetTime( mach_timespec_t * clock_time);

extern mach_timespec_t IOZeroTvalspec;

#endif /* IOKIT_DEPRECATED */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__IOKIT_IOLIB_H */
