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


#ifndef _IOKIT_KERNELINTERNAL_H
#define _IOKIT_KERNELINTERNAL_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <vm/pmap.h>
#include <mach/memory_object_types.h>
#include <device/device_port.h>

typedef kern_return_t (*IOIteratePageableMapsCallback)(vm_map_t map, void * ref);

void IOLibInit(void);
kern_return_t IOIteratePageableMaps(vm_size_t size,
                    IOIteratePageableMapsCallback callback, void * ref);
vm_map_t IOPageableMapForAddress( vm_address_t address );
SInt32 OSKernelStackRemaining( void );

mach_vm_address_t
IOKernelAllocateContiguous(mach_vm_size_t size, mach_vm_size_t alignment);
void
IOKernelFreeContiguous(mach_vm_address_t address, mach_vm_size_t size);

extern vm_size_t debug_iomallocpageable_size;

// osfmk/device/iokit_rpc.c
// LP64todo - these need to expand 
extern kern_return_t IOMapPages(vm_map_t map, mach_vm_address_t va, mach_vm_address_t pa,
			mach_vm_size_t length, unsigned int options);
extern kern_return_t IOUnmapPages(vm_map_t map, mach_vm_address_t va, mach_vm_size_t length);

extern kern_return_t IOProtectCacheMode(vm_map_t map, mach_vm_address_t va,
					mach_vm_size_t length, unsigned int mapFlags);

extern ppnum_t IOGetLastPageNumber(void);

extern ppnum_t gIOLastPage;

/* Physical to physical copy (ints must be disabled) */
extern void bcopy_phys(addr64_t from, addr64_t to, int size);

__END_DECLS

// Used for dedicated communications for IODMACommand
enum  {
    kIOMDWalkSegments         = 0x00000001,
    kIOMDFirstSegment	      = 0x00000002 | kIOMDWalkSegments,
    kIOMDGetCharacteristics   = 0x00000004,
    kIOMDLastDMACommandOperation
};
struct IOMDDMACharacteristics {
    UInt64 fLength;
    UInt32 fSGCount;
    UInt32 fPages;
    UInt32 fPageAlign;
    ppnum_t fHighestPage;
    IODirection fDirection;
    UInt8 fIsMapped, fIsPrepared;
};
struct IOMDDMAWalkSegmentArgs {
    UInt64 fOffset;			// Input/Output offset
    UInt64 fIOVMAddr, fLength;		// Output variables
    UInt8 fMapped;			// Input Variable, Require mapped IOVMA
};
typedef UInt8 IOMDDMAWalkSegmentState[128];

#endif /* ! _IOKIT_KERNELINTERNAL_H */
