/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
vm_map_t IOPageableMapForAddress(uintptr_t address);

kern_return_t 
IOMemoryDescriptorMapMemEntry(vm_map_t map, ipc_port_t entry, IOOptionBits options, bool pageable,
				mach_vm_size_t offset, mach_vm_address_t * address, mach_vm_size_t length);
kern_return_t 
IOMemoryDescriptorMapCopy(vm_map_t map, 
				vm_map_t src_map, 
				mach_vm_offset_t src_address,
				IOOptionBits options,
				mach_vm_size_t offset, 
				mach_vm_address_t * address, mach_vm_size_t length);

mach_vm_address_t
IOKernelAllocateContiguous(mach_vm_size_t size,
			    mach_vm_address_t maxPhys, mach_vm_size_t alignment);
void
IOKernelFreeContiguous(mach_vm_address_t address, mach_vm_size_t size);

extern vm_size_t debug_iomallocpageable_size;

// osfmk/device/iokit_rpc.c
extern kern_return_t IOMapPages(vm_map_t map, mach_vm_address_t va, mach_vm_address_t pa,
                                 mach_vm_size_t length, unsigned int mapFlags);
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
    kIOMDSetDMAActive         = 0x00000005,
    kIOMDSetDMAInactive       = 0x00000006,
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

struct IODMACommandInternal
{
    IOMDDMAWalkSegmentState fState;
    IOMDDMACharacteristics  fMDSummary;

    UInt64 fPreparedOffset;
    UInt64 fPreparedLength;

	UInt32 fSourceAlignMask;
	
    UInt8  fCursor;
    UInt8  fCheckAddressing;
    UInt8  fIterateOnly;
    UInt8  fMisaligned;
    UInt8  fMapContig;
    UInt8  fPrepared;
    UInt8  fDoubleBuffer;
    UInt8  fNewMD;
    UInt8  fLocalMapper;
	
	ppnum_t  fCopyMapperPageAlloc;
    ppnum_t  fCopyPageCount;
    ppnum_t  fNextRemapIndex;
    addr64_t fCopyNext;

	ppnum_t  fLocalMapperPageAlloc;
    ppnum_t  fLocalMapperPageCount;

    class IOBufferMemoryDescriptor * fCopyMD;

    // IODMAEventSource use
    IOReturn fStatus;
    UInt64   fActualByteCount;
};

extern "C" struct timeval gIOLastSleepTime;
extern "C" struct timeval gIOLastWakeTime;

extern "C" void IOKitResetTime( void );
extern "C" void IOKitInitializeTime( void );

extern "C" OSString * IOCopyLogNameForPID(int pid);

#endif /* ! _IOKIT_KERNELINTERNAL_H */
