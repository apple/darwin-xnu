/*
 * Copyright (c) 1998-2016 Apple Inc. All rights reserved.
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


#include <sys/cdefs.h>

#include <IOKit/assert.h>
#include <IOKit/system.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOKitKeysPrivate.h>

#include <IOKit/IOSubMemoryDescriptor.h>
#include <IOKit/IOMultiMemoryDescriptor.h>

#include <IOKit/IOKitDebug.h>
#include <libkern/OSDebug.h>
#include <libkern/OSKextLibPrivate.h>

#include "IOKitKernelInternal.h"

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSNumber.h>
#include <os/overflow.h>

#include <sys/uio.h>

__BEGIN_DECLS
#include <vm/pmap.h>
#include <vm/vm_pageout.h>
#include <mach/memory_object_types.h>
#include <device/device_port.h>

#include <mach/vm_prot.h>
#include <mach/mach_vm.h>
#include <mach/memory_entry.h>
#include <vm/vm_fault.h>
#include <vm/vm_protos.h>

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern void ipc_port_release_send(ipc_port_t port);

__END_DECLS

#define kIOMapperWaitSystem     ((IOMapper *) 1)

static IOMapper * gIOSystemMapper = NULL;

ppnum_t           gIOLastPage;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors( IOMemoryDescriptor, OSObject )

#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOGeneralMemoryDescriptor, IOMemoryDescriptor)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IORecursiveLock * gIOMemoryLock;

#define LOCK    IORecursiveLockLock( gIOMemoryLock)
#define UNLOCK  IORecursiveLockUnlock( gIOMemoryLock)
#define SLEEP   IORecursiveLockSleep( gIOMemoryLock, (void *)this, THREAD_UNINT)
#define WAKEUP  \
    IORecursiveLockWakeup( gIOMemoryLock, (void *)this, /* one-thread */ false)

#if 0
#define DEBG(fmt, args...)      { kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)      {}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Some data structures and accessor macros used by the initWithOptions
// Function

enum ioPLBlockFlags {
	kIOPLOnDevice  = 0x00000001,
	kIOPLExternUPL = 0x00000002,
};

struct IOMDPersistentInitData {
	const IOGeneralMemoryDescriptor * fMD;
	IOMemoryReference               * fMemRef;
};

struct ioPLBlock {
	upl_t fIOPL;
	vm_address_t fPageInfo; // Pointer to page list or index into it
	uint32_t fIOMDOffset;       // The offset of this iopl in descriptor
	ppnum_t fMappedPage;        // Page number of first page in this iopl
	unsigned int fPageOffset;   // Offset within first page of iopl
	unsigned int fFlags;        // Flags
};

enum { kMaxWireTags = 6 };

struct ioGMDData {
	IOMapper *  fMapper;
	uint64_t    fDMAMapAlignment;
	uint64_t    fMappedBase;
	uint64_t    fMappedLength;
	uint64_t    fPreparationID;
#if IOTRACKING
	IOTracking  fWireTracking;
#endif /* IOTRACKING */
	unsigned int      fPageCnt;
	uint8_t           fDMAMapNumAddressBits;
	unsigned char     fDiscontig:1;
	unsigned char     fCompletionError:1;
	unsigned char     fMappedBaseValid:1;
	unsigned char     _resv:3;
	unsigned char     fDMAAccess:2;

	/* variable length arrays */
	upl_page_info_t fPageList[1]
#if __LP64__
	// align fPageList as for ioPLBlock
	__attribute__((aligned(sizeof(upl_t))))
#endif
	;
	//ioPLBlock fBlocks[1];
};

#define getDataP(osd)   ((ioGMDData *) (osd)->getBytesNoCopy())
#define getIOPLList(d)  ((ioPLBlock *) (void *)&(d->fPageList[d->fPageCnt]))
#define getNumIOPL(osd, d)      \
    (((osd)->getLength() - ((char *) getIOPLList(d) - (char *) d)) / sizeof(ioPLBlock))
#define getPageList(d)  (&(d->fPageList[0]))
#define computeDataSize(p, u) \
    (offsetof(ioGMDData, fPageList) + p * sizeof(upl_page_info_t) + u * sizeof(ioPLBlock))

enum { kIOMemoryHostOrRemote = kIOMemoryHostOnly | kIOMemoryRemote };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define next_page(a) ( trunc_page(a) + PAGE_SIZE )

extern "C" {
kern_return_t
device_data_action(
	uintptr_t               device_handle,
	ipc_port_t              device_pager,
	vm_prot_t               protection,
	vm_object_offset_t      offset,
	vm_size_t               size)
{
	kern_return_t        kr;
	IOMemoryDescriptorReserved * ref = (IOMemoryDescriptorReserved *) device_handle;
	IOMemoryDescriptor * memDesc;

	LOCK;
	memDesc = ref->dp.memory;
	if (memDesc) {
		memDesc->retain();
		kr = memDesc->handleFault(device_pager, offset, size);
		memDesc->release();
	} else {
		kr = KERN_ABORTED;
	}
	UNLOCK;

	return kr;
}

kern_return_t
device_close(
	uintptr_t     device_handle)
{
	IOMemoryDescriptorReserved * ref = (IOMemoryDescriptorReserved *) device_handle;

	IODelete( ref, IOMemoryDescriptorReserved, 1 );

	return kIOReturnSuccess;
}
};      // end extern "C"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Note this inline function uses C++ reference arguments to return values
// This means that pointers are not passed and NULLs don't have to be
// checked for as a NULL reference is illegal.
static inline void
getAddrLenForInd(mach_vm_address_t &addr, mach_vm_size_t &len, // Output variables
    UInt32 type, IOGeneralMemoryDescriptor::Ranges r, UInt32 ind)
{
	assert(kIOMemoryTypeUIO == type
	    || kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type
	    || kIOMemoryTypePhysical == type || kIOMemoryTypePhysical64 == type);
	if (kIOMemoryTypeUIO == type) {
		user_size_t us;
		user_addr_t ad;
		uio_getiov((uio_t) r.uio, ind, &ad, &us); addr = ad; len = us;
	}
#ifndef __LP64__
	else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type)) {
		IOAddressRange cur = r.v64[ind];
		addr = cur.address;
		len  = cur.length;
	}
#endif /* !__LP64__ */
	else {
		IOVirtualRange cur = r.v[ind];
		addr = cur.address;
		len  = cur.length;
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn
purgeableControlBits(IOOptionBits newState, vm_purgable_t * control, int * state)
{
	IOReturn err = kIOReturnSuccess;

	*control = VM_PURGABLE_SET_STATE;

	enum { kIOMemoryPurgeableControlMask = 15 };

	switch (kIOMemoryPurgeableControlMask & newState) {
	case kIOMemoryPurgeableKeepCurrent:
		*control = VM_PURGABLE_GET_STATE;
		break;

	case kIOMemoryPurgeableNonVolatile:
		*state = VM_PURGABLE_NONVOLATILE;
		break;
	case kIOMemoryPurgeableVolatile:
		*state = VM_PURGABLE_VOLATILE | (newState & ~kIOMemoryPurgeableControlMask);
		break;
	case kIOMemoryPurgeableEmpty:
		*state = VM_PURGABLE_EMPTY | (newState & ~kIOMemoryPurgeableControlMask);
		break;
	default:
		err = kIOReturnBadArgument;
		break;
	}

	if (*control == VM_PURGABLE_SET_STATE) {
		// let VM know this call is from the kernel and is allowed to alter
		// the volatility of the memory entry even if it was created with
		// MAP_MEM_PURGABLE_KERNEL_ONLY
		*control = VM_PURGABLE_SET_STATE_FROM_KERNEL;
	}

	return err;
}

static IOReturn
purgeableStateBits(int * state)
{
	IOReturn err = kIOReturnSuccess;

	switch (VM_PURGABLE_STATE_MASK & *state) {
	case VM_PURGABLE_NONVOLATILE:
		*state = kIOMemoryPurgeableNonVolatile;
		break;
	case VM_PURGABLE_VOLATILE:
		*state = kIOMemoryPurgeableVolatile;
		break;
	case VM_PURGABLE_EMPTY:
		*state = kIOMemoryPurgeableEmpty;
		break;
	default:
		*state = kIOMemoryPurgeableNonVolatile;
		err = kIOReturnNotReady;
		break;
	}
	return err;
}

typedef struct {
	unsigned int wimg;
	unsigned int object_type;
} iokit_memtype_entry;

static const iokit_memtype_entry iomd_mem_types[] = {
	[kIODefaultCache] = {VM_WIMG_DEFAULT, MAP_MEM_NOOP},
	[kIOInhibitCache] = {VM_WIMG_IO, MAP_MEM_IO},
	[kIOWriteThruCache] = {VM_WIMG_WTHRU, MAP_MEM_WTHRU},
	[kIOWriteCombineCache] = {VM_WIMG_WCOMB, MAP_MEM_WCOMB},
	[kIOCopybackCache] = {VM_WIMG_COPYBACK, MAP_MEM_COPYBACK},
	[kIOCopybackInnerCache] = {VM_WIMG_INNERWBACK, MAP_MEM_INNERWBACK},
	[kIOPostedWrite] = {VM_WIMG_POSTED, MAP_MEM_POSTED},
	[kIORealTimeCache] = {VM_WIMG_RT, MAP_MEM_RT},
	[kIOPostedReordered] = {VM_WIMG_POSTED_REORDERED, MAP_MEM_POSTED_REORDERED},
	[kIOPostedCombinedReordered] = {VM_WIMG_POSTED_COMBINED_REORDERED, MAP_MEM_POSTED_COMBINED_REORDERED},
};

static vm_prot_t
vmProtForCacheMode(IOOptionBits cacheMode)
{
	assert(cacheMode < (sizeof(iomd_mem_types) / sizeof(iomd_mem_types[0])));
	vm_prot_t prot = 0;
	SET_MAP_MEM(iomd_mem_types[cacheMode].object_type, prot);
	return prot;
}

static unsigned int
pagerFlagsForCacheMode(IOOptionBits cacheMode)
{
	assert(cacheMode < (sizeof(iomd_mem_types) / sizeof(iomd_mem_types[0])));
	if (cacheMode == kIODefaultCache) {
		return -1U;
	}
	return iomd_mem_types[cacheMode].wimg;
}

static IOOptionBits
cacheModeForPagerFlags(unsigned int pagerFlags)
{
	pagerFlags &= VM_WIMG_MASK;
	IOOptionBits cacheMode = kIODefaultCache;
	for (IOOptionBits i = 0; i < (sizeof(iomd_mem_types) / sizeof(iomd_mem_types[0])); ++i) {
		if (iomd_mem_types[i].wimg == pagerFlags) {
			cacheMode = i;
			break;
		}
	}
	return (cacheMode == kIODefaultCache) ? kIOCopybackCache : cacheMode;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOMemoryEntry {
	ipc_port_t entry;
	int64_t    offset;
	uint64_t   size;
};

struct IOMemoryReference {
	volatile SInt32             refCount;
	vm_prot_t                   prot;
	uint32_t                    capacity;
	uint32_t                    count;
	struct IOMemoryReference  * mapRef;
	IOMemoryEntry               entries[0];
};

enum{
	kIOMemoryReferenceReuse = 0x00000001,
	kIOMemoryReferenceWrite = 0x00000002,
	kIOMemoryReferenceCOW   = 0x00000004,
};

SInt32 gIOMemoryReferenceCount;

IOMemoryReference *
IOGeneralMemoryDescriptor::memoryReferenceAlloc(uint32_t capacity, IOMemoryReference * realloc)
{
	IOMemoryReference * ref;
	size_t              newSize, oldSize, copySize;

	newSize = (sizeof(IOMemoryReference)
	    - sizeof(ref->entries)
	    + capacity * sizeof(ref->entries[0]));
	ref = (typeof(ref))IOMalloc(newSize);
	if (realloc) {
		oldSize = (sizeof(IOMemoryReference)
		    - sizeof(realloc->entries)
		    + realloc->capacity * sizeof(realloc->entries[0]));
		copySize = oldSize;
		if (copySize > newSize) {
			copySize = newSize;
		}
		if (ref) {
			bcopy(realloc, ref, copySize);
		}
		IOFree(realloc, oldSize);
	} else if (ref) {
		bzero(ref, sizeof(*ref));
		ref->refCount = 1;
		OSIncrementAtomic(&gIOMemoryReferenceCount);
	}
	if (!ref) {
		return NULL;
	}
	ref->capacity = capacity;
	return ref;
}

void
IOGeneralMemoryDescriptor::memoryReferenceFree(IOMemoryReference * ref)
{
	IOMemoryEntry * entries;
	size_t          size;

	if (ref->mapRef) {
		memoryReferenceFree(ref->mapRef);
		ref->mapRef = NULL;
	}

	entries = ref->entries + ref->count;
	while (entries > &ref->entries[0]) {
		entries--;
		ipc_port_release_send(entries->entry);
	}
	size = (sizeof(IOMemoryReference)
	    - sizeof(ref->entries)
	    + ref->capacity * sizeof(ref->entries[0]));
	IOFree(ref, size);

	OSDecrementAtomic(&gIOMemoryReferenceCount);
}

void
IOGeneralMemoryDescriptor::memoryReferenceRelease(IOMemoryReference * ref)
{
	if (1 == OSDecrementAtomic(&ref->refCount)) {
		memoryReferenceFree(ref);
	}
}


IOReturn
IOGeneralMemoryDescriptor::memoryReferenceCreate(
	IOOptionBits         options,
	IOMemoryReference ** reference)
{
	enum { kCapacity = 4, kCapacityInc = 4 };

	kern_return_t        err;
	IOMemoryReference *  ref;
	IOMemoryEntry *      entries;
	IOMemoryEntry *      cloneEntries;
	vm_map_t             map;
	ipc_port_t           entry, cloneEntry;
	vm_prot_t            prot;
	memory_object_size_t actualSize;
	uint32_t             rangeIdx;
	uint32_t             count;
	mach_vm_address_t    entryAddr, endAddr, entrySize;
	mach_vm_size_t       srcAddr, srcLen;
	mach_vm_size_t       nextAddr, nextLen;
	mach_vm_size_t       offset, remain;
	IOByteCount          physLen;
	IOOptionBits         type = (_flags & kIOMemoryTypeMask);
	IOOptionBits         cacheMode;
	unsigned int         pagerFlags;
	vm_tag_t             tag;
	vm_named_entry_kernel_flags_t vmne_kflags;

	ref = memoryReferenceAlloc(kCapacity, NULL);
	if (!ref) {
		return kIOReturnNoMemory;
	}

	tag = getVMTag(kernel_map);
	vmne_kflags = VM_NAMED_ENTRY_KERNEL_FLAGS_NONE;
	entries = &ref->entries[0];
	count = 0;
	err = KERN_SUCCESS;

	offset = 0;
	rangeIdx = 0;
	if (_task) {
		getAddrLenForInd(nextAddr, nextLen, type, _ranges, rangeIdx);
	} else {
		nextAddr = getPhysicalSegment(offset, &physLen, kIOMemoryMapperNone);
		nextLen = physLen;

		// default cache mode for physical
		if (kIODefaultCache == ((_flags & kIOMemoryBufferCacheMask) >> kIOMemoryBufferCacheShift)) {
			IOOptionBits mode = cacheModeForPagerFlags(IODefaultCacheBits(nextAddr));
			_flags |= (mode << kIOMemoryBufferCacheShift);
		}
	}

	// cache mode & vm_prot
	prot = VM_PROT_READ;
	cacheMode = ((_flags & kIOMemoryBufferCacheMask) >> kIOMemoryBufferCacheShift);
	prot |= vmProtForCacheMode(cacheMode);
	// VM system requires write access to change cache mode
	if (kIODefaultCache != cacheMode) {
		prot |= VM_PROT_WRITE;
	}
	if (kIODirectionOut != (kIODirectionOutIn & _flags)) {
		prot |= VM_PROT_WRITE;
	}
	if (kIOMemoryReferenceWrite & options) {
		prot |= VM_PROT_WRITE;
	}
	if (kIOMemoryReferenceCOW   & options) {
		prot |= MAP_MEM_VM_COPY;
	}

	if (kIOMemoryUseReserve & _flags) {
		prot |= MAP_MEM_GRAB_SECLUDED;
	}

	if ((kIOMemoryReferenceReuse & options) && _memRef) {
		cloneEntries = &_memRef->entries[0];
		prot |= MAP_MEM_NAMED_REUSE;
	}

	if (_task) {
		// virtual ranges

		if (kIOMemoryBufferPageable & _flags) {
			int ledger_tag, ledger_no_footprint;

			// IOBufferMemoryDescriptor alloc - set flags for entry + object create
			prot |= MAP_MEM_NAMED_CREATE;

			// default accounting settings:
			//   + "none" ledger tag
			//   + include in footprint
			// can be changed later with ::setOwnership()
			ledger_tag = VM_LEDGER_TAG_NONE;
			ledger_no_footprint = 0;

			if (kIOMemoryBufferPurgeable & _flags) {
				prot |= (MAP_MEM_PURGABLE | MAP_MEM_PURGABLE_KERNEL_ONLY);
				if (VM_KERN_MEMORY_SKYWALK == tag) {
					// Skywalk purgeable memory accounting:
					//    + "network" ledger tag
					//    + not included in footprint
					ledger_tag = VM_LEDGER_TAG_NETWORK;
					ledger_no_footprint = 1;
				} else {
					// regular purgeable memory accounting:
					//    + no ledger tag
					//    + included in footprint
					ledger_tag = VM_LEDGER_TAG_NONE;
					ledger_no_footprint = 0;
				}
			}
			vmne_kflags.vmnekf_ledger_tag = ledger_tag;
			vmne_kflags.vmnekf_ledger_no_footprint = ledger_no_footprint;
			if (kIOMemoryUseReserve & _flags) {
				prot |= MAP_MEM_GRAB_SECLUDED;
			}

			prot |= VM_PROT_WRITE;
			map = NULL;
		} else {
			map = get_task_map(_task);
		}

		remain = _length;
		while (remain) {
			srcAddr  = nextAddr;
			srcLen   = nextLen;
			nextAddr = 0;
			nextLen  = 0;
			// coalesce addr range
			for (++rangeIdx; rangeIdx < _rangesCount; rangeIdx++) {
				getAddrLenForInd(nextAddr, nextLen, type, _ranges, rangeIdx);
				if ((srcAddr + srcLen) != nextAddr) {
					break;
				}
				srcLen += nextLen;
			}
			entryAddr = trunc_page_64(srcAddr);
			endAddr   = round_page_64(srcAddr + srcLen);
			do{
				entrySize = (endAddr - entryAddr);
				if (!entrySize) {
					break;
				}
				actualSize = entrySize;

				cloneEntry = MACH_PORT_NULL;
				if (MAP_MEM_NAMED_REUSE & prot) {
					if (cloneEntries < &_memRef->entries[_memRef->count]) {
						cloneEntry = cloneEntries->entry;
					} else {
						prot &= ~MAP_MEM_NAMED_REUSE;
					}
				}

				err = mach_make_memory_entry_internal(map,
				    &actualSize, entryAddr, prot, vmne_kflags, &entry, cloneEntry);

				if (KERN_SUCCESS != err) {
					break;
				}
				if (actualSize > entrySize) {
					panic("mach_make_memory_entry_64 actualSize");
				}

				if (count >= ref->capacity) {
					ref = memoryReferenceAlloc(ref->capacity + kCapacityInc, ref);
					entries = &ref->entries[count];
				}
				entries->entry  = entry;
				entries->size   = actualSize;
				entries->offset = offset + (entryAddr - srcAddr);
				entryAddr += actualSize;
				if (MAP_MEM_NAMED_REUSE & prot) {
					if ((cloneEntries->entry == entries->entry)
					    && (cloneEntries->size == entries->size)
					    && (cloneEntries->offset == entries->offset)) {
						cloneEntries++;
					} else {
						prot &= ~MAP_MEM_NAMED_REUSE;
					}
				}
				entries++;
				count++;
			}while (true);
			offset += srcLen;
			remain -= srcLen;
		}
	} else {
		// _task == 0, physical or kIOMemoryTypeUPL
		memory_object_t pager;
		vm_size_t       size = ptoa_64(_pages);

		if (!getKernelReserved()) {
			panic("getKernelReserved");
		}

		reserved->dp.pagerContig = (1 == _rangesCount);
		reserved->dp.memory      = this;

		pagerFlags = pagerFlagsForCacheMode(cacheMode);
		if (-1U == pagerFlags) {
			panic("phys is kIODefaultCache");
		}
		if (reserved->dp.pagerContig) {
			pagerFlags |= DEVICE_PAGER_CONTIGUOUS;
		}

		pager = device_pager_setup((memory_object_t) NULL, (uintptr_t) reserved,
		    size, pagerFlags);
		assert(pager);
		if (!pager) {
			err = kIOReturnVMError;
		} else {
			srcAddr  = nextAddr;
			entryAddr = trunc_page_64(srcAddr);
			err = mach_memory_object_memory_entry_64((host_t) 1, false /*internal*/,
			    size, VM_PROT_READ | VM_PROT_WRITE, pager, &entry);
			assert(KERN_SUCCESS == err);
			if (KERN_SUCCESS != err) {
				device_pager_deallocate(pager);
			} else {
				reserved->dp.devicePager = pager;
				entries->entry  = entry;
				entries->size   = size;
				entries->offset = offset + (entryAddr - srcAddr);
				entries++;
				count++;
			}
		}
	}

	ref->count = count;
	ref->prot  = prot;

	if (_task && (KERN_SUCCESS == err)
	    && (kIOMemoryMapCopyOnWrite & _flags)
	    && !(kIOMemoryReferenceCOW & options)) {
		err = memoryReferenceCreate(options | kIOMemoryReferenceCOW, &ref->mapRef);
	}

	if (KERN_SUCCESS == err) {
		if (MAP_MEM_NAMED_REUSE & prot) {
			memoryReferenceFree(ref);
			OSIncrementAtomic(&_memRef->refCount);
			ref = _memRef;
		}
	} else {
		memoryReferenceFree(ref);
		ref = NULL;
	}

	*reference = ref;

	return err;
}

kern_return_t
IOMemoryDescriptorMapAlloc(vm_map_t map, void * _ref)
{
	IOMemoryDescriptorMapAllocRef * ref = (typeof(ref))_ref;
	IOReturn                        err;
	vm_map_offset_t                 addr;

	addr = ref->mapped;

	err = vm_map_enter_mem_object(map, &addr, ref->size,
	    (vm_map_offset_t) 0,
	    (((ref->options & kIOMapAnywhere)
	    ? VM_FLAGS_ANYWHERE
	    : VM_FLAGS_FIXED)),
	    VM_MAP_KERNEL_FLAGS_NONE,
	    ref->tag,
	    IPC_PORT_NULL,
	    (memory_object_offset_t) 0,
	    false,                       /* copy */
	    ref->prot,
	    ref->prot,
	    VM_INHERIT_NONE);
	if (KERN_SUCCESS == err) {
		ref->mapped = (mach_vm_address_t) addr;
		ref->map = map;
	}

	return err;
}

IOReturn
IOGeneralMemoryDescriptor::memoryReferenceMap(
	IOMemoryReference * ref,
	vm_map_t            map,
	mach_vm_size_t      inoffset,
	mach_vm_size_t      size,
	IOOptionBits        options,
	mach_vm_address_t * inaddr)
{
	IOReturn        err;
	int64_t         offset = inoffset;
	uint32_t        rangeIdx, entryIdx;
	vm_map_offset_t addr, mapAddr;
	vm_map_offset_t pageOffset, entryOffset, remain, chunk;

	mach_vm_address_t nextAddr;
	mach_vm_size_t    nextLen;
	IOByteCount       physLen;
	IOMemoryEntry   * entry;
	vm_prot_t         prot, memEntryCacheMode;
	IOOptionBits      type;
	IOOptionBits      cacheMode;
	vm_tag_t          tag;
	// for the kIOMapPrefault option.
	upl_page_info_t * pageList = NULL;
	UInt              currentPageIndex = 0;
	bool              didAlloc;

	if (ref->mapRef) {
		err = memoryReferenceMap(ref->mapRef, map, inoffset, size, options, inaddr);
		return err;
	}

	type = _flags & kIOMemoryTypeMask;

	prot = VM_PROT_READ;
	if (!(kIOMapReadOnly & options)) {
		prot |= VM_PROT_WRITE;
	}
	prot &= ref->prot;

	cacheMode = ((options & kIOMapCacheMask) >> kIOMapCacheShift);
	if (kIODefaultCache != cacheMode) {
		// VM system requires write access to update named entry cache mode
		memEntryCacheMode = (MAP_MEM_ONLY | VM_PROT_WRITE | prot | vmProtForCacheMode(cacheMode));
	}

	tag = getVMTag(map);

	if (_task) {
		// Find first range for offset
		if (!_rangesCount) {
			return kIOReturnBadArgument;
		}
		for (remain = offset, rangeIdx = 0; rangeIdx < _rangesCount; rangeIdx++) {
			getAddrLenForInd(nextAddr, nextLen, type, _ranges, rangeIdx);
			if (remain < nextLen) {
				break;
			}
			remain -= nextLen;
		}
	} else {
		rangeIdx = 0;
		remain   = 0;
		nextAddr = getPhysicalSegment(offset, &physLen, kIOMemoryMapperNone);
		nextLen  = size;
	}

	assert(remain < nextLen);
	if (remain >= nextLen) {
		return kIOReturnBadArgument;
	}

	nextAddr  += remain;
	nextLen   -= remain;
	pageOffset = (page_mask & nextAddr);
	addr       = 0;
	didAlloc   = false;

	if (!(options & kIOMapAnywhere)) {
		addr = *inaddr;
		if (pageOffset != (page_mask & addr)) {
			return kIOReturnNotAligned;
		}
		addr -= pageOffset;
	}

	// find first entry for offset
	for (entryIdx = 0;
	    (entryIdx < ref->count) && (offset >= ref->entries[entryIdx].offset);
	    entryIdx++) {
	}
	entryIdx--;
	entry = &ref->entries[entryIdx];

	// allocate VM
	size = round_page_64(size + pageOffset);
	if (kIOMapOverwrite & options) {
		if ((map == kernel_map) && (kIOMemoryBufferPageable & _flags)) {
			map = IOPageableMapForAddress(addr);
		}
		err = KERN_SUCCESS;
	} else {
		IOMemoryDescriptorMapAllocRef ref;
		ref.map     = map;
		ref.tag     = tag;
		ref.options = options;
		ref.size    = size;
		ref.prot    = prot;
		if (options & kIOMapAnywhere) {
			// vm_map looks for addresses above here, even when VM_FLAGS_ANYWHERE
			ref.mapped = 0;
		} else {
			ref.mapped = addr;
		}
		if ((ref.map == kernel_map) && (kIOMemoryBufferPageable & _flags)) {
			err = IOIteratePageableMaps( ref.size, &IOMemoryDescriptorMapAlloc, &ref );
		} else {
			err = IOMemoryDescriptorMapAlloc(ref.map, &ref);
		}
		if (KERN_SUCCESS == err) {
			addr     = ref.mapped;
			map      = ref.map;
			didAlloc = true;
		}
	}

	/*
	 * If the memory is associated with a device pager but doesn't have a UPL,
	 * it will be immediately faulted in through the pager via populateDevicePager().
	 * kIOMapPrefault is redundant in that case, so don't try to use it for UPL
	 * operations.
	 */
	if ((reserved != NULL) && (reserved->dp.devicePager) && (_wireCount != 0)) {
		options &= ~kIOMapPrefault;
	}

	/*
	 * Prefaulting is only possible if we wired the memory earlier. Check the
	 * memory type, and the underlying data.
	 */
	if (options & kIOMapPrefault) {
		/*
		 * The memory must have been wired by calling ::prepare(), otherwise
		 * we don't have the UPL. Without UPLs, pages cannot be pre-faulted
		 */
		assert(_wireCount != 0);
		assert(_memoryEntries != NULL);
		if ((_wireCount == 0) ||
		    (_memoryEntries == NULL)) {
			return kIOReturnBadArgument;
		}

		// Get the page list.
		ioGMDData* dataP = getDataP(_memoryEntries);
		ioPLBlock const* ioplList = getIOPLList(dataP);
		pageList = getPageList(dataP);

		// Get the number of IOPLs.
		UInt numIOPLs = getNumIOPL(_memoryEntries, dataP);

		/*
		 * Scan through the IOPL Info Blocks, looking for the first block containing
		 * the offset. The research will go past it, so we'll need to go back to the
		 * right range at the end.
		 */
		UInt ioplIndex = 0;
		while (ioplIndex < numIOPLs && offset >= ioplList[ioplIndex].fIOMDOffset) {
			ioplIndex++;
		}
		ioplIndex--;

		// Retrieve the IOPL info block.
		ioPLBlock ioplInfo = ioplList[ioplIndex];

		/*
		 * For external UPLs, the fPageInfo points directly to the UPL's page_info_t
		 * array.
		 */
		if (ioplInfo.fFlags & kIOPLExternUPL) {
			pageList = (upl_page_info_t*) ioplInfo.fPageInfo;
		} else {
			pageList = &pageList[ioplInfo.fPageInfo];
		}

		// Rebase [offset] into the IOPL in order to looks for the first page index.
		mach_vm_size_t offsetInIOPL = offset - ioplInfo.fIOMDOffset + ioplInfo.fPageOffset;

		// Retrieve the index of the first page corresponding to the offset.
		currentPageIndex = atop_32(offsetInIOPL);
	}

	// enter mappings
	remain  = size;
	mapAddr = addr;
	addr    += pageOffset;

	while (remain && (KERN_SUCCESS == err)) {
		entryOffset = offset - entry->offset;
		if ((page_mask & entryOffset) != pageOffset) {
			err = kIOReturnNotAligned;
			break;
		}

		if (kIODefaultCache != cacheMode) {
			vm_size_t unused = 0;
			err = mach_make_memory_entry(NULL /*unused*/, &unused, 0 /*unused*/,
			    memEntryCacheMode, NULL, entry->entry);
			assert(KERN_SUCCESS == err);
		}

		entryOffset -= pageOffset;
		if (entryOffset >= entry->size) {
			panic("entryOffset");
		}
		chunk = entry->size - entryOffset;
		if (chunk) {
			vm_map_kernel_flags_t vmk_flags;

			vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
			vmk_flags.vmkf_iokit_acct = TRUE; /* iokit accounting */

			if (chunk > remain) {
				chunk = remain;
			}
			if (options & kIOMapPrefault) {
				UInt nb_pages = round_page(chunk) / PAGE_SIZE;

				err = vm_map_enter_mem_object_prefault(map,
				    &mapAddr,
				    chunk, 0 /* mask */,
				    (VM_FLAGS_FIXED
				    | VM_FLAGS_OVERWRITE),
				    vmk_flags,
				    tag,
				    entry->entry,
				    entryOffset,
				    prot,                        // cur
				    prot,                        // max
				    &pageList[currentPageIndex],
				    nb_pages);

				// Compute the next index in the page list.
				currentPageIndex += nb_pages;
				assert(currentPageIndex <= _pages);
			} else {
				err = vm_map_enter_mem_object(map,
				    &mapAddr,
				    chunk, 0 /* mask */,
				    (VM_FLAGS_FIXED
				    | VM_FLAGS_OVERWRITE),
				    vmk_flags,
				    tag,
				    entry->entry,
				    entryOffset,
				    false,               // copy
				    prot,               // cur
				    prot,               // max
				    VM_INHERIT_NONE);
			}
			if (KERN_SUCCESS != err) {
				break;
			}
			remain -= chunk;
			if (!remain) {
				break;
			}
			mapAddr  += chunk;
			offset   += chunk - pageOffset;
		}
		pageOffset = 0;
		entry++;
		entryIdx++;
		if (entryIdx >= ref->count) {
			err = kIOReturnOverrun;
			break;
		}
	}

	if ((KERN_SUCCESS != err) && didAlloc) {
		(void) mach_vm_deallocate(map, trunc_page_64(addr), size);
		addr = 0;
	}
	*inaddr = addr;

	return err;
}

IOReturn
IOGeneralMemoryDescriptor::memoryReferenceGetPageCounts(
	IOMemoryReference * ref,
	IOByteCount       * residentPageCount,
	IOByteCount       * dirtyPageCount)
{
	IOReturn        err;
	IOMemoryEntry * entries;
	unsigned int resident, dirty;
	unsigned int totalResident, totalDirty;

	totalResident = totalDirty = 0;
	err = kIOReturnSuccess;
	entries = ref->entries + ref->count;
	while (entries > &ref->entries[0]) {
		entries--;
		err = mach_memory_entry_get_page_counts(entries->entry, &resident, &dirty);
		if (KERN_SUCCESS != err) {
			break;
		}
		totalResident += resident;
		totalDirty    += dirty;
	}

	if (residentPageCount) {
		*residentPageCount = totalResident;
	}
	if (dirtyPageCount) {
		*dirtyPageCount    = totalDirty;
	}
	return err;
}

IOReturn
IOGeneralMemoryDescriptor::memoryReferenceSetPurgeable(
	IOMemoryReference * ref,
	IOOptionBits        newState,
	IOOptionBits      * oldState)
{
	IOReturn        err;
	IOMemoryEntry * entries;
	vm_purgable_t   control;
	int             totalState, state;

	totalState = kIOMemoryPurgeableNonVolatile;
	err = kIOReturnSuccess;
	entries = ref->entries + ref->count;
	while (entries > &ref->entries[0]) {
		entries--;

		err = purgeableControlBits(newState, &control, &state);
		if (KERN_SUCCESS != err) {
			break;
		}
		err = memory_entry_purgeable_control_internal(entries->entry, control, &state);
		if (KERN_SUCCESS != err) {
			break;
		}
		err = purgeableStateBits(&state);
		if (KERN_SUCCESS != err) {
			break;
		}

		if (kIOMemoryPurgeableEmpty == state) {
			totalState = kIOMemoryPurgeableEmpty;
		} else if (kIOMemoryPurgeableEmpty == totalState) {
			continue;
		} else if (kIOMemoryPurgeableVolatile == totalState) {
			continue;
		} else if (kIOMemoryPurgeableVolatile == state) {
			totalState = kIOMemoryPurgeableVolatile;
		} else {
			totalState = kIOMemoryPurgeableNonVolatile;
		}
	}

	if (oldState) {
		*oldState = totalState;
	}
	return err;
}

IOReturn
IOGeneralMemoryDescriptor::memoryReferenceSetOwnership(
	IOMemoryReference * ref,
	task_t              newOwner,
	int                 newLedgerTag,
	IOOptionBits        newLedgerOptions)
{
	IOReturn        err, totalErr;
	IOMemoryEntry * entries;

	totalErr = kIOReturnSuccess;
	entries = ref->entries + ref->count;
	while (entries > &ref->entries[0]) {
		entries--;

		err = mach_memory_entry_ownership(entries->entry, newOwner, newLedgerTag, newLedgerOptions);
		if (KERN_SUCCESS != err) {
			totalErr = err;
		}
	}

	return totalErr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(void *      address,
    IOByteCount   length,
    IODirection direction)
{
	return IOMemoryDescriptor::
	       withAddressRange((IOVirtualAddress) address, length, direction | kIOMemoryAutoPrepare, kernel_task);
}

#ifndef __LP64__
IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(IOVirtualAddress address,
    IOByteCount  length,
    IODirection  direction,
    task_t       task)
{
	IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
	if (that) {
		if (that->initWithAddress(address, length, direction, task)) {
			return that;
		}

		that->release();
	}
	return NULL;
}
#endif /* !__LP64__ */

IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalAddress(
	IOPhysicalAddress       address,
	IOByteCount             length,
	IODirection             direction )
{
	return IOMemoryDescriptor::withAddressRange(address, length, direction, TASK_NULL);
}

#ifndef __LP64__
IOMemoryDescriptor *
IOMemoryDescriptor::withRanges( IOVirtualRange * ranges,
    UInt32           withCount,
    IODirection      direction,
    task_t           task,
    bool             asReference)
{
	IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
	if (that) {
		if (that->initWithRanges(ranges, withCount, direction, task, asReference)) {
			return that;
		}

		that->release();
	}
	return NULL;
}
#endif /* !__LP64__ */

IOMemoryDescriptor *
IOMemoryDescriptor::withAddressRange(mach_vm_address_t address,
    mach_vm_size_t length,
    IOOptionBits   options,
    task_t         task)
{
	IOAddressRange range = { address, length };
	return IOMemoryDescriptor::withAddressRanges(&range, 1, options, task);
}

IOMemoryDescriptor *
IOMemoryDescriptor::withAddressRanges(IOAddressRange *   ranges,
    UInt32           rangeCount,
    IOOptionBits     options,
    task_t           task)
{
	IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
	if (that) {
		if (task) {
			options |= kIOMemoryTypeVirtual64;
		} else {
			options |= kIOMemoryTypePhysical64;
		}

		if (that->initWithOptions(ranges, rangeCount, 0, task, options, /* mapper */ NULL)) {
			return that;
		}

		that->release();
	}

	return NULL;
}


/*
 * withOptions:
 *
 * Create a new IOMemoryDescriptor. The buffer is made up of several
 * virtual address ranges, from a given task.
 *
 * Passing the ranges as a reference will avoid an extra allocation.
 */
IOMemoryDescriptor *
IOMemoryDescriptor::withOptions(void *          buffers,
    UInt32          count,
    UInt32          offset,
    task_t          task,
    IOOptionBits    opts,
    IOMapper *      mapper)
{
	IOGeneralMemoryDescriptor *self = new IOGeneralMemoryDescriptor;

	if (self
	    && !self->initWithOptions(buffers, count, offset, task, opts, mapper)) {
		self->release();
		return NULL;
	}

	return self;
}

bool
IOMemoryDescriptor::initWithOptions(void *         buffers,
    UInt32         count,
    UInt32         offset,
    task_t         task,
    IOOptionBits   options,
    IOMapper *     mapper)
{
	return false;
}

#ifndef __LP64__
IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalRanges( IOPhysicalRange * ranges,
    UInt32          withCount,
    IODirection     direction,
    bool            asReference)
{
	IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
	if (that) {
		if (that->initWithPhysicalRanges(ranges, withCount, direction, asReference)) {
			return that;
		}

		that->release();
	}
	return NULL;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withSubRange(IOMemoryDescriptor *   of,
    IOByteCount             offset,
    IOByteCount             length,
    IODirection             direction)
{
	return IOSubMemoryDescriptor::withSubRange(of, offset, length, direction);
}
#endif /* !__LP64__ */

IOMemoryDescriptor *
IOMemoryDescriptor::withPersistentMemoryDescriptor(IOMemoryDescriptor *originalMD)
{
	IOGeneralMemoryDescriptor *origGenMD =
	    OSDynamicCast(IOGeneralMemoryDescriptor, originalMD);

	if (origGenMD) {
		return IOGeneralMemoryDescriptor::
		       withPersistentMemoryDescriptor(origGenMD);
	} else {
		return NULL;
	}
}

IOMemoryDescriptor *
IOGeneralMemoryDescriptor::withPersistentMemoryDescriptor(IOGeneralMemoryDescriptor *originalMD)
{
	IOMemoryReference * memRef;

	if (kIOReturnSuccess != originalMD->memoryReferenceCreate(kIOMemoryReferenceReuse, &memRef)) {
		return NULL;
	}

	if (memRef == originalMD->_memRef) {
		originalMD->retain();       // Add a new reference to ourselves
		originalMD->memoryReferenceRelease(memRef);
		return originalMD;
	}

	IOGeneralMemoryDescriptor * self = new IOGeneralMemoryDescriptor;
	IOMDPersistentInitData initData = { originalMD, memRef };

	if (self
	    && !self->initWithOptions(&initData, 1, 0, NULL, kIOMemoryTypePersistentMD, NULL)) {
		self->release();
		self = NULL;
	}
	return self;
}

#ifndef __LP64__
bool
IOGeneralMemoryDescriptor::initWithAddress(void *      address,
    IOByteCount   withLength,
    IODirection withDirection)
{
	_singleRange.v.address = (vm_offset_t) address;
	_singleRange.v.length  = withLength;

	return initWithRanges(&_singleRange.v, 1, withDirection, kernel_task, true);
}

bool
IOGeneralMemoryDescriptor::initWithAddress(IOVirtualAddress address,
    IOByteCount    withLength,
    IODirection  withDirection,
    task_t       withTask)
{
	_singleRange.v.address = address;
	_singleRange.v.length  = withLength;

	return initWithRanges(&_singleRange.v, 1, withDirection, withTask, true);
}

bool
IOGeneralMemoryDescriptor::initWithPhysicalAddress(
	IOPhysicalAddress      address,
	IOByteCount            withLength,
	IODirection            withDirection )
{
	_singleRange.p.address = address;
	_singleRange.p.length  = withLength;

	return initWithPhysicalRanges( &_singleRange.p, 1, withDirection, true);
}

bool
IOGeneralMemoryDescriptor::initWithPhysicalRanges(
	IOPhysicalRange * ranges,
	UInt32            count,
	IODirection       direction,
	bool              reference)
{
	IOOptionBits mdOpts = direction | kIOMemoryTypePhysical;

	if (reference) {
		mdOpts |= kIOMemoryAsReference;
	}

	return initWithOptions(ranges, count, 0, NULL, mdOpts, /* mapper */ NULL);
}

bool
IOGeneralMemoryDescriptor::initWithRanges(
	IOVirtualRange * ranges,
	UInt32           count,
	IODirection      direction,
	task_t           task,
	bool             reference)
{
	IOOptionBits mdOpts = direction;

	if (reference) {
		mdOpts |= kIOMemoryAsReference;
	}

	if (task) {
		mdOpts |= kIOMemoryTypeVirtual;

		// Auto-prepare if this is a kernel memory descriptor as very few
		// clients bother to prepare() kernel memory.
		// But it was not enforced so what are you going to do?
		if (task == kernel_task) {
			mdOpts |= kIOMemoryAutoPrepare;
		}
	} else {
		mdOpts |= kIOMemoryTypePhysical;
	}

	return initWithOptions(ranges, count, 0, task, mdOpts, /* mapper */ NULL);
}
#endif /* !__LP64__ */

/*
 * initWithOptions:
 *
 *  IOMemoryDescriptor. The buffer is made up of several virtual address ranges,
 * from a given task, several physical ranges, an UPL from the ubc
 * system or a uio (may be 64bit) from the BSD subsystem.
 *
 * Passing the ranges as a reference will avoid an extra allocation.
 *
 * An IOMemoryDescriptor can be re-used by calling initWithOptions again on an
 * existing instance -- note this behavior is not commonly supported in other
 * I/O Kit classes, although it is supported here.
 */

bool
IOGeneralMemoryDescriptor::initWithOptions(void *       buffers,
    UInt32       count,
    UInt32       offset,
    task_t       task,
    IOOptionBits options,
    IOMapper *   mapper)
{
	IOOptionBits type = options & kIOMemoryTypeMask;

#ifndef __LP64__
	if (task
	    && (kIOMemoryTypeVirtual == type)
	    && vm_map_is_64bit(get_task_map(task))
	    && ((IOVirtualRange *) buffers)->address) {
		OSReportWithBacktrace("IOMemoryDescriptor: attempt to create 32b virtual in 64b task, use ::withAddressRange()");
		return false;
	}
#endif /* !__LP64__ */

	// Grab the original MD's configuation data to initialse the
	// arguments to this function.
	if (kIOMemoryTypePersistentMD == type) {
		IOMDPersistentInitData *initData = (typeof(initData))buffers;
		const IOGeneralMemoryDescriptor *orig = initData->fMD;
		ioGMDData *dataP = getDataP(orig->_memoryEntries);

		// Only accept persistent memory descriptors with valid dataP data.
		assert(orig->_rangesCount == 1);
		if (!(orig->_flags & kIOMemoryPersistent) || !dataP) {
			return false;
		}

		_memRef = initData->fMemRef; // Grab the new named entry
		options = orig->_flags & ~kIOMemoryAsReference;
		type = options & kIOMemoryTypeMask;
		buffers = orig->_ranges.v;
		count = orig->_rangesCount;

		// Now grab the original task and whatever mapper was previously used
		task = orig->_task;
		mapper = dataP->fMapper;

		// We are ready to go through the original initialisation now
	}

	switch (type) {
	case kIOMemoryTypeUIO:
	case kIOMemoryTypeVirtual:
#ifndef __LP64__
	case kIOMemoryTypeVirtual64:
#endif /* !__LP64__ */
		assert(task);
		if (!task) {
			return false;
		}
		break;

	case kIOMemoryTypePhysical:     // Neither Physical nor UPL should have a task
#ifndef __LP64__
	case kIOMemoryTypePhysical64:
#endif /* !__LP64__ */
	case kIOMemoryTypeUPL:
		assert(!task);
		break;
	default:
		return false; /* bad argument */
	}

	assert(buffers);
	assert(count);

	/*
	 * We can check the _initialized  instance variable before having ever set
	 * it to an initial value because I/O Kit guarantees that all our instance
	 * variables are zeroed on an object's allocation.
	 */

	if (_initialized) {
		/*
		 * An existing memory descriptor is being retargeted to point to
		 * somewhere else.  Clean up our present state.
		 */
		IOOptionBits type = _flags & kIOMemoryTypeMask;
		if ((kIOMemoryTypePhysical != type) && (kIOMemoryTypePhysical64 != type)) {
			while (_wireCount) {
				complete();
			}
		}
		if (_ranges.v && !(kIOMemoryAsReference & _flags)) {
			if (kIOMemoryTypeUIO == type) {
				uio_free((uio_t) _ranges.v);
			}
#ifndef __LP64__
			else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type)) {
				IODelete(_ranges.v64, IOAddressRange, _rangesCount);
			}
#endif /* !__LP64__ */
			else {
				IODelete(_ranges.v, IOVirtualRange, _rangesCount);
			}
		}

		options |= (kIOMemoryRedirected & _flags);
		if (!(kIOMemoryRedirected & options)) {
			if (_memRef) {
				memoryReferenceRelease(_memRef);
				_memRef = NULL;
			}
			if (_mappings) {
				_mappings->flushCollection();
			}
		}
	} else {
		if (!super::init()) {
			return false;
		}
		_initialized = true;
	}

	// Grab the appropriate mapper
	if (kIOMemoryHostOrRemote & options) {
		options |= kIOMemoryMapperNone;
	}
	if (kIOMemoryMapperNone & options) {
		mapper = NULL; // No Mapper
	} else if (mapper == kIOMapperSystem) {
		IOMapper::checkForSystemMapper();
		gIOSystemMapper = mapper = IOMapper::gSystem;
	}

	// Remove the dynamic internal use flags from the initial setting
	options               &= ~(kIOMemoryPreparedReadOnly);
	_flags                 = options;
	_task                  = task;

#ifndef __LP64__
	_direction             = (IODirection) (_flags & kIOMemoryDirectionMask);
#endif /* !__LP64__ */

	_dmaReferences = 0;
	__iomd_reservedA = 0;
	__iomd_reservedB = 0;
	_highestPage = 0;

	if (kIOMemoryThreadSafe & options) {
		if (!_prepareLock) {
			_prepareLock = IOLockAlloc();
		}
	} else if (_prepareLock) {
		IOLockFree(_prepareLock);
		_prepareLock = NULL;
	}

	if (kIOMemoryTypeUPL == type) {
		ioGMDData *dataP;
		unsigned int dataSize = computeDataSize(/* pages */ 0, /* upls */ 1);

		if (!initMemoryEntries(dataSize, mapper)) {
			return false;
		}
		dataP = getDataP(_memoryEntries);
		dataP->fPageCnt = 0;
		switch (kIOMemoryDirectionMask & options) {
		case kIODirectionOut:
			dataP->fDMAAccess = kIODMAMapReadAccess;
			break;
		case kIODirectionIn:
			dataP->fDMAAccess = kIODMAMapWriteAccess;
			break;
		case kIODirectionNone:
		case kIODirectionOutIn:
		default:
			panic("bad dir for upl 0x%x\n", (int) options);
			break;
		}
		//       _wireCount++;	// UPLs start out life wired

		_length    = count;
		_pages    += atop_32(offset + count + PAGE_MASK) - atop_32(offset);

		ioPLBlock iopl;
		iopl.fIOPL = (upl_t) buffers;
		upl_set_referenced(iopl.fIOPL, true);
		upl_page_info_t *pageList = UPL_GET_INTERNAL_PAGE_LIST(iopl.fIOPL);

		if (upl_get_size(iopl.fIOPL) < (count + offset)) {
			panic("short external upl");
		}

		_highestPage = upl_get_highest_page(iopl.fIOPL);

		// Set the flag kIOPLOnDevice convieniently equal to 1
		iopl.fFlags  = pageList->device | kIOPLExternUPL;
		if (!pageList->device) {
			// Pre-compute the offset into the UPL's page list
			pageList = &pageList[atop_32(offset)];
			offset &= PAGE_MASK;
		}
		iopl.fIOMDOffset = 0;
		iopl.fMappedPage = 0;
		iopl.fPageInfo = (vm_address_t) pageList;
		iopl.fPageOffset = offset;
		_memoryEntries->appendBytes(&iopl, sizeof(iopl));
	} else {
		// kIOMemoryTypeVirtual  | kIOMemoryTypeVirtual64 | kIOMemoryTypeUIO
		// kIOMemoryTypePhysical | kIOMemoryTypePhysical64

		// Initialize the memory descriptor
		if (options & kIOMemoryAsReference) {
#ifndef __LP64__
			_rangesIsAllocated = false;
#endif /* !__LP64__ */

			// Hack assignment to get the buffer arg into _ranges.
			// I'd prefer to do _ranges = (Ranges) buffers, but that doesn't
			// work, C++ sigh.
			// This also initialises the uio & physical ranges.
			_ranges.v = (IOVirtualRange *) buffers;
		} else {
#ifndef __LP64__
			_rangesIsAllocated = true;
#endif /* !__LP64__ */
			switch (type) {
			case kIOMemoryTypeUIO:
				_ranges.v = (IOVirtualRange *) uio_duplicate((uio_t) buffers);
				break;

#ifndef __LP64__
			case kIOMemoryTypeVirtual64:
			case kIOMemoryTypePhysical64:
				if (count == 1
#ifndef __arm__
				    && (((IOAddressRange *) buffers)->address + ((IOAddressRange *) buffers)->length) <= 0x100000000ULL
#endif
				    ) {
					if (kIOMemoryTypeVirtual64 == type) {
						type = kIOMemoryTypeVirtual;
					} else {
						type = kIOMemoryTypePhysical;
					}
					_flags = (_flags & ~kIOMemoryTypeMask) | type | kIOMemoryAsReference;
					_rangesIsAllocated = false;
					_ranges.v = &_singleRange.v;
					_singleRange.v.address = ((IOAddressRange *) buffers)->address;
					_singleRange.v.length  = ((IOAddressRange *) buffers)->length;
					break;
				}
				_ranges.v64 = IONew(IOAddressRange, count);
				if (!_ranges.v64) {
					return false;
				}
				bcopy(buffers, _ranges.v, count * sizeof(IOAddressRange));
				break;
#endif /* !__LP64__ */
			case kIOMemoryTypeVirtual:
			case kIOMemoryTypePhysical:
				if (count == 1) {
					_flags |= kIOMemoryAsReference;
#ifndef __LP64__
					_rangesIsAllocated = false;
#endif /* !__LP64__ */
					_ranges.v = &_singleRange.v;
				} else {
					_ranges.v = IONew(IOVirtualRange, count);
					if (!_ranges.v) {
						return false;
					}
				}
				bcopy(buffers, _ranges.v, count * sizeof(IOVirtualRange));
				break;
			}
		}
		_rangesCount = count;

		// Find starting address within the vector of ranges
		Ranges vec = _ranges;
		mach_vm_size_t totalLength = 0;
		unsigned int ind, pages = 0;
		for (ind = 0; ind < count; ind++) {
			mach_vm_address_t addr;
			mach_vm_address_t endAddr;
			mach_vm_size_t    len;

			// addr & len are returned by this function
			getAddrLenForInd(addr, len, type, vec, ind);
			if (os_add3_overflow(addr, len, PAGE_MASK, &endAddr)) {
				break;
			}
			if (os_add_overflow(pages, (atop_64(endAddr) - atop_64(addr)), &pages)) {
				break;
			}
			if (os_add_overflow(totalLength, len, &totalLength)) {
				break;
			}
			if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
				ppnum_t highPage = atop_64(addr + len - 1);
				if (highPage > _highestPage) {
					_highestPage = highPage;
				}
			}
		}
		if ((ind < count)
		    || (totalLength != ((IOByteCount) totalLength))) {
			return false;                                   /* overflow */
		}
		_length      = totalLength;
		_pages       = pages;

		// Auto-prepare memory at creation time.
		// Implied completion when descriptor is free-ed


		if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
			_wireCount++; // Physical MDs are, by definition, wired
		} else { /* kIOMemoryTypeVirtual | kIOMemoryTypeVirtual64 | kIOMemoryTypeUIO */
			ioGMDData *dataP;
			unsigned dataSize;

			if (_pages > atop_64(max_mem)) {
				return false;
			}

			dataSize = computeDataSize(_pages, /* upls */ count * 2);
			if (!initMemoryEntries(dataSize, mapper)) {
				return false;
			}
			dataP = getDataP(_memoryEntries);
			dataP->fPageCnt = _pages;

			if (((_task != kernel_task) || (kIOMemoryBufferPageable & _flags))
			    && (VM_KERN_MEMORY_NONE == _kernelTag)) {
				_kernelTag = IOMemoryTag(kernel_map);
				if (_kernelTag == gIOSurfaceTag) {
					_userTag = VM_MEMORY_IOSURFACE;
				}
			}

			if ((kIOMemoryPersistent & _flags) && !_memRef) {
				IOReturn
				    err = memoryReferenceCreate(0, &_memRef);
				if (kIOReturnSuccess != err) {
					return false;
				}
			}

			if ((_flags & kIOMemoryAutoPrepare)
			    && prepare() != kIOReturnSuccess) {
				return false;
			}
		}
	}

	return true;
}

/*
 * free
 *
 * Free resources.
 */
void
IOGeneralMemoryDescriptor::free()
{
	IOOptionBits type = _flags & kIOMemoryTypeMask;

	if (reserved) {
		LOCK;
		reserved->dp.memory = NULL;
		UNLOCK;
	}
	if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
		ioGMDData * dataP;
		if (_memoryEntries && (dataP = getDataP(_memoryEntries)) && dataP->fMappedBaseValid) {
			dmaUnmap(dataP->fMapper, NULL, 0, dataP->fMappedBase, dataP->fMappedLength);
			dataP->fMappedBaseValid = dataP->fMappedBase = 0;
		}
	} else {
		while (_wireCount) {
			complete();
		}
	}

	if (_memoryEntries) {
		_memoryEntries->release();
	}

	if (_ranges.v && !(kIOMemoryAsReference & _flags)) {
		if (kIOMemoryTypeUIO == type) {
			uio_free((uio_t) _ranges.v);
		}
#ifndef __LP64__
		else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type)) {
			IODelete(_ranges.v64, IOAddressRange, _rangesCount);
		}
#endif /* !__LP64__ */
		else {
			IODelete(_ranges.v, IOVirtualRange, _rangesCount);
		}

		_ranges.v = NULL;
	}

	if (reserved) {
		cleanKernelReserved(reserved);
		if (reserved->dp.devicePager) {
			// memEntry holds a ref on the device pager which owns reserved
			// (IOMemoryDescriptorReserved) so no reserved access after this point
			device_pager_deallocate((memory_object_t) reserved->dp.devicePager );
		} else {
			IODelete(reserved, IOMemoryDescriptorReserved, 1);
		}
		reserved = NULL;
	}

	if (_memRef) {
		memoryReferenceRelease(_memRef);
	}
	if (_prepareLock) {
		IOLockFree(_prepareLock);
	}

	super::free();
}

#ifndef __LP64__
void
IOGeneralMemoryDescriptor::unmapFromKernel()
{
	panic("IOGMD::unmapFromKernel deprecated");
}

void
IOGeneralMemoryDescriptor::mapIntoKernel(unsigned rangeIndex)
{
	panic("IOGMD::mapIntoKernel deprecated");
}
#endif /* !__LP64__ */

/*
 * getDirection:
 *
 * Get the direction of the transfer.
 */
IODirection
IOMemoryDescriptor::getDirection() const
{
#ifndef __LP64__
	if (_direction) {
		return _direction;
	}
#endif /* !__LP64__ */
	return (IODirection) (_flags & kIOMemoryDirectionMask);
}

/*
 * getLength:
 *
 * Get the length of the transfer (over all ranges).
 */
IOByteCount
IOMemoryDescriptor::getLength() const
{
	return _length;
}

void
IOMemoryDescriptor::setTag( IOOptionBits tag )
{
	_tag = tag;
}

IOOptionBits
IOMemoryDescriptor::getTag( void )
{
	return _tag;
}

uint64_t
IOMemoryDescriptor::getFlags(void)
{
	return _flags;
}

#ifndef __LP64__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// @@@ gvdl: who is using this API?  Seems like a wierd thing to implement.
IOPhysicalAddress
IOMemoryDescriptor::getSourceSegment( IOByteCount   offset, IOByteCount * length )
{
	addr64_t physAddr = 0;

	if (prepare() == kIOReturnSuccess) {
		physAddr = getPhysicalSegment64( offset, length );
		complete();
	}

	return (IOPhysicalAddress) physAddr; // truncated but only page offset is used
}

#pragma clang diagnostic pop

#endif /* !__LP64__ */

IOByteCount
IOMemoryDescriptor::readBytes
(IOByteCount offset, void *bytes, IOByteCount length)
{
	addr64_t dstAddr = CAST_DOWN(addr64_t, bytes);
	IOByteCount remaining;

	// Assert that this entire I/O is withing the available range
	assert(offset <= _length);
	assert(offset + length <= _length);
	if ((offset >= _length)
	    || ((offset + length) > _length)) {
		return 0;
	}

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return 0;
	}

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}

	remaining = length = min(length, _length - offset);
	while (remaining) { // (process another target segment?)
		addr64_t        srcAddr64;
		IOByteCount     srcLen;

		srcAddr64 = getPhysicalSegment(offset, &srcLen, kIOMemoryMapperNone);
		if (!srcAddr64) {
			break;
		}

		// Clip segment length to remaining
		if (srcLen > remaining) {
			srcLen = remaining;
		}

		copypv(srcAddr64, dstAddr, srcLen,
		    cppvPsrc | cppvNoRefSrc | cppvFsnk | cppvKmap);

		dstAddr   += srcLen;
		offset    += srcLen;
		remaining -= srcLen;
	}

	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	assert(!remaining);

	return length - remaining;
}

IOByteCount
IOMemoryDescriptor::writeBytes
(IOByteCount inoffset, const void *bytes, IOByteCount length)
{
	addr64_t srcAddr = CAST_DOWN(addr64_t, bytes);
	IOByteCount remaining;
	IOByteCount offset = inoffset;

	// Assert that this entire I/O is withing the available range
	assert(offset <= _length);
	assert(offset + length <= _length);

	assert( !(kIOMemoryPreparedReadOnly & _flags));

	if ((kIOMemoryPreparedReadOnly & _flags)
	    || (offset >= _length)
	    || ((offset + length) > _length)) {
		return 0;
	}

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return 0;
	}

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}

	remaining = length = min(length, _length - offset);
	while (remaining) { // (process another target segment?)
		addr64_t    dstAddr64;
		IOByteCount dstLen;

		dstAddr64 = getPhysicalSegment(offset, &dstLen, kIOMemoryMapperNone);
		if (!dstAddr64) {
			break;
		}

		// Clip segment length to remaining
		if (dstLen > remaining) {
			dstLen = remaining;
		}

		if (!srcAddr) {
			bzero_phys(dstAddr64, dstLen);
		} else {
			copypv(srcAddr, (addr64_t) dstAddr64, dstLen,
			    cppvPsnk | cppvFsnk | cppvNoRefSrc | cppvNoModSnk | cppvKmap);
			srcAddr   += dstLen;
		}
		offset    += dstLen;
		remaining -= dstLen;
	}

	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	assert(!remaining);

#if defined(__x86_64__)
	// copypv does not cppvFsnk on intel
#else
	if (!srcAddr) {
		performOperation(kIOMemoryIncoherentIOFlush, inoffset, length);
	}
#endif

	return length - remaining;
}

#ifndef __LP64__
void
IOGeneralMemoryDescriptor::setPosition(IOByteCount position)
{
	panic("IOGMD::setPosition deprecated");
}
#endif /* !__LP64__ */

static volatile SInt64 gIOMDPreparationID __attribute__((aligned(8))) = (1ULL << 32);

uint64_t
IOGeneralMemoryDescriptor::getPreparationID( void )
{
	ioGMDData *dataP;

	if (!_wireCount) {
		return kIOPreparationIDUnprepared;
	}

	if (((kIOMemoryTypeMask & _flags) == kIOMemoryTypePhysical)
	    || ((kIOMemoryTypeMask & _flags) == kIOMemoryTypePhysical64)) {
		IOMemoryDescriptor::setPreparationID();
		return IOMemoryDescriptor::getPreparationID();
	}

	if (!_memoryEntries || !(dataP = getDataP(_memoryEntries))) {
		return kIOPreparationIDUnprepared;
	}

	if (kIOPreparationIDUnprepared == dataP->fPreparationID) {
		SInt64 newID = OSIncrementAtomic64(&gIOMDPreparationID);
		OSCompareAndSwap64(kIOPreparationIDUnprepared, newID, &dataP->fPreparationID);
	}
	return dataP->fPreparationID;
}

void
IOMemoryDescriptor::cleanKernelReserved( IOMemoryDescriptorReserved * reserved )
{
	if (reserved->creator) {
		task_deallocate(reserved->creator);
		reserved->creator = NULL;
	}
}

IOMemoryDescriptorReserved *
IOMemoryDescriptor::getKernelReserved( void )
{
	if (!reserved) {
		reserved = IONewZero(IOMemoryDescriptorReserved, 1);
	}
	return reserved;
}

void
IOMemoryDescriptor::setPreparationID( void )
{
	if (getKernelReserved() && (kIOPreparationIDUnprepared == reserved->preparationID)) {
		SInt64 newID = OSIncrementAtomic64(&gIOMDPreparationID);
		OSCompareAndSwap64(kIOPreparationIDUnprepared, newID, &reserved->preparationID);
	}
}

uint64_t
IOMemoryDescriptor::getPreparationID( void )
{
	if (reserved) {
		return reserved->preparationID;
	} else {
		return kIOPreparationIDUnsupported;
	}
}

void
IOMemoryDescriptor::setVMTags(uint32_t kernelTag, uint32_t userTag)
{
	_kernelTag = (vm_tag_t) kernelTag;
	_userTag   = (vm_tag_t) userTag;
}

uint32_t
IOMemoryDescriptor::getVMTag(vm_map_t map)
{
	if (vm_kernel_map_is_kernel(map)) {
		if (VM_KERN_MEMORY_NONE != _kernelTag) {
			return (uint32_t) _kernelTag;
		}
	} else {
		if (VM_KERN_MEMORY_NONE != _userTag) {
			return (uint32_t) _userTag;
		}
	}
	return IOMemoryTag(map);
}

IOReturn
IOGeneralMemoryDescriptor::dmaCommandOperation(DMACommandOps op, void *vData, UInt dataSize) const
{
	IOReturn err = kIOReturnSuccess;
	DMACommandOps params;
	IOGeneralMemoryDescriptor * md = const_cast<IOGeneralMemoryDescriptor *>(this);
	ioGMDData *dataP;

	params = (op & ~kIOMDDMACommandOperationMask & op);
	op &= kIOMDDMACommandOperationMask;

	if (kIOMDDMAMap == op) {
		if (dataSize < sizeof(IOMDDMAMapArgs)) {
			return kIOReturnUnderrun;
		}

		IOMDDMAMapArgs * data = (IOMDDMAMapArgs *) vData;

		if (!_memoryEntries
		    && !md->initMemoryEntries(computeDataSize(0, 0), kIOMapperWaitSystem)) {
			return kIOReturnNoMemory;
		}

		if (_memoryEntries && data->fMapper) {
			bool remap, keepMap;
			dataP = getDataP(_memoryEntries);

			if (data->fMapSpec.numAddressBits < dataP->fDMAMapNumAddressBits) {
				dataP->fDMAMapNumAddressBits = data->fMapSpec.numAddressBits;
			}
			if (data->fMapSpec.alignment > dataP->fDMAMapAlignment) {
				dataP->fDMAMapAlignment      = data->fMapSpec.alignment;
			}

			keepMap = (data->fMapper == gIOSystemMapper);
			keepMap &= ((data->fOffset == 0) && (data->fLength == _length));

			if ((data->fMapper == gIOSystemMapper) && _prepareLock) {
				IOLockLock(_prepareLock);
			}

			remap = (!keepMap);
			remap |= (dataP->fDMAMapNumAddressBits < 64)
			    && ((dataP->fMappedBase + _length) > (1ULL << dataP->fDMAMapNumAddressBits));
			remap |= (dataP->fDMAMapAlignment > page_size);

			if (remap || !dataP->fMappedBaseValid) {
//		if (dataP->fMappedBaseValid) OSReportWithBacktrace("kIOMDDMAMap whole %d remap %d params %d\n", whole, remap, params);
				err = md->dmaMap(data->fMapper, data->fCommand, &data->fMapSpec, data->fOffset, data->fLength, &data->fAlloc, &data->fAllocLength);
				if (keepMap && (kIOReturnSuccess == err) && !dataP->fMappedBaseValid) {
					dataP->fMappedBase      = data->fAlloc;
					dataP->fMappedBaseValid = true;
					dataP->fMappedLength    = data->fAllocLength;
					data->fAllocLength      = 0;    // IOMD owns the alloc now
				}
			} else {
				data->fAlloc = dataP->fMappedBase;
				data->fAllocLength = 0;         // give out IOMD map
				md->dmaMapRecord(data->fMapper, data->fCommand, dataP->fMappedLength);
			}
			data->fMapContig = !dataP->fDiscontig;

			if ((data->fMapper == gIOSystemMapper) && _prepareLock) {
				IOLockUnlock(_prepareLock);
			}
		}
		return err;
	}
	if (kIOMDDMAUnmap == op) {
		if (dataSize < sizeof(IOMDDMAMapArgs)) {
			return kIOReturnUnderrun;
		}
		IOMDDMAMapArgs * data = (IOMDDMAMapArgs *) vData;

		err = md->dmaUnmap(data->fMapper, data->fCommand, data->fOffset, data->fAlloc, data->fAllocLength);

		return kIOReturnSuccess;
	}

	if (kIOMDAddDMAMapSpec == op) {
		if (dataSize < sizeof(IODMAMapSpecification)) {
			return kIOReturnUnderrun;
		}

		IODMAMapSpecification * data = (IODMAMapSpecification *) vData;

		if (!_memoryEntries
		    && !md->initMemoryEntries(computeDataSize(0, 0), kIOMapperWaitSystem)) {
			return kIOReturnNoMemory;
		}

		if (_memoryEntries) {
			dataP = getDataP(_memoryEntries);
			if (data->numAddressBits < dataP->fDMAMapNumAddressBits) {
				dataP->fDMAMapNumAddressBits = data->numAddressBits;
			}
			if (data->alignment > dataP->fDMAMapAlignment) {
				dataP->fDMAMapAlignment = data->alignment;
			}
		}
		return kIOReturnSuccess;
	}

	if (kIOMDGetCharacteristics == op) {
		if (dataSize < sizeof(IOMDDMACharacteristics)) {
			return kIOReturnUnderrun;
		}

		IOMDDMACharacteristics *data = (IOMDDMACharacteristics *) vData;
		data->fLength = _length;
		data->fSGCount = _rangesCount;
		data->fPages = _pages;
		data->fDirection = getDirection();
		if (!_wireCount) {
			data->fIsPrepared = false;
		} else {
			data->fIsPrepared = true;
			data->fHighestPage = _highestPage;
			if (_memoryEntries) {
				dataP = getDataP(_memoryEntries);
				ioPLBlock *ioplList = getIOPLList(dataP);
				UInt count = getNumIOPL(_memoryEntries, dataP);
				if (count == 1) {
					data->fPageAlign = (ioplList[0].fPageOffset & PAGE_MASK) | ~PAGE_MASK;
				}
			}
		}

		return kIOReturnSuccess;
	} else if (kIOMDDMAActive == op) {
		if (params) {
			int16_t prior;
			prior = OSAddAtomic16(1, &md->_dmaReferences);
			if (!prior) {
				md->_mapName = NULL;
			}
		} else {
			if (md->_dmaReferences) {
				OSAddAtomic16(-1, &md->_dmaReferences);
			} else {
				panic("_dmaReferences underflow");
			}
		}
	} else if (kIOMDWalkSegments != op) {
		return kIOReturnBadArgument;
	}

	// Get the next segment
	struct InternalState {
		IOMDDMAWalkSegmentArgs fIO;
		mach_vm_size_t fOffset2Index;
		mach_vm_size_t fNextOffset;
		UInt fIndex;
	} *isP;

	// Find the next segment
	if (dataSize < sizeof(*isP)) {
		return kIOReturnUnderrun;
	}

	isP = (InternalState *) vData;
	mach_vm_size_t offset = isP->fIO.fOffset;
	uint8_t mapped = isP->fIO.fMapped;
	uint64_t mappedBase;

	if (mapped && (kIOMemoryRemote & _flags)) {
		return kIOReturnNotAttached;
	}

	if (IOMapper::gSystem && mapped
	    && (!(kIOMemoryHostOnly & _flags))
	    && (!_memoryEntries || !getDataP(_memoryEntries)->fMappedBaseValid)) {
//	&& (_memoryEntries && !getDataP(_memoryEntries)->fMappedBaseValid))
		if (!_memoryEntries
		    && !md->initMemoryEntries(computeDataSize(0, 0), kIOMapperWaitSystem)) {
			return kIOReturnNoMemory;
		}

		dataP = getDataP(_memoryEntries);
		if (dataP->fMapper) {
			IODMAMapSpecification mapSpec;
			bzero(&mapSpec, sizeof(mapSpec));
			mapSpec.numAddressBits = dataP->fDMAMapNumAddressBits;
			mapSpec.alignment = dataP->fDMAMapAlignment;
			err = md->dmaMap(dataP->fMapper, NULL, &mapSpec, 0, _length, &dataP->fMappedBase, &dataP->fMappedLength);
			if (kIOReturnSuccess != err) {
				return err;
			}
			dataP->fMappedBaseValid = true;
		}
	}

	if (kIOMDDMAWalkMappedLocal == mapped) {
		mappedBase = isP->fIO.fMappedBase;
	} else if (mapped) {
		if (IOMapper::gSystem
		    && (!(kIOMemoryHostOnly & _flags))
		    && _memoryEntries
		    && (dataP = getDataP(_memoryEntries))
		    && dataP->fMappedBaseValid) {
			mappedBase = dataP->fMappedBase;
		} else {
			mapped = 0;
		}
	}

	if (offset >= _length) {
		return (offset == _length)? kIOReturnOverrun : kIOReturnInternalError;
	}

	// Validate the previous offset
	UInt ind;
	mach_vm_size_t off2Ind = isP->fOffset2Index;
	if (!params
	    && offset
	    && (offset == isP->fNextOffset || off2Ind <= offset)) {
		ind = isP->fIndex;
	} else {
		ind = off2Ind = 0; // Start from beginning
	}
	mach_vm_size_t length;
	UInt64 address;

	if ((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical) {
		// Physical address based memory descriptor
		const IOPhysicalRange *physP = (IOPhysicalRange *) &_ranges.p[0];

		// Find the range after the one that contains the offset
		mach_vm_size_t len;
		for (len = 0; off2Ind <= offset; ind++) {
			len = physP[ind].length;
			off2Ind += len;
		}

		// Calculate length within range and starting address
		length   = off2Ind - offset;
		address  = physP[ind - 1].address + len - length;

		if (true && mapped) {
			address = mappedBase + offset;
		} else {
			// see how far we can coalesce ranges
			while (ind < _rangesCount && address + length == physP[ind].address) {
				len = physP[ind].length;
				length += len;
				off2Ind += len;
				ind++;
			}
		}

		// correct contiguous check overshoot
		ind--;
		off2Ind -= len;
	}
#ifndef __LP64__
	else if ((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64) {
		// Physical address based memory descriptor
		const IOAddressRange *physP = (IOAddressRange *) &_ranges.v64[0];

		// Find the range after the one that contains the offset
		mach_vm_size_t len;
		for (len = 0; off2Ind <= offset; ind++) {
			len = physP[ind].length;
			off2Ind += len;
		}

		// Calculate length within range and starting address
		length   = off2Ind - offset;
		address  = physP[ind - 1].address + len - length;

		if (true && mapped) {
			address = mappedBase + offset;
		} else {
			// see how far we can coalesce ranges
			while (ind < _rangesCount && address + length == physP[ind].address) {
				len = physP[ind].length;
				length += len;
				off2Ind += len;
				ind++;
			}
		}
		// correct contiguous check overshoot
		ind--;
		off2Ind -= len;
	}
#endif /* !__LP64__ */
	else {
		do {
			if (!_wireCount) {
				panic("IOGMD: not wired for the IODMACommand");
			}

			assert(_memoryEntries);

			dataP = getDataP(_memoryEntries);
			const ioPLBlock *ioplList = getIOPLList(dataP);
			UInt numIOPLs = getNumIOPL(_memoryEntries, dataP);
			upl_page_info_t *pageList = getPageList(dataP);

			assert(numIOPLs > 0);

			// Scan through iopl info blocks looking for block containing offset
			while (ind < numIOPLs && offset >= ioplList[ind].fIOMDOffset) {
				ind++;
			}

			// Go back to actual range as search goes past it
			ioPLBlock ioplInfo = ioplList[ind - 1];
			off2Ind = ioplInfo.fIOMDOffset;

			if (ind < numIOPLs) {
				length = ioplList[ind].fIOMDOffset;
			} else {
				length = _length;
			}
			length -= offset;       // Remainder within iopl

			// Subtract offset till this iopl in total list
			offset -= off2Ind;

			// If a mapped address is requested and this is a pre-mapped IOPL
			// then just need to compute an offset relative to the mapped base.
			if (mapped) {
				offset += (ioplInfo.fPageOffset & PAGE_MASK);
				address = trunc_page_64(mappedBase) + ptoa_64(ioplInfo.fMappedPage) + offset;
				continue; // Done leave do/while(false) now
			}

			// The offset is rebased into the current iopl.
			// Now add the iopl 1st page offset.
			offset += ioplInfo.fPageOffset;

			// For external UPLs the fPageInfo field points directly to
			// the upl's upl_page_info_t array.
			if (ioplInfo.fFlags & kIOPLExternUPL) {
				pageList = (upl_page_info_t *) ioplInfo.fPageInfo;
			} else {
				pageList = &pageList[ioplInfo.fPageInfo];
			}

			// Check for direct device non-paged memory
			if (ioplInfo.fFlags & kIOPLOnDevice) {
				address = ptoa_64(pageList->phys_addr) + offset;
				continue; // Done leave do/while(false) now
			}

			// Now we need compute the index into the pageList
			UInt pageInd = atop_32(offset);
			offset &= PAGE_MASK;

			// Compute the starting address of this segment
			IOPhysicalAddress pageAddr = pageList[pageInd].phys_addr;
			if (!pageAddr) {
				panic("!pageList phys_addr");
			}

			address = ptoa_64(pageAddr) + offset;

			// length is currently set to the length of the remainider of the iopl.
			// We need to check that the remainder of the iopl is contiguous.
			// This is indicated by pageList[ind].phys_addr being sequential.
			IOByteCount contigLength = PAGE_SIZE - offset;
			while (contigLength < length
			    && ++pageAddr == pageList[++pageInd].phys_addr) {
				contigLength += PAGE_SIZE;
			}

			if (contigLength < length) {
				length = contigLength;
			}


			assert(address);
			assert(length);
		} while (false);
	}

	// Update return values and state
	isP->fIO.fIOVMAddr = address;
	isP->fIO.fLength   = length;
	isP->fIndex        = ind;
	isP->fOffset2Index = off2Ind;
	isP->fNextOffset   = isP->fIO.fOffset + length;

	return kIOReturnSuccess;
}

addr64_t
IOGeneralMemoryDescriptor::getPhysicalSegment(IOByteCount offset, IOByteCount *lengthOfSegment, IOOptionBits options)
{
	IOReturn          ret;
	mach_vm_address_t address = 0;
	mach_vm_size_t    length  = 0;
	IOMapper *        mapper  = gIOSystemMapper;
	IOOptionBits      type    = _flags & kIOMemoryTypeMask;

	if (lengthOfSegment) {
		*lengthOfSegment = 0;
	}

	if (offset >= _length) {
		return 0;
	}

	// IOMemoryDescriptor::doMap() cannot use getPhysicalSegment() to obtain the page offset, since it must
	// support the unwired memory case in IOGeneralMemoryDescriptor, and hibernate_write_image() cannot use
	// map()->getVirtualAddress() to obtain the kernel pointer, since it must prevent the memory allocation
	// due to IOMemoryMap, so _kIOMemorySourceSegment is a necessary evil until all of this gets cleaned up

	if ((options & _kIOMemorySourceSegment) && (kIOMemoryTypeUPL != type)) {
		unsigned rangesIndex = 0;
		Ranges vec = _ranges;
		mach_vm_address_t addr;

		// Find starting address within the vector of ranges
		for (;;) {
			getAddrLenForInd(addr, length, type, vec, rangesIndex);
			if (offset < length) {
				break;
			}
			offset -= length; // (make offset relative)
			rangesIndex++;
		}

		// Now that we have the starting range,
		// lets find the last contiguous range
		addr   += offset;
		length -= offset;

		for (++rangesIndex; rangesIndex < _rangesCount; rangesIndex++) {
			mach_vm_address_t newAddr;
			mach_vm_size_t    newLen;

			getAddrLenForInd(newAddr, newLen, type, vec, rangesIndex);
			if (addr + length != newAddr) {
				break;
			}
			length += newLen;
		}
		if (addr) {
			address = (IOPhysicalAddress) addr; // Truncate address to 32bit
		}
	} else {
		IOMDDMAWalkSegmentState _state;
		IOMDDMAWalkSegmentArgs * state = (IOMDDMAWalkSegmentArgs *) (void *)&_state;

		state->fOffset = offset;
		state->fLength = _length - offset;
		state->fMapped = (0 == (options & kIOMemoryMapperNone)) && !(_flags & kIOMemoryHostOrRemote);

		ret = dmaCommandOperation(kIOMDFirstSegment, _state, sizeof(_state));

		if ((kIOReturnSuccess != ret) && (kIOReturnOverrun != ret)) {
			DEBG("getPhysicalSegment dmaCommandOperation(%lx), %p, offset %qx, addr %qx, len %qx\n",
			    ret, this, state->fOffset,
			    state->fIOVMAddr, state->fLength);
		}
		if (kIOReturnSuccess == ret) {
			address = state->fIOVMAddr;
			length  = state->fLength;
		}

		// dmaCommandOperation() does not distinguish between "mapped" and "unmapped" physical memory, even
		// with fMapped set correctly, so we must handle the transformation here until this gets cleaned up

		if (mapper && ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type))) {
			if ((options & kIOMemoryMapperNone) && !(_flags & kIOMemoryMapperNone)) {
				addr64_t    origAddr = address;
				IOByteCount origLen  = length;

				address = mapper->mapToPhysicalAddress(origAddr);
				length = page_size - (address & (page_size - 1));
				while ((length < origLen)
				    && ((address + length) == mapper->mapToPhysicalAddress(origAddr + length))) {
					length += page_size;
				}
				if (length > origLen) {
					length = origLen;
				}
			}
		}
	}

	if (!address) {
		length = 0;
	}

	if (lengthOfSegment) {
		*lengthOfSegment = length;
	}

	return address;
}

#ifndef __LP64__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

addr64_t
IOMemoryDescriptor::getPhysicalSegment(IOByteCount offset, IOByteCount *lengthOfSegment, IOOptionBits options)
{
	addr64_t address = 0;

	if (options & _kIOMemorySourceSegment) {
		address = getSourceSegment(offset, lengthOfSegment);
	} else if (options & kIOMemoryMapperNone) {
		address = getPhysicalSegment64(offset, lengthOfSegment);
	} else {
		address = getPhysicalSegment(offset, lengthOfSegment);
	}

	return address;
}
#pragma clang diagnostic pop

addr64_t
IOGeneralMemoryDescriptor::getPhysicalSegment64(IOByteCount offset, IOByteCount *lengthOfSegment)
{
	return getPhysicalSegment(offset, lengthOfSegment, kIOMemoryMapperNone);
}

IOPhysicalAddress
IOGeneralMemoryDescriptor::getPhysicalSegment(IOByteCount offset, IOByteCount *lengthOfSegment)
{
	addr64_t    address = 0;
	IOByteCount length  = 0;

	address = getPhysicalSegment(offset, lengthOfSegment, 0);

	if (lengthOfSegment) {
		length = *lengthOfSegment;
	}

	if ((address + length) > 0x100000000ULL) {
		panic("getPhysicalSegment() out of 32b range 0x%qx, len 0x%lx, class %s",
		    address, (long) length, (getMetaClass())->getClassName());
	}

	return (IOPhysicalAddress) address;
}

addr64_t
IOMemoryDescriptor::getPhysicalSegment64(IOByteCount offset, IOByteCount *lengthOfSegment)
{
	IOPhysicalAddress phys32;
	IOByteCount       length;
	addr64_t          phys64;
	IOMapper *        mapper = NULL;

	phys32 = getPhysicalSegment(offset, lengthOfSegment);
	if (!phys32) {
		return 0;
	}

	if (gIOSystemMapper) {
		mapper = gIOSystemMapper;
	}

	if (mapper) {
		IOByteCount origLen;

		phys64 = mapper->mapToPhysicalAddress(phys32);
		origLen = *lengthOfSegment;
		length = page_size - (phys64 & (page_size - 1));
		while ((length < origLen)
		    && ((phys64 + length) == mapper->mapToPhysicalAddress(phys32 + length))) {
			length += page_size;
		}
		if (length > origLen) {
			length = origLen;
		}

		*lengthOfSegment = length;
	} else {
		phys64 = (addr64_t) phys32;
	}

	return phys64;
}

IOPhysicalAddress
IOMemoryDescriptor::getPhysicalSegment(IOByteCount offset, IOByteCount *lengthOfSegment)
{
	return (IOPhysicalAddress) getPhysicalSegment(offset, lengthOfSegment, 0);
}

IOPhysicalAddress
IOGeneralMemoryDescriptor::getSourceSegment(IOByteCount offset, IOByteCount *lengthOfSegment)
{
	return (IOPhysicalAddress) getPhysicalSegment(offset, lengthOfSegment, _kIOMemorySourceSegment);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

void *
IOGeneralMemoryDescriptor::getVirtualSegment(IOByteCount offset,
    IOByteCount * lengthOfSegment)
{
	if (_task == kernel_task) {
		return (void *) getSourceSegment(offset, lengthOfSegment);
	} else {
		panic("IOGMD::getVirtualSegment deprecated");
	}

	return NULL;
}
#pragma clang diagnostic pop
#endif /* !__LP64__ */

IOReturn
IOMemoryDescriptor::dmaCommandOperation(DMACommandOps op, void *vData, UInt dataSize) const
{
	IOMemoryDescriptor *md = const_cast<IOMemoryDescriptor *>(this);
	DMACommandOps params;
	IOReturn err;

	params = (op & ~kIOMDDMACommandOperationMask & op);
	op &= kIOMDDMACommandOperationMask;

	if (kIOMDGetCharacteristics == op) {
		if (dataSize < sizeof(IOMDDMACharacteristics)) {
			return kIOReturnUnderrun;
		}

		IOMDDMACharacteristics *data = (IOMDDMACharacteristics *) vData;
		data->fLength = getLength();
		data->fSGCount = 0;
		data->fDirection = getDirection();
		data->fIsPrepared = true; // Assume prepared - fails safe
	} else if (kIOMDWalkSegments == op) {
		if (dataSize < sizeof(IOMDDMAWalkSegmentArgs)) {
			return kIOReturnUnderrun;
		}

		IOMDDMAWalkSegmentArgs *data = (IOMDDMAWalkSegmentArgs *) vData;
		IOByteCount offset  = (IOByteCount) data->fOffset;

		IOPhysicalLength length;
		if (data->fMapped && IOMapper::gSystem) {
			data->fIOVMAddr = md->getPhysicalSegment(offset, &length);
		} else {
			data->fIOVMAddr = md->getPhysicalSegment(offset, &length, kIOMemoryMapperNone);
		}
		data->fLength = length;
	} else if (kIOMDAddDMAMapSpec == op) {
		return kIOReturnUnsupported;
	} else if (kIOMDDMAMap == op) {
		if (dataSize < sizeof(IOMDDMAMapArgs)) {
			return kIOReturnUnderrun;
		}
		IOMDDMAMapArgs * data = (IOMDDMAMapArgs *) vData;

		if (params) {
			panic("class %s does not support IODMACommand::kIterateOnly", getMetaClass()->getClassName());
		}

		data->fMapContig = true;
		err = md->dmaMap(data->fMapper, data->fCommand, &data->fMapSpec, data->fOffset, data->fLength, &data->fAlloc, &data->fAllocLength);

		return err;
	} else if (kIOMDDMAUnmap == op) {
		if (dataSize < sizeof(IOMDDMAMapArgs)) {
			return kIOReturnUnderrun;
		}
		IOMDDMAMapArgs * data = (IOMDDMAMapArgs *) vData;

		err = md->dmaUnmap(data->fMapper, data->fCommand, data->fOffset, data->fAlloc, data->fAllocLength);

		return kIOReturnSuccess;
	} else {
		return kIOReturnBadArgument;
	}

	return kIOReturnSuccess;
}

IOReturn
IOGeneralMemoryDescriptor::setPurgeable( IOOptionBits newState,
    IOOptionBits * oldState )
{
	IOReturn      err = kIOReturnSuccess;

	vm_purgable_t control;
	int           state;

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (_memRef) {
		err = super::setPurgeable(newState, oldState);
	} else {
		if (kIOMemoryThreadSafe & _flags) {
			LOCK;
		}
		do{
			// Find the appropriate vm_map for the given task
			vm_map_t curMap;
			if (_task == kernel_task && (kIOMemoryBufferPageable & _flags)) {
				err = kIOReturnNotReady;
				break;
			} else if (!_task) {
				err = kIOReturnUnsupported;
				break;
			} else {
				curMap = get_task_map(_task);
				if (NULL == curMap) {
					err = KERN_INVALID_ARGUMENT;
					break;
				}
			}

			// can only do one range
			Ranges vec = _ranges;
			IOOptionBits type = _flags & kIOMemoryTypeMask;
			mach_vm_address_t addr;
			mach_vm_size_t    len;
			getAddrLenForInd(addr, len, type, vec, 0);

			err = purgeableControlBits(newState, &control, &state);
			if (kIOReturnSuccess != err) {
				break;
			}
			err = vm_map_purgable_control(curMap, addr, control, &state);
			if (oldState) {
				if (kIOReturnSuccess == err) {
					err = purgeableStateBits(&state);
					*oldState = state;
				}
			}
		}while (false);
		if (kIOMemoryThreadSafe & _flags) {
			UNLOCK;
		}
	}

	return err;
}

IOReturn
IOMemoryDescriptor::setPurgeable( IOOptionBits newState,
    IOOptionBits * oldState )
{
	IOReturn err = kIOReturnNotReady;

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}
	if (_memRef) {
		err = IOGeneralMemoryDescriptor::memoryReferenceSetPurgeable(_memRef, newState, oldState);
	}
	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	return err;
}

IOReturn
IOGeneralMemoryDescriptor::setOwnership( task_t newOwner,
    int newLedgerTag,
    IOOptionBits newLedgerOptions )
{
	IOReturn      err = kIOReturnSuccess;

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (iokit_iomd_setownership_enabled == FALSE) {
		return kIOReturnUnsupported;
	}

	if (_memRef) {
		err = super::setOwnership(newOwner, newLedgerTag, newLedgerOptions);
	} else {
		err = kIOReturnUnsupported;
	}

	return err;
}

IOReturn
IOMemoryDescriptor::setOwnership( task_t newOwner,
    int newLedgerTag,
    IOOptionBits newLedgerOptions )
{
	IOReturn err = kIOReturnNotReady;

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (iokit_iomd_setownership_enabled == FALSE) {
		return kIOReturnUnsupported;
	}

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}
	if (_memRef) {
		err = IOGeneralMemoryDescriptor::memoryReferenceSetOwnership(_memRef, newOwner, newLedgerTag, newLedgerOptions);
	} else {
		IOMultiMemoryDescriptor * mmd;
		IOSubMemoryDescriptor   * smd;
		if ((smd = OSDynamicCast(IOSubMemoryDescriptor, this))) {
			err = smd->setOwnership(newOwner, newLedgerTag, newLedgerOptions);
		} else if ((mmd = OSDynamicCast(IOMultiMemoryDescriptor, this))) {
			err = mmd->setOwnership(newOwner, newLedgerTag, newLedgerOptions);
		}
	}
	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	return err;
}

IOReturn
IOMemoryDescriptor::getPageCounts( IOByteCount * residentPageCount,
    IOByteCount * dirtyPageCount )
{
	IOReturn err = kIOReturnNotReady;

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}
	if (_memRef) {
		err = IOGeneralMemoryDescriptor::memoryReferenceGetPageCounts(_memRef, residentPageCount, dirtyPageCount);
	} else {
		IOMultiMemoryDescriptor * mmd;
		IOSubMemoryDescriptor   * smd;
		if ((smd = OSDynamicCast(IOSubMemoryDescriptor, this))) {
			err = smd->getPageCounts(residentPageCount, dirtyPageCount);
		} else if ((mmd = OSDynamicCast(IOMultiMemoryDescriptor, this))) {
			err = mmd->getPageCounts(residentPageCount, dirtyPageCount);
		}
	}
	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	return err;
}


#if defined(__arm__) || defined(__arm64__)
extern "C" void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count, unsigned int remaining, unsigned int *res);
extern "C" void dcache_incoherent_io_store64(addr64_t pa, unsigned int count, unsigned int remaining, unsigned int *res);
#else /* defined(__arm__) || defined(__arm64__) */
extern "C" void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count);
extern "C" void dcache_incoherent_io_store64(addr64_t pa, unsigned int count);
#endif /* defined(__arm__) || defined(__arm64__) */

static void
SetEncryptOp(addr64_t pa, unsigned int count)
{
	ppnum_t page, end;

	page = atop_64(round_page_64(pa));
	end  = atop_64(trunc_page_64(pa + count));
	for (; page < end; page++) {
		pmap_clear_noencrypt(page);
	}
}

static void
ClearEncryptOp(addr64_t pa, unsigned int count)
{
	ppnum_t page, end;

	page = atop_64(round_page_64(pa));
	end  = atop_64(trunc_page_64(pa + count));
	for (; page < end; page++) {
		pmap_set_noencrypt(page);
	}
}

IOReturn
IOMemoryDescriptor::performOperation( IOOptionBits options,
    IOByteCount offset, IOByteCount length )
{
	IOByteCount remaining;
	unsigned int res;
	void (*func)(addr64_t pa, unsigned int count) = NULL;
#if defined(__arm__) || defined(__arm64__)
	void (*func_ext)(addr64_t pa, unsigned int count, unsigned int remaining, unsigned int *result) = NULL;
#endif

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	switch (options) {
	case kIOMemoryIncoherentIOFlush:
#if defined(__arm__) || defined(__arm64__)
		func_ext = &dcache_incoherent_io_flush64;
#if __ARM_COHERENT_IO__
		func_ext(0, 0, 0, &res);
		return kIOReturnSuccess;
#else /* __ARM_COHERENT_IO__ */
		break;
#endif /* __ARM_COHERENT_IO__ */
#else /* defined(__arm__) || defined(__arm64__) */
		func = &dcache_incoherent_io_flush64;
		break;
#endif /* defined(__arm__) || defined(__arm64__) */
	case kIOMemoryIncoherentIOStore:
#if defined(__arm__) || defined(__arm64__)
		func_ext = &dcache_incoherent_io_store64;
#if __ARM_COHERENT_IO__
		func_ext(0, 0, 0, &res);
		return kIOReturnSuccess;
#else /* __ARM_COHERENT_IO__ */
		break;
#endif /* __ARM_COHERENT_IO__ */
#else /* defined(__arm__) || defined(__arm64__) */
		func = &dcache_incoherent_io_store64;
		break;
#endif /* defined(__arm__) || defined(__arm64__) */

	case kIOMemorySetEncrypted:
		func = &SetEncryptOp;
		break;
	case kIOMemoryClearEncrypted:
		func = &ClearEncryptOp;
		break;
	}

#if defined(__arm__) || defined(__arm64__)
	if ((func == NULL) && (func_ext == NULL)) {
		return kIOReturnUnsupported;
	}
#else /* defined(__arm__) || defined(__arm64__) */
	if (!func) {
		return kIOReturnUnsupported;
	}
#endif /* defined(__arm__) || defined(__arm64__) */

	if (kIOMemoryThreadSafe & _flags) {
		LOCK;
	}

	res = 0x0UL;
	remaining = length = min(length, getLength() - offset);
	while (remaining) {
		// (process another target segment?)
		addr64_t    dstAddr64;
		IOByteCount dstLen;

		dstAddr64 = getPhysicalSegment(offset, &dstLen, kIOMemoryMapperNone);
		if (!dstAddr64) {
			break;
		}

		// Clip segment length to remaining
		if (dstLen > remaining) {
			dstLen = remaining;
		}

#if defined(__arm__) || defined(__arm64__)
		if (func) {
			(*func)(dstAddr64, dstLen);
		}
		if (func_ext) {
			(*func_ext)(dstAddr64, dstLen, remaining, &res);
			if (res != 0x0UL) {
				remaining = 0;
				break;
			}
		}
#else /* defined(__arm__) || defined(__arm64__) */
		(*func)(dstAddr64, dstLen);
#endif /* defined(__arm__) || defined(__arm64__) */

		offset    += dstLen;
		remaining -= dstLen;
	}

	if (kIOMemoryThreadSafe & _flags) {
		UNLOCK;
	}

	return remaining ? kIOReturnUnderrun : kIOReturnSuccess;
}

/*
 *
 */

#if defined(__i386__) || defined(__x86_64__)

#define io_kernel_static_start  vm_kernel_stext
#define io_kernel_static_end    vm_kernel_etext

#elif defined(__arm__) || defined(__arm64__)

extern vm_offset_t              static_memory_end;

#if defined(__arm64__)
#define io_kernel_static_start vm_kext_base
#else /* defined(__arm64__) */
#define io_kernel_static_start vm_kernel_stext
#endif /* defined(__arm64__) */

#define io_kernel_static_end    static_memory_end

#else
#error io_kernel_static_end is undefined for this architecture
#endif

static kern_return_t
io_get_kernel_static_upl(
	vm_map_t                /* map */,
	uintptr_t               offset,
	upl_size_t              *upl_size,
	upl_t                   *upl,
	upl_page_info_array_t   page_list,
	unsigned int            *count,
	ppnum_t                 *highest_page)
{
	unsigned int pageCount, page;
	ppnum_t phys;
	ppnum_t highestPage = 0;

	pageCount = atop_32(*upl_size);
	if (pageCount > *count) {
		pageCount = *count;
	}

	*upl = NULL;

	for (page = 0; page < pageCount; page++) {
		phys = pmap_find_phys(kernel_pmap, ((addr64_t)offset) + ptoa_64(page));
		if (!phys) {
			break;
		}
		page_list[page].phys_addr = phys;
		page_list[page].free_when_done = 0;
		page_list[page].absent    = 0;
		page_list[page].dirty     = 0;
		page_list[page].precious  = 0;
		page_list[page].device    = 0;
		if (phys > highestPage) {
			highestPage = phys;
		}
	}

	*highest_page = highestPage;

	return (page >= pageCount) ? kIOReturnSuccess : kIOReturnVMError;
}

IOReturn
IOGeneralMemoryDescriptor::wireVirtual(IODirection forDirection)
{
	IOOptionBits type = _flags & kIOMemoryTypeMask;
	IOReturn error = kIOReturnSuccess;
	ioGMDData *dataP;
	upl_page_info_array_t pageInfo;
	ppnum_t mapBase;
	vm_tag_t tag = VM_KERN_MEMORY_NONE;

	assert(kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type);

	if ((kIODirectionOutIn & forDirection) == kIODirectionNone) {
		forDirection = (IODirection) (forDirection | getDirection());
	}

	dataP = getDataP(_memoryEntries);
	upl_control_flags_t uplFlags; // This Mem Desc's default flags for upl creation
	switch (kIODirectionOutIn & forDirection) {
	case kIODirectionOut:
		// Pages do not need to be marked as dirty on commit
		uplFlags = UPL_COPYOUT_FROM;
		dataP->fDMAAccess = kIODMAMapReadAccess;
		break;

	case kIODirectionIn:
		dataP->fDMAAccess = kIODMAMapWriteAccess;
		uplFlags = 0;   // i.e. ~UPL_COPYOUT_FROM
		break;

	default:
		dataP->fDMAAccess = kIODMAMapReadAccess | kIODMAMapWriteAccess;
		uplFlags = 0;   // i.e. ~UPL_COPYOUT_FROM
		break;
	}

	if (_wireCount) {
		if ((kIOMemoryPreparedReadOnly & _flags) && !(UPL_COPYOUT_FROM & uplFlags)) {
			OSReportWithBacktrace("IOMemoryDescriptor 0x%lx prepared read only", VM_KERNEL_ADDRPERM(this));
			error = kIOReturnNotWritable;
		}
	} else {
		IOMapper *mapper;

		mapper = dataP->fMapper;
		dataP->fMappedBaseValid = dataP->fMappedBase = 0;

		uplFlags |= UPL_SET_IO_WIRE | UPL_SET_LITE;
		tag = _kernelTag;
		if (VM_KERN_MEMORY_NONE == tag) {
			tag = IOMemoryTag(kernel_map);
		}

		if (kIODirectionPrepareToPhys32 & forDirection) {
			if (!mapper) {
				uplFlags |= UPL_NEED_32BIT_ADDR;
			}
			if (dataP->fDMAMapNumAddressBits > 32) {
				dataP->fDMAMapNumAddressBits = 32;
			}
		}
		if (kIODirectionPrepareNoFault    & forDirection) {
			uplFlags |= UPL_REQUEST_NO_FAULT;
		}
		if (kIODirectionPrepareNoZeroFill & forDirection) {
			uplFlags |= UPL_NOZEROFILLIO;
		}
		if (kIODirectionPrepareNonCoherent & forDirection) {
			uplFlags |= UPL_REQUEST_FORCE_COHERENCY;
		}

		mapBase = 0;

		// Note that appendBytes(NULL) zeros the data up to the desired length
		//           and the length parameter is an unsigned int
		size_t uplPageSize = dataP->fPageCnt * sizeof(upl_page_info_t);
		if (uplPageSize > ((unsigned int)uplPageSize)) {
			return kIOReturnNoMemory;
		}
		if (!_memoryEntries->appendBytes(NULL, uplPageSize)) {
			return kIOReturnNoMemory;
		}
		dataP = NULL;

		// Find the appropriate vm_map for the given task
		vm_map_t curMap;
		if ((NULL != _memRef) || ((_task == kernel_task && (kIOMemoryBufferPageable & _flags)))) {
			curMap = NULL;
		} else {
			curMap = get_task_map(_task);
		}

		// Iterate over the vector of virtual ranges
		Ranges vec = _ranges;
		unsigned int pageIndex  = 0;
		IOByteCount mdOffset    = 0;
		ppnum_t highestPage     = 0;

		IOMemoryEntry * memRefEntry = NULL;
		if (_memRef) {
			memRefEntry = &_memRef->entries[0];
		}

		for (UInt range = 0; range < _rangesCount; range++) {
			ioPLBlock iopl;
			mach_vm_address_t startPage, startPageOffset;
			mach_vm_size_t    numBytes;
			ppnum_t highPage = 0;

			// Get the startPage address and length of vec[range]
			getAddrLenForInd(startPage, numBytes, type, vec, range);
			startPageOffset = startPage & PAGE_MASK;
			iopl.fPageOffset = startPageOffset;
			numBytes += startPageOffset;
			startPage = trunc_page_64(startPage);

			if (mapper) {
				iopl.fMappedPage = mapBase + pageIndex;
			} else {
				iopl.fMappedPage = 0;
			}

			// Iterate over the current range, creating UPLs
			while (numBytes) {
				vm_address_t kernelStart = (vm_address_t) startPage;
				vm_map_t theMap;
				if (curMap) {
					theMap = curMap;
				} else if (_memRef) {
					theMap = NULL;
				} else {
					assert(_task == kernel_task);
					theMap = IOPageableMapForAddress(kernelStart);
				}

				// ioplFlags is an in/out parameter
				upl_control_flags_t ioplFlags = uplFlags;
				dataP = getDataP(_memoryEntries);
				pageInfo = getPageList(dataP);
				upl_page_list_ptr_t baseInfo = &pageInfo[pageIndex];

				mach_vm_size_t _ioplSize    = round_page(numBytes);
				upl_size_t          ioplSize    = (_ioplSize <= MAX_UPL_SIZE_BYTES) ? _ioplSize : MAX_UPL_SIZE_BYTES;
				unsigned int    numPageInfo = atop_32(ioplSize);

				if ((theMap == kernel_map)
				    && (kernelStart >= io_kernel_static_start)
				    && (kernelStart < io_kernel_static_end)) {
					error = io_get_kernel_static_upl(theMap,
					    kernelStart,
					    &ioplSize,
					    &iopl.fIOPL,
					    baseInfo,
					    &numPageInfo,
					    &highPage);
				} else if (_memRef) {
					memory_object_offset_t entryOffset;

					entryOffset = mdOffset;
					entryOffset = (entryOffset - iopl.fPageOffset - memRefEntry->offset);
					if (entryOffset >= memRefEntry->size) {
						memRefEntry++;
						if (memRefEntry >= &_memRef->entries[_memRef->count]) {
							panic("memRefEntry");
						}
						entryOffset = 0;
					}
					if (ioplSize > (memRefEntry->size - entryOffset)) {
						ioplSize = (memRefEntry->size - entryOffset);
					}
					error = memory_object_iopl_request(memRefEntry->entry,
					    entryOffset,
					    &ioplSize,
					    &iopl.fIOPL,
					    baseInfo,
					    &numPageInfo,
					    &ioplFlags,
					    tag);
				} else {
					assert(theMap);
					error = vm_map_create_upl(theMap,
					    startPage,
					    (upl_size_t*)&ioplSize,
					    &iopl.fIOPL,
					    baseInfo,
					    &numPageInfo,
					    &ioplFlags,
					    tag);
				}

				if (error != KERN_SUCCESS) {
					goto abortExit;
				}

				assert(ioplSize);

				if (iopl.fIOPL) {
					highPage = upl_get_highest_page(iopl.fIOPL);
				}
				if (highPage > highestPage) {
					highestPage = highPage;
				}

				if (baseInfo->device) {
					numPageInfo = 1;
					iopl.fFlags = kIOPLOnDevice;
				} else {
					iopl.fFlags = 0;
				}

				iopl.fIOMDOffset = mdOffset;
				iopl.fPageInfo = pageIndex;
				if (mapper && pageIndex && (page_mask & (mdOffset + startPageOffset))) {
					dataP->fDiscontig = true;
				}

				if (!_memoryEntries->appendBytes(&iopl, sizeof(iopl))) {
					// Clean up partial created and unsaved iopl
					if (iopl.fIOPL) {
						upl_abort(iopl.fIOPL, 0);
						upl_deallocate(iopl.fIOPL);
					}
					error = kIOReturnNoMemory;
					goto abortExit;
				}
				dataP = NULL;

				// Check for a multiple iopl's in one virtual range
				pageIndex += numPageInfo;
				mdOffset -= iopl.fPageOffset;
				if (ioplSize < numBytes) {
					numBytes -= ioplSize;
					startPage += ioplSize;
					mdOffset += ioplSize;
					iopl.fPageOffset = 0;
					if (mapper) {
						iopl.fMappedPage = mapBase + pageIndex;
					}
				} else {
					mdOffset += numBytes;
					break;
				}
			}
		}

		_highestPage = highestPage;

		if (UPL_COPYOUT_FROM & uplFlags) {
			_flags |= kIOMemoryPreparedReadOnly;
		}
	}

#if IOTRACKING
	if (!(_flags & kIOMemoryAutoPrepare) && (kIOReturnSuccess == error)) {
		dataP = getDataP(_memoryEntries);
		if (!dataP->fWireTracking.link.next) {
			IOTrackingAdd(gIOWireTracking, &dataP->fWireTracking, ptoa(_pages), false, tag);
		}
	}
#endif /* IOTRACKING */

	return error;

abortExit:
	{
		dataP = getDataP(_memoryEntries);
		UInt done = getNumIOPL(_memoryEntries, dataP);
		ioPLBlock *ioplList = getIOPLList(dataP);

		for (UInt range = 0; range < done; range++) {
			if (ioplList[range].fIOPL) {
				upl_abort(ioplList[range].fIOPL, 0);
				upl_deallocate(ioplList[range].fIOPL);
			}
		}
		(void) _memoryEntries->initWithBytes(dataP, computeDataSize(0, 0)); // == setLength()
	}

	if (error == KERN_FAILURE) {
		error = kIOReturnCannotWire;
	} else if (error == KERN_MEMORY_ERROR) {
		error = kIOReturnNoResources;
	}

	return error;
}

bool
IOGeneralMemoryDescriptor::initMemoryEntries(size_t size, IOMapper * mapper)
{
	ioGMDData * dataP;
	unsigned    dataSize = size;

	if (!_memoryEntries) {
		_memoryEntries = OSData::withCapacity(dataSize);
		if (!_memoryEntries) {
			return false;
		}
	} else if (!_memoryEntries->initWithCapacity(dataSize)) {
		return false;
	}

	_memoryEntries->appendBytes(NULL, computeDataSize(0, 0));
	dataP = getDataP(_memoryEntries);

	if (mapper == kIOMapperWaitSystem) {
		IOMapper::checkForSystemMapper();
		mapper = IOMapper::gSystem;
	}
	dataP->fMapper               = mapper;
	dataP->fPageCnt              = 0;
	dataP->fMappedBase           = 0;
	dataP->fDMAMapNumAddressBits = 64;
	dataP->fDMAMapAlignment      = 0;
	dataP->fPreparationID        = kIOPreparationIDUnprepared;
	dataP->fDiscontig            = false;
	dataP->fCompletionError      = false;
	dataP->fMappedBaseValid      = false;

	return true;
}

IOReturn
IOMemoryDescriptor::dmaMap(
	IOMapper                    * mapper,
	IODMACommand                * command,
	const IODMAMapSpecification * mapSpec,
	uint64_t                      offset,
	uint64_t                      length,
	uint64_t                    * mapAddress,
	uint64_t                    * mapLength)
{
	IOReturn err;
	uint32_t mapOptions;

	mapOptions = 0;
	mapOptions |= kIODMAMapReadAccess;
	if (!(kIOMemoryPreparedReadOnly & _flags)) {
		mapOptions |= kIODMAMapWriteAccess;
	}

	err = mapper->iovmMapMemory(this, offset, length, mapOptions,
	    mapSpec, command, NULL, mapAddress, mapLength);

	if (kIOReturnSuccess == err) {
		dmaMapRecord(mapper, command, *mapLength);
	}

	return err;
}

void
IOMemoryDescriptor::dmaMapRecord(
	IOMapper                    * mapper,
	IODMACommand                * command,
	uint64_t                      mapLength)
{
	kern_allocation_name_t alloc;
	int16_t                prior;

	if ((alloc = mapper->fAllocName) /* && mapper != IOMapper::gSystem */) {
		kern_allocation_update_size(mapper->fAllocName, mapLength);
	}

	if (!command) {
		return;
	}
	prior = OSAddAtomic16(1, &_dmaReferences);
	if (!prior) {
		if (alloc && (VM_KERN_MEMORY_NONE != _kernelTag)) {
			_mapName  = alloc;
			mapLength = _length;
			kern_allocation_update_subtotal(alloc, _kernelTag, mapLength);
		} else {
			_mapName = NULL;
		}
	}
}

IOReturn
IOMemoryDescriptor::dmaUnmap(
	IOMapper                    * mapper,
	IODMACommand                * command,
	uint64_t                      offset,
	uint64_t                      mapAddress,
	uint64_t                      mapLength)
{
	IOReturn ret;
	kern_allocation_name_t alloc;
	kern_allocation_name_t mapName;
	int16_t prior;

	mapName = NULL;
	prior = 0;
	if (command) {
		mapName = _mapName;
		if (_dmaReferences) {
			prior = OSAddAtomic16(-1, &_dmaReferences);
		} else {
			panic("_dmaReferences underflow");
		}
	}

	if (!mapLength) {
		return kIOReturnSuccess;
	}

	ret = mapper->iovmUnmapMemory(this, command, mapAddress, mapLength);

	if ((alloc = mapper->fAllocName)) {
		kern_allocation_update_size(alloc, -mapLength);
		if ((1 == prior) && mapName && (VM_KERN_MEMORY_NONE != _kernelTag)) {
			mapLength = _length;
			kern_allocation_update_subtotal(mapName, _kernelTag, -mapLength);
		}
	}

	return ret;
}

IOReturn
IOGeneralMemoryDescriptor::dmaMap(
	IOMapper                    * mapper,
	IODMACommand                * command,
	const IODMAMapSpecification * mapSpec,
	uint64_t                      offset,
	uint64_t                      length,
	uint64_t                    * mapAddress,
	uint64_t                    * mapLength)
{
	IOReturn          err = kIOReturnSuccess;
	ioGMDData *       dataP;
	IOOptionBits      type = _flags & kIOMemoryTypeMask;

	*mapAddress = 0;
	if (kIOMemoryHostOnly & _flags) {
		return kIOReturnSuccess;
	}
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if ((type == kIOMemoryTypePhysical) || (type == kIOMemoryTypePhysical64)
	    || offset || (length != _length)) {
		err = super::dmaMap(mapper, command, mapSpec, offset, length, mapAddress, mapLength);
	} else if (_memoryEntries && _pages && (dataP = getDataP(_memoryEntries))) {
		const ioPLBlock * ioplList = getIOPLList(dataP);
		upl_page_info_t * pageList;
		uint32_t          mapOptions = 0;

		IODMAMapSpecification mapSpec;
		bzero(&mapSpec, sizeof(mapSpec));
		mapSpec.numAddressBits = dataP->fDMAMapNumAddressBits;
		mapSpec.alignment = dataP->fDMAMapAlignment;

		// For external UPLs the fPageInfo field points directly to
		// the upl's upl_page_info_t array.
		if (ioplList->fFlags & kIOPLExternUPL) {
			pageList = (upl_page_info_t *) ioplList->fPageInfo;
			mapOptions |= kIODMAMapPagingPath;
		} else {
			pageList = getPageList(dataP);
		}

		if ((_length == ptoa_64(_pages)) && !(page_mask & ioplList->fPageOffset)) {
			mapOptions |= kIODMAMapPageListFullyOccupied;
		}

		assert(dataP->fDMAAccess);
		mapOptions |= dataP->fDMAAccess;

		// Check for direct device non-paged memory
		if (ioplList->fFlags & kIOPLOnDevice) {
			mapOptions |= kIODMAMapPhysicallyContiguous;
		}

		IODMAMapPageList dmaPageList =
		{
			.pageOffset    = (uint32_t)(ioplList->fPageOffset & page_mask),
			.pageListCount = _pages,
			.pageList      = &pageList[0]
		};
		err = mapper->iovmMapMemory(this, offset, length, mapOptions, &mapSpec,
		    command, &dmaPageList, mapAddress, mapLength);

		if (kIOReturnSuccess == err) {
			dmaMapRecord(mapper, command, *mapLength);
		}
	}

	return err;
}

/*
 * prepare
 *
 * Prepare the memory for an I/O transfer.  This involves paging in
 * the memory, if necessary, and wiring it down for the duration of
 * the transfer.  The complete() method completes the processing of
 * the memory after the I/O transfer finishes.  This method needn't
 * called for non-pageable memory.
 */

IOReturn
IOGeneralMemoryDescriptor::prepare(IODirection forDirection)
{
	IOReturn     error    = kIOReturnSuccess;
	IOOptionBits type = _flags & kIOMemoryTypeMask;

	if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
		return kIOReturnSuccess;
	}

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (_prepareLock) {
		IOLockLock(_prepareLock);
	}

	if (kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type) {
		if ((forDirection & kIODirectionPrepareAvoidThrottling) && NEED_TO_HARD_THROTTLE_THIS_TASK()) {
			error = kIOReturnNotReady;
			goto finish;
		}
		error = wireVirtual(forDirection);
	}

	if (kIOReturnSuccess == error) {
		if (1 == ++_wireCount) {
			if (kIOMemoryClearEncrypt & _flags) {
				performOperation(kIOMemoryClearEncrypted, 0, _length);
			}
		}
	}

finish:

	if (_prepareLock) {
		IOLockUnlock(_prepareLock);
	}

	return error;
}

/*
 * complete
 *
 * Complete processing of the memory after an I/O transfer finishes.
 * This method should not be called unless a prepare was previously
 * issued; the prepare() and complete() must occur in pairs, before
 * before and after an I/O transfer involving pageable memory.
 */

IOReturn
IOGeneralMemoryDescriptor::complete(IODirection forDirection)
{
	IOOptionBits type = _flags & kIOMemoryTypeMask;
	ioGMDData  * dataP;

	if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
		return kIOReturnSuccess;
	}

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return kIOReturnNotAttached;
	}

	if (_prepareLock) {
		IOLockLock(_prepareLock);
	}
	do{
		assert(_wireCount);
		if (!_wireCount) {
			break;
		}
		dataP = getDataP(_memoryEntries);
		if (!dataP) {
			break;
		}

		if (kIODirectionCompleteWithError & forDirection) {
			dataP->fCompletionError = true;
		}

		if ((kIOMemoryClearEncrypt & _flags) && (1 == _wireCount)) {
			performOperation(kIOMemorySetEncrypted, 0, _length);
		}

		_wireCount--;
		if (!_wireCount || (kIODirectionCompleteWithDataValid & forDirection)) {
			ioPLBlock *ioplList = getIOPLList(dataP);
			UInt ind, count = getNumIOPL(_memoryEntries, dataP);

			if (_wireCount) {
				// kIODirectionCompleteWithDataValid & forDirection
				if (kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type) {
					vm_tag_t tag;
					tag = getVMTag(kernel_map);
					for (ind = 0; ind < count; ind++) {
						if (ioplList[ind].fIOPL) {
							iopl_valid_data(ioplList[ind].fIOPL, tag);
						}
					}
				}
			} else {
				if (_dmaReferences) {
					panic("complete() while dma active");
				}

				if (dataP->fMappedBaseValid) {
					dmaUnmap(dataP->fMapper, NULL, 0, dataP->fMappedBase, dataP->fMappedLength);
					dataP->fMappedBaseValid = dataP->fMappedBase = 0;
				}
#if IOTRACKING
				if (dataP->fWireTracking.link.next) {
					IOTrackingRemove(gIOWireTracking, &dataP->fWireTracking, ptoa(_pages));
				}
#endif /* IOTRACKING */
				// Only complete iopls that we created which are for TypeVirtual
				if (kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type) {
					for (ind = 0; ind < count; ind++) {
						if (ioplList[ind].fIOPL) {
							if (dataP->fCompletionError) {
								upl_abort(ioplList[ind].fIOPL, 0 /*!UPL_ABORT_DUMP_PAGES*/);
							} else {
								upl_commit(ioplList[ind].fIOPL, NULL, 0);
							}
							upl_deallocate(ioplList[ind].fIOPL);
						}
					}
				} else if (kIOMemoryTypeUPL == type) {
					upl_set_referenced(ioplList[0].fIOPL, false);
				}

				(void) _memoryEntries->initWithBytes(dataP, computeDataSize(0, 0)); // == setLength()

				dataP->fPreparationID = kIOPreparationIDUnprepared;
				_flags &= ~kIOMemoryPreparedReadOnly;
			}
		}
	}while (false);

	if (_prepareLock) {
		IOLockUnlock(_prepareLock);
	}

	return kIOReturnSuccess;
}

IOReturn
IOGeneralMemoryDescriptor::doMap(
	vm_map_t                __addressMap,
	IOVirtualAddress *      __address,
	IOOptionBits            options,
	IOByteCount             __offset,
	IOByteCount             __length )
{
#ifndef __LP64__
	if (!(kIOMap64Bit & options)) {
		panic("IOGeneralMemoryDescriptor::doMap !64bit");
	}
#endif /* !__LP64__ */

	kern_return_t  err;

	IOMemoryMap *  mapping = (IOMemoryMap *) *__address;
	mach_vm_size_t offset  = mapping->fOffset + __offset;
	mach_vm_size_t length  = mapping->fLength;

	IOOptionBits type = _flags & kIOMemoryTypeMask;
	Ranges vec = _ranges;

	mach_vm_address_t range0Addr = 0;
	mach_vm_size_t    range0Len = 0;

	if ((offset >= _length) || ((offset + length) > _length)) {
		return kIOReturnBadArgument;
	}

	assert(!(kIOMemoryRemote & _flags));
	if (kIOMemoryRemote & _flags) {
		return 0;
	}

	if (vec.v) {
		getAddrLenForInd(range0Addr, range0Len, type, vec, 0);
	}

	// mapping source == dest? (could be much better)
	if (_task
	    && (mapping->fAddressTask == _task)
	    && (mapping->fAddressMap == get_task_map(_task))
	    && (options & kIOMapAnywhere)
	    && (!(kIOMapUnique & options))
	    && (1 == _rangesCount)
	    && (0 == offset)
	    && range0Addr
	    && (length <= range0Len)) {
		mapping->fAddress = range0Addr;
		mapping->fOptions |= kIOMapStatic;

		return kIOReturnSuccess;
	}

	if (!_memRef) {
		IOOptionBits createOptions = 0;
		if (!(kIOMapReadOnly & options)) {
			createOptions |= kIOMemoryReferenceWrite;
#if DEVELOPMENT || DEBUG
			if ((kIODirectionOut == (kIODirectionOutIn & _flags))
			    && (!reserved || (reserved->creator != mapping->fAddressTask))) {
				OSReportWithBacktrace("warning: creating writable mapping from IOMemoryDescriptor(kIODirectionOut) - use kIOMapReadOnly or change direction");
			}
#endif
		}
		err = memoryReferenceCreate(createOptions, &_memRef);
		if (kIOReturnSuccess != err) {
			return err;
		}
	}

	memory_object_t pager;
	pager = (memory_object_t) (reserved ? reserved->dp.devicePager : NULL);

	// <upl_transpose //
	if ((kIOMapReference | kIOMapUnique) == ((kIOMapReference | kIOMapUnique) & options)) {
		do{
			upl_t               redirUPL2;
			upl_size_t          size;
			upl_control_flags_t flags;
			unsigned int        lock_count;

			if (!_memRef || (1 != _memRef->count)) {
				err = kIOReturnNotReadable;
				break;
			}

			size = round_page(mapping->fLength);
			flags = UPL_COPYOUT_FROM | UPL_SET_INTERNAL
			    | UPL_SET_LITE | UPL_SET_IO_WIRE | UPL_BLOCK_ACCESS;

			if (KERN_SUCCESS != memory_object_iopl_request(_memRef->entries[0].entry, 0, &size, &redirUPL2,
			    NULL, NULL,
			    &flags, getVMTag(kernel_map))) {
				redirUPL2 = NULL;
			}

			for (lock_count = 0;
			    IORecursiveLockHaveLock(gIOMemoryLock);
			    lock_count++) {
				UNLOCK;
			}
			err = upl_transpose(redirUPL2, mapping->fRedirUPL);
			for (;
			    lock_count;
			    lock_count--) {
				LOCK;
			}

			if (kIOReturnSuccess != err) {
				IOLog("upl_transpose(%x)\n", err);
				err = kIOReturnSuccess;
			}

			if (redirUPL2) {
				upl_commit(redirUPL2, NULL, 0);
				upl_deallocate(redirUPL2);
				redirUPL2 = NULL;
			}
			{
				// swap the memEntries since they now refer to different vm_objects
				IOMemoryReference * me = _memRef;
				_memRef = mapping->fMemory->_memRef;
				mapping->fMemory->_memRef = me;
			}
			if (pager) {
				err = populateDevicePager( pager, mapping->fAddressMap, mapping->fAddress, offset, length, options );
			}
		}while (false);
	}
	// upl_transpose> //
	else {
		err = memoryReferenceMap(_memRef, mapping->fAddressMap, offset, length, options, &mapping->fAddress);
#if IOTRACKING
		if ((err == KERN_SUCCESS) && ((kIOTracking & gIOKitDebug) || _task)) {
			// only dram maps in the default on developement case
			IOTrackingAddUser(gIOMapTracking, &mapping->fTracking, mapping->fLength);
		}
#endif /* IOTRACKING */
		if ((err == KERN_SUCCESS) && pager) {
			err = populateDevicePager(pager, mapping->fAddressMap, mapping->fAddress, offset, length, options);

			if (err != KERN_SUCCESS) {
				doUnmap(mapping->fAddressMap, (IOVirtualAddress) mapping, 0);
			} else if (kIOMapDefaultCache == (options & kIOMapCacheMask)) {
				mapping->fOptions |= ((_flags & kIOMemoryBufferCacheMask) >> kIOMemoryBufferCacheShift);
			}
		}
	}

	return err;
}

#if IOTRACKING
IOReturn
IOMemoryMapTracking(IOTrackingUser * tracking, task_t * task,
    mach_vm_address_t * address, mach_vm_size_t * size)
{
#define iomap_offsetof(type, field) ((size_t)(&((type *)NULL)->field))

	IOMemoryMap * map = (typeof(map))(((uintptr_t) tracking) - iomap_offsetof(IOMemoryMap, fTracking));

	if (!map->fAddressMap || (map->fAddressMap != get_task_map(map->fAddressTask))) {
		return kIOReturnNotReady;
	}

	*task    = map->fAddressTask;
	*address = map->fAddress;
	*size    = map->fLength;

	return kIOReturnSuccess;
}
#endif /* IOTRACKING */

IOReturn
IOGeneralMemoryDescriptor::doUnmap(
	vm_map_t                addressMap,
	IOVirtualAddress        __address,
	IOByteCount             __length )
{
	return super::doUnmap(addressMap, __address, __length);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSObject

OSDefineMetaClassAndStructors( IOMemoryMap, OSObject )

OSMetaClassDefineReservedUnused(IOMemoryMap, 0);
OSMetaClassDefineReservedUnused(IOMemoryMap, 1);
OSMetaClassDefineReservedUnused(IOMemoryMap, 2);
OSMetaClassDefineReservedUnused(IOMemoryMap, 3);
OSMetaClassDefineReservedUnused(IOMemoryMap, 4);
OSMetaClassDefineReservedUnused(IOMemoryMap, 5);
OSMetaClassDefineReservedUnused(IOMemoryMap, 6);
OSMetaClassDefineReservedUnused(IOMemoryMap, 7);

/* ex-inline function implementation */
IOPhysicalAddress
IOMemoryMap::getPhysicalAddress()
{
	return getPhysicalSegment( 0, NULL );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOMemoryMap::init(
	task_t                  intoTask,
	mach_vm_address_t       toAddress,
	IOOptionBits            _options,
	mach_vm_size_t          _offset,
	mach_vm_size_t          _length )
{
	if (!intoTask) {
		return false;
	}

	if (!super::init()) {
		return false;
	}

	fAddressMap  = get_task_map(intoTask);
	if (!fAddressMap) {
		return false;
	}
	vm_map_reference(fAddressMap);

	fAddressTask = intoTask;
	fOptions     = _options;
	fLength      = _length;
	fOffset      = _offset;
	fAddress     = toAddress;

	return true;
}

bool
IOMemoryMap::setMemoryDescriptor(IOMemoryDescriptor * _memory, mach_vm_size_t _offset)
{
	if (!_memory) {
		return false;
	}

	if (!fSuperMap) {
		if ((_offset + fLength) > _memory->getLength()) {
			return false;
		}
		fOffset = _offset;
	}

	_memory->retain();
	if (fMemory) {
		if (fMemory != _memory) {
			fMemory->removeMapping(this);
		}
		fMemory->release();
	}
	fMemory = _memory;

	return true;
}

IOReturn
IOMemoryDescriptor::doMap(
	vm_map_t                __addressMap,
	IOVirtualAddress *      __address,
	IOOptionBits            options,
	IOByteCount             __offset,
	IOByteCount             __length )
{
	return kIOReturnUnsupported;
}

IOReturn
IOMemoryDescriptor::handleFault(
	void *                  _pager,
	mach_vm_size_t          sourceOffset,
	mach_vm_size_t          length)
{
	if (kIOMemoryRedirected & _flags) {
#if DEBUG
		IOLog("sleep mem redirect %p, %qx\n", this, sourceOffset);
#endif
		do {
			SLEEP;
		} while (kIOMemoryRedirected & _flags);
	}
	return kIOReturnSuccess;
}

IOReturn
IOMemoryDescriptor::populateDevicePager(
	void *                  _pager,
	vm_map_t                addressMap,
	mach_vm_address_t       address,
	mach_vm_size_t          sourceOffset,
	mach_vm_size_t          length,
	IOOptionBits            options )
{
	IOReturn            err = kIOReturnSuccess;
	memory_object_t     pager = (memory_object_t) _pager;
	mach_vm_size_t      size;
	mach_vm_size_t      bytes;
	mach_vm_size_t      page;
	mach_vm_size_t      pageOffset;
	mach_vm_size_t      pagerOffset;
	IOPhysicalLength    segLen, chunk;
	addr64_t            physAddr;
	IOOptionBits        type;

	type = _flags & kIOMemoryTypeMask;

	if (reserved->dp.pagerContig) {
		sourceOffset = 0;
		pagerOffset  = 0;
	}

	physAddr = getPhysicalSegment( sourceOffset, &segLen, kIOMemoryMapperNone );
	assert( physAddr );
	pageOffset = physAddr - trunc_page_64( physAddr );
	pagerOffset = sourceOffset;

	size = length + pageOffset;
	physAddr -= pageOffset;

	segLen += pageOffset;
	bytes = size;
	do{
		// in the middle of the loop only map whole pages
		if (segLen >= bytes) {
			segLen = bytes;
		} else if (segLen != trunc_page_64(segLen)) {
			err = kIOReturnVMError;
		}
		if (physAddr != trunc_page_64(physAddr)) {
			err = kIOReturnBadArgument;
		}

		if (kIOReturnSuccess != err) {
			break;
		}

#if DEBUG || DEVELOPMENT
		if ((kIOMemoryTypeUPL != type)
		    && pmap_has_managed_page(atop_64(physAddr), atop_64(physAddr + segLen - 1))) {
			OSReportWithBacktrace("IOMemoryDescriptor physical with managed page 0x%qx:0x%qx", physAddr, segLen);
		}
#endif /* DEBUG || DEVELOPMENT */

		chunk = (reserved->dp.pagerContig ? round_page(segLen) : page_size);
		for (page = 0;
		    (page < segLen) && (KERN_SUCCESS == err);
		    page += chunk) {
			err = device_pager_populate_object(pager, pagerOffset,
			    (ppnum_t)(atop_64(physAddr + page)), chunk);
			pagerOffset += chunk;
		}

		assert(KERN_SUCCESS == err);
		if (err) {
			break;
		}

		// This call to vm_fault causes an early pmap level resolution
		// of the mappings created above for kernel mappings, since
		// faulting in later can't take place from interrupt level.
		if ((addressMap == kernel_map) && !(kIOMemoryRedirected & _flags)) {
			err = vm_fault(addressMap,
			    (vm_map_offset_t)trunc_page_64(address),
			    options & kIOMapReadOnly ? VM_PROT_READ : VM_PROT_READ | VM_PROT_WRITE,
			    FALSE, VM_KERN_MEMORY_NONE,
			    THREAD_UNINT, NULL,
			    (vm_map_offset_t)0);

			if (KERN_SUCCESS != err) {
				break;
			}
		}

		sourceOffset += segLen - pageOffset;
		address += segLen;
		bytes -= segLen;
		pageOffset = 0;
	}while (bytes && (physAddr = getPhysicalSegment( sourceOffset, &segLen, kIOMemoryMapperNone )));

	if (bytes) {
		err = kIOReturnBadArgument;
	}

	return err;
}

IOReturn
IOMemoryDescriptor::doUnmap(
	vm_map_t                addressMap,
	IOVirtualAddress        __address,
	IOByteCount             __length )
{
	IOReturn          err;
	IOMemoryMap *     mapping;
	mach_vm_address_t address;
	mach_vm_size_t    length;

	if (__length) {
		panic("doUnmap");
	}

	mapping = (IOMemoryMap *) __address;
	addressMap = mapping->fAddressMap;
	address    = mapping->fAddress;
	length     = mapping->fLength;

	if (kIOMapOverwrite & mapping->fOptions) {
		err = KERN_SUCCESS;
	} else {
		if ((addressMap == kernel_map) && (kIOMemoryBufferPageable & _flags)) {
			addressMap = IOPageableMapForAddress( address );
		}
#if DEBUG
		if (kIOLogMapping & gIOKitDebug) {
			IOLog("IOMemoryDescriptor::doUnmap map %p, 0x%qx:0x%qx\n",
			    addressMap, address, length );
		}
#endif
		err = mach_vm_deallocate( addressMap, address, length );
	}

#if IOTRACKING
	IOTrackingRemoveUser(gIOMapTracking, &mapping->fTracking);
#endif /* IOTRACKING */

	return err;
}

IOReturn
IOMemoryDescriptor::redirect( task_t safeTask, bool doRedirect )
{
	IOReturn            err = kIOReturnSuccess;
	IOMemoryMap *       mapping = NULL;
	OSIterator *        iter;

	LOCK;

	if (doRedirect) {
		_flags |= kIOMemoryRedirected;
	} else {
		_flags &= ~kIOMemoryRedirected;
	}

	do {
		if ((iter = OSCollectionIterator::withCollection( _mappings))) {
			memory_object_t   pager;

			if (reserved) {
				pager = (memory_object_t) reserved->dp.devicePager;
			} else {
				pager = MACH_PORT_NULL;
			}

			while ((mapping = (IOMemoryMap *) iter->getNextObject())) {
				mapping->redirect( safeTask, doRedirect );
				if (!doRedirect && !safeTask && pager && (kernel_map == mapping->fAddressMap)) {
					err = populateDevicePager(pager, mapping->fAddressMap, mapping->fAddress, mapping->fOffset, mapping->fLength, kIOMapDefaultCache );
				}
			}

			iter->release();
		}
	} while (false);

	if (!doRedirect) {
		WAKEUP;
	}

	UNLOCK;

#ifndef __LP64__
	// temporary binary compatibility
	IOSubMemoryDescriptor * subMem;
	if ((subMem = OSDynamicCast( IOSubMemoryDescriptor, this))) {
		err = subMem->redirect( safeTask, doRedirect );
	} else {
		err = kIOReturnSuccess;
	}
#endif /* !__LP64__ */

	return err;
}

IOReturn
IOMemoryMap::redirect( task_t safeTask, bool doRedirect )
{
	IOReturn err = kIOReturnSuccess;

	if (fSuperMap) {
//        err = ((IOMemoryMap *)superMap)->redirect( safeTask, doRedirect );
	} else {
		LOCK;

		do{
			if (!fAddress) {
				break;
			}
			if (!fAddressMap) {
				break;
			}

			if ((!safeTask || (get_task_map(safeTask) != fAddressMap))
			    && (0 == (fOptions & kIOMapStatic))) {
				IOUnmapPages( fAddressMap, fAddress, fLength );
				err = kIOReturnSuccess;
#if DEBUG
				IOLog("IOMemoryMap::redirect(%d, %p) 0x%qx:0x%qx from %p\n", doRedirect, this, fAddress, fLength, fAddressMap);
#endif
			} else if (kIOMapWriteCombineCache == (fOptions & kIOMapCacheMask)) {
				IOOptionBits newMode;
				newMode = (fOptions & ~kIOMapCacheMask) | (doRedirect ? kIOMapInhibitCache : kIOMapWriteCombineCache);
				IOProtectCacheMode(fAddressMap, fAddress, fLength, newMode);
			}
		}while (false);
		UNLOCK;
	}

	if ((((fMemory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
	    || ((fMemory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64))
	    && safeTask
	    && (doRedirect != (0 != (fMemory->_flags & kIOMemoryRedirected)))) {
		fMemory->redirect(safeTask, doRedirect);
	}

	return err;
}

IOReturn
IOMemoryMap::unmap( void )
{
	IOReturn    err;

	LOCK;

	if (fAddress && fAddressMap && (NULL == fSuperMap) && fMemory
	    && (0 == (kIOMapStatic & fOptions))) {
		err = fMemory->doUnmap(fAddressMap, (IOVirtualAddress) this, 0);
	} else {
		err = kIOReturnSuccess;
	}

	if (fAddressMap) {
		vm_map_deallocate(fAddressMap);
		fAddressMap = NULL;
	}

	fAddress = 0;

	UNLOCK;

	return err;
}

void
IOMemoryMap::taskDied( void )
{
	LOCK;
	if (fUserClientUnmap) {
		unmap();
	}
#if IOTRACKING
	else {
		IOTrackingRemoveUser(gIOMapTracking, &fTracking);
	}
#endif /* IOTRACKING */

	if (fAddressMap) {
		vm_map_deallocate(fAddressMap);
		fAddressMap = NULL;
	}
	fAddressTask = NULL;
	fAddress     = 0;
	UNLOCK;
}

IOReturn
IOMemoryMap::userClientUnmap( void )
{
	fUserClientUnmap = true;
	return kIOReturnSuccess;
}

// Overload the release mechanism.  All mappings must be a member
// of a memory descriptors _mappings set.  This means that we
// always have 2 references on a mapping.  When either of these mappings
// are released we need to free ourselves.
void
IOMemoryMap::taggedRelease(const void *tag) const
{
	LOCK;
	super::taggedRelease(tag, 2);
	UNLOCK;
}

void
IOMemoryMap::free()
{
	unmap();

	if (fMemory) {
		LOCK;
		fMemory->removeMapping(this);
		UNLOCK;
		fMemory->release();
	}

	if (fOwner && (fOwner != fMemory)) {
		LOCK;
		fOwner->removeMapping(this);
		UNLOCK;
	}

	if (fSuperMap) {
		fSuperMap->release();
	}

	if (fRedirUPL) {
		upl_commit(fRedirUPL, NULL, 0);
		upl_deallocate(fRedirUPL);
	}

	super::free();
}

IOByteCount
IOMemoryMap::getLength()
{
	return fLength;
}

IOVirtualAddress
IOMemoryMap::getVirtualAddress()
{
#ifndef __LP64__
	if (fSuperMap) {
		fSuperMap->getVirtualAddress();
	} else if (fAddressMap
	    && vm_map_is_64bit(fAddressMap)
	    && (sizeof(IOVirtualAddress) < 8)) {
		OSReportWithBacktrace("IOMemoryMap::getVirtualAddress(0x%qx) called on 64b map; use ::getAddress()", fAddress);
	}
#endif /* !__LP64__ */

	return fAddress;
}

#ifndef __LP64__
mach_vm_address_t
IOMemoryMap::getAddress()
{
	return fAddress;
}

mach_vm_size_t
IOMemoryMap::getSize()
{
	return fLength;
}
#endif /* !__LP64__ */


task_t
IOMemoryMap::getAddressTask()
{
	if (fSuperMap) {
		return fSuperMap->getAddressTask();
	} else {
		return fAddressTask;
	}
}

IOOptionBits
IOMemoryMap::getMapOptions()
{
	return fOptions;
}

IOMemoryDescriptor *
IOMemoryMap::getMemoryDescriptor()
{
	return fMemory;
}

IOMemoryMap *
IOMemoryMap::copyCompatible(
	IOMemoryMap * newMapping )
{
	task_t              task      = newMapping->getAddressTask();
	mach_vm_address_t   toAddress = newMapping->fAddress;
	IOOptionBits        _options  = newMapping->fOptions;
	mach_vm_size_t      _offset   = newMapping->fOffset;
	mach_vm_size_t      _length   = newMapping->fLength;

	if ((!task) || (!fAddressMap) || (fAddressMap != get_task_map(task))) {
		return NULL;
	}
	if ((fOptions ^ _options) & kIOMapReadOnly) {
		return NULL;
	}
	if ((kIOMapDefaultCache != (_options & kIOMapCacheMask))
	    && ((fOptions ^ _options) & kIOMapCacheMask)) {
		return NULL;
	}

	if ((0 == (_options & kIOMapAnywhere)) && (fAddress != toAddress)) {
		return NULL;
	}

	if (_offset < fOffset) {
		return NULL;
	}

	_offset -= fOffset;

	if ((_offset + _length) > fLength) {
		return NULL;
	}

	retain();
	if ((fLength == _length) && (!_offset)) {
		newMapping = this;
	} else {
		newMapping->fSuperMap = this;
		newMapping->fOffset   = fOffset + _offset;
		newMapping->fAddress  = fAddress + _offset;
	}

	return newMapping;
}

IOReturn
IOMemoryMap::wireRange(
	uint32_t                options,
	mach_vm_size_t          offset,
	mach_vm_size_t          length)
{
	IOReturn kr;
	mach_vm_address_t start = trunc_page_64(fAddress + offset);
	mach_vm_address_t end   = round_page_64(fAddress + offset + length);
	vm_prot_t prot;

	prot = (kIODirectionOutIn & options);
	if (prot) {
		kr = vm_map_wire_kernel(fAddressMap, start, end, prot, fMemory->getVMTag(kernel_map), FALSE);
	} else {
		kr = vm_map_unwire(fAddressMap, start, end, FALSE);
	}

	return kr;
}


IOPhysicalAddress
#ifdef __LP64__
IOMemoryMap::getPhysicalSegment( IOByteCount _offset, IOPhysicalLength * _length, IOOptionBits _options)
#else /* !__LP64__ */
IOMemoryMap::getPhysicalSegment( IOByteCount _offset, IOPhysicalLength * _length)
#endif /* !__LP64__ */
{
	IOPhysicalAddress   address;

	LOCK;
#ifdef __LP64__
	address = fMemory->getPhysicalSegment( fOffset + _offset, _length, _options );
#else /* !__LP64__ */
	address = fMemory->getPhysicalSegment( fOffset + _offset, _length );
#endif /* !__LP64__ */
	UNLOCK;

	return address;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSObject

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOMemoryDescriptor::initialize( void )
{
	if (NULL == gIOMemoryLock) {
		gIOMemoryLock = IORecursiveLockAlloc();
	}

	gIOLastPage = IOGetLastPageNumber();
}

void
IOMemoryDescriptor::free( void )
{
	if (_mappings) {
		_mappings->release();
	}

	if (reserved) {
		cleanKernelReserved(reserved);
		IODelete(reserved, IOMemoryDescriptorReserved, 1);
		reserved = NULL;
	}
	super::free();
}

IOMemoryMap *
IOMemoryDescriptor::setMapping(
	task_t                  intoTask,
	IOVirtualAddress        mapAddress,
	IOOptionBits            options )
{
	return createMappingInTask( intoTask, mapAddress,
	           options | kIOMapStatic,
	           0, getLength());
}

IOMemoryMap *
IOMemoryDescriptor::map(
	IOOptionBits            options )
{
	return createMappingInTask( kernel_task, 0,
	           options | kIOMapAnywhere,
	           0, getLength());
}

#ifndef __LP64__
IOMemoryMap *
IOMemoryDescriptor::map(
	task_t                  intoTask,
	IOVirtualAddress        atAddress,
	IOOptionBits            options,
	IOByteCount             offset,
	IOByteCount             length )
{
	if ((!(kIOMapAnywhere & options)) && vm_map_is_64bit(get_task_map(intoTask))) {
		OSReportWithBacktrace("IOMemoryDescriptor::map() in 64b task, use ::createMappingInTask()");
		return NULL;
	}

	return createMappingInTask(intoTask, atAddress,
	           options, offset, length);
}
#endif /* !__LP64__ */

IOMemoryMap *
IOMemoryDescriptor::createMappingInTask(
	task_t                  intoTask,
	mach_vm_address_t       atAddress,
	IOOptionBits            options,
	mach_vm_size_t          offset,
	mach_vm_size_t          length)
{
	IOMemoryMap * result;
	IOMemoryMap * mapping;

	if (0 == length) {
		length = getLength();
	}

	mapping = new IOMemoryMap;

	if (mapping
	    && !mapping->init( intoTask, atAddress,
	    options, offset, length )) {
		mapping->release();
		mapping = NULL;
	}

	if (mapping) {
		result = makeMapping(this, intoTask, (IOVirtualAddress) mapping, options | kIOMap64Bit, 0, 0);
	} else {
		result = NULL;
	}

#if DEBUG
	if (!result) {
		IOLog("createMappingInTask failed desc %p, addr %qx, options %x, offset %qx, length %llx\n",
		    this, atAddress, (uint32_t) options, offset, length);
	}
#endif

	return result;
}

#ifndef __LP64__ // there is only a 64 bit version for LP64
IOReturn
IOMemoryMap::redirect(IOMemoryDescriptor * newBackingMemory,
    IOOptionBits         options,
    IOByteCount          offset)
{
	return redirect(newBackingMemory, options, (mach_vm_size_t)offset);
}
#endif

IOReturn
IOMemoryMap::redirect(IOMemoryDescriptor * newBackingMemory,
    IOOptionBits         options,
    mach_vm_size_t       offset)
{
	IOReturn err = kIOReturnSuccess;
	IOMemoryDescriptor * physMem = NULL;

	LOCK;

	if (fAddress && fAddressMap) {
		do{
			if (((fMemory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
			    || ((fMemory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64)) {
				physMem = fMemory;
				physMem->retain();
			}

			if (!fRedirUPL && fMemory->_memRef && (1 == fMemory->_memRef->count)) {
				upl_size_t          size = round_page(fLength);
				upl_control_flags_t flags = UPL_COPYOUT_FROM | UPL_SET_INTERNAL
				    | UPL_SET_LITE | UPL_SET_IO_WIRE | UPL_BLOCK_ACCESS;
				if (KERN_SUCCESS != memory_object_iopl_request(fMemory->_memRef->entries[0].entry, 0, &size, &fRedirUPL,
				    NULL, NULL,
				    &flags, fMemory->getVMTag(kernel_map))) {
					fRedirUPL = NULL;
				}

				if (physMem) {
					IOUnmapPages( fAddressMap, fAddress, fLength );
					if ((false)) {
						physMem->redirect(NULL, true);
					}
				}
			}

			if (newBackingMemory) {
				if (newBackingMemory != fMemory) {
					fOffset = 0;
					if (this != newBackingMemory->makeMapping(newBackingMemory, fAddressTask, (IOVirtualAddress) this,
					    options | kIOMapUnique | kIOMapReference | kIOMap64Bit,
					    offset, fLength)) {
						err = kIOReturnError;
					}
				}
				if (fRedirUPL) {
					upl_commit(fRedirUPL, NULL, 0);
					upl_deallocate(fRedirUPL);
					fRedirUPL = NULL;
				}
				if ((false) && physMem) {
					physMem->redirect(NULL, false);
				}
			}
		}while (false);
	}

	UNLOCK;

	if (physMem) {
		physMem->release();
	}

	return err;
}

IOMemoryMap *
IOMemoryDescriptor::makeMapping(
	IOMemoryDescriptor *    owner,
	task_t                  __intoTask,
	IOVirtualAddress        __address,
	IOOptionBits            options,
	IOByteCount             __offset,
	IOByteCount             __length )
{
#ifndef __LP64__
	if (!(kIOMap64Bit & options)) {
		panic("IOMemoryDescriptor::makeMapping !64bit");
	}
#endif /* !__LP64__ */

	IOMemoryDescriptor *  mapDesc = NULL;
	__block IOMemoryMap * result  = NULL;

	IOMemoryMap *  mapping = (IOMemoryMap *) __address;
	mach_vm_size_t offset  = mapping->fOffset + __offset;
	mach_vm_size_t length  = mapping->fLength;

	mapping->fOffset = offset;

	LOCK;

	do{
		if (kIOMapStatic & options) {
			result = mapping;
			addMapping(mapping);
			mapping->setMemoryDescriptor(this, 0);
			continue;
		}

		if (kIOMapUnique & options) {
			addr64_t phys;
			IOByteCount       physLen;

//	    if (owner != this)		continue;

			if (((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
			    || ((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64)) {
				phys = getPhysicalSegment(offset, &physLen, kIOMemoryMapperNone);
				if (!phys || (physLen < length)) {
					continue;
				}

				mapDesc = IOMemoryDescriptor::withAddressRange(
					phys, length, getDirection() | kIOMemoryMapperNone, NULL);
				if (!mapDesc) {
					continue;
				}
				offset = 0;
				mapping->fOffset = offset;
			}
		} else {
			// look for a compatible existing mapping
			if (_mappings) {
				_mappings->iterateObjects(^(OSObject * object)
				{
					IOMemoryMap * lookMapping = (IOMemoryMap *) object;
					if ((result = lookMapping->copyCompatible(mapping))) {
					        addMapping(result);
					        result->setMemoryDescriptor(this, offset);
					        return true;
					}
					return false;
				});
			}
			if (result || (options & kIOMapReference)) {
				if (result != mapping) {
					mapping->release();
					mapping = NULL;
				}
				continue;
			}
		}

		if (!mapDesc) {
			mapDesc = this;
			mapDesc->retain();
		}
		IOReturn
		    kr = mapDesc->doMap( NULL, (IOVirtualAddress *) &mapping, options, 0, 0 );
		if (kIOReturnSuccess == kr) {
			result = mapping;
			mapDesc->addMapping(result);
			result->setMemoryDescriptor(mapDesc, offset);
		} else {
			mapping->release();
			mapping = NULL;
		}
	}while (false);

	UNLOCK;

	if (mapDesc) {
		mapDesc->release();
	}

	return result;
}

void
IOMemoryDescriptor::addMapping(
	IOMemoryMap * mapping )
{
	if (mapping) {
		if (NULL == _mappings) {
			_mappings = OSSet::withCapacity(1);
		}
		if (_mappings) {
			_mappings->setObject( mapping );
		}
	}
}

void
IOMemoryDescriptor::removeMapping(
	IOMemoryMap * mapping )
{
	if (_mappings) {
		_mappings->removeObject( mapping);
	}
}

#ifndef __LP64__
// obsolete initializers
// - initWithOptions is the designated initializer
bool
IOMemoryDescriptor::initWithAddress(void *      address,
    IOByteCount   length,
    IODirection direction)
{
	return false;
}

bool
IOMemoryDescriptor::initWithAddress(IOVirtualAddress address,
    IOByteCount    length,
    IODirection  direction,
    task_t       task)
{
	return false;
}

bool
IOMemoryDescriptor::initWithPhysicalAddress(
	IOPhysicalAddress      address,
	IOByteCount            length,
	IODirection            direction )
{
	return false;
}

bool
IOMemoryDescriptor::initWithRanges(
	IOVirtualRange * ranges,
	UInt32           withCount,
	IODirection      direction,
	task_t           task,
	bool             asReference)
{
	return false;
}

bool
IOMemoryDescriptor::initWithPhysicalRanges(     IOPhysicalRange * ranges,
    UInt32           withCount,
    IODirection      direction,
    bool             asReference)
{
	return false;
}

void *
IOMemoryDescriptor::getVirtualSegment(IOByteCount offset,
    IOByteCount * lengthOfSegment)
{
	return NULL;
}
#endif /* !__LP64__ */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOGeneralMemoryDescriptor::serialize(OSSerialize * s) const
{
	OSSymbol const *keys[2] = {NULL};
	OSObject *values[2] = {NULL};
	OSArray * array;
	vm_size_t vcopy_size;

	struct SerData {
		user_addr_t address;
		user_size_t length;
	} *vcopy = NULL;
	unsigned int index, nRanges;
	bool result = false;

	IOOptionBits type = _flags & kIOMemoryTypeMask;

	if (s == NULL) {
		return false;
	}

	array = OSArray::withCapacity(4);
	if (!array) {
		return false;
	}

	nRanges = _rangesCount;
	if (os_mul_overflow(sizeof(SerData), nRanges, &vcopy_size)) {
		result = false;
		goto bail;
	}
	vcopy = (SerData *) IOMalloc(vcopy_size);
	if (vcopy == NULL) {
		result = false;
		goto bail;
	}

	keys[0] = OSSymbol::withCString("address");
	keys[1] = OSSymbol::withCString("length");

	// Copy the volatile data so we don't have to allocate memory
	// while the lock is held.
	LOCK;
	if (nRanges == _rangesCount) {
		Ranges vec = _ranges;
		for (index = 0; index < nRanges; index++) {
			mach_vm_address_t addr; mach_vm_size_t len;
			getAddrLenForInd(addr, len, type, vec, index);
			vcopy[index].address = addr;
			vcopy[index].length  = len;
		}
	} else {
		// The descriptor changed out from under us.  Give up.
		UNLOCK;
		result = false;
		goto bail;
	}
	UNLOCK;

	for (index = 0; index < nRanges; index++) {
		user_addr_t addr = vcopy[index].address;
		IOByteCount len = (IOByteCount) vcopy[index].length;
		values[0] = OSNumber::withNumber(addr, sizeof(addr) * 8);
		if (values[0] == NULL) {
			result = false;
			goto bail;
		}
		values[1] = OSNumber::withNumber(len, sizeof(len) * 8);
		if (values[1] == NULL) {
			result = false;
			goto bail;
		}
		OSDictionary *dict = OSDictionary::withObjects((const OSObject **)values, (const OSSymbol **)keys, 2);
		if (dict == NULL) {
			result = false;
			goto bail;
		}
		array->setObject(dict);
		dict->release();
		values[0]->release();
		values[1]->release();
		values[0] = values[1] = NULL;
	}

	result = array->serialize(s);

bail:
	if (array) {
		array->release();
	}
	if (values[0]) {
		values[0]->release();
	}
	if (values[1]) {
		values[1]->release();
	}
	if (keys[0]) {
		keys[0]->release();
	}
	if (keys[1]) {
		keys[1]->release();
	}
	if (vcopy) {
		IOFree(vcopy, vcopy_size);
	}

	return result;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 0);
#ifdef __LP64__
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 1);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 2);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 3);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 4);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 5);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 6);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 7);
#else /* !__LP64__ */
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 1);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 2);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 3);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 4);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 5);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 6);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 7);
#endif /* !__LP64__ */
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 8);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 9);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 10);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 11);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 12);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 13);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 14);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 15);

/* ex-inline function implementation */
IOPhysicalAddress
IOMemoryDescriptor::getPhysicalAddress()
{
	return getPhysicalSegment( 0, NULL );
}
