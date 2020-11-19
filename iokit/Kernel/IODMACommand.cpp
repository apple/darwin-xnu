/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

#define IOKIT_ENABLE_SHARED_PTR

#include <IOKit/assert.h>

#include <libkern/OSTypes.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSDebug.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include "IOKitKernelInternal.h"

#define MAPTYPE(type)           ((UInt) (type) & kTypeMask)
#define IS_NONCOHERENT(type)    (MAPTYPE(type) == kNonCoherent)

enum{
	kWalkSyncIn       = 0x01,// bounce -> md
	kWalkSyncOut      = 0x02,// bounce <- md
	kWalkSyncAlways   = 0x04,
	kWalkPreflight    = 0x08,
	kWalkDoubleBuffer = 0x10,
	kWalkPrepare      = 0x20,
	kWalkComplete     = 0x40,
	kWalkClient       = 0x80
};


#define fInternalState reserved
#define fState         reserved->fState
#define fMDSummary     reserved->fMDSummary


#if 1
// no direction => OutIn
#define SHOULD_COPY_DIR(op, direction)                                      \
	((kIODirectionNone == (direction))                                  \
	    || (kWalkSyncAlways & (op))                                     \
	    || (((kWalkSyncIn & (op)) ? kIODirectionIn : kIODirectionOut)   \
	                                            & (direction)))

#else
#define SHOULD_COPY_DIR(state, direction) (true)
#endif

#if 0
#define DEBG(fmt, args...)      { IOLog(fmt, ## args); kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)      {}
#endif

#if 0
#define LOGTAG          0x87654321
#endif

/**************************** class IODMACommand ***************************/

#undef super
#define super IOCommand
OSDefineMetaClassAndStructorsWithZone(IODMACommand, IOCommand, ZC_NONE);

OSMetaClassDefineReservedUsedX86(IODMACommand, 0);
OSMetaClassDefineReservedUsedX86(IODMACommand, 1);
OSMetaClassDefineReservedUsedX86(IODMACommand, 2);
OSMetaClassDefineReservedUsedX86(IODMACommand, 3);
OSMetaClassDefineReservedUsedX86(IODMACommand, 4);
OSMetaClassDefineReservedUsedX86(IODMACommand, 5);
OSMetaClassDefineReservedUsedX86(IODMACommand, 6);
OSMetaClassDefineReservedUnused(IODMACommand, 7);
OSMetaClassDefineReservedUnused(IODMACommand, 8);
OSMetaClassDefineReservedUnused(IODMACommand, 9);
OSMetaClassDefineReservedUnused(IODMACommand, 10);
OSMetaClassDefineReservedUnused(IODMACommand, 11);
OSMetaClassDefineReservedUnused(IODMACommand, 12);
OSMetaClassDefineReservedUnused(IODMACommand, 13);
OSMetaClassDefineReservedUnused(IODMACommand, 14);
OSMetaClassDefineReservedUnused(IODMACommand, 15);


OSSharedPtr<IODMACommand>
IODMACommand::withRefCon(void * refCon)
{
	OSSharedPtr<IODMACommand> me = OSMakeShared<IODMACommand>();

	if (me && !me->initWithRefCon(refCon)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<IODMACommand>
IODMACommand::withSpecification(SegmentFunction  outSegFunc,
    const SegmentOptions * segmentOptions,
    uint32_t               mappingOptions,
    IOMapper             * mapper,
    void                 * refCon)
{
	OSSharedPtr<IODMACommand> me = OSMakeShared<IODMACommand>();

	if (me && !me->initWithSpecification(outSegFunc, segmentOptions, mappingOptions,
	    mapper, refCon)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<IODMACommand>
IODMACommand::withSpecification(SegmentFunction outSegFunc,
    UInt8           numAddressBits,
    UInt64          maxSegmentSize,
    MappingOptions  mappingOptions,
    UInt64          maxTransferSize,
    UInt32          alignment,
    IOMapper       *mapper,
    void           *refCon)
{
	OSSharedPtr<IODMACommand> me = OSMakeShared<IODMACommand>();

	if (me && !me->initWithSpecification(outSegFunc,
	    numAddressBits, maxSegmentSize,
	    mappingOptions, maxTransferSize,
	    alignment, mapper, refCon)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<IODMACommand>
IODMACommand::cloneCommand(void *refCon)
{
	SegmentOptions segmentOptions =
	{
		.fStructSize                = sizeof(segmentOptions),
		.fNumAddressBits            = (uint8_t)fNumAddressBits,
		.fMaxSegmentSize            = fMaxSegmentSize,
		.fMaxTransferSize           = fMaxTransferSize,
		.fAlignment                 = fAlignMask + 1,
		.fAlignmentLength           = fAlignMaskInternalSegments + 1,
		.fAlignmentInternalSegments = fAlignMaskLength + 1
	};

	return IODMACommand::withSpecification(fOutSeg, &segmentOptions,
	           fMappingOptions, fMapper.get(), refCon);
}

#define kLastOutputFunction ((SegmentFunction) kLastOutputFunction)

bool
IODMACommand::initWithRefCon(void * refCon)
{
	if (!super::init()) {
		return false;
	}

	if (!reserved) {
		reserved = IONew(IODMACommandInternal, 1);
		if (!reserved) {
			return false;
		}
	}
	bzero(reserved, sizeof(IODMACommandInternal));
	fRefCon = refCon;

	return true;
}

bool
IODMACommand::initWithSpecification(SegmentFunction        outSegFunc,
    const SegmentOptions * segmentOptions,
    uint32_t               mappingOptions,
    IOMapper             * mapper,
    void                 * refCon)
{
	if (!initWithRefCon(refCon)) {
		return false;
	}

	if (kIOReturnSuccess != setSpecification(outSegFunc, segmentOptions,
	    mappingOptions, mapper)) {
		return false;
	}

	return true;
}

bool
IODMACommand::initWithSpecification(SegmentFunction outSegFunc,
    UInt8           numAddressBits,
    UInt64          maxSegmentSize,
    MappingOptions  mappingOptions,
    UInt64          maxTransferSize,
    UInt32          alignment,
    IOMapper       *mapper,
    void           *refCon)
{
	SegmentOptions segmentOptions =
	{
		.fStructSize                = sizeof(segmentOptions),
		.fNumAddressBits            = numAddressBits,
		.fMaxSegmentSize            = maxSegmentSize,
		.fMaxTransferSize           = maxTransferSize,
		.fAlignment                 = alignment,
		.fAlignmentLength           = 1,
		.fAlignmentInternalSegments = alignment
	};

	return initWithSpecification(outSegFunc, &segmentOptions, mappingOptions, mapper, refCon);
}

IOReturn
IODMACommand::setSpecification(SegmentFunction        outSegFunc,
    const SegmentOptions * segmentOptions,
    uint32_t               mappingOptions,
    IOMapper             * mapper)
{
	IOService * device = NULL;
	UInt8       numAddressBits;
	UInt64      maxSegmentSize;
	UInt64      maxTransferSize;
	UInt32      alignment;

	bool        is32Bit;

	if (!outSegFunc || !segmentOptions) {
		return kIOReturnBadArgument;
	}

	is32Bit = ((OutputHost32 == outSegFunc)
	    || (OutputBig32 == outSegFunc)
	    || (OutputLittle32 == outSegFunc));

	numAddressBits = segmentOptions->fNumAddressBits;
	maxSegmentSize = segmentOptions->fMaxSegmentSize;
	maxTransferSize = segmentOptions->fMaxTransferSize;
	alignment = segmentOptions->fAlignment;
	if (is32Bit) {
		if (!numAddressBits) {
			numAddressBits = 32;
		} else if (numAddressBits > 32) {
			return kIOReturnBadArgument;  // Wrong output function for bits
		}
	}

	if (numAddressBits && (numAddressBits < PAGE_SHIFT)) {
		return kIOReturnBadArgument;
	}

	if (!maxSegmentSize) {
		maxSegmentSize--;               // Set Max segment to -1
	}
	if (!maxTransferSize) {
		maxTransferSize--;              // Set Max transfer to -1
	}
	if (mapper && !OSDynamicCast(IOMapper, mapper)) {
		device = mapper;
		mapper = NULL;
	}
	if (!mapper && (kUnmapped != MAPTYPE(mappingOptions))) {
		IOMapper::checkForSystemMapper();
		mapper = IOMapper::gSystem;
	}

	fNumSegments     = 0;
	fOutSeg          = outSegFunc;
	fNumAddressBits  = numAddressBits;
	fMaxSegmentSize  = maxSegmentSize;
	fMappingOptions  = mappingOptions;
	fMaxTransferSize = maxTransferSize;
	if (!alignment) {
		alignment = 1;
	}
	fAlignMask       = alignment - 1;

	alignment = segmentOptions->fAlignmentLength;
	if (!alignment) {
		alignment = 1;
	}
	fAlignMaskLength = alignment - 1;

	alignment = segmentOptions->fAlignmentInternalSegments;
	if (!alignment) {
		alignment = (fAlignMask + 1);
	}
	fAlignMaskInternalSegments = alignment - 1;

	switch (MAPTYPE(mappingOptions)) {
	case kMapped:       break;
	case kUnmapped:     break;
	case kNonCoherent:  break;

	case kBypassed:
		if (!mapper) {
			break;
		}
		return kIOReturnBadArgument;

	default:
		return kIOReturnBadArgument;
	}
	;

	if (mapper != fMapper) {
		fMapper.reset(mapper, OSRetain);
	}

	fInternalState->fIterateOnly = (0 != (kIterateOnly & mappingOptions));
	fInternalState->fDevice = device;

	return kIOReturnSuccess;
}

void
IODMACommand::free()
{
	if (reserved) {
		IODelete(reserved, IODMACommandInternal, 1);
	}

	fMapper.reset();

	// Correct use of this class when setting an IOMemoryDescriptor
	// in fMemory via setMemoryDescriptor(desc) is, for the caller, to
	// have a matching call to clearMemoryDescriptor() before releasing
	// the object. The matching call has also the effect of releasing
	// the ref taken on the IOMemoryDescriptor in setMemoryDescriptor().
	//
	// A number of "misbehaving" drivers has been found during testing,
	// whereby a matching call to clearMemoryDescriptor() is missing:
	//
	// rdar://59947343
	// rdar://59946968
	//
	// Both the approaches taken in said drivers are wrong, but have gone
	// basically silent with fMemory being a regular pointer. With fMemory
	// becoming a OSSharedPtr, the IODMACommand destructor expects to find
	// either fMemory reset (through the call to clearMemoryDescriptor()) or
	// a reference hold for the release.
	//
	// For this reason, this workaround of detaching fMemory is put in
	// place here, choosing the leak over the panic for misbehaving
	// drivers. Once all instances are fixed, this workaround will be
	// removed.
	//
	// Note: all well behaving drivers that have matching calls for
	// setMemoryDescriptor() and clearMemoryDescriptor() are unaffected
	// since fMemory will be null at this point.
	fMemory.detach();

	super::free();
}

IOReturn
IODMACommand::setMemoryDescriptor(const IOMemoryDescriptor *mem, bool autoPrepare)
{
	IOReturn err = kIOReturnSuccess;

	if (mem == fMemory) {
		if (!autoPrepare) {
			while (fActive) {
				complete();
			}
		}
		return kIOReturnSuccess;
	}

	if (fMemory) {
		// As we are almost certainly being called from a work loop thread
		// if fActive is true it is probably not a good time to potentially
		// block.  Just test for it and return an error
		if (fActive) {
			return kIOReturnBusy;
		}
		clearMemoryDescriptor();
	}

	if (mem) {
		bzero(&fMDSummary, sizeof(fMDSummary));
		err = mem->dmaCommandOperation(kIOMDGetCharacteristics | (kMapped == MAPTYPE(fMappingOptions)),
		    &fMDSummary, sizeof(fMDSummary));
		if (err) {
			return err;
		}

		ppnum_t highPage = fMDSummary.fHighestPage ? fMDSummary.fHighestPage : gIOLastPage;

		if ((kMapped == MAPTYPE(fMappingOptions))
		    && fMapper) {
			fInternalState->fCheckAddressing = false;
		} else {
			fInternalState->fCheckAddressing = (fNumAddressBits && (highPage >= (1UL << (fNumAddressBits - PAGE_SHIFT))));
		}

		fInternalState->fNewMD = true;
		fMemory.reset(const_cast<IOMemoryDescriptor *>(mem), OSRetain);
		fInternalState->fSetActiveNoMapper = (!fMapper);
		if (fInternalState->fSetActiveNoMapper) {
			mem->dmaCommandOperation(kIOMDSetDMAActive, this, 0);
		}
		if (autoPrepare) {
			err = prepare();
			if (err) {
				clearMemoryDescriptor();
			}
		}
	}

	return err;
}

IOReturn
IODMACommand::clearMemoryDescriptor(bool autoComplete)
{
	if (fActive && !autoComplete) {
		return kIOReturnNotReady;
	}

	if (fMemory) {
		while (fActive) {
			complete();
		}
		if (fInternalState->fSetActiveNoMapper) {
			fMemory->dmaCommandOperation(kIOMDSetDMAInactive, this, 0);
		}
		fMemory.reset();
	}

	return kIOReturnSuccess;
}

const IOMemoryDescriptor *
IODMACommand::getMemoryDescriptor() const
{
	return fMemory.get();
}

IOMemoryDescriptor *
IODMACommand::getIOMemoryDescriptor() const
{
	OSSharedPtr<IOMemoryDescriptor> mem;

	mem = reserved->fCopyMD;
	if (!mem) {
		mem = fMemory;
	}

	return mem.get();
}

IOReturn
IODMACommand::segmentOp(
	void         *reference,
	IODMACommand *target,
	Segment64     segment,
	void         *segments,
	UInt32        segmentIndex)
{
	IOOptionBits op = (IOOptionBits)(uintptr_t) reference;
	addr64_t     maxPhys, address;
	uint64_t     length;
	uint32_t     numPages;
	uint32_t     mask;

	IODMACommandInternal * state = target->reserved;

	if (target->fNumAddressBits && (target->fNumAddressBits < 64) && (state->fLocalMapperAllocValid || !target->fMapper)) {
		maxPhys = (1ULL << target->fNumAddressBits);
	} else {
		maxPhys = 0;
	}
	maxPhys--;

	address = segment.fIOVMAddr;
	length = segment.fLength;

	assert(length);

	if (!state->fMisaligned) {
		mask = (segmentIndex ? target->fAlignMaskInternalSegments : state->fSourceAlignMask);
		state->fMisaligned |= (0 != (mask & address));
		if (state->fMisaligned) {
			DEBG("misaligned address %qx:%qx, %x\n", address, length, mask);
		}
	}
	if (!state->fMisaligned) {
		mask = target->fAlignMaskLength;
		state->fMisaligned |= (0 != (mask & length));
		if (state->fMisaligned) {
			DEBG("misaligned length %qx:%qx, %x\n", address, length, mask);
		}
	}

	if (state->fMisaligned && (kWalkPreflight & op)) {
		return kIOReturnNotAligned;
	}

	if (!state->fDoubleBuffer) {
		if ((address + length - 1) <= maxPhys) {
			length = 0;
		} else if (address <= maxPhys) {
			DEBG("tail %qx, %qx", address, length);
			length = (address + length - maxPhys - 1);
			address = maxPhys + 1;
			DEBG("-> %qx, %qx\n", address, length);
		}
	}

	if (!length) {
		return kIOReturnSuccess;
	}

	uint64_t numPages64 = atop_64(round_page_64((address & PAGE_MASK) + length));
	if (numPages64 > UINT_MAX) {
		return kIOReturnVMError;
	}
	numPages = (typeof(numPages))numPages64;

	if (kWalkPreflight & op) {
		state->fCopyPageCount += numPages;
	} else {
		vm_page_t lastPage;
		lastPage = NULL;
		if (kWalkPrepare & op) {
			lastPage = state->fCopyNext;
			for (IOItemCount idx = 0; idx < numPages; idx++) {
				vm_page_set_offset(lastPage, atop_64(address) + idx);
				lastPage = vm_page_get_next(lastPage);
			}
		}

		if (!lastPage || SHOULD_COPY_DIR(op, target->fMDSummary.fDirection)) {
			lastPage = state->fCopyNext;
			for (IOItemCount idx = 0; idx < numPages; idx++) {
				if (SHOULD_COPY_DIR(op, target->fMDSummary.fDirection)) {
					addr64_t cpuAddr = address;
					addr64_t remapAddr;
					uint64_t chunk;

					if ((kMapped == MAPTYPE(target->fMappingOptions))
					    && target->fMapper) {
						cpuAddr = target->fMapper->mapToPhysicalAddress(address);
					}

					remapAddr = ptoa_64(vm_page_get_phys_page(lastPage));
					if (!state->fDoubleBuffer) {
						remapAddr += (address & PAGE_MASK);
					}
					chunk = PAGE_SIZE - (address & PAGE_MASK);
					if (chunk > length) {
						chunk = length;
					}
					if (chunk > (UINT_MAX - PAGE_SIZE + 1)) {
						chunk = (UINT_MAX - PAGE_SIZE + 1);
					}

					DEBG("cpv: 0x%qx %s 0x%qx, 0x%qx, 0x%02lx\n", remapAddr,
					    (kWalkSyncIn & op) ? "->" : "<-",
					    address, chunk, op);

					if (kWalkSyncIn & op) { // cppvNoModSnk
						copypv(remapAddr, cpuAddr, (unsigned int) chunk,
						    cppvPsnk | cppvFsnk | cppvPsrc | cppvNoRefSrc );
					} else {
						copypv(cpuAddr, remapAddr, (unsigned int) chunk,
						    cppvPsnk | cppvFsnk | cppvPsrc | cppvNoRefSrc );
					}
					address += chunk;
					length -= chunk;
				}
				lastPage = vm_page_get_next(lastPage);
			}
		}
		state->fCopyNext = lastPage;
	}

	return kIOReturnSuccess;
}

OSSharedPtr<IOBufferMemoryDescriptor>
IODMACommand::createCopyBuffer(IODirection direction, UInt64 length)
{
	mach_vm_address_t mask = 0xFFFFF000;    //state->fSourceAlignMask
	return IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
	           direction, length, mask);
}

IOReturn
IODMACommand::walkAll(uint32_t op)
{
	IODMACommandInternal * state = fInternalState;

	IOReturn     ret = kIOReturnSuccess;
	UInt32       numSegments;
	UInt64       offset;

	if (kWalkPreflight & op) {
		state->fMisaligned     = false;
		state->fDoubleBuffer   = false;
		state->fPrepared       = false;
		state->fCopyNext       = NULL;
		state->fCopyPageAlloc  = NULL;
		state->fCopyPageCount  = 0;
		state->fNextRemapPage  = NULL;
		state->fCopyMD         = NULL;

		if (!(kWalkDoubleBuffer & op)) {
			offset = 0;
			numSegments = 0 - 1;
			ret = genIOVMSegments(op, segmentOp, (void *)(uintptr_t) op, &offset, state, &numSegments);
		}

		op &= ~kWalkPreflight;

		state->fDoubleBuffer = (state->fMisaligned || state->fForceDoubleBuffer);
		state->fForceDoubleBuffer = false;
		if (state->fDoubleBuffer) {
			state->fCopyPageCount = (typeof(state->fCopyPageCount))(atop_64(round_page(state->fPreparedLength)));
		}

		if (state->fCopyPageCount) {
			vm_page_t mapBase = NULL;

			DEBG("preflight fCopyPageCount %d\n", state->fCopyPageCount);

			if (!fMapper && !state->fDoubleBuffer) {
				kern_return_t kr;

				if (fMapper) {
					panic("fMapper copying");
				}

				kr = vm_page_alloc_list(state->fCopyPageCount,
				    KMA_LOMEM | KMA_NOPAGEWAIT, &mapBase);
				if (KERN_SUCCESS != kr) {
					DEBG("vm_page_alloc_list(%d) failed (%d)\n", state->fCopyPageCount, kr);
					mapBase = NULL;
				}
			}

			if (mapBase) {
				state->fCopyPageAlloc = mapBase;
				state->fCopyNext = state->fCopyPageAlloc;
				offset = 0;
				numSegments = 0 - 1;
				ret = genIOVMSegments(op, segmentOp, (void *)(uintptr_t) op, &offset, state, &numSegments);
				state->fPrepared = true;
				op &= ~(kWalkSyncIn | kWalkSyncOut);
			} else {
				DEBG("alloc IOBMD\n");
				state->fCopyMD = createCopyBuffer(fMDSummary.fDirection, state->fPreparedLength);

				if (state->fCopyMD) {
					ret = kIOReturnSuccess;
					state->fPrepared = true;
				} else {
					DEBG("IODMACommand !alloc IOBMD");
					return kIOReturnNoResources;
				}
			}
		}
	}

	if (state->fPrepared && ((kWalkSyncIn | kWalkSyncOut) & op)) {
		if (state->fCopyPageCount) {
			DEBG("sync fCopyPageCount %d\n", state->fCopyPageCount);

			if (state->fCopyPageAlloc) {
				state->fCopyNext = state->fCopyPageAlloc;
				offset = 0;
				numSegments = 0 - 1;
				ret = genIOVMSegments(op, segmentOp, (void *)(uintptr_t) op, &offset, state, &numSegments);
			} else if (state->fCopyMD) {
				DEBG("sync IOBMD\n");

				if (SHOULD_COPY_DIR(op, fMDSummary.fDirection)) {
					OSSharedPtr<IOMemoryDescriptor> poMD = fMemory;

					IOByteCount bytes;

					if (kWalkSyncIn & op) {
						bytes = poMD->writeBytes(state->fPreparedOffset,
						    state->fCopyMD->getBytesNoCopy(),
						    state->fPreparedLength);
					} else {
						bytes = poMD->readBytes(state->fPreparedOffset,
						    state->fCopyMD->getBytesNoCopy(),
						    state->fPreparedLength);
					}
					DEBG("fCopyMD %s %lx bytes\n", (kWalkSyncIn & op) ? "wrote" : "read", bytes);
					ret = (bytes == state->fPreparedLength) ? kIOReturnSuccess : kIOReturnUnderrun;
				} else {
					ret = kIOReturnSuccess;
				}
			}
		}
	}

	if (kWalkComplete & op) {
		if (state->fCopyPageAlloc) {
			vm_page_free_list(state->fCopyPageAlloc, FALSE);
			state->fCopyPageAlloc = NULL;
			state->fCopyPageCount = 0;
		}
		if (state->fCopyMD) {
			state->fCopyMD.reset();
		}

		state->fPrepared = false;
	}
	return ret;
}

UInt8
IODMACommand::getNumAddressBits(void)
{
	return (UInt8) fNumAddressBits;
}

UInt32
IODMACommand::getAlignment(void)
{
	return fAlignMask + 1;
}

uint32_t
IODMACommand::getAlignmentLength(void)
{
	return fAlignMaskLength + 1;
}

uint32_t
IODMACommand::getAlignmentInternalSegments(void)
{
	return fAlignMaskInternalSegments + 1;
}

IOReturn
IODMACommand::prepareWithSpecification(SegmentFunction        outSegFunc,
    const SegmentOptions * segmentOptions,
    uint32_t               mappingOptions,
    IOMapper             * mapper,
    UInt64                 offset,
    UInt64                 length,
    bool                   flushCache,
    bool                   synchronize)
{
	IOReturn ret;

	if (fActive) {
		return kIOReturnNotPermitted;
	}

	ret = setSpecification(outSegFunc, segmentOptions, mappingOptions, mapper);
	if (kIOReturnSuccess != ret) {
		return ret;
	}

	ret = prepare(offset, length, flushCache, synchronize);

	return ret;
}

IOReturn
IODMACommand::prepareWithSpecification(SegmentFunction  outSegFunc,
    UInt8            numAddressBits,
    UInt64           maxSegmentSize,
    MappingOptions   mappingOptions,
    UInt64           maxTransferSize,
    UInt32           alignment,
    IOMapper         *mapper,
    UInt64           offset,
    UInt64           length,
    bool             flushCache,
    bool             synchronize)
{
	SegmentOptions segmentOptions =
	{
		.fStructSize                = sizeof(segmentOptions),
		.fNumAddressBits            = numAddressBits,
		.fMaxSegmentSize            = maxSegmentSize,
		.fMaxTransferSize           = maxTransferSize,
		.fAlignment                 = alignment,
		.fAlignmentLength           = 1,
		.fAlignmentInternalSegments = alignment
	};

	return prepareWithSpecification(outSegFunc, &segmentOptions, mappingOptions, mapper,
	           offset, length, flushCache, synchronize);
}


IOReturn
IODMACommand::prepare(UInt64 offset, UInt64 length, bool flushCache, bool synchronize)
{
	IODMACommandInternal *  state = fInternalState;
	IOReturn                  ret = kIOReturnSuccess;
	uint32_t       mappingOptions = fMappingOptions;

	// check specification has been set
	if (!fOutSeg) {
		return kIOReturnNotReady;
	}

	if (!length) {
		length = fMDSummary.fLength;
	}

	if (length > fMaxTransferSize) {
		return kIOReturnNoSpace;
	}

	if (fActive++) {
		if ((state->fPreparedOffset != offset)
		    || (state->fPreparedLength != length)) {
			ret = kIOReturnNotReady;
		}
	} else {
		if (fAlignMaskLength & length) {
			return kIOReturnNotAligned;
		}

		if (atop_64(state->fPreparedLength) > UINT_MAX) {
			return kIOReturnVMError;
		}
		state->fPreparedOffset = offset;
		state->fPreparedLength = length;

		state->fMisaligned     = false;
		state->fDoubleBuffer   = false;
		state->fPrepared       = false;
		state->fCopyNext       = NULL;
		state->fCopyPageAlloc  = NULL;
		state->fCopyPageCount  = 0;
		state->fNextRemapPage  = NULL;
		state->fCopyMD         = NULL;
		state->fLocalMapperAlloc       = 0;
		state->fLocalMapperAllocValid  = false;
		state->fLocalMapperAllocLength = 0;

		state->fSourceAlignMask = fAlignMask;
		if (fMapper) {
			state->fSourceAlignMask &= page_mask;
		}

		state->fCursor = state->fIterateOnly
		    || (!state->fCheckAddressing
		    && (!state->fSourceAlignMask
		    || ((fMDSummary.fPageAlign & (1 << 31)) && (0 == (fMDSummary.fPageAlign & state->fSourceAlignMask)))));

		if (!state->fCursor) {
			IOOptionBits op = kWalkPrepare | kWalkPreflight;
			if (synchronize) {
				op |= kWalkSyncOut;
			}
			ret = walkAll(op);
		}

		if (IS_NONCOHERENT(mappingOptions) && flushCache) {
			if (state->fCopyMD) {
				state->fCopyMD->performOperation(kIOMemoryIncoherentIOStore, 0, length);
			} else {
				fMemory->performOperation(kIOMemoryIncoherentIOStore, offset, length);
			}
		}

		if (fMapper) {
			IOMDDMAMapArgs mapArgs;
			bzero(&mapArgs, sizeof(mapArgs));
			mapArgs.fMapper = fMapper.get();
			mapArgs.fCommand = this;
			mapArgs.fMapSpec.device         = state->fDevice;
			mapArgs.fMapSpec.alignment      = fAlignMask + 1;
			mapArgs.fMapSpec.numAddressBits = fNumAddressBits ? ((UInt8) fNumAddressBits) : 64;
			mapArgs.fLength = state->fPreparedLength;
			OSSharedPtr<IOMemoryDescriptor> md = state->fCopyMD;
			if (md) {
				mapArgs.fOffset = 0;
			} else {
				md = fMemory;
				mapArgs.fOffset = state->fPreparedOffset;
			}

			ret = md->dmaCommandOperation(kIOMDDMAMap, &mapArgs, sizeof(mapArgs));

			if ((kIOReturnSuccess == ret)
			    && mapArgs.fAllocLength
			    && (mapArgs.fAllocLength != mapArgs.fLength)) {
				do {
					// multisegment case
					IOMDDMAWalkSegmentState  walkState;
					IOMDDMAWalkSegmentArgs * walkArgs = (IOMDDMAWalkSegmentArgs *) (void *)&walkState;
					IOOptionBits             mdOp;
					uint64_t                 index;
					IOPhysicalLength         segLen;
					uint32_t                         segCount;
					uint64_t                         phys, align;
					uint64_t                         mapperPageMask;
					uint64_t                         mapperPageShift;
					uint64_t                         insertOffset;
					uint32_t                         mapOptions;
					uint64_t                         length;

					assert(mapArgs.fAllocLength > mapArgs.fLength);

					mapperPageMask    = fMapper->getPageSize();
					assert(mapperPageMask);
					mapperPageMask   -= 1;
					mapperPageShift   = (64 - __builtin_clzll(mapperPageMask));
					walkArgs->fMapped = false;
					length            = state->fPreparedLength;
					mdOp              = kIOMDFirstSegment;
					segCount          = 0;
					for (index = 0; index < length; segCount++) {
						walkArgs->fOffset = state->fPreparedOffset + index;

						ret    = md->dmaCommandOperation(mdOp, &walkState, sizeof(walkState));
						mdOp   = kIOMDWalkSegments;
						assert(kIOReturnSuccess == ret);
						if (ret != kIOReturnSuccess) {
							panic("dmaCommandOperation");
						}
						segLen = walkArgs->fLength;
						index += segLen;
					}
					if (ret != kIOReturnSuccess) {
						break;
					}

#if defined(LOGTAG)
					if (LOGTAG == fMemory->getTag()) {
						IOLog("DMA[%p] alloc 0x%qx, 0x%qx\n", this, mapArgs.fAlloc, mapArgs.fAllocLength);
					}
#endif /* defined(LOGTAG) */

					state->fMapSegments = IONewZero(IODMACommandMapSegment, segCount);
					if (!state->fMapSegments) {
						ret = kIOReturnNoMemory;
						break;
					}
					state->fMapSegmentsCount = segCount;

					switch (kIODirectionOutIn & fMDSummary.fDirection) {
					case kIODirectionOut:
						mapOptions = kIODMAMapReadAccess;
						break;
					case kIODirectionIn:
						mapOptions = kIODMAMapWriteAccess;
						break;
					default:
						mapOptions = kIODMAMapReadAccess | kIODMAMapWriteAccess;
						break;
					}

					mdOp = kIOMDFirstSegment;
					segCount = 0;
					for (insertOffset = 0, index = 0; index < length; segCount++) {
						walkArgs->fOffset = state->fPreparedOffset + index;
						ret = md->dmaCommandOperation(mdOp, &walkState, sizeof(walkState));
						mdOp = kIOMDWalkSegments;
						if (ret != kIOReturnSuccess) {
							panic("dmaCommandOperation 0x%x", ret);
						}
						phys = walkArgs->fIOVMAddr;
						segLen = walkArgs->fLength;

#if defined(LOGTAG)
						if (LOGTAG == fMemory->getTag()) {
							IOLog("DMA[%p] phys[%d] 0x%qx, 0x%qx\n", this, segCount, (uint64_t) phys, (uint64_t) segLen);
						}
#endif /* defined(LOGTAG) */

						align = (phys & mapperPageMask);

#if defined(LOGTAG)
						if (LOGTAG == fMemory->getTag()) {
							IOLog("DMA[%p] runs[%d] dmaoff 0x%qx, mapoff 0x%qx, align 0x%qx\n", this, segCount, index, insertOffset, align);
						}
#endif /* defined(LOGTAG) */

						assert(segCount < state->fMapSegmentsCount);
						state->fMapSegments[segCount].fDMAOffset = state->fPreparedOffset + index;
						state->fMapSegments[segCount].fMapOffset = insertOffset;
						state->fMapSegments[segCount].fPageOffset = align;
						index  += segLen;

						// segment page align
						segLen  = ((phys + segLen + mapperPageMask) & ~mapperPageMask);
						phys   -= align;
						segLen -= phys;
						insertOffset += segLen;
					}
					state->fLocalMapperAllocBase = (mapArgs.fAlloc & ~mapperPageMask);
#if defined(LOGTAG)
					if (LOGTAG == fMemory->getTag()) {
						IOLog("IODMACommand fMapSegmentsCount %d\n", state->fMapSegmentsCount);
					}
#endif /* defined(LOGTAG) */
				} while (false);
			}
			if (kIOReturnSuccess == ret) {
				state->fLocalMapperAlloc       = mapArgs.fAlloc;
				state->fLocalMapperAllocValid  = true;
				state->fLocalMapperAllocLength = mapArgs.fAllocLength;
			}
		}
		if (kIOReturnSuccess == ret) {
			state->fPrepared = true;
		}
	}
	return ret;
}

IOReturn
IODMACommand::complete(bool invalidateCache, bool synchronize)
{
	IODMACommandInternal * state = fInternalState;
	IOReturn               ret   = kIOReturnSuccess;
	OSSharedPtr<IOMemoryDescriptor> copyMD;

	if (fActive < 1) {
		return kIOReturnNotReady;
	}

	if (!--fActive) {
		copyMD = state->fCopyMD;

		if (IS_NONCOHERENT(fMappingOptions) && invalidateCache) {
			if (copyMD) {
				copyMD->performOperation(kIOMemoryIncoherentIOFlush, 0, state->fPreparedLength);
			} else {
				OSSharedPtr<IOMemoryDescriptor> md = fMemory;
				md->performOperation(kIOMemoryIncoherentIOFlush, state->fPreparedOffset, state->fPreparedLength);
			}
		}

		if (!state->fCursor) {
			IOOptionBits op = kWalkComplete;
			if (synchronize) {
				op |= kWalkSyncIn;
			}
			ret = walkAll(op);
		}

		if (state->fLocalMapperAllocValid) {
			IOMDDMAMapArgs mapArgs;
			bzero(&mapArgs, sizeof(mapArgs));
			mapArgs.fMapper = fMapper.get();
			mapArgs.fCommand = this;
			mapArgs.fAlloc = state->fLocalMapperAlloc;
			mapArgs.fAllocLength = state->fLocalMapperAllocLength;
			OSSharedPtr<IOMemoryDescriptor> md = copyMD;
			if (md) {
				mapArgs.fOffset = 0;
			} else {
				md = fMemory;
				mapArgs.fOffset = state->fPreparedOffset;
			}

			ret = md->dmaCommandOperation(kIOMDDMAUnmap, &mapArgs, sizeof(mapArgs));

			state->fLocalMapperAlloc       = 0;
			state->fLocalMapperAllocValid  = false;
			state->fLocalMapperAllocLength = 0;
			if (state->fMapSegments) {
				IODelete(state->fMapSegments, IODMACommandMapSegment, state->fMapSegmentsCount);
				state->fMapSegments      = NULL;
				state->fMapSegmentsCount = 0;
			}
		}

		state->fPrepared = false;
	}

	return ret;
}

IOReturn
IODMACommand::getPreparedOffsetAndLength(UInt64 * offset, UInt64 * length)
{
	IODMACommandInternal * state = fInternalState;
	if (fActive < 1) {
		return kIOReturnNotReady;
	}

	if (offset) {
		*offset = state->fPreparedOffset;
	}
	if (length) {
		*length = state->fPreparedLength;
	}

	return kIOReturnSuccess;
}

IOReturn
IODMACommand::synchronize(IOOptionBits options)
{
	IODMACommandInternal * state = fInternalState;
	IOReturn               ret   = kIOReturnSuccess;
	IOOptionBits           op;

	if (kIODirectionOutIn == (kIODirectionOutIn & options)) {
		return kIOReturnBadArgument;
	}

	if (fActive < 1) {
		return kIOReturnNotReady;
	}

	op = 0;
	if (kForceDoubleBuffer & options) {
		if (state->fDoubleBuffer) {
			return kIOReturnSuccess;
		}
		ret = complete(false /* invalidateCache */, true /* synchronize */);
		state->fCursor = false;
		state->fForceDoubleBuffer = true;
		ret = prepare(state->fPreparedOffset, state->fPreparedLength, false /* flushCache */, true /* synchronize */);

		return ret;
	} else if (state->fCursor) {
		return kIOReturnSuccess;
	}

	if (kIODirectionIn & options) {
		op |= kWalkSyncIn | kWalkSyncAlways;
	} else if (kIODirectionOut & options) {
		op |= kWalkSyncOut | kWalkSyncAlways;
	}

	ret = walkAll(op);

	return ret;
}

struct IODMACommandTransferContext {
	void *   buffer;
	UInt64   bufferOffset;
	UInt64   remaining;
	UInt32   op;
};
enum{
	kIODMACommandTransferOpReadBytes  = 1,
	kIODMACommandTransferOpWriteBytes = 2
};

IOReturn
IODMACommand::transferSegment(void   *reference,
    IODMACommand *target,
    Segment64     segment,
    void         *segments,
    UInt32        segmentIndex)
{
	IODMACommandTransferContext * context = (IODMACommandTransferContext *) reference;
	UInt64   length  = min(segment.fLength, context->remaining);
	addr64_t ioAddr  = segment.fIOVMAddr;
	addr64_t cpuAddr = ioAddr;

	context->remaining -= length;

	while (length) {
		UInt64 copyLen = length;
		if ((kMapped == MAPTYPE(target->fMappingOptions))
		    && target->fMapper) {
			cpuAddr = target->fMapper->mapToPhysicalAddress(ioAddr);
			copyLen = min(copyLen, page_size - (ioAddr & (page_size - 1)));
			ioAddr += copyLen;
		}
		if (copyLen > (UINT_MAX - PAGE_SIZE + 1)) {
			copyLen = (UINT_MAX - PAGE_SIZE + 1);
		}

		switch (context->op) {
		case kIODMACommandTransferOpReadBytes:
			copypv(cpuAddr, context->bufferOffset + (addr64_t) context->buffer, (unsigned int) copyLen,
			    cppvPsrc | cppvNoRefSrc | cppvFsnk | cppvKmap);
			break;
		case kIODMACommandTransferOpWriteBytes:
			copypv(context->bufferOffset + (addr64_t) context->buffer, cpuAddr, (unsigned int) copyLen,
			    cppvPsnk | cppvFsnk | cppvNoRefSrc | cppvNoModSnk | cppvKmap);
			break;
		}
		length                -= copyLen;
		context->bufferOffset += copyLen;
	}

	return context->remaining ? kIOReturnSuccess : kIOReturnOverrun;
}

UInt64
IODMACommand::transfer(IOOptionBits transferOp, UInt64 offset, void * buffer, UInt64 length)
{
	IODMACommandInternal *      state = fInternalState;
	IODMACommandTransferContext context;
	Segment64                   segments[1];
	UInt32                      numSegments = 0 - 1;

	if (fActive < 1) {
		return 0;
	}

	if (offset >= state->fPreparedLength) {
		return 0;
	}
	length = min(length, state->fPreparedLength - offset);

	context.buffer       = buffer;
	context.bufferOffset = 0;
	context.remaining    = length;
	context.op           = transferOp;
	(void) genIOVMSegments(kWalkClient, transferSegment, &context, &offset, &segments[0], &numSegments);

	return length - context.remaining;
}

UInt64
IODMACommand::readBytes(UInt64 offset, void *bytes, UInt64 length)
{
	return transfer(kIODMACommandTransferOpReadBytes, offset, bytes, length);
}

UInt64
IODMACommand::writeBytes(UInt64 offset, const void *bytes, UInt64 length)
{
	return transfer(kIODMACommandTransferOpWriteBytes, offset, const_cast<void *>(bytes), length);
}

IOReturn
IODMACommand::genIOVMSegments(UInt64 *offsetP,
    void   *segmentsP,
    UInt32 *numSegmentsP)
{
	return genIOVMSegments(kWalkClient, clientOutputSegment, (void *) fOutSeg,
	           offsetP, segmentsP, numSegmentsP);
}

IOReturn
IODMACommand::genIOVMSegments(uint32_t op,
    InternalSegmentFunction outSegFunc,
    void   *reference,
    UInt64 *offsetP,
    void   *segmentsP,
    UInt32 *numSegmentsP)
{
	IODMACommandInternal * internalState = fInternalState;
	IOOptionBits           mdOp = kIOMDWalkSegments;
	IOReturn               ret  = kIOReturnSuccess;

	if (!(kWalkComplete & op) && !fActive) {
		return kIOReturnNotReady;
	}

	if (!offsetP || !segmentsP || !numSegmentsP || !*numSegmentsP) {
		return kIOReturnBadArgument;
	}

	IOMDDMAWalkSegmentArgs *state =
	    (IOMDDMAWalkSegmentArgs *)(void *) fState;

	UInt64 offset    = *offsetP + internalState->fPreparedOffset;
	UInt64 memLength = internalState->fPreparedOffset + internalState->fPreparedLength;

	if (offset >= memLength) {
		return kIOReturnOverrun;
	}

	if ((offset == internalState->fPreparedOffset) || (offset != state->fOffset) || internalState->fNewMD) {
		state->fOffset                                   = 0;
		internalState->fIOVMAddrValid = state->fIOVMAddr = 0;
		internalState->fNextRemapPage                    = NULL;
		internalState->fNewMD                            = false;
		mdOp                                             = kIOMDFirstSegment;
		if (fMapper) {
			if (internalState->fLocalMapperAllocValid) {
				state->fMapped = true;
				state->fMappedBase = internalState->fLocalMapperAlloc;
			} else {
				state->fMapped = false;
			}
		}
	}

	UInt32    segIndex = 0;
	UInt32    numSegments = *numSegmentsP;
	Segment64 curSeg = { 0, 0 };
	bool      curSegValid = false;
	addr64_t  maxPhys;

	if (fNumAddressBits && (fNumAddressBits < 64)) {
		maxPhys = (1ULL << fNumAddressBits);
	} else {
		maxPhys = 0;
	}
	maxPhys--;

	while (internalState->fIOVMAddrValid || (state->fOffset < memLength)) {
		// state = next seg
		if (!internalState->fIOVMAddrValid) {
			IOReturn rtn;

			state->fOffset = offset;
			state->fLength = memLength - offset;

			bool done = false;
			bool check = false;

			if (internalState->fLocalMapperAllocValid) {
				if (!internalState->fMapSegmentsCount) {
					state->fIOVMAddr = internalState->fLocalMapperAlloc + offset - internalState->fPreparedOffset;
					rtn = kIOReturnSuccess;
					done = true;
					check = true;
				} else {
					uint64_t address;
					uint64_t length;
					uint64_t runOffset;
					uint64_t ind;
					uint64_t off2Ind = internalState->fOffset2Index;

					// Validate the previous offset
					if (offset
					    && (offset == internalState->fNextOffset || off2Ind <= offset)) {
						ind = internalState->fIndex;
					} else {
						ind = off2Ind = 0; // Start from beginning
					}
#if defined(LOGTAG)
					if (LOGTAG == fMemory->getTag()) {
						IOLog("DMA[%p] offsets 0x%qx, 0x%qx, 0x%qx ind %qd\n", this, offset, internalState->fPreparedOffset, internalState->fNextOffset, ind);
					}
#endif /* defined(LOGTAG) */

					// Scan through iopl info blocks looking for block containing offset
					while (ind < internalState->fMapSegmentsCount && offset >= internalState->fMapSegments[ind].fDMAOffset) {
						ind++;
					}
					if (ind < internalState->fMapSegmentsCount) {
						length = internalState->fMapSegments[ind].fDMAOffset;
					} else {
						length = memLength;
					}
					length -= offset;       // Remainder within iopl

					// Go back to actual range as search goes past it
					ind--;
					off2Ind = internalState->fMapSegments[ind].fDMAOffset;

					// Subtract offset till this iopl in total list
					runOffset = offset - off2Ind;

					// Compute an offset relative to the mapped base

					runOffset += internalState->fMapSegments[ind].fPageOffset;
					address = internalState->fLocalMapperAllocBase + internalState->fMapSegments[ind].fMapOffset + runOffset;
#if defined(LOGTAG)
					if (LOGTAG == fMemory->getTag()) {
						IOLog("DMA[%p] addrlen 0x%qx, 0x%qx\n", this, address, length);
					}
#endif /* defined(LOGTAG) */

					state->fIOVMAddr = address;
					state->fLength   = length;

					internalState->fIndex        = ind;
					internalState->fOffset2Index = off2Ind;
					internalState->fNextOffset   = state->fOffset + length;

					rtn = kIOReturnSuccess;
					done = true;
					check = true;
				}
			}

			if (!done) {
				IOMemoryDescriptor * memory =
				    internalState->fCopyMD ? internalState->fCopyMD.get() : fMemory.get();
				rtn = memory->dmaCommandOperation(mdOp, fState, sizeof(fState));
				mdOp = kIOMDWalkSegments;
			}
#if 0
			if (check
			    && !ml_at_interrupt_context()
			    && (rtn == kIOReturnSuccess)
			    && fMapper
			    && strcmp("AppleNVMeMMU", fMapper->getName())) {
				uint64_t checkOffset;
				IOPhysicalLength segLen;
				IOMemoryDescriptor * memory =
				    internalState->fCopyMD ? internalState->fCopyMD.get() : fMemory.get();
				for (checkOffset = 0; checkOffset < state->fLength;) {
					addr64_t phys = memory->getPhysicalSegment(offset + checkOffset, &segLen, kIOMemoryMapperNone);
					addr64_t mapperPhys;

					mapperPhys = fMapper->mapToPhysicalAddress(state->fIOVMAddr + checkOffset);
					mapperPhys |= (phys & (fMapper->getPageSize() - 1));
					if (mapperPhys != phys) {
						panic("DMA[%p] mismatch at offset %llx + %llx, dma %llx mapperPhys %llx != %llx, len %llx\n",
						    this, offset, checkOffset,
						    state->fIOVMAddr + checkOffset, mapperPhys, phys, state->fLength);
					}
					checkOffset += page_size - (phys & page_mask);
				}
			}
#endif
			if (rtn == kIOReturnSuccess) {
				internalState->fIOVMAddrValid = true;
				assert(state->fLength);
				if (curSegValid && ((curSeg.fIOVMAddr + curSeg.fLength) == state->fIOVMAddr)) {
					UInt64 length = state->fLength;
					offset          += length;
					curSeg.fLength  += length;
					internalState->fIOVMAddrValid = state->fIOVMAddr = 0;
				}
			} else if (rtn == kIOReturnOverrun) {
				internalState->fIOVMAddrValid = state->fIOVMAddr = state->fLength = 0; // At end
			} else {
				return rtn;
			}
		}

		// seg = state, offset = end of seg
		if (!curSegValid) {
			UInt64 length                 = state->fLength;
			offset                       += length;
			curSeg.fIOVMAddr              = state->fIOVMAddr;
			curSeg.fLength                = length;
			curSegValid                   = true;
			internalState->fIOVMAddrValid = state->fIOVMAddr = 0;
		}

		if (!internalState->fIOVMAddrValid) {
			// maxPhys
			if ((kWalkClient & op) && (curSeg.fIOVMAddr + curSeg.fLength - 1) > maxPhys) {
				if (internalState->fCursor) {
					curSegValid = curSeg.fIOVMAddr = 0;
					ret = kIOReturnMessageTooLarge;
					break;
				} else if (curSeg.fIOVMAddr <= maxPhys) {
					UInt64 remain, newLength;

					newLength        = (maxPhys + 1 - curSeg.fIOVMAddr);
					DEBG("trunc %qx, %qx-> %qx\n", curSeg.fIOVMAddr, curSeg.fLength, newLength);
					remain           = curSeg.fLength - newLength;
					state->fIOVMAddr = newLength + curSeg.fIOVMAddr;
					internalState->fIOVMAddrValid = true;
					curSeg.fLength   = newLength;
					state->fLength   = remain;
					offset          -= remain;
				} else {
					UInt64    addr = curSeg.fIOVMAddr;
					ppnum_t   addrPage = (ppnum_t) atop_64(addr);
					vm_page_t remap = NULL;
					UInt64    remain, newLength;

					DEBG("sparse switch %qx, %qx ", addr, curSeg.fLength);

					remap = internalState->fNextRemapPage;
					if (remap && (addrPage == vm_page_get_offset(remap))) {
					} else {
						for (remap = internalState->fCopyPageAlloc;
						    remap && (addrPage != vm_page_get_offset(remap));
						    remap = vm_page_get_next(remap)) {
						}
					}

					if (!remap) {
						panic("no remap page found");
					}

					curSeg.fIOVMAddr = ptoa_64(vm_page_get_phys_page(remap))
					    + (addr & PAGE_MASK);
					curSegValid = true;
					internalState->fNextRemapPage = vm_page_get_next(remap);

					newLength            = PAGE_SIZE - (addr & PAGE_MASK);
					if (newLength < curSeg.fLength) {
						remain           = curSeg.fLength - newLength;
						state->fIOVMAddr = addr + newLength;
						internalState->fIOVMAddrValid = true;
						curSeg.fLength   = newLength;
						state->fLength   = remain;
						offset          -= remain;
					}
					DEBG("-> %qx, %qx offset %qx\n", curSeg.fIOVMAddr, curSeg.fLength, offset);
				}
			}

			// reduce size of output segment
			uint64_t reduce, leftover = 0;

			// fMaxSegmentSize
			if (curSeg.fLength > fMaxSegmentSize) {
				leftover      += curSeg.fLength - fMaxSegmentSize;
				curSeg.fLength = fMaxSegmentSize;
				state->fIOVMAddr = curSeg.fLength + curSeg.fIOVMAddr;
				internalState->fIOVMAddrValid = true;
			}

			// alignment current length

			reduce = (curSeg.fLength & fAlignMaskLength);
			if (reduce && (curSeg.fLength > reduce)) {
				leftover       += reduce;
				curSeg.fLength -= reduce;
				state->fIOVMAddr = curSeg.fLength + curSeg.fIOVMAddr;
				internalState->fIOVMAddrValid = true;
			}

			// alignment next address

			reduce = (state->fIOVMAddr & fAlignMaskInternalSegments);
			if (reduce && (curSeg.fLength > reduce)) {
				leftover       += reduce;
				curSeg.fLength -= reduce;
				state->fIOVMAddr = curSeg.fLength + curSeg.fIOVMAddr;
				internalState->fIOVMAddrValid = true;
			}

			if (leftover) {
				DEBG("reduce seg by 0x%llx @ 0x%llx [0x%llx, 0x%llx]\n",
				    leftover, offset,
				    curSeg.fIOVMAddr, curSeg.fLength);
				state->fLength   = leftover;
				offset          -= leftover;
			}

			//

			if (internalState->fCursor) {
				bool misaligned;
				uint32_t mask;

				mask = (segIndex ? fAlignMaskInternalSegments : internalState->fSourceAlignMask);
				misaligned = (0 != (mask & curSeg.fIOVMAddr));
				if (!misaligned) {
					mask = fAlignMaskLength;
					misaligned |= (0 != (mask &  curSeg.fLength));
				}
				if (misaligned) {
					if (misaligned) {
						DEBG("cursor misaligned %qx:%qx\n", curSeg.fIOVMAddr, curSeg.fLength);
					}
					curSegValid = curSeg.fIOVMAddr = 0;
					ret = kIOReturnNotAligned;
					break;
				}
			}

			if (offset >= memLength) {
				curSeg.fLength   -= (offset - memLength);
				offset = memLength;
				internalState->fIOVMAddrValid = state->fIOVMAddr = state->fLength = 0; // At end
				break;
			}
		}

		if (internalState->fIOVMAddrValid) {
			if ((segIndex + 1 == numSegments)) {
				break;
			}
#if defined(LOGTAG)
			if ((LOGTAG == fMemory->getTag()) && (kWalkClient == op)) {
				IOLog("DMA[%p] outseg 0x%qx, 0x%qx\n", this, curSeg.fIOVMAddr, curSeg.fLength);
			}
#endif /* defined(LOGTAG) */
			ret = (*outSegFunc)(reference, this, curSeg, segmentsP, segIndex++);
			curSegValid = curSeg.fIOVMAddr = 0;
			if (kIOReturnSuccess != ret) {
				break;
			}
		}
	}

	if (curSegValid) {
#if defined(LOGTAG)
		if ((LOGTAG == fMemory->getTag()) && (kWalkClient == op)) {
			IOLog("DMA[%p] outseg 0x%qx, 0x%qx\n", this, curSeg.fIOVMAddr, curSeg.fLength);
		}
#endif /* defined(LOGTAG) */
		ret = (*outSegFunc)(reference, this, curSeg, segmentsP, segIndex++);
	}

	if (kIOReturnSuccess == ret) {
		state->fOffset = offset;
		*offsetP       = offset - internalState->fPreparedOffset;
		*numSegmentsP  = segIndex;
	}
	return ret;
}

IOReturn
IODMACommand::clientOutputSegment(
	void *reference, IODMACommand *target,
	Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	SegmentFunction segmentFunction = (SegmentFunction) reference;
	IOReturn ret = kIOReturnSuccess;

	if (target->fNumAddressBits && (target->fNumAddressBits < 64)
	    && ((segment.fIOVMAddr + segment.fLength - 1) >> target->fNumAddressBits)
	    && (target->reserved->fLocalMapperAllocValid || !target->fMapper)) {
		DEBG("kIOReturnMessageTooLarge(fNumAddressBits) %qx, %qx\n", segment.fIOVMAddr, segment.fLength);
		ret = kIOReturnMessageTooLarge;
	}

	if (!(*segmentFunction)(target, segment, vSegList, outSegIndex)) {
		DEBG("kIOReturnMessageTooLarge(fOutSeg) %qx, %qx\n", segment.fIOVMAddr, segment.fLength);
		ret = kIOReturnMessageTooLarge;
	}

	return ret;
}

IOReturn
IODMACommand::genIOVMSegments(SegmentFunction segmentFunction,
    UInt64   *offsetP,
    void     *segmentsP,
    UInt32   *numSegmentsP)
{
	return genIOVMSegments(kWalkClient, clientOutputSegment, (void *) segmentFunction,
	           offsetP, segmentsP, numSegmentsP);
}

bool
IODMACommand::OutputHost32(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	Segment32 *base = (Segment32 *) vSegList;
	base[outSegIndex].fIOVMAddr = (UInt32) segment.fIOVMAddr;
	base[outSegIndex].fLength   = (UInt32) segment.fLength;
	return true;
}

bool
IODMACommand::OutputBig32(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	const UInt offAddr = outSegIndex * sizeof(Segment32);
	const UInt offLen  = offAddr + sizeof(UInt32);
	OSWriteBigInt32(vSegList, offAddr, (UInt32) segment.fIOVMAddr);
	OSWriteBigInt32(vSegList, offLen, (UInt32) segment.fLength);
	return true;
}

bool
IODMACommand::OutputLittle32(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	const UInt offAddr = outSegIndex * sizeof(Segment32);
	const UInt offLen  = offAddr + sizeof(UInt32);
	OSWriteLittleInt32(vSegList, offAddr, (UInt32) segment.fIOVMAddr);
	OSWriteLittleInt32(vSegList, offLen, (UInt32) segment.fLength);
	return true;
}

bool
IODMACommand::OutputHost64(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	Segment64 *base = (Segment64 *) vSegList;
	base[outSegIndex] = segment;
	return true;
}

bool
IODMACommand::OutputBig64(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	const UInt offAddr = outSegIndex * sizeof(Segment64);
	const UInt offLen  = offAddr + sizeof(UInt64);
	OSWriteBigInt64(vSegList, offAddr, (UInt64) segment.fIOVMAddr);
	OSWriteBigInt64(vSegList, offLen, (UInt64) segment.fLength);
	return true;
}

bool
IODMACommand::OutputLittle64(IODMACommand *,
    Segment64 segment, void *vSegList, UInt32 outSegIndex)
{
	const UInt offAddr = outSegIndex * sizeof(Segment64);
	const UInt offLen  = offAddr + sizeof(UInt64);
	OSWriteLittleInt64(vSegList, offAddr, (UInt64) segment.fIOVMAddr);
	OSWriteLittleInt64(vSegList, offLen, (UInt64) segment.fLength);
	return true;
}
