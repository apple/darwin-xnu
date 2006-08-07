/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
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
// 45678901234567890123456789012345678901234567890123456789012345678901234567890
#include <sys/cdefs.h>

#include <IOKit/assert.h>
#include <IOKit/system.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOKitKeysPrivate.h>

#include <IOKit/IOKitDebug.h>

#include "IOKitKernelInternal.h"
#include "IOCopyMapper.h"

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSNumber.h>

#include <sys/uio.h>

__BEGIN_DECLS
#include <vm/pmap.h>
#include <vm/vm_pageout.h>
#include <vm/vm_shared_memory_server.h>
#include <mach/memory_object_types.h>
#include <device/device_port.h>

#include <mach/vm_prot.h>
#include <vm/vm_fault.h>

extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
void ipc_port_release_send(ipc_port_t port);

/* Copy between a physical page and a virtual address in the given vm_map */
kern_return_t copypv(addr64_t source, addr64_t sink, unsigned int size, int which);

memory_object_t
device_pager_setup(
	memory_object_t	pager,
	int		device_handle,
	vm_size_t	size,
	int		flags);
void
device_pager_deallocate(
        memory_object_t);
kern_return_t
device_pager_populate_object(
	memory_object_t		pager,
	vm_object_offset_t	offset,
	ppnum_t			phys_addr,
	vm_size_t		size);
kern_return_t
memory_object_iopl_request(
	ipc_port_t		port,
	memory_object_offset_t	offset,
	vm_size_t		*upl_size,
	upl_t			*upl_ptr,
	upl_page_info_array_t	user_page_list,
	unsigned int		*page_list_count,
	int			*flags);

unsigned int  IOTranslateCacheBits(struct phys_entry *pp);

__END_DECLS

#define kIOMaximumMappedIOByteCount	(512*1024*1024)

static IOMapper * gIOSystemMapper = NULL;

IOCopyMapper *	  gIOCopyMapper = NULL;

static ppnum_t	  gIOMaximumMappedIOPageCount = atop_32(kIOMaximumMappedIOByteCount);

ppnum_t		  gIOLastPage;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors( IOMemoryDescriptor, OSObject )

#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOGeneralMemoryDescriptor, IOMemoryDescriptor)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IORecursiveLock * gIOMemoryLock;

#define LOCK	IORecursiveLockLock( gIOMemoryLock)
#define UNLOCK	IORecursiveLockUnlock( gIOMemoryLock)
#define SLEEP	IORecursiveLockSleep( gIOMemoryLock, (void *)this, THREAD_UNINT)
#define WAKEUP	\
    IORecursiveLockWakeup( gIOMemoryLock, (void *)this, /* one-thread */ false)

#if 0
#define DEBG(fmt, args...)  	{ kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)  	{}
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class _IOMemoryMap : public IOMemoryMap
{
    OSDeclareDefaultStructors(_IOMemoryMap)
public:
    IOMemoryDescriptor * memory;
    IOMemoryMap *	superMap;
    IOByteCount		offset;
    IOByteCount		length;
    IOVirtualAddress	logical;
    task_t		addressTask;
    vm_map_t		addressMap;
    IOOptionBits	options;
    upl_t		redirUPL;
    ipc_port_t		redirEntry;
    IOMemoryDescriptor * owner;

protected:
    virtual void taggedRelease(const void *tag = 0) const;
    virtual void free();

public:

    // IOMemoryMap methods
    virtual IOVirtualAddress 	getVirtualAddress();
    virtual IOByteCount 	getLength();
    virtual task_t		getAddressTask();
    virtual IOMemoryDescriptor * getMemoryDescriptor();
    virtual IOOptionBits 	getMapOptions();

    virtual IOReturn 		unmap();
    virtual void 		taskDied();

    virtual IOReturn		redirect(IOMemoryDescriptor * newBackingMemory,
					 IOOptionBits         options,
					 IOByteCount          offset = 0);

    virtual IOPhysicalAddress 	getPhysicalSegment(IOByteCount offset,
	       					   IOByteCount * length);

    // for IOMemoryDescriptor use
    _IOMemoryMap * copyCompatible(
		IOMemoryDescriptor *	owner,
                task_t			intoTask,
                IOVirtualAddress	toAddress,
                IOOptionBits		options,
                IOByteCount		offset,
                IOByteCount		length );

    bool initCompatible(
	IOMemoryDescriptor *	memory,
	IOMemoryMap *		superMap,
        IOByteCount		offset,
        IOByteCount		length );

    bool initWithDescriptor(
	IOMemoryDescriptor *	memory,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
        IOByteCount		offset,
        IOByteCount		length );

    IOReturn redirect(
	task_t			intoTask, bool redirect );
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Some data structures and accessor macros used by the initWithOptions
// Function

enum ioPLBlockFlags {
    kIOPLOnDevice  = 0x00000001,
    kIOPLExternUPL = 0x00000002,
};

struct typePersMDData
{
    const IOGeneralMemoryDescriptor *fMD;
    ipc_port_t fMemEntry;
};

struct ioPLBlock {
    upl_t fIOPL;
    vm_address_t fIOMDOffset;	// The offset of this iopl in descriptor
    vm_offset_t fPageInfo;	// Pointer to page list or index into it
    ppnum_t fMappedBase;	// Page number of first page in this iopl
    unsigned int fPageOffset;	// Offset within first page of iopl
    unsigned int fFlags;	// Flags
};

struct ioGMDData {
    IOMapper *fMapper;
    unsigned int fPageCnt;
    upl_page_info_t fPageList[];
    ioPLBlock fBlocks[];
};

#define getDataP(osd)	((ioGMDData *) (osd)->getBytesNoCopy())
#define getIOPLList(d)	((ioPLBlock *) &(d->fPageList[d->fPageCnt]))
#define getNumIOPL(osd, d)	\
    (((osd)->getLength() - ((char *) getIOPLList(d) - (char *) d)) / sizeof(ioPLBlock))
#define getPageList(d)	(&(d->fPageList[0]))
#define computeDataSize(p, u) \
    (sizeof(ioGMDData) + p * sizeof(upl_page_info_t) + u * sizeof(ioPLBlock))


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define next_page(a) ( trunc_page_32(a) + PAGE_SIZE )


extern "C" {

kern_return_t device_data_action(
               int                     device_handle, 
               ipc_port_t              device_pager,
               vm_prot_t               protection, 
               vm_object_offset_t      offset, 
               vm_size_t               size)
{
    struct ExpansionData {
        void *				devicePager;
        unsigned int			pagerContig:1;
        unsigned int			unused:31;
	IOMemoryDescriptor *		memory;
    };
    kern_return_t	 kr;
    ExpansionData *      ref = (ExpansionData *) device_handle;
    IOMemoryDescriptor * memDesc;

    LOCK;
    memDesc = ref->memory;
    if( memDesc)
    {
	memDesc->retain();
	kr = memDesc->handleFault( device_pager, 0, 0,
                offset, size, kIOMapDefaultCache /*?*/);
	memDesc->release();
    }
    else
	kr = KERN_ABORTED;
    UNLOCK;

    return( kr );
}

kern_return_t device_close(
               int     device_handle)
{
    struct ExpansionData {
        void *				devicePager;
        unsigned int			pagerContig:1;
        unsigned int			unused:31;
	IOMemoryDescriptor *		memory;
    };
    ExpansionData *   ref = (ExpansionData *) device_handle;

    IODelete( ref, ExpansionData, 1 );

    return( kIOReturnSuccess );
}
};	// end extern "C"

// Note this inline function uses C++ reference arguments to return values
// This means that pointers are not passed and NULLs don't have to be
// checked for as a NULL reference is illegal.
static inline void
getAddrLenForInd(addr64_t &addr, IOPhysicalLength &len, // Output variables
     UInt32 type, IOGeneralMemoryDescriptor::Ranges r, UInt32 ind)
{
    assert(kIOMemoryTypeUIO       == type
	|| kIOMemoryTypeVirtual   == type || kIOMemoryTypeVirtual64 == type
	|| kIOMemoryTypePhysical  == type || kIOMemoryTypePhysical64 == type);
    if (kIOMemoryTypeUIO == type) {
	user_size_t us;
	uio_getiov((uio_t) r.uio, ind, &addr, &us); len = us;
    }
    else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type)) {
	IOAddressRange cur = r.v64[ind];
	addr = cur.address;
	len  = cur.length;
    }
    else {
	IOVirtualRange cur = r.v[ind];
	addr = cur.address;
	len  = cur.length;
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * withAddress:
 *
 * Create a new IOMemoryDescriptor.  The buffer is a virtual address
 * relative to the specified task.  If no task is supplied, the kernel
 * task is implied.
 */
IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(void *      address,
                                IOByteCount   length,
                                IODirection direction)
{
    return IOMemoryDescriptor::
        withAddress((vm_address_t) address, length, direction, kernel_task);
}

IOMemoryDescriptor *
IOMemoryDescriptor::withAddress(vm_address_t address,
                                IOByteCount  length,
                                IODirection  direction,
                                task_t       task)
{
#if TEST_V64
    if (task)
    {
	IOOptionBits options = (IOOptionBits) direction;
	if (task == kernel_task)
	    options |= kIOMemoryAutoPrepare;
	return (IOMemoryDescriptor::withAddressRange(address, length, options, task));
    }
#endif
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithAddress(address, length, direction, task))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalAddress(
				IOPhysicalAddress	address,
				IOByteCount		length,
				IODirection      	direction )
{
#if TEST_P64
    return (IOMemoryDescriptor::withAddressRange(address, length, (IOOptionBits) direction, NULL));
#endif
    IOGeneralMemoryDescriptor *self = new IOGeneralMemoryDescriptor;
    if (self
    && !self->initWithPhysicalAddress(address, length, direction)) {
        self->release();
        return 0;
    }

    return self;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withRanges(	IOVirtualRange * ranges,
				UInt32           withCount,
				IODirection      direction,
				task_t           task,
				bool             asReference)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithRanges(ranges, withCount, direction, task, asReference))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withAddressRange(mach_vm_address_t address,
                                       mach_vm_size_t length,
                                       IOOptionBits   options,
                                       task_t         task)
{
    IOAddressRange range = { address, length };
    return (IOMemoryDescriptor::withAddressRanges(&range, 1, options, task));
}

IOMemoryDescriptor *
IOMemoryDescriptor::withAddressRanges(IOAddressRange *   ranges,
                                       UInt32           rangeCount,
                                       IOOptionBits     options,
                                       task_t           task)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (task)
	    options |= kIOMemoryTypeVirtual64;
	else
	    options |= kIOMemoryTypePhysical64;

       if (that->initWithOptions(ranges, rangeCount, 0, task, options, /* mapper */ 0))
           return that;

       that->release();
    }

    return 0;
}


/*
 * withRanges:
 *
 * Create a new IOMemoryDescriptor. The buffer is made up of several
 * virtual address ranges, from a given task.
 *
 * Passing the ranges as a reference will avoid an extra allocation.
 */
IOMemoryDescriptor *
IOMemoryDescriptor::withOptions(void *		buffers,
                                UInt32		count,
                                UInt32		offset,
                                task_t		task,
                                IOOptionBits	opts,
                                IOMapper *	mapper)
{
    IOGeneralMemoryDescriptor *self = new IOGeneralMemoryDescriptor;

    if (self
    && !self->initWithOptions(buffers, count, offset, task, opts, mapper))
    {
        self->release();
        return 0;
    }

    return self;
}

// Can't leave abstract but this should never be used directly,
bool IOMemoryDescriptor::initWithOptions(void *		buffers,
                                         UInt32		count,
                                         UInt32		offset,
                                         task_t		task,
                                         IOOptionBits	options,
                                         IOMapper *	mapper)
{
    // @@@ gvdl: Should I panic?
    panic("IOMD::initWithOptions called\n");
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withPhysicalRanges(	IOPhysicalRange * ranges,
                                        UInt32          withCount,
                                        IODirection     direction,
                                        bool            asReference)
{
    IOGeneralMemoryDescriptor * that = new IOGeneralMemoryDescriptor;
    if (that)
    {
	if (that->initWithPhysicalRanges(ranges, withCount, direction, asReference))
	    return that;

        that->release();
    }
    return 0;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withSubRange(IOMemoryDescriptor *	of,
				IOByteCount		offset,
				IOByteCount		length,
				IODirection		direction)
{
    IOSubMemoryDescriptor *self = new IOSubMemoryDescriptor;

    if (self && !self->initSubRange(of, offset, length, direction)) {
        self->release();
	self = 0;
    }
    return self;
}

IOMemoryDescriptor *
IOMemoryDescriptor::withPersistentMemoryDescriptor(IOMemoryDescriptor *originalMD)
{
    IOGeneralMemoryDescriptor *origGenMD = 
	OSDynamicCast(IOGeneralMemoryDescriptor, originalMD);

    if (origGenMD)
	return IOGeneralMemoryDescriptor::
	    withPersistentMemoryDescriptor(origGenMD);
    else
	return 0;
}

IOMemoryDescriptor *
IOGeneralMemoryDescriptor::withPersistentMemoryDescriptor(IOGeneralMemoryDescriptor *originalMD)
{
    ipc_port_t sharedMem = (ipc_port_t) originalMD->createNamedEntry();

    if (!sharedMem)
	return 0;
   
    if (sharedMem == originalMD->_memEntry) {
	originalMD->retain();		    // Add a new reference to ourselves
	ipc_port_release_send(sharedMem);   // Remove extra send right
	return originalMD;
    }

    IOGeneralMemoryDescriptor * self = new IOGeneralMemoryDescriptor;
    typePersMDData initData = { originalMD, sharedMem };

    if (self
    && !self->initWithOptions(&initData, 1, 0, 0, kIOMemoryTypePersistentMD, 0)) {
        self->release();
	self = 0;
    }
    return self;
}

void *IOGeneralMemoryDescriptor::createNamedEntry()
{
    kern_return_t error;
    ipc_port_t sharedMem;

    IOOptionBits type = _flags & kIOMemoryTypeMask;

    user_addr_t range0Addr;
    IOByteCount range0Len;
    getAddrLenForInd(range0Addr, range0Len, type, _ranges, 0);
    range0Addr = trunc_page_64(range0Addr);

    vm_size_t size = ptoa_32(_pages);
    vm_address_t kernelPage = (vm_address_t) range0Addr;

    vm_map_t theMap = ((_task == kernel_task)
			&& (kIOMemoryBufferPageable & _flags)) 
		    ? IOPageableMapForAddress(kernelPage)
		    : get_task_map(_task);

    memory_object_size_t  actualSize = size;
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE;
    if (_memEntry)
	prot |= MAP_MEM_NAMED_REUSE;

    error = mach_make_memory_entry_64(theMap,
	    &actualSize, range0Addr, prot, &sharedMem, (ipc_port_t) _memEntry);

    if (KERN_SUCCESS == error) {
	if (actualSize == size) {
	    return sharedMem;
	} else {
#if IOASSERT
	    IOLog("IOGMD::mach_make_memory_entry_64 (%08llx) size (%08lx:%08x)\n",
			(UInt64)range0Addr, (UInt32)actualSize, size);
#endif    
	    ipc_port_release_send( sharedMem );
	}
    }

    return MACH_PORT_NULL;
}

/*
 * initWithAddress:
 *
 * Initialize an IOMemoryDescriptor. The buffer is a virtual address
 * relative to the specified task.  If no task is supplied, the kernel
 * task is implied.
 *
 * An IOMemoryDescriptor can be re-used by calling initWithAddress or
 * initWithRanges again on an existing instance -- note this behavior
 * is not commonly supported in other I/O Kit classes, although it is
 * supported here.
 */
bool
IOGeneralMemoryDescriptor::initWithAddress(void *      address,
                                    IOByteCount   withLength,
                                    IODirection withDirection)
{
    _singleRange.v.address = (vm_address_t) address;
    _singleRange.v.length  = withLength;

    return initWithRanges(&_singleRange.v, 1, withDirection, kernel_task, true);
}

bool
IOGeneralMemoryDescriptor::initWithAddress(vm_address_t address,
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
				 IOPhysicalAddress	address,
				 IOByteCount		withLength,
				 IODirection      	withDirection )
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

    if (reference)
        mdOpts |= kIOMemoryAsReference;

    return initWithOptions(ranges, count, 0, 0, mdOpts, /* mapper */ 0);
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

    if (reference)
        mdOpts |= kIOMemoryAsReference;

    if (task) {
        mdOpts |= kIOMemoryTypeVirtual;

	// Auto-prepare if this is a kernel memory descriptor as very few
	// clients bother to prepare() kernel memory.
	// But it was not  enforced so what are you going to do?
        if (task == kernel_task)
            mdOpts |= kIOMemoryAutoPrepare;
    }
    else
        mdOpts |= kIOMemoryTypePhysical;
    
    return initWithOptions(ranges, count, 0, task, mdOpts, /* mapper */ 0);
}

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
IOGeneralMemoryDescriptor::initWithOptions(void *	buffers,
                                           UInt32	count,
                                           UInt32	offset,
                                           task_t	task,
                                           IOOptionBits	options,
                                           IOMapper *	mapper)
{
    IOOptionBits type = options & kIOMemoryTypeMask;

    // Grab the original MD's configuation data to initialse the
    // arguments to this function.
    if (kIOMemoryTypePersistentMD == type) {

	typePersMDData *initData = (typePersMDData *) buffers;
	const IOGeneralMemoryDescriptor *orig = initData->fMD;
	ioGMDData *dataP = getDataP(orig->_memoryEntries);

	// Only accept persistent memory descriptors with valid dataP data.
	assert(orig->_rangesCount == 1);
	if ( !(orig->_flags & kIOMemoryPersistent) || !dataP)
	    return false;

	_memEntry = initData->fMemEntry;	// Grab the new named entry
	options = orig->_flags | kIOMemoryAsReference; 
	_singleRange = orig->_singleRange;	// Initialise our range
	buffers = &_singleRange;
	count = 1;

	// Now grab the original task and whatever mapper was previously used
	task = orig->_task;
	mapper = dataP->fMapper;

	// We are ready to go through the original initialisation now
    }

    switch (type) {
    case kIOMemoryTypeUIO:
    case kIOMemoryTypeVirtual:
    case kIOMemoryTypeVirtual64:
        assert(task);
        if (!task)
            return false;
        else
            break;

    case kIOMemoryTypePhysical:		// Neither Physical nor UPL should have a task
    case kIOMemoryTypePhysical64:
	mapper = kIOMapperNone;

    case kIOMemoryTypeUPL:
        assert(!task);
        break;
    default:
        return false;	/* bad argument */
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

        while (_wireCount)
            complete();
        if (_ranges.v && _rangesIsAllocated)
	{
	    if (kIOMemoryTypeUIO == type)
		uio_free((uio_t) _ranges.v);
	    else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type))
		IODelete(_ranges.v64, IOAddressRange, _rangesCount);
	    else
		IODelete(_ranges.v, IOVirtualRange, _rangesCount);
	}
	if (_memEntry)
	    { ipc_port_release_send((ipc_port_t) _memEntry); _memEntry = 0; }
    }
    else {
        if (!super::init())
            return false;
        _initialized = true;
    }

    // Grab the appropriate mapper
    if (mapper == kIOMapperNone)
        mapper = 0;	// No Mapper
    else if (mapper == kIOMapperSystem) {
        IOMapper::checkForSystemMapper();
        gIOSystemMapper = mapper = IOMapper::gSystem;
    }

    // Remove the dynamic internal use flags from the initial setting
    options 		  &= ~(kIOMemoryPreparedReadOnly);
    _flags		   = options;
    _task                  = task;

    // DEPRECATED variable initialisation
    _direction             = (IODirection) (_flags & kIOMemoryDirectionMask);

    __iomd_reservedA = 0;
    __iomd_reservedB = 0;
    __iomd_reservedC = 0;

    _highestPage = 0;

    if (kIOMemoryTypeUPL == type) {

        ioGMDData *dataP;
        unsigned int dataSize = computeDataSize(/* pages */ 0, /* upls */ 1);

        if (!_memoryEntries) {
            _memoryEntries = OSData::withCapacity(dataSize);
            if (!_memoryEntries)
                return false;
        }
        else if (!_memoryEntries->initWithCapacity(dataSize))
            return false;

        _memoryEntries->appendBytes(0, sizeof(ioGMDData));
        dataP = getDataP(_memoryEntries);
        dataP->fMapper = mapper;
        dataP->fPageCnt = 0;

 //       _wireCount++;	// UPLs start out life wired

        _length    = count;
        _pages    += atop_32(offset + count + PAGE_MASK) - atop_32(offset);

        ioPLBlock iopl;
        upl_page_info_t *pageList = UPL_GET_INTERNAL_PAGE_LIST((upl_t) buffers);

        iopl.fIOPL = (upl_t) buffers;
        // Set the flag kIOPLOnDevice convieniently equal to 1
        iopl.fFlags  = pageList->device | kIOPLExternUPL;
        iopl.fIOMDOffset = 0;

        _highestPage = upl_get_highest_page(iopl.fIOPL);

        if (!pageList->device) {
            // Pre-compute the offset into the UPL's page list
            pageList = &pageList[atop_32(offset)];
            offset &= PAGE_MASK;
            if (mapper) {
                iopl.fMappedBase = mapper->iovmAlloc(_pages);
                mapper->iovmInsert(iopl.fMappedBase, 0, pageList, _pages);
            }
	    else
		iopl.fMappedBase = 0;
        }
	else
	    iopl.fMappedBase = 0;
        iopl.fPageInfo = (vm_address_t) pageList;
        iopl.fPageOffset = offset;

        _memoryEntries->appendBytes(&iopl, sizeof(iopl));
    }
    else {
	// kIOMemoryTypeVirtual  | kIOMemoryTypeVirtual64 | kIOMemoryTypeUIO 
	// kIOMemoryTypePhysical | kIOMemoryTypePhysical64
	
	// Initialize the memory descriptor
	if (options & kIOMemoryAsReference) {
	    _rangesIsAllocated = false;

	    // Hack assignment to get the buffer arg into _ranges.
	    // I'd prefer to do _ranges = (Ranges) buffers, but that doesn't
	    // work, C++ sigh.
	    // This also initialises the uio & physical ranges.
	    _ranges.v = (IOVirtualRange *) buffers;
	}
	else {
	    _rangesIsAllocated = true;
	    switch (_flags & kIOMemoryTypeMask)
	    {
	      case kIOMemoryTypeUIO:
		_ranges.v = (IOVirtualRange *) uio_duplicate((uio_t) buffers);
		break;

	      case kIOMemoryTypeVirtual64:
	      case kIOMemoryTypePhysical64:
		_ranges.v64 = IONew(IOAddressRange, count);
		if (!_ranges.v64)
		    return false;
		bcopy(buffers, _ranges.v, count * sizeof(IOAddressRange));
		break;
	      case kIOMemoryTypeVirtual:
		_ranges.v = IONew(IOVirtualRange, count);
		if (!_ranges.v)
		    return false;
		bcopy(buffers, _ranges.v, count * sizeof(IOVirtualRange));
		break;
	    }
	} 

	// Find starting address within the vector of ranges
	Ranges vec = _ranges;
	UInt32 length = 0;
	UInt32 pages = 0;
	for (unsigned ind = 0; ind < count;  ind++) {
	    user_addr_t addr;
	    UInt32 len;

	    // addr & len are returned by this function
	    getAddrLenForInd(addr, len, type, vec, ind);
	    pages += (atop_64(addr + len + PAGE_MASK) - atop_64(addr));
	    len += length;
	    assert(len >= length);	// Check for 32 bit wrap around
	    length = len;

	    if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type))
	    {
		ppnum_t highPage = atop_64(addr + len - 1);
		if (highPage > _highestPage)
		    _highestPage = highPage;
	    }
	} 
	_length      = length;
	_pages       = pages;
	_rangesCount = count;

        // Auto-prepare memory at creation time.
        // Implied completion when descriptor is free-ed
        if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type))
            _wireCount++;	// Physical MDs are, by definition, wired
        else { /* kIOMemoryTypeVirtual | kIOMemoryTypeVirtual64 | kIOMemoryTypeUIO */
            ioGMDData *dataP;
            unsigned dataSize = computeDataSize(_pages, /* upls */ count * 2);

            if (!_memoryEntries) {
                _memoryEntries = OSData::withCapacity(dataSize);
                if (!_memoryEntries)
		    return false;
            }
            else if (!_memoryEntries->initWithCapacity(dataSize))
                return false;
    
            _memoryEntries->appendBytes(0, sizeof(ioGMDData));
            dataP = getDataP(_memoryEntries);
            dataP->fMapper = mapper;
            dataP->fPageCnt = _pages;

	    if ( (kIOMemoryPersistent & _flags) && !_memEntry)
		_memEntry = createNamedEntry();

            if ((_flags & kIOMemoryAutoPrepare)
             && prepare() != kIOReturnSuccess)
                return false;
        }
    }

    return true;
}

/*
 * free
 *
 * Free resources.
 */
void IOGeneralMemoryDescriptor::free()
{
    LOCK;
    if( reserved)
	reserved->memory = 0;
    UNLOCK;

    while (_wireCount)
        complete();
    if (_memoryEntries)
        _memoryEntries->release();

    if (_ranges.v && _rangesIsAllocated)
    {
	IOOptionBits type = _flags & kIOMemoryTypeMask;
	if (kIOMemoryTypeUIO == type)
	    uio_free((uio_t) _ranges.v);
	else if ((kIOMemoryTypeVirtual64 == type) || (kIOMemoryTypePhysical64 == type))
	    IODelete(_ranges.v64, IOAddressRange, _rangesCount);
	else
	    IODelete(_ranges.v, IOVirtualRange, _rangesCount);
    }

    if (reserved && reserved->devicePager)
	device_pager_deallocate( (memory_object_t) reserved->devicePager );

    // memEntry holds a ref on the device pager which owns reserved
    // (ExpansionData) so no reserved access after this point
    if (_memEntry)
        ipc_port_release_send( (ipc_port_t) _memEntry );

    super::free();
}

/* DEPRECATED */ void IOGeneralMemoryDescriptor::unmapFromKernel()
/* DEPRECATED */ {
                    panic("IOGMD::unmapFromKernel deprecated");
/* DEPRECATED */ }
/* DEPRECATED */ 
/* DEPRECATED */ void IOGeneralMemoryDescriptor::mapIntoKernel(unsigned rangeIndex)
/* DEPRECATED */ {
                    panic("IOGMD::mapIntoKernel deprecated");
/* DEPRECATED */ }

/*
 * getDirection:
 *
 * Get the direction of the transfer.
 */
IODirection IOMemoryDescriptor::getDirection() const
{
    return _direction;
}

/*
 * getLength:
 *
 * Get the length of the transfer (over all ranges).
 */
IOByteCount IOMemoryDescriptor::getLength() const
{
    return _length;
}

void IOMemoryDescriptor::setTag( IOOptionBits tag )
{
    _tag = tag;    
}

IOOptionBits IOMemoryDescriptor::getTag( void )
{
    return( _tag);
}

// @@@ gvdl: who is using this API?  Seems like a wierd thing to implement.
IOPhysicalAddress
IOMemoryDescriptor::getSourceSegment( IOByteCount   offset, IOByteCount * length )
{
    addr64_t physAddr = 0;

    if( prepare() == kIOReturnSuccess) {
        physAddr = getPhysicalSegment64( offset, length );
        complete();
    }

    return( (IOPhysicalAddress) physAddr ); // truncated but only page offset is used
}

IOByteCount IOMemoryDescriptor::readBytes
                (IOByteCount offset, void *bytes, IOByteCount length)
{
    addr64_t dstAddr = (addr64_t) (UInt32) bytes;
    IOByteCount remaining;

    // Assert that this entire I/O is withing the available range
    assert(offset < _length);
    assert(offset + length <= _length);
    if (offset >= _length) {
IOLog("IOGMD(%p): rB = o%lx, l%lx\n", this, offset, length);	// @@@ gvdl
        return 0;
    }

    remaining = length = min(length, _length - offset);
    while (remaining) {	// (process another target segment?)
        addr64_t	srcAddr64;
        IOByteCount	srcLen;

        srcAddr64 = getPhysicalSegment64(offset, &srcLen);
        if (!srcAddr64)
            break;

        // Clip segment length to remaining
        if (srcLen > remaining)
            srcLen = remaining;

        copypv(srcAddr64, dstAddr, srcLen,
                            cppvPsrc | cppvNoRefSrc | cppvFsnk | cppvKmap);

        dstAddr   += srcLen;
        offset    += srcLen;
        remaining -= srcLen;
    }

    assert(!remaining);

    return length - remaining;
}

IOByteCount IOMemoryDescriptor::writeBytes
                (IOByteCount offset, const void *bytes, IOByteCount length)
{
    addr64_t srcAddr = (addr64_t) (UInt32) bytes;
    IOByteCount remaining;

    // Assert that this entire I/O is withing the available range
    assert(offset < _length);
    assert(offset + length <= _length);

    assert( !(kIOMemoryPreparedReadOnly & _flags) );

    if ( (kIOMemoryPreparedReadOnly & _flags) || offset >= _length) {
IOLog("IOGMD(%p): wB = o%lx, l%lx\n", this, offset, length);	// @@@ gvdl
        return 0;
    }

    remaining = length = min(length, _length - offset);
    while (remaining) {	// (process another target segment?)
        addr64_t    dstAddr64;
        IOByteCount dstLen;

        dstAddr64 = getPhysicalSegment64(offset, &dstLen);
        if (!dstAddr64)
            break;

        // Clip segment length to remaining
        if (dstLen > remaining)
            dstLen = remaining;

        copypv(srcAddr, (addr64_t) dstAddr64, dstLen,
                            cppvPsnk | cppvFsnk | cppvNoRefSrc | cppvNoModSnk | cppvKmap);

        srcAddr   += dstLen;
        offset    += dstLen;
        remaining -= dstLen;
    }

    assert(!remaining);

    return length - remaining;
}

// osfmk/device/iokit_rpc.c
extern "C" unsigned int IODefaultCacheBits(addr64_t pa);

/* DEPRECATED */ void IOGeneralMemoryDescriptor::setPosition(IOByteCount position)
/* DEPRECATED */ {
                    panic("IOGMD::setPosition deprecated");
/* DEPRECATED */ }

IOReturn IOGeneralMemoryDescriptor::dmaCommandOperation(DMACommandOps op, void *vData, UInt dataSize) const
{
    if (kIOMDGetCharacteristics == op) {

	if (dataSize < sizeof(IOMDDMACharacteristics))
	    return kIOReturnUnderrun;

	IOMDDMACharacteristics *data = (IOMDDMACharacteristics *) vData;
	data->fLength = _length;
	data->fSGCount = _rangesCount;
	data->fPages = _pages;
	data->fDirection = _direction;
	if (!_wireCount)
	    data->fIsPrepared = false;
	else {
	    data->fIsPrepared = true;
	    data->fHighestPage = _highestPage;
	    if (_memoryEntries) {
		ioGMDData *gmdData = getDataP(_memoryEntries);
		ioPLBlock *ioplList = getIOPLList(gmdData);
		UInt count = getNumIOPL(_memoryEntries, gmdData);

		data->fIsMapped = (gmdData->fMapper && _pages && (count > 0)
			       && ioplList[0].fMappedBase);
		if (count == 1)
		    data->fPageAlign = (ioplList[0].fPageOffset & PAGE_MASK) | ~PAGE_MASK;
	    }
	    else
		data->fIsMapped = false;
	}

	return kIOReturnSuccess;
    }
    else if (!(kIOMDWalkSegments & op))
	return kIOReturnBadArgument;

    // Get the next segment
    struct InternalState {
	IOMDDMAWalkSegmentArgs fIO;
	UInt fOffset2Index;
	UInt fIndex;
	UInt fNextOffset;
    } *isP;

    // Find the next segment
    if (dataSize < sizeof(*isP))
	return kIOReturnUnderrun;

    isP = (InternalState *) vData;
    UInt offset = isP->fIO.fOffset;
    bool mapped = isP->fIO.fMapped;

    if (offset >= _length)
	return (offset == _length)? kIOReturnOverrun : kIOReturnInternalError;

    // Validate the previous offset
    UInt ind, off2Ind = isP->fOffset2Index;
    if ((kIOMDFirstSegment != op) 
	&& offset 
	&& (offset == isP->fNextOffset || off2Ind <= offset))
	ind = isP->fIndex;
    else
	ind = off2Ind = 0;	// Start from beginning

    UInt length;
    UInt64 address;
    if ( (_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical) {

	// Physical address based memory descriptor
	const IOPhysicalRange *physP = (IOPhysicalRange *) &_ranges.p[0];

	// Find the range after the one that contains the offset
	UInt len;
	for (len = 0; off2Ind <= offset; ind++) {
	    len = physP[ind].length;
	    off2Ind += len;
	}

	// Calculate length within range and starting address
	length   = off2Ind - offset;
	address  = physP[ind - 1].address + len - length;

	// see how far we can coalesce ranges
	while (ind < _rangesCount && address + length == physP[ind].address) {
	    len = physP[ind].length;
	    length += len;
	    off2Ind += len;
	    ind++;
	}

	// correct contiguous check overshoot
	ind--;
	off2Ind -= len;
    }
    else if ( (_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64) {

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

	// see how far we can coalesce ranges
	while (ind < _rangesCount && address + length == physP[ind].address) {
	    len = physP[ind].length;
	    length += len;
	    off2Ind += len;
	    ind++;
	}

	// correct contiguous check overshoot
	ind--;
	off2Ind -= len;
    }
    else do {
	if (!_wireCount)
	    panic("IOGMD: not wired for the IODMACommand");

	assert(_memoryEntries);

	ioGMDData * dataP = getDataP(_memoryEntries);
	const ioPLBlock *ioplList = getIOPLList(dataP);
	UInt numIOPLs = getNumIOPL(_memoryEntries, dataP);
	upl_page_info_t *pageList = getPageList(dataP);

	assert(numIOPLs > 0);

	// Scan through iopl info blocks looking for block containing offset
	while (ind < numIOPLs && offset >= ioplList[ind].fIOMDOffset)
	    ind++;

	// Go back to actual range as search goes past it
	ioPLBlock ioplInfo = ioplList[ind - 1];
	off2Ind = ioplInfo.fIOMDOffset;

	if (ind < numIOPLs)
	    length = ioplList[ind].fIOMDOffset;
	else
	    length = _length;
	length -= offset;			// Remainder within iopl

	// Subtract offset till this iopl in total list
	offset -= off2Ind;

	// If a mapped address is requested and this is a pre-mapped IOPL
	// then just need to compute an offset relative to the mapped base.
	if (mapped && ioplInfo.fMappedBase) {
	    offset += (ioplInfo.fPageOffset & PAGE_MASK);
	    address = ptoa_64(ioplInfo.fMappedBase) + offset;
	    continue;	// Done leave do/while(false) now
	}

	// The offset is rebased into the current iopl.
	// Now add the iopl 1st page offset.
	offset += ioplInfo.fPageOffset;

	// For external UPLs the fPageInfo field points directly to
	// the upl's upl_page_info_t array.
	if (ioplInfo.fFlags & kIOPLExternUPL)
	    pageList = (upl_page_info_t *) ioplInfo.fPageInfo;
	else
	    pageList = &pageList[ioplInfo.fPageInfo];

	// Check for direct device non-paged memory
	if ( ioplInfo.fFlags & kIOPLOnDevice ) {
	    address = ptoa_64(pageList->phys_addr) + offset;
	    continue;	// Done leave do/while(false) now
	}

	// Now we need compute the index into the pageList
	UInt pageInd = atop_32(offset);
	offset &= PAGE_MASK;

	// Compute the starting address of this segment
	IOPhysicalAddress pageAddr = pageList[pageInd].phys_addr;
	address = ptoa_64(pageAddr) + offset;

	// length is currently set to the length of the remainider of the iopl.
	// We need to check that the remainder of the iopl is contiguous.
	// This is indicated by pageList[ind].phys_addr being sequential.
	IOByteCount contigLength = PAGE_SIZE - offset;
	while (contigLength < length
		&& ++pageAddr == pageList[++pageInd].phys_addr)
	{
	    contigLength += PAGE_SIZE;
	}

	if (contigLength < length)
	    length = contigLength;
	

	assert(address);
	assert(length);

    } while (false);

    // Update return values and state
    isP->fIO.fIOVMAddr = address;
    isP->fIO.fLength   = length;
    isP->fIndex        = ind;
    isP->fOffset2Index = off2Ind;
    isP->fNextOffset   = isP->fIO.fOffset + length;

    return kIOReturnSuccess;
}

addr64_t
IOGeneralMemoryDescriptor::getPhysicalSegment64(IOByteCount offset, IOByteCount *lengthOfSegment)
{
    IOReturn    ret;
    IOByteCount length  = 0;
    addr64_t    address = 0;

    if (offset < _length) // (within bounds?)
    {
	IOMDDMAWalkSegmentState _state;
	IOMDDMAWalkSegmentArgs * state = (IOMDDMAWalkSegmentArgs *) &_state;

	state->fOffset = offset;
	state->fLength = _length - offset;
	state->fMapped = false;

	ret = dmaCommandOperation(kIOMDFirstSegment, _state, sizeof(_state));

	if ((kIOReturnSuccess != ret) && (kIOReturnOverrun != ret))
		DEBG("getPhysicalSegment64 dmaCommandOperation(%lx), %p, offset %qx, addr %qx, len %qx\n", 
					ret, this, state->fOffset,
					state->fIOVMAddr, state->fLength);
	if (kIOReturnSuccess == ret)
	{
	    address = state->fIOVMAddr;
	    length  = state->fLength;
	}
        if (!address)
            length = 0;
    }

    if (lengthOfSegment)
        *lengthOfSegment = length;

    return (address);
}

IOPhysicalAddress
IOGeneralMemoryDescriptor::getPhysicalSegment(IOByteCount offset, IOByteCount *lengthOfSegment)
{
    IOReturn          ret;
    IOByteCount       length  = 0;
    addr64_t	      address = 0;

//  assert(offset <= _length);

    if (offset < _length) // (within bounds?)
    {
	IOMDDMAWalkSegmentState _state;
	IOMDDMAWalkSegmentArgs * state = (IOMDDMAWalkSegmentArgs *) &_state;

	state->fOffset = offset;
	state->fLength = _length - offset;
	state->fMapped = true;

	ret = dmaCommandOperation(
		kIOMDFirstSegment, _state, sizeof(_state));

	if ((kIOReturnSuccess != ret) && (kIOReturnOverrun != ret))
	    DEBG("getPhysicalSegment dmaCommandOperation(%lx), %p, offset %qx, addr %qx, len %qx\n", 
				    ret, this, state->fOffset,
				    state->fIOVMAddr, state->fLength);
	if (kIOReturnSuccess == ret)
	{
	    address = state->fIOVMAddr;
	    length  = state->fLength;
	}

        if (!address)
            length = 0;
    }

    if ((address + length) > 0x100000000ULL)
    {
	panic("getPhysicalSegment() out of 32b range 0x%qx, len 0x%x, class %s",
		    address, length, (getMetaClass())->getClassName());
    }

    if (lengthOfSegment)
        *lengthOfSegment = length;

    return ((IOPhysicalAddress) address);
}

addr64_t
IOMemoryDescriptor::getPhysicalSegment64(IOByteCount offset, IOByteCount *lengthOfSegment)
{
    IOPhysicalAddress phys32;
    IOByteCount	      length;
    addr64_t 	      phys64;
    IOMapper *        mapper = 0;

    phys32 = getPhysicalSegment(offset, lengthOfSegment);
    if (!phys32)
	return 0;

    if (gIOSystemMapper)
	mapper = gIOSystemMapper;

    if (mapper)
    {
	IOByteCount origLen;

	phys64 = mapper->mapAddr(phys32);
	origLen = *lengthOfSegment;
	length = page_size - (phys64 & (page_size - 1));
	while ((length < origLen)
	    && ((phys64 + length) == mapper->mapAddr(phys32 + length)))
	    length += page_size;
	if (length > origLen)
	    length = origLen;

	*lengthOfSegment = length;
    }
    else
	phys64 = (addr64_t) phys32;

    return phys64;
}

IOPhysicalAddress
IOGeneralMemoryDescriptor::getSourceSegment(IOByteCount offset, IOByteCount *lengthOfSegment)
{
    IOPhysicalAddress address = 0;
    IOPhysicalLength  length  = 0;
    IOOptionBits      type    = _flags & kIOMemoryTypeMask;

    assert(offset <= _length);

    if ( type == kIOMemoryTypeUPL)
	return super::getSourceSegment( offset, lengthOfSegment );
    else if ( offset < _length ) // (within bounds?)
    {
        unsigned rangesIndex = 0;
	Ranges vec = _ranges;
	user_addr_t addr;

	// Find starting address within the vector of ranges
	for (;;) {
	    getAddrLenForInd(addr, length, type, vec, rangesIndex);
	    if (offset < length)
		break;
	    offset -= length; // (make offset relative)
	    rangesIndex++;
	} 

	// Now that we have the starting range,
	// lets find the last contiguous range
        addr   += offset;
        length -= offset;

        for ( ++rangesIndex; rangesIndex < _rangesCount; rangesIndex++ ) {
	    user_addr_t      newAddr;
	    IOPhysicalLength newLen;

	    getAddrLenForInd(newAddr, newLen, type, vec, rangesIndex);
	    if (addr + length != newAddr)
		break;
	    length += newLen;
	} 
        if (addr)
	    address = (IOPhysicalAddress) addr;	// Truncate address to 32bit
	else
	    length = 0;
    }

    if ( lengthOfSegment )  *lengthOfSegment = length;

    return address;
}

/* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */
/* DEPRECATED */ void * IOGeneralMemoryDescriptor::getVirtualSegment(IOByteCount offset,
/* DEPRECATED */ 							IOByteCount * lengthOfSegment)
/* DEPRECATED */ {
                    if (_task == kernel_task)
                        return (void *) getSourceSegment(offset, lengthOfSegment);
                    else
                        panic("IOGMD::getVirtualSegment deprecated");

                    return 0;
/* DEPRECATED */ }
/* DEPRECATED */ /* USE INSTEAD: map(), readBytes(), writeBytes() */



IOReturn 
IOMemoryDescriptor::dmaCommandOperation(DMACommandOps op, void *vData, UInt dataSize) const
{
    if (kIOMDGetCharacteristics == op) {
	if (dataSize < sizeof(IOMDDMACharacteristics))
	    return kIOReturnUnderrun;

	IOMDDMACharacteristics *data = (IOMDDMACharacteristics *) vData;
	data->fLength = getLength();
	data->fSGCount = 0;
	data->fDirection = _direction;
	if (IOMapper::gSystem)
	    data->fIsMapped = true;
	data->fIsPrepared = true;	// Assume prepared - fails safe
    }
    else if (kIOMDWalkSegments & op) {
	if (dataSize < sizeof(IOMDDMAWalkSegmentArgs))
	    return kIOReturnUnderrun;

	IOMDDMAWalkSegmentArgs *data = (IOMDDMAWalkSegmentArgs *) vData;
	IOByteCount offset  = (IOByteCount) data->fOffset;

	IOPhysicalLength length;
	IOMemoryDescriptor *ncmd = const_cast<IOMemoryDescriptor *>(this);
	if (data->fMapped && IOMapper::gSystem)
	    data->fIOVMAddr = ncmd->getPhysicalSegment(offset, &length);
	else
	    data->fIOVMAddr = ncmd->getPhysicalSegment64(offset, &length);
	data->fLength = length;
    }
    else
	return kIOReturnBadArgument;

    return kIOReturnSuccess;
}

IOReturn IOMemoryDescriptor::setPurgeable( IOOptionBits newState,
                                           IOOptionBits * oldState )
{
    IOReturn	  err = kIOReturnSuccess;
    vm_purgable_t control;
    int           state;

    do 
    {
        if (!_memEntry)
        {
            err = kIOReturnNotReady;
            break;
        }

        control = VM_PURGABLE_SET_STATE;
        switch (newState)
        {
            case kIOMemoryPurgeableKeepCurrent:
                control = VM_PURGABLE_GET_STATE;
                break;

            case kIOMemoryPurgeableNonVolatile:
                state = VM_PURGABLE_NONVOLATILE;
                break;
            case kIOMemoryPurgeableVolatile:
                state = VM_PURGABLE_VOLATILE;
                break;
            case kIOMemoryPurgeableEmpty:
                state = VM_PURGABLE_EMPTY;
                break;
            default:
                err = kIOReturnBadArgument;
                break;
        }

        if (kIOReturnSuccess != err)
            break;

        err = mach_memory_entry_purgable_control((ipc_port_t) _memEntry, control, &state);

        if (oldState)
        {
            if (kIOReturnSuccess == err)
            {
                switch (state)
                {
                    case VM_PURGABLE_NONVOLATILE:
                        state = kIOMemoryPurgeableNonVolatile;
                        break;
                    case VM_PURGABLE_VOLATILE:
                        state = kIOMemoryPurgeableVolatile;
                        break;
                    case VM_PURGABLE_EMPTY:
                        state = kIOMemoryPurgeableEmpty;
                        break;
                    default:
                        state = kIOMemoryPurgeableNonVolatile;
                        err = kIOReturnNotReady;
                        break;
                }
                *oldState = state;
            }
        }
    }
    while (false);

    return (err);
}

extern "C" void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count);
extern "C" void dcache_incoherent_io_store64(addr64_t pa, unsigned int count);

IOReturn IOMemoryDescriptor::performOperation( IOOptionBits options,
                                                IOByteCount offset, IOByteCount length )
{
    IOByteCount remaining;
    void (*func)(addr64_t pa, unsigned int count) = 0;

    switch (options)
    {
        case kIOMemoryIncoherentIOFlush:
            func = &dcache_incoherent_io_flush64;
            break;
        case kIOMemoryIncoherentIOStore:
            func = &dcache_incoherent_io_store64;
            break;
    }

    if (!func)
        return (kIOReturnUnsupported);

    remaining = length = min(length, getLength() - offset);
    while (remaining)
    // (process another target segment?)
    {
        addr64_t    dstAddr64;
        IOByteCount dstLen;

        dstAddr64 = getPhysicalSegment64(offset, &dstLen);
        if (!dstAddr64)
            break;

        // Clip segment length to remaining
        if (dstLen > remaining)
            dstLen = remaining;

	(*func)(dstAddr64, dstLen);

        offset    += dstLen;
        remaining -= dstLen;
    }

    return (remaining ? kIOReturnUnderrun : kIOReturnSuccess);
}

#ifdef __ppc__
extern vm_offset_t		static_memory_end;
#define io_kernel_static_end	static_memory_end
#else
extern vm_offset_t		first_avail;
#define io_kernel_static_end	first_avail
#endif

static kern_return_t
io_get_kernel_static_upl(
	vm_map_t		/* map */,
	vm_address_t		offset,
	vm_size_t		*upl_size,
	upl_t			*upl,
	upl_page_info_array_t	page_list,
	unsigned int		*count,
	ppnum_t			*highest_page)
{
    unsigned int pageCount, page;
    ppnum_t phys;
    ppnum_t highestPage = 0;

    pageCount = atop_32(*upl_size);
    if (pageCount > *count)
	pageCount = *count;

    *upl = NULL;

    for (page = 0; page < pageCount; page++)
    {
	phys = pmap_find_phys(kernel_pmap, ((addr64_t)offset) + ptoa_64(page));
	if (!phys)
	    break;
	page_list[page].phys_addr = phys;
	page_list[page].pageout	  = 0;
	page_list[page].absent	  = 0;
	page_list[page].dirty	  = 0;
	page_list[page].precious  = 0;
	page_list[page].device	  = 0;
	if (phys > highestPage)
	    highestPage = page;
    }

    *highest_page = highestPage;

    return ((page >= pageCount) ? kIOReturnSuccess : kIOReturnVMError);
}

IOReturn IOGeneralMemoryDescriptor::wireVirtual(IODirection forDirection)
{
    IOOptionBits type = _flags & kIOMemoryTypeMask;
    IOReturn error = kIOReturnNoMemory;
    ioGMDData *dataP;
    ppnum_t mapBase = 0;
    IOMapper *mapper;
    ipc_port_t sharedMem = (ipc_port_t) _memEntry;

    assert(!_wireCount);
    assert(kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type);

    if (_pages >= gIOMaximumMappedIOPageCount)
	return kIOReturnNoResources;

    dataP = getDataP(_memoryEntries);
    mapper = dataP->fMapper;
    if (mapper && _pages)
        mapBase = mapper->iovmAlloc(_pages);

    // Note that appendBytes(NULL) zeros the data up to the
    // desired length.
    _memoryEntries->appendBytes(0, dataP->fPageCnt * sizeof(upl_page_info_t));
    dataP = 0;	// May no longer be valid so lets not get tempted.

    if (forDirection == kIODirectionNone)
        forDirection = _direction;

    int uplFlags;    // This Mem Desc's default flags for upl creation
    switch (kIODirectionOutIn & forDirection)
    {
    case kIODirectionOut:
        // Pages do not need to be marked as dirty on commit
        uplFlags = UPL_COPYOUT_FROM;
        _flags |= kIOMemoryPreparedReadOnly;
        break;

    case kIODirectionIn:
    default:
        uplFlags = 0;	// i.e. ~UPL_COPYOUT_FROM
        break;
    }
    uplFlags |= UPL_SET_IO_WIRE | UPL_SET_LITE;

#ifdef UPL_NEED_32BIT_ADDR
    if (kIODirectionPrepareToPhys32 & forDirection) 
	uplFlags |= UPL_NEED_32BIT_ADDR;
#endif

    // Find the appropriate vm_map for the given task
    vm_map_t curMap;
    if (_task == kernel_task && (kIOMemoryBufferPageable & _flags))
        curMap = 0;
    else
        { curMap = get_task_map(_task); }

    // Iterate over the vector of virtual ranges
    Ranges vec = _ranges;
    unsigned int pageIndex = 0;
    IOByteCount mdOffset = 0;
    ppnum_t highestPage = 0;
    for (UInt range = 0; range < _rangesCount; range++) {
        ioPLBlock iopl;
	user_addr_t startPage;
        IOByteCount numBytes;
	ppnum_t highPage = 0;

	// Get the startPage address and length of vec[range]
	getAddrLenForInd(startPage, numBytes, type, vec, range);
	iopl.fPageOffset = (short) startPage & PAGE_MASK;
	numBytes += iopl.fPageOffset;
	startPage = trunc_page_64(startPage);

	if (mapper)
	    iopl.fMappedBase = mapBase + pageIndex;
	else
	    iopl.fMappedBase = 0;

	// Iterate over the current range, creating UPLs
        while (numBytes) {
            dataP = getDataP(_memoryEntries);
	    vm_address_t kernelStart = (vm_address_t) startPage;
            vm_map_t theMap;
	    if (curMap)
		theMap = curMap;
	    else if (!sharedMem) {
		assert(_task == kernel_task);
		theMap = IOPageableMapForAddress(kernelStart);
	    }
	    else
		theMap = NULL;

            upl_page_info_array_t pageInfo = getPageList(dataP);
            int ioplFlags = uplFlags;
            upl_page_list_ptr_t baseInfo = &pageInfo[pageIndex];

            vm_size_t ioplSize = round_page_32(numBytes);
            unsigned int numPageInfo = atop_32(ioplSize);

	    if (theMap == kernel_map && kernelStart < io_kernel_static_end) {
		error = io_get_kernel_static_upl(theMap, 
						kernelStart,
						&ioplSize,
						&iopl.fIOPL,
						baseInfo,
						&numPageInfo,
						&highPage);
	    }
	    else if (sharedMem) {
		error = memory_object_iopl_request(sharedMem, 
						ptoa_32(pageIndex),
						&ioplSize,
						&iopl.fIOPL,
						baseInfo,
						&numPageInfo,
						&ioplFlags);
	    }
	    else {
		assert(theMap);
		error = vm_map_create_upl(theMap,
						startPage,
						&ioplSize,
						&iopl.fIOPL,
						baseInfo,
						&numPageInfo,
						&ioplFlags);
	    }

            assert(ioplSize);
            if (error != KERN_SUCCESS)
                goto abortExit;

	    if (iopl.fIOPL)
		highPage = upl_get_highest_page(iopl.fIOPL);
	    if (highPage > highestPage)
		highestPage = highPage;

            error = kIOReturnNoMemory;

            if (baseInfo->device) {
                numPageInfo = 1;
                iopl.fFlags  = kIOPLOnDevice;
                // Don't translate device memory at all 
		if (mapper && mapBase) {
		    mapper->iovmFree(mapBase, _pages);
		    mapBase = 0;
		    iopl.fMappedBase = 0;
		}
            }
            else {
                iopl.fFlags = 0;
		if (mapper)
                    mapper->iovmInsert(mapBase, pageIndex,
                                       baseInfo, numPageInfo);
            }

            iopl.fIOMDOffset = mdOffset;
            iopl.fPageInfo = pageIndex;

	    if ((_flags & kIOMemoryAutoPrepare) && iopl.fIOPL)
	    {
		upl_commit(iopl.fIOPL, 0, 0);
		upl_deallocate(iopl.fIOPL);
		iopl.fIOPL = 0;
	    }

            if (!_memoryEntries->appendBytes(&iopl, sizeof(iopl))) {
                // Clean up partial created and unsaved iopl
                if (iopl.fIOPL) {
                    upl_abort(iopl.fIOPL, 0);
                    upl_deallocate(iopl.fIOPL);
                }
                goto abortExit;
            }

            // Check for a multiple iopl's in one virtual range
            pageIndex += numPageInfo;
            mdOffset -= iopl.fPageOffset;
            if (ioplSize < numBytes) {
                numBytes -= ioplSize;
                startPage += ioplSize;
                mdOffset += ioplSize;
                iopl.fPageOffset = 0;
		if (mapper)
		    iopl.fMappedBase = mapBase + pageIndex;
            }
            else {
                mdOffset += numBytes;
                break;
            }
        }
    }

    _highestPage = highestPage;

    return kIOReturnSuccess;

abortExit:
    {
        dataP = getDataP(_memoryEntries);
        UInt done = getNumIOPL(_memoryEntries, dataP);
        ioPLBlock *ioplList = getIOPLList(dataP);
    
        for (UInt range = 0; range < done; range++)
	{
	    if (ioplList[range].fIOPL) {
             upl_abort(ioplList[range].fIOPL, 0);
             upl_deallocate(ioplList[range].fIOPL);
	    }
	}
	(void) _memoryEntries->initWithBytes(dataP, sizeof(ioGMDData)); // == setLength()

        if (mapper && mapBase)
            mapper->iovmFree(mapBase, _pages);
    }

    return error;
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
IOReturn IOGeneralMemoryDescriptor::prepare(IODirection forDirection)
{
    IOReturn error    = kIOReturnSuccess;
    IOOptionBits type = _flags & kIOMemoryTypeMask;

    if (!_wireCount
    && (kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type) ) {
        error = wireVirtual(forDirection);
        if (error)
            return error;
    }

    _wireCount++;

    return kIOReturnSuccess;
}

/*
 * complete
 *
 * Complete processing of the memory after an I/O transfer finishes.
 * This method should not be called unless a prepare was previously
 * issued; the prepare() and complete() must occur in pairs, before
 * before and after an I/O transfer involving pageable memory.
 */
 
IOReturn IOGeneralMemoryDescriptor::complete(IODirection /* forDirection */)
{
    assert(_wireCount);

    if (!_wireCount)
        return kIOReturnSuccess;

    _wireCount--;
    if (!_wireCount) {
	IOOptionBits type = _flags & kIOMemoryTypeMask;

        if ((kIOMemoryTypePhysical == type) || (kIOMemoryTypePhysical64 == type)) {
            /* kIOMemoryTypePhysical */
            // DO NOTHING
        }
        else {
            ioGMDData * dataP = getDataP(_memoryEntries);
            ioPLBlock *ioplList = getIOPLList(dataP);
	    UInt count = getNumIOPL(_memoryEntries, dataP);

            if (dataP->fMapper && _pages && ioplList[0].fMappedBase)
                dataP->fMapper->iovmFree(ioplList[0].fMappedBase, _pages);

            // Only complete iopls that we created which are for TypeVirtual
            if (kIOMemoryTypeVirtual == type || kIOMemoryTypeVirtual64 == type || kIOMemoryTypeUIO == type) {
                for (UInt ind = 0; ind < count; ind++)
		    if (ioplList[ind].fIOPL) {
			 upl_commit(ioplList[ind].fIOPL, 0, 0);
			 upl_deallocate(ioplList[ind].fIOPL);
		    }
            }

            (void) _memoryEntries->initWithBytes(dataP, sizeof(ioGMDData)); // == setLength()
        }
    }
    return kIOReturnSuccess;
}

IOReturn IOGeneralMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset,
	IOByteCount		length )
{
    kern_return_t kr;
    ipc_port_t sharedMem = (ipc_port_t) _memEntry;

    IOOptionBits type = _flags & kIOMemoryTypeMask;
    Ranges vec = _ranges;

    user_addr_t range0Addr = 0;
    IOByteCount range0Len = 0;

    if (vec.v)
	getAddrLenForInd(range0Addr, range0Len, type, vec, 0);

    // mapping source == dest? (could be much better)
    if( _task
    && (addressMap == get_task_map(_task)) && (options & kIOMapAnywhere)
    && (1 == _rangesCount) && (0 == sourceOffset)
    && range0Addr && (length <= range0Len) ) {
	if (sizeof(user_addr_t) > 4 && ((UInt64) range0Addr) >> 32)
	    return kIOReturnOverrun;	// Doesn't fit in 32bit return field
	else {
	    *atAddress = range0Addr;
	    return( kIOReturnSuccess );
	}
    }

    if( 0 == sharedMem) {

        vm_size_t size = ptoa_32(_pages);

        if( _task) {

            memory_object_size_t actualSize = size;
            kr = mach_make_memory_entry_64(get_task_map(_task),
                        &actualSize, range0Addr,
                        VM_PROT_READ | VM_PROT_WRITE, &sharedMem,
                        NULL );

            if( (KERN_SUCCESS == kr) && (actualSize != round_page_32(size))) {
#if IOASSERT
                IOLog("mach_make_memory_entry_64 (%08llx) size (%08lx:%08x)\n",
                            range0Addr, (UInt32) actualSize, size);
#endif
                kr = kIOReturnVMError;
                ipc_port_release_send( sharedMem );
            }

            if( KERN_SUCCESS != kr)
                sharedMem = MACH_PORT_NULL;

        } else do {	// _task == 0, must be physical

            memory_object_t 	pager;
	    unsigned int    	flags = 0;
    	    addr64_t		pa;
    	    IOPhysicalLength	segLen;

	    pa = getPhysicalSegment64( sourceOffset, &segLen );

            if( !reserved) {
                reserved = IONew( ExpansionData, 1 );
                if( !reserved)
                    continue;
            }
            reserved->pagerContig = (1 == _rangesCount);
	    reserved->memory = this;

	    /*What cache mode do we need*/
            switch(options & kIOMapCacheMask ) {

		case kIOMapDefaultCache:
		default:
		    flags = IODefaultCacheBits(pa);
		    break;
	
		case kIOMapInhibitCache:
		    flags = DEVICE_PAGER_CACHE_INHIB | 
				    DEVICE_PAGER_COHERENT | DEVICE_PAGER_GUARDED;
		    break;
	
		case kIOMapWriteThruCache:
		    flags = DEVICE_PAGER_WRITE_THROUGH |
				    DEVICE_PAGER_COHERENT | DEVICE_PAGER_GUARDED;
		    break;

		case kIOMapCopybackCache:
		    flags = DEVICE_PAGER_COHERENT;
		    break;

		case kIOMapWriteCombineCache:
		    flags = DEVICE_PAGER_CACHE_INHIB |
				    DEVICE_PAGER_COHERENT;
		    break;
            }

	    flags |= reserved->pagerContig ? DEVICE_PAGER_CONTIGUOUS : 0;

            pager = device_pager_setup( (memory_object_t) 0, (int) reserved, 
								size, flags);
            assert( pager );

            if( pager) {
                kr = mach_memory_object_memory_entry_64( (host_t) 1, false /*internal*/, 
                            size, VM_PROT_READ | VM_PROT_WRITE, pager, &sharedMem );

                assert( KERN_SUCCESS == kr );
                if( KERN_SUCCESS != kr) {
		    device_pager_deallocate( pager );
                    pager = MACH_PORT_NULL;
                    sharedMem = MACH_PORT_NULL;
                }
            }
	    if( pager && sharedMem)
		reserved->devicePager    = pager;
	    else {
		IODelete( reserved, ExpansionData, 1 );
		reserved = 0;
	    }

        } while( false );

        _memEntry = (void *) sharedMem;
    }


    if( 0 == sharedMem)
      kr = kIOReturnVMError;
    else
      kr = super::doMap( addressMap, atAddress,
                           options, sourceOffset, length );

    return( kr );
}

IOReturn IOGeneralMemoryDescriptor::doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length )
{
    // could be much better
    if( _task && (addressMap == get_task_map(_task)) && (1 == _rangesCount)) {

	IOOptionBits type = _flags & kIOMemoryTypeMask;
	user_addr_t range0Addr;
	IOByteCount range0Len;

	getAddrLenForInd(range0Addr, range0Len, type, _ranges, 0);
	if (logical == range0Addr && length <= range0Len)
	    return( kIOReturnSuccess );
    }

    return( super::doUnmap( addressMap, logical, length ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndAbstractStructors( IOMemoryMap, OSObject )

/* inline function implementation */
IOPhysicalAddress IOMemoryMap::getPhysicalAddress()
    { return( getPhysicalSegment( 0, 0 )); }


#undef super
#define super IOMemoryMap

OSDefineMetaClassAndStructors(_IOMemoryMap, IOMemoryMap)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool _IOMemoryMap::initCompatible(
	IOMemoryDescriptor *	_memory,
	IOMemoryMap *		_superMap,
        IOByteCount		_offset,
        IOByteCount		_length )
{

    if( !super::init())
	return( false);

    if( (_offset + _length) > _superMap->getLength())
	return( false);

    _memory->retain();
    memory	= _memory;
    _superMap->retain();
    superMap 	= _superMap;

    offset	= _offset;
    if( _length)
        length	= _length;
    else
        length	= _memory->getLength();

    options	= superMap->getMapOptions();
    logical	= superMap->getVirtualAddress() + offset;

    return( true );
}

bool _IOMemoryMap::initWithDescriptor(
        IOMemoryDescriptor *	_memory,
        task_t			intoTask,
        IOVirtualAddress	toAddress,
        IOOptionBits		_options,
        IOByteCount		_offset,
        IOByteCount		_length )
{
    bool ok;
    bool redir = ((kIOMapUnique|kIOMapReference) == ((kIOMapUnique|kIOMapReference) & _options));

    if ((!_memory) || (!intoTask))
	return( false);

    if( (_offset + _length) > _memory->getLength())
	return( false);

    if (!redir)
    {
	if (!super::init())
	    return(false);
	addressMap  = get_task_map(intoTask);
	if( !addressMap)
	    return( false);
	vm_map_reference(addressMap);
	addressTask = intoTask;
	logical	    = toAddress;
	options     = _options;
    }

    _memory->retain();

    offset	= _offset;
    if( _length)
        length	= _length;
    else
        length	= _memory->getLength();

    if( options & kIOMapStatic)
	ok = true;
    else
	ok = (kIOReturnSuccess == _memory->doMap( addressMap, &toAddress,
						  _options, offset, length ));
    if (ok || redir)
    {
	if (memory)
	    memory->release();
	memory	= _memory;
	logical = toAddress;
    }
    else
    {
        _memory->release();
	if (!redir)
	{
	    logical = 0;
	    memory = 0;
	    vm_map_deallocate(addressMap);
	    addressMap = 0;
	}
    }

    return( ok );
}

/* LP64todo - these need to expand */
struct IOMemoryDescriptorMapAllocRef
{
    ipc_port_t		sharedMem;
    vm_size_t		size;
    vm_offset_t		mapped;
    IOByteCount		sourceOffset;
    IOOptionBits	options;
};

static kern_return_t IOMemoryDescriptorMapAlloc(vm_map_t map, void * _ref)
{
    IOMemoryDescriptorMapAllocRef * ref = (IOMemoryDescriptorMapAllocRef *)_ref;
    IOReturn			    err;

    do {
        if( ref->sharedMem) {
            vm_prot_t prot = VM_PROT_READ
                            | ((ref->options & kIOMapReadOnly) ? 0 : VM_PROT_WRITE);

            // set memory entry cache
            vm_prot_t memEntryCacheMode = prot | MAP_MEM_ONLY;
            switch (ref->options & kIOMapCacheMask)
            {
		case kIOMapInhibitCache:
                    SET_MAP_MEM(MAP_MEM_IO, memEntryCacheMode);
                    break;
	
		case kIOMapWriteThruCache:
                    SET_MAP_MEM(MAP_MEM_WTHRU, memEntryCacheMode);
                    break;

		case kIOMapWriteCombineCache:
                    SET_MAP_MEM(MAP_MEM_WCOMB, memEntryCacheMode);
                    break;

		case kIOMapCopybackCache:
                    SET_MAP_MEM(MAP_MEM_COPYBACK, memEntryCacheMode);
                    break;

		case kIOMapDefaultCache:
		default:
                    SET_MAP_MEM(MAP_MEM_NOOP, memEntryCacheMode);
                    break;
            }

            vm_size_t unused = 0;

            err = mach_make_memory_entry( NULL /*unused*/, &unused, 0 /*unused*/, 
                                            memEntryCacheMode, NULL, ref->sharedMem );
            if (KERN_SUCCESS != err)
                IOLog("MAP_MEM_ONLY failed %d\n", err);

            err = vm_map( map,
                            &ref->mapped,
                            ref->size, 0 /* mask */, 
                            (( ref->options & kIOMapAnywhere ) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                            | VM_MAKE_TAG(VM_MEMORY_IOKIT), 
                            ref->sharedMem, ref->sourceOffset,
                            false, // copy
                            prot, // cur
                            prot, // max
                            VM_INHERIT_NONE);

            if( KERN_SUCCESS != err) {
                ref->mapped = 0;
                continue;
            }
    
        } else {
    
            err = vm_allocate( map, &ref->mapped, ref->size,
                            ((ref->options & kIOMapAnywhere) ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED)
                            | VM_MAKE_TAG(VM_MEMORY_IOKIT) );
    
            if( KERN_SUCCESS != err) {
                ref->mapped = 0;
                continue;
            }
    
            // we have to make sure that these guys don't get copied if we fork.
            err = vm_inherit( map, ref->mapped, ref->size, VM_INHERIT_NONE);
            assert( KERN_SUCCESS == err );
        }

    } while( false );

    return( err );
}


IOReturn IOMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset,
	IOByteCount		length )
{
    IOReturn		err = kIOReturnSuccess;
    memory_object_t	pager;
    vm_address_t	logical;
    IOByteCount		pageOffset;
    IOPhysicalAddress	sourceAddr;
    IOMemoryDescriptorMapAllocRef	ref;

    ref.sharedMem	= (ipc_port_t) _memEntry;
    ref.sourceOffset	= sourceOffset;
    ref.options		= options;

    do {

        if( 0 == length)
            length = getLength();

	sourceAddr = getSourceSegment( sourceOffset, NULL );
	pageOffset = sourceAddr - trunc_page_32( sourceAddr );

	ref.size = round_page_32( length + pageOffset );

	if ((kIOMapReference|kIOMapUnique) == ((kIOMapReference|kIOMapUnique) & options))
	{
	    upl_t	  redirUPL2;
	    vm_size_t	  size;
	    int		  flags;

	    _IOMemoryMap * mapping = (_IOMemoryMap *) *atAddress;
	    ref.mapped = mapping->getVirtualAddress();
    
	    if (!_memEntry)
	    {
		err = kIOReturnNotReadable;
		continue;
	    }

	    size = length;
	    flags = UPL_COPYOUT_FROM | UPL_SET_INTERNAL 
			| UPL_SET_LITE | UPL_SET_IO_WIRE | UPL_BLOCK_ACCESS;

	    if (KERN_SUCCESS != memory_object_iopl_request((ipc_port_t) _memEntry, 0, &size, &redirUPL2,
					    NULL, NULL,
					    &flags))
		redirUPL2 = NULL;

	    err = upl_transpose(redirUPL2, mapping->redirUPL);
	    if (kIOReturnSuccess != err)
	    {
		IOLog("upl_transpose(%x)\n", err);
		err = kIOReturnSuccess;
	    }

	    if (redirUPL2)
	    {
		upl_commit(redirUPL2, NULL, 0);
		upl_deallocate(redirUPL2);
		redirUPL2 = 0;
	    }
	    {
		// swap the memEntries since they now refer to different vm_objects
		void * me = _memEntry;
		_memEntry = mapping->memory->_memEntry;
		mapping->memory->_memEntry = me;
	    }
	}
	else
	{
    
	    logical = *atAddress;
	    if( options & kIOMapAnywhere) 
		// vm_map looks for addresses above here, even when VM_FLAGS_ANYWHERE
		ref.mapped = 0;
	    else {
		ref.mapped = trunc_page_32( logical );
		if( (logical - ref.mapped) != pageOffset) {
		    err = kIOReturnVMError;
		    continue;
		}
	    }
    
	    if( ref.sharedMem && (addressMap == kernel_map) && (kIOMemoryBufferPageable & _flags))
		err = IOIteratePageableMaps( ref.size, &IOMemoryDescriptorMapAlloc, &ref );
	    else
		err = IOMemoryDescriptorMapAlloc( addressMap, &ref );
	}

        if( err != KERN_SUCCESS)
            continue;

        if( reserved)
            pager = (memory_object_t) reserved->devicePager;
        else
            pager = MACH_PORT_NULL;

        if( !ref.sharedMem || pager )
            err = handleFault( pager, addressMap, ref.mapped, sourceOffset, length, options );

    } while( false );

    if( err != KERN_SUCCESS) {
        if( ref.mapped)
            doUnmap( addressMap, ref.mapped, ref.size );
        *atAddress = NULL;
    } else
        *atAddress = ref.mapped + pageOffset;

    return( err );
}

enum {
    kIOMemoryRedirected	= 0x00010000
};

IOReturn IOMemoryDescriptor::handleFault(
        void *			_pager,
	vm_map_t		addressMap,
	IOVirtualAddress	address,
	IOByteCount		sourceOffset,
	IOByteCount		length,
        IOOptionBits		options )
{
    IOReturn		err = kIOReturnSuccess;
    memory_object_t	pager = (memory_object_t) _pager;
    vm_size_t		size;
    vm_size_t		bytes;
    vm_size_t		page;
    IOByteCount		pageOffset;
    IOByteCount		pagerOffset;
    IOPhysicalLength	segLen;
    addr64_t		physAddr;

    if( !addressMap) {

        if( kIOMemoryRedirected & _flags) {
#ifdef DEBUG
            IOLog("sleep mem redirect %p, %lx\n", this, sourceOffset);
#endif
            do {
	    	SLEEP;
            } while( kIOMemoryRedirected & _flags );
        }

        return( kIOReturnSuccess );
    }

    physAddr = getPhysicalSegment64( sourceOffset, &segLen );
    assert( physAddr );
    pageOffset = physAddr - trunc_page_64( physAddr );
    pagerOffset = sourceOffset;

    size = length + pageOffset;
    physAddr -= pageOffset;

    segLen += pageOffset;
    bytes = size;
    do {
	// in the middle of the loop only map whole pages
	if( segLen >= bytes)
	    segLen = bytes;
	else if( segLen != trunc_page_32( segLen))
	    err = kIOReturnVMError;
        if( physAddr != trunc_page_64( physAddr))
	    err = kIOReturnBadArgument;

#ifdef DEBUG
	if( kIOLogMapping & gIOKitDebug)
	    IOLog("_IOMemoryMap::map(%p) %08lx->%08qx:%08lx\n",
                addressMap, address + pageOffset, physAddr + pageOffset,
		segLen - pageOffset);
#endif

        if( pager) {
            if( reserved && reserved->pagerContig) {
                IOPhysicalLength	allLen;
                addr64_t		allPhys;

                allPhys = getPhysicalSegment64( 0, &allLen );
                assert( allPhys );
                err = device_pager_populate_object( pager, 0, allPhys >> PAGE_SHIFT, round_page_32(allLen) );

            } else {

	    for( page = 0;
                     (page < segLen) && (KERN_SUCCESS == err);
                     page += page_size) {
                        err = device_pager_populate_object(pager, pagerOffset,
                        	(ppnum_t)((physAddr + page) >> PAGE_SHIFT), page_size);
			pagerOffset += page_size;
                }
            }
            assert( KERN_SUCCESS == err );
            if( err)
                break;
        }

	/*  *** ALERT *** */
	/*  *** Temporary Workaround *** */

	/* This call to vm_fault causes an early pmap level resolution	*/
	/* of the mappings created above.  Need for this is in absolute	*/
	/* violation of the basic tenet that the pmap layer is a cache.	*/
	/* Further, it implies a serious I/O architectural violation on	*/
	/* the part of some user of the mapping.  As of this writing, 	*/
	/* the call to vm_fault is needed because the NVIDIA driver 	*/
	/* makes a call to pmap_extract.  The NVIDIA driver needs to be	*/
	/* fixed as soon as possible.  The NVIDIA driver should not 	*/
	/* need to query for this info as it should know from the doMap	*/
	/* call where the physical memory is mapped.  When a query is 	*/
	/* necessary to find a physical mapping, it should be done 	*/
	/* through an iokit call which includes the mapped memory 	*/
	/* handle.  This is required for machine architecture independence.*/

	if(!(kIOMemoryRedirected & _flags)) {
		vm_fault(addressMap, 
			 (vm_map_offset_t)address, 
			 VM_PROT_READ|VM_PROT_WRITE, 
			 FALSE, THREAD_UNINT, NULL, 
			 (vm_map_offset_t)0);
	}

	/*  *** Temporary Workaround *** */
	/*  *** ALERT *** */

	sourceOffset += segLen - pageOffset;
	address += segLen;
	bytes -= segLen;
	pageOffset = 0;

    } while( bytes
	&& (physAddr = getPhysicalSegment64( sourceOffset, &segLen )));

    if( bytes)
        err = kIOReturnBadArgument;

    return( err );
}

IOReturn IOMemoryDescriptor::doUnmap(
	vm_map_t		addressMap,
	IOVirtualAddress	logical,
	IOByteCount		length )
{
    IOReturn	err;

#ifdef DEBUG
    if( kIOLogMapping & gIOKitDebug)
	kprintf("IOMemoryDescriptor::doUnmap(%x) %08x:%08x\n",
                addressMap, logical, length );
#endif

    if( true /* && (addressMap == kernel_map) || (addressMap == get_task_map(current_task()))*/) {

        if( _memEntry && (addressMap == kernel_map) && (kIOMemoryBufferPageable & _flags))
            addressMap = IOPageableMapForAddress( logical );

        err = vm_deallocate( addressMap, logical, length );

    } else
        err = kIOReturnSuccess;

    return( err );
}

IOReturn IOMemoryDescriptor::redirect( task_t safeTask, bool doRedirect )
{
    IOReturn		err = kIOReturnSuccess;
    _IOMemoryMap *	mapping = 0;
    OSIterator *	iter;

    LOCK;

    if( doRedirect)
        _flags |= kIOMemoryRedirected;
    else
        _flags &= ~kIOMemoryRedirected;

    do {
	if( (iter = OSCollectionIterator::withCollection( _mappings))) {
	    while( (mapping = (_IOMemoryMap *) iter->getNextObject()))
		mapping->redirect( safeTask, doRedirect );

	    iter->release();
	}
    } while( false );

    if (!doRedirect)
    {
        WAKEUP;
    }

    UNLOCK;

    // temporary binary compatibility
    IOSubMemoryDescriptor * subMem;
    if( (subMem = OSDynamicCast( IOSubMemoryDescriptor, this)))
	err = subMem->redirect( safeTask, doRedirect );
    else
	err = kIOReturnSuccess;

    return( err );
}

IOReturn IOSubMemoryDescriptor::redirect( task_t safeTask, bool doRedirect )
{
    return( _parent->redirect( safeTask, doRedirect ));
}

IOReturn _IOMemoryMap::redirect( task_t safeTask, bool doRedirect )
{
    IOReturn err = kIOReturnSuccess;

    if( superMap) {
//        err = ((_IOMemoryMap *)superMap)->redirect( safeTask, doRedirect );
    } else {

        LOCK;

	do
	{
	    if (!logical)
		break;
	    if (!addressMap)
		break;

	    if ((!safeTask || (get_task_map(safeTask) != addressMap))
	      && (0 == (options & kIOMapStatic)))
	    {
		IOUnmapPages( addressMap, logical, length );
		if(!doRedirect && safeTask
		 && (((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical) 
		    || ((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64)))
		 {
		    err = vm_deallocate( addressMap, logical, length );
		    err = memory->doMap( addressMap, &logical,
					 (options & ~kIOMapAnywhere) /*| kIOMapReserve*/,
					 offset, length );
		} else
		    err = kIOReturnSuccess;
#ifdef DEBUG
		IOLog("IOMemoryMap::redirect(%d, %p) %x:%lx from %p\n", doRedirect, this, logical, length, addressMap);
#endif
	    }
	    else if (kIOMapWriteCombineCache == (options & kIOMapCacheMask))
	    {
		IOOptionBits newMode;
		newMode = (options & ~kIOMapCacheMask) | (doRedirect ? kIOMapInhibitCache : kIOMapWriteCombineCache);
		IOProtectCacheMode(addressMap, logical, length, newMode);
	    }
	}
	while (false);

	UNLOCK;
    }

    if ((((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
	 || ((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64))
     && safeTask
     && (doRedirect != (0 != (memory->_flags & kIOMemoryRedirected))))
	memory->redirect(safeTask, doRedirect);

    return( err );
}

IOReturn _IOMemoryMap::unmap( void )
{
    IOReturn	err;

    LOCK;

    if( logical && addressMap && (0 == superMap)
	&& (0 == (options & kIOMapStatic))) {

        err = memory->doUnmap( addressMap, logical, length );
        vm_map_deallocate(addressMap);
        addressMap = 0;

    } else
	err = kIOReturnSuccess;

    logical = 0;

    UNLOCK;

    return( err );
}

void _IOMemoryMap::taskDied( void )
{
    LOCK;
    if( addressMap) {
        vm_map_deallocate(addressMap);
        addressMap = 0;
    }
    addressTask	= 0;
    logical	= 0;
    UNLOCK;
}

// Overload the release mechanism.  All mappings must be a member
// of a memory descriptors _mappings set.  This means that we
// always have 2 references on a mapping.  When either of these mappings
// are released we need to free ourselves.
void _IOMemoryMap::taggedRelease(const void *tag) const
{
    LOCK;
    super::taggedRelease(tag, 2);
    UNLOCK;
}

void _IOMemoryMap::free()
{
    unmap();

    if( memory) {
        LOCK;
	memory->removeMapping( this);
	UNLOCK;
	memory->release();
    }

    if (owner && (owner != memory))
    {
        LOCK;
	owner->removeMapping(this);
	UNLOCK;
    }

    if( superMap)
	superMap->release();

    if (redirUPL) {
	upl_commit(redirUPL, NULL, 0);
	upl_deallocate(redirUPL);
    }

    super::free();
}

IOByteCount _IOMemoryMap::getLength()
{
    return( length );
}

IOVirtualAddress _IOMemoryMap::getVirtualAddress()
{
    return( logical);
}

task_t _IOMemoryMap::getAddressTask()
{
    if( superMap)
	return( superMap->getAddressTask());
    else
        return( addressTask);
}

IOOptionBits _IOMemoryMap::getMapOptions()
{
    return( options);
}

IOMemoryDescriptor * _IOMemoryMap::getMemoryDescriptor()
{
    return( memory );
}

_IOMemoryMap * _IOMemoryMap::copyCompatible(
		IOMemoryDescriptor *	owner,
                task_t			task,
                IOVirtualAddress	toAddress,
                IOOptionBits		_options,
                IOByteCount		_offset,
                IOByteCount		_length )
{
    _IOMemoryMap * mapping;

    if( (!task) || (!addressMap) || (addressMap != get_task_map(task)))
	return( 0 );
    if( options & kIOMapUnique)
	return( 0 );
    if( (options ^ _options) & kIOMapReadOnly)
	return( 0 );
    if( (kIOMapDefaultCache != (_options & kIOMapCacheMask)) 
     && ((options ^ _options) & kIOMapCacheMask))
	return( 0 );

    if( (0 == (_options & kIOMapAnywhere)) && (logical != toAddress))
	return( 0 );

    if( _offset < offset)
	return( 0 );

    _offset -= offset;

    if( (_offset + _length) > length)
	return( 0 );

    if( (length == _length) && (!_offset)) {
        retain();
	mapping = this;

    } else {
        mapping = new _IOMemoryMap;
        if( mapping
        && !mapping->initCompatible( owner, this, _offset, _length )) {
            mapping->release();
            mapping = 0;
        }
    }

    return( mapping );
}

IOPhysicalAddress 
_IOMemoryMap::getPhysicalSegment( IOByteCount _offset, IOPhysicalLength * _length)
{
    IOPhysicalAddress	address;

    LOCK;
    address = memory->getPhysicalSegment( offset + _offset, _length );
    UNLOCK;

    return( address );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSObject

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOMemoryDescriptor::initialize( void )
{
    if( 0 == gIOMemoryLock)
	gIOMemoryLock = IORecursiveLockAlloc();

    IORegistryEntry::getRegistryRoot()->setProperty(kIOMaximumMappedIOByteCountKey,
						    ptoa_64(gIOMaximumMappedIOPageCount), 64);
    if (!gIOCopyMapper)
    {
    	IOMapper *
	mapper = new IOCopyMapper;
	if (mapper)
	{
	    if (mapper->init() && mapper->start(NULL))
		gIOCopyMapper = (IOCopyMapper *) mapper;
	    else
		mapper->release();
	}
    }

    gIOLastPage = IOGetLastPageNumber();
}

void IOMemoryDescriptor::free( void )
{
    if( _mappings)
	_mappings->release();

    super::free();
}

IOMemoryMap * IOMemoryDescriptor::setMapping(
	task_t			intoTask,
	IOVirtualAddress	mapAddress,
	IOOptionBits		options )
{
    _IOMemoryMap *		newMap;

    newMap = new _IOMemoryMap;

    LOCK;

    if( newMap
     && !newMap->initWithDescriptor( this, intoTask, mapAddress,
                    options | kIOMapStatic, 0, getLength() )) {
	newMap->release();
	newMap = 0;
    }

    addMapping( newMap);

    UNLOCK;

    return( newMap);
}

IOMemoryMap * IOMemoryDescriptor::map( 
	IOOptionBits		options )
{

    return( makeMapping( this, kernel_task, 0,
			options | kIOMapAnywhere,
			0, getLength() ));
}

IOMemoryMap * IOMemoryDescriptor::map(
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length )
{
    if( 0 == length)
	length = getLength();

    return( makeMapping( this, intoTask, toAddress, options, offset, length ));
}

IOReturn _IOMemoryMap::redirect(IOMemoryDescriptor * newBackingMemory,
			        IOOptionBits         options,
			        IOByteCount          offset)
{
    IOReturn err = kIOReturnSuccess;
    IOMemoryDescriptor * physMem = 0;

    LOCK;

    if (logical && addressMap) do 
    {
	if (((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
	    || ((memory->_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64))
	{
	    physMem = memory;
	    physMem->retain();
	}

	if (!redirUPL)
	{
	    vm_size_t size = length;
	    int flags = UPL_COPYOUT_FROM | UPL_SET_INTERNAL 
			| UPL_SET_LITE | UPL_SET_IO_WIRE | UPL_BLOCK_ACCESS;
	    if (KERN_SUCCESS != memory_object_iopl_request((ipc_port_t) memory->_memEntry, 0, &size, &redirUPL,
					    NULL, NULL,
					    &flags))
		redirUPL = 0;

	    if (physMem)
	    {
		IOUnmapPages( addressMap, logical, length );
		physMem->redirect(0, true);
	    }
	}

	if (newBackingMemory)
	{
	    if (newBackingMemory != memory)
	    {
		if (this != newBackingMemory->makeMapping(newBackingMemory, addressTask, (IOVirtualAddress) this, 
							    options | kIOMapUnique | kIOMapReference,
							    offset, length))
		    err = kIOReturnError;
	    }
	    if (redirUPL)
	    {
		upl_commit(redirUPL, NULL, 0);
		upl_deallocate(redirUPL);
		redirUPL = 0;
	    }
	    if (physMem)
		physMem->redirect(0, false);
	}
    }
    while (false);

    UNLOCK;

    if (physMem)
	physMem->release();

    return (err);
}

IOMemoryMap * IOMemoryDescriptor::makeMapping(
	IOMemoryDescriptor *	owner,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length )
{
    IOMemoryDescriptor * mapDesc = 0;
    _IOMemoryMap *	mapping = 0;
    OSIterator *	iter;

    LOCK;

    do
    {
	if (kIOMapUnique & options)
	{
	    IOPhysicalAddress phys;
	    IOByteCount       physLen;

	    if (owner != this)
		continue;

	    if (((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical)
		|| ((_flags & kIOMemoryTypeMask) == kIOMemoryTypePhysical64))
	    {
		phys = getPhysicalSegment(offset, &physLen);
		if (!phys || (physLen < length))
		    continue;
    
		mapDesc = IOMemoryDescriptor::withPhysicalAddress(
				phys, length, _direction);
		if (!mapDesc)
		    continue;
		offset = 0;
	    }
	    else
	    {
		mapDesc = this;
		mapDesc->retain();
	    }

	    if (kIOMapReference & options)
	    {
		mapping = (_IOMemoryMap *) toAddress;
		mapping->retain();

#if 1
		uint32_t pageOffset1 = mapDesc->getSourceSegment( offset, NULL );
		pageOffset1 -= trunc_page_32( pageOffset1 );

		uint32_t pageOffset2 = mapping->getVirtualAddress();
		pageOffset2 -= trunc_page_32( pageOffset2 );
		
		if (pageOffset1 != pageOffset2)
		    IOLog("::redirect can't map offset %x to addr %x\n", 
			    pageOffset1, mapping->getVirtualAddress());
#endif


		if (!mapping->initWithDescriptor( mapDesc, intoTask, toAddress, options,
						    offset, length ))
		{
#ifdef DEBUG
		    IOLog("Didn't redirect map %08lx : %08lx\n", offset, length );
#endif
		}

		if (mapping->owner)
		    mapping->owner->removeMapping(mapping);
		continue;
	    }
	}
	else
	{
	    // look for an existing mapping
	    if( (iter = OSCollectionIterator::withCollection( _mappings))) {
    
		while( (mapping = (_IOMemoryMap *) iter->getNextObject())) {
    
		    if( (mapping = mapping->copyCompatible( 
					    owner, intoTask, toAddress,
					    options | kIOMapReference,
					    offset, length )))
			break;
		}
		iter->release();
	    }


	if (mapping)
	    mapping->retain();

	    if( mapping || (options & kIOMapReference))
		continue;

	    mapDesc = owner;
	    mapDesc->retain();
	}
	owner = this;

        mapping = new _IOMemoryMap;
	if( mapping
	&& !mapping->initWithDescriptor( mapDesc, intoTask, toAddress, options,
			   offset, length )) {
#ifdef DEBUG
	    IOLog("Didn't make map %08lx : %08lx\n", offset, length );
#endif
	    mapping->release();
            mapping = 0;
	}

	if (mapping)
	    mapping->retain();

    } while( false );

    if (mapping)
    {
	mapping->owner = owner;
	owner->addMapping( mapping);
	mapping->release();
    }

    UNLOCK;

    if (mapDesc)
	mapDesc->release();

    return( mapping);
}

void IOMemoryDescriptor::addMapping(
	IOMemoryMap * mapping )
{
    if( mapping) {
        if( 0 == _mappings)
            _mappings = OSSet::withCapacity(1);
	if( _mappings )
	    _mappings->setObject( mapping );
    }
}

void IOMemoryDescriptor::removeMapping(
	IOMemoryMap * mapping )
{
    if( _mappings)
        _mappings->removeObject( mapping);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOMemoryDescriptor

OSDefineMetaClassAndStructors(IOSubMemoryDescriptor, IOMemoryDescriptor)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOSubMemoryDescriptor::initSubRange( IOMemoryDescriptor * parent,
					IOByteCount offset, IOByteCount length,
					IODirection direction )
{
    if( !parent)
	return( false);

    if( (offset + length) > parent->getLength())
	return( false);

    /*
     * We can check the _parent instance variable before having ever set it
     * to an initial value because I/O Kit guarantees that all our instance
     * variables are zeroed on an object's allocation.
     */

    if( !_parent) {
	if( !super::init())
	    return( false );
    } else {
	/*
	 * An existing memory descriptor is being retargeted to
	 * point to somewhere else.  Clean up our present state.
	 */

	_parent->release();
	_parent = 0;
    }

    parent->retain();
    _parent	= parent;
    _start	= offset;
    _length	= length;
    _direction  = direction;
    _tag	= parent->getTag();

    return( true );
}

void IOSubMemoryDescriptor::free( void )
{
    if( _parent)
	_parent->release();

    super::free();
}


IOReturn
IOSubMemoryDescriptor::dmaCommandOperation(DMACommandOps op, void *vData, UInt dataSize) const
{
    IOReturn rtn;

    if (kIOMDGetCharacteristics == op) {

	rtn = _parent->dmaCommandOperation(op, vData, dataSize);
	if (kIOReturnSuccess == rtn) {
	    IOMDDMACharacteristics *data = (IOMDDMACharacteristics *) vData;
	    data->fLength = _length;
	    data->fSGCount = 0;	// XXX gvdl: need to compute and pages
	    data->fPages = 0;
	    data->fPageAlign = 0;
	}

	return rtn;
    }
    else if (kIOMDWalkSegments & op) {
	if (dataSize < sizeof(IOMDDMAWalkSegmentArgs))
	    return kIOReturnUnderrun;

	IOMDDMAWalkSegmentArgs *data =
	    reinterpret_cast<IOMDDMAWalkSegmentArgs *>(vData);
	UInt offset = data->fOffset;
	UInt remain = _length - offset;
	if ((int) remain <= 0)
	    return (!remain)? kIOReturnOverrun : kIOReturnInternalError;

	data->fOffset = offset + _start;
	rtn = _parent->dmaCommandOperation(op, vData, dataSize);
	if (data->fLength > remain)
	    data->fLength = remain;
	data->fOffset  = offset;

	return rtn;
    }
    else
	return kIOReturnBadArgument;
}

addr64_t
IOSubMemoryDescriptor::getPhysicalSegment64(IOByteCount offset, IOByteCount * length)
{
    addr64_t	address;
    IOByteCount	actualLength;

    assert(offset <= _length);

    if( length)
        *length = 0;

    if( offset >= _length)
        return( 0 );

    address = _parent->getPhysicalSegment64( offset + _start, &actualLength );

    if( address && length)
	*length = min( _length - offset, actualLength );

    return( address );
}

IOPhysicalAddress
IOSubMemoryDescriptor::getPhysicalSegment( IOByteCount offset, IOByteCount * length )
{
    IOPhysicalAddress	address;
    IOByteCount		actualLength;

    assert(offset <= _length);

    if( length)
        *length = 0;

    if( offset >= _length)
        return( 0 );

    address = _parent->getPhysicalSegment( offset + _start, &actualLength );

    if( address && length)
	*length = min( _length - offset, actualLength );

    return( address );
}


IOReturn IOSubMemoryDescriptor::doMap(
	vm_map_t		addressMap,
	IOVirtualAddress *	atAddress,
	IOOptionBits		options,
	IOByteCount		sourceOffset,
	IOByteCount		length )
{
    if( sourceOffset >= _length)
        return( kIOReturnOverrun );
    return (_parent->doMap(addressMap, atAddress, options, sourceOffset + _start, length));
}

IOPhysicalAddress 
IOSubMemoryDescriptor::getSourceSegment( IOByteCount offset, IOByteCount * length )
{
    IOPhysicalAddress	address;
    IOByteCount		actualLength;

    assert(offset <= _length);

    if( length)
        *length = 0;

    if( offset >= _length)
        return( 0 );

    address = _parent->getSourceSegment( offset + _start, &actualLength );

    if( address && length)
	*length = min( _length - offset, actualLength );

    return( address );
}

void * IOSubMemoryDescriptor::getVirtualSegment(IOByteCount offset,
					IOByteCount * lengthOfSegment)
{
    return( 0 );
}

IOByteCount IOSubMemoryDescriptor::readBytes(IOByteCount offset,
					void * bytes, IOByteCount length)
{
    IOByteCount	byteCount;

    assert(offset <= _length);

    if( offset >= _length)
        return( 0 );

    LOCK;
    byteCount = _parent->readBytes( _start + offset, bytes,
				min(length, _length - offset) );
    UNLOCK;

    return( byteCount );
}

IOByteCount IOSubMemoryDescriptor::writeBytes(IOByteCount offset,
				const void* bytes, IOByteCount length)
{
    IOByteCount	byteCount;

    assert(offset <= _length);

    if( offset >= _length)
        return( 0 );

    LOCK;
    byteCount = _parent->writeBytes( _start + offset, bytes,
				min(length, _length - offset) );
    UNLOCK;

    return( byteCount );
}

IOReturn IOSubMemoryDescriptor::setPurgeable( IOOptionBits newState,
                                    IOOptionBits * oldState )
{
    IOReturn err;

    LOCK;
    err = _parent->setPurgeable( newState, oldState );
    UNLOCK;

    return( err );
}

IOReturn IOSubMemoryDescriptor::performOperation( IOOptionBits options,
                                        IOByteCount offset, IOByteCount length )
{
    IOReturn err;

    assert(offset <= _length);

    if( offset >= _length)
        return( kIOReturnOverrun );

    LOCK;
    err = _parent->performOperation( options, _start + offset,
                                      min(length, _length - offset) );
    UNLOCK;

    return( err );
}

IOReturn IOSubMemoryDescriptor::prepare(
		IODirection forDirection)
{
    IOReturn	err;

    LOCK;
    err = _parent->prepare( forDirection);
    UNLOCK;

    return( err );
}

IOReturn IOSubMemoryDescriptor::complete(
		IODirection forDirection)
{
    IOReturn	err;

    LOCK;
    err = _parent->complete( forDirection);
    UNLOCK;

    return( err );
}

IOMemoryMap * IOSubMemoryDescriptor::makeMapping(
	IOMemoryDescriptor *	owner,
	task_t			intoTask,
	IOVirtualAddress	toAddress,
	IOOptionBits		options,
	IOByteCount		offset,
	IOByteCount		length )
{
    IOMemoryMap * mapping = 0;

    if (!(kIOMapUnique & options))
	mapping = (IOMemoryMap *) _parent->makeMapping(
					_parent, intoTask,
					toAddress - (_start + offset),
					options | kIOMapReference,
					_start + offset, length );

    if( !mapping)
        mapping = (IOMemoryMap *) _parent->makeMapping(
					_parent, intoTask,
					toAddress,
					options, _start + offset, length );

    if( !mapping)
	mapping = super::makeMapping( owner, intoTask, toAddress, options,
					offset, length );

    return( mapping );
}

/* ick */

bool
IOSubMemoryDescriptor::initWithAddress(void *      address,
                                    IOByteCount   length,
                                    IODirection direction)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithAddress(vm_address_t address,
                                    IOByteCount    length,
                                    IODirection  direction,
                                    task_t       task)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithPhysicalAddress(
				 IOPhysicalAddress	address,
				 IOByteCount		length,
				 IODirection      	direction )
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithRanges(
                                   	IOVirtualRange * ranges,
                                   	UInt32           withCount,
                                   	IODirection      direction,
                                   	task_t           task,
                                  	bool             asReference)
{
    return( false );
}

bool
IOSubMemoryDescriptor::initWithPhysicalRanges(	IOPhysicalRange * ranges,
                                        	UInt32           withCount,
                                        	IODirection      direction,
                                        	bool             asReference)
{
    return( false );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOGeneralMemoryDescriptor::serialize(OSSerialize * s) const
{
    OSSymbol const *keys[2];
    OSObject *values[2];
    struct SerData {
	user_addr_t address;
	user_size_t length;
    } *vcopy;
    unsigned int index, nRanges;
    bool result;

    IOOptionBits type = _flags & kIOMemoryTypeMask;

    if (s == NULL) return false;
    if (s->previouslySerialized(this)) return true;

    // Pretend we are an array.
    if (!s->addXMLStartTag(this, "array")) return false;

    nRanges = _rangesCount;
    vcopy = (SerData *) IOMalloc(sizeof(SerData) * nRanges);
    if (vcopy == 0) return false;

    keys[0] = OSSymbol::withCString("address");
    keys[1] = OSSymbol::withCString("length");

    result = false;
    values[0] = values[1] = 0;

    // From this point on we can go to bail.

    // Copy the volatile data so we don't have to allocate memory
    // while the lock is held.
    LOCK;
    if (nRanges == _rangesCount) {
	Ranges vec = _ranges;
        for (index = 0; index < nRanges; index++) {
	    user_addr_t addr; IOByteCount len;
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

    for (index = 0; index < nRanges; index++)
    {
	user_addr_t addr = vcopy[index].address;
	IOByteCount len = (IOByteCount) vcopy[index].length;
	values[0] =
	    OSNumber::withNumber(addr, (((UInt64) addr) >> 32)? 64 : 32);
	if (values[0] == 0) {
	  result = false;
	  goto bail;
	}
	values[1] = OSNumber::withNumber(len, sizeof(len) * 8);
	if (values[1] == 0) {
	  result = false;
	  goto bail;
	}
        OSDictionary *dict = OSDictionary::withObjects((const OSObject **)values, (const OSSymbol **)keys, 2);
	if (dict == 0) {
	  result = false;
	  goto bail;
	}
	values[0]->release();
	values[1]->release();
	values[0] = values[1] = 0;

	result = dict->serialize(s);
	dict->release();
	if (!result) {
	  goto bail;
	}
    }
    result = s->addXMLEndTag("array");

 bail:
    if (values[0])
      values[0]->release();
    if (values[1])
      values[1]->release();
    if (keys[0])
      keys[0]->release();
    if (keys[1])
      keys[1]->release();
    if (vcopy)
        IOFree(vcopy, sizeof(IOVirtualRange) * nRanges);
    return result;
}

bool IOSubMemoryDescriptor::serialize(OSSerialize * s) const
{
    if (!s) {
	return (false);
    }
    if (s->previouslySerialized(this)) return true;

    // Pretend we are a dictionary.
    // We must duplicate the functionality of OSDictionary here
    // because otherwise object references will not work;
    // they are based on the value of the object passed to
    // previouslySerialized and addXMLStartTag.

    if (!s->addXMLStartTag(this, "dict")) return false;

    char const *keys[3] = {"offset", "length", "parent"};

    OSObject *values[3];
    values[0] = OSNumber::withNumber(_start, sizeof(_start) * 8);
    if (values[0] == 0)
	return false;
    values[1] = OSNumber::withNumber(_length, sizeof(_length) * 8);
    if (values[1] == 0) {
	values[0]->release();
	return false;
    }
    values[2] = _parent;

    bool result = true;
    for (int i=0; i<3; i++) {
        if (!s->addString("<key>") ||
	    !s->addString(keys[i]) ||
	    !s->addXMLEndTag("key") ||
	    !values[i]->serialize(s)) {
	  result = false;
	  break;
        }
    }
    values[0]->release();
    values[1]->release();
    if (!result) {
      return false;
    }

    return s->addXMLEndTag("dict");
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 0);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 1);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 2);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 3);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 4);
OSMetaClassDefineReservedUsed(IOMemoryDescriptor, 5);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 6);
OSMetaClassDefineReservedUnused(IOMemoryDescriptor, 7);
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
        { return( getPhysicalSegment( 0, 0 )); }



