/*
 * Copyright (c) 1998-2010 Apple Inc. All rights reserved.
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


#include <sys/sysctl.h>
extern "C" {
#include <vm/vm_kern.h>
}

#include <libkern/c++/OSContainers.h>
#include <libkern/OSDebug.h>
#include <libkern/c++/OSCPPDebug.h>

#include <IOKit/IOKitDebug.h>
#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>

#ifdef IOKITDEBUG
#define DEBUG_INIT_VALUE IOKITDEBUG
#else
#define DEBUG_INIT_VALUE 0
#endif

SInt64          gIOKitDebug = DEBUG_INIT_VALUE;
SInt64          gIOKitTrace = 0;

#if DEVELOPMENT || DEBUG
#define IODEBUG_CTLFLAGS        CTLFLAG_RW
#else
#define IODEBUG_CTLFLAGS        CTLFLAG_RD
#endif

SYSCTL_QUAD(_debug, OID_AUTO, iokit, IODEBUG_CTLFLAGS | CTLFLAG_LOCKED, &gIOKitDebug, "boot_arg io");
SYSCTL_QUAD(_debug, OID_AUTO, iotrace, CTLFLAG_RW | CTLFLAG_LOCKED, &gIOKitTrace, "trace io");


int             debug_malloc_size;
int             debug_iomalloc_size;

vm_size_t       debug_iomallocpageable_size;
int             debug_container_malloc_size;
// int          debug_ivars_size; // in OSObject.cpp

extern "C" {

#if 0
#define DEBG(fmt, args...)   { kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)   { IOLog(fmt, ## args); }
#endif

void IOPrintPlane( const IORegistryPlane * plane )
{
    IORegistryEntry *           next;
    IORegistryIterator *        iter;
    OSOrderedSet *              all;
    char                        format[] = "%xxxs";
    IOService *                 service;

    iter = IORegistryIterator::iterateOver( plane );
    assert( iter );
    all = iter->iterateAll();
    if( all) {
        DEBG("Count %d\n", all->getCount() );
        all->release();
    } else
        DEBG("Empty\n");

    iter->reset();
    while( (next = iter->getNextObjectRecursive())) {
        snprintf(format + 1, sizeof(format) - 1, "%ds", 2 * next->getDepth( plane ));
        DEBG( format, "");
        DEBG( "\033[33m%s", next->getName( plane ));
        if( (next->getLocation( plane )))
            DEBG("@%s", next->getLocation( plane ));
        DEBG("\033[0m <class %s", next->getMetaClass()->getClassName());
        if( (service = OSDynamicCast(IOService, next)))
            DEBG(", busy %ld", (long) service->getBusyState());
        DEBG( ">\n");
//      IOSleep(250);
    }
    iter->release();
}

void db_piokjunk(void)
{
}

void db_dumpiojunk( const IORegistryPlane * plane __unused )
{
}

void IOPrintMemory( void )
{

//    OSMetaClass::printInstanceCounts();

    IOLog("\n"
            "ivar kalloc()       0x%08x\n"
            "malloc()            0x%08x\n"
            "containers kalloc() 0x%08x\n"
            "IOMalloc()          0x%08x\n"
            "----------------------------------------\n",
            debug_ivars_size,
            debug_malloc_size,
            debug_container_malloc_size,
            debug_iomalloc_size
            );
}

} /* extern "C" */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super OSObject
OSDefineMetaClassAndStructors(IOKitDiagnostics, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSObject * IOKitDiagnostics::diagnostics( void )
{
    IOKitDiagnostics * diags;

    diags = new IOKitDiagnostics;
    if( diags && !diags->init()) {
        diags->release();
        diags = 0;
    }

    return( diags );
}

void IOKitDiagnostics::updateOffset( OSDictionary * dict,
                        UInt64 value, const char * name )
{
    OSNumber * off;

    off = OSNumber::withNumber( value, 64 );
    if( !off)
        return;

    dict->setObject( name, off );
    off->release();
}

bool IOKitDiagnostics::serialize(OSSerialize *s) const
{
    OSDictionary *      dict;
    bool                ok;

    dict = OSDictionary::withCapacity( 5 );
    if( !dict)
        return( false );

    updateOffset( dict, debug_ivars_size, "Instance allocation" );
    updateOffset( dict, debug_container_malloc_size, "Container allocation" );
    updateOffset( dict, debug_iomalloc_size, "IOMalloc allocation" );
    updateOffset( dict, debug_iomallocpageable_size, "Pageable allocation" );

    OSMetaClass::serializeClassDictionary(dict);

    ok = dict->serialize( s );

    dict->release();

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if IOTRACKING

#include <libkern/c++/OSCPPDebug.h>
#include <libkern/c++/OSKext.h>
#include <kern/zalloc.h>

__private_extern__ "C" void qsort(
    void * array,
    size_t nmembers,
    size_t member_size,
    int (*)(const void *, const void *));

extern "C" ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern "C" ppnum_t pmap_valid_page(ppnum_t pn);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct IOTRecursiveLock
{
    lck_mtx_t * mutex;
    thread_t    thread;
    UInt32      count;
};

struct IOTrackingQueue
{
    queue_chain_t     link;
    IOTRecursiveLock  lock;
    queue_head_t      sites;
    const char *      name;
    size_t            allocSize;
    size_t            minCaptureSize;
    uint32_t          siteCount;
    uint8_t           captureOn;
    uint8_t           isAlloc;
};

struct IOTrackingCallSite
{
    queue_chain_t          link;
    IOTrackingQueue *      queue;
    uint32_t               crc;
    IOTrackingCallSiteInfo info; 
    queue_chain_t          instances;
    IOTracking *           addresses;
};

struct IOTrackingLeaksRef
{
    uintptr_t * instances;
    uint32_t    count;
    uint32_t    found;
    size_t      bytes;
};

enum
{
    kInstanceFlagAddress    = 0x01UL,
    kInstanceFlagReferenced = 0x02UL,
    kInstanceFlags          = 0x03UL
};

lck_mtx_t *  gIOTrackingLock;
queue_head_t gIOTrackingQ;

enum
{
    kTrackingAddressFlagAllocated    = 0x00000001
};

#if defined(__LP64__)
#define IOTrackingAddressFlags(ptr)	(ptr->flags)
#else
#define IOTrackingAddressFlags(ptr)	(ptr->tracking.flags)
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void 
IOTRecursiveLockLock(IOTRecursiveLock * lock)
{
    if (lock->thread == current_thread()) lock->count++;
    else
    {
        lck_mtx_lock(lock->mutex);
        assert(lock->thread == 0);
        assert(lock->count == 0);
        lock->thread = current_thread();
        lock->count = 1;
    }
}

static void 
IOTRecursiveLockUnlock(IOTRecursiveLock * lock)
{
    assert(lock->thread == current_thread());
    if (0 == (--lock->count))
    {
        lock->thread = 0;
        lck_mtx_unlock(lock->mutex);
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingInit(void)
{
    queue_init(&gIOTrackingQ);
    gIOTrackingLock = lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOTrackingQueue *
IOTrackingQueueAlloc(const char * name, size_t allocSize, size_t minCaptureSize, bool isAlloc)
{
    IOTrackingQueue * queue;
    queue = (typeof(queue)) kalloc(sizeof(IOTrackingQueue));
    bzero(queue, sizeof(IOTrackingQueue));

    queue->name           = name;
    queue->allocSize      = allocSize;
    queue->minCaptureSize = minCaptureSize;
    queue->lock.mutex     = lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    queue_init(&queue->sites);

    queue->captureOn = (0 != (kIOTrackingBoot & gIOKitDebug));
    queue->isAlloc   = isAlloc;

    lck_mtx_lock(gIOTrackingLock);
    queue_enter(&gIOTrackingQ, queue, IOTrackingQueue *, link);
    lck_mtx_unlock(gIOTrackingLock);

    return (queue);
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingQueueFree(IOTrackingQueue * queue)
{
    lck_mtx_lock(gIOTrackingLock);
    IOTrackingReset(queue);
    remque(&queue->link);
    lck_mtx_unlock(gIOTrackingLock);

    lck_mtx_free(queue->lock.mutex, IOLockGroup);

    kfree(queue, sizeof(IOTrackingQueue));
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* fasthash
   The MIT License

   Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without
   restriction, including without limitation the rights to use, copy,
   modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/


// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
#define mix(h) ({                               \
                  (h) ^= (h) >> 23;             \
                  (h) *= 0x2127599bf4325c37ULL; \
                  (h) ^= (h) >> 47; })

static uint64_t
fasthash64(const void *buf, size_t len, uint64_t seed)
{
    const uint64_t    m = 0x880355f21e6d1965ULL;
    const uint64_t *pos = (const uint64_t *)buf;
    const uint64_t *end = pos + (len / 8);
    const unsigned char *pos2;
    uint64_t h = seed ^ (len * m);
    uint64_t v;

    while (pos != end) {
        v  = *pos++;
        h ^= mix(v);
        h *= m;
    }

    pos2 = (const unsigned char*)pos;
    v = 0;

    switch (len & 7) {
    case 7: v ^= (uint64_t)pos2[6] << 48;
    case 6: v ^= (uint64_t)pos2[5] << 40;
    case 5: v ^= (uint64_t)pos2[4] << 32;
    case 4: v ^= (uint64_t)pos2[3] << 24;
    case 3: v ^= (uint64_t)pos2[2] << 16;
    case 2: v ^= (uint64_t)pos2[1] << 8;
    case 1: v ^= (uint64_t)pos2[0];
            h ^= mix(v);
            h *= m;
    }

    return mix(h);
} 

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static uint32_t
fasthash32(const void *buf, size_t len, uint32_t seed)
{
    // the following trick converts the 64-bit hashcode to Fermat
    // residue, which shall retain information from both the higher
    // and lower parts of hashcode.
    uint64_t h = fasthash64(buf, len, seed);
    return h - (h >> 32);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingAdd(IOTrackingQueue * queue, IOTracking * mem, size_t size, bool address)
{
    IOTrackingCallSite * site;
    uint32_t             crc, num;
    uintptr_t            bt[kIOTrackingCallSiteBTs + 1];

    if (mem->site)                    return;
    if (!queue->captureOn)            return;
    if (size < queue->minCaptureSize) return;

    assert(!mem->link.next);

    num  = fastbacktrace(&bt[0], kIOTrackingCallSiteBTs + 1);
    num--;
    crc = fasthash32(&bt[1], num * sizeof(bt[0]), 0x04C11DB7);

    IOTRecursiveLockLock(&queue->lock);
    queue_iterate(&queue->sites, site, IOTrackingCallSite *, link)
    {
        if (crc == site->crc) break;
    }

    if (queue_end(&queue->sites, (queue_entry_t) site))
    {
        site = (typeof(site)) kalloc(sizeof(IOTrackingCallSite));

        queue_init(&site->instances);
        site->addresses  = (IOTracking *) &site->instances;
        site->queue      = queue;
        site->crc        = crc;
        site->info.count = 0;
        memset(&site->info.size[0], 0, sizeof(site->info.size));
        bcopy(&bt[1], &site->info.bt[0], num * sizeof(site->info.bt[0]));
        assert(num <= kIOTrackingCallSiteBTs);
        bzero(&site->info.bt[num], (kIOTrackingCallSiteBTs - num) * sizeof(site->info.bt[0]));

        queue_enter_first(&queue->sites, site, IOTrackingCallSite *, link);
        queue->siteCount++;
    }

    if (address)
    {
        queue_enter/*last*/(&site->instances, mem, IOTrackingCallSite *, link);
        if (queue_end(&site->instances, (queue_entry_t)site->addresses)) site->addresses = mem;
    }
    else queue_enter_first(&site->instances, mem, IOTrackingCallSite *, link);

    mem->site = site;
    site->info.size[0] += size;
    site->info.count++;

    IOTRecursiveLockUnlock(&queue->lock);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingRemove(IOTrackingQueue * queue, IOTracking * mem, size_t size)
{
    if (!mem->link.next) return;

    IOTRecursiveLockLock(&queue->lock);

    assert(mem->site);

    if (mem == mem->site->addresses) mem->site->addresses = (IOTracking *) queue_next(&mem->link);
    remque(&mem->link);

    assert(mem->site->info.count);
    mem->site->info.count--;
    assert(mem->site->info.size[0] >= size);
    mem->site->info.size[0] -= size;
    if (!mem->site->info.count)
    {
        assert(queue_empty(&mem->site->instances));
        assert(!mem->site->info.size[0]);
        assert(!mem->site->info.size[1]);

        remque(&mem->site->link);
        assert(queue->siteCount);
        queue->siteCount--;
        kfree(mem->site, sizeof(IOTrackingCallSite));
    }
    IOTRecursiveLockUnlock(&queue->lock);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingAlloc(IOTrackingQueue * queue, uintptr_t address, size_t size)
{
    IOTrackingAddress * tracking;
    
    if (!queue->captureOn)            return;
    if (size < queue->minCaptureSize) return;

    address = ~address;
    tracking = (typeof(tracking)) kalloc(sizeof(IOTrackingAddress));
    bzero(tracking, sizeof(IOTrackingAddress));
    IOTrackingAddressFlags(tracking) |= kTrackingAddressFlagAllocated;
    tracking->address = address;
    tracking->size    = size;

    IOTrackingAdd(queue, &tracking->tracking, size, true);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingFree(IOTrackingQueue * queue, uintptr_t address, size_t size)
{
    IOTrackingCallSite * site;
    IOTrackingAddress  * tracking;
    bool                 done;

    address = ~address;
    IOTRecursiveLockLock(&queue->lock);
    done = false;
    queue_iterate(&queue->sites, site, IOTrackingCallSite *, link)
    {
        for (tracking = (IOTrackingAddress *) site->addresses; 
                !done && !queue_end(&site->instances, (queue_entry_t) tracking);
                tracking = (IOTrackingAddress *) queue_next(&tracking->tracking.link))
        {
            if ((done = (address == tracking->address)))
            {
                IOTrackingRemove(queue, &tracking->tracking, size);
                kfree(tracking, sizeof(IOTrackingAddress));
            }
        }
        if (done) break;
    }

    IOTRecursiveLockUnlock(&queue->lock);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingAccumSize(IOTrackingQueue * queue, IOTracking * mem, size_t size)
{
    IOTRecursiveLockLock(&queue->lock);
    if (mem->link.next)
    {
        assert(mem->site);
        assert((size > 0) || (mem->site->info.size[1] >= -size));
        mem->site->info.size[1] += size;    
    };
    IOTRecursiveLockUnlock(&queue->lock);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void
IOTrackingReset(IOTrackingQueue * queue)
{
    IOTrackingCallSite * site;
    IOTracking         * tracking;
    IOTrackingAddress  * trackingAddress;
    bool                 addresses;

    IOTRecursiveLockLock(&queue->lock);
    while (!queue_empty(&queue->sites))
    {
        queue_remove_first(&queue->sites, site, IOTrackingCallSite *, link);
        addresses = false;
        while (!queue_empty(&site->instances))
        {
            queue_remove_first(&site->instances, tracking, IOTracking *, link);
            tracking->link.next = 0;
            if (tracking == site->addresses) addresses = true;
            if (addresses)
            {
                trackingAddress = (typeof(trackingAddress)) tracking;
                if (kTrackingAddressFlagAllocated & IOTrackingAddressFlags(trackingAddress))
                {
		    kfree(tracking, sizeof(IOTrackingAddress));
		}
	    }
        }
        kfree(site, sizeof(IOTrackingCallSite));
    }
    queue->siteCount = 0;
    IOTRecursiveLockUnlock(&queue->lock);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int
IOTrackingCallSiteInfoCompare(const void * left, const void * right)
{
    IOTrackingCallSiteInfo * l = (typeof(l)) left;
    IOTrackingCallSiteInfo * r = (typeof(r)) right;
    size_t                   lsize, rsize;

    rsize = r->size[0] + r->size[1];
    lsize = l->size[0] + l->size[1];

    return ((rsize > lsize) ? 1 : ((rsize == lsize) ? 0 : -1));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int
IOTrackingAddressCompare(const void * left, const void * right)
{
    IOTracking * instance;
    uintptr_t    inst, laddr, raddr;

    inst = ((typeof(inst) *) left)[0];
    instance = (typeof(instance)) (inst & ~kInstanceFlags);
    if (kInstanceFlagAddress & inst) laddr = ~((IOTrackingAddress *)instance)->address;
    else                             laddr = (uintptr_t) (instance + 1);

    inst = ((typeof(inst) *) right)[0];
    instance = (typeof(instance)) (inst & ~kInstanceFlags);
    if (kInstanceFlagAddress & inst) raddr = ~((IOTrackingAddress *)instance)->address;
    else                             raddr = (uintptr_t) (instance + 1);

    return ((laddr > raddr) ? 1 : ((laddr == raddr) ? 0 : -1));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void
IOTrackingLeakScan(void * refcon)
{
    IOTrackingLeaksRef * ref = (typeof(ref)) refcon;
    uintptr_t          * instances;
    IOTracking         * instance;
    uint64_t             vaddr, vincr;
    ppnum_t              ppn;
    uintptr_t            ptr, addr, inst;
    size_t               size;
    uint32_t             baseIdx, lim, ptrIdx, count;
    boolean_t            is;

//    if (cpu_number()) return;

    instances = ref->instances;
    count     = ref->count;

    for (vaddr = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
         vaddr < VM_MAX_KERNEL_ADDRESS;
         ml_set_interrupts_enabled(is), vaddr += vincr)
    {
#if !defined(__LP64__)
        thread_block(NULL);
#endif
        is = ml_set_interrupts_enabled(false);

        ppn = kernel_pmap_present_mapping(vaddr, &vincr);
        // check noencrypt to avoid VM structs (map entries) with pointers
        if (ppn && (!pmap_valid_page(ppn) || pmap_is_noencrypt(ppn))) ppn = 0;
        if (!ppn) continue;

        for (ptrIdx = 0; ptrIdx < (page_size / sizeof(uintptr_t)); ptrIdx++)
        {
            ptr = ((uintptr_t *)vaddr)[ptrIdx];

            for (lim = count, baseIdx = 0; lim; lim >>= 1)
            {
                inst = instances[baseIdx + (lim >> 1)];
                instance = (typeof(instance)) (inst & ~kInstanceFlags);
                if (kInstanceFlagAddress & inst)
                {
                    addr = ~((IOTrackingAddress *)instance)->address;
                    size = ((IOTrackingAddress *)instance)->size;
                }
                else
                {
                    addr = (uintptr_t) (instance + 1);
                    size = instance->site->queue->allocSize;
                }
                if ((ptr >= addr) && (ptr < (addr + size)))
                {
                    if (!(kInstanceFlagReferenced & inst))
                    {
                        inst |= kInstanceFlagReferenced;
                        instances[baseIdx + (lim >> 1)] = inst;
                        ref->found++;
                    }
                    break;
                }
                if (ptr > addr) 
                {       
                    // move right
                    baseIdx += (lim >> 1) + 1;
                    lim--;
                }
                // else move left
            }
        }
        ref->bytes += page_size;    
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static OSData *
IOTrackingLeaks(OSData * data)
{
    IOTrackingLeaksRef       ref;
    IOTrackingCallSiteInfo   unslideInfo;
    IOTrackingCallSite     * site;
    OSData                 * leakData;
    uintptr_t              * instances;
    IOTracking             * instance;
    uintptr_t                inst;
    uint32_t                 count, idx, numSites, dups, siteCount;

    instances = (typeof(instances)) data->getBytesNoCopy();
    count = (data->getLength() / sizeof(*instances));
    qsort(instances, count, sizeof(*instances), &IOTrackingAddressCompare);
    
    bzero(&ref, sizeof(ref));
    ref.instances = instances;
    ref.count = count;

    IOTrackingLeakScan(&ref);
    
    IOLog("leaks scanned %ld MB, instance count %d, found %d\n", ref.bytes / 1024 / 1024, count, ref.found);

    leakData = OSData::withCapacity(128 * sizeof(IOTrackingCallSiteInfo));

    for (numSites = 0, idx = 0; idx < count; idx++)
    {
        inst = instances[idx];
        if (kInstanceFlagReferenced & inst) continue;
        instance = (typeof(instance)) (inst & ~kInstanceFlags);
        site = instance->site;
	instances[numSites] = (uintptr_t) site;
	numSites++;
    }

    for (idx = 0; idx < numSites; idx++)
    {
        inst = instances[idx];
        if (!inst) continue;
        site = (typeof(site)) inst;
	for (siteCount = 1, dups = (idx + 1); dups < numSites; dups++)
	{
	    if (instances[dups] == (uintptr_t) site)
	    {
		siteCount++;
		instances[dups] = 0;
	    }
	}
        unslideInfo.count   = siteCount;
        unslideInfo.size[0] = (site->info.size[0] * site->info.count) / siteCount;
        unslideInfo.size[1] = (site->info.size[1] * site->info.count) / siteCount;;
        for (uint32_t j = 0; j < kIOTrackingCallSiteBTs; j++)
        {
            unslideInfo.bt[j] = VM_KERNEL_UNSLIDE(site->info.bt[j]);
        }
        leakData->appendBytes(&unslideInfo, sizeof(unslideInfo));
    }
    data->release();

    return (leakData);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static bool
SkipName(uint32_t options, const char * name, size_t namesLen, const char * names)
{
    const char * scan;
    const char * next;
    bool         exclude, found;
    size_t       qLen, sLen;

    if (!namesLen || !names) return (false);
    // <len><name>...<len><name><0>
    exclude = (0 != (kIOTrackingExcludeNames & options));
    qLen    = strlen(name);
    scan    = names;
    found   = false;
    do
    {
        sLen = scan[0];
        scan++;
        next = scan + sLen;
        if (next >= (names + namesLen)) break;
        found = ((sLen == qLen) && !strncmp(scan, name, sLen));
        scan = next;
    }
    while (!found && (scan < (names + namesLen)));

    return (!(exclude ^ found));
}

#endif /* IOTRACKING */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOTrackingDebug(uint32_t selector, uint32_t options,
                const char * names, size_t namesLen, 
                size_t size, OSObject ** result)
{
    kern_return_t            ret;
    OSData                 * data;

    if (result) *result = 0;
    data = 0;
    ret = kIOReturnNotReady;

#if IOTRACKING

    IOTrackingQueue        * queue;
    IOTracking             * instance;
    IOTrackingCallSite     * site;
    IOTrackingCallSiteInfo * siteInfos;
    IOTrackingCallSiteInfo * siteInfo;
    bool                     addresses;
    uint32_t                 num, idx;
    uintptr_t                instFlags;

    if (!(kIOTracking & gIOKitDebug)) return (kIOReturnNotReady);
    ret = kIOReturnNotFound;

    lck_mtx_lock(gIOTrackingLock);
    queue_iterate(&gIOTrackingQ, queue, IOTrackingQueue *, link)
    {
        if (SkipName(options, queue->name, namesLen, names)) continue;

        switch (selector)
        {
            case kIOTrackingResetTracking:
            {
                IOTrackingReset(queue);
                ret = kIOReturnSuccess;
                break;
            }

            case kIOTrackingStartCapture:
            case kIOTrackingStopCapture:
            {
                queue->captureOn = (kIOTrackingStartCapture == selector);
                ret = kIOReturnSuccess;
                break;
            }

            case kIOTrackingSetMinCaptureSize:
            {
                queue->minCaptureSize = size;
                ret = kIOReturnSuccess;
                break;
            }

            case kIOTrackingLeaks:
            {
                if (!queue->isAlloc) break;

                if (!data) data = OSData::withCapacity(1024 * sizeof(uintptr_t));

                IOTRecursiveLockLock(&queue->lock);
                queue_iterate(&queue->sites, site, IOTrackingCallSite *, link)
                {
                    addresses = false;
                    queue_iterate(&site->instances, instance, IOTracking *, link)
                    {
                        if (instance == site->addresses) addresses = true;
                        instFlags = (typeof(instFlags)) instance; 
                        if (addresses) instFlags |= kInstanceFlagAddress;
                        data->appendBytes(&instFlags, sizeof(instFlags));
                    }
                }
                // queue is locked
                ret = kIOReturnSuccess;
                break;
            }

            case kIOTrackingGetTracking:
            case kIOTrackingPrintTracking:
            {
                if (!data) data = OSData::withCapacity(128 * sizeof(IOTrackingCallSiteInfo));

                IOTRecursiveLockLock(&queue->lock);
                num = queue->siteCount;
                idx = 0;
                queue_iterate(&queue->sites, site, IOTrackingCallSite *, link)
                {
                    assert(idx < num);
                    idx++;

                    if (size && ((site->info.size[0] + site->info.size[1]) < size)) continue;

                    IOTrackingCallSiteInfo unslideInfo;
                    unslideInfo.count = site->info.count;
                    memcpy(&unslideInfo.size[0], &site->info.size[0], sizeof(unslideInfo.size));

                    for (uint32_t j = 0; j < kIOTrackingCallSiteBTs; j++)
                    {
                        unslideInfo.bt[j] = VM_KERNEL_UNSLIDE(site->info.bt[j]);
                    }
                    data->appendBytes(&unslideInfo, sizeof(unslideInfo));
                }
                assert(idx == num);
                IOTRecursiveLockUnlock(&queue->lock);
                ret = kIOReturnSuccess;
                break;
            }
            default:
                ret = kIOReturnUnsupported;
                break;
        }
    }

    if ((kIOTrackingLeaks == selector) && data)
    {
        data = IOTrackingLeaks(data);
        queue_iterate(&gIOTrackingQ, queue, IOTrackingQueue *, link)
        {
            if (SkipName(options, queue->name, namesLen, names)) continue;
            if (!queue->isAlloc)                                 continue;
            IOTRecursiveLockUnlock(&queue->lock);
        }
    }

    lck_mtx_unlock(gIOTrackingLock);

    if (data)
    {
        siteInfos = (typeof(siteInfos)) data->getBytesNoCopy();
        num = (data->getLength() / sizeof(IOTrackingCallSiteInfo));
        qsort(siteInfos, num, sizeof(*siteInfos), &IOTrackingCallSiteInfoCompare);

        if (kIOTrackingPrintTracking == selector)
        {
            for (idx = 0; idx < num; idx++)
            {
                siteInfo = &siteInfos[idx];
                printf("\n0x%lx bytes (0x%lx + 0x%lx), %d call%s, [%d]\n",
                    siteInfo->size[0] + siteInfo->size[1], 
                    siteInfo->size[0], siteInfo->size[1], 
                    siteInfo->count, (siteInfo->count != 1) ? "s" : "", idx);
                uintptr_t * bt = &siteInfo->bt[0];
                printf("      Backtrace 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n", 
                        bt[0], bt[1], bt[2], bt[3], bt[4], bt[5], bt[6], bt[7], 
                        bt[8], bt[9], bt[10], bt[11], bt[12], bt[13], bt[14], bt[15]);
                kmod_dump_log((vm_offset_t *) &bt[0], kIOTrackingCallSiteBTs, FALSE);
            }
            data->release();
            data = 0;
        }
    }

    *result = data;

#endif /* IOTRACKING */

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <IOKit/IOKitDiagnosticsUserClient.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOKitDiagnosticsClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOUserClient * IOKitDiagnosticsClient::withTask(task_t owningTask)
{
    IOKitDiagnosticsClient * inst;

    inst = new IOKitDiagnosticsClient;
    if (inst && !inst->init())
    {
        inst->release();
        inst = 0;
    }

    return (inst);
}

IOReturn IOKitDiagnosticsClient::clientClose(void)
{
    terminate();
    return (kIOReturnSuccess);
}

IOReturn IOKitDiagnosticsClient::setProperties(OSObject * properties)
{
    IOReturn kr = kIOReturnUnsupported;
    return (kr);
}

IOReturn IOKitDiagnosticsClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
                                                IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
    IOReturn                           ret = kIOReturnBadArgument;
    const IOKitDiagnosticsParameters * params;
    const char * names;
    size_t       namesLen;
    OSObject   * result;

    if (args->structureInputSize < sizeof(IOKitDiagnosticsParameters)) return (kIOReturnBadArgument);
    params = (typeof(params)) args->structureInput;
    if (!params) return (kIOReturnBadArgument);

    names = 0;
    namesLen = args->structureInputSize - sizeof(IOKitDiagnosticsParameters);
    if (namesLen) names = (typeof(names))(params + 1);

    ret = IOTrackingDebug(selector, params->options, names, namesLen, params->size, &result);

    if ((kIOReturnSuccess == ret) && args->structureVariableOutputData) *args->structureVariableOutputData = result;
    else if (result) result->release();

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
