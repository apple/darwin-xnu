/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* IOSymbol.cpp created by gvdl on Fri 1998-11-17 */

#include <string.h>
#include <sys/cdefs.h>

__BEGIN_DECLS
#include <kern/lock.h>
__END_DECLS

#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSLib.h>
#include <string.h>

#define super OSString

typedef struct { int i, j; } OSSymbolPoolState;

#if OSALLOCDEBUG
extern "C" {
    extern int debug_container_malloc_size;
};
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif

class OSSymbolPool
{
private:
    static const unsigned int kInitBucketCount = 16;

    typedef struct { unsigned int count; OSSymbol **symbolP; } Bucket;

    Bucket *buckets;
    unsigned int nBuckets;
    unsigned int count;
    mutex_t *poolGate;

    static inline void hashSymbol(const char *s,
                                  unsigned int *hashP,
                                  unsigned int *lenP)
    {
        unsigned int hash = 0;
        unsigned int len = 0;

        /* Unroll the loop. */
        for (;;) {
            if (!*s) break; len++; hash ^= *s++;
            if (!*s) break; len++; hash ^= *s++ <<  8;
            if (!*s) break; len++; hash ^= *s++ << 16;
            if (!*s) break; len++; hash ^= *s++ << 24;
        }
        *lenP = len;
        *hashP = hash;
    }

    static unsigned long log2(unsigned int x);
    static unsigned long exp2ml(unsigned int x);

    void reconstructSymbols();

public:
    static void *operator new(size_t size);
    static void operator delete(void *mem, size_t size);

    OSSymbolPool() { };
    OSSymbolPool(const OSSymbolPool *old);
    virtual ~OSSymbolPool();

    bool init();

    inline void closeGate() { mutex_lock(poolGate); };
    inline void openGate()  { mutex_unlock(poolGate); };

    OSSymbol *findSymbol(const char *cString, OSSymbol ***replace) const;
    OSSymbol *insertSymbol(OSSymbol *sym);
    void removeSymbol(OSSymbol *sym);

    OSSymbolPoolState initHashState();
    OSSymbol *nextHashState(OSSymbolPoolState *stateP);
};

void * OSSymbolPool::operator new(size_t size)
{
    void *mem = (void *)kalloc(size);
    ACCUMSIZE(size);
    assert(mem);
    bzero(mem, size);

    return mem;
}

void OSSymbolPool::operator delete(void *mem, size_t size)
{
    kfree((vm_offset_t)mem, size);
    ACCUMSIZE(-size);
}

bool OSSymbolPool::init()
{
    count = 0;
    nBuckets = exp2ml(1 + log2(kInitBucketCount));
    buckets = (Bucket *) kalloc(nBuckets * sizeof(Bucket));
    ACCUMSIZE(nBuckets * sizeof(Bucket));
    if (!buckets)
        return false;

    bzero(buckets, nBuckets * sizeof(Bucket));

    poolGate = mutex_alloc(0);

    return poolGate != 0;
}

OSSymbolPool::OSSymbolPool(const OSSymbolPool *old)
{
    count = old->count;
    nBuckets = old->nBuckets;
    buckets = old->buckets;

    poolGate = 0;	// Do not duplicate the poolGate
}

OSSymbolPool::~OSSymbolPool()
{
    if (buckets) {
        kfree((vm_offset_t)buckets, nBuckets * sizeof(Bucket));
        ACCUMSIZE(-(nBuckets * sizeof(Bucket)));
    }

    if (poolGate)
        kfree((vm_offset_t) poolGate, 36 * 4);
}

unsigned long OSSymbolPool::log2(unsigned int x)
{
    unsigned long i;

    for (i = 0; x > 1 ; i++)
        x >>= 1;
    return i;
}

unsigned long OSSymbolPool::exp2ml(unsigned int x)
{
    return (1 << x) - 1;
}

OSSymbolPoolState OSSymbolPool::initHashState()
{
    OSSymbolPoolState newState = { nBuckets, 0 };
    return newState;
}

OSSymbol *OSSymbolPool::nextHashState(OSSymbolPoolState *stateP)
{
    Bucket *thisBucket = &buckets[stateP->i];

    while (!stateP->j) {
        if (!stateP->i)
            return 0;
        stateP->i--;
        thisBucket--;
        stateP->j = thisBucket->count;
    }

    stateP->j--;
    if (thisBucket->count == 1)
        return (OSSymbol *) thisBucket->symbolP;
    else
        return thisBucket->symbolP[stateP->j];
}

void OSSymbolPool::reconstructSymbols()
{
    OSSymbolPool old(this);
    OSSymbol *insert;
    OSSymbolPoolState state;

    nBuckets += nBuckets + 1;
    count = 0;
    buckets = (Bucket *) kalloc(nBuckets * sizeof(Bucket));
    ACCUMSIZE(nBuckets * sizeof(Bucket));
    /* @@@ gvdl: Zero test and panic if can't set up pool */
    bzero(buckets, nBuckets * sizeof(Bucket));

    state = old.initHashState();
    while ( (insert = old.nextHashState(&state)) )
        insertSymbol(insert);
}

OSSymbol *OSSymbolPool::findSymbol(const char *cString, OSSymbol ***replace) const
{
    Bucket *thisBucket;
    unsigned int j, inLen, hash;
    OSSymbol *probeSymbol, **list;

    hashSymbol(cString, &hash, &inLen); inLen++;
    thisBucket = &buckets[hash % nBuckets];
    j = thisBucket->count;

    *replace = NULL;

    if (!j)
        return 0;

    if (j == 1) {
        probeSymbol = (OSSymbol *) thisBucket->symbolP;

        if (inLen == probeSymbol->length
        &&  (strcmp(probeSymbol->string, cString) == 0)) {
	    probeSymbol->retain();
	    if (probeSymbol->getRetainCount() != 0xffff)
		return probeSymbol;
	    else
		// replace this one
		*replace = (OSSymbol **) &thisBucket->symbolP;
        }
	return 0;
    }

    for (list = thisBucket->symbolP; j--; list++) {
        probeSymbol = *list;
        if (inLen == probeSymbol->length
        &&  (strcmp(probeSymbol->string, cString) == 0)) {
	    probeSymbol->retain();
	    if (probeSymbol->getRetainCount() != 0xffff)
		return probeSymbol;
	    else
		// replace this one
		*replace = list;
	}
    }

    return 0;
}

OSSymbol *OSSymbolPool::insertSymbol(OSSymbol *sym)
{
    const char *cString = sym->string;
    Bucket *thisBucket;
    unsigned int j, inLen, hash;
    OSSymbol *probeSymbol, **list;

    hashSymbol(cString, &hash, &inLen); inLen++;
    thisBucket = &buckets[hash % nBuckets];
    j = thisBucket->count;

    if (!j) {
        thisBucket->symbolP = (OSSymbol **) sym;
        thisBucket->count++;
        count++;
        return 0;
    }

    if (j == 1) {
        probeSymbol = (OSSymbol *) thisBucket->symbolP;

        if (inLen == probeSymbol->length
        &&  strcmp(probeSymbol->string, cString) == 0)
            return probeSymbol;

        list = (OSSymbol **) kalloc(2 * sizeof(OSSymbol *));
        ACCUMSIZE(2 * sizeof(OSSymbol *));
        /* @@@ gvdl: Zero test and panic if can't set up pool */
        list[0] = sym;
        list[1] = probeSymbol;
        thisBucket->symbolP = list;
        thisBucket->count++;
        count++;
        if (count > nBuckets)
            reconstructSymbols();

        return 0;
    }

    for (list = thisBucket->symbolP; j--; list++) {
        probeSymbol = *list;
        if (inLen == probeSymbol->length
        &&  strcmp(probeSymbol->string, cString) == 0)
            return probeSymbol;
    }

    j = thisBucket->count++;
    count++;
    list = (OSSymbol **) kalloc(thisBucket->count * sizeof(OSSymbol *));
    ACCUMSIZE(thisBucket->count * sizeof(OSSymbol *));
    /* @@@ gvdl: Zero test and panic if can't set up pool */
    list[0] = sym;
    bcopy(thisBucket->symbolP, list + 1, j * sizeof(OSSymbol *));
    kfree((vm_offset_t)thisBucket->symbolP, j * sizeof(OSSymbol *));
    ACCUMSIZE(-(j * sizeof(OSSymbol *)));
    thisBucket->symbolP = list;
    if (count > nBuckets)
        reconstructSymbols();

    return 0;
}

void OSSymbolPool::removeSymbol(OSSymbol *sym)
{
    Bucket *thisBucket;
    unsigned int j, inLen, hash;
    OSSymbol *probeSymbol, **list;

    hashSymbol(sym->string, &hash, &inLen); inLen++;
    thisBucket = &buckets[hash % nBuckets];
    j = thisBucket->count;
    list = thisBucket->symbolP;

    if (!j)
        return;

    if (j == 1) {
        probeSymbol = (OSSymbol *) list;

        if (probeSymbol == sym) {
            thisBucket->symbolP = 0;
            count--;
            thisBucket->count--;
            return;
        }
        return;
    }

    if (j == 2) {
        probeSymbol = list[0];
        if (probeSymbol == sym) {
            thisBucket->symbolP = (OSSymbol **) list[1];
            kfree((vm_offset_t)list, 2 * sizeof(OSSymbol *));
	    ACCUMSIZE(-(2 * sizeof(OSSymbol *)));
            count--;
            thisBucket->count--;
            return;
        }

        probeSymbol = list[1];
        if (probeSymbol == sym) {
            thisBucket->symbolP = (OSSymbol **) list[0];
            kfree((vm_offset_t)list, 2 * sizeof(OSSymbol *));
	    ACCUMSIZE(-(2 * sizeof(OSSymbol *)));
            count--;
            thisBucket->count--;
            return;
        }
        return;
    }

    for (; j--; list++) {
        probeSymbol = *list;
        if (probeSymbol == sym) {

            list = (OSSymbol **)
                kalloc((thisBucket->count-1) * sizeof(OSSymbol *));
	    ACCUMSIZE((thisBucket->count-1) * sizeof(OSSymbol *));
            if (thisBucket->count-1 != j)
                bcopy(thisBucket->symbolP, list,
                      (thisBucket->count-1-j) * sizeof(OSSymbol *));
            if (j)
                bcopy(thisBucket->symbolP + thisBucket->count-j,
                      list + thisBucket->count-1-j,
                      j * sizeof(OSSymbol *));
            kfree((vm_offset_t)thisBucket->symbolP, thisBucket->count * sizeof(OSSymbol *));
	    ACCUMSIZE(-(thisBucket->count * sizeof(OSSymbol *)));
            thisBucket->symbolP = list;
            count--;
            thisBucket->count--;
            return;
        }
    }
}

/*
 *********************************************************************
 * From here on we are actually implementing the OSSymbol class
 *********************************************************************
 */
OSDefineMetaClassAndStructorsWithInit(OSSymbol, OSString,
                                      OSSymbol::initialize())
OSMetaClassDefineReservedUnused(OSSymbol, 0);
OSMetaClassDefineReservedUnused(OSSymbol, 1);
OSMetaClassDefineReservedUnused(OSSymbol, 2);
OSMetaClassDefineReservedUnused(OSSymbol, 3);
OSMetaClassDefineReservedUnused(OSSymbol, 4);
OSMetaClassDefineReservedUnused(OSSymbol, 5);
OSMetaClassDefineReservedUnused(OSSymbol, 6);
OSMetaClassDefineReservedUnused(OSSymbol, 7);

static OSSymbolPool *pool;

void OSSymbol::initialize()
{
    pool = new OSSymbolPool;
    assert(pool);

    if (!pool->init()) {
        delete pool;
        assert(false);
    };
}

bool OSSymbol::initWithCStringNoCopy(const char *) { return false; }
bool OSSymbol::initWithCString(const char *) { return false; }
bool OSSymbol::initWithString(const OSString *) { return false; }

const OSSymbol *OSSymbol::withString(const OSString *aString)
{
    // This string may be a OSSymbol already, cheap check.
    if (OSDynamicCast(OSSymbol, aString)) {
	aString->retain();
	return (const OSSymbol *) aString;
    }
    else if (((const OSSymbol *) aString)->flags & kOSStringNoCopy)
        return OSSymbol::withCStringNoCopy(aString->getCStringNoCopy());
    else
        return OSSymbol::withCString(aString->getCStringNoCopy());
}

const OSSymbol *OSSymbol::withCString(const char *cString)
{
    OSSymbol **replace;

    pool->closeGate();

    OSSymbol *newSymb = pool->findSymbol(cString, &replace);
    if (!newSymb && (newSymb = new OSSymbol) ) {
	if (newSymb->OSString::initWithCString(cString)) {
	    if (replace)
		*replace = newSymb;
	    else
		pool->insertSymbol(newSymb);
	} else {
	    newSymb->OSString::free();
	    newSymb = 0;
	}
    }
    pool->openGate();

    return newSymb;
}

const OSSymbol *OSSymbol::withCStringNoCopy(const char *cString)
{
    OSSymbol **replace;

    pool->closeGate();

    OSSymbol *newSymb = pool->findSymbol(cString, &replace);
    if (!newSymb && (newSymb = new OSSymbol) ) {
	if (newSymb->OSString::initWithCStringNoCopy(cString)) {
	    if (replace)
		*replace = newSymb;
	    else
		pool->insertSymbol(newSymb);
	} else {
	    newSymb->OSString::free();
	    newSymb = 0;
	}
    }
    pool->openGate();

    return newSymb;
}

void OSSymbol::checkForPageUnload(void *startAddr, void *endAddr)
{
    OSSymbol *probeSymbol;
    OSSymbolPoolState state;

    pool->closeGate();
    state = pool->initHashState();
    while ( (probeSymbol = pool->nextHashState(&state)) ) {
        if (probeSymbol->string >= startAddr && probeSymbol->string < endAddr) {
            const char *oldString = probeSymbol->string;

            probeSymbol->string = (char *) kalloc(probeSymbol->length);
	    ACCUMSIZE(probeSymbol->length);
            bcopy(oldString, probeSymbol->string, probeSymbol->length);
            probeSymbol->flags &= ~kOSStringNoCopy;
        }
    }
    pool->openGate();
}

void OSSymbol::free()
{
    pool->closeGate();
    pool->removeSymbol(this);
    pool->openGate();
    
    super::free();
}

bool OSSymbol::isEqualTo(const char *aCString) const
{
    return super::isEqualTo(aCString);
}

bool OSSymbol::isEqualTo(const OSSymbol *aSymbol) const
{
    return aSymbol == this;
}

bool OSSymbol::isEqualTo(const OSMetaClassBase *obj) const
{
    OSSymbol *	sym;
    OSString *	str;

    if ((sym = OSDynamicCast(OSSymbol, obj)))
	return isEqualTo(sym);
    else if ((str = OSDynamicCast(OSString, obj)))
	return super::isEqualTo(str);
    else
	return false;
}
