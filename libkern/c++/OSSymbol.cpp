/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
/* IOSymbol.cpp created by gvdl on Fri 1998-11-17 */

#define IOKIT_ENABLE_SHARED_PTR

#include <string.h>
#include <sys/cdefs.h>

#include <kern/locks.h>

#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/c++/OSLib.h>
#include <os/cpp_util.h>
#include <string.h>

#define super OSString

typedef struct { unsigned int i, j; } OSSymbolPoolState;

#define INITIAL_POOL_SIZE  ((unsigned int)((exp2ml(1 + log2(kInitBucketCount)))))

#define GROW_FACTOR   (1)
#define SHRINK_FACTOR (3)

#define GROW_POOL()     do \
    if (count * GROW_FACTOR > nBuckets) { \
	reconstructSymbols(true); \
    } \
while (0)

#define SHRINK_POOL()     do \
    if (count * SHRINK_FACTOR < nBuckets && \
	nBuckets > INITIAL_POOL_SIZE) { \
	reconstructSymbols(false); \
    } \
while (0)

class OSSymbolPool
{
private:
	static const unsigned int kInitBucketCount = 16;

	typedef struct { unsigned int count; OSSymbol **symbolP; } Bucket;

	Bucket *buckets;
	unsigned int nBuckets;
	unsigned int count;
	lck_rw_t *poolGate;

	static inline void
	hashSymbol(const char *s,
	    unsigned int *hashP,
	    unsigned int *lenP)
	{
		unsigned int hash = 0;
		unsigned int len = 0;

		/* Unroll the loop. */
		for (;;) {
			if (!*s) {
				break;
			}
			len++; hash ^= (unsigned int)(unsigned char) *s++;
			if (!*s) {
				break;
			}
			len++; hash ^= ((unsigned int)(unsigned char) *s++) <<  8;
			if (!*s) {
				break;
			}
			len++; hash ^= ((unsigned int)(unsigned char) *s++) << 16;
			if (!*s) {
				break;
			}
			len++; hash ^= ((unsigned int)(unsigned char) *s++) << 24;
		}
		*lenP = len;
		*hashP = hash;
	}

	static unsigned long log2(unsigned int x);
	static unsigned long exp2ml(unsigned long x);

	void reconstructSymbols(void);
	void reconstructSymbols(bool grow);

public:
	static void *operator new(size_t size);
	static void operator delete(void *mem, size_t size);

	OSSymbolPool()
	{
	}
	OSSymbolPool(const OSSymbolPool *old);
	virtual
	~OSSymbolPool();

	bool init();

	inline void
	closeReadGate()
	{
		lck_rw_lock(poolGate, LCK_RW_TYPE_SHARED);
	}

	inline void
	openReadGate()
	{
		lck_rw_unlock(poolGate, LCK_RW_TYPE_SHARED);
	}


	inline void
	closeWriteGate()
	{
		lck_rw_lock(poolGate, LCK_RW_TYPE_EXCLUSIVE);
	}

	inline void
	openWriteGate()
	{
		lck_rw_unlock(poolGate, LCK_RW_TYPE_EXCLUSIVE);
	}

	OSSharedPtr<OSSymbol> findSymbol(const char *cString) const;
	OSSharedPtr<OSSymbol> insertSymbol(OSSymbol *sym);
	void removeSymbol(OSSymbol *sym);

	OSSymbolPoolState initHashState();
	LIBKERN_RETURNS_NOT_RETAINED OSSymbol * nextHashState(OSSymbolPoolState *stateP);
};

void *
OSSymbolPool::operator new(size_t size)
{
	void *mem = (void *)kalloc_tag(size, VM_KERN_MEMORY_LIBKERN);
	OSMETA_ACCUMSIZE(size);
	assert(mem);
	bzero(mem, size);

	return mem;
}

void
OSSymbolPool::operator delete(void *mem, size_t size)
{
	kfree(mem, size);
	OSMETA_ACCUMSIZE(-size);
}

extern lck_grp_t *IOLockGroup;

bool
OSSymbolPool::init()
{
	count = 0;
	nBuckets = INITIAL_POOL_SIZE;
	buckets = (Bucket *) kalloc_tag(nBuckets * sizeof(Bucket), VM_KERN_MEMORY_LIBKERN);
	OSMETA_ACCUMSIZE(nBuckets * sizeof(Bucket));
	if (!buckets) {
		return false;
	}
	bzero(buckets, nBuckets * sizeof(Bucket));

	poolGate = lck_rw_alloc_init(IOLockGroup, LCK_ATTR_NULL);

	return poolGate != NULL;
}

OSSymbolPool::OSSymbolPool(const OSSymbolPool *old)
{
	count = old->count;
	nBuckets = old->nBuckets;
	buckets = old->buckets;

	poolGate = NULL; // Do not duplicate the poolGate
}

OSSymbolPool::~OSSymbolPool()
{
	if (buckets) {
		Bucket *thisBucket;
		for (thisBucket = &buckets[0]; thisBucket < &buckets[nBuckets]; thisBucket++) {
			if (thisBucket->count > 1) {
				kfree(thisBucket->symbolP, thisBucket->count * sizeof(OSSymbol *));
				OSMETA_ACCUMSIZE(-(thisBucket->count * sizeof(OSSymbol *)));
			}
		}
		kfree(buckets, nBuckets * sizeof(Bucket));
		OSMETA_ACCUMSIZE(-(nBuckets * sizeof(Bucket)));
	}

	if (poolGate) {
		lck_rw_free(poolGate, IOLockGroup);
	}
}

unsigned long
OSSymbolPool::log2(unsigned int x)
{
	unsigned long i;

	for (i = 0; x > 1; i++) {
		x >>= 1;
	}
	return i;
}

unsigned long
OSSymbolPool::exp2ml(unsigned long x)
{
	return (1 << x) - 1;
}

OSSymbolPoolState
OSSymbolPool::initHashState()
{
	OSSymbolPoolState newState = { nBuckets, 0 };
	return newState;
}

OSSymbol *
OSSymbolPool::nextHashState(OSSymbolPoolState *stateP)
{
	Bucket *thisBucket = &buckets[stateP->i];

	while (!stateP->j) {
		if (!stateP->i) {
			return NULL;
		}
		stateP->i--;
		thisBucket--;
		stateP->j = thisBucket->count;
	}

	stateP->j--;
	if (thisBucket->count == 1) {
		return (OSSymbol *) thisBucket->symbolP;
	} else {
		return thisBucket->symbolP[stateP->j];
	}
}

void
OSSymbolPool::reconstructSymbols(void)
{
	this->reconstructSymbols(true);
}

void
OSSymbolPool::reconstructSymbols(bool grow)
{
	unsigned int new_nBuckets = nBuckets;
	OSSymbol *insert;
	OSSymbolPoolState state;

	if (grow) {
		new_nBuckets += new_nBuckets + 1;
	} else {
		/* Don't shrink the pool below the default initial size.
		 */
		if (nBuckets <= INITIAL_POOL_SIZE) {
			return;
		}
		new_nBuckets = (new_nBuckets - 1) / 2;
	}

	/* Create old pool to iterate after doing above check, cause it
	 * gets finalized at return.
	 */
	OSSymbolPool old(this);

	count = 0;
	nBuckets = new_nBuckets;
	buckets = (Bucket *) kalloc_tag(nBuckets * sizeof(Bucket), VM_KERN_MEMORY_LIBKERN);
	OSMETA_ACCUMSIZE(nBuckets * sizeof(Bucket));
	/* @@@ gvdl: Zero test and panic if can't set up pool */
	bzero(buckets, nBuckets * sizeof(Bucket));

	state = old.initHashState();
	while ((insert = old.nextHashState(&state))) {
		insertSymbol(insert);
	}
}

OSSharedPtr<OSSymbol>
OSSymbolPool::findSymbol(const char *cString) const
{
	Bucket *thisBucket;
	unsigned int j, inLen, hash;
	OSSymbol *probeSymbol, **list;
	OSSharedPtr<OSSymbol> ret;

	hashSymbol(cString, &hash, &inLen); inLen++;
	thisBucket = &buckets[hash % nBuckets];
	j = thisBucket->count;

	if (!j) {
		return NULL;
	}

	if (j == 1) {
		probeSymbol = (OSSymbol *) thisBucket->symbolP;

		if (inLen == probeSymbol->length
		    && strncmp(probeSymbol->string, cString, probeSymbol->length) == 0
		    && probeSymbol->taggedTryRetain(nullptr)) {
			ret.reset(probeSymbol, OSNoRetain);
			return ret;
		}
		return NULL;
	}

	for (list = thisBucket->symbolP; j--; list++) {
		probeSymbol = *list;
		if (inLen == probeSymbol->length
		    && strncmp(probeSymbol->string, cString, probeSymbol->length) == 0
		    && probeSymbol->taggedTryRetain(nullptr)) {
			ret.reset(probeSymbol, OSNoRetain);
			return ret;
		}
	}

	return NULL;
}

OSSharedPtr<OSSymbol>
OSSymbolPool::insertSymbol(OSSymbol *sym)
{
	const char *cString = sym->string;
	Bucket *thisBucket;
	unsigned int j, inLen, hash;
	OSSymbol *probeSymbol, **list;
	OSSharedPtr<OSSymbol> ret;

	hashSymbol(cString, &hash, &inLen); inLen++;
	thisBucket = &buckets[hash % nBuckets];
	j = thisBucket->count;

	if (!j) {
		thisBucket->symbolP = (OSSymbol **) sym;
		thisBucket->count++;
		count++;
		return nullptr;
	}

	if (j == 1) {
		probeSymbol = (OSSymbol *) thisBucket->symbolP;

		if (inLen == probeSymbol->length
		    && strncmp(probeSymbol->string, cString, probeSymbol->length) == 0
		    && probeSymbol->taggedTryRetain(nullptr)) {
			ret.reset(probeSymbol, OSNoRetain);
			return ret;
		}

		list = (OSSymbol **) kalloc_tag(2 * sizeof(OSSymbol *), VM_KERN_MEMORY_LIBKERN);
		OSMETA_ACCUMSIZE(2 * sizeof(OSSymbol *));
		/* @@@ gvdl: Zero test and panic if can't set up pool */
		list[0] = sym;
		list[1] = probeSymbol;
		thisBucket->symbolP = list;
		thisBucket->count++;
		count++;
		GROW_POOL();

		return nullptr;
	}

	for (list = thisBucket->symbolP; j--; list++) {
		probeSymbol = *list;
		if (inLen == probeSymbol->length
		    && strncmp(probeSymbol->string, cString, probeSymbol->length) == 0
		    && probeSymbol->taggedTryRetain(nullptr)) {
			ret.reset(probeSymbol, OSNoRetain);
			return ret;
		}
	}

	j = thisBucket->count++;
	count++;
	list = (OSSymbol **) kalloc_tag(thisBucket->count * sizeof(OSSymbol *), VM_KERN_MEMORY_LIBKERN);
	OSMETA_ACCUMSIZE(thisBucket->count * sizeof(OSSymbol *));
	/* @@@ gvdl: Zero test and panic if can't set up pool */
	list[0] = sym;
	bcopy(thisBucket->symbolP, list + 1, j * sizeof(OSSymbol *));
	kfree(thisBucket->symbolP, j * sizeof(OSSymbol *));
	OSMETA_ACCUMSIZE(-(j * sizeof(OSSymbol *)));
	thisBucket->symbolP = list;
	GROW_POOL();

	return nullptr;
}

void
OSSymbolPool::removeSymbol(OSSymbol *sym)
{
	Bucket *thisBucket;
	unsigned int j, inLen, hash;
	OSSymbol *probeSymbol, **list;

	hashSymbol(sym->string, &hash, &inLen); inLen++;
	thisBucket = &buckets[hash % nBuckets];
	j = thisBucket->count;
	list = thisBucket->symbolP;

	if (!j) {
		// couldn't find the symbol; probably means string hash changed
		panic("removeSymbol %s count %d ", sym->string ? sym->string : "no string", count);
		return;
	}

	if (j == 1) {
		probeSymbol = (OSSymbol *) list;

		if (probeSymbol == sym) {
			thisBucket->symbolP = NULL;
			count--;
			thisBucket->count--;
			SHRINK_POOL();
			return;
		}
		// couldn't find the symbol; probably means string hash changed
		panic("removeSymbol %s count %d ", sym->string ? sym->string : "no string", count);
		return;
	}

	if (j == 2) {
		probeSymbol = list[0];
		if (probeSymbol == sym) {
			thisBucket->symbolP = (OSSymbol **) list[1];
			kfree(list, 2 * sizeof(OSSymbol *));
			OSMETA_ACCUMSIZE(-(2 * sizeof(OSSymbol *)));
			count--;
			thisBucket->count--;
			SHRINK_POOL();
			return;
		}

		probeSymbol = list[1];
		if (probeSymbol == sym) {
			thisBucket->symbolP = (OSSymbol **) list[0];
			kfree(list, 2 * sizeof(OSSymbol *));
			OSMETA_ACCUMSIZE(-(2 * sizeof(OSSymbol *)));
			count--;
			thisBucket->count--;
			SHRINK_POOL();
			return;
		}
		// couldn't find the symbol; probably means string hash changed
		panic("removeSymbol %s count %d ", sym->string ? sym->string : "no string", count);
		return;
	}

	for (; j--; list++) {
		probeSymbol = *list;
		if (probeSymbol == sym) {
			list = (OSSymbol **)
			    kalloc_tag((thisBucket->count - 1) * sizeof(OSSymbol *), VM_KERN_MEMORY_LIBKERN);
			OSMETA_ACCUMSIZE((thisBucket->count - 1) * sizeof(OSSymbol *));
			if (thisBucket->count - 1 != j) {
				bcopy(thisBucket->symbolP, list,
				    (thisBucket->count - 1 - j) * sizeof(OSSymbol *));
			}
			if (j) {
				bcopy(thisBucket->symbolP + thisBucket->count - j,
				    list + thisBucket->count - 1 - j,
				    j * sizeof(OSSymbol *));
			}
			kfree(thisBucket->symbolP, thisBucket->count * sizeof(OSSymbol *));
			OSMETA_ACCUMSIZE(-(thisBucket->count * sizeof(OSSymbol *)));
			thisBucket->symbolP = list;
			count--;
			thisBucket->count--;
			return;
		}
	}
	// couldn't find the symbol; probably means string hash changed
	panic("removeSymbol %s count %d ", sym->string ? sym->string : "no string", count);
}

/*
 *********************************************************************
 * From here on we are actually implementing the OSSymbol class
 *********************************************************************
 */
OSDefineMetaClassAndStructorsWithInitAndZone(OSSymbol, OSString,
    OSSymbol::initialize(), ZC_ZFREE_CLEARMEM)
OSMetaClassDefineReservedUnused(OSSymbol, 0);
OSMetaClassDefineReservedUnused(OSSymbol, 1);
OSMetaClassDefineReservedUnused(OSSymbol, 2);
OSMetaClassDefineReservedUnused(OSSymbol, 3);
OSMetaClassDefineReservedUnused(OSSymbol, 4);
OSMetaClassDefineReservedUnused(OSSymbol, 5);
OSMetaClassDefineReservedUnused(OSSymbol, 6);
OSMetaClassDefineReservedUnused(OSSymbol, 7);

static OSSymbolPool *pool;

void
OSSymbol::initialize()
{
	pool = new OSSymbolPool;
	assert(pool);

	if (pool && !pool->init()) {
		delete pool;
		assert(false);
	}
	;
}

bool
OSSymbol::initWithCStringNoCopy(const char *)
{
	return false;
}
bool
OSSymbol::initWithCString(const char *)
{
	return false;
}
bool
OSSymbol::initWithString(const OSString *)
{
	return false;
}

OSSharedPtr<const OSSymbol>
OSSymbol::withString(const OSString *aString)
{
	// This string may be a OSSymbol already, cheap check.
	if (OSDynamicCast(OSSymbol, aString)) {
		OSSharedPtr<const OSSymbol> aStringNew((const OSSymbol *)aString, OSRetain);
		return aStringNew;
	} else if (((const OSSymbol *) aString)->flags & kOSStringNoCopy) {
		return OSSymbol::withCStringNoCopy(aString->getCStringNoCopy());
	} else {
		return OSSymbol::withCString(aString->getCStringNoCopy());
	}
}

OSSharedPtr<const OSSymbol>
OSSymbol::withCString(const char *cString)
{
	OSSharedPtr<const OSSymbol> symbol;

	// Check if the symbol exists already, we don't need to take a lock here,
	// since existingSymbolForCString will take the shared lock.
	symbol = OSSymbol::existingSymbolForCString(cString);
	if (symbol) {
		return symbol;
	}

	OSSharedPtr<OSSymbol> newSymb = OSMakeShared<OSSymbol>();
	if (!newSymb) {
		return os::move(newSymb);
	}

	if (newSymb->OSString::initWithCString(cString)) {
		pool->closeWriteGate();
		symbol = pool->insertSymbol(newSymb.get());
		pool->openWriteGate();

		if (symbol) {
			// Somebody must have inserted the new symbol so free our copy
			newSymb.detach()->OSString::free();
			return symbol;
		}
	}

	return os::move(newSymb); // return the newly created & inserted symbol.
}

OSSharedPtr<const OSSymbol>
OSSymbol::withCStringNoCopy(const char *cString)
{
	OSSharedPtr<const OSSymbol> symbol;
	OSSharedPtr<OSSymbol> newSymb;

	// Check if the symbol exists already, we don't need to take a lock here,
	// since existingSymbolForCString will take the shared lock.
	symbol = OSSymbol::existingSymbolForCString(cString);
	if (symbol) {
		return symbol;
	}

	newSymb = OSMakeShared<OSSymbol>();
	if (!newSymb) {
		return os::move(newSymb);
	}

	if (newSymb->OSString::initWithCStringNoCopy(cString)) {
		pool->closeWriteGate();
		symbol = pool->insertSymbol(newSymb.get());
		pool->openWriteGate();

		if (symbol) {
			newSymb.detach()->OSString::free();
			// Somebody must have inserted the new symbol so free our copy
			return symbol;
		}
	}

	return os::move(newSymb); // return the newly created & inserted symbol.
}

OSSharedPtr<const OSSymbol>
OSSymbol::existingSymbolForString(const OSString *aString)
{
	if (OSDynamicCast(OSSymbol, aString)) {
		OSSharedPtr<const OSSymbol> aStringNew((const OSSymbol *)aString, OSRetain);
		return aStringNew;
	}

	return OSSymbol::existingSymbolForCString(aString->getCStringNoCopy());
}

OSSharedPtr<const OSSymbol>
OSSymbol::existingSymbolForCString(const char *cString)
{
	OSSharedPtr<OSSymbol> symbol;

	pool->closeReadGate();
	symbol = pool->findSymbol(cString);
	pool->openReadGate();

	return os::move(symbol);
}

void
OSSymbol::checkForPageUnload(void *startAddr, void *endAddr)
{
	OSSymbol *probeSymbol;
	OSSymbolPoolState state;

	pool->closeWriteGate();
	state = pool->initHashState();
	while ((probeSymbol = pool->nextHashState(&state))) {
		if (probeSymbol->string >= startAddr && probeSymbol->string < endAddr) {
			probeSymbol->OSString::initWithCString(probeSymbol->string);
		}
	}
	pool->openWriteGate();
}

void
OSSymbol::taggedRelease(const void *tag) const
{
	super::taggedRelease(tag);
}

void
OSSymbol::taggedRelease(const void *tag, const int when) const
{
	super::taggedRelease(tag, when);
}

void
OSSymbol::free()
{
	pool->closeWriteGate();
	pool->removeSymbol(this);
	pool->openWriteGate();
	super::free();
}

bool
OSSymbol::isEqualTo(const char *aCString) const
{
	return super::isEqualTo(aCString);
}

bool
OSSymbol::isEqualTo(const OSSymbol *aSymbol) const
{
	return aSymbol == this;
}

bool
OSSymbol::isEqualTo(const OSMetaClassBase *obj) const
{
	OSSymbol *  sym;
	OSString *  str;

	if ((sym = OSDynamicCast(OSSymbol, obj))) {
		return isEqualTo(sym);
	} else if ((str = OSDynamicCast(OSString, obj))) {
		return super::isEqualTo(str);
	} else {
		return false;
	}
}

unsigned int
OSSymbol::bsearch(
	const void *  key,
	const void *  array,
	unsigned int  arrayCount,
	size_t        memberSize)
{
	const void **p;
	unsigned int baseIdx = 0;
	unsigned int lim;

	for (lim = arrayCount; lim; lim >>= 1) {
		p = (typeof(p))(((uintptr_t) array) + (baseIdx + (lim >> 1)) * memberSize);
		if (key == *p) {
			return baseIdx + (lim >> 1);
		}
		if (key > *p) {
			// move right
			baseIdx += (lim >> 1) + 1;
			lim--;
		}
		// else move left
	}
	// not found, insertion point here
	return baseIdx + (lim >> 1);
}
