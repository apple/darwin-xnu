/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* OSMetaClass.cpp created by gvdl on Fri 1998-11-17 */

#include <string.h>

#include <libkern/OSReturn.h>

#include <libkern/c++/OSMetaClass.h>

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>   
#include <libkern/c++/OSSet.h>	 
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/OSAtomic.h>

#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/IOMessage.h>

__BEGIN_DECLS

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <kern/lock.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <kern/host.h>
#include <mach/kmod.h>
#include <mach/mach_interface.h>

extern void OSRuntimeUnloadCPP(kmod_info_t *ki, void *);

#if OSALLOCDEBUG
extern int debug_container_malloc_size;
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while(0)
#else
#define ACCUMSIZE(s)
#endif /* OSALLOCDEBUG */

__END_DECLS

static enum {
    kCompletedBootstrap = 0,
    kNoDictionaries = 1,
    kMakingDictionaries = 2
} sBootstrapState = kNoDictionaries;

static const int kClassCapacityIncrement = 40;
static const int kKModCapacityIncrement = 10;
static OSDictionary *sAllClassesDict, *sKModClassesDict, *sSortedByClassesDict;

static mutex_t *loadLock = 0;
static struct StalledData {
    const char *kmodName;
    OSReturn result;
    unsigned int capacity;
    unsigned int count;
    OSMetaClass **classes;
} *sStalled;

static unsigned int sConsiderUnloadDelay = 60;	/* secs */
static bool unloadsEnabled = true;  // set to false when system going to sleep
static thread_call_t unloadCallout = 0;

static const char OSMetaClassBasePanicMsg[] =
    "OSMetaClassBase::_RESERVEDOSMetaClassBase%d called\n";

#if SLOT_USED
void OSMetaClassBase::_RESERVEDOSMetaClassBase0()
    { panic(OSMetaClassBasePanicMsg, 0); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase1()
    { panic(OSMetaClassBasePanicMsg, 1); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase2()
    { panic(OSMetaClassBasePanicMsg, 2); }
#endif /* SLOT_USED */

// As these slots are used move them up inside the #if above
void OSMetaClassBase::_RESERVEDOSMetaClassBase3()
    { panic(OSMetaClassBasePanicMsg, 3); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase4()
    { panic(OSMetaClassBasePanicMsg, 4); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase5()
    { panic(OSMetaClassBasePanicMsg, 5); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase6()
    { panic(OSMetaClassBasePanicMsg, 6); }
    
/*
 * These used to be inline in the header but gcc didn't believe us
 * Now we MUST pull the inline out at least until the compiler is
 * repaired.
 */
// Helper inlines for runtime type preprocessor macros
OSMetaClassBase *OSMetaClassBase::
safeMetaCast(const OSMetaClassBase *me, const OSMetaClass *toType)
    { return (me)? me->metaCast(toType) : 0; }

bool OSMetaClassBase::
checkTypeInst(const OSMetaClassBase *inst, const OSMetaClassBase *typeinst)
{
    const OSMetaClass *toType = OSTypeIDInst(typeinst);
    return typeinst && inst && (0 != inst->metaCast(toType));
}


// If you need this slot you had better setup an IOCTL style interface.
// 'Cause the whole kernel world depends on OSMetaClassBase and YOU
// CANT change the VTABLE size ever.
void OSMetaClassBase::_RESERVEDOSMetaClassBase7()
    { panic(OSMetaClassBasePanicMsg, 7); }

OSMetaClassBase::OSMetaClassBase()
{
}

OSMetaClassBase::~OSMetaClassBase()
{
    void **thisVTable;

    thisVTable = (void **) this;
    *thisVTable = (void *) -1UL;
}

bool OSMetaClassBase::isEqualTo(const OSMetaClassBase *anObj) const
{
    return this == anObj;
}

OSMetaClassBase *OSMetaClassBase::metaCast(const OSMetaClass *toMeta) const
{
    return toMeta->checkMetaCast(this);
}

OSMetaClassBase *OSMetaClassBase::metaCast(const OSSymbol *toMetaSymb) const
{
    return OSMetaClass::checkMetaCastWithName(toMetaSymb, this);
}

OSMetaClassBase *OSMetaClassBase::metaCast(const OSString *toMetaStr) const
{
    const OSSymbol *tempSymb = OSSymbol::withString(toMetaStr);
    OSMetaClassBase *ret = 0;
    if (tempSymb) {
        ret = metaCast(tempSymb);
        tempSymb->release();
    }
    return ret;
}

OSMetaClassBase *OSMetaClassBase::metaCast(const char *toMetaCStr) const
{
    const OSSymbol *tempSymb = OSSymbol::withCString(toMetaCStr);
    OSMetaClassBase *ret = 0;
    if (tempSymb) {
        ret = metaCast(tempSymb);
        tempSymb->release();
    }
    return ret;
}

class OSMetaClassMeta : public OSMetaClass 
{
public:
    OSMetaClassMeta();
    OSObject *alloc() const;
};
OSMetaClassMeta::OSMetaClassMeta()
    : OSMetaClass("OSMetaClass", 0, sizeof(OSMetaClass))
    { }
OSObject *OSMetaClassMeta::alloc() const { return 0; }

static OSMetaClassMeta sOSMetaClassMeta;

const OSMetaClass * const OSMetaClass::metaClass = &sOSMetaClassMeta;
const OSMetaClass * OSMetaClass::getMetaClass() const
    { return &sOSMetaClassMeta; }

static const char OSMetaClassPanicMsg[] =
    "OSMetaClass::_RESERVEDOSMetaClass%d called\n";

void OSMetaClass::_RESERVEDOSMetaClass0()
    { panic(OSMetaClassPanicMsg, 0); }
void OSMetaClass::_RESERVEDOSMetaClass1()
    { panic(OSMetaClassPanicMsg, 1); }
void OSMetaClass::_RESERVEDOSMetaClass2()
    { panic(OSMetaClassPanicMsg, 2); }
void OSMetaClass::_RESERVEDOSMetaClass3()
    { panic(OSMetaClassPanicMsg, 3); }
void OSMetaClass::_RESERVEDOSMetaClass4()
    { panic(OSMetaClassPanicMsg, 4); }
void OSMetaClass::_RESERVEDOSMetaClass5()
    { panic(OSMetaClassPanicMsg, 5); }
void OSMetaClass::_RESERVEDOSMetaClass6()
    { panic(OSMetaClassPanicMsg, 6); }
void OSMetaClass::_RESERVEDOSMetaClass7()
    { panic(OSMetaClassPanicMsg, 7); }

void OSMetaClass::logError(OSReturn result)
{
    const char *msg;

    switch (result) {
    case kOSMetaClassNoInit:
	msg="OSMetaClass::preModLoad wasn't called, runtime internal error";
	break;
    case kOSMetaClassNoDicts:
	msg="Allocation failure for Metaclass internal dictionaries"; break;
    case kOSMetaClassNoKModSet:
	msg="Allocation failure for internal kmodule set"; break;
    case kOSMetaClassNoInsKModSet:
	msg="Can't insert the KMod set into the module dictionary"; break;
    case kOSMetaClassDuplicateClass:
	msg="Duplicate class"; break;
    case kOSMetaClassNoSuper:
	msg="Can't associate a class with its super class"; break;
    case kOSMetaClassInstNoSuper:
	msg="Instance construction, unknown super class."; break;
    default:
    case kOSMetaClassInternal:
	msg="runtime internal error"; break;
    case kOSReturnSuccess:
	return;
    }
    printf("%s\n", msg);
}

OSMetaClass::OSMetaClass(const char *inClassName,
                         const OSMetaClass *inSuperClass,
                         unsigned int inClassSize)
{
    instanceCount = 0;
    classSize = inClassSize;
    superClassLink = inSuperClass;

    className = (const OSSymbol *) inClassName;

    if (!sStalled) {
	printf("OSMetaClass::preModLoad wasn't called for %s, "
	       "runtime internal error\n", inClassName);
    } else if (!sStalled->result) {
	// Grow stalled array if neccessary
	if (sStalled->count >= sStalled->capacity) {
	    OSMetaClass **oldStalled = sStalled->classes;
	    int oldSize = sStalled->capacity * sizeof(OSMetaClass *);
	    int newSize = oldSize
			+ kKModCapacityIncrement * sizeof(OSMetaClass *);

	    sStalled->classes = (OSMetaClass **) kalloc(newSize);
	    if (!sStalled->classes) {
		sStalled->classes = oldStalled;
		sStalled->result = kOSMetaClassNoTempData;
		return;
	    }

	    sStalled->capacity += kKModCapacityIncrement;
	    memmove(sStalled->classes, oldStalled, oldSize);
	    kfree(oldStalled, oldSize);
	    ACCUMSIZE(newSize - oldSize);
	}

	sStalled->classes[sStalled->count++] = this;
    }
}

OSMetaClass::~OSMetaClass()
{
    do {
	OSCollectionIterator *iter;

	if (sAllClassesDict) {
	    sAllClassesDict->removeObject(className);
	    className->release();
	}

	iter = OSCollectionIterator::withCollection(sKModClassesDict);
	if (!iter)
	    break;

	OSSymbol *iterKey;
	while ( (iterKey = (OSSymbol *) iter->getNextObject()) ) {
	    OSSet *kmodClassSet;
	    kmodClassSet = (OSSet *) sKModClassesDict->getObject(iterKey);
	    if (kmodClassSet && kmodClassSet->containsObject(this)) {
		kmodClassSet->removeObject(this);
		break;
	    }
	}
	iter->release();
    } while (false);

    if (sStalled) {
	unsigned int i;

	// First pass find class in stalled list
	for (i = 0; i < sStalled->count; i++)
	    if (this == sStalled->classes[i])
		break;

	if (i < sStalled->count) {
	    sStalled->count--;
	    if (i < sStalled->count)
		memmove(&sStalled->classes[i], &sStalled->classes[i+1],
			    (sStalled->count - i) * sizeof(OSMetaClass *));
	}
    }
}

void *OSMetaClass::operator new(__unused size_t size) { return 0; }
void OSMetaClass::retain() const { }
void OSMetaClass::release() const { }
void OSMetaClass::release(__unused int when) const { }
void OSMetaClass::taggedRetain(__unused const void *tag) const { }
void OSMetaClass::taggedRelease(__unused const void *tag) const { }
void OSMetaClass::taggedRelease(__unused const void *tag, __unused const int when) const { }
int  OSMetaClass::getRetainCount() const { return 0; }

const char *OSMetaClass::getClassName() const
{
    return className->getCStringNoCopy();
}

unsigned int OSMetaClass::getClassSize() const
{
    return classSize;
}

void *OSMetaClass::preModLoad(const char *kmodName)
{
    if (!loadLock) {
        loadLock = mutex_alloc(0);
	mutex_lock(loadLock);
    }
    else
	mutex_lock(loadLock);

    sStalled = (StalledData *) kalloc(sizeof(*sStalled));
    if (sStalled) {
	sStalled->classes  = (OSMetaClass **)
			kalloc(kKModCapacityIncrement * sizeof(OSMetaClass *));
	if (!sStalled->classes) {
	    kfree(sStalled, sizeof(*sStalled));
	    return 0;
	}
	ACCUMSIZE((kKModCapacityIncrement * sizeof(OSMetaClass *)) + sizeof(*sStalled));

        sStalled->result   = kOSReturnSuccess;
	sStalled->capacity = kKModCapacityIncrement;
	sStalled->count	   = 0;
	sStalled->kmodName = kmodName;
	bzero(sStalled->classes, kKModCapacityIncrement * sizeof(OSMetaClass *));
    }

    return sStalled;
}

bool OSMetaClass::checkModLoad(void *loadHandle)
{
    return sStalled && loadHandle == sStalled
	&& sStalled->result == kOSReturnSuccess;
}

OSReturn OSMetaClass::postModLoad(void *loadHandle)
{
    OSReturn result = kOSReturnSuccess;
    OSSet *kmodSet = 0;
    OSSymbol *myname = 0;

    if (!sStalled || loadHandle != sStalled) {
	logError(kOSMetaClassInternal);
	return kOSMetaClassInternal;
    }

    if (sStalled->result)
	result = sStalled->result;
    else switch (sBootstrapState) {
    case kNoDictionaries:
	sBootstrapState = kMakingDictionaries;
	// No break; fall through

    case kMakingDictionaries:
	sKModClassesDict = OSDictionary::withCapacity(kKModCapacityIncrement);
	sAllClassesDict = OSDictionary::withCapacity(kClassCapacityIncrement);
	sSortedByClassesDict = OSDictionary::withCapacity(kClassCapacityIncrement);
	if (!sAllClassesDict || !sKModClassesDict || !sSortedByClassesDict) {
	    result = kOSMetaClassNoDicts;
	    break;
	}
	// No break; fall through

    case kCompletedBootstrap:
    {
        unsigned int i;
        myname = (OSSymbol *)OSSymbol::withCStringNoCopy(sStalled->kmodName);

	if (!sStalled->count)
	    break;	// Nothing to do so just get out

	// First pass checking classes aren't already loaded
	for (i = 0; i < sStalled->count; i++) {
	    OSMetaClass *me = sStalled->classes[i];

	    if (0 != sAllClassesDict->getObject((const char *) me->className)) {
                printf("Class \"%s\" is duplicate\n", (const char *) me->className);
                result = kOSMetaClassDuplicateClass;
                break;
            }
	}
        if (i != sStalled->count)
	    break;

	kmodSet = OSSet::withCapacity(sStalled->count);
	if (!kmodSet) {
	    result = kOSMetaClassNoKModSet;
	    break;
	}

	if (!sKModClassesDict->setObject(myname, kmodSet)) {
	    result = kOSMetaClassNoInsKModSet;
	    break;
	}

	// Second pass symbolling strings and inserting classes in dictionary
	for (i = 0; i < sStalled->count; i++) {
	    OSMetaClass *me = sStalled->classes[i];
	    me->className = 
                OSSymbol::withCStringNoCopy((const char *) me->className);

	    sAllClassesDict->setObject(me->className, me);
	    kmodSet->setObject(me);
	    sSortedByClassesDict->setObject((const OSSymbol *)me, myname);
	}
	sBootstrapState = kCompletedBootstrap;
	break;
    }

    default:
	result = kOSMetaClassInternal;
	break;
    }

    if (kmodSet)
	kmodSet->release();

	if (myname)
	myname->release();

    if (sStalled) {
	ACCUMSIZE(-(sStalled->capacity * sizeof(OSMetaClass *)
		     + sizeof(*sStalled)));
	kfree(sStalled->classes,
	      sStalled->capacity * sizeof(OSMetaClass *));
	kfree(sStalled, sizeof(*sStalled));
	sStalled = 0;
    }

    logError(result);
    mutex_unlock(loadLock);
    return result;
}


void OSMetaClass::instanceConstructed() const
{
    // if ((0 == OSIncrementAtomic((SInt32 *)&(((OSMetaClass *) this)->instanceCount))) && superClassLink)
    if ((0 == OSIncrementAtomic((SInt32 *) &instanceCount)) && superClassLink)
	superClassLink->instanceConstructed();
}

void OSMetaClass::instanceDestructed() const
{
    if ((1 == OSDecrementAtomic((SInt32 *) &instanceCount)) && superClassLink)
	superClassLink->instanceDestructed();

    if( ((int) instanceCount) < 0)
	printf("%s: bad retain(%d)", getClassName(), instanceCount);
}

bool OSMetaClass::modHasInstance(const char *kmodName)
{
    bool result = false;

    if (!loadLock) {
        loadLock = mutex_alloc(0);
	mutex_lock(loadLock);
    }
    else
	mutex_lock(loadLock);

    do {
	OSSet *kmodClasses;
	OSCollectionIterator *iter;
	OSMetaClass *checkClass;

	kmodClasses = OSDynamicCast(OSSet,
				    sKModClassesDict->getObject(kmodName));
	if (!kmodClasses)
	    break;

	iter = OSCollectionIterator::withCollection(kmodClasses);
	if (!iter)
	    break;

	while ( (checkClass = (OSMetaClass *) iter->getNextObject()) )
	    if (checkClass->getInstanceCount()) {
		result = true;
		break;
	    }

	iter->release();
    } while (false);

    mutex_unlock(loadLock);

    return result;
}

void OSMetaClass::reportModInstances(const char *kmodName)
{
    OSSet *kmodClasses;
    OSCollectionIterator *iter;
    OSMetaClass *checkClass;

    kmodClasses = OSDynamicCast(OSSet,
				 sKModClassesDict->getObject(kmodName));
    if (!kmodClasses)
	return;

    iter = OSCollectionIterator::withCollection(kmodClasses);
    if (!iter)
	return;

    while ( (checkClass = (OSMetaClass *) iter->getNextObject()) )
	if (checkClass->getInstanceCount()) {
	    printf("%s: %s has %d instance(s)\n",
		  kmodName,
		  checkClass->getClassName(),
		  checkClass->getInstanceCount());
	}

    iter->release();
}


extern "C" {

IOReturn OSMetaClassSystemSleepOrWake(UInt32 messageType)
{
    mutex_lock(loadLock);

   /* If the system is going to sleep, cancel the reaper thread timer
    * and mark unloads disabled in case it just fired but hasn't
    * taken the lock yet. If we are coming back from sleep, just
    * set unloads enabled; IOService's normal operation will cause
    * unloads to be considered soon enough.
    */
    if (messageType == kIOMessageSystemWillSleep) {
        if (unloadCallout) {
            thread_call_cancel(unloadCallout);
        }
        unloadsEnabled = false;
    } else if (messageType == kIOMessageSystemHasPoweredOn) {
        unloadsEnabled = true;
    }
    mutex_unlock(loadLock);

    return kIOReturnSuccess;
}

};

extern "C" kern_return_t kmod_unload_cache(void);

static void _OSMetaClassConsiderUnloads(__unused thread_call_param_t p0,
                                        __unused thread_call_param_t p1)
{
    OSSet *kmodClasses;
    OSSymbol *kmodName;
    OSCollectionIterator *kmods;
    OSCollectionIterator *classes;
    OSMetaClass *checkClass;
    kmod_info_t *ki = 0;
    kern_return_t ret;
    bool didUnload;

    mutex_lock(loadLock);

    if (!unloadsEnabled) {
        mutex_unlock(loadLock);
        return;
    }

    do {

	kmods = OSCollectionIterator::withCollection(sKModClassesDict);
	if (!kmods)
	    break;

        didUnload = false;
        while ( (kmodName = (OSSymbol *) kmods->getNextObject()) ) {

            if (ki) {
                kfree(ki, sizeof(kmod_info_t));
                ki = 0;
            }

            ki = kmod_lookupbyname_locked((char *)kmodName->getCStringNoCopy());
            if (!ki)
                continue;

            if (ki->reference_count) {
                 continue;
            }

            kmodClasses = OSDynamicCast(OSSet,
                                sKModClassesDict->getObject(kmodName));
            classes = OSCollectionIterator::withCollection(kmodClasses);
            if (!classes)
                continue;
    
            while ((checkClass = (OSMetaClass *) classes->getNextObject())
              && (0 == checkClass->getInstanceCount()))
                {}
            classes->release();

            if (0 == checkClass) {
                record_kext_unload(ki->id);
                OSRuntimeUnloadCPP(ki, 0);	// call destructors
                ret = kmod_destroy(host_priv_self(), ki->id);
                didUnload = true;
            }

        }

        kmods->release();

    } while (didUnload);

    mutex_unlock(loadLock);

    kmod_unload_cache();
}

void OSMetaClass::considerUnloads()
{
    AbsoluteTime when;

    mutex_lock(loadLock);

    if (!unloadCallout)
        unloadCallout = thread_call_allocate(&_OSMetaClassConsiderUnloads, 0);

    thread_call_cancel(unloadCallout);
    clock_interval_to_deadline(sConsiderUnloadDelay, 1000 * 1000 * 1000, &when);
    thread_call_enter_delayed(unloadCallout, when);

    mutex_unlock(loadLock);
}

const OSMetaClass *OSMetaClass::getMetaClassWithName(const OSSymbol *name)
{
    OSMetaClass *retMeta = 0;

    if (!name)
	return 0;

    if (sAllClassesDict)
	retMeta = (OSMetaClass *) sAllClassesDict->getObject(name);

    if (!retMeta && sStalled)
    {
	// Oh dear we have to scan the stalled list and walk the
	// the stalled list manually.
	const char *cName = name->getCStringNoCopy();
	unsigned int i;

	// find class in stalled list
	for (i = 0; i < sStalled->count; i++) {
	    retMeta = sStalled->classes[i];
	    if (0 == strcmp(cName, (const char *) retMeta->className))
		break;
	}

	if (i < sStalled->count)
	    retMeta = 0;
    }

    return retMeta;
}

OSObject *OSMetaClass::allocClassWithName(const OSSymbol *name)
{
    OSObject * result;
    mutex_lock(loadLock);

    const OSMetaClass * const meta = getMetaClassWithName(name);

    if (meta)
	result = meta->alloc();
    else
        result = 0;

    mutex_unlock(loadLock);

    return result;
}

OSObject *OSMetaClass::allocClassWithName(const OSString *name)
{
    const OSSymbol *tmpKey = OSSymbol::withString(name);
    OSObject *result = allocClassWithName(tmpKey);
    tmpKey->release();
    return result;
}

OSObject *OSMetaClass::allocClassWithName(const char *name)
{
    const OSSymbol *tmpKey = OSSymbol::withCStringNoCopy(name);
    OSObject *result = allocClassWithName(tmpKey);
    tmpKey->release();
    return result;
}


OSMetaClassBase *OSMetaClass::
checkMetaCastWithName(const OSSymbol *name, const OSMetaClassBase *in)
{
    OSMetaClassBase * result;
    mutex_lock(loadLock);
    const OSMetaClass * const meta = getMetaClassWithName(name);

    if (meta)
	result = meta->checkMetaCast(in);
    else
        result = 0;

    mutex_unlock(loadLock);
    return result;
}

OSMetaClassBase *OSMetaClass::
checkMetaCastWithName(const OSString *name, const OSMetaClassBase *in)
{
    const OSSymbol *tmpKey = OSSymbol::withString(name);
    OSMetaClassBase *result = checkMetaCastWithName(tmpKey, in);
    tmpKey->release();
    return result;
}

OSMetaClassBase *OSMetaClass::
checkMetaCastWithName(const char *name, const OSMetaClassBase *in)
{
    const OSSymbol *tmpKey = OSSymbol::withCStringNoCopy(name);
    OSMetaClassBase *result = checkMetaCastWithName(tmpKey, in);
    tmpKey->release();
    return result;
}

/*
OSMetaClass::checkMetaCast
    checkMetaCast(const OSMetaClassBase *check)

Check to see if the 'check' object has this object in it's metaclass chain.  Returns check if it is indeed a kind of the current meta class, 0 otherwise.

Generally this method is not invoked directly but is used to implement the OSMetaClassBase::metaCast member function.

See also OSMetaClassBase::metaCast

 */
OSMetaClassBase *OSMetaClass::checkMetaCast(const OSMetaClassBase *check) const
{
    const OSMetaClass * const toMeta = this;
    const OSMetaClass *fromMeta;

    for (fromMeta = check->getMetaClass(); ; fromMeta = fromMeta->superClassLink) {
	if (toMeta == fromMeta)
	    return (OSMetaClassBase *) check; // Discard const

	if (!fromMeta->superClassLink)
	    break;
    }

    return 0;
}

void OSMetaClass::reservedCalled(int ind) const
{
    const char *cname = className->getCStringNoCopy();
    panic("%s::_RESERVED%s%d called\n", cname, cname, ind);
}

const OSMetaClass *OSMetaClass::getSuperClass() const
{
    return superClassLink;
}

const OSSymbol *OSMetaClass::getKmodName() const
{	
    return (const OSSymbol *)sSortedByClassesDict->getObject((OSSymbol *)this);
}

unsigned int OSMetaClass::getInstanceCount() const
{
    return instanceCount;
}

void OSMetaClass::printInstanceCounts()
{
    OSCollectionIterator *classes;
    OSSymbol		 *className;
    OSMetaClass		 *meta;

    classes = OSCollectionIterator::withCollection(sAllClassesDict);
    if (!classes)
	return;

    while( (className = (OSSymbol *)classes->getNextObject())) {
	meta = (OSMetaClass *) sAllClassesDict->getObject(className);
	assert(meta);

	printf("%24s count: %03d x 0x%03x = 0x%06x\n",
	    className->getCStringNoCopy(),
	    meta->getInstanceCount(),
	    meta->getClassSize(),
	    meta->getInstanceCount() * meta->getClassSize() );
    }
    printf("\n");
    classes->release();
}

OSDictionary * OSMetaClass::getClassDictionary()
{
    panic("OSMetaClass::getClassDictionary(): Obsoleted\n");
    return 0;
}

bool OSMetaClass::serialize(__unused OSSerialize *s) const
{
    panic("OSMetaClass::serialize(): Obsoleted\n");
    return false;
}

void OSMetaClass::serializeClassDictionary(OSDictionary *serializeDictionary)
{
    OSDictionary *classDict;

    classDict = OSDictionary::withCapacity(sAllClassesDict->getCount());
    if (!classDict)
        return;

    mutex_lock(loadLock);
    do {
        OSCollectionIterator *classes;
        const OSSymbol *className;

        classes = OSCollectionIterator::withCollection(sAllClassesDict);
        if (!classes)
            break;
    
        while ((className = (const OSSymbol *) classes->getNextObject())) {
            const OSMetaClass *meta;
            OSNumber *count;

            meta = (OSMetaClass *) sAllClassesDict->getObject(className);
            count = OSNumber::withNumber(meta->getInstanceCount(), 32);
            if (count) {
                classDict->setObject(className, count);
                count->release();
            }
        }
        classes->release();

        serializeDictionary->setObject("Classes", classDict);
    } while (0);

    mutex_unlock(loadLock);

    classDict->release();
}
