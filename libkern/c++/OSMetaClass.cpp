/*
 * Copyright (c) 2000-2006 Apple Inc. All rights reserved.
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
#include <libkern/c++/OSKext.h>

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
#include <IOKit/IOLib.h>

__BEGIN_DECLS

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <kern/locks.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <kern/host.h>
#include <mach/mach_interface.h>

#if PRAGMA_MARK
#pragma mark Macros
#endif /* PRAGMA_MARK */
/*********************************************************************
* Macros
*********************************************************************/
#if OSALLOCDEBUG
extern int debug_container_malloc_size;
#define ACCUMSIZE(s) do { debug_container_malloc_size += (s); } while (0)
#else
#define ACCUMSIZE(s)
#endif /* OSALLOCDEBUG */

__END_DECLS

#if PRAGMA_MARK
#pragma mark Internal constants & data structs
#endif /* PRAGMA_MARK */
/*********************************************************************
* Internal constants & data structs
*********************************************************************/
OSKextLogSpec kOSMetaClassLogSpec =
    kOSKextLogErrorLevel |
    kOSKextLogLoadFlag |
    kOSKextLogKextBookkeepingFlag;

static enum {
    kCompletedBootstrap = 0,
    kNoDictionaries     = 1,
    kMakingDictionaries = 2
} sBootstrapState = kNoDictionaries;

static const int      kClassCapacityIncrement = 40;
static const int      kKModCapacityIncrement  = 10;
static OSDictionary * sAllClassesDict;
IOLock              * sAllClassesLock = NULL;

/*
 * While loading a kext and running all its constructors to register
 * all OSMetaClass classes, the classes are queued up here. Only one
 * kext can be in flight at a time, guarded by sStalledClassesLock
 */
static struct StalledData {
    const char   * kextIdentifier;
    OSReturn       result;
    unsigned int   capacity;
    unsigned int   count;
    OSMetaClass ** classes;
} * sStalled;
IOLock * sStalledClassesLock = NULL;

#if PRAGMA_MARK
#pragma mark OSMetaClassBase
#endif /* PRAGMA_MARK */
/*********************************************************************
* OSMetaClassBase.
*********************************************************************/

/*********************************************************************
* Reserved vtable functions.
*********************************************************************/
#if SLOT_USED
void OSMetaClassBase::_RESERVEDOSMetaClassBase0()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 0); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase1()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 1); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase2()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 2); }
#endif /* SLOT_USED */

// As these slots are used move them up inside the #if above
void OSMetaClassBase::_RESERVEDOSMetaClassBase3()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 3); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase4()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 4); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase5()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 5); }
void OSMetaClassBase::_RESERVEDOSMetaClassBase6()
    { panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 6); }
    
/*********************************************************************
* These used to be inline in the header but gcc didn't believe us
* Now we MUST pull the inline out at least until the compiler is
* repaired.
*
* Helper inlines for runtime type preprocessor macros
*********************************************************************/

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClassBase::safeMetaCast(
    const OSMetaClassBase * me,
    const OSMetaClass     * toType)
{
    return (me)? me->metaCast(toType) : 0;
}

/*********************************************************************
*********************************************************************/
bool
OSMetaClassBase::checkTypeInst(
    const OSMetaClassBase * inst,
    const OSMetaClassBase * typeinst)
{
    const OSMetaClass * toType = OSTypeIDInst(typeinst);
    return typeinst && inst && (0 != inst->metaCast(toType));
}

/*********************************************************************
*********************************************************************/
void OSMetaClassBase::
initialize()
{
    sAllClassesLock = IOLockAlloc();
    sStalledClassesLock = IOLockAlloc();
}

/*********************************************************************
* If you need this slot you had better setup an IOCTL style interface.
* 'Cause the whole kernel world depends on OSMetaClassBase and YOU
* CANT change the VTABLE size ever.
*********************************************************************/
void
OSMetaClassBase::_RESERVEDOSMetaClassBase7()
{ panic("OSMetaClassBase::_RESERVEDOSMetaClassBase%d called.", 7); }

/*********************************************************************
*********************************************************************/
OSMetaClassBase::OSMetaClassBase()
{
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase::~OSMetaClassBase()
{
    void ** thisVTable;

    thisVTable = (void **) this;
    *thisVTable = (void *) -1UL;
}

/*********************************************************************
*********************************************************************/
bool
OSMetaClassBase::isEqualTo(const OSMetaClassBase * anObj) const
{
    return this == anObj;
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClassBase::metaCast(const OSMetaClass * toMeta) const
{
    return toMeta->checkMetaCast(this);
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClassBase::metaCast(const OSSymbol * toMetaSymb) const
{
    return OSMetaClass::checkMetaCastWithName(toMetaSymb, this);
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClassBase::metaCast(const OSString * toMetaStr) const
{
    const OSSymbol  * tempSymb = OSSymbol::withString(toMetaStr);
    OSMetaClassBase * ret = 0;
    if (tempSymb) {
        ret = metaCast(tempSymb);
        tempSymb->release();
    }
    return ret;
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClassBase::metaCast(const char * toMetaCStr) const
{
    const OSSymbol  * tempSymb = OSSymbol::withCString(toMetaCStr);
    OSMetaClassBase * ret = 0;
    if (tempSymb) {
        ret = metaCast(tempSymb);
        tempSymb->release();
    }
    return ret;
}

#if PRAGMA_MARK
#pragma mark OSMetaClassMeta
#endif /* PRAGMA_MARK */
/*********************************************************************
* OSMetaClassMeta - the bootstrap metaclass of OSMetaClass
*********************************************************************/
class OSMetaClassMeta : public OSMetaClass 
{
public:
    OSMetaClassMeta();
    OSObject * alloc() const;
};
OSMetaClassMeta::OSMetaClassMeta()
    : OSMetaClass("OSMetaClass", 0, sizeof(OSMetaClass))
    { }
OSObject * OSMetaClassMeta::alloc() const { return 0; }

static OSMetaClassMeta sOSMetaClassMeta;

const OSMetaClass * const OSMetaClass::metaClass = &sOSMetaClassMeta;
const OSMetaClass * OSMetaClass::getMetaClass() const
    { return &sOSMetaClassMeta; }

#if PRAGMA_MARK
#pragma mark OSMetaClass
#endif /* PRAGMA_MARK */
/*********************************************************************
* OSMetaClass
*********************************************************************/

/*********************************************************************
* Reserved functions.
*********************************************************************/
void OSMetaClass::_RESERVEDOSMetaClass0()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 0); }
void OSMetaClass::_RESERVEDOSMetaClass1()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 1); }
void OSMetaClass::_RESERVEDOSMetaClass2()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 2); }
void OSMetaClass::_RESERVEDOSMetaClass3()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 3); }
void OSMetaClass::_RESERVEDOSMetaClass4()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 4); }
void OSMetaClass::_RESERVEDOSMetaClass5()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 5); }
void OSMetaClass::_RESERVEDOSMetaClass6()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 6); }
void OSMetaClass::_RESERVEDOSMetaClass7()
    { panic("OSMetaClass::_RESERVEDOSMetaClass%d called", 7); }

/*********************************************************************
*********************************************************************/
static void
OSMetaClassLogErrorForKext(
    OSReturn   error,
    OSKext   * aKext)
{
    const char * message = NULL;

    switch (error) {
    case kOSReturnSuccess:
        return;
    case kOSMetaClassNoInit:  // xxx - never returned; logged at fail site
        message = "OSMetaClass: preModLoad() wasn't called (runtime internal error).";
        break;
    case kOSMetaClassNoDicts:
        message = "OSMetaClass: Allocation failure for OSMetaClass internal dictionaries.";
        break;
    case kOSMetaClassNoKModSet:
        message = "OSMetaClass: Allocation failure for internal kext recording set/set missing.";
        break;
    case kOSMetaClassNoInsKModSet:
        message = "OSMetaClass: Failed to record class in kext.";
        break;
    case kOSMetaClassDuplicateClass:
        message = "OSMetaClass: Duplicate class encountered.";
        break;
    case kOSMetaClassNoSuper:  // xxx - never returned
        message = "OSMetaClass: Can't associate a class with its superclass.";
        break;
    case kOSMetaClassInstNoSuper:  // xxx - never returned
        message = "OSMetaClass: Instance construction error; unknown superclass.";
        break;
    case kOSMetaClassNoKext:
        message = "OSMetaClass: Kext not found for metaclass.";
        break;
    case kOSMetaClassInternal:
    default:
        message = "OSMetaClass: Runtime internal error.";
        break;
    }

    if (message) {
        OSKextLog(aKext, kOSMetaClassLogSpec, "%s", message);
    }
    return;
}

void
OSMetaClass::logError(OSReturn error)
{
    OSMetaClassLogErrorForKext(error, NULL);
}

/*********************************************************************
* The core constructor for a MetaClass (defined with this name always
* but within the scope of its represented class).
*
* MetaClass constructors are invoked in OSRuntimeInitializeCPP(),
* in between calls to OSMetaClass::preModLoad(), which sets up for
* registration, and OSMetaClass::postModLoad(), which actually
* records all the class/kext relationships of the new MetaClasses.
*********************************************************************/
OSMetaClass::OSMetaClass(
    const char        * inClassName,
    const OSMetaClass * inSuperClass,
    unsigned int        inClassSize)
{
    instanceCount = 0;
    classSize = inClassSize;
    superClassLink = inSuperClass;

   /* Hack alert: We are just casting inClassName and storing it in
    * an OSString * instance variable. This may be because you can't
    * create C++ objects in static constructors, but I really don't know!
    */
    className = (const OSSymbol *)inClassName;

    // sStalledClassesLock taken in preModLoad
    if (!sStalled) {
       /* There's no way we can look up the kext here, unfortunately.
        */
        OSKextLog(/* kext */ NULL, kOSMetaClassLogSpec,
            "OSMetaClass: preModLoad() wasn't called for class %s "
            "(runtime internal error).",
            inClassName);
    } else if (!sStalled->result) {
        // Grow stalled array if neccessary
        if (sStalled->count >= sStalled->capacity) {
            OSMetaClass **oldStalled = sStalled->classes;
            int oldSize = sStalled->capacity * sizeof(OSMetaClass *);
            int newSize = oldSize
                + kKModCapacityIncrement * sizeof(OSMetaClass *);

            sStalled->classes = (OSMetaClass **)kalloc(newSize);
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

/*********************************************************************
*********************************************************************/
OSMetaClass::~OSMetaClass()
{
    OSKext * myKext = (OSKext *)reserved; // do not release

   /* Hack alert: 'className' is a C string during early C++ init, and
    * is converted to a real OSSymbol only when we record the OSKext in
    * OSMetaClass::postModLoad(). So only do this bit if we have an OSKext.
    * We can't safely cast or check 'className'.
    *
    * Also, release className *after* calling into the kext,
    * as removeClass() may access className.
    */
    IOLockLock(sAllClassesLock);
    if (sAllClassesDict) {
        if (myKext) {
            sAllClassesDict->removeObject(className);
        } else {
            sAllClassesDict->removeObject((char *)className);
        }
    }
    IOLockUnlock(sAllClassesLock);
    
    if (myKext) {
        if (myKext->removeClass(this) != kOSReturnSuccess) {
            // xxx - what can we do?
        }
        className->release();
    }

    // sStalledClassesLock taken in preModLoad
    if (sStalled) {
        unsigned int i;
        
       /* First pass find class in stalled list. If we find it that means
        * we started C++ init with constructors but now we're tearing down
        * because of some failure.
        */
        for (i = 0; i < sStalled->count; i++) {
            if (this == sStalled->classes[i]) {
                break;
            }
        }
        
       /* Remove this metaclass from the stalled list so postModLoad() doesn't
        * try to register it.
        */
        if (i < sStalled->count) {
            sStalled->count--;
            if (i < sStalled->count) {
                memmove(&sStalled->classes[i], &sStalled->classes[i+1],
                    (sStalled->count - i) * sizeof(OSMetaClass *));
            }
        }
    }
}

/*********************************************************************
* Empty overrides.
*********************************************************************/
void * OSMetaClass::operator new(__unused size_t size) { return 0; }
void OSMetaClass::retain() const { }
void OSMetaClass::release() const { }
void OSMetaClass::release(__unused int when) const { }
void OSMetaClass::taggedRetain(__unused const void * tag) const { }
void OSMetaClass::taggedRelease(__unused const void * tag) const { }
void OSMetaClass::taggedRelease(__unused const void * tag, __unused const int when) const { }
int  OSMetaClass::getRetainCount() const { return 0; }

/*********************************************************************
*********************************************************************/
const char *
OSMetaClass::getClassName() const
{
    if (!className) return NULL;
    return className->getCStringNoCopy();
}

/*********************************************************************
*********************************************************************/
unsigned int
OSMetaClass::getClassSize() const
{
    return classSize;
}

/*********************************************************************
*********************************************************************/
void *
OSMetaClass::preModLoad(const char * kextIdentifier)
{
    IOLockLock(sStalledClassesLock);

    assert (sStalled == NULL);
    sStalled = (StalledData *)kalloc(sizeof(* sStalled));
    if (sStalled) {
        sStalled->classes = (OSMetaClass **)
            kalloc(kKModCapacityIncrement * sizeof(OSMetaClass *));
        if (!sStalled->classes) {
            kfree(sStalled, sizeof(*sStalled));
            return 0;
        }
        ACCUMSIZE((kKModCapacityIncrement * sizeof(OSMetaClass *)) +
            sizeof(*sStalled));

        sStalled->result   = kOSReturnSuccess;
        sStalled->capacity = kKModCapacityIncrement;
        sStalled->count    = 0;
        sStalled->kextIdentifier = kextIdentifier;
        bzero(sStalled->classes, kKModCapacityIncrement * sizeof(OSMetaClass *));
    }

    // keep sStalledClassesLock locked until postModLoad
    
    return sStalled;
}

/*********************************************************************
*********************************************************************/
bool
OSMetaClass::checkModLoad(void * loadHandle)
{
    return sStalled && loadHandle == sStalled &&
        sStalled->result == kOSReturnSuccess;
}

/*********************************************************************
*********************************************************************/
OSReturn
OSMetaClass::postModLoad(void * loadHandle)
{
    OSReturn         result     = kOSReturnSuccess;
    OSSymbol       * myKextName = 0;  // must release
    OSKext         * myKext     = 0;  // must release

    if (!sStalled || loadHandle != sStalled) {
        result = kOSMetaClassInternal;
        goto finish;
    }
    
    if (sStalled->result) {
        result = sStalled->result;
    } else switch (sBootstrapState) {

        case kNoDictionaries:
            sBootstrapState = kMakingDictionaries;
            // No break; fall through
            
        case kMakingDictionaries:
            sAllClassesDict = OSDictionary::withCapacity(kClassCapacityIncrement);
            if (!sAllClassesDict) {
                result = kOSMetaClassNoDicts;
                break;
            }

        // No break; fall through

        case kCompletedBootstrap:
        {
            unsigned int i;
            myKextName = const_cast<OSSymbol *>(OSSymbol::withCStringNoCopy(
                sStalled->kextIdentifier));
            
            if (!sStalled->count) {
                break;  // Nothing to do so just get out
            }
            
            myKext = OSKext::lookupKextWithIdentifier(myKextName);
            if (!myKext) {
                result = kOSMetaClassNoKext;

               /* Log this error here so we can include the kext name.
                */
                OSKextLog(/* kext */ NULL, kOSMetaClassLogSpec,
                    "OSMetaClass: Can't record classes for kext %s - kext not found.",
                    sStalled->kextIdentifier);
                break;
            }
            
           /* First pass checking classes aren't already loaded. If any already
            * exist, we don't register any, and so we don't technically have
            * to do any C++ teardown.
            *
            * Hack alert: me->className has been a C string until now.
            * We only release the OSSymbol if we store the kext.
            */
            IOLockLock(sAllClassesLock);
            for (i = 0; i < sStalled->count; i++) {
                OSMetaClass * me = sStalled->classes[i];
                OSMetaClass * orig = OSDynamicCast(OSMetaClass,
                    sAllClassesDict->getObject((const char *)me->className));
                
                if (orig) {

                   /* Log this error here so we can include the class name.
                    * xxx - we should look up the other kext that defines the class
                    */
                    OSKextLog(myKext, kOSMetaClassLogSpec,
                        "OSMetaClass: Kext %s class %s is a duplicate;"
                        "kext %s already has a class by that name.",
                         sStalled->kextIdentifier, (const char *)me->className,
                        ((OSKext *)orig->reserved)->getIdentifierCString());
                    result = kOSMetaClassDuplicateClass;
                    break;
                }
            }
            IOLockUnlock(sAllClassesLock);
            
           /* Bail if we didn't go through the entire list of new classes
            * (if we hit a duplicate).
            */
            if (i != sStalled->count) {
                break;
            }

            // Second pass symbolling strings and inserting classes in dictionary
            IOLockLock(sAllClassesLock);
            for (i = 0; i < sStalled->count; i++) {
                OSMetaClass * me = sStalled->classes[i];
                
               /* Hack alert: me->className has been a C string until now.
                * We only release the OSSymbol in ~OSMetaClass()
                * if we set the reference to the kext.
                */
                me->className = 
                    OSSymbol::withCStringNoCopy((const char *)me->className);

                // xxx - I suppose if these fail we're going to panic soon....
                sAllClassesDict->setObject(me->className, me);
                
               /* Do not retain the kext object here.
                */
                me->reserved = (ExpansionData *)myKext;
                if (myKext) {
                    result = myKext->addClass(me, sStalled->count);
                    if (result != kOSReturnSuccess) {
                       /* OSKext::addClass() logs with kOSMetaClassNoInsKModSet. */
                        break;
                    }
                }
            }
            IOLockUnlock(sAllClassesLock);
            sBootstrapState = kCompletedBootstrap;
            break;
        }
            
        default:
            result = kOSMetaClassInternal;
            break;
    }
    
finish:
   /* Don't call logError() for success or the conditions logged above
    * or by called function.
    */
    if (result != kOSReturnSuccess &&
        result != kOSMetaClassNoInsKModSet &&
        result != kOSMetaClassDuplicateClass &&
        result != kOSMetaClassNoKext) {

        OSMetaClassLogErrorForKext(result, myKext);
    }

    OSSafeRelease(myKextName);
    OSSafeRelease(myKext);

    if (sStalled) {
        ACCUMSIZE(-(sStalled->capacity * sizeof(OSMetaClass *) +
            sizeof(*sStalled)));
        kfree(sStalled->classes, sStalled->capacity * sizeof(OSMetaClass *));
        kfree(sStalled, sizeof(*sStalled));
        sStalled = 0;
    }
    
    IOLockUnlock(sStalledClassesLock);

    return result;
}


/*********************************************************************
*********************************************************************/
void
OSMetaClass::instanceConstructed() const
{
    // if ((0 == OSIncrementAtomic(&(((OSMetaClass *) this)->instanceCount))) && superClassLink)
    if ((0 == OSIncrementAtomic(&instanceCount)) && superClassLink) {
        superClassLink->instanceConstructed();
    }
}

/*********************************************************************
*********************************************************************/
void
OSMetaClass::instanceDestructed() const
{
    if ((1 == OSDecrementAtomic(&instanceCount)) && superClassLink) {
        superClassLink->instanceDestructed();
    }

    if (((int)instanceCount) < 0) {
        OSKext * myKext = (OSKext *)reserved;

        OSKextLog(myKext, kOSMetaClassLogSpec,
            // xxx - this phrasing is rather cryptic
            "OSMetaClass: Class %s - bad retain (%d)",
            getClassName(), instanceCount);
    }
}

/*********************************************************************
*********************************************************************/
bool
OSMetaClass::modHasInstance(const char * kextIdentifier)
{
    bool     result  = false;
    OSKext * theKext = NULL;  // must release
    
    theKext = OSKext::lookupKextWithIdentifier(kextIdentifier);
    if (!theKext) {
        goto finish;
    }
    
    result = theKext->hasOSMetaClassInstances();

finish:
    OSSafeRelease(theKext);
    return result;
}

/*********************************************************************
*********************************************************************/
void
OSMetaClass::reportModInstances(const char * kextIdentifier)
{
    OSKext::reportOSMetaClassInstances(kextIdentifier,
        kOSKextLogExplicitLevel);
    return;
}

/*********************************************************************
*********************************************************************/
void
OSMetaClass::considerUnloads()
{
    OSKext::considerUnloads();
}

/*********************************************************************
*********************************************************************/
const OSMetaClass *
OSMetaClass::getMetaClassWithName(const OSSymbol * name)
{
    OSMetaClass * retMeta = 0;

    if (!name) {
        return 0;
    }

    IOLockLock(sAllClassesLock);
    if (sAllClassesDict) {
        retMeta = (OSMetaClass *) sAllClassesDict->getObject(name);
    }
    IOLockUnlock(sAllClassesLock);

    return retMeta;
}

/*********************************************************************
*********************************************************************/
OSObject *
OSMetaClass::allocClassWithName(const OSSymbol * name)
{
    OSObject * result = 0;

    const OSMetaClass * const meta = getMetaClassWithName(name);

    if (meta) {
        result = meta->alloc();
    }

    return result;
}

/*********************************************************************
*********************************************************************/
OSObject *
OSMetaClass::allocClassWithName(const OSString * name)
{
    const OSSymbol * tmpKey = OSSymbol::withString(name);
    OSObject * result = allocClassWithName(tmpKey);
    tmpKey->release();
    return result;
}

/*********************************************************************
*********************************************************************/
OSObject *
OSMetaClass::allocClassWithName(const char * name)
{
    const OSSymbol * tmpKey = OSSymbol::withCStringNoCopy(name);
    OSObject       * result = allocClassWithName(tmpKey);
    tmpKey->release();
    return result;
}


/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClass::checkMetaCastWithName(
    const OSSymbol        * name,
    const OSMetaClassBase * in)
{
    OSMetaClassBase * result = 0;

    const OSMetaClass * const meta = getMetaClassWithName(name);

    if (meta) {
        result = meta->checkMetaCast(in);
    }

    return result;
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase * OSMetaClass::
checkMetaCastWithName(
    const OSString        * name,
    const OSMetaClassBase * in)
{
    const OSSymbol  * tmpKey = OSSymbol::withString(name);
    OSMetaClassBase * result = checkMetaCastWithName(tmpKey, in);

    tmpKey->release();
    return result;
}

/*********************************************************************
*********************************************************************/
OSMetaClassBase *
OSMetaClass::checkMetaCastWithName(
    const char            * name,
    const OSMetaClassBase * in)
{
    const OSSymbol  * tmpKey = OSSymbol::withCStringNoCopy(name);
    OSMetaClassBase * result = checkMetaCastWithName(tmpKey, in);

    tmpKey->release();
    return result;
}

/*********************************************************************
 * OSMetaClass::checkMetaCast()
 * Check to see if the 'check' object has this object in its metaclass chain.
 * Returns check if it is indeed a kind of the current meta class, 0 otherwise.
 *
 * Generally this method is not invoked directly but is used to implement
 * the OSMetaClassBase::metaCast member function.
 *
 * See also OSMetaClassBase::metaCast
*********************************************************************/
OSMetaClassBase * OSMetaClass::checkMetaCast(
    const OSMetaClassBase * check) const
{
    const OSMetaClass * const toMeta   = this;
    const OSMetaClass *       fromMeta;

    for (fromMeta = check->getMetaClass(); ; fromMeta = fromMeta->superClassLink) {
        if (toMeta == fromMeta) {
            return const_cast<OSMetaClassBase *>(check); // Discard const
        }
        if (!fromMeta->superClassLink) {
            break;
        }
    }

    return 0;
}

/*********************************************************************
*********************************************************************/
void
OSMetaClass::reservedCalled(int ind) const
{
    const char * cname = className->getCStringNoCopy();
    panic("%s::_RESERVED%s%d called.", cname, cname, ind);
}

/*********************************************************************
*********************************************************************/
const
OSMetaClass *
OSMetaClass::getSuperClass() const
{
    return superClassLink;
}

/*********************************************************************
* xxx - I want to rename this :-/
*********************************************************************/
const OSSymbol *
OSMetaClass::getKmodName() const
{
    OSKext * myKext = (OSKext *)reserved;
    if (myKext) {
        return myKext->getIdentifier();
    }
    return OSSymbol::withCStringNoCopy("unknown");
}

/*********************************************************************
*********************************************************************/
unsigned int
OSMetaClass::getInstanceCount() const
{
    return instanceCount;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSMetaClass::printInstanceCounts()
{
    OSCollectionIterator * classes;
    OSSymbol             * className;
    OSMetaClass          * meta;

    IOLockLock(sAllClassesLock);
    classes = OSCollectionIterator::withCollection(sAllClassesDict);
    assert(classes);

    while( (className = (OSSymbol *)classes->getNextObject())) {
        meta = (OSMetaClass *)sAllClassesDict->getObject(className);
        assert(meta);

        printf("%24s count: %03d x 0x%03x = 0x%06x\n",
            className->getCStringNoCopy(),
            meta->getInstanceCount(),
            meta->getClassSize(),
            meta->getInstanceCount() * meta->getClassSize() );
    }
    printf("\n");
    classes->release();
    IOLockUnlock(sAllClassesLock);
    return;
}

/*********************************************************************
*********************************************************************/
OSDictionary *
OSMetaClass::getClassDictionary()
{
    panic("OSMetaClass::getClassDictionary() is obsoleted.\n");
    return 0;
}

/*********************************************************************
*********************************************************************/
bool
OSMetaClass::serialize(__unused OSSerialize * s) const
{
    panic("OSMetaClass::serialize(): Obsoleted\n");
    return false;
}

/*********************************************************************
*********************************************************************/
/* static */
void
OSMetaClass::serializeClassDictionary(OSDictionary * serializeDictionary)
{
    OSDictionary * classDict = NULL;

    IOLockLock(sAllClassesLock);

    classDict = OSDictionary::withCapacity(sAllClassesDict->getCount());
    if (!classDict) {
        goto finish;
    }

    do {
        OSCollectionIterator * classes;
        const OSSymbol * className;

        classes = OSCollectionIterator::withCollection(sAllClassesDict);
        if (!classes) {
            break;
        }
    
        while ((className = (const OSSymbol *)classes->getNextObject())) {
            const OSMetaClass * meta;
            OSNumber * count;

            meta = (OSMetaClass *)sAllClassesDict->getObject(className);
            count = OSNumber::withNumber(meta->getInstanceCount(), 32);
            if (count) {
                classDict->setObject(className, count);
                count->release();
            }
        }
        classes->release();

        serializeDictionary->setObject("Classes", classDict);
    } while (0);

finish:
    OSSafeRelease(classDict);

    IOLockUnlock(sAllClassesLock);

    return;
}
