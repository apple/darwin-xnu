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
/*
Copyright (c) 1998 Apple Computer, Inc.	 All rights reserved.
HISTORY
    1998-10-30	Godfrey van der Linden(gvdl)
	Created
*/
#ifndef _LIBKERN_OSOBJECT_H
#define _LIBKERN_OSOBJECT_H

#include <libkern/c++/OSMetaClass.h>

class OSSymbol;
class OSString;
/*!
    @class OSObject : OSMetaClassBase
    @abstract The root base class for Mac OS X kernel and just generally all-round useful class to have around.
    @discussion
Defines the minimum functionality that an object can expect.  Implements reference counting, type safe object casting, allocation primitives & serialisation among other functionality.	 This object is an abstract base class and can not be copied, nor can it be constructed by itself.

<br><br> Construction <br><br>

As Mac OS X's C++ is based upon Embedded C++ we have a problem with the typical C++ method of using constructors.  Embedded C++ does not allow exceptions.  This means that the standard constructors can not report a failure.  Well obviously initialisation of a new object can fail so we have had to work around this language limitation.  In the Mac OS X kernel we have chosen to break object construction into two phases.  Phase one is the familiar C++ new operator, the only initialisation is the object has exactly one reference after creation.  Once the new is called the client MUST call init and check it's return value.  If the init call fails then the object MUST be immediately released.  IOKit usually implements factory methods to make construction a one step process for clients.  

<br><br>Reference Counting<br><br>

OSObject provides reference counting services using the $link retain(), $link release(), $link release(int when) and $link free() functions.  The public interface to the reference counting is retain() & release().  release() is implemented as a simple call to release(1).  The actual implementation of release(when) is a little subtle.  If the current reference count is less than or equal to the 'when' parameter the object will call free on itself.  
<br>
In general a subclass is expected to only override $link free().  It may also choose to override release() if the object has a circular retain count, see $link release(int when);

<br><br>Runtime Type Information System<br><br>

The Mac OS X C++ implements a basic runtime type information system using meta class information and a number of macros, $link OSDynamicCast, $link OSTypeID, $link OSTypeIDInst, $link OSCheckTypeInst and $link OSMetaClass.
*/
class OSObject : public OSMetaClassBase
{
    OSDeclareAbstractStructors(OSObject)

private:
/*! @var retainCount Number of references held on this instance. */
    mutable int retainCount;

protected:

/*! @function release
    @abstract Primary implementation of the release mechanism.
    @discussion  If $link retainCount <= the when argument then call $link free().  This indirect implementation of $link release allows the developer to break reference circularity.  An example of this sort of problem is a parent/child mutual reference, either the parent or child can implement: void release() { release(2); } thus breaking the cirularity. 
    @param when When retainCount == when then call free(). */
    virtual void release(int when) const;

/*! @function init
    @abstract Mac OS X kernel's primary mechanism for constructing objects.
    @discussion Your responsibility as a subclass author is to override the init method of your parent.  In general most of our implementations call <super>::init() before doing local initialisation, if the parent fails then return false immediately.  If you have a failure during you local initialisation then return false.
    @result OSObject::init Always returns true, but subclasses will return false on init failure.
*/
    virtual bool init();

/*! @function free
    @abstract The last reference is gone so clean up your resources.
    @discussion Release all resources held by the object, then call your parent's free().  

<br><br>Caution:
<br>1> You can not assume that you have completed initialization before your free is called, so be very careful in your implementation.  
<br>2> The implementation is OSObject::free() { delete this; } so do not call super::free() until just before you return.
<br>3> Free is not allowed to fail all resource must be released on completion. */
    virtual void free();

/*! @function operator delete
    @abstract Release the 'operator new'ed memory.
    @discussion Never attempt to delete an object that inherits from OSObject directly use $link release().
    @param mem pointer to block of memory
    @param size size of block of memory
*/
    static void operator delete(void *mem, size_t size);

public:

/*! @function operator new
    @abstract Allocator for all objects that inherit from OSObject
    @param size number of bytes to allocate
    @result returns pointer to block of memory if available, 0 otherwise.
*/
    static void *operator new(size_t size);

/*! @function getRetainCount
    @abstract How many times has this object been retained?
    @result Current retain count
*/
    virtual int getRetainCount() const;

/*! @function retain
    @abstract Retain a reference in this object.
*/
    virtual void retain() const;

/*! @function release
    @abstract Release a reference to this object
*/
    virtual void release() const;

/*! @function serialize
    @abstract 
    @discussion 
    @param s
    @result 
*/
    virtual bool serialize(OSSerialize *s) const;

    // Unused Padding
    OSMetaClassDeclareReservedUnused(OSObject,  0);
    OSMetaClassDeclareReservedUnused(OSObject,  1);
    OSMetaClassDeclareReservedUnused(OSObject,  2);
    OSMetaClassDeclareReservedUnused(OSObject,  3);
    OSMetaClassDeclareReservedUnused(OSObject,  4);
    OSMetaClassDeclareReservedUnused(OSObject,  5);
    OSMetaClassDeclareReservedUnused(OSObject,  6);
    OSMetaClassDeclareReservedUnused(OSObject,  7);
    OSMetaClassDeclareReservedUnused(OSObject,  8);
    OSMetaClassDeclareReservedUnused(OSObject,  9);
    OSMetaClassDeclareReservedUnused(OSObject, 10);
    OSMetaClassDeclareReservedUnused(OSObject, 11);
    OSMetaClassDeclareReservedUnused(OSObject, 12);
    OSMetaClassDeclareReservedUnused(OSObject, 13);
    OSMetaClassDeclareReservedUnused(OSObject, 14);
    OSMetaClassDeclareReservedUnused(OSObject, 15);
    OSMetaClassDeclareReservedUnused(OSObject, 16);
    OSMetaClassDeclareReservedUnused(OSObject, 17);
    OSMetaClassDeclareReservedUnused(OSObject, 18);
    OSMetaClassDeclareReservedUnused(OSObject, 19);
    OSMetaClassDeclareReservedUnused(OSObject, 20);
    OSMetaClassDeclareReservedUnused(OSObject, 21);
    OSMetaClassDeclareReservedUnused(OSObject, 22);
    OSMetaClassDeclareReservedUnused(OSObject, 23);
    OSMetaClassDeclareReservedUnused(OSObject, 24);
    OSMetaClassDeclareReservedUnused(OSObject, 25);
    OSMetaClassDeclareReservedUnused(OSObject, 26);
    OSMetaClassDeclareReservedUnused(OSObject, 27);
    OSMetaClassDeclareReservedUnused(OSObject, 28);
    OSMetaClassDeclareReservedUnused(OSObject, 29);
    OSMetaClassDeclareReservedUnused(OSObject, 30);
    OSMetaClassDeclareReservedUnused(OSObject, 31);
};

#endif /* !_LIBKERN_OSOBJECT_H */
