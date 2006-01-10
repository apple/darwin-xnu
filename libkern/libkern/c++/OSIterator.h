/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1998-1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#ifndef _OS_OSITERATOR_H
#define _OS_OSITERATOR_H

#include <libkern/c++/OSObject.h>

/*!
    @class OSIterator
    @abstract Abstract super class for iterator classes.
    @discussion
    OSIterator is an abstract super class providing a consistent set of API's for subclasses.
*/
class OSIterator : public OSObject
{
    OSDeclareAbstractStructors(OSIterator)

public:
    /*!
        @function reset
        @abstract A pure virtual member function to be over-ridden by the subclass which reset the iterator to the beginning of the collection.
    */
    virtual void reset() = 0;

    /*!
        @function isValid
        @abstract A pure virtual member function to be over-ridden by the subclass which indicates a modification was made to the collection.
    */
    virtual bool isValid() = 0;

    /*!
        @function getNextObject
        @abstract A pure virtual function to be over-ridden by the subclass which returns a reference to the current object in the collection and advances the interator to the next object.
    */
    virtual OSObject *getNextObject() = 0;

    OSMetaClassDeclareReservedUnused(OSIterator, 0);
    OSMetaClassDeclareReservedUnused(OSIterator, 1);
    OSMetaClassDeclareReservedUnused(OSIterator, 2);
    OSMetaClassDeclareReservedUnused(OSIterator, 3);
};

#endif /* ! _OS_OSITERATOR_H */
