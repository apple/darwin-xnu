/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/* OSBoolean.cpp created by rsulack on Tue Oct 12 1999 */

#ifndef _OS_OSBOOLEAN_H
#define _OS_OSBOOLEAN_H

#include <libkern/c++/OSObject.h>

class OSString;

/*!
    @class OSBoolean
    @abstract Container class for boolean values.
*/
class OSBoolean : public OSObject
{
    OSDeclareDefaultStructors(OSBoolean)

protected:
    bool value;

    /*D @function taggedRelease
	@abstract Override tagged release mechanism.
	@param when Unused. */
    virtual void taggedRelease(const void *tag, const int when) const;

public:
    static void initialize();

    /*D
        @function withBoolean
        @abstract A static constructor function to create and initialize an instance of OSBoolean.
        @param value A boolean value.
        @result Returns and instance of OSBoolean, or 0 if an error occurred.
    */
    static OSBoolean *withBoolean(bool value);

    /*D
        @function free
        @abstract A member function to release all resources used by the OSBoolean instance.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*D @function taggedRetain
	@abstract Override tagged retain mechanism. */
    virtual void taggedRetain(const void *tag) const;

    /*!
        @function isTrue
        @abstract A member function to test if the boolean object is true.
        @result Returns true if the OSBoolean object is true, false otherwise.
    */
    virtual bool isTrue() const;
    /*!
        @function isFalse
        @abstract A member function to test if the boolean object is false.
        @result Returns true if the OSBoolean object is false, false otherwise.
    */
    virtual bool isFalse() const;

    /*!
        @function getValue
        @abstract Obtains the value of the OSBoolean object as the standard C++ type bool.
        @result The value of the OSBoolean object. 
    */
    virtual bool getValue() const;

    /*!
        @function isEqualTo
        @abstract A member function to test the equality of two OSBoolean objects.
        @param boolean An OSBoolean object to be compared against the receiver.
        @result Returns true if the two objects are equivalent.
    */
    virtual bool isEqualTo(const OSBoolean *boolean) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality between an arbitrary OSObject derived object and an OSBoolean object.
        @param obj An OSObject derived object to be compared against the receiver.
        @result Returns true if the two objects are equivalent.
    */
    virtual bool isEqualTo(const OSMetaClassBase *obj) const;

    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;

    OSMetaClassDeclareReservedUnused(OSBoolean, 0);
    OSMetaClassDeclareReservedUnused(OSBoolean, 1);
    OSMetaClassDeclareReservedUnused(OSBoolean, 2);
    OSMetaClassDeclareReservedUnused(OSBoolean, 3);
    OSMetaClassDeclareReservedUnused(OSBoolean, 4);
    OSMetaClassDeclareReservedUnused(OSBoolean, 5);
    OSMetaClassDeclareReservedUnused(OSBoolean, 6);
    OSMetaClassDeclareReservedUnused(OSBoolean, 7);
};

/*!
    @defined kOSBooleanTrue
    @abstract The OSBoolean constant for "true".
    @discussion The OSBoolean constant for "true".  The object does not need to be retained or released.  Comparisons of the form (booleanObject == kOSBooleanTrue) are acceptable and would be equivalent to (booleanObject->getValue() == true).
*/
extern OSBoolean * const & kOSBooleanTrue;

/*!
    @defined kOSBooleanFalse
    @abstract The OSBoolean constant for "false".
    @discussion The OSBoolean constant for "false".  The object does not need to be retained or released.  Comparisons of the form (booleanObject == kOSBooleanFalse) are acceptable and would be equivalent to (booleanObject->getValue() == false).
*/
extern OSBoolean * const & kOSBooleanFalse;

#endif /* !_OS_OSBOOLEAN_H */
