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
/* IOString.h created by rsulack on Wed 17-Sep-1997 */
/* IOString.h converted to C++ by gvdl on Fri 1998-10-30 */

#ifndef _OS_OSSTRING_H
#define _OS_OSSTRING_H

#include <libkern/c++/OSObject.h>

class OSData;

enum { kOSStringNoCopy = 0x00000001 };

/*!
    @class OSString
    @abstract A container class for managing strings.
    @discussion
    OSString is a container class for managing arrays of characters.  Strings come in two varieties, mutable and immutable.  An immutable OSString string is one which was created or initialized with the "NoCopy" functions, all other strings are mutable.  When modifying an immutable string, the function called to perform the action will fail.
*/
class OSString : public OSObject
{
    OSDeclareDefaultStructors(OSString)

protected:
    unsigned int    flags;
    unsigned int    length;
    char	   *string;

public:
    /*!
        @function withString
        @abstract Static constructor function to create and initialize an instance of OSString from another OSString.
        @param aString An OSString object.
        @result Returns an instance of OSString or 0 on error.
    */
    static OSString *withString(const OSString *aString);
    /*!
        @function withCString
        @abstract Static constructor function to create and initialize an instance of OSString.
        @param cString A simple c-string.
        @result Returns an instance of OSString or 0 on error.
    */
    static OSString *withCString(const char *cString);
    /*!
        @function withCStringNoCopy
        @abstract Static constructor function to create and initialize an instance of OSString but does not copy the original c-string into container.
        @param cString A simple c-string.
        @result Returns an instance of OSString or 0 on error.
    */
    static OSString *withCStringNoCopy(const char *cString);

    /*!
        @function initWithString
        @abstract Member function to initialize an instance of OSString from another OSString object.
        @param aString An OSString object.
        @result Returns true on success, false otherwise.
    */
    virtual bool initWithString(const OSString *aString);
    /*!
        @function initWithCString
        @abstract Member function to initialize an instance of OSString with a simple c-string.
        @param cString A simple c-string.
        @result Returns true on success, false otherwise.
    */
    virtual bool initWithCString(const char *cString);
    /*!
        @function initWithCStringNoCopy
        @abstract Member function to initialize an instance of OSString with a simple c-string but does not copy the string into the container.
        @param cString A simple c-string.
        @result Returns true on success, false otherwise.
    */
    virtual bool initWithCStringNoCopy(const char *cString);
    /*!
        @function free
        @abstract Releases all resources used by the OSString object.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*!
        @function getLength
        @abstract A member function to return the length of the string.
        @result Returns the length of the string.
    */
    virtual unsigned int getLength() const;
    /*!
        @function getChar
        @abstract Returns a character at a particular index in the string object.
        @param index The index into the string.
        @result Returns a character.
    */
    virtual char getChar(unsigned int index) const;
    /*!
        @function setChar
        @abstract Replaces a character at a particular index in the string object.
        @param index The index into the string.
        @result Returns true if the character was successfully replaced or false if the string is immutable or index was beyond the bounds of the character array.
    */
    virtual bool setChar(char aChar, unsigned int index);

    /*!
        @function getCStringNoCopy
        @abstract Returns a pointer to the internal c-string array.
        @result Returns a pointer to the internal c-string array.
    */
    virtual const char *getCStringNoCopy() const;

    /*!
        @function isEqualTo
        @abstract A member function to test the equality of two OSString objects.
        @param aString An OSString object.
        @result Returns true if the two strings are equal, false otherwise.
    */
    virtual bool isEqualTo(const OSString *aString) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of c-string and the internal string array of the receiving OSString object.
        @param aCString A simple c-string.
        @result Returns true if the two strings are equal, false otherwise.
    */
    virtual bool isEqualTo(const char *aCString) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of an unknown OSObject derived object and the OSString instance.
        @param obj An OSObject derived object.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSMetaClassBase *obj) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of an unknown OSData object and the OSString instance.
        @param obj An OSData object.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSData *obj) const;

    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;

    OSMetaClassDeclareReservedUnused(OSString,  0);
    OSMetaClassDeclareReservedUnused(OSString,  1);
    OSMetaClassDeclareReservedUnused(OSString,  2);
    OSMetaClassDeclareReservedUnused(OSString,  3);
    OSMetaClassDeclareReservedUnused(OSString,  4);
    OSMetaClassDeclareReservedUnused(OSString,  5);
    OSMetaClassDeclareReservedUnused(OSString,  6);
    OSMetaClassDeclareReservedUnused(OSString,  7);
    OSMetaClassDeclareReservedUnused(OSString,  8);
    OSMetaClassDeclareReservedUnused(OSString,  9);
    OSMetaClassDeclareReservedUnused(OSString, 10);
    OSMetaClassDeclareReservedUnused(OSString, 11);
    OSMetaClassDeclareReservedUnused(OSString, 12);
    OSMetaClassDeclareReservedUnused(OSString, 13);
    OSMetaClassDeclareReservedUnused(OSString, 14);
    OSMetaClassDeclareReservedUnused(OSString, 15);
};

#endif /* !_OS_OSSTRING_H */
