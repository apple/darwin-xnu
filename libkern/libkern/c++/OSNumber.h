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
/* IOOffset.h created by rsulack on Wed 17-Sep-1997 */
/* IOOffset.h converted to C++ by gvdl on Fri 1998-10-30 */

#ifndef _OS_OSNUMBER_H
#define _OS_OSNUMBER_H

#include <libkern/c++/OSObject.h>

/*!
    @class OSNumber
    @abstract A container class for numeric values.
*/
class OSNumber : public OSObject
{
    OSDeclareDefaultStructors(OSNumber)

protected:
    unsigned long long value;
    unsigned int size;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

public:
    /*!
        @function withNumber
        @abstract A static constructor function to create and initialize an instance of OSNumber with a given value.
        @param value The numeric integer value.
        @param numberOfBits The number of bit required to represent the value.
        @result Returns an instance of OSNumber or 0 if an error occurred.
    */
    static OSNumber *withNumber(unsigned long long value,
                            unsigned int numberOfBits);
    /*!
        @function withNumber
        @abstract A static constructor function to create and initialize an instance of OSNumber with a given value represented as a simple c-string.
        @param value A c-string representing a numeric value.
        @param numberOfBits The number of bit required to represent the value.
        @result Returns an instance of OSNumber or 0 if an error occurred.
    */
    static OSNumber *withNumber(const char *value, unsigned int numberOfBits);

    /*!
        @function init
        @abstract A member function to initialize an instance of OSNumber.
        @param value An integer value.
        @param numberOfBits The number of bit required to represent the value.
        @result Returns true if instance was successfully initialized, false otherwise.
    */
    virtual bool init(unsigned long long value, unsigned int numberOfBits);
    /*!
        @function init
        @abstract A member function to initialize an instance of OSNumber.
        @param value A c-string representation of a numeric value.
        @param numberOfBits The number of bit required to represent the value.
        @result Returns true if instance was successfully initialized, false otherwise.
    */
    virtual bool init(const char *value, unsigned int numberOfBits);
    /*!
        @function free
        @abstract Releases and deallocates resources created by the OSNumber instances.
        @discussion This function should not be called directly, use release() instead.
    */
    virtual void free();

    /*!
        @function numberOfBits
        @abstract A member function which returns the number of bits used to represent the value.
        @result Returns the number of bits required to represent the value.
    */
    virtual unsigned int numberOfBits() const;
    /*!
        @function numberOfBytes
        @abstract A member function which returns the number of bytes used to represent the value.
        @result Returns the number of bytes required to represent the value.
    */
    virtual unsigned int numberOfBytes() const;

    /*!
        @function unsigned8BitValue
        @abstract A member function which returns its internal value as an 8-bit value.
        @result Returns the internal value as an 8-bit value.
    */
    virtual unsigned char unsigned8BitValue() const;
    /*!
        @function unsigned16BitValue
        @abstract A member function which returns its internal value as an 16-bit value.
        @result Returns the internal value as an 16-bit value.
    */
    virtual unsigned short unsigned16BitValue() const;
    /*!
        @function unsigned32BitValue
        @abstract A member function which returns its internal value as an 32-bit value.
        @result Returns the internal value as an 32-bit value.
    */
    virtual unsigned int unsigned32BitValue() const;
    /*!
        @function unsigned64BitValue
        @abstract A member function which returns its internal value as an 64-bit value.
        @result Returns the internal value as an 64-bit value.
    */
    virtual unsigned long long unsigned64BitValue() const;

    /*!
        @function addValue
        @abstract A member function which adds an integer value to the internal numeric value of the OSNumber object.
        @param value The value to be added.
    */
    virtual void addValue(signed long long value);
    /*!
        @function setValue
        @abstract Replaces the current internal numeric value of the OSNumber object by the value given.
        @param value The new value for the OSNumber object.
    */
    virtual void setValue(unsigned long long value);

    /*!
        @function isEqualTo
        @abstract A member function to test the equality of two OSNumber objects.
        @param integer The OSNumber object to be compared against the receiver.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSNumber *integer) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of an arbitrary OSObject derived object and an OSNumber object.
        @param obj The OSObject derived object to be compared to the receiver.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSMetaClassBase *obj) const;

    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;


    OSMetaClassDeclareReservedUnused(OSNumber, 0);
    OSMetaClassDeclareReservedUnused(OSNumber, 1);
    OSMetaClassDeclareReservedUnused(OSNumber, 2);
    OSMetaClassDeclareReservedUnused(OSNumber, 3);
    OSMetaClassDeclareReservedUnused(OSNumber, 4);
    OSMetaClassDeclareReservedUnused(OSNumber, 5);
    OSMetaClassDeclareReservedUnused(OSNumber, 6);
    OSMetaClassDeclareReservedUnused(OSNumber, 7);
};

#endif /* !_OS_OSNUMBER_H */
