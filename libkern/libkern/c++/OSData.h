/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* IOData.h created by rsulack on Wed 17-Sep-1997 */
/* IOData.h converted to C++ by gvdl on Fri 1998-10-30 */

#ifndef _OS_OSDATA_H
#define _OS_OSDATA_H

#include <libkern/c++/OSObject.h>

class OSString; 

/*!
    @class OSData
    @abstract A container class to manage an array of bytes.
*/
class OSData : public OSObject
{
    OSDeclareDefaultStructors(OSData)

protected:
    void 	*data;
    unsigned int length;
    unsigned int capacity;
    unsigned int capacityIncrement;

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

public:
    /*!
        @function withCapacity
        @abstract A static constructor function to create and initialize an empty instance of OSData with a given capacity.
        @param inCapacity The initial capacity of the OSData object in bytes.
        @result Returns an instance of OSData or 0 if a failure occurs.
    */
    static OSData *withCapacity(unsigned int inCapacity);
    /*!
        @function withBytes
        @abstract A static constructor function to create and initialize an instance of OSData and copies in the provided data.
        @param bytes A buffer of data.
        @param inLength The size of the given buffer.
        @result Returns an instance of OSData or 0 if a failure occurs.
    */
    static OSData *withBytes(const void *bytes, unsigned int inLength);
    /*!
        @function withBytesNoCopy
        @abstract A static constructor function to create and initialize an instance of OSData which references a buffer of data.
        @param bytes A reference to a block of data.
        @param inLength The size of the data block.
        @result Returns an instance of OSData or 0 if a failure occurs.
    */
    static OSData *withBytesNoCopy(void *bytes, unsigned int inLength);
    /*!
        @function withData
        @abstract A static constructor function to create and initialize an instance of OSData with the data provided.
        @param inData An OSData object which provides the initial data.
        @result Returns an instance of OSData or 0 if a failure occurs.
    */
    static OSData *withData(const OSData *inData);
    /*!
        @function withData
        @abstract A static constructor function to create and initialize an instance of OSData with a specific range of the data provided.
        @param inData An OSData object which provides the initial data.
        @param start The starting index at which the data will be copied.
        @param inLength The number of bytes to be copied starting at index 'start'.
        @result Returns an instance of OSData or 0 if a failure occurs.
    */
    static OSData *withData(const OSData *inData,
                                unsigned int start, unsigned int inLength);

    /*!
        @function initWithCapacity
        @abstract A member function to initialize an instance of OSData with a minimum capacity of at least the given size.  If this function is called an an object that has been previously used then the length is set down to 0 and a new block of data is allocated if necessary to ensure the given capacity.
        @param capacity The length of the allocated block of data.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initWithCapacity(unsigned int capacity);
    /*!
        @function initWithBytes
        @abstract A member function to initialize an instance of OSData which references a block of data.
        @param bytes A reference to a block of data
        @param inLength The length of the block of data.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initWithBytes(const void *bytes, unsigned int inLength);
    /*!
        @function initWithBytes
        @abstract A member function to initialize an instance of OSData which references a block of data.
        @param bytes A reference to a block of data
        @param inLength The length of the block of data.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initWithBytesNoCopy(void *bytes, unsigned int inLength);
    /*!
        @function initWithData
        @abstract A member function to initialize an instance of OSData with the data provided.
        @param inData An OSData object which provides the data to be copied.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initWithData(const OSData *inData);
    /*!
        @function initWithData
        @abstract A member function to initialize an instance of OSData with a specific range of the data provided
        @param inData An OSData object.
        @param start The starting range of data to be copied.
        @param inLength The length in bytes of the data to be copied.
        @result Returns true if initialization was successful, false otherwise.
    */
    virtual bool initWithData(const OSData *inData,
                              unsigned int start, unsigned int inLength);
    /*!
        @function free
        @abstract A member function which releases all resources created or used by the OSData object.
        @discussion Do not call this function directly, use release() instead.
    */
    virtual void free();

    /*!
        @function getLength
        @abstract A member function which returns the length of the internal data buffer.
        @result Returns an integer value for the length of data in the object's internal data buffer.
    */
    virtual unsigned int getLength() const;
    /*!
        @function getCapacity
        @abstract A member function which returns the capacity of the internal data buffer.
        @result Returns an integer value for the size of the object's internal data buffer.
    */
    virtual unsigned int getCapacity() const;
    /*!
        @function getCapacityIncrement
        @abstract A member function which returns the size by which the data buffer will grow.
        @result Returns the size by which the data buffer will grow.
    */
    virtual unsigned int getCapacityIncrement() const;
    /*!
        @function setCapacityIncrement
        @abstract A member function which sets the growth size of the data buffer.
        @result Returns the new growth size.
    */
    virtual unsigned int setCapacityIncrement(unsigned increment);
    /*!
        @function ensureCapacity
        @abstract A member function which will expand the size of the collection to a given storage capacity.
        @param newCapacity The new capacity for the data buffer.
        @result Returns the new capacity of the data buffer or the previous capacity upon error.
    */
    virtual unsigned int ensureCapacity(unsigned int newCapacity);
    /*!
        @function appendBytes
        @abstract A member function which appends a buffer of data onto the end of the object's internal data buffer.
        @param bytes A pointer to the block of data.  If the value is 0 then append zero-ed memory to the data object.
        @param inLength The length of the data block.
        @result Returns true if the object was able to append the new data, false otherwise.
    */
    virtual bool appendBytes(const void *bytes, unsigned int inLength);
    /*!
        @function appendBytes
        @abstract A member function which appends the data contained in an OSData object to the receiver.
        @param other An OSData object.
        @result Returns true if appending the new data was successful, false otherwise.
    */
    virtual bool appendBytes(const OSData *other);

    /*!
        @function getBytesNoCopy
        @abstract A member function to return a pointer to the OSData object's internal data buffer.
        @result Returns a reference to the OSData object's internal data buffer.
    */
    virtual const void *getBytesNoCopy() const;
    /*!
        @function getBytesNoCopy
        @abstract Returns a reference into the OSData object's internal data buffer at particular offset and with a particular length.
        @param start The offset from the base of the internal data buffer.
        @param inLength The length of window.
        @result Returns a pointer at a particular offset into the data buffer, or 0 if the starting offset or length are not valid.
    */
    virtual const void *getBytesNoCopy(unsigned int start,
                                       unsigned int inLength) const;

    /*!
        @function isEqualTo
        @abstract A member function to test the equality of two OSData objects.
        @param aData The OSData object to be compared to the receiver.
        @result Returns true if the two objects are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const OSData *aData) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality of an arbitrary block of data with the OSData object's internal data buffer.
        @param someData A pointer to a block of data.
        @param inLength The length of the block of data.
        @result Returns true if the two blocks of data are equivalent, false otherwise.
    */
    virtual bool isEqualTo(const void *someData, unsigned int inLength) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality between an OSData object and an arbitrary OSObject derived object.
        @param obj An OSObject derived object.
        @result Returns true if the two objects are equivalent.
    */
    virtual bool isEqualTo(const OSMetaClassBase *obj) const;
    /*!
        @function isEqualTo
        @abstract A member function to test the equality between an OSData object and an OSString object.
        @param obj An OSString object
        @result Returns true if the two objects are equivalent.
    */
    virtual bool isEqualTo(const OSString *obj) const;
    /*!
        @function serialize
        @abstract A member function which archives the receiver.
        @param s The OSSerialize object.
        @result Returns true if serialization was successful, false if not.
    */
    virtual bool serialize(OSSerialize *s) const;

    /*!
        @function appendByte
        @abstract A member function which appends a buffer of constant data onto the end of the object's internal data buffer.
        @param byte A byte value to replicate as the added data.
        @param inCount The length of the data to add.
        @result Returns true if the object was able to append the new data, false otherwise.
    */
    virtual bool appendByte(unsigned char byte, unsigned int inCount);



private:
    OSMetaClassDeclareReservedUnused(OSData, 0);
    OSMetaClassDeclareReservedUnused(OSData, 1);
    OSMetaClassDeclareReservedUnused(OSData, 2);
    OSMetaClassDeclareReservedUnused(OSData, 3);
    OSMetaClassDeclareReservedUnused(OSData, 4);
    OSMetaClassDeclareReservedUnused(OSData, 5);
    OSMetaClassDeclareReservedUnused(OSData, 6);
    OSMetaClassDeclareReservedUnused(OSData, 7);
};

#endif /* !_OS_OSDATA_H */
