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
/* OSSerialize.h created by rsulack on Wen 25-Nov-1998 */

#ifndef _OS_OSSERIALIZE_H
#define _OS_OSSERIALIZE_H

#include <libkern/c++/OSObject.h>

class OSSet;
class OSDictionary;

/*!
    @class OSSerialize
    @abstract A class used by the OS Container classes to serialize their instance data.
    @discussion This class is for the most part internal to the OS Container classes and should not be used directly.  Each class inherits a serialize() method from OSObject which is used to actually serialize an object.
*/

class OSSerialize : public OSObject
{
    OSDeclareDefaultStructors(OSSerialize)

protected:
    char *data;			// container for serialized data
    unsigned int length;		// of serialized data (counting NULL)
    unsigned int capacity;		// of container
    unsigned int capacityIncrement;	// of container

    unsigned int tag;
    OSDictionary *tags;		// tags for all objects seen

    struct ExpansionData { };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;


public:
    static OSSerialize *withCapacity(unsigned int capacity);

    virtual char *text() const;

    virtual void clearText();	// using this can be a great speedup
                                    // if you are serializing the same object
                                    // over and over again

    // stuff to serialize your object
    virtual bool previouslySerialized(const OSMetaClassBase *);

    virtual bool addXMLStartTag(const OSMetaClassBase *o, const char *tagString);
    virtual bool addXMLEndTag(const char *tagString);

    virtual bool addChar(const char);
    virtual bool addString(const char *);

    // stuff you should never have to use (in theory)

    virtual bool initWithCapacity(unsigned int inCapacity);
    virtual unsigned int getLength() const;
    virtual unsigned int getCapacity() const;
    virtual unsigned int getCapacityIncrement() const;
    virtual unsigned int setCapacityIncrement(unsigned increment);
    virtual unsigned int ensureCapacity(unsigned int newCapacity);
    virtual void free();

    OSMetaClassDeclareReservedUnused(OSSerialize, 0);
    OSMetaClassDeclareReservedUnused(OSSerialize, 1);
    OSMetaClassDeclareReservedUnused(OSSerialize, 2);
    OSMetaClassDeclareReservedUnused(OSSerialize, 3);
    OSMetaClassDeclareReservedUnused(OSSerialize, 4);
    OSMetaClassDeclareReservedUnused(OSSerialize, 5);
    OSMetaClassDeclareReservedUnused(OSSerialize, 6);
    OSMetaClassDeclareReservedUnused(OSSerialize, 7);
};

typedef bool (*OSSerializerCallback)(void * target, void * ref,
                                     OSSerialize * s);

class OSSerializer : public OSObject
{
    OSDeclareDefaultStructors(OSSerializer)

    void * target;
    void * ref;
    OSSerializerCallback callback;
    
public:

    static OSSerializer * forTarget(void * target,
                                OSSerializerCallback callback, void * ref = 0);

    virtual bool serialize(OSSerialize * s) const;
};

#endif /* _OS_OSSERIALIZE_H */
