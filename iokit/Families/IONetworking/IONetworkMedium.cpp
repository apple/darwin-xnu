/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IONetworkMedium.cpp
 *
 * HISTORY
 *
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSSerialize.h>
#include <IOKit/network/IONetworkMedium.h>

//---------------------------------------------------------------------------
// OSMetaClass macros.

#define super OSObject
OSDefineMetaClassAndStructors( IONetworkMedium, OSObject )
OSMetaClassDefineReservedUnused( IONetworkMedium,  0);
OSMetaClassDefineReservedUnused( IONetworkMedium,  1);
OSMetaClassDefineReservedUnused( IONetworkMedium,  2);
OSMetaClassDefineReservedUnused( IONetworkMedium,  3);

//---------------------------------------------------------------------------
// Initialize an IONetworkMedium instance.
//
// type:  The medium type, the fields are encoded with bits defined in
//        IONetworkMedium.h.
//
// speed: The maximum (or the only) link speed supported over this medium
//        in units of bits per second.
//
// flags: An optional flag for the medium object.
//        See IONetworkMedium.h for defined flags.
//
// index: An optional 32-bit index assigned by the caller. Drivers can use
//        this to store an index or a pointer to a media table inside the 
//        driver, or it may map to a driver defined media type.
//
// name:  An name to assign to this medium object. If 0, then a name
//        will be created based on the medium type given using nameForType().
//
// Returns true on success, false otherwise.

bool IONetworkMedium::init(IOMediumType  type,
                           UInt64        speed,
                           UInt32        flags = 0,
                           UInt32        index = 0,
                           const char *  name  = 0)
{
    if ( super::init() == false )
        return false;

    _type  = type;
    _flags = flags;
    _speed = speed;
    _index = index;

    if (name)
        _name = OSSymbol::withCString(name);
    else
        _name = IONetworkMedium::nameForType(type);

    if (!_name)
        return false;

    return true;
}

//---------------------------------------------------------------------------
// Factory method which performs allocation and initialization
// of an IONetworkMedium instance.
//
// Returns an IONetworkMedium instance on success, or 0 otherwise.

IONetworkMedium * IONetworkMedium::medium(IOMediumType  type,
                                          UInt64        speed,
                                          UInt32        flags = 0,
                                          UInt32        index = 0,
                                          const char *  name  = 0)
{
    IONetworkMedium * medium = new IONetworkMedium;
    
    if (medium && !medium->init(type, speed, flags, index, name))
    {
        medium->release();
        medium = 0;
    }

    return medium;
}

//---------------------------------------------------------------------------
// Free the IONetworkMedium instance.

void IONetworkMedium::free()
{
    if (_name)
    {
        _name->release();
        _name = 0;
    }
    super::free();
}

//---------------------------------------------------------------------------
// Return the assigned medium type.

IOMediumType IONetworkMedium::getType() const
{
    return _type;
}

//---------------------------------------------------------------------------
// Return the medium flags.

UInt32 IONetworkMedium::getFlags() const
{
    return _flags;
}

//---------------------------------------------------------------------------
// Return the maximum medium speed.

UInt64 IONetworkMedium::getSpeed() const
{
    return _speed;
}

//---------------------------------------------------------------------------
// Return the assigned index.

UInt32 IONetworkMedium::getIndex() const
{
    return _index;
}

//---------------------------------------------------------------------------
// Return the name for this instance.

const OSSymbol * IONetworkMedium::getName() const
{
    return _name;
}

//---------------------------------------------------------------------------
// Given a medium type, create an unique OSymbol name for the medium.
// The caller is responsible for releasing the OSSymbol object returned.
//
// type: A medium type. See IONetworkMedium.h for type encoding.
//
// Returns an OSSymbol created based on the type provided.

const OSSymbol * IONetworkMedium::nameForType(IOMediumType type)
{
    char  buffer[10];

    sprintf(buffer, "%08lx", type);

    // Caller must remember to free the OSSymbol!
    //
    return OSSymbol::withCString(buffer);
}

//---------------------------------------------------------------------------
// Test for equality between two IONetworkMedium objects.
// Two IONetworkMedium objects are considered equal if
// they have similar properties assigned to them during initialization.
//
// medium: An IONetworkMedium to test against the IONetworkMedium
//         object being called.
//
// Returns true if equal, false otherwise.

bool IONetworkMedium::isEqualTo(const IONetworkMedium * medium) const
{
    return ( (medium->_name  == _name)  &&
             (medium->_type  == _type)  &&
             (medium->_flags == _flags) &&
             (medium->_speed == _speed) &&
             (medium->_index == _index) );
}

//---------------------------------------------------------------------------
// Test for equality between a IONetworkMedium object and an OSObject.
// The OSObject is considered equal to the IONetworkMedium object if the 
// OSObject is an IONetworkMedium, and they have similar properties assigned
// to them during initialization.
//
// obj: An OSObject to test against the IONetworkMedium object being called.
//
// Returns true if equal, false otherwise.

bool IONetworkMedium::isEqualTo(const OSMetaClassBase * obj) const
{
    IONetworkMedium * medium;
    if ((medium = OSDynamicCast(IONetworkMedium, obj)))
        return isEqualTo(medium);
    else
        return false;
}

//---------------------------------------------------------------------------
// Create an OSData containing an IOMediumDescriptor structure (not copied), 
// and ask the OSData to serialize.
//
// s: An OSSerialize object to handle the serialization.
//
// Returns true on success, false otherwise.

static bool addNumberToDict(OSDictionary * dict,
                            const char *   key,
                            UInt32         val,
                            UInt32         bits = 32)
{
    OSNumber * num = OSNumber::withNumber(val, bits);
    bool       ret;

    if ( num == 0 ) return false;
    ret = dict->setObject( key, num );
    num->release();
    return ret;
}

bool IONetworkMedium::serialize(OSSerialize * s) const
{
    bool           ret;
    OSDictionary * dict;

    dict = OSDictionary::withCapacity(4);
    if ( dict == 0 ) return false;

    addNumberToDict(dict, kIOMediumType,  getType());
    addNumberToDict(dict, kIOMediumSpeed, getSpeed(), 64);
    addNumberToDict(dict, kIOMediumIndex, getIndex());
    addNumberToDict(dict, kIOMediumFlags, getFlags());

    ret = dict->serialize(s);
    dict->release();

    return ret;
}

//---------------------------------------------------------------------------
// A helper function to add an IONetworkMedium object to a given dictionary.
// The name of the medium is used as the key for the new dictionary entry.
//
// dict:   An OSDictionary object where the medium object should be added to.
// medium: The IONetworkMedium object to add to the dictionary.
//
// Returns true on success, false otherwise.

bool IONetworkMedium::addMedium(OSDictionary *          dict,
                                const IONetworkMedium * medium)
{
    // Arguments type checking.
    //
    if (!OSDynamicCast(OSDictionary, dict) ||
        !OSDynamicCast(IONetworkMedium, medium))
        return false;
    
    return dict->setObject(medium->getName(), medium);
}

//---------------------------------------------------------------------------
// A helper function to remove an entry in a dictionary with a key that
// matches the name of the IONetworkMedium object provided.
//
// dict:   An OSDictionary object where the medium object should be removed
//         from.
// medium: The name of this medium object is used as the removal key.

void IONetworkMedium::removeMedium(OSDictionary *          dict,
                                   const IONetworkMedium * medium)
{
    // Arguments type checking.
    //
    if (!OSDynamicCast(OSDictionary, dict) ||
        !OSDynamicCast(IONetworkMedium, medium))
        return;

    dict->removeObject(medium->getName());
}

//---------------------------------------------------------------------------
// Iterate through a dictionary and return an IONetworkMedium entry that 
// satisfies the matching criteria. Returns 0 if there is no match.

IONetworkMedium * IONetworkMedium::getMediumWithType(
                                      const OSDictionary * dict,
                                      IOMediumType         type,
                                      IOMediumType         mask = 0)
{
    OSCollectionIterator *  iter;
    OSSymbol *              key;
    IONetworkMedium *       medium;
    IONetworkMedium *       match = 0;

    if (!dict) return 0;

    // Shouldn't withCollection take an (const OSDictionary *) argument?

    iter = OSCollectionIterator::withCollection((OSDictionary *) dict);
    if (!iter)
        return 0;

    while ( (key = (OSSymbol *) iter->getNextObject()) )
    {
        medium = OSDynamicCast(IONetworkMedium, dict->getObject(key));
        if (medium == 0) continue;

        if ( ( (medium->getType() ^ type) & ~mask) == 0 )
        {
            match = medium;
            break;
        }
    }

    iter->release();

    return match;
}

IONetworkMedium * IONetworkMedium::getMediumWithIndex(
                                      const OSDictionary * dict,
                                      UInt32               index,
                                      UInt32               mask = 0)
{
    OSCollectionIterator *  iter;
    OSSymbol *              key;
    IONetworkMedium *       medium;
    IONetworkMedium *       match = 0;

    if (!dict) return 0;

    // Shouldn't withCollection take an (const OSDictionary *) argument?

    iter = OSCollectionIterator::withCollection((OSDictionary *) dict);
    if (!iter)
        return 0;

    while ( (key = (OSSymbol *) iter->getNextObject()) )
    {
        medium = OSDynamicCast(IONetworkMedium, dict->getObject(key));
        if (medium == 0) continue;

        if ( ( (medium->getIndex() ^ index) & ~mask) == 0 )
        {
            match = medium;
            break;
        }
    }

    iter->release();

    return match;
}
