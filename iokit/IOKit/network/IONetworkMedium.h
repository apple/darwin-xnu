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
 * IONetworkMedium.h
 *
 * HISTORY
 *
 */

#ifndef _IONETWORKMEDIUM_H
#define _IONETWORKMEDIUM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <net/if_media.h>

/*! @typedef IOMediumType
    @discussion A 32-bit value divided into fields which describes
    a single medium type. */

typedef UInt32 IOMediumType;

/*! @defined kIOMediumType
    @abstract kIOMediumType is a property of IONetworkMedium objects.
        It is an OSNumber object.
    @discussion The kIOMediumType property describes the type of
        medium that this object represents. */

#define kIOMediumType           "Type"

/*! @defined kIOMediumFlags
    @abstract kIOMediumFlags is a property of IONetworkMedium objects.
        It is an OSNumber object.
    @discussion The kIOMediumFlags property describes a set of
        attributes assigned to the medium. */

#define kIOMediumFlags          "Flags"

/*! @defined kIOMediumSpeed
    @abstract kIOMediumSpeed is a property of IONetworkMedium objects.
        It is an OSNumber object.
    @discussion The kIOMediumSpeed property describes the maximum link
        speed supported by the medium in bits per second. */

#define kIOMediumSpeed          "Speed"

/*! @defined kIOMediumIndex
    @abstract kIOMediumIndex is a property of IONetworkMedium objects.
        It is an OSNumber object.
    @discussion The kIOMediumIndex property describes an index assigned
        by the owner of the medium object. Its interpretation is driver
        specific. */

#define kIOMediumIndex          "Index"

//===========================================================================
// Medium Type (IOMediumType).
//
// The medium type is encoded by a 32-bit value. The definitions of
// the fields and the encoding for each field is adapted from FreeBSD.
//
// Bits     Definition
// -------------------
//  4-0     medium subtype
//  7-5     network type
// 15-8     network specific options
// 19-16    reserved
// 27-20    common options
// 31-28    instance number

// Ethernet.
//
enum {
    kIOMediumEthernet             =  IFM_ETHER,
    kIOMediumEthernetAuto         =  ( IFM_AUTO    | IFM_ETHER ),
    kIOMediumEthernetManual       =  ( IFM_MANUAL  | IFM_ETHER ),
    kIOMediumEthernetNone         =  ( IFM_NONE    | IFM_ETHER ),
    kIOMediumEthernet10BaseT      =  ( IFM_10_T    | IFM_ETHER ),
    kIOMediumEthernet10Base2      =  ( IFM_10_2    | IFM_ETHER ),
    kIOMediumEthernet10Base5      =  ( IFM_10_5    | IFM_ETHER ),
    kIOMediumEthernet100BaseTX    =  ( IFM_100_TX  | IFM_ETHER ),
    kIOMediumEthernet100BaseFX    =  ( IFM_100_FX  | IFM_ETHER ),
    kIOMediumEthernet100BaseT4    =  ( IFM_100_T4  | IFM_ETHER ),
    kIOMediumEthernet100BaseVG    =  ( IFM_100_VG  | IFM_ETHER ),
    kIOMediumEthernet100BaseT2    =  ( IFM_100_T2  | IFM_ETHER ),
    kIOMediumEthernet1000BaseSX   =  ( IFM_1000_SX | IFM_ETHER ),
    kIOMediumEthernet10BaseSTP    =  ( IFM_10_STP  | IFM_ETHER ),
    kIOMediumEthernet10BaseFL     =  ( IFM_10_FL   | IFM_ETHER ),
    kIOMediumEthernet1000BaseLX   =  ( IFM_1000_LX | IFM_ETHER ),
    kIOMediumEthernet1000BaseCX   =  ( IFM_1000_CX | IFM_ETHER ),
    kIOMediumEthernet1000BaseTX   =  ( IFM_1000_TX | IFM_ETHER ),
    kIOMediumEthernetHomePNA1     =  ( IFM_HPNA_1  | IFM_ETHER ),
};

// IEEE 802.11 Wireless.
//
enum {
    kIOMediumIEEE80211            =  IFM_IEEE80211,
    kIOMediumIEEE80211Auto        =  ( IFM_AUTO           | IFM_IEEE80211 ),
    kIOMediumIEEE80211Manual      =  ( IFM_MANUAL         | IFM_IEEE80211 ),
    kIOMediumIEEE80211None        =  ( IFM_NONE           | IFM_IEEE80211 ),
    kIOMediumIEEE80211FH1         =  ( IFM_IEEE80211_FH1  | IFM_IEEE80211 ),
    kIOMediumIEEE80211FH2         =  ( IFM_IEEE80211_FH2  | IFM_IEEE80211 ),
    kIOMediumIEEE80211DS2         =  ( IFM_IEEE80211_DS2  | IFM_IEEE80211 ),
    kIOMediumIEEE80211DS5         =  ( IFM_IEEE80211_DS5  | IFM_IEEE80211 ),
    kIOMediumIEEE80211DS11        =  ( IFM_IEEE80211_DS11 | IFM_IEEE80211 ),
    kIOMediumIEEE80211DS1         =  ( IFM_IEEE80211_DS1  | IFM_IEEE80211 ),
    kIOMediumIEEE80211OptionAdhoc =  IFM_IEEE80211_ADHOC,
};

// Common options.
//
enum {
    kIOMediumOptionFullDuplex     = IFM_FDX,
    kIOMediumOptionHalfDuplex     = IFM_HDX,
    kIOMediumOptionFlowControl    = IFM_FLOW,
    kIOMediumOptionFlag0          = IFM_FLAG0,
    kIOMediumOptionFlag1          = IFM_FLAG1,
    kIOMediumOptionFlag2          = IFM_FLAG2,
    kIOMediumOptionLoopback       = IFM_LOOP,
};

// Medium type masks.
//
#define kIOMediumSubTypeMask        IFM_TMASK
#define kIOMediumNetworkTypeMask    IFM_NMASK
#define kIOMediumOptionsMask        IFM_OMASK
#define kIOMediumCommonOptionsMask  IFM_GMASK
#define kIOMediumInstanceShift      IFM_ISHIFT
#define kIOMediumInstanceMask       IFM_IMASK

// Medium type field accessors.
//
#define IOMediumGetSubType(x)       ((x)  & kIOMediumSubTypeMask)
#define IOMediumGetNetworkType(x)   ((x)  & kIOMediumNetworkMask)
#define IOMediumGetInstance(x)      (((x) & kIOMediumInstanceMask) >> \
                                            kIOMediumInstanceShift)

//===========================================================================
// Medium flags.


//===========================================================================
// Link status bits.
//
enum {
    kIONetworkLinkValid        = IFM_AVALID,    // link status is valid
    kIONetworkLinkActive       = IFM_ACTIVE,    // link is up/active.
};

#ifdef __cplusplus
}
#endif

//===========================================================================
// IONetworkMedium class.

#ifdef KERNEL

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSSymbol.h>

/*! @class IONetworkMedium
    @abstract An object that encapsulates information about a network
    medium (i.e. 10Base-T, or 100Base-T Full Duplex). The main purpose of
    this object is for network drivers to advertise its media capability,
    through a collection of IONetworkMedium objects stored in a dictionary
    in its property table. IONetworkMedium supports serialization, and will
    encode its properties in the form of a dictionary to the serialization
    stream when instructed. This will allow a user-space application to
    browse the set of media types supported by the controller. */

class IONetworkMedium : public OSObject
{
    OSDeclareDefaultStructors( IONetworkMedium )

protected:
    IOMediumType      _type;
    UInt32            _flags;
    UInt64            _speed;
    UInt32            _index;
    const OSSymbol *  _name;

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *_reserved;


/*! @function free
    @abstract Free the IONetworkMedium object. */

    virtual void free();

public:

/*! @function nameForType
    @abstract Create a name that describes a medium type.
    @discussion Given a medium type, create an OSymbol object that
    describes the medium type. There is a 1-to-1 mapping between the
    medium type, and the medium name created by this method. The caller
    is responsible for releasing the OSSymbol object returned.
    @param type A medium type. See IONetworkMedium.h for type encoding.
    @result An OSSymbol object is created based on the type provided. */

    static const OSSymbol * nameForType(IOMediumType type);

/*! @function addMedium
    @abstract Add an IONetworkMedium object to a dictionary.
    @discussion A helper function to add an IONetworkMedium object to a
    given dictionary. The name of the medium is used as the key for the
    new dictionary entry.
    @param dict An OSDictionary object where the medium object should be
    added as a new entry.
    @param medium The IONetworkMedium object to add to the dictionary.
    @result true on success, false otherwise. */

    static bool addMedium(OSDictionary *          dict,
                          const IONetworkMedium * medium);

/*! @function removeMedium
    @abstract Remove an IONetworkMedium object from a dictionary.
    @discussion A helper function to remove an entry in a dictionary.
    @param dict The OSDictionary object where the medium object should be
    removed from.
    @param medium The name of this medium object is used as the key. */

    static void removeMedium(OSDictionary *          dict,
                             const IONetworkMedium * medium);

/*! @function getMediumWithType
    @abstract Find a medium object from a dictionary with a given type.
    @discussion Iterate through a dictionary and return an IONetworkMedium
    entry with the given type. An optional mask supplies the don't care bits.
    @param dict The dictionary to look for a matching entry.
    @param type Search for an entry with this type.
    @param mask The don't care bits in IOMediumType. Defaults to 0, which
    implies that a perfect match is desired.
    @result The first matching IONetworkMedium entry found,
    or 0 if no match was found. */

    static IONetworkMedium * getMediumWithType(const OSDictionary * dict,
                                               IOMediumType         type,
                                               IOMediumType         mask = 0);

/*! @function getMediumWithIndex
    @abstract Find a medium object from a dictionary with a given index.
    @discussion Iterate through a dictionary and return an IONetworkMedium
    entry with the given index. An optional mask supplies the don't care bits.
    @param dict The dictionary to look for a matching entry.
    @param index Search for an entry with the given index.
    @param mask The don't care bits in index. Defaults to 0, which
    implies that a perfect match is desired.
    @result The first matching IONetworkMedium entry found,
    or 0 if no match was found. */

    static IONetworkMedium * getMediumWithIndex(const OSDictionary * dict,
                                                UInt32               index,
                                                UInt32               mask = 0);

/*! @function init
    @abstract Initialize an IONetworkMedium object.
    @param type The medium type, this value is encoded with bits defined in
           IONetworkMedium.h.
    @param speed The maximum (or the only) link speed supported over this 
           medium in units of bits per second.
    @param flags An optional flag for the medium object.
           See IONetworkMedium.h for defined flags.
    @param index An optional index number assigned by the owner.
           Drivers can use this to store an index to a media table in
           the driver, or it may map to a driver defined media type.
    @param name An optional name assigned to this medium object. If 0,
           then a name will be created based on the medium type by
           calling IONetworkMedium::nameForType(). Since the name of
           the medium is used as a key when inserted into a dictionary,
           the name chosen must be unique within the scope of the owner.
    @result true on success, false otherwise. */

    virtual bool init(IOMediumType  type,
                      UInt64        speed,
                      UInt32        flags = 0,
                      UInt32        index = 0,
                      const char *  name  = 0);

/*! @function medium
    @abstract Factory method which performs allocation and initialization
    of an IONetworkMedium object.
    @param type The medium type, this value is encoded with bits defined in
           IONetworkMedium.h.
    @param speed The maximum (or the only) link speed supported over this 
           medium in units of bits per second.
    @param flags An optional flag for the medium object.
           See IONetworkMedium.h for defined flags.
    @param index An optional index number assigned by the owner.
           Drivers can use this to store an index to a media table in
           the driver, or it may map to a driver defined media type.
    @param name An optional name assigned to this medium object. If 0,
           then a name will be created based on the medium type by
           calling IONetworkMedium::nameForType(). Since the name of
           the medium is used as a key when inserted into a dictionary,
           the name chosen must be unique within the scope of the owner.
    @result An IONetworkMedium instance on success, or 0 otherwise. */

    static IONetworkMedium * medium(IOMediumType  type,
                                    UInt64        speed,
                                    UInt32        flags = 0,
                                    UInt32        index = 0,
                                    const char *  name  = 0);

/*! @function getType
    @result The medium type assigned to this medium object. */

    virtual IOMediumType  getType() const;

/*! @function getSpeed
    @result The maximum link speed supported by this medium. */

    virtual UInt64        getSpeed() const;

/*! @function getFlags
    @result The medium flags. */

    virtual UInt32        getFlags() const;

/*! @function getIndex
    @result The assigned medium index. */

    virtual UInt32        getIndex() const;

/*! @function getName
    @result The name assigned to this medium object. */

    virtual const OSSymbol * getName() const;

/*! @function getKey
    @result The key to use for this medium object. This key should be
    used when this object is added to a dictionary. Same as getName(). */

    virtual const OSSymbol * getKey() const;

/*! @function isEqualTo
    @abstract Test for equality between two IONetworkMedium objects.
    @discussion Two IONetworkMedium objects are considered equal if
    they have similar properties assigned to them during initialization.
    @param medium An IONetworkMedium to test against the IONetworkMedium
    object being called.
    @result true if equal, false otherwise. */

    virtual bool isEqualTo(const IONetworkMedium * medium) const;

/*! @function isEqualTo
    @abstract Test for equality between a IONetworkMedium object and an
    OSObject.
    @discussion The OSObject is considered equal to the IONetworkMedium
    object if the OSObject is an IONetworkMedium, and they have
    similar properties assigned to them during initialization.
    @param obj An OSObject to test against an IONetworkMedium object.
    @result true if equal, false otherwise. */

    virtual bool isEqualTo(const OSMetaClassBase * obj) const;

/*! @function serialize
    @abstract Serialize the IONetworkMedium object.
    @discussion A dictionary is created containing the properties
    assigned to this medium object, and this dictionary is then
    serialized using the OSSerialize object provided.
    @param s An OSSerialize object.
    @result true on success, false otherwise. */

    virtual bool serialize(OSSerialize * s) const;

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IONetworkMedium,  0);
    OSMetaClassDeclareReservedUnused( IONetworkMedium,  1);
    OSMetaClassDeclareReservedUnused( IONetworkMedium,  2);
    OSMetaClassDeclareReservedUnused( IONetworkMedium,  3);
};

// Translate getKey() to getName().
//
inline const OSSymbol * IONetworkMedium::getKey() const
{
    return getName();
}

#endif /* KERNEL */

#endif /* !_IONETWORKMEDIUM_H */
