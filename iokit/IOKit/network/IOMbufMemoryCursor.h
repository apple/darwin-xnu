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
 * IOMbufMemoryCursor.h created by gvdl on 1999-1-20
 *
 */

#ifndef _IOKIT_NETWORK_IOMBUFMEMORYCURSOR_H
#define _IOKIT_NETWORK_IOMBUFMEMORYCURSOR_H

#include <IOKit/IOMemoryCursor.h>

struct mbuf;

/*! @class IOMbufMemoryCursor : public IOMemoryCursor
    @abstract A mechanism to convert mbuf chains to physical addresses.
    @discussion The IOMbufMemoryCursor defines the super class that all
    specific mbuf cursors must inherit from, but a mbuf cursor can be created   
    without a specific formal subclass by just providing a segment function to
    the initializers. This class performs the task of walking a given
    mbuf chain and creating a physical scatter/gather list appropriate for
    the target hardware. When necessary, this class may also coalesce
    mbuf chains when the generated scatter/gather list exceeds the specified 
    hardware limit. However, this should be avoided since it exacts a 
    performance cost.
    <br><br>
    A driver is expected to create a mbuf cursor and configure it to match the
    limitations of it's DMA hardware; for instance the mbuf cursor used by
    an Ethernet controller driver may have a maximum physical segment size
    of 1520, and allow for up to 6 physical segments. Thus it would create a 
    mbuf cursor with a maxSegmentSize of 1520 and a maxNumSegments of 6.
    The driver may choose to supply an OutputSegmentFunc function to
    format the output of each scatter/gather segment to match the
    hardware descriptor format, or it may use a subclass of 
    IOMbufMemoryCursor to generate IOPhysicalSegment segments with 
    various byte orders.
    <br><br>
    A driver may also create more than one mbuf cursor, perhaps one
    dedicated for the transmit thread, and the other for the receive thread.
    This becomes a requirement when the driver is multi-threaded, since the 
    mbuf cursor maintains state and does not support reentrancy. */

class IOMbufMemoryCursor : public IOMemoryCursor
{
    OSDeclareAbstractStructors(IOMbufMemoryCursor)

protected:
    UInt32 maxNumSegments;
    UInt32 coalesceCount;
    UInt32 packetTooBigErrors;

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

    virtual bool initWithSpecification(OutputSegmentFunc outSeg,
                                       UInt32 maxSegmentSize,
                                       UInt32 maxTransferSize,
                                       UInt32 align);

public:
/*! @function initWithSpecification
    @abstract Primary initializer for the IOMbufMemoryCursor class.
    @param outSeg Function to call to output one physical segment.
    @param maxSegmentSize Maximum allowable size for one segment.
    @param maxNumSegments Maximum number of segments.
    @result true if the inherited classes and this instance initialized
    successfully. */

    virtual bool initWithSpecification(OutputSegmentFunc outSeg,
                                       UInt32 maxSegmentSize,
                                       UInt32 maxNumSegments);

/*! @function genPhysicalSegments
    @abstract Generate a physical scatter/gather list given a mbuf packet.
    @discussion Generates a list of physical segments from the given mbuf.
    @param packet The mbuf packet.
    @param vector Void pointer to base of output physical scatter/gather list.
    Always passed directly onto the OutputSegmentFunc without interpretation
    by the cursor. 
    @param maxSegs Maximum number of segments that can be written to segments
    array.
    @param doCoalesce Set to true to perform coalescing when the required 
    number of segments exceeds the specified limit, otherwise abort and
    return 0.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    virtual UInt32 genPhysicalSegments(struct mbuf * packet, void * vector,
                                       UInt32 maxSegs, bool doCoalesce);

/*! @function getAndResetCoalesceCount
    @abstract Returns a count of the total number of mbuf chains coalesced
    by genPhysicalSegments(). The counter is then reset to 0.
    @result The coalesce count. */

    UInt32 getAndResetCoalesceCount();

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IOMbufMemoryCursor,  0);
    OSMetaClassDeclareReservedUnused( IOMbufMemoryCursor,  1);
    OSMetaClassDeclareReservedUnused( IOMbufMemoryCursor,  2);
    OSMetaClassDeclareReservedUnused( IOMbufMemoryCursor,  3);
};


/*! @class IOMbufNaturalMemoryCursor : public IOMbufMemoryCursor
    @abstract A IOMbufMemoryCursor subclass that outputs a vector of
    IOPhysicalSegments in the natural byte orientation for the cpu.  
    @discussion The IOMbufNaturalMemoryCursor would be used when it is too
    difficult to implement an OutputSegmentFunc that is more appropriate for
    your hardware.  This cursor just outputs an array of IOPhysicalSegments. */

class IOMbufNaturalMemoryCursor : public IOMbufMemoryCursor
{
    OSDeclareDefaultStructors(IOMbufNaturalMemoryCursor)

public:

/*! @function withSpecification
    @abstract Factory function to create and initialize an 
    IOMbufNaturalMemoryCursor in one operation, see
    IOMbufMemoryCursor::initWithSpecification.
    @param maxSegmentSize Maximum allowable size for one segment.
    @param maxNumSegments Maximum number of segments.
    @result A new mbuf cursor if successfully created and initialized,
    0 otherwise. */

    static IOMbufNaturalMemoryCursor * withSpecification(UInt32 maxSegmentSize, 
                                                         UInt32 maxNumSegments);

/*! @function getPhysicalSegments
    @abstract Generate a cpu natural physical scatter/gather list from a given
    mbuf.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegments(struct mbuf * packet,
                               struct IOPhysicalSegment * vector,
                               UInt32 numVectorSegments = 0);

/*! @function getPhysicalSegmentsWithCoalesce
    @abstract Generate a cpu natural physical scatter/gather list from a given
    mbuf.
    @discussion Generate a cpu natural physical scatter/gather list from a 
    given mbuf. Coalesce mbuf chain when the number of segments in the 
    scatter/gather list exceeds numVectorSegments.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegmentsWithCoalesce(struct mbuf * packet,
                                           struct IOPhysicalSegment * vector,
                                           UInt32 numVectorSegments = 0);
};

//===========================================================================
//===========================================================================

/*! @class IOMbufBigMemoryCursor : public IOMbufMemoryCursor
    @abstract A IOMbufMemoryCursor subclass that outputs a vector of 
    IOPhysicalSegments in the big endian byte order.  
    @discussion The IOMbufBigMemoryCursor would be used when the DMA hardware 
    requires a big endian address and length pair.  This cursor outputs an 
    array of IOPhysicalSegments that are encoded in big-endian format. */

class IOMbufBigMemoryCursor : public IOMbufMemoryCursor
{
    OSDeclareDefaultStructors(IOMbufBigMemoryCursor)

public:

/*! @function withSpecification
    @abstract Factory function to create and initialize an 
    IOMbufBigMemoryCursor in one operation, see
    IOMbufMemoryCursor::initWithSpecification.
    @param maxSegmentSize Maximum allowable size for one segment.
    @param maxNumSegments Maximum number of segments.
    @result A new mbuf cursor if successfully created and initialized,
    0 otherwise. */

    static IOMbufBigMemoryCursor * withSpecification(UInt32 maxSegmentSize,
                                                     UInt32 maxNumSegments);

/*! @function getPhysicalSegments
    @abstract Generate a big endian physical scatter/gather list from a given
    mbuf.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegments(struct mbuf * packet,
                               struct IOPhysicalSegment * vector,
                               UInt32 numVectorSegments = 0);

/*! @function getPhysicalSegmentsWithCoalesce
    @abstract Generate a big endian physical scatter/gather list from a given
    mbuf.
    @discussion Generate a big endian physical scatter/gather list from a 
    given mbuf. Coalesce mbuf chain when the number of segments in the 
    scatter/gather list exceeds numVectorSegments.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegmentsWithCoalesce(struct mbuf * packet,
                                           struct IOPhysicalSegment * vector,
                                           UInt32 numVectorSegments = 0);
};

//===========================================================================
//===========================================================================

/*! @class IOMbufLittleMemoryCursor : public IOMbufMemoryCursor
    @abstract A IOMbufMemoryCursor subclass that outputs a vector of 
    IOPhysicalSegments in the little endian byte order.  
    @discussion The IOMbufLittleMemoryCursor would be used when the DMA 
    hardware requires a little endian address and length pair.  This cursor 
    outputs an array of IOPhysicalSegments that are encoded in little endian 
    format. */

class IOMbufLittleMemoryCursor : public IOMbufMemoryCursor
{
    OSDeclareDefaultStructors(IOMbufLittleMemoryCursor)

public:

/*! @function withSpecification
    @abstract Factory function to create and initialize an 
    IOMbufLittleMemoryCursor in one operation, see
    IOMbufMemoryCursor::initWithSpecification.
    @param maxSegmentSize Maximum allowable size for one segment.
    @param maxNumSegments Maximum number of segments.
    @result A new mbuf cursor if successfully created and initialized,
    0 otherwise. */

    static IOMbufLittleMemoryCursor * withSpecification(UInt32 maxSegmentSize, 
                                                        UInt32 maxNumSegments);

/*! @function getPhysicalSegments
    @abstract Generate a little endian physical scatter/gather list from a 
    given mbuf.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegments(struct mbuf * packet,
                               struct IOPhysicalSegment * vector,
                               UInt32 numVectorSegments = 0);

/*! @function getPhysicalSegmentsWithCoalesce
    @abstract Generate a little endian physical scatter/gather list from a 
    given mbuf.
    @discussion Generate a little endian physical scatter/gather list from a 
    given mbuf. Coalesce mbuf chain when the number of segments in the 
    scatter/gather list exceeds numVectorSegments.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IOPhysicalSegments for the output 
    physical scatter/gather list.
    @param numVectorSegments Maximum number of IOPhysicalSegments accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegmentsWithCoalesce(struct mbuf * packet,
                                           struct IOPhysicalSegment * vector,
                                           UInt32 numVectorSegments = 0);
};

#ifdef __ppc__

struct IODBDMADescriptor;

//===========================================================================
//===========================================================================

/*! @class IOMbufDBDMAMemoryCursor : public IOMbufMemoryCursor
    @abstract A IOMbufMemoryCursor subclass that outputs a vector of 
    IODBDMADescriptors. */

class IOMbufDBDMAMemoryCursor : public IOMbufMemoryCursor
{
    OSDeclareDefaultStructors(IOMbufDBDMAMemoryCursor)

public:

/*! @function withSpecification
    @abstract Factory function to create and initialize an 
    IOMbufDBDMAMemoryCursor in one operation, see
    IOMbufMemoryCursor::initWithSpecification.
    @param maxSegmentSize Maximum allowable size for one segment.
    @param maxNumSegments Maximum number of segments.
    @result A new mbuf cursor if successfully created and initialized,
    0 otherwise. */

    static IOMbufDBDMAMemoryCursor * withSpecification(UInt32 maxSegmentSize, 
                                                       UInt32 maxNumSegments);

/*! @function getPhysicalSegments
    @abstract Generate a DBDMA descriptor list from a given mbuf.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IODBDMADescriptor for the output list.
    @param numVectorSegments Maximum number of IODBDMADescriptors accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegments(struct mbuf * packet,
                               struct IODBDMADescriptor *vector,
                               UInt32 numVectorSegments = 0);

/*! @function getPhysicalSegmentsWithCoalesce
    @abstract Generate a DBDMA descriptor list from a given mbuf.
    @discussion Generate a DBDMA descriptor list from a given mbuf.
    Coalesce mbuf chain when the number of elements in the list exceeds
    numVectorSegments.
    @param packet The mbuf packet.
    @param vector Pointer to an array of IODBDMADescriptor for the output list.
    @param numVectorSegments Maximum number of IODBDMADescriptors accepted.
    @result The number of segments that were filled in is returned, or
    0 if an error occurred. */

    UInt32 getPhysicalSegmentsWithCoalesce(struct mbuf * packet,
                                           struct IODBDMADescriptor * vector,
                                           UInt32 numVectorSegments = 0);
};

#endif /* __ppc__ */

inline UInt32 IOMbufMemoryCursor::getAndResetCoalesceCount()
{
    UInt32 cnt = coalesceCount; coalesceCount = 0; return cnt;
}

inline UInt32
IOMbufNaturalMemoryCursor::getPhysicalSegments(struct mbuf *packet,
                       struct IOPhysicalSegment *vector,
                       UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, false);
}

inline UInt32
IOMbufNaturalMemoryCursor::getPhysicalSegmentsWithCoalesce(struct mbuf *packet,
                                   struct IOPhysicalSegment *vector,
                                   UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, true);
}

inline UInt32
IOMbufBigMemoryCursor::getPhysicalSegments(struct mbuf *packet,
                       struct IOPhysicalSegment *vector,
                       UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, false);
}

inline UInt32
IOMbufBigMemoryCursor::getPhysicalSegmentsWithCoalesce(struct mbuf *packet,
                                   struct IOPhysicalSegment *vector,
                                   UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, true);
}

inline UInt32
IOMbufLittleMemoryCursor::getPhysicalSegments(struct mbuf *packet,
                       struct IOPhysicalSegment *vector,
                       UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, false);
}

inline UInt32
IOMbufLittleMemoryCursor::getPhysicalSegmentsWithCoalesce(struct mbuf *packet,
                                   struct IOPhysicalSegment *vector,
                                   UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, true);
}

#ifdef __ppc__
inline UInt32
IOMbufDBDMAMemoryCursor::getPhysicalSegments(struct mbuf *packet,
                                   struct IODBDMADescriptor *vector,
                                   UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, false);
}

inline UInt32
IOMbufDBDMAMemoryCursor::getPhysicalSegmentsWithCoalesce(struct mbuf *packet,
                                   struct IODBDMADescriptor *vector,
                                   UInt32 numVectorSegments = 0)
{
    return genPhysicalSegments(packet, vector, numVectorSegments, true);
}
#endif /* __ppc__ */

#endif /* !_IOKIT_NETWORK_IOMBUFMEMORYCURSOR_H */

