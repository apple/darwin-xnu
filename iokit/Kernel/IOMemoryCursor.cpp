/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
/* IOMemoryCursor.cpp created by wgulland on 1999-3-02 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryCursor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/OSByteOrder.h>

/**************************** class IOMemoryCursor ***************************/

#undef super
#define super OSObject
OSDefineMetaClassAndStructors(IOMemoryCursor, OSObject)

IOMemoryCursor *
IOMemoryCursor::withSpecification(SegmentFunction  inSegFunc,
                                  IOPhysicalLength inMaxSegmentSize,
                                  IOPhysicalLength inMaxTransferSize,
                                  IOPhysicalLength inAlignment)
{
    IOMemoryCursor * me = new IOMemoryCursor;

    if (me && !me->initWithSpecification(inSegFunc,
                                         inMaxSegmentSize,
                                         inMaxTransferSize,
                                         inAlignment))
    {
        me->release();
        return 0;
    }

    return me;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IOMemoryCursor::initWithSpecification(SegmentFunction  inSegFunc,
                                      IOPhysicalLength inMaxSegmentSize,
                                      IOPhysicalLength inMaxTransferSize,
                                      IOPhysicalLength inAlignment)
{
    if (!super::init())
        return false;

    if (!inSegFunc)
        return false;

    outSeg		= inSegFunc;
    maxSegmentSize	= inMaxSegmentSize;
    if (inMaxTransferSize)
        maxTransferSize = inMaxTransferSize;
    else
        maxTransferSize = (IOPhysicalLength) -1;
    alignMask		= inAlignment - 1;
    assert(alignMask == 0);		// No alignment code yet!

    return true;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

UInt32 
IOMemoryCursor::genPhysicalSegments(IOMemoryDescriptor *inDescriptor,
                                    IOPhysicalLength	fromPosition,
                                    void *		inSegments,
                                    UInt32		inMaxSegments,
                                    UInt32		inMaxTransferSize,
                                    IOByteCount		*outTransferSize)
{
    if (!inDescriptor)
        return 0;

    if (!inMaxSegments)
        return 0;

    if (!inMaxTransferSize)
        inMaxTransferSize = maxTransferSize;

    /*
     * Iterate over the packet, translating segments where allowed
     *
     * If we finished cleanly return number of segments found
     * and update the position in the descriptor.
     */
    UInt curSegIndex = 0;
    UInt curTransferSize = 0;
    PhysicalSegment seg;

    while ((curSegIndex < inMaxSegments)
    &&  (curTransferSize < inMaxTransferSize)
    &&  (seg.location = inDescriptor->getPhysicalSegment(
                            fromPosition + curTransferSize, &seg.length)))
    {
        assert(seg.length);
        seg.length = min(inMaxTransferSize-curTransferSize,
                         (min(seg.length, maxSegmentSize)));
        (*outSeg)(seg, inSegments, curSegIndex++);
        curTransferSize += seg.length;
    }

    if (outTransferSize)
        *outTransferSize = curTransferSize;

    return curSegIndex;
}

/************************ class IONaturalMemoryCursor ************************/

#undef super
#define super IOMemoryCursor
OSDefineMetaClassAndStructors(IONaturalMemoryCursor, IOMemoryCursor)

void IONaturalMemoryCursor::outputSegment(PhysicalSegment segment,
                                          void *	  outSegments,
                                          UInt32	  outSegmentIndex)
{
    ((PhysicalSegment *) outSegments)[outSegmentIndex] = segment;
}

IONaturalMemoryCursor * 
IONaturalMemoryCursor::withSpecification(IOPhysicalLength inMaxSegmentSize,
                                         IOPhysicalLength inMaxTransferSize,
                                         IOPhysicalLength inAlignment)
{
    IONaturalMemoryCursor *me = new IONaturalMemoryCursor;

    if (me && !me->initWithSpecification(inMaxSegmentSize,
                                         inMaxTransferSize,
                                         inAlignment))
    {
        me->release();
        return 0;
    }

    return me;
}

bool 
IONaturalMemoryCursor::initWithSpecification(IOPhysicalLength inMaxSegmentSize,
                                             IOPhysicalLength inMaxTransferSize,
                                             IOPhysicalLength inAlignment)
{
    return super::initWithSpecification(&IONaturalMemoryCursor::outputSegment,
                                        inMaxSegmentSize,
                                        inMaxTransferSize,
                                        inAlignment);
}

/************************** class IOBigMemoryCursor **************************/

#undef super
#define super IOMemoryCursor
OSDefineMetaClassAndStructors(IOBigMemoryCursor, IOMemoryCursor)

void 
IOBigMemoryCursor::outputSegment(PhysicalSegment inSegment,
                                 void *		 inSegments,
                                 UInt32		 inSegmentIndex)
{
    IOPhysicalAddress * segment;

    segment = &((PhysicalSegment *) inSegments)[inSegmentIndex].location;
    OSWriteBigInt(segment, 0, inSegment.location);
    OSWriteBigInt(segment, sizeof(IOPhysicalAddress), inSegment.length);
}

IOBigMemoryCursor *
IOBigMemoryCursor::withSpecification(IOPhysicalLength inMaxSegmentSize,
                                     IOPhysicalLength inMaxTransferSize,
                                     IOPhysicalLength inAlignment)
{
    IOBigMemoryCursor * me = new IOBigMemoryCursor;

    if (me && !me->initWithSpecification(inMaxSegmentSize,
                                         inMaxTransferSize,
                                         inAlignment))
    {
        me->release();
        return 0;
    }

    return me;
}

bool 
IOBigMemoryCursor::initWithSpecification(IOPhysicalLength inMaxSegmentSize,
                                         IOPhysicalLength inMaxTransferSize,
                                         IOPhysicalLength inAlignment)
{
    return super::initWithSpecification(&IOBigMemoryCursor::outputSegment,
                                        inMaxSegmentSize,
                                        inMaxTransferSize,
                                        inAlignment);
}

/************************* class IOLittleMemoryCursor ************************/

#undef super
#define super IOMemoryCursor
OSDefineMetaClassAndStructors(IOLittleMemoryCursor, IOMemoryCursor)

void 
IOLittleMemoryCursor::outputSegment(PhysicalSegment inSegment,
                                    void *	    inSegments,
                                    UInt32	    inSegmentIndex)
{
    IOPhysicalAddress * segment;

    segment = &((PhysicalSegment *) inSegments)[inSegmentIndex].location;
    OSWriteLittleInt(segment, 0, inSegment.location);
    OSWriteLittleInt(segment, sizeof(IOPhysicalAddress), inSegment.length);
}

IOLittleMemoryCursor *
IOLittleMemoryCursor::withSpecification(IOPhysicalLength inMaxSegmentSize,
                                        IOPhysicalLength inMaxTransferSize,
                                        IOPhysicalLength inAlignment)
{
    IOLittleMemoryCursor * me = new IOLittleMemoryCursor;

    if (me && !me->initWithSpecification(inMaxSegmentSize,
                                         inMaxTransferSize,
                                         inAlignment))
    {
        me->release();
        return 0;
    }

    return me;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool 
IOLittleMemoryCursor::initWithSpecification(IOPhysicalLength inMaxSegmentSize,
                                            IOPhysicalLength inMaxTransferSize,
                                            IOPhysicalLength inAlignment)
{
    return super::initWithSpecification(&IOLittleMemoryCursor::outputSegment,
                                        inMaxSegmentSize,
                                        inMaxTransferSize,
                                        inAlignment);
}

/************************* class IODBDMAMemoryCursor *************************/

#if defined(__ppc__)

#include <IOKit/ppc/IODBDMA.h>

#undef super
#define super IOMemoryCursor
OSDefineMetaClassAndStructors(IODBDMAMemoryCursor, IOMemoryCursor)

void 
IODBDMAMemoryCursor::outputSegment(PhysicalSegment inSegment,
                                   void *	   inSegments,
                                   UInt32	   inSegmentIndex)
{
    IODBDMADescriptor *segment;

    segment = &((IODBDMADescriptor *) inSegments)[inSegmentIndex];

    // Write location into address field
    OSWriteSwapInt32((UInt32 *) segment, 4, inSegment.location);

    // Write count into 1st two bytes of operation field.
    // DO NOT touch rest of operation field as it should contain a STOP command.
    OSWriteSwapInt16((UInt16 *) segment, 0, inSegment.length);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IODBDMAMemoryCursor *
IODBDMAMemoryCursor::withSpecification(IOPhysicalLength inMaxSegmentSize,
                                       IOPhysicalLength inMaxTransferSize,
                                       IOPhysicalLength inAlignment)
{
    IODBDMAMemoryCursor *me = new IODBDMAMemoryCursor;

    if (me && !me->initWithSpecification(inMaxSegmentSize,
                                         inMaxTransferSize,
                                         inAlignment))
    {
        me->release();
        return 0;
    }

    return me;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool
IODBDMAMemoryCursor::initWithSpecification(IOPhysicalLength inMaxSegmentSize,
                                           IOPhysicalLength inMaxTransferSize,
                                           IOPhysicalLength inAlignment)
{
    return super::initWithSpecification(&IODBDMAMemoryCursor::outputSegment,
                                        inMaxSegmentSize,
                                        inMaxTransferSize,
                                        inAlignment);
}

#endif /* defined(__ppc__) */

