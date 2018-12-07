/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
// @@@ gvdl: Remove me
#if 1
static UInt sMaxDBDMASegment;
if (!sMaxDBDMASegment) {
    sMaxDBDMASegment = (UInt) -1;
    if (PE_parse_boot_argn("mseg", &sMaxDBDMASegment, sizeof (sMaxDBDMASegment)))
        IOLog("Setting MaxDBDMASegment to %d\n", sMaxDBDMASegment);
}

if (inMaxSegmentSize > sMaxDBDMASegment) inMaxSegmentSize = sMaxDBDMASegment;
#endif

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
                                    IOByteCount		fromPosition,
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
    PhysicalSegment curSeg = { 0, 0 };
    UInt curSegIndex = 0;
    UInt curTransferSize = 0;
    IOByteCount inDescriptorLength = inDescriptor->getLength();
    PhysicalSegment seg = { 0, 0 };

    while ((seg.location) || (fromPosition < inDescriptorLength)) 
    {
        if (!seg.location)
        {
            seg.location = inDescriptor->getPhysicalSegment(
                               fromPosition, (IOByteCount*)&seg.length);
            assert(seg.location);
            assert(seg.length);
            fromPosition += seg.length;
        }

        if (!curSeg.location)
        {
            curTransferSize += seg.length;
            curSeg = seg;
            seg.location = 0;
        }
        else if ((curSeg.location + curSeg.length == seg.location))
        {
            curTransferSize += seg.length;
            curSeg.length += seg.length;
            seg.location = 0;
        }

        if (!seg.location)
        {
            if ((curSeg.length > maxSegmentSize))
            {
                seg.location = curSeg.location + maxSegmentSize;
                seg.length = curSeg.length - maxSegmentSize;
                curTransferSize -= seg.length;
                curSeg.length -= seg.length;
            }

            if ((curTransferSize >= inMaxTransferSize))
            {
                curSeg.length -= curTransferSize - inMaxTransferSize;
                curTransferSize = inMaxTransferSize;
                break;
            }
        }

        if (seg.location)
        {
            if ((curSegIndex + 1 == inMaxSegments))
                break;
            (*outSeg)(curSeg, inSegments, curSegIndex++);
            curSeg.location = 0;
        }
    }

    if (curSeg.location)
        (*outSeg)(curSeg, inSegments, curSegIndex++);

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
#if IOPhysSize == 64
    OSWriteBigInt64(segment, 0, inSegment.location);
    OSWriteBigInt64(segment, sizeof(IOPhysicalAddress), inSegment.length);
#else
    OSWriteBigInt(segment, 0, inSegment.location);
    OSWriteBigInt(segment, sizeof(IOPhysicalAddress), inSegment.length);
#endif
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
#if IOPhysSize == 64
    OSWriteLittleInt64(segment, 0, inSegment.location);
    OSWriteLittleInt64(segment, sizeof(IOPhysicalAddress), inSegment.length);
#else
    OSWriteLittleInt(segment, 0, inSegment.location);
    OSWriteLittleInt(segment, sizeof(IOPhysicalAddress), inSegment.length);
#endif
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
