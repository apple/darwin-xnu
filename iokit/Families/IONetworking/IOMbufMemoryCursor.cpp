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
/* IOMbufMemoryCursor.cpp created by gvdl on 1999-1-20 */

#include <sys/cdefs.h>

__BEGIN_DECLS
#include <IOKit/assert.h>

#include <sys/param.h>
#include <sys/mbuf.h>
#include <architecture/byte_order.h>
__END_DECLS

#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/IOLib.h>

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */

#define next_page(x) trunc_page(x + PAGE_SIZE)

/* Define the meta class stuff for the entire file here */
OSDefineMetaClassAndAbstractStructors(IOMbufMemoryCursor, IOMemoryCursor)
OSMetaClassDefineReservedUnused( IOMbufMemoryCursor,  0);
OSMetaClassDefineReservedUnused( IOMbufMemoryCursor,  1);
OSMetaClassDefineReservedUnused( IOMbufMemoryCursor,  2);
OSMetaClassDefineReservedUnused( IOMbufMemoryCursor,  3);

OSDefineMetaClassAndStructors(IOMbufNaturalMemoryCursor, IOMbufMemoryCursor)
OSDefineMetaClassAndStructors(IOMbufBigMemoryCursor, IOMbufMemoryCursor)
OSDefineMetaClassAndStructors(IOMbufLittleMemoryCursor, IOMbufMemoryCursor)

#ifdef __ppc__
OSDefineMetaClassAndStructors(IOMbufDBDMAMemoryCursor, IOMbufMemoryCursor)
#endif /* __ppc__ */

/*********************** class IOMbufMemoryCursor ***********************/
#define super IOMemoryCursor

bool IOMbufMemoryCursor::initWithSpecification(OutputSegmentFunc outSeg,
                                               UInt32 maxSegmentSize,
                                               UInt32 maxTransferSize,
                                               UInt32 align)
{
    return false;
}

bool IOMbufMemoryCursor::initWithSpecification(OutputSegmentFunc inOutSeg,
                                               UInt32 inMaxSegmentSize,
                                               UInt32 inMaxNumSegments)
{
    if (!super::initWithSpecification(inOutSeg, inMaxSegmentSize, 0, 1))
        return false;

#if 0
    // It is too confusing to force the max segment size to be at least
    // as large as a page. Most Enet devices only have 11-12 bit fields,
    // enough for a full size frame, and also the PAGE_SIZE parameter
    // may be architecture dependent.

    assert(inMaxSegmentSize >= PAGE_SIZE);
    if (inMaxSegmentSize < PAGE_SIZE)
        return false;
#else
    if (!inMaxSegmentSize)
        return false;
#endif

    maxSegmentSize = MIN(maxSegmentSize, PAGE_SIZE);
    maxNumSegments = inMaxNumSegments;
    coalesceCount = 0;

    return true;
}

//
// Copy the src packet into the destination packet. The amount to copy is
// determined by the dstm->m_len, which is setup by analyseSegments, see below.
// The source mbuf is not freed nor modified.
//
#define BCOPY(s, d, l) do { bcopy((void *) s, (void *) d, l); } while(0)

static inline void coalesceSegments(struct mbuf *srcm, struct mbuf *dstm)
{
    vm_offset_t src, dst;
    SInt32 srcLen, dstLen;
    struct mbuf *temp;
            
    srcLen = srcm->m_len;
    src = mtod(srcm, vm_offset_t);

    dstLen = dstm->m_len;
    dst = mtod(dstm, vm_offset_t);

    for (;;) {
        if (srcLen < dstLen) {

            // Copy remainder of src mbuf to current dst.
            BCOPY(src, dst, srcLen);
            dst += srcLen;
            dstLen -= srcLen;

            // Move on to the next source mbuf.
            temp = srcm->m_next; assert(temp);
            srcm = temp;

            srcLen = srcm->m_len;
            src = mtod(srcm, vm_offset_t);
        }
        else if (srcLen > dstLen) {

            // Copy some of src mbuf to remaining space in dst mbuf.
            BCOPY(src, dst, dstLen);
            src += dstLen;
            srcLen -= dstLen;
            
            // Move on to the next destination mbuf.
            temp = dstm->m_next; assert(temp);
            dstm = temp;

            dstLen = dstm->m_len;
            dst = mtod(dstm, vm_offset_t);
        }
        else {  /* (srcLen == dstLen) */

            // copy remainder of src into remaining space of current dst
            BCOPY(src, dst, srcLen);

            // Free current mbuf and move the current onto the next
            srcm = srcm->m_next;

            // Do we have any data left to copy?
            if (!dstm->m_next)
                break;
            dstm = dstm->m_next;

            assert(srcm);
            dstLen = dstm->m_len;
            dst = mtod(dstm, vm_offset_t);
            srcLen = srcm->m_len;
            src = mtod(srcm, vm_offset_t);
        }
    }
}

static const UInt32 kMBufDataCacheSize = 16;

static inline bool analyseSegments(
    struct mbuf *packet,        /* input packet mbuf */
    const UInt32 mbufsInCache,  /* number of entries in segsPerMBuf[] */
    const UInt32 segsPerMBuf[], /* segments required per mbuf */
    SInt32 numSegs,               /* total number of segments */
    const UInt32 maxSegs)       /* max controller segments per mbuf */
{
    struct mbuf *newPacket;     // output mbuf chain.
    struct mbuf *out;           // current output mbuf link.
    SInt32 outSize;               // size of current output mbuf link.
    SInt32 outSegs;               // segments for current output mbuf link.
    SInt32 doneSegs;              // segments for output mbuf chain.
    SInt32 outLen;                // remaining length of input buffer.

    struct mbuf *in = packet;   // save the original input packet pointer.
    UInt32 inIndex = 0;

    // Allocate a mbuf (non header mbuf) to begin the output mbuf chain.
    //
    MGET(newPacket, M_DONTWAIT, MT_DATA);
    if (!newPacket) {
        IOLog("analyseSegments: MGET() 1 error\n");
        return false;
    }

    /* Initialise outgoing packet controls */
    out = newPacket;
    outSize = MLEN;
    doneSegs = outSegs = outLen = 0;

    // numSegs stores the delta between the total and the max. For each
    // input mbuf consumed, we decrement numSegs.
    //
    numSegs -= maxSegs;

    // Loop through the input packet mbuf 'in' and construct a new mbuf chain
    // large enough to make (numSegs + doneSegs + outSegs) less than or
    // equal to zero.
    //  
    do {
        vm_offset_t vmo;
        
        outLen += in->m_len;

        while (outLen > outSize) {
            // Oh dear the current outgoing length is too big.
            if (outSize != MCLBYTES) {
                // Current mbuf is not yet a cluster so promote, then
                // check for error.

                MCLGET(out, M_DONTWAIT);
                if ( !(out->m_flags & M_EXT) ) {
                    IOLog("analyseSegments: MCLGET() error\n");
                    goto bombAnalysis;
                }
                
                outSize = MCLBYTES;
                
                continue;
            }
            
            vmo = mtod(out, vm_offset_t);
            out->m_len = MCLBYTES;  /* Fill in target copy size */
            doneSegs += (round_page(vmo + MCLBYTES) - trunc_page(vmo))
                     /   PAGE_SIZE;

            // If the number of segments of the output chain, plus
            // the segment for the mbuf we are about to allocate is greater
            // than maxSegs, then abort.
            //
            if (doneSegs + 1 > (int) maxSegs) {
                IOLog("analyseSegments: maxSegs limit 1 reached! %ld %ld\n",
                    doneSegs, maxSegs);
                goto bombAnalysis;
            }

            MGET(out->m_next, M_DONTWAIT, MT_DATA);
            if (!out->m_next) {
                IOLog("analyseSegments: MGET() error\n");
                goto bombAnalysis;
            }
            
            out = out->m_next;
            outSize = MLEN;
            outLen -= MCLBYTES;
        }

        // Compute number of segment in current outgoing mbuf.
        vmo = mtod(out, vm_offset_t);
        outSegs = (round_page(vmo + outLen) - trunc_page(vmo)) / PAGE_SIZE;
        if (doneSegs + outSegs > (int) maxSegs) {
            IOLog("analyseSegments: maxSegs limit 2 reached! %ld %ld %ld\n",
                doneSegs, outSegs, maxSegs);
            goto bombAnalysis;
        }

        // Get the number of segments in the current inbuf
        if (inIndex < mbufsInCache)
            numSegs -= segsPerMBuf[inIndex];    // Yeah, in cache
        else {
            // Hmm, we have to recompute from scratch. Copy code from genPhys.
            int thisLen = 0, mbufLen;

            vmo = mtod(in, vm_offset_t);
            for (mbufLen = in->m_len; mbufLen; mbufLen -= thisLen) {
                thisLen = MIN(next_page(vmo), vmo + mbufLen) - vmo;
                vmo += thisLen;
                numSegs--;
            }
        }

        // Walk the incoming buffer on one.
        in = in->m_next;
        inIndex++;

        // continue looping until the total number of segments has dropped
        // to an acceptable level, or if we ran out of mbuf links.

    } while (in && ((numSegs + doneSegs + outSegs) > 0));

    if ( (int) (numSegs + doneSegs + outSegs) <= 0) {   // success

        out->m_len = outLen;    // Set last mbuf with the remaining length.
        
        // The amount to copy is determine by the segment length in each
        // mbuf linked to newPacket. The sum can be smaller than
        // packet->pkthdr.len;
        //
        coalesceSegments(packet, newPacket);
        
        // Copy complete. 
        
        // If 'in' is non zero, then it means that we only need to copy part
        // of the input packet, beginning at the start. The mbuf chain
        // beginning at 'in' must be preserved and linked to the new
        // output packet chain. Everything before 'in', except for the
        // header mbuf can be freed.
        //
        struct mbuf *m = packet->m_next;
        while (m != in)
            m = m_free(m);

        // The initial header mbuf is preserved, its length set to zero, and
        // linked to the new packet chain.
        
        packet->m_len = 0;
        packet->m_next = newPacket;
        newPacket->m_next = in;
        
        return true;
    }

bombAnalysis:

    m_freem(newPacket);
    return false;
}
                               
UInt32 IOMbufMemoryCursor::genPhysicalSegments(struct mbuf *packet, void *vector,
                                       UInt32 maxSegs, bool doCoalesce)
{
    bool doneCoalesce = false;

    if (!packet || !(packet->m_flags & M_PKTHDR))
        return 0;

    if (!maxSegs)
        maxSegs = maxNumSegments;
    if (!maxSegs)
        return 0;

    if ( packet->m_next == 0 )
    {
        vm_offset_t         src;
        struct IOPhysicalSegment    physSeg;
        /*
     * the packet consists of only 1 mbuf
     * so if the data buffer doesn't span a page boundary
     * we can take the simple way out
     */
        src = mtod(packet, vm_offset_t);
            
    if ( trunc_page(src) == trunc_page(src+packet->m_len-1) )
    {
        if ((physSeg.location = 
            (IOPhysicalAddress)mcl_to_paddr((char *)src)) == 0)
            physSeg.location = (IOPhysicalAddress)pmap_extract(kernel_pmap, src);
        if (!physSeg.location)
            return 0;
        physSeg.length = packet->m_len;
        (*outSeg)(physSeg, vector, 0);

        return 1; 
    }
    }

    if ( doCoalesce == true && maxSegs == 1 )
    {
        vm_offset_t         src;
        vm_offset_t                     dst;
        struct mbuf         *m;
        struct mbuf         *mnext;
        struct mbuf         *out;
        UInt32              len = 0;
        struct IOPhysicalSegment    physSeg;

        m = packet;
        
    MGET(out, M_DONTWAIT, MT_DATA);
        if ( out == 0 ) return 0;

        MCLGET(out, M_DONTWAIT);
        if ( !(out->m_flags & M_EXT) )
        {
            m_free( out ); 
            return 0;
        }
        dst = mtod(out, vm_offset_t);

        do 
        {
            src = mtod(m, vm_offset_t);
            BCOPY( src, dst, m->m_len );
            dst += m->m_len;
            len += m->m_len;
        } while ( (m = m->m_next) != 0 );

        out->m_len = len;

        dst = mtod(out, vm_offset_t);
    if ((physSeg.location = (IOPhysicalAddress)mcl_to_paddr((char *)dst)) == 0)
        physSeg.location = (IOPhysicalAddress)pmap_extract(kernel_pmap, dst);
    if (!physSeg.location)
        return 0;
        physSeg.length = out->m_len;
        (*outSeg)(physSeg, vector, 0);

    m = packet->m_next;
    while (m != 0)
        {
            mnext = m->m_next;
        m_free(m);
            m = mnext;
        }

    // The initial header mbuf is preserved, its length set to zero, and
    // linked to the new packet chain.
        
    packet->m_len  = 0;
    packet->m_next = out;
    out->m_next    = 0;

        return 1;             
    }


    //
    // Iterate over the mbuf, translating segments were allowed.  When we
    // are not allowed to translate segments then accumulate segment
    // statistics up to kMBufDataCacheSize of mbufs.  Finally
    // if we overflow our cache just count how many segments this
    // packet represents.
    //
    UInt32 segsPerMBuf[kMBufDataCacheSize];

tryAgain:
    UInt32 curMBufIndex = 0;
    UInt32 curSegIndex = 0;
    UInt32 lastSegCount = 0;
    struct mbuf *m = packet;

    // For each mbuf in incoming packet.
    do {
        vm_size_t mbufLen, thisLen = 0;
        vm_offset_t src;

        // Step through each segment in the current mbuf
        for (mbufLen = m->m_len, src = mtod(m, vm_offset_t);
             mbufLen;
             src += thisLen, mbufLen -= thisLen)
        {
            // If maxSegmentSize is atleast PAGE_SIZE, then
            // thisLen = MIN(next_page(src), src + mbufLen) - src;

            thisLen = MIN(mbufLen, maxSegmentSize);
            thisLen = MIN(next_page(src), src + thisLen) - src;

            // If room left then find the current segment addr and output
            if (curSegIndex < maxSegs) {
                struct IOPhysicalSegment physSeg;

        if ((physSeg.location =
            (IOPhysicalAddress)mcl_to_paddr((char *)src)) == 0)
            physSeg.location = (IOPhysicalAddress)pmap_extract(kernel_pmap, src);
                if (!physSeg.location)
                    return 0;
                physSeg.length = thisLen;
                (*outSeg)(physSeg, vector, curSegIndex);
            }
            // Count segments if we are coalescing. 
            curSegIndex++;
        } 

        // Cache the segment count data if room is available.
        if (curMBufIndex < kMBufDataCacheSize) {
            segsPerMBuf[curMBufIndex] = curSegIndex - lastSegCount;
            lastSegCount = curSegIndex;
        }

        // Move on to next imcoming mbuf
        curMBufIndex++;
        m = m->m_next;
    } while (m);

    // If we finished cleanly return number of segments found
    if (curSegIndex <= maxSegs)
        return curSegIndex;
    if (!doCoalesce)
        return 0;   // if !coalescing we've got a problem.


    // If we are coalescing and it is possible then attempt coalesce, 
    if (!doneCoalesce
    &&  (UInt) packet->m_pkthdr.len <= maxSegs * maxSegmentSize) {
        // Hmm, we have to do some coalescing.
        bool analysisRet;
            
        analysisRet = analyseSegments(packet,
                                      MIN(curMBufIndex, kMBufDataCacheSize),
                                      segsPerMBuf,
                                      curSegIndex, maxSegs);
        if (analysisRet) {
            doneCoalesce = true;
            coalesceCount++;
            goto tryAgain;
        }
    }

    assert(!doneCoalesce);  // Problem in Coalesce code.
    packetTooBigErrors++;
    return 0;
}

/********************* class IOMbufBigMemoryCursor **********************/
IOMbufBigMemoryCursor *
IOMbufBigMemoryCursor::withSpecification(UInt32 maxSegSize, UInt32 maxNumSegs)
{
    IOMbufBigMemoryCursor *me = new IOMbufBigMemoryCursor;

    if (me && !me->initWithSpecification(&bigOutputSegment,
                                         maxSegSize, maxNumSegs)) {
        me->release();
        return 0;
    }

    return me;
}


/******************* class IOMbufNaturalMemoryCursor ********************/
IOMbufNaturalMemoryCursor *
IOMbufNaturalMemoryCursor::withSpecification(UInt32 maxSegSize, UInt32 maxNumSegs)
{
    IOMbufNaturalMemoryCursor *me = new IOMbufNaturalMemoryCursor;

    if (me && !me->initWithSpecification(&naturalOutputSegment,
                                         maxSegSize, maxNumSegs)) {
        me->release();
        return 0;
    }

    return me;
}


/******************** class IOMbufLittleMemoryCursor ********************/
IOMbufLittleMemoryCursor *
IOMbufLittleMemoryCursor::withSpecification(UInt32 maxSegSize, UInt32 maxNumSegs)
{
    IOMbufLittleMemoryCursor *me = new IOMbufLittleMemoryCursor;

    if (me && !me->initWithSpecification(&littleOutputSegment,
                                         maxSegSize, maxNumSegs)) {
        me->release();
        return 0;
    }

    return me;
}


/******************** class IOMbufDBDMAMemoryCursor *********************/
#ifdef __ppc__

IOMbufDBDMAMemoryCursor *
IOMbufDBDMAMemoryCursor::withSpecification(UInt32 maxSegSize, UInt32 maxNumSegs)
{
    IOMbufDBDMAMemoryCursor *me = new IOMbufDBDMAMemoryCursor;

    if (me && !me->initWithSpecification(&dbdmaOutputSegment,
                                         maxSegSize, maxNumSegs)) {
        me->release();
        return 0;
    }

    return me;
}
#endif /* __ppc__ */
