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

#ifndef _IOMBUFQUEUE_H
#define _IOMBUFQUEUE_H

extern "C" {
#include <sys/param.h>
#include <sys/mbuf.h>
}

struct IOMbufQueue {
    struct mbuf *  head;
    struct mbuf *  tail;
    UInt32         size;
    UInt32         capacity;
};

static __inline__
UInt32 IOMbufFree(struct mbuf * m)
{
/*LD####
    UInt32 count = 0;
    struct mbuf * mn;

    while (( mn = m ))
    {
        m = mn->m_nextpkt;
        mn->m_nextpkt = 0;
        m_freem(mn);
        count++;
    }
    return count;
*/
    return m_freem_list(m);
}

static __inline__
void IOMbufQueueInit(IOMbufQueue * q, UInt32 capacity)
{
    q->head = q->tail = 0;
    q->size = 0;
    q->capacity = capacity;
}

static __inline__
bool IOMbufQueueEnqueue(IOMbufQueue * q, struct mbuf * m)
{
    if (q->size >= q->capacity) return false;

    if (q->size++ > 0)
        q->tail->m_nextpkt = m;
    else
        q->head = m;

    for (q->tail = m;
         q->tail->m_nextpkt;
         q->tail = q->tail->m_nextpkt, q->size++)
        ;

    return true;
}

static __inline__
bool IOMbufQueueEnqueue(IOMbufQueue * q, IOMbufQueue * qe)
{
    if (qe->size)
    {
        if (q->size == 0)
            q->head = qe->head;
        else
            q->tail->m_nextpkt = qe->head;
        q->tail  = qe->tail;
        q->size += qe->size;

        qe->head = qe->tail = 0;
        qe->size = 0;
    }
    return true;
}

static __inline__
void IOMbufQueuePrepend(IOMbufQueue * q, struct mbuf * m)
{
    struct mbuf * tail;

    for (tail = m, q->size++;
         tail->m_nextpkt;
         tail = tail->m_nextpkt, q->size++)
        ;

    tail->m_nextpkt = q->head;
    if (q->tail == 0)
        q->tail = tail;
    q->head = m;
}

static __inline__
void IOMbufQueuePrepend(IOMbufQueue * q, IOMbufQueue * qp)
{
    if (qp->size)
    {
        qp->tail->m_nextpkt = q->head;
        if (q->tail == 0)
            q->tail = qp->tail;
        q->head  = qp->head;
        q->size += qp->size;

        qp->head = qp->tail = 0;
        qp->size = 0;
    }
}

static __inline__
struct mbuf * IOMbufQueueDequeue(IOMbufQueue * q)
{   
    struct mbuf * m = q->head;
    if (m)
    {
        if ((q->head = m->m_nextpkt) == 0)
            q->tail = 0;
        m->m_nextpkt = 0;
        q->size--;
    }
    return m;
}

static __inline__
struct mbuf * IOMbufQueueDequeueAll(IOMbufQueue * q)
{
    struct mbuf * m = q->head;
    q->head = q->tail = 0;
    q->size = 0;
    return m;
}

static __inline__
struct mbuf * IOMbufQueuePeek(IOMbufQueue * q)
{
    return q->head;
}

static __inline__
UInt32 IOMbufQueueGetSize(IOMbufQueue * q)
{
    return q->size;
}

static __inline__
UInt32 IOMbufQueueGetCapacity(IOMbufQueue * q)
{
    return q->capacity;
}

static __inline__
void IOMbufQueueSetCapacity(IOMbufQueue * q, UInt32 capacity)
{
	q->capacity = capacity;
}

#endif /* !_IOMBUFQUEUE_H */
