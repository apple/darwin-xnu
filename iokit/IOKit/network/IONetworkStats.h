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
 * IONetworkStats.h
 *
 * HISTORY
 */

#ifndef _IONETWORKSTATS_H
#define _IONETWORKSTATS_H

/*! @header IONetworkStats.h
    @discussion Generic network statistics. */

//------------------------------------------------------------------------
// Generic network statistics. Common to all network interfaces.
//
// WARNING: This structure must match the statistics field in
// ifnet->if_data. This structure will overlay a portion of ifnet.

/*! @typedef IONetworkStats
        @discussion Generic network statistics structure.
        @field inputPackets count input packets.
        @field inputErrors count input errors.
        @field outputPackets count output packets.
        @field outputErrors count output errors.
        @field collisions count collisions on CDMA networks. */

typedef struct {
        UInt32  inputPackets;
        UInt32  inputErrors;
        UInt32  outputPackets;
        UInt32  outputErrors;
        UInt32  collisions;
} IONetworkStats;

/*! @defined kIONetworkStatsKey
        @discussion Defines the name of an IONetworkData that contains
        an IONetworkStats. */

#define kIONetworkStatsKey              "IONetworkStatsKey"

//------------------------------------------------------------------------
// Output queue statistics.

/*! @typedef IOOutputQueueStats
        @discussion Statistics recorded by IOOutputQueue objects.
        @field capacity queue capacity.
        @field size current size of the queue.
        @field peakSize peak size of the queue.
        @field dropCount number of packets dropped.
        @field outputCount number of output packets.
        @field retryCount number of retries.
        @field stallCount number of queue stalls. */

typedef struct {
        UInt32  capacity;
        UInt32  size;
        UInt32  peakSize;
        UInt32  dropCount;
        UInt32  outputCount;
        UInt32  retryCount;
        UInt32  stallCount;
        UInt32  reserved[4];
} IOOutputQueueStats;

/*! @defined kIOOutputQueueStatsKey
        @discussion Defines the name of an IONetworkData that contains
        an IOOutputQueueStats. */

#define kIOOutputQueueStatsKey          "IOOutputQueueStatsKey"

#endif /* !_IONETWORKSTATS_H */
