/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved. 
 *
 * AppleATAPIIXTiming.h - Timing tables.
 *
 * HISTORY
 *
 */

#ifndef _APPLEATAPIIXTIMING_H
#define _APPLEATAPIIXTIMING_H

/*
 * Supported transfer protocols. Entries in this table must map to the
 * entries in ATATimingProtocol table.
 */
typedef enum {
    kPIIXProtocolPIO  = 0,
    kPIIXProtocolDMA,
    kPIIXProtocolUDMA33,
    kPIIXProtocolUDMA66,
    kPIIXProtocolLast
} PIIXProtocol;

/*
 * PIIX PIO/DMA timing table.
 */
typedef struct {
    UInt8    pioMode;        // PIO mode
    UInt8    swDMAMode;      // single-word DMA mode (obsolete)
    UInt8    mwDMAMode;      // multiword DMA mode
    UInt8    isp;            // IORDY sample point in PCI clocks
    UInt8    rtc;            // Recovery time in PCI clocks
    UInt16   cycle;          // cycle time in ns
} PIIXTiming;

#define _NVM_    0xff        // not a valid mode

static const
PIIXTiming PIIXPIOTimingTable[] = {
/*  PIO     SW     MW     ISP   RTC   CYCLE (ns)   */
    {0,     0,     0,     5,    4,    600},
    {1,     1,     _NVM_, 5,    4,    600},
    {2,     2,     _NVM_, 4,    4,    240},
    {3,     _NVM_, 1,     3,    3,    180},
    {4,     _NVM_, 2,     3,    1,    120},
    {5,     _NVM_, 2,     3,    1,    120},
};

static const UInt8 PIIXPIOTimingTableSize = sizeof(PIIXPIOTimingTable) / 
                                            sizeof(PIIXPIOTimingTable[0]);

/*
 * PIIX Ultra-DMA/33 timing table.
 */
typedef struct {
    UInt8    mode;           // mode number
    UInt8    ct;             // cycle time in PCI clocks
    UInt8    rp;             // Ready to Pause time in PCI clocks
    UInt8    bits;           // register bit setting
    UInt16   strobe;         // strobe period (cycle) in ns
} PIIXUDMATiming;

static const
PIIXUDMATiming PIIXUDMATimingTable[] = {
/*  MODE    CT     RP     BITS   STROBE/CYCLE (ns)   */
    {0,     4,     6,     0,     120},
    {1,     3,     5,     1,     90},
    {2,     2,     4,     2,     60},
};

static const UInt8
PIIXUDMATimingTableSize = sizeof(PIIXUDMATimingTable) / 
                          sizeof(PIIXUDMATimingTable[0]);

/*
 * For each drive, the following table will store the chosen timings
 * for each supported protocol.
 */
typedef struct {
    UInt8   activeTimings[kPIIXProtocolLast];   // selected timings
    UInt8   validTimings[kPIIXProtocolLast];    // calculated timings
    UInt32  validFlag;
    UInt32  activeFlag;
} PIIXSelectedTimings;

/*
 * Convert from ATATimingProtocol to PIIXProtocol.
 */
inline PIIXProtocol ataToPIIXProtocol(ATATimingProtocol timingProtocol)
{
    int piixProtocol = kPIIXProtocolPIO;
    int ataProtocol  = timingProtocol;
    
    while (ataProtocol != 1) {
        ataProtocol >>= 1; piixProtocol++;
    }
    return ((PIIXProtocol) piixProtocol);
}

/*
 * Misc macros to get information from the PIIXSelectedTimings table.
 */
#define PIIX_ACTIVATE_PROTOCOL(p) {                                  \
    timings[unit].activeTimings[p] = timings[unit].validTimings[p];  \
    timings[unit].activeFlag |= (1 << (p));                          \
}

#define PIIX_DEACTIVATE_PROTOCOL(p) {                                \
    timings[unit].activeFlag &= ~(1 << (p));                         \
}

#define PIIX_GET_ACTIVE_TIMING(p)    (timings[unit].activeTimings[p])

#define PIIX_PROTOCOL_IS_ACTIVE(p)   ((bool) \
                                      (timings[unit].activeFlag & (1 << (p))))

#define PIIX_PROTOCOL_IS_VALID(p)    ((bool) \
                                      (timings[unit].validFlag & (1 << (p))))

#endif /* !_APPLEATAPIIXTIMING_H */
