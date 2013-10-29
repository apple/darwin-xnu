/*
 * @APPLE_LICENSE_HEADER_START@
 *
 * Copyright (c) 2012 Apple Computer, Inc.  All Rights Reserved.
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

#ifndef _IOREPORT_MACROS_H_
#define _IOREPORT_MACROS_H_

#include "IOReportTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    Background

    These macros allow non-I/O Kit software to generate IOReporting
    reports.  Clients must prevent concurrent access to any given
    report buffer from multiple threads.

    While these macros allow non-I/O Kit software to participate
    in IOReporting, an IOService instance must lend its driver ID,
    respond to the appropriate IOService overrides, and shuttle
    data back and forth.  In some cases, it may be useful to have
    the I/O Kit driver initialize the report buffer with the
    appropriate macro.
*/

/*
 * Returns the buffer size required for a Simple report.
 */
#define SIMPLEREPORT_BUFSIZE   (sizeof(IOReportElement))

/*
 * Initialize a buffer to hold a Simple (integer) report.
 *
 *                  void* buffer - ptr to SIMPLEREPORT_BUFSIZE bytes
 *                size_t bufSize - sanity check of buffer's size
 *           uint64_t providerID - registry Entry ID of the reporting service
 *            uint64_t channelID - the report's channel ID
 * IOReportCategories categories - categories of this channel
 *
 * If the buffer is not of sufficient size, the macro performs a
 * null pointer reference to trigger a segfault.  Then, the buffer is
 * filled with 0xbadcafe.
 */
#define SIMPLEREPORT_INIT(buffer, bufSize, providerID, channelID, cats)  \
do {  \
    IOReportElement     *__elem = (IOReportElement *)(buffer);  \
    IOSimpleReportValues *__vals;  \
    if ((bufSize) >= SIMPLEREPORT_BUFSIZE) {  \
        __elem->channel_id = (channelID);  \
        __elem->provider_id = (providerID);  \
        __elem->channel_type.report_format = kIOReportFormatSimple;  \
        __elem->channel_type.reserved = 0;  \
        __elem->channel_type.categories = (cats);  \
        __elem->channel_type.nelements = 1;  \
        __elem->channel_type.element_idx = 0;  \
        __elem->timestamp = 0;  \
		__vals = (IOSimpleReportValues*)&__elem->values;  \
		__vals->simple_value = kIOReportInvalidValue;  \
    }  \
    else {  \
        uint32_t *__nptr = NULL;  \
        *__nptr = 1;  \
        POLLUTE_BUF((buffer), (bufSize));  \
    }  \
} while(0)


/*
 * Sets the SimpleReport channel to a new value.
 *
 *     void* simp_buf - ptr to memory initialized by SIMPLEREPORT_INIT()
 * uint64_t new_value - new value for the channel
 */
#define SIMPLEREPORT_SETVALUE(simp_buf, new_value)  \
do {  \
    IOReportElement *__elem = (IOReportElement *)(simp_buf);  \
    IOSimpleReportValues *__vals;  \
    __vals = (IOSimpleReportValues*)&__elem->values;  \
    __vals->simple_value = (new_value);  \
} while(0)

/*
 * Prepare simple report buffer for
 * IOService::updateReport(kIOReportCopyChannelData...)
 *
 * void* simp_buf  - Ptr to memory updated by SIMPLEREPORT_SETVALUE()
 * void* ptr2cpy   - On return, 'ptr2cpy' points to the memory that needs to be
 *                   copied for kIOReportCopyChannelData.
 * size_t size2cpy - On return, 'size2cpy' is set to the size of the report
 *                   data that needs to be copied for kIOReportCopyChannelData.
 */
#define SIMPLEREPORT_UPDATEPREP(simp_buf, ptr2cpy, size2cpy)  \
do {  \
    (ptr2cpy) = (simp_buf);  \
    (size2cpy) = sizeof(IOReportElement);  \
} while(0)


/*
 * Updates the result field received as a parameter for
 * kIOReportGetDimensions & kIOReportCopyChannelData actions.
 *
 * IOReportConfigureAction action - configure/updateReport() 'action' param
 *                   void* result - configure/updateReport() 'result' param
 */

#define SIMPLEREPORT_UPDATERES(action, result)  \
do {  \
    if (((action) == kIOReportGetDimensions) || ((action) == kIOReportCopyChannelData)) {  \
        int *__nElements = (int *)(result);  \
        *__nElements += 1;  \
    }  \
} while (0)



/*
 * Returns the channel id from the buffer previously initialized by
 * SIMPLEREPORT_INIT().
 *
 * void* simp_buf - ptr to memory initialized by SIMPLEREPORT_INIT()
 */

#define SIMPLEREPORT_GETCHID(simp_buf)  \
    (((IOReportElement *)(simp_buf))->channel_id);  \



// Internal struct for State report buffer
typedef struct {
   uint16_t        curr_state;
   uint64_t        update_ts;
   IOReportElement elem[]; // Array of elements
} IOStateReportInfo;

/*
 * Returns the size required to be allocated for using STATEREPORT_*()
 *
 * int nstates - number of states for the intended channel
 */
#define STATEREPORT_BUFSIZE(nstates)  \
    (sizeof(IOStateReportInfo) + (nstates) * sizeof(IOReportElement))


/*
 * Initializes a buffer so it can be used with STATEREPORT_*().
 *
 *                   int nstates - number of states to be reported
 *                  void* buffer - ptr to STATEREPORT_BUFSIZE(nstates) bytes
 *                size_t bufSize - sanity check of buffer's size
 *           uint64_t providerID - registry Entry ID of the reporting service
 *            uint64_t channelID - ID of this channel, see IOREPORT_MAKEID()
 * IOReportCategories categories - categories of this channel
 *
 * If the buffer is not of sufficient size, the macro performs a
 * null pointer reference to trigger a segfault.  Then, the buffer is
 * filled with 0xbadcafe.
 */
#define STATEREPORT_INIT(nstates, buf, bufSize, providerID, channelID, cats) \
do {  \
    IOStateReportInfo *__info = (IOStateReportInfo *)(buf);  \
    IOStateReportValues *__rep;  \
    IOReportElement     *__elem;  \
    if ((bufSize) >= STATEREPORT_BUFSIZE(nstates)) {  \
        for (unsigned __no = 0; __no < (nstates); __no++) {  \
            __elem =  &(__info->elem[__no]);  \
            __rep = (IOStateReportValues *) &(__elem->values);  \
            __elem->channel_id = (channelID);  \
            __elem->provider_id = (providerID);  \
            __elem->channel_type.report_format = kIOReportFormatState;  \
            __elem->channel_type.reserved = 0;  \
            __elem->channel_type.categories = (cats);  \
            __elem->channel_type.nelements = (nstates);  \
            __elem->channel_type.element_idx = __no;  \
            __elem->timestamp = 0;  \
            __rep->state_id = __no;  \
            __rep->intransitions = 0;  \
            __rep->upticks = 0;  \
        }  \
        __info->curr_state = 0;  \
        __info->update_ts = 0;  \
    }  \
    else {  \
        int *__nptr = NULL;  \
        *__nptr = 1;  \
        POLLUTE_BUF((buf), (bufSize));  \
    }  \
} while(0)

/*
 * Initializes the state id field of a state with the specified value.  By
 * default, STATEREPORT_INIT initializes the state id with the index of
 * that state.  This macro can be used to provide a more descriptive state id.
 *
 *   void* state_buf - ptr to memory initialized by STATEREPORT_INIT()
 * unsigned stateIdx - index of the state, out of bounds -> no-op
 *  uint64_t stateID - new state id, see IOREPORT_MAKEID()
 */
#define STATEREPORT_SETSTATEID(state_buf, stateIdx, stateID)  \
do {  \
    IOStateReportInfo *__info = (IOStateReportInfo *)(state_buf);  \
    IOStateReportValues *__rep;  \
    if ((stateIdx) < __info->elem[0].channel_type.nelements) {  \
        __rep = (IOStateReportValues*) &(__info->elem[(stateIdx)].values);  \
        __rep->state_id = (stateID);  \
    }  \
} while (0)


/*
 * Set the state of a State report.
 *
 *      void* state_buf - pointer to memory initialized by STATEREPORT_INIT()
 * unsigned newStateIdx - index of new state, out of bounds -> no-op
 *  uint64_t changeTime - time at which the transition occurred
 */
#define STATEREPORT_SETSTATE(state_buf, newStateIdx, changeTime)  \
do {  \
    IOStateReportInfo *__info = (IOStateReportInfo *)(state_buf);  \
    IOStateReportValues *__rep;  \
    if ((newStateIdx) < __info->elem[0].channel_type.nelements ) {  \
        __rep = (IOStateReportValues*) &(__info->elem[__info->curr_state].values);  \
        if (__info->update_ts)  \
            __rep->upticks += (changeTime) - __info->update_ts;  \
        __info->elem[(newStateIdx)].timestamp = (changeTime);  \
        __rep = (IOStateReportValues*) &(__info->elem[(newStateIdx)].values);  \
        __rep->intransitions++;  \
        __info->curr_state = (newStateIdx);  \
        __info->update_ts = (changeTime);  \
    }  \
} while(0)

/*
 * Prepare StateReport for UpdateReport call
 *
 *      void* state_buf - ptr to memory initialized by STATEREPORT_INIT()
 * uint64_t currentTime - current timestamp
 *        void* ptr2cpy - filled in with pointer to buffer to be copied out
 *      size_t size2cpy - filled in with the size of the buffer to copy out
 */
#define STATEREPORT_UPDATEPREP(state_buf, currentTime, ptr2cpy, size2cpy)  \
do {  \
    IOStateReportInfo *__info = (IOStateReportInfo *)(state_buf);  \
    IOReportElement     *__elem;  \
    IOStateReportValues *__state;  \
    (size2cpy) = __info->elem[0].channel_type.nelements * sizeof(IOReportElement);  \
    (ptr2cpy) =  (void *) &__info->elem[0];  \
    if (__info->update_ts)  {  \
        __elem = &__info->elem[__info->curr_state];  \
        __state = (IOStateReportValues *)&__elem->values;  \
        __elem->timestamp = (currentTime);  \
        __state->upticks  += (currentTime) - __info->update_ts;  \
        __info->update_ts = (currentTime);  \
    }  \
} while(0)

/*
 * Updates the result field received as a parameter for kIOReportGetDimensions &
 * kIOReportCopyChannelData actions.
 *
 *                void* state_buf - memory initialized by STATEREPORT_INIT()
 * IOReportConfigureAction action - configure/updateReport() 'action'
 *                   void* result - configure/updateReport() 'result'
 */

#define STATEREPORT_UPDATERES(state_buf, action, result)  \
do {  \
    IOStateReportInfo *__info = (IOStateReportInfo *)(state_buf);  \
    IOReportElement     *__elem;  \
    int *__nElements = (int *)(result);  \
    if (((action) == kIOReportGetDimensions) || ((action) == kIOReportCopyChannelData)) {  \
        __elem =  &(__info->elem[0]);  \
        *__nElements += __elem->channel_type.nelements;  \
    }  \
} while (0)



/*
 * Returns the channel id from the buffer previously initialized by STATEREPORT_INIT().
 *
 * void* state_buf - ptr to memory initialized by STATEREPORT_INIT()
 */

#define STATEREPORT_GETCHID(state_buf)  \
    (((IOStateReportInfo *)(state_buf))->elem[0].channel_id)

/*
 * Returns number of transitions occurred from the given state
 *
 *   void* state_buf - ptr to memory initialized by STATEREPORT_INIT()
 * unsigned stateIdx - index of state, out of bounds -> kIOReportInvalidValue
 *
 */

#define STATEREPORT_GETTRANSITIONS(state_buf, stateIdx)  \
    (((stateIdx) < ((IOStateReportInfo *)(state_buf))->elem[0].channel_type.nelements)  \
        ? ((IOStateReportValues*)&(((IOStateReportInfo*)(state_buf))->elem[(stateIdx)].values))->intransitions  \
        : kIOReportInvalidValue)

/*
 * Returns the total number of ticks spent in the given state.
 *
 *   void* state_buf - ptr to memory initialized by STATEREPORT_INIT()
 * unsigned stateIdx - index of state, out of bounds -> kIOReportInvalidValue
 */

#define STATEREPORT_GETTICKS(state_buf, stateIdx)  \
    (((stateIdx) < ((IOStateReportInfo*)(state_buf))->elem[0].channel_type.nelements)  \
        ? ((IOStateReportValues*)&(((IOStateReportInfo*)(state_buf))->elem[(stateIdx)].values))->upticks  \
        : kIOReportInvalidValue)


#define POLLUTE_BUF(buf, bufSize)  \
do {  \
    int __cnt = (bufSize)/sizeof(uint32_t);  \
    while (--__cnt >= 0)  \
        ((uint32_t*)(buf))[__cnt] = 0xbadcafe;  \
} while (0)

#ifdef __cplusplus
}
#endif

#endif // _IOREPORT_MACROS_H_


