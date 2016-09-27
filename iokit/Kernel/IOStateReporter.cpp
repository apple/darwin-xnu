/*
 * Copyright (c) 2012-2013 Apple Computer, Inc.  All Rights Reserved.
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

#include <IOKit/IOKernelReportStructs.h>
#include <IOKit/IOKernelReporters.h>
#include "IOReporterDefs.h"


#define super IOReporter
OSDefineMetaClassAndStructors(IOStateReporter, IOReporter);


/* static */
IOStateReporter*
IOStateReporter::with(IOService *reportingService,
                      IOReportCategories categories,
                      int nstates,
                      IOReportUnits unit/* = kIOReportUnitHWTicks*/)
{
    IOStateReporter *reporter, *rval = NULL;
    
    // kprintf("%s\n", __func__);      // can't IORLOG() from static
    
    reporter = new IOStateReporter;
    if (!reporter)      goto finish;

    if (!reporter->initWith(reportingService, categories, nstates, unit)) {
        goto finish;
    }
    
    // success
    rval = reporter;
    
finish:
    if (!rval) {
        OSSafeReleaseNULL(reporter);
    }
    
    return rval;
}

bool
IOStateReporter::initWith(IOService *reportingService,
                          IOReportCategories categories,
                          int16_t nstates,
                          IOReportUnits unit)
{
    bool success = false;
    
    IOReportChannelType channelType = {
        .categories = categories,
        .report_format = kIOReportFormatState,
        .nelements = static_cast<uint16_t>(nstates),
        .element_idx = 0
    };
    
    if(super::init(reportingService, channelType, unit) != true) {
        IORLOG("ERROR super::initWith failed");
        success = false;
        goto finish;
    }
    
    _currentStates = NULL;
    _lastUpdateTimes = NULL;
    
    success = true;
    
finish:    
    return success;
}


void
IOStateReporter::free(void)
{
    if (_currentStates) {
        PREFL_MEMOP_PANIC(_nChannels, int);
        IOFree(_currentStates, (size_t)_nChannels * sizeof(int));
    }
    if (_lastUpdateTimes) {
        PREFL_MEMOP_PANIC(_nChannels, uint64_t);
        IOFree(_lastUpdateTimes, (size_t)_nChannels * sizeof(uint64_t));
    }
    
    super::free();
}


IOReturn
IOStateReporter::handleSwapPrepare(int newNChannels)
{
    IOReturn res = kIOReturnError;
    size_t newCurStatesSize, newTSSize;
    
    //IORLOG("handleSwapPrepare (state) _nChannels before = %u", _nChannels);
    
    IOREPORTER_CHECK_CONFIG_LOCK();

    if (_swapCurrentStates || _swapLastUpdateTimes) {
        panic("IOStateReporter::_swap* already in use");
    }
    
    // new currentStates buffer
    PREFL_MEMOP_FAIL(newNChannels, int);
    newCurStatesSize = (size_t)newNChannels * sizeof(int);
    _swapCurrentStates = (int*)IOMalloc(newCurStatesSize);
    if (_swapCurrentStates == NULL) {
        res = kIOReturnNoMemory; goto finish;
    }
    memset(_swapCurrentStates, -1, newCurStatesSize);   // init w/"no state"
    
    // new timestamps buffer
    PREFL_MEMOP_FAIL(newNChannels, uint64_t);
    newTSSize = (size_t)newNChannels * sizeof(uint64_t);
    _swapLastUpdateTimes = (uint64_t *)IOMalloc(newTSSize);
    if (_swapLastUpdateTimes == NULL) {
        res = kIOReturnNoMemory; goto finish;
    }
    memset(_swapLastUpdateTimes, 0, newTSSize);

    res = super::handleSwapPrepare(newNChannels);
    
finish:
    if (res) {
        if (_swapCurrentStates) {
            IOFree(_swapCurrentStates, newCurStatesSize);
            _swapCurrentStates = NULL;
        }
        if (_swapLastUpdateTimes) {
            IOFree(_swapLastUpdateTimes, newTSSize);
            _swapLastUpdateTimes = NULL;
        }
    }

    return res;
}

IOReturn
IOStateReporter::handleAddChannelSwap(uint64_t channelID,
                                      const OSSymbol *symChannelName)
{
    IOReturn res = kIOReturnError;
    int cnt;
    int *tmpCurStates;
    uint64_t *tmpTimestamps;
    bool swapComplete = false;
    
    //IORLOG("IOStateReporter::handleSwap");
    
    if (!_swapCurrentStates || !_swapLastUpdateTimes) {
        IORLOG("IOReporter::handleSwap ERROR swap variables uninitialized!");
        goto finish;
    }
    
    IOREPORTER_CHECK_CONFIG_LOCK();
    IOREPORTER_CHECK_LOCK();
    
    // Copy any existing buffers
    if (_currentStates) {
        PREFL_MEMOP_FAIL(_nChannels, int);
        memcpy(_swapCurrentStates, _currentStates,
               (size_t)_nChannels * sizeof(int));
        
        if (!_lastUpdateTimes) {
            panic("IOStateReporter::handleAddChannelSwap _lastUpdateTimes unset despite non-NULL _currentStates");
        }
        PREFL_MEMOP_FAIL(_nChannels, uint64_t);
        memcpy(_swapLastUpdateTimes, _lastUpdateTimes,
               (size_t)_nChannels * sizeof(uint64_t));
    }
    
    // Update principal instance variables, keep old values in _swap* for cleanup
    tmpCurStates = _currentStates;
    _currentStates = _swapCurrentStates;
    _swapCurrentStates = tmpCurStates;

    tmpTimestamps = _lastUpdateTimes;
    _lastUpdateTimes = _swapLastUpdateTimes;
    _swapLastUpdateTimes = tmpTimestamps;

    swapComplete = true;
    
    // subclass success

    // invoke superclass(es): base class updates _nChannels & _nElements
    res = super::handleAddChannelSwap(channelID, symChannelName);
    if (res) {
        IORLOG("handleSwap(state) ERROR super::handleSwap failed!");
        goto finish;
    }
    
    // Channel added successfully, initialize the new channel's state_ids to 0..nStates-1
    for (cnt = 0; cnt < _channelDimension; cnt++) {
        handleSetStateID(channelID, cnt, (uint64_t)cnt);
    }
    
finish:
    if (res && swapComplete) {
        // unswap so the unused buffers get cleaned up
        tmpCurStates = _currentStates;
        _currentStates = _swapCurrentStates;
        _swapCurrentStates = tmpCurStates;

        tmpTimestamps = _lastUpdateTimes;
        _lastUpdateTimes = _swapLastUpdateTimes;
        _swapLastUpdateTimes = tmpTimestamps;
    }

    return res;
}


void
IOStateReporter::handleSwapCleanup(int swapNChannels)
{
    IOREPORTER_CHECK_CONFIG_LOCK();

    super::handleSwapCleanup(swapNChannels);

    if (_swapCurrentStates) {
        PREFL_MEMOP_PANIC(swapNChannels, int);
        IOFree(_swapCurrentStates, (size_t)swapNChannels * sizeof(int));
        _swapCurrentStates = NULL;
    }
    if (_swapLastUpdateTimes) {
        PREFL_MEMOP_PANIC(swapNChannels, uint64_t);
        IOFree(_swapLastUpdateTimes, (size_t)swapNChannels * sizeof(uint64_t));
        _swapLastUpdateTimes = NULL;
    }
}


IOReturn
IOStateReporter::_getStateIndices(uint64_t channel_id,
                                  uint64_t state_id,
                                  int *channel_index,
                                  int *state_index)
{
    IOReturn res = kIOReturnError;
    int cnt;
    IOStateReportValues *values;
    int element_index = 0;
    
    IOREPORTER_CHECK_LOCK();
    
    if (getChannelIndices(channel_id,
                          channel_index,
                          &element_index) != kIOReturnSuccess) {
        res = kIOReturnBadArgument;

        goto finish;
    }
    
    for (cnt = 0; cnt < _channelDimension; cnt++) {
        
        values = (IOStateReportValues *)getElementValues(element_index + cnt);
        
        if (values == NULL) {

            res = kIOReturnError;
            goto finish;
        }
        
        if (values->state_id == state_id) {
            *state_index = cnt;
            res = kIOReturnSuccess;
            goto finish;
        }
    }
    
    res = kIOReturnBadArgument;
    
finish:
    return res;
}


IOReturn
IOStateReporter::setChannelState(uint64_t channel_id,
                                 uint64_t new_state_id)
{
    IOReturn res = kIOReturnError;
    int channel_index, new_state_index;
    uint64_t last_intransition = 0;
    uint64_t prev_state_residency = 0;
    
    lockReporter();
    
    if (_getStateIndices(channel_id, new_state_id, &channel_index, &new_state_index) == kIOReturnSuccess) {
        res = handleSetStateByIndices(channel_index, new_state_index,
                                      last_intransition,
                                      prev_state_residency);
        goto finish;
    }
    
    res = kIOReturnBadArgument;
    
finish:
    unlockReporter();
    return res;
}

IOReturn
IOStateReporter::setChannelState(uint64_t channel_id,
                                 uint64_t new_state_id,
                                 uint64_t last_intransition,
                                 uint64_t prev_state_residency)
{
    return setChannelState(channel_id, new_state_id);
}

IOReturn
IOStateReporter::overrideChannelState(uint64_t channel_id,
                                      uint64_t state_id,
                                      uint64_t time_in_state,
                                      uint64_t intransitions,
                                      uint64_t last_intransition /*=0*/)
{
    IOReturn res = kIOReturnError;
    int channel_index, state_index;
    
    lockReporter();
    
    if (_getStateIndices(channel_id, state_id, &channel_index, &state_index) == kIOReturnSuccess) {
        
        if (_lastUpdateTimes[channel_index]) {
            panic("overrideChannelState() cannot be used after setChannelState()!\n");
        }
        
        res = handleOverrideChannelStateByIndices(channel_index, state_index,
                                                  time_in_state, intransitions,
                                                  last_intransition);
        goto finish;
    }
    
    res = kIOReturnBadArgument;
    
finish:
    unlockReporter();
    return res;
}


IOReturn
IOStateReporter::handleOverrideChannelStateByIndices(int channel_index,
                                             int state_index,
                                             uint64_t time_in_state,
                                             uint64_t intransitions,
                                             uint64_t last_intransition /*=0*/)
{
    IOReturn kerr, result = kIOReturnError;
    IOStateReportValues state_values;
    int element_index;
    
    if (channel_index < 0 || channel_index >= _nChannels) {
        result = kIOReturnBadArgument; goto finish;
    }
    
    if (channel_index < 0 || channel_index > (_nElements - state_index)
                                             / _channelDimension) {
        result = kIOReturnOverrun; goto finish;
    }
    element_index = channel_index * _channelDimension + state_index;
    
    kerr = copyElementValues(element_index,(IOReportElementValues*)&state_values);
    if (kerr) {
        result = kerr; goto finish;
    }
    
    // last_intransition = 0 -> no current state ("residency summary only")
    state_values.last_intransition = last_intransition;
    state_values.intransitions = intransitions;
    state_values.upticks = time_in_state;
    
    // determines current time for metadata
    kerr = setElementValues(element_index, (IOReportElementValues *)&state_values);
    if (kerr) {
        result = kerr; goto finish;
    }
    
    // success
    result = kIOReturnSuccess;
    
finish:
    return result;
}


IOReturn
IOStateReporter::incrementChannelState(uint64_t channel_id,
                                       uint64_t state_id,
                                       uint64_t time_in_state,
                                       uint64_t intransitions,
                                       uint64_t last_intransition /*=0*/)
{
    IOReturn res = kIOReturnError;
    int channel_index, state_index;
    
    lockReporter();
    
    if (_getStateIndices(channel_id, state_id, &channel_index, &state_index) == kIOReturnSuccess) {
        
        if (_lastUpdateTimes[channel_index]) {
            panic("incrementChannelState() cannot be used after setChannelState()!\n");
        }
        
        res = handleIncrementChannelStateByIndices(channel_index, state_index,
                                                   time_in_state, intransitions,
                                                   last_intransition);
        goto finish;
    }
    
    res = kIOReturnBadArgument;
    
finish:
    unlockReporter();
    return res;

}


IOReturn
IOStateReporter::handleIncrementChannelStateByIndices(int channel_index,
                                                      int state_index,
                                                      uint64_t time_in_state,
                                                      uint64_t intransitions,
                                                      uint64_t last_intransition /*=0*/)
{
    IOReturn kerr, result = kIOReturnError;
    IOStateReportValues state_values;
    int element_index;
    
    if (channel_index < 0 || channel_index >= _nChannels) {
        result = kIOReturnBadArgument; goto finish;
    }
    
    if (channel_index < 0 || channel_index > (_nElements - state_index)
                                             / _channelDimension) {
        result = kIOReturnOverrun; goto finish;
    }
    element_index = channel_index * _channelDimension + state_index;
    
    kerr = copyElementValues(element_index,(IOReportElementValues*)&state_values);
    if (kerr) {
        result = kerr;
        goto finish;
    }

    state_values.last_intransition = last_intransition;
    state_values.intransitions += intransitions;
    state_values.upticks += time_in_state;
    
    // determines current time for metadata
    kerr = setElementValues(element_index, (IOReportElementValues *)&state_values);
    if (kerr) {
        result = kerr;
        goto finish;
    }
    
    // success
    result = kIOReturnSuccess;
    
finish:
    return result;
}


IOReturn
IOStateReporter::setState(uint64_t new_state_id)
{
    uint64_t last_intransition = 0;
    uint64_t prev_state_residency = 0;
    IOReturn res = kIOReturnError;
    IOStateReportValues *values;
    int channel_index = 0, element_index = 0, new_state_index = 0;
    int cnt;
    
    lockReporter();
    
    if (_nChannels == 1) {

        for (cnt = 0; cnt < _channelDimension; cnt++) {
            
            new_state_index = element_index + cnt;
            
            values = (IOStateReportValues *)getElementValues(new_state_index);
            
            if (values == NULL) {
                res = kIOReturnError;
                goto finish;
            }
                        
            if (values->state_id == new_state_id) {
                
                res = handleSetStateByIndices(channel_index, new_state_index,
                                              last_intransition,
                                              prev_state_residency);
                goto finish;
            }
        }
    }
    
    res = kIOReturnBadArgument;

finish:
    unlockReporter();
    return res;
}

IOReturn
IOStateReporter::setState(uint64_t new_state_id,
                          uint64_t last_intransition,
                          uint64_t prev_state_residency)
{
    return setState(new_state_id);
}

IOReturn
IOStateReporter::setStateID(uint64_t channel_id,
                            int state_index,
                            uint64_t state_id)
{
    IOReturn res = kIOReturnError;
    
    lockReporter();
    
    res = handleSetStateID(channel_id, state_index, state_id);
    
    unlockReporter();
    
    return res;    
}


IOReturn
IOStateReporter::handleSetStateID(uint64_t channel_id,
                                  int state_index,
                                  uint64_t state_id)
{
    IOReturn res = kIOReturnError;
    IOStateReportValues state_values;
    int element_index = 0;
    
    IOREPORTER_CHECK_LOCK();
    
    if (getFirstElementIndex(channel_id, &element_index) == kIOReturnSuccess) {
        
        if (state_index >= _channelDimension) {
            res = kIOReturnBadArgument; goto finish;
        }
        if (_nElements - state_index <= element_index) {
            res = kIOReturnOverrun; goto finish;
        }
        element_index += state_index;
        
        if (copyElementValues(element_index, (IOReportElementValues *)&state_values) != kIOReturnSuccess) {
            res = kIOReturnBadArgument;
            goto finish;
        }
        
        state_values.state_id = state_id;
        
        res = setElementValues(element_index, (IOReportElementValues *)&state_values);
    }
    
    // FIXME: set a bit somewhere (reporter-wide?) that state_ids can no longer be
    // assumed to be contiguous
finish:
    return res;
}

IOReturn
IOStateReporter::setStateByIndices(int channel_index,
                                   int new_state_index)
{
    IOReturn res = kIOReturnError;
    uint64_t last_intransition = 0;
    uint64_t prev_state_residency = 0;
    
    lockReporter();
    
    res = handleSetStateByIndices(channel_index, new_state_index,
                                  last_intransition, prev_state_residency);
    
    unlockReporter();
    
    return res;
}

IOReturn
IOStateReporter::setStateByIndices(int channel_index,
                                   int new_state_index,
                                   uint64_t last_intransition,
                                   uint64_t prev_state_residency)
{
    return setStateByIndices(channel_index, new_state_index);
}

IOReturn
IOStateReporter::handleSetStateByIndices(int channel_index,
                                         int new_state_index,
                                         uint64_t last_intransition,
                                         uint64_t prev_state_residency)
{
    IOReturn res = kIOReturnError;
    
    IOStateReportValues curr_state_values, new_state_values;
    int curr_state_index = 0;
    int curr_element_index, new_element_index;
    uint64_t last_ch_update_time = 0;
    uint64_t recordTime = mach_absolute_time();
    
    IOREPORTER_CHECK_LOCK();
    
    if (channel_index < 0 || channel_index >= _nChannels) {
        res = kIOReturnBadArgument; goto finish;
    }
    
    // if no timestamp provided, last_intransition = time of recording (now)
    if (last_intransition == 0) {
        last_intransition = recordTime;
    }

    // First update target state if different than the current state
    // _currentStates[] initialized to -1 to detect first state transition
    curr_state_index = _currentStates[channel_index];
    if (new_state_index != curr_state_index) {
        // fetch element data
        if (channel_index < 0 || channel_index > (_nElements-new_state_index)
                                                 / _channelDimension) {
            res = kIOReturnOverrun; goto finish;
        }
        new_element_index = channel_index*_channelDimension + new_state_index;
        if (copyElementValues(new_element_index,
                              (IOReportElementValues *)&new_state_values)) {
            res = kIOReturnBadArgument;
            goto finish;
        }
    
        // Update new state's transition info
        new_state_values.intransitions += 1;
        new_state_values.last_intransition = last_intransition;

        // and store the values
        res = setElementValues(new_element_index,
                               (IOReportElementValues *)&new_state_values,
                               recordTime);

        if (res != kIOReturnSuccess) {
            goto finish;
        }
        
        _currentStates[channel_index] = new_state_index;
    }
    
    /* Now update time spent in any previous state
       If new_state_index = curr_state_index, this updates time in the
       current state.  If this is the channel's first state transition,
       the last update time will be zero.

       Note: While setState() should never be called on a channel being
       updated with increment/overrideChannelState(), that's another way
       that the last update time might not exist.  Regardless, if there
       is no basis for determining time spent in previous state, there's
       nothing to update!
     */
    last_ch_update_time = _lastUpdateTimes[channel_index];
    if (last_ch_update_time != 0) {
        if (channel_index < 0 || channel_index > (_nElements-curr_state_index)
                                                 / _channelDimension) {
            res = kIOReturnOverrun; goto finish;
        }
        curr_element_index = channel_index*_channelDimension + curr_state_index;
        if (copyElementValues(curr_element_index,
                              (IOReportElementValues *)&curr_state_values)) {
            res = kIOReturnBadArgument;
            goto finish;
        }
        // compute the time spent in previous state, unless provided
        if (prev_state_residency == 0) {
            prev_state_residency = last_intransition - last_ch_update_time;
        }
        
        curr_state_values.upticks += prev_state_residency;
        
        res = setElementValues(curr_element_index,
                               (IOReportElementValues*)&curr_state_values,
                               recordTime);
        
        if (res != kIOReturnSuccess) {
            goto finish;
        }
    }
    
    // record basis for next "time in prior state" calculation
    // (also arms a panic in override/incrementChannelState())
    _lastUpdateTimes[channel_index] = last_intransition;
    
finish:
    return res;
}


// blocks might make this slightly easier?
uint64_t
IOStateReporter::getStateInTransitions(uint64_t channel_id,
                                       uint64_t state_id)
{
    return _getStateValue(channel_id, state_id, kInTransitions);
}

uint64_t
IOStateReporter::getStateResidencyTime(uint64_t channel_id,
                                       uint64_t state_id)
{
    return _getStateValue(channel_id, state_id, kResidencyTime);
}

uint64_t
IOStateReporter::getStateLastTransitionTime(uint64_t channel_id,
                                            uint64_t state_id)
{
    return _getStateValue(channel_id, state_id, kLastTransitionTime);
}

uint64_t
IOStateReporter::_getStateValue(uint64_t channel_id,
                                uint64_t state_id,
                                enum valueSelector value)
{
    int channel_index = 0, element_index = 0, cnt;
    IOStateReportValues *values = NULL;
    uint64_t result = kIOReportInvalidValue;
    
    lockReporter();
    
    if (getChannelIndices(channel_id, &channel_index, &element_index) == kIOReturnSuccess) {
        
        if (updateChannelValues(channel_index) == kIOReturnSuccess) {
        
            for (cnt = 0; cnt < _channelDimension; cnt++) {
                
                values = (IOStateReportValues *)getElementValues(element_index);
                
                if (state_id == values->state_id) {
                    
                    switch (value) {
                        case kInTransitions:
                            result = values->intransitions;
                            break;
                        case kResidencyTime:
                            result = values->upticks;
                            break;
                        case kLastTransitionTime:
                            result = values->last_intransition;
                            break;
                        default:
                            break;
                    }
                    
                    break;
                }
                
                element_index++;
            }
        }
    }

    unlockReporter();
    return result;
}


uint64_t
IOStateReporter::getStateLastChannelUpdateTime(uint64_t channel_id)
{
    int channel_index;
    uint64_t result = kIOReportInvalidValue;
    
    lockReporter();
    
    if (getChannelIndex(channel_id, &channel_index) == kIOReturnSuccess) {
        
        result = _lastUpdateTimes[channel_index];
    }
    
    unlockReporter();
        
    return result;
}


/* updateChannelValues() is called to refresh state before being
   reported outside the reporter.  In the case of IOStateReporter,
   this is primarily an update to the "time in state" data.
*/
IOReturn
IOStateReporter::updateChannelValues(int channel_index)
{
    IOReturn kerr, result = kIOReturnError;
    
    int state_index, element_idx;
    uint64_t currentTime;
    uint64_t last_ch_update_time;
    uint64_t time_in_state;
    IOStateReportValues state_values;
    
    IOREPORTER_CHECK_LOCK();

    if (channel_index < 0 || channel_index >= _nChannels) {
        result = kIOReturnBadArgument; goto finish;
    }
    
    /* First check to see whether this channel has begun self-
       calculation of time in state.  It's possible this channel
       has yet to be initialized or that the driver is updating
       the channel with override/incrementChannelState() which
       never enable automatic time-in-state updates.  In that case,
       there is nothing to update and we return success.
     */
    last_ch_update_time = _lastUpdateTimes[channel_index];
    if (last_ch_update_time == 0) {
        result = kIOReturnSuccess; goto finish;
    }

    // figure out the current state (if any)
    state_index = _currentStates[channel_index];
    
    // e.g. given 4 4-state channels, the boundary is ch[3].st[3] <- _elems[15]
    if (channel_index < 0 || channel_index > (_nElements - state_index)
                                             / _channelDimension) {
        result = kIOReturnOverrun; goto finish;
    }
    element_idx = channel_index * _channelDimension + state_index;
    
    // get the current values
    kerr = copyElementValues(element_idx,(IOReportElementValues*)&state_values);
    if (kerr) {
        result = kerr; goto finish;
    }

    // calculate time in state
    currentTime = mach_absolute_time();
    time_in_state = currentTime - last_ch_update_time;
    state_values.upticks += time_in_state;
    
    // and store the values
    kerr = setElementValues(element_idx,
                            (IOReportElementValues *)&state_values,
                            currentTime);
    if (kerr) {
        result = kerr; goto finish;
    }
    
    // Record basis for next "prior time" calculation
    _lastUpdateTimes[channel_index] = currentTime;


    // success
    result = kIOReturnSuccess;
    
finish:
    return result;
}
