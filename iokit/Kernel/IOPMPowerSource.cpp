/*
 * Copyright (c) 1998-2005 Apple Computer, Inc. All rights reserved.
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

#include <IOKit/pwr_mgt/IOPMPowerSource.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOLib.h>

#define super IOService

OSDefineMetaClassAndStructors(IOPMPowerSource, IOService)

// *****************************************************************************
// powerSource
//
// Static initializer for IOPMPowerSource. Returns a new instance of the class
// which the caller must attach to the power plane.
// *****************************************************************************

IOPMPowerSource *IOPMPowerSource::powerSource(void)
{
    IOPMPowerSource *ps = new IOPMPowerSource;    

    if(ps) {
        ps->init();
        return ps;
    }    
    return NULL;
}

// *****************************************************************************
// init
//
// *****************************************************************************
bool IOPMPowerSource::init (void)
{
    if (!super::init()) {
        return false;
    }

    nextInList = NULL;

    properties = OSDictionary::withCapacity(10);
    if(!properties) return false;
    properties->setCapacityIncrement(1);

    externalConnectedKey = OSSymbol::withCString(kIOPMPSExternalConnectedKey);
    externalChargeCapableKey = OSSymbol::withCString(kIOPMPSExternalChargeCapableKey);
    batteryInstalledKey = OSSymbol::withCString(kIOPMPSBatteryInstalledKey);
    chargingKey = OSSymbol::withCString(kIOPMPSIsChargingKey);
    warnLevelKey = OSSymbol::withCString(kIOPMPSAtWarnLevelKey);
    criticalLevelKey = OSSymbol::withCString(kIOPMPSAtCriticalLevelKey);
    currentCapacityKey = OSSymbol::withCString(kIOPMPSCurrentCapacityKey);
    maxCapacityKey = OSSymbol::withCString(kIOPMPSMaxCapacityKey);
    timeRemainingKey = OSSymbol::withCString(kIOPMPSTimeRemainingKey);
    amperageKey = OSSymbol::withCString(kIOPMPSAmperageKey);
    voltageKey = OSSymbol::withCString(kIOPMPSVoltageKey);
    cycleCountKey = OSSymbol::withCString(kIOPMPSCycleCountKey);
    adapterInfoKey = OSSymbol::withCString(kIOPMPSAdapterInfoKey);
    locationKey = OSSymbol::withCString(kIOPMPSLocationKey);
    errorConditionKey = OSSymbol::withCString(kIOPMPSErrorConditionKey);
    manufacturerKey = OSSymbol::withCString(kIOPMPSManufacturerKey);
    modelKey = OSSymbol::withCString(kIOPMPSModelKey);
    serialKey = OSSymbol::withCString(kIOPMPSSerialKey);
    batteryInfoKey = OSSymbol::withCString(kIOPMPSLegacyBatteryInfoKey);

    return true;
}

// *****************************************************************************
// free
//
// *****************************************************************************
void IOPMPowerSource::free(void)
{
    if(properties) properties->release();
    if(externalConnectedKey) externalConnectedKey->release();
    if(externalChargeCapableKey) externalChargeCapableKey->release();
    if(batteryInstalledKey) batteryInstalledKey->release();
    if(chargingKey) chargingKey->release();
    if(warnLevelKey) warnLevelKey->release();
    if(criticalLevelKey) criticalLevelKey->release();
    if(currentCapacityKey) currentCapacityKey->release();
    if(maxCapacityKey) maxCapacityKey->release();
    if(timeRemainingKey) timeRemainingKey->release();
    if(amperageKey) amperageKey->release();
    if(voltageKey) voltageKey->release();
    if(cycleCountKey) cycleCountKey->release();
    if(adapterInfoKey) adapterInfoKey->release();
    if(errorConditionKey) errorConditionKey->release();
    if(manufacturerKey) manufacturerKey->release();
    if(modelKey) modelKey->release();
    if(serialKey) serialKey->release();
    if(locationKey) locationKey->release();
    if(batteryInfoKey) batteryInfoKey->release();
}

// *****************************************************************************
// updateStatus
//
// Update power source state in IORegistry and message interested clients
// notifying them of our change.
// *****************************************************************************
void IOPMPowerSource::updateStatus (void)
{
    OSCollectionIterator            *iterator;
    OSObject                        *iteratorKey;
    OSObject                        *obj;

    iterator = OSCollectionIterator::withCollection(properties);
    if(!iterator) return;

    while ((iteratorKey = iterator->getNextObject())) {
        OSSymbol *key;
    
        key = OSDynamicCast(OSSymbol, iteratorKey);
        if (!key) continue;
        obj = properties->getObject(key);
        if(!obj) continue;
        setProperty(key, obj);
    }
    iterator->release();

    // And up goes the flare
    messageClients(kIOPMMessageBatteryStatusHasChanged);
}


/*******************************************************************************
 *
 * PROTECTED Accessors. All the setters! Yay!
 *
 ******************************************************************************/
 
void IOPMPowerSource::setExternalConnected(bool b) {
    properties->setObject(
                externalConnectedKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}

void IOPMPowerSource::setExternalChargeCapable(bool b) {
    properties->setObject(
                externalChargeCapableKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}

void IOPMPowerSource::setBatteryInstalled(bool b) {
    properties->setObject(
                batteryInstalledKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}

void IOPMPowerSource::setIsCharging(bool b) {
    properties->setObject(
                chargingKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}

void IOPMPowerSource::setAtWarnLevel(bool b) {
    properties->setObject(
                warnLevelKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}

void IOPMPowerSource::setAtCriticalLevel(bool b) {
    properties->setObject(
                criticalLevelKey,
                b ? kOSBooleanTrue:kOSBooleanFalse);    
}


void IOPMPowerSource::setCurrentCapacity(unsigned int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                currentCapacityKey,
                n);
    n->release();
}

void IOPMPowerSource::setMaxCapacity(unsigned int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                maxCapacityKey,
                n);
    n->release();
}

void IOPMPowerSource::setTimeRemaining(int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                timeRemainingKey,
                n);
    n->release();
}

void IOPMPowerSource::setAmperage(int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                amperageKey,
                n);
    n->release();
}

void IOPMPowerSource::setVoltage(unsigned int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                voltageKey,
                n);
    n->release();
}

void IOPMPowerSource::setCycleCount(unsigned int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                cycleCountKey,
                n);
    n->release();
}

void IOPMPowerSource::setAdapterInfo(int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                adapterInfoKey,
                n);
    n->release();
}

void IOPMPowerSource::setLocation(int val) {
    OSNumber *n = OSNumber::withNumber(val, 32);
    properties->setObject(
                locationKey,
                n);
    n->release();
}

void IOPMPowerSource::setErrorCondition(OSSymbol *s) {
    properties->setObject(errorConditionKey, s);
}

void IOPMPowerSource::setManufacturer(OSSymbol *s) {
    properties->setObject(manufacturerKey, s);
}

void IOPMPowerSource::setModel(OSSymbol *s) {
    properties->setObject(modelKey, s);
}

void IOPMPowerSource::setSerial(OSSymbol *s) {
    properties->setObject(serialKey, s);
}

void IOPMPowerSource::setLegacyIOBatteryInfo(OSDictionary *d) {
    properties->setObject(batteryInfoKey, d);
}




/*******************************************************************************
 *
 * PUBLIC Accessors. All the getters! Boo!
 *
 ******************************************************************************/

bool IOPMPowerSource::externalConnected(void) {
    return (kOSBooleanTrue == properties->getObject(externalConnectedKey));
}

bool IOPMPowerSource::externalChargeCapable(void) {
    return (kOSBooleanTrue == properties->getObject(externalChargeCapableKey));
}

bool IOPMPowerSource::batteryInstalled(void) {
    return (kOSBooleanTrue == properties->getObject(batteryInstalledKey));
}

bool IOPMPowerSource::isCharging(void) {
    return (kOSBooleanTrue == properties->getObject(chargingKey));
}

bool IOPMPowerSource::atWarnLevel(void) {
    return (kOSBooleanTrue == properties->getObject(warnLevelKey));
}

bool IOPMPowerSource::atCriticalLevel(void) {
    return (kOSBooleanTrue == properties->getObject(criticalLevelKey));
}

unsigned int IOPMPowerSource::currentCapacity(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(currentCapacityKey));
    if(!n) return 0;
    else return (unsigned int)n->unsigned32BitValue();
}

unsigned int IOPMPowerSource::maxCapacity(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(maxCapacityKey));
    if(!n) return 0;
    else return (unsigned int)n->unsigned32BitValue();
}

unsigned int IOPMPowerSource::capacityPercentRemaining(void) 
{
    unsigned int _currentCapacity = currentCapacity();
    unsigned int _maxCapacity = maxCapacity();
    if(0 == _maxCapacity) {
        return 0;
    } else {
        return ((100*_currentCapacity) / _maxCapacity);
    }
}

int IOPMPowerSource::timeRemaining(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(timeRemainingKey));
    if(!n) return 0;
    else return (int)n->unsigned32BitValue();
}

int IOPMPowerSource::amperage(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(amperageKey));
    if(!n) return 0;
    else return (int)n->unsigned32BitValue();
}

unsigned int IOPMPowerSource::voltage(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(voltageKey));
    if(!n) return 0;
    else return (unsigned int)n->unsigned32BitValue();
}

unsigned int IOPMPowerSource::cycleCount(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(cycleCountKey));
    if(!n) return 0;
    else return (unsigned int)n->unsigned32BitValue();
}

int IOPMPowerSource::adapterInfo(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(adapterInfoKey));
    if(!n) return 0;
    else return (int)n->unsigned32BitValue();
}

int IOPMPowerSource::location(void) {
    OSNumber        *n;
    n = OSDynamicCast(OSNumber, properties->getObject(locationKey));
    if(!n) return 0;
    else return (unsigned int)n->unsigned32BitValue();
}

OSSymbol *IOPMPowerSource::errorCondition(void) {
    return OSDynamicCast(OSSymbol, properties->getObject(errorConditionKey));
}

OSSymbol *IOPMPowerSource::manufacturer(void) {
    return OSDynamicCast(OSSymbol, properties->getObject(manufacturerKey));
}

OSSymbol *IOPMPowerSource::model(void) {
    return OSDynamicCast(OSSymbol, properties->getObject(modelKey));
}

OSSymbol *IOPMPowerSource::serial(void) {
    return OSDynamicCast(OSSymbol, properties->getObject(serialKey));
}

OSDictionary *IOPMPowerSource::legacyIOBatteryInfo(void) {
    return OSDynamicCast(OSDictionary, properties->getObject(batteryInfoKey));
}
