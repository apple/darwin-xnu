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
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * Common symbol definitions for IOKit. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOKITKEYS_H
#define _IOKIT_IOKITKEYS_H

// properties found in the registry root
#define kIOKitBuildVersionKey		"IOKitBuildVersion"
#define kIOKitDiagnosticsKey		"IOKitDiagnostics"
	// a dictionary keyed by plane name
#define kIORegistryPlanesKey		"IORegistryPlanes"
#define kIOCatalogueKey			"IOCatalogue"

// registry plane names
#define kIOServicePlane			"IOService"
#define kIOPowerPlane			"IOPower"
#define kIODeviceTreePlane		"IODeviceTree"
#define kIOAudioPlane			"IOAudio"
#define kIOFireWirePlane		"IOFireWire"
#define kIOUSBPlane			"IOUSB"

// IOService class name
#define kIOServiceClass			"IOService"

// IOResources class name
#define kIOResourcesClass		"IOResources"

// IOService driver probing property names
#define kIOClassKey			"IOClass"
#define kIOProbeScoreKey		"IOProbeScore"
#define kIOKitDebugKey			"IOKitDebug"

// IOService matching property names
#define kIOProviderClassKey		"IOProviderClass"
#define kIONameMatchKey			"IONameMatch"
#define kIOPropertyMatchKey		"IOPropertyMatch"
#define kIOPathMatchKey			"IOPathMatch"
#define kIOLocationMatchKey		"IOLocationMatch"
#define kIOParentMatchKey		"IOParentMatch"
#define kIOResourceMatchKey		"IOResourceMatch"
#define kIOMatchedServiceCountKey	"IOMatchedServiceCountMatch"

#define kIONameMatchedKey		"IONameMatched"

#define kIOMatchCategoryKey		"IOMatchCategory"
#define kIODefaultMatchCategoryKey	"IODefaultMatchCategory"

// IOService default user client class, for loadable user clients
#define kIOUserClientClassKey		"IOUserClientClass"

// IOService notification types
#define kIOPublishNotification		"IOServicePublish"
#define kIOFirstPublishNotification	"IOServiceFirstPublish"
#define kIOMatchedNotification		"IOServiceMatched"
#define kIOFirstMatchNotification	"IOServiceFirstMatch"
#define kIOTerminatedNotification	"IOServiceTerminate"

// IOService interest notification types
#define kIOGeneralInterest		"IOGeneralInterest"
#define kIOBusyInterest			"IOBusyInterest"
#define kIOAppPowerStateInterest	"IOAppPowerStateInterest"
#define kIOPriorityPowerStateInterest	"IOPriorityPowerStateInterest"

// IOService interest notification types
#define kIOCFPlugInTypesKey		"IOCFPlugInTypes"

// properties found in services that implement command pooling
#define kIOCommandPoolSizeKey	       "IOCommandPoolSize"          // (OSNumber)

// properties found in services that have transfer constraints
#define kIOMaximumBlockCountReadKey        "IOMaximumBlockCountRead"        // (OSNumber)
#define kIOMaximumBlockCountWriteKey       "IOMaximumBlockCountWrite"       // (OSNumber)
#define kIOMaximumByteCountReadKey         "IOMaximumByteCountRead"         // (OSNumber)
#define kIOMaximumByteCountWriteKey        "IOMaximumByteCountWrite"        // (OSNumber)
#define kIOMaximumSegmentCountReadKey      "IOMaximumSegmentCountRead"      // (OSNumber)
#define kIOMaximumSegmentCountWriteKey     "IOMaximumSegmentCountWrite"     // (OSNumber)
#define kIOMaximumSegmentByteCountReadKey  "IOMaximumSegmentByteCountRead"  // (OSNumber)
#define kIOMaximumSegmentByteCountWriteKey "IOMaximumSegmentByteCountWrite" // (OSNumber)

// properties found in services that wish to describe an icon
//
// IOIcon = 
// {
//     CFBundleIdentifier   = "com.example.driver.example";
//     IOBundleResourceFile = "example.icns";
// };
//
// where IOBundleResourceFile is the filename of the resource

#define kIOIconKey               "IOIcon"               // (OSDictionary)
#define kIOBundleResourceFileKey "IOBundleResourceFile" // (OSString)

#define kIOBusBadgeKey           "IOBusBadge"           // (OSDictionary)
#define kIODeviceIconKey         "IODeviceIcon"         // (OSDictionary)

// property of root that describes the machine's serial number as a string
#define kIOPlatformSerialNumberKey	"IOPlatformSerialNumber"	// (OSString)

// IODTNVRAM property keys
#define kIONVRAMDeletePropertyKey	"IONVRAM-DELETE-PROPERTY"
#define kIODTNVRAMPanicInfoKey		"aapl,panic-info"

// keys for complex boot information
#define kIOBootDeviceKey          "IOBootDevice"		// dict | array of dicts
#define kIOBootDevicePathKey      "IOBootDevicePath"	// arch-neutral OSString
#define kIOBootDeviceSizeKey      "IOBootDeviceSize"	// OSNumber of bytes

#endif /* ! _IOKIT_IOKITKEYS_H */
