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
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * evsio.h - Get/Set parameter calls for Event Status Driver.
 *
 *	CAUTION: Developers should stick to the API exported in
 *		<drivers/event_status_driver.h> to guarantee
 *		binary compatability of their applications in future
 *		releases.
 *
 * HISTORY
 * 22 May 1992    Mike Paquette at NeXT
 *      Created. 
 */
#ifndef _DEV_EVSIO_H
#define _DEV_EVSIO_H

/* Public type definitions. */
#include <IOKit/hidsystem/IOHIDTypes.h>
#include <IOKit/hidsystem/IOLLEvent.h>

/*
 * Identify this driver as one that uses the new driverkit and messaging API
 */
#ifndef _NeXT_MACH_EVENT_DRIVER_
#define _NeXT_MACH_EVENT_DRIVER_	(1)
#endif /* !_NeXT_MACH_EVENT_DRIVER_ */

/* * */

#define kIOHIDKindKey			"HIDKind"
#define kIOHIDInterfaceIDKey		"HIDInterfaceID"
#define kIOHIDSubinterfaceIDKey		"HIDSubinterfaceID"

#define kIOHIDKeyRepeatKey		"HIDKeyRepeat"
#define kIOHIDInitialKeyRepeatKey	"HIDInitialKeyRepeat"
#define kIOHIDKeyMappingKey		"HIDKeyMapping"
#define kIOHIDResetKeyboardKey		"HIDResetKeyboard"

#define kIOHIDPointerResolutionKey	"HIDPointerResolution"
#define kIOHIDPointerAccelerationKey	"HIDPointerAcceleration"
#define kIOHIDResetPointerKey		"HIDResetPointer"
#define kIOHIDPointerConvertAbsoluteKey	"HIDPointerConvertAbsolute"
#define kIOHIDPointerContactToMoveKey	"HIDPointerContactToMove"
#define kIOHIDPointerPressureToClickKey	"HIDPointerPressureToClick"

#define kIOHIDClickTimeKey		"HIDClickTime"
#define kIOHIDClickSpaceKey		"HIDClickSpace"

#define kIOHIDAutoDimThresholdKey	"HIDAutoDimThreshold"
#define kIOHIDAutoDimStateKey		"HIDAutoDimState"
#define kIOHIDAutoDimTimeKey		"HIDAutoDimTime"
#define kIOHIDIdleTimeKey		"HIDIdleTime"

#define kIOHIDBrightnessKey		"HIDBrightness"
#define kIOHIDAutoDimBrightnessKey	"HIDAutoDimBrightness"

#ifdef _undef
#define EVS_PREFIX	"Evs_"	/* All EVS calls start with this string */

/* WaitCursor-related ioctls */

#define EVSIOSWT "Evs_SetWaitThreshold"
#define EVSIOSWT_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOSWS "Evs_SetWaitSustain"
#define EVSIOSWS_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOSWFI "Evs_SetWaitFrameInterval"
#define EVSIOSWFI_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOCWINFO	"Evs_CurrentWaitCursorInfo"
#define EVSIOCWINFO_THRESH	0
#define EVSIOCWINFO_SUSTAIN	(EVSIOCWINFO_THRESH + EVS_PACKED_TIME_SIZE)
#define EVSIOCWINFO_FINTERVAL	(EVSIOCWINFO_SUSTAIN + EVS_PACKED_TIME_SIZE)
#define EVSIOCWINFO_SIZE	(EVSIOCWINFO_FINTERVAL + EVS_PACKED_TIME_SIZE)
#endif

#define EVS_PACKED_TIME_SIZE (sizeof(UInt64) / sizeof( unsigned int))

/* Device control ioctls. Levels specified may be in the range 0 - 64. */

#define EVSIOSB	  	kIOHIDBrightnessKey
#define EVSIOSB_SIZE	1

#define EVSIOSADB 	kIOHIDAutoDimBrightnessKey
#define EVSIOSADB_SIZE	1

#ifdef _undef
#define EVSIOSA	  "Evs_SetAttenuation"
#define EVIOSA_SIZE	1

#define EVSIO_DCTLINFO	"Evs_DeviceControlInfo"
typedef enum {
	EVSIO_DCTLINFO_BRIGHT,
	EVSIO_DCTLINFO_ATTEN,
	EVSIO_DCTLINFO_AUTODIMBRIGHT
} evsio_DCTLINFOIndices;
#define EVSIO_DCTLINFO_SIZE	(EVSIO_DCTLINFO_AUTODIMBRIGHT + 1)
#endif

/*
 * Device status request
 */
#define	EVSIOINFO  NX_EVS_DEVICE_INFO


/* Keyboard-related ioctls - implemented within Event Sources */

#define EVSIOSKR  	kIOHIDKeyRepeatKey
#define EVSIOSKR_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOSIKR 	kIOHIDInitialKeyRepeatKey
#define EVSIOSIKR_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIORKBD 	kIOHIDResetKeyboardKey
#define EVSIORKBD_SIZE	1

#define EVSIOCKR_SIZE	EVS_PACKED_TIME_SIZE

#define	EVSIOCKML 	kIOHIDKeyMappingKey
#define EVSIOCKML_SIZE	1

/* The following two tokens are for use with the get/set character routines. */
#define EVSIOSKM  	kIOHIDKeyMappingKey
#define EVSIOSKM_SIZE	4096

#define	EVSIOCKM  	kIOHIDKeyMappingKey
#define EVSIOCKM_SIZE	4096

/* Mouse-related ioctls - implemented within Event Sources */

#define	EVSIOSMS  	kIOHIDPointerAccelerationKey
#define	EVSIOSMS_SIZE		(1)

#define	EVSIOCMS  	kIOHIDPointerAccelerationKey
#define	EVSIOCMS_SIZE		(1)

#ifdef _undef
#define EVSIOSMH  "Evs_SetMouseHandedness"
#define EVSIOSMH_SIZE	1		// value from NXMouseButton enum

#define EVSIOCMH  "Evs_CurrentMouseHandedness"
#define EVSIOCMH_SIZE	1
#endif

/* Generic pointer device controls, implemented by the Event Driver. */
#define	EVSIOSCT  	kIOHIDClickTimeKey
#define EVSIOSCT_SIZE	EVS_PACKED_TIME_SIZE

#define	EVSIOSCS  	kIOHIDClickSpaceKey
typedef enum {
	EVSIOSCS_X,
	EVSIOSCS_Y
} evsioEVSIOSCSIndices;
#define EVSIOSCS_SIZE	(EVSIOSCS_Y + 1)

#define EVSIOSADT	 kIOHIDAutoDimThresholdKey
#define EVSIOSADT_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOSADS 	kIOHIDAutoDimStateKey
#define EVSIOSADS_SIZE	1

#define EVSIORMS  	kIOHIDResetPointerKey
#define EVSIORMS_SIZE	1

#define	EVSIOCCT  	kIOHIDClickTimeKey
#define EVSIOCCT_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOCADT 	kIOHIDAutoDimThresholdKey
#define EVSIOCADT_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOGDADT 	kIOHIDAutoDimTimeKey
#define EVSIOGDADT_SIZE	EVS_PACKED_TIME_SIZE

#define EVSIOIDLE 	kIOHIDIdleTimeKey
#define EVSIOIDLE_SIZE	EVS_PACKED_TIME_SIZE

#define	EVSIOCCS  	kIOHIDClickSpaceKey
typedef enum {
	EVSIOCCS_X,
	EVSIOCCS_Y
} evsioEVSIOCCSIndices;
#define EVSIOCCS_SIZE	(EVSIOCCS_Y + 1)

#define EVSIOCADS 	kIOHIDAutoDimStateKey
#define EVSIOCADS_SIZE	1

#endif /* !_DEV_EVSIO_H */
