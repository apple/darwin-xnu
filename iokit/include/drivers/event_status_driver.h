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
/******************************************************************************
	event_status_driver.h
	API for the events status driver.
	This file contains public API.
	mpaque 11Oct91
	
	Copyright 1991 NeXT Computer, Inc.
	
	Modified:
	
******************************************************************************/

#ifndef _DRIVERS_EVENT_STATUS_DRIVER_
#define _DRIVERS_EVENT_STATUS_DRIVER_

#ifdef __cplusplus
extern "C" {
#endif

#include <mach/port.h>
#include <IOKit/hidsystem/IOLLEvent.h>
#include <IOKit/hidsystem/IOHIDTypes.h>


/*
 * Event System Handle:
 *
 * Information used by the system between calls to NXOpenEventSystem and
 * NXCloseEventSystem.  The application should not
 * access any of the elements of this structure.
 */
typedef mach_port_t NXEventHandle;

/* Open and Close */
NXEventHandle NXOpenEventStatus(void);
void NXCloseEventStatus(NXEventHandle handle);

/* Status */
extern NXEventSystemInfoType NXEventSystemInfo(NXEventHandle handle,
				char *flavor,
				int *evs_info,
				unsigned int *evs_info_cnt);
/* Keyboard */
extern void NXSetKeyRepeatInterval(NXEventHandle handle, double seconds);
extern double NXKeyRepeatInterval(NXEventHandle handle);
extern void NXSetKeyRepeatThreshold(NXEventHandle handle, double threshold);
extern double NXKeyRepeatThreshold(NXEventHandle handle);
extern NXKeyMapping *NXSetKeyMapping(NXEventHandle h, NXKeyMapping *keymap);
extern int NXKeyMappingLength(NXEventHandle handle);
extern NXKeyMapping *NXGetKeyMapping(NXEventHandle h, NXKeyMapping *keymap);
extern void NXResetKeyboard(NXEventHandle handle);

/* Mouse */
extern void NXSetClickTime(NXEventHandle handle, double seconds);
extern double NXClickTime(NXEventHandle handle);
extern void NXSetClickSpace(NXEventHandle handle, _NXSize_ *area);
extern void NXGetClickSpace(NXEventHandle handle, _NXSize_ *area);
extern void NXSetMouseScaling(NXEventHandle handle, NXMouseScaling *scaling);
extern void NXGetMouseScaling(NXEventHandle handle, NXMouseScaling *scaling);
#ifdef _undef
extern void NXEnableMouseButton(NXEventHandle handle, NXMouseButton button);
extern NXMouseButton NXMouseButtonEnabled(NXEventHandle handle);
#endif
extern void NXResetMouse(NXEventHandle handle);

/* Screen Brightness and Auto-dimming */

extern void NXSetAutoDimThreshold(NXEventHandle handle, double seconds);
extern double NXAutoDimThreshold(NXEventHandle handle);
extern double NXAutoDimTime(NXEventHandle handle);
extern double NXIdleTime(NXEventHandle handle);
extern void NXSetAutoDimState(NXEventHandle handle, boolean_t dimmed);
extern boolean_t NXAutoDimState(NXEventHandle handle);
extern void NXSetAutoDimBrightness(NXEventHandle handle, double level);
extern double NXAutoDimBrightness(NXEventHandle handle);
extern void NXSetScreenBrightness(NXEventHandle handle, double level);
extern double NXScreenBrightness(NXEventHandle handle);

/* Speaker Volume */
#ifdef _undef
extern void NXSetCurrentVolume(NXEventHandle handle, double volume);
extern double NXCurrentVolume(NXEventHandle handle);
#endif

/* Wait Cursor */
#ifdef _undef
extern void NXSetWaitCursorThreshold(NXEventHandle handle, double seconds);
extern double NXWaitCursorThreshold(NXEventHandle handle);
extern void NXSetWaitCursorSustain(NXEventHandle handle, double seconds);
extern double NXWaitCursorSustain(NXEventHandle handle);
extern void NXSetWaitCursorFrameInterval(NXEventHandle handle, double seconds);
extern double NXWaitCursorFrameInterval(NXEventHandle handle);
#endif

/*
 * Generic calls.  Argument values are device and architecture dependent.
 * This API is provided for the convenience of special device users.  Code
 * which is intended to be portable across multiple platforms and architectures
 * should not use the following functions.
 */
#ifdef _undef
extern int NXEvSetParameterInt(NXEventHandle handle,
			char *parameterName,
			unsigned int *parameterArray,
			unsigned int count);

extern int NXEvSetParameterChar(NXEventHandle handle,
			char *parameterName,
			unsigned char *parameterArray,
			unsigned int count);

extern int NXEvGetParameterInt(NXEventHandle handle,
			char *parameterName,
			unsigned int maxCount,
			unsigned int *parameterArray,
			unsigned int *returnedCount);

extern int NXEvGetParameterChar(NXEventHandle handle,
			char *parameterName,
			unsigned int maxCount,
			unsigned char *parameterArray,
			unsigned int *returnedCount);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*_DRIVERS_EVENT_STATUS_DRIVER_ */

