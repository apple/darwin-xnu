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
	ev_types.h
	Data types for the events status driver.
	This file contains public API.
	mpaque 11Oct91
	
	Copyright 1991 NeXT Computer, Inc.
	
	Modified:
	
******************************************************************************/

#ifndef _DEV_EV_TYPES_H
#define _DEV_EV_TYPES_H

#include <mach/boolean.h>
#include <IOKit/IOSharedLock.h>
#include <IOKit/graphics/IOGraphicsTypes.h>

/* Shared memory versions */
#define EVENT_SYSTEM_VERSION   2

/* Maximum length of SetMouseScaling arrays */
#define NX_MAXMOUSESCALINGS 20

typedef struct evsioKeymapping		/* Match old struct names in kernel */
{
    int size;
    char *mapping;
} NXKeyMapping;

typedef struct evsioMouseScaling	/* Match old struct names in kernel */
{
    int numScaleLevels;
    short scaleThresholds[NX_MAXMOUSESCALINGS];
    short scaleFactors[NX_MAXMOUSESCALINGS];
} NXMouseScaling;

typedef enum {
    NX_OneButton,
    NX_LeftButton,
    NX_RightButton
} NXMouseButton;

/*
 * NXEventSystemInfo() information structures.  These are designed to
 * allow for expansion.
 *
 * The current implementation of NXEventSystemInfo() uses an ioctl call.
 * THIS WILL CHANGE.
 */
 
/*
 * Generic query max size and typedefs.
 *
 *	The maximum size is selected to support anticipated future extensions
 *	of request flavors.  Certain flavors planned for future releases may 
 *	require roughtly 800 ints to represent.  We allow a little extra, in
 *	case further growth is needed.
 */
typedef int *NXEventSystemInfoType;
#define NX_EVS_INFO_MAX		(1024)	/* Max array size */
typedef int NXEventSystemInfoData[NX_EVS_INFO_MAX];

/* Event System Devices query */
#define NX_EVS_DEVICE_MAX	16

	/* Interface types */
#define NX_EVS_DEVICE_INTERFACE_OTHER		0
#define NX_EVS_DEVICE_INTERFACE_NeXT		1 // NeXT custom, in older sys
#define NX_EVS_DEVICE_INTERFACE_ADB		2 // NeXT/fruit keybds/mice
#define NX_EVS_DEVICE_INTERFACE_ACE		3 // For x86 PC keyboards
#define NX_EVS_DEVICE_INTERFACE_SERIAL_ACE	4 // For PC serial mice 
#define NX_EVS_DEVICE_INTERFACE_BUS_ACE		5 // For PC bus mice 
#define NX_EVS_DEVICE_INTERFACE_HIL		6 // For HIL hp keyboard 
#define NX_EVS_DEVICE_INTERFACE_TYPE5		7 // For Sun Type5 keyboard

/*
 * Note! if any new interface types are added above, the following
 * definition of the number of interfaces supported must reflect this.
 * This is used in the libkeymap project (storemap.c module) which needs
 * to be cognizant of the number of new devices coming online
 * via support for heterogeneous architecture platforms.
 * e.g., PCs, HP's HIL, Sun's Type5 keyboard,...
 */
#define NUM_SUPPORTED_INTERFACES	(NX_EVS_DEVICE_INTERFACE_TYPE5 + 1)
					// Other, NeXT, ADB, ACE,...

	/* Device types */
#define NX_EVS_DEVICE_TYPE_OTHER	0
#define NX_EVS_DEVICE_TYPE_KEYBOARD	1
#define NX_EVS_DEVICE_TYPE_MOUSE	2	// Relative position devices
#define NX_EVS_DEVICE_TYPE_TABLET	3	// Absolute position devices

typedef struct {
	int	interface;	/* NeXT, ADB, other */
	int	interface_addr;	/* Device address on the interface */
	int	dev_type;	/* Keyboard, mouse, tablet, other */
	int	id;		/* manufacturer's device handler ID */
} NXEventSystemDevice;

typedef struct {
	NXEventSystemDevice	dev[NX_EVS_DEVICE_MAX];
} NXEventSystemDeviceList;

#define __OLD_NX_EVS_DEVICE_INFO		1
#define NX_EVS_DEVICE_INFO			"Evs_EventDeviceInfo"
#define NX_EVS_DEVICE_INFO_COUNT \
	(sizeof (NXEventSystemDeviceList) / sizeof (int))

/*
 * Types used in evScreen protocol compliant operations.
 */

typedef enum {EVNOP, EVHIDE, EVSHOW, EVMOVE, EVLEVEL} EvCmd; /* Cursor state */

#define EV_SCREEN_MIN_BRIGHTNESS	0
#define EV_SCREEN_MAX_BRIGHTNESS	64
/* Scale should lie between MIN_BRIGHTNESS and MAX_BRIGHTNESS */
#define EV_SCALE_BRIGHTNESS( scale, datum ) \
	((((unsigned long)(datum))*((unsigned long)scale)) >> 6)

/*
 * Definition of a tick, as a time in milliseconds. This controls how
 * often the event system periodic jobs are run.  All actual tick times
 * are derived from the nanosecond timer.  These values are typically used
 * as part of computing mouse velocity for acceleration purposes.
 */
#define EV_TICK_TIME		16			/* 16 milliseconds */
#define EV_TICKS_PER_SEC	(1000/EV_TICK_TIME)	/* ~ 62 Hz */

/* Mouse Button bits, as passed from an EventSrc to the Event Driver */
#define EV_RB			(0x01)
#define EV_LB			(0x04)
#define EV_MOUSEBUTTONMASK	(EV_LB | EV_RB)

/* Tablet Pressure Constants, as passed from an EventSrc to the Event Driver */
#define EV_MINPRESSURE 0
#define EV_MAXPRESSURE 255

/* Cursor size in pixels */
#define EV_CURSOR_WIDTH		16
#define EV_CURSOR_HEIGHT	16


#define kAppleOnboardGUID 	0x0610000000000000ULL

#endif /* !_DEV_EV_TYPES_H */

