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
	event.h (PostScript side version)
	
	CONFIDENTIAL
	Copyright (c) 1988 NeXT, Inc. as an unpublished work.
	All Rights Reserved.

	Created Leo 01Mar88

	Modified:
	04May88 Leo  Final event types and record
	22Aug88 Leo  Change short -> int for window, add reserved
	26May90 Ted  Added NX_UNDIMMASK to correct triggering of UndoAutoDim
	12Dec91 Mike Brought into sync with dpsclient/event.h, and fixed
		     the #ifndef interlock with dpsclient/event.h that was
		     broken during the Great Header Revision.

	The PostScript version of this file differs from the
	Window Kit version in that the coordinates here are
	ints instead of floats.
******************************************************************************/

#ifndef _DEV_EVENT_H
#define _DEV_EVENT_H

#include <libkern/OSTypes.h>
#include <IOKit/hidsystem/IOHIDTypes.h>

#ifdef EVENT_H		/* Interlock with dpsclient/event.h */
#if !defined(_NXSIZE_)	/* Work around patch for old event.h in Phase 3 projs*/
#define _NXSIZE_	1	/* NXCoord, NXPoint, NXSize decl seen */
#define _NXSize_	NXSize
#endif /* _NXSIZE_ */
#else  /* EVENT_H */		/* Haven't seen dpsclient/event.h, so define away */
#define EVENT_H

#ifdef	KERNEL
#else	/* KERNEL */

#if !defined(_NXSIZE_)	/* Work around patch for old event.h in Phase 3 projs*/
#define _NXSIZE_	1	/* NXCoord, NXPoint, NXSize decl seen */
typedef float   NXCoord;

typedef struct _NXPoint {	/* point */
    NXCoord         x, y;
} NXPoint;

typedef struct _NXSize {	/* size */
    NXCoord         width, height;
} NXSize;
#define _NXSize_	NXSize	/* Correct usage in event_status_driver.h */
#endif /* _NXSIZE_ */

#endif	/* KERNEL */

/* Event types */

#define NX_NULLEVENT		0	/* internal use */

/* mouse events */

#define NX_LMOUSEDOWN		1	/* left mouse-down event */
#define NX_LMOUSEUP		2	/* left mouse-up event */
#define NX_RMOUSEDOWN		3	/* right mouse-down event */
#define NX_RMOUSEUP		4	/* right mouse-up event */
#define NX_MOUSEMOVED		5	/* mouse-moved event */
#define NX_LMOUSEDRAGGED	6	/* left mouse-dragged event */
#define NX_RMOUSEDRAGGED	7	/* right mouse-dragged event */
#define NX_MOUSEENTERED		8	/* mouse-entered event */
#define NX_MOUSEEXITED		9	/* mouse-exited event */

/* keyboard events */

#define NX_KEYDOWN		10	/* key-down event */
#define NX_KEYUP		11	/* key-up event */
#define NX_FLAGSCHANGED		12	/* flags-changed event */

/* composite events */

#define NX_KITDEFINED		13	/* application-kit-defined event */
#define NX_SYSDEFINED		14	/* system-defined event */
#define NX_APPDEFINED		15	/* application-defined event */
/* There are additional DPS client defined events past this point. */

/* Scroll wheel events */

#define NX_SCROLLWHEELMOVED	22

/* tablet events */

#define NX_TABLETPOINTER	23
#define NX_TABLETPROXIMITY	24

#define NX_FIRSTEVENT		0
#define NX_LASTEVENT		24
#define NX_NUMPROCS		(NX_LASTEVENT-NX_FIRSTEVENT+1)

/* Event masks */

#define NX_LMOUSEDOWNMASK	(1 << NX_LMOUSEDOWN)	/* left mouse-down */
#define NX_LMOUSEUPMASK		(1 << NX_LMOUSEUP)	/* left mouse-up */
#define NX_RMOUSEDOWNMASK	(1 << NX_RMOUSEDOWN)	/* right mouse-down */
#define NX_RMOUSEUPMASK		(1 << NX_RMOUSEUP)	/* right mouse-up */
#define NX_MOUSEMOVEDMASK	(1 << NX_MOUSEMOVED)	/* mouse-moved */
#define NX_LMOUSEDRAGGEDMASK	(1 << NX_LMOUSEDRAGGED)	/* left-dragged */
#define NX_RMOUSEDRAGGEDMASK	(1 << NX_RMOUSEDRAGGED)	/* right-dragged */
#define NX_MOUSEENTEREDMASK	(1 << NX_MOUSEENTERED)	/* mouse-entered */
#define NX_MOUSEEXITEDMASK	(1 << NX_MOUSEEXITED)	/* mouse-exited */
#define NX_KEYDOWNMASK		(1 << NX_KEYDOWN)	/* key-down */
#define NX_KEYUPMASK		(1 << NX_KEYUP)		/* key-up */
#define NX_FLAGSCHANGEDMASK	(1 << NX_FLAGSCHANGED)	/* flags-changed */
#define NX_KITDEFINEDMASK 	(1 << NX_WINCHANGED)	/* kit-defined */
#define NX_SYSDEFINEDMASK 	(1 << NX_SYSDEFINED)	/* system-defined */
#define NX_APPDEFINEDMASK 	(1 << NX_APPDEFINED)	/* app-defined */
#define NX_SCROLLWHEELMOVEDMASK	(1 << NX_SCROLLWHEELMOVED)	/* scroll wheel moved */
#define NX_TABLETPOINTERMASK	(1 << NX_TABLETPOINTER)	/* tablet pointer moved */
#define NX_TABLETPROXIMITYMASK	(1 << NX_TABLETPROXIMITY)	/* tablet pointer proximity */

#define EventCodeMask(type)	(1 << (type))
#define NX_ALLEVENTS		-1	/* Check for all events */

/* sub types for system defined events */

#define NX_SUBTYPE_POWER_KEY				1
#define NX_SUBTYPE_AUX_MOUSE_BUTTONS		7
#define NX_SUBTYPE_AUX_CONTROL_BUTTONS		8

#define NX_SUBTYPE_EJECT_KEY				10
#define NX_SUBTYPE_SLEEP_EVENT				11
#define NX_SUBTYPE_RESTART_EVENT			12
#define NX_SUBTYPE_SHUTDOWN_EVENT			13

/* Masks for the bits in event.flags */

/* device-independent */

#define	NX_ALPHASHIFTMASK	0x00010000
#define	NX_SHIFTMASK		0x00020000
#define	NX_CONTROLMASK		0x00040000
#define	NX_ALTERNATEMASK	0x00080000
#define	NX_COMMANDMASK		0x00100000
#define	NX_NUMERICPADMASK	0x00200000
#define	NX_HELPMASK		0x00400000
#define	NX_SECONDARYFNMASK	0x00800000

/* device-dependent (really?) */

//#define	NX_NEXTCTLKEYMASK	0x00000001
//#define	NX_NEXTLSHIFTKEYMASK	0x00000002
//#define	NX_NEXTRSHIFTKEYMASK	0x00000004
//#define	NX_NEXTLCMDKEYMASK	0x00000008
//#define	NX_NEXTRCMDKEYMASK	0x00000010
//#define	NX_NEXTLALTKEYMASK	0x00000020
//#define	NX_NEXTRALTKEYMASK	0x00000040

/* 
 * Additional reserved bits in event.flags
 */

#define NX_STYLUSPROXIMITYMASK	0x00000080
#define NX_NONCOALSESCEDMASK	0x00000100

/* click state values
 * If you have the following events in close succession, the click
 * field has the indicated value:
 *	
 *  Event	Click Value	Comments
 *  mouse-down	1		Not part of any click yet
 *  mouse-up	1		Aha! A click!
 *  mouse-down	2		Doing a double-click
 *  mouse-up	2		It's finished
 *  mouse-down	3		A triple
 *  mouse-up	3
 */

/* Values for the character set in event.data.key.charSet */

#define	NX_ASCIISET		0
#define NX_SYMBOLSET		1
#define	NX_DINGBATSSET		2

/* EventData type: defines the data field of an event */

typedef	union {
    struct {	/* For mouse-down and mouse-up events */
	unsigned char	subx;		/* sub-pixel position for x */
	unsigned char	suby;		/* sub-pixel position for y */
	short		eventNum;	/* unique identifier for this button */
	int		click;		/* click state of this event */
    	unsigned char	pressure;	/* pressure value: 0=none, 255=full */
	char		reserved1;
	short		reserved2;
        int		reserved3;
        int		reserved4;
        int		reserved5;
        int		reserved6;
        int		reserved7;
    } mouse;
    struct {
        int		dx;
        int		dy;
        int		reserved1;
        int		reserved2;
        int		reserved3;
        int		reserved4;
        int		reserved5;
        int		reserved6;
    } mouseMove;
    struct {	/* For key-down and key-up events */
    	unsigned short	origCharSet;	/* unmodified character set code */
	short		repeat;	 /* for key-down: nonzero if really a repeat */
	unsigned short	charSet;	/* character set code */
	unsigned short	charCode;	/* character code in that set */
	unsigned short	keyCode;	/* device-dependent key number */
	unsigned short	origCharCode;	/* unmodified character code */
        int		reserved1;
        unsigned int    keyboardType;
        int		reserved2;
        int		reserved3;
        int		reserved4;
    } key;
    struct {	/* For mouse-entered and mouse-exited events */
    	short	reserved;
        short	eventNum;	/* unique identifier from mouse down event */
        int	trackingNum;	/* unique identifier from settrackingrect */
        int	userData;   /* uninterpreted integer from settrackingrect */
        int		reserved1;
        int		reserved2;
        int		reserved3;
        int		reserved4;
        int		reserved5;
    } tracking;
    struct {
        short	deltaAxis1;
        short	deltaAxis2;
        short	deltaAxis3;
        short	reserved1;
        int	reserved2;
        int	reserved3;
        int	reserved4;
        int	reserved5;
        int	reserved6;
        int	reserved7;
    } scrollWheel;
    struct {	/* For window-changed, sys-defined, and app-defined events */
    	short	reserved;
        short	subType;	/* event subtype for compound events */
        union {
            float	F[7];	/* for use in compound events */
            long	L[7];	/* for use in compound events */
            short	S[14];	/* for use in compound events */
            char	C[28];	/* for use in compound events */
        } misc;
    } compound;
    struct {
        SInt32	x;	/* absolute x coordinate in tablet space at full tablet resolution */
        SInt32	y;	/* absolute y coordinate in tablet space at full tablet resolution */
        SInt32	z;	/* absolute z coordinate in tablet space at full tablet resolution */
        UInt16	buttons;	/* one bit per button - bit 0 is first button - 1 = closed */ 
        UInt16	pressure;	/* scaled pressure value; MAXPRESSURE=(2^16)-1, MINPRESSURE=0 */
        struct {
            SInt16 x;	/* scaled tilt x value; range is -((2^15)-1) to (2^15)-1 (-32767 to 32767) */
            SInt16 y;	/* scaled tilt y value; range is -((2^15)-1) to (2^15)-1 (-32767 to 32767) */
        } tilt;
        UInt16	rotation;	/* Fixed-point representation of device rotation in a 10.6 format */
        SInt16	tangentialPressure;	/* tangential pressure on the device; range same as tilt */
        UInt16	deviceID;	/* system-assigned unique device ID - matches to deviceID field in proximity event */
        SInt16	vendor1;	/* vendor-defined signed 16-bit integer */
        SInt16	vendor2;	/* vendor-defined signed 16-bit integer */
        SInt16	vendor3;	/* vendor-defined signed 16-bit integer */
    } tablet;
    struct {
        UInt16	vendorID;	/* vendor-defined ID - typically will be USB vendor ID */
        UInt16	tabletID;	/* vendor-defined tablet ID - typically will be USB product ID for the tablet */
        UInt16	pointerID;	/* vendor-defined ID of the specific pointing device */
        UInt16	deviceID;	/* system-assigned unique device ID - matches to deviceID field in tablet event */
        UInt16	systemTabletID;	/* system-assigned unique tablet ID */
        UInt16	vendorPointerType;	/* vendor-defined pointer type */
        UInt32  pointerSerialNumber;	/* vendor-defined serial number of the specific pointing device */
        UInt64	uniqueID;	/* vendor-defined unique ID for this pointer */
        UInt32	capabilityMask;	/* mask representing the capabilities of the device */
        UInt8	pointerType;	/* type of pointing device - enum to be defined */
        UInt8	enterProximity;	/* non-zero = entering; zero = leaving */
        SInt16	reserved1;
    } proximity;
} NXEventData;

/* Finally! The event record! */
typedef struct _NXEvent {
    int			type;		/* An event type from above */
    struct {
	int		x, y;		/* Base coordinates in window, */
    }			location;	/* from bottom left */
    unsigned long long	time;		/* time since launch */
    int			flags;		/* key state flags */
    unsigned int	window;		/* window number of assigned window */
    NXEventData		data;		/* type-dependent data */
} NXEvent, *NXEventPtr;


/* How to pick window(s) for event (for PostEvent) */
#define NX_NOWINDOW		-1
#define NX_BYTYPE		0
#define NX_BROADCAST		1
#define NX_TOPWINDOW		2
#define NX_FIRSTWINDOW		3
#define NX_MOUSEWINDOW		4
#define NX_NEXTWINDOW		5
#define NX_LASTLEFT		6
#define NX_LASTRIGHT		7
#define NX_LASTKEY		8
#define NX_EXPLICIT		9
#define NX_TRANSMIT		10
#define NX_BYPSCONTEXT		11

#endif /* EVENT_H */	/* End of defs common with dpsclient/event.h */

/* Mask of events that cause screen to undim */

#define NX_UNDIMMASK		(NX_KEYDOWNMASK | NX_KEYUPMASK | \
				 NX_LMOUSEDOWNMASK | NX_LMOUSEUPMASK | \
				 NX_RMOUSEDOWNMASK | NX_RMOUSEUPMASK | \
				 NX_MOUSEMOVEDMASK | NX_FLAGSCHANGEDMASK | \
				 NX_MOUSEENTEREDMASK | NX_MOUSEEXITEDMASK | \
				 NX_LMOUSEDRAGGEDMASK | NX_RMOUSEDRAGGEDMASK | \
                 NX_SCROLLWHEELMOVEDMASK | NX_TABLETPOINTERMASK | \
                       NX_TABLETPROXIMITYMASK)

#endif /* !_DEV_EVENT_H */

