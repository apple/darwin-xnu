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
 *	ev_keymap.h
 *	Defines the structure used for parsing keymappings.  These structures
 *	and definitions are used by event sources in the kernel and by
 *	applications and utilities which manipulate keymaps.
 *	
 * HISTORY
 * 02-Jun-1992    Mike Paquette at NeXT
 *      Created. 
 */

#ifndef _DEV_EV_KEYMAP_H
#define _DEV_EV_KEYMAP_H

#define	NX_NUMKEYCODES	128	/* Highest key code is 0x7f */
#define NX_NUMSEQUENCES	128	/* Maximum possible number of sequences */
#define	NX_NUMMODIFIERS	16	/* Maximum number of modifier bits */
#define	NX_BYTE_CODES	0	/* If first short 0, all are bytes (else shorts) */

#define	NX_WHICHMODMASK	0x0f 	/* bits out of keyBits for bucky bits */
#define	NX_MODMASK	0x10	/* Bit out of keyBits indicates modifier bit */
#define	NX_CHARGENMASK	0x20	/* bit out of keyBits for char gen */
#define	NX_SPECIALKEYMASK 0x40	/* bit out of keyBits for specialty key */
#define	NX_KEYSTATEMASK	0x80	/* OBSOLETE - DO NOT USE IN NEW DESIGNS */

/*
 * Special keys currently known to and understood by the system.
 * If new specialty keys are invented, extend this list as appropriate.
 * The presence of these keys in a particular implementation is not
 * guaranteed.
 */
#define NX_NOSPECIALKEY			0xFFFF
#define NX_KEYTYPE_SOUND_UP		0
#define NX_KEYTYPE_SOUND_DOWN		1
#define NX_KEYTYPE_BRIGHTNESS_UP	2
#define NX_KEYTYPE_BRIGHTNESS_DOWN	3
#define NX_KEYTYPE_CAPS_LOCK		4
#define NX_KEYTYPE_HELP			5
#define NX_POWER_KEY			6
#define	NX_KEYTYPE_MUTE			7
#define NX_UP_ARROW_KEY			8
#define NX_DOWN_ARROW_KEY		9
#define NX_KEYTYPE_NUM_LOCK		10

#define NX_KEYTYPE_CONTRAST_UP		11
#define NX_KEYTYPE_CONTRAST_DOWN	12
#define NX_KEYTYPE_LAUNCH_PANEL		13
#define NX_KEYTYPE_EJECT		14

#define	NX_NUMSPECIALKEYS		15 /* Maximum number of special keys */
#define NX_NUM_SCANNED_SPECIALKEYS	15 /* First 15 special keys are */
					  /* actively scanned in kernel */

/* Mask of special keys that are posted as events */

#define NX_SPECIALKEY_POST_MASK		\
                                ((1 << NX_KEYTYPE_SOUND_UP) | (1 << NX_KEYTYPE_SOUND_DOWN) | \
                                (1 << NX_POWER_KEY) | (1 << NX_KEYTYPE_MUTE) | \
                                (1 << NX_KEYTYPE_BRIGHTNESS_UP) | (1 << NX_KEYTYPE_BRIGHTNESS_DOWN) | \
                                (1 << NX_KEYTYPE_CONTRAST_UP) | (1 << NX_KEYTYPE_CONTRAST_UP) | \
                                (1 << NX_KEYTYPE_LAUNCH_PANEL) | (1 << NX_KEYTYPE_EJECT) | \
                                0)

/* Modifier key indices into modDefs[] */
#define NX_MODIFIERKEY_ALPHALOCK	0
#define NX_MODIFIERKEY_SHIFT		1
#define NX_MODIFIERKEY_CONTROL		2
#define NX_MODIFIERKEY_ALTERNATE	3
#define NX_MODIFIERKEY_COMMAND		4
#define NX_MODIFIERKEY_NUMERICPAD	5
#define NX_MODIFIERKEY_HELP		6
#define NX_MODIFIERKEY_SECONDARYFN     	7
#define NX_MODIFIERKEY_NUMLOCK		8


typedef struct _NXParsedKeyMapping_ {
 	/* If nonzero, all numbers are shorts; if zero, all numbers are bytes*/
	short	shorts;
	
	/*
	 *  For each keycode, low order bit says if the key
	 *  generates characters.
	 *  High order bit says if the key is assigned to a modifier bit.
	 *  The second to low order bit gives the current state of the key.
	 */
	char	keyBits[NX_NUMKEYCODES];
	
	/* Bit number of highest numbered modifier bit */
	int			maxMod;
	
	/* Pointers to where the list of keys for each modifiers bit begins,
	 * or NULL.
	 */
	unsigned char *modDefs[NX_NUMMODIFIERS];
	
	/* Key code of highest key deinfed to generate characters */
	int			numDefs;
	
	/* Pointer into the keyMapping where this key's definitions begin */
	unsigned char *keyDefs[NX_NUMKEYCODES];
	
	/* number of sequence definitions */
	int			numSeqs;
	
	/* pointers to sequences */
	unsigned char *seqDefs[NX_NUMSEQUENCES];
	
	/* Special key definitions */
	int			numSpecialKeys;
	
	/* Special key values, or 0xFFFF if none */
	unsigned short specialKeys[NX_NUMSPECIALKEYS];
	
	/* Pointer to the original keymapping string */	
	const unsigned char *mapping;
	
	/* Length of the original string */
	int	mappingLen;	
} NXParsedKeyMapping;

#endif /* !_DEV_EV_KEYMAP_H */
