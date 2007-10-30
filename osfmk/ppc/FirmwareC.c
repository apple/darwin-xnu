/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 *	This file contains firmware code.
 *
 */

#include <debug.h>
#include <mach_vm_debug.h>
#include <db_machine_commands.h>

#include <kern/thread.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <kern/spl.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/mem.h>
#include <ppc/pmap.h>
#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <pexpert/pexpert.h>
#include <ddb/db_output.h>

Boot_Video dgVideo;
extern GDWorkArea GratefulDebWork[];

struct RuptCtr {		/* Counts hardware interrupts */
	struct GDpos {		/* Screen position for Grateful Deb display */
		unsigned short col;	/* Column  (-1 means no display) */
		unsigned short row;	/* Row */
	} GDpos;
	unsigned int count;	/* Count of interrupt */
	unsigned int timed;	/* If set, count updates at timed rate  */
	unsigned int lasttime;	/* Low of timebase when last updated */
};

/* Window layout for Grateful Deb:
 *
 *	0				9
 *
 *	0	Total			Decrimenter
 *	1	DSI				ISI
 *	2	System call		External
 *	3	SIGP			Floating point
 *	4	Program			Alignment
 */

struct RuptCtr RuptCtrs[96] = {
	{	/* Total interruptions */
		.GDpos = {
			.col = 0,
			.row = 0,
		},
		.count = 0,
		.timed = 1,
	},
	{	/* Reset */
		.GDpos = {
			.col = -1,
			.row = -1,
		},
		.count = 0,
		.timed = 0,
	},
	{	/* Machine check */
		.GDpos = {
			.col = -1,
			.row = -1,
		},
		.count = 0,
		.timed = 0,
	},
	{	/* DSIs */
		.GDpos = {
			.col = 0,
			.row = 1,
		},
		.count = 0,
		.timed = 1},
	{	/* ISIs */
		.GDpos = {
			.col = 1,
			.row = 1,
		},
		.count = 0,
		.timed = 1,
	},
	{	/* Externals */
		.GDpos = {
			.col = 1,
			.row = 2,
		},
		.count = 0,
		.timed = 1,
	},
	{	/* Alignment */
		.GDpos = {
			.col = 1,
			.row = 4,
		},
		.count = 0,
		.timed = 0,
	},
	{.GDpos = {.col = 0,.row = 4},.count = 0,.timed = 0},	/* Program */
	{.GDpos = {.col = 1,.row = 3},.count = 0,.timed = 0},	/* Floating point */
	{.GDpos = {.col = 1,.row = 0},.count = 0,.timed = 1},	/* Decrementer */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* I/O error */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = 0,.row = 2},.count = 0,.timed = 1},	/* System call */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Trace */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Floating point assist */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Performance monitor */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* VMX */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Instruction breakpoint */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* System management */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Trace */
	{.GDpos = {.col = 0,.row = 3},.count = 0,.timed = 0},	/* SIGP */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Preemption */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Context switch */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Special, update frequency controls */

	/*Start of second processor counts */

	{.GDpos = {.col = 0,.row = 0},.count = 0,.timed = 1},	/* Total interruptions */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reset */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Machine check */
	{.GDpos = {.col = 0,.row = 1},.count = 0,.timed = 1},	/* DSIs */
	{.GDpos = {.col = 1,.row = 1},.count = 0,.timed = 1},	/* ISIs */
	{.GDpos = {.col = 1,.row = 2},.count = 0,.timed = 1},	/* Externals */
	{.GDpos = {.col = 1,.row = 4},.count = 0,.timed = 0},	/* Alignment */
	{.GDpos = {.col = 0,.row = 4},.count = 0,.timed = 0},	/* Program */
	{.GDpos = {.col = 1,.row = 3},.count = 0,.timed = 0},	/* Floating point */
	{.GDpos = {.col = 1,.row = 0},.count = 0,.timed = 1},	/* Decrementer */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* I/O error */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = 0,.row = 2},.count = 0,.timed = 1},	/* System call */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Trace */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Floating point assist */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Performance monitor */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* VMX */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Instruction breakpoint */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* System management */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Trace */
	{.GDpos = {.col = 0,.row = 3},.count = 0,.timed = 0},	/* SIGP */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Preemption */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Context switch */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Reserved */
	{.GDpos = {.col = -1,.row = -1},.count = 0,.timed = 0},	/* Special, update frequency controls */
};

void
GratefulDebInit(bootBumbleC *boot_video_info)
{				/* Initialize the video debugger */

	unsigned int fillframe[256];
	unsigned int startpos, startbyte, windowleft, newwidth, i, j, startword,
	    oldwidth, nrmlgn;
	unsigned int nwords, *byteleft, lstlgn, pixlgn, bytelgn;

	if (!boot_video_info) {	/* Are we disabling it? */
		GratefulDebWork[0].GDready = 0;	/* Disable output */
		return;
	}

	nrmlgn = (9 * GDfontsize) * (boot_video_info->v_depth / 8);	/* Get the normal column size in bytes */
	lstlgn = (((8 * GDfontsize) + (GDfontsize >> 1)) * boot_video_info->v_depth) / 8;	/* Same as normal, but with 1/2 character space */
	nrmlgn = (nrmlgn + 31) & -32;	/* Round to a line */

	bytelgn = (nrmlgn * (GDdispcols - 1)) + lstlgn;	/* Length in bytes */
	pixlgn = bytelgn / (boot_video_info->v_depth / 8);	/* Number of pixels wide */

	startbyte = (boot_video_info->v_width * (boot_video_info->v_depth / 8)) - bytelgn;	/* Get the starting byte unaligned */
	startpos = boot_video_info->v_width - pixlgn;	/* Starting pixel position */

	startbyte += (unsigned int)boot_video_info->v_baseAddr & 31;	/* Add the extra to cache boundary in frame buffer */
	startbyte &= -32;	/* Make sure it's on a cache line for speed */
	startbyte += (unsigned int)boot_video_info->v_baseAddr & 31;	/* Subtract the extra to cache boundary in frame buffer */

	windowleft = startbyte - (((GDfontsize / 2) * boot_video_info->v_depth) / 8);	/* Back up a half character */
	windowleft &= -4;	/* Make sure it is on a word boundary */
	newwidth = windowleft / (boot_video_info->v_depth / 8);	/* Get the new pixel width of screen */

	oldwidth = boot_video_info->v_width;	/* Save the old width */
//      boot_video_info->v_width = newwidth;                                    /* Set the new width */

	nwords = oldwidth - newwidth;	/* See how much to fill in pixels */
	nwords = nwords / (32 / boot_video_info->v_depth);	/* Get that in bytes */

	startword = (newwidth + 3) / 4;	/* Where does it start? */

	byteleft = (unsigned int *)(boot_video_info->v_baseAddr + windowleft);	/* Starting place */
	for (i = 0; i < nwords; i++)
		byteleft[i] = 0;	/* Set the row to all black */

	byteleft = (unsigned int *)(boot_video_info->v_baseAddr + windowleft + (boot_video_info->v_rowBytes * 1));	/* Starting place */
	for (i = 0; i < nwords; i++)
		byteleft[i] = 0;	/* Set the row to all black */

	byteleft = (unsigned int *)(boot_video_info->v_baseAddr + windowleft + (boot_video_info->v_rowBytes * (boot_video_info->v_height - 2)));	/* Starting place */
	for (i = 0; i < nwords; i++)
		byteleft[i] = 0;	/* Set the row to all black */

	byteleft = (unsigned int *)(boot_video_info->v_baseAddr + windowleft + (boot_video_info->v_rowBytes * (boot_video_info->v_height - 1)));	/* Starting place */
	for (i = 0; i < nwords; i++)
		byteleft[i] = 0;	/* Set the row to all black */

	for (i = 0; i < nwords; i++)
		fillframe[i] = 0xFFFFFFFF;	/* Set the row to all white */

	if (boot_video_info->v_depth == 8) {	/* See if 8 bits a pixel */
		fillframe[0] = 0x0000FFFF;	/* Make left border */
		fillframe[nwords - 1] = 0xFFFF0000;	/* Make right border */
	} else if (boot_video_info->v_depth == 16) {	/* See if 16 bits a pixel */
		fillframe[0] = 0x00000000;	/* Make left border */
		fillframe[nwords - 1] = 0x00000000;	/* Make right border */
	} else {
		fillframe[0] = 0x00000000;	/* Make left border */
		fillframe[1] = 0x00000000;	/* Make left border */
		fillframe[nwords - 1] = 0x00000000;	/* Make right border */
		fillframe[nwords - 2] = 0x00000000;	/* Make right border */
	}

	byteleft = (unsigned int *)(boot_video_info->v_baseAddr + windowleft + (boot_video_info->v_rowBytes * 2));	/* Place to start filling */

	for (i = 2; i < (boot_video_info->v_height - 2); i++) {	/* Fill the rest */
		for (j = 0; j < nwords; j++)
			byteleft[j] = fillframe[j];	/* Fill the row */
		byteleft = (unsigned int *)((unsigned int)byteleft + boot_video_info->v_rowBytes);	/* Next row */
	}

	for (i = 0; i < 2; i++) {	/* Initialize both (for now) processor areas */

		GratefulDebWork[i].GDtop =
		    2 + (GDfontsize / 2) + (i * 18 * GDfontsize);
		GratefulDebWork[i].GDleft = 2 + startpos + (GDfontsize / 2);
		GratefulDebWork[i].GDtopleft =
		    boot_video_info->v_baseAddr + startbyte +
		    (GratefulDebWork[i].GDtop * boot_video_info->v_rowBytes);
		GratefulDebWork[i].GDrowbytes = boot_video_info->v_rowBytes;
		GratefulDebWork[i].GDrowchar =
		    boot_video_info->v_rowBytes * (GDfontsize +
						   (GDfontsize / 4));
		GratefulDebWork[i].GDdepth = boot_video_info->v_depth;
		GratefulDebWork[i].GDcollgn = nrmlgn;

//              RuptCtrs[(48*i)+47].timed = gPEClockFrequencyInfo.timebase_frequency_hz >> 4;   /* (Update every 16th of a second (16 fps) */
		RuptCtrs[(48 * i) + 47].timed = gPEClockFrequencyInfo.timebase_frequency_hz >> 3;	/* (Update every 8th of a second (8 fps) */
//              RuptCtrs[(48*i)+47].timed = gPEClockFrequencyInfo.timebase_frequency_hz >> 2;   /* (Update every 4th of a second (4 fps) */
//              RuptCtrs[(48*i)+47].timed = gPEClockFrequencyInfo.timebase_frequency_hz >> 1;   /* (Update every 2th of a second (2 fps) */
//              RuptCtrs[(48*i)+47].timed = gPEClockFrequencyInfo.timebase_frequency_hz >> 0;   /* (Update every 1 second (1 fps) */

		sync();

		GratefulDebWork[i].GDready = 1;	/* This one's all ready */
	}
}

void debugNoop(void);
void
debugNoop(void)
{				/* This does absolutely nothing */
}
