/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File: screen.h
 * 	Author: Alessandro Forin, Carnegie Mellon University
 *	Date:	9/90
 *
 *	Definitions for the Generic Screen Driver.
 */

#ifndef _SCREEN_H_
#define _SCREEN_H_

/*
 * Most of these structures are defined so that the
 * resulting structure mapped to user space appears
 * to be compatible with the one used by the DEC X
 * servers (pm_info..). Keep it that way and the
 * X servers will keep on running.
 */

/*
 * Generic structures and defines
 */

/* colors */
typedef struct {
	unsigned short	red;
	unsigned short	green;
	unsigned short	blue;
} color_map_t;

typedef struct {
	short		unused;
	unsigned short	index;
	color_map_t	value;
} color_map_entry_t;

typedef struct {
	unsigned int	Bg_rgb[3];
	unsigned int	Fg_rgb[3];
} cursor_color_t;

/* generic input event */
typedef struct {
        short	        x;		/* x position */
        short 	        y;		/* y position */
        unsigned int    time;		/* 1 millisecond units */

        unsigned char   type;		/* button up/down/raw or motion */
#	define	EVT_BUTTON_UP		0
#	define	EVT_BUTTON_DOWN		1
#	define	EVT_BUTTON_RAW		2
#	define	EVT_PTR_MOTION		3

        unsigned char   key;		/* the key (button only) */
#	define	KEY_LEFT_BUTTON		1
#	define	KEY_MIDDLE_BUTTON	2
#	define	KEY_RIGHT_BUTTON	3
#	define	KEY_TBL_LEFT_BUTTON	0
#	define	KEY_TBL_FRONT_BUTTON	1
#	define	KEY_TBL_RIGHT_BUTTON	2
#	define	KEY_TBL_BACK_BUTTON	3

        unsigned char   index;		/* which instance of device */

        unsigned char   device;		/* which device */
#	define	DEV_NULL		0
#	define	DEV_MOUSE		1
#	define	DEV_KEYBD		2
#	define	DEV_TABLET		3
#	define	DEV_AUX			4
#	define	DEV_CONSOLE		5
#	define	DEV_KNOB		8
#	define	DEV_JOYSTICK		9

} screen_event_t;

/* timed coordinate info */
typedef struct {
	unsigned int	time;
	short		x, y;
} screen_timed_point_t;

/* queue of input events, and ring of mouse motions track */
typedef struct {
	screen_event_t 	*events;
	unsigned int 	q_size;
        unsigned int    q_head;
        unsigned int    q_tail;
	unsigned	long	timestamp;
	screen_timed_point_t	*track;
	unsigned int	t_size;
	unsigned int	t_next;
} screen_evque_t;

/* mouse/cursor position */
typedef struct {
        short x;
        short y;
} screen_point_t;

/* mouse motion bounding boxes */
typedef struct {
        short bottom;
        short right;
        short left;
        short top;
} screen_rect_t;

/*
 * Here it is, each field is marked as
 *
 * Kset	: kernel sets it unconditionally
 * Kuse : kernel uses it, safely
 * Kdep : kernel might depend on it
 */
typedef struct {
  screen_evque_t	evque;		/* Kset, Kuse */
  short			mouse_buttons;	/* Kset */
  screen_point_t 	xx3	/*tablet*/;
  short			xx4	/*tswitches*/;
  screen_point_t 	cursor;		/* Kset */
  short			row;		/* Kdep */
  short			col;		/* Kdep */
  short			max_row;	/* Kdep */
  short			max_col;	/* Kdep */
  short			max_x;		/* Kset */
  short			max_y;		/* Kset */
  short			max_cur_x;	/* Kdep */
  short			max_cur_y;	/* Kdep */
  int			version;	/* Kset */
  union {
    struct {
	unsigned char *	bitmap;		/* Kset */
	short *		x16	/*scanmap*/;
	short *		x17	/*cursorbits*/;
	short *		x18	/*pmaddr*/;
	unsigned char *	planemask;	/* Kset */
    } pm;
    struct {
	int		x15	/* flags */;
	int *		gram	/* Kset */;
	int *		rb_addr	/* Kset */;
	int		rb_phys	/* Kset */;
	int		rb_size	/* Kset */;
    } gx;
  } dev_dep_1;
  screen_point_t 	mouse_loc;	/* Kdep */
  screen_rect_t		mouse_box;	/* Kdep */
  short			mouse_threshold;/* Kuse */
  short			mouse_scale;	/* Kuse */
  short			min_cur_x;	/* Kdep */
  short			min_cur_y;	/* Kdep */
  union {
    struct {
	int		x26	/*dev_type*/;
	char *		x27	/*framebuffer*/;
	char *		x28	/*volatile struct bt459 *bt459*/;
	int		x29	/*slot*/;
	char		cursor_sprite[1024];/* Kset */
	unsigned char	Bg_color[3];	/* Kset */
	unsigned char	Fg_color[3];	/* Kset */
	int		tablet_scale_x;	/* Kuse */
	int 		tablet_scale_y;	/* Kuse */
    } pm;
    struct {
	char *		gxo		/* Kset */;
	char		stamp_width	/* Kset */;
	char		stamp_height	/* Kset */;
	char		nplanes		/* Kset */;
	char		x27_4	/* n10_present */;
	char		x28_1	/* dplanes */;
	char		zplanes		/* Kset */;
	char		zzplanes	/* Kset */;
	unsigned char	cursor_sprite[1024]	/* Kuse */;
	char		x285_0		/* padding for next, which was int */;
	unsigned char	Fg_color[4]	/* Kuse */;
	unsigned char	Bg_color[4]	/* Kuse */;
	unsigned short	cmap_index	/* Kuse */;
	unsigned short	cmap_count	/* Kuse */;
	unsigned int	colormap[256]	/* Kuse */;
	int *		stic_dma_rb	/* Kset */;
	int *		stic_reg	/* Kset */;
	int		ptpt_phys	/* Kdep */;
	int		ptpt_size	/* Kdep */;
	int *		ptpt_pgin	/* Kset */;
    } gx;
  } dev_dep_2;
  short		frame_scanline_width;	/* in pixels, Kset */
  short		frame_height;		/* in scanlines, Kset */
  /*
   * Event queues are allocated right after that
   */
#define	MAX_EVENTS	64
#define	MAX_TRACK	100
  screen_event_t	event_queue[MAX_EVENTS]; /* Kset */
  screen_timed_point_t	point_track[MAX_TRACK];  /* Kset */
  /*
   * Some like it hot
   */
  unsigned int		event_id;
  int			interrupt_info;
} user_info_t;


/*
 * Screen get_status codes and arguments
 */
#include <sys/ioctl.h>

	/* Get size (and offset) of mapped info */
#define	SCREEN_GET_OFFSETS	_IOR('q', 6, unsigned **)

	/* Get screen status flags */
#define SCREEN_STATUS_FLAGS	_IOR('q', 22, int *)
#	define	MONO_SCREEN	0x01
#	define	COLOR_SCREEN	0x02
#	define	SCREEN_BEING_UPDATED 0x04

/*
 * Screen set_status codes and arguments
 */

	/* start/stop screen saver, control fading interval */
#define	SCREEN_FADE		_IOW('q', 114, int)	/* fade screen */
#	define	NO_FADE		-1

	/* Turn video on/off manually */
#define SCREEN_ON		_IO('q', 10)
#define	SCREEN_OFF		_IO('q', 11)

	/* Fixup pointers inside mapped info structure */
#define	SCREEN_ADJ_MAPPED_INFO 	_IOR('q', 1, user_info_t *)

	/* Initialize anything that needs to, hw-wise */
#define SCREEN_INIT		_IO('q', 4)

	/* Position cursor to a specific spot */
#define SCREEN_SET_CURSOR	_IOW('q', 2, screen_point_t)

	/* Load Bg/Fg colors for cursor */
#define	SCREEN_SET_CURSOR_COLOR	_IOW('q', 3, cursor_color_t)

	/* Load cursor sprite, small cursor form */
typedef unsigned short cursor_sprite_t[32];

#define	SCREEN_LOAD_CURSOR	_IOW('q', 7, cursor_sprite_t)

	/* Load cursor sprite, large 64x64 cursor form */
typedef char cursor_sprite_long_t[1024];

#define	SCREEN_LOAD_CURSOR_LONG	_IOW('q', 13, cursor_sprite_long_t)

	/* Modify a given entry in the color map (VDAC) */
#define	SCREEN_SET_CMAP_ENTRY	_IOW('q', 12, color_map_entry_t)

	/* Return some other information about hardware (optional) */
typedef struct {
	int	frame_width;
	int	frame_height;
	int	frame_visible_width;
	int	frame_visible_height;
} screen_hw_info_t;
#define	SCREEN_HARDWARE_INFO	_IOR('q', 23, screen_hw_info_t)

	/* Screen-dependent, unspecified (and despised) */
#define	SCREEN_HARDWARE_DEP	_IO('q', 24)

#endif /* _SCREEN_H_ */
