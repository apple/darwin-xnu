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
 * @OSF_FREE_COPYRIGHT@
 * 
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/* MACH PPC - video_console.c 
 *
 * Original based on NetBSD's mac68k/dev/ite.c driver
 *
 * This driver differs in
 *	- MACH driver"ized"
 *	- Uses phys_copy and flush_cache to in several places
 *	  for performance optimizations
 *	- 7x15 font
 *	- Black background and white (character) foreground
 *	- Assumes 6100/7100/8100 class of machine 
 *
 * The original header follows...
 *
 *
 *	NetBSD: ite.c,v 1.16 1995/07/17 01:24:34 briggs Exp	
 *
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Utah $Hdr: ite.c 1.28 92/12/20$
 *
 *	@(#)ite.c	8.2 (Berkeley) 1/12/94
 */

/*
 * ite.c
 *
 * The ite module handles the system console; that is, stuff printed
 * by the kernel and by user programs while "desktop" and X aren't
 * running.  Some (very small) parts are based on hp300's 4.4 ite.c,
 * hence the above copyright.
 *
 *   -- Brad and Lawrence, June 26th, 1994
 *
 */

#include <vc.h>

#include <mach_kdb.h>
#include <kern/spl.h>
#include <machine/machparam.h>          /* spl definitions */
#include <types.h>
#include <ppc/iso_font.h>
#include <ppc/Firmware.h>

#include <ppc/POWERMAC/video_console_entries.h>
#include <ppc/POWERMAC/video_console.h>
#include <pexpert/pexpert.h>
#include <kern/time_out.h>
#include <kern/lock.h>
#include <kern/debug.h>

#include <kdp/kdp_udp.h>

#include "panic_image.c"
#include "rendered_numbers.c"


#define FAST_JUMP_SCROLL

#define	CHARWIDTH	8
#define	CHARHEIGHT	16

#define ATTR_NONE	0
#define ATTR_BOLD	1
#define ATTR_UNDER	2
#define ATTR_REVERSE	4

enum vt100state_e {
	ESnormal,		/* Nothing yet                             */
	ESesc,			/* Got ESC                                 */
	ESsquare,		/* Got ESC [				   */
	ESgetpars,		/* About to get or getting the parameters  */
	ESgotpars,		/* Finished getting the parameters         */
	ESfunckey,		/* Function key                            */
	EShash,			/* DEC-specific stuff (screen align, etc.) */
	ESsetG0,		/* Specify the G0 character set            */
	ESsetG1,		/* Specify the G1 character set            */
	ESask,
	EScharsize,
	ESignore		/* Ignore this sequence                    */
} vt100state = ESnormal;

struct vc_info			vinfo;

/* Calculated in vccninit(): */
static int vc_wrap_mode = 1, vc_relative_origin = 0;
static int vc_charset_select = 0, vc_save_charset_s = 0;
static int vc_charset[2] = { 0, 0 };
static int vc_charset_save[2] = { 0, 0 };

/* VT100 state: */
#define MAXPARS	16
static int x = 0, y = 0, savex, savey;
static int par[MAXPARS], numpars, hanging_cursor, attr, saveattr;

/* VT100 tab stops & scroll region */
static char tab_stops[255];
static int  scrreg_top, scrreg_bottom;

/* Misc */
static void	vc_initialize(void);
static void 	vc_flush_forward_buffer(void);
static void	vc_store_char(unsigned char);
static void 	vc_putchar(char ch);

void	vcattach(void);

/* panic dialog and info saving */
int mac_addr_digit_x;
int mac_addr_digit_y;
static void blit_digit( int digit );
boolean_t panicDialogDrawn = FALSE;

static void 
panic_blit_rect(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_8(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_16(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_32(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );

static void 
blit_rect_of_size_and_color(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			unsigned int dataPtr );

static void 
dim_screen(void);

/*static void 
dim_screen8(void);
*/

static void 
dim_screen16(void);

static void 
dim_screen32(void);


/*
 * For the color support (Michel Pollet)
 */
static unsigned char vc_color_index_table[33] = 
	{  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

static unsigned long vc_color_depth_masks[4] = 
	{ 0x000000FF, 0x00007FFF, 0x00FFFFFF };

static unsigned long vc_colors[8][3] = {
	{ 0xFFFFFFFF, 0x00000000, 0x00000000 },	/* black */
	{ 0x23232323, 0x7C007C00, 0x00FF0000 },	/* red	*/
	{ 0xb9b9b9b9, 0x03e003e0, 0x0000FF00 },	/* green */
	{ 0x05050505, 0x7FE07FE0, 0x00FFFF00 },	/* yellow */
	{ 0xd2d2d2d2, 0x001f001f, 0x000000FF},	/* blue	 */
//	{ 0x80808080, 0x31933193, 0x00666699 },	/* blue	 */
	{ 0x18181818, 0x7C1F7C1F, 0x00FF00FF },	/* magenta */
	{ 0xb4b4b4b4, 0x03FF03FF, 0x0000FFFF },	/* cyan	*/
	{ 0x00000000, 0x7FFF7FFF, 0x00FFFFFF }	/* white */
};

static unsigned long vc_color_mask = 0;
static unsigned long vc_color_fore = 0;
static unsigned long vc_color_back = 0;
static int vc_normal_background = 1;


/*
 * For the jump scroll and buffering (Michel Pollet)
 * 80*22 means on a 80*24 screen, the screen will
 * scroll jump almost a full screen
 * keeping only what's necessary for you to be able to read ;-)
 */
#define VC_MAX_FORWARD_SIZE	(100*36)

/*
 * Delay between console updates in clock hz units, the larger the
 * delay the fuller the jump-scroll buffer will be and so the faster the
 * (scrolling) output. The smaller the delay, the less jerky the
 * display. Heuristics show that at 10 touch-typists (Mike!) complain
 */
#define VC_CONSOLE_UPDATE_TIMEOUT	5

static unsigned char vc_forward_buffer[VC_MAX_FORWARD_SIZE];
static long vc_forward_buffer_size = 0;
static int vc_forward_buffer_enabled = 0;
static int vc_forward_buffer_busy = 0;
decl_simple_lock_data(,vc_forward_lock)

#ifdef FAST_JUMP_SCROLL
static void (*vc_forward_paintchar) (unsigned char c, int x, int y, int attrs);
static enum {
	PFoff,
	PFwind,
	PFscroll,
	PFunwind
} vc_forward_preflight_mode = PFoff;
static struct {
	enum vt100state_e vt100state;

	int vc_wrap_mode, vc_relative_origin;
	int vc_charset_select, vc_save_charset_s;
	int vc_charset[2];
	int vc_charset_save[2];

	int x, y, savex, savey;
	int par[MAXPARS], numpars, hanging_cursor, attr, saveattr;

	char tab_stops[255];
	int  scrreg_top, scrreg_bottom;

        unsigned long vc_color_fore;
        unsigned long vc_color_back;
} vc_forward_preflight_save;
static int vc_forward_scroll = 0;
#endif FAST_JUMP_SCROLL

/* 
 * New Rendering code from Michel Pollet
 */

/* That function will be called for drawing */
static void (*vc_paintchar) (unsigned char c, int x, int y, int attrs);

#ifdef RENDERALLOCATE
static unsigned char *renderedFont = NULL;	/* rendered font buffer */
#else
#define REN_MAX_DEPTH	32
/* that's the size for a 32 bits buffer... */
#define REN_MAX_SIZE 	(128L*1024)
static unsigned char renderedFont[REN_MAX_SIZE];
#endif

/* Rendered Font Size */
static unsigned long vc_rendered_font_size = REN_MAX_SIZE;
static long vc_rendered_error = 0;

/* If the one bit table was reversed */
static short vc_one_bit_reversed = 0;

/* Size of a character in the table (bytes) */
static int	vc_rendered_char_size = 0;

/*
# Attribute codes: 
# 00=none 01=bold 04=underscore 05=blink 07=reverse 08=concealed
# Text color codes:
# 30=black 31=red 32=green 33=yellow 34=blue 35=magenta 36=cyan 37=white
# Background color codes:
# 40=black 41=red 42=green 43=yellow 44=blue 45=magenta 46=cyan 47=white
*/

#define VC_RESET_BACKGROUND 40
#define VC_RESET_FOREGROUND 37

static void vc_color_set(int color)
{
	if (vinfo.v_depth < 8)
		return;
	if (color >= 30 && color <= 37)
		vc_color_fore = vc_colors[color-30][vc_color_index_table[vinfo.v_depth]];
	if (color >= 40 && color <= 47) {
		vc_color_back = vc_colors[color-40][vc_color_index_table[vinfo.v_depth]];
		vc_normal_background = color == 40;
	}

}

static void vc_render_font(short olddepth, short newdepth)
{
	int charIndex;	/* index in ISO font */
	union {
		unsigned char  *charptr;
		unsigned short *shortptr;
		unsigned long  *longptr;
	} current; 	/* current place in rendered font, multiple types. */

	unsigned char *theChar;	/* current char in iso_font */

	if (olddepth == newdepth && renderedFont) {
		return;	/* nothing to do */
	}
	
	if (olddepth != 1 && renderedFont) {
#ifdef RENDERALLOCATE
		(void) kmem_free(kernel_map, (vm_offset_t*)renderedFont, vc_rendered_font_size);
#endif
	}
	vc_rendered_font_size = REN_MAX_SIZE;
	if (newdepth == 1) {
#ifdef RENDERALLOCATE
		renderedFont = iso_font;
#endif
		vc_rendered_char_size = 16;
		if (!vc_one_bit_reversed) {	/* reverse the font for the blitter */
			int i;
			for (i = 0; i < ((ISO_CHAR_MAX-ISO_CHAR_MIN+1) * vc_rendered_char_size); i++) {
				if (iso_font[i]) {
					unsigned char mask1 = 0x80;
					unsigned char mask2 = 0x01;
					unsigned char val = 0;
					while (mask1) { 
						if (iso_font[i] & mask1)
							val |= mask2;
						mask1 >>= 1;
						mask2 <<= 1;
					}
					renderedFont[i] = ~val;
				} else renderedFont[i] = 0xff;
			}
			vc_one_bit_reversed = 1;
		}
		return;
	}
	{
		long csize = newdepth / 8;	/* bytes per pixel */
		vc_rendered_char_size = csize ? CHARHEIGHT * (csize * CHARWIDTH) : 
				/* for 2 & 4 */	CHARHEIGHT * (CHARWIDTH/(6-newdepth));
		csize = (ISO_CHAR_MAX-ISO_CHAR_MIN+1) * vc_rendered_char_size;
#ifndef RENDERALLOCATE
		if (csize > vc_rendered_font_size) {
			vc_rendered_error = csize;
			return;
		} else 
			vc_rendered_font_size = csize;
#else
		vc_rendered_font_size = csize;
#endif
	}

#ifdef RENDERALLOCATE
	if (kmem_alloc(kernel_map,
		       (vm_offset_t *)&renderedFont,
		       vc_rendered_font_size) != KERN_SUCCESS) {
		renderedFont = NULL;
		vc_rendered_error = vc_rendered_font_size;
		return;
	}
#endif
	current.charptr = renderedFont;
	theChar = iso_font;
	for (charIndex = ISO_CHAR_MIN; charIndex <= ISO_CHAR_MAX; charIndex++) {
		int line;
		for (line = 0; line < CHARHEIGHT; line++) {
			unsigned char mask = 1;
			do {
				switch (newdepth) {
				case 2: {
					unsigned char value = 0;
					if (*theChar & mask) value |= 0xC0; mask <<= 1;
					if (*theChar & mask) value |= 0x30; mask <<= 1;
					if (*theChar & mask) value |= 0x0C; mask <<= 1;
					if (*theChar & mask) value |= 0x03;
					value = ~value;
					*current.charptr++ = value;
				}
					break;
				case 4:
				{
					unsigned char value = 0;
					if (*theChar & mask) value |= 0xF0; mask <<= 1;
					if (*theChar & mask) value |= 0x0F;
					value = ~value;
					*current.charptr++ = value;
				}
				break;
				case 8: 
					*current.charptr++ = (*theChar & mask) ? 0xff : 0;
					break;
				case 16:
					*current.shortptr++ = (*theChar & mask) ? 0xFFFF : 0;
					break;

				case 32: 
					*current.longptr++ = (*theChar & mask) ? 0xFFFFFFFF : 0;
					break;
				}
				mask <<= 1;
			} while (mask);	/* while the single bit drops to the right */
			theChar++;
		}
	}
}

#ifdef FAST_JUMP_SCROLL
static void vc_paint_char(unsigned char ch, int xx, int yy, int attrs)
{
	switch (vc_forward_preflight_mode) {
		case PFoff:
			vc_forward_paintchar(ch, xx, yy, attrs);
			break;
		case PFwind:
			break;
		case PFscroll:
			break;
		case PFunwind:
			if (yy >= scrreg_top && yy < scrreg_bottom) {
				yy -= vc_forward_scroll;
				if (yy < scrreg_top || yy >= scrreg_bottom)
					break;
			}
			vc_forward_paintchar(ch, xx, yy, attrs);
			break;
	}
}
#endif FAST_JUMP_SCROLL

static void vc_paint_char1(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned char *theChar;
	unsigned char *where;
	int i;
	
	theChar = (unsigned char*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned char*)(vinfo.v_baseaddr + 
				 (yy * CHARHEIGHT * vinfo.v_rowbytes) + 
				 (xx));

	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attributes ? FLY !!!! */
		*where = *theChar++;
		
		where = (unsigned char*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) {	/* a little bit slower */
		unsigned char val = *theChar++, save = val;
		if (attrs & ATTR_BOLD) {		/* bold support */
			unsigned char mask1 = 0xC0, mask2 = 0x40;
			int bit = 0;
			for (bit = 0; bit < 7; bit++) {
				if ((save & mask1) == mask2)
					val &= ~mask2;
				mask1 >>= 1;
				mask2 >>= 1;
			}
		}
		if (attrs & ATTR_REVERSE) val = ~val;
		if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;
		*where = val;
		
		where = (unsigned char*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}

static void vc_paint_char2(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned short *theChar;
	unsigned short *where;
	int i;

	theChar = (unsigned short*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned short*)(vinfo.v_baseaddr + 
				  (yy * CHARHEIGHT * vinfo.v_rowbytes) + 
				  (xx * 2));
	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attributes ? FLY !!!! */
		*where = *theChar++;
		
		where = (unsigned short*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) {	/* a little bit slower */
		unsigned short val = *theChar++, save = val;
		if (attrs & ATTR_BOLD) {		/* bold support */
			unsigned short mask1 = 0xF000, mask2 = 0x3000;
			int bit = 0;
			for (bit = 0; bit < 7; bit++) {
				if ((save & mask1) == mask2)
					val &= ~mask2;
				mask1 >>= 2;
				mask2 >>= 2;
			}
		}
		if (attrs & ATTR_REVERSE) val = ~val;
		if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;
		*where = val;
		
		where = (unsigned short*)(((unsigned char*)where)+vinfo.v_rowbytes);
	}

}

static void vc_paint_char4(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned long *theChar;
	unsigned long *where;
	int i;

	theChar = (unsigned long*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned long*)(vinfo.v_baseaddr + 
				 (yy * CHARHEIGHT * vinfo.v_rowbytes) + 
				 (xx * 4));

	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attributes ? FLY !!!! */
		*where = *theChar++;
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) {	/* a little bit slower */
		unsigned long val = *theChar++, save = val;
		if (attrs & ATTR_BOLD) {		/* bold support */
			unsigned long mask1 = 0xff000000, mask2 = 0x0F000000;
			int bit = 0;
			for (bit = 0; bit < 7; bit++) {
				if ((save & mask1) == mask2)
					val &= ~mask2;
				mask1 >>= 4;
				mask2 >>= 4;
			}
		}
		if (attrs & ATTR_REVERSE) val = ~val;
		if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;
		*where = val;
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	}

}

static void vc_paint_char8c(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned long *theChar;
	unsigned long *where;
	int i;
	
	theChar = (unsigned long*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned long*)(vinfo.v_baseaddr + 
					(yy * CHARHEIGHT * vinfo.v_rowbytes) + 
					(xx * CHARWIDTH));

	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attr? FLY !*/
		unsigned long *store = where;
		int x;
		for (x = 0; x < 2; x++) {
			unsigned long val = *theChar++;
			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) {	/* a little slower */
		unsigned long *store = where, lastpixel = 0;
		int x;
		for (x = 0 ; x < 2; x++) {
			unsigned long val = *theChar++, save = val;
			if (attrs & ATTR_BOLD) {	/* bold support */
				if (lastpixel && !(save & 0xFF000000))
					val |= 0xff000000;
				if ((save & 0xFFFF0000) == 0xFF000000)
					val |= 0x00FF0000;
				if ((save & 0x00FFFF00) == 0x00FF0000)
					val |= 0x0000FF00;
				if ((save & 0x0000FFFF) == 0x0000FF00)
					val |= 0x000000FF;
			}
			if (attrs & ATTR_REVERSE) val = ~val;
			if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
			lastpixel = save & 0xff;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}
static void vc_paint_char16c(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned long *theChar;
	unsigned long *where;
	int i;
	
	theChar = (unsigned long*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned long*)(vinfo.v_baseaddr + 
				 (yy * CHARHEIGHT * vinfo.v_rowbytes) + 
				 (xx * CHARWIDTH * 2));

	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attrs ? FLY ! */
		unsigned long *store = where;
		int x;
		for (x = 0; x < 4; x++) {
			unsigned long val = *theChar++;
			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) { /* a little bit slower */
		unsigned long *store = where, lastpixel = 0;
		int x;
		for (x = 0 ; x < 4; x++) {
			unsigned long val = *theChar++, save = val;
			if (attrs & ATTR_BOLD) {	/* bold support */
				if (save == 0xFFFF0000) val |= 0xFFFF;
				else if (lastpixel && !(save & 0xFFFF0000))
					val |= 0xFFFF0000;
			}
			if (attrs & ATTR_REVERSE) val = ~val;
			if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);

			*store++ = val;
			lastpixel = save & 0x7fff;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}
static void vc_paint_char32c(unsigned char ch, int xx, int yy, int attrs) 
{
	unsigned long *theChar;
	unsigned long *where;
	int i;
	
	theChar = (unsigned long*)(renderedFont + (ch * vc_rendered_char_size));
	where = (unsigned long*)(vinfo.v_baseaddr + 
					(yy * CHARHEIGHT * vinfo.v_rowbytes) + 
					(xx * CHARWIDTH * 4));

	if (!attrs) for (i = 0; i < CHARHEIGHT; i++) {	/* No attrs ? FLY ! */
		unsigned long *store = where;
		int x;
		for (x = 0; x < 8; x++) {
			unsigned long val = *theChar++;
			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < CHARHEIGHT; i++) {	/* a little slower */
		unsigned long *store = where, lastpixel = 0;
		int x;
		for (x = 0 ; x < 8; x++) {
			unsigned long val = *theChar++, save = val;
			if (attrs & ATTR_BOLD) {	/* bold support */
				if (lastpixel && !save)
					val = 0xFFFFFFFF;
			}
			if (attrs & ATTR_REVERSE) val = ~val;
			if (attrs & ATTR_UNDER &&  i == CHARHEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
			lastpixel = save;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}

/*
 * That's a plain dumb reverse of the cursor position
 * It do a binary reverse, so it will not looks good when we have
 * color support. we'll see that later
 */
static void reversecursor(void)
{
	union {
		unsigned char  *charptr;
		unsigned short *shortptr;
		unsigned long  *longptr;
	} where;
	int line, col;
	
	where.longptr =  (unsigned long*)(vinfo.v_baseaddr + 
					(y * CHARHEIGHT * vinfo.v_rowbytes) + 
					(x /** CHARWIDTH*/ * vinfo.v_depth));
	for (line = 0; line < CHARHEIGHT; line++) {
		switch (vinfo.v_depth) {
			case 1:
				*where.charptr = ~*where.charptr;
				break;
			case 2:
				*where.shortptr = ~*where.shortptr;
				break;
			case 4:
				*where.longptr = ~*where.longptr;
				break;
/* that code still exists because since characters on the screen are
 * of different colors that reverse function may not work if the
 * cursor is on a character that is in a different color that the
 * current one. When we have buffering, things will work better. MP
 */
#ifdef VC_BINARY_REVERSE
			case 8:
				where.longptr[0] = ~where.longptr[0];
				where.longptr[1] = ~where.longptr[1];
				break;
			case 16:
				for (col = 0; col < 4; col++)
					where.longptr[col] = ~where.longptr[col];
				break;
			case 32:
				for (col = 0; col < 8; col++)
					where.longptr[col] = ~where.longptr[col];
				break;
#else
			case 8:
				for (col = 0; col < 8; col++)
					where.charptr[col] = where.charptr[col] != (vc_color_fore & vc_color_mask) ?
										vc_color_fore & vc_color_mask : vc_color_back & vc_color_mask;
				break;
			case 16:
				for (col = 0; col < 8; col++)
					where.shortptr[col] = where.shortptr[col] != (vc_color_fore & vc_color_mask) ?
										vc_color_fore & vc_color_mask : vc_color_back & vc_color_mask;
				break;
			case 32:
				for (col = 0; col < 8; col++)
					where.longptr[col] = where.longptr[col] != (vc_color_fore & vc_color_mask) ?
										vc_color_fore & vc_color_mask : vc_color_back & vc_color_mask;
				break;
#endif
		}
		where.charptr += vinfo.v_rowbytes;
	}
}


static void 
scrollup(int num)
{
	unsigned long *from, *to, linelongs, i, line, rowline, rowscanline;

	linelongs = (vinfo.v_rowbytes * CHARHEIGHT) >> 2;
	rowline = (vinfo.v_rowbytes) >> 2;
	rowscanline = (vinfo.v_rowscanbytes) >> 2;

#ifdef FAST_JUMP_SCROLL
	if (vc_forward_preflight_mode == PFwind) {
		vc_forward_scroll += num;
		return;
	}
	if (vc_forward_preflight_mode == PFscroll || vc_forward_preflight_mode == PFoff) {
#endif FAST_JUMP_SCROLL

	to = (unsigned long *) vinfo.v_baseaddr + (scrreg_top * linelongs);
	from = to + (linelongs * num);	/* handle multiple line scroll (Michel Pollet) */

	i = (scrreg_bottom - scrreg_top) - num;

	while (i-- > 0) {
		for (line = 0; line < CHARHEIGHT; line++) {
			/*
			 * Only copy what is displayed
			 */
			video_scroll_up((unsigned int) from, 
					(unsigned int) (from+(vinfo.v_rowscanbytes/4)), 
					(unsigned int) to);

			from += rowline;
			to += rowline;
		}
	}

	/* Now set the freed up lines to the background colour */


	to = ((unsigned long *) vinfo.v_baseaddr + (scrreg_top * linelongs))
		+ ((scrreg_bottom - scrreg_top - num) * linelongs);

#ifdef FAST_JUMP_SCROLL
		if (vc_forward_preflight_mode == PFscroll)
			return;
	} else if (vc_forward_preflight_mode == PFunwind) {
		long linestart, linelast;
		vc_forward_scroll -= num;

		linestart = scrreg_bottom - num - vc_forward_scroll;
		linelast  = linestart + num - 1;

		if (linestart >= scrreg_bottom || linelast < scrreg_top)
			return;

		if (linelast >= scrreg_bottom)
			linelast = scrreg_bottom - 1;
		if (linestart < scrreg_top)
			linestart = scrreg_top;

		to = ((unsigned long *) vinfo.v_baseaddr) + (linelongs * linestart);
		num = linelast - linestart + 1;
	}
#endif FAST_JUMP_SCROLL

	for (linelongs = CHARHEIGHT * num;  linelongs-- > 0;) {
		from = to;
		for (i = 0; i < rowscanline; i++) 
			*to++ = vc_color_back;

		to = from + rowline;
	}

}

static void 
scrolldown(int num)
{
	unsigned long *from, *to,  linelongs, i, line, rowline, rowscanline;

	linelongs = (vinfo.v_rowbytes * CHARHEIGHT) >> 2;
	rowline = (vinfo.v_rowbytes) >> 2;
	rowscanline = (vinfo.v_rowscanbytes) >> 2;

#ifdef FAST_JUMP_SCROLL
	if (vc_forward_preflight_mode == PFwind) {
		vc_forward_scroll -= num;
		return;
	}
	if (vc_forward_preflight_mode == PFscroll || vc_forward_preflight_mode == PFoff) {
#endif FAST_JUMP_SCROLL

	to = (unsigned long *) vinfo.v_baseaddr + (linelongs * scrreg_bottom)
		- (rowline - rowscanline);
	from = to - (linelongs * num);	/* handle multiple line scroll (Michel Pollet) */

	i = (scrreg_bottom - scrreg_top) - num;

	while (i-- > 0) {
		for (line = 0; line < CHARHEIGHT; line++) {
			/*
			 * Only copy what is displayed
			 */
			video_scroll_down((unsigned int) from, 
					(unsigned int) (from-(vinfo.v_rowscanbytes/4)), 
					(unsigned int) to);

			from -= rowline;
			to -= rowline;
		}
	}

	/* Now set the freed up lines to the background colour */

	to = (unsigned long *) vinfo.v_baseaddr + (linelongs * scrreg_top);

#ifdef FAST_JUMP_SCROLL
		if (vc_forward_preflight_mode == PFscroll)
			return;
	} else if (vc_forward_preflight_mode == PFunwind) {
		long linestart, linelast;
		vc_forward_scroll += num;

		linestart = scrreg_top - vc_forward_scroll;
		linelast  = linestart + num - 1;

		if (linestart >= scrreg_bottom || linelast < scrreg_top)
			return;

		if (linelast >= scrreg_bottom)
			linelast = scrreg_bottom - 1;
		if (linestart < scrreg_top)
			linestart = scrreg_top;

		to = ((unsigned long *) vinfo.v_baseaddr) + (linelongs * linestart);
		num = linelast - linestart + 1;
	}
#endif FAST_JUMP_SCROLL

	for (line = CHARHEIGHT * num; line > 0; line--) {
		from = to;

		for (i = 0; i < rowscanline; i++) 
			*(to++) = vc_color_back;

		to = from + rowline;
	}

}


static void 
clear_line(int which)
{
	int     start, end, i;

	/*
	 * This routine runs extremely slowly.  I don't think it's
	 * used all that often, except for To end of line.  I'll go
	 * back and speed this up when I speed up the whole vc
	 * module. --LK
	 */

	switch (which) {
	case 0:		/* To end of line	 */
		start = x;
		end = vinfo.v_columns-1;
		break;
	case 1:		/* To start of line	 */
		start = 0;
		end = x;
		break;
	case 2:		/* Whole line		 */
		start = 0;
		end = vinfo.v_columns-1;
		break;
	}

	for (i = start; i <= end; i++) {
		vc_paintchar(' ', i, y, ATTR_NONE);
	}

}

static void 
clear_screen(int which)
{
	unsigned long *p, *endp, *row;
	int      linelongs, col;
	int      rowline, rowlongs;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;;
	endp = (unsigned long*) vinfo.v_baseaddr;

	linelongs = vinfo.v_rowbytes * CHARHEIGHT / 4;

	switch (which) {
	case 0:		/* To end of screen	 */
		clear_line(0);
		if (y < vinfo.v_rows - 1) {
			p += (y + 1) * linelongs;
			endp += rowlongs * vinfo.v_height;
		}
		break;
	case 1:		/* To start of screen	 */
		clear_line(1);
		if (y > 1) {
			endp += (y + 1) * linelongs;
		}
		break;
	case 2:		/* Whole screen		 */
		endp += rowlongs * vinfo.v_height;
		break;
	}

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) 
			*(row+col) = vc_color_back;
	}

}

static void
reset_tabs(void)
{
	int i;

	for (i = 0; i<= vinfo.v_columns; i++) {
		tab_stops[i] = ((i % 8) == 0);
	}

}

static void
vt100_reset(void)
{
	reset_tabs();
	scrreg_top    = 0;
	scrreg_bottom = vinfo.v_rows;
	attr = ATTR_NONE;
	vc_charset[0] = vc_charset[1] = 0;
	vc_charset_select = 0;
	vc_wrap_mode = 1;
	vc_relative_origin = 0;
	vc_color_set(VC_RESET_BACKGROUND);
	vc_color_set(VC_RESET_FOREGROUND);	

}

static void 
putc_normal(unsigned char ch)
{
	switch (ch) {
	case '\a':		/* Beep			 */
        {
            spl_t s;

            if(FALSE) {
                /*
                 * No sound hardware, invert the screen twice instead
                 */
                unsigned long *ptr;
                int i, j;
                /* XOR the screen twice */
                for (i = 0; i < 2 ; i++) {
                    /* For each row, xor the scanbytes */
                    for (ptr = (unsigned long*)vinfo.v_baseaddr;
                        ptr < (unsigned long*)(vinfo.v_baseaddr +
                                (vinfo.v_height * vinfo.v_rowbytes));
                        ptr += (vinfo.v_rowbytes /
                                sizeof (unsigned long*)))
                            for (j = 0;
                                j < vinfo.v_rowscanbytes /
                                        sizeof (unsigned long*);
                                j++)
                                    *(ptr+j) =~*(ptr+j);
                }
            }
        }
        break;

	case 127:		/* Delete		 */
	case '\b':		/* Backspace		 */
		if (hanging_cursor) {
			hanging_cursor = 0;
		} else
			if (x > 0) {
				x--;
			}
		break;
	case '\t':		/* Tab			 */
		while (x < vinfo.v_columns && !tab_stops[++x]);
		if (x >= vinfo.v_columns)
			x = vinfo.v_columns-1;
		break;
	case 0x0b:
	case 0x0c:
	case '\n':		/* Line feed		 */
		if (y >= scrreg_bottom -1 ) {
			scrollup(1);
			y = scrreg_bottom - 1;
		} else {
			y++;
		}
		break;
	case '\r':		/* Carriage return	 */
		x = 0;
		hanging_cursor = 0;
		break;
	case 0x0e:  /* Select G1 charset (Control-N) */
		vc_charset_select = 1;
		break;
	case 0x0f:  /* Select G0 charset (Control-O) */
		vc_charset_select = 0;
		break;
	case 0x18 : /* CAN : cancel */
	case 0x1A : /* like cancel */
			/* well, i do nothing here, may be later */
		break;
	case '\033':		/* Escape		 */
		vt100state = ESesc;
		hanging_cursor = 0;
		break;
	default:
		if (ch >= ' ') {
			if (hanging_cursor) {
				x = 0;
				if (y >= scrreg_bottom -1 ) {
					scrollup(1);
					y = scrreg_bottom - 1;
				} else {
					y++;
				}
				hanging_cursor = 0;
			}
			vc_paintchar((ch >= 0x60 && ch <= 0x7f) ? ch + vc_charset[vc_charset_select]
								: ch, x, y, attr);
			if (x == vinfo.v_columns - 1) {
				hanging_cursor = vc_wrap_mode;
			} else {
				x++;
			}
		}
		break;
	}

}

static void 
putc_esc(unsigned char ch)
{
	vt100state = ESnormal;

	switch (ch) {
	case '[':
		vt100state = ESsquare;
		break;
	case 'c':		/* Reset terminal 	 */
		vt100_reset();
		clear_screen(2);
		x = y = 0;
		break;
	case 'D':		/* Line feed		 */
	case 'E':
		if (y >= scrreg_bottom -1) {
			scrollup(1);
			y = scrreg_bottom - 1;
		} else {
			y++;
		}
		if (ch == 'E') x = 0;
		break;
	case 'H':		/* Set tab stop		 */
		tab_stops[x] = 1;
		break;
	case 'M':		/* Cursor up		 */
		if (y <= scrreg_top) {
			scrolldown(1);
			y = scrreg_top;
		} else {
			y--;
		}
		break;
	case '>':
		vt100_reset();
		break;
	case '7':		/* Save cursor		 */
		savex = x;
		savey = y;
		saveattr = attr;
		vc_save_charset_s = vc_charset_select;
		vc_charset_save[0] = vc_charset[0];
		vc_charset_save[1] = vc_charset[1];
		break;
	case '8':		/* Restore cursor	 */
		x = savex;
		y = savey;
		attr = saveattr;
		vc_charset_select = vc_save_charset_s;
		vc_charset[0] = vc_charset_save[0];
		vc_charset[1] = vc_charset_save[1];
		break;
	case 'Z':		/* return terminal ID */
		break;
	case '#':		/* change characters height */
		vt100state = EScharsize;
		break;
	case '(':
		vt100state = ESsetG0;
		break;
	case ')':		/* character set sequence */
		vt100state = ESsetG1;
		break;
	case '=':
		break;
	default:
		/* Rest not supported */
		break;
	}

}

static void
putc_askcmd(unsigned char ch)
{
	if (ch >= '0' && ch <= '9') {
		par[numpars] = (10*par[numpars]) + (ch-'0');
		return;
	}
	vt100state = ESnormal;

	switch (par[0]) {
		case 6:
			vc_relative_origin = ch == 'h';
			break;
		case 7:	/* wrap around mode h=1, l=0*/
			vc_wrap_mode = ch == 'h';
			break;
		default:
			break;
	}

}

static void
putc_charsizecmd(unsigned char ch)
{
	vt100state = ESnormal;

	switch (ch) {
		case '3' :
		case '4' :
		case '5' :
		case '6' :
			break;
		case '8' :	/* fill 'E's */
			{
				int xx, yy;
				for (yy = 0; yy < vinfo.v_rows; yy++)
					for (xx = 0; xx < vinfo.v_columns; xx++)
						vc_paintchar('E', xx, yy, ATTR_NONE);
			}
			break;
	}

}

static void
putc_charsetcmd(int charset, unsigned char ch)
{
	vt100state = ESnormal;

	switch (ch) {
		case 'A' :
		case 'B' :
		default:
			vc_charset[charset] = 0;
			break;
		case '0' :	/* Graphic characters */
		case '2' :
			vc_charset[charset] = 0x21;
			break;
	}

}

static void 
putc_gotpars(unsigned char ch)
{
	int     i;

	if (ch < ' ') {
		/* special case for vttest for handling cursor
		   movement in escape sequences */
		putc_normal(ch);
		vt100state = ESgotpars;
		return;
	}
	vt100state = ESnormal;
	switch (ch) {
	case 'A':		/* Up			 */
		y -= par[0] ? par[0] : 1;
		if (y < scrreg_top)
			y = scrreg_top;
		break;
	case 'B':		/* Down			 */
		y += par[0] ? par[0] : 1;
		if (y >= scrreg_bottom)
			y = scrreg_bottom - 1;
		break;
	case 'C':		/* Right		 */
		x += par[0] ? par[0] : 1;
		if (x >= vinfo.v_columns)
			x = vinfo.v_columns-1;
		break;
	case 'D':		/* Left			 */
		x -= par[0] ? par[0] : 1;
		if (x < 0)
			x = 0;
		break;
	case 'H':		/* Set cursor position	 */
	case 'f':
		x = par[1] ? par[1] - 1 : 0;
		y = par[0] ? par[0] - 1 : 0;
		if (vc_relative_origin)
			y += scrreg_top;
		hanging_cursor = 0;
		break;
	case 'X':		/* clear p1 characters */
		if (numpars) {
			int i;
			for (i = x; i < x + par[0]; i++)
				vc_paintchar(' ', i, y, ATTR_NONE);
		}
		break;
	case 'J':		/* Clear part of screen	 */
		clear_screen(par[0]);
		break;
	case 'K':		/* Clear part of line	 */
		clear_line(par[0]);
		break;
	case 'g':		/* tab stops	 	 */
		switch (par[0]) {
			case 1:
			case 2:	/* reset tab stops */
				/* reset_tabs(); */
				break;				
			case 3:	/* Clear every tabs */
				{
					int i;

					for (i = 0; i <= vinfo.v_columns; i++)
						tab_stops[i] = 0;
				}
				break;
			case 0:
				tab_stops[x] = 0;
				break;
		}
		break;
	case 'm':		/* Set attribute	 */
		for (i = 0; i < numpars; i++) {
			switch (par[i]) {
			case 0:
				attr = ATTR_NONE;
				vc_color_set(VC_RESET_BACKGROUND);
				vc_color_set(VC_RESET_FOREGROUND);	
				break;
			case 1:
				attr |= ATTR_BOLD;
				break;
			case 4:
				attr |= ATTR_UNDER;
				break;
			case 7:
				attr |= ATTR_REVERSE;
				break;
			case 22:
				attr &= ~ATTR_BOLD;
				break;
			case 24:
				attr &= ~ATTR_UNDER;
				break;
			case 27:
				attr &= ~ATTR_REVERSE;
				break;
			case 5:
			case 25:	/* blink/no blink */
				break;
			default:
				vc_color_set(par[i]);
				break;
			}
		}
		break;
	case 'r':		/* Set scroll region	 */
		x = y = 0;
		/* ensure top < bottom, and both within limits */
		if ((numpars > 0) && (par[0] < vinfo.v_rows)) {
			scrreg_top = par[0] ? par[0] - 1 : 0;
			if (scrreg_top < 0)
				scrreg_top = 0;
		} else {
			scrreg_top = 0;
		}
		if ((numpars > 1) && (par[1] <= vinfo.v_rows) && (par[1] > par[0])) {
			scrreg_bottom = par[1];
			if (scrreg_bottom > vinfo.v_rows)
				scrreg_bottom = vinfo.v_rows;
		} else {
			scrreg_bottom = vinfo.v_rows;
		}
		if (vc_relative_origin)
			y = scrreg_top;
		break;
	}

}

static void 
putc_getpars(unsigned char ch)
{
	if (ch == '?') {
		vt100state = ESask;
		return;
	}
	if (ch == '[') {
		vt100state = ESnormal;
		/* Not supported */
		return;
	}
	if (ch == ';' && numpars < MAXPARS - 1) {
		numpars++;
	} else
		if (ch >= '0' && ch <= '9') {
			par[numpars] *= 10;
			par[numpars] += ch - '0';
		} else {
			numpars++;
			vt100state = ESgotpars;
			putc_gotpars(ch);
		}
}

static void 
putc_square(unsigned char ch)
{
	int     i;

	for (i = 0; i < MAXPARS; i++) {
		par[i] = 0;
	}

	numpars = 0;
	vt100state = ESgetpars;

	putc_getpars(ch);

}

static void 
vc_putchar(char ch)
{
	if (!ch) {
		return;	/* ignore null characters */
	}
	switch (vt100state) {
		default:vt100state = ESnormal;	/* FALLTHROUGH */
	case ESnormal:
		putc_normal(ch);
		break;
	case ESesc:
		putc_esc(ch);
		break;
	case ESsquare:
		putc_square(ch);
		break;
	case ESgetpars:
		putc_getpars(ch);
		break;
	case ESgotpars:
		putc_gotpars(ch);
		break;
	case ESask:
		putc_askcmd(ch);
		break;
	case EScharsize:
		putc_charsizecmd(ch);
		break;
	case ESsetG0:
		putc_charsetcmd(0, ch);
		break;
	case ESsetG1:
		putc_charsetcmd(1, ch);
		break;
	}

	if (x >= vinfo.v_columns) {
		x = vinfo.v_columns - 1;
	}
	if (x < 0) {
		x = 0;
	}
	if (y >= vinfo.v_rows) {
		y = vinfo.v_rows - 1;
	}
	if (y < 0) {
		y = 0;
	}

}

/*
 * Actually draws the buffer, handle the jump scroll
 */
static void vc_flush_forward_buffer(void)
{
	int start = 0;
	int todo = 0;
	spl_t s;

	assert(vc_forward_buffer_enabled);

	s = splhigh();
	simple_lock(&vc_forward_lock);

	if (vc_forward_buffer_busy) {
		/* Bail out if we're already in the middle of a flush. */
		simple_unlock(&vc_forward_lock);
		splx(s);
		return;
	}

	vc_forward_buffer_busy = 1;

	while (todo < vc_forward_buffer_size) {
		todo = vc_forward_buffer_size;

		/* Drop the lock while we update the screen. */
		simple_unlock(&vc_forward_lock);
		splx(s);

		reversecursor();

		do {
			int i;
#ifdef FAST_JUMP_SCROLL
			if ((todo - start) < 2) {
				vc_putchar(vc_forward_buffer[start++]);
			} else {
				assert(vc_forward_scroll == 0);

				vc_forward_preflight_save.vt100state         = vt100state;
				vc_forward_preflight_save.vc_wrap_mode       = vc_wrap_mode;
				vc_forward_preflight_save.vc_relative_origin = vc_relative_origin;
				vc_forward_preflight_save.vc_charset_select  = vc_charset_select;
				vc_forward_preflight_save.vc_save_charset_s  = vc_save_charset_s;
				vc_forward_preflight_save.vc_charset[0]      = vc_charset[0];
				vc_forward_preflight_save.vc_charset[1]      = vc_charset[1];
				vc_forward_preflight_save.vc_charset_save[0] = vc_charset_save[0];
				vc_forward_preflight_save.vc_charset_save[1] = vc_charset_save[1];
				vc_forward_preflight_save.x                  = x;
				vc_forward_preflight_save.y                  = y;
				vc_forward_preflight_save.savex              = savex;
				vc_forward_preflight_save.savey              = savey;
				vc_forward_preflight_save.numpars            = numpars;
				vc_forward_preflight_save.hanging_cursor     = hanging_cursor;
				vc_forward_preflight_save.attr               = attr;
				vc_forward_preflight_save.saveattr           = saveattr;
				vc_forward_preflight_save.scrreg_top         = scrreg_top;
				vc_forward_preflight_save.scrreg_bottom      = scrreg_bottom;
				vc_forward_preflight_save.vc_color_fore      = vc_color_fore;
				vc_forward_preflight_save.vc_color_back      = vc_color_back;
				bcopy( (const char *) par,
				       (char *)       vc_forward_preflight_save.par,
				       (vm_size_t)    sizeof(par) );
				bcopy( (const char *) tab_stops,
				       (char *)       vc_forward_preflight_save.tab_stops,
				       (vm_size_t)    sizeof(tab_stops) );

				vc_forward_preflight_mode = PFwind;

				for (i = start;
				     i < todo &&
				     vc_forward_preflight_save.scrreg_top == scrreg_top &&
				     vc_forward_preflight_save.scrreg_bottom == scrreg_bottom;
				     i++)
					vc_putchar(vc_forward_buffer[i]);

				vt100state         = vc_forward_preflight_save.vt100state;
				vc_wrap_mode       = vc_forward_preflight_save.vc_wrap_mode;
				vc_relative_origin = vc_forward_preflight_save.vc_relative_origin;
				vc_charset_select  = vc_forward_preflight_save.vc_charset_select;
				vc_save_charset_s  = vc_forward_preflight_save.vc_save_charset_s;
				vc_charset[0]      = vc_forward_preflight_save.vc_charset[0];
				vc_charset[1]      = vc_forward_preflight_save.vc_charset[1];
				vc_charset_save[0] = vc_forward_preflight_save.vc_charset_save[0];
				vc_charset_save[1] = vc_forward_preflight_save.vc_charset_save[1];
				x                  = vc_forward_preflight_save.x;
				y                  = vc_forward_preflight_save.y;
				savex              = vc_forward_preflight_save.savex;
				savey              = vc_forward_preflight_save.savey;
				numpars            = vc_forward_preflight_save.numpars;
				hanging_cursor     = vc_forward_preflight_save.hanging_cursor;
				attr               = vc_forward_preflight_save.attr;
				saveattr           = vc_forward_preflight_save.saveattr;
				scrreg_top         = vc_forward_preflight_save.scrreg_top;
				scrreg_bottom      = vc_forward_preflight_save.scrreg_bottom;
				vc_color_fore      = vc_forward_preflight_save.vc_color_fore;
				vc_color_back      = vc_forward_preflight_save.vc_color_back;
				bcopy( (const char *) vc_forward_preflight_save.par,
				       (char *)       par,
				       (vm_size_t)    sizeof(par) );
				bcopy( (const char *) vc_forward_preflight_save.tab_stops,
				       (char *)       tab_stops,
				       (vm_size_t)    sizeof(tab_stops) );

				vc_forward_preflight_mode = PFscroll;

				if (vc_forward_scroll > 0)
					scrollup(vc_forward_scroll > scrreg_bottom - scrreg_top ?
					         scrreg_bottom - scrreg_top : vc_forward_scroll);
				else if (vc_forward_scroll < 0)
					scrolldown(-vc_forward_scroll > scrreg_bottom - scrreg_top ?
					           scrreg_bottom - scrreg_top : -vc_forward_scroll);

				vc_forward_preflight_mode = PFunwind;

				for (; start < i; start++)
					vc_putchar(vc_forward_buffer[start]);

				assert(vc_forward_scroll == 0);

				vc_forward_preflight_mode = PFoff;
			}
#else !FAST_JUMP_SCROLL
			int plaintext = 1;
			int drawlen = start;
			int jump = 0;
			int param = 0, changebackground = 0;
			enum vt100state_e vtState = vt100state;
			/* 
			 * In simple words, here we're pre-parsing the text to look for
			 *  + Newlines, for computing jump scroll
			 *  + /\033\[[0-9;]*]m/ to continue on
			 * any other sequence will stop. We don't want to have cursor
			 * movement escape sequences while we're trying to pre-scroll
			 * the screen.
			 * We have to be extra carefull about the sequences that changes
			 * the background color to prevent scrolling in those 
			 * particular cases.
			 * That parsing was added to speed up 'man' and 'color-ls' a 
			 * zillion time (at least). It's worth it, trust me. 
			 * (mail Nick Stephen for a True Performance Graph)
			 * Michel Pollet
			 */
			for (i = start; i < todo && plaintext; i++) {
				drawlen++;
				switch (vtState) {
					case ESnormal:
						switch (vc_forward_buffer[i]) {
							case '\033':
								vtState = ESesc;
								break;
							case '\n':
								jump++;
								break;
						}
						break;
					case ESesc:
						switch (vc_forward_buffer[i]) {
							case '[':
								vtState = ESgetpars;
								param = 0;
								changebackground = 0;
								break;
							default:
								plaintext = 0;
								break;
						}
						break;
					case ESgetpars:
						if ((vc_forward_buffer[i] >= '0' &&
						    vc_forward_buffer[i] <= '9') ||
						    vc_forward_buffer[i] == ';') {
							if (vc_forward_buffer[i] >= '0' &&
						    	    vc_forward_buffer[i] <= '9')
								param = (param*10)+(vc_forward_buffer[i]-'0');
							else {
								if (param >= 40 && param <= 47)
									changebackground = 1;
								if (!vc_normal_background &&
								    !param)
									changebackground = 1;
								param = 0;
							}
							break; /* continue on */
						}
						vtState = ESgotpars;
						/* fall */
					case ESgotpars:
						switch (vc_forward_buffer[i]) {
							case 'm':
								vtState = ESnormal;
								if (param >= 40 && param <= 47)
									changebackground = 1;
								if (!vc_normal_background &&
								    !param)
									changebackground = 1;
								if (changebackground) {
									plaintext = 0;
									jump = 0;
									/* REALLY don't jump */
								}
								/* Yup ! we've got it */
								break;
							default:
								plaintext = 0;
								break;
						}
						break;
					default:
						plaintext = 0;
						break;
				}
				
			}

			/*
			 * Then we look if it would be appropriate to forward jump
			 * the screen before drawing
			 */
			if (jump && (scrreg_bottom - scrreg_top) > 2) {
				jump -= scrreg_bottom - y - 1;
				if (jump > 0 ) {
					if (jump >= scrreg_bottom - scrreg_top)
						jump = scrreg_bottom - scrreg_top -1;
					y -= jump;
					scrollup(jump);
				}
			}
			/*
			 * and we draw what we've found to the parser
			 */
			for (i = start; i < drawlen; i++)
				vc_putchar(vc_forward_buffer[start++]);
			/*
			 * Continue sending characters to the parser until we're sure we're
			 * back on normal characters.
			 */
			for (i = start; i < todo &&
					vt100state != ESnormal ; i++)
				vc_putchar(vc_forward_buffer[start++]);
#endif !FAST_JUMP_SCROLL
			/* Then loop again if there still things to draw */
		} while (start < todo);

		reversecursor();

		/* Re-acquire the lock while we check our state. */
		s = splhigh();
		simple_lock(&vc_forward_lock);
	}

	vc_forward_buffer_busy = 0;
	vc_forward_buffer_size = 0;

	simple_unlock(&vc_forward_lock);
	splx(s);
}

int
vcputc(int l, int u, int c)
{
        if(!vinfo.v_baseaddr)
            return;

	/*
	 * Either we're really buffering stuff or we're not yet because
	 * the probe hasn't been done.
	 */
	if (vc_forward_buffer_enabled)
		vc_store_char(c);
	else
		vc_putchar(c);

	return 0;
}

/*
 * Store characters to be drawn 'later', handle overflows
 */

static void
vc_store_char(unsigned char c)
{
	int	flush = 0;
	spl_t	s;

	assert(vc_forward_buffer_enabled);

	s = splhigh();
	simple_lock(&vc_forward_lock);

	/* Spin until the buffer has space for another character. */
	while (vc_forward_buffer_size == VC_MAX_FORWARD_SIZE) {
		simple_unlock(&vc_forward_lock);
		splx(s);
		/* wait */
		s = splhigh();
		simple_lock(&vc_forward_lock);
	}

	assert(vc_forward_buffer_size < VC_MAX_FORWARD_SIZE);

	vc_forward_buffer[vc_forward_buffer_size++] = (unsigned char)c;

	if (vc_forward_buffer_size == 1) {
		/* If we're adding the first character to the buffer,
		 * start the timer, otherwise it is already running.
		 */
		if (debug_mode) {
			flush = 1;
		} else {
			timeout((timeout_fcn_t)vc_flush_forward_buffer,
				(void *)0,
				VC_CONSOLE_UPDATE_TIMEOUT);
		}
	} else if (vc_forward_buffer_size == VC_MAX_FORWARD_SIZE || debug_mode) {
		/*
		 * If there is an overflow or this is an immediate character display
		 * (eg. pre-clock printfs, panics), then we force a draw (take into
		 * account that a flush might already be in progress).
		 */
		if (!vc_forward_buffer_busy) {
			flush = 1;
			untimeout((timeout_fcn_t)vc_flush_forward_buffer, (void *)0);
		}
	}

	simple_unlock(&vc_forward_lock);
	splx(s);

	if (flush) {
		/* 
		 * Immediate character display.. kernel printf uses this. Make sure
		 * get flushed and that panics get fully displayed.
		 */
		vc_flush_forward_buffer();
	}
}

static void
vc_initialize(void)
{
#if 0
	GratefulDebInit();				/* (TEST/DEBUG) */
#endif

#if DEBUG && SERIAL_CONSOLE_DEFAULT && !defined(MACH_PE)
	printf("    Video info: %d; video_board=%08X\n", i, vboard);
	printf("    Video name: %s\n", vinfo.v_name);
	printf("    height=%d; width=%d, depth=%d; rowbytes=%d; type=%08X\n",
		vinfo.v_height, vinfo.v_width, vinfo.v_depth, vinfo.v_rowbytes, vinfo.v_type);
	printf("    physical address=%08X\n", vinfo.v_physaddr);
#endif

	vinfo.v_rows = vinfo.v_height / CHARHEIGHT;
	vinfo.v_columns = vinfo.v_width / CHARWIDTH;

	if (vinfo.v_depth >= 8) {
		vinfo.v_rowscanbytes = (vinfo.v_depth / 8) * vinfo.v_width;
	} else {
		vinfo.v_rowscanbytes = vinfo.v_width / (8 / vinfo.v_depth);
	}

#if DEBUG && SERIAL_CONSOLE_DEFAULT  && !defined(MACH_PE)
	printf("    inited=%d\n", vc_initted);
#endif


	vc_render_font(1, vinfo.v_depth);
	vc_color_mask = vc_color_depth_masks[vc_color_index_table[vinfo.v_depth]];
	vt100_reset();
	switch (vinfo.v_depth) {
	default:
	case 1:
		vc_paintchar = vc_paint_char1;
		break;
	case 2:
		vc_paintchar = vc_paint_char2;
		break;
	case 4:
		vc_paintchar = vc_paint_char4;
		break;
	case 8:
		vc_paintchar = vc_paint_char8c;
		break;
	case 16:
		vc_paintchar = vc_paint_char16c;
		break;
	case 32:
		vc_paintchar = vc_paint_char32c;
		break;
	}

#ifdef FAST_JUMP_SCROLL
	vc_forward_paintchar = vc_paintchar;
	vc_paintchar = vc_paint_char;
#endif FAST_JUMP_SCROLL
}

void 
vcattach(void)
{
	if (vinfo.v_depth >= 8)
		printf("\033[31mC\033[32mO\033[33mL\033[34mO\033[35mR\033[0m ");
	printf("video console at 0x%x (%dx%dx%d)\n", vinfo.v_baseaddr,
		vinfo.v_width, vinfo.v_height,  vinfo.v_depth);

	/*
	 * Added for the buffering and jump scrolling 
	 */
	/* Init our lock */
	simple_lock_init(&vc_forward_lock, ETAP_IO_TTY);

	vc_forward_buffer_enabled = 1;

}


struct vc_progress_element {
    unsigned int	version;
    unsigned int	flags;
    unsigned int	time;
    unsigned char	count;
    unsigned char	res[3];
    int			width;
    int			height;
    int			dx;
    int			dy;
    int			transparent;
    unsigned int	res2[3];
    unsigned char	data[0];
};
typedef struct vc_progress_element vc_progress_element;

static vc_progress_element *	vc_progress;
static const unsigned char *    vc_progress_data;
static const unsigned char *    vc_progress_alpha;
static boolean_t		vc_progress_enable;
static const unsigned char *    vc_clut;
static const unsigned char *    vc_clut8;
static unsigned char            vc_revclut8[256];
static unsigned int		vc_progress_tick;
static boolean_t		vc_graphics_mode;
static boolean_t		vc_acquired;
static boolean_t		vc_need_clear;
static boolean_t		vc_needsave;
static vm_address_t		vc_saveunder;
static vm_size_t		vc_saveunder_len;

static void vc_blit_rect_8c(	int x, int y,
                                int width, int height, 
                                const unsigned char * dataPtr,
				const unsigned char * alphaPtr,
                                unsigned char * backPtr,
				boolean_t save, boolean_t static_alpha )
{
    volatile unsigned char * dst;
    int line, col;
    unsigned int data;
    unsigned char alpha;

    dst = (unsigned char *)(vinfo.v_baseaddr +
                            (y * vinfo.v_rowbytes) +
                            (x));

    for( line = 0; line < height; line++) {
        for( col = 0; col < width; col++) {
	    data = 0;
	    if( dataPtr != 0) data = *dataPtr++;
	    else if( alphaPtr != 0) data = vc_revclut8[*alphaPtr++];
            *(dst + col) = data;
	}
        dst = (volatile unsigned char *) (((int)dst) + vinfo.v_rowbytes);
    }

}

static void vc_blit_rect_16(	int x, int y,
                                int width, int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                unsigned short *  backPtr,
                                boolean_t save, boolean_t static_alpha )
{
    volatile unsigned short * dst;
    int line, col;
    unsigned int data, index, alpha, back;

    dst = (volatile unsigned short *)(vinfo.v_baseaddr +
                                    (y * vinfo.v_rowbytes) +
                                    (x * 2));

    for( line = 0; line < height; line++) {
        for( col = 0; col < width; col++) {
	    if( dataPtr != 0) {
	        index = *dataPtr++;
                index *= 3;
	    }

            if( alphaPtr && backPtr) {

		alpha = *alphaPtr++;
                data = 0;
		if( dataPtr != 0) {
                    if( vc_clut[index + 0] > alpha)
                        data |= (((vc_clut[index + 0] - alpha) & 0xf8) << 7);
                    if( vc_clut[index + 1] > alpha)
                        data |= (((vc_clut[index + 1] - alpha) & 0xf8) << 2);
                    if( vc_clut[index + 2] > alpha)
                        data |= (((vc_clut[index + 2] - alpha) & 0xf8) >> 3);
		}

                if( save) {
                    back = *(dst + col);
                    if ( !static_alpha)
                        *backPtr++ = back;
                        back = (((((back & 0x7c00) * alpha) + 0x3fc00) >> 8) & 0x7c00)
                             | (((((back & 0x03e0) * alpha) + 0x01fe0) >> 8) & 0x03e0)
                             | (((((back & 0x001f) * alpha) + 0x000ff) >> 8) & 0x001f);
                    if ( static_alpha)
                        *backPtr++ = back;
                } else {
                    back = *backPtr++;
                    if ( !static_alpha) {
                        back = (((((back & 0x7c00) * alpha) + 0x3fc00) >> 8) & 0x7c00)
                             | (((((back & 0x03e0) * alpha) + 0x01fe0) >> 8) & 0x03e0)
                             | (((((back & 0x001f) * alpha) + 0x000ff) >> 8) & 0x001f);
                    }
                }

                data += back;

            } else
                if( dataPtr != 0) {
            	    data = ( (0xf8 & (vc_clut[index + 0])) << 7)
                           | ( (0xf8 & (vc_clut[index + 1])) << 2)
                           | ( (0xf8 & (vc_clut[index + 2])) >> 3);
		}

            *(dst + col) = data;
	}
        dst = (volatile unsigned short *) (((int)dst) + vinfo.v_rowbytes);
    }
}

static void vc_blit_rect_32(	unsigned int x, unsigned int y,
                                unsigned int width, unsigned int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                unsigned int *  backPtr,
                                boolean_t save, boolean_t static_alpha )
{
    volatile unsigned int * dst;
    int line, col;
    unsigned int data, index, alpha, back;

    dst = (volatile unsigned int *) (vinfo.v_baseaddr +
                                    (y * vinfo.v_rowbytes) +
                                    (x * 4));

    for( line = 0; line < height; line++) {
        for( col = 0; col < width; col++) {
            if( dataPtr != 0) {
	        index = *dataPtr++;
                index *= 3;
	    }

            if( alphaPtr && backPtr) {

		alpha = *alphaPtr++;
                data = 0;
                if( dataPtr != 0) {
                    if( vc_clut[index + 0] > alpha)
                        data |= ((vc_clut[index + 0] - alpha) << 16);
                    if( vc_clut[index + 1] > alpha)
                        data |= ((vc_clut[index + 1] - alpha) << 8);
                    if( vc_clut[index + 2] > alpha)
                        data |= ((vc_clut[index + 2] - alpha));
		}

                if( save) {
                    back = *(dst + col);
                    if ( !static_alpha)
                        *backPtr++ = back;
                    back = (((((back & 0x00ff00ff) * alpha) + 0x00ff00ff) >> 8) & 0x00ff00ff)
                         | (((((back & 0x0000ff00) * alpha) + 0x0000ff00) >> 8) & 0x0000ff00);
                    if ( static_alpha)
                        *backPtr++ = back;
                } else {
                    back = *backPtr++;
                    if ( !static_alpha) {
                        back = (((((back & 0x00ff00ff) * alpha) + 0x00ff00ff) >> 8) & 0x00ff00ff)
                             | (((((back & 0x0000ff00) * alpha) + 0x0000ff00) >> 8) & 0x0000ff00);
                    }
		}

                data += back;

            } else
                if( dataPtr != 0) {
                    data =    (vc_clut[index + 0] << 16)
                            | (vc_clut[index + 1] << 8)
                            | (vc_clut[index + 2]);
		}

            *(dst + col) = data;
	}
        dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
    }
}

void 
draw_panic_dialog( void )
{
	int pd_x,pd_y, iconx, icony, tx_line, tx_col;
	int line_width = 1;
	int f1, f2, d1, d2, d3, rem;
	char *pair = "ff";
	int count = 0;
	char digit;
	int nibble;
	char colon = ':';
	char dot = '.';
	struct ether_addr kdp_mac_addr  = kdp_get_mac_addr();
	unsigned int ip_addr = kdp_get_ip_address();	
	
	
	if (!panicDialogDrawn)
	{
		if ( !logPanicDataToScreen )
		{

			/* dim the screen 50% before putting up panic dialog */
			dim_screen();

			/* set up to draw background box */
			pd_x = (vinfo.v_width/2) - panic_dialog.pd_width/2;
			pd_y = (vinfo.v_height/2) - panic_dialog.pd_height/2;
		
			/*  draw image	*/
			panic_blit_rect( pd_x, pd_y, panic_dialog.pd_width, panic_dialog.pd_height, 0, (unsigned char*) panic_dialog.image_pixel_data);
		
			/* offset for mac address text */
			mac_addr_digit_x = (vinfo.v_width/2) - 130; /* use 62 if no ip */
			mac_addr_digit_y = (vinfo.v_height/2) + panic_dialog.pd_height/2 - 20;
		
			if(kdp_mac_addr.ether_addr_octet[0] || kdp_mac_addr.ether_addr_octet[1]|| kdp_mac_addr.ether_addr_octet[2]
				|| kdp_mac_addr.ether_addr_octet[3] || kdp_mac_addr.ether_addr_octet[4] || kdp_mac_addr.ether_addr_octet[5])
			{
				/* blit the digits for mac address */
				for (count = 0; count < 6; count++ )
				{
					nibble =  (kdp_mac_addr.ether_addr_octet[count] & 0xf0) >> 4;
					digit = nibble < 10 ? nibble + '0':nibble - 10 + 'a';
					blit_digit(digit);
				
					nibble =  kdp_mac_addr.ether_addr_octet[count] & 0xf;
					digit = nibble < 10 ? nibble + '0':nibble - 10 + 'a';
					blit_digit(digit);
					if( count < 5 )
						blit_digit( colon );
				}
			}
			else	/* blit the ff's */
			{
				for( count = 0; count < 6; count++ )
				{
					digit = pair[0];
					blit_digit(digit);
					digit = pair[1];
					blit_digit(digit);
					if( count < 5 )
						blit_digit( colon );
				}
			}
			/* now print the ip address */
			mac_addr_digit_x = (vinfo.v_width/2) + 10;
			if(ip_addr != 0)
			{
				/* blit the digits for ip address */
				for (count = 0; count < 4; count++ )
				{
					nibble = (ip_addr & 0xff000000 ) >> 24;
				
					d3 = (nibble % 0xa) + '0';
					nibble = nibble/0xa;
					d2 = (nibble % 0xa) + '0';
					nibble = nibble /0xa;
					d1 = (nibble % 0xa) + '0';
					
					if( d1 ) blit_digit(d1);
					blit_digit(d2);
					blit_digit(d3);
					if( count < 3 )
						blit_digit(dot);
					
					d1= d2 = d3 = 0;
					ip_addr = ip_addr << 8;
				}
			}
		}
	}
	panicDialogDrawn = TRUE;

}


static void 
blit_digit( int digit )
{
	switch( digit )
	{
		case '0':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_0.num_w, num_0.num_h, 255, (unsigned char*) num_0.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_0.num_w - 1;
			break;
		}
		case '1':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_1.num_w, num_1.num_h, 255, (unsigned char*) num_1.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_1.num_w ;
			break;
		}
		case '2':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_2.num_w, num_2.num_h, 255, (unsigned char*) num_2.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_2.num_w ;
			break;
		}
		case '3':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_3.num_w, num_3.num_h, 255, (unsigned char*) num_3.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_3.num_w ;
			break;
		}
		case '4':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_4.num_w, num_4.num_h, 255, (unsigned char*) num_4.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_4.num_w ;
			break;
		}
		case '5':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_5.num_w, num_5.num_h, 255, (unsigned char*) num_5.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_5.num_w ;
			break;
		}
		case '6':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_6.num_w, num_6.num_h, 255, (unsigned char*) num_6.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_6.num_w ;
			break;
		}
		case '7':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_7.num_w, num_7.num_h, 255, (unsigned char*) num_7.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_7.num_w ;
			break;
		}
		case '8':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_8.num_w, num_8.num_h, 255, (unsigned char*) num_8.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_8.num_w ;
			break;
		}
		case '9':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_9.num_w, num_9.num_h, 255, (unsigned char*) num_9.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_9.num_w ;
			break;
		}
		case 'a':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_a.num_w, num_a.num_h, 255, (unsigned char*) num_a.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_a.num_w ;
			break;
		}
		case 'b':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_b.num_w, num_b.num_h, 255, (unsigned char*) num_b.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_b.num_w ;
			break;
		}
		case 'c':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_c.num_w, num_c.num_h, 255, (unsigned char*) num_c.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_c.num_w ;
			break;
		}
		case 'd':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_d.num_w, num_d.num_h, 255, (unsigned char*) num_d.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_d.num_w ;
			break;
		}
		case 'e':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_e.num_w, num_e.num_h, 255, (unsigned char*) num_e.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_e.num_w ;
			break;
		}
		case 'f':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_f.num_w, num_f.num_h, 255, (unsigned char*) num_f.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_f.num_w ;
			break;
		}
		case ':':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_colon.num_w, num_colon.num_h, 255, (unsigned char*) num_colon.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_colon.num_w;
			break;
		}
		case '.':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y + (num_colon.num_h/2), num_colon.num_w, num_colon.num_h/2, 255, (unsigned char*) num_colon.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_colon.num_w;
			break;
		}
		default:
			break;
	
	}
}

static void 
panic_blit_rect(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr )
{
	if(!vinfo.v_depth)
		return;
		
    switch( vinfo.v_depth) {
	case 8:
	    panic_blit_rect_8( x, y, width, height, transparent, dataPtr);
	    break;
	case 16:
	    panic_blit_rect_16( x, y, width, height, transparent, dataPtr);
	    break;
	case 32:
	    panic_blit_rect_32( x, y, width, height, transparent, dataPtr);
	    break;
    }
}

/* panic_blit_rect_8 is not tested and probably doesn't draw correctly. 
	it really needs a clut to use
*/
static void 
panic_blit_rect_8(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr )
{
    volatile unsigned int * dst;
    int line, col;
    unsigned int pixelR, pixelG, pixelB;

    dst = (volatile unsigned int *) (vinfo.v_baseaddr +
                                    (y * vinfo.v_rowbytes) +
                                    x);

    for( line = 0; line < height; line++) {
        for( col = 0; col < width; col++) {
			pixelR = *dataPtr++;
			pixelG = *dataPtr++;
			pixelB = *dataPtr++;
			if(( pixelR != transparent) || (pixelG != transparent) || (pixelB != transparent))
			{
				*(dst + col) = ((19595 * pixelR +
								 38470 * pixelG +
								 7471  * pixelB ) / 65536);
			}
	
		}
        dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
    }
}

/* panic_blit_rect_16 draws adequately. It would be better if it had a clut
	to use instead of scaling the 32bpp color values.
	
	panic_blit_rect_16 decodes the RLE encoded image data on the fly, scales it down
	to 16bpp,  and fills in each of the three pixel values (RGB) for each pixel
	and writes it to the screen.
	
*/
static void 
panic_blit_rect_16(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr )
{
    volatile unsigned int * dst;
    int line, value, total = 0;
    unsigned int  quantity, tmp, pixel;
    int pix_pos = 2;
    int w = width / 2;
    boolean_t secondTime = 0;
    int pix_incr = 0;
    

    dst = (volatile unsigned int *) (vinfo.v_baseaddr +
                                    (y * vinfo.v_rowbytes) +
                                    (x * 2));

/*
            *(dst + col) =	( (0xf8 & (vc_clut[data + 0])) << 7)
                              | ( (0xf8 & (vc_clut[data + 1])) << 2)
                              | ( (0xf8 & (vc_clut[data + 2])) >> 3);

*/
    for( line = 0; line < height; line++) 
    {
    	while ( total < width )
    	{
    		quantity = *dataPtr++;
        	value = *dataPtr++;
        	value = (0x1f * value)/255;
			while( quantity > 0 )
			{
				switch( pix_pos )
				{
					case 2:		/* red */
					{
						tmp |= (value << 10) & 0x7c00;
		//				tmp |= (value & 0xf8) << 7;
						quantity--;
						pix_pos--;
						break;
					}
					case 1:		/* green */
					{
						tmp |= (value << 5) & 0x3e0;
		//				tmp |= (value & 0xf8) << 2;
						quantity--;
						pix_pos--;
						break;
					}
					default:	/* blue */
					{
						tmp |= value & 0x1f;
		//				tmp |= (value & 0xf8) >> 3;
						total++;
						quantity--;
						pix_pos = 2;
						if( secondTime )
						{
							pixel |= tmp;
							secondTime = 0;
							*(dst + pix_incr++) = pixel;
							tmp = 0;
							pixel = 0;
						}
						else
						{
							pixel = tmp << 16;
							secondTime = 1;
						}
						break;
					}
				}
			}
		}
        dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
        total = 0;
        pix_incr = 0;
    }
}

/*
	panic_blit_rect_32 decodes the RLE encoded image data on the fly, and fills
	in each of the three pixel values (RGB) for each pixel and writes it to the 
	screen.
*/	
static void 
panic_blit_rect_32(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr )
{
    volatile unsigned int * dst;
    int line, total = 0;
    unsigned int value, quantity, tmp;
    int pix_pos = 2;

    dst = (volatile unsigned int *) (vinfo.v_baseaddr +
                                    (y * vinfo.v_rowbytes) +
                                    (x * 4));

    for( line = 0; line < height; line++) 
    {
    	while ( total < width )
    	{
    		quantity = *dataPtr++;
        	value = *dataPtr++;
			while( quantity > 0 )
			{
				switch( pix_pos )
				{
					case 2:
					{
						tmp = value << 16;
						quantity--;
						pix_pos--;
						break;
					}
					case 1:
					{
						tmp |= value << 8;
						quantity--;
						pix_pos--;
						break;
					}
					default:
					{
						tmp |= value;
						*(dst + total) = tmp;
						total++;
						quantity--;
						pix_pos = 2;
						break;
					}
				
				}
			}
	
		}
        dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
        total = 0;
    }
}

static void 
dim_screen(void)
{
	if(!vinfo.v_depth)
		return;
		
    switch( vinfo.v_depth) {
	/*case 8:
	    dim_screen8();
	    break;
        */
	case 16:
	    dim_screen16();
	    break;
	case 32:
	    dim_screen32();
	    break;
    }
}

static void 
dim_screen16(void)
{
	unsigned long *p, *endp, *row;
	int      linelongs, col;
	int      rowline, rowlongs;
        unsigned long value, tmp;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;;
	endp = (unsigned long*) vinfo.v_baseaddr;

	linelongs = vinfo.v_rowbytes * CHARHEIGHT / 4;
        endp += rowlongs * vinfo.v_height;

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) {
                        value = *(row+col);
                        tmp =  ((value & 0x7C007C00) >> 1) & 0x3C003C00;
                        tmp |= ((value & 0x03E003E0) >> 1) & 0x01E001E0;
                        tmp |= ((value & 0x001F001F) >> 1) & 0x000F000F;
                        *(row+col) = tmp;		//half (dimmed)?
                }

	}

}

static void 
dim_screen32(void)
{
	unsigned long *p, *endp, *row;
	int      linelongs, col;
	int      rowline, rowlongs;
        unsigned long value, tmp;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;;
	endp = (unsigned long*) vinfo.v_baseaddr;

	linelongs = vinfo.v_rowbytes * CHARHEIGHT / 4;
        endp += rowlongs * vinfo.v_height;

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) {
                        value = *(row+col);
                        tmp =  ((value & 0x00FF0000) >> 1) & 0x007F0000;
                        tmp |= ((value & 0x0000FF00) >> 1) & 0x00007F00;
                        tmp |= (value & 0x000000FF) >> 1;
                        *(row+col) = tmp;		//half (dimmed)?
                }

	}

}

static void vc_blit_rect(	unsigned int x, unsigned int y,
                                unsigned int width, unsigned int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                vm_address_t backBuffer,
                                boolean_t save, boolean_t static_alpha )
{
    if(!vinfo.v_baseaddr)
        return;

    switch( vinfo.v_depth) {
	case 8:
            if( vc_clut8 == vc_clut)
                vc_blit_rect_8c( x, y, width, height, dataPtr, alphaPtr, (unsigned char *) backBuffer, save, static_alpha );
	    break;
	case 16:
	    vc_blit_rect_16( x, y, width, height, dataPtr, alphaPtr, (unsigned short *) backBuffer, save, static_alpha );
	    break;
	case 32:
	    vc_blit_rect_32( x, y, width, height, dataPtr, alphaPtr, (unsigned int *) backBuffer, save, static_alpha );
	    break;
    }
}

static void vc_progress_task( void * arg )
{
    spl_t		s;
    int			count = (int) arg;
    int			x, y, width, height;
    const unsigned char * data;

    s = splhigh();
    simple_lock(&vc_forward_lock);

    if( vc_progress_enable) {

        count++;
        if( count >= vc_progress->count)
            count = 0;

	width = vc_progress->width;
	height = vc_progress->height;
	x = vc_progress->dx;
	y = vc_progress->dy;
	data = vc_progress_data;
	data += count * width * height;
	if( 1 & vc_progress->flags) {
	    x += ((vinfo.v_width - width) / 2);
	    y += ((vinfo.v_height - height) / 2);
	}
	vc_blit_rect( x, y, width, height,
			NULL, data, vc_saveunder,
			vc_needsave, (0 == (4 & vc_progress->flags)) );
        vc_needsave = FALSE;

        timeout( vc_progress_task, (void *) count,
                 vc_progress_tick );
    }
    simple_unlock(&vc_forward_lock);
    splx(s);
}

void vc_display_icon( vc_progress_element * desc,
			const unsigned char * data )
{
    int			x, y, width, height;

    if( vc_acquired && vc_graphics_mode && vc_clut) {

	width = desc->width;
	height = desc->height;
	x = desc->dx;
	y = desc->dy;
	if( 1 & desc->flags) {
	    x += ((vinfo.v_width - width) / 2);
	    y += ((vinfo.v_height - height) / 2);
	}
	vc_blit_rect( x, y, width, height, data, NULL, (vm_address_t) NULL, FALSE, TRUE );
    }
}

static boolean_t ignore_first_enable = TRUE;

static boolean_t
vc_progress_set( boolean_t enable, unsigned int initial_tick )
{
    spl_t	     s;
    vm_address_t     saveBuf = 0;
    vm_size_t        saveLen = 0;
    unsigned int     count;
    unsigned int     index;
    unsigned char    data8;
    unsigned short   data16;
    unsigned short * buf16;
    unsigned int     data32;
    unsigned int *   buf32;

    if( !vc_progress)
	return( FALSE );

    if( enable & ignore_first_enable) {
	enable = FALSE;
	ignore_first_enable = FALSE;
    }

    if( enable) {
        saveLen = vc_progress->width * vc_progress->height * vinfo.v_depth / 8;
        saveBuf = kalloc( saveLen );

	if( !vc_need_clear) switch( vinfo.v_depth) {
	    case 8 :
		for( count = 0; count < 256; count++) {
		    vc_revclut8[count] = vc_clut[0x01 * 3];
		    data8 = (vc_clut[0x01 * 3] * count + 0x0ff) >> 8;
		    for( index = 0; index < 256; index++) {
			if( (data8 == vc_clut[index * 3 + 0]) &&
			    (data8 == vc_clut[index * 3 + 1]) &&
			    (data8 == vc_clut[index * 3 + 2])) {
			    vc_revclut8[count] = index;
			    break;
			}
		    }
		}
		memset( (void *) saveBuf, 0x01, saveLen );
		break;

	    case 16 :
		buf16 = (unsigned short *) saveBuf;
		data16 = ((vc_clut[0x01 * 3 + 0] & 0xf8) << 7)
		       | ((vc_clut[0x01 * 3 + 0] & 0xf8) << 2)
		       | ((vc_clut[0x01 * 3 + 0] & 0xf8) >> 3);
		for( count = 0; count < saveLen / 2; count++)
		    buf16[count] = data16;
		break;

	    case 32 :
		buf32 = (unsigned int *) saveBuf;
		data32 = ((vc_clut[0x01 * 3 + 0] & 0xff) << 16)
		       | ((vc_clut[0x01 * 3 + 1] & 0xff) << 8)
		       | ((vc_clut[0x01 * 3 + 2] & 0xff) << 0);
		for( count = 0; count < saveLen / 4; count++)
		    buf32[count] = data32;
		break;
	}
    }

    s = splhigh();
    simple_lock(&vc_forward_lock);

    if( vc_progress_enable != enable) {
        vc_progress_enable = enable;
        if( enable) {
            vc_needsave      = vc_need_clear;
            vc_saveunder     = saveBuf;
            vc_saveunder_len = saveLen;
            saveBuf	     = 0;
            saveLen 	     = 0;
            timeout(vc_progress_task, (void *) 0,
                    initial_tick );
        } else {
            if( vc_saveunder) {
                saveBuf      = vc_saveunder;
                saveLen      = vc_saveunder_len;
                vc_saveunder = 0;
                vc_saveunder_len = 0;
            }
            untimeout( vc_progress_task, (void *) 0 );
        }
    }

    if( !enable) {
        vc_forward_buffer_size = 0;
        untimeout((timeout_fcn_t)vc_flush_forward_buffer, (void *)0);

        /* Spin if the flush is in progress */
        while (vc_forward_buffer_busy) {
            simple_unlock(&vc_forward_lock);
            splx(s);
            /* wait */
            s = splhigh();
            simple_lock(&vc_forward_lock);
            vc_forward_buffer_size = 0;
        }
    }

    simple_unlock(&vc_forward_lock);
    splx(s);

    if( saveBuf)
        kfree( saveBuf, saveLen );

    return( TRUE );
}


boolean_t
vc_progress_initialize( vc_progress_element * desc,
			const unsigned char * data,
			const unsigned char * clut )
{
    if( (!clut) || (!desc) || (!data))
	return( FALSE );
    vc_clut = clut;
    vc_clut8 = clut;

    vc_progress = desc;
    vc_progress_data = data;
    if( 2 & vc_progress->flags)
        vc_progress_alpha = vc_progress_data
                            + vc_progress->count * vc_progress->width * vc_progress->height;
    else
        vc_progress_alpha = NULL;
    vc_progress_tick = vc_progress->time * hz / 1000;

    return( TRUE );
}

// FirmwareC.c needs:
Boot_Video boot_video_info;

extern int disableConsoleOutput;

static void vc_clear_screen( void )
{
    reversecursor();
    vt100_reset();
    x = y = 0;
    clear_screen(2);
    reversecursor();
};

void
initialize_screen(Boot_Video * boot_vinfo, unsigned int op)
{
	if( boot_vinfo) {
            bcopy( (const void *) boot_vinfo,
                    (void *) &boot_video_info,
                    sizeof( boot_video_info));

            vinfo.v_name[0] = 0;
            vinfo.v_width = boot_vinfo->v_width;
            vinfo.v_height = boot_vinfo->v_height;
            vinfo.v_depth = boot_vinfo->v_depth;
            vinfo.v_rowbytes = boot_vinfo->v_rowBytes;
            vinfo.v_physaddr = boot_vinfo->v_baseAddr;
            vinfo.v_baseaddr = vinfo.v_physaddr;
            vinfo.v_type = 0;

            vc_initialize();
#if 0
            GratefulDebInit((bootBumbleC *)boot_vinfo);	/* Re-initialize GratefulDeb */
#endif
	}

	switch( op ) {

	    case kPEGraphicsMode:
		vc_graphics_mode = TRUE;
		disableConsoleOutput = TRUE;
		vc_acquired = TRUE;
		break;

	    case kPETextMode:
		vc_graphics_mode = FALSE;
		disableConsoleOutput = FALSE;
		vc_acquired = TRUE;
		vc_clear_screen();
		break;

	    case kPETextScreen:
		vc_progress_set( FALSE, 0 );
		disableConsoleOutput = FALSE;
		if( vc_need_clear) {
		    vc_need_clear = FALSE;
                    vc_clear_screen();
		}
		break;

            case kPEEnableScreen:
		if( vc_acquired) {
                    if( vc_graphics_mode)
                        vc_progress_set( TRUE, vc_progress_tick );
                    else
                        vc_clear_screen();
		}
		break;

            case kPEDisableScreen:
		vc_progress_set( FALSE, 0 );
		break;

	    case kPEAcquireScreen:
		vc_need_clear = (FALSE == vc_acquired);
		vc_acquired = TRUE;
		vc_progress_set( vc_graphics_mode, vc_need_clear ? 2 * hz : 0 );
		disableConsoleOutput = vc_graphics_mode;
		if( vc_need_clear && !vc_graphics_mode) {
		    vc_need_clear = FALSE;
                    vc_clear_screen();
		}
		break;

	    case kPEReleaseScreen:
		vc_acquired = FALSE;
		vc_progress_set( FALSE, 0 );
                vc_clut8 = NULL;
		disableConsoleOutput = TRUE;
#if 0
		GratefulDebInit(0);						/* Stop grateful debugger */
#endif
		break;
	}
#if 0
	if( boot_vinfo) GratefulDebInit((bootBumbleC *)boot_vinfo);	/* Re initialize GratefulDeb */
#endif
}
