/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 * 
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
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

#include <console/video_console.h>
#include <console/serial_protos.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/thread_call.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <machine/io_map_entries.h>
#include <machine/machine_cpu.h>

#include <pexpert/pexpert.h>

#include "iso_font.c"

#include "sys/msgbuf.h"

/*
 * Generic Console (Front-End)
 * ---------------------------
 */

struct vc_info vinfo;
/* if panicDialogDesired is true then we use the panic dialog when its */
/* allowed otherwise we won't use the panic dialog even if it is allowed */
boolean_t panicDialogDesired;

 
extern int       disableConsoleOutput;
static boolean_t gc_enabled     = FALSE;
static boolean_t gc_initialized = FALSE;
static boolean_t vm_initialized = FALSE;

static struct {
	void (*initialize)(struct vc_info * info);
	void (*enable)(boolean_t enable);
	void (*paint_char)(unsigned int xx, unsigned int yy, unsigned char ch,
			   int attrs, unsigned char ch_previous,
			   int attrs_previous);
	void (*clear_screen)(unsigned int xx, unsigned int yy, unsigned int top,
			     unsigned int bottom, int which);
	void (*scroll_down)(int num, unsigned int top, unsigned int bottom);
	void (*scroll_up)(int num, unsigned int top, unsigned int bottom);
	void (*hide_cursor)(unsigned int xx, unsigned int yy);
	void (*show_cursor)(unsigned int xx, unsigned int yy);
	void (*update_color)(int color, boolean_t fore);
} gc_ops;

static unsigned char *gc_buffer_attributes;
static unsigned char *gc_buffer_characters;
static unsigned char *gc_buffer_colorcodes;
static unsigned long gc_buffer_columns;
static unsigned long gc_buffer_rows;
static unsigned long gc_buffer_size;

#ifdef __i386__
decl_simple_lock_data(static, vcputc_lock);

#define VCPUTC_LOCK_INIT()				\
MACRO_BEGIN						\
	simple_lock_init(&vcputc_lock, 0);		\
MACRO_END

#define VCPUTC_LOCK_LOCK()				\
MACRO_BEGIN						\
	boolean_t istate = ml_get_interrupts_enabled();	\
	while (!simple_lock_try(&vcputc_lock))		\
	{						\
		if (!istate)				\
			handle_pending_TLB_flushes();	\
		cpu_pause();				\
	}						\
MACRO_END

#define VCPUTC_LOCK_UNLOCK()				\
MACRO_BEGIN						\
	simple_unlock(&vcputc_lock);			\
MACRO_END
#else
static hw_lock_data_t vcputc_lock;

#define VCPUTC_LOCK_INIT()				\
MACRO_BEGIN						\
	hw_lock_init(&vcputc_lock);			\
MACRO_END

#define VCPUTC_LOCK_LOCK()				\
MACRO_BEGIN						\
	if (!hw_lock_to(&vcputc_lock, LockTimeOut*10))	\
	{						\
		panic("VCPUTC_LOCK_LOCK");		\
	}						\
MACRO_END

#define VCPUTC_LOCK_UNLOCK()				\
MACRO_BEGIN						\
	hw_lock_unlock(&vcputc_lock);			\
MACRO_END
#endif

/*
# Attribute codes: 
# 00=none 01=bold 04=underscore 05=blink 07=reverse 08=concealed
# Text color codes:
# 30=black 31=red 32=green 33=yellow 34=blue 35=magenta 36=cyan 37=white
# Background color codes:
# 40=black 41=red 42=green 43=yellow 44=blue 45=magenta 46=cyan 47=white
*/

#define ATTR_NONE	0
#define ATTR_BOLD	1
#define ATTR_UNDER	2
#define ATTR_REVERSE	4

#define COLOR_BACKGROUND 0
#define COLOR_FOREGROUND 7

#define COLOR_CODE_GET(code, fore)        (((code) & ((fore) ? 0xF0 : 0x0F))            >> ((fore) ? 4 : 0))
#define COLOR_CODE_SET(code, color, fore) (((code) & ((fore) ? 0x0F : 0xF0)) | ((color) << ((fore) ? 4 : 0)))

static unsigned char gc_color_code;

/* VT100 state: */
#define MAXPARS	16
static unsigned int gc_x, gc_y, gc_savex, gc_savey;
static unsigned int gc_par[MAXPARS], gc_numpars, gc_hanging_cursor, gc_attr, gc_saveattr;

/* VT100 tab stops & scroll region */
static char gc_tab_stops[255];
static unsigned int gc_scrreg_top, gc_scrreg_bottom;

#ifdef CONFIG_VC_PROGRESS_WHITE
enum { kProgressAcquireDelay = 0 /* secs */ };
#else
enum { kProgressAcquireDelay = 5 /* secs */ };
#endif

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
} gc_vt100state = ESnormal;

static int gc_wrap_mode = 1, gc_relative_origin = 0;
static int gc_charset_select = 0, gc_save_charset_s = 0;
static int gc_charset[2] = { 0, 0 };
static int gc_charset_save[2] = { 0, 0 };

static void gc_clear_line(unsigned int xx, unsigned int yy, int which);
static void gc_clear_screen(unsigned int xx, unsigned int yy, int top,
		unsigned int bottom, int which);
static void gc_enable(boolean_t enable);
static void gc_hide_cursor(unsigned int xx, unsigned int yy);
static void gc_initialize(struct vc_info * info);
static void gc_paint_char(unsigned int xx, unsigned int yy, unsigned char ch,
		int attrs);
static void gc_putchar(char ch);
static void gc_putc_askcmd(unsigned char ch);
static void gc_putc_charsetcmd(int charset, unsigned char ch);
static void gc_putc_charsizecmd(unsigned char ch);
static void gc_putc_esc(unsigned char ch);
static void gc_putc_getpars(unsigned char ch);
static void gc_putc_gotpars(unsigned char ch);
static void gc_putc_normal(unsigned char ch);
static void gc_putc_square(unsigned char ch);
static void gc_reset_screen(void);
static void gc_reset_tabs(void);
static void gc_reset_vt100(void);
static void gc_scroll_down(int num, unsigned int top, unsigned int bottom);
static void gc_scroll_up(int num, unsigned int top, unsigned int bottom);
static void gc_show_cursor(unsigned int xx, unsigned int yy);
static void gc_update_color(int color, boolean_t fore);

static void 
gc_clear_line(unsigned int xx, unsigned int yy, int which)
{
	unsigned int start, end, i;

	/*
	 * This routine runs extremely slowly.  I don't think it's
	 * used all that often, except for To end of line.  I'll go
	 * back and speed this up when I speed up the whole vc
	 * module. --LK
	 */

	switch (which) {
	case 0:		/* To end of line	 */
		start = xx;
		end = vinfo.v_columns-1;
		break;
	case 1:		/* To start of line	 */
		start = 0;
		end = xx;
		break;
	case 2:		/* Whole line		 */
		start = 0;
		end = vinfo.v_columns-1;
		break;
	default:
		return;
	}

	for (i = start; i <= end; i++) {
		gc_paint_char(i, yy, ' ', ATTR_NONE);
	}
}

static void 
gc_clear_screen(unsigned int xx, unsigned int yy, int top, unsigned int bottom,
		int which)
{
        if (!gc_buffer_size) return;

	if ( xx < gc_buffer_columns && yy < gc_buffer_rows && bottom <= gc_buffer_rows )
	{
		unsigned long start, end;

		switch (which) {
			case 0:		/* To end of screen	 */
				start = (yy * gc_buffer_columns) + xx;
				end = (bottom * gc_buffer_columns) - 1;
				break;
			case 1:		/* To start of screen	 */
				start = (top * gc_buffer_columns);
				end = (yy * gc_buffer_columns) + xx;
				break;
			case 2:		/* Whole screen		 */
				start = (top * gc_buffer_columns);
				end = (bottom * gc_buffer_columns) - 1;
				break;
			default:
				start = 0;
				end = 0;
				break;
		}

		memset(gc_buffer_attributes + start, ATTR_NONE, end - start + 1);
		memset(gc_buffer_characters + start, ' ', end - start + 1);
		memset(gc_buffer_colorcodes + start, gc_color_code, end - start + 1);
	}

	gc_ops.clear_screen(xx, yy, top, bottom, which);
}

static void
gc_enable( boolean_t enable )
{
	unsigned char *buffer_attributes = NULL;
	unsigned char *buffer_characters = NULL;
	unsigned char *buffer_colorcodes = NULL;
	unsigned long buffer_columns = 0;
	unsigned long buffer_rows = 0;
	unsigned long buffer_size = 0;
	spl_t s;

	if ( enable == FALSE )
	{
		// only disable console output if it goes to the graphics console
		if ( console_is_serial() == FALSE )
			disableConsoleOutput = TRUE;
		gc_enabled           = FALSE;
		gc_ops.enable(FALSE);
	}

	s = splhigh( );
	VCPUTC_LOCK_LOCK( );

	if ( gc_buffer_size )
	{
		buffer_attributes = gc_buffer_attributes;
		buffer_characters = gc_buffer_characters;
		buffer_colorcodes = gc_buffer_colorcodes;
		buffer_size       = gc_buffer_size;

		gc_buffer_attributes = NULL;
		gc_buffer_characters = NULL;
		gc_buffer_colorcodes = NULL;
		gc_buffer_columns    = 0;
		gc_buffer_rows       = 0;
		gc_buffer_size       = 0;

		VCPUTC_LOCK_UNLOCK( );
		splx( s );

		kfree( buffer_attributes, buffer_size );
		kfree( buffer_characters, buffer_size );
		kfree( buffer_colorcodes, buffer_size );
	}
	else
	{
		VCPUTC_LOCK_UNLOCK( );
		splx( s );
	}

	if ( enable )
	{
		if ( vm_initialized )
		{
			buffer_columns = vinfo.v_columns;
			buffer_rows    = vinfo.v_rows;
			buffer_size    = buffer_columns * buffer_rows;

			if ( buffer_size )
			{
				buffer_attributes = (unsigned char *) kalloc( buffer_size );
				buffer_characters = (unsigned char *) kalloc( buffer_size );
				buffer_colorcodes = (unsigned char *) kalloc( buffer_size );

				if ( buffer_attributes == NULL ||
				     buffer_characters == NULL ||
				     buffer_colorcodes == NULL )
				{
					if ( buffer_attributes ) kfree( buffer_attributes, buffer_size );
					if ( buffer_characters ) kfree( buffer_characters, buffer_size );
					if ( buffer_colorcodes ) kfree( buffer_colorcodes, buffer_size );

					buffer_columns = 0;
					buffer_rows    = 0;
					buffer_size    = 0;
				}
				else
				{
					memset( buffer_attributes, ATTR_NONE, buffer_size );
					memset( buffer_characters, ' ', buffer_size );
					memset( buffer_colorcodes, COLOR_CODE_SET( 0, COLOR_FOREGROUND, TRUE ), buffer_size );
				}
			}
		}

		s = splhigh( );
		VCPUTC_LOCK_LOCK( );

		gc_buffer_attributes = buffer_attributes;
		gc_buffer_characters = buffer_characters;
		gc_buffer_colorcodes = buffer_colorcodes;
		gc_buffer_columns    = buffer_columns;
		gc_buffer_rows       = buffer_rows;
		gc_buffer_size       = buffer_size;

		gc_reset_screen();

		VCPUTC_LOCK_UNLOCK( );
		splx( s );

		gc_ops.clear_screen(gc_x, gc_y, 0, vinfo.v_rows, 2);
		gc_ops.show_cursor(gc_x, gc_y);

		gc_ops.enable(TRUE);
		gc_enabled           = TRUE;
		disableConsoleOutput = FALSE;
	}
}

static void
gc_hide_cursor(unsigned int xx, unsigned int yy)
{
	if ( xx < gc_buffer_columns && yy < gc_buffer_rows )
	{
		unsigned long index = (yy * gc_buffer_columns) + xx;
		unsigned char attribute = gc_buffer_attributes[index];
		unsigned char character = gc_buffer_characters[index];
		unsigned char colorcode = gc_buffer_colorcodes[index];
		unsigned char colorcodesave = gc_color_code;

		gc_update_color(COLOR_CODE_GET(colorcode, TRUE ), TRUE );
		gc_update_color(COLOR_CODE_GET(colorcode, FALSE), FALSE);

		gc_ops.paint_char(xx, yy, character, attribute, 0, 0);

		gc_update_color(COLOR_CODE_GET(colorcodesave, TRUE ), TRUE );
		gc_update_color(COLOR_CODE_GET(colorcodesave, FALSE), FALSE);
	}
	else
	{
		gc_ops.hide_cursor(xx, yy);
	}
}

static void
gc_initialize(struct vc_info * info)
{
	if ( gc_initialized == FALSE )
	{
		/* Init our lock */
		VCPUTC_LOCK_INIT();

		gc_initialized = TRUE;
	}

	gc_ops.initialize(info);

	gc_reset_vt100();
	gc_x = gc_y = 0;
}

static void
gc_paint_char(unsigned int xx, unsigned int yy, unsigned char ch, int attrs)
{
	if ( xx < gc_buffer_columns && yy < gc_buffer_rows )
	{
		unsigned long index = (yy * gc_buffer_columns) + xx;
 
		gc_buffer_attributes[index] = attrs;
		gc_buffer_characters[index] = ch;
		gc_buffer_colorcodes[index] = gc_color_code;
	}

	gc_ops.paint_char(xx, yy, ch, attrs, 0, 0);
}

static void 
gc_putchar(char ch)
{
	if (!ch) {
		return;	/* ignore null characters */
	}
	switch (gc_vt100state) {
		default:gc_vt100state = ESnormal;	/* FALLTHROUGH */
	case ESnormal:
		gc_putc_normal(ch);
		break;
	case ESesc:
		gc_putc_esc(ch);
		break;
	case ESsquare:
		gc_putc_square(ch);
		break;
	case ESgetpars:
		gc_putc_getpars(ch);
		break;
	case ESgotpars:
		gc_putc_gotpars(ch);
		break;
	case ESask:
		gc_putc_askcmd(ch);
		break;
	case EScharsize:
		gc_putc_charsizecmd(ch);
		break;
	case ESsetG0:
		gc_putc_charsetcmd(0, ch);
		break;
	case ESsetG1:
		gc_putc_charsetcmd(1, ch);
		break;
	}

	if (gc_x >= vinfo.v_columns) {
		if (0 == vinfo.v_columns)
			gc_x = 0;
		else
			gc_x = vinfo.v_columns - 1;
	}
	if (gc_y >= vinfo.v_rows) {
		if (0 == vinfo.v_rows)
			gc_y = 0;
		else
			gc_y = vinfo.v_rows - 1;
	}
}

static void
gc_putc_askcmd(unsigned char ch)
{
	if (ch >= '0' && ch <= '9') {
		gc_par[gc_numpars] = (10*gc_par[gc_numpars]) + (ch-'0');
		return;
	}
	gc_vt100state = ESnormal;

	switch (gc_par[0]) {
		case 6:
			gc_relative_origin = ch == 'h';
			break;
		case 7:	/* wrap around mode h=1, l=0*/
			gc_wrap_mode = ch == 'h';
			break;
		default:
			break;
	}

}

static void
gc_putc_charsetcmd(int charset, unsigned char ch)
{
	gc_vt100state = ESnormal;

	switch (ch) {
		case 'A' :
		case 'B' :
		default:
			gc_charset[charset] = 0;
			break;
		case '0' :	/* Graphic characters */
		case '2' :
			gc_charset[charset] = 0x21;
			break;
	}

}

static void
gc_putc_charsizecmd(unsigned char ch)
{
	gc_vt100state = ESnormal;

	switch (ch) {
		case '3' :
		case '4' :
		case '5' :
		case '6' :
			break;
		case '8' :	/* fill 'E's */
			{
				unsigned int xx, yy;
				for (yy = 0; yy < vinfo.v_rows; yy++)
					for (xx = 0; xx < vinfo.v_columns; xx++)
						gc_paint_char(xx, yy, 'E', ATTR_NONE);
			}
			break;
	}

}

static void 
gc_putc_esc(unsigned char ch)
{
	gc_vt100state = ESnormal;

	switch (ch) {
	case '[':
		gc_vt100state = ESsquare;
		break;
	case 'c':		/* Reset terminal 	 */
		gc_reset_vt100();
		gc_clear_screen(gc_x, gc_y, 0, vinfo.v_rows, 2);
		gc_x = gc_y = 0;
		break;
	case 'D':		/* Line feed		 */
	case 'E':
		if (gc_y >= gc_scrreg_bottom -1) {
			gc_scroll_up(1, gc_scrreg_top, gc_scrreg_bottom);
			gc_y = gc_scrreg_bottom - 1;
		} else {
			gc_y++;
		}
		if (ch == 'E') gc_x = 0;
		break;
	case 'H':		/* Set tab stop		 */
		gc_tab_stops[gc_x] = 1;
		break;
	case 'M':		/* Cursor up		 */
		if (gc_y <= gc_scrreg_top) {
			gc_scroll_down(1, gc_scrreg_top, gc_scrreg_bottom);
			gc_y = gc_scrreg_top;
		} else {
			gc_y--;
		}
		break;
	case '>':
		gc_reset_vt100();
		break;
	case '7':		/* Save cursor		 */
		gc_savex = gc_x;
		gc_savey = gc_y;
		gc_saveattr = gc_attr;
		gc_save_charset_s = gc_charset_select;
		gc_charset_save[0] = gc_charset[0];
		gc_charset_save[1] = gc_charset[1];
		break;
	case '8':		/* Restore cursor	 */
		gc_x = gc_savex;
		gc_y = gc_savey;
		gc_attr = gc_saveattr;
		gc_charset_select = gc_save_charset_s;
		gc_charset[0] = gc_charset_save[0];
		gc_charset[1] = gc_charset_save[1];
		break;
	case 'Z':		/* return terminal ID */
		break;
	case '#':		/* change characters height */
		gc_vt100state = EScharsize;
		break;
	case '(':
		gc_vt100state = ESsetG0;
		break;
	case ')':		/* character set sequence */
		gc_vt100state = ESsetG1;
		break;
	case '=':
		break;
	default:
		/* Rest not supported */
		break;
	}

}

static void 
gc_putc_getpars(unsigned char ch)
{
	if (ch == '?') {
		gc_vt100state = ESask;
		return;
	}
	if (ch == '[') {
		gc_vt100state = ESnormal;
		/* Not supported */
		return;
	}
	if (ch == ';' && gc_numpars < MAXPARS - 1) {
		gc_numpars++;
	} else
		if (ch >= '0' && ch <= '9') {
			gc_par[gc_numpars] *= 10;
			gc_par[gc_numpars] += ch - '0';
		} else {
			gc_numpars++;
			gc_vt100state = ESgotpars;
			gc_putc_gotpars(ch);
		}
}

static void 
gc_putc_gotpars(unsigned char ch)
{
	unsigned int i;

	if (ch < ' ') {
		/* special case for vttest for handling cursor
		   movement in escape sequences */
		gc_putc_normal(ch);
		gc_vt100state = ESgotpars;
		return;
	}
	gc_vt100state = ESnormal;
	switch (ch) {
	case 'A':		/* Up			 */
		gc_y -= gc_par[0] ? gc_par[0] : 1;
		if (gc_y < gc_scrreg_top)
			gc_y = gc_scrreg_top;
		break;
	case 'B':		/* Down			 */
		gc_y += gc_par[0] ? gc_par[0] : 1;
		if (gc_y >= gc_scrreg_bottom)
			gc_y = gc_scrreg_bottom - 1;
		break;
	case 'C':		/* Right		 */
		gc_x += gc_par[0] ? gc_par[0] : 1;
		if (gc_x >= vinfo.v_columns)
			gc_x = vinfo.v_columns-1;
		break;
	case 'D':		/* Left			 */
		if (gc_par[0] > gc_x)
			gc_x = 0;
		else if (gc_par[0])
			gc_x -= gc_par[0];
		else if (gc_x)
			--gc_x;
		break;
	case 'H':		/* Set cursor position	 */
	case 'f':
		gc_x = gc_par[1] ? gc_par[1] - 1 : 0;
		gc_y = gc_par[0] ? gc_par[0] - 1 : 0;
		if (gc_relative_origin)
			gc_y += gc_scrreg_top;
		gc_hanging_cursor = 0;
		break;
	case 'X':		/* clear p1 characters */
		if (gc_numpars) {
			for (i = gc_x; i < gc_x + gc_par[0]; i++)
				gc_paint_char(i, gc_y, ' ', ATTR_NONE);
		}
		break;
	case 'J':		/* Clear part of screen	 */
		gc_clear_screen(gc_x, gc_y, 0, vinfo.v_rows, gc_par[0]);
		break;
	case 'K':		/* Clear part of line	 */
		gc_clear_line(gc_x, gc_y, gc_par[0]);
		break;
	case 'g':		/* tab stops	 	 */
		switch (gc_par[0]) {
			case 1:
			case 2:	/* reset tab stops */
				/* gc_reset_tabs(); */
				break;				
			case 3:	/* Clear every tabs */
				{
					for (i = 0; i <= vinfo.v_columns; i++)
						gc_tab_stops[i] = 0;
				}
				break;
			case 0:
				gc_tab_stops[gc_x] = 0;
				break;
		}
		break;
	case 'm':		/* Set attribute	 */
		for (i = 0; i < gc_numpars; i++) {
			switch (gc_par[i]) {
			case 0:
				gc_attr = ATTR_NONE;
				gc_update_color(COLOR_BACKGROUND, FALSE);
				gc_update_color(COLOR_FOREGROUND, TRUE );	
				break;
			case 1:
				gc_attr |= ATTR_BOLD;
				break;
			case 4:
				gc_attr |= ATTR_UNDER;
				break;
			case 7:
				gc_attr |= ATTR_REVERSE;
				break;
			case 22:
				gc_attr &= ~ATTR_BOLD;
				break;
			case 24:
				gc_attr &= ~ATTR_UNDER;
				break;
			case 27:
				gc_attr &= ~ATTR_REVERSE;
				break;
			case 5:
			case 25:	/* blink/no blink */
				break;
			default:
				if (gc_par[i] >= 30 && gc_par[i] <= 37)
					gc_update_color(gc_par[i] - 30, TRUE);
				if (gc_par[i] >= 40 && gc_par[i] <= 47)
					gc_update_color(gc_par[i] - 40, FALSE);
				break;
			}
		}
		break;
	case 'r':		/* Set scroll region	 */
		gc_x = gc_y = 0;
		/* ensure top < bottom, and both within limits */
		if ((gc_numpars > 0) && (gc_par[0] < vinfo.v_rows)) {
			gc_scrreg_top = gc_par[0] ? gc_par[0] - 1 : 0;
		} else {
			gc_scrreg_top = 0;
		}
		if ((gc_numpars > 1) && (gc_par[1] <= vinfo.v_rows) && (gc_par[1] > gc_par[0])) {
			gc_scrreg_bottom = gc_par[1];
			if (gc_scrreg_bottom > vinfo.v_rows)
				gc_scrreg_bottom = vinfo.v_rows;
		} else {
			gc_scrreg_bottom = vinfo.v_rows;
		}
		if (gc_relative_origin)
			gc_y = gc_scrreg_top;
		break;
	}

}

static void 
gc_putc_normal(unsigned char ch)
{
	switch (ch) {
	case '\a':		/* Beep			 */
        break;
	case 127:		/* Delete		 */
	case '\b':		/* Backspace		 */
		if (gc_hanging_cursor) {
			gc_hanging_cursor = 0;
		} else
			if (gc_x > 0) {
				gc_x--;
			}
		break;
	case '\t':		/* Tab			 */
		while (gc_x < vinfo.v_columns && !gc_tab_stops[++gc_x]);
		if (gc_x >= vinfo.v_columns)
			gc_x = vinfo.v_columns-1;
		break;
	case 0x0b:
	case 0x0c:
	case '\n':		/* Line feed		 */
		if (gc_y >= gc_scrreg_bottom -1 ) {
			gc_scroll_up(1, gc_scrreg_top, gc_scrreg_bottom);
			gc_y = gc_scrreg_bottom - 1;
		} else {
			gc_y++;
		}
		break;
	case '\r':		/* Carriage return	 */
		gc_x = 0;
		gc_hanging_cursor = 0;
		break;
	case 0x0e:  /* Select G1 charset (Control-N) */
		gc_charset_select = 1;
		break;
	case 0x0f:  /* Select G0 charset (Control-O) */
		gc_charset_select = 0;
		break;
	case 0x18 : /* CAN : cancel */
	case 0x1A : /* like cancel */
			/* well, i do nothing here, may be later */
		break;
	case '\033':		/* Escape		 */
		gc_vt100state = ESesc;
		gc_hanging_cursor = 0;
		break;
	default:
		if (ch >= ' ') {
			if (gc_hanging_cursor) {
				gc_x = 0;
				if (gc_y >= gc_scrreg_bottom -1 ) {
					gc_scroll_up(1, gc_scrreg_top, gc_scrreg_bottom);
					gc_y = gc_scrreg_bottom - 1;
				} else {
					gc_y++;
				}
				gc_hanging_cursor = 0;
			}
			gc_paint_char(gc_x, gc_y, (ch >= 0x60 && ch <= 0x7f) ? ch + gc_charset[gc_charset_select]
								: ch, gc_attr);
			if (gc_x == vinfo.v_columns - 1) {
				gc_hanging_cursor = gc_wrap_mode;
			} else {
				gc_x++;
			}
		}
		break;
	}

}

static void 
gc_putc_square(unsigned char ch)
{
	int     i;

	for (i = 0; i < MAXPARS; i++) {
		gc_par[i] = 0;
	}

	gc_numpars = 0;
	gc_vt100state = ESgetpars;

	gc_putc_getpars(ch);

}

static void
gc_reset_screen(void)
{
	gc_reset_vt100();
	gc_x = gc_y = 0;
}

static void
gc_reset_tabs(void)
{
	unsigned int i;

	for (i = 0; i<= vinfo.v_columns; i++) {
		gc_tab_stops[i] = ((i % 8) == 0);
	}

}

static void
gc_reset_vt100(void)
{
	gc_reset_tabs();
	gc_scrreg_top    = 0;
	gc_scrreg_bottom = vinfo.v_rows;
	gc_attr = ATTR_NONE;
	gc_charset[0] = gc_charset[1] = 0;
	gc_charset_select = 0;
	gc_wrap_mode = 1;
	gc_relative_origin = 0;
	gc_update_color(COLOR_BACKGROUND, FALSE);
	gc_update_color(COLOR_FOREGROUND, TRUE);
}

static void 
gc_scroll_down(int num, unsigned int top, unsigned int bottom)
{
        if (!gc_buffer_size) return;

	if ( bottom <= gc_buffer_rows )
	{
		unsigned char colorcodesave = gc_color_code;
		unsigned long column, row;
		unsigned long index, jump;

		jump = num * gc_buffer_columns;

		for ( row = bottom - 1 ; row >= top + num ; row-- )
		{
			index = row * gc_buffer_columns;

			for ( column = 0 ; column < gc_buffer_columns ; index++, column++ )
			{
				if ( gc_buffer_attributes[index] != gc_buffer_attributes[index - jump] || 
				     gc_buffer_characters[index] != gc_buffer_characters[index - jump] || 
				     gc_buffer_colorcodes[index] != gc_buffer_colorcodes[index - jump] )
				{
					if ( gc_color_code != gc_buffer_colorcodes[index - jump] )
					{
						gc_update_color(COLOR_CODE_GET(gc_buffer_colorcodes[index - jump], TRUE ), TRUE );
						gc_update_color(COLOR_CODE_GET(gc_buffer_colorcodes[index - jump], FALSE), FALSE);
					}

					if ( gc_buffer_colorcodes[index] != gc_buffer_colorcodes[index - jump] )
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ gc_buffer_characters[index - jump],
						                   /* attrs          */ gc_buffer_attributes[index - jump],
						                   /* ch_previous    */ 0,
						                   /* attrs_previous */ 0 );
					}
					else
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ gc_buffer_characters[index - jump],
						                   /* attrs          */ gc_buffer_attributes[index - jump],
						                   /* ch_previous    */ gc_buffer_characters[index],
						                   /* attrs_previous */ gc_buffer_attributes[index] );
					}

					gc_buffer_attributes[index] = gc_buffer_attributes[index - jump];
					gc_buffer_characters[index] = gc_buffer_characters[index - jump];
					gc_buffer_colorcodes[index] = gc_buffer_colorcodes[index - jump];
				}
			}
		}

		if ( colorcodesave != gc_color_code )
		{
			gc_update_color(COLOR_CODE_GET(colorcodesave, TRUE ), TRUE );
			gc_update_color(COLOR_CODE_GET(colorcodesave, FALSE), FALSE);
		}

		/* Now set the freed up lines to the background colour */

		for ( row = top ; row < top + num ; row++ )
		{
			index = row * gc_buffer_columns;

			for ( column = 0 ; column < gc_buffer_columns ; index++, column++ )
			{
				if ( gc_buffer_attributes[index] != ATTR_NONE     || 
				     gc_buffer_characters[index] != ' '           || 
				     gc_buffer_colorcodes[index] != gc_color_code )
				{
					if ( gc_buffer_colorcodes[index] != gc_color_code )
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ ' ',
						                   /* attrs          */ ATTR_NONE,
						                   /* ch_previous    */ 0,
						                   /* attrs_previous */ 0 );
					}
					else
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ ' ',
						                   /* attrs          */ ATTR_NONE,
						                   /* ch_previous    */ gc_buffer_characters[index],
						                   /* attrs_previous */ gc_buffer_attributes[index] );
					}

					gc_buffer_attributes[index] = ATTR_NONE;
					gc_buffer_characters[index] = ' ';
					gc_buffer_colorcodes[index] = gc_color_code;
				}
			}
		}
	}
	else
	{
		gc_ops.scroll_down(num, top, bottom);

		/* Now set the freed up lines to the background colour */

		gc_clear_screen(vinfo.v_columns - 1, top + num - 1, top, bottom, 1);
	}
}

static void 
gc_scroll_up(int num, unsigned int top, unsigned int bottom)
{
        if (!gc_buffer_size) return;

	if ( bottom <= gc_buffer_rows )
	{
		unsigned char colorcodesave = gc_color_code;
		unsigned long column, row;
		unsigned long index, jump;

		jump = num * gc_buffer_columns;

		for ( row = top ; row < bottom - num ; row++ )
		{
			index = row * gc_buffer_columns;

			for ( column = 0 ; column < gc_buffer_columns ; index++, column++ )
			{
				if ( gc_buffer_attributes[index] != gc_buffer_attributes[index + jump] || 
				     gc_buffer_characters[index] != gc_buffer_characters[index + jump] || 
				     gc_buffer_colorcodes[index] != gc_buffer_colorcodes[index + jump] )
				{
					if ( gc_color_code != gc_buffer_colorcodes[index + jump] )
					{
						gc_update_color(COLOR_CODE_GET(gc_buffer_colorcodes[index + jump], TRUE ), TRUE );
						gc_update_color(COLOR_CODE_GET(gc_buffer_colorcodes[index + jump], FALSE), FALSE);
					}

					if ( gc_buffer_colorcodes[index] != gc_buffer_colorcodes[index + jump] )
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ gc_buffer_characters[index + jump],
						                   /* attrs          */ gc_buffer_attributes[index + jump],
						                   /* ch_previous    */ 0,
						                   /* attrs_previous */ 0 );
					}
					else
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ gc_buffer_characters[index + jump],
						                   /* attrs          */ gc_buffer_attributes[index + jump],
						                   /* ch_previous    */ gc_buffer_characters[index],
						                   /* attrs_previous */ gc_buffer_attributes[index] );
					}

					gc_buffer_attributes[index] = gc_buffer_attributes[index + jump];
					gc_buffer_characters[index] = gc_buffer_characters[index + jump];
					gc_buffer_colorcodes[index] = gc_buffer_colorcodes[index + jump];
				}
			}
		}

		if ( colorcodesave != gc_color_code )
		{
			gc_update_color(COLOR_CODE_GET(colorcodesave, TRUE ), TRUE );
			gc_update_color(COLOR_CODE_GET(colorcodesave, FALSE), FALSE);
		}

		/* Now set the freed up lines to the background colour */

		for ( row = bottom - num ; row < bottom ; row++ )
		{
			index = row * gc_buffer_columns;

			for ( column = 0 ; column < gc_buffer_columns ; index++, column++ )
			{
				if ( gc_buffer_attributes[index] != ATTR_NONE     || 
				     gc_buffer_characters[index] != ' '           || 
				     gc_buffer_colorcodes[index] != gc_color_code )
				{
					if ( gc_buffer_colorcodes[index] != gc_color_code )
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ ' ',
						                   /* attrs          */ ATTR_NONE,
						                   /* ch_previous    */ 0,
						                   /* attrs_previous */ 0 );
					}
					else
					{
						gc_ops.paint_char( /* xx             */ column,
						                   /* yy             */ row,
						                   /* ch             */ ' ',
						                   /* attrs          */ ATTR_NONE,
						                   /* ch_previous    */ gc_buffer_characters[index],
						                   /* attrs_previous */ gc_buffer_attributes[index] );
					}

					gc_buffer_attributes[index] = ATTR_NONE;
					gc_buffer_characters[index] = ' ';
					gc_buffer_colorcodes[index] = gc_color_code;
				}
			}
		}
	}
	else
	{
		gc_ops.scroll_up(num, top, bottom);

		/* Now set the freed up lines to the background colour */

		gc_clear_screen(0, bottom - num, top, bottom, 0);
	}
}

static void
gc_show_cursor(unsigned int xx, unsigned int yy)
{
	if ( xx < gc_buffer_columns && yy < gc_buffer_rows )
	{
		unsigned long index = (yy * gc_buffer_columns) + xx;
		unsigned char attribute = gc_buffer_attributes[index];
		unsigned char character = gc_buffer_characters[index];
		unsigned char colorcode = gc_buffer_colorcodes[index];
		unsigned char colorcodesave = gc_color_code;

		gc_update_color(COLOR_CODE_GET(colorcode, FALSE), TRUE );
		gc_update_color(COLOR_CODE_GET(colorcode, TRUE ), FALSE);

		gc_ops.paint_char(xx, yy, character, attribute, 0, 0);

		gc_update_color(COLOR_CODE_GET(colorcodesave, TRUE ), TRUE );
		gc_update_color(COLOR_CODE_GET(colorcodesave, FALSE), FALSE);
	}
	else
	{
		gc_ops.show_cursor(xx, yy);
	}
}

static void
gc_update_color(int color, boolean_t fore)
{
	gc_color_code = COLOR_CODE_SET(gc_color_code, color, fore);
	gc_ops.update_color(color, fore);
}

void
vcputc(__unused int l, __unused int u, int c)
{
	if ( gc_enabled || debug_mode )
	{
		spl_t s;

		s = splhigh();
		VCPUTC_LOCK_LOCK();

		gc_hide_cursor(gc_x, gc_y);
		gc_putchar(c);
		gc_show_cursor(gc_x, gc_y);

		VCPUTC_LOCK_UNLOCK();
		splx(s);
	}
}

/*
 * Video Console (Back-End)
 * ------------------------
 */
 
/*
 * For the color support (Michel Pollet)
 */
static unsigned char vc_color_index_table[33] = 
	{  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

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

static unsigned long vc_color_fore = 0;
static unsigned long vc_color_back = 0;

/* 
 * New Rendering code from Michel Pollet
 */

/* Rendered Font Buffer */
static unsigned char *vc_rendered_font = NULL;

/* Rendered Font Size */
static unsigned long vc_rendered_font_size = 0;

/* Size of a character in the table (bytes) */
static int vc_rendered_char_size = 0;

#define REN_MAX_DEPTH	32
static unsigned char vc_rendered_char[ISO_CHAR_HEIGHT * ((REN_MAX_DEPTH / 8) * ISO_CHAR_WIDTH)];

static void 
vc_clear_screen(unsigned int xx, unsigned int yy, unsigned int scrreg_top,
		unsigned int scrreg_bottom, int which)
{
	unsigned long *p, *endp, *row;
	int      linelongs, col;
	int      rowline, rowlongs;

	if(!vinfo.v_depth)
		return;

	linelongs = vinfo.v_rowbytes * (ISO_CHAR_HEIGHT >> 2);
	rowline = vinfo.v_rowscanbytes >> 2;
	rowlongs = vinfo.v_rowbytes >> 2;

	p = (unsigned long*) vinfo.v_baseaddr;
	endp = (unsigned long*) vinfo.v_baseaddr;

	switch (which) {
	case 0:		/* To end of screen	 */
		gc_clear_line(xx, yy, 0);
		if (yy < scrreg_bottom - 1) {
			p += (yy + 1) * linelongs;
			endp += scrreg_bottom * linelongs;
		}
		break;
	case 1:		/* To start of screen	 */
		gc_clear_line(xx, yy, 1);
		if (yy > scrreg_top) {
			p += scrreg_top * linelongs;
			endp += yy * linelongs;
		}
		break;
	case 2:		/* Whole screen		 */
		p += scrreg_top * linelongs;
		if (scrreg_bottom == vinfo.v_rows) {
			endp += rowlongs * vinfo.v_height;
		} else {
			endp += scrreg_bottom * linelongs;
		}
		break;
	}

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) 
			*(row+col) = vc_color_back;
	}
}

static void
vc_initialize(__unused struct vc_info * vinfo_p)
{

	vinfo.v_rows = vinfo.v_height / ISO_CHAR_HEIGHT;
	vinfo.v_columns = vinfo.v_width / ISO_CHAR_WIDTH;
	vinfo.v_rowscanbytes = (vinfo.v_depth / 8) * vinfo.v_width;
}

static void
vc_render_char(unsigned char ch, unsigned char *renderptr, short newdepth)
{
	union {
		unsigned char  *charptr;
		unsigned short *shortptr;
		unsigned long  *longptr;
	} current; 	/* current place in rendered font, multiple types. */
	unsigned char *theChar;	/* current char in iso_font */
	int line;

	current.charptr = renderptr;
	theChar = iso_font + (ch * ISO_CHAR_HEIGHT);

	for (line = 0; line < ISO_CHAR_HEIGHT; line++) {
		unsigned char mask = 1;
		do {
			switch (newdepth) {
			case 8: 
				*current.charptr++ = (*theChar & mask) ? 0xFF : 0;
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

static void
vc_paint_char_8(unsigned int xx, unsigned int yy, unsigned char ch, int attrs,
		__unused unsigned char ch_previous, __unused int attrs_previous)
{
	unsigned long *theChar;
	unsigned long *where;
	int i;
	
	if (vc_rendered_font) {
		theChar = (unsigned long*)(vc_rendered_font + (ch * vc_rendered_char_size));
	} else {
		vc_render_char(ch, vc_rendered_char, 8);
		theChar = (unsigned long*)(vc_rendered_char);
	}
	where = (unsigned long*)(vinfo.v_baseaddr + 
					(yy * ISO_CHAR_HEIGHT * vinfo.v_rowbytes) + 
					(xx * ISO_CHAR_WIDTH));

	if (!attrs) for (i = 0; i < ISO_CHAR_HEIGHT; i++) {	/* No attr? FLY !*/
		unsigned long *store = where;
		int x;
		for (x = 0; x < 2; x++) {
			unsigned long val = *theChar++;
			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < ISO_CHAR_HEIGHT; i++) {	/* a little slower */
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
			if (attrs & ATTR_UNDER &&  i == ISO_CHAR_HEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
			lastpixel = save & 0xff;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}

static void
vc_paint_char_16(unsigned int xx, unsigned int yy, unsigned char ch, int attrs,
		 __unused unsigned char ch_previous,
		 __unused int attrs_previous) 
{
	unsigned long *theChar;
	unsigned long *where;
	int i;
	
	if (vc_rendered_font) {
		theChar = (unsigned long*)(vc_rendered_font + (ch * vc_rendered_char_size));
	} else {
		vc_render_char(ch, vc_rendered_char, 16);
		theChar = (unsigned long*)(vc_rendered_char);
	}
	where = (unsigned long*)(vinfo.v_baseaddr + 
				 (yy * ISO_CHAR_HEIGHT * vinfo.v_rowbytes) + 
				 (xx * ISO_CHAR_WIDTH * 2));

	if (!attrs) for (i = 0; i < ISO_CHAR_HEIGHT; i++) {	/* No attrs ? FLY ! */
		unsigned long *store = where;
		int x;
		for (x = 0; x < 4; x++) {
			unsigned long val = *theChar++;
			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < ISO_CHAR_HEIGHT; i++) { /* a little bit slower */
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
			if (attrs & ATTR_UNDER &&  i == ISO_CHAR_HEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);

			*store++ = val;
			lastpixel = save & 0x7fff;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}

static void
vc_paint_char_32(unsigned int xx, unsigned int yy, unsigned char ch, int attrs,
		 unsigned char ch_previous, int attrs_previous) 
{
	unsigned long *theChar;
	unsigned long *theCharPrevious;
	unsigned long *where;
	int i;
	
	if (vc_rendered_font) {
		theChar = (unsigned long*)(vc_rendered_font + (ch * vc_rendered_char_size));
		theCharPrevious = (unsigned long*)(vc_rendered_font + (ch_previous * vc_rendered_char_size));
	} else {
		vc_render_char(ch, vc_rendered_char, 32);
		theChar = (unsigned long*)(vc_rendered_char);
		theCharPrevious = NULL;
	}
	if (!ch_previous) {
		theCharPrevious = NULL;
	}
	if (attrs_previous) {
		theCharPrevious = NULL;
	}
	where = (unsigned long*)(vinfo.v_baseaddr + 
					(yy * ISO_CHAR_HEIGHT * vinfo.v_rowbytes) + 
					(xx * ISO_CHAR_WIDTH * 4));

	if (!attrs) for (i = 0; i < ISO_CHAR_HEIGHT; i++) {	/* No attrs ? FLY ! */
		unsigned long *store = where;
		int x;
		for (x = 0; x < 8; x++) {
			unsigned long val = *theChar++;
			if (theCharPrevious == NULL || val != *theCharPrevious++ ) {
				val = (vc_color_back & ~val) | (vc_color_fore & val);
				*store++ = val;
			} else {
				store++;
			}
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);
	} else for (i = 0; i < ISO_CHAR_HEIGHT; i++) {	/* a little slower */
		unsigned long *store = where, lastpixel = 0;
		int x;
		for (x = 0 ; x < 8; x++) {
			unsigned long val = *theChar++, save = val;
			if (attrs & ATTR_BOLD) {	/* bold support */
				if (lastpixel && !save)
					val = 0xFFFFFFFF;
			}
			if (attrs & ATTR_REVERSE) val = ~val;
			if (attrs & ATTR_UNDER &&  i == ISO_CHAR_HEIGHT-1) val = ~val;

			val = (vc_color_back & ~val) | (vc_color_fore & val);
			*store++ = val;
			lastpixel = save;
		}
		
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}

}

static void
vc_paint_char(unsigned int xx, unsigned int yy, unsigned char ch, int attrs,
	      unsigned char ch_previous, int attrs_previous)
{
	if(!vinfo.v_depth)
		return;

	switch(vinfo.v_depth) {
	case 8:
		vc_paint_char_8(xx, yy, ch, attrs, ch_previous, attrs_previous);
		break;
	case 16:
		vc_paint_char_16(xx, yy, ch, attrs, ch_previous,
				 attrs_previous);
		break;
	case 32:
		vc_paint_char_32(xx, yy, ch, attrs, ch_previous,
				 attrs_previous);
		break;
	}
}

static void
vc_render_font(short newdepth)
{
	static short olddepth = 0;

	int charindex;	/* index in ISO font */
	unsigned char *rendered_font;
	unsigned long rendered_font_size;
	int rendered_char_size;
	spl_t s;

	if (vm_initialized == FALSE) {
		return;	/* nothing to do */
	}
	if (olddepth == newdepth && vc_rendered_font) {
		return;	/* nothing to do */
	}

	s = splhigh();
	VCPUTC_LOCK_LOCK();

	rendered_font      = vc_rendered_font;
	rendered_font_size = vc_rendered_font_size;
	rendered_char_size = vc_rendered_char_size;

	vc_rendered_font      = NULL;
	vc_rendered_font_size = 0;
	vc_rendered_char_size = 0;

	VCPUTC_LOCK_UNLOCK();
	splx(s);

	if (rendered_font) {
		kfree(rendered_font, rendered_font_size);
		rendered_font = NULL;
	}

	if (newdepth) {
		rendered_char_size = ISO_CHAR_HEIGHT * ((newdepth / 8) * ISO_CHAR_WIDTH);
		rendered_font_size = (ISO_CHAR_MAX-ISO_CHAR_MIN+1) * rendered_char_size;
		rendered_font = (unsigned char *) kalloc(rendered_font_size);
	}

	if (rendered_font == NULL) {
		return;
	}

	for (charindex = ISO_CHAR_MIN; charindex <= ISO_CHAR_MAX; charindex++) {
		vc_render_char(charindex, rendered_font + (charindex * rendered_char_size), newdepth);
	}

	olddepth = newdepth;

	s = splhigh();
	VCPUTC_LOCK_LOCK();

	vc_rendered_font      = rendered_font;
	vc_rendered_font_size = rendered_font_size;
	vc_rendered_char_size = rendered_char_size;

	VCPUTC_LOCK_UNLOCK();
	splx(s);
}

static void
vc_enable(boolean_t enable)
{
	vc_render_font(enable ? vinfo.v_depth : 0);
}

static void
vc_reverse_cursor(unsigned int xx, unsigned int yy)
{
	unsigned long *where;
	int line, col;

	if(!vinfo.v_depth)
		return;

	where = (unsigned long*)(vinfo.v_baseaddr + 
			(yy * ISO_CHAR_HEIGHT * vinfo.v_rowbytes) + 
			(xx /** ISO_CHAR_WIDTH*/ * vinfo.v_depth));
	for (line = 0; line < ISO_CHAR_HEIGHT; line++) {
		switch (vinfo.v_depth) {
			case 8:
				where[0] = ~where[0];
				where[1] = ~where[1];
				break;
			case 16:
				for (col = 0; col < 4; col++)
					where[col] = ~where[col];
				break;
			case 32:
				for (col = 0; col < 8; col++)
					where[col] = ~where[col];
				break;
		}
		where = (unsigned long*)(((unsigned char*)where)+vinfo.v_rowbytes);		
	}
}

static void 
vc_scroll_down(int num, unsigned int scrreg_top, unsigned int scrreg_bottom)
{
	unsigned long *from, *to,  linelongs, i, line, rowline, rowscanline;

	if(!vinfo.v_depth)
		return;

	linelongs = vinfo.v_rowbytes * (ISO_CHAR_HEIGHT >> 2);
	rowline = vinfo.v_rowbytes >> 2;
	rowscanline = vinfo.v_rowscanbytes >> 2;

	to = (unsigned long *) vinfo.v_baseaddr + (linelongs * scrreg_bottom)
		- (rowline - rowscanline);
	from = to - (linelongs * num);	/* handle multiple line scroll (Michel Pollet) */

	i = (scrreg_bottom - scrreg_top) - num;

	while (i-- > 0) {
		for (line = 0; line < ISO_CHAR_HEIGHT; line++) {
			/*
			 * Only copy what is displayed
			 */
			video_scroll_down((unsigned int) from, 
					(unsigned int) (from-(vinfo.v_rowscanbytes >> 2)), 
					(unsigned int) to);

			from -= rowline;
			to -= rowline;
		}
	}
}

static void 
vc_scroll_up(int num, unsigned int scrreg_top, unsigned int scrreg_bottom)
{
	unsigned long *from, *to, linelongs, i, line, rowline, rowscanline;

	if(!vinfo.v_depth)
		return;

	linelongs = vinfo.v_rowbytes * (ISO_CHAR_HEIGHT >> 2);
	rowline = vinfo.v_rowbytes >> 2;
	rowscanline = vinfo.v_rowscanbytes >> 2;

	to = (unsigned long *) vinfo.v_baseaddr + (scrreg_top * linelongs);
	from = to + (linelongs * num);	/* handle multiple line scroll (Michel Pollet) */

	i = (scrreg_bottom - scrreg_top) - num;

	while (i-- > 0) {
		for (line = 0; line < ISO_CHAR_HEIGHT; line++) {
			/*
			 * Only copy what is displayed
			 */
			video_scroll_up((unsigned int) from, 
					(unsigned int) (from+(vinfo.v_rowscanbytes >> 2)), 
					(unsigned int) to);

			from += rowline;
			to += rowline;
		}
	}
}

static void
vc_update_color(int color, boolean_t fore)
{
	if (!vinfo.v_depth)
		return;
	if (fore) {
        	vc_color_fore = vc_colors[color][vc_color_index_table[vinfo.v_depth]];
	} else {
		vc_color_back = vc_colors[color][vc_color_index_table[vinfo.v_depth]];
	}
}

/*
 * Video Console (Back-End): Icon Control
 * --------------------------------------
 */

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
static uint32_t            	vc_progress_interval;
static uint64_t			vc_progress_deadline;
static thread_call_data_t	vc_progress_call;
static boolean_t		vc_needsave;
static void *			vc_saveunder;
static vm_size_t		vc_saveunder_len;
decl_simple_lock_data(,vc_progress_lock)

static void vc_blit_rect(    int x, int y, int width, int height,
                             const unsigned char * dataPtr, const unsigned char * alphaPtr,
                             void * backBuffer, boolean_t save, boolean_t static_alpha );
static void vc_blit_rect_8(  int x, int y, int width, int height,
                             const unsigned char * dataPtr, const unsigned char * alphaPtr,
                             unsigned char * backBuffer, boolean_t save, boolean_t static_alpha );
static void vc_blit_rect_16( int x, int y, int width, int height,
                             const unsigned char * dataPtr, const unsigned char * alphaPtr,
                             unsigned short * backBuffer, boolean_t save, boolean_t static_alpha );
static void vc_blit_rect_32( int x, int y, int width, int height,
                             const unsigned char * dataPtr, const unsigned char * alphaPtr,
                             unsigned int * backBuffer, boolean_t save, boolean_t static_alpha );
extern void vc_display_icon( vc_progress_element * desc, const unsigned char * data );
extern void vc_progress_initialize( vc_progress_element * desc, const unsigned char * data, const unsigned char * clut );
static void vc_progress_set(boolean_t enable, uint32_t vc_delay);
static void vc_progress_task( void * arg0, void * arg );

static void vc_blit_rect(	int x, int y,
                                int width, int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                void * backBuffer,
                                boolean_t save, boolean_t static_alpha )
{
    if(!vinfo.v_depth)
        return;

    switch( vinfo.v_depth) {
	case 8:
            if( vc_clut8 == vc_clut)
                vc_blit_rect_8( x, y, width, height, dataPtr, alphaPtr, (unsigned char *) backBuffer, save, static_alpha );
	    break;
	case 16:
	    vc_blit_rect_16( x, y, width, height, dataPtr, alphaPtr, (unsigned short *) backBuffer, save, static_alpha );
	    break;
	case 32:
	    vc_blit_rect_32( x, y, width, height, dataPtr, alphaPtr, (unsigned int *) backBuffer, save, static_alpha );
	    break;
    }
}

static void
vc_blit_rect_8(int x, int y, int width, int height,
	       const unsigned char * dataPtr, const unsigned char * alphaPtr,
	       __unused unsigned char * backPtr, __unused boolean_t save,
	       __unused boolean_t static_alpha)
{
    volatile unsigned char * dst;
    int line, col;
    unsigned int data;

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

/* For ARM, 16-bit is 565 (RGB); it is 1555 (XRGB) on other platforms */

#define CLUT_MASK_R	0xf8
#define CLUT_MASK_G	0xf8
#define CLUT_MASK_B	0xf8
#define CLUT_SHIFT_R	<< 7
#define CLUT_SHIFT_G	<< 2
#define CLUT_SHIFT_B	>> 3
#define MASK_R		0x7c00
#define MASK_G		0x03e0
#define MASK_B		0x001f
#define MASK_R_8	0x3fc00
#define MASK_G_8	0x01fe0
#define MASK_B_8	0x000ff

static void vc_blit_rect_16(	int x, int y,
                                int width, int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                unsigned short *  backPtr,
                                boolean_t save, boolean_t static_alpha )
{
    volatile unsigned short * dst;
    int line, col;
    unsigned int data = 0, index = 0, alpha, back;

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
                        data |= (((vc_clut[index + 0] - alpha) & CLUT_MASK_R) CLUT_SHIFT_R);
                    if( vc_clut[index + 1] > alpha)
                        data |= (((vc_clut[index + 1] - alpha) & CLUT_MASK_G) CLUT_SHIFT_G);
                    if( vc_clut[index + 2] > alpha)
                        data |= (((vc_clut[index + 2] - alpha) & CLUT_MASK_B) CLUT_SHIFT_B);
		}
#ifdef CONFIG_VC_PROGRESS_WHITE
		else {
		    data |= (((0xff - alpha) & CLUT_MASK_R) CLUT_SHIFT_R);
		    data |= (((0xff - alpha) & CLUT_MASK_G) CLUT_SHIFT_G);
		    data |= (((0xff - alpha) & CLUT_MASK_B) CLUT_SHIFT_B);
		}
#endif

                if( save) {
                    back = *(dst + col);
                    if ( !static_alpha)
                        *backPtr++ = back;
                        back = (((((back & MASK_R) * alpha) + MASK_R_8) >> 8) & MASK_R)
                             | (((((back & MASK_G) * alpha) + MASK_G_8) >> 8) & MASK_G)
                             | (((((back & MASK_B) * alpha) + MASK_B_8) >> 8) & MASK_B);
                    if ( static_alpha)
                        *backPtr++ = back;
                } else {
                    back = *backPtr++;
                    if ( !static_alpha) {
                        back = (((((back & MASK_R) * alpha) + MASK_R_8) >> 8) & MASK_R)
                             | (((((back & MASK_G) * alpha) + MASK_G_8) >> 8) & MASK_G)
                             | (((((back & MASK_B) * alpha) + MASK_B_8) >> 8) & MASK_B);
                    }
                }

                data += back;

            } else
                if( dataPtr != 0) {
            	    data = ( (CLUT_MASK_R & (vc_clut[index + 0])) CLUT_SHIFT_R)
                           | ( (CLUT_MASK_G & (vc_clut[index + 1])) CLUT_SHIFT_G)
                           | ( (CLUT_MASK_B & (vc_clut[index + 2])) CLUT_SHIFT_B);
		}

            *(dst + col) = data;
	}
        dst = (volatile unsigned short *) (((int)dst) + vinfo.v_rowbytes);
    }
}

static void vc_blit_rect_32(	int x, int y,
                                int width, int height,
                                const unsigned char * dataPtr,
                                const unsigned char * alphaPtr,
                                unsigned int *  backPtr,
                                boolean_t save, boolean_t static_alpha )
{
    volatile unsigned int * dst;
    int line, col;
    unsigned int data = 0, index = 0, alpha, back;

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
#ifdef CONFIG_VC_PROGRESS_WHITE
		else {
		    data |= (0xff - alpha) << 16;
		    data |= (0xff - alpha) << 8;
		    data |= (0xff - alpha);
		}
#endif

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

void vc_display_icon( vc_progress_element * desc,
			const unsigned char * data )
{
    int			x, y, width, height;

    if( vc_progress_enable && vc_clut) {

	width = desc->width;
	height = desc->height;
	x = desc->dx;
	y = desc->dy;
	if( 1 & desc->flags) {
	    x += ((vinfo.v_width - width) / 2);
	    y += ((vinfo.v_height - height) / 2);
	}
	vc_blit_rect( x, y, width, height, data, NULL, NULL, FALSE, TRUE );
    }
}

void
vc_progress_initialize( vc_progress_element * desc,
			const unsigned char * data,
			const unsigned char * clut )
{
	uint64_t	abstime;

    if( (!clut) || (!desc) || (!data))
	return;
    vc_clut = clut;
    vc_clut8 = clut;

    simple_lock_init(&vc_progress_lock, 0);

    vc_progress = desc;
    vc_progress_data = data;
    if( 2 & vc_progress->flags)
        vc_progress_alpha = vc_progress_data
                            + vc_progress->count * vc_progress->width * vc_progress->height;
    else
        vc_progress_alpha = NULL;

    thread_call_setup(&vc_progress_call, vc_progress_task, NULL);

    clock_interval_to_absolutetime_interval(vc_progress->time, 1000 * 1000, &abstime);
    vc_progress_interval = abstime;
}

static void
vc_progress_set(boolean_t enable, uint32_t vc_delay)
{
    spl_t	     s;
    void             *saveBuf = NULL;
    vm_size_t        saveLen = 0;
    unsigned int     count;
    unsigned int     index;
    unsigned char    pdata8;
    unsigned short   pdata16;
    unsigned short * buf16;
    unsigned int     pdata32;
    unsigned int *   buf32;

    if( !vc_progress)
	return;

    if( enable) {
        saveLen = vc_progress->width * vc_progress->height * vinfo.v_depth / 8;
        saveBuf = kalloc( saveLen );

	switch( vinfo.v_depth) {
	    case 8 :
		for( count = 0; count < 256; count++) {
		    vc_revclut8[count] = vc_clut[0x01 * 3];
		    pdata8 = (vc_clut[0x01 * 3] * count + 0x0ff) >> 8;
		    for( index = 0; index < 256; index++) {
			if( (pdata8 == vc_clut[index * 3 + 0]) &&
			    (pdata8 == vc_clut[index * 3 + 1]) &&
			    (pdata8 == vc_clut[index * 3 + 2])) {
			    vc_revclut8[count] = index;
			    break;
			}
		    }
		}
		memset( saveBuf, 0x01, saveLen );
		break;

	    case 16 :
		buf16 = (unsigned short *) saveBuf;
		pdata16 = ((vc_clut[0x01 * 3 + 0] & CLUT_MASK_R) CLUT_SHIFT_R)
		       | ((vc_clut[0x01 * 3 + 0] & CLUT_MASK_G) CLUT_SHIFT_G)
		       | ((vc_clut[0x01 * 3 + 0] & CLUT_MASK_B) CLUT_SHIFT_B);
		for( count = 0; count < saveLen / 2; count++)
		    buf16[count] = pdata16;
		break;

	    case 32 :
		buf32 = (unsigned int *) saveBuf;
		pdata32 = ((vc_clut[0x01 * 3 + 0] & 0xff) << 16)
		       | ((vc_clut[0x01 * 3 + 1] & 0xff) << 8)
		       | ((vc_clut[0x01 * 3 + 2] & 0xff) << 0);
		for( count = 0; count < saveLen / 4; count++)
		    buf32[count] = pdata32;
		break;
	}
    }

    s = splhigh();
    simple_lock(&vc_progress_lock);

    if( vc_progress_enable != enable) {
        vc_progress_enable = enable;
        if( enable) {
            vc_needsave      = TRUE;
            vc_saveunder     = saveBuf;
            vc_saveunder_len = saveLen;
            saveBuf	     = NULL;
            saveLen 	     = 0;

            clock_interval_to_deadline(vc_delay,
				       1000 * 1000 * 1000 /*second scale*/,
				       &vc_progress_deadline);
            thread_call_enter_delayed(&vc_progress_call, vc_progress_deadline);

        } else {
            if( vc_saveunder) {
                saveBuf      = vc_saveunder;
                saveLen      = vc_saveunder_len;
                vc_saveunder = NULL;
                vc_saveunder_len = 0;
            }

            thread_call_cancel(&vc_progress_call);
        }
    }

    simple_unlock(&vc_progress_lock);
    splx(s);

    if( saveBuf)
        kfree( saveBuf, saveLen );
}

static void
vc_progress_task(__unused void *arg0, void *arg)
{
    spl_t		s;
    int			count = (int) arg;
    int			x, y, width, height;
    const unsigned char * data;

    s = splhigh();
    simple_lock(&vc_progress_lock);

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

        clock_deadline_for_periodic_event(vc_progress_interval, mach_absolute_time(), &vc_progress_deadline);
        thread_call_enter1_delayed(&vc_progress_call, (void *)count, vc_progress_deadline);
    }
    simple_unlock(&vc_progress_lock);
    splx(s);
}

/*
 * Generic Console (Front-End): Master Control
 * -------------------------------------------
 */

#ifdef __i386__
#include <console/i386/text_console.h>
#include <pexpert/i386/boot.h>
#endif /* __i386__ */

static boolean_t gc_acquired      = FALSE;
static boolean_t gc_graphics_boot = FALSE;
static boolean_t gc_desire_text   = FALSE;

static unsigned int lastVideoPhys   = 0;
static unsigned int lastVideoVirt   = 0;
static unsigned int lastVideoSize   = 0;
static boolean_t    lastVideoMapped = FALSE;

void
initialize_screen(PE_Video * boot_vinfo, unsigned int op)
{
	unsigned int fbsize = 0;
	unsigned int newVideoVirt = 0;
	boolean_t graphics_now;
	ppnum_t fbppage;

	if ( boot_vinfo )
	{
		struct vc_info new_vinfo = vinfo;

//        	bcopy((const void *)boot_vinfo, (void *)&boot_video_info, sizeof(boot_video_info));

		/* 
		 *	First, check if we are changing the size and/or location of the framebuffer
		 */
		new_vinfo.v_name[0]  = 0;
		new_vinfo.v_width    = boot_vinfo->v_width;
		new_vinfo.v_height   = boot_vinfo->v_height;
		new_vinfo.v_depth    = boot_vinfo->v_depth;
		new_vinfo.v_rowbytes = boot_vinfo->v_rowBytes;
		new_vinfo.v_physaddr = boot_vinfo->v_baseAddr;		/* Get the physical address */
#ifdef __i386__
                new_vinfo.v_type     = boot_vinfo->v_display;
#else
                new_vinfo.v_type = 0;
#endif
     
		if (!lastVideoMapped)
		    kprintf("initialize_screen: b=%08lX, w=%08lX, h=%08lX, r=%08lX, d=%08lX\n",                  /* (BRINGUP) */
			    new_vinfo.v_physaddr, new_vinfo.v_width,  new_vinfo.v_height,  new_vinfo.v_rowbytes, new_vinfo.v_type);     /* (BRINGUP) */

#ifdef __i386__
                if ( (new_vinfo.v_type == VGA_TEXT_MODE) )
                {
                    if (new_vinfo.v_physaddr == 0) {
                        new_vinfo.v_physaddr = 0xb8000;
                        new_vinfo.v_width = 80;
                        new_vinfo.v_height = 25;
                        new_vinfo.v_depth = 8;
                        new_vinfo.v_rowbytes = 0x8000;
                    }
                }
#endif /* __i386__ */

		if (!new_vinfo.v_physaddr)							/* Check to see if we have a framebuffer */
		{
			kprintf("initialize_screen: No video - forcing serial mode\n");		/* (BRINGUP) */
			new_vinfo.v_depth = 0;						/* vc routines are nop */
			(void)switch_to_serial_console();				/* Switch into serial mode */
			gc_graphics_boot = FALSE;					/* Say we are not in graphics mode */
			disableConsoleOutput = FALSE;					/* Allow printfs to happen */
			gc_acquired = TRUE;
		}
		else
		{
		    /*
		    *	Note that for the first time only, boot_vinfo->v_baseAddr is physical.
		    */
    
		    if (kernel_map != VM_MAP_NULL)					/* If VM is up, we are given a virtual address */
		    {
			    fbppage = pmap_find_phys(kernel_pmap, (addr64_t)boot_vinfo->v_baseAddr);	/* Get the physical address of frame buffer */
			    if(!fbppage)						/* Did we find it? */
			    {
				    panic("initialize_screen: Strange framebuffer - addr = %08X\n", (uint32_t)boot_vinfo->v_baseAddr);
			    }
			    new_vinfo.v_physaddr = (fbppage << 12) | (boot_vinfo->v_baseAddr & PAGE_MASK);			/* Get the physical address */
		    }
    
		    if (boot_vinfo->v_length != 0)
			    fbsize = round_page_32(boot_vinfo->v_length);
		    else
			    fbsize = round_page_32(new_vinfo.v_height * new_vinfo.v_rowbytes);			/* Remember size */

    
		    if ((lastVideoPhys != new_vinfo.v_physaddr) || (fbsize > lastVideoSize))		/* Did framebuffer change location or get bigger? */
		    {
			    unsigned int
#if FALSE
			    flags = (new_vinfo.v_type == VGA_TEXT_MODE) ? VM_WIMG_IO : VM_WIMG_WCOMB;
#else
			    flags = VM_WIMG_IO;
#endif
			    newVideoVirt = io_map_spec((vm_offset_t)new_vinfo.v_physaddr, fbsize, flags);	/* Allocate address space for framebuffer */
    		    }
		}

		if (newVideoVirt != 0)
		    new_vinfo.v_baseaddr = newVideoVirt + boot_vinfo->v_offset;				/* Set the new framebuffer address */
		else
		    new_vinfo.v_baseaddr = lastVideoVirt + boot_vinfo->v_offset;				/* Set the new framebuffer address */

		/* Update the vinfo structure atomically with respect to the vc_progress task if running */
		if (vc_progress)
		{
		    simple_lock(&vc_progress_lock);
		    vinfo = new_vinfo;
		    simple_unlock(&vc_progress_lock);
		}
		else
		{
		    vinfo = new_vinfo;
		}

		// If we changed the virtual address, remove the old mapping
		if (newVideoVirt != 0)
		{
			if (lastVideoVirt)							/* Was the framebuffer mapped before? */
			{
#if FALSE
				if(lastVideoMapped)                            /* Was this not a special pre-VM mapping? */
#endif
				{
					pmap_remove(kernel_pmap, trunc_page_64(lastVideoVirt),
						round_page_64(lastVideoVirt + lastVideoSize));	/* Toss mappings */
				}
				if(lastVideoMapped)                            /* Was this not a special pre-VM mapping? */
				{
					kmem_free(kernel_map, lastVideoVirt, lastVideoSize);	/* Toss kernel addresses */
				}
			}
			lastVideoPhys = new_vinfo.v_physaddr;					/* Remember the framebuffer address */
			lastVideoSize = fbsize;							/* Remember the size */
			lastVideoVirt = newVideoVirt;						/* Remember the virtual framebuffer address */
			lastVideoMapped  = (NULL != kernel_map);
		}

#ifdef __i386__
		if ( (vinfo.v_type == VGA_TEXT_MODE) )
		{
			// Text mode setup by the booter.

			gc_ops.initialize   = tc_initialize;
			gc_ops.enable       = tc_enable;
			gc_ops.paint_char   = tc_paint_char;
			gc_ops.clear_screen = tc_clear_screen;
			gc_ops.scroll_down  = tc_scroll_down;
			gc_ops.scroll_up    = tc_scroll_up;
			gc_ops.hide_cursor  = tc_hide_cursor;
			gc_ops.show_cursor  = tc_show_cursor;
			gc_ops.update_color = tc_update_color;
		}
		else
#endif /* __i386__ */
		{
			// Graphics mode setup by the booter.

			gc_ops.initialize   = vc_initialize;
			gc_ops.enable       = vc_enable;
			gc_ops.paint_char   = vc_paint_char;
			gc_ops.scroll_down  = vc_scroll_down;
			gc_ops.scroll_up    = vc_scroll_up;
			gc_ops.clear_screen = vc_clear_screen;
			gc_ops.hide_cursor  = vc_reverse_cursor;
			gc_ops.show_cursor  = vc_reverse_cursor;
			gc_ops.update_color = vc_update_color;
		}

		gc_initialize(&vinfo);

#ifdef GRATEFULDEBUGGER
		GratefulDebInit((bootBumbleC *)boot_vinfo);	/* Re-initialize GratefulDeb */
#endif /* GRATEFULDEBUGGER */
	}

	switch ( op )
	{
		case kPEGraphicsMode:
			panicDialogDesired = TRUE;
			gc_graphics_boot = TRUE;
			gc_desire_text = FALSE;
			break;

		case kPETextMode:
			panicDialogDesired = FALSE;
			gc_graphics_boot = FALSE;
			break;

		case kPEAcquireScreen:
			if ( gc_acquired ) break;
			graphics_now = gc_graphics_boot && !gc_desire_text;
			vc_progress_set( graphics_now, kProgressAcquireDelay );
			gc_enable( !graphics_now );
			gc_acquired = TRUE;
			gc_desire_text = FALSE;
			break;

		case kPEEnableScreen:
			/* deprecated */
			break;

		case kPETextScreen:
			if ( console_is_serial() ) break;

			panicDialogDesired = FALSE;
			if ( gc_acquired == FALSE )
			{
				gc_desire_text = TRUE;
				break;
			}
			if ( gc_graphics_boot == FALSE ) break;

			vc_progress_set( FALSE, 0 );
			gc_enable( TRUE );
			break;

		case kPEDisableScreen:
			/* deprecated */
			/* skip break */

		case kPEReleaseScreen:
			gc_acquired = FALSE;
			gc_desire_text = FALSE;
			gc_enable( FALSE );
			vc_progress_set( FALSE, 0 );

			vc_clut8 = NULL;
#ifdef GRATEFULDEBUGGER
			GratefulDebInit(0);						/* Stop grateful debugger */
#endif /* GRATEFULDEBUGGER */
			break;
	}
#ifdef GRATEFULDEBUGGER
	if ( boot_vinfo ) GratefulDebInit((bootBumbleC *)boot_vinfo);	/* Re initialize GratefulDeb */
#endif /* GRATEFULDEBUGGER */
}

void vcattach(void); /* XXX gcc 4 warning cleanup */

void
vcattach(void)
{
	vm_initialized = TRUE;

	if ( gc_graphics_boot == FALSE )
	{
		long index;

		if ( gc_acquired )
		{
			initialize_screen(NULL, kPEReleaseScreen);
		}

		initialize_screen(NULL, kPEAcquireScreen);

		for ( index = 0 ; index < msgbufp->msg_bufx ; index++ )
		{
			vcputc( 0, 0, msgbufp->msg_bufc[index] );

			if ( msgbufp->msg_bufc[index] == '\n' )
			{
				vcputc( 0, 0,'\r' );
			}
		}
	}
}
