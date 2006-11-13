/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#ifndef _PEXPERT_I386_KDSOFT_H_
#define _PEXPERT_I386_KDSOFT_H_

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
 *  File:         kdsoft.h
 *  Description:  Software structures for keyboard/display driver, shared with
 * 	drivers for specific graphics cards.
 * 
 *  $ Header: $
 * 
 *  Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
 *  All rights reserved.
 * 
 *   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.,
 * Cupertino, California.
 * 
 * 		All Rights Reserved
 * 
 *   Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Olivetti
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 *   OLIVETTI DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL OLIVETTI BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUR OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This driver handles two types of graphics cards.  The first type
 * (e.g., EGA, CGA), treats the screen as a page of characters and
 * has a hardware cursor.  The second type (e.g., the Blit) treats the
 * screen as a bitmap.  A hardware cursor may be present, but it is
 * ignored in favor of a software cursor.
 *
 *
 * Most of the driver uses the following abstraction for the display:
 *
 * The cursor position is simply an index into a (logical) linear char
 * array that wraps around at the end of each line.  Each character
 * takes up ONE_SPACE bytes.  Values in [0..ONE_PAGE) are positions in
 * the displayed page.  Values < 0 and >= ONE_PAGE are off the page
 * and require some scrolling to put the cursor back on the page.
 *
 * The kd_dxxx routines handle the conversion from this abstraction to
 * what the hardware requires.
 *
 * (*kd_dput)(pos, ch, chattr)
 *	csrpos_t pos;
 *	char ch, chattr;
 *  Displays a character at "pos", where "ch" = the character to
 *  be displayed and "chattr" is its attribute byte.
 *
 * (*kd_dmvup)(from, to, count)
 *	csrpos_t from, to;
 *	int count;
 *  Does a (relatively) fast block transfer of characters upward.
 *  "count" is the number of character positions (not bytes) to move.
 *  "from" is the character position to start moving from (at the start
 *  of the block to be moved).  "to" is the character position to start
 *  moving to.
 *
 * (*kd_dmvdown)(from, to, count)
 *	csrpos_t from, to;
 *	int count;
 *  "count" is the number of character positions (not bytes) to move.
 *  "from" is the character position to start moving from (at the end
 *  of the block to be moved).  "to" is the character position to
 *  start moving to.
 *
 * (*kd_dclear)(to, count, chattr)
 *	csrpos_t, to;
 *	int count;
 *	char chattr;
 *  Erases "count" character positions, starting with "to".
 *
 * (*kd_dsetcursor)(pos)
 *  Sets kd_curpos and moves the displayed cursor to track it.  "pos"
 *  should be in the range [0..ONE_PAGE).
 *  
 * (*kd_dreset)()
 *  In some cases, the boot program expects the display to be in a
 *  particular state, and doing a soft reset (i.e.,
 *  software-controlled reboot) doesn't put it into that state.  For
 *  these cases, the machine-specific driver should provide a "reset"
 *  procedure, which will be called just before the kd code causes the
 *  system to reboot.
 */

//ERICHACK#include <device/io_req.h>

/*
 * Globals used for both character-based controllers and bitmap-based
 * controllers.
 */

typedef	short	csrpos_t;	/* cursor position, ONE_SPACE bytes per char */
extern u_char 	*vid_start;	/* VM start of video RAM or frame buffer */
extern csrpos_t kd_curpos;		/* should be set only by kd_setpos */
extern short	kd_lines;		/* num lines in tty display */
extern short	kd_cols;
extern char	kd_attr;		/* current character attribute */


/*
 * Globals used only for bitmap-based controllers.
 * XXX - probably needs reworking for color.
 */

/*
 * The following font layout is assumed:
 *
 *  The top scan line of all the characters comes first.  Then the
 *  second scan line, then the third, etc.
 *
 *     ------ ... ---------|-----N--------|-------------- ... -----------
 *     ------ ... ---------|-----N--------|-------------- ... -----------
 *		.
 *		.
 *		.
 *     ------ ... ---------|-----N--------|-------------- ... -----------
 *
 * In the picture, each line is a scan line from the font.  Each scan
 * line is stored in memory immediately after the previous one.  The
 * bits between the vertical lines are the bits for a single character
 * (e.g., the letter "N").
 * There are "char_height" scan lines.  Each character is "char_width"
 * bits wide.  We make the simplifying assumption that characters are
 * on byte boundaries.  (We also assume that a byte is 8 bits.)
 */

extern u_char	*font_start;		/* starting addr of font */

extern short	fb_width;		/* bits in frame buffer scan line */
extern short	fb_height;		/* scan lines in frame buffer*/
extern short	char_width;		/* bit width of 1 char */
extern short	char_height;		/* bit height of 1 char */
extern short	chars_in_font;
extern short	cursor_height;		/* bit height of cursor */
			/* char_height + cursor_height = line_height */

extern u_char	char_black;		/* 8 black (off) bits */
extern u_char	char_white;		/* 8 white (on) bits */


/*
 * The tty emulation does not usually require the entire frame buffer.
 * (xstart, ystart) is the bit address for the upper left corner of the 
 * tty "screen".
 */

extern short	xstart, ystart;


/*
 * Accelerators for bitmap displays.
 */

extern short	char_byte_width;	/* char_width/8 */
extern short	fb_byte_width;		/* fb_width/8 */
extern short	font_byte_width;	/* num bytes in 1 scan line of font */

extern void		bmpput(
				csrpos_t	pos,
				char		ch,
				char		chattr);
extern void		bmpmvup(
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		bmpmvdown(
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		bmpclear(
				csrpos_t	to,
				int		count,
				char		chattr);
extern void		bmpsetcursor(
				csrpos_t	pos);

extern void		(*kd_dput)(		/* put attributed char */
				csrpos_t	pos,
				char		ch,
				char		chattr);
extern void		(*kd_dmvup)(		/* block move up */
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		(*kd_dmvdown)(		/* block move down */
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		(*kd_dclear)(		/* block clear */
				csrpos_t	to,
				int		count,
				char		chattr);
extern void		(*kd_dsetcursor)(
				/* set cursor position on displayed page */
				csrpos_t	pos);
extern void		(*kd_dreset)(void);	/* prepare for reboot */


#include <pexpert/i386/kd_entries.h>

extern void		kdintr(
				int		vec,
				int		regs);

#endif /* _PEXPERT_I386_KDSOFT_H_ */
