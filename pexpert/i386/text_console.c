/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * text_console.c
 *
 * VGA text console support.
 */

#include <sys/types.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include "video_console.h"

/*
 * Macros and typedefs.
 */
typedef short  csrpos_t;    /* cursor position, ONE_SPACE bytes per char */

#define ONE_SPACE       2                       /* bytes per character */
#define ONE_LINE        (vga_cols * ONE_SPACE)  /* number of bytes in line */
#define ONE_PAGE        (vga_rows * ONE_LINE)   /* number of bytes in page */
#define SPACE_CHAR      0x20

#define VGA_FB_START    0x0b8000
#define VGA_FB_SIZE     0x8000
#define VGA_IDX_REG     0x3d4
#define VGA_IO_REG      0x3d5

/*
 * Commands sent to graphics adapter.
 */
#define VGA_C_LOW           0x0f    /* return low byte of cursor addr */
#define VGA_C_HIGH          0x0e    /* high byte */

/*
 * Attributes for character sent to display.
 */
#define VGA_ATTR_NORMAL     0x07
#define VGA_ATTR_REVERSE    0x70

/*
 * Convert from XY coordinate to a location in display memory.
 */
#define XY_TO_CSRPOS(x, y)    (((y) * vga_cols + (x)) * ONE_SPACE)

/*
 * Globals.
 */
static short    vga_idx_reg     = 0;   /* location of VGA index register */
static short    vga_io_reg      = 0;   /* location of VGA data register */
static short    vga_cols        = 80;  /* number of columns */
static short    vga_rows        = 25;  /* number of rows */
static char     vga_attr        = 0;   /* current character attribute */
static char     vga_attr_rev    = 0;   /* current reverse attribute */
static char *   vram_start      = 0;   /* VM start of VGA frame buffer */

/*
 * Functions in kdasm.s.
 */
extern void kd_slmwd(u_char * pos, int count,  u_short val);
extern void kd_slmscu(u_char * from, u_char * to, int count);
extern void kd_slmscd(u_char * from, u_char * to, int count);

/*
 * move_up
 *
 * Block move up for VGA.
 */
static void
move_up( csrpos_t  from,
         csrpos_t  to,
         int       count)
{
    kd_slmscu( vram_start + from, vram_start + to, count );
}

/*
 * move_down
 *
 * Block move down for VGA.
 */
static void
move_down( csrpos_t  from,
           csrpos_t  to,
           int       count )
{
    kd_slmscd( vram_start + from, vram_start + to, count );
}

/*
 * clear_block
 *
 * Fast clear for VGA.
 */
static void
clear_block( csrpos_t  start,
             int       size,
             char      attr)
{
    kd_slmwd( vram_start + start, size,
              ((unsigned short) attr << 8) + SPACE_CHAR);
}

/*
 * set_cursor_position
 *
 * This function sets the hardware cursor position
 * on the screen.
 */
static void
set_cursor_position( csrpos_t newpos )
{
    short curpos;  /* position, not scaled for attribute byte */

    curpos = newpos / ONE_SPACE;

    outb(vga_idx_reg, VGA_C_HIGH);
    outb(vga_io_reg, (u_char)(curpos >> 8));

    outb(vga_idx_reg, VGA_C_LOW);
    outb(vga_io_reg, (u_char)(curpos & 0xff));
}

/*
 * display_char
 *
 * Display attributed character for VGA (mode 3).
 */
static void
display_char( csrpos_t    pos,      /* where to put it */
              char        ch,       /* the character */
              char        attr )    /* its attribute */
{
    *(vram_start + pos)     = ch;
    *(vram_start + pos + 1) = attr;
}

/*
 * vga_init
 *
 * Initialize the VGA text console.
 */
static void
vga_init(int cols, int rows, unsigned char * addr)
{
    vram_start   = addr;
    vga_idx_reg  = VGA_IDX_REG;
    vga_io_reg   = VGA_IO_REG;
    vga_rows     = rows;
    vga_cols     = cols;
    vga_attr     = VGA_ATTR_NORMAL;
    vga_attr_rev = VGA_ATTR_REVERSE;

    set_cursor_position(0);
}

/*
 * tc_scrollup
 *
 * Scroll the screen up 'n' character lines.
 */
void
tc_scrollup( int lines )
{
    csrpos_t  to;
    csrpos_t  from;
    int       size;

    /* scroll up */
    to   = 0;
    from = ONE_LINE * lines;
    size = ( ONE_PAGE - ( ONE_LINE * lines ) ) / ONE_SPACE;
    move_up(from, to, size);

    /* clear bottom line */
    to   = ( ( vga_rows - lines) * ONE_LINE );
    size = ( ONE_LINE * lines ) / ONE_SPACE;
    clear_block(to, size, vga_attr);
}

/*
 * tc_scrolldown
 *
 * Scrolls the screen down 'n' character lines.
 */
void
tc_scrolldown( int lines )
{
    csrpos_t  to;
    csrpos_t  from;
    int       size;

    /* move down */
    to   = ONE_PAGE - ONE_SPACE;
    from = ONE_PAGE - ( ONE_LINE * lines ) - ONE_SPACE;
    size = ( ONE_PAGE - ( ONE_LINE * lines ) ) / ONE_SPACE;
    move_down(from, to, size);

    /* clear top line */
    to   = 0;
    size = ( ONE_LINE * lines ) / ONE_SPACE;
    clear_block(to, size, vga_attr);
}

/* Default colors for 16-color palette */
enum {
    kVGAColorBlack = 0,
    kVGAColorBlue,
    kVGAColorGreen,
    kVGAColorCyan,
    kVGAColorRed,
    kVGAColorMagenta,
    kVGAColorBrown,
    kVGAColorWhite,
    kVGAColorGray,
    kVGAColorLightBlue,
    kVGAColorLightGreen,
    kVGAColorLightCyan,
    kVGAColorLightRed,
    kVGAColorLightMagenta,
    kVGAColorLightBrown,
    kVGAColorBrightWhite
};

/*
 * tc_update_color
 *
 * Update the foreground / background color.
 */
void
tc_update_color( int color, int fore )
{
    unsigned char mask_on, mask_off;

    switch ( color )
    {
        case 1:  mask_on = kVGAColorRed;        break;
        case 3:  mask_on = kVGAColorLightBrown; break;
        case 4:  mask_on = kVGAColorBlue;       break;
        case 6:  mask_on = kVGAColorCyan;       break;
        default: mask_on = color;               break;
    }

    if ( fore )
    {
        mask_off = 0x0f;
    }
    else
    {
        mask_off = 0xf0;
        mask_on  <<= 4;
    }

    vga_attr     = (vga_attr & ~mask_off) | mask_on;

    vga_attr_rev = ( ((vga_attr << 4) & 0xf0) |
                     ((vga_attr >> 4) & 0x0f) );
}

/*
 * tc_show_cursor
 *
 * Show the hardware cursor.
 */
void
tc_show_cursor( int x, int y )
{
    set_cursor_position( XY_TO_CSRPOS(x, y) );
}

/*
 * tc_hide_cursor
 *
 * Hide the hardware cursor.
 */
void
tc_hide_cursor( int x, int y )
{
    return;
}

/*
 * tc_clear_screen
 *
 * Clear the entire screen, or a portion of the screen
 * relative to the current cursor position.
 */
void
tc_clear_screen(int x, int y, int operation)
{
    csrpos_t start;
    int      count;

    switch ( operation )
    {
        case 0:   /* To end of screen */
            start = XY_TO_CSRPOS(x, y);
            count = ONE_PAGE - start;
            break;
        case 1:   /* To start of screen */
            start = 0;
            count = XY_TO_CSRPOS(x, y) + ONE_SPACE;
            break;
        default:
        case 2:   /* Whole screen */
            start = 0;
            count = ONE_PAGE;
            break;
    }
    clear_block(start, count, vga_attr);
}

/*
 * tc_putchar
 *
 * Display a character on screen with the given coordinates,
 * and attributes.
 */
void
tc_putchar( unsigned char ch, int x, int y, int attrs )
{
    char my_attr = vga_attr;

    if ( attrs & 4 ) my_attr = vga_attr_rev;

    display_char( XY_TO_CSRPOS(x, y), ch, vga_attr );
}

/*
 * tc_initialize
 *
 * Must be called before any other exported functions.
 */
void
tc_initialize(struct vc_info * vinfo_p)
{
    vinfo_p->v_rows    = vinfo_p->v_height;
    vinfo_p->v_columns = vinfo_p->v_width;

    vga_init( vinfo_p->v_columns,
              vinfo_p->v_rows,
              (unsigned char *) vinfo_p->v_baseaddr);
}
