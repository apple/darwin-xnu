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

#ifndef __PEXPERT_VIDEO_CONSOLE_H
#define __PEXPERT_VIDEO_CONSOLE_H

/*
 * Video console properties.
 */
struct vc_info {
    unsigned long  v_height;    /* pixels */
    unsigned long  v_width;     /* pixels */
    unsigned long  v_depth;
    unsigned long  v_rowbytes;
    unsigned long  v_baseaddr;
    unsigned long  v_type;
    char           v_name[32];
    unsigned long  v_physaddr;
    unsigned long  v_rows;      /* characters */
    unsigned long  v_columns;   /* characters */
    unsigned long  v_rowscanbytes;  /* Actualy number of bytes used for display per row */
    unsigned long  v_reserved[5];
};

/*
 * From text_console.c
 */
extern void tc_putchar(unsigned char ch, int x, int y, int attrs);
extern void tc_scrolldown(int lines);
extern void tc_scrollup(int lines);
extern void tc_clear_screen(int x, int y, int operation);
extern void tc_show_cursor(int x, int y);
extern void tc_hide_cursor(int x, int y); 
extern void tc_initialize(struct vc_info * vinfo_p);
extern void tc_update_color(int color, int fore);

#endif /* !__PEXPERT_VIDEO_CONSOLE_H */
