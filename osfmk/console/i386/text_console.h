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

#ifndef _TEXT_CONSOLE_H_
#define _TEXT_CONSOLE_H_

#define TEXT_MODE 0

void tc_paint_char(int x, int y, unsigned char ch, int attrs, unsigned char ch_previous, int attrs_previous);
void tc_scroll_down(int lines, int top, int bottom);
void tc_scroll_up(int lines, int top, int bottom);
void tc_clear_screen(int x, int y, int top, int bottom, int operation);
void tc_show_cursor(int x, int y);
void tc_hide_cursor(int x, int y); 
void tc_enable(boolean_t enable);
void tc_initialize(struct vc_info * vinfo_p);
void tc_update_color(int color, int fore);

#endif /* !_TEXT_CONSOLE_H_ */
