/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * @OSF_COPYRIGHT@
 */

#ifndef _NEW_SCREEN_H_
#define _NEW_SCREEN_H_

#include <ppc/boot.h>

/* AV and HPV cards */
#define	AV_BUFFER_START	   0xE0000000
#define	AV_BUFFER_END	   0xE0500000
#define	HPV_BUFFER_START   0xFE000000
#define	HPV_BUFFER_END	   0xFF000000

extern void clear_RGB16(int color);
extern void adj_position(unsigned char C);
extern void put_cursor(int color);
extern void screen_put_char(unsigned char C);
extern void initialize_screen(
		Boot_Video * boot_vinfo,
		unsigned int op);

#endif /* _NEW_SCREEN_H_ */
