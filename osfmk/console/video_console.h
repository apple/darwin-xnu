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
 * @APPLE_FREE_COPYRIGHT@
 */

#ifndef _VIDEO_CONSOLE_H_
#define _VIDEO_CONSOLE_H_

#include <device/device_types.h>

int vcputc(	int		l,
		int		u,
		int		c );

int vcgetc(	int		l,
		int		u,
		boolean_t	wait,
		boolean_t	raw );

void video_scroll_up(	unsigned long	start,
			unsigned long	end,
			unsigned long	dest );

void video_scroll_down(	unsigned long	start,  /* HIGH addr */
			unsigned long	end,    /* LOW addr */
			unsigned long	dest ); /* HIGH addr */

struct vc_info
{
	unsigned long	v_height;	/* pixels */
	unsigned long	v_width;	/* pixels */
	unsigned long	v_depth;
	unsigned long	v_rowbytes;
	unsigned long	v_baseaddr;
	unsigned long	v_type;
	char		v_name[32];
	unsigned long	v_physaddr;
	unsigned long	v_rows;		/* characters */
	unsigned long	v_columns;	/* characters */
	unsigned long	v_rowscanbytes;	/* Actualy number of bytes used for display per row*/
	unsigned long	v_reserved[5];
};

#endif /* _VIDEO_CONSOLE_H_ */
