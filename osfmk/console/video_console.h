/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

#ifndef _VIDEO_CONSOLE_H_
#define _VIDEO_CONSOLE_H_

#include <device/device_types.h>

void vcputc(int, int, int);

int vcgetc(	int		l,
		int		u,
		boolean_t	wait,
		boolean_t	raw );

void video_scroll_up(	void	*start,
			void	*end,
			void	*dest );

void video_scroll_down(	void	*start,  /* HIGH addr */
			void	*end,    /* LOW addr */
			void	*dest ); /* HIGH addr */

struct vc_info
{
	unsigned int	v_height;	/* pixels */
	unsigned int	v_width;	/* pixels */
	unsigned int	v_depth;
	unsigned int	v_rowbytes;
	unsigned long	v_baseaddr;
	unsigned int	v_type;
	char		v_name[32];
	unsigned long	v_physaddr;
	unsigned int	v_rows;		/* characters */
	unsigned int	v_columns;	/* characters */
	unsigned int	v_rowscanbytes;	/* Actualy number of bytes used for display per row*/
	unsigned int	v_reserved[5];
};

#endif /* _VIDEO_CONSOLE_H_ */
