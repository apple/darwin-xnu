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

#include <pexpert/GearImage.h>


#warning shared video_console.c
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
};
typedef struct vc_progress_element vc_progress_element;

struct boot_progress_element {
    unsigned int	width;
    unsigned int	height;
    int			yOffset;
    unsigned int	res[5];
    unsigned char	data[0];
};
typedef struct boot_progress_element boot_progress_element;


static const unsigned char * default_progress_data = gGearPict;
static const unsigned char * default_noroot_data = 0;

static vc_progress_element default_progress = 
	{   0, 4|1, 1000 / kGearFPS, kGearFrames, {0, 0, 0}, 
            kGearWidth, kGearHeight, 0, kGearOffset,
            0, {0, 0, 0} };

static vc_progress_element default_noroot = 
	{   0, 1, 0, 0, {0, 0, 0}, 
            128, 128, 0, 0,
	    -1, {0, 0, 0} };
