/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#include  <driverkit/ppc/IOMacOSTypes.h>
#include "IOMacOSVideo.h"
#include <stdlib.h>

struct TimingToEDID {
    UInt32	timingID;
    UInt8	spare;
    UInt8	establishedBit;
    UInt16	standardTiming;
};
typedef struct TimingToEDID TimingToEDID;

#define MAKESTD(h,a,r)		( (((h/8)-31)<<8) | (a<<6) | (r-60) )

static const TimingToEDID timingToEDID[] = {
    { timingApple_512x384_60hz,		0, 0xff, MAKESTD(  512,1,60) },
    { timingApple_640x480_67hz,		0, 0x04, MAKESTD(  640,1,67) },
    { timingVESA_640x480_60hz,		0, 0x05, MAKESTD(  640,1,60) },
    { timingVESA_640x480_72hz ,		0, 0x03, MAKESTD(  640,1,72) },
    { timingVESA_640x480_75hz,		0, 0x02, MAKESTD(  640,1,75) },
    { timingVESA_640x480_85hz,		0, 0xff, MAKESTD(  640,1,85) },
    { timingApple_832x624_75hz,		0, 0x0d, MAKESTD(  832,1,75) },
    { timingVESA_800x600_56hz,		0, 0x01, MAKESTD(  800,1,56) },
    { timingVESA_800x600_60hz,		0, 0x00, MAKESTD(  800,1,60) },
    { timingVESA_800x600_72hz,		0, 0x0f, MAKESTD(  800,1,72) },
    { timingVESA_800x600_75hz,		0, 0x0e, MAKESTD(  800,1,75) },
    { timingVESA_800x600_85hz,		0, 0xff, MAKESTD(  800,1,85) },
    { timingVESA_1024x768_60hz,		0, 0x0b, MAKESTD( 1024,1,60) },
    { timingVESA_1024x768_70hz,		0, 0x0a, MAKESTD( 1024,1,70) },
    { timingVESA_1024x768_75hz,		0, 0x09, MAKESTD( 1024,1,75) },
    { timingVESA_1024x768_85hz,		0, 0xff, MAKESTD( 1024,1,85) },
    { timingApple_1024x768_75hz,	0, 0x09, MAKESTD( 1024,1,75) },
    { timingApple_1152x870_75hz,	0, 0x17, MAKESTD( 0000,0,00) },
    { timingVESA_1280x960_75hz,		0, 0xff, MAKESTD( 1280,1,75) },
    { timingVESA_1280x1024_60hz,	0, 0xff, MAKESTD( 1280,2,60) },
    { timingVESA_1280x1024_75hz,	0, 0x08, MAKESTD( 1280,2,75) },
    { timingVESA_1280x1024_85hz,	0, 0xff, MAKESTD( 1280,2,85) },
    { timingVESA_1600x1200_60hz,	0, 0xff, MAKESTD( 1600,1,60) },
    { timingVESA_1600x1200_65hz,	0, 0xff, MAKESTD( 1600,1,65) },
    { timingVESA_1600x1200_70hz,	0, 0xff, MAKESTD( 1600,1,70) },
    { timingVESA_1600x1200_75hz,	0, 0xff, MAKESTD( 1600,1,75) },
    { timingVESA_1600x1200_80hz,	0, 0xff, MAKESTD( 1600,1,80) }
};


void main( void )
{
    const TimingToEDID	*	lookTiming;

    lookTiming = timingToEDID;
    while( lookTiming < (timingToEDID + sizeof( timingToEDID) / sizeof( TimingToEDID))) {

	printf("%d 0x%x ", lookTiming->timingID, 
		*((unsigned int *)&lookTiming->spare) );
	lookTiming++;
    }
    printf("\n");
}

