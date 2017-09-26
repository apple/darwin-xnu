/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
//
//cc scalegear.c -framework Accelerate -g -Wall */

#include <stdio.h>
#include <stdlib.h>
#include <Accelerate/Accelerate.h>

#include "../../../pexpert/pexpert/GearImage.h"

int main(int argc, char * argv[])
{
    vImage_Buffer vs;
    vImage_Buffer vd;
    vImage_Error  verr;
    uint32_t      i, data32;
    uint8_t       data8;

    vs.width  = kGearWidth * 2;
    vs.height = kGearHeight * 2 * kGearFrames;
    vs.rowBytes  = vs.width * sizeof(uint32_t);
    vs.data = malloc(vs.height * vs.rowBytes);

    vd.width  = 1.5 * vs.width;
    vd.height = 1.5 * vs.height;
    vd.rowBytes  = vd.width * sizeof(uint32_t);
    vd.data = malloc(vd.height * vd.rowBytes);

    for (i = 0; i < vs.width * vs.height; i++)
    {
    	data32 = gGearPict2x[i];
    	data32 = (0xFF000000 | (data32 << 16) | (data32 << 8) | data32);
    	((uint32_t *)vs.data)[i] = data32;
    }

    verr = vImageScale_ARGB8888(&vs, &vd, NULL, kvImageHighQualityResampling);

    if (kvImageNoError != verr) exit(1);

    printf("const unsigned char gGearPict3x[9*kGearFrames*kGearWidth*kGearHeight] = {");

    for (i = 0; i < vd.width * vd.height; i++)
    {
    	data32 = ((uint32_t *)vd.data)[i];
	data8 = (0xFF & data32);
    	if (data32 != (0xFF000000 | (data8 << 16) | (data8 << 8) | data8)) exit(1);

 	if (0 == (15 & i)) printf("\n    ");
	printf("0x%02x,", data8);
    }
    printf("\n};\n");

    exit(0);
}
