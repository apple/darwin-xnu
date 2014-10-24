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
