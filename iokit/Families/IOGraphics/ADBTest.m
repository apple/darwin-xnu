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
#include <driverkit/IODevice.h>
#include <driverkit/IODeviceMaster.h>
#include <stdlib.h>

void main( void )
{
    IOReturn		err;
    IOString		kind;
    int			reg[ 2 ];
    int			retCount;
    IOObjectNumber	obj;
    int			i;

        err = _IOLookupByDeviceName( device_master_self(), "display@Display0",
		 &obj, &kind);
        printf("_IOLookupByDeviceName = %d\n", err );

        retCount = sizeof(int);
        err = _IOCallDeviceMethod( device_master_self(), obj,
                    "IOSMADBGetAVDeviceID:size:",
                    nil, 0,
                    &retCount,
                    &reg[ 1 ],
                    &retCount);
        printf("IOSMADBGetAVDeviceID(%d) = %08x\n", err, reg[ 1 ] );

	reg[0] = 0xff;
	reg[1] = 0xff;
        retCount = 0;
	err = _IOCallDeviceMethod( device_master_self(), obj,
                    "IOSMADBSetLogicalRegister:size:",
                    reg, sizeof( reg),
                    &retCount,
                    nil,
                    &retCount);
        printf("IOSMADBSetLogicalRegister(%d)\n", err );

	for( i = 0; i < 4; i++) {
            reg[0] = 0xff;
	    retCount = sizeof(int);
            err = _IOCallDeviceMethod( device_master_self(), obj,
                        "IOSMADBGetLogicalRegister:size:result:size:",
                        reg, sizeof( int),
                        &retCount,
                        &reg[ 1 ],
                        &retCount);
            printf("IOSMADBGetLogicalRegister(%d) = %08x\n", err, reg[ 1 ] );
	}
}
