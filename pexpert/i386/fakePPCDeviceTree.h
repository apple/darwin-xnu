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

unsigned long busRange[] = { 0, 0 };
unsigned long picAddress[] = { 0x00008000, 0x00000000, 0x00000000,
                                        0xC8000000, 0x00080000};

dt_init fakePPCDeviceTree[] = {
    NODE( 7, 2 ),
        PROP( "name", "device-tree"),
        PROP( "model", "Power Macintosh"),
        PROP( "compatible", "AAPL,9900\0MacRISC"),
        INTPROP( "AAPL,cpu-id", 0x39006086),
        INTPROP( "clock-frequency", 0x02FAF080),
        INTPROP( "#address-cells", 1),
        INTPROP( "#size-cells", 1),

        NODE( 1,0 ),
            PROP( "name", "ps2controller"),

        NODE( 3,0 ),
            PROP( "name", "display"),
            PROP( "model", "silly"),
            INTPROP( "AAPL,boot-display", 1),
#if 0
	NODE( 6,1 ),
            PROP( "name", "i386generic"),
            PROP( "device_type", "pci"),
            INTPROP( "#address-cells", 3),
            INTPROP( "#size-cells", 2),
	    PROP( "bus-range", busRange),
	    NULLPROP( "ranges" ),

	    NODE( 4, 0),
                PROP( "name", "i386pic"),
                PROP( "device_type", "pic"),
                PROP( "reg", picAddress),
                PROP( "assigned-addresses", picAddress),
#endif
    NODE( 0, 0),
};
