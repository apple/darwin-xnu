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

extern dt_data gMemoryMapNode;
extern dt_data gDriversProp;

dt_init fakePPCDeviceTree[] =
{
    NODE( 2, 1 ),
        PROP( "name", "device-tree"),
        PROP( "compatible", "X86PC"),
        NODE( 1, 1 ),
            PROP( "name", "chosen" ),
            DATANODE( gMemoryMapNode ),
                PROP( "name", "memory-map" ),
                DATAPROP( gDriversProp ),
    NODE( 0, 0),
};
