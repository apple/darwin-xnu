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
/*
 * Copyright (c) 1998-1999 Apple Software, Inc.
 *
 * Miscellaneous definitions for the Sun GEM Ethernet controller.
 *
 * HISTORY
 *
 */

#include "UniNEnetPrivate.h"


void xWriteUniNRegister( IOPPCAddress ioBaseEnet, u_int32_t reg_offset, u_int32_t data )
{
    switch ( reg_offset >> 16 )
    {
        case 1:
            ((u_int8_t *) ioBaseEnet)[reg_offset & 0xffff] = data;
            break;
        case 2:
            ((u_int16_t *)ioBaseEnet)[(reg_offset & 0xFFFF) >> 1] = OSSwapInt16( data );
            break; 
        case 4:
            ((u_int32_t *)ioBaseEnet)[(reg_offset & 0xFFFF) >> 2] = OSSwapInt32( data );
            break; 
    }
    eieio();
}


volatile u_int32_t xReadUniNRegister( IOPPCAddress ioBaseEnet, u_int32_t reg_offset )
{
    switch ( reg_offset >> 16 )
    {
        case 1:
            return ((u_int8_t *) ioBaseEnet)[reg_offset & 0xffff];
       
        case 2:
            return OSSwapInt16( ((u_int16_t *)ioBaseEnet)[(reg_offset & 0xFFFF) >> 1] );
 
        case 4:
            return OSSwapInt32( ((u_int32_t *)ioBaseEnet)[(reg_offset & 0xFFFF) >> 2] );
    }

    return 0;
}


/*
 * Procedure for reading EEPROM 
 */
