/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Sym8xxMisc.m created by russb2 on Sat 30-May-1998 */

#include "Sym8xxController.h"

/*
 * Miscellaneous IO worker routines
 */

UInt32 Sym8xxSCSIController::Sym8xxReadRegs( volatile UInt8 *chipRegs, UInt32 regOffset, UInt32 regSize )
{
    if ( regSize == 1 )
    {
        return chipRegs[regOffset];
    }
    if ( regSize == 2 )
    {
        return OSSwapHostToLittleInt16( *(volatile u_int16_t *)&chipRegs[regOffset] );
    }
    else if (regSize == 4 )
    {
        return OSSwapHostToLittleInt32( *(volatile UInt32 *)&chipRegs[regOffset] );
    }
    else
    {
        kprintf("SCSI(SymBios875): Sym8xxReadRegs incorrect regSize\n\r" );
        return 0;
    } 
}

void Sym8xxSCSIController::Sym8xxWriteRegs( volatile UInt8 *chipRegs, UInt32 regOffset, UInt32 regSize, UInt32 regValue )
{
    if ( regSize == 1 )
    {
        chipRegs[regOffset] = regValue;
    }
    else if ( regSize == 2 )
    {
        volatile u_int16_t *p = (volatile u_int16_t *)&chipRegs[regOffset];
        *p = OSSwapHostToLittleInt16( regValue );
    }
    else if ( regSize == 4 )
    {
        volatile UInt32 *p = (volatile UInt32 *)&chipRegs[regOffset];
        *p = OSSwapHostToLittleInt32( regValue );
    }
    else
    {
        kprintf("SCSI(SymBios875): Sym8xxWriteRegs incorrect regSize\n\r" );
    }
    eieio();
}
