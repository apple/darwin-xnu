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
 * Copyright (c) 1998-1999 by Apple Computer, Inc., All rights reserved.
 *
 * Interface for hardware dependent (relatively) code 
 * for the BMac Ethernet chip 
 *
 * HISTORY
 *
 */

#ifndef _BMACENETPRIVATE_H
#define _BMACENETPRIVATE_H

#include "BMacEnet.h"
#include "BMacEnetMII.h"

void WriteBigMacRegister( IOPPCAddress ioEnetBase, u_int32_t reg_offset, 
	u_int16_t data);

volatile u_int16_t ReadBigMacRegister( IOPPCAddress ioEnetBase,
	u_int32_t reg_offset);

void reset_and_select_srom(IOPPCAddress base);

u_int16_t read_srom(IOPPCAddress base, unsigned int addr,
	unsigned int addr_len);

#endif /* !_BMACENETPRIVATE_H */
