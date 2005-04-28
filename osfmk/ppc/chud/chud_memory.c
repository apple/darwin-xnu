/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/vm_param.h>
#include <ppc/chud/chud_xnu.h>
#include <ppc/machine_routines.h>

__private_extern__
uint64_t chudxnu_avail_memory_size(void)
{
    return mem_size;
}

__private_extern__
uint64_t chudxnu_phys_memory_size(void)
{
    return mem_actual;
}

__private_extern__
vm_offset_t chudxnu_io_map(uint64_t phys_addr, vm_size_t size)
{
    return ml_io_map(phys_addr, size); // XXXXX limited to first 2GB XXXXX
}

__private_extern__
uint32_t chudxnu_phys_addr_wimg(uint64_t phys_addr)
{
    return IODefaultCacheBits(phys_addr);
}
