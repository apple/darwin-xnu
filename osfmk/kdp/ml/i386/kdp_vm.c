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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <libsa/types.h>
 
unsigned kdp_vm_read( caddr_t, caddr_t, unsigned);
unsigned kdp_vm_write( caddr_t, caddr_t, unsigned);
unsigned kdp_copy_kmem( caddr_t, caddr_t, unsigned);

/*
 *
 */
unsigned kdp_vm_read(
	caddr_t src, 
	caddr_t dst, 
	unsigned len)
{
	return kdp_copy_kmem(src, dst, len);
}

/*
 * 
 */
unsigned kdp_vm_write(
        caddr_t src,
        caddr_t dst,
        unsigned len)
{       
	return kdp_copy_kmem(src, dst, len);
}

