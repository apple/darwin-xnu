/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <libsa/types.h>
 
unsigned kdp_vm_read( caddr_t, caddr_t, unsigned);
unsigned kdp_vm_write( caddr_t, caddr_t, unsigned);
unsigned kdp_copy_kmem( caddr_t, caddr_t, unsigned);
int	 kern_dump(void);

unsigned int not_in_kdp = 1; /* Cleared when we begin to access vm functions in kdp */

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

/* A stub until i386 support is added for remote kernel core dumps */
int kern_dump(void)
{
  return 0;
}
