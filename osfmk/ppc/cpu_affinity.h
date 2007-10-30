/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifdef KERNEL_PRIVATE
#ifndef _PPC_CPU_AFFINITY_H_
#define _PPC_CPU_AFFINITY_H_

/*
 * Just one hardware affinity set - the whole machine.
 * This allows us to give the pretense that PPC supports the affinity policy
 * SPI. The kernel will accept affinity hints but effectively ignore them. 
 * Hence Universal Apps can use platform-independent code.
 */
static inline int ml_get_max_affinity_sets(void)
{
	return 1;
}

/*
 * Return the single processor set.
 */
static inline processor_set_t ml_affinity_to_pset(__unused int affinity_num)
{
	return processor_pset(master_processor);
}

#endif /* _I386_CPU_AFFINITY_H_ */
#endif /* KERNEL_PRIVATE */
