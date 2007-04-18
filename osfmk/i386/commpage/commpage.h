/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_COMMPAGE_H
#define _I386_COMMPAGE_H

#ifndef	__ASSEMBLER__
#include <stdint.h>
#endif /* __ASSEMBLER__ */

/* The following macro is used to generate the 64-bit commpage address for a given
 * routine, based on its 32-bit address.  This is used in the kernel to compile
 * the 64-bit commpage.  Since the kernel is a 32-bit object, cpu_capabilities.h
 * only defines the 32-bit address.
 */
#define	_COMM_PAGE_32_TO_64( ADDRESS )	( ADDRESS + _COMM_PAGE64_START_ADDRESS - _COMM_PAGE32_START_ADDRESS )


#ifdef	__ASSEMBLER__

#define	COMMPAGE_DESCRIPTOR(label,address,must,cant)	\
L ## label ## _end:					;\
.const_data						;\
L ## label ## _size = L ## label ## _end - L ## label	;\
.private_extern _commpage_ ## label			;\
_commpage_ ## label ## :				;\
    .long	L ## label 				;\
    .long	L ## label ## _size			;\
    .long	address					;\
    .long	must					;\
    .long	cant					;\
.text

#else /* __ASSEMBLER__ */

/* Each potential commpage routine is described by one of these.
 * Note that the COMMPAGE_DESCRIPTOR macro (above), used in
 * assembly language, must agree with this.
 */
 
typedef	struct	commpage_descriptor	{
    void	*code_address;					// address of code
    long 	code_length;					// length in bytes
    long	commpage_address;				// put at this address (_COMM_PAGE_BCOPY etc)
    long	musthave;					// _cpu_capability bits we must have
    long	canthave;					// _cpu_capability bits we can't have
} commpage_descriptor;


extern	char	*commPagePtr32;				// virt address of 32-bit commpage in kernel map
extern	char	*commPagePtr64;				// ...and of 64-bit commpage

extern	void	_commpage_set_timestamp(uint64_t abstime, uint64_t secs);
#define commpage_set_timestamp(x, y, z)		_commpage_set_timestamp((x), (y))

extern  void	commpage_set_nanotime(uint64_t tsc_base, uint64_t ns_base, uint32_t scale, uint32_t shift);

#include <kern/page_decrypt.h>

#endif	/* __ASSEMBLER__ */

#endif /* _I386_COMMPAGE_H */
