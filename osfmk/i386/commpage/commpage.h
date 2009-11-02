/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_COMMPAGE_H
#define _I386_COMMPAGE_H

#ifndef	__ASSEMBLER__
#include <stdint.h>
#endif /* __ASSEMBLER__ */

#ifdef	__ASSEMBLER__
#include <machine/asm.h>

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


extern	char	*commPagePtr;				// virt address of commpage in kernel map

extern	void	commpage_set_timestamp(uint64_t tbr,uint32_t secs,uint32_t usecs,uint32_t ticks_per_sec);

typedef struct {
	uint64_t	nt_base_tsc;
	uint64_t	nt_base_ns; 
	uint32_t	nt_scale;
	uint32_t	nt_shift;
	uint64_t	nt_check_tsc;
} commpage_nanotime_t;
extern  void	commpage_set_nanotime(commpage_nanotime_t *new_nanotime);

#endif	/* __ASSEMBLER__ */

#endif /* _I386_COMMPAGE_H */
