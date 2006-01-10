/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _PPC_COMMPAGE_H
#define _PPC_COMMPAGE_H

#ifndef	__ASSEMBLER__
#include <stdint.h>
#endif /* __ASSEMBLER__ */


/* Special check bits for the compage_descriptor "special" field. */
 
#define	kCommPageDCBA		0x0001			// this routine uses DCBA, map to NOP if not appropriate
#define	kCommPageSYNC		0x0002			// this routine uses SYNC, LWSYNC, or EIEIO, map to NOP if UP
#define kCommPageISYNC		0x0004			// this routine uses ISYNC, map to NOP if UP
#define	kCommPageMTCRF		0x0008			// set bit 11 in MTCRF if only 1 cr specified

#define kPort32to64			0x1000			// written for 32-bit, must port to 64-bit
#define kCommPage64			0x2000			// this routine is useable in 64-bit mode
#define kCommPage32			0x4000			// this routine is useable in 32-bit mode
#define kCommPageBoth		(kCommPage32+kCommPage64)


#ifdef	__ASSEMBLER__

#define	COMMPAGE_DESCRIPTOR(label,address,must,cant,special)	\
    .globl  EXT(label)  @\
LEXT(label)	@\
    .short	label-.	@\
    .short	.-label-2	@\
    .short	address	@\
    .short	special	@\
    .long	must    @\
    .long	cant
    

#else /* __ASSEMBLER__ */

/* Each potential commpage routine is described by one of these.
 * Note that the COMMPAGE_DESCRIPTOR macro (above), used in
 * assembly language, must agree with this.
 */
 
typedef	struct	commpage_descriptor	{
    short	code_offset;					// offset to code from this descriptor
    short	code_length;					// length in bytes
    short	commpage_address;				// put at this address (_COMM_PAGE_BCOPY etc)
    short	special;						// special handling bits for DCBA and SYNC etc
    long	musthave;						// _cpu_capability bits we must have
    long	canthave;						// _cpu_capability bits we can't have
} commpage_descriptor;


extern	char	*commPagePtr32;				// virt address of 32-bit commpage in kernel map
extern	char	*commPagePtr64;				// virt address of 64-bit commpage in kernel map


extern	void	commpage_set_timestamp(uint64_t tbr,uint32_t secs,uint32_t usecs,uint32_t ticks_per_sec);
extern	int		commpage_time_dcba( void );

#endif	/* __ASSEMBLER__ */

#endif /* _PPC_COMMPAGE_H */
