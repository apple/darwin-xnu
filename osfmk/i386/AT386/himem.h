/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:38  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:39  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.3.11.4  1995/12/15  10:49:49  bernadat
 * 	cbus includes moved to busses/cbus
 * 	[95/12/15            bernadat]
 *
 * Revision 1.3.11.3  1995/08/21  20:33:23  devrcs
 * 	ri-osc CR1547:  Fix himem buffer translation to cope with non
 * 	page-aligned addresses.
 * 	[1995/08/08  16:52:06  bolinger]
 * 
 * Revision 1.3.11.2  1995/01/26  22:14:56  ezf
 * 	removed extraneous CMU CR
 * 	[1995/01/26  20:24:48  ezf]
 * 
 * Revision 1.3.9.2  1994/06/08  21:14:27  dswartz
 * 	Preemption merge.
 * 	[1994/06/08  21:12:31  dswartz]
 * 
 * Revision 1.3.9.1  1994/05/19  20:30:30  dwm
 * 	mk6 CR 80.  Add himem_init prototype.
 * 	[1994/05/19  20:30:10  dwm]
 * 
 * Revision 1.3.2.3  1993/08/09  19:37:21  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:50:06  dswartz]
 * 
 * Revision 1.3.2.2  1993/06/09  02:25:24  gm
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  18:58:40  jeffc]
 * 
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:01:57  jeffc]
 * 
 * Revision 1.3  1993/04/19  16:09:54  devrcs
 * 	Use free copyright
 * 	[1993/03/03  12:12:12  bernadat]
 * 
 * Revision 1.2  1992/11/25  01:07:16  robert
 * 	integrate changes below for norma_14
 * 	[1992/11/13  19:28:57  robert]
 * 
 * $EndLog$
 */

#ifndef _I386AT_HIMEM_H_
#define _I386AT_HIMEM_H_

/*
 * support of memory above 16 Megs for DMA limited to memory
 * below 16 Megs.
 */

#include <platforms.h>

#define HIMEM_STATS 0

#if	HIMEM_STATS
extern int himem_request;
extern int himem_used;
#endif	/* HIMEM_STATS */

struct himem_link {
	struct himem_link *next;
	vm_offset_t	high_addr;	/* physical address */
	vm_offset_t	low_page;	/* physical page */
	vm_offset_t offset;		/* offset on page */
	vm_size_t	length;
};
 
typedef struct himem_link *hil_t;	


#define HIGH_MEM		((vm_offset_t) 0xf00000)

#define _high_mem_page(x)	((vm_offset_t)(x) >= HIGH_MEM)


#if	HIMEM_STATS
#define high_mem_page(x) \
	(++himem_request && _high_mem_page(x) && ++himem_used)

#else	/* HIMEM_STATS */
#define high_mem_page(x) 	_high_mem_page(x)
#endif	/* HIMEM_STATS */

extern void		himem_init(void);
extern void		himem_reserve(
				int		npages);
extern vm_offset_t	himem_convert(
				vm_offset_t	paddr,
				vm_size_t	len,
				int		op,
				hil_t		* hil);
extern void		himem_revert(
				hil_t		hil);

#endif /* _I386AT_HIMEM_H_ */
