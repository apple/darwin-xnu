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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.4.1  1995/02/23  17:31:45  alanl
 * 	DIPC:  Merge from nmk17b2 to nmk18b8.
 * 	[95/01/05            alanl]
 *
 * Revision 1.1.10.1  1994/12/01  20:43:40  dwm
 * 	mk6 CR801 - copyright marker not FREE_
 * 	[1994/12/01  19:25:52  dwm]
 * 
 * Revision 1.1.5.2  1994/09/10  21:47:18  bolinger
 * 	Merge up to NMK17.3
 * 	[1994/09/08  19:58:04  bolinger]
 * 
 * Revision 1.1.5.1  1994/06/21  19:43:06  dlb
 * 	Bring forward to NMK18
 * 	[1994/06/17  18:58:04  dlb]
 * 
 * Revision 1.1.2.2  1994/07/22  09:54:09  paire
 * 	Added vm_remap_remote prototype.
 * 	[94/07/05            paire]
 * 
 * Revision 1.1.2.1  1994/12/06  20:11:22  alanl
 * 	Initial revision.  Moved here from kern/norma_task.h to avoid a
 * 	name collision with the mig-generated kern/norma_task.h.
 * 	[94/12/05            mmp]
 * 
 * $EndLog$
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#ifndef	_KERN_NORMA_PROTOS_H_
#define	_KERN_NORMA_PROTOS_H_

extern void		task_copy_vm(
				ipc_port_t	host,
				vm_map_t	old_map,
				boolean_t	clone,
				boolean_t	kill_parent,
				ipc_port_t	to);

extern kern_return_t	vm_remap_remote(
				ipc_port_t	target_task_port,
				vm_offset_t	*target_address,
				vm_size_t	size,
				vm_offset_t	mask,
				boolean_t	anywhere,
				ipc_port_t	source_task_port,
				vm_offset_t	source_address,
				boolean_t	copy,
				vm_prot_t	*cur_protection,
				vm_prot_t	*max_protection,
				vm_inherit_t	inheritance);

#endif	/* _KERN_NORMA_PROTOS_H_ */
