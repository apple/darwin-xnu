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
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1996/09/17  16:26:58  bruel
 * 	use standalone includes only
 * 	[1996/09/17  15:38:08  bruel]
 *
 * Revision 1.1.4.1  1996/02/02  12:16:40  emcmanus
 * 	Copied from nmk20b5_shared.
 * 	[1996/02/01  16:56:11  emcmanus]
 * 
 * Revision 1.1.2.1  1995/12/30  17:12:07  emcmanus
 * 	Renamed from i386/etap_map.c and made this file machine-independent.
 * 	Delete declarations of event_table and subs_table, now declared with
 * 	different types in etap_macros.h.
 * 	[1995/12/30  17:03:55  emcmanus]
 * 
 * Revision 1.1.2.4  1995/10/09  17:07:21  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:48:15  joe]
 * 
 * Revision 1.1.2.3  1995/09/18  19:10:05  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:48:15  joe]
 * 
 * Revision 1.1.2.2  1995/01/10  04:51:59  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	tweak signatures, a la osc1.3b26
 * 	[1994/12/09  20:38:32  dwm]
 * 
 * 	mk6 CR801 - new file for mk6_shared from cnmk_shared.
 * 	[1994/12/01  21:11:35  dwm]
 * 
 * Revision 1.1.2.1  1994/10/21  18:35:57  joe
 * 	Initial ETAP submission
 * 	[1994/10/20  19:21:39  joe]
 * 
 * $EndLog$
 */
/*
 * File :  etap_map.c
 * 
 *	   Pseudo-device driver to calculate the virtual addresses
 *         of all mappable ETAP buffers and tables: event table, 
 *         subsystem table, cumulative buffer and monitor buffers.
 *
 */
/*
 * Minor device number representation:
 * 
 * 	0       = ETAP_TABLE_EVENT
 * 	1       = ETAP_TABLE_SUBSYSTEM
 *     	2       = ETAP_BUFFER_CUMULATIVE
 *     	3 & up  = a specific monitor buffer
 *
 */

#include <types.h>

#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <mach/kern_return.h>
#include <vm/pmap.h>
#include <device/io_req.h>
#include <device/dev_hdr.h>

#include <cpus.h>
#include <kern/etap_options.h>
#include <mach/etap.h>
#include <kern/etap_map.h>


#if     ETAP_LOCK_ACCUMULATE
extern	cumulative_buffer_t 	cbuff;
#endif  /* ETAP_LOCK_ACCUMULATE */

#if     ETAP_MONITOR
extern	monitor_buffer_t	mbuff[];
#endif  /* ETAP_MONITOR */


/*
 * etap_map_open - Check for valid minor device
 */

io_return_t
etap_map_open(
        dev_t           dev,
        dev_mode_t      flags,
        io_req_t        ior)
{	
	int buffer = minor(dev);

	if (buffer >= ETAP_MAX_DEVICES)
		return(D_NO_SUCH_DEVICE);

	return(D_SUCCESS);
}

vm_offset_t
etap_map_mmap (
        dev_t		dev,
        vm_offset_t	off,
        vm_prot_t 	prot)
{
	int		buffer = minor(dev);
	vm_offset_t 	addr;

	/*
	 *  Check request validity
	 */
    
	if (prot & VM_PROT_WRITE)
		return(KERN_PROTECTION_FAILURE);

	if (buffer < 0 || buffer >= ETAP_MAX_DEVICES)
		return(KERN_INVALID_ARGUMENT);

	switch(buffer) {
		case ETAP_TABLE_EVENT : 
			addr = trunc_page((char *) event_table) + off;
			break;
		case ETAP_TABLE_SUBSYSTEM :
			addr = trunc_page((char *) subs_table) + off;
			break;
		case ETAP_BUFFER_CUMULATIVE :
#if     ETAP_LOCK_ACCUMULATE
			addr = (vm_offset_t) cbuff + off;
			break;
#else 	/* ETAP_LOCK_ACCUMULATE */
			return(KERN_INVALID_ARGUMENT);
#endif	/* ETAP_LOCK_ACCUMULATE */

		default :
#if	ETAP_MONITOR
			addr = (vm_offset_t) mbuff[buffer - 3] + off;
			break;
#else	/* ETAP_MONITOR */
			return(KERN_INVALID_ARGUMENT);
#endif	/* ETAP_MONITOR */

	}
	return machine_btop(pmap_extract(pmap_kernel(), addr));
}
