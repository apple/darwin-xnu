/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:36  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:37  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.7.1  1994/09/23  01:54:44  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:23:10  ezf]
 *
 * Revision 1.1.2.2  1993/08/24  09:39:55  rod
 * 	Created for iX86 common high resolution clock common code.  CR #9400.
 * 	[1993/08/17  11:26:08  rod]
 * 
 * $EndLog$
 */

#include <vm/pmap.h>
#include <i386/hi_res_clock.h>

extern int *high_res_clock;

vm_offset_t
hi_res_clk_mmap(
	dev_t		dev,
	vm_offset_t	off,
	int		prot)
{
               if (prot & VM_PROT_WRITE) return (-1);
               return (i386_btop(pmap_extract(pmap_kernel(), 
		                              (vm_offset_t) high_res_clock)));
}
