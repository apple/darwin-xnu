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
 * Revision 1.1.4.1  1996/02/02  12:16:46  emcmanus
 * 	Copied from nmk20b5_shared.
 * 	[1996/02/01  16:56:16  emcmanus]
 *
 * Revision 1.1.2.1  1995/12/30  17:12:11  emcmanus
 * 	Renamed from i386/etap_map.h and fixed parentheses in ETAP_MAX_DEVICES.
 * 	[1995/12/30  17:04:00  emcmanus]
 * 
 * Revision 1.1.2.4  1995/10/09  17:07:25  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:48:18  joe]
 * 
 * Revision 1.1.2.3  1995/09/18  19:10:09  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:48:18  joe]
 * 
 * Revision 1.1.2.2  1995/01/10  04:52:03  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	tweak protos, a la osc1.3b26
 * 	[1994/12/09  20:38:34  dwm]
 * 
 * 	mk6 CR801 - new file for mk6_shared from cnmk_shared.
 * 	[1994/12/01  21:11:38  dwm]
 * 
 * Revision 1.1.2.1  1994/10/21  18:36:01  joe
 * 	Initial ETAP submission
 * 	[1994/10/20  19:21:40  joe]
 * 
 * $EndLog$
 */
/*
 * File : etap_map.h
 */

#ifndef	_ETAP_MAP_H_
#define _ETAP_MAP_H_ 

#define ETAP_MAX_DEVICES  (3+NCPUS)


extern io_return_t	etap_map_open(
				 dev_t		dev,
				 dev_mode_t	flags,
				 io_req_t	ior);

extern vm_offset_t	etap_map_mmap(
				 dev_t		dev,
				 vm_offset_t	off,
				 vm_prot_t	prot);

#endif	/* _ETAP_MAP_H_ */
