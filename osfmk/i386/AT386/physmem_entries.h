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
 * Revision 1.1.1.1  1998/09/22 21:05:39  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:38  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.4.1  1996/11/29  16:56:56  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Created. Prototypes for the "physmem" device.
 * 	[1996/11/22  15:25:06  barbou]
 *
 * $EndLog$
 */

extern io_return_t	physmem_open(
				dev_t		dev,
				dev_mode_t	flag,
				io_req_t	ior);
extern void		physmem_close(
				dev_t		dev);
extern io_return_t	physmem_read(
				dev_t		dev,
				io_req_t	ior);
extern io_return_t	physmem_write(
				dev_t		dev,
				io_req_t	ior);
extern io_return_t	physmem_getstat(
				dev_t		dev,
				dev_flavor_t	flavor,
				dev_status_t	data,
				mach_msg_type_number_t * count);
extern io_return_t	physmem_setstat(
				dev_t		dev,
				dev_flavor_t	flavor,
				dev_status_t	data,
				mach_msg_type_number_t	count);
extern vm_offset_t	physmem_mmap(
				dev_t		dev,
				vm_offset_t	off,
				vm_prot_t	prot);
extern io_return_t	phsymem_async_in(
				dev_t		dev,
				ipc_port_t	rcv_port,
				int		pri,
				filter_t	*filter,
				mach_msg_type_number_t fcount,
				device_t	device);
extern void		physmem_reset(
				dev_t		dev);
extern boolean_t	phsymem_port_death(
				dev_t		dev,
				ipc_port_t	port);
extern io_return_t	physmem_dev_info(
				dev_t		dev,
				dev_flavor_t	flavor,
				char		* info);
