/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#ifndef _PEXPERT_I386_KD_ENTRIES_H_
#define _PEXPERT_I386_KD_ENTRIES_H_
/*
 * @OSF_COPYRIGHT@
 */
typedef int		io_return_t;
typedef unsigned int	dev_mode_t;
typedef unsigned int	dev_flavor_t;
typedef int		*dev_status_t;

extern io_return_t	kdopen(
				dev_t		dev,
				dev_mode_t	flag,
				io_req_t	ior);
extern void		kdclose(
				dev_t		dev);
extern io_return_t	kdread(
				dev_t		dev,
				io_req_t	ior);
extern io_return_t	kdwrite(
				dev_t		dev,
				io_req_t	ior);
extern vm_offset_t	kdmmap(
				dev_t		dev,
				vm_offset_t	off,
				vm_prot_t	prot);
extern boolean_t	kdportdeath(
				dev_t		dev,
				ipc_port_t	port);
extern io_return_t	kdgetstat(
				dev_t		dev,
				dev_flavor_t	flavor,
				dev_status_t	data,
				natural_t	*count);
extern io_return_t	kdsetstat(
				dev_t		dev,
				dev_flavor_t	flavor,
				dev_status_t	data,
				natural_t	count);
extern void		kd_cmdreg_write(
				u_char		val);
extern int		kd_mouse_write(
				u_char		val);
extern void		kd_mouse_read(
				int		no,
				char		* bufp);
extern void		kd_mouse_drain(void);
extern void		kdreboot(void);
extern void		bmpput(
				csrpos_t	pos,
				char		ch,
				char		chattr);
extern void		bmpmvup(
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		bmpmvdown(
				csrpos_t	from,
				csrpos_t	to,
				int		count);
extern void		bmpclear(
				csrpos_t	to,
				int		count,
				char		chattr);
extern void		bmpsetsetcursor(
				csrpos_t	pos);
extern void		kd_slmscu(
				u_char		* from,
				u_char		* to,
				int		count);
extern void		kd_slmscd(
				u_char		* from,
				u_char		* to,
				int		count);
extern void		kd_slmwd(
				u_char		* pos,
				int		count,
				u_short		val);
extern void		kd_sendcmd(
				u_char		c);

#endif /* _PEXPERT_POWERMAC_PDM_H_ */
