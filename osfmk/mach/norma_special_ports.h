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
/*
 */
/*
 *	File:	mach/norma_special_ports.h
 *
 *	Defines codes for remote access to special ports.  These are NOT
 *	port identifiers - they are only used for the norma_get_special_port
 *	and norma_set_special_port routines.
 */

#ifndef	_MACH_NORMA_SPECIAL_PORTS_H_
#define _MACH_NORMA_SPECIAL_PORTS_H_

#define	MAX_SPECIAL_KERNEL_ID	10
#define	MAX_SPECIAL_ID		40

/*
 * Provided by kernel
 */
#define NORMA_DEVICE_PORT	1
#define NORMA_HOST_PORT		2
#define NORMA_HOST_PRIV_PORT	3

/*
 * Not provided by kernel
 */
#define NORMA_NAMESERVER_PORT	(1 + MAX_SPECIAL_KERNEL_ID)

/*
 * Definitions for ease of use.
 *
 * In the get call, the host parameter can be any host, but will generally
 * be the local node host port. In the set call, the host must the per-node
 * host port for the node being affected.
 */

#define norma_get_device_port(host, node, port)	\
	(norma_get_special_port((host), (node), NORMA_DEVICE_PORT, (port)))

#define norma_set_device_port(host, port)	\
	(norma_set_special_port((host), NORMA_DEVICE_PORT, (port)))

#define norma_get_host_port(host, node, port)	\
	(norma_get_special_port((host), (node), NORMA_HOST_PORT, (port)))

#define norma_set_host_port(host, port)	\
	(norma_set_special_port((host), NORMA_HOST_PORT, (port)))

#define norma_get_host_priv_port(host, node, port)	\
	(norma_get_special_port((host), (node), NORMA_HOST_PRIV_PORT, (port)))

#define norma_set_host_priv_port(host, port)	\
	(norma_set_special_port((host), NORMA_HOST_PRIV_PORT, (port)))

#define norma_get_nameserver_port(host, node, port)	\
	(norma_get_special_port((host), (node), NORMA_NAMESERVER_PORT, (port)))

#define norma_set_nameserver_port(host, port)	\
	(norma_set_special_port((host), NORMA_NAMESERVER_PORT, (port)))

#endif	/* _MACH_NORMA_SPECIAL_PORTS_H_ */
