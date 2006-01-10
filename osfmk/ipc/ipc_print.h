/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef _IPC_PRINT_H_
#define	_IPC_PRINT_H_

#if     MACH_KDB

#include <mach_kdb.h>

#include <mach/mach_types.h>
#include <mach/message.h>
#include <ipc/ipc_types.h>
#include <ddb/db_expr.h>

extern void ipc_pset_print(
			ipc_pset_t	pset);

extern void ipc_port_print(
			ipc_port_t	port,
			boolean_t	have_addr,
			db_expr_t	count,
			char		*modif);

extern void	ipc_kmsg_print(
			ipc_kmsg_t      kmsg);

extern void	ipc_msg_print(
		mach_msg_header_t       *msgh);

extern ipc_port_t ipc_name_to_data(
			task_t			task,
			mach_port_name_t	name);

#endif  /* MACH_KDB */

#endif	/* IPC_PRINT_H */
