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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
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
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */
/*
 * Data access functions for debugger.
 */

#ifndef	_DDB_DB_ACCESS_H_
#define	_DDB_DB_ACCESS_H_

#include <mach/boolean.h>
#include <machine/db_machdep.h>
#include <ddb/db_task_thread.h>

/* implementation dependent access capability */
#define	DB_ACCESS_KERNEL	0	/* only kernel space */
#define DB_ACCESS_CURRENT	1	/* kernel or current task space */
#define DB_ACCESS_ANY		2	/* any space */

#ifndef	DB_ACCESS_LEVEL
#define DB_ACCESS_LEVEL		DB_ACCESS_KERNEL
#endif	/* DB_ACCESS_LEVEL */

#ifndef DB_VALID_KERN_ADDR
#define DB_VALID_KERN_ADDR(addr)	((addr) >= VM_MIN_KERNEL_ADDRESS \
					  && (addr) < VM_MAX_KERNEL_ADDRESS)
#define DB_VALID_ADDRESS(addr,user)	((user != 0) ^ DB_VALID_KERN_ADDR(addr))
#define DB_PHYS_EQ(task1,addr1,task2,addr2)	0
#define DB_CHECK_ACCESS(addr,size,task)	db_is_current_space(task)
#endif	/* DB_VALID_KERN_ADDR */

extern int db_access_level;



/* Prototypes for functions exported by ddb/db_access.c.
 */
db_expr_t db_get_task_value(
	db_addr_t	addr,
	register int	size,
	boolean_t	is_signed,
	task_t		task);

void db_put_task_value(
	db_addr_t	addr,
	register int	size,
	register db_expr_t value,
	task_t		task);

db_expr_t db_get_value(
	db_addr_t	addr,
	int		size,
	boolean_t	is_signed);

void db_put_value(
	db_addr_t	addr,
	int		size,
	db_expr_t	value);

#endif	/* !_DDB_DB_ACCESS_H_ */
