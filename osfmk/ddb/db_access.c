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
#include <mach/boolean.h>
#include <machine/db_machdep.h>		/* type definitions */
#include <machine/setjmp.h>
#include <machine/endian.h>
#include <kern/task.h>
#include <ddb/db_access.h>



/*
 * Access unaligned data items on aligned (longword)
 * boundaries.
 */

int db_access_level = DB_ACCESS_LEVEL;

db_expr_t
db_get_task_value(
	db_addr_t	addr,
	register int	size,
	boolean_t	is_signed,
	task_t		task)
{
	char		data[sizeof(db_expr_t)];
	register db_expr_t value;
	register int	i;
	uint64_t signx;

	if(size == 0) return 0;

	db_read_bytes((vm_offset_t)addr, size, data, task);

	value = 0;
#if	BYTE_MSF
	for (i = 0; i < size; i++)
#else	/* BYTE_LSF */
	for (i = size - 1; i >= 0; i--)
#endif
	{
	    value = (value << 8) + (data[i] & 0xFF);
	}
	
	if(!is_signed) return value;
	
	signx = 0xFFFFFFFFFFFFFFFFULL << ((size << 3) - 1);
	 
	if(value & signx) value |= signx;	/* Add 1s to front if sign bit is on */

	return (value);
}

void
db_put_task_value(
	db_addr_t	addr,
	register int	size,
	register db_expr_t value,
	task_t		task)
{
	char		data[sizeof(db_expr_t)];
	register int	i;

#if	BYTE_MSF
	for (i = size - 1; i >= 0; i--)
#else	/* BYTE_LSF */
	for (i = 0; i < size; i++)
#endif
	{
	    data[i] = value & 0xFF;
	    value >>= 8;
	}

	db_write_bytes((vm_offset_t)addr, size, data, task);
}

db_expr_t
db_get_value(
	db_addr_t	addr,
	int		size,
	boolean_t	is_signed)
{
	return(db_get_task_value(addr, size, is_signed, TASK_NULL));
}

void
db_put_value(
	db_addr_t	addr,
	int		size,
	db_expr_t	value)
{
	db_put_task_value(addr, size, value, TASK_NULL);
}
