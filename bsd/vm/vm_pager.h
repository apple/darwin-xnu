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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 *	File:	vm_pager.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Copyright (C) 1986, Avadis Tevanian, Jr., Michael Wayne Young
 *	Copyright (C) 1985, Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Pager routine interface definition
 */

#ifndef	_VM_PAGER_
#define	_VM_PAGER_

#include <mach/boolean.h>

struct	pager_struct {
	boolean_t	is_device;
};
typedef	struct pager_struct	*vm_pager_t;
#define	vm_pager_null		((vm_pager_t) 0)

#define	PAGER_SUCCESS		0  /* page read or written */
#define	PAGER_ABSENT		1  /* pager does not have page */
#define	PAGER_ERROR		2  /* pager unable to read or write page */

#ifdef	KERNEL
typedef	int		pager_return_t;

vm_pager_t	vm_pager_allocate();
void		vm_pager_deallocate();
pager_return_t	vm_pager_get();
pager_return_t	vm_pager_put();
boolean_t	vm_pager_has_page();
#endif	/* KERNEL */

#endif	/* _VM_PAGER_ */
