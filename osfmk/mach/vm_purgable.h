/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 *	Virtual memory map purgable object definitions.
 *
 */

#ifndef	_MACH_VM_PURGABLE_H_
#define	_MACH_VM_PURGABLE_H_

/*
 *	Types defined:
 *
 *	vm_purgable_t	purgable object control codes.
 */

typedef int	vm_purgable_t;

/*
 *	Enumeration of valid values for vm_purgable_t.
 */
#define VM_PURGABLE_SET_STATE	((vm_purgable_t) 0)	/* set state of purgable object */
#define VM_PURGABLE_GET_STATE	((vm_purgable_t) 1)	/* get state of purgable object */

/*
 * Valid states of a purgable object.
 */
#define VM_PURGABLE_STATE_MIN	0			/* minimum purgable object state value */
#define VM_PURGABLE_STATE_MAX	2			/* maximum purgable object state value */

#define VM_PURGABLE_NONVOLATILE	0			/* purgable object is non-volatile */
#define VM_PURGABLE_VOLATILE	1			/* purgable object is volatile */
#define VM_PURGABLE_EMPTY	2			/* purgable object is volatile and empty */

#endif	/* _MACH_VM_PURGABLE_H_ */
