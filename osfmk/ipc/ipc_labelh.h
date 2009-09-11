/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _IPC_LABELH_H_
#define _IPC_LABELH_H_

#include <kern/lock.h>
#include <ipc/ipc_port.h>
#include <security/_label.h>

#if CONFIG_MACF_MACH
typedef struct ipc_labelh
{
	natural_t         lh_references;
	int               lh_type;
	struct label      lh_label;
	ipc_port_t        lh_port;
	decl_lck_mtx_data(,	lh_lock_data)
} *ipc_labelh_t;

#define	LABELH_TYPE_KERN	0
#define	LABELH_TYPE_USER	1

void labelh_destroy(ipc_port_t port);
ipc_labelh_t labelh_duplicate(ipc_labelh_t old);
ipc_labelh_t labelh_modify(ipc_labelh_t old);
ipc_labelh_t labelh_new(int canblock);
kern_return_t labelh_new_user(ipc_space_t, struct label *, mach_port_name_t *);
void labelh_release(ipc_labelh_t lh);
ipc_labelh_t labelh_reference(ipc_labelh_t lh);

#define lh_reference(lh)	((lh)->lh_references++)
#define lh_release(lh)						\
MACRO_BEGIN							\
	assert((lh)->lh_references > 0);			\
	(lh)->lh_references--;					\
MACRO_END

extern zone_t ipc_labelh_zone;

#define lh_lock_init(lh)	lck_mtx_init(&(lh)->lh_lock_data, &ipc_lck_grp, &ipc_lck_attr)
#define lh_lock(lh)			lck_mtx_lock(&(lh)->lh_lock_data)
#define lh_unlock(lh)		lck_mtx_unlock(&(lh)->lh_lock_data)

/*
 * Check the number of references the label handle has left.
 * If there are 0 references and this is a kernel-allocated
 * label handle, deallocate the associated port.  The
 * storage space for the label handle will be deallocated
 * as part of the port destruction.  User-allocated label
 * handles are destroyed along with their ports.
 */
#define lh_check_unlock(lh)					\
MACRO_BEGIN							\
	_VOLATILE_ natural_t _refs = (lh)->lh_references;	\
								\
	lh_unlock(lh);						\
	if (_refs == 0 && (lh)->lh_type == LABELH_TYPE_KERN)	\
		ipc_port_dealloc_kernel((lh)->lh_port);		\
MACRO_END

#endif /* MAC_MACH */
#endif /* _IPC_LABELH_H_ */
