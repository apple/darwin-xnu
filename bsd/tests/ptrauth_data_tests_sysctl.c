/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#if DEVELOPMENT || DEBUG
#if __has_feature(ptrauth_calls)

#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>


#include <mach/task.h>
#include <kern/task.h>
#include <sys/ubc_internal.h>

extern kern_return_t ptrauth_data_tests(void);

/*
 * Given an existing PAC pointer (ptr), its declaration type (decl), the (key)
 * used to sign it and the string discriminator (discr), extract the raw pointer
 * along with the signature and compare it with one computed on the fly
 * via ptrauth_sign_unauthenticated().
 *
 * If the two mismatch, return an error and fail the test.
 */
#define VALIDATE_PTR(decl, ptr, key, discr) { \
	decl raw = *(decl *)&(ptr);      \
	decl cmp = ptrauth_sign_unauthenticated(ptr, key, \
	        ptrauth_blend_discriminator(&ptr, ptrauth_string_discriminator(discr))); \
	if (cmp != raw) { \
	        printf("kern.run_pac_test: %s (%s) (discr=%s) is not signed as expected (%p vs %p)\n", #decl, #ptr, #discr, raw, cmp); \
	        kr = EINVAL; \
	} \
}

/*
 * Allocate the containing structure, and store a pointer to the desired member,
 * which should be subject to pointer signing.
 */
#define ALLOC_VALIDATE_DATA_PTR(structure, decl, member, discr) { \
	structure *tmp =  kheap_alloc(KHEAP_TEMP, sizeof(structure), Z_WAITOK | Z_ZERO); \
	if (!tmp) return ENOMEM; \
	tmp->member = (void*)0xffffffff41414141; \
	VALIDATE_DATA_PTR(decl, tmp->member, discr) \
	kheap_free(KHEAP_TEMP, tmp, sizeof(structure)); \
}

#define VALIDATE_DATA_PTR(decl, ptr, discr) VALIDATE_PTR(decl, ptr, ptrauth_key_process_independent_data, discr)

/*
 * Validate that a pointer that is supposed to be signed, is, and that the signature
 * matches based on signing key, location and discriminator
 */
static int
sysctl_run_ptrauth_data_tests SYSCTL_HANDLER_ARGS
{
	#pragma unused(arg1, arg2, oidp)

	unsigned int dummy;
	int error, changed, kr;
	error = sysctl_io_number(req, 0, sizeof(dummy), &dummy, &changed);
	if (error || !changed) {
		return error;
	}

	/* proc_t */
	ALLOC_VALIDATE_DATA_PTR(struct proc, void *, task, "proc.task");
	ALLOC_VALIDATE_DATA_PTR(struct proc, struct proc *, p_pptr, "proc.p_pptr");
	ALLOC_VALIDATE_DATA_PTR(struct proc, struct vnode *, p_textvp, "proc.p_textvp");
	ALLOC_VALIDATE_DATA_PTR(struct proc, struct pgrp *, p_pgrp, "proc.p_pgrp");

	/* cs_blob */
	ALLOC_VALIDATE_DATA_PTR(struct cs_blob, struct cs_blob *, csb_next, "cs_blob.csb_next");
	ALLOC_VALIDATE_DATA_PTR(struct cs_blob, const CS_CodeDirectory *, csb_cd, "cs_blob.csb_cd");
	ALLOC_VALIDATE_DATA_PTR(struct cs_blob, const char *, csb_teamid, "cs_blob.csb_teamid");
	ALLOC_VALIDATE_DATA_PTR(struct cs_blob, const CS_GenericBlob *, csb_entitlements_blob, "cs_blob.csb_entitlements_blob");
	ALLOC_VALIDATE_DATA_PTR(struct cs_blob, void *, csb_entitlements, "cs_blob.csb_entitlements");

	/* The rest of the tests live in osfmk/ */
	kr = ptrauth_data_tests();

	if (error == 0) {
		error = mach_to_bsd_errno(kr);
	}

	return kr;
}

SYSCTL_PROC(_kern, OID_AUTO, run_ptrauth_data_tests,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, sysctl_run_ptrauth_data_tests, "I", "");

#endif /*  __has_feature(ptrauth_calls) */
#endif /* DEVELOPMENT || DEBUG */
