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

#ifndef __CORETRUST_H
#define __CORETRUST_H

#include <os/base.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#if XNU_KERNEL_PRIVATE
/*
 * Only include this when building for XNU. CoreTrust will include its
 * local copy of the header.
 */
#include <coretrust/CTEvaluate.h>
#endif

/*
 * We add more definitions as the need for them arises. Please refer
 * to <coretrust/CTEvaluate.h> for more information.
 */

typedef int (*coretrust_CTEvaluateAMFICodeSignatureCMS_t)(
	const uint8_t *cms_data,
	size_t cms_data_length,
	const uint8_t *detached_data,
	size_t detached_data_length,
	bool allow_test_hierarchy,
	const uint8_t **leaf_certificate,
	size_t *leaf_certificate_length,
	CoreTrustPolicyFlags *policy_flags,
	CoreTrustDigestType *cms_digest_type,
	CoreTrustDigestType *hash_agility_digest_type,
	const uint8_t **digest_data,
	size_t *digest_length
	);

typedef struct _coretrust {
	coretrust_CTEvaluateAMFICodeSignatureCMS_t CTEvaluateAMFICodeSignatureCMS;
} coretrust_t;

__BEGIN_DECLS

/*!
 * @const coretrust
 * The CoreTrust interface that was registered.
 */
extern const coretrust_t *coretrust;

/*!
 * @function coretrust_interface_register
 * Registers the CoreTrust kext interface for use within the kernel proper.
 *
 * @param ct
 * The interface to register.
 *
 * @discussion
 * This routine may only be called once and must be called before late-const has
 * been applied to kernel memory.
 */
OS_EXPORT OS_NONNULL1
void
coretrust_interface_register(const coretrust_t *ct);

__END_DECLS

#endif // __CORETRUST_H
