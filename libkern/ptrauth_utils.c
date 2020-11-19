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

#include <IOKit/IOLib.h>
#include <kern/debug.h> // for panic()

#include <libkern/ptrauth_utils.h>


#if __has_feature(ptrauth_calls)

/*
 * ptrauth_utils_sign_blob_generic
 *
 * Sign a blob of data with the GA key
 *
 */
ptrauth_generic_signature_t
ptrauth_utils_sign_blob_generic(void * ptr, size_t len_bytes, uint64_t data, int flags)
{
	ptrauth_generic_signature_t sig = 0;

	uint64_t rounds = len_bytes / sizeof(uintptr_t);
	size_t ntrailing = len_bytes % sizeof(uintptr_t);
	uintptr_t trailing = 0;

	if (ptr == NULL) {
		return 0;
	}

	/* If address diversification is requested, mix the blob address with the salt */
	if (flags & PTRAUTH_ADDR_DIVERSIFY) {
		data ^= (uint64_t)ptr;
	}

	/* First round adds salt */
	sig = ptrauth_sign_generic_data(sig, data);

	/* Calculate an additive signature of the buffer */
	for (uint64_t i = 0; i < rounds; i++) {
		sig = ptrauth_sign_generic_data(*(uintptr_t *)ptr, sig);
		ptr += sizeof(uintptr_t);
	}

	/* ptrauth_sign_generic_data operates on pointer-sized values only,
	 * so we need to handle trailing bytes for the non-pointer-aligned case */
	if (ntrailing) {
		memcpy(&trailing, ptr, ntrailing);
		sig = ptrauth_sign_generic_data(trailing, sig);
	}

	return sig;
}

/*
 * ptrauth_utils_auth_blob_generic
 *
 * Authenticate signature produced by ptrauth_utils_sign_blob_generic
 */
void
ptrauth_utils_auth_blob_generic(void * ptr, size_t len_bytes, uint64_t data, int flags, ptrauth_generic_signature_t signature)
{
	ptrauth_generic_signature_t calculated_signature = 0;

	if (ptr == NULL) {
		if (flags & PTRAUTH_NON_NULL) {
			panic("ptrauth_utils_auth_blob_generic: ptr must not be NULL");
		} else {
			return;
		}
	}

	if ((calculated_signature = ptrauth_utils_sign_blob_generic(ptr, len_bytes, data, flags)) == signature) {
		return;
	} else {
		panic("signature mismatch for %lu bytes at %p, calculated %lx vs %lx", len_bytes,
		    ptr,
		    calculated_signature,
		    signature);
	}
}

#endif //!ptrauth_calls
