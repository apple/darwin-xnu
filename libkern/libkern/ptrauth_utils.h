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

#ifndef __PTRAUTH_UTILS_H
#define __PTRAUTH_UTILS_H

#include <ptrauth.h>

/* ptrauth_utils flags */
#define PTRAUTH_ADDR_DIVERSIFY  0x0001  /* Mix storage address in to signature */
#define PTRAUTH_NON_NULL        0x0002  /* ptr must not be NULL */

/* ptrauth_utils_sign_blob_generic
 *
 * Description:	Sign a blob of data with the GA key and extra data, optionally
 * diversified by its storage address.
 *
 * Caveat: A race window exists between the blob being written to memory and its signature being
 * calculated by this function. In normal operation, standard thread safety semantics prevent this being
 * an issue, however in the malicious case it should be acknowledged that an attacker may be able to accurately
 * time overwriting parts/all of the blob and we would generate a signature for that modified data. It is
 * therefore important that users of this API minimise that window by calculating signatures immediately
 * after modification to the blob.
 *
 *
 * Parameters:	ptr				Address of data to sign
 *				len_bytes		Length in bytes of data to sign
 *				data			Salt to mix in signature when signing
 *				flags               Signing options
 *
 * Returns:		ptrauth_generic_signature_t		Signature of blob
 *
 */
#if __has_feature(ptrauth_calls)
ptrauth_generic_signature_t
ptrauth_utils_sign_blob_generic(void * ptr, size_t len_bytes, uint64_t data, int flags);
#else
static inline ptrauth_generic_signature_t
ptrauth_utils_sign_blob_generic(__unused void * ptr, __unused size_t len_bytes, __unused uint64_t data, __unused int flags)
{
	return 0;
}
#endif // __has_feature(ptrauth_calls)


/* ptrauth_utils_auth_blob_generic
 *
 * Description:	Authenticates a signature for a blob of data
 *
 * Caveat: As with ptrauth_utils_sign_blob_generic, an attacker who is able to accurately time access between
 * authenticating blobs and its use may be able to modify its contents. Failure to time this correctly will
 * result in a panic. Care should be taken to authenticate immediately before reading data from the blob to
 * minimise this window.
 *
 * Parameters:	ptr				Address of data being authenticated
 *				len_bytes		Length of data being authenticated
 *				data			Salt to mix with digest when authenticating
 *				flags           Signing options
 *				signature		The signature to verify
 *
 * Returns:		void			If the function returns, the authentication succeeded,
 *								else we panic as something's gone awry
 *
 */
#if __has_feature(ptrauth_calls)
void
ptrauth_utils_auth_blob_generic(void * ptr, size_t len_bytes, uint64_t data, int flags, ptrauth_generic_signature_t signature);
#else
static inline void
ptrauth_utils_auth_blob_generic(__unused void * ptr, __unused size_t len_bytes, __unused uint64_t data, __unused int flags, __unused ptrauth_generic_signature_t signature)
{
	return;
}
#endif // __has_feature(ptrauth_calls)


#endif // __PTRAUTH_UTILS_H
