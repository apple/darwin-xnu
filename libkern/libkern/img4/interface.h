/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

/*!
 * @header
 * Interfaces to register the AppleImage4 interface with xnu-proper to avoid a
 * build-time layering inversion.
 */
#ifndef __IMG4_INTERFACE_H
#define __IMG4_INTERFACE_H

#include <os/base.h>
#include <sys/cdefs.h>

/*
 * We rely on img4.h's logic for either including sys/types.h or declaring
 * errno_t ourselves.
 */
#include <img4/img4.h>

/*!
 * @const IMG4_INTERFACE_VERSION
 * The version of the interface supported by the implementation. As new
 * functions are added to the interface, this value will be incremented so that
 * it can be tested at build-time and not require rev-locked submissions of xnu
 * and AppleImage4.
 */
#define IMG4_INTERFACE_VERSION (1u)

/*!
 * @typedef img4_init_t
 * A type describing the img4_init() function.
 */
typedef errno_t (*img4_init_t)(
	img4_t *i4,
	img4_flags_t flags,
	const uint8_t *bytes,
	size_t len,
	img4_destructor_t destructor
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_set_custom_tag_handler() function.
 */
typedef void (*img4_set_custom_tag_handler_t)(
	img4_t *i4,
	const img4_custom_tag_t *tags,
	size_t tags_cnt
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_get_trusted_payload() function.
 */
typedef errno_t (*img4_get_trusted_payload_t)(
	img4_t *i4,
	img4_tag_t tag,
	const img4_environment_t *env,
	void *ctx,
	const uint8_t **bytes,
	size_t *len
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_get_trusted_external_payload() function.
 */
typedef errno_t (*img4_get_trusted_external_payload_t)(
	img4_t *img4,
	img4_payload_t *payload,
	const img4_environment_t *env,
	void *ctx,
	const uint8_t **bytes,
	size_t *len
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_get_entitlement_bool() function.
 */
typedef bool (*img4_get_entitlement_bool_t)(
	img4_t *i4,
	img4_tag_t entitlement
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_get_object_entitlement_bool() function.
 */
typedef bool (*img4_get_object_entitlement_bool_t)(
	img4_t *i4,
	img4_tag_t object,
	img4_tag_t entitlement
);

/*!
 * @typedef img4_init_t
 * A type describing the img4_destroy() function.
 */
typedef void (*img4_destroy_t)(
	img4_t *i4
);

/*!
 * @typedef img4_interface_t
 * A structure describing the interface to the AppleImage4 kext.
 *
 * @property i4if_version
 * The version of the structure supported by the implementation.
 *
 * @property i4if_init
 * A pointer to the img4_init function.
 *
 * @property i4if_set_custom_tag_handler
 * A pointer to the img4_set_custom_tag_handler function.
 *
 * @property i4if_get_trusted_payload
 * A pointer to the img4_get_trusted_payload function.
 *
 * @property i4if_get_trusted_external_payload
 * A pointer to the img4_get_trusted_external_payload function.
 *
 * @property i4if_get_entitlement_bool
 * A pointer to the img4_get_entitlement_bool function.
 *
 * @property i4if_get_object_entitlement_bool
 * A pointer to the img4_get_object_entitlement_bool function.
 *
 * @property i4if_destroy
 * A pointer to the img4_destroy function.
 *
 * @property i4if_v1
 * All members added in version 1 of the structure.
 *
 * @property environment_platform
 * The IMG4_ENVIRONMENT_PLATFORM global.
 */
typedef struct _img4_interface {
	const uint32_t i4if_version;
	const img4_init_t i4if_init;
	const img4_set_custom_tag_handler_t i4if_set_custom_tag_handler;
	const img4_get_trusted_payload_t i4if_get_trusted_payload;
	const img4_get_trusted_external_payload_t i4if_get_trusted_external_payload;
	const img4_get_entitlement_bool_t i4if_get_entitlement_bool;
	const img4_get_object_entitlement_bool_t i4if_get_object_entitlement_bool;
	const img4_destroy_t i4if_destroy;
	struct {
		const img4_environment_t *environment_platform;
	} i4if_v1;
	void *__reserved[23];
} img4_interface_t;

__BEGIN_DECLS;

/*!
 * @const img4if
 * The AppleImage4 interface that was registered.
 */
extern const img4_interface_t *img4if;

/*!
 * @function img4_interface_register
 * Registers the AppleImage4 kext interface with xnu.
 *
 * @param i4
 * The interface to register.
 *
 * @discussion
 * This routine may only be called once and must be called before late-const has
 * been applied to kernel memory.
 */
OS_EXPORT OS_NONNULL1
void
img4_interface_register(const img4_interface_t *i4);

__END_DECLS;

#endif // __IMG4_INTERFACE_H
