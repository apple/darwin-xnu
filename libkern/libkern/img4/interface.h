/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
 * We rely on firmware.h's logic for either including sys/types.h or declaring
 * errno_t ourselves. So when building the kernel, include firmware.h from our
 * external headers. Avoid this inclusion if we're building AppleImage4, which
 * will have included its own internal version of the header.
 */
#if MACH_KERNEL_PRIVATE || !_DARWIN_BUILDING_PROJECT_APPLEIMAGE4
#include <img4/firmware.h>
#endif

/*!
 * @const IMG4_INTERFACE_VERSION
 * The version of the interface supported by the implementation. As new
 * functions are added to the interface, this value will be incremented so that
 * it can be tested at build-time and not require rev-locked submissions of xnu
 * and AppleImage4.
 */
#define IMG4_INTERFACE_VERSION (10u)

/*!
 * @typegroup
 * Type definitions for all exported functions and constants in the AppleImage4
 * kext.
 */
typedef const void *img4_retired_t;

typedef errno_t (*const img4_nonce_domain_copy_nonce_t)(
	const img4_nonce_domain_t *nd,
	img4_nonce_t *n
	);

typedef errno_t (*const img4_nonce_domain_roll_nonce_t)(
	const img4_nonce_domain_t *nd
	);

typedef img4_chip_t *(*img4_chip_init_from_buff_t)(
	void *buff,
	size_t len
	);

typedef const img4_chip_t *(*img4_chip_select_personalized_ap_t)(
	void
	);

typedef const img4_chip_t *(*img4_chip_select_effective_ap_t)(
	void
	);

typedef errno_t (*img4_chip_instantiate_t)(
	const img4_chip_t *chip,
	img4_chip_instance_t *chip_instance
	);

typedef const img4_chip_t *(*img4_chip_custom_t)(
	const img4_chip_instance_t *chip_instance,
	img4_chip_t *chip
	);

typedef img4_firmware_t (*img4_firmware_new_t)(
	const img4_runtime_t *rt,
	const img4_firmware_execution_context_t *exec,
	img4_4cc_t _4cc,
	img4_buff_t *buff,
	img4_firmware_flags_t flags
	);

typedef img4_firmware_t (*img4_firmware_new_from_vnode_4xnu_t)(
	const img4_runtime_t *rt,
	const img4_firmware_execution_context_t *exec,
	img4_4cc_t _4cc,
	vnode_t vn,
	img4_firmware_flags_t flags
	);

typedef img4_firmware_t (*img4_firmware_init_from_buff_t)(
	void *buff,
	size_t len
	);

typedef void (*img4_firmware_init_t)(
	img4_firmware_t fw,
	const img4_runtime_t *rt,
	const img4_firmware_execution_context_t *exec,
	img4_4cc_t _4cc,
	img4_buff_t *buff,
	img4_firmware_flags_t flags
	);

typedef void (*img4_firmware_attach_manifest_t)(
	img4_firmware_t fw,
	img4_buff_t *buff
	);

typedef void (*img4_firmware_execute_t)(
	img4_firmware_t fw,
	const img4_chip_t *chip,
	const img4_nonce_t *nonce
	);

typedef void (*img4_firmware_destroy_t)(
	img4_firmware_t *fw
	);

typedef const img4_buff_t *(*img4_image_get_bytes_t)(
	img4_image_t image
	);

typedef const bool *(*img4_image_get_property_bool_t)(
	img4_image_t image,
	img4_4cc_t _4cc,
	bool *storage
	);

typedef const uint32_t *(*img4_image_get_property_uint32_t)(
	img4_image_t image,
	img4_4cc_t _4cc,
	uint32_t *storage
	);

typedef const uint64_t *(*img4_image_get_property_uint64_t)(
	img4_image_t image,
	img4_4cc_t _4cc,
	uint64_t *storage
	);

typedef const img4_buff_t *(*img4_image_get_property_data_t)(
	img4_image_t image,
	img4_4cc_t _4cc,
	img4_buff_t *storage
	);

typedef void (*img4_buff_dealloc_t)(
	img4_buff_t *buff
	);

typedef errno_t (*img4_firmware_evaluate_t)(
	img4_firmware_t fw,
	const img4_chip_t *chip,
	const img4_nonce_t *nonce
	);

typedef const img4_chip_t *(*img4_firmware_select_chip_t)(
	const img4_firmware_t fw,
	const img4_chip_select_array_t acceptable_chips,
	size_t acceptable_chips_cnt
	);

typedef struct _img4_interface {
	const uint32_t i4if_version;
	img4_retired_t i4if_init;
	img4_retired_t i4if_set_nonce;
	img4_retired_t i4if_get_trusted_payload;
	img4_retired_t i4if_get_trusted_external_payload;
	img4_retired_t i4if_destroy;
	img4_retired_t i4if_payload_init;
	img4_retired_t i4if_payload_destroy;
	img4_retired_t i4if_environment_platform;
	img4_retired_t i4if_environment_reserved;
	img4_retired_t i4if_environment_trust_cache;
	struct {
		img4_retired_t set_nonce_domain;
		img4_nonce_domain_copy_nonce_t nonce_domain_copy_nonce;
		img4_nonce_domain_roll_nonce_t nonce_domain_roll_nonce;
		const img4_nonce_domain_t *nonce_domain_trust_cache;
	} i4if_v1;
	struct {
		img4_retired_t payload_init_with_vnode_4xnu;
	} i4if_v2;
	struct {
		const img4_nonce_domain_t *nonce_domain_pdi;
		const img4_nonce_domain_t *nonce_domain_cryptex;
	} i4if_v3;
	struct {
		img4_retired_t environment_init_identity;
	} i4if_v4;
	struct {
		img4_retired_t environment_t2;
		img4_retired_t environment_init_from_identity;
		img4_retired_t identity_init_from_environment;
	} i4if_v5;
	struct {
		img4_retired_t environment_x86;
	} i4if_v6;
	struct {
		const img4_chip_t *chip_ap_sha1;
		const img4_chip_t *chip_ap_sha2_384;
		const img4_chip_t *chip_ap_hybrid;
		const img4_chip_t *chip_ap_reduced;
		const img4_chip_t *chip_ap_software_ff00;
		const img4_chip_t *chip_ap_software_ff01;
		const img4_chip_t *chip_x86;
		const img4_chip_t *chip_x86_software_8012;
		img4_chip_init_from_buff_t chip_init_from_buff;
		img4_chip_select_personalized_ap_t chip_select_personalized_ap;
		img4_chip_select_effective_ap_t chip_select_effective_ap;
		img4_chip_instantiate_t chip_instantiate;
		img4_chip_custom_t chip_custom;
		img4_firmware_new_t firmware_new;
		img4_firmware_new_from_vnode_4xnu_t firmware_new_from_vnode_4xnu;
		img4_firmware_init_from_buff_t firmware_init_from_buff;
		img4_firmware_init_t firmware_init;
		img4_firmware_attach_manifest_t firmware_attach_manifest;
		img4_firmware_execute_t firmware_execute;
		img4_firmware_destroy_t firmware_destroy;
		img4_image_get_bytes_t image_get_bytes;
		img4_image_get_property_bool_t image_get_property_bool;
		img4_image_get_property_uint32_t image_get_property_uint32;
		img4_image_get_property_uint64_t image_get_property_uint64;
		img4_image_get_property_data_t image_get_property_data;
		const img4_object_spec_t *firmware_spec;
		const img4_object_spec_t *chip_spec;
		const img4_runtime_t *runtime_default;
		const img4_runtime_t *runtime_pmap_cs;
		img4_buff_dealloc_t buff_dealloc;
	} i4if_v7;
	struct {
		const img4_chip_t *chip_ap_permissive;
		const img4_chip_t *chip_ap_hybrid_medium;
		const img4_chip_t *chip_ap_hybrid_relaxed;
	} i4if_v8;
	struct {
		img4_firmware_evaluate_t firmware_evaluate;
	} i4if_v9;
	struct {
		img4_firmware_select_chip_t firmware_select_chip;
	} i4if_v10;
} img4_interface_t;

__BEGIN_DECLS

/*!
 * @const img4if
 * The AppleImage4 interface that was registered.
 */
extern const img4_interface_t *img4if;

/*!
 * @function img4_interface_register
 * Registers the AppleImage4 kext interface for use within the kernel proper.
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

__END_DECLS

#endif // __IMG4_INTERFACE_H
