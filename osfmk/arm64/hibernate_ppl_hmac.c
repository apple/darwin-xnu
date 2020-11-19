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
/**
 * These functions are wrappers around the PPL HIB extension. They provide a
 * higher level interface to the PPL HIB ioctl interface, and include logic for
 * turning the HMAC block on when necessary. Refer to the comments in the PPL HIB
 * extension for more details.
 */
#include "hibernate_ppl_hmac.h"

#include <mach/vm_param.h>
#include <pexpert/arm64/board_config.h>
#include <vm/pmap.h>
#include <arm64/amcc_rorgn.h>
#include <arm64/ppl/ppl_hib.h>
#include "pal_hibernate.h"
#include <stdbool.h>

#if XNU_MONITOR_PPL_HIB


#error New SoC defined in board_config.h that supports PPL HIB but no \
        embedded headers included in hibernate_ppl_hmac.c for that SoC.


#include <soc/module/address_map.h>
#include <soc/module/pmgr_soc.h>

static ppl_iommu_state *pplHmacState;
static void *pplHmacScratchPage;

static void
ppl_hmac_enable_aes_ps(void)
{
	static vm_address_t aes_ps_reg_base;
	if (!aes_ps_reg_base) {
		/* map the AES PS registers */
		aes_ps_reg_base = ml_io_map(PMGR_REG_BASE, PAGE_SIZE);
	}
	volatile uint32_t *psreg = (volatile uint32_t *)(aes_ps_reg_base + PMGR_AES_OFFSET);
	// set PS_MANUAL to on
	*psreg |= 0xf;
	while ((*psreg & 0xf) != ((*psreg >> 4) & 0xf)) {
		// poll until the block's PS_ACTUAL matches PS_MANUAL
	}
}

static int
hibernate_compress_page(const void *src, void *dst)
{
	assert((((uint64_t)src) & PAGE_MASK) == 0);
	assert((((uint64_t)dst) & 63) == 0);
	struct {
		uint32_t count:8;
		uint32_t svp:1;
		uint32_t reserved:3;
		uint32_t status:3;
		uint32_t reserved2:17;
		uint32_t popcnt:18;
		uint32_t reserved3:14;
	} result = { .status = ~0u };
	__asm__ volatile ("wkdmc %0, %1" : "=r"(result): "r"(dst), "0"(src));
	if (result.status) {
		return -1;
	}
	if (result.svp) {
		return 0;
	}
	return (result.count + 1) * 64;
}

/* initialize context needed for ppl computations */
kern_return_t
ppl_hmac_init(void)
{
	// don't initialize ppl_hib if hibernation isn't supported
	if (!ppl_hib_hibernation_supported()) {
		return KERN_FAILURE;
	}

	if (!pplHmacState) {
		/* construct context needed to talk to PPL */

		ppl_iommu_state *pplState = NULL;
		vm_address_t hmac_reg_base = 0;

		// turn on AES_PS
		ppl_hmac_enable_aes_ps();

		// set up the hmac engine
		hmac_reg_base = ml_io_map(HMAC_REG_BASE, PAGE_SIZE);
		ppl_hib_init_data init_data = { .version = PPL_HIB_VERSION, .hmac_reg_base = hmac_reg_base };
		kern_return_t kr = pmap_iommu_init(ppl_hib_get_desc(), "HMAC", &init_data, sizeof(init_data), &pplState);
		if (kr != KERN_SUCCESS) {
			printf("ppl_hmac_init: failed to initialize PPL state object: 0x%x\n", kr);
			if (hmac_reg_base) {
				ml_io_unmap(hmac_reg_base, PAGE_SIZE);
			}
			return kr;
		}

		pplHmacState = pplState;
	}

	return KERN_SUCCESS;
}

/**
 * Reset state for a new signature.
 *
 * @param wired_pages True if this context will be used to hash wired pages (image1),
 *                    false otherwise (image2).
 */
void
ppl_hmac_reset(bool wired_pages)
{
	// make sure AES_PS is on
	ppl_hmac_enable_aes_ps();

	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_RESET,
	    &wired_pages, sizeof(wired_pages), NULL, 0);
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_reset: PPL ioctl PPL_HIB_IOCTL_RESET failed: 0x%x\n", kr);
	}
}

/**
 * Inform HMAC driver that we're going to hibernate.
 */
void
ppl_hmac_hibernate_begin(void)
{
	uintptr_t scratchPage = 0;
	kern_return_t kr = pmap_iommu_map(pplHmacState, NULL, 0, 0, &scratchPage);
	if (kr != KERN_SUCCESS) {
		panic("ppl_register_scratch_page: pmap_iommu_map failed: 0x%x\n", kr);
	}
	pplHmacScratchPage = (void *)scratchPage;
}

/**
 * Inform HMAC driver that we're done hibernating.
 */
void
ppl_hmac_hibernate_end(void)
{
	pmap_iommu_unmap(pplHmacState, NULL, 0, 0, NULL);
	pplHmacScratchPage = NULL;
}

/* get the hmac register base */
vm_address_t
ppl_hmac_get_reg_base(void)
{
	return HMAC_REG_BASE;
}

/**
 * Update the PPL HMAC hash computation with the given page.
 *
 * @param  pageNumber   Page to add into the hash.
 * @param  uncompressed Out parameter that receives a pointer to the uncompressed data of the given page.
 * @param  compressed   Buffer that will receive the compressed content of the given page
 * @result              The compressed size, 0 if the page was a single repeated value, or -1 if the page failed to compress.
 */
int
ppl_hmac_update_and_compress_page(ppnum_t pageNumber, void **uncompressed, void *compressed)
{
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_UPDATE_AND_COPY_PAGE,
	    &pageNumber, sizeof(pageNumber), NULL, 0);
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_update_and_compress_page: PPL ioctl PPL_HIB_IOCTL_UPDATE_PAGE failed: 0x%x\n", kr);
	}
	// page was copied to scratch, so compress it into compressed
	int result;
	if (uncompressed) {
		*uncompressed = pplHmacScratchPage;
	}
	if (compressed) {
		result = hibernate_compress_page(pplHmacScratchPage, compressed);
	} else {
		result = 0;
	}
	return result;
}

/* finalize HMAC calculation */
void
ppl_hmac_final(uint8_t *output, size_t outputLen)
{
	if (outputLen != HMAC_HASH_SIZE) {
		panic("ppl_hmac_final: outputLen should be %d but is %zu\n", HMAC_HASH_SIZE, outputLen);
	}
	uint8_t hashOutput[HMAC_HASH_SIZE];
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_FINAL, NULL, 0, hashOutput, sizeof(hashOutput));
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_final: PPL ioctl PPL_HIB_IOCTL_FINAL failed: 0x%x\n", kr);
	}
	memcpy(output, hashOutput, HMAC_HASH_SIZE);
}

/* HMAC the hibseg and get metadata */
void
ppl_hmac_fetch_hibseg_and_info(void *buffer,
    uint64_t bufferLen,
    IOHibernateHibSegInfo *info)
{
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_FETCH_HIBSEG, NULL, 0, buffer, bufferLen);
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_fetch_hibseg_and_info: PPL ioctl PPL_HIB_IOCTL_FETCH_HIBSEG failed: 0x%x\n", kr);
	}
	IOHibernateHibSegInfo segInfo;
	kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_FETCH_HIBSEG_INFO, NULL, 0, &segInfo, sizeof(segInfo));
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_fetch_hibseg_and_info: PPL ioctl PPL_HIB_IOCTL_FETCH_HIBSEG_INFO failed: 0x%x\n", kr);
	}
	memcpy(info, &segInfo, sizeof(segInfo));
}

/* HMAC the entire read-only region, or compare to previous HMAC */
void
ppl_hmac_compute_rorgn_hmac(void)
{
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_COMPUTE_RORGN_HMAC, NULL, 0, NULL, 0);
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_compute_rorgn_hmac: PPL ioctl PPL_HIB_IOCTL_COMPUTE_RORGN_HMAC failed: 0x%x\n", kr);
	}
}

/**
 * Finish hashing the hibernation image and return out the signed hash. This also
 * hashes the hibernation header.
 */
void
ppl_hmac_finalize_image(const void *header, size_t headerLen, uint8_t *hmac, size_t hmacLen)
{
	if (hmacLen != HMAC_HASH_SIZE) {
		panic("ppl_hmac_finalize_image: hmacLen should be %d but is %zu\n", HMAC_HASH_SIZE, hmacLen);
	}
	uint8_t hashOutput[HMAC_HASH_SIZE];
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_FINALIZE_IMAGE, header, headerLen, hashOutput, sizeof(hashOutput));
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_finalize_image: PPL ioctl PPL_HIB_IOCTL_FINALIZE_IMAGE failed: 0x%x\n", kr);
	}
	memcpy(hmac, hashOutput, HMAC_HASH_SIZE);
}


/**
 * Return back an array of I/O ranges that need to be included within the hibernation
 * image. If there are no I/O ranges that need hashing, then `*io_ranges` will be
 * NULL and `*num_io_ranges` will be zero.
 */
void
ppl_hmac_get_io_ranges(const ppl_hib_io_range **io_ranges, uint16_t *num_io_ranges)
{
	assert((io_ranges != NULL) && (num_io_ranges != NULL));

	ppl_hib_get_io_ranges_data io;
	kern_return_t kr = pmap_iommu_ioctl(pplHmacState, PPL_HIB_IOCTL_GET_IO_RANGES, NULL, 0, &io, sizeof(io));
	if (kr != KERN_SUCCESS) {
		panic("ppl_hmac_finalize_image: PPL ioctl PPL_HIB_IOCTL_GET_IO_RANGES failed: 0x%x\n", kr);
	}

	/**
	 * This returns back pointers to PPL-owned data but this is fine since the
	 * caller only needs read-only access to this data (and the kernel has RO
	 * access to PPL-owned memory).
	 */
	*io_ranges = io.ranges;
	*num_io_ranges = io.num_io_ranges;
}

#endif /* XNU_MONITOR_PPL_HIB */
