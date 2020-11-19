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
#ifndef _ARM64_HIBERNATE_PPL_HMAC_H_
#define _ARM64_HIBERNATE_PPL_HMAC_H_

#include <sys/cdefs.h>
#include <stdint.h>
#include <stdbool.h>
#include <libkern/crypto/sha2.h>
#include <mach/vm_types.h>
#include <arm64/ppl/ppl_hib.h>
#include <IOKit/IOHibernatePrivate.h>

#define HMAC_HASH_SIZE 48

__BEGIN_DECLS

kern_return_t ppl_hmac_init(void);
void ppl_hmac_reset(bool wired_pages);
void ppl_hmac_hibernate_begin(void);
void ppl_hmac_hibernate_end(void);
vm_address_t ppl_hmac_get_reg_base(void);
int ppl_hmac_update_and_compress_page(ppnum_t pageNumber, void **uncompressed, void *compressed);
void ppl_hmac_final(uint8_t *output, size_t outputLen);
void ppl_hmac_fetch_hibseg_and_info(/* out */ void *buffer,
    /* in */ uint64_t bufferLen,
    /* out */ IOHibernateHibSegInfo *info);
void ppl_hmac_compute_rorgn_hmac(void);
void ppl_hmac_finalize_image(const void *header, size_t headerLen, uint8_t *hmac, size_t hmacLen);
void ppl_hmac_get_io_ranges(const ppl_hib_io_range **io_ranges, uint16_t *num_io_ranges);

__END_DECLS

#endif /* _ARM64_HIBERNATE_PPL_HMAC_H_ */
