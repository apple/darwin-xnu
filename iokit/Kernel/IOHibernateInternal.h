/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <IOKit/IOHibernatePrivate.h>

#ifdef __cplusplus

#if HIBERNATE_HMAC_IMAGE
#include <libkern/crypto/sha2.h>
#endif /* HIBERNATE_HMAC_IMAGE */

enum { kIOHibernateAESKeySize = 16 };  /* bytes */

#if HIBERNATE_HMAC_IMAGE
// when we call out to PPL to compute IOHibernateHibSegInfo, we use
// srcBuffer as a temporary buffer, to copy out all of the required
// HIB segments, so it should be big enough to contain those segments
#define HIBERNATION_SRC_BUFFER_SIZE (16 * 1024 * 1024)
#else
// srcBuffer has to be big enough for a source page, the WKDM
// compressed output, and a scratch page needed by WKDM
#define HIBERNATION_SRC_BUFFER_SIZE (2 * page_size + WKdm_SCRATCH_BUF_SIZE_INTERNAL)
#endif

struct IOHibernateVars {
	hibernate_page_list_t *             page_list;
	hibernate_page_list_t *             page_list_wired;
	hibernate_page_list_t *             page_list_pal;
	class IOBufferMemoryDescriptor *    ioBuffer;
	class IOBufferMemoryDescriptor *    srcBuffer;
	class IOBufferMemoryDescriptor *    handoffBuffer;
	class IOMemoryDescriptor *          previewBuffer;
	OSData *                            previewData;
	OSObject *                          saveBootDevice;

	struct IOPolledFileIOVars *         fileVars;
	uint64_t                            fileMinSize;
	uint64_t                            fileMaxSize;
	vm_offset_t                         videoMapping;
	vm_size_t                           videoAllocSize;
	vm_size_t                           videoMapSize;
	uint8_t *                           consoleMapping;
	uint8_t                             haveFastBoot;
	uint8_t                             saveBootAudioVolume;
	uint8_t                             hwEncrypt;
	uint8_t                             wiredCryptKey[kIOHibernateAESKeySize];
	uint8_t                             cryptKey[kIOHibernateAESKeySize];
	size_t                              volumeCryptKeySize;
	uint8_t                             volumeCryptKey[64];
#if HIBERNATE_HMAC_IMAGE
	SHA256_CTX *                        imageShaCtx;
#endif /* HIBERNATE_HMAC_IMAGE */
};
typedef struct IOHibernateVars IOHibernateVars;

#endif          /* __cplusplus */

enum{
	kIOHibernateTagSignature = 0x53000000,
	kIOHibernateTagLength    = 0x00007fff,
};

#ifdef __cplusplus
extern "C"
#endif          /* __cplusplus */
uint32_t
hibernate_sum_page(uint8_t *buf, uint32_t ppnum);

#if defined(__i386__) || defined(__x86_64__)
extern vm_offset_t segHIBB;
extern unsigned long segSizeHIB;
#elif defined(__arm64__)
extern vm_offset_t sectHIBTEXTB;
extern unsigned long sectSizeHIBTEXT;
#endif

extern ppnum_t gIOHibernateHandoffPages[];
extern const uint32_t gIOHibernateHandoffPageCount;

// max address that can fit in a ppnum_t
#define IO_MAX_PAGE_ADDR        (((uint64_t) UINT_MAX) << PAGE_SHIFT)
// atop() returning ppnum_t
#define atop_64_ppnum(x) ((ppnum_t)((uint64_t)(x) >> PAGE_SHIFT))
