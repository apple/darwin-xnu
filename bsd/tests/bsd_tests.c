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

#include <tests/ktest.h>
#include <tests/xnupost.h>
#include <kern/assert.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/kdebug.h>
#include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <sys/cdefs.h>
#include <libkern/version.h>
#include <kern/clock.h>
#include <kern/kern_cdata.h>
#include <pexpert/pexpert.h>


#if !(DEVELOPMENT || DEBUG)
#error "Testing is not enabled on RELEASE configurations"
#endif

#ifdef __arm64__
extern kern_return_t arm64_lock_test(void);
#endif
#if defined(__arm__) || defined(__arm64__)
extern kern_return_t pmap_test(void);
#endif /* defined(__arm__) || defined(__arm64__) */
kern_return_t kalloc_test(void);
kern_return_t ipi_test(void);
#if defined(KERNEL_INTEGRITY_CTRR)
extern kern_return_t ctrr_test(void);
#endif
#if __ARM_PAN_AVAILABLE__
extern kern_return_t arm64_late_pan_test(void);
#endif
#if HAS_TWO_STAGE_SPR_LOCK
extern kern_return_t arm64_spr_lock_test(void);
#endif
extern kern_return_t copyio_test(void);

struct xnupost_test bsd_post_tests[] = {
#ifdef __arm64__
	XNUPOST_TEST_CONFIG_BASIC(arm64_lock_test),
#endif
#if defined(__arm__) || defined(__arm64__)
	XNUPOST_TEST_CONFIG_BASIC(pmap_test),
#endif /* defined(__arm__) || defined(__arm64__) */
#if defined(KERNEL_INTEGRITY_CTRR)
	XNUPOST_TEST_CONFIG_BASIC(ctrr_test),
#endif
#if __ARM_PAN_AVAILABLE__
	XNUPOST_TEST_CONFIG_BASIC(arm64_late_pan_test),
#endif
	XNUPOST_TEST_CONFIG_BASIC(kalloc_test),
	XNUPOST_TEST_CONFIG_BASIC(ipi_test),
#if HAS_TWO_STAGE_SPR_LOCK
	XNUPOST_TEST_CONFIG_BASIC(arm64_spr_lock_test),
#endif
	XNUPOST_TEST_CONFIG_BASIC(copyio_test),
};

uint32_t bsd_post_tests_count = sizeof(bsd_post_tests) / sizeof(xnupost_test_data_t);

extern uint64_t last_loaded_timestamp; /* updated by OSKext::load() */
extern uint64_t kernel_post_args;
int
bsd_list_tests()
{
	if (kernel_post_args == 0) {
		return 0;
	}

	uint64_t prev_load_time    = last_loaded_timestamp;
	int no_load_counter        = 5;
	int absolute_break_counter = 15;
	int delay_duration_usecs   = 300000; /* 0.3 second for kext loading to stabilize */

	while (no_load_counter > 0) {
		printf("bsd_list_tests:INFO waiting for %d usecs\n", delay_duration_usecs);
		printf("bsd_list_tests: prev: %llu current: %llu\n", prev_load_time, last_loaded_timestamp);

		delay(delay_duration_usecs);
		absolute_break_counter -= 1;

		if (absolute_break_counter <= 0) {
			printf("bsd_list_tests: WARNING: Waiting beyond normal time for stabilizing kext loading\n");
			break;
		}

		if (prev_load_time == last_loaded_timestamp) {
			no_load_counter -= 1;
			printf("bsd_list_tests: INFO: no new kexts loaded. remaining checks: %d\n", no_load_counter);
		}

		prev_load_time = last_loaded_timestamp;
	}

	return xnupost_list_tests(bsd_post_tests, bsd_post_tests_count);
}

int
bsd_do_post()
{
	return xnupost_run_tests(bsd_post_tests, bsd_post_tests_count);
}

kern_return_t
kalloc_test()
{
	uint64_t * data_ptr;
	size_t alloc_size;

	T_LOG("Running kalloc test.\n");

	alloc_size = sizeof(uint64_t);
	data_ptr = kalloc(alloc_size);
	T_ASSERT_NOTNULL(data_ptr, "kalloc sizeof(uint64_t) return not null");
	kfree(data_ptr, alloc_size);

	alloc_size = 3544;
	data_ptr = kalloc(alloc_size);
	T_ASSERT_NOTNULL(data_ptr, "kalloc 3544 return not null");
	kfree(data_ptr, alloc_size);

	return KERN_SUCCESS;
}

/* kcdata type definition */
#define XNUPOST_TNAME_MAXLEN 132

struct kcdata_subtype_descriptor kc_xnupost_test_def[] = {
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_UINT16, .kcs_elem_offset = 0, .kcs_elem_size = sizeof(uint16_t), .kcs_name = "config"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_UINT16, .kcs_elem_offset = 1 * sizeof(uint16_t), .kcs_elem_size = sizeof(uint16_t), .kcs_name = "test_num"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_INT32, .kcs_elem_offset = 2 * sizeof(uint16_t), .kcs_elem_size = sizeof(int32_t), .kcs_name = "retval"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_INT32, .kcs_elem_offset = 2 * sizeof(uint16_t) + sizeof(int32_t), .kcs_elem_size = sizeof(int32_t), .kcs_name = "expected_retval"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_UINT64, .kcs_elem_offset = 2 * (sizeof(uint16_t) + sizeof(int32_t)), .kcs_elem_size = sizeof(uint64_t), .kcs_name = "begin_time"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_NONE, .kcs_elem_type = KC_ST_UINT64, .kcs_elem_offset = 2 * (sizeof(uint16_t) + sizeof(int32_t)) + sizeof(uint64_t), .kcs_elem_size = sizeof(uint64_t), .kcs_name = "end_time"},
	{.kcs_flags = KCS_SUBTYPE_FLAGS_ARRAY,
	 .kcs_elem_type = KC_ST_CHAR,
	 .kcs_elem_offset = 2 * (sizeof(uint16_t) + sizeof(int32_t) + sizeof(uint64_t)),
	 .kcs_elem_size = KCS_SUBTYPE_PACK_SIZE(XNUPOST_TNAME_MAXLEN * sizeof(char), sizeof(char)),
	 .kcs_name = "test_name"}
};

const uint32_t kc_xnupost_test_def_count = sizeof(kc_xnupost_test_def) / sizeof(struct kcdata_subtype_descriptor);

kern_return_t xnupost_copyout_test(xnupost_test_t t, mach_vm_address_t outaddr);

int
xnupost_copyout_test(xnupost_test_t t, mach_vm_address_t outaddr)
{
	/* code to copyout test config */
	int kret         = 0;
	size_t namelen = 0;

	kret = copyout(&t->xt_config, (user_addr_t)outaddr, sizeof(uint16_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint16_t);

	kret = copyout(&t->xt_test_num, (user_addr_t)outaddr, sizeof(uint16_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint16_t);

	kret = copyout(&t->xt_retval, (user_addr_t)outaddr, sizeof(uint32_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint32_t);

	kret = copyout(&t->xt_expected_retval, (user_addr_t)outaddr, sizeof(uint32_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint32_t);

	kret = copyout(&t->xt_begin_time, (user_addr_t)outaddr, sizeof(uint64_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint64_t);

	kret = copyout(&t->xt_end_time, (user_addr_t)outaddr, sizeof(uint64_t));
	if (kret) {
		return kret;
	}
	outaddr += sizeof(uint64_t);

	namelen = strnlen(t->xt_name, XNUPOST_TNAME_MAXLEN);
	kret = copyout(t->xt_name, (user_addr_t)outaddr, namelen);
	if (kret) {
		return kret;
	}
	outaddr += namelen;

	return 0;
}

uint32_t
xnupost_get_estimated_testdata_size(void)
{
	uint32_t total_tests = bsd_post_tests_count + kernel_post_tests_count;
	uint32_t elem_size = kc_xnupost_test_def[kc_xnupost_test_def_count - 1].kcs_elem_offset +
	    kcs_get_elem_size(&kc_xnupost_test_def[kc_xnupost_test_def_count - 1]);
	uint32_t retval = 1024; /* account for type definition and mach timebase */
	retval += 1024;         /* kernel version and boot-args string data */
	retval += (total_tests * elem_size);

	return retval;
}

int
xnupost_export_testdata(void * outp, size_t size_in, uint32_t * lenp)
{
	struct kcdata_descriptor kcd;
	mach_vm_address_t user_addr        = 0;
	mach_vm_address_t tmp_entry_addr   = 0;
	kern_return_t kret                 = 0;
	uint32_t i                         = 0;
	char kctype_name[32]               = "xnupost_test_config";
	mach_timebase_info_data_t timebase = {0, 0};
	uint32_t length_to_copy            = 0;
	unsigned int size                  = (unsigned int)size_in;

	if (size_in > UINT_MAX) {
		return ENOSPC;
	}

#define RET_IF_OP_FAIL                                                                                       \
	do {                                                                                                     \
	        if (kret != KERN_SUCCESS) {                                                                          \
	                return (kret == KERN_NO_ACCESS) ? EACCES : ((kret == KERN_RESOURCE_SHORTAGE) ? ENOMEM : EINVAL); \
	        }                                                                                                    \
	} while (0)

	kret = kcdata_memory_static_init(&kcd, (mach_vm_address_t)outp, KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG, size, KCFLAG_USE_COPYOUT);
	RET_IF_OP_FAIL;

	/* add mach timebase info */
	clock_timebase_info(&timebase);
	kret = kcdata_get_memory_addr(&kcd, KCDATA_TYPE_TIMEBASE, sizeof(timebase), &user_addr);
	RET_IF_OP_FAIL;
	kret = copyout(&timebase, (user_addr_t)user_addr, sizeof(timebase));
	RET_IF_OP_FAIL;

	/* save boot-args and osversion string */
	length_to_copy = MIN((uint32_t)(strlen(version) + 1), OSVERSIZE);
	kret           = kcdata_get_memory_addr(&kcd, STACKSHOT_KCTYPE_OSVERSION, length_to_copy, &user_addr);
	RET_IF_OP_FAIL;
	kret = copyout(&version[0], (user_addr_t)user_addr, length_to_copy);
	RET_IF_OP_FAIL;

	length_to_copy = MIN((uint32_t)(strlen(PE_boot_args()) + 1), BOOT_LINE_LENGTH);
	kret           = kcdata_get_memory_addr(&kcd, STACKSHOT_KCTYPE_BOOTARGS, length_to_copy, &user_addr);
	RET_IF_OP_FAIL;
	kret = copyout(PE_boot_args(), (user_addr_t)user_addr, length_to_copy);
	RET_IF_OP_FAIL;

	/* add type definition to buffer */
	kret = kcdata_add_type_definition(&kcd, XNUPOST_KCTYPE_TESTCONFIG, kctype_name, &kc_xnupost_test_def[0],
	    kc_xnupost_test_def_count);
	RET_IF_OP_FAIL;

	/* add the tests to buffer as array */
	uint32_t total_tests = bsd_post_tests_count + kernel_post_tests_count;
	uint32_t elem_size = kc_xnupost_test_def[kc_xnupost_test_def_count - 1].kcs_elem_offset +
	    kcs_get_elem_size(&kc_xnupost_test_def[kc_xnupost_test_def_count - 1]);

	kret = kcdata_get_memory_addr_for_array(&kcd, XNUPOST_KCTYPE_TESTCONFIG, elem_size, total_tests, &user_addr);
	RET_IF_OP_FAIL;

	for (i = 0; i < bsd_post_tests_count; i++) {
		tmp_entry_addr = (mach_vm_address_t)((uint64_t)(user_addr) + (uint64_t)(i * elem_size));
		kret           = xnupost_copyout_test(&bsd_post_tests[i], tmp_entry_addr);
		RET_IF_OP_FAIL;
	}
	user_addr = (mach_vm_address_t)((uint64_t)(user_addr) + (uint64_t)(i * elem_size));

	for (i = 0; i < kernel_post_tests_count; i++) {
		tmp_entry_addr = (mach_vm_address_t)((uint64_t)(user_addr) + (uint64_t)(i * elem_size));
		kret           = xnupost_copyout_test(&kernel_post_tests[i], tmp_entry_addr);
		RET_IF_OP_FAIL;
	}

	if (kret == KERN_SUCCESS && lenp != NULL) {
		*lenp = (uint32_t)kcdata_memory_get_used_bytes(&kcd);
	}
	RET_IF_OP_FAIL;

#undef RET_IF_OP_FAIL
	return kret;
}

int
xnupost_reset_all_tests(void)
{
	xnupost_reset_tests(&bsd_post_tests[0], bsd_post_tests_count);
	xnupost_reset_tests(&kernel_post_tests[0], kernel_post_tests_count);
	return 0;
}
