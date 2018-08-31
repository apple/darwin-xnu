/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <string.h>
#include <vm/vm_map.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <mach/mach_vm.h>
#include <mach/vm_param.h>
#include <libkern/libkern.h>
#include <libkern/kernel_mach_header.h>
#include <sys/queue.h>
#include <kasan.h>
#include <kasan_internal.h>
#include <memintrinsics.h>

#define STATIC_ARRAY_SZ 66
#define STACK_ARRAY_SZ 9
#define BUFSZ 34
#define LBUFSZ 255

enum {
	TEST_PASS,
	TEST_FAIL_NOFAULT,
	TEST_FAIL_BADFAULT,
	TEST_SETUP_FAIL = 1,
	TEST_INVALID,
	TEST_UNKNOWN
};

unsigned long static_array[STATIC_ARRAY_SZ];

static jmp_buf jbuf;
static volatile int in_test = 0;

struct kasan_test {
	int (* func)(struct kasan_test *);
	void (* cleanup)(struct kasan_test *);
	const char *name;
	int result;
	void *data;
	size_t datasz;
};

#define TEST_BARRIER()    do { __asm__ __volatile__ ("" ::: "memory"); } while(0)
#define TEST_START(t)     do { t->result = 1; TEST_BARRIER(); } while (0)
#define TEST_FAULT(t)     do { TEST_BARRIER(); t->result = 0; TEST_BARRIER(); } while (0)
#define TEST_NOFAULT(t)   do { TEST_BARRIER(); t->result = 1; TEST_BARRIER(); } while (0)
#define TEST_DONE(t,res)  do { t->result = (res); kasan_handle_test(); } while (0)
#define DECLARE_TEST(f,s)    { .func = f, .name = s }
#define DECLARE_TEST3(f,c,s) { .func = f, .cleanup = c, .name = s }

static void heap_cleanup(struct kasan_test *t)
{
	if (t->data) {
		kfree(t->data, t->datasz);
		t->data = NULL;
	}
}

static int test_global_overflow(struct kasan_test __unused *t)
{
	int i;
	/* rookie error */
	for (i = 0; i <= STATIC_ARRAY_SZ; i++) {
		static_array[i] = i;
	}
	return 0;
}

static int test_heap_underflow(struct kasan_test __unused *t)
{
	uint8_t *x = kalloc(BUFSZ);
	if (!x) {
		return 1;
	}
	t->datasz = BUFSZ;
	t->data = x;
	x[-1] = 0x12;
	return 0;
}

static int test_heap_overflow(struct kasan_test __unused *t)
{
	uint8_t *x = kalloc(BUFSZ);
	if (!x) {
		return 1;
	}
	t->datasz = BUFSZ;
	t->data = x;
	x[BUFSZ] = 0x11;
	return 0;
}

static int test_heap_uaf(struct kasan_test __unused *t)
{
	uint8_t *x = kalloc(LBUFSZ);
	if (!x) {
		return 1;
	}
	kfree(x, LBUFSZ);
	x[0] = 0x10;
	return 0;
}

static int test_heap_inval_free(struct kasan_test __unused *t)
{
	int x;
	kfree(&x, BUFSZ);
	return 0;
}

static int test_heap_double_free(struct kasan_test *t)
{
	TEST_START(t);

	uint8_t *x = kalloc(BUFSZ);
	if (!x) {
		return 1;
	}
	kfree(x, BUFSZ);

	TEST_FAULT(t);
	kfree(x, BUFSZ);

	return 0;
}

static int test_heap_small_free(struct kasan_test *t)
{
	TEST_START(t);

	uint8_t *x = kalloc(BUFSZ);
	if (!x) {
		return 1;
	}
	t->datasz = BUFSZ;
	t->data = x;

	TEST_FAULT(t);
	kfree(x, BUFSZ-2);
	t->data = NULL;
	t->datasz = 0;

	return 0;
}

static int test_stack_overflow(struct kasan_test *t)
{
	TEST_START(t);

	int i;
	volatile uint8_t a[STACK_ARRAY_SZ];

	for (i = 0; i < STACK_ARRAY_SZ; i++) {
		a[i] = i;
	}

	TEST_FAULT(t);
	a[i] = i; /* rookie error */
	TEST_NOFAULT(t);

	TEST_BARRIER();

	return !(a[0] == 0);
}

static int test_stack_underflow(struct kasan_test *t)
{
	TEST_START(t);

	long idx;
	uint8_t a[STACK_ARRAY_SZ];

	__nosan_memset(a, 0, STACK_ARRAY_SZ);

	/* generate a negative index without the compiler noticing */
#if __x86_64__
	__asm__ __volatile__("movq $-1, %0" : "=r"(idx) :: "memory");
#else
	__asm__ __volatile__("mov %0, #-1" : "=r"(idx) :: "memory");
#endif

	TEST_FAULT(t);
	a[idx] = 0xbd;
	TEST_NOFAULT(t);

	TEST_BARRIER();
	return (a[0] == 0);
}

static int test_memcpy(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t a1[STACK_ARRAY_SZ];
	uint8_t a2[STACK_ARRAY_SZ];

	/* should work */
	memcpy(a1, a2, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	memcpy(a2, a1, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_memmove(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t a1[STACK_ARRAY_SZ];
	uint8_t a2[STACK_ARRAY_SZ];

	/* should work */
	memmove(a1, a2, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	memmove(a2, a1, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_bcopy(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t a1[STACK_ARRAY_SZ];
	uint8_t a2[STACK_ARRAY_SZ];

	/* should work */
	bcopy(a1, a2, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	bcopy(a2, a1, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_memset(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t a1[STACK_ARRAY_SZ];

	/* should work */
	memset(a1, 'e', STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	memset(a1, 'f', STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_memcmp(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t *a1;
	uint8_t *a2;

	a1 = kalloc(STACK_ARRAY_SZ);
	if (!a1)
		return 1;
	a2 = kalloc(STACK_ARRAY_SZ+1);
	if (!a2)
		return 1;

	/* should work */
	memcmp(a1, a2, STACK_ARRAY_SZ);
	memcmp(a1, a2+1, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	memcmp(a1, a2, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_bcmp(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t *a1;
	uint8_t *a2;

	a1 = kalloc(STACK_ARRAY_SZ);
	if (!a1)
		return 1;
	a2 = kalloc(STACK_ARRAY_SZ+1);
	if (!a2)
		return 1;

	/* should work */
	bcmp(a1, a2, STACK_ARRAY_SZ);
	bcmp(a1, a2+1, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	bcmp(a1, a2, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_bzero(struct kasan_test *t)
{
	TEST_START(t);
	uint8_t a1[STACK_ARRAY_SZ];

	/* should work */
	bzero(a1, STACK_ARRAY_SZ);

	TEST_BARRIER();

	/* should fail */
	TEST_FAULT(t);
	bzero(a1, STACK_ARRAY_SZ+1);
	TEST_NOFAULT(t);

	return 0;
}

static int test_strlcpy(struct kasan_test *t)
{
	TEST_START(t);
	char a1[8];

	/* should not fault */
	strlcpy(a1, "small", 8);
	strlcpy(a1, "looooonnnnggg", 8);

	TEST_FAULT(t);
	strlcpy(a1, "looooooooonnnnggg", 9);
	TEST_NOFAULT(t);

	return 0;
}

static int test_strncpy(struct kasan_test *t)
{
	TEST_START(t);
	char a1[9];

	/* should not fault */
	strncpy(a1, "small", 9);
	strncpy(a1, "looooonnnnggg", 9);

	TEST_FAULT(t);
	strncpy(a1, "looooonnnnggg", 10);
	TEST_NOFAULT(t);

	return a1[0] != 'l';
}

static int test_strlcat(struct kasan_test *t)
{
	TEST_START(t);
	char a1[9] = {};

	/* should not fault */
	strlcat(a1, "abcd", 9);
	strlcat(a1, "efgh", 9);
	strlcat(a1, "ijkl", 9);
	a1[0] = '\0';
	strlcat(a1, "looooonnnnggg", 9);

	a1[0] = '\0';
	TEST_FAULT(t);
	strlcat(a1, "looooonnnnggg", 10);
	TEST_NOFAULT(t);

	return a1[0] != 'l';
}

static int test_strncat(struct kasan_test *t)
{
	TEST_START(t);
	char a1[9] = {};

	/* should not fault */
	strncat(a1, "abcd", 4);
	strncat(a1, "efgh", 4);

	TEST_FAULT(t);
	strncat(a1, "i", 1);
	TEST_NOFAULT(t);

	return a1[0] != 'a';
}

/* we ignore the top *two* frames in backtrace - so add an extra one */
static int __attribute__((noinline))
test_blacklist_helper(void)
{
	return kasan_is_blacklisted(TYPE_TEST);
}

static int __attribute__((noinline))
test_blacklist(struct kasan_test *t)
{
	TEST_START(t);
	int res = (int)!test_blacklist_helper();
	TEST_DONE(t, res);
	return 0;
}

static int __attribute__((noinline))
test_blacklist_str(struct kasan_test *t)
{
	TEST_START(t);
	char a1[8];

	bcopy("123456", a1, 8);

	TEST_DONE(t, 0); /* success */
	return 0;
}

#if 0
static int test_strnlen(struct kasan_test *t)
{
	TEST_START(t);
	const char *a1 = "abcdef";

	/* should not fault */
	if (strnlen(a1, 6) != 6)
		return 1;
	if (strnlen(a1, 7) != 6)
		return 1;

	TEST_FAULT(t);
	if (strnlen(a1, 8) != 6)
		return 1;
	TEST_NOFAULT(t);

	return a1[0] != 'a';
}
#endif

int *uaf_ptr;
static int * NOINLINE
stack_uaf_helper(void)
{
	int x;
	uaf_ptr = &x;
	return uaf_ptr;
}

static int test_stack_uaf(struct kasan_test __unused *t)
{
	int *x = stack_uaf_helper();
	*x = 0xb4d;
	TEST_BARRIER();
	return !(*x == 0xb4d);
}

static struct kasan_test xnu_tests[] = {
	DECLARE_TEST(NULL, NULL),
	DECLARE_TEST(test_global_overflow, "Global overflow"),
	DECLARE_TEST3(test_heap_underflow,  heap_cleanup, "Heap underflow"),
	DECLARE_TEST3(test_heap_overflow,   heap_cleanup, "Heap overflow"),
	DECLARE_TEST(test_heap_uaf,        "Heap use-after-free"),
	DECLARE_TEST(test_heap_inval_free, "Heap invalid free"),
	DECLARE_TEST(test_heap_double_free,"Heap double free"),
	DECLARE_TEST3(test_heap_small_free, heap_cleanup, "Heap small free"),
	DECLARE_TEST(test_stack_overflow,  "Stack overflow"),
	DECLARE_TEST(test_stack_underflow, "Stack underflow"),
	DECLARE_TEST(test_stack_uaf,       "Stack use-after-return"),
	DECLARE_TEST(test_memcpy,          "memcpy"),
	DECLARE_TEST(test_memmove,         "memmmove"),
	DECLARE_TEST(test_bcopy,           "bcopy"),
	DECLARE_TEST(test_memset,          "memset"),
	DECLARE_TEST(test_memcmp,          "memcmp"),
	DECLARE_TEST(test_bcmp,            "bcmp"),
	DECLARE_TEST(test_bzero,           "bzero"),
	DECLARE_TEST(test_strlcpy,         "strlcpy"),
	DECLARE_TEST(test_strlcat,         "strlcat"),
	DECLARE_TEST(test_strncpy,         "strncpy"),
	DECLARE_TEST(test_strncat,         "strncat"),
	DECLARE_TEST(test_blacklist,       "blacklist"),
	DECLARE_TEST(test_blacklist_str,   "blacklist_str"),
	// DECLARE_TEST(test_strnlen,         "strnlen"),
};
static int num_xnutests = sizeof(xnu_tests)/sizeof(xnu_tests[0]);

static int
kasan_run_test(struct kasan_test *test_list, int testno, int fail)
{
	int status = TEST_UNKNOWN;
	struct kasan_test *t = &test_list[testno];

	if (testno < 0 || testno >= num_xnutests || !t->func) {
		printf("KASan: test.%02d INVALID\n", testno);
		return TEST_INVALID;
	}

	// printf("KASan: test.%02d RUNNING (%s)\n", testno, t->name);

	if (!fail) {
		in_test = 1;
	}

	if (_setjmp(jbuf) == 0) {
		t->result = 0;
		int ret = t->func(t);
		if (ret) {
			printf("KASan: test.%02d SETUP FAIL (%s)\n", testno, t->name);
			status = ret;
		} else {
			/* did not fault when it should have */
			printf("KASan: test.%02d FAIL (%s)\n", testno, t->name);
			status = TEST_FAIL_NOFAULT;
		}
	} else {
		/* Triggering a KASan violation will return here by longjmp, bypassing
		 * stack unpoisoning, so do it here explicitly. We just hope that
		 * fakestack free will happen later... */
		kasan_unpoison_curstack(true);

		if (t->result) {
			/* faulted, but at the wrong place */
			printf("KASan: test.%02d FAIL %d (%s)\n", testno, t->result, t->name);
			status = TEST_FAIL_BADFAULT;
		} else {
			printf("KASan: test.%02d PASS (%s)\n", testno, t->name);
			status = TEST_PASS;
		}
	}
	in_test = 0;
	if (t->cleanup) {
		t->cleanup(t);
	}

	return status;
}

void
kasan_test(int testno, int fail)
{
	int i = 1;
	int pass = 0, total = 0;
	int ret;

	if (testno == -1) {
		/* shorthand for all tests */
		testno = (1U << (num_xnutests-1)) - 1;
	}

	while (testno) {
		if (testno & 0x1) {
			ret = kasan_run_test(xnu_tests, i, fail);
			if (ret == TEST_PASS) {
				pass++;
			}
			if (ret != TEST_INVALID) {
				total++;
			}
		}

		i++;
		testno >>= 1;
	}
	printf("KASan: TEST SUMMARY %d/%d passed\n", pass, total);
}

void
kasan_handle_test(void)
{
	if (in_test) {
		_longjmp(jbuf, 1);
		/* NOTREACHED */
	}
}

void
__kasan_runtests(struct kasan_test *kext_tests, int numtests)
{
	int i;
	for (i = 0; i < numtests; i++) {
		kasan_run_test(kext_tests, i, 0);
	}
}
