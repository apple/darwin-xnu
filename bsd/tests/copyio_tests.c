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

#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach/mach_vm.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/vm.h>
#include <tests/ktest.h>

kern_return_t copyio_test(void);

#define copyio_test_buf_size (PAGE_SIZE * 16)
static const char copyio_test_string[] = {'T', 'e', 's', 't', ' ', 'S', 't', 'r', 'i', 'n', 'g', '!', '\0', 'A', 'B', 'C'};

struct copyio_test_data {
	/* VM map of the current userspace process. */
	vm_map_t user_map;
	/* The start of a `copyio_test_buf_size'-sized region mapped into userspace. */
	mach_vm_offset_t user_addr;
	/* The start of a page-sized region that guaranteed to be unmapped in userspace. */
	mach_vm_offset_t unmapped_addr;
	/* The start of a page-sized region mapped at the largest possible userspace address. */
	mach_vm_offset_t user_lastpage_addr;
	/* Kernel mapping of the physical pages mapped at `user_addr'. */
	void *kern_addr;

	/* Scratch buffers of size `copyio_test_buf_size'. */
	char *buf1, *buf2;
	/* Scratch data to pass to helper threads */
	union {
		void *thread_ptr;
		uint64_t thread_data;
	};
};

typedef int (*copyio_thread_fn_t)(struct copyio_test_data *);

struct copyio_test_thread_data {
	copyio_thread_fn_t fn;
	struct copyio_test_data *data;
	int ret;
	semaphore_t done;
};

static void
copyio_thread_call_fn(void *arg, wait_result_t __unused res)
{
	struct copyio_test_thread_data *tdata = arg;
	tdata->ret = tdata->fn(tdata->data);
	semaphore_signal(tdata->done);
}

static int
copyio_test_run_in_thread(copyio_thread_fn_t fn, struct copyio_test_data *data)
{
	struct copyio_test_thread_data tdata = {
		.fn = fn,
		.data = data,
	};
	thread_t thread;

	semaphore_create(current_task(), &tdata.done, SYNC_POLICY_FIFO, 0);
	kernel_thread_start(copyio_thread_call_fn, &tdata, &thread);

	semaphore_wait(tdata.done);

	thread_deallocate(thread);
	semaphore_destroy(current_task(), tdata.done);

	return tdata.ret;
}

static void
copyio_test_protect(struct copyio_test_data *data, vm_prot_t prot)
{
	kern_return_t ret = mach_vm_protect(data->user_map, data->user_addr, copyio_test_buf_size, false, prot);
	assert(ret == KERN_SUCCESS);
}

static int
copyin_from_kernel(struct copyio_test_data *data)
{
	char *in_buf = data->buf2;
	return copyin((uintptr_t)data->kern_addr, in_buf, copyio_test_buf_size);
}

static void
copyin_test(struct copyio_test_data *data)
{
	char *out_buf = data->buf1;
	char *in_buf = data->buf2;

	for (size_t i = 0; i < copyio_test_buf_size; i++) {
		out_buf[i] = (char)i;
	}
	memcpy(data->kern_addr, out_buf, copyio_test_buf_size);

	int err = copyin(data->user_addr, in_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, 0, "copyin() with valid parameters should succeed");
	int cmp = memcmp(out_buf, in_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyin() should correctly copy in data");

	err = copyin(data->unmapped_addr, NULL, 0);
	T_EXPECT_EQ_INT(err, 0, "copyin() with 0 size should always succeed");

	err = copyin(data->unmapped_addr, in_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin() from unmapped userspace address should return EFAULT");
	err = copyin(data->unmapped_addr - PAGE_SIZE, in_buf, PAGE_SIZE * 2);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin() from partially valid userspace range should return EFAULT");
	err = copyin(data->user_lastpage_addr, in_buf, PAGE_SIZE * 2);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin() past end of userspace address space should return EFAULT");

	bzero(in_buf, copyio_test_buf_size);
	err = copyio_test_run_in_thread(copyin_from_kernel, data);
	T_EXPECT_EQ_INT(err, 0, "copyin() from kernel address in kernel_task thread should succeed");
	cmp = memcmp(data->kern_addr, in_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyin() from kernel address should correctly copy in data");
	err = copyin_from_kernel(data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin() from kernel address in other threads should return EFAULT");

	copyio_test_protect(data, VM_PROT_WRITE);
	err = copyin(data->user_addr, in_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin() from write-only address should return EFAULT");
	copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);
}

static int
copyout_to_kernel(struct copyio_test_data *data)
{
	char *out_buf = data->buf1;
	return copyout(out_buf, (uintptr_t)data->kern_addr, copyio_test_buf_size);
}

static void
copyout_test(struct copyio_test_data *data)
{
	char *out_buf = data->buf1;

	bzero(data->kern_addr, copyio_test_buf_size);

	for (size_t i = 0; i < copyio_test_buf_size; i++) {
		out_buf[i] = ~(char)i;
	}
	int err = copyout(out_buf, data->user_addr, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, 0, "copyout() with valid parameters should succeed");

	int cmp = memcmp(data->kern_addr, out_buf, copyio_test_buf_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyout() should correctly copy out data");

	err = copyout(NULL, data->unmapped_addr, 0);
	T_EXPECT_EQ_INT(err, 0, "copyout() with 0 size should always succeed");

	err = copyout(out_buf, data->unmapped_addr, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, EFAULT, "copyout() to unmapped userspace address should return EFAULT");
	err = copyout(out_buf, data->unmapped_addr - PAGE_SIZE, PAGE_SIZE * 2);
	T_EXPECT_EQ_INT(err, EFAULT, "copyout() to partially valid userspace range should return EFAULT");
	err = copyout(out_buf, data->user_lastpage_addr, PAGE_SIZE * 2);
	T_EXPECT_EQ_INT(err, EFAULT, "copyout() past end of userspace address space should return EFAULT");

	bzero(data->kern_addr, copyio_test_buf_size);

	err = copyio_test_run_in_thread(copyout_to_kernel, data);
	T_EXPECT_EQ_INT(err, 0, "copyout() to kernel address in kernel_task thread should succeed");
	cmp = memcmp(out_buf, data->kern_addr, copyio_test_buf_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyout() to kernel address should correctly copy out data");
	err = copyout_to_kernel(data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyout() to kernel address in other threads should return EFAULT");

	copyio_test_protect(data, VM_PROT_READ);
	err = copyout(out_buf, data->user_addr, copyio_test_buf_size);
	T_EXPECT_EQ_INT(err, EFAULT, "copyout() to read-only address should return EFAULT");
	copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);
}

static int
copyinstr_from_kernel(struct copyio_test_data *data)
{
	char *in_buf = data->buf1;
	size_t *lencopied = data->thread_ptr;
	return copyinstr((user_addr_t)data->kern_addr, in_buf, copyio_test_buf_size, lencopied);
}

static void
copyinstr_test(struct copyio_test_data *data)
{
	char *in_buf = data->buf1;

	memcpy(data->kern_addr, copyio_test_string, sizeof(copyio_test_string));

	bzero(in_buf, copyio_test_buf_size);
	size_t lencopied;
	int err = copyinstr(data->user_addr, in_buf, copyio_test_buf_size, &lencopied);
	T_EXPECT_EQ_INT(err, 0, "copyinstr() with valid parameters should succeed");
	T_EXPECT_EQ_ULONG(lencopied, strlen(copyio_test_string) + 1, "copyinstr() with a large enough buffer should read entire string");

	int cmp = strncmp(in_buf, copyio_test_string, lencopied);
	T_EXPECT_EQ_INT(cmp, 0, "copyinstr() should correctly copy string up to NULL terminator");
	cmp = memcmp(in_buf, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_NE_INT(cmp, 0, "copyinstr() should not read past NULL terminator");

	bzero(in_buf, copyio_test_buf_size);
	const vm_size_t trunc_size = strlen(copyio_test_string) - 4;
	err = copyinstr(data->user_addr, in_buf, trunc_size, &lencopied);
	T_EXPECT_EQ_INT(err, ENAMETOOLONG, "truncated copyinstr() should return ENAMETOOLONG");
	T_EXPECT_EQ_ULONG(lencopied, trunc_size, "truncated copyinstr() should copy exactly `maxlen' bytes");
	cmp = memcmp(in_buf, copyio_test_string, trunc_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyinstr() should correctly copy in truncated string");
	cmp = memcmp(in_buf, copyio_test_string, strlen(copyio_test_string));
	T_EXPECT_NE_INT(cmp, 0, "copyinstr() should stop copying at `maxlen' bytes");

	err = copyinstr(data->unmapped_addr, in_buf, copyio_test_buf_size, &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() from unmapped userspace address should return EFAULT");
	err = copyinstr(data->user_lastpage_addr, in_buf, PAGE_SIZE * 2, &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() past end of userspace address space should return EFAULT");

	bzero(in_buf, copyio_test_buf_size);
	data->thread_ptr = &lencopied;

	err = copyio_test_run_in_thread(copyinstr_from_kernel, data);
#if defined(CONFIG_EMBEDDED)
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() from kernel address in kernel_task thread should return EFAULT");
#else
	T_EXPECT_EQ_INT(err, 0, "copyinstr() from kernel address in kernel_task thread should succeed");
	T_EXPECT_EQ_ULONG(lencopied, strlen(copyio_test_string) + 1, "copyinstr() from kernel address should read entire string");
	cmp = strncmp(in_buf, copyio_test_string, lencopied);
	T_EXPECT_EQ_INT(cmp, 0, "copyinstr() from kernel address should correctly copy string up to NULL terminator");
	cmp = memcmp(in_buf, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_NE_INT(cmp, 0, "copyinstr() from kernel address should not read past NULL terminator");
#endif
	err = copyinstr_from_kernel(data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() from kernel address in other threads should return EFAULT");

	copyio_test_protect(data, VM_PROT_WRITE);
	err = copyinstr(data->user_addr, in_buf, copyio_test_buf_size, &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() from write-only address should return EFAULT");
	copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);

	/* Place an unterminated string at the end of the mapped region */
	const size_t unterminated_size = 16;
	char *kern_unterminated_addr = (char *)data->kern_addr + copyio_test_buf_size - unterminated_size;
	memset(kern_unterminated_addr, 'A', unterminated_size);

	mach_vm_offset_t user_unterminated_addr = data->user_addr + copyio_test_buf_size - unterminated_size;
	err = copyinstr(user_unterminated_addr, in_buf, copyio_test_buf_size, &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyinstr() from userspace region without NULL terminator should return EFAULT");
}

static int
copyoutstr_to_kernel(struct copyio_test_data *data)
{
	size_t *lencopied = data->thread_ptr;
	return copyoutstr(copyio_test_string, (user_addr_t)data->kern_addr, sizeof(copyio_test_string), lencopied);
}

static void
copyoutstr_test(struct copyio_test_data *data)
{
	bzero(data->kern_addr, sizeof(copyio_test_string));

	size_t lencopied;
	int err = copyoutstr(copyio_test_string, data->user_addr, sizeof(copyio_test_string), &lencopied);
	T_EXPECT_EQ_INT(err, 0, "copyoutstr() with valid parameters should succeed");
	T_EXPECT_EQ_ULONG(lencopied, strlen(copyio_test_string) + 1, "copyoutstr() should copy string up to NULL terminator");

	int cmp = strncmp(data->kern_addr, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_EQ_INT(cmp, 0, "copyoutstr() should correctly copy out string");
	cmp = memcmp(data->kern_addr, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_NE_INT(cmp, 0, "copyoutstr() should stop copying at NULL terminator");

	bzero(data->kern_addr, sizeof(copyio_test_string));

	const vm_size_t trunc_size = strlen(copyio_test_string) - 4;
	err = copyoutstr(copyio_test_string, data->user_addr, trunc_size, &lencopied);
	T_EXPECT_EQ_INT(err, ENAMETOOLONG, "truncated copyoutstr() should return ENAMETOOLONG");
	T_EXPECT_EQ_ULONG(lencopied, trunc_size, "truncated copyoutstr() should copy exactly `maxlen' bytes");
	cmp = strncmp(data->kern_addr, copyio_test_string, trunc_size);
	T_EXPECT_EQ_INT(cmp, 0, "copyoutstr() should correctly copy out truncated string");
	cmp = memcmp(data->kern_addr, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_NE_INT(cmp, 0, "copyoutstr() should stop copying at `maxlen' bytes");

	err = copyoutstr(copyio_test_string, data->unmapped_addr, strlen(copyio_test_string), &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() to unmapped userspace address should return EFAULT");
	err = copyoutstr(copyio_test_string, data->unmapped_addr - 1, strlen(copyio_test_string), &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() to partially valid userspace range should return EFAULT");
	err = copyoutstr(copyio_test_string, data->user_lastpage_addr + PAGE_SIZE - 1, strlen(copyio_test_string), &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() past end of userspace address space should return EFAULT");

	bzero(data->kern_addr, sizeof(copyio_test_string));
	data->thread_ptr = &lencopied;

	err = copyio_test_run_in_thread(copyoutstr_to_kernel, data);
#if defined(CONFIG_EMBEDDED)
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() to kernel address in kernel_task thread should return EFAULT");
#else
	T_EXPECT_EQ_INT(err, 0, "copyoutstr() to kernel address in kernel_task thread should succeed");
	T_EXPECT_EQ_ULONG(lencopied, strlen(copyio_test_string) + 1, "copyoutstr() to kernel address should copy string up to NULL terminator");
	cmp = strncmp(data->kern_addr, copyio_test_string, sizeof(copyio_test_string));
	T_EXPECT_EQ_INT(cmp, 0, "copyoutstr() to kernel address should correctly copy out data");
#endif
	err = copyoutstr_to_kernel(data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() to kernel address in other threads should return EFAULT");

	copyio_test_protect(data, VM_PROT_READ);
	err = copyoutstr(copyio_test_string, data->user_addr, strlen(copyio_test_string), &lencopied);
	T_EXPECT_EQ_INT(err, EFAULT, "copyoutstr() to read-only address should return EFAULT");
	copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);
}

static int
copyin_atomic32_from_kernel(struct copyio_test_data *data)
{
	return copyin_atomic32((uintptr_t)data->kern_addr, data->thread_ptr);
}

static int
copyin_atomic64_from_kernel(struct copyio_test_data *data)
{
	return copyin_atomic64((uintptr_t)data->kern_addr, data->thread_ptr);
}

static int
copyout_atomic32_to_kernel(struct copyio_test_data *data)
{
	return copyout_atomic32(data->thread_data, (user_addr_t)data->kern_addr);
}

static int
copyout_atomic64_to_kernel(struct copyio_test_data *data)
{
	return copyout_atomic64(data->thread_data, (user_addr_t)data->kern_addr);
}

/**
 * Note: we can't test atomic copyio calls which go past the end of the
 * userspace address space, since there's no way to provide a range
 * that straddles the userspace address boundary while being suitably
 * aligned for the copy.
 */
#define copyin_atomic_test(data, word_t, copyin_fn, copyin_from_kernel_fn)                                              \
	do {                                                                                                            \
	        const word_t word_out = (word_t)0x123456789ABCDEF0UL;                                                   \
	        word_t word_in = 0;                                                                                     \
	        memcpy(data->kern_addr, &word_out, sizeof(word_out));                                                   \
                                                                                                                        \
	        int err = copyin_fn(data->user_addr, &word_in);                                                         \
	        T_EXPECT_EQ_INT(err, 0, #copyin_fn "() with valid parameters should succeed");                          \
                                                                                                                        \
	        int cmp = memcmp(&word_in, &word_out, sizeof(word_t));                                                  \
	        T_EXPECT_EQ_INT(cmp, 0, #copyin_fn "() should correctly copy word");                                    \
                                                                                                                        \
	        for (unsigned int offset = 1; offset < sizeof(word_t); offset++) {                                      \
	                err = copyin_fn(data->user_addr + offset, &word_in);                                            \
	                T_EXPECT_EQ_INT(err, EINVAL,                                                                    \
	                    #copyin_fn "() from unaligned userspace address should return EINVAL (offset = %u)",        \
	                    offset);                                                                                    \
	        };                                                                                                      \
	        err = copyin_fn(data->unmapped_addr, &word_in);                                                         \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyin_fn "() from unmapped userspace address should return EFAULT");     \
                                                                                                                        \
	        data->thread_ptr = &word_in;                                                                            \
                                                                                                                        \
	        err = copyio_test_run_in_thread(copyin_from_kernel_fn, data);                                           \
	        T_EXPECT_EQ_INT(err, EFAULT,                                                                            \
	            #copyin_fn "() from kernel address in kernel_task threads should return EFAULT");                   \
	        err = copyin_from_kernel_fn(data);                                                                      \
	        T_EXPECT_EQ_INT(err, EFAULT,                                                                            \
	            #copyin_fn "() from kernel address in other threads should return EFAULT");                         \
                                                                                                                        \
	        copyio_test_protect(data, VM_PROT_WRITE);                                                               \
	        err = copyin_fn(data->user_addr, &word_in);                                                             \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyin_fn "() from write-only address should return EFAULT");             \
	        copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);                                                \
	} while (0)

#define copyout_atomic_test(data, word_t, copyout_fn, copyout_to_kernel_fn)                                             \
	do {                                                                                                            \
	        const word_t word_out = (word_t)0x123456789ABCDEF0UL;                                                   \
	        bzero(data->kern_addr, sizeof(word_t));                                                                 \
                                                                                                                        \
	        int err = copyout_fn(word_out, data->user_addr);                                                        \
	        T_EXPECT_EQ_INT(err, 0, #copyout_fn "() with valid parameters should succeed");                         \
                                                                                                                        \
	        int cmp = memcmp(data->kern_addr, &word_out, sizeof(word_t));                                           \
	        T_EXPECT_EQ_INT(cmp, 0, #copyout_fn "() should correctly copy word");                                   \
                                                                                                                        \
	        for (unsigned int offset = 1; offset < sizeof(word_t); offset++) {                                      \
	                err = copyout_fn(word_out, data->user_addr + offset);                                           \
	                T_EXPECT_EQ_INT(err, EINVAL,                                                                    \
	                    #copyout_fn "() to unaligned userspace address should return EINVAL (offset = %u)",         \
	                    offset);                                                                                    \
	        };                                                                                                      \
	        err = copyout_fn(word_out, data->unmapped_addr);                                                        \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyout_fn "() to unmapped userspace address should return EFAULT");      \
	        err = copyout_fn(word_out, (uintptr_t)data->kern_addr);                                                 \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyout_fn "() to kernel address should return EFAULT");                  \
                                                                                                                        \
	        data->thread_data = word_out;                                                                           \
                                                                                                                        \
	        err = copyio_test_run_in_thread(copyout_to_kernel_fn, data);                                            \
	        T_EXPECT_EQ_INT(err, EFAULT,                                                                            \
	                #copyout_fn "() to kernel address in kernel_task thread should return EFAULT");                 \
	        err = copyout_to_kernel_fn(data);                                                                       \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyout_fn "() to kernel address in other threads should return EFAULT"); \
                                                                                                                        \
	        copyio_test_protect(data, VM_PROT_READ);                                                                \
	        err = copyout_fn(word_out, data->user_addr);                                                            \
	        T_EXPECT_EQ_INT(err, EFAULT, #copyout_fn "() to read-only address should return EFAULT");               \
	        copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);                                                \
	} while (0)

#define copyio_atomic_test(data, size)                                                          \
	do {                                                                                    \
	        copyin_atomic_test((data), uint ## size ## _t, copyin_atomic ## size,           \
	            copyin_atomic ## size ## _from_kernel);                                     \
	        copyout_atomic_test((data), uint ## size ## _t, copyout_atomic ## size,         \
	            copyout_atomic ## size ## _to_kernel);                                      \
	} while (0)

static int
copyin_atomic32_wait_if_equals_from_kernel(struct copyio_test_data *data)
{
	return copyin_atomic32_wait_if_equals((uintptr_t)data->kern_addr, data->thread_data);
}

static void
copyin_atomic32_wait_if_equals_test(struct copyio_test_data *data)
{
	bzero(data->kern_addr, sizeof(uint32_t));
	int err = copyin_atomic32_wait_if_equals(data->user_addr, 0);
	T_EXPECT_EQ_INT(err, 0, "copyin_atomic32_wait_if_equals() should return 0 when equals");
	err = copyin_atomic32_wait_if_equals(data->user_addr, ~0U);
	T_EXPECT_EQ_INT(err, ESTALE, "copyin_atomic32_wait_if_equals() should return ESTALE when not equals");

	for (unsigned int offset = 1; offset < sizeof(uint32_t); offset++) {
		err = copyin_atomic32_wait_if_equals(data->user_addr + offset, 0);
		T_EXPECT_EQ_INT(err, EINVAL,
		    "copyin_atomic32_wait_if_equals() on unaligned userspace address should return EINVAL (offset = %u)",
		    offset);
	}
	err = copyin_atomic32_wait_if_equals(data->unmapped_addr, 0);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin_atomic32_wait_if_equals() on unmapped userspace address should return EFAULT");

	data->thread_data = 0;

	err = copyio_test_run_in_thread(copyin_atomic32_wait_if_equals_from_kernel, data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin_atomic32_wait_if_equals() from kernel address in kernel_task thread should return EFAULT");
	err = copyin_atomic32_wait_if_equals_from_kernel(data);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin_atomic32_wait_if_equals() from kernel address in other threads should return EFAULT");

	copyio_test_protect(data, VM_PROT_WRITE);
	err = copyin_atomic32_wait_if_equals(data->user_addr, 0);
	T_EXPECT_EQ_INT(err, EFAULT, "copyin_atomic32_wait_if_equals() on write-only address should return EFAULT");
	copyio_test_protect(data, VM_PROT_READ | VM_PROT_WRITE);
}

kern_return_t
copyio_test(void)
{
	struct copyio_test_data data = {};
	kern_return_t ret = KERN_SUCCESS;

	data.buf1 = kalloc(copyio_test_buf_size);
	data.buf2 = kalloc(copyio_test_buf_size);
	if (!data.buf1 || !data.buf2) {
		T_FAIL("failed to allocate scratch buffers");
		ret = KERN_NO_SPACE;
		goto err_kalloc;
	}

	/**
	 * This test needs to manipulate the current userspace process's
	 * address space.  This is okay to do at the specific point in time
	 * when bsd_do_post() runs: current_proc() points to the init process,
	 * which has been set up to the point of having a valid vm_map, but
	 * not to the point of actually execing yet.
	 */
	proc_t proc = current_proc();
	assert(proc->p_pid == 1);
	data.user_map = get_task_map_reference(proc->task);

	ret = mach_vm_allocate_kernel(data.user_map, &data.user_addr, copyio_test_buf_size + PAGE_SIZE, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_NONE);
	if (ret) {
		T_FAIL("mach_vm_allocate_kernel(user_addr) failed: %d", ret);
		goto err_user_alloc;
	}

	data.user_lastpage_addr = get_map_max(data.user_map) - PAGE_SIZE;
	ret = mach_vm_allocate_kernel(data.user_map, &data.user_lastpage_addr, PAGE_SIZE, VM_FLAGS_FIXED, VM_KERN_MEMORY_NONE);
	if (ret) {
		T_FAIL("mach_vm_allocate_kernel(user_lastpage_addr) failed: %d", ret);
		goto err_user_lastpage_alloc;
	}

	data.unmapped_addr = data.user_addr + copyio_test_buf_size;
	mach_vm_deallocate(data.user_map, data.unmapped_addr, PAGE_SIZE);

	vm_prot_t cur_protection, max_protection;
	mach_vm_offset_t kern_addr = 0;
	ret = mach_vm_remap_kernel(kernel_map, &kern_addr, copyio_test_buf_size, VM_PROT_READ | VM_PROT_WRITE, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_NONE,
	    data.user_map, data.user_addr, false, &cur_protection, &max_protection, VM_INHERIT_NONE);
	if (ret) {
		T_FAIL("mach_vm_remap_kernel() failed: %d", ret);
		goto err_kern_remap;
	}
	data.kern_addr = (void *)kern_addr;

	copyin_test(&data);
	copyout_test(&data);
	copyinstr_test(&data);
	copyoutstr_test(&data);
	copyio_atomic_test(&data, 32);
	copyio_atomic_test(&data, 64);
	copyin_atomic32_wait_if_equals_test(&data);

	mach_vm_deallocate(kernel_map, kern_addr, copyio_test_buf_size);
err_kern_remap:
	mach_vm_deallocate(data.user_map, data.user_lastpage_addr, PAGE_SIZE);
err_user_lastpage_alloc:
	mach_vm_deallocate(data.user_map, data.user_addr, copyio_test_buf_size);
err_user_alloc:
	vm_map_deallocate(data.user_map);
err_kalloc:
	kfree(data.buf2, copyio_test_buf_size);
	kfree(data.buf1, copyio_test_buf_size);
	return ret;
}
