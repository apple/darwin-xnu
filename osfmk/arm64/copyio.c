/*
 * Copyright (c) 2012-2020 Apple Inc. All rights reserved.
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

#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <kern/thread.h>
#include <kern/zalloc_internal.h>
#include <sys/errno.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <san/kasan.h>

#undef copyin
#undef copyout

extern int _bcopyin(const char *src, char *dst, vm_size_t len);
extern int _bcopyinstr(const char *src, char *dst, vm_size_t max, vm_size_t *actual);
extern int _bcopyout(const char *src, char *dst, vm_size_t len);
extern int _copyin_atomic32(const char *src, uint32_t *dst);
extern int _copyin_atomic32_wait_if_equals(const char *src, uint32_t dst);
extern int _copyin_atomic64(const char *src, uint64_t *dst);
extern int _copyout_atomic32(uint32_t u32, const char *dst);
extern int _copyout_atomic64(uint64_t u64, const char *dst);

extern int copyoutstr_prevalidate(const void *kaddr, user_addr_t uaddr, size_t len);

extern pmap_t kernel_pmap;

extern const vm_map_address_t physmap_base;
extern const vm_map_address_t physmap_end;

/*!
 * @typedef copyio_flags_t
 *
 * @const COPYIO_IN
 * The copy is user -> kernel.
 * One of COPYIO_IN or COPYIO_OUT should always be specified.
 *
 * @const COPYIO_OUT
 * The copy is kernel -> user
 * One of COPYIO_IN or COPYIO_OUT should always be specified.
 *
 * @const COPYIO_ALLOW_KERNEL_TO_KERNEL
 * The "user_address" is allowed to be in the VA space of the kernel.
 *
 * @const COPYIO_VALIDATE_USER_ONLY
 * There isn't really a kernel address used, and only the user address
 * needs to be validated.
 *
 * @const COPYIO_ATOMIC
 * The copyio operation is atomic, ensure that it is properly aligned.
 */
__options_decl(copyio_flags_t, uint32_t, {
	COPYIO_IN                       = 0x0001,
	COPYIO_OUT                      = 0x0002,
	COPYIO_ALLOW_KERNEL_TO_KERNEL   = 0x0004,
	COPYIO_VALIDATE_USER_ONLY       = 0x0008,
	COPYIO_ATOMIC                   = 0x0010,
});

static inline void
user_access_enable(void)
{
#if __ARM_PAN_AVAILABLE__
	assert(__builtin_arm_rsr("pan") != 0);
	__builtin_arm_wsr("pan", 0);
#endif  /* __ARM_PAN_AVAILABLE__ */
}

static inline void
user_access_disable(void)
{
#if __ARM_PAN_AVAILABLE__
	__builtin_arm_wsr("pan", 1);
#endif  /* __ARM_PAN_AVAILABLE__ */
}

/*
 * Copy sizes bigger than this value will cause a kernel panic.
 *
 * Yes, this is an arbitrary fixed limit, but it's almost certainly
 * a programming error to be copying more than this amount between
 * user and wired kernel memory in a single invocation on this
 * platform.
 */
const int copysize_limit_panic = (64 * 1024 * 1024);

static inline bool
is_kernel_to_kernel_copy()
{
	return current_thread()->map->pmap == kernel_pmap;
}

/*
 * Validate the arguments to copy{in,out} on this platform.
 *
 * Returns EXDEV when the current thread pmap is the kernel's
 * which is non fatal for certain routines.
 */
static int
copy_validate(const user_addr_t user_addr, uintptr_t kernel_addr,
    vm_size_t nbytes, copyio_flags_t flags)
{
	thread_t self = current_thread();

	user_addr_t user_addr_last;
	uintptr_t kernel_addr_last;

	if (__improbable(nbytes > copysize_limit_panic)) {
		panic("%s(%p, %p, %lu) - transfer too large", __func__,
		    (void *)user_addr, (void *)kernel_addr, nbytes);
	}

	if (__improbable((user_addr < vm_map_min(self->map)) ||
	    os_add_overflow(user_addr, nbytes, &user_addr_last) ||
	    (user_addr_last > vm_map_max(self->map)))) {
		return EFAULT;
	}

	if (flags & COPYIO_ATOMIC) {
		if (__improbable(user_addr & (nbytes - 1))) {
			return EINVAL;
		}
	}

	if ((flags & COPYIO_VALIDATE_USER_ONLY) == 0) {
		if (__improbable(os_add_overflow(kernel_addr, nbytes, &kernel_addr_last))) {
			panic("%s(%p, %p, %lu) - kaddr not in kernel", __func__,
			    (void *)user_addr, (void *)kernel_addr, nbytes);
		}

		bool in_kva = (kernel_addr >= VM_MIN_KERNEL_ADDRESS) && (kernel_addr_last <= VM_MAX_KERNEL_ADDRESS);
		bool in_physmap = (kernel_addr >= physmap_base) && (kernel_addr_last <= physmap_end);

		if (__improbable(!(in_kva || in_physmap))) {
			panic("%s(%p, %p, %lu) - kaddr not in kernel", __func__,
			    (void *)user_addr, (void *)kernel_addr, nbytes);
		}
	}

	if (is_kernel_to_kernel_copy()) {
		if (__improbable((flags & COPYIO_ALLOW_KERNEL_TO_KERNEL) == 0)) {
			return EFAULT;
		}
		return EXDEV;
	}

	if (__improbable(user_addr & TBI_MASK)) {
		return EINVAL;
	}

	if ((flags & COPYIO_VALIDATE_USER_ONLY) == 0) {
		if (__probable(!zalloc_disable_copyio_check)) {
			zone_t src_zone = NULL;
			vm_size_t kernel_buf_size = zone_element_size((void *)kernel_addr, &src_zone);
			/*
			 * Size of elements in the permanent zone is not saved as a part of the
			 * zone's info
			 */
			if (__improbable(src_zone && !src_zone->permanent &&
			    kernel_buf_size < nbytes)) {
				panic("copyio_preflight: kernel buffer 0x%lx has size %lu < nbytes %lu",
				    kernel_addr, kernel_buf_size, nbytes);
			}
		}

#if KASAN
		/* For user copies, asan-check the kernel-side buffer */
		if (flags & COPYIO_IN) {
			__asan_storeN(kernel_addr, nbytes);
		} else {
			__asan_loadN(kernel_addr, nbytes);
			kasan_check_uninitialized((vm_address_t)kernel_addr, nbytes);
		}
#endif
	}
	return 0;
}

int
copyin_kern(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
	bcopy((const char*)(uintptr_t)user_addr, kernel_addr, nbytes);

	return 0;
}

int
copyout_kern(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	bcopy(kernel_addr, (char *)(uintptr_t)user_addr, nbytes);

	return 0;
}

int
copyin(const user_addr_t user_addr, void *kernel_addr, vm_size_t nbytes)
{
	int result;

	if (__improbable(nbytes == 0)) {
		return 0;
	}

	result = copy_validate(user_addr, (uintptr_t)kernel_addr, nbytes,
	    COPYIO_IN | COPYIO_ALLOW_KERNEL_TO_KERNEL);
	if (result == EXDEV) {
		return copyin_kern(user_addr, kernel_addr, nbytes);
	}
	if (__improbable(result)) {
		return result;
	}

	user_access_enable();
	result = _bcopyin((const char *)user_addr, kernel_addr, nbytes);
	user_access_disable();
	return result;
}

/*
 * copy{in,out}_atomic{32,64}
 * Read or store an aligned value from userspace as a single memory transaction.
 * These functions support userspace synchronization features
 */
int
copyin_atomic32(const user_addr_t user_addr, uint32_t *kernel_addr)
{
	int result = copy_validate(user_addr, (uintptr_t)kernel_addr, 4,
	    COPYIO_IN | COPYIO_ATOMIC);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _copyin_atomic32((const char *)user_addr, kernel_addr);
	user_access_disable();
	return result;
}

int
copyin_atomic32_wait_if_equals(const user_addr_t user_addr, uint32_t value)
{
	int result = copy_validate(user_addr, 0, 4,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _copyin_atomic32_wait_if_equals((const char *)user_addr, value);
	user_access_disable();
	return result;
}

int
copyin_atomic64(const user_addr_t user_addr, uint64_t *kernel_addr)
{
	int result = copy_validate(user_addr, (uintptr_t)kernel_addr, 8,
	    COPYIO_IN | COPYIO_ATOMIC);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _copyin_atomic64((const char *)user_addr, kernel_addr);
	user_access_disable();
	return result;
}

int
copyout_atomic32(uint32_t value, user_addr_t user_addr)
{
	int result = copy_validate(user_addr, 0, 4,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _copyout_atomic32(value, (const char *)user_addr);
	user_access_disable();
	return result;
}

int
copyout_atomic64(uint64_t value, user_addr_t user_addr)
{
	int result = copy_validate(user_addr, 0, 8,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _copyout_atomic64(value, (const char *)user_addr);
	user_access_disable();
	return result;
}

int
copyinstr(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	int result;
	vm_size_t bytes_copied = 0;

	*lencopied = 0;
	if (__improbable(nbytes == 0)) {
		return ENAMETOOLONG;
	}

	result = copy_validate(user_addr, (uintptr_t)kernel_addr, nbytes, COPYIO_IN);
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _bcopyinstr((const char *)user_addr, kernel_addr, nbytes,
	    &bytes_copied);
	user_access_disable();
	if (result != EFAULT) {
		*lencopied = bytes_copied;
	}
	return result;
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	int result;

	if (nbytes == 0) {
		return 0;
	}

	result = copy_validate(user_addr, (uintptr_t)kernel_addr, nbytes,
	    COPYIO_OUT | COPYIO_ALLOW_KERNEL_TO_KERNEL);
	if (result == EXDEV) {
		return copyout_kern(kernel_addr, user_addr, nbytes);
	}
	if (__improbable(result)) {
		return result;
	}
	user_access_enable();
	result = _bcopyout(kernel_addr, (char *)user_addr, nbytes);
	user_access_disable();
	return result;
}

int
copyoutstr_prevalidate(const void *__unused kaddr, user_addr_t __unused uaddr, size_t __unused len)
{
	if (__improbable(is_kernel_to_kernel_copy())) {
		return EFAULT;
	}

	return 0;
}
