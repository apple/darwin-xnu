/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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
#include <sys/errno.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <san/kasan.h>

extern int _bcopyin(const char *src, char *dst, vm_size_t len);
extern int _bcopyinstr(const char *src, char *dst, vm_size_t max, vm_size_t *actual);
extern int _bcopyout(const char *src, char *dst, vm_size_t len);
extern int _copyin_word(const char *src, uint64_t *dst, vm_size_t len);

extern pmap_t kernel_pmap;
extern boolean_t arm_pan_enabled;

typedef enum copyio_type {
	COPYIO_IN,
	COPYIO_IN_WORD,
	COPYIO_INSTR,
	COPYIO_OUT,
} copyio_type_t;

int
copyio_check_user_addr(user_addr_t user_addr, vm_size_t nbytes)
{
	if (nbytes && (user_addr + nbytes <= user_addr))
		return EFAULT;

	if ((user_addr + nbytes) > vm_map_max(current_thread()->map))
		return EFAULT;

	return 0;
}

static inline void
user_access_enable(void)
{
#if __ARM_PAN_AVAILABLE__
    if (arm_pan_enabled) {
        __builtin_arm_wsr("pan", 0);
    }
#endif  /* __ARM_PAN_AVAILABLE__ */
}

static inline void
user_access_disable(void)
{
#if __ARM_PAN_AVAILABLE__
    if (arm_pan_enabled) {
		__builtin_arm_wsr("pan", 1);
    }
#endif  /* __ARM_PAN_AVAILABLE__ */
}

static int
copyio(copyio_type_t copytype, const char *src, char *dst,
	   vm_size_t nbytes, vm_size_t *lencopied)
{
	int result = 0;
	vm_size_t bytes_copied = 0;

	/* Reject TBI addresses */
	if (copytype == COPYIO_OUT) {
		if ((uintptr_t)dst & TBI_MASK)
			return EINVAL;
	} else {
		if ((uintptr_t)src & TBI_MASK)
			return EINVAL;
	}

	if (!nbytes) {
		return 0;
	}

#if KASAN
	/* For user copies, asan-check the kernel-side buffer */
	if (copytype == COPYIO_IN || copytype == COPYIO_INSTR || copytype == COPYIO_IN_WORD) {
		__asan_storeN((uintptr_t)dst, nbytes);
	} else if (copytype == COPYIO_OUT) {
		__asan_loadN((uintptr_t)src, nbytes);
	}
#endif

    user_access_enable();

	/* Select copy routines based on direction:
	 *   COPYIO_IN - Use unprivileged loads to read from user address
	 *   COPYIO_OUT - Use unprivleged stores to write to user address
	 */

	switch (copytype) {
	case COPYIO_IN:
		result = _bcopyin(src, dst, nbytes);
		break;
	case COPYIO_INSTR:
		result = _bcopyinstr(src, dst, nbytes, &bytes_copied);
		if (result != EFAULT) {
			*lencopied = bytes_copied;
		}
		break;
	case COPYIO_IN_WORD:
		result = _copyin_word(src, (uint64_t *)(uintptr_t)dst, nbytes);
		break;
	case COPYIO_OUT:
		result = _bcopyout(src, dst, nbytes);
		break;
	default:
		result = EINVAL;
	}

    user_access_disable();
	return result;
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
copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
	int result;

	if (user_addr >= VM_MIN_KERNEL_ADDRESS || user_addr + nbytes >= VM_MIN_KERNEL_ADDRESS) {
		if (current_thread()->map->pmap == kernel_pmap)
			return copyin_kern(user_addr, kernel_addr, nbytes);
		else
			return EFAULT;
	}

	if (nbytes >= 4096) {
		result = copyin_validate(user_addr, (uintptr_t)kernel_addr, nbytes);
		if (result) return result;
	}

	result = copyio_check_user_addr(user_addr, nbytes);

	if (result) return result;

	return copyio(COPYIO_IN, (const char *)(uintptr_t)user_addr, kernel_addr, nbytes, NULL);
}

/*
 * copyin_word
 * Read an aligned value from userspace as a single memory transaction.
 * This function supports userspace synchronization features
 */
int
copyin_word(const user_addr_t user_addr, uint64_t *kernel_addr, vm_size_t nbytes)
{
	int			result;

	/* Verify sizes */
	if ((nbytes != 4) && (nbytes != 8))
		return EINVAL;

	/* Test alignment */
	if (user_addr & (nbytes - 1))
		return EINVAL;

	/* Address must be user */
	if (user_addr >= VM_MIN_KERNEL_ADDRESS || user_addr + nbytes >= VM_MIN_KERNEL_ADDRESS)
		return EFAULT;

	result = copyio_check_user_addr(user_addr, nbytes);
	if (result)
		return result;

	return copyio(COPYIO_IN_WORD, (const char *)user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL);
}

int
copyinstr(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	int result;

	if (user_addr >= VM_MIN_KERNEL_ADDRESS || user_addr + nbytes >= VM_MIN_KERNEL_ADDRESS) {
		return EFAULT;
	}

	result = copyio_check_user_addr(user_addr, nbytes);

	if (result) return result;

	if (!nbytes) {
		return ENAMETOOLONG;
	}

	return copyio(COPYIO_INSTR, (const char *)(uintptr_t)user_addr, kernel_addr, nbytes, lencopied);
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	int result;

	if (user_addr >= VM_MIN_KERNEL_ADDRESS || user_addr + nbytes >= VM_MIN_KERNEL_ADDRESS) {
		if (current_thread()->map->pmap == kernel_pmap)
			return copyout_kern(kernel_addr, user_addr, nbytes);
		else
			return EFAULT;
	}

	if (nbytes >= 4096) {
		result = copyout_validate((uintptr_t)kernel_addr, user_addr, nbytes);
		if (result) return result;
	}

	result = copyio_check_user_addr(user_addr, nbytes);

	if (result) return result;

	return copyio(COPYIO_OUT, kernel_addr, (char *)(uintptr_t)user_addr, nbytes, NULL);
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

/*
 * Validate the arguments to copy{in,out} on this platform.
 *
 * Called when nbytes is "large" e.g. more than a page.  Such sizes are
 * infrequent, and very large sizes are likely indications of attempts
 * to exploit kernel programming errors (bugs).
 */
static int
copy_validate(const user_addr_t user_addr,
	uintptr_t kernel_addr, vm_size_t nbytes)
{
	uintptr_t kernel_addr_last = kernel_addr + nbytes;

	if (kernel_addr < VM_MIN_KERNEL_ADDRESS ||
	    kernel_addr > VM_MAX_KERNEL_ADDRESS ||
	    kernel_addr_last < kernel_addr ||
	    kernel_addr_last > VM_MAX_KERNEL_ADDRESS)
		panic("%s(%p, %p, %lu) - kaddr not in kernel", __func__,
		       (void *)user_addr, (void *)kernel_addr, nbytes);

	user_addr_t user_addr_last = user_addr + nbytes;

	if (user_addr_last < user_addr || user_addr_last > VM_MIN_KERNEL_ADDRESS)
		return (EFAULT);

	if (__improbable(nbytes > copysize_limit_panic))
		panic("%s(%p, %p, %lu) - transfer too large", __func__,
		       (void *)user_addr, (void *)kernel_addr, nbytes);

	return (0);
}

int
copyin_validate(const user_addr_t ua, uintptr_t ka, vm_size_t nbytes)
{
	return (copy_validate(ua, ka, nbytes));
}

int
copyout_validate(uintptr_t ka, const user_addr_t ua, vm_size_t nbytes)
{
	return (copy_validate(ua, ka, nbytes));
}

