/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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

#include <mach_assert.h>
#include <mach/vm_types.h>
#include <mach/mach_time.h>
#include <kern/timer.h>
#include <kern/clock.h>
#include <kern/machine.h>
#include <mach/machine.h>
#include <mach/machine/vm_param.h>
#include <mach_kdp.h>
#include <kdp/kdp_udp.h>
#if !MACH_KDP
#include <kdp/kdp_callout.h>
#endif /* !MACH_KDP */
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/caches_internal.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <arm/misc_protos.h>

#include <sys/errno.h>

#define INT_SIZE        (BYTE_SIZE * sizeof (int))

/* machine_routines_asm.s calls these */
extern int copyin_validate(const user_addr_t, uintptr_t, vm_size_t);
extern int copyin_user_validate(const user_addr_t, uintptr_t, vm_size_t);
extern int copyout_validate(uintptr_t, const user_addr_t, vm_size_t);
extern int copyio_user_validate(int, int, user_addr_t, vm_size_t);
extern int copyoutstr_prevalidate(const void *, user_addr_t, size_t);

void
bcopy_phys(addr64_t src, addr64_t dst, vm_size_t bytes)
{
	unsigned int    src_index;
	unsigned int    dst_index;
	vm_offset_t     src_offset;
	vm_offset_t     dst_offset;
	unsigned int    cpu_num;
	unsigned int    wimg_bits_src, wimg_bits_dst;
	ppnum_t         pn_src = (src >> PAGE_SHIFT);
	ppnum_t         pn_dst = (dst >> PAGE_SHIFT);

	wimg_bits_src = pmap_cache_attributes(pn_src);
	wimg_bits_dst = pmap_cache_attributes(pn_dst);

	if (mmu_kvtop_wpreflight(phystokv((pmap_paddr_t) dst)) &&
	    ((wimg_bits_src & VM_WIMG_MASK) == VM_WIMG_DEFAULT) &&
	    ((wimg_bits_dst & VM_WIMG_MASK) == VM_WIMG_DEFAULT)) {
		/* Fast path - dst is writable and both source and destination have default attributes */
		bcopy((char *)phystokv((pmap_paddr_t) src), (char *)phystokv((pmap_paddr_t) dst), bytes);
		return;
	}

	src_offset = src & PAGE_MASK;
	dst_offset = dst & PAGE_MASK;

	if ((src_offset + bytes) > PAGE_SIZE || (dst_offset + bytes) > PAGE_SIZE) {
		panic("bcopy extends beyond copy windows");
	}

	mp_disable_preemption();
	cpu_num = cpu_number();
	src_index = pmap_map_cpu_windows_copy(pn_src, VM_PROT_READ, wimg_bits_src);
	dst_index = pmap_map_cpu_windows_copy(pn_dst, VM_PROT_READ | VM_PROT_WRITE, wimg_bits_dst);

	bcopy((char *)(pmap_cpu_windows_copy_addr(cpu_num, src_index) + src_offset),
	    (char *)(pmap_cpu_windows_copy_addr(cpu_num, dst_index) + dst_offset),
	    bytes);

	pmap_unmap_cpu_windows_copy(src_index);
	pmap_unmap_cpu_windows_copy(dst_index);
	mp_enable_preemption();
}

void
bzero_phys_nc(addr64_t src64, vm_size_t bytes)
{
	bzero_phys(src64, bytes);
}

/* Zero bytes starting at a physical address */
void
bzero_phys(addr64_t src, vm_size_t bytes)
{
	unsigned int    wimg_bits;
	ppnum_t         pn = (src >> PAGE_SHIFT);

	wimg_bits = pmap_cache_attributes(pn);
	if (__probable((wimg_bits & VM_WIMG_MASK) == VM_WIMG_DEFAULT)) {
		/* Fast path - default attributes */
		bzero((char *)phystokv((pmap_paddr_t) src), bytes);
	} else {
		mp_disable_preemption();

		unsigned int cpu_num = cpu_number();

		while (bytes > 0) {
			vm_offset_t offset = src & PAGE_MASK;
			uint32_t count = PAGE_SIZE - offset;

			if (count > bytes) {
				count = bytes;
			}

			unsigned int index = pmap_map_cpu_windows_copy(src >> PAGE_SHIFT, VM_PROT_READ | VM_PROT_WRITE, wimg_bits);

			bzero((char *)(pmap_cpu_windows_copy_addr(cpu_num, index) + offset), count);

			pmap_unmap_cpu_windows_copy(index);

			src += count;
			bytes -= count;
		}

		mp_enable_preemption();
	}
}

/*
 *  Read data from a physical address.
 */


static unsigned int
ml_phys_read_data(pmap_paddr_t paddr, int size)
{
	unsigned int    index;
	unsigned int    result;
	unsigned int    wimg_bits;
	ppnum_t         pn = (paddr >> PAGE_SHIFT);
	unsigned char   s1;
	unsigned short  s2;
	vm_offset_t     copywindow_vaddr = 0;

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ, wimg_bits);
	copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | ((uint32_t)paddr & PAGE_MASK);;

	switch (size) {
	case 1:
		s1 = *(volatile unsigned char *)(copywindow_vaddr);
		result = s1;
		break;
	case 2:
		s2 = *(volatile unsigned short *)(copywindow_vaddr);
		result = s2;
		break;
	case 4:
	default:
		result = *(volatile unsigned int *)(copywindow_vaddr);
		break;
	}

	pmap_unmap_cpu_windows_copy(index);
	mp_enable_preemption();

	return result;
}

static unsigned long long
ml_phys_read_long_long(pmap_paddr_t paddr)
{
	unsigned int    index;
	unsigned int    result;
	unsigned int    wimg_bits;
	ppnum_t         pn = (paddr >> PAGE_SHIFT);

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ, wimg_bits);

	result = *(volatile unsigned long long *)(pmap_cpu_windows_copy_addr(cpu_number(), index)
	    | ((uint32_t)paddr & PAGE_MASK));

	pmap_unmap_cpu_windows_copy(index);
	mp_enable_preemption();

	return result;
}

unsigned int
ml_phys_read( vm_offset_t paddr)
{
	return ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int
ml_phys_read_word(vm_offset_t paddr)
{
	return ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int
ml_phys_read_64(addr64_t paddr64)
{
	return ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int
ml_phys_read_word_64(addr64_t paddr64)
{
	return ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int
ml_phys_read_half(vm_offset_t paddr)
{
	return ml_phys_read_data((pmap_paddr_t)paddr, 2);
}

unsigned int
ml_phys_read_half_64(addr64_t paddr64)
{
	return ml_phys_read_data((pmap_paddr_t)paddr64, 2);
}

unsigned int
ml_phys_read_byte(vm_offset_t paddr)
{
	return ml_phys_read_data((pmap_paddr_t)paddr, 1);
}

unsigned int
ml_phys_read_byte_64(addr64_t paddr64)
{
	return ml_phys_read_data((pmap_paddr_t)paddr64, 1);
}

unsigned long long
ml_phys_read_double(vm_offset_t paddr)
{
	return ml_phys_read_long_long((pmap_paddr_t)paddr);
}

unsigned long long
ml_phys_read_double_64(addr64_t paddr64)
{
	return ml_phys_read_long_long((pmap_paddr_t)paddr64);
}



/*
 *  Write data to a physical address.
 */

static void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long data, int size)
{
	unsigned int    index;
	unsigned int    wimg_bits;
	ppnum_t         pn = (paddr >> PAGE_SHIFT);
	vm_offset_t     copywindow_vaddr = 0;

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ | VM_PROT_WRITE, wimg_bits);
	copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | ((uint32_t) paddr & PAGE_MASK);

	switch (size) {
	case 1:
		*(volatile unsigned char *)(copywindow_vaddr) = (unsigned char)data;
		break;
	case 2:
		*(volatile unsigned short *)(copywindow_vaddr) = (unsigned short)data;
		break;
	case 4:
	default:
		*(volatile unsigned int *)(copywindow_vaddr) = (uint32_t)data;
		break;
	}

	pmap_unmap_cpu_windows_copy(index);
	mp_enable_preemption();
}

static void
ml_phys_write_long_long(pmap_paddr_t paddr, unsigned long long data)
{
	unsigned int    index;
	unsigned int    wimg_bits;
	ppnum_t         pn = (paddr >> PAGE_SHIFT);

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ | VM_PROT_WRITE, wimg_bits);

	*(volatile unsigned long long *)(pmap_cpu_windows_copy_addr(cpu_number(), index)
	| ((uint32_t)paddr & PAGE_MASK)) = data;

	pmap_unmap_cpu_windows_copy(index);
	mp_enable_preemption();
}



void
ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr, data, 1);
}

void
ml_phys_write_byte_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr64, data, 1);
}

void
ml_phys_write_half(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr, data, 2);
}

void
ml_phys_write_half_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr64, data, 2);
}

void
ml_phys_write(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr, data, 4);
}

void
ml_phys_write_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr64, data, 4);
}

void
ml_phys_write_word(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr, data, 4);
}

void
ml_phys_write_word_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data((pmap_paddr_t)paddr64, data, 4);
}

void
ml_phys_write_double(vm_offset_t paddr, unsigned long long data)
{
	ml_phys_write_long_long((pmap_paddr_t)paddr, data);
}

void
ml_phys_write_double_64(addr64_t paddr64, unsigned long long data)
{
	ml_phys_write_long_long((pmap_paddr_t)paddr64, data);
}


/*
 * Set indicated bit in bit string.
 */
void
setbit(int bitno, int *s)
{
	s[bitno / INT_SIZE] |= 1 << (bitno % INT_SIZE);
}

/*
 * Clear indicated bit in bit string.
 */
void
clrbit(int bitno, int *s)
{
	s[bitno / INT_SIZE] &= ~(1 << (bitno % INT_SIZE));
}

/*
 * Test if indicated bit is set in bit string.
 */
int
testbit(int bitno, int *s)
{
	return s[bitno / INT_SIZE] & (1 << (bitno % INT_SIZE));
}

/*
 * Find first bit set in bit string.
 */
int
ffsbit(int *s)
{
	int             offset;

	for (offset = 0; !*s; offset += INT_SIZE, ++s) {
		;
	}
	return offset + __builtin_ctz(*s);
}

int
ffs(unsigned int mask)
{
	if (mask == 0) {
		return 0;
	}

	/*
	 * NOTE: cannot use __builtin_ffs because it generates a call to
	 * 'ffs'
	 */
	return 1 + __builtin_ctz(mask);
}

int
ffsll(unsigned long long mask)
{
	if (mask == 0) {
		return 0;
	}

	/*
	 * NOTE: cannot use __builtin_ffsll because it generates a call to
	 * 'ffsll'
	 */
	return 1 + __builtin_ctzll(mask);
}

/*
 * Find last bit set in bit string.
 */
int
fls(unsigned int mask)
{
	if (mask == 0) {
		return 0;
	}

	return (sizeof(mask) << 3) - __builtin_clz(mask);
}

int
flsll(unsigned long long mask)
{
	if (mask == 0) {
		return 0;
	}

	return (sizeof(mask) << 3) - __builtin_clzll(mask);
}

int
bcmp(
	const void *pa,
	const void *pb,
	size_t len)
{
	const char     *a = (const char *) pa;
	const char     *b = (const char *) pb;

	if (len == 0) {
		return 0;
	}

	do{
		if (*a++ != *b++) {
			break;
		}
	} while (--len);

	return len;
}

int
memcmp(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++) {
				return *--p1 - *--p2;
			}
		} while (--n != 0);
	}
	return 0;
}

unsigned long
memcmp_zero_ptr_aligned(const void *s, size_t n)
{
	uintptr_t p = (uintptr_t)s;
	uintptr_t end = (uintptr_t)s + n;
	uint32_t a, b;

	static_assert(sizeof(unsigned long) == sizeof(uint32_t));

	a = *(const uint32_t *)p;
	b = *(const uint32_t *)(end - sizeof(uint32_t));

	/*
	 * align p to the next 64bit boundary
	 * align end to the previous 64bit boundary
	 *
	 * and do a nice ldrd loop.
	 */
	p = (p + sizeof(uint64_t) - 1) & -sizeof(uint64_t);
	end &= -sizeof(uint64_t);

	for (; p < end; p += sizeof(uint64_t)) {
		uint64_t v = *(const uint64_t *)p;
		a |= (uint32_t)v;
		b |= (uint32_t)(v >> 32);
	}

	return a | b;
}

kern_return_t
copypv(addr64_t source, addr64_t sink, unsigned int size, int which)
{
	kern_return_t   retval = KERN_SUCCESS;
	void            *from, *to;
	unsigned int    from_wimg_bits, to_wimg_bits;

	from = CAST_DOWN(void *, source);
	to = CAST_DOWN(void *, sink);

	if ((which & (cppvPsrc | cppvPsnk)) == 0) {     /* Make sure that only
		                                         * one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");     /* Not allowed */
	}
	if (which & cppvPsrc) {
		from = (void *)phystokv((pmap_paddr_t)from);
	}
	if (which & cppvPsnk) {
		to = (void *)phystokv((pmap_paddr_t)to);
	}

	if ((which & (cppvPsrc | cppvKmap)) == 0) {     /* Source is virtual in
		                                         * current map */
		retval = copyin((user_addr_t) from, to, size);
	} else if ((which & (cppvPsnk | cppvKmap)) == 0) { /* Sink is virtual in
		                                            * current map */
		retval = copyout(from, (user_addr_t) to, size);
	} else {                /* both addresses are physical or kernel map */
		bcopy(from, to, size);
	}

	if (which & cppvFsrc) {
		flush_dcache64(source, size, ((which & cppvPsrc) == cppvPsrc));
	} else if (which & cppvPsrc) {
		from_wimg_bits = pmap_cache_attributes(source >> PAGE_SHIFT);
		if ((from_wimg_bits != VM_WIMG_COPYBACK) && (from_wimg_bits != VM_WIMG_WTHRU)) {
			flush_dcache64(source, size, TRUE);
		}
	}

	if (which & cppvFsnk) {
		flush_dcache64(sink, size, ((which & cppvPsnk) == cppvPsnk));
	} else if (which & cppvPsnk) {
		to_wimg_bits = pmap_cache_attributes(sink >> PAGE_SHIFT);
		if (to_wimg_bits != VM_WIMG_COPYBACK) {
			flush_dcache64(sink, size, TRUE);
		}
	}
	return retval;
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

static int
copy_validate_user(const user_addr_t user_addr, vm_size_t nbytes, bool kern_to_kern_allowed)
{
	user_addr_t user_addr_last = user_addr + nbytes;
	thread_t self = current_thread();

	if (__improbable(!kern_to_kern_allowed && is_kernel_to_kernel_copy())) {
		return EFAULT;
	}

	if (__improbable((user_addr_last < user_addr) ||
	    ((user_addr + nbytes) > vm_map_max(self->map)) ||
	    (user_addr < vm_map_min(self->map)))) {
		return EFAULT;
	}

	if (__improbable(nbytes > copysize_limit_panic)) {
		panic("%s(%p, ..., %u) - transfer too large", __func__,
		    (void *)user_addr, nbytes);
	}

	return 0;
}

/*
 * Validate the arguments to copy{in,out} on this platform.
 *
 * Called when nbytes is "large" e.g. more than a page.  Such sizes are
 * infrequent, and very large sizes are likely indications of attempts
 * to exploit kernel programming errors (bugs).
 */
static int
copy_validate(const user_addr_t user_addr,
    uintptr_t kernel_addr, vm_size_t nbytes, bool kern_to_kern_allowed)
{
	uintptr_t kernel_addr_last = kernel_addr + nbytes;

	if (__improbable(kernel_addr < VM_MIN_KERNEL_ADDRESS ||
	    kernel_addr > VM_MAX_KERNEL_ADDRESS ||
	    kernel_addr_last < kernel_addr ||
	    kernel_addr_last > VM_MAX_KERNEL_ADDRESS)) {
		panic("%s(%p, %p, %u) - kaddr not in kernel", __func__,
		    (void *)user_addr, (void *)kernel_addr, nbytes);
	}

	return copy_validate_user(user_addr, nbytes, kern_to_kern_allowed);
}

int
copyin_validate(const user_addr_t ua, uintptr_t ka, vm_size_t nbytes)
{
	return copy_validate(ua, ka, nbytes, true);
}

int
copyin_user_validate(const user_addr_t ua, uintptr_t ka, vm_size_t nbytes)
{
	return copy_validate(ua, ka, nbytes, false);
}

int
copyout_validate(uintptr_t ka, const user_addr_t ua, vm_size_t nbytes)
{
	return copy_validate(ua, ka, nbytes, true);
}

int
copyio_user_validate(int a __unused, int b __unused,
    user_addr_t ua, vm_size_t nbytes)
{
	return copy_validate_user(ua, nbytes, false);
}

int
copyoutstr_prevalidate(const void *__unused kaddr, user_addr_t __unused uaddr, size_t __unused len)
{
	if (__improbable(is_kernel_to_kernel_copy())) {
		return EFAULT;
	}

	return 0;
}

#if     MACH_ASSERT

extern int copyinframe(vm_address_t fp, char *frame);

/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
void
machine_callstack(
	uintptr_t * buf,
	vm_size_t callstack_max)
{
	/* Captures the USER call stack */
	uint32_t i = 0;
	uint32_t frame[2];

	struct arm_saved_state* state = find_user_regs(current_thread());

	if (!state) {
		while (i < callstack_max) {
			buf[i++] = 0;
		}
	} else {
		buf[i++] = (uintptr_t)state->pc;
		frame[0] = state->r[7];

		while (i < callstack_max && frame[0] != 0) {
			if (copyinframe(frame[0], (void*) frame)) {
				break;
			}
			buf[i++] = (uintptr_t)frame[1];
		}

		while (i < callstack_max) {
			buf[i++] = 0;
		}
	}
}

#endif                          /* MACH_ASSERT */

int
clr_be_bit(void)
{
	panic("clr_be_bit");
	return 0;
}

boolean_t
ml_probe_read(
	__unused vm_offset_t paddr,
	__unused unsigned int *val)
{
	panic("ml_probe_read() unimplemented");
	return 1;
}

boolean_t
ml_probe_read_64(
	__unused addr64_t paddr,
	__unused unsigned int *val)
{
	panic("ml_probe_read_64() unimplemented");
	return 1;
}


void
ml_thread_policy(
	__unused thread_t thread,
	__unused unsigned policy_id,
	__unused unsigned policy_info)
{
	//    <rdar://problem/7141284>: Reduce print noise
	//	kprintf("ml_thread_policy() unimplemented\n");
}

#if !MACH_KDP
void
kdp_register_callout(kdp_callout_fn_t fn, void *arg)
{
#pragma unused(fn,arg)
}
#endif
