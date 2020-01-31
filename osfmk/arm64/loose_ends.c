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

#define BCOPY_PHYS_SRC_IS_PHYS(flags) (((flags) & cppvPsrc) != 0)
#define BCOPY_PHYS_DST_IS_PHYS(flags) (((flags) & cppvPsnk) != 0)
#define BCOPY_PHYS_SRC_IS_USER(flags) (((flags) & (cppvPsrc | cppvKmap)) == 0)
#define BCOPY_PHYS_DST_IS_USER(flags) (((flags) & (cppvPsnk | cppvKmap)) == 0)

static kern_return_t
bcopy_phys_internal(addr64_t src, addr64_t dst, vm_size_t bytes, int flags)
{
	unsigned int    src_index;
	unsigned int    dst_index;
	vm_offset_t     src_offset;
	vm_offset_t     dst_offset;
	unsigned int    wimg_bits_src, wimg_bits_dst;
	unsigned int    cpu_num = 0;
	ppnum_t         pn_src;
	ppnum_t         pn_dst;
	addr64_t        end __assert_only;
	kern_return_t   res = KERN_SUCCESS;

	assert(!__improbable(os_add_overflow(src, bytes, &end)));
	assert(!__improbable(os_add_overflow(dst, bytes, &end)));

	while ((bytes > 0) && (res == KERN_SUCCESS)) {
		src_offset = src & PAGE_MASK;
		dst_offset = dst & PAGE_MASK;
		boolean_t use_copy_window_src = FALSE;
		boolean_t use_copy_window_dst = FALSE;
		vm_size_t count = bytes;
		vm_size_t count2 = bytes;
		if (BCOPY_PHYS_SRC_IS_PHYS(flags)) {
			use_copy_window_src = !pmap_valid_address(src);
			pn_src = (ppnum_t)(src >> PAGE_SHIFT);
#if !defined(__ARM_COHERENT_IO__) && !__ARM_PTE_PHYSMAP__
			count = PAGE_SIZE - src_offset;
			wimg_bits_src = pmap_cache_attributes(pn_src);
			if ((wimg_bits_src & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
				use_copy_window_src = TRUE;
			}
#else
			if (use_copy_window_src) {
				wimg_bits_src = pmap_cache_attributes(pn_src);
				count = PAGE_SIZE - src_offset;
			}
#endif
		}
		if (BCOPY_PHYS_DST_IS_PHYS(flags)) {
			// write preflighting needed for things like dtrace which may write static read-only mappings
			use_copy_window_dst = (!pmap_valid_address(dst) || !mmu_kvtop_wpreflight(phystokv((pmap_paddr_t)dst)));
			pn_dst = (ppnum_t)(dst >> PAGE_SHIFT);
#if !defined(__ARM_COHERENT_IO__) && !__ARM_PTE_PHYSMAP__
			count2 = PAGE_SIZE - dst_offset;
			wimg_bits_dst = pmap_cache_attributes(pn_dst);
			if ((wimg_bits_dst & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
				use_copy_window_dst = TRUE;
			}
#else
			if (use_copy_window_dst) {
				wimg_bits_dst = pmap_cache_attributes(pn_dst);
				count2 = PAGE_SIZE - dst_offset;
			}
#endif
		}

		char *tmp_src;
		char *tmp_dst;

		if (use_copy_window_src || use_copy_window_dst) {
			mp_disable_preemption();
			cpu_num = cpu_number();
		}

		if (use_copy_window_src) {
			src_index = pmap_map_cpu_windows_copy(pn_src, VM_PROT_READ, wimg_bits_src);
			tmp_src = (char*)(pmap_cpu_windows_copy_addr(cpu_num, src_index) + src_offset);
		} else if (BCOPY_PHYS_SRC_IS_PHYS(flags)) {
			tmp_src = (char*)phystokv_range((pmap_paddr_t)src, &count);
		} else {
			tmp_src = (char*)src;
		}
		if (use_copy_window_dst) {
			dst_index = pmap_map_cpu_windows_copy(pn_dst, VM_PROT_READ | VM_PROT_WRITE, wimg_bits_dst);
			tmp_dst = (char*)(pmap_cpu_windows_copy_addr(cpu_num, dst_index) + dst_offset);
		} else if (BCOPY_PHYS_DST_IS_PHYS(flags)) {
			tmp_dst = (char*)phystokv_range((pmap_paddr_t)dst, &count2);
		} else {
			tmp_dst = (char*)dst;
		}

		if (count > count2) {
			count = count2;
		}
		if (count > bytes) {
			count = bytes;
		}

		if (BCOPY_PHYS_SRC_IS_USER(flags)) {
			res = copyin((user_addr_t)src, tmp_dst, count);
		} else if (BCOPY_PHYS_DST_IS_USER(flags)) {
			res = copyout(tmp_src, (user_addr_t)dst, count);
		} else {
			bcopy(tmp_src, tmp_dst, count);
		}

		if (use_copy_window_src) {
			pmap_unmap_cpu_windows_copy(src_index);
		}
		if (use_copy_window_dst) {
			pmap_unmap_cpu_windows_copy(dst_index);
		}
		if (use_copy_window_src || use_copy_window_dst) {
			mp_enable_preemption();
		}

		src += count;
		dst += count;
		bytes -= count;
	}
	return res;
}

void
bcopy_phys(addr64_t src, addr64_t dst, vm_size_t bytes)
{
	bcopy_phys_internal(src, dst, bytes, cppvPsrc | cppvPsnk);
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
	unsigned int    cpu_num = cpu_number();
	ppnum_t         pn;
	addr64_t        end __assert_only;

	assert(!__improbable(os_add_overflow(src, bytes, &end)));

	vm_offset_t offset = src & PAGE_MASK;
	while (bytes > 0) {
		vm_size_t count = bytes;

		boolean_t use_copy_window = !pmap_valid_address(src);
		pn = (ppnum_t)(src >> PAGE_SHIFT);
#if !defined(__ARM_COHERENT_IO__) && !__ARM_PTE_PHYSMAP__
		count = PAGE_SIZE - offset;
		wimg_bits = pmap_cache_attributes(pn);
		if ((wimg_bits & VM_WIMG_MASK) != VM_WIMG_DEFAULT) {
			use_copy_window = TRUE;
		}
#else
		if (use_copy_window) {
			wimg_bits = pmap_cache_attributes(pn);
			count = PAGE_SIZE - offset;
		}
#endif
		char *buf;
		unsigned int index;
		if (use_copy_window) {
			mp_disable_preemption();
			cpu_num = cpu_number();
			index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ | VM_PROT_WRITE, wimg_bits);
			buf = (char *)(pmap_cpu_windows_copy_addr(cpu_num, index) + offset);
		} else {
			buf = (char *)phystokv_range((pmap_paddr_t)src, &count);
		}

		if (count > bytes) {
			count = bytes;
		}

		bzero(buf, count);

		if (use_copy_window) {
			pmap_unmap_cpu_windows_copy(index);
			mp_enable_preemption();
		}

		src += count;
		bytes -= count;
		offset = 0;
	}
}

/*
 *  Read data from a physical address.
 */


static unsigned long long
ml_phys_read_data(pmap_paddr_t paddr, int size)
{
	unsigned int   index;
	unsigned int   wimg_bits;
	ppnum_t        pn = (ppnum_t)(paddr >> PAGE_SHIFT);
	ppnum_t        pn_end = (ppnum_t)((paddr + size - 1) >> PAGE_SHIFT);
	unsigned long  long result = 0;
	vm_offset_t    copywindow_vaddr = 0;
	unsigned char  s1;
	unsigned short s2;
	unsigned int   s4;

	if (__improbable(pn_end != pn)) {
		panic("%s: paddr 0x%llx spans a page boundary", __func__, (uint64_t)paddr);
	}

#if defined(__ARM_COHERENT_IO__) || __ARM_PTE_PHYSMAP__
	if (pmap_valid_address(paddr)) {
		switch (size) {
		case 1:
			s1 = *(volatile unsigned char *)phystokv(paddr);
			result = s1;
			break;
		case 2:
			s2 = *(volatile unsigned short *)phystokv(paddr);
			result = s2;
			break;
		case 4:
			s4 = *(volatile unsigned int *)phystokv(paddr);
			result = s4;
			break;
		case 8:
			result = *(volatile unsigned long long *)phystokv(paddr);
			break;
		default:
			panic("Invalid size %d for ml_phys_read_data\n", size);
			break;
		}
		return result;
	}
#endif

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ, wimg_bits);
	copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | ((uint32_t)paddr & PAGE_MASK);

	switch (size) {
	case 1:
		s1 = *(volatile unsigned char *)copywindow_vaddr;
		result = s1;
		break;
	case 2:
		s2 = *(volatile unsigned short *)copywindow_vaddr;
		result = s2;
		break;
	case 4:
		s4 = *(volatile unsigned int *)copywindow_vaddr;
		result = s4;
		break;
	case 8:
		result = *(volatile unsigned long long*)copywindow_vaddr;
		break;
	default:
		panic("Invalid size %d for ml_phys_read_data\n", size);
		break;
	}

	pmap_unmap_cpu_windows_copy(index);
	mp_enable_preemption();

	return result;
}

unsigned int
ml_phys_read( vm_offset_t paddr)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int
ml_phys_read_word(vm_offset_t paddr)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int
ml_phys_read_64(addr64_t paddr64)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int
ml_phys_read_word_64(addr64_t paddr64)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int
ml_phys_read_half(vm_offset_t paddr)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr, 2);
}

unsigned int
ml_phys_read_half_64(addr64_t paddr64)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr64, 2);
}

unsigned int
ml_phys_read_byte(vm_offset_t paddr)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr, 1);
}

unsigned int
ml_phys_read_byte_64(addr64_t paddr64)
{
	return (unsigned int)ml_phys_read_data((pmap_paddr_t)paddr64, 1);
}

unsigned long long
ml_phys_read_double(vm_offset_t paddr)
{
	return ml_phys_read_data((pmap_paddr_t)paddr, 8);
}

unsigned long long
ml_phys_read_double_64(addr64_t paddr64)
{
	return ml_phys_read_data((pmap_paddr_t)paddr64, 8);
}



/*
 *  Write data to a physical address.
 */

static void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long long data, int size)
{
	unsigned int    index;
	unsigned int    wimg_bits;
	ppnum_t         pn = (ppnum_t)(paddr >> PAGE_SHIFT);
	ppnum_t         pn_end = (ppnum_t)((paddr + size - 1) >> PAGE_SHIFT);
	vm_offset_t     copywindow_vaddr = 0;

	if (__improbable(pn_end != pn)) {
		panic("%s: paddr 0x%llx spans a page boundary", __func__, (uint64_t)paddr);
	}

#if defined(__ARM_COHERENT_IO__) || __ARM_PTE_PHYSMAP__
	if (pmap_valid_address(paddr)) {
		switch (size) {
		case 1:
			*(volatile unsigned char *)phystokv(paddr) = (unsigned char)data;
			return;
		case 2:
			*(volatile unsigned short *)phystokv(paddr) = (unsigned short)data;
			return;
		case 4:
			*(volatile unsigned int *)phystokv(paddr) = (unsigned int)data;
			return;
		case 8:
			*(volatile unsigned long long *)phystokv(paddr) = data;
			return;
		default:
			panic("Invalid size %d for ml_phys_write_data\n", size);
		}
	}
#endif

	mp_disable_preemption();
	wimg_bits = pmap_cache_attributes(pn);
	index = pmap_map_cpu_windows_copy(pn, VM_PROT_READ | VM_PROT_WRITE, wimg_bits);
	copywindow_vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | ((uint32_t)paddr & PAGE_MASK);

	switch (size) {
	case 1:
		*(volatile unsigned char *)(copywindow_vaddr) =
		    (unsigned char)data;
		break;
	case 2:
		*(volatile unsigned short *)(copywindow_vaddr) =
		    (unsigned short)data;
		break;
	case 4:
		*(volatile unsigned int *)(copywindow_vaddr) =
		    (uint32_t)data;
		break;
	case 8:
		*(volatile unsigned long long *)(copywindow_vaddr) =
		    (unsigned long long)data;
		break;
	default:
		panic("Invalid size %d for ml_phys_write_data\n", size);
		break;
	}

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
	ml_phys_write_data((pmap_paddr_t)paddr, data, 8);
}

void
ml_phys_write_double_64(addr64_t paddr64, unsigned long long data)
{
	ml_phys_write_data((pmap_paddr_t)paddr64, data, 8);
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

#undef bcmp
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

	/*
	 * Check for the overflow case but continue to handle the non-overflow
	 * case the same way just in case someone is using the return value
	 * as more than zero/non-zero
	 */
	if ((len & 0xFFFFFFFF00000000ULL) && !(len & 0x00000000FFFFFFFFULL)) {
		return 0xFFFFFFFFL;
	} else {
		return (int)len;
	}
}

#undef memcmp
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

kern_return_t
copypv(addr64_t source, addr64_t sink, unsigned int size, int which)
{
	if ((which & (cppvPsrc | cppvPsnk)) == 0) {     /* Make sure that only one is virtual */
		panic("%s: no more than 1 parameter may be virtual", __func__);
	}

	kern_return_t res = bcopy_phys_internal(source, sink, size, which);

#ifndef __ARM_COHERENT_IO__
	if (which & cppvFsrc) {
		flush_dcache64(source, size, ((which & cppvPsrc) == cppvPsrc));
	}

	if (which & cppvFsnk) {
		flush_dcache64(sink, size, ((which & cppvPsnk) == cppvPsnk));
	}
#endif

	return res;
}

#if     MACH_ASSERT

extern int copyinframe(vm_address_t fp, char *frame, boolean_t is64bit);

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

	struct arm_saved_state *state = find_user_regs(current_thread());

	if (!state) {
		while (i < callstack_max) {
			buf[i++] = 0;
		}
	} else {
		if (is_saved_state64(state)) {
			uint64_t frame[2];
			buf[i++] = (uintptr_t)get_saved_state_pc(state);
			frame[0] = get_saved_state_fp(state);
			while (i < callstack_max && frame[0] != 0) {
				if (copyinframe(frame[0], (void*) frame, TRUE)) {
					break;
				}
				buf[i++] = (uintptr_t)frame[1];
			}
		} else {
			uint32_t frame[2];
			buf[i++] = (uintptr_t)get_saved_state_pc(state);
			frame[0] = (uint32_t)get_saved_state_fp(state);
			while (i < callstack_max && frame[0] != 0) {
				if (copyinframe(frame[0], (void*) frame, FALSE)) {
					break;
				}
				buf[i++] = (uintptr_t)frame[1];
			}
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

void
panic_unimplemented()
{
	panic("Not yet implemented.");
}

/* ARM64_TODO <rdar://problem/9198953> */
void abort(void);

void
abort()
{
	panic("Abort.");
}


#if !MACH_KDP
void
kdp_register_callout(kdp_callout_fn_t fn, void *arg)
{
#pragma unused(fn,arg)
}
#endif
