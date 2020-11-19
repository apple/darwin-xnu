/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
#include <mach_assert.h>

#include <string.h>
#include <mach/boolean.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/vm_param.h>
#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <kern/locks.h>
#include <sys/errno.h>
#include <i386/param.h>
#include <i386/misc_protos.h>
#include <i386/panic_notify.h>
#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/cpuid.h>
#include <i386/vmx.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>
#include <sys/kdebug.h>

#if !MACH_KDP
#include <kdp/kdp_callout.h>
#endif /* !MACH_KDP */

#include <architecture/i386/pio.h>

#include <libkern/OSDebug.h>
#if CONFIG_DTRACE
#include <mach/sdt.h>
#endif

#if 0

#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#define KDEBUG 1

#endif

/* prevent infinite recursion when memmove calls bcopy; in string.h, bcopy is defined to call memmove */
#undef bcopy

/* XXX - should be gone from here */
extern void             invalidate_icache64(addr64_t addr, unsigned cnt, int phys);
extern void             flush_dcache64(addr64_t addr, unsigned count, int phys);
extern boolean_t        phys_page_exists(ppnum_t);
extern void             bcopy_no_overwrite(const char *from, char *to, vm_size_t bytes);
extern void             pmap_set_reference(ppnum_t pn);
extern void             mapping_set_mod(ppnum_t pa);
extern void             mapping_set_ref(ppnum_t pn);

extern void             ovbcopy(const char      *from,
    char            *to,
    vm_size_t       nbytes);
void machine_callstack(uintptr_t *buf, vm_size_t callstack_max);


#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000ULL)
#define low32(x)  ((unsigned int)((x) & 0x00000000FFFFFFFFULL))

#define INT_SIZE        (BYTE_SIZE * sizeof (int))

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

	for (offset = 0; !*s; offset += (int)INT_SIZE, ++s) {
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

void
bzero_phys_nc(
	addr64_t src64,
	uint32_t bytes)
{
	bzero_phys(src64, bytes);
}

void
bzero_phys(
	addr64_t src64,
	uint32_t bytes)
{
	bzero(PHYSMAP_PTOV(src64), bytes);
}


/*
 * bcopy_phys - like bcopy but copies from/to physical addresses.
 */

void
bcopy_phys(
	addr64_t src64,
	addr64_t dst64,
	vm_size_t bytes)
{
	/* Not necessary for K64 - but ensure we stay within a page */
	if (((((uint32_t)src64 & (NBPG - 1)) + bytes) > NBPG) ||
	    ((((uint32_t)dst64 & (NBPG - 1)) + bytes) > NBPG)) {
		panic("bcopy_phys alignment");
	}
	bcopy(PHYSMAP_PTOV(src64), PHYSMAP_PTOV(dst64), bytes);
}

/*
 * allow a function to get a quick virtual mapping of a physical page
 */

int
apply_func_phys(
	addr64_t dst64,
	vm_size_t bytes,
	int (*func)(void * buffer, vm_size_t bytes, void * arg),
	void * arg)
{
	/* Not necessary for K64 - but ensure we stay within a page */
	if (((((uint32_t)dst64 & (NBPG - 1)) + bytes) > NBPG)) {
		panic("apply_func_phys alignment");
	}

	return func(PHYSMAP_PTOV(dst64), bytes, arg);
}

/*
 * ovbcopy - like bcopy, but recognizes overlapping ranges and handles
 *           them correctly.
 */

void
ovbcopy(
	const char      *from,
	char            *to,
	vm_size_t       bytes)          /* num bytes to copy */
{
	/* Assume that bcopy copies left-to-right (low addr first). */
	if (from + bytes <= to || to + bytes <= from || to == from) {
		bcopy_no_overwrite(from, to, bytes);    /* non-overlapping or no-op*/
	} else if (from > to) {
		bcopy_no_overwrite(from, to, bytes);    /* overlapping but OK */
	} else {
		/* to > from: overlapping, and must copy right-to-left. */
		from += bytes - 1;
		to += bytes - 1;
		while (bytes-- > 0) {
			*to-- = *from--;
		}
	}
}


/*
 *  Read data from a physical address. Memory should not be cache inhibited.
 */

uint64_t reportphyreaddelayabs;
uint64_t reportphywritedelayabs;
uint32_t reportphyreadosbt;
uint32_t reportphywriteosbt;

#if DEVELOPMENT || DEBUG
uint32_t phyreadpanic = 1;
uint32_t phywritepanic = 1;
uint64_t tracephyreaddelayabs = 50 * NSEC_PER_USEC;
uint64_t tracephywritedelayabs = 50 * NSEC_PER_USEC;
uint64_t simulate_stretched_io = 0;
#else
uint32_t phyreadpanic = 0;
uint32_t phywritepanic = 0;
uint64_t tracephyreaddelayabs = 0;
uint64_t tracephywritedelayabs = 0;
#endif

__private_extern__ uint64_t
ml_phys_read_data(uint64_t paddr, int size)
{
	uint64_t result = 0;
	unsigned char s1;
	unsigned short s2;
	boolean_t istate = TRUE, timeread = FALSE;
	uint64_t sabs = 0, eabs;

	if (__improbable(!physmap_enclosed(paddr))) {
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);
	}

	if (__improbable(reportphyreaddelayabs != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timeread = TRUE;
	}
#if DEVELOPMENT || DEBUG
	if (__improbable(timeread && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* x86_64 DEVELOPMENT || DEBUG */

	switch (size) {
	case 1:
		s1 = *(volatile unsigned char *)PHYSMAP_PTOV(paddr);
		result = s1;
		break;
	case 2:
		s2 = *(volatile unsigned short *)PHYSMAP_PTOV(paddr);
		result = s2;
		break;
	case 4:
		result = *(volatile unsigned int *)PHYSMAP_PTOV(paddr);
		break;
	case 8:
		result = *(volatile unsigned long long *)PHYSMAP_PTOV(paddr);
		break;
	default:
		panic("Invalid size %d for ml_phys_read_data", size);
		break;
	}

	if (__improbable(timeread == TRUE)) {
		eabs = mach_absolute_time();

#if DEVELOPMENT || DEBUG
		iotrace(IOTRACE_PHYS_READ, 0, paddr, size, result, sabs, eabs - sabs);
#endif

		if (__improbable((eabs - sabs) > reportphyreaddelayabs)) {
			(void)ml_set_interrupts_enabled(istate);

			if (phyreadpanic && (machine_timeout_suspended() == FALSE)) {
				panic_notify();
				panic("Read from physical addr 0x%llx took %llu ns, "
				    "result: 0x%llx (start: %llu, end: %llu), ceiling: %llu",
				    paddr, (eabs - sabs), result, sabs, eabs,
				    reportphyreaddelayabs);
			}

			if (reportphyreadosbt) {
				OSReportWithBacktrace("ml_phys_read_data took %lluus",
				    (eabs - sabs) / NSEC_PER_USEC);
			}
#if CONFIG_DTRACE
			DTRACE_PHYSLAT4(physread, uint64_t, (eabs - sabs),
			    uint64_t, paddr, uint32_t, size, uint64_t, result);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(tracephyreaddelayabs > 0 && (eabs - sabs) > tracephyreaddelayabs)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_PHYS_READ),
			    (eabs - sabs), sabs, paddr, result);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}

	return result;
}

static unsigned long long
ml_phys_read_long_long(uint64_t paddr)
{
	return ml_phys_read_data(paddr, 8);
}

unsigned int
ml_phys_read(vm_offset_t paddr)
{
	return (unsigned int) ml_phys_read_data(paddr, 4);
}

unsigned int
ml_phys_read_word(vm_offset_t paddr)
{
	return (unsigned int) ml_phys_read_data(paddr, 4);
}

unsigned int
ml_phys_read_64(addr64_t paddr64)
{
	return (unsigned int) ml_phys_read_data(paddr64, 4);
}

unsigned int
ml_phys_read_word_64(addr64_t paddr64)
{
	return (unsigned int) ml_phys_read_data(paddr64, 4);
}

unsigned int
ml_phys_read_half(vm_offset_t paddr)
{
	return (unsigned int) ml_phys_read_data(paddr, 2);
}

unsigned int
ml_phys_read_half_64(addr64_t paddr64)
{
	return (unsigned int) ml_phys_read_data(paddr64, 2);
}

unsigned int
ml_phys_read_byte(vm_offset_t paddr)
{
	return (unsigned int) ml_phys_read_data(paddr, 1);
}

unsigned int
ml_phys_read_byte_64(addr64_t paddr64)
{
	return (unsigned int) ml_phys_read_data(paddr64, 1);
}

unsigned long long
ml_phys_read_double(vm_offset_t paddr)
{
	return ml_phys_read_long_long(paddr);
}

unsigned long long
ml_phys_read_double_64(addr64_t paddr64)
{
	return ml_phys_read_long_long(paddr64);
}



/*
 *  Write data to a physical address. Memory should not be cache inhibited.
 */

__private_extern__ void
ml_phys_write_data(uint64_t paddr, unsigned long long data, int size)
{
	boolean_t istate = TRUE, timewrite = FALSE;
	uint64_t sabs = 0, eabs;

	if (__improbable(!physmap_enclosed(paddr))) {
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);
	}

	if (__improbable(reportphywritedelayabs != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timewrite = TRUE;
	}
#if DEVELOPMENT || DEBUG
	if (__improbable(timewrite && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* x86_64 DEVELOPMENT || DEBUG */

	switch (size) {
	case 1:
		*(volatile unsigned char *)PHYSMAP_PTOV(paddr) = (unsigned char)data;
		break;
	case 2:
		*(volatile unsigned short *)PHYSMAP_PTOV(paddr) = (unsigned short)data;
		break;
	case 4:
		*(volatile unsigned int *)PHYSMAP_PTOV(paddr) = (unsigned int)data;
		break;
	case 8:
		*(volatile unsigned long *)PHYSMAP_PTOV(paddr) = data;
		break;
	default:
		panic("Invalid size %d for ml_phys_write_data", size);
		break;
	}

	if (__improbable(timewrite == TRUE)) {
		eabs = mach_absolute_time();

#if DEVELOPMENT || DEBUG
		iotrace(IOTRACE_PHYS_WRITE, 0, paddr, size, data, sabs, eabs - sabs);
#endif

		if (__improbable((eabs - sabs) > reportphywritedelayabs)) {
			(void)ml_set_interrupts_enabled(istate);

			if (phywritepanic && (machine_timeout_suspended() == FALSE)) {
				panic_notify();
				panic("Write to physical addr 0x%llx took %llu ns, "
				    "data: 0x%llx (start: %llu, end: %llu), ceiling: %llu",
				    paddr, (eabs - sabs), data, sabs, eabs,
				    reportphywritedelayabs);
			}

			if (reportphywriteosbt) {
				OSReportWithBacktrace("ml_phys_write_data (%p, 0x%llx) "
				    "took %lluus",
				    paddr, data, (eabs - sabs) / NSEC_PER_USEC);
			}
#if CONFIG_DTRACE
			DTRACE_PHYSLAT4(physwrite, uint64_t, (eabs - sabs),
			    uint64_t, paddr, uint32_t, size, uint64_t, data);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(tracephywritedelayabs > 0 && (eabs - sabs) > tracephywritedelayabs)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_PHYS_WRITE),
			    (eabs - sabs), sabs, paddr, data);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}
}

void
ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data(paddr, data, 1);
}

void
ml_phys_write_byte_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data(paddr64, data, 1);
}

void
ml_phys_write_half(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data(paddr, data, 2);
}

void
ml_phys_write_half_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data(paddr64, data, 2);
}

void
ml_phys_write(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data(paddr, data, 4);
}

void
ml_phys_write_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data(paddr64, data, 4);
}

void
ml_phys_write_word(vm_offset_t paddr, unsigned int data)
{
	ml_phys_write_data(paddr, data, 4);
}

void
ml_phys_write_word_64(addr64_t paddr64, unsigned int data)
{
	ml_phys_write_data(paddr64, data, 4);
}

void
ml_phys_write_double(vm_offset_t paddr, unsigned long long data)
{
	ml_phys_write_data(paddr, data, 8);
}

void
ml_phys_write_double_64(addr64_t paddr64, unsigned long long data)
{
	ml_phys_write_data(paddr64, data, 8);
}

uint32_t
ml_port_io_read(uint16_t ioport, int size)
{
	uint32_t result = 0;

	uint64_t sabs, eabs;
	boolean_t istate, timeread = FALSE;

	if (__improbable(reportphyreaddelayabs != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timeread = TRUE;
	}

#if DEVELOPMENT || DEBUG
	if (__improbable(timeread && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* x86_64 DEVELOPMENT || DEBUG */

	switch (size) {
	case 1:
		result = inb(ioport);
		break;
	case 2:
		result = inw(ioport);
		break;
	case 4:
		result = inl(ioport);
		break;
	default:
		panic("Invalid size %d for ml_port_io_read(0x%x)", size, (unsigned)ioport);
		break;
	}

	if (__improbable(timeread == TRUE)) {
		eabs = mach_absolute_time();

#if DEVELOPMENT || DEBUG
		iotrace(IOTRACE_PORTIO_READ, 0, ioport, size, result, sabs, eabs - sabs);
#endif

		if (__improbable((eabs - sabs) > reportphyreaddelayabs)) {
			(void)ml_set_interrupts_enabled(istate);

			if (phyreadpanic && (machine_timeout_suspended() == FALSE)) {
				panic_notify();
				panic("Read from IO port 0x%x took %llu ns, "
				    "result: 0x%x (start: %llu, end: %llu), ceiling: %llu",
				    ioport, (eabs - sabs), result, sabs, eabs,
				    reportphyreaddelayabs);
			}

			if (reportphyreadosbt) {
				OSReportWithBacktrace("ml_port_io_read(0x%x) took %lluus",
				    ioport, (eabs - sabs) / NSEC_PER_USEC);
			}
#if CONFIG_DTRACE
			DTRACE_PHYSLAT3(portioread, uint64_t, (eabs - sabs),
			    uint16_t, ioport, uint32_t, size);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(tracephyreaddelayabs > 0 && (eabs - sabs) > tracephyreaddelayabs)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_PORTIO_READ),
			    (eabs - sabs), sabs, ioport, result);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}

	return result;
}

void
ml_port_io_write(uint16_t ioport, uint32_t val, int size)
{
	uint64_t sabs, eabs;
	boolean_t istate, timewrite = FALSE;

	if (__improbable(reportphywritedelayabs != 0)) {
		istate = ml_set_interrupts_enabled(FALSE);
		sabs = mach_absolute_time();
		timewrite = TRUE;
	}
#if DEVELOPMENT || DEBUG
	if (__improbable(timewrite && simulate_stretched_io)) {
		sabs -= simulate_stretched_io;
	}
#endif /* x86_64 DEVELOPMENT || DEBUG */

	switch (size) {
	case 1:
		outb(ioport, (uint8_t)val);
		break;
	case 2:
		outw(ioport, (uint16_t)val);
		break;
	case 4:
		outl(ioport, (uint32_t)val);
		break;
	default:
		panic("Invalid size %d for ml_port_io_write(0x%x)", size, (unsigned)ioport);
		break;
	}

	if (__improbable(timewrite == TRUE)) {
		eabs = mach_absolute_time();

#if DEVELOPMENT || DEBUG
		iotrace(IOTRACE_PORTIO_WRITE, 0, ioport, size, val, sabs, eabs - sabs);
#endif

		if (__improbable((eabs - sabs) > reportphywritedelayabs)) {
			(void)ml_set_interrupts_enabled(istate);

			if (phywritepanic && (machine_timeout_suspended() == FALSE)) {
				panic_notify();
				panic("Write to IO port 0x%x took %llu ns, val: 0x%x"
				    " (start: %llu, end: %llu), ceiling: %llu",
				    ioport, (eabs - sabs), val, sabs, eabs,
				    reportphywritedelayabs);
			}

			if (reportphywriteosbt) {
				OSReportWithBacktrace("ml_port_io_write(0x%x, %d, 0x%llx) "
				    "took %lluus",
				    ioport, size, val, (eabs - sabs) / NSEC_PER_USEC);
			}

#if CONFIG_DTRACE
			DTRACE_PHYSLAT4(portiowrite, uint64_t, (eabs - sabs),
			    uint16_t, ioport, uint32_t, size, uint64_t, val);
#endif /* CONFIG_DTRACE */
		} else if (__improbable(tracephywritedelayabs > 0 && (eabs - sabs) > tracephywritedelayabs)) {
			KDBG(MACHDBG_CODE(DBG_MACH_IO, DBC_MACH_IO_PORTIO_WRITE),
			    (eabs - sabs), sabs, ioport, val);

			(void)ml_set_interrupts_enabled(istate);
		} else {
			(void)ml_set_interrupts_enabled(istate);
		}
	}
}

uint8_t
ml_port_io_read8(uint16_t ioport)
{
	return ml_port_io_read(ioport, 1);
}

uint16_t
ml_port_io_read16(uint16_t ioport)
{
	return ml_port_io_read(ioport, 2);
}

uint32_t
ml_port_io_read32(uint16_t ioport)
{
	return ml_port_io_read(ioport, 4);
}

void
ml_port_io_write8(uint16_t ioport, uint8_t val)
{
	ml_port_io_write(ioport, val, 1);
}

void
ml_port_io_write16(uint16_t ioport, uint16_t val)
{
	ml_port_io_write(ioport, val, 2);
}

void
ml_port_io_write32(uint16_t ioport, uint32_t val)
{
	ml_port_io_write(ioport, val, 4);
}

/* PCI config cycle probing
 *
 *
 *      Read the memory location at physical address paddr.
 * *Does not* recover from machine checks, unlike the PowerPC implementation.
 * Should probably be deprecated.
 */

boolean_t
ml_probe_read(vm_offset_t paddr, unsigned int *val)
{
	if ((PAGE_SIZE - (paddr & PAGE_MASK)) < 4) {
		return FALSE;
	}

	*val = ml_phys_read(paddr);

	return TRUE;
}

/*
 *  Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */
boolean_t
ml_probe_read_64(addr64_t paddr64, unsigned int *val)
{
	if ((PAGE_SIZE - (paddr64 & PAGE_MASK)) < 4) {
		return FALSE;
	}

	*val = ml_phys_read_64(paddr64);
	return TRUE;
}


#undef bcmp
int
bcmp(
	const void      *pa,
	const void      *pb,
	size_t  len)
{
	const char *a = (const char *)pa;
	const char *b = (const char *)pb;

	if (len == 0) {
		return 0;
	}

	do {
		if (*a++ != *b++) {
			break;
		}
	} while (--len);

	/*
	 * Check for the overflow case but continue to handle the non-overflow
	 * case the same way just in case someone is using the return value
	 * as more than zero/non-zero
	 */
	if (__improbable(!(len & 0x00000000FFFFFFFFULL) && (len & 0xFFFFFFFF00000000ULL))) {
		return 0xFFFFFFFF;
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

unsigned long
memcmp_zero_ptr_aligned(const void *addr, size_t size)
{
	const uint64_t *p = (const uint64_t *)addr;
	uint64_t a = p[0];

	static_assert(sizeof(unsigned long) == sizeof(uint64_t));

	if (size < 4 * sizeof(uint64_t)) {
		if (size > 1 * sizeof(uint64_t)) {
			a |= p[1];
			if (size > 2 * sizeof(uint64_t)) {
				a |= p[2];
			}
		}
	} else {
		size_t count = size / sizeof(uint64_t);
		uint64_t b = p[1];
		uint64_t c = p[2];
		uint64_t d = p[3];

		/*
		 * note: for sizes not a multiple of 32 bytes, this will load
		 * the bytes [size % 32 .. 32) twice which is ok
		 */
		while (count > 4) {
			count -= 4;
			a |= p[count + 0];
			b |= p[count + 1];
			c |= p[count + 2];
			d |= p[count + 3];
		}

		a |= b | c | d;
	}

	return a;
}

#undef memmove
void *
memmove(void *dst, const void *src, size_t ulen)
{
	bcopy(src, dst, ulen);
	return dst;
}

/*
 * Abstract:
 * strlen returns the number of characters in "string" preceeding
 * the terminating null character.
 */

#undef strlen
size_t
strlen(
	const char *string)
{
	const char *ret = string;

	while (*string++ != '\0') {
		continue;
	}
	return string - 1 - ret;
}

#if     MACH_ASSERT

/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
void
machine_callstack(
	__unused uintptr_t      *buf,
	__unused vm_size_t      callstack_max)
{
}

#endif  /* MACH_ASSERT */

void
fillPage(ppnum_t pa, unsigned int fill)
{
	uint64_t        src;
	int             cnt = PAGE_SIZE / sizeof(unsigned int);

	src = i386_ptob(pa);
	memset_word((int *)PHYSMAP_PTOV(src), fill, cnt);
}

static inline void
__clflush(void *ptr)
{
	__asm__ volatile ("clflush (%0)" : : "r" (ptr));
}

void
dcache_incoherent_io_store64(addr64_t pa, unsigned int count)
{
	addr64_t  linesize = cpuid_info()->cache_linesize;
	addr64_t  bound = (pa + count + linesize - 1) & ~(linesize - 1);

	mfence();

	while (pa < bound) {
		__clflush(PHYSMAP_PTOV(pa));
		pa += linesize;
	}

	mfence();
}

void
dcache_incoherent_io_flush64(addr64_t pa, unsigned int count)
{
	return dcache_incoherent_io_store64(pa, count);
}

void
flush_dcache64(addr64_t addr, unsigned count, int phys)
{
	if (phys) {
		dcache_incoherent_io_flush64(addr, count);
	} else {
		uint64_t  linesize = cpuid_info()->cache_linesize;
		addr64_t  bound = (addr + count + linesize - 1) & ~(linesize - 1);
		mfence();
		while (addr < bound) {
			__clflush((void *) (uintptr_t) addr);
			addr += linesize;
		}
		mfence();
	}
}

void
invalidate_icache64(__unused addr64_t addr,
    __unused unsigned count,
    __unused int phys)
{
}


addr64_t         vm_last_addr;

void
mapping_set_mod(ppnum_t pn)
{
	pmap_set_modify(pn);
}

void
mapping_set_ref(ppnum_t pn)
{
	pmap_set_reference(pn);
}

extern i386_cpu_info_t  cpuid_cpu_info;
void
cache_flush_page_phys(ppnum_t pa)
{
	boolean_t       istate;
	unsigned char   *cacheline_addr;
	i386_cpu_info_t *cpuid_infop = cpuid_info();
	int             cacheline_size;
	int             cachelines_to_flush;

	cacheline_size = cpuid_infop->cache_linesize;
	if (cacheline_size == 0) {
		panic("cacheline_size=0 cpuid_infop=%p\n", cpuid_infop);
	}
	cachelines_to_flush = PAGE_SIZE / cacheline_size;

	mfence();

	istate = ml_set_interrupts_enabled(FALSE);

	for (cacheline_addr = (unsigned char *)PHYSMAP_PTOV(i386_ptob(pa));
	    cachelines_to_flush > 0;
	    cachelines_to_flush--, cacheline_addr += cacheline_size) {
		__clflush((void *) cacheline_addr);
	}

	(void) ml_set_interrupts_enabled(istate);

	mfence();
}


#if !MACH_KDP
void
kdp_register_callout(kdp_callout_fn_t fn, void *arg)
{
#pragma unused(fn,arg)
}
#endif

#if !CONFIG_VMX
int
host_vmxon(boolean_t exclusive __unused)
{
	return VMX_UNSUPPORTED;
}

void
host_vmxoff(void)
{
	return;
}
#endif

static lck_grp_t       xcpm_lck_grp;
static lck_grp_attr_t  xcpm_lck_grp_attr;
static lck_attr_t      xcpm_lck_attr;
static lck_spin_t      xcpm_lock;

void xcpm_bootstrap(void);
void xcpm_mbox_lock(void);
void xcpm_mbox_unlock(void);
uint32_t xcpm_bios_mbox_cmd_read(uint32_t cmd);
uint32_t xcpm_bios_mbox_cmd_unsafe_read(uint32_t cmd);
void xcpm_bios_mbox_cmd_write(uint32_t cmd, uint32_t data);
boolean_t xcpm_is_hwp_enabled(void);

void
xcpm_bootstrap(void)
{
	lck_grp_attr_setdefault(&xcpm_lck_grp_attr);
	lck_grp_init(&xcpm_lck_grp, "xcpm", &xcpm_lck_grp_attr);
	lck_attr_setdefault(&xcpm_lck_attr);
	lck_spin_init(&xcpm_lock, &xcpm_lck_grp, &xcpm_lck_attr);
}

void
xcpm_mbox_lock(void)
{
	lck_spin_lock(&xcpm_lock);
}

void
xcpm_mbox_unlock(void)
{
	lck_spin_unlock(&xcpm_lock);
}

static uint32_t __xcpm_state[64] = {};

uint32_t
xcpm_bios_mbox_cmd_read(uint32_t cmd)
{
	uint32_t reg;
	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	xcpm_mbox_lock();
	reg = xcpm_bios_mbox_cmd_unsafe_read(cmd);
	xcpm_mbox_unlock();
	ml_set_interrupts_enabled(istate);
	return reg;
}

uint32_t
xcpm_bios_mbox_cmd_unsafe_read(uint32_t cmd)
{
	return __xcpm_state[cmd % (sizeof(__xcpm_state) / sizeof(__xcpm_state[0]))];
}

void
xcpm_bios_mbox_cmd_write(uint32_t cmd, uint32_t data)
{
	uint32_t idx = cmd % (sizeof(__xcpm_state) / sizeof(__xcpm_state[0]));
	idx &= ~0x1;

	boolean_t istate = ml_set_interrupts_enabled(FALSE);
	xcpm_mbox_lock();
	__xcpm_state[idx] = data;
	xcpm_mbox_unlock();
	ml_set_interrupts_enabled(istate);
}

boolean_t
xcpm_is_hwp_enabled(void)
{
	return FALSE;
}

