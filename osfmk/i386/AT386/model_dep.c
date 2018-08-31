/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989, 1988 Carnegie Mellon University
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

/*
 *	File:	model_dep.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Copyright (C) 1986, Avadis Tevanian, Jr., Michael Wayne Young
 *
 *	Basic initialization for I386 - ISA bus machines.
 */


#define __APPLE_API_PRIVATE 1
#define __APPLE_API_UNSTABLE 1
#include <kern/debug.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <sys/kdebug.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/cpu_data.h>
#include <kern/machine.h>
#include <i386/postcode.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/trap.h>
#include <i386/machine_routines.h>
#include <i386/mp.h>		/* mp_rendezvous_break_lock */
#include <i386/cpuid.h>
#include <i386/fpu.h>
#include <i386/machine_cpu.h>
#include <i386/pmap.h>
#if CONFIG_MTRR
#include <i386/mtrr.h>
#endif
#include <i386/ucode.h>
#include <i386/pmCPU.h>
#include <i386/panic_hooks.h>

#include <architecture/i386/pio.h> /* inb() */
#include <pexpert/i386/boot.h>

#include <kdp/kdp_dyld.h>
#include <kdp/kdp_core.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOHibernatePrivate.h>

#include <pexpert/i386/efi.h>

#include <kern/thread.h>
#include <kern/sched.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <libkern/kernel_mach_header.h>
#include <libkern/OSKextLibPrivate.h>

#include <mach/branch_predicates.h>

#if	DEBUG || DEVELOPMENT
#define DPRINTF(x...)	kprintf(x)
#else
#define DPRINTF(x...)
#endif

#ifndef ROUNDUP
#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))
#endif

#ifndef ROUNDDOWN
#define ROUNDDOWN(x,y) (((x)/(y))*(y))
#endif

static void machine_conf(void);
void panic_print_symbol_name(vm_address_t search);
void RecordPanicStackshot(void);

typedef enum paniclog_flush_type {
    kPaniclogFlushBase		= 1, /* Flush the initial log and paniclog header */
    kPaniclogFlushStackshot	= 2, /* Flush only the stackshot data, then flush the header */
    kPaniclogFlushOtherLog	= 3  /* Flush the other log, then flush the header */
} paniclog_flush_type_t;

void paniclog_flush_internal(paniclog_flush_type_t variant);

extern const char	version[];
extern char 	osversion[];
extern int		max_unsafe_quanta;
extern int		max_poll_quanta;
extern unsigned int	panic_is_inited;

extern int	proc_pid(void *p);

/* Definitions for frame pointers */
#define FP_ALIGNMENT_MASK      ((uint32_t)(0x3))
#define FP_LR_OFFSET           ((uint32_t)4)
#define FP_LR_OFFSET64         ((uint32_t)8)
#define FP_MAX_NUM_TO_EVALUATE (50)

volatile int pbtcpu = -1;
hw_lock_data_t pbtlock;		/* backtrace print lock */
uint32_t pbtcnt = 0;

volatile int panic_double_fault_cpu = -1;

#define PRINT_ARGS_FROM_STACK_FRAME	0

typedef struct _cframe_t {
    struct _cframe_t	*prev;
    uintptr_t		caller;
#if PRINT_ARGS_FROM_STACK_FRAME
    unsigned		args[0];
#endif
} cframe_t;

static unsigned panic_io_port;
static unsigned	commit_paniclog_to_nvram;
boolean_t coprocessor_paniclog_flush = FALSE;

struct kcdata_descriptor kc_panic_data;
static boolean_t begun_panic_stackshot = FALSE;
extern kern_return_t	do_stackshot(void *);

extern void	 	kdp_snapshot_preflight(int pid, void *tracebuf,
					       uint32_t tracebuf_size, uint32_t flags,
					       kcdata_descriptor_t data_p,
						boolean_t enable_faulting);
extern int 		kdp_stack_snapshot_bytes_traced(void);

#if DEVELOPMENT || DEBUG
vm_offset_t panic_stackshot_buf = 0;
size_t panic_stackshot_len = 0;
#endif

/*
 * Backtrace a single frame.
 */
void
print_one_backtrace(pmap_t pmap, vm_offset_t topfp, const char *cur_marker,
	boolean_t is_64_bit)
{
	int		    i = 0;
	addr64_t	lr;
	addr64_t	fp;
	addr64_t	fp_for_ppn;
	ppnum_t		ppn;
	boolean_t	dump_kernel_stack;

	fp = topfp;
	fp_for_ppn = 0;
	ppn = (ppnum_t)NULL;

	if (fp >= VM_MIN_KERNEL_ADDRESS)
		dump_kernel_stack = TRUE;
	else
		dump_kernel_stack = FALSE;

	do {
		if ((fp == 0) || ((fp & FP_ALIGNMENT_MASK) != 0))
			break;
		if (dump_kernel_stack && ((fp < VM_MIN_KERNEL_ADDRESS) || (fp > VM_MAX_KERNEL_ADDRESS)))
			break;
		if ((!dump_kernel_stack) && (fp >=VM_MIN_KERNEL_ADDRESS))
			break;
			
        /* Check to see if current address will result in a different
           ppn than previously computed (to avoid recomputation) via
           (addr) ^ fp_for_ppn) >> PAGE_SHIFT) */

		if ((((fp + FP_LR_OFFSET) ^ fp_for_ppn) >> PAGE_SHIFT) != 0x0U) {
			ppn = pmap_find_phys(pmap, fp + FP_LR_OFFSET);
			fp_for_ppn = fp + (is_64_bit ? FP_LR_OFFSET64 : FP_LR_OFFSET);
		}
		if (ppn != (ppnum_t)NULL) {
			if (is_64_bit) {
				lr = ml_phys_read_double_64(((((vm_offset_t)ppn) << PAGE_SHIFT)) | ((fp + FP_LR_OFFSET64) & PAGE_MASK));
			} else {
				lr = ml_phys_read_word(((((vm_offset_t)ppn) << PAGE_SHIFT)) | ((fp + FP_LR_OFFSET) & PAGE_MASK));
			}
		} else {
			if (is_64_bit) {
				paniclog_append_noflush("%s\t  Could not read LR from frame at 0x%016llx\n", cur_marker, fp + FP_LR_OFFSET64);
			} else {
				paniclog_append_noflush("%s\t  Could not read LR from frame at 0x%08x\n", cur_marker, (uint32_t)(fp + FP_LR_OFFSET));
			}
			break;
		}
		if (((fp ^ fp_for_ppn) >> PAGE_SHIFT) != 0x0U) {
			ppn = pmap_find_phys(pmap, fp);
			fp_for_ppn = fp;
		}
		if (ppn != (ppnum_t)NULL) {
			if (is_64_bit) {
				fp = ml_phys_read_double_64(((((vm_offset_t)ppn) << PAGE_SHIFT)) | (fp & PAGE_MASK));
			} else {
				fp = ml_phys_read_word(((((vm_offset_t)ppn) << PAGE_SHIFT)) | (fp & PAGE_MASK));
			}
		} else {
			if (is_64_bit) {
				paniclog_append_noflush("%s\t  Could not read FP from frame at 0x%016llx\n", cur_marker, fp);
			} else {
				paniclog_append_noflush("%s\t  Could not read FP from frame at 0x%08x\n", cur_marker, (uint32_t)fp);
			}
			break;
		}

		if (is_64_bit) {
			paniclog_append_noflush("%s\t0x%016llx\n", cur_marker, lr);
		} else {
			paniclog_append_noflush("%s\t0x%08x\n", cur_marker, (uint32_t)lr);
		}
	} while ((++i < FP_MAX_NUM_TO_EVALUATE) && (fp != topfp));
}
void
machine_startup(void)
{
	int	boot_arg;

#if 0
	if( PE_get_hotkey( kPEControlKey ))
            halt_in_debugger = halt_in_debugger ? 0 : 1;
#endif

	if (!PE_parse_boot_argn("nvram_paniclog", &commit_paniclog_to_nvram, sizeof (commit_paniclog_to_nvram)))
		commit_paniclog_to_nvram = 1;

	/*
	 * Entering the debugger will put the CPUs into a "safe"
	 * power mode.
	 */
	if (PE_parse_boot_argn("pmsafe_debug", &boot_arg, sizeof (boot_arg)))
	    pmsafe_debug = boot_arg;

	hw_lock_init(&pbtlock);		/* initialize print backtrace lock */

	if (PE_parse_boot_argn("preempt", &boot_arg, sizeof (boot_arg))) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_argn("unsafe", &boot_arg, sizeof (boot_arg))) {
		max_unsafe_quanta = boot_arg;
	}
	if (PE_parse_boot_argn("poll", &boot_arg, sizeof (boot_arg))) {
		max_poll_quanta = boot_arg;
	}
	if (PE_parse_boot_argn("yield", &boot_arg, sizeof (boot_arg))) {
		sched_poll_yield_shift = boot_arg;
	}
/* The I/O port to issue a read from, in the event of a panic. Useful for
 * triggering logic analyzers.
 */
	if (PE_parse_boot_argn("panic_io_port", &boot_arg, sizeof (boot_arg))) {
		/*I/O ports range from 0 through 0xFFFF */
		panic_io_port = boot_arg & 0xffff;
	}

	machine_conf();

	panic_hooks_init();

	/*
	 * Start the system.
	 */
	kernel_bootstrap();
	/*NOTREACHED*/
}


static void
machine_conf(void)
{
	machine_info.memory_size = (typeof(machine_info.memory_size))mem_size;
}


extern void *gPEEFIRuntimeServices;
extern void *gPEEFISystemTable;

/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 *
 *  First, the polynomial itself and its table of feedback terms.  The
 *  polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *
 *  Note that we take it "backwards" and put the highest-order term in
 *  the lowest-order bit.  The X^32 term is "implied"; the LSB is the
 *  X^31 term, etc.  The X^0 term (usually shown as "+1") results in
 *  the MSB being 1
 *
 *  Note that the usual hardware shift register implementation, which
 *  is what we're using (we're merely optimizing it by doing eight-bit
 *  chunks at a time) shifts bits into the lowest-order term.  In our
 *  implementation, that means shifting towards the right.  Why do we
 *  do it this way?  Because the calculated CRC must be transmitted in
 *  order from highest-order term to lowest-order term.  UARTs transmit
 *  characters in order from LSB to MSB.  By storing the CRC this way
 *  we hand it to the UART in the order low-byte to high-byte; the UART
 *  sends each low-bit to hight-bit; and the result is transmission bit
 *  by bit from highest- to lowest-order term without requiring any bit
 *  shuffling on our part.  Reception works similarly
 *
 *  The feedback terms table consists of 256, 32-bit entries.  Notes
 *
 *      The table can be generated at runtime if desired; code to do so
 *      is shown later.  It might not be obvious, but the feedback
 *      terms simply represent the results of eight shift/xor opera
 *      tions for all combinations of data and CRC register values
 *
 *      The values must be right-shifted by eight bits by the "updcrc
 *      logic; the shift must be unsigned (bring in zeroes).  On some
 *      hardware you could probably optimize the shift in assembler by
 *      using byte-swap instructions
 *      polynomial $edb88320
 *
 *
 * CRC32 code derived from work by Gary S. Brown.
 */

static uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t
crc32(uint32_t crc, const void *buf, size_t size)
{
	const uint8_t *p;

	p = buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

static void
efi_set_tables_64(EFI_SYSTEM_TABLE_64 * system_table)
{
    EFI_RUNTIME_SERVICES_64 *runtime;
    uint32_t hdr_cksum;
    uint32_t cksum;

    DPRINTF("Processing 64-bit EFI tables at %p\n", system_table);
    do {
	DPRINTF("Header:\n");
	DPRINTF("  Signature:   0x%016llx\n", system_table->Hdr.Signature);
	DPRINTF("  Revision:    0x%08x\n", system_table->Hdr.Revision);
	DPRINTF("  HeaderSize:  0x%08x\n", system_table->Hdr.HeaderSize);
	DPRINTF("  CRC32:       0x%08x\n", system_table->Hdr.CRC32);
	DPRINTF("RuntimeServices: 0x%016llx\n", system_table->RuntimeServices);
        if (system_table->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
	    kprintf("Bad EFI system table signature\n");
            break;
        }
        // Verify signature of the system table
        hdr_cksum = system_table->Hdr.CRC32;
        system_table->Hdr.CRC32 = 0;
        cksum = crc32(0L, system_table, system_table->Hdr.HeaderSize);

        DPRINTF("System table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
        system_table->Hdr.CRC32 = hdr_cksum;
        if (cksum != hdr_cksum) {
            kprintf("Bad EFI system table checksum\n");
            break;
        }

        gPEEFISystemTable     = system_table;

        if(system_table->RuntimeServices == 0) {
            kprintf("No runtime table present\n");
            break;
        }
        DPRINTF("RuntimeServices table at 0x%qx\n", system_table->RuntimeServices);
        // 64-bit virtual address is OK for 64-bit EFI and 64/32-bit kernel.
        runtime = (EFI_RUNTIME_SERVICES_64 *) (uintptr_t)system_table->RuntimeServices;
        DPRINTF("Checking runtime services table %p\n", runtime);
        if (runtime->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE) {
            kprintf("Bad EFI runtime table signature\n");
            break;
        }

	// Verify signature of runtime services table
	hdr_cksum = runtime->Hdr.CRC32;
	runtime->Hdr.CRC32 = 0;
	cksum = crc32(0L, runtime, runtime->Hdr.HeaderSize);

	DPRINTF("Runtime table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
	runtime->Hdr.CRC32 = hdr_cksum;
	if (cksum != hdr_cksum) {
	    kprintf("Bad EFI runtime table checksum\n");
	    break;
	}

	gPEEFIRuntimeServices = runtime;
    }
    while (FALSE);
}

static void
efi_set_tables_32(EFI_SYSTEM_TABLE_32 * system_table)
{
    EFI_RUNTIME_SERVICES_32 *runtime;
    uint32_t hdr_cksum;
    uint32_t cksum;

    DPRINTF("Processing 32-bit EFI tables at %p\n", system_table);
    do {
	DPRINTF("Header:\n");
	DPRINTF("  Signature:   0x%016llx\n", system_table->Hdr.Signature);
	DPRINTF("  Revision:    0x%08x\n", system_table->Hdr.Revision);
	DPRINTF("  HeaderSize:  0x%08x\n", system_table->Hdr.HeaderSize);
	DPRINTF("  CRC32:       0x%08x\n", system_table->Hdr.CRC32);
	DPRINTF("RuntimeServices: 0x%08x\n", system_table->RuntimeServices);
        if (system_table->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
            kprintf("Bad EFI system table signature\n");
            break;
        }
        // Verify signature of the system table
        hdr_cksum = system_table->Hdr.CRC32;
        system_table->Hdr.CRC32 = 0;
        DPRINTF("System table at %p HeaderSize 0x%x\n", system_table, system_table->Hdr.HeaderSize);
        cksum = crc32(0L, system_table, system_table->Hdr.HeaderSize);

        DPRINTF("System table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
        system_table->Hdr.CRC32 = hdr_cksum;
        if (cksum != hdr_cksum) {
            kprintf("Bad EFI system table checksum\n");
            break;
        }

        gPEEFISystemTable     = system_table;

        if(system_table->RuntimeServices == 0) {
            kprintf("No runtime table present\n");
            break;
        }
        DPRINTF("RuntimeServices table at 0x%x\n", system_table->RuntimeServices);
        // 32-bit virtual address is OK for 32-bit EFI and 32-bit kernel.
        // For a 64-bit kernel, booter provides a virtual address mod 4G
        runtime = (EFI_RUNTIME_SERVICES_32 *)
			(system_table->RuntimeServices | VM_MIN_KERNEL_ADDRESS);
	DPRINTF("Runtime table addressed at %p\n", runtime);
        if (runtime->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE) {
            kprintf("Bad EFI runtime table signature\n");
            break;
        }

	// Verify signature of runtime services table
	hdr_cksum = runtime->Hdr.CRC32;
	runtime->Hdr.CRC32 = 0;
	cksum = crc32(0L, runtime, runtime->Hdr.HeaderSize);

	DPRINTF("Runtime table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
	runtime->Hdr.CRC32 = hdr_cksum;
	if (cksum != hdr_cksum) {
	    kprintf("Bad EFI runtime table checksum\n");
	    break;
	}

	DPRINTF("Runtime functions\n");
	DPRINTF("  GetTime                  : 0x%x\n", runtime->GetTime);
	DPRINTF("  SetTime                  : 0x%x\n", runtime->SetTime);
	DPRINTF("  GetWakeupTime            : 0x%x\n", runtime->GetWakeupTime);
	DPRINTF("  SetWakeupTime            : 0x%x\n", runtime->SetWakeupTime);
	DPRINTF("  SetVirtualAddressMap     : 0x%x\n", runtime->SetVirtualAddressMap);
	DPRINTF("  ConvertPointer           : 0x%x\n", runtime->ConvertPointer);
	DPRINTF("  GetVariable              : 0x%x\n", runtime->GetVariable);
	DPRINTF("  GetNextVariableName      : 0x%x\n", runtime->GetNextVariableName);
	DPRINTF("  SetVariable              : 0x%x\n", runtime->SetVariable);
	DPRINTF("  GetNextHighMonotonicCount: 0x%x\n", runtime->GetNextHighMonotonicCount);
	DPRINTF("  ResetSystem              : 0x%x\n", runtime->ResetSystem);

	gPEEFIRuntimeServices = runtime;
    }
    while (FALSE);
}


/* Map in EFI runtime areas. */
static void
efi_init(void)
{
    boot_args *args = (boot_args *)PE_state.bootArgs;

    kprintf("Initializing EFI runtime services\n");

    do
    {
	vm_offset_t vm_size, vm_addr;
	vm_map_offset_t phys_addr;
	EfiMemoryRange *mptr;
	unsigned int msize, mcount;
	unsigned int i;

	msize = args->MemoryMapDescriptorSize;
	mcount = args->MemoryMapSize / msize;

	DPRINTF("efi_init() kernel base: 0x%x size: 0x%x\n",
		args->kaddr, args->ksize);
	DPRINTF("           efiSystemTable physical: 0x%x virtual: %p\n",
		args->efiSystemTable,
		(void *) ml_static_ptovirt(args->efiSystemTable));
	DPRINTF("           efiRuntimeServicesPageStart: 0x%x\n",
		args->efiRuntimeServicesPageStart);
	DPRINTF("           efiRuntimeServicesPageCount: 0x%x\n",
		args->efiRuntimeServicesPageCount);
	DPRINTF("           efiRuntimeServicesVirtualPageStart: 0x%016llx\n",
		args->efiRuntimeServicesVirtualPageStart);
	mptr = (EfiMemoryRange *)ml_static_ptovirt(args->MemoryMap);
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if (((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) ) {
		vm_size = (vm_offset_t)i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		/* For K64 on EFI32, shadow-map into high KVA */
		if (vm_addr < VM_MIN_KERNEL_ADDRESS)
			vm_addr |= VM_MIN_KERNEL_ADDRESS;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;
		DPRINTF(" Type: %x phys: %p EFIv: %p kv: %p size: %p\n",
			mptr->Type,
			(void *) (uintptr_t) phys_addr,
			(void *) (uintptr_t) mptr->VirtualStart,
			(void *) vm_addr,
			(void *) vm_size);
		pmap_map_bd(vm_addr, phys_addr, phys_addr + round_page(vm_size),
		     (mptr->Type == kEfiRuntimeServicesCode) ? VM_PROT_READ | VM_PROT_EXECUTE : VM_PROT_READ|VM_PROT_WRITE,
		     (mptr->Type == EfiMemoryMappedIO)       ? VM_WIMG_IO   : VM_WIMG_USE_DEFAULT);
	    }
	}

        if (args->Version != kBootArgsVersion2)
            panic("Incompatible boot args version %d revision %d\n", args->Version, args->Revision);

	DPRINTF("Boot args version %d revision %d mode %d\n", args->Version, args->Revision, args->efiMode);
        if (args->efiMode == kBootArgsEfiMode64) {
            efi_set_tables_64((EFI_SYSTEM_TABLE_64 *) ml_static_ptovirt(args->efiSystemTable));
        } else {
            efi_set_tables_32((EFI_SYSTEM_TABLE_32 *) ml_static_ptovirt(args->efiSystemTable));
        }
    }
    while (FALSE);

    return;
}

/* Returns TRUE if a page belongs to the EFI Runtime Services (code or data) */ 
boolean_t
efi_valid_page(ppnum_t ppn) 
{
    boot_args *args = (boot_args *)PE_state.bootArgs;
    ppnum_t    pstart = args->efiRuntimeServicesPageStart;
    ppnum_t    pend = pstart + args->efiRuntimeServicesPageCount;

    return pstart <= ppn && ppn < pend;
}

/* Remap EFI runtime areas. */
void
hibernate_newruntime_map(void * map, vm_size_t map_size, uint32_t system_table_offset)
{
    boot_args *args = (boot_args *)PE_state.bootArgs;

    kprintf("Reinitializing EFI runtime services\n");

    do
    {
        vm_offset_t vm_size, vm_addr;
	vm_map_offset_t phys_addr;
	EfiMemoryRange *mptr;
	unsigned int msize, mcount;
	unsigned int i;

	gPEEFISystemTable     = 0;
	gPEEFIRuntimeServices = 0;

	system_table_offset += ptoa_32(args->efiRuntimeServicesPageStart);

	kprintf("Old system table 0x%x, new 0x%x\n",
	    (uint32_t)args->efiSystemTable,    system_table_offset);

	args->efiSystemTable    = system_table_offset;

	kprintf("Old map:\n");
	msize = args->MemoryMapDescriptorSize;
	mcount = args->MemoryMapSize / msize;
	mptr = (EfiMemoryRange *)ml_static_ptovirt(args->MemoryMap);
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if ((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) {

		vm_size = (vm_offset_t)i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		/* K64 on EFI32 */
		if (vm_addr < VM_MIN_KERNEL_ADDRESS)
			vm_addr |= VM_MIN_KERNEL_ADDRESS;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;

		kprintf("mapping[%u] %qx @ %lx, %llu\n", mptr->Type, phys_addr, (unsigned long)vm_addr, mptr->NumberOfPages);
	    }
	}

	pmap_remove(kernel_pmap, i386_ptob(args->efiRuntimeServicesPageStart), 
				 i386_ptob(args->efiRuntimeServicesPageStart + args->efiRuntimeServicesPageCount));

	kprintf("New map:\n");
	msize = args->MemoryMapDescriptorSize;
	mcount = (unsigned int )(map_size / msize);
	mptr = map;
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if ((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) {

		vm_size = (vm_offset_t)i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		if (vm_addr < VM_MIN_KERNEL_ADDRESS)
			vm_addr |= VM_MIN_KERNEL_ADDRESS;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;

		kprintf("mapping[%u] %qx @ %lx, %llu\n", mptr->Type, phys_addr, (unsigned long)vm_addr, mptr->NumberOfPages);

		pmap_map(vm_addr, phys_addr, phys_addr + round_page(vm_size),
			 (mptr->Type == kEfiRuntimeServicesCode) ? VM_PROT_READ | VM_PROT_EXECUTE : VM_PROT_READ|VM_PROT_WRITE,
			 (mptr->Type == EfiMemoryMappedIO)       ? VM_WIMG_IO   : VM_WIMG_USE_DEFAULT);
	    }
	}

        if (args->Version != kBootArgsVersion2)
            panic("Incompatible boot args version %d revision %d\n", args->Version, args->Revision);

        kprintf("Boot args version %d revision %d mode %d\n", args->Version, args->Revision, args->efiMode);
        if (args->efiMode == kBootArgsEfiMode64) {
	    efi_set_tables_64((EFI_SYSTEM_TABLE_64 *) ml_static_ptovirt(args->efiSystemTable));
        } else {
	    efi_set_tables_32((EFI_SYSTEM_TABLE_32 *) ml_static_ptovirt(args->efiSystemTable));
        }
    }
    while (FALSE);

    kprintf("Done reinitializing EFI runtime services\n");

    return;
}

/*
 * Find devices.  The system is alive.
 */
void
machine_init(void)
{
	/* Now with VM up, switch to dynamically allocated cpu data */
	cpu_data_realloc();

        /* Ensure panic buffer is initialized. */
        debug_log_init();

	/*
	 * Display CPU identification
	 */
	cpuid_cpu_display("CPU identification");
	cpuid_feature_display("CPU features");
	cpuid_extfeature_display("CPU extended features");

        /*
         * Initialize EFI runtime services.
         */
        efi_init();

	smp_init();

	/*
	 * Set up to use floating point.
	 */
	init_fpu();

	/*
	 * Configure clock devices.
	 */
	clock_config();

#if CONFIG_MTRR
	/*
	 * Initialize MTRR from boot processor.
	 */
	mtrr_init();

	/*
	 * Set up PAT for boot processor.
	 */
	pat_init();
#endif

	/*
	 * Free lowmem pages and complete other setup
	 */
	pmap_lowmem_finalize();
}

/*
 * Halt a cpu.
 */
void
halt_cpu(void)
{
	halt_all_cpus(FALSE);
}

int reset_mem_on_reboot = 1;

/*
 * Halt the system or reboot.
 */
__attribute__((noreturn))
void
halt_all_cpus(boolean_t reboot)
{
	if (reboot) {
		printf("MACH Reboot\n");
		PEHaltRestart( kPERestartCPU );
	} else {
		printf("CPU halted\n");
		PEHaltRestart( kPEHaltCPU );
	}
	while(1);
}

 
/* Issue an I/O port read if one has been requested - this is an event logic
 * analyzers can use as a trigger point.
 */

void
panic_io_port_read(void) {
	if (panic_io_port)
		(void)inb(panic_io_port);
}

/* For use with the MP rendezvous mechanism
 */

uint64_t panic_restart_timeout = ~(0ULL);

#define PANIC_RESTART_TIMEOUT (3ULL * NSEC_PER_SEC)

/*
 * We should always return from this function with the other log offset
 * set in the panic_info structure.
 */
void
RecordPanicStackshot()
{
	int err = 0, bytes_traced = 0, bytes_used = 0, bytes_remaining = 0;
	char *stackshot_begin_loc = NULL;

	/* Don't re-enter this code if we panic here */
	if (begun_panic_stackshot) {
		if (panic_info->mph_other_log_offset == 0) {
			panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
		}
		return;
	}
	begun_panic_stackshot = TRUE;

	/* The panic log length should have been set before we came to capture a stackshot */
	if (panic_info->mph_panic_log_len == 0) {
		kdb_printf("Found zero length panic log, skipping capturing panic stackshot\n");
		if (panic_info->mph_other_log_offset == 0) {
			panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
		}
		return;
	}

	/*
	 * Try to capture an in memory panic_stackshot (enabled during boot
	 * on systems with co-processors).
	 */
	if (extended_debug_log_enabled) {
		if (stackshot_active()) {
			panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_FAILED_NESTED;
			panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
			kdb_printf("Panicked during stackshot, skipping panic stackshot\n");
			return;
		} else {
			stackshot_begin_loc = debug_buf_ptr;

			bytes_remaining = debug_buf_size - (unsigned int)((uintptr_t)stackshot_begin_loc - (uintptr_t)debug_buf_base);
			err = kcdata_memory_static_init(&kc_panic_data, (mach_vm_address_t)stackshot_begin_loc,
					KCDATA_BUFFER_BEGIN_STACKSHOT, bytes_remaining, KCFLAG_USE_MEMCOPY);
			if (err != KERN_SUCCESS) {
				panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR;
				panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
				kdb_printf("Failed to initialize kcdata buffer for in-memory panic stackshot, skipping ...\n");
				return;
			}

			kdp_snapshot_preflight(-1, (void *) stackshot_begin_loc, bytes_remaining,
									(STACKSHOT_SAVE_KEXT_LOADINFO | STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT |
									STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_FROM_PANIC |
									STACKSHOT_NO_IO_STATS | STACKSHOT_THREAD_WAITINFO), &kc_panic_data, 0);
			err = do_stackshot(NULL);
			bytes_traced = (int) kdp_stack_snapshot_bytes_traced();
			bytes_used = (int) kcdata_memory_get_used_bytes(&kc_panic_data);

			if ((err != KERN_SUCCESS) && (bytes_used > 0)) {
				/*
				 * We ran out of space while trying to capture a stackshot, try again without user frames.
				 * It's not safe to log from here, but append a flag to the panic flags.
				 */
				panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_KERNEL_ONLY;
				panic_stackshot_reset_state();

				/* Erase the stackshot data (this region is pre-populated with the NULL character) */
				memset(stackshot_begin_loc, '\0', bytes_used);

				err = kcdata_memory_static_init(&kc_panic_data, (mach_vm_address_t)stackshot_begin_loc,
					KCDATA_BUFFER_BEGIN_STACKSHOT, bytes_remaining, KCFLAG_USE_MEMCOPY);
				if (err != KERN_SUCCESS) {
					panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR;
					panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
					kdb_printf("Failed to re-initialize kcdata buffer for kernel only in-memory panic stackshot, skipping ...\n");
					return;
				}

				kdp_snapshot_preflight(-1, (void *) stackshot_begin_loc, bytes_remaining, (STACKSHOT_KCDATA_FORMAT |
						STACKSHOT_NO_IO_STATS | STACKSHOT_SAVE_KEXT_LOADINFO | STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY |
						STACKSHOT_FROM_PANIC | STACKSHOT_THREAD_WAITINFO), &kc_panic_data, 0);
				err = do_stackshot(NULL);
				bytes_traced = (int) kdp_stack_snapshot_bytes_traced();
				bytes_used = (int) kcdata_memory_get_used_bytes(&kc_panic_data);
			}

			if (err == KERN_SUCCESS) {
				debug_buf_ptr += bytes_traced;
				panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_SUCCEEDED;
				panic_info->mph_stackshot_offset = PE_get_offset_into_panic_region(stackshot_begin_loc);
				panic_info->mph_stackshot_len = bytes_traced;

				panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
				kdb_printf("\n** In Memory Panic Stackshot Succeeded ** Bytes Traced %d **\n", bytes_traced);
			} else {
				if (bytes_used > 0) {
					/* Erase the stackshot data (this region is pre-populated with the NULL character) */
					memset(stackshot_begin_loc, '\0', bytes_used);
					panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_FAILED_INCOMPLETE;

					panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
					kdb_printf("\n** In Memory Panic Stackshot Incomplete ** Bytes Filled %d ** Err %d\n", bytes_used, err);
				} else {
					bzero(stackshot_begin_loc, bytes_used);
					panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR;

					panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
					kdb_printf("\n** In Memory Panic Stackshot Failed ** Bytes Traced %d, err %d\n", bytes_traced, err);
				}
			}
		}
#if DEVELOPMENT || DEBUG
		if (panic_stackshot_buf != 0) {
			/* We're going to try to take another stackshot, reset the state. */
			panic_stackshot_reset_state();
		}
#endif /* DEVELOPMENT || DEBUG */
	} else {
		panic_info->mph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);
	}

#if DEVELOPMENT || DEBUG

	if (panic_stackshot_buf == 0) {
		kdb_printf("No stackshot buffer allocated for file backed panic stackshot, skipping...\n");
		return;
	}

	if (stackshot_active()) {
		kdb_printf("Panicked during stackshot, skipping file backed panic stackshot\n");
		return;
	}

	err = kcdata_memory_static_init(&kc_panic_data, (mach_vm_address_t)panic_stackshot_buf, KCDATA_BUFFER_BEGIN_STACKSHOT,
			PANIC_STACKSHOT_BUFSIZE, KCFLAG_USE_MEMCOPY);
	if (err != KERN_SUCCESS) {
		kdb_printf("Failed to initialize kcdata buffer for file backed panic stackshot, skipping ...\n");
		return;
	}

	kdp_snapshot_preflight(-1, (void *) panic_stackshot_buf, PANIC_STACKSHOT_BUFSIZE, (STACKSHOT_GET_GLOBAL_MEM_STATS | STACKSHOT_SAVE_LOADINFO | STACKSHOT_KCDATA_FORMAT |
									STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_FROM_PANIC | STACKSHOT_NO_IO_STATS
									| STACKSHOT_THREAD_WAITINFO), &kc_panic_data, 0);
	err = do_stackshot(NULL);
	bytes_traced = (int) kdp_stack_snapshot_bytes_traced();
	if (bytes_traced > 0 && !err) {
		panic_stackshot_len = bytes_traced;
		kdb_printf("File backed panic stackshot succeeded, length: %u bytes\n", bytes_traced);
	} else {
		bytes_used = (int) kcdata_memory_get_used_bytes(&kc_panic_data);
		if (bytes_used > 0) {
			kdb_printf("File backed panic stackshot incomplete, consumed %u bytes, error : %d \n", bytes_used, err);
		} else {
			kdb_printf("File backed panic stackshot incomplete, consumed %u bytes, error : %d \n", bytes_used, err);
		}
	}
#endif /* DEVELOPMENT || DEBUG */

	return;
}

void
SavePanicInfo(
	__unused const char *message, uint64_t panic_options)
{
	void *stackptr;
	int cn = cpu_number();

	/*
	 * Issue an I/O port read if one has been requested - this is an event logic
	 * analyzers can use as a trigger point.
	 */
	panic_io_port_read();

	/* Obtain current frame pointer */
	__asm__ volatile("movq %%rbp, %0" : "=m" (stackptr));

	/* Print backtrace - callee is internally synchronized */
	if (panic_options & DEBUGGER_OPTION_INITPROC_PANIC) {
		/* Special handling of launchd died panics */
		print_launchd_info();
	} else {
		panic_i386_backtrace(stackptr, ((panic_double_fault_cpu == cn) ? 80: 48), NULL, FALSE, NULL);
	}

	if (panic_options & DEBUGGER_OPTION_COPROC_INITIATED_PANIC) {
		panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_COPROC_INITIATED_PANIC;
	}

	if (PE_get_offset_into_panic_region(debug_buf_ptr) < panic_info->mph_panic_log_offset) {
		kdb_printf("Invalid panic log offset found (not properly initialized?): debug_buf_ptr : 0x%p, panic_info: 0x%p mph_panic_log_offset: 0x%x\n",
			debug_buf_ptr, panic_info, panic_info->mph_panic_log_offset);
		panic_info->mph_panic_log_len = 0;
	} else {
		panic_info->mph_panic_log_len = PE_get_offset_into_panic_region(debug_buf_ptr) - panic_info->mph_panic_log_offset;
	}

	/* Flush the panic log */
	paniclog_flush_internal(kPaniclogFlushBase);

	/* Try to take a panic stackshot */
	RecordPanicStackshot();

	/*
	 * Flush the panic log again with the stackshot or any relevant logging
	 * from when we tried to capture it.
	 */
	if (extended_debug_log_enabled) {
		paniclog_flush_internal(kPaniclogFlushStackshot);
	}
}

void paniclog_flush_internal(paniclog_flush_type_t variant)
{
	/* Update the other log offset if we've opened the other log */
	if (panic_info->mph_other_log_offset != 0) {
		panic_info->mph_other_log_len = PE_get_offset_into_panic_region(debug_buf_ptr) - panic_info->mph_other_log_offset;
	}

	/*
	 * If we've detected that we're on a co-processor system, we flush the panic log via the kPEPanicSync
	 * panic callbacks, otherwise we flush via nvram (unless that has been disabled).
	 */
	if (coprocessor_paniclog_flush) {
		uint32_t overall_buffer_size = debug_buf_size;
		uint32_t size_to_flush = 0, offset_to_flush = 0;
		if (extended_debug_log_enabled) {
			/*
			 * debug_buf_size for the extended log does not include the length of the header.
			 * There may be some extra data at the end of the 'basic' log that wouldn't get flushed
			 * for the non-extended case (this is a concession we make to not shrink the paniclog data
			 * for non-coprocessor systems that only use the basic log).
			 */
			overall_buffer_size = debug_buf_size + sizeof(struct macos_panic_header);
		}

		/* Update the CRC */
		panic_info->mph_crc = crc32(0L, &panic_info->mph_version, (overall_buffer_size - offsetof(struct macos_panic_header, mph_version)));

		if (variant == kPaniclogFlushBase) {
			/* Flush the header and base panic log. */
			kprintf("Flushing base panic log\n");
			size_to_flush = ROUNDUP((panic_info->mph_panic_log_offset + panic_info->mph_panic_log_len), PANIC_FLUSH_BOUNDARY);
			offset_to_flush = 0;
			PESavePanicInfoAction(panic_info, offset_to_flush, size_to_flush);
		} else if ((variant == kPaniclogFlushStackshot) || (variant == kPaniclogFlushOtherLog)) {
			if (variant == kPaniclogFlushStackshot) {
				/*
				 * We flush the stackshot before flushing the updated header because the stackshot
				 * can take a while to flush. We want the paniclog header to be as consistent as possible even
				 * if the stackshot isn't flushed completely. Flush starting from the end of the panic log.
				 */
				kprintf("Flushing panic log stackshot\n");
				offset_to_flush = ROUNDDOWN((panic_info->mph_panic_log_offset + panic_info->mph_panic_log_len), PANIC_FLUSH_BOUNDARY);
				size_to_flush = ROUNDUP((panic_info->mph_stackshot_len + (panic_info->mph_stackshot_offset - offset_to_flush)), PANIC_FLUSH_BOUNDARY);
				PESavePanicInfoAction(panic_info, offset_to_flush, size_to_flush);
			}

			/* Flush the other log -- everything after the stackshot */
			kprintf("Flushing panic 'other' log\n");
			offset_to_flush = ROUNDDOWN((panic_info->mph_stackshot_offset + panic_info->mph_stackshot_len), PANIC_FLUSH_BOUNDARY);
			size_to_flush = ROUNDUP((panic_info->mph_other_log_len + (panic_info->mph_other_log_offset - offset_to_flush)), PANIC_FLUSH_BOUNDARY);
			PESavePanicInfoAction(panic_info, offset_to_flush, size_to_flush);

			/* Flush the header -- everything before the paniclog */
			kprintf("Flushing panic log header\n");
			size_to_flush = ROUNDUP(panic_info->mph_panic_log_offset, PANIC_FLUSH_BOUNDARY);
			offset_to_flush = 0;
			PESavePanicInfoAction(panic_info, offset_to_flush, size_to_flush);
		}
	} else if (commit_paniclog_to_nvram) {
		assert(debug_buf_size != 0);
		unsigned int bufpos;
		unsigned long pi_size = 0;
		uintptr_t cr0;

		debug_putc(0);

		/*
		 * Now call the compressor
		 * XXX Consider using the WKdm compressor in the
		 * future, rather than just packing - would need to
		 * be co-ordinated with crashreporter, which decodes
		 * this post-restart. The compressor should be
		 * capable of in-place compression.
		 *
		 * Don't include the macOS panic header (for co-processor systems only)
		 */
		bufpos = packA(debug_buf_base, (unsigned int) (debug_buf_ptr - debug_buf_base),
				debug_buf_size);
		/*
		 * If compression was successful, use the compressed length
		 */
		pi_size = bufpos ? bufpos : (unsigned) (debug_buf_ptr - debug_buf_base);

		/*
		 * The following sequence is a workaround for:
		 * <rdar://problem/5915669> SnowLeopard10A67: AppleEFINVRAM should not invoke
		 * any routines that use floating point (MMX in this case) when saving panic
		 * logs to nvram/flash.
		 */
		cr0 = get_cr0();
		clear_ts();

		/*
		 * Save panic log to non-volatile store
		 * Panic info handler must truncate data that is
		 * too long for this platform.
		 * This call must save data synchronously,
		 * since we can subsequently halt the system.
		 */
		kprintf("Attempting to commit panic log to NVRAM\n");
		pi_size = PESavePanicInfo((unsigned char *)debug_buf_base,
				(uint32_t)pi_size );
		set_cr0(cr0);

		/*
		 * Uncompress in-place, to permit examination of
		 * the panic log by debuggers.
		 */
		if (bufpos) {
			unpackA(debug_buf_base, bufpos);
		}
	}
}

void
paniclog_flush()
{
	/* Called outside of this file to update logging appended to the "other" log */
	paniclog_flush_internal(kPaniclogFlushOtherLog);
	return;
}

char *
machine_boot_info(char *buf, __unused vm_size_t size)
{
	*buf ='\0';
	return buf;
}

/* Routines for address - symbol translation. Not called unless the "keepsyms"
 * boot-arg is supplied.
 */

static int
panic_print_macho_symbol_name(kernel_mach_header_t *mh, vm_address_t search, const char *module_name)
{
    kernel_nlist_t	*sym = NULL;
    struct load_command		*cmd;
    kernel_segment_command_t	*orig_ts = NULL, *orig_le = NULL;
    struct symtab_command	*orig_st = NULL;
    unsigned int			i;
    char					*strings, *bestsym = NULL;
    vm_address_t			bestaddr = 0, diff, curdiff;

    /* Assume that if it's loaded and linked into the kernel, it's a valid Mach-O */
    
    cmd = (struct load_command *) &mh[1];
    for (i = 0; i < mh->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_KERNEL) {
            kernel_segment_command_t *orig_sg = (kernel_segment_command_t *) cmd;
            
            if (strncmp(SEG_TEXT, orig_sg->segname,
				    sizeof(orig_sg->segname)) == 0)
                orig_ts = orig_sg;
            else if (strncmp(SEG_LINKEDIT, orig_sg->segname,
				    sizeof(orig_sg->segname)) == 0)
                orig_le = orig_sg;
            else if (strncmp("", orig_sg->segname,
				    sizeof(orig_sg->segname)) == 0)
                orig_ts = orig_sg; /* pre-Lion i386 kexts have a single unnamed segment */
        }
        else if (cmd->cmd == LC_SYMTAB)
            orig_st = (struct symtab_command *) cmd;
        
        cmd = (struct load_command *) ((uintptr_t) cmd + cmd->cmdsize);
    }
    
    if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
        return 0;
    
    if ((search < orig_ts->vmaddr) ||
        (search >= orig_ts->vmaddr + orig_ts->vmsize)) {
        /* search out of range for this mach header */
        return 0;
    }
    
    sym = (kernel_nlist_t *)(uintptr_t)(orig_le->vmaddr + orig_st->symoff - orig_le->fileoff);
    strings = (char *)(uintptr_t)(orig_le->vmaddr + orig_st->stroff - orig_le->fileoff);
    diff = search;
    
    for (i = 0; i < orig_st->nsyms; i++) {
        if (sym[i].n_type & N_STAB) continue;

        if (sym[i].n_value <= search) {
            curdiff = search - (vm_address_t)sym[i].n_value;
            if (curdiff < diff) {
                diff = curdiff;
                bestaddr = sym[i].n_value;
                bestsym = strings + sym[i].n_un.n_strx;
            }
        }
    }
    
    if (bestsym != NULL) {
        if (diff != 0) {
            paniclog_append_noflush("%s : %s + 0x%lx", module_name, bestsym, (unsigned long)diff);
        } else {
            paniclog_append_noflush("%s : %s", module_name, bestsym);
        }
        return 1;
    }
    return 0;
}

extern kmod_info_t * kmod; /* the list of modules */

static void
panic_print_kmod_symbol_name(vm_address_t search)
{
    u_int i;

    if (gLoadedKextSummaries == NULL)
	    return;
    for (i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {
        OSKextLoadedKextSummary *summary = gLoadedKextSummaries->summaries + i;

        if ((search >= summary->address) &&
            (search < (summary->address + summary->size)))
        {
            kernel_mach_header_t *header = (kernel_mach_header_t *)(uintptr_t) summary->address;
            if (panic_print_macho_symbol_name(header, search, summary->name) == 0) {
                paniclog_append_noflush("%s + %llu", summary->name, (unsigned long)search - summary->address);
            }
            break;
        }
    }
}

void
panic_print_symbol_name(vm_address_t search)
{
    /* try searching in the kernel */
    if (panic_print_macho_symbol_name(&_mh_execute_header, search, "mach_kernel") == 0) {
        /* that failed, now try to search for the right kext */
        panic_print_kmod_symbol_name(search);
    }
}

/* Generate a backtrace, given a frame pointer - this routine
 * should walk the stack safely. The trace is appended to the panic log
 * and conditionally, to the console. If the trace contains kernel module
 * addresses, display the module name, load address and dependencies.
 */

#define DUMPFRAMES 32
#define PBT_TIMEOUT_CYCLES (5 * 1000 * 1000 * 1000ULL)
void
panic_i386_backtrace(void *_frame, int nframes, const char *msg, boolean_t regdump, x86_saved_state_t *regs)
{
	cframe_t	*frame = (cframe_t *)_frame;
	vm_offset_t raddrs[DUMPFRAMES];
	vm_offset_t PC = 0;
	int frame_index;
	volatile uint32_t *ppbtcnt = &pbtcnt;
	uint64_t bt_tsc_timeout;
	boolean_t keepsyms = FALSE;
	int cn = cpu_number();
	boolean_t old_doprnt_hide_pointers = doprnt_hide_pointers;

	if(pbtcpu != cn) {
		hw_atomic_add(&pbtcnt, 1);
		/* Spin on print backtrace lock, which serializes output
		 * Continue anyway if a timeout occurs.
		 */
		hw_lock_to(&pbtlock, ~0U);
		pbtcpu = cn;
	}

	if (__improbable(doprnt_hide_pointers == TRUE)) {
		/* If we're called directly, the Debugger() function will not be called,
		 * so we need to reset the value in here. */
		doprnt_hide_pointers = FALSE;
	}

	panic_check_hook();

	PE_parse_boot_argn("keepsyms", &keepsyms, sizeof (keepsyms));

	if (msg != NULL) {
		paniclog_append_noflush("%s", msg);
	}

	if ((regdump == TRUE) && (regs != NULL)) {
		x86_saved_state64_t	*ss64p = saved_state64(regs);
		paniclog_append_noflush(
		    "RAX: 0x%016llx, RBX: 0x%016llx, RCX: 0x%016llx, RDX: 0x%016llx\n"
		    "RSP: 0x%016llx, RBP: 0x%016llx, RSI: 0x%016llx, RDI: 0x%016llx\n"
		    "R8:  0x%016llx, R9:  0x%016llx, R10: 0x%016llx, R11: 0x%016llx\n"
		    "R12: 0x%016llx, R13: 0x%016llx, R14: 0x%016llx, R15: 0x%016llx\n"
		    "RFL: 0x%016llx, RIP: 0x%016llx, CS:  0x%016llx, SS:  0x%016llx\n",
		    ss64p->rax, ss64p->rbx, ss64p->rcx, ss64p->rdx,
		    ss64p->isf.rsp, ss64p->rbp, ss64p->rsi, ss64p->rdi,
		    ss64p->r8,  ss64p->r9,  ss64p->r10, ss64p->r11,
		    ss64p->r12, ss64p->r13, ss64p->r14, ss64p->r15,
		    ss64p->isf.rflags, ss64p->isf.rip, ss64p->isf.cs,
		    ss64p->isf.ss);
		PC = ss64p->isf.rip;
	}

	paniclog_append_noflush("Backtrace (CPU %d), "
#if PRINT_ARGS_FROM_STACK_FRAME
	"Frame : Return Address (4 potential args on stack)\n", cn);
#else
	"Frame : Return Address\n", cn);
#endif

	for (frame_index = 0; frame_index < nframes; frame_index++) {
		vm_offset_t curframep = (vm_offset_t) frame;

		if (!curframep)
			break;

		if (curframep & 0x3) {
			paniclog_append_noflush("Unaligned frame\n");
			goto invalid;
		}

		if (!kvtophys(curframep) ||
		    !kvtophys(curframep + sizeof(cframe_t) - 1)) {
			paniclog_append_noflush("No mapping exists for frame pointer\n");
			goto invalid;
		}

		paniclog_append_noflush("%p : 0x%lx ", frame, frame->caller);
		if (frame_index < DUMPFRAMES)
			raddrs[frame_index] = frame->caller;

#if PRINT_ARGS_FROM_STACK_FRAME
		if (kvtophys((vm_offset_t)&(frame->args[3])))
			paniclog_append_noflush("(0x%x 0x%x 0x%x 0x%x) ",
			    frame->args[0], frame->args[1],
			    frame->args[2], frame->args[3]);
#endif

		/* Display address-symbol translation only if the "keepsyms"
		 * boot-arg is suppplied, since we unload LINKEDIT otherwise.
		 * This routine is potentially unsafe; also, function
		 * boundary identification is unreliable after a strip -x.
		 */
		if (keepsyms)
			panic_print_symbol_name((vm_address_t)frame->caller);
		
		paniclog_append_noflush("\n");

		frame = frame->prev;
	}

	if (frame_index >= nframes)
		paniclog_append_noflush("\tBacktrace continues...\n");

	goto out;

invalid:
	paniclog_append_noflush("Backtrace terminated-invalid frame pointer %p\n",frame);
out:

	/* Identify kernel modules in the backtrace and display their
	 * load addresses and dependencies. This routine should walk
	 * the kmod list safely.
	 */
	if (frame_index)
		kmod_panic_dump((vm_offset_t *)&raddrs[0], frame_index);

	if (PC != 0)
		kmod_panic_dump(&PC, 1);

	panic_display_system_configuration(FALSE);

	doprnt_hide_pointers = old_doprnt_hide_pointers;

	/* Release print backtrace lock, to permit other callers in the
	 * event of panics on multiple processors.
	 */
	hw_lock_unlock(&pbtlock);
	hw_atomic_sub(&pbtcnt, 1);
	/* Wait for other processors to complete output
	 * Timeout and continue after PBT_TIMEOUT_CYCLES.
	 */
	bt_tsc_timeout = rdtsc64() + PBT_TIMEOUT_CYCLES;
	while(*ppbtcnt && (rdtsc64() < bt_tsc_timeout));
}

static boolean_t
debug_copyin(pmap_t p, uint64_t uaddr, void *dest, size_t size)
{
        size_t rem = size;
        char *kvaddr = dest;

        while (rem) {
                ppnum_t upn = pmap_find_phys(p, uaddr);
                uint64_t phys_src = ptoa_64(upn) | (uaddr & PAGE_MASK);
                uint64_t phys_dest = kvtophys((vm_offset_t)kvaddr);
                uint64_t src_rem = PAGE_SIZE - (phys_src & PAGE_MASK);
                uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
                size_t cur_size = (uint32_t) MIN(src_rem, dst_rem);
                cur_size = MIN(cur_size, rem);

                if (upn && pmap_valid_page(upn) && phys_dest) {
                        bcopy_phys(phys_src, phys_dest, cur_size);
                }
                else
                        break;
                uaddr += cur_size;
                kvaddr += cur_size;
                rem -= cur_size;
        }
        return (rem == 0);
}

void
print_threads_registers(thread_t thread)
{
	x86_saved_state_t *savestate;
	
	savestate = get_user_regs(thread);
	paniclog_append_noflush(
		"\nRAX: 0x%016llx, RBX: 0x%016llx, RCX: 0x%016llx, RDX: 0x%016llx\n"
	    "RSP: 0x%016llx, RBP: 0x%016llx, RSI: 0x%016llx, RDI: 0x%016llx\n"
	    "R8:  0x%016llx, R9:  0x%016llx, R10: 0x%016llx, R11: 0x%016llx\n"
		"R12: 0x%016llx, R13: 0x%016llx, R14: 0x%016llx, R15: 0x%016llx\n"
		"RFL: 0x%016llx, RIP: 0x%016llx, CS:  0x%016llx, SS:  0x%016llx\n\n",
		savestate->ss_64.rax, savestate->ss_64.rbx, savestate->ss_64.rcx, savestate->ss_64.rdx,
		savestate->ss_64.isf.rsp, savestate->ss_64.rbp, savestate->ss_64.rsi, savestate->ss_64.rdi,
		savestate->ss_64.r8, savestate->ss_64.r9,  savestate->ss_64.r10, savestate->ss_64.r11,
		savestate->ss_64.r12, savestate->ss_64.r13, savestate->ss_64.r14, savestate->ss_64.r15,
		savestate->ss_64.isf.rflags, savestate->ss_64.isf.rip, savestate->ss_64.isf.cs,
		savestate->ss_64.isf.ss);
}

void
print_tasks_user_threads(task_t task)
{
	thread_t		thread = current_thread();
	x86_saved_state_t *savestate;
	pmap_t			pmap = 0;
	uint64_t		rbp;
	const char		*cur_marker = 0;
	int             j;
	
	for (j = 0, thread = (thread_t) queue_first(&task->threads); j < task->thread_count;
			++j, thread = (thread_t) queue_next(&thread->task_threads)) {

		paniclog_append_noflush("Thread %d: %p\n", j, thread);
		pmap = get_task_pmap(task);
		savestate = get_user_regs(thread);
		rbp = savestate->ss_64.rbp;
		paniclog_append_noflush("\t0x%016llx\n", savestate->ss_64.isf.rip);
		print_one_backtrace(pmap, (vm_offset_t)rbp, cur_marker, TRUE);
		paniclog_append_noflush("\n");
	}
}

void
print_thread_num_that_crashed(task_t task)
{
	thread_t		c_thread = current_thread();
	thread_t		thread;
	int             j;
	
	for (j = 0, thread = (thread_t) queue_first(&task->threads); j < task->thread_count;
			++j, thread = (thread_t) queue_next(&thread->task_threads)) {

		if (c_thread == thread) {
			paniclog_append_noflush("\nThread %d crashed\n", j);
			break;
		}
	}
}

#define PANICLOG_UUID_BUF_SIZE 256

void print_uuid_info(task_t task)
{
	uint32_t		uuid_info_count = 0;
	mach_vm_address_t	uuid_info_addr = 0;
	boolean_t		have_map = (task->map != NULL) &&	(ml_validate_nofault((vm_offset_t)(task->map), sizeof(struct _vm_map)));
	boolean_t		have_pmap = have_map && (task->map->pmap != NULL) && (ml_validate_nofault((vm_offset_t)(task->map->pmap), sizeof(struct pmap)));
	int				task_pid = pid_from_task(task);
	char			uuidbuf[PANICLOG_UUID_BUF_SIZE] = {0};
	char			*uuidbufptr = uuidbuf;
	uint32_t		k;

	if (have_pmap && task->active && task_pid > 0) {
		/* Read dyld_all_image_infos struct from task memory to get UUID array count & location */
		struct user64_dyld_all_image_infos task_image_infos;
		if (debug_copyin(task->map->pmap, task->all_image_info_addr,
			&task_image_infos, sizeof(struct user64_dyld_all_image_infos))) {
			uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
			uuid_info_addr = task_image_infos.uuidArray;
		}

		/* If we get a NULL uuid_info_addr (which can happen when we catch dyld
		 * in the middle of updating this data structure), we zero the
		 * uuid_info_count so that we won't even try to save load info for this task
		 */
		if (!uuid_info_addr) {
			uuid_info_count = 0;
		}
	}

	if (task_pid > 0 && uuid_info_count > 0) {
		uint32_t uuid_info_size = sizeof(struct user64_dyld_uuid_info);
		uint32_t uuid_array_size = uuid_info_count * uuid_info_size;
		uint32_t uuid_copy_size = 0;
		uint32_t uuid_image_count = 0;
		char *current_uuid_buffer = NULL;
		/* Copy in the UUID info array. It may be nonresident, in which case just fix up nloadinfos to 0 */
		
		paniclog_append_noflush("\nuuid info:\n");
		while (uuid_array_size) {
			if (uuid_array_size <= PANICLOG_UUID_BUF_SIZE) {
				uuid_copy_size = uuid_array_size;
				uuid_image_count = uuid_array_size/uuid_info_size;
			} else {
				uuid_image_count = PANICLOG_UUID_BUF_SIZE/uuid_info_size;
				uuid_copy_size = uuid_image_count * uuid_info_size;
			}
			if (have_pmap && !debug_copyin(task->map->pmap, uuid_info_addr, uuidbufptr,
				uuid_copy_size)) {
				paniclog_append_noflush("Error!! Failed to copy UUID info for task %p pid %d\n", task, task_pid);
				uuid_image_count = 0;
				break;
			}

			if (uuid_image_count > 0) {
				current_uuid_buffer = uuidbufptr;
				for (k = 0; k < uuid_image_count; k++) {
					paniclog_append_noflush(" %#llx", *(uint64_t *)current_uuid_buffer);
					current_uuid_buffer += sizeof(uint64_t);
					uint8_t *uuid = (uint8_t *)current_uuid_buffer;
					paniclog_append_noflush("\tuuid = <%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x>\n",
					uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8],
					uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
					current_uuid_buffer += 16;
				}
				bzero(&uuidbuf, sizeof(uuidbuf));
			}
			uuid_info_addr += uuid_copy_size;
			uuid_array_size -= uuid_copy_size;
		}
	}
}

void print_launchd_info(void)
{
	task_t		task = current_task();
	thread_t	thread = current_thread();
	volatile	uint32_t *ppbtcnt = &pbtcnt;
	uint64_t	bt_tsc_timeout;
	int		cn = cpu_number();

	if(pbtcpu != cn) {
		hw_atomic_add(&pbtcnt, 1);
		/* Spin on print backtrace lock, which serializes output
		 * Continue anyway if a timeout occurs.
		 */
		hw_lock_to(&pbtlock, ~0U);
		pbtcpu = cn;
	}
	
	print_uuid_info(task);
	print_thread_num_that_crashed(task);
	print_threads_registers(thread);
	print_tasks_user_threads(task);

	panic_display_system_configuration(TRUE);
	
	/* Release print backtrace lock, to permit other callers in the
	 * event of panics on multiple processors.
	 */
	hw_lock_unlock(&pbtlock);
	hw_atomic_sub(&pbtcnt, 1);
	/* Wait for other processors to complete output
	 * Timeout and continue after PBT_TIMEOUT_CYCLES.
	 */
	bt_tsc_timeout = rdtsc64() + PBT_TIMEOUT_CYCLES;
	while(*ppbtcnt && (rdtsc64() < bt_tsc_timeout));

}
