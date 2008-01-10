/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <platforms.h>
#include <mach_kdb.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/cpu_data.h>
#include <kern/machine.h>
#include <i386/fpu.h>
#include <i386/ipl.h>
#include <i386/misc_protos.h>
#include <i386/mtrr.h>
#include <i386/machine_routines.h>
#include <i386/pmCPU.h>
#include <i386/postcode.h>
#include <architecture/i386/pio.h> /* inb() */
#include <pexpert/i386/boot.h>
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <i386/mp_desc.h>
#include <i386/mp.h>
#include <i386/cpuid.h>

#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOHibernatePrivate.h>

#include <pexpert/i386/efi.h>

#include <kern/thread.h>
#include <i386/thread.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

void	enable_bluebox(void);
void	disable_bluebox(void);

static void machine_conf(void);

extern int		default_preemption_rate;
extern int		max_unsafe_quanta;
extern int		max_poll_quanta;
extern int		idlehalt;
extern unsigned int	panic_is_inited;

int db_run_mode;

static int packAsc (uint8_t *inbuf, unsigned int length);

volatile int pbtcpu = -1;
hw_lock_data_t pbtlock;		/* backtrace print lock */
uint32_t pbtcnt = 0;

extern const char version[];

typedef struct _cframe_t {
    struct _cframe_t	*prev;
    unsigned		caller;
    unsigned		args[0];
} cframe_t;

void panic_i386_backtrace(void *_frame, int nframes);

static unsigned panic_io_port = 0;

void
machine_startup()
{
	int	boot_arg;

#if 0
	if( PE_get_hotkey( kPEControlKey ))
            halt_in_debugger = halt_in_debugger ? 0 : 1;
#endif

	if (PE_parse_boot_arg("debug", &boot_arg)) {
		if (boot_arg & DB_HALT) halt_in_debugger=1;
		if (boot_arg & DB_PRT) disableDebugOuput=FALSE; 
		if (boot_arg & DB_SLOG) systemLogDiags=TRUE; 
		if (boot_arg & DB_NMI) panicDebugging=TRUE; 
		if (boot_arg & DB_LOG_PI_SCRN) logPanicDataToScreen=TRUE; 
	}

#if NOTYET
	hw_lock_init(&debugger_lock);	/* initialize debugger lock */
#endif
	hw_lock_init(&pbtlock);		/* initialize print backtrace lock */

#if	MACH_KDB
	/*
	 * Initialize KDB
	 */
#if	DB_MACHINE_COMMANDS
	db_machine_commands_install(ppc_db_commands);
#endif	/* DB_MACHINE_COMMANDS */
	ddb_init();

	if (boot_arg & DB_KDB)
		current_debugger = KDB_CUR_DB;

	/*
	 * Cause a breakpoint trap to the debugger before proceeding
	 * any further if the proper option bit was specified in
	 * the boot flags.
	 */
	if (halt_in_debugger && (current_debugger == KDB_CUR_DB)) {
	        Debugger("inline call to debugger(machine_startup)");
		halt_in_debugger = 0;
		active_debugger =1;
	}
#endif /* MACH_KDB */

	if (PE_parse_boot_arg("preempt", &boot_arg)) {
		default_preemption_rate = boot_arg;
	}
	if (PE_parse_boot_arg("unsafe", &boot_arg)) {
		max_unsafe_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("poll", &boot_arg)) {
		max_poll_quanta = boot_arg;
	}
	if (PE_parse_boot_arg("yield", &boot_arg)) {
		sched_poll_yield_shift = boot_arg;
	}
	if (PE_parse_boot_arg("idlehalt", &boot_arg)) {
		idlehalt = boot_arg;
	}
/* The I/O port to issue a read from, in the event of a panic. Useful for
 * triggering logic analyzers.
 */
	if (PE_parse_boot_arg("panic_io_port", &boot_arg)) {
		/*I/O ports range from 0 through 0xFFFF */
		panic_io_port = boot_arg & 0xffff;
	}

/*
 *	fn is used to force napping.
 *		fn=0 means no napping allowed
 *		fn=1 means forces napping on, normal C2 and C4 transitions
 *		fn=2 means forces napping on, but C4 is disabled
 *		fn=3 means forces napping on, but use halt
 *		fn=4 means forces napping on and will always use C4
 *
 *		Note that this will take effect only when the system normally starts napping.
 *
 */ 

	if (!PE_parse_boot_arg("fn", &forcenap)) forcenap = 0;	/* If force nap not set, make 0 */
	else {
		if(forcenap < 5) forcenap = forcenap + 1;		/* See comments above for decode, this is set to fn + 1 */
		else forcenap = 0;								/* Clear for error case */
	}
	machine_nap_policy();								/* Make sure the nap policy reflects the user's choice */

	machine_conf();

#if NOTYET
	ml_thrm_init();		/* Start thermal monitoring on this processor */
#endif

	/*
	 * Start the system.
	 */
	kernel_bootstrap();
	/*NOTREACHED*/
}


static void
machine_conf(void)
{
	machine_info.memory_size = mem_size;
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

    kprintf("Processing 64-bit EFI tables at 0x%x\n", (unsigned int)system_table);
    do {
        if (system_table->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
	    kprintf("Bad EFI system table signature\n");
            break;
        }
        // Verify signature of the system table
        hdr_cksum = system_table->Hdr.CRC32;
        system_table->Hdr.CRC32 = 0;
        cksum = crc32(0L, system_table, system_table->Hdr.HeaderSize);

        //kprintf("System table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
        system_table->Hdr.CRC32 = hdr_cksum;
        if (cksum != hdr_cksum) {
            kprintf("Bad EFI system table checksum\n");
            break;
        }

	gPEEFISystemTable     = system_table;

        kprintf("RuntimeServices table at 0x%qx\n", system_table->RuntimeServices);
        runtime = (EFI_RUNTIME_SERVICES_64 *) (uint32_t)system_table->RuntimeServices; // XXX
        kprintf("Checking runtime services table 0x%x\n", runtime);
	if (runtime->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE) {
	    kprintf("Bad EFI runtime table signature\n");
	    break;
	}

	// Verify signature of runtime services table
	hdr_cksum = runtime->Hdr.CRC32;
	runtime->Hdr.CRC32 = 0;
	cksum = crc32(0L, runtime, runtime->Hdr.HeaderSize);

	//kprintf("Runtime table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
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
efi_set_tables_32(EFI_SYSTEM_TABLE * system_table)
{
    EFI_RUNTIME_SERVICES *runtime;
    uint32_t hdr_cksum;
    uint32_t cksum;

    kprintf("Processing 32-bit EFI tables at 0x%x\n", (unsigned int)system_table);
    do {
        if (system_table->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
	    kprintf("Bad EFI system table signature\n");
            break;
        }
        // Verify signature of the system table
        hdr_cksum = system_table->Hdr.CRC32;
        system_table->Hdr.CRC32 = 0;
        cksum = crc32(0L, system_table, system_table->Hdr.HeaderSize);

        //kprintf("System table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
        system_table->Hdr.CRC32 = hdr_cksum;
        if (cksum != hdr_cksum) {
            kprintf("Bad EFI system table checksum\n");
            break;
        }

	gPEEFISystemTable     = system_table;

        runtime = (EFI_RUNTIME_SERVICES *) system_table->RuntimeServices;
	if (runtime->Hdr.Signature != EFI_RUNTIME_SERVICES_SIGNATURE) {
	    kprintf("Bad EFI runtime table signature\n");
	    break;
	}

	// Verify signature of runtime services table
	hdr_cksum = runtime->Hdr.CRC32;
	runtime->Hdr.CRC32 = 0;
	cksum = crc32(0L, runtime, runtime->Hdr.HeaderSize);

	//kprintf("Runtime table calculated CRC32 = 0x%x, header = 0x%x\n", cksum, hdr_cksum);
	runtime->Hdr.CRC32 = hdr_cksum;
	if (cksum != hdr_cksum) {
	    kprintf("Bad EFI runtime table checksum\n");
	    break;
	}

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

	mptr = (EfiMemoryRange *)args->MemoryMap;
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if (((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) ) {
		vm_size = i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;
		pmap_map(vm_addr, phys_addr, phys_addr + round_page(vm_size),
		     (mptr->Type == kEfiRuntimeServicesCode) ? VM_PROT_READ | VM_PROT_EXECUTE : VM_PROT_READ|VM_PROT_WRITE,
		     (mptr->Type == EfiMemoryMappedIO)       ? VM_WIMG_IO   : VM_WIMG_USE_DEFAULT);
	    }
	}

        if (args->Version > 1)
                panic("Incompatible boot args version %d\n", args->Version);

        kprintf("Boot args version %d revision %d mode %d\n", args->Version, args->Revision, args->efiMode);
        if (args->Revision >= 4 && args->efiMode == kBootArgsEfiMode64) {
                efi_set_tables_64((EFI_SYSTEM_TABLE_64 *) args->efiSystemTable);
        } else {
                efi_set_tables_32((EFI_SYSTEM_TABLE *) args->efiSystemTable);
        }
    }
    while (FALSE);

    return;
}

/* Remap EFI runtime areas. */
void
hibernate_newruntime_map(void * map, vm_size_t map_size, uint32_t system_table_offset)
{
    boot_args *args = (boot_args *)PE_state.bootArgs;

    kprintf("Reinitializing EFI runtime services\n");

    if (args->Revision < 3)
	return;
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

	kprintf("Old system table %p, new %p\n",
	    args->efiSystemTable,    (void *) system_table_offset);

	args->efiSystemTable    = (uint32_t) system_table_offset;

	kprintf("Old map:\n");
	msize = args->MemoryMapDescriptorSize;
	mcount = args->MemoryMapSize / msize;
	mptr = (EfiMemoryRange *)args->MemoryMap;
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if ((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) {

		vm_size = i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;

		kprintf("mapping[%d] %qx @ %x, %x\n", mptr->Type, phys_addr, vm_addr, mptr->NumberOfPages);
	    }
	}

	pmap_remove(kernel_pmap, i386_ptob(args->efiRuntimeServicesPageStart), 
				 i386_ptob(args->efiRuntimeServicesPageStart + args->efiRuntimeServicesPageCount));

	kprintf("New map:\n");
	msize = args->MemoryMapDescriptorSize;
	mcount = map_size / msize;
	mptr = map;
	for (i=0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	    if ((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) {

		vm_size = i386_ptob((uint32_t)mptr->NumberOfPages);
		vm_addr =   (vm_offset_t) mptr->VirtualStart;
		phys_addr = (vm_map_offset_t) mptr->PhysicalStart;

		kprintf("mapping[%d] %qx @ %x, %x\n", mptr->Type, phys_addr, vm_addr, mptr->NumberOfPages);

		pmap_map(vm_addr, phys_addr, phys_addr + round_page(vm_size),
			 (mptr->Type == kEfiRuntimeServicesCode) ? VM_PROT_READ | VM_PROT_EXECUTE : VM_PROT_READ|VM_PROT_WRITE,
			 (mptr->Type == EfiMemoryMappedIO)       ? VM_WIMG_IO   : VM_WIMG_USE_DEFAULT);
	    }
	}

        if (args->Version > 1)
                panic("Incompatible boot args version %d\n", args->Version);

        kprintf("Boot args version %d revision %d mode %d\n", args->Version, args->Revision, args->efiMode);
        if (args->Revision >= 4 && args->efiMode == kBootArgsEfiMode64) {
                efi_set_tables_64((EFI_SYSTEM_TABLE_64 *) args->efiSystemTable);
        } else {
                efi_set_tables_32((EFI_SYSTEM_TABLE *) args->efiSystemTable);
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

	/*
	 * Initialize MTRR from boot processor.
	 */
	mtrr_init();

	/*
	 * Set up PAT for boot processor.
	 */
	pat_init();

	/*
	 * Free lowmem pages
	 */
	x86_lowmem_free();
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

static void
machine_halt_cpu(__unused void *arg) {
	panic_io_port_read();
	__asm__ volatile("hlt");
}

void
Debugger(
	const char	*message)
{
	unsigned long pi_size = 0;
	void *stackptr;

	hw_atomic_add(&debug_mode, 1);   
	if (!panic_is_inited) {
		postcode(PANIC_HLT);
		asm("hlt");
	}


	printf("Debugger called: <%s>\n", message);
	kprintf("Debugger called: <%s>\n", message);

	/*
	 * Skip the graphical panic box if no panic string.
	 * This is the case if we're being called from
	 *   host_reboot(,HOST_REBOOT_DEBUGGER)
	 * as a quiet way into the debugger.
	 */

	if (panicstr) {
		disable_preemption();

/* Issue an I/O port read if one has been requested - this is an event logic
 * analyzers can use as a trigger point.
 */
		panic_io_port_read();

		/* Obtain current frame pointer */
		__asm__ volatile("movl %%ebp, %0" : "=m" (stackptr));

		/* Print backtrace - callee is internally synchronized */
		panic_i386_backtrace(stackptr, 16);

		/* everything should be printed now so copy to NVRAM
		 */

		if( debug_buf_size > 0) {
		    /* Do not compress the panic log 
		     * or save to NVRAM unless kernel debugging 
		     * is disabled. The NVRAM shim doesn't
		     * sync to the store until haltRestart is called.
		     */
		    if (!panicDebugging) {
			unsigned int bufpos;
			
                        debug_putc(0);

			/* Now call the compressor */
			/* XXX Consider using the WKdm compressor in the
			 * future, rather than just packing - would need to
			 * be co-ordinated with crashreporter, which decodes
			 * this post-restart.
			 */
			bufpos = packAsc ((uint8_t *)debug_buf,
			    (unsigned int) (debug_buf_ptr - debug_buf) );
			/* If compression was successful,
			 * use the compressed length
			 */
			if (bufpos) {
			    debug_buf_ptr = debug_buf + bufpos;
                        }
			/* Save panic log to non-volatile store
			 * Panic info handler must truncate data that is 
			 * too long for this platform.
			 * This call must save data synchronously,
			 * since we can subsequently halt the system.
			 */
                        pi_size = debug_buf_ptr - debug_buf;
                        pi_size = PESavePanicInfo((unsigned char *)debug_buf,
			    pi_size );
                    }
                }
		draw_panic_dialog();

		if (!panicDebugging) {
			/* Clear the MP rendezvous function lock, in the event
			 * that a panic occurred while in that codepath.
			 */
			mp_rendezvous_break_lock();
			/* Force all CPUs to disable interrupts and HLT.
			 * We've panicked, and shouldn't depend on the
			 * PEHaltRestart() mechanism, which relies on several
			 * bits of infrastructure.
			 */
			mp_rendezvous_no_intrs(machine_halt_cpu, NULL);
			/* NOT REACHED */
		}
        }

	__asm__("int3");
	hw_atomic_sub(&debug_mode, 1);   
}

void
enable_bluebox(void)
{
}

void
disable_bluebox(void)
{
}

char *
machine_boot_info(char *buf, __unused vm_size_t size)
{
	*buf ='\0';
	return buf;
}


struct pasc {
    unsigned a: 7;
    unsigned b: 7;
    unsigned c: 7;
    unsigned d: 7;
    unsigned e: 7;
    unsigned f: 7;
    unsigned g: 7;
    unsigned h: 7;
}  __attribute__((packed));

typedef struct pasc pasc_t;

static int packAsc (unsigned char *inbuf, unsigned int length)
{
  unsigned int i, j = 0;
  unsigned int extra;
  pasc_t pack;

  for (i = 0; i < length; i+=8)
    {
      pack.a = inbuf[i];
      pack.b = inbuf[i+1];
      pack.c = inbuf[i+2];
      pack.d = inbuf[i+3];
      pack.e = inbuf[i+4];
      pack.f = inbuf[i+5];
      pack.g = inbuf[i+6];
      pack.h = inbuf[i+7];
      bcopy ((char *) &pack, inbuf + j, 7);
      j += 7;
    }
  extra = (i - length);
  if (extra > 0) {
    inbuf[j - extra] &= (0xFF << (8-extra));
  }
  return j-((extra == 7) ? 6 : extra);
}

/* Routines for address - symbol translation. Not called unless the "keepsyms"
 * boot-arg is supplied.
 */

static int
panic_print_macho_symbol_name(struct mach_header *mh, vm_address_t search)
{
    struct nlist			*sym = NULL;
    struct load_command		*cmd;
    struct segment_command	*orig_ts = NULL, *orig_le = NULL;
    struct symtab_command	*orig_st = NULL;
    unsigned int			i;
    char					*strings, *bestsym = NULL;
    vm_address_t			bestaddr = 0, diff, curdiff;
    
    if (mh->magic != MH_MAGIC) {
        /* bad magic number */
        return 0;
    }
    
    cmd = (struct load_command *) &mh[1];
    for (i = 0; i < mh->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *orig_sg = (struct segment_command *) cmd;
            
            if (strcmp(SEG_TEXT, orig_sg->segname) == 0)
                orig_ts = orig_sg;
            else if (strcmp(SEG_LINKEDIT, orig_sg->segname) == 0)
                orig_le = orig_sg;
            else if (strcmp("", orig_sg->segname) == 0)
                orig_ts = orig_sg; /* kexts have a single unnamed segment */
        }
        else if (cmd->cmd == LC_SYMTAB)
            orig_st = (struct symtab_command *) cmd;
        
        cmd = (struct load_command *) ((caddr_t) cmd + cmd->cmdsize);
    }
    
    if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
        return 0;
    
    /* kexts don't have a LINKEDIT segment for now, so we'll never get this far for kexts */
    
    vm_address_t slide = ((vm_address_t)mh) - orig_ts->vmaddr;
    if (slide != 0)
        search -= slide; /* adjusting search since the binary has slid */
    
    if ((search < orig_ts->vmaddr) ||
        (search >= orig_ts->vmaddr + orig_ts->vmsize)) {
        /* search out of range for this mach header */
        return 0;
    }
    
    sym = (struct nlist *)orig_le->vmaddr;
    strings = ((char *)sym) + orig_st->nsyms * sizeof(struct nlist);
    diff = search;
    
    for (i = 0; i < orig_st->nsyms; i++) {
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
            kdb_printf("%s + 0x%08x ", bestsym, diff);
        } else {
            kdb_printf("%s ", bestsym);
        }
        return 1;
    }
    return 0;
}

extern kmod_info_t * kmod; /* the list of modules */

static void
panic_print_kmod_symbol_name(vm_address_t search)
{
    kmod_info_t *			current_kmod = kmod;
    
    while (current_kmod != NULL) {
        if ((current_kmod->address <= search) &&
            (current_kmod->address + current_kmod->size > search))
            break;
        current_kmod = current_kmod->next;
    }
    if (current_kmod != NULL) {
        /* if kexts had symbol table loaded, we'd call search_symbol_name again; alas, they don't */
        kdb_printf("%s + %d ", current_kmod->name, search - current_kmod->address);
    }
}

extern struct mach_header _mh_execute_header; /* the kernel's mach header */

static void
panic_print_symbol_name(vm_address_t search)
{
    /* try searching in the kernel */
    if (panic_print_macho_symbol_name(&_mh_execute_header, search) == 0) {
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
panic_i386_backtrace(void *_frame, int nframes)
{
	cframe_t	*frame = (cframe_t *)_frame;
	vm_offset_t raddrs[DUMPFRAMES];
	int frame_index;
	volatile uint32_t *ppbtcnt = &pbtcnt;
	uint64_t bt_tsc_timeout;
	boolean_t keepsyms = FALSE;

	if(pbtcpu != cpu_number()) {
		hw_atomic_add(&pbtcnt, 1);
		/* Spin on print backtrace lock, which serializes output
		 * Continue anyway if a timeout occurs.
		 */
		hw_lock_to(&pbtlock, LockTimeOut*100);
		pbtcpu = cpu_number();
	}

	PE_parse_boot_arg("keepsyms", &keepsyms);

	kdb_printf("Backtrace, "
	    "Format - Frame : Return Address (4 potential args on stack) ");

	for (frame_index = 0; frame_index < nframes; frame_index++) {
		vm_offset_t curframep = (vm_offset_t) frame;

		if (!curframep)
			break;

		if (curframep & 0x3) {
			kdb_printf("Unaligned frame\n");
			goto invalid;
		}

		if (!kvtophys(curframep) ||
		    !kvtophys(curframep + sizeof(cframe_t))) {
			kdb_printf("No mapping exists for frame pointer\n");
			goto invalid;
		}

		kdb_printf("\n0x%x : 0x%x ",
		    frame, frame->caller);
		if (frame_index < DUMPFRAMES)
			raddrs[frame_index] = frame->caller;

		if (kvtophys((vm_offset_t)&(frame->args[3])))
			kdb_printf("(0x%x 0x%x 0x%x 0x%x) ",
			    frame->args[0], frame->args[1],
			    frame->args[2], frame->args[3]);

		/* Display address-symbol translation only if the "keepsyms"
		 * boot-arg is suppplied, since we unload LINKEDIT otherwise.
		 * This routine is potentially unsafe; also, function
		 * boundary identification is unreliable after a strip -x.
		 */
		if (keepsyms)
			panic_print_symbol_name((vm_address_t)frame->caller);
		
		/* Stack grows downward */
		if (frame->prev < frame) {
			frame = frame->prev;
			goto invalid;
		}
		frame = frame->prev;
	}

	if (frame_index >= nframes)
		kdb_printf("\tBacktrace continues...\n");

	goto out;

invalid:
	kdb_printf("Backtrace terminated-invalid frame pointer 0x%x\n",frame);
out:

	/* Identify kernel modules in the backtrace and display their
	 * load addresses and dependencies. This routine should walk
	 * the kmod list safely.
	 */
	if (frame_index)
		kmod_dump((vm_offset_t *)&raddrs[0], frame_index);

	kdb_printf("\nKernel version:\n%s\n\n",version);

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
