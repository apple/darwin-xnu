/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <platforms.h>
#include <mp_v1_1.h>
#include <mach_kdb.h>
#include <himem.h>
#include <fast_idle.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/etap_macros.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/clock.h>
#include <kern/time_out.h>
#include <kern/xpr.h>
#include <kern/cpu_data.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <i386/fpu.h>
#include <i386/pmap.h>
#include <i386/ipl.h>
#include <i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/cpuid.h>
#include <i386/rtclock_entries.h>
#include <i386/AT386/mp/mp.h>
#if	MACH_KDB
#include <ddb/db_aout.h>
#endif /* MACH_KDB */
#include <ddb/tr.h>
#ifdef __MACHO__
#include <i386/AT386/kernBootStruct.h>
#include <mach/boot_info.h>
#include <mach/thread_status.h>
#endif

#if	NCPUS > 1
#include <i386/mp_desc.h>
#endif	/* NCPUS */

#if	MP_V1_1
#include <i386/AT386/mp/mp_v1_1.h>
#endif	/* MP_V1_1 */

vm_size_t	mem_size = 0; 
vm_offset_t	first_addr = 0;	/* set by start.s - keep out of bss */
vm_offset_t	first_avail = 0;/* first after page tables */
vm_offset_t	last_addr;

vm_offset_t	avail_start, avail_end;
vm_offset_t	virtual_avail, virtual_end;
vm_offset_t	hole_start, hole_end;
vm_offset_t	avail_next;
unsigned int	avail_remaining;

/* parameters passed from bootstrap loader */
int		cnvmem = 0;		/* must be in .data section */
int		extmem = 0;

/* FIXME!! REMOVE WHEN OSFMK DEVICES ARE COMPLETELY PULLED OUT */
int		dev_name_count = 0;
int		dev_name_list = 0;

#ifndef __MACHO__
extern char	edata, end;
#endif

extern char	version[];

int		rebootflag = 0;	/* exported to kdintr */


void		parse_arguments(void);
const char	*getenv(const char *);

#define 	BOOT_LINE_LENGTH 160
char		boot_string_store[BOOT_LINE_LENGTH] = {0};
char 		*boot_string = (char *)0;
int		boot_string_sz = BOOT_LINE_LENGTH;
int		boottype = 0;

#if	__MACHO__
#include	<mach-o/loader.h>
vm_offset_t	edata, etext, end;

extern struct mach_header _mh_execute_header;
void *sectTEXTB; int sectSizeTEXT;
void *sectDATAB; int sectSizeDATA;
void *sectOBJCB; int sectSizeOBJC;
void *sectLINKB; int sectSizeLINK;

/* Kernel boot information */
KERNBOOTSTRUCT kernBootStructData;
KERNBOOTSTRUCT *kernBootStruct;
#endif

vm_offset_t	kern_args_start = 0;	/* kernel arguments */
vm_size_t	kern_args_size = 0;	/* size of kernel arguments */

#ifdef __MACHO__

unsigned long
i386_preinit()
{
	int i;
	struct segment_command	*sgp;
	struct section		*sp;

	sgp = (struct segment_command *) getsegbyname("__DATA");
	if (sgp) {
		sp = (struct section *) firstsect(sgp);
		if (sp) {
			do {
				if (sp->flags & S_ZEROFILL)
					bzero((char *) sp->addr, sp->size);
			} while (sp = (struct section *)nextsect(sgp, sp));
		}
	}

	bcopy((char *) KERNSTRUCT_ADDR, (char *) &kernBootStructData,
					sizeof(kernBootStructData));

	kernBootStruct = &kernBootStructData;

    end = round_page( kernBootStruct->kaddr + kernBootStruct->ksize );

	return	end;
}
#endif

/*
 *	Cpu initialization.  Running virtual, but without MACH VM
 *	set up.  First C routine called.
 */
void
machine_startup(void)
{

#ifdef	__MACHO__


	/* Now copy over various bits.. */
	cnvmem = kernBootStruct->convmem;
	extmem = kernBootStruct->extmem;
	kern_args_start = (vm_offset_t) kernBootStruct->bootString;
	kern_args_size = strlen(kernBootStruct->bootString);
	boottype = kernBootStruct->rootdev;

	/* Now retrieve addresses for end, edata, and etext 
	 * from MACH-O headers.
	 */

	sectTEXTB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__TEXT", &sectSizeTEXT);
	sectDATAB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__DATA", &sectSizeDATA);
	sectOBJCB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__OBJC", &sectSizeOBJC);
	sectLINKB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__LINKEDIT", &sectSizeLINK);

	etext = (vm_offset_t) sectTEXTB + sectSizeTEXT;
	edata = (vm_offset_t) sectDATAB + sectSizeDATA;
#endif

	/*
	 * Parse startup arguments
	 */
	parse_arguments();

	disableDebugOuput = FALSE;
	debug_mode = TRUE;
	
	printf_init();						/* Init this in case we need debugger */
	panic_init();						/* Init this in case we need debugger */

	PE_init_platform(FALSE, kernBootStruct);
	PE_init_kprintf(FALSE);
	PE_init_printf(FALSE);

	/*
	 * Do basic VM initialization
	 */
	i386_init();

	PE_init_platform(TRUE, kernBootStruct);
	PE_init_kprintf(TRUE);
	PE_init_printf(TRUE);

#if	MACH_KDB

	/*
	 * Initialize the kernel debugger.
	 */
	ddb_init();

	/*
	 * Cause a breakpoint trap to the debugger before proceeding
	 * any further if the proper option bit was specified in
	 * the boot flags.
	 *
	 * XXX use -a switch to invoke kdb, since there's no
	 *     boot-program switch to turn on RB_HALT!
	 */

	if (halt_in_debugger) {
		printf("inline call to debugger(machine_startup)\n");
	        Debugger("inline call");
	}
#endif	/* MACH_KDB */
	TR_INIT();

	printf(version);

	machine_slot[0].is_cpu = TRUE;
	machine_slot[0].running = TRUE;
#ifdef	MACH_BSD
	/* FIXME */
	machine_slot[0].cpu_type = CPU_TYPE_I386;
	machine_slot[0].cpu_subtype = CPU_SUBTYPE_PENTPRO;
#else
	machine_slot[0].cpu_type = cpuid_cputype(0);
	machine_slot[0].cpu_subtype = CPU_SUBTYPE_AT386;
#endif

	/*
	 * Start the system.
	 */
#if	NCPUS > 1
	mp_desc_init(0);
#endif	/* NCPUS */

	setup_main();
}


vm_offset_t	env_start = 0;		/* environment */
vm_size_t	env_size = 0;		/* size of environment */

/*
 * Parse command line arguments.
 */
void
parse_arguments(void)
{
	char *p = (char *) kern_args_start;
	char *endp = (char *) kern_args_start + kern_args_size - 1;
	char ch;

	if (kern_args_start == 0)
	    return;

	/*
	 * handle switches in exact format of  -h  or -m64
	 */
	while ( (p < endp) && (*p != '\0')) {
	  if (*p++ != '-') 
	    continue;
	  switch (*p++) {
	  case 'h':
	    halt_in_debugger = 1;
	    break;
	  case 'm':
	    mem_size = atoi_term(p,&p)*1024*1024;
	    break;
	  case 'k':
	    mem_size = atoi_term(p,&p)*1024;
	    break;
	  default:
	    break;
	  }
	}

}

const char *
getenv(const char *name)
{
	int len = strlen(name);
	const char *p = (const char *)env_start;
	const char *endp = p + env_size;

	while (p < endp) {
		if (len >= endp - p)
			break;
		if (strncmp(name, p, len) == 0 && *(p + len) == '=')
			return p + len + 1;
		while (*p++)
			;
	}
	return NULL;
}

extern void
calibrate_delay(void);

/*
 * Find devices.  The system is alive.
 */
void
machine_init(void)
{
	int unit;
	const char *p;
	int n;

	/*
	 * Adjust delay count before entering drivers
	 */

	calibrate_delay();

	/*
	 * Display CPU identification
	 */
	cpuid_cpu_display("CPU identification", 0);
	cpuid_cache_display("CPU configuration", 0);

#if	MP_V1_1
	mp_v1_1_init();
#endif	/* MP_V1_1 */

	/*
	 * Set up to use floating point.
	 */
	init_fpu();

#if 0
#if	NPCI > 0
	dma_zones_init();
#endif	/* NPCI > 0 */
#endif

	/*
	 * Configure clock devices.
	 */
	clock_config();
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
halt_all_cpus(
	boolean_t	reboot)
{
	if (reboot) {
	    /*
	     * Tell the BIOS not to clear and test memory.
	     */
	    if (! reset_mem_on_reboot)
		*(unsigned short *)phystokv(0x472) = 0x1234;

	    kdreboot();
	}
	else {
	    rebootflag = 1;
	    printf("In tight loop: hit ctl-alt-del to reboot\n");
	    (void) spllo();
	}
	for (;;)
	    continue;
}

/*
 * Basic VM initialization.
 */

void
i386_init(void)
{
	int i,j;			/* Standard index vars. */
	vm_size_t	bios_hole_size;	

#ifndef	__MACHO__
	/*
	 * Zero the BSS.
	 */

	bzero((char *)&edata,(unsigned)(&end - &edata));
#endif

	boot_string = &boot_string_store[0];

	/*
	 * Initialize the pic prior to any possible call to an spl.
	 */

	set_cpu_model();
	vm_set_page_size();

	/*
	 * Initialize the Event Trace Analysis Package
	 * Static Phase: 1 of 2
	 */
	etap_init_phase1();

	/*
	 * Compute the memory size.
	 */

#if  1
	/* FIXME 
	 * fdisk needs to change to use a sysctl instead of
	 * opening /dev/kmem and reading out the kernboot structure
	 */

	first_addr = (char *)(KERNSTRUCT_ADDR) + sizeof(KERNBOOTSTRUCT);
#else
#if NCPUS > 1
	first_addr = 0x1000;
#else
	/* First two pages are used to boot the other cpus. */
	/* TODO - reclaim pages after all cpus have booted */

	first_addr = 0x3000;
#endif
#endif

		/* BIOS leaves data in low memory */
	last_addr = 1024*1024 + extmem*1024;
	/* extended memory starts at 1MB */
       
	bios_hole_size = 1024*1024 - trunc_page((vm_offset_t)(1024 * cnvmem));

	/*
	 *	Initialize for pmap_free_pages and pmap_next_page.
	 *	These guys should be page-aligned.
	 */

	hole_start = trunc_page((vm_offset_t)(1024 * cnvmem));
	hole_end = round_page((vm_offset_t)first_avail);

	/*
	 * compute mem_size
	 */

	if (mem_size != 0) {
	    if (mem_size < (last_addr) - bios_hole_size)
		last_addr = mem_size + bios_hole_size;
	}

	first_addr = round_page(first_addr);
	last_addr = trunc_page(last_addr);
	mem_size = last_addr - bios_hole_size;

	avail_start = first_addr;
	avail_end = last_addr;
	avail_next = avail_start;

	/*
	 *	Initialize kernel physical map, mapping the
	 *	region from loadpt to avail_start.
	 *	Kernel virtual address starts at VM_KERNEL_MIN_ADDRESS.
	 */


#if	NCPUS > 1 && AT386
	/*
	 * Must Allocate interrupt stacks before kdb is called and also
	 * before vm is initialized. Must find out number of cpus first.
	 */
	/*
	 * Get number of cpus to boot, passed as an optional argument
	 * boot: mach [-sah#]	# from 0 to 9 is the number of cpus to boot
	 */
	if (wncpu == -1) {
		/*
		 * "-1" check above is to allow for old boot loader to pass
		 * wncpu through boothowto. New boot loader uses environment.
		 */
		const char *cpus;
		if ((cpus = getenv("cpus")) != NULL) {
			/* only a single digit for now */
			if ((*cpus > '0') && (*cpus <= '9'))
				wncpu = *cpus - '0';
		} else
			wncpu = NCPUS;
	}
	mp_probe_cpus();
	interrupt_stack_alloc();

#endif	/* NCPUS > 1 && AT386 */

	pmap_bootstrap(0);

	avail_remaining = atop((avail_end - avail_start) -
			       (hole_end - hole_start));
}

unsigned int
pmap_free_pages(void)
{
	return avail_remaining;
}

boolean_t
pmap_next_page(
	vm_offset_t *addrp)
{
	if (avail_next == avail_end) 
		return FALSE;

	/* skip the hole */

	if (avail_next == hole_start)
		avail_next = hole_end;

	*addrp = avail_next;
	avail_next += PAGE_SIZE;
	avail_remaining--;

	return TRUE;
}

boolean_t
pmap_valid_page(
	vm_offset_t x)
{
	return ((avail_start <= x) && (x < avail_end));
}

/*XXX*/
void fc_get(mach_timespec_t *ts);
#include <kern/clock.h>
#include <i386/rtclock_entries.h>
extern kern_return_t	sysclk_gettime(
			mach_timespec_t	*cur_time);
void fc_get(mach_timespec_t *ts) {
	(void )sysclk_gettime(ts);
}

void
Debugger(
	const char	*message)
{
	printf("Debugger called: <%s>\n", message);

	__asm__("int3");
}

void
display_syscall(int syscall)
{
	printf("System call happened %d\n", syscall);
}

#if	XPR_DEBUG && (NCPUS == 1 || MP_V1_1)

extern kern_return_t	sysclk_gettime_interrupts_disabled(
				mach_timespec_t	*cur_time);

int	xpr_time(void)
{
        mach_timespec_t	time;

	sysclk_gettime_interrupts_disabled(&time);
	return(time.tv_sec*1000000 + time.tv_nsec/1000);
}
#endif	/* XPR_DEBUG && (NCPUS == 1 || MP_V1_1) */

enable_bluebox()
{
}
disable_bluebox()
{
}

char *
machine_boot_info(char *buf, vm_size_t size)
{
	*buf ='\0';
	return buf;
}

