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

#include <cpus.h>
#include <mach_rt.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <i386/AT386/misc_protos.h>
#include <i386/AT386/mp/mp_v1_1.h>
#include <i386/AT386/mp/mp.h>
#include <i386/AT386/mp/boot.h>
#include <i386/apic.h>
#include <i386/ipl.h>
#include <i386/fpu.h>
#include <i386/pio.h>
#include <i386/cpuid.h>
#include <i386/proc_reg.h>
#include <i386/misc_protos.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <vm/vm_kern.h>
#include <kern/startup.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>

#define MP_DEBUG 1

#if	MP_DEBUG
vm_offset_t	bios_start;
#endif	/* MP_DEBUG */

unsigned int 	lapic_id_initdata = 0;
int 		lapic_id = (int)&lapic_id_initdata;
vm_offset_t 	lapic_start;

void 		lapic_init(void);
int 		get_ncpus(void);
void 		validate_cpus(int ncpus);
void 		cpu_interrupt(int cpu);
void 		slave_boot(int cpu);

boolean_t 	mp_v1_1_initialized = FALSE;

void
mp_v1_1_init(void)
{
	/*WILL BE REMOVED IN FUTURE REVISION!!! !*/
	/* SIMPLY COMMENTED OUT FOR THE MOMENT */
	return;
}

void
lapic_init(void)
{
}

void
cpu_interrupt(
	int	cpu)
{
}

#if NCPUS > 1
void
slave_boot(
	int	cpu)
{
}

void
start_other_cpus(void)
{
}

void
validate_cpus(int ncpus)
{
	int i;
	for(i=0;i<NCPUS;i++)
	    machine_slot[i].is_cpu = TRUE;
}

int
get_ncpus(void)
{
	return 1;
}

void
slave_machine_init(void)
{
}

#endif	/* NCPUS > 1 */

#if	MACH_KDB
#include <ddb/db_output.h>

#define TRAP_DEBUG 0 /* Must match interrupt.s and spl.s */


#if	TRAP_DEBUG
#define MTRAPS 100
struct mp_trap_hist_struct {
	unsigned char type;
	unsigned char data[5];
} trap_hist[MTRAPS], *cur_trap_hist = trap_hist,
    *max_trap_hist = &trap_hist[MTRAPS];

void db_trap_hist(void);

/*
 * SPL:
 *	1: new spl
 *	2: old spl
 *	3: new tpr
 *	4: old tpr
 * INT:
 * 	1: int vec
 *	2: old spl
 *	3: new spl
 *	4: post eoi tpr
 *	5: exit tpr
 */

void
db_trap_hist(void)
{
	int i,j;
	for(i=0;i<MTRAPS;i++)
	    if (trap_hist[i].type == 1 || trap_hist[i].type == 2) {
		    db_printf("%s%s",
			      (&trap_hist[i]>=cur_trap_hist)?"*":" ",
			      (trap_hist[i].type == 1)?"SPL":"INT");
		    for(j=0;j<5;j++)
			db_printf(" %02x", trap_hist[i].data[j]);
		    db_printf("\n");
	    }
		
}
#endif	/* TRAP_DEBUG */

void db_lapic(int cpu);
unsigned int db_remote_read(int cpu, int reg);
void db_ioapic(unsigned int);
void kdb_console(void);

void
kdb_console(void)
{
}

#define BOOLP(a) ((a)?' ':'!')

static char *DM[8] = {
	"Fixed",
	"Lowest Priority",
	"Invalid",
	"Invalid",
	"NMI",
	"Reset",
	"Invalid",
	"ExtINT"};

unsigned int
db_remote_read(int cpu, int reg)
{
	return -1;
}

void
db_lapic(int cpu)
{
}

void
db_ioapic(unsigned int ind)
{
}

#endif	/* MACH_KDB */
