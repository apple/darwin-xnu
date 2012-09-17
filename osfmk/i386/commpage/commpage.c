/*
 * Copyright (c) 2003-2010 Apple Inc. All rights reserved.
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
 *	Here's what to do if you want to add a new routine to the comm page:
 *
 *		1. Add a definition for it's address in osfmk/i386/cpu_capabilities.h,
 *		   being careful to reserve room for future expansion.
 *
 *		2. Write one or more versions of the routine, each with it's own
 *		   commpage_descriptor.  The tricky part is getting the "special",
 *		   "musthave", and "canthave" fields right, so that exactly one
 *		   version of the routine is selected for every machine.
 *		   The source files should be in osfmk/i386/commpage/.
 *
 *		3. Add a ptr to your new commpage_descriptor(s) in the "routines"
 *		   array in osfmk/i386/commpage/commpage_asm.s.  There are two
 *		   arrays, one for the 32-bit and one for the 64-bit commpage.
 *
 *		4. Write the code in Libc to use the new routine.
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/machine.h>
#include <i386/cpuid.h>
#include <i386/tsc.h>
#include <i386/rtclock_protos.h>
#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <i386/cpuid.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <ipc/ipc_port.h>

#include <kern/page_decrypt.h>
#include <kern/processor.h>

/* the lists of commpage routines are in commpage_asm.s  */
extern	commpage_descriptor*	commpage_32_routines[];
extern	commpage_descriptor*	commpage_64_routines[];

extern vm_map_t	commpage32_map;	// the shared submap, set up in vm init
extern vm_map_t	commpage64_map;	// the shared submap, set up in vm init

char	*commPagePtr32 = NULL;		// virtual addr in kernel map of 32-bit commpage
char	*commPagePtr64 = NULL;		// ...and of 64-bit commpage
uint32_t     _cpu_capabilities = 0;          // define the capability vector

int	noVMX = 0;		/* if true, do not set kHasAltivec in ppc _cpu_capabilities */

typedef uint32_t commpage_address_t;

static commpage_address_t	next;			// next available address in comm page
static commpage_address_t	cur_routine;		// comm page address of "current" routine
static boolean_t		matched;		// true if we've found a match for "current" routine

static char    *commPagePtr;		// virtual addr in kernel map of commpage we are working on
static commpage_address_t	commPageBaseOffset; // subtract from 32-bit runtime address to get offset in virtual commpage in kernel map

static	commpage_time_data	*time_data32 = NULL;
static	commpage_time_data	*time_data64 = NULL;

decl_simple_lock_data(static,commpage_active_cpus_lock);

/* Allocate the commpage and add to the shared submap created by vm:
 * 	1. allocate a page in the kernel map (RW)
 *	2. wire it down
 *	3. make a memory entry out of it
 *	4. map that entry into the shared comm region map (R-only)
 */

static  void*
commpage_allocate( 
	vm_map_t	submap,			// commpage32_map or commpage_map64
	size_t		area_used )		// _COMM_PAGE32_AREA_USED or _COMM_PAGE64_AREA_USED
{
	vm_offset_t	kernel_addr = 0;	// address of commpage in kernel map
	vm_offset_t	zero = 0;
	vm_size_t	size = area_used;	// size actually populated
	vm_map_entry_t	entry;
	ipc_port_t	handle;

	if (submap == NULL)
		panic("commpage submap is null");

	if (vm_map(kernel_map,&kernel_addr,area_used,0,VM_FLAGS_ANYWHERE,NULL,0,FALSE,VM_PROT_ALL,VM_PROT_ALL,VM_INHERIT_NONE))
		panic("cannot allocate commpage");

	if (vm_map_wire(kernel_map,kernel_addr,kernel_addr+area_used,VM_PROT_DEFAULT,FALSE))
		panic("cannot wire commpage");

	/* 
	 * Now that the object is created and wired into the kernel map, mark it so that no delay
	 * copy-on-write will ever be performed on it as a result of mapping it into user-space.
	 * If such a delayed copy ever occurred, we could remove the kernel's wired mapping - and
	 * that would be a real disaster.
	 *
	 * JMM - What we really need is a way to create it like this in the first place.
	 */
	if (!vm_map_lookup_entry( kernel_map, vm_map_trunc_page(kernel_addr), &entry) || entry->is_sub_map)
		panic("cannot find commpage entry");
	entry->object.vm_object->copy_strategy = MEMORY_OBJECT_COPY_NONE;

	if (mach_make_memory_entry( kernel_map,		// target map
				    &size,		// size 
				    kernel_addr,	// offset (address in kernel map)
				    VM_PROT_ALL,	// map it RWX
				    &handle,		// this is the object handle we get
				    NULL ))		// parent_entry (what is this?)
		panic("cannot make entry for commpage");

	if (vm_map_64(	submap,				// target map (shared submap)
			&zero,				// address (map into 1st page in submap)
			area_used,			// size
			0,				// mask
			VM_FLAGS_FIXED,			// flags (it must be 1st page in submap)
			handle,				// port is the memory entry we just made
			0,                              // offset (map 1st page in memory entry)
			FALSE,                          // copy
			VM_PROT_READ|VM_PROT_EXECUTE,   // cur_protection (R-only in user map)
			VM_PROT_READ|VM_PROT_EXECUTE,   // max_protection
			VM_INHERIT_SHARE ))             // inheritance
		panic("cannot map commpage");

	ipc_port_release(handle);
	
	// Initialize the text section of the commpage with INT3
	char *commpage_ptr = (char*)(intptr_t)kernel_addr;
	vm_size_t i;
	for( i = _COMM_PAGE_TEXT_START - _COMM_PAGE_START_ADDRESS; i < size; i++ )
		// This is the hex for the X86 opcode INT3
		commpage_ptr[i] = 0xCC;

	return (void*)(intptr_t)kernel_addr;                     // return address in kernel map
}

/* Get address (in kernel map) of a commpage field. */

static void*
commpage_addr_of(
    commpage_address_t     addr_at_runtime )
{
	return  (void*) ((uintptr_t)commPagePtr + (addr_at_runtime - commPageBaseOffset));
}

/* Determine number of CPUs on this system.  We cannot rely on
 * machine_info.max_cpus this early in the boot.
 */
static int
commpage_cpus( void )
{
	int cpus;

	cpus = ml_get_max_cpus();                   // NB: this call can block

	if (cpus == 0)
		panic("commpage cpus==0");
	if (cpus > 0xFF)
		cpus = 0xFF;

	return cpus;
}

/* Initialize kernel version of _cpu_capabilities vector (used by KEXTs.) */

static void
commpage_init_cpu_capabilities( void )
{
	uint32_t bits;
	int cpus;
	ml_cpu_info_t cpu_info;

	bits = 0;
	ml_cpu_get_info(&cpu_info);
	
	switch (cpu_info.vector_unit) {
		case 9:
			bits |= kHasAVX1_0;
			/* fall thru */
		case 8:
			bits |= kHasSSE4_2;
			/* fall thru */
		case 7:
			bits |= kHasSSE4_1;
			/* fall thru */
		case 6:
			bits |= kHasSupplementalSSE3;
			/* fall thru */
		case 5:
			bits |= kHasSSE3;
			/* fall thru */
		case 4:
			bits |= kHasSSE2;
			/* fall thru */
		case 3:
			bits |= kHasSSE;
			/* fall thru */
		case 2:
			bits |= kHasMMX;
		default:
			break;
	}
	switch (cpu_info.cache_line_size) {
		case 128:
			bits |= kCache128;
			break;
		case 64:
			bits |= kCache64;
			break;
		case 32:
			bits |= kCache32;
			break;
		default:
			break;
	}
	cpus = commpage_cpus();			// how many CPUs do we have

	if (cpus == 1)
		bits |= kUP;

	bits |= (cpus << kNumCPUsShift);

	bits |= kFastThreadLocalStorage;	// we use %gs for TLS

	if (cpu_mode_is64bit())			// k64Bit means processor is 64-bit capable
		bits |= k64Bit;

	if (tscFreq <= SLOW_TSC_THRESHOLD)	/* is TSC too slow for _commpage_nanotime?  */
		bits |= kSlow;

	bits |= (cpuid_features() & CPUID_FEATURE_AES) ? kHasAES : 0;

	bits |= (cpuid_features() & CPUID_FEATURE_F16C) ? kHasF16C : 0;
	bits |= (cpuid_features() & CPUID_FEATURE_RDRAND) ? kHasRDRAND : 0;
	bits |= ((cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_ENFSTRG) &&
		 (rdmsr64(MSR_IA32_MISC_ENABLE) & 1ULL )) ? kHasENFSTRG : 0;

	_cpu_capabilities = bits;		// set kernel version for use by drivers etc
}

int
_get_cpu_capabilities(void)
{
	return _cpu_capabilities;
}

/* Copy data into commpage. */

static void
commpage_stuff(
    commpage_address_t 	address,
    const void 	*source,
    int 	length	)
{    
    void	*dest = commpage_addr_of(address);
    
    if (address < next)
       panic("commpage overlap at address 0x%p, 0x%x < 0x%x", dest, address, next);
    
    bcopy(source,dest,length);
    
    next = address + length;
}

/* Copy a routine into comm page if it matches running machine.
 */
static void
commpage_stuff_routine(
    commpage_descriptor	*rd	)
{
    uint32_t		must,cant;
    
    if (rd->commpage_address != cur_routine) {
        if ((cur_routine!=0) && (matched==0))
            panic("commpage no match for last, next address %08x", rd->commpage_address);
        cur_routine = rd->commpage_address;
        matched = 0;
    }
    
    must = _cpu_capabilities & rd->musthave;
    cant = _cpu_capabilities & rd->canthave;
    
    if ((must == rd->musthave) && (cant == 0)) {
        if (matched)
            panic("commpage multiple matches for address %08x", rd->commpage_address);
        matched = 1;
        
        commpage_stuff(rd->commpage_address,rd->code_address,rd->code_length);
	}
}

/* Fill in the 32- or 64-bit commpage.  Called once for each.
 */

static void
commpage_populate_one( 
	vm_map_t	submap,		// commpage32_map or compage64_map
	char **		kernAddressPtr,	// &commPagePtr32 or &commPagePtr64
	size_t		area_used,	// _COMM_PAGE32_AREA_USED or _COMM_PAGE64_AREA_USED
	commpage_address_t base_offset,	// will become commPageBaseOffset
	commpage_descriptor** commpage_routines, // list of routine ptrs for this commpage
	commpage_time_data** time_data,	// &time_data32 or &time_data64
	const char*	signature )	// "commpage 32-bit" or "commpage 64-bit"
{
	uint8_t	c1;
   	short   c2;
	int	    c4;
	uint64_t c8;
	uint32_t	cfamily;
	commpage_descriptor **rd;
	short   version = _COMM_PAGE_THIS_VERSION;

	next = 0;
	cur_routine = 0;
	commPagePtr = (char *)commpage_allocate( submap, (vm_size_t) area_used );
	*kernAddressPtr = commPagePtr;				// save address either in commPagePtr32 or 64
	commPageBaseOffset = base_offset;

	*time_data = commpage_addr_of( _COMM_PAGE_TIME_DATA_START );

	/* Stuff in the constants.  We move things into the comm page in strictly
	* ascending order, so we can check for overlap and panic if so.
	*/
	commpage_stuff(_COMM_PAGE_SIGNATURE,signature,(int)strlen(signature));
	commpage_stuff(_COMM_PAGE_VERSION,&version,sizeof(short));
	commpage_stuff(_COMM_PAGE_CPU_CAPABILITIES,&_cpu_capabilities,sizeof(int));

	c2 = 32;  // default
	if (_cpu_capabilities & kCache64)
		c2 = 64;
	else if (_cpu_capabilities & kCache128)
		c2 = 128;
	commpage_stuff(_COMM_PAGE_CACHE_LINESIZE,&c2,2);
	
	c4 = MP_SPIN_TRIES;
	commpage_stuff(_COMM_PAGE_SPIN_COUNT,&c4,4);

	/* machine_info valid after ml_get_max_cpus() */
	c1 = machine_info.physical_cpu_max;
	commpage_stuff(_COMM_PAGE_PHYSICAL_CPUS,&c1,1);
	c1 = machine_info.logical_cpu_max;
	commpage_stuff(_COMM_PAGE_LOGICAL_CPUS,&c1,1);

	c8 = ml_cpu_cache_size(0);
	commpage_stuff(_COMM_PAGE_MEMORY_SIZE, &c8, 8);

	cfamily = cpuid_info()->cpuid_cpufamily;
	commpage_stuff(_COMM_PAGE_CPUFAMILY, &cfamily, 4);

	for( rd = commpage_routines; *rd != NULL ; rd++ )
		commpage_stuff_routine(*rd);

	if (!matched)
		panic("commpage no match on last routine");

	if (next > _COMM_PAGE_END)
		panic("commpage overflow: next = 0x%08x, commPagePtr = 0x%p", next, commPagePtr);

}


/* Fill in commpages: called once, during kernel initialization, from the
 * startup thread before user-mode code is running.
 *
 * See the top of this file for a list of what you have to do to add
 * a new routine to the commpage.
 */  

void
commpage_populate( void )
{
	commpage_init_cpu_capabilities();
	
	commpage_populate_one(	commpage32_map, 
				&commPagePtr32,
				_COMM_PAGE32_AREA_USED,
				_COMM_PAGE32_BASE_ADDRESS,
				commpage_32_routines, 
				&time_data32,
				"commpage 32-bit");
#ifndef __LP64__
	pmap_commpage32_init((vm_offset_t) commPagePtr32, _COMM_PAGE32_BASE_ADDRESS, 
			   _COMM_PAGE32_AREA_USED/INTEL_PGBYTES);
#endif			   
	time_data64 = time_data32;			/* if no 64-bit commpage, point to 32-bit */

	if (_cpu_capabilities & k64Bit) {
		commpage_populate_one(	commpage64_map, 
					&commPagePtr64,
					_COMM_PAGE64_AREA_USED,
					_COMM_PAGE32_START_ADDRESS, /* commpage address are relative to 32-bit commpage placement */
					commpage_64_routines, 
					&time_data64,
					"commpage 64-bit");
#ifndef __LP64__
		pmap_commpage64_init((vm_offset_t) commPagePtr64, _COMM_PAGE64_BASE_ADDRESS, 
				   _COMM_PAGE64_AREA_USED/INTEL_PGBYTES);
#endif
	}

	simple_lock_init(&commpage_active_cpus_lock, 0);

	commpage_update_active_cpus();
	rtc_nanotime_init_commpage();
}


/* Update commpage nanotime information.  Note that we interleave
 * setting the 32- and 64-bit commpages, in order to keep nanotime more
 * nearly in sync between the two environments.
 *
 * This routine must be serialized by some external means, ie a lock.
 */

void
commpage_set_nanotime(
	uint64_t	tsc_base,
	uint64_t	ns_base,
	uint32_t	scale,
	uint32_t	shift )
{
	commpage_time_data	*p32 = time_data32;
	commpage_time_data	*p64 = time_data64;
	static uint32_t	generation = 0;
	uint32_t	next_gen;
	
	if (p32 == NULL)		/* have commpages been allocated yet? */
		return;
		
	if ( generation != p32->nt_generation )
		panic("nanotime trouble 1");	/* possibly not serialized */
	if ( ns_base < p32->nt_ns_base )
		panic("nanotime trouble 2");
	if ((shift != 32) && ((_cpu_capabilities & kSlow)==0) )
		panic("nanotime trouble 3");
		
	next_gen = ++generation;
	if (next_gen == 0)
		next_gen = ++generation;
	
	p32->nt_generation = 0;		/* mark invalid, so commpage won't try to use it */
	p64->nt_generation = 0;
	
	p32->nt_tsc_base = tsc_base;
	p64->nt_tsc_base = tsc_base;
	
	p32->nt_ns_base = ns_base;
	p64->nt_ns_base = ns_base;
	
	p32->nt_scale = scale;
	p64->nt_scale = scale;
	
	p32->nt_shift = shift;
	p64->nt_shift = shift;
	
	p32->nt_generation = next_gen;	/* mark data as valid */
	p64->nt_generation = next_gen;
}


/* Disable commpage gettimeofday(), forcing commpage to call through to the kernel.  */

void
commpage_disable_timestamp( void )
{
	time_data32->gtod_generation = 0;
	time_data64->gtod_generation = 0;
}


/* Update commpage gettimeofday() information.  As with nanotime(), we interleave
 * updates to the 32- and 64-bit commpage, in order to keep time more nearly in sync 
 * between the two environments.
 *
 * This routine must be serializeed by some external means, ie a lock.
 */
 
 void
 commpage_set_timestamp(
	uint64_t	abstime,
	uint64_t	secs )
{
	commpage_time_data	*p32 = time_data32;
	commpage_time_data	*p64 = time_data64;
	static uint32_t	generation = 0;
	uint32_t	next_gen;
	
	next_gen = ++generation;
	if (next_gen == 0)
		next_gen = ++generation;
	
	p32->gtod_generation = 0;		/* mark invalid, so commpage won't try to use it */
	p64->gtod_generation = 0;
	
	p32->gtod_ns_base = abstime;
	p64->gtod_ns_base = abstime;
	
	p32->gtod_sec_base = secs;
	p64->gtod_sec_base = secs;
	
	p32->gtod_generation = next_gen;	/* mark data as valid */
	p64->gtod_generation = next_gen;
}


/* Update _COMM_PAGE_MEMORY_PRESSURE.  Called periodically from vm's compute_memory_pressure()  */

void
commpage_set_memory_pressure(
	unsigned int 	pressure )
{
	char	    *cp;
	uint32_t    *ip;
	
	cp = commPagePtr32;
	if ( cp ) {
		cp += (_COMM_PAGE_MEMORY_PRESSURE - _COMM_PAGE32_BASE_ADDRESS);
		ip = (uint32_t*) cp;
		*ip = (uint32_t) pressure;
	}
	
	cp = commPagePtr64;
	if ( cp ) {
		cp += (_COMM_PAGE_MEMORY_PRESSURE - _COMM_PAGE32_START_ADDRESS);
		ip = (uint32_t*) cp;
		*ip = (uint32_t) pressure;
	}

}


/* Update _COMM_PAGE_SPIN_COUNT.  We might want to reduce when running on a battery, etc. */

void
commpage_set_spin_count(
	unsigned int 	count )
{
	char	    *cp;
	uint32_t    *ip;
	
	if (count == 0)	    /* we test for 0 after decrement, not before */
	    count = 1;
	    
	cp = commPagePtr32;
	if ( cp ) {
		cp += (_COMM_PAGE_SPIN_COUNT - _COMM_PAGE32_BASE_ADDRESS);
		ip = (uint32_t*) cp;
		*ip = (uint32_t) count;
	}
	
	cp = commPagePtr64;
	if ( cp ) {
		cp += (_COMM_PAGE_SPIN_COUNT - _COMM_PAGE32_START_ADDRESS);
		ip = (uint32_t*) cp;
		*ip = (uint32_t) count;
	}

}

/* Updated every time a logical CPU goes offline/online */
void
commpage_update_active_cpus(void)
{
	char	    *cp;
	volatile uint8_t    *ip;
	
	/* At least 32-bit commpage must be initialized */
	if (!commPagePtr32)
		return;

	simple_lock(&commpage_active_cpus_lock);

	cp = commPagePtr32;
	cp += (_COMM_PAGE_ACTIVE_CPUS - _COMM_PAGE32_BASE_ADDRESS);
	ip = (volatile uint8_t*) cp;
	*ip = (uint8_t) processor_avail_count;
	
	cp = commPagePtr64;
	if ( cp ) {
		cp += (_COMM_PAGE_ACTIVE_CPUS - _COMM_PAGE32_START_ADDRESS);
		ip = (volatile uint8_t*) cp;
		*ip = (uint8_t) processor_avail_count;
	}

	simple_unlock(&commpage_active_cpus_lock);
}


/* Check to see if a given address is in the Preemption Free Zone (PFZ) */

uint32_t
commpage_is_in_pfz32(uint32_t addr32)
{
	if ( (addr32 >= _COMM_PAGE_PFZ_START) && (addr32 < _COMM_PAGE_PFZ_END)) {
		return 1;
	}
	else
		return 0;
}

uint32_t
commpage_is_in_pfz64(addr64_t addr64)
{
	if ( (addr64 >= _COMM_PAGE_32_TO_64(_COMM_PAGE_PFZ_START))
	     && (addr64 <  _COMM_PAGE_32_TO_64(_COMM_PAGE_PFZ_END))) {
		return 1;
	}
	else
		return 0;
}

