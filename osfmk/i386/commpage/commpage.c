/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 *	Here's what to do if you want to add a new routine to the comm page:
 *
 *		1. Add a definition for it's address in osfmk/ppc/cpu_capabilities.h,
 *		   being careful to reserve room for future expansion.
 *
 *		2. Write one or more versions of the routine, each with it's own
 *		   commpage_descriptor.  The tricky part is getting the "special",
 *		   "musthave", and "canthave" fields right, so that exactly one
 *		   version of the routine is selected for every machine.
 *		   The source files should be in osfmk/ppc/commpage/.
 *
 *		3. Add a ptr to your new commpage_descriptor(s) in the "routines"
 *		   array in commpage_populate().  Of course, you'll also have to
 *		   declare them "extern" in commpage_populate().
 *
 *		4. Write the code in Libc to use the new routine.
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <i386/machine_routines.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <mach/vm_map.h>

static  uintptr_t	next = 0;			// next available byte in comm page
static  int     	cur_routine = 0;	// comm page address of "current" routine
static  int     	matched;			// true if we've found a match for "current" routine

int     _cpu_capabilities = 0;          // define the capability vector

char    *commPagePtr = NULL;            // virtual address of comm page in kernel map

/* Allocate the commpage and add to the shared submap created by vm:
 * 	1. allocate a page in the kernel map (RW)
 *	2. wire it down
 *	3. make a memory entry out of it
 *	4. map that entry into the shared comm region map (R-only)
 */

static  void*
commpage_allocate( void )
{
    extern  vm_map_t    com_region_map;             // the shared submap, set up in vm init
    vm_offset_t         kernel_addr;                // address of commpage in kernel map
    vm_offset_t         zero = 0;
    vm_size_t           size = _COMM_PAGE_AREA_LENGTH;
    ipc_port_t          handle;

    if (com_region_map == NULL)
        panic("commpage map is null");

    if (vm_allocate(kernel_map,&kernel_addr,_COMM_PAGE_AREA_LENGTH,VM_FLAGS_ANYWHERE))
        panic("cannot allocate commpage");

    if (vm_map_wire(kernel_map,kernel_addr,kernel_addr+_COMM_PAGE_AREA_LENGTH,VM_PROT_DEFAULT,FALSE))
        panic("cannot wire commpage");

    if (mach_make_memory_entry( kernel_map,         // target map
                                &size,              // size 
                                kernel_addr,        // offset (address in kernel map)
                                VM_PROT_DEFAULT,    // map it RW
                                &handle,            // this is the object handle we get
                                NULL ))             // parent_entry (what is this?)
        panic("cannot make entry for commpage");

    if (vm_map_64(  com_region_map,                 // target map (shared submap)
                    &zero,                          // address (map into 1st page in submap)
                    _COMM_PAGE_AREA_LENGTH,         // size
                    0,                              // mask
                    VM_FLAGS_FIXED,                 // flags (it must be 1st page in submap)
                    handle,                         // port is the memory entry we just made
                    0,                              // offset (map 1st page in memory entry)
                    FALSE,                          // copy
                    VM_PROT_READ,                   // cur_protection (R-only in user map)
                    VM_PROT_READ,                   // max_protection
                    VM_INHERIT_SHARE ))             // inheritance
        panic("cannot map commpage");

    ipc_port_release(handle);

    return (void*) kernel_addr;                     // return address in kernel map
}

/* Get address (in kernel map) of a commpage field. */

static  void*
commpage_addr_of(
    int     addr_at_runtime )
{
    return  (void*) ((uintptr_t)commPagePtr + addr_at_runtime - _COMM_PAGE_BASE_ADDRESS);
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
	int bits;
	int cpus;
	ml_cpu_info_t cpu_info;

	bits = 0;
	ml_cpu_get_info(&cpu_info);
	
	switch (cpu_info.vector_unit) {
		case 5:
			bits |= kHasPNI;
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

	_cpu_capabilities = bits;		// set kernel version for use by drivers etc
}

/* Copy data into commpage. */

static void
commpage_stuff(
    int 	address,
    void 	*source,
    int 	length	)
{    
    void	*dest = commpage_addr_of(address);
    
    if ((uintptr_t)dest < next)
        panic("commpage overlap");
    
    bcopy(source,dest,length);
    
    next = ((uintptr_t)dest + length);
}

/* Copy a routine into comm page if it matches running machine.
 */
static void
commpage_stuff_routine(
    commpage_descriptor	*rd	)
{
    int		must,cant;
    
    if (rd->commpage_address != cur_routine) {
        if ((cur_routine!=0) && (matched==0))
            panic("commpage no match");
        cur_routine = rd->commpage_address;
        matched = 0;
    }
    
    must = _cpu_capabilities & rd->musthave;
    cant = _cpu_capabilities & rd->canthave;
    
    if ((must == rd->musthave) && (cant == 0)) {
        if (matched)
            panic("commpage duplicate matches");
        matched = 1;
        
        commpage_stuff(rd->commpage_address,rd->code_address,rd->code_length);
	}
}

/* Fill in commpage: called once, during kernel initialization, from the
 * startup thread before user-mode code is running.
 * See the top of this file for a list of what you have to do to add
 * a new routine to the commpage.
 */

void
commpage_populate( void )
{
	commpage_descriptor **rd;
	short   version = _COMM_PAGE_THIS_VERSION;
	void	*sig_addr;

	extern char commpage_sigs_begin[];
	extern char commpage_sigs_end[];
 
	extern commpage_descriptor commpage_mach_absolute_time;
	extern commpage_descriptor commpage_spin_lock_try_mp;
	extern commpage_descriptor commpage_spin_lock_try_up;
	extern commpage_descriptor commpage_spin_lock_mp;
	extern commpage_descriptor commpage_spin_lock_up;
	extern commpage_descriptor commpage_spin_unlock;
	extern commpage_descriptor commpage_pthread_getspecific;
	extern commpage_descriptor commpage_gettimeofday;
	extern commpage_descriptor commpage_sys_flush_dcache;
	extern commpage_descriptor commpage_sys_icache_invalidate;
	extern commpage_descriptor commpage_pthread_self;
	extern commpage_descriptor commpage_relinquish;
	extern commpage_descriptor commpage_bzero_scalar;
	extern commpage_descriptor commpage_bcopy_scalar;

	static  commpage_descriptor *routines[] = {
		&commpage_mach_absolute_time,
		&commpage_spin_lock_try_mp,
		&commpage_spin_lock_try_up,
		&commpage_spin_lock_mp,
		&commpage_spin_lock_up,
		&commpage_spin_unlock,
		&commpage_pthread_getspecific,
		&commpage_gettimeofday,
		&commpage_sys_flush_dcache,
		&commpage_sys_icache_invalidate,
		&commpage_pthread_self,
		&commpage_relinquish,
		&commpage_bzero_scalar,
		&commpage_bcopy_scalar,
		NULL
	};

	commPagePtr = (char *)commpage_allocate();

	commpage_init_cpu_capabilities();

	/* Stuff in the constants.  We move things into the comm page in strictly
	* ascending order, so we can check for overlap and panic if so.
	*/

	commpage_stuff(_COMM_PAGE_VERSION,&version,sizeof(short));
	commpage_stuff(_COMM_PAGE_CPU_CAPABILITIES,&_cpu_capabilities,
		sizeof(int));

	for( rd = routines; *rd != NULL ; rd++ )
		commpage_stuff_routine(*rd);

	if (!matched)
		panic("commpage no match on last routine");

	if (next > ((uintptr_t)commPagePtr + PAGE_SIZE))
		panic("commpage overflow");

#define STUFF_SIG(addr, func) \
	extern char commpage_sig_ ## func [];					\
	sig_addr = (void *)(	(uintptr_t)_COMM_PAGE_BASE_ADDRESS + 		\
				(uintptr_t)_COMM_PAGE_SIGS_OFFSET + 0x1000 +	\
				(uintptr_t)&commpage_sig_ ## func - 		\
				(uintptr_t)&commpage_sigs_begin	);		\
	commpage_stuff(addr + _COMM_PAGE_SIGS_OFFSET, &sig_addr, sizeof(void *));

	STUFF_SIG(_COMM_PAGE_ABSOLUTE_TIME, mach_absolute_time);
	STUFF_SIG(_COMM_PAGE_SPINLOCK_TRY, spin_lock_try);
	STUFF_SIG(_COMM_PAGE_SPINLOCK_LOCK, spin_lock);
	STUFF_SIG(_COMM_PAGE_SPINLOCK_UNLOCK, spin_unlock);
	STUFF_SIG(_COMM_PAGE_PTHREAD_GETSPECIFIC, pthread_getspecific);
	STUFF_SIG(_COMM_PAGE_GETTIMEOFDAY, gettimeofday);
	STUFF_SIG(_COMM_PAGE_FLUSH_DCACHE, sys_dcache_flush);
	STUFF_SIG(_COMM_PAGE_FLUSH_ICACHE, sys_icache_invalidate); 
	STUFF_SIG(_COMM_PAGE_PTHREAD_SELF, pthread_self);
	STUFF_SIG(_COMM_PAGE_BZERO, bzero);
	STUFF_SIG(_COMM_PAGE_BCOPY, bcopy);
	STUFF_SIG(_COMM_PAGE_MEMCPY, memmove);

	commpage_stuff(_COMM_PAGE_BASE_ADDRESS + _COMM_PAGE_SIGS_OFFSET + 0x1000, &commpage_sigs_begin,
			(uintptr_t)&commpage_sigs_end - (uintptr_t)&commpage_sigs_begin);	
}
