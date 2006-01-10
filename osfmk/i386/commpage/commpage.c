/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#include <mach/vm_map.h>
#include <i386/machine_routines.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <ipc/ipc_port.h>


extern vm_map_t	com_region_map32;	// the shared submap, set up in vm init

static uintptr_t next = 0;		// next available byte in comm page
static int     	cur_routine = 0;	// comm page address of "current" routine
static int     	matched;		// true if we've found a match for "current" routine

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
    vm_offset_t         kernel_addr;                // address of commpage in kernel map
    vm_offset_t         zero = 0;
    vm_size_t           size = _COMM_PAGE_AREA_LENGTH;
    vm_map_entry_t	entry;
    ipc_port_t          handle;

    if (com_region_map32 == NULL)
        panic("commpage map is null");

    if (vm_allocate(kernel_map,&kernel_addr,_COMM_PAGE_AREA_LENGTH,VM_FLAGS_ANYWHERE))
        panic("cannot allocate commpage");

    if (vm_map_wire(kernel_map,kernel_addr,kernel_addr+_COMM_PAGE_AREA_LENGTH,VM_PROT_DEFAULT,FALSE))
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

    if (mach_make_memory_entry( kernel_map,         // target map
                                &size,              // size 
                                kernel_addr,        // offset (address in kernel map)
                                VM_PROT_DEFAULT,    // map it RW
                                &handle,            // this is the object handle we get
                                NULL ))             // parent_entry (what is this?)
        panic("cannot make entry for commpage");

    if (vm_map_64(  com_region_map32,               // target map (shared submap)
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

static void*
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
        panic("commpage overlap at address 0x%x, 0x%x < 0x%x", address, dest, next);
    
    bcopy(source,dest,length);
    
    next = ((uintptr_t)dest + length);
}


static void
commpage_stuff2(
	int address,
	void *source,
	int length )
{
	commpage_stuff(address, source, length);
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

 
#define COMMPAGE_DESC(name)	commpage_ ## name
#define EXTERN_COMMPAGE_DESC(name)				\
	extern commpage_descriptor COMMPAGE_DESC(name)

EXTERN_COMMPAGE_DESC(compare_and_swap32_mp);
EXTERN_COMMPAGE_DESC(compare_and_swap32_up);
EXTERN_COMMPAGE_DESC(compare_and_swap64_mp);
EXTERN_COMMPAGE_DESC(compare_and_swap64_up);
EXTERN_COMMPAGE_DESC(atomic_add32_mp);
EXTERN_COMMPAGE_DESC(atomic_add32_up);
EXTERN_COMMPAGE_DESC(mach_absolute_time);
EXTERN_COMMPAGE_DESC(spin_lock_try_mp);
EXTERN_COMMPAGE_DESC(spin_lock_try_up);
EXTERN_COMMPAGE_DESC(spin_lock_mp);
EXTERN_COMMPAGE_DESC(spin_lock_up);
EXTERN_COMMPAGE_DESC(spin_unlock);
EXTERN_COMMPAGE_DESC(pthread_getspecific);
EXTERN_COMMPAGE_DESC(gettimeofday);
EXTERN_COMMPAGE_DESC(sys_flush_dcache);
EXTERN_COMMPAGE_DESC(sys_icache_invalidate);
EXTERN_COMMPAGE_DESC(pthread_self);
EXTERN_COMMPAGE_DESC(relinquish);
EXTERN_COMMPAGE_DESC(bit_test_and_set_mp);
EXTERN_COMMPAGE_DESC(bit_test_and_set_up);
EXTERN_COMMPAGE_DESC(bit_test_and_clear_mp);
EXTERN_COMMPAGE_DESC(bit_test_and_clear_up);
EXTERN_COMMPAGE_DESC(bzero_scalar);
EXTERN_COMMPAGE_DESC(bcopy_scalar);
EXTERN_COMMPAGE_DESC(nanotime);

static  commpage_descriptor *routines[] = {
	&COMMPAGE_DESC(compare_and_swap32_mp),
	&COMMPAGE_DESC(compare_and_swap32_up),
	&COMMPAGE_DESC(compare_and_swap64_mp),
	&COMMPAGE_DESC(compare_and_swap64_up),
	&COMMPAGE_DESC(atomic_add32_mp),
	&COMMPAGE_DESC(atomic_add32_up),
	&COMMPAGE_DESC(mach_absolute_time),
	&COMMPAGE_DESC(spin_lock_try_mp),
	&COMMPAGE_DESC(spin_lock_try_up),
	&COMMPAGE_DESC(spin_lock_mp),
	&COMMPAGE_DESC(spin_lock_up),
	&COMMPAGE_DESC(spin_unlock),
	&COMMPAGE_DESC(pthread_getspecific),
	&COMMPAGE_DESC(gettimeofday),
	&COMMPAGE_DESC(sys_flush_dcache),
	&COMMPAGE_DESC(sys_icache_invalidate),
	&COMMPAGE_DESC(pthread_self),
	&COMMPAGE_DESC(relinquish),
	&COMMPAGE_DESC(bit_test_and_set_mp),
	&COMMPAGE_DESC(bit_test_and_set_up),
	&COMMPAGE_DESC(bit_test_and_clear_mp),
	&COMMPAGE_DESC(bit_test_and_clear_up),
	&COMMPAGE_DESC(bzero_scalar),
	&COMMPAGE_DESC(bcopy_scalar),
	&COMMPAGE_DESC(nanotime),
	NULL
};


/* Fill in commpage: called once, during kernel initialization, from the
 * startup thread before user-mode code is running.
 * See the top of this file for a list of what you have to do to add
 * a new routine to the commpage.
 */

void
commpage_populate( void )
{
   	short   c2;
	static double   two52 = 1048576.0 * 1048576.0 * 4096.0; // 2**52
	static double   ten6 = 1000000.0;                       // 10**6
	commpage_descriptor **rd;
	short   version = _COMM_PAGE_THIS_VERSION;

	commPagePtr = (char *)commpage_allocate();

	commpage_init_cpu_capabilities();

	/* Stuff in the constants.  We move things into the comm page in strictly
	* ascending order, so we can check for overlap and panic if so.
	*/

	commpage_stuff2(_COMM_PAGE_VERSION,&version,sizeof(short));
	commpage_stuff(_COMM_PAGE_CPU_CAPABILITIES,&_cpu_capabilities,
		sizeof(int));

	if (_cpu_capabilities & kCache32)
		c2 = 32;
	else if (_cpu_capabilities & kCache64)
		c2 = 64;
	else if (_cpu_capabilities & kCache128)
		c2 = 128;
	commpage_stuff(_COMM_PAGE_CACHE_LINESIZE,&c2,2);

	c2 = 32;

	commpage_stuff2(_COMM_PAGE_2_TO_52,&two52,8);

	commpage_stuff2(_COMM_PAGE_10_TO_6,&ten6,8);

	for( rd = routines; *rd != NULL ; rd++ )
		commpage_stuff_routine(*rd);

	if (!matched)
		panic("commpage no match on last routine");

	if (next > (uintptr_t)_COMM_PAGE_END)
		panic("commpage overflow: next = 0x%08x, commPagePtr = 0x%08x", next, (uintptr_t)commPagePtr);


	pmap_commpage_init((vm_offset_t) commPagePtr, _COMM_PAGE_BASE_ADDRESS, 
			   _COMM_PAGE_AREA_LENGTH/INTEL_PGBYTES);
}

/*
 * This macro prevents compiler instruction scheduling:
 */
#define NO_REORDERING	asm volatile("" : : : "memory")

void
commpage_set_nanotime(commpage_nanotime_t *newp)
{
	commpage_nanotime_t	*cnp;

	/* Nop if commpage not set up yet */
	if (commPagePtr == NULL)
		return;

	cnp = (commpage_nanotime_t *)commpage_addr_of(_COMM_PAGE_NANOTIME_INFO);

	/*
	 * Update in reverse order:
	 * check_tsc first - it's read and compared with base_tsc last.
	 */
	cnp->nt_check_tsc = newp->nt_base_tsc;	NO_REORDERING;
	cnp->nt_shift     = newp->nt_shift;	NO_REORDERING;
	cnp->nt_scale     = newp->nt_scale;	NO_REORDERING;
	cnp->nt_base_ns   = newp->nt_base_ns;	NO_REORDERING;
	cnp->nt_base_tsc  = newp->nt_base_tsc;
}

