/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <ipc/ipc_port.h>

#include <kern/page_decrypt.h>

/* the lists of commpage routines are in commpage_asm.s  */
extern	commpage_descriptor*	commpage_32_routines[];
extern	commpage_descriptor*	commpage_64_routines[];

/* translated commpage descriptors from commpage_sigs.c  */
extern	commpage_descriptor sigdata_descriptor;
extern	commpage_descriptor *ba_descriptors[];

extern vm_map_t	com_region_map32;	// the shared submap, set up in vm init
extern vm_map_t	com_region_map64;	// the shared submap, set up in vm init

char	*commPagePtr32 = NULL;		// virtual addr in kernel map of 32-bit commpage
char	*commPagePtr64 = NULL;		// ...and of 64-bit commpage
int     _cpu_capabilities = 0;          // define the capability vector

int	noVMX = 0;		/* if true, do not set kHasAltivec in ppc _cpu_capabilities */

void*	dsmos_blobs[3];         /* ptrs to the system integrity data in each commpage */
int	dsmos_blob_count = 0;

static uintptr_t next;			// next available byte in comm page
static int     	cur_routine;		// comm page address of "current" routine
static int     	matched;		// true if we've found a match for "current" routine

static char    *commPagePtr;		// virtual addr in kernel map of commpage we are working on
static size_t	commPageBaseOffset;	// add to 32-bit runtime address to get offset in commpage

/* Allocate the commpage and add to the shared submap created by vm:
 * 	1. allocate a page in the kernel map (RW)
 *	2. wire it down
 *	3. make a memory entry out of it
 *	4. map that entry into the shared comm region map (R-only)
 */

static  void*
commpage_allocate( 
	vm_map_t	submap,			// com_region_map32 or com_region_map64
	size_t		area_used )		// _COMM_PAGE32_AREA_USED or _COMM_PAGE64_AREA_USED
{
	vm_offset_t	kernel_addr;		// address of commpage in kernel map
	vm_offset_t	zero = 0;
	vm_size_t	size = area_used;	// size actually populated
	vm_map_entry_t	entry;
	ipc_port_t	handle;

	if (submap == NULL)
		panic("commpage submap is null");

	if (vm_allocate(kernel_map,&kernel_addr,area_used,VM_FLAGS_ANYWHERE))
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
				    VM_PROT_DEFAULT,	// map it RW
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
    return  (void*) ((uintptr_t)commPagePtr + addr_at_runtime - commPageBaseOffset);
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

	_cpu_capabilities = bits;		// set kernel version for use by drivers etc
}

int
_get_cpu_capabilities()
{
	return _cpu_capabilities;
}

/* Copy data into commpage. */

static void
commpage_stuff(
    int 	address,
    const void 	*source,
    int 	length	)
{    
    void	*dest = commpage_addr_of(address);
    
    if ((uintptr_t)dest < next)
        panic("commpage overlap at address 0x%x, 0x%x < 0x%x", address, dest, next);
    
    bcopy(source,dest,length);
    
    next = ((uintptr_t)dest + length);
}

static void
commpage_stuff_swap(
	int	address,
	void	*source,
	int	length,
	int	legacy )
{
	if ( legacy ) {
		void *dest = commpage_addr_of(address);
		dest = (void *)((uintptr_t) dest + _COMM_PAGE_SIGS_OFFSET);
		switch (length) {
			case 2:
				OSWriteSwapInt16(dest, 0, *(uint16_t *)source);
				break;
			case 4:
				OSWriteSwapInt32(dest, 0, *(uint32_t *)source);
				break;
			case 8:
				OSWriteSwapInt64(dest, 0, *(uint64_t *)source);
				break;
		}
	}
}

static void
commpage_stuff2(
	int	address,
	void	*source,
	int	length,
	int	legacy )
{
	commpage_stuff_swap(address, source, length, legacy);
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
 * The 32-bit ("legacy") commpage has a bunch of stuff added to it
 * for translated processes, some of which is byte-swapped.
 */

static void
commpage_populate_one( 
	vm_map_t	submap,		// com_region_map32 or com_region_map64
	char **		kernAddressPtr,	// &commPagePtr32 or &commPagePtr64
	size_t		area_used,	// _COMM_PAGE32_AREA_USED or _COMM_PAGE64_AREA_USED
	size_t		base_offset,	// will become commPageBaseOffset
	commpage_descriptor** commpage_routines, // list of routine ptrs for this commpage
	boolean_t	legacy,		// true if 32-bit commpage
	const char*	signature )	// "commpage 32-bit" or "commpage 64-bit"
{
   	short   c2;
	static double   two52 = 1048576.0 * 1048576.0 * 4096.0; // 2**52
	static double   ten6 = 1000000.0;                       // 10**6
	commpage_descriptor **rd;
	short   version = _COMM_PAGE_THIS_VERSION;
	int		swapcaps;

	next = (uintptr_t) NULL;
	cur_routine = 0;
	commPagePtr = (char *)commpage_allocate( submap, (vm_size_t) area_used );
	*kernAddressPtr = commPagePtr;				// save address either in commPagePtr32 or 64
	commPageBaseOffset = base_offset;

	/* Stuff in the constants.  We move things into the comm page in strictly
	* ascending order, so we can check for overlap and panic if so.
	*/
	commpage_stuff(_COMM_PAGE_SIGNATURE,signature,strlen(signature));
	commpage_stuff2(_COMM_PAGE_VERSION,&version,sizeof(short),legacy);
	commpage_stuff(_COMM_PAGE_CPU_CAPABILITIES,&_cpu_capabilities,sizeof(int));

	/* excuse our magic constants, we cannot include ppc/cpu_capabilities.h */
	/* always set kCache32 and kDcbaAvailable */
	swapcaps =  0x44;
	if ( _cpu_capabilities & kUP )
		swapcaps |= (kUP + (1 << kNumCPUsShift));
	else
		swapcaps |= 2 << kNumCPUsShift;	/* limit #cpus to 2 */
	if ( ! noVMX )		/* if rosetta will be emulating altivec... */
		swapcaps |= 0x101;	/* ...then set kHasAltivec and kDataStreamsAvailable too */
	commpage_stuff_swap(_COMM_PAGE_CPU_CAPABILITIES, &swapcaps, sizeof(int), legacy);
	c2 = 32;
	commpage_stuff_swap(_COMM_PAGE_CACHE_LINESIZE,&c2,2,legacy);

	if (_cpu_capabilities & kCache32)
		c2 = 32;
	else if (_cpu_capabilities & kCache64)
		c2 = 64;
	else if (_cpu_capabilities & kCache128)
		c2 = 128;
	commpage_stuff(_COMM_PAGE_CACHE_LINESIZE,&c2,2);

	if ( legacy ) {
		commpage_stuff2(_COMM_PAGE_2_TO_52,&two52,8,legacy);
		commpage_stuff2(_COMM_PAGE_10_TO_6,&ten6,8,legacy);
	}

	for( rd = commpage_routines; *rd != NULL ; rd++ )
		commpage_stuff_routine(*rd);

	if (!matched)
		panic("commpage no match on last routine");

	if (next > (uintptr_t)_COMM_PAGE_END)
		panic("commpage overflow: next = 0x%08x, commPagePtr = 0x%08x", next, (uintptr_t)commPagePtr);

	if ( legacy ) {
		next = (uintptr_t) NULL;
		for( rd = ba_descriptors; *rd != NULL ; rd++ )
			commpage_stuff_routine(*rd);

		next = (uintptr_t) NULL;
		commpage_stuff_routine(&sigdata_descriptor);
	}	

	/* salt away a ptr to the system integrity data in this commpage */
	dsmos_blobs[dsmos_blob_count++] = 
		commpage_addr_of( _COMM_PAGE_SYSTEM_INTEGRITY );
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
	
	commpage_populate_one(	com_region_map32, 
				&commPagePtr32,
				_COMM_PAGE32_AREA_USED,
				_COMM_PAGE32_BASE_ADDRESS,
				commpage_32_routines, 
				TRUE,			/* legacy (32-bit) commpage */
				"commpage 32-bit");
	pmap_commpage32_init((vm_offset_t) commPagePtr32, _COMM_PAGE32_BASE_ADDRESS, 
			   _COMM_PAGE32_AREA_USED/INTEL_PGBYTES);

	if (_cpu_capabilities & k64Bit) {
		commpage_populate_one(	com_region_map64, 
					&commPagePtr64,
					_COMM_PAGE64_AREA_USED,
					_COMM_PAGE32_START_ADDRESS, /* because kernel is built 32-bit */
					commpage_64_routines, 
					FALSE,		/* not a legacy commpage */
					"commpage 64-bit");
		pmap_commpage64_init((vm_offset_t) commPagePtr64, _COMM_PAGE64_BASE_ADDRESS, 
				   _COMM_PAGE64_AREA_USED/INTEL_PGBYTES);
	}

	rtc_nanotime_init_commpage();
}
