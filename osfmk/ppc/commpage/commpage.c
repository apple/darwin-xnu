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
#include <ppc/exception.h>
#include <ppc/machine_routines.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <mach/vm_map.h>

static	char	*next = NULL;			// next available byte in comm page
static	int		cur_routine = 0;		// comm page address of "current" routine
static	int		matched;				// true if we've found a match for "current" routine

int		_cpu_capabilities = 0;			// define the capability vector

char	*commPagePtr = NULL;			// virtual address of comm page in kernel map


/* Allocate the commpages and add to the shared submap created by vm:
 * 	1. allocate pages in the kernel map (RW)
 *	2. wire them down
 *	3. make a memory entry out of them
 *	4. map that entry into the shared comm region map (R-only)
 */
static	void*
commpage_allocate( void )
{
    extern	vm_map_t	com_region_map;				// the shared submap, set up in vm init
    vm_offset_t			kernel_addr;				// address of commpage in kernel map
    vm_offset_t			zero = 0;
    vm_size_t			size = _COMM_PAGE_AREA_USED;	// size actually populated
    ipc_port_t			handle;
    
    if (com_region_map == NULL)
        panic("commpage map is null");
    
    if (vm_allocate(kernel_map,&kernel_addr,_COMM_PAGE_AREA_USED,VM_FLAGS_ANYWHERE))
        panic("cannot allocate commpage");
        
    if (vm_map_wire(kernel_map,kernel_addr,kernel_addr+_COMM_PAGE_AREA_USED,VM_PROT_DEFAULT,FALSE))
        panic("cannot wire commpage");
    
    if (mach_make_memory_entry(	kernel_map,			// target map
                                &size,				// size
                                kernel_addr,		// offset (address in kernel map)
                                VM_PROT_DEFAULT,	// map it RW
                                &handle,			// this is the object handle we get
                                NULL ))				// parent_entry
        panic("cannot make entry for commpage");
    
    if (vm_map_64(	com_region_map,					// target map (shared submap)
                    &zero,							// address (map into 1st page in submap)
                    _COMM_PAGE_AREA_USED,			// size
                    0,								// mask
                    VM_FLAGS_FIXED,					// flags (it must be 1st page in submap)
                    handle,							// port is the memory entry we just made
                    0,								// offset (map 1st page in memory entry)
                    FALSE,							// copy
                    VM_PROT_READ,					// cur_protection (R-only in user map)
                    VM_PROT_READ,					// max_protection
                    VM_INHERIT_SHARE ))				// inheritance
        panic("cannot map commpage");
        
    ipc_port_release(handle);
        
    return (void*) kernel_addr;						// return address in kernel map
}


/* Get address (in kernel map) of a commpage field. */

static	void*
commpage_addr_of(
    int 	addr_at_runtime	)
{
    return	(void*) (commPagePtr + addr_at_runtime - _COMM_PAGE_BASE_ADDRESS);
}


/* Determine number of CPUs on this system.  We cannot rely on
 * machine_info.max_cpus this early in the boot.
 */
static int
commpage_cpus( void )
{
    int		cpus;
    
    cpus = ml_get_max_cpus();			// NB: this call can block
    
    if (cpus == 0)
        panic("commpage cpus==0");
    if (cpus > 0xFF)
        cpus = 0xFF;
    
    return	cpus;
}


/* Initialize kernel version of _cpu_capabilities vector (used by KEXTs.) */

static void
commpage_init_cpu_capabilities( void )
{
    struct per_proc_info *pp;
    procFeatures	*pfp;
    int	cpus;
    int	available;

    pp = per_proc_info;					// use CPU 0's per-proc
    pfp = &pp->pf;						// point to features in per-proc
    available = pfp->Available;

    // If AltiVec is disabled make sure it is not reported as available.
    if ((available & pfAltivec) == 0) {
        _cpu_capabilities &= ~kHasAltivec;
    }

    if (_cpu_capabilities & kDcbaAvailable) { 		// if this processor has DCBA, time it...
        _cpu_capabilities |= commpage_time_dcba();	// ...and set kDcbaRecomended if it helps.
    }

    cpus = commpage_cpus();				// how many CPUs do we have
    if (cpus == 1) _cpu_capabilities |= kUP;
    _cpu_capabilities |= (cpus << kNumCPUsShift);
}


/* Copy data into commpage. */

 void
commpage_stuff(
    int 	address,
    void 	*source,
    int 	length	)
{    
    char	*dest = commpage_addr_of(address);
    
    if (dest < next)
        panic("commpage overlap: %08 - %08X", dest, next);
    
    bcopy((char*)source,dest,length);
    
    next = (dest + length);
}


/* Modify commpage code in-place for this specific platform. */

static void
commpage_change(
    uint32_t 	*ptr,
    int 		bytes,
    uint32_t 	search_mask, 
    uint32_t 	search_pattern,
    uint32_t 	new_mask,
    uint32_t 	new_pattern,
    int			(*check)(uint32_t instruction)	)
{
    int			words = bytes >> 2;
    uint32_t	word;
    int			found_one = 0;

    while( (--words) >= 0 ) {
        word = *ptr;
        if ((word & search_mask)==search_pattern) {
            if ((check==NULL) || (check(word))) {	// check instruction if necessary
                found_one = 1;
                word &= ~new_mask;
                word |= new_pattern;
                *ptr = word;
            }
        }
        ptr++;
    }
    
    if (!found_one)
        panic("commpage opcode not found");
}


/* Check to see if exactly one bit is set in a MTCRF instruction's FXM field.
 */
static int
commpage_onebit(
    uint32_t	mtcrf )
{
    int x = (mtcrf >> 12) & 0xFF;		// isolate the FXM field of the MTCRF
    
    if (x==0)
        panic("commpage bad mtcrf");
        
    return	(x & (x-1))==0 ? 1 : 0;		// return 1 iff exactly 1 bit set in FXM field
}


/* Handle kCommPageDCBA bit: this routine uses DCBA.  If the machine we're
 * running on doesn't benefit from use of that instruction, map them to NOPs
 * in the commpage.
 */
static void
commpage_handle_dcbas(
    int 	address,
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;
    
    if ((_cpu_capabilities & kDcbaAvailable) == 0) {
        ptr = commpage_addr_of(address);
        
        search_mask =	0xFC0007FE;		// search x-form opcode bits
        search =		0x7C0005EC;		// for a DCBA
        replace_mask = 	0xFFFFFFFF;		// replace all bits...
        replace =		0x60000000;		// ...with a NOP
    
        commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);
    }
}


/* Handle kCommPageSYNC bit: this routine uses SYNC or LWSYNC.  If we're
 * running on a UP machine, map them to NOPs.
 */
static void
commpage_handle_syncs(
    int 	address, 
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;
    
    if (_NumCPUs() == 1) {
        ptr = commpage_addr_of(address);
        
        search_mask =	0xFC0007FE;		// search x-form opcode bits
        search =		0x7C0004AC;		// for a SYNC or LWSYNC
        replace_mask = 	0xFFFFFFFF;		// replace all bits...
        replace =		0x60000000;		// ...with a NOP
    
        commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);
    }
}


/* Handle kCommPageMTCRF bit.  When this was written (3/03), the assembler did not
 * recognize the special form of MTCRF instructions, in which exactly one bit is set
 * in the 8-bit mask field.  Bit 11 of the instruction should be set in this case,
 * since the 970 and probably other 64-bit processors optimize it.  Once the assembler
 * has been updated this code can be removed, though it need not be.
 */
static void
commpage_handle_mtcrfs(
    int 	address, 
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;
    
    if (_cpu_capabilities & k64Bit) {
        ptr = commpage_addr_of(address);
        
        search_mask =	0xFC0007FE;		// search x-form opcode bits
        search =		0x7C000120;		// for a MTCRF
        replace_mask = 	0x00100000;		// replace bit 11...
        replace =		0x00100000;		// ...with a 1-bit
    
        commpage_change(ptr,length,search_mask,search,replace_mask,replace,commpage_onebit);
    }
}


/* Copy a routine into comm page if it matches running machine.
 */
static void
commpage_stuff_routine(
    commpage_descriptor	*rd	)
{
    char	*routine_code;
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
        routine_code = ((char*)rd) + rd->code_offset;
        
        commpage_stuff(rd->commpage_address,routine_code,rd->code_length);
        
        if (rd->special & kCommPageDCBA)
            commpage_handle_dcbas(rd->commpage_address,rd->code_length);
            
        if (rd->special & kCommPageSYNC)
            commpage_handle_syncs(rd->commpage_address,rd->code_length);
            
        if (rd->special & kCommPageMTCRF)
            commpage_handle_mtcrfs(rd->commpage_address,rd->code_length);
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
    char	c1;
    short	c2;
    addr64_t c8;
    static double	two52 = 1048576.0 * 1048576.0 * 4096.0;	// 2**52
    static double	ten6 = 1000000.0;						// 10**6
    commpage_descriptor	**rd;
    short	version = _COMM_PAGE_THIS_VERSION;
    
    
    commPagePtr = (char*) commpage_allocate();
    
    commpage_init_cpu_capabilities();


    /* Stuff in the constants.  We move things into the comm page in strictly
     * ascending order, so we can check for overlap and panic if so.
     */
     
    commpage_stuff(_COMM_PAGE_VERSION,&version,2);

    commpage_stuff(_COMM_PAGE_CPU_CAPABILITIES,&_cpu_capabilities,sizeof(int));
    
    c1 = (_cpu_capabilities & kHasAltivec) ? -1 : 0;
    commpage_stuff(_COMM_PAGE_ALTIVEC,&c1,1);
    
    c1 = (_cpu_capabilities & k64Bit) ? -1 : 0;
    commpage_stuff(_COMM_PAGE_64_BIT,&c1,1);
    
    if (_cpu_capabilities & kCache32)
        c2 = 32;
    else if (_cpu_capabilities & kCache64)
        c2 = 64;
    else if (_cpu_capabilities & kCache128)
        c2 = 128;
    commpage_stuff(_COMM_PAGE_CACHE_LINESIZE,&c2,2);
    
    commpage_stuff(_COMM_PAGE_2_TO_52,&two52,8);
    
    commpage_stuff(_COMM_PAGE_10_TO_6,&ten6,8);
    
    c8 = 0;													// 0 timestamp means "disabled"
    commpage_stuff(_COMM_PAGE_TIMEBASE,&c8,8);
    commpage_stuff(_COMM_PAGE_TIMESTAMP,&c8,8);
    commpage_stuff(_COMM_PAGE_SEC_PER_TICK,&c8,8);


    /* Now the routines.  We try each potential routine in turn,
     * and copy in any that "match" the platform we are running on.
     * We require that exactly one routine match for each slot in the
     * comm page, and panic if not.
     *
     * The check for overlap assumes that these routines are
     * in strictly ascending order, sorted by address in the
     * comm page.
     */

    extern	commpage_descriptor	mach_absolute_time_32;
    extern	commpage_descriptor	mach_absolute_time_64;
    extern	commpage_descriptor	spinlock_32_try_mp;
    extern	commpage_descriptor	spinlock_32_try_up;
    extern	commpage_descriptor	spinlock_64_try_mp;
    extern	commpage_descriptor	spinlock_64_try_up;
    extern	commpage_descriptor	spinlock_32_lock_mp;
    extern	commpage_descriptor	spinlock_32_lock_up;
    extern	commpage_descriptor	spinlock_64_lock_mp;
    extern	commpage_descriptor	spinlock_64_lock_up;
    extern	commpage_descriptor	spinlock_32_unlock_mp;
    extern	commpage_descriptor	spinlock_32_unlock_up;
    extern	commpage_descriptor	spinlock_64_unlock_mp;
    extern	commpage_descriptor	spinlock_64_unlock_up;
    extern	commpage_descriptor	pthread_getspecific_sprg3;
    extern	commpage_descriptor	pthread_getspecific_uftrap;
    extern	commpage_descriptor	gettimeofday_32;
    extern	commpage_descriptor	gettimeofday_64;
    extern	commpage_descriptor	commpage_flush_dcache;
    extern	commpage_descriptor	commpage_flush_icache;
    extern	commpage_descriptor	pthread_self_sprg3;
    extern	commpage_descriptor	pthread_self_uftrap;
    extern	commpage_descriptor	spinlock_relinquish;
    extern	commpage_descriptor	bzero_32;
    extern	commpage_descriptor	bzero_128;
    extern	commpage_descriptor	bcopy_g3;
    extern	commpage_descriptor	bcopy_g4;
    extern	commpage_descriptor	bcopy_970;
    extern	commpage_descriptor	bcopy_64;
    extern	commpage_descriptor	bigcopy_970;
    
    static	commpage_descriptor	*routines[] = {
        &mach_absolute_time_32,
        &mach_absolute_time_64,
        &spinlock_32_try_mp,
        &spinlock_32_try_up,
        &spinlock_64_try_mp,
        &spinlock_64_try_up,
        &spinlock_32_lock_mp,
        &spinlock_32_lock_up,
        &spinlock_64_lock_mp,
        &spinlock_64_lock_up,
        &spinlock_32_unlock_mp,
        &spinlock_32_unlock_up,
        &spinlock_64_unlock_mp,
        &spinlock_64_unlock_up,
        &pthread_getspecific_sprg3,
        &pthread_getspecific_uftrap,
        &gettimeofday_32,
        &gettimeofday_64,
        &commpage_flush_dcache,
        &commpage_flush_icache,
        &pthread_self_sprg3,
        &pthread_self_uftrap,
        &spinlock_relinquish,
        &bzero_32,
        &bzero_128,
        &bcopy_g3,
        &bcopy_g4,
        &bcopy_970,
        &bcopy_64,
        &bigcopy_970,
        NULL };
        
    for( rd = routines; *rd != NULL ; rd++ ) 
        commpage_stuff_routine(*rd);
        
    if (!matched)
        panic("commpage no match on last routine");
    
    if (next > (commPagePtr + _COMM_PAGE_AREA_USED))
        panic("commpage overflow");
        
    sync_cache_virtual((vm_offset_t) commPagePtr,_COMM_PAGE_AREA_USED);	// make all that new code executable

}

