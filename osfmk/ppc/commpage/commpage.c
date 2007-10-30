/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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
 *		   static array below.  Of course, you'll also have to declare them 
 *		   "extern".
 *
 *		4. Write the code in Libc to use the new routine.
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/vm_map.h>
#include <ppc/exception.h>
#include <ppc/machine_routines.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <ipc/ipc_port.h>

extern	vm_map_t	commpage32_map;   // the 32-bit shared submap, set up in vm init
extern  vm_map_t	commpage64_map;   // the 64-bit shared submap

char	*commPagePtr32 = NULL;			// virtual address of 32-bit comm page in kernel map
char	*commPagePtr64 = NULL;			// and 64-bit commpage
int		_cpu_capabilities = 0;			// define the capability vector

static	char	*next;					// next available byte in comm page
static	int		cur_routine;			// comm page address of "current" routine
static	int		matched;				// true if we've found a match for "current" routine
static  char	*commPagePtr;			// virtual address in kernel of commpage we are working on

extern	commpage_descriptor	compare_and_swap32_on32;
extern	commpage_descriptor	compare_and_swap32_on64;
extern	commpage_descriptor	compare_and_swap64;
extern	commpage_descriptor	atomic_enqueue32;
extern	commpage_descriptor	atomic_enqueue64;
extern	commpage_descriptor	atomic_dequeue32_on32;
extern	commpage_descriptor	atomic_dequeue32_on64;
extern	commpage_descriptor	atomic_dequeue64;
extern	commpage_descriptor	memory_barrier_up;
extern	commpage_descriptor	memory_barrier_mp32;
extern	commpage_descriptor	memory_barrier_mp64;
extern	commpage_descriptor	atomic_add32;
extern	commpage_descriptor	atomic_add64;
extern	commpage_descriptor	mach_absolute_time_32;
extern	commpage_descriptor	mach_absolute_time_64;
extern	commpage_descriptor	mach_absolute_time_lp64;
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
extern	commpage_descriptor	pthread_getspecific_sprg3_32;
extern	commpage_descriptor	pthread_getspecific_sprg3_64;
extern	commpage_descriptor	pthread_getspecific_uftrap;
extern	commpage_descriptor	gettimeofday_32;
extern	commpage_descriptor	gettimeofday_g5_32;
extern	commpage_descriptor	gettimeofday_g5_64;
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
extern	commpage_descriptor	compare_and_swap32_on32b;
extern	commpage_descriptor	compare_and_swap32_on64b;
extern	commpage_descriptor	compare_and_swap64b;
extern  commpage_descriptor memset_64;
extern  commpage_descriptor memset_g3;
extern  commpage_descriptor memset_g4;
extern  commpage_descriptor memset_g5;
extern	commpage_descriptor	bigcopy_970;

/* The list of all possible commpage routines.  WARNING: the check for overlap
 * assumes that these routines are in strictly ascending order, sorted by address
 * in the commpage.  We panic if not.
 */
static	commpage_descriptor	*routines[] = {
    &compare_and_swap32_on32,
    &compare_and_swap32_on64,
    &compare_and_swap64,
    &atomic_enqueue32,
    &atomic_enqueue64,
    &atomic_dequeue32_on32,
    &atomic_dequeue32_on64,
    &atomic_dequeue64,
    &memory_barrier_up,
    &memory_barrier_mp32,
    &memory_barrier_mp64,
    &atomic_add32,
    &atomic_add64,
    &mach_absolute_time_32,
    &mach_absolute_time_64,
    &mach_absolute_time_lp64,
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
    &pthread_getspecific_sprg3_32,
    &pthread_getspecific_sprg3_64,
    &pthread_getspecific_uftrap,
    &gettimeofday_32,
    &gettimeofday_g5_32,
    &gettimeofday_g5_64,
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
    &compare_and_swap32_on32b,
    &compare_and_swap32_on64b,
    &compare_and_swap64b,
    &memset_64,
    &memset_g3,
    &memset_g4,
    &memset_g5,
    &bigcopy_970,
    NULL };


/* Allocate the commpages and add to one of the shared submaps created by vm.
 * Called once each for the 32 and 64-bit submaps.
 * 	1. allocate pages in the kernel map (RW)
 *	2. wire them down
 *	3. make a memory entry out of them
 *	4. map that entry into the shared comm region map (R-only)
 */
static	void*
commpage_allocate( 
	vm_map_t			submap )					// commpage32_map or commpage64_map
{
    vm_offset_t			kernel_addr = 0;		// address of commpage in kernel map
    vm_offset_t			zero = 0;
    vm_size_t			size = _COMM_PAGE_AREA_USED;	// size actually populated
    vm_map_entry_t		entry;
    ipc_port_t			handle;
    
    if (submap == NULL)
        panic("commpage submap is null");
    
    if (vm_map(kernel_map,&kernel_addr,_COMM_PAGE_AREA_USED,0,VM_FLAGS_ANYWHERE,NULL,0,FALSE,VM_PROT_ALL,VM_PROT_ALL,VM_INHERIT_NONE))
        panic("cannot allocate commpage");
        
    if (vm_map_wire(kernel_map,kernel_addr,kernel_addr+_COMM_PAGE_AREA_USED,VM_PROT_DEFAULT,FALSE))
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
	
    if (mach_make_memory_entry(	kernel_map,			// target map
                                &size,				// size
                                kernel_addr,		// offset (address in kernel map)
                                VM_PROT_ALL,		// map it RWX
                                &handle,			// this is the object handle we get
                                NULL ))				// parent_entry
        panic("cannot make entry for commpage");
    
    if (vm_map_64(	submap,							// target map (shared submap)
                    &zero,							// address (map into 1st page in submap)
                    _COMM_PAGE_AREA_USED,			// size
                    0,								// mask
                    VM_FLAGS_FIXED,					// flags (it must be 1st page in submap)
                    handle,							// port is the memory entry we just made
                    0,								// offset (map 1st page in memory entry)
                    FALSE,							// copy
                    VM_PROT_READ|VM_PROT_EXECUTE,				// cur_protection (R-only in user map)
                    VM_PROT_READ|VM_PROT_EXECUTE,				// max_protection
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
    procFeatures	*pfp;
    int	cpus;
    int	available;

    pfp = &(PerProcTable[0].ppe_vaddr->pf);			// point to features in per-proc
    available = pfp->Available;

    // If AltiVec is disabled make sure it is not reported as available.
    if ((available & pfAltivec) == 0) {
        _cpu_capabilities &= ~kHasAltivec;
    }

    if (_cpu_capabilities & kDcbaAvailable) { 		// if this processor has DCBA, time it...
        _cpu_capabilities |= commpage_time_dcba();	// ...and set kDcbaRecomended if it helps.
    }

    cpus = commpage_cpus();                         // how many CPUs do we have
    if (cpus == 1) _cpu_capabilities |= kUP;
    _cpu_capabilities |= (cpus << kNumCPUsShift);

    if (_cpu_capabilities & k64Bit)                 // 64-bit processors use SPRG3 for TLS
        _cpu_capabilities |= kFastThreadLocalStorage;
}


/* Copy data into commpage. */

static void
commpage_stuff(
    int         address,
    const void 	*source,
    int         length	)
{    
    char	*dest = commpage_addr_of(address);
    
    if (dest < next)
        panic("commpage overlap: %p - %p", dest, next);
    
    bcopy((const char*)source,dest,length);
    
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

    while( (--words) >= 0 ) {
        word = *ptr;
        if ((word & search_mask)==search_pattern) {
            if ((check==NULL) || (check(word))) {	// check instruction if necessary
                word &= ~new_mask;
                word |= new_pattern;
                *ptr = word;
            }
        }
        ptr++;
    }
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


/* Check to see if a RLWINM (whose ME is 31) is a SRWI.  Since to shift right n bits
 * you must "RLWINM ra,rs,32-n,n,31", if (SH+MB)==32 then we have a SRWI.
 */
static int
commpage_srwi(
	uint32_t	rlwinm )
{
	int			sh = (rlwinm >> 11) & 0x1F;		// extract SH field of RLWINM, ie bits 16-20
	int			mb = (rlwinm >> 6 ) & 0x1F;		// extract MB field of RLWINM, ie bits 21-25
	
	return  (sh + mb) == 32;					// it is a SRWI if (SH+MB)==32
}


/* Handle kCommPageDCBA bit: the commpage routine uses DCBA.  If the machine we're
 * running on doesn't benefit from use of that instruction, map them to NOPs
 * in the commpage.
 */
static void
commpage_handle_dcbas(
    int 	address,
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;
    
    if ( (_cpu_capabilities & kDcbaRecommended) == 0 ) {
        ptr = commpage_addr_of(address);
        
        search_mask =	0xFC0007FE;		// search x-form opcode bits
        search =		0x7C0005EC;		// for a DCBA
        replace_mask = 	0xFFFFFFFF;		// replace all bits...
        replace =		0x60000000;		// ...with a NOP
    
        commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);
    }
}


/* Handle kCommPageSYNC bit: this routine uses SYNC, LWSYNC, or EIEIO.  If we're
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
        
        search_mask =	0xFC0005FE;		// search x-form opcode bits (but ignore bit 0x00000200)
        search =		0x7C0004AC;		// for a SYNC, LWSYNC, or EIEIO
        replace_mask = 	0xFFFFFFFF;		// replace all bits...
        replace =		0x60000000;		// ...with a NOP
    
        commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);
    }
}


/* Handle kCommPageISYNC bit: this routine uses ISYNCs.  If we're running on a UP machine,
 * map them to NOPs.
 */
static void
commpage_handle_isyncs(
    int 	address, 
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;
    
    if (_NumCPUs() == 1) {
        ptr = commpage_addr_of(address);
        
        search_mask =	0xFC0007FE;		// search xl-form opcode bits
        search =		0x4C00012C;		// for an ISYNC
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


/* Port 32-bit code to 64-bit for use in the 64-bit commpage.  This sounds fancier than
 * it is.  We do the following:
 *		- map "cmpw*" into "cmpd*"
 *		- map "srwi" into "srdi"
 * Perhaps surprisingly, this is enough to permit lots of code to run in 64-bit mode, as
 * long as it is written with this in mind.
 */
static void
commpage_port_32_to_64(
    int 	address, 
    int 	length	)
{
    uint32_t	*ptr, search_mask, search, replace_mask, replace;

	ptr = commpage_addr_of(address);
	
	search_mask =	0xFC2007FE;		// search x-form opcode bits (and L bit)
	search =		0x7C000000;		// for a CMPW
	replace_mask = 	0x00200000;		// replace bit 10 (L)...
	replace =		0x00200000;		// ...with a 1-bit, converting word to doubleword compares
	commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);

	search_mask =	0xFC2007FE;		// search x-form opcode bits (and L bit)
	search =		0x7C000040;		// for a CMPLW
	replace_mask = 	0x00200000;		// replace bit 10 (L)...
	replace =		0x00200000;		// ...with a 1-bit, converting word to doubleword compares
	commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);

	search_mask =	0xFC200000;		// search d-form opcode bits (and L bit)
	search =		0x28000000;		// for a CMPLWI
	replace_mask = 	0x00200000;		// replace bit 10 (L)...
	replace =		0x00200000;		// ...with a 1-bit, converting word to doubleword compares
	commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);

	search_mask =	0xFC200000;		// search d-form opcode bits (and L bit)
	search =		0x2C000000;		// for a CMPWI
	replace_mask = 	0x00200000;		// replace bit 10 (L)...
	replace =		0x00200000;		// ...with a 1-bit, converting word to doubleword compares
	commpage_change(ptr,length,search_mask,search,replace_mask,replace,NULL);
	
	search_mask =	0xFC00003E;		// search d-form opcode bits and ME (mask end) field
	search =		0x5400003E;		// for an RLWINM with ME=31 (which might be a "srwi")
	replace_mask = 	0xFC00003E;		// then replace RLWINM's opcode and ME field to make a RLDICL
	replace =		0x78000002;		// opcode is 30, ME is 0, except we add 32 to SH amount
	commpage_change(ptr,length,search_mask,search,replace_mask,replace,commpage_srwi);
} 


/* Copy a routine into comm page if it matches running machine.
 */
static void
commpage_stuff_routine(
    commpage_descriptor	*rd,
	int					mode )				// kCommPage32 or kCommPage64
{
    char	*routine_code;
    int		must,cant;
	
	if ( (rd->special & mode) == 0 )		// is this routine useable in this mode?
		return;
    
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
        routine_code = ((char*)rd) + rd->code_offset;
        
        commpage_stuff(rd->commpage_address,routine_code,rd->code_length);
        
        if (rd->special & kCommPageDCBA)
            commpage_handle_dcbas(rd->commpage_address,rd->code_length);
            
        if (rd->special & kCommPageSYNC)
            commpage_handle_syncs(rd->commpage_address,rd->code_length);
            
        if (rd->special & kCommPageISYNC)
            commpage_handle_isyncs(rd->commpage_address,rd->code_length);
            
        if (rd->special & kCommPageMTCRF)
            commpage_handle_mtcrfs(rd->commpage_address,rd->code_length);
			
		if ((mode == kCommPage64) && (rd->special & kPort32to64))
			commpage_port_32_to_64(rd->commpage_address,rd->code_length);
    }
}


/* Fill in the 32- or 64-bit commpage.  Called once for each.  */

static void
commpage_populate_one( 
	vm_map_t	submap,			// the map to populate
	char	**  kernAddressPtr,	// address within kernel of this commpage
	int			mode,           // either kCommPage32 or kCommPage64
    const char* signature )     // "commpage 32-bit" or "commpage 64-bit"
{
    char	c1;
    short	c2;
    addr64_t c8;
    static double	two52 = 1048576.0 * 1048576.0 * 4096.0;	// 2**52
    static double	ten6 = 1000000.0;						// 10**6
    static uint64_t magicFE = 0xFEFEFEFEFEFEFEFFLL;         // used to find 0s in strings
    static uint64_t magic80 = 0x8080808080808080LL;         // also used to find 0s
    commpage_descriptor	**rd;
    short	version = _COMM_PAGE_THIS_VERSION;
    
    next = NULL;								// initialize next available byte in the commpage
	cur_routine = 0;							// initialize comm page address of "current" routine
	
    commPagePtr = (char*) commpage_allocate( submap );
    *kernAddressPtr = commPagePtr;				// save address either in commPagePtr32 or 64

    /* Stuff in the constants.  We move things into the comm page in strictly
     * ascending order, so we can check for overlap and panic if so.
     */
    
    commpage_stuff(_COMM_PAGE_SIGNATURE,signature,strlen(signature));
    
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
    commpage_stuff(_COMM_PAGE_MAGIC_FE,&magicFE,8);
    commpage_stuff(_COMM_PAGE_MAGIC_80,&magic80,8);
    
    c8 = 0;													// 0 timestamp means "disabled"
    commpage_stuff(_COMM_PAGE_TIMEBASE,&c8,8);
    commpage_stuff(_COMM_PAGE_TIMESTAMP,&c8,8);
    commpage_stuff(_COMM_PAGE_SEC_PER_TICK,&c8,8);

    /* Now the routines.  We try each potential routine in turn,
     * and copy in any that "match" the platform we are running on.
     * We require that exactly one routine match for each slot in the
     * comm page, and panic if not.
     */
        
    for( rd = routines; *rd != NULL ; rd++ ) 
        commpage_stuff_routine(*rd,mode);
        
    if (!matched)
        panic("commpage no match on last routine");
    
    if (next > (commPagePtr + _COMM_PAGE_AREA_USED))
        panic("commpage overflow");
	
	
	// make all that new code executable
	
    sync_cache_virtual((vm_offset_t) commPagePtr,_COMM_PAGE_AREA_USED);
}


/* Fill in commpage: called once, during kernel initialization, from the
 * startup thread before user-mode code is running.
 *
 * See the top of this file for a list of what you have to do to add
 * a new routine to the commpage.
 */  

void
commpage_populate( void )
{
    commpage_init_cpu_capabilities();
	commpage_populate_one( commpage32_map, &commPagePtr32, kCommPage32, "commpage 32-bit");
	if (_cpu_capabilities & k64Bit) {
		commpage_populate_one( commpage64_map, &commPagePtr64, kCommPage64, "commpage 64-bit");
		pmap_init_sharedpage((vm_offset_t)commPagePtr64);			// Do the 64-bit version        
	}
        
}
