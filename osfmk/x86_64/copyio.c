/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <mach_assert.h>

#include <sys/errno.h>
#include <i386/param.h>
#include <i386/misc_protos.h>
#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/cpuid.h>
#include <i386/vmx.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <sys/kdebug.h>

static int copyio(int, user_addr_t, char *, vm_size_t, vm_size_t *, int);
static int copyio_phys(addr64_t, addr64_t, vm_size_t, int);

/*
 * The copy engine has the following characteristics
 *   - copyio() handles copies to/from user or kernel space
 *   - copypv() deals with physical or virtual addresses
 *
 * Readers familiar with the 32-bit kernel will expect Joe's thesis at this
 * point describing the full glory of the copy window implementation. In K64,
 * however, there is no need for windowing. Thanks to the vast shared address
 * space, the kernel has direct access to userspace and to physical memory.
 *
 * User virtual addresses are accessible provided the user's cr3 is loaded.
 * Physical addresses are accessible via the direct map and the PHYSMAP_PTOV()
 * translation.
 *
 * Copyin/out variants all boil done to just these 2 routines in locore.s which
 * provide fault-recoverable copying:
 */
extern int _bcopy(const void *, void *, vm_size_t);
extern int _bcopystr(const void *, void *, vm_size_t, vm_size_t *);


/*
 * Types of copies:
 */
#define COPYIN		0	/* from user virtual to kernel virtual */
#define COPYOUT		1	/* from kernel virtual to user virtual */
#define COPYINSTR	2	/* string variant of copyout */
#define COPYINPHYS	3	/* from user virtual to kernel physical */
#define COPYOUTPHYS	4	/* from kernel physical to user virtual */


static int
copyio(int copy_type, user_addr_t user_addr, char *kernel_addr,
       vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
        thread_t	thread;
	pmap_t		pmap;
	vm_size_t	bytes_copied;
	int		error = 0;
	boolean_t	istate = FALSE;
	boolean_t	recursive_CopyIOActive;
#if KDEBUG
	int		debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif

	thread = current_thread();

	KERNEL_DEBUG(debug_type | DBG_FUNC_START,
		     (unsigned)(user_addr >> 32), (unsigned)user_addr,
		     nbytes, thread->machine.copyio_state, 0);

	if (nbytes == 0)
		goto out;

        pmap = thread->map->pmap;

	if ((copy_type != COPYINPHYS) && (copy_type != COPYOUTPHYS) && ((vm_offset_t)kernel_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS)) {
		panic("Invalid copy parameter, copy type: %d, kernel address: %p", copy_type, kernel_addr);
	}

	/* Sanity and security check for addresses to/from a user */

	if (((pmap != kernel_pmap) && (use_kernel_map == 0)) &&
	    ((nbytes && (user_addr+nbytes <= user_addr)) || ((user_addr + nbytes) > vm_map_max(thread->map)))) {
		error = EFAULT;
		goto out;
	}

	/*
	 * If the no_shared_cr3 boot-arg is set (true), the kernel runs on 
	 * its own pmap and cr3 rather than the user's -- so that wild accesses
	 * from kernel or kexts can be trapped. So, during copyin and copyout,
	 * we need to switch back to the user's map/cr3. The thread is flagged
	 * "CopyIOActive" at this time so that if the thread is pre-empted,
	 * we will later restore the correct cr3.
	 */
	recursive_CopyIOActive = thread->machine.specFlags & CopyIOActive;
	thread->machine.specFlags |= CopyIOActive;
	if (no_shared_cr3) {
		istate = ml_set_interrupts_enabled(FALSE);
 		if (get_cr3_base() != pmap->pm_cr3)
			set_cr3_raw(pmap->pm_cr3);
	}

	/*
	 * Ensure that we're running on the target thread's cr3.
	 */
	if ((pmap != kernel_pmap) && !use_kernel_map &&
	    (get_cr3_base() != pmap->pm_cr3)) {
		panic("copyio(%d,%p,%p,%ld,%p,%d) cr3 is %p expects %p",
			copy_type, (void *)user_addr, kernel_addr, nbytes, lencopied, use_kernel_map,
			(void *) get_cr3_raw(), (void *) pmap->pm_cr3);
	}
	if (no_shared_cr3)
		(void) ml_set_interrupts_enabled(istate);

	KERNEL_DEBUG(0xeff70044 | DBG_FUNC_NONE, (unsigned)user_addr,
		     (unsigned)kernel_addr, nbytes, 0, 0);

        switch (copy_type) {

	case COPYIN:
	        error = _bcopy((const void *) user_addr,
				kernel_addr,
				nbytes);
		break;
			
	case COPYOUT:
	        error = _bcopy(kernel_addr,
				(void *) user_addr,
				nbytes);
		break;

	case COPYINPHYS:
	        error = _bcopy((const void *) user_addr,
				PHYSMAP_PTOV(kernel_addr),
				nbytes);
		break;

	case COPYOUTPHYS:
	        error = _bcopy((const void *) PHYSMAP_PTOV(kernel_addr),
				(void *) user_addr,
				nbytes);
		break;

	case COPYINSTR:
	        error = _bcopystr((const void *) user_addr,
				kernel_addr,
				(int) nbytes,
				&bytes_copied);

		/*
		 * lencopied should be updated on success
		 * or ENAMETOOLONG...  but not EFAULT
		 */
		if (error != EFAULT)
		        *lencopied = bytes_copied;

		if (error) {
#if KDEBUG
		        nbytes = *lencopied;
#endif
		        break;
		}
		if (*(kernel_addr + bytes_copied - 1) == 0) {
		        /*
			 * we found a NULL terminator... we're done
			 */
#if KDEBUG
		        nbytes = *lencopied;
#endif
			break;
		} else {
		        /*
			 * no more room in the buffer and we haven't
			 * yet come across a NULL terminator
			 */
#if KDEBUG
		        nbytes = *lencopied;
#endif
		        error = ENAMETOOLONG;
			break;
		}
		break;
	}

	if (!recursive_CopyIOActive) {
		thread->machine.specFlags &= ~CopyIOActive;
	}
	if (no_shared_cr3) {
		istate = ml_set_interrupts_enabled(FALSE);
		if  (get_cr3_raw() != kernel_pmap->pm_cr3)
			set_cr3_raw(kernel_pmap->pm_cr3);
		(void) ml_set_interrupts_enabled(istate);
	}

out:
	KERNEL_DEBUG(debug_type | DBG_FUNC_END, (unsigned)user_addr,
		     (unsigned)kernel_addr, (unsigned)nbytes, error, 0);

	return (error);
}


static int
copyio_phys(addr64_t source, addr64_t sink, vm_size_t csize, int which)
{
        char	    *paddr;
	user_addr_t vaddr;
	int         ctype;

	if (which & cppvPsnk) {
		paddr  = (char *)sink;
	        vaddr  = (user_addr_t)source;
		ctype  = COPYINPHYS;
	} else {
	        paddr  = (char *)source;
		vaddr  = (user_addr_t)sink;
		ctype  = COPYOUTPHYS;
	}
	return copyio(ctype, vaddr, paddr, csize, NULL, which & cppvKmap);
}

int
copyinmsg(const user_addr_t user_addr, char *kernel_addr, mach_msg_size_t nbytes)
{
    return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}    

int
copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
    return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}

int
copyinstr(const user_addr_t user_addr,  char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
    *lencopied = 0;

    return copyio(COPYINSTR, user_addr, kernel_addr, nbytes, lencopied, 0);
}

int
copyoutmsg(const char *kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes)
{
    return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
    return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}


kern_return_t
copypv(addr64_t src64, addr64_t snk64, unsigned int size, int which)
{
	unsigned int lop, csize;
	int bothphys = 0;
	
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_START, (unsigned)src64,
		     (unsigned)snk64, size, which, 0);

	if ((which & (cppvPsrc | cppvPsnk)) == 0 )				/* Make sure that only one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");	/* Not allowed */

	if ((which & (cppvPsrc | cppvPsnk)) == (cppvPsrc | cppvPsnk))
	        bothphys = 1;							/* both are physical */

	while (size) {
	  
	        if (bothphys) {
		        lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));		/* Assume sink smallest */

			if (lop > (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1))))
			        lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));	/* No, source is smaller */
		} else {
		        /*
			 * only need to compute the resid for the physical page
			 * address... we don't care about where we start/finish in
			 * the virtual since we just call the normal copyin/copyout
			 */
		        if (which & cppvPsrc)
			        lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));
			else
			        lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));
		}
		csize = size;						/* Assume we can copy it all */
		if (lop < size)
		        csize = lop;					/* Nope, we can't do it all */
#if 0		
		/*
		 * flush_dcache64 is currently a nop on the i386... 
		 * it's used when copying to non-system memory such
		 * as video capture cards... on PPC there was a need
		 * to flush due to how we mapped this memory... not
		 * sure if it's needed on i386.
		 */
		if (which & cppvFsrc)
		        flush_dcache64(src64, csize, 1);		/* If requested, flush source before move */
		if (which & cppvFsnk)
		        flush_dcache64(snk64, csize, 1);		/* If requested, flush sink before move */
#endif
		if (bothphys)
		        bcopy_phys(src64, snk64, csize);		/* Do a physical copy, virtually */
		else {
		        if (copyio_phys(src64, snk64, csize, which))
			        return (KERN_FAILURE);
		}
#if 0
		if (which & cppvFsrc)
		        flush_dcache64(src64, csize, 1);	/* If requested, flush source after move */
		if (which & cppvFsnk)
		        flush_dcache64(snk64, csize, 1);	/* If requested, flush sink after move */
#endif
		size   -= csize;					/* Calculate what is left */
		snk64 += csize;					/* Bump sink to next physical address */
		src64 += csize;					/* Bump source to next physical address */
	}
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_END, (unsigned)src64,
		     (unsigned)snk64, size, which, 0);

	return KERN_SUCCESS;
}
