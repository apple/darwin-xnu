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
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <sys/kdebug.h>

/*
 * the copy engine has the following characteristics
 *   - copyio handles copies to/from user or kernel space
 *   - copypv deals with physical or virtual addresses
 *
 * implementation details as follows
 *   - a cache of up to NCOPY_WINDOWS is maintained per thread for
 *     access of user virutal space
 *   - the window size is determined by the amount of virtual space
 *     that can be mapped by a single page table
 *   - the mapping is done by copying the page table pointer from
 *     the user's directory entry corresponding to the window's
 *     address in user space to the directory entry corresponding
 *     to the window slot in the kernel's address space
 *   - the set of mappings is preserved across context switches,
 *     so the copy can run with pre-emption enabled
 *   - there is a gdt entry set up to anchor the kernel window on
 *     each processor
 *   - the copies are done using the selector corresponding to the
 *     gdt entry
 *   - the addresses corresponding to the user virtual address are
 *     relative to the beginning of the window being used to map
 *     that region... thus the thread can be pre-empted and switched
 *     to a different processor while in the midst of a copy
 *   - the window caches must be invalidated if the pmap changes out
 *     from under the thread... this can happen during vfork/exec...
 *     inval_copy_windows is the invalidation routine to be used
 *   - the copyio engine has 4 different states associated with it
 *     that allows for lazy tlb flushes and the ability to avoid
 *     a flush all together if we've just come from user space
 *     the 4 states are as follows...
 *
 *	WINDOWS_OPENED - set by copyio to indicate to the context
 *	  switch code that it is necessary to do a tlbflush after
 * 	  switching the windows since we're in the middle of a copy
 *
 *	WINDOWS_CLOSED - set by copyio to indicate that it's done
 *	  using the windows, so that the context switch code need
 *	  not do the tlbflush... instead it will set the state to...
 *
 *	WINDOWS_DIRTY - set by the context switch code to indicate
 *	  to the copy engine that it is responsible for doing a 
 *	  tlbflush before using the windows again... it's also
 *	  set by the inval_copy_windows routine to indicate the
 *	  same responsibility.
 *
 *	WINDOWS_CLEAN - set by the return to user path to indicate
 * 	  that a tlbflush has happened and that there is no need
 *	  for copyio to do another when it is entered next...
 *
 *   - a window for mapping single physical pages is provided for copypv
 *   - this window is maintained across context switches and has the
 *     same characteristics as the user space windows w/r to pre-emption
 */

extern int copyout_user(const char *, vm_offset_t, vm_size_t);
extern int copyout_kern(const char *, vm_offset_t, vm_size_t);
extern int copyin_user(const vm_offset_t, char *, vm_size_t);
extern int copyin_kern(const vm_offset_t, char *, vm_size_t);
extern int copyoutphys_user(const char *, vm_offset_t, vm_size_t);
extern int copyoutphys_kern(const char *, vm_offset_t, vm_size_t);
extern int copyinphys_user(const vm_offset_t, char *, vm_size_t);
extern int copyinphys_kern(const vm_offset_t, char *, vm_size_t);
extern int copyinstr_user(const vm_offset_t, char *, vm_size_t, vm_size_t *);
extern int copyinstr_kern(const vm_offset_t, char *, vm_size_t, vm_size_t *);

static int copyio(int, user_addr_t, char *, vm_size_t, vm_size_t *, int);
static int copyio_phys(addr64_t, addr64_t, vm_size_t, int);


#define COPYIN		0
#define COPYOUT		1
#define COPYINSTR	2
#define COPYINPHYS	3
#define COPYOUTPHYS	4

void inval_copy_windows(thread_t thread)
{
        int	i;

	for (i = 0; i < NCOPY_WINDOWS; i++) {
                thread->machine.copy_window[i].user_base = -1;
	}
	thread->machine.nxt_window = 0;
	thread->machine.copyio_state = WINDOWS_DIRTY;

	KERNEL_DEBUG(0xeff70058 | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), (int)thread->map, 0, 0, 0);
}


static int
copyio(int copy_type, user_addr_t user_addr, char *kernel_addr,
       vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
        thread_t	thread;
	pmap_t		pmap;
	pt_entry_t	*updp;
	pt_entry_t	*kpdp;
	user_addr_t 	user_base;
	vm_offset_t 	user_offset;
	vm_offset_t 	kern_vaddr;
	vm_size_t	cnt;
	vm_size_t	bytes_copied;
	int		error = 0;
	int		window_index;
	int		copyio_state;
        boolean_t	istate;
#if KDEBUG
	int		debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif

	thread = current_thread();

	KERNEL_DEBUG(debug_type | DBG_FUNC_START, (int)(user_addr >> 32), (int)user_addr,
		     (int)nbytes, thread->machine.copyio_state, 0);

	if (nbytes == 0) {
	        KERNEL_DEBUG(debug_type | DBG_FUNC_END, (unsigned)user_addr,
			     (unsigned)kernel_addr, (unsigned)nbytes, 0, 0);
	        return (0);
	}
        pmap = thread->map->pmap;

        if (pmap == kernel_pmap || use_kernel_map) {

	        kern_vaddr = (vm_offset_t)user_addr;
	  
	        switch (copy_type) {

		case COPYIN:
		        error = copyin_kern(kern_vaddr, kernel_addr, nbytes);
			break;

		case COPYOUT:
		        error = copyout_kern(kernel_addr, kern_vaddr, nbytes);
			break;

		case COPYINSTR:
		        error = copyinstr_kern(kern_vaddr, kernel_addr, nbytes, lencopied);
			break;

		case COPYINPHYS:
		        error = copyinphys_kern(kern_vaddr, kernel_addr, nbytes);
			break;

		case COPYOUTPHYS:
		        error = copyoutphys_kern(kernel_addr, kern_vaddr, nbytes);
			break;
		}
		KERNEL_DEBUG(debug_type | DBG_FUNC_END, (unsigned)kern_vaddr,
			     (unsigned)kernel_addr, (unsigned)nbytes,
			     error | 0x80000000, 0);
		return (error);
	}
	
#if CONFIG_DTRACE
	thread->machine.specFlags |= CopyIOActive;
#endif /* CONFIG_DTRACE */
	
	if ((nbytes && (user_addr + nbytes <= user_addr)) ||
	    (user_addr          < vm_map_min(thread->map)) ||
	    (user_addr + nbytes > vm_map_max(thread->map))) {
		error = EFAULT;
		goto done;
	}

	user_base = user_addr & ~((user_addr_t)(NBPDE - 1));
	user_offset = (vm_offset_t)(user_addr & (NBPDE - 1));

	KERNEL_DEBUG(debug_type | DBG_FUNC_NONE, (int)(user_base >> 32), (int)user_base,
		     (int)user_offset, 0, 0);

	cnt = NBPDE - user_offset;

	if (cnt > nbytes)
	        cnt = nbytes;

	istate = ml_set_interrupts_enabled(FALSE);

	copyio_state = thread->machine.copyio_state;
	thread->machine.copyio_state = WINDOWS_OPENED;

	(void) ml_set_interrupts_enabled(istate);


	for (;;) {

	        for (window_index = 0; window_index < NCOPY_WINDOWS; window_index++) {
		        if (thread->machine.copy_window[window_index].user_base == user_base)
					break;
		}
	        if (window_index >= NCOPY_WINDOWS) {

		        window_index = thread->machine.nxt_window;
			thread->machine.nxt_window++;

			if (thread->machine.nxt_window >= NCOPY_WINDOWS)
			        thread->machine.nxt_window = 0;

			/*
			 * it's necessary to disable pre-emption
			 * since I have to compute the kernel descriptor pointer
			 * for the new window
			 */
			istate = ml_set_interrupts_enabled(FALSE);

			thread->machine.copy_window[window_index].user_base = user_base;

		        updp = pmap_pde(pmap, user_base);

			kpdp = current_cpu_datap()->cpu_copywindow_pdp;
			kpdp += window_index;

			pmap_store_pte(kpdp, updp ? *updp : 0);

			(void) ml_set_interrupts_enabled(istate);

		        copyio_state = WINDOWS_DIRTY;

			KERNEL_DEBUG(0xeff70040 | DBG_FUNC_NONE, window_index,
				     (unsigned)user_base, (unsigned)updp,
				     (unsigned)kpdp, 0);

		}
#if JOE_DEBUG
		else {
			istate = ml_set_interrupts_enabled(FALSE);

		        updp = pmap_pde(pmap, user_base);

			kpdp = current_cpu_datap()->cpu_copywindow_pdp;

			kpdp += window_index;

			if ((*kpdp & PG_FRAME) != (*updp & PG_FRAME)) {
				panic("copyio: user pdp mismatch - kpdp = 0x%qx,  updp = 0x%qx\n", *kpdp, *updp);
			}
			(void) ml_set_interrupts_enabled(istate);
		}
#endif
		if (copyio_state == WINDOWS_DIRTY) {
		        flush_tlb();

		        copyio_state = WINDOWS_CLEAN;

			KERNEL_DEBUG(0xeff70054 | DBG_FUNC_NONE, window_index, 0, 0, 0, 0);
		}
		user_offset += (window_index * NBPDE);

		KERNEL_DEBUG(0xeff70044 | DBG_FUNC_NONE, (unsigned)user_offset,
			     (unsigned)kernel_addr, cnt, 0, 0);

	        switch (copy_type) {

		case COPYIN:
		        error = copyin_user(user_offset, kernel_addr, cnt);
			break;
			
		case COPYOUT:
		        error = copyout_user(kernel_addr, user_offset, cnt);
			break;

		case COPYINPHYS:
		        error = copyinphys_user(user_offset, kernel_addr, cnt);
			break;
			
		case COPYOUTPHYS:
		        error = copyoutphys_user(kernel_addr, user_offset, cnt);
			break;

		case COPYINSTR:
		        error = copyinstr_user(user_offset, kernel_addr, cnt, &bytes_copied);

			/*
			 * lencopied should be updated on success
			 * or ENAMETOOLONG...  but not EFAULT
			 */
			if (error != EFAULT)
			        *lencopied += bytes_copied;

			/*
			 * if we still have room, then the ENAMETOOLONG
			 * is just an artifact of the buffer straddling
			 * a window boundary and we should continue
			 */
			if (error == ENAMETOOLONG && nbytes > cnt)
			        error = 0;

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
				goto done;
			}
			if (cnt == nbytes) {
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
			assert(cnt == bytes_copied);

			break;
		}
		if (error)
		        break;
		if ((nbytes -= cnt) == 0)
		        break;

		kernel_addr += cnt;
		user_base += NBPDE;
		user_offset = 0;

		if (nbytes > NBPDE)
		        cnt = NBPDE;
		else
		        cnt = nbytes;
	}
done:
	thread->machine.copyio_state = WINDOWS_CLOSED;

	KERNEL_DEBUG(debug_type | DBG_FUNC_END, (unsigned)user_addr,
		     (unsigned)kernel_addr, (unsigned)nbytes, error, 0);

#if CONFIG_DTRACE
	thread->machine.specFlags &= ~CopyIOActive;
#endif /* CONFIG_DTRACE */

	return (error);
}

static int
copyio_phys(addr64_t source, addr64_t sink, vm_size_t csize, int which)
{
        pmap_paddr_t paddr;
	user_addr_t vaddr;
	char        *window_offset;
	pt_entry_t  pentry;
	int         ctype;
	int	    retval;
	boolean_t   istate;


	if (which & cppvPsnk) {
		paddr  = (pmap_paddr_t)sink;
	        vaddr  = (user_addr_t)source;
		ctype  = COPYINPHYS;
		pentry = (pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_RW);
	} else {
	        paddr  = (pmap_paddr_t)source;
		vaddr  = (user_addr_t)sink;
		ctype  = COPYOUTPHYS;
		pentry = (pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME));
	}
	/* Fold in cache attributes for this physical page */
	pentry |= pmap_get_cache_attributes(i386_btop(paddr));
	window_offset = (char *)(uintptr_t)((uint32_t)paddr & (PAGE_SIZE - 1));

	assert(!((current_thread()->machine.specFlags & CopyIOActive) && ((which & cppvKmap) == 0)));

	if (current_thread()->machine.physwindow_busy) {
	        pt_entry_t	old_pentry;

	        KERNEL_DEBUG(0xeff70048 | DBG_FUNC_NONE, paddr, csize, 0, -1, 0);
		/*
		 * we had better be targeting wired memory at this point
		 * we will not be able to handle a fault with interrupts
		 * disabled... we disable them because we can't tolerate
		 * being preempted during this nested use of the window
		 */
		istate = ml_set_interrupts_enabled(FALSE);

		old_pentry = *(current_cpu_datap()->cpu_physwindow_ptep);
		pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep), pentry);

		invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);

		retval = copyio(ctype, vaddr, window_offset, csize, NULL, which & cppvKmap);

		pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep), old_pentry);

		invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);

		(void) ml_set_interrupts_enabled(istate);
	} else {
	        /*
		 * mark the window as in use... if an interrupt hits while we're
		 * busy, or we trigger another coyppv from the fault path into
		 * the driver on a user address space page fault due to a copyin/out
		 * then we need to save and restore the current window state instead
		 * of caching the window preserving it across context switches
		 */
	        current_thread()->machine.physwindow_busy = 1;

	        if (current_thread()->machine.physwindow_pte != pentry) {
		        KERNEL_DEBUG(0xeff70048 | DBG_FUNC_NONE, paddr, csize, 0, 0, 0);

			current_thread()->machine.physwindow_pte = pentry;
			
			/*
			 * preemption at this point would be bad since we
			 * could end up on the other processor after we grabbed the
			 * pointer to the current cpu data area, but before we finished
			 * using it to stuff the page table entry since we would
			 * be modifying a window that no longer belonged to us
			 * the invlpg can be done unprotected since it only flushes
			 * this page address from the tlb... if it flushes the wrong
			 * one, no harm is done, and the context switch that moved us
			 * to the other processor will have already take care of 
			 * flushing the tlb after it reloaded the page table from machine.physwindow_pte
			 */
			istate = ml_set_interrupts_enabled(FALSE);

			pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep), pentry);
			(void) ml_set_interrupts_enabled(istate);

			invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);
		}
#if JOE_DEBUG
		else {
		        if (pentry !=
			    (*(current_cpu_datap()->cpu_physwindow_ptep) & (INTEL_PTE_VALID | PG_FRAME | INTEL_PTE_RW)))
			        panic("copyio_phys: pentry != *physwindow_ptep");
		}
#endif
		retval = copyio(ctype, vaddr, window_offset, csize, NULL, which & cppvKmap);

	        current_thread()->machine.physwindow_busy = 0;
	}
	return (retval);
}

int
copyinmsg(const user_addr_t user_addr, char *kernel_addr, mach_msg_size_t nbytes)
{
        return (copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0));
}    

int
copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
        return (copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0));
}

int
copyinstr(const user_addr_t user_addr,  char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	*lencopied = 0;

        return (copyio(COPYINSTR, user_addr, kernel_addr, nbytes, lencopied, 0));
}

int
copyoutmsg(const char *kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes)
{
	return (copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0));
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	return (copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0));
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
		if (bothphys) {
			bcopy_phys(src64, snk64, csize);		/* Do a physical copy, virtually */
		}
		else {
			if (copyio_phys(src64, snk64, csize, which)) {
				return (KERN_FAILURE);
			}
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
void
copy_window_fault(thread_t thread, vm_map_t map, int window)
{
	pt_entry_t	*updp;
	pt_entry_t	*kpdp;

	/*
	 * in case there was no page table assigned
	 * for the user base address and the pmap
	 * got 'expanded' due to this fault, we'll
	 * copy in the descriptor 
	 *
	 * we're either setting the page table descriptor
	 * to the same value or it was 0... no need
	 * for a TLB flush in either case
	 */

        updp = pmap_pde(map->pmap, thread->machine.copy_window[window].user_base);
	assert(updp);
	if (0 == updp) panic("trap: updp 0"); /* XXX DEBUG */
	kpdp = current_cpu_datap()->cpu_copywindow_pdp;
	kpdp += window;

#if JOE_DEBUG
	if (*kpdp && (*kpdp & PG_FRAME) != (*updp & PG_FRAME))
	        panic("kernel_fault: user pdp doesn't match - updp = 0x%qx, kpdp = 0x%qx\n", *updp, *kpdp);
#endif
	pmap_store_pte(kpdp, *updp);
}
