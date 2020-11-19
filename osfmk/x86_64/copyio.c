/*
 * Copyright (c) 2009-2020 Apple Inc. All rights reserved.
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
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/cpuid.h>
#include <i386/vmx.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>
#include <san/kasan.h>

#include <sys/kdebug.h>

#include <kern/copyout_shim.h>
#include <kern/zalloc_internal.h>

#undef copyin
#undef copyout

static int copyio(int, user_addr_t, char *, vm_size_t, vm_size_t *, int);
static int copyio_phys(addr64_t, addr64_t, vm_size_t, int);

/*
 * Copy sizes bigger than this value will cause a kernel panic.
 *
 * Yes, this is an arbitrary fixed limit, but it's almost certainly
 * a programming error to be copying more than this amount between
 * user and wired kernel memory in a single invocation on this
 * platform.
 */
const int copysize_limit_panic = (64 * MB);

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
extern int _copyin_atomic32(const char *src, uint32_t *dst);
extern int _copyin_atomic64(const char *src, uint64_t *dst);
extern int _copyout_atomic32(const uint32_t *u32, char *src);
extern int _copyout_atomic64(const uint64_t *u64, char *src);

/*
 * Types of copies:
 */
#define COPYIN          0       /* from user virtual to kernel virtual */
#define COPYOUT         1       /* from kernel virtual to user virtual */
#define COPYINSTR       2       /* string variant of copyout */
#define COPYINPHYS      3       /* from user virtual to kernel physical */
#define COPYOUTPHYS     4       /* from kernel physical to user virtual */
#define COPYINATOMIC32  5       /* from user virtual to kernel virtual */
#define COPYINATOMIC64  6       /* from user virtual to kernel virtual */
#define COPYOUTATOMIC32 7       /* from user virtual to kernel virtual */
#define COPYOUTATOMIC64 8       /* from user virtual to kernel virtual */

#if ENABLE_SMAPLOG
typedef struct {
	uint64_t        timestamp;
	thread_t        thread;
	uintptr_t       cr4;
	uint8_t         cpuid;
	uint8_t         smap_state;
	uint8_t         copyio_active;
} smaplog_entry_t;

#define SMAPLOG_BUFFER_SIZE (50)
static smaplog_entry_t  smaplog_cbuf[SMAPLOG_BUFFER_SIZE];
static uint32_t         smaplog_head = 0;

static void
smaplog_add_entry(boolean_t enabling)
{
	uint32_t index = 0;
	thread_t thread = current_thread();

	do {
		index = smaplog_head;
	} while (!OSCompareAndSwap(index, (index + 1) % SMAPLOG_BUFFER_SIZE, &smaplog_head));

	assert(index < SMAPLOG_BUFFER_SIZE);
	assert(smaplog_head < SMAPLOG_BUFFER_SIZE);
	assert(thread);

	smaplog_cbuf[index].timestamp = mach_absolute_time();
	smaplog_cbuf[index].thread = thread;
	smaplog_cbuf[index].cpuid = cpu_number();
	smaplog_cbuf[index].cr4 = get_cr4();
	smaplog_cbuf[index].smap_state = enabling;
	smaplog_cbuf[index].copyio_active = (thread->machine.specFlags & CopyIOActive) ? 1 : 0;
}
#endif /* ENABLE_SMAPLOG */

extern boolean_t pmap_smap_enabled;
static inline void
user_access_enable(void)
{
	if (pmap_smap_enabled) {
		stac();
#if ENABLE_SMAPLOG
		smaplog_add_entry(TRUE);
#endif
	}
}
static inline void
user_access_disable(void)
{
	if (pmap_smap_enabled) {
		clac();
#if ENABLE_SMAPLOG
		smaplog_add_entry(FALSE);
#endif
	}
}

#if COPYIO_TRACE_ENABLED
#define COPYIO_TRACE(x, a, b, c, d, e) KERNEL_DEBUG_CONSTANT(x, a, b, c, d, e)
#else
#define COPYIO_TRACE(x, a, b, c, d, e) do { } while(0)
#endif

static int
copyio(int copy_type, user_addr_t user_addr, char *kernel_addr,
    vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
	thread_t        thread = current_thread();
	pmap_t          pmap;
	vm_size_t       bytes_copied;
	int             error = 0;
	boolean_t       istate = FALSE;
	boolean_t       recursive_CopyIOActive;
#if     COPYIO_TRACE_ENABLED
	int             debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif
	vm_size_t kernel_buf_size = 0;

	if (__improbable(nbytes > copysize_limit_panic)) {
		panic("%s(%p, %p, %lu) - transfer too large", __func__,
		    (void *)user_addr, (void *)kernel_addr, nbytes);
	}

	COPYIO_TRACE(debug_type | DBG_FUNC_START,
	    user_addr, kernel_addr, nbytes, use_kernel_map, 0);

	if (__improbable(nbytes == 0)) {
		goto out;
	}

	pmap = thread->map->pmap;
	boolean_t nopagezero = thread->map->pmap->pagezero_accessible;

	if ((copy_type != COPYINPHYS) && (copy_type != COPYOUTPHYS)) {
		if (__improbable((vm_offset_t)kernel_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS)) {
			panic("Invalid copy parameter, copy type: %d, kernel address: %p", copy_type, kernel_addr);
		}
		if (__probable(!zalloc_disable_copyio_check)) {
			zone_t src_zone = NULL;
			kernel_buf_size = zone_element_size(kernel_addr, &src_zone);
			/*
			 * Size of elements in the permanent zone is not saved as a part of the
			 * zone's info
			 */
			if (__improbable(src_zone && !src_zone->permanent &&
			    kernel_buf_size < nbytes)) {
				panic("copyio: kernel buffer %p has size %lu < nbytes %lu", kernel_addr, kernel_buf_size, nbytes);
			}
		}
	}

	/* Sanity and security check for addresses to/from a user */

	if (__improbable(((pmap != kernel_pmap) && (use_kernel_map == 0)) &&
	    ((nbytes && (user_addr + nbytes <= user_addr)) || ((user_addr + nbytes) > vm_map_max(thread->map))))) {
		error = EFAULT;
		goto out;
	}

	if (copy_type >= COPYINATOMIC32 && copy_type <= COPYOUTATOMIC64) {
		if (__improbable(pmap == kernel_pmap)) {
			error = EFAULT;
			goto out;
		}
	}

#if KASAN
	switch (copy_type) {
	case COPYIN:
	case COPYINSTR:
	case COPYINATOMIC32:
	case COPYINATOMIC64:
		__asan_storeN((uptr)kernel_addr, nbytes);
		break;
	case COPYOUT:
	case COPYOUTATOMIC32:
	case COPYOUTATOMIC64:
		__asan_loadN((uptr)kernel_addr, nbytes);
		kasan_check_uninitialized((vm_address_t)kernel_addr, nbytes);
		break;
	}
#endif

	/*
	 * If the no_shared_cr3 boot-arg is set (true), the kernel runs on
	 * its own pmap and cr3 rather than the user's -- so that wild accesses
	 * from kernel or kexts can be trapped. So, during copyin and copyout,
	 * we need to switch back to the user's map/cr3. The thread is flagged
	 * "CopyIOActive" at this time so that if the thread is pre-empted,
	 * we will later restore the correct cr3.
	 */
	recursive_CopyIOActive = thread->machine.specFlags & CopyIOActive;

	boolean_t pdswitch = no_shared_cr3 || nopagezero;

	if (__improbable(pdswitch)) {
		istate = ml_set_interrupts_enabled(FALSE);
		if (nopagezero && pmap_pcid_ncpus) {
			pmap_pcid_activate(pmap, cpu_number(), TRUE, TRUE);
		} else if (get_cr3_base() != pmap->pm_cr3) {
			set_cr3_raw(pmap->pm_cr3);
		}
		thread->machine.specFlags |= CopyIOActive;
	} else {
		thread->machine.specFlags |= CopyIOActive;
	}

	user_access_enable();

#if DEVELOPMENT || DEBUG
	/*
	 * Ensure that we're running on the target thread's cr3.
	 */
	if ((pmap != kernel_pmap) && !use_kernel_map &&
	    (get_cr3_base() != pmap->pm_cr3)) {
		panic("copyio(%d,%p,%p,%ld,%p,%d) cr3 is %p expects %p",
		    copy_type, (void *)user_addr, kernel_addr, nbytes, lencopied, use_kernel_map,
		    (void *) get_cr3_raw(), (void *) pmap->pm_cr3);
	}
#endif

	if (__improbable(pdswitch)) {
		(void) ml_set_interrupts_enabled(istate);
	}

	COPYIO_TRACE(0xeff70044 | DBG_FUNC_NONE, user_addr,
	    kernel_addr, nbytes, 0, 0);

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

	case COPYINATOMIC32:
		error = _copyin_atomic32((const void *) user_addr,
		    (void *) kernel_addr);
		break;

	case COPYINATOMIC64:
		error = _copyin_atomic64((const void *) user_addr,
		    (void *) kernel_addr);
		break;

	case COPYOUTATOMIC32:
		error = _copyout_atomic32((const void *) kernel_addr,
		    (void *) user_addr);
		break;

	case COPYOUTATOMIC64:
		error = _copyout_atomic64((const void *) kernel_addr,
		    (void *) user_addr);
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
		if (error != EFAULT) {
			*lencopied = bytes_copied;
		}

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
	}

	user_access_disable();

	if (__improbable(pdswitch)) {
		istate = ml_set_interrupts_enabled(FALSE);
		if (!recursive_CopyIOActive && (get_cr3_raw() != kernel_pmap->pm_cr3)) {
			if (nopagezero && pmap_pcid_ncpus) {
				pmap_pcid_activate(pmap, cpu_number(), TRUE, FALSE);
			} else {
				set_cr3_raw(kernel_pmap->pm_cr3);
			}
		}

		if (!recursive_CopyIOActive) {
			thread->machine.specFlags &= ~CopyIOActive;
		}
		(void) ml_set_interrupts_enabled(istate);
	} else if (!recursive_CopyIOActive) {
		thread->machine.specFlags &= ~CopyIOActive;
	}

out:
	COPYIO_TRACE(debug_type | DBG_FUNC_END, user_addr, kernel_addr, nbytes, error, 0);

	return error;
}


static int
copyio_phys(addr64_t source, addr64_t sink, vm_size_t csize, int which)
{
	char        *paddr;
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
		CALL_COPYOUT_SHIM_PHYS((void *)PHYSMAP_PTOV(source), sink, csize)
	}
	return copyio(ctype, vaddr, paddr, csize, NULL, which & cppvKmap);
}

int
copyinmsg(const user_addr_t user_addr, char *kernel_addr, mach_msg_size_t nbytes)
{
	return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}

int
copyin(const user_addr_t user_addr, void *kernel_addr, vm_size_t nbytes)
{
	return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}

/*
 * copy{in,out}_atomic{32,64}
 * Read or store an aligned value from userspace as a single memory transaction.
 * These functions support userspace synchronization features
 */
int
copyin_atomic32(const user_addr_t user_addr, uint32_t *kernel_addr)
{
	/* Test alignment */
	if (user_addr & 3) {
		return EINVAL;
	}
	return copyio(COPYINATOMIC32, user_addr, (char *)(uintptr_t)kernel_addr, 4, NULL, 0);
}

int
copyin_atomic32_wait_if_equals(const user_addr_t user_addr, uint32_t value)
{
	uint32_t u32;
	int result = copyin_atomic32(user_addr, &u32);
	if (__improbable(result)) {
		return result;
	}
	if (u32 != value) {
		return ESTALE;
	}
	cpu_pause();
	return 0;
}

int
copyin_atomic64(const user_addr_t user_addr, uint64_t *kernel_addr)
{
	/* Test alignment */
	if (user_addr & 7) {
		return EINVAL;
	}
	return copyio(COPYINATOMIC64, user_addr, (char *)(uintptr_t)kernel_addr, 8, NULL, 0);
}

int
copyout_atomic32(uint32_t value, user_addr_t user_addr)
{
	/* Test alignment */
	if (user_addr & 3) {
		return EINVAL;
	}
	return copyio(COPYOUTATOMIC32, user_addr, (char *)&value, 4, NULL, 0);
}

int
copyout_atomic64(uint64_t value, user_addr_t user_addr)
{
	/* Test alignment */
	if (user_addr & 7) {
		return EINVAL;
	}
	return copyio(COPYOUTATOMIC64, user_addr, (char *)&value, 8, NULL, 0);
}

int
copyinstr(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	*lencopied = 0;

	return copyio(COPYINSTR, user_addr, kernel_addr, nbytes, lencopied, 0);
}

int
copyoutmsg(const char *kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes)
{
	CALL_COPYOUT_SHIM_MSG(kernel_addr, user_addr, (vm_size_t)nbytes)
	return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	CALL_COPYOUT_SHIM_NRML(kernel_addr, user_addr, nbytes)
	return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}


kern_return_t
copypv(addr64_t src64, addr64_t snk64, unsigned int size, int which)
{
	unsigned int lop, csize;
	int bothphys = 0;

	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_START, (unsigned)src64,
	    (unsigned)snk64, size, which, 0);

	if ((which & (cppvPsrc | cppvPsnk)) == 0) {                             /* Make sure that only one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");     /* Not allowed */
	}
	if ((which & (cppvPsrc | cppvPsnk)) == (cppvPsrc | cppvPsnk)) {
		bothphys = 1;                                                   /* both are physical */
	}
	while (size) {
		if (bothphys) {
			lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));            /* Assume sink smallest */

			if (lop > (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)))) {
				lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));    /* No, source is smaller */
			}
		} else {
			/*
			 * only need to compute the resid for the physical page
			 * address... we don't care about where we start/finish in
			 * the virtual since we just call the normal copyin/copyout
			 */
			if (which & cppvPsrc) {
				lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));
			} else {
				lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));
			}
		}
		csize = size;                                           /* Assume we can copy it all */
		if (lop < size) {
			csize = lop;                                    /* Nope, we can't do it all */
		}
#if 0
		/*
		 * flush_dcache64 is currently a nop on the i386...
		 * it's used when copying to non-system memory such
		 * as video capture cards... on PPC there was a need
		 * to flush due to how we mapped this memory... not
		 * sure if it's needed on i386.
		 */
		if (which & cppvFsrc) {
			flush_dcache64(src64, csize, 1);                /* If requested, flush source before move */
		}
		if (which & cppvFsnk) {
			flush_dcache64(snk64, csize, 1);                /* If requested, flush sink before move */
		}
#endif
		if (bothphys) {
			bcopy_phys(src64, snk64, csize);                /* Do a physical copy, virtually */
		} else {
			if (copyio_phys(src64, snk64, csize, which)) {
				return KERN_FAILURE;
			}
		}
#if 0
		if (which & cppvFsrc) {
			flush_dcache64(src64, csize, 1);        /* If requested, flush source after move */
		}
		if (which & cppvFsnk) {
			flush_dcache64(snk64, csize, 1);        /* If requested, flush sink after move */
		}
#endif
		size   -= csize;                                        /* Calculate what is left */
		snk64 += csize;                                 /* Bump sink to next physical address */
		src64 += csize;                                 /* Bump source to next physical address */
	}
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_END, (unsigned)src64,
	    (unsigned)snk64, size, which, 0);

	return KERN_SUCCESS;
}
