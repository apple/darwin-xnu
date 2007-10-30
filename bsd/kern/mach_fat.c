/*
 * Copyright (c) 1991-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <vm/vm_kern.h>
#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <kern/cpu_number.h>
#include <mach-o/fat.h>
#include <kern/mach_loader.h>
#include <libkern/OSByteOrder.h>
#include <machine/exec.h>

/**********************************************************************
 * Routine:	fatfile_getarch2()
 *
 * Function:	Locate the architecture-dependant contents of a fat
 *		file that match this CPU.
 *
 * Args:	vp:		The vnode for the fat file.
 *		header:		A pointer to the fat file header.
 *		req_cpu_type:	The required cpu type.
 *		mask_bits:	Bits to mask from the sub-image type when
 *				grading it vs. the req_cpu_type
 *		archret (out):	Pointer to fat_arch structure to hold
 *				the results.
 *
 * Returns:	KERN_SUCCESS:	Valid architecture found.
 *		KERN_FAILURE:	No valid architecture found.
 **********************************************************************/
static load_return_t
fatfile_getarch2(
#if 0
	struct vnode	*vp,
#else
	__unused struct vnode	*vp,
#endif
	vm_offset_t	data_ptr,
	cpu_type_t	req_cpu_type,
	cpu_type_t	mask_bits,
	struct fat_arch	*archret)
{
	/* vm_pager_t		pager; */
	vm_offset_t		addr;
	vm_size_t		size;
	load_return_t		lret;
	struct fat_arch		*arch;
	struct fat_arch		*best_arch;
	int			grade;
	int			best_grade;
	int			nfat_arch;
	off_t			end_of_archs;
	cpu_type_t		testtype;
	cpu_type_t		testsubtype;
	struct fat_header	*header;
#if 0
	off_t filesize;
#endif

	/*
	 * 	Get the pager for the file.
	 */

	header = (struct fat_header *)data_ptr;

	/*
	 *	Map portion that must be accessible directly into
	 *	kernel's map.
	 */
	nfat_arch = OSSwapBigToHostInt32(header->nfat_arch);

	end_of_archs = (off_t)nfat_arch * sizeof(struct fat_arch) +
			sizeof(struct fat_header);
#if 0
	filesize = ubc_getsize(vp);
	if (end_of_archs > (int)filesize) {
		return(LOAD_BADMACHO);
	}
#endif

	/*
	 * This check is limited on the top end because we are reading
	 * only PAGE_SIZE bytes
	 */
	if (end_of_archs > PAGE_SIZE ||
	    end_of_archs < (sizeof(struct fat_header)+sizeof(struct fat_arch)))
		return(LOAD_BADMACHO);

	/*
	 * 	Round size of fat_arch structures up to page boundry.
	 */
	size = round_page_32(end_of_archs);
	if (size == 0)
		return(LOAD_BADMACHO);

	/*
	 * Ignore LIB64 flag so that binary slices with the flag set
	 * don't choke in grade_binary.
	 */
	mask_bits |= CPU_SUBTYPE_LIB64;

	/*
	 * Scan the fat_arch's looking for the best one.  */
	addr = data_ptr;
	best_arch = NULL;
	best_grade = 0;
	arch = (struct fat_arch *) (addr + sizeof(struct fat_header));
	for (; nfat_arch-- > 0; arch++) {

		/* 
		 *	Collect flags from both cputype and cpusubtype 
		 */
 		testtype = OSSwapBigToHostInt32(arch->cputype) |
 				(OSSwapBigToHostInt32(arch->cpusubtype) & 
 					CPU_SUBTYPE_MASK);
 		testsubtype = OSSwapBigToHostInt32(arch->cpusubtype) 
 			& ~CPU_SUBTYPE_MASK;

		/*
		 *	Check to see if right cpu type.
		 */
 		if((testtype & ~mask_bits) != req_cpu_type) {
			continue;
		}

		/*
		 * 	Get the grade of the cpu subtype (without feature flags)
		 */
 		grade = grade_binary(
				(testtype & ~CPU_SUBTYPE_LIB64), 
				testsubtype);

		/*
		 *	Remember it if it's the best we've seen.
		 */
		if (grade > best_grade) {
			best_grade = grade;
			best_arch = arch;
		}
	}

	/*
	 *	Return our results.
	 */
	if (best_arch == NULL) {
		lret = LOAD_BADARCH;
	} else {
		archret->cputype	=
			    OSSwapBigToHostInt32(best_arch->cputype);
		archret->cpusubtype	=
			    OSSwapBigToHostInt32(best_arch->cpusubtype);
		archret->offset		=
			    OSSwapBigToHostInt32(best_arch->offset);
		archret->size		=
			    OSSwapBigToHostInt32(best_arch->size);
		archret->align		=
			    OSSwapBigToHostInt32(best_arch->align);

		lret = LOAD_SUCCESS;
	}

	/*
	 * Free the memory we allocated and return.
	 */
	return(lret);
}

load_return_t
fatfile_getarch_affinity(
		struct vnode		*vp,
		vm_offset_t		data_ptr,
		struct fat_arch	*archret,
		int 				affinity)
{
		load_return_t lret;
		int handler = (exec_archhandler_ppc.path[0] != 0);
		cpu_type_t primary_type, fallback_type;

		if (handler && affinity) {
				primary_type = CPU_TYPE_POWERPC;
				fallback_type = cpu_type();
		} else {
				primary_type = cpu_type();
				fallback_type = CPU_TYPE_POWERPC;
		}
		/*
		 * Ignore all architectural bits when determining if an image
		 * in a fat file should be skipped or graded.
		 */
		lret = fatfile_getarch2(vp, data_ptr, primary_type, 
				CPU_ARCH_MASK, archret);
		if ((lret != 0) && handler) {
			lret = fatfile_getarch2(vp, data_ptr, fallback_type,
						CPU_SUBTYPE_LIB64, archret);
		}
		return lret;
}

/**********************************************************************
 * Routine:	fatfile_getarch()
 *
 * Function:	Locate the architecture-dependant contents of a fat
 *		file that match this CPU.
 *
 * Args:	vp:		The vnode for the fat file.
 *		header:		A pointer to the fat file header.
 *		archret (out):	Pointer to fat_arch structure to hold
 *				the results.
 *
 * Returns:	KERN_SUCCESS:	Valid architecture found.
 *		KERN_FAILURE:	No valid architecture found.
 **********************************************************************/
load_return_t
fatfile_getarch(
	struct vnode		*vp,
	vm_offset_t 	data_ptr,
	struct fat_arch		*archret)
{
	return fatfile_getarch2(vp, data_ptr, cpu_type(), 
			CPU_SUBTYPE_LIB64, archret);
}

/**********************************************************************
 * Routine:	fatfile_getarch_with_bits()
 *
 * Function:	Locate the architecture-dependant contents of a fat
 *		file that match this CPU.
 *
 * Args:	vp:		The vnode for the fat file.
 *		archbits:	Architecture specific feature bits
 *		header:		A pointer to the fat file header.
 *		archret (out):	Pointer to fat_arch structure to hold
 *				the results.
 *
 * Returns:	KERN_SUCCESS:	Valid architecture found.
 *		KERN_FAILURE:	No valid architecture found.
 **********************************************************************/
load_return_t
fatfile_getarch_with_bits(
	struct vnode		*vp,
	integer_t		archbits,
	vm_offset_t 	data_ptr,
	struct fat_arch		*archret)
{
	return fatfile_getarch2(vp, data_ptr, archbits | cpu_type(), 
			CPU_SUBTYPE_LIB64, archret);
}

