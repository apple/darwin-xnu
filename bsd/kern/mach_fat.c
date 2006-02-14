/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1991 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	kern/mach_fat.c
 *	Author:	Peter King
 *
 *	Fat file support routines.
 *
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
#include <architecture/byte_order.h>

/* XXX should be in common header */
extern int grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype);

#define CPU_TYPE_NATIVE		(cpu_type())
#define CPU_TYPE_CLASSIC	CPU_TYPE_POWERPC

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
	int			end_of_archs;
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
	nfat_arch = NXSwapBigLongToHost(header->nfat_arch);

	end_of_archs = sizeof(struct fat_header)
		+ nfat_arch * sizeof(struct fat_arch);
#if 0
	filesize = ubc_getsize(vp);
	if (end_of_archs > (int)filesize) {
		return(LOAD_BADMACHO);
	}
#endif

	/* This is beacuse we are reading only 512 bytes */

	if (end_of_archs > 512)
		return(LOAD_BADMACHO);
	/*
	 * 	Round size of fat_arch structures up to page boundry.
	 */
	size = round_page_32(end_of_archs);
	if (size == 0)
		return(LOAD_BADMACHO);

	/*
	 * Scan the fat_arch's looking for the best one.
	 */
	addr = data_ptr;
	best_arch = NULL;
	best_grade = 0;
	arch = (struct fat_arch *) (addr + sizeof(struct fat_header));
	for (; nfat_arch-- > 0; arch++) {

		/*
		 *	Check to see if right cpu type.
		 */
		if(((cpu_type_t)NXSwapBigIntToHost(arch->cputype) & ~mask_bits) != req_cpu_type)
			continue;

		/*
		 * 	Get the grade of the cpu subtype.
		 */
		grade = grade_binary(
			    NXSwapBigIntToHost(arch->cputype),
			    NXSwapBigIntToHost(arch->cpusubtype));

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
			    NXSwapBigIntToHost(best_arch->cputype);
		archret->cpusubtype	=
			    NXSwapBigIntToHost(best_arch->cpusubtype);
		archret->offset		=
			    NXSwapBigLongToHost(best_arch->offset);
		archret->size		=
			    NXSwapBigLongToHost(best_arch->size);
		archret->align		=
			    NXSwapBigLongToHost(best_arch->align);

		lret = LOAD_SUCCESS;
	}

	/*
	 * Free the memory we allocated and return.
	 */
	return(lret);
}

extern char classichandler[];

load_return_t
fatfile_getarch_affinity(
		struct vnode		*vp,
		vm_offset_t		data_ptr,
		struct fat_arch	*archret,
		int 				affinity)
{
		load_return_t lret;
		int handler = (classichandler[0] != 0);
		cpu_type_t primary_type, fallback_type;

		if (handler && affinity) {
				primary_type = CPU_TYPE_CLASSIC;
				fallback_type = CPU_TYPE_NATIVE;
		} else {
				primary_type = CPU_TYPE_NATIVE;
				fallback_type = CPU_TYPE_CLASSIC;
		}
		/*
		 * Ignore the architectural bits when determining if an image
		 * in a fat file should be skipped or graded.
		 */
		lret = fatfile_getarch2(vp, data_ptr, primary_type, CPU_ARCH_MASK, archret);
		if ((lret != 0) && handler) {
			lret = fatfile_getarch2(vp, data_ptr, fallback_type,
						0, archret);
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
	return fatfile_getarch2(vp, data_ptr, CPU_TYPE_NATIVE, 0, archret);
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
	return fatfile_getarch2(vp, data_ptr, archbits | CPU_TYPE_NATIVE, 0, archret);
}

