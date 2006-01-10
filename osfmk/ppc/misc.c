/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
#if 0  // dead code
#include <debug.h>
#include <mach_debug.h>

#include <mach/ppc/thread_status.h>
#include <mach/vm_types.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/pmap.h>
#include <ppc/misc_protos.h>
#include <ppc/exception.h>

/*
 * copyin/out_multiple - the assembler copyin/out functions jump to C for
 * help when the copyin lies over a segment boundary. The C breaks
 * down the copy into two sub-copies and re-calls the assembler with
 * these sub-copies. Very rare occurrance. Warning: These functions are
 * called whilst active_thread->thread_recover is still set.
 */

extern boolean_t copyin_multiple(const char *src,
				 char *dst,
				 vm_size_t count);

boolean_t copyin_multiple(const char *src,
			  char *dst,
			  vm_size_t count)
{
	const char *midpoint;
	vm_size_t first_count;
	boolean_t first_result;

	/* Assert that we've been called because of a segment boundary,
	 * this function is more expensive than the assembler, and should
	 * only be called in this difficult case.
	 */
	assert(((vm_offset_t)src & 0xF0000000) !=
	       ((vm_offset_t)(src + count -1) & 0xF0000000));

	/* TODO NMGS define sensible constants for segments, and apply
	 * to C and assembler (assembler is much harder)
	 */
	midpoint = (const char*) ((vm_offset_t)(src + count) & 0xF0000000);
	first_count = (midpoint - src);

	first_result = copyin(CAST_USER_ADDR_T(src), dst, first_count);
	
	/* If there was an error, stop now and return error */
	if (first_result != 0)
		return first_result;

	/* otherwise finish the job and return result */
	return copyin(CAST_USER_ADDR_T(midpoint), dst + first_count, count-first_count);
}

extern int copyout_multiple(const char *src, char *dst, vm_size_t count);

int copyout_multiple(const char *src, char *dst, vm_size_t count)
{
	char *midpoint;
	vm_size_t first_count;
	boolean_t first_result;

	/* Assert that we've been called because of a segment boundary,
	 * this function is more expensive than the assembler, and should
	 * only be called in this difficult case. For copyout, the
	 * segment boundary is on the dst
	 */
	assert(((vm_offset_t)dst & 0xF0000000) !=
	       ((vm_offset_t)(dst + count - 1) & 0xF0000000));

	/* TODO NMGS define sensible constants for segments, and apply
	 * to C and assembler (assembler is much harder)
	 */
	midpoint = (char *) ((vm_offset_t)(dst + count) & 0xF0000000);
	first_count = (midpoint - dst);

	first_result = copyout(src, CAST_USER_ADDR_T(dst), first_count);
	
	/* If there was an error, stop now and return error */
	if (first_result != 0)
		return first_result;

	/* otherwise finish the job and return result */

	return copyout(src + first_count, CAST_USER_ADDR_T(midpoint), count-first_count);
}
#endif // dead code

