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
/*
 * @OSF_COPYRIGHT@
 */
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

	first_result = copyin(src, dst, first_count);
	
	/* If there was an error, stop now and return error */
	if (first_result != 0)
		return first_result;

	/* otherwise finish the job and return result */
	return copyin(midpoint, dst + first_count, count-first_count);
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

	first_result = copyout(src, dst, first_count);
	
	/* If there was an error, stop now and return error */
	if (first_result != 0)
		return first_result;

	/* otherwise finish the job and return result */

	return copyout(src + first_count, midpoint, count-first_count);
}

#define HAVE_ASSEMBLY_BCMP
#ifndef HAVE_ASSEMBLY_BCMP
int bcmp(
	const char	*a,
	const char	*b,
	vm_size_t	len)
{
	if (len == 0)
		return 0;

	do
		if (*a++ != *b++)
			break;
	while (--len);  

	return len;
} 
#endif /* HAVE_ASSEMBLY_BCMP */

#define HAVE_ASSEMBLY_MEMCMP
#ifndef HAVE_ASSEMBLY_MEMCMP
int
memcmp(s1, s2, n)
	register char *s1, *s2;
	register n;
{
	while (--n >= 0)
		if (*s1++ != *s2++)
			return (*--s1 - *--s2);
	return (0);
}
#endif /* HAVE_ASSEMBLY_MEMCMP */

#define HAVE_ASSEMBLY_STRLEN
#ifndef HAVE_ASSEMBLY_STRLEN
/*
 * Abstract:
 * strlen returns the number of characters in "string" preceeding
 * the terminating null character.
 */

size_t
strlen(
	register const char *string)
{
	register const char *ret = string;

	while (*string++ != '\0')
		continue;
	return string - 1 - ret;
}
#endif /* HAVE_ASSEMBLY_STRLEN */

#if DEBUG
void regDump(struct ppc_saved_state *state)
{
	int i;

	for (i=0; i<32; i++) {
		if ((i % 8) == 0)
			kprintf("\n%4d :",i);
			kprintf(" %08x",*(&state->r0+i));
	}

	kprintf("\n");
	kprintf("cr        = 0x%08x\t\t",state->cr);
	kprintf("xer       = 0x%08x\n",state->xer); 
	kprintf("lr        = 0x%08x\t\t",state->lr); 
	kprintf("ctr       = 0x%08x\n",state->ctr); 
	kprintf("srr0(iar) = 0x%08x\t\t",state->srr0); 
	kprintf("srr1(msr) = 0x%08B\n",state->srr1,
		    "\x10\x11""EE\x12PR\x13""FP\x14ME\x15""FE0\x16SE\x18"
		    "FE1\x19""AL\x1a""EP\x1bIT\x1c""DT");
	kprintf("mq        = 0x%08x\t\t",state->mq);
	kprintf("sr_copyin = 0x%08x\n",state->sr_copyin);
	kprintf("\n");

	/* Be nice - for user tasks, generate some stack trace */
	if (state->srr1 & MASK(MSR_PR)) {
		char *addr = (char*)state->r1;
		unsigned int buf[2];
		for (i = 0; i < 8; i++) {
			if (addr == (char*)NULL)
				break;
			if (!copyin(addr,(char*)buf, 2 * sizeof(int))) {
				printf("0x%08x : %08x\n",buf[0],buf[1]);
				addr = (char*)buf[0];
			} else {
				break;
			}
		}
	}
}
#endif /* DEBUG */

#if 0
/*
 * invalidate_cache_for_io
 *
 * Takes cache of those requests which may require to flush the
 * data cache first before invalidation.
 */


void
invalidate_cache_for_io(vm_offset_t area, unsigned count, boolean_t phys)
{
	vm_offset_t aligned_start, aligned_end, end;

	/* For unaligned reads we need to flush any
	 * unaligned cache lines. We invalidate the
	 * rest as this is faster
	 */

	aligned_start = area & ~(CACHE_LINE_SIZE-1);
	if (aligned_start != area)
		flush_dcache(aligned_start, CACHE_LINE_SIZE, phys);

	end = area + count;
	aligned_end = (end & ~(CACHE_LINE_SIZE-1));
	if (aligned_end != end)
		flush_dcache(aligned_end, CACHE_LINE_SIZE, phys);

	invalidate_dcache(area, count, phys);
}

extern void tracecopyin(unsigned int src, unsigned int dest, unsigned int lgn, unsigned int from);
void tracecopyin(unsigned int src, unsigned int dest, unsigned int lgn, unsigned int from) {
	
	spl_t					spl;

	spl = splhigh();
	printf("Copy in called from %08X: src=%08X; dest=%08X; lgn=%08X\n", from, src, dest, lgn);
	splx(spl);
	return;
}

extern void tracecopyout(unsigned int src, unsigned int dest, unsigned int lgn, unsigned int from);
void tracecopyout(unsigned int src, unsigned int dest, unsigned int lgn, unsigned int from) {

	spl_t					spl;

	spl = splhigh();
	printf("Copy out called from %08X: src=%08X; dest=%08X; lgn=%08X\n", from, src, dest, lgn);
	splx(spl);
	return;
}

extern void tracecopystr(unsigned int src, unsigned int dest, unsigned int max, 
	unsigned int lgn, unsigned int from);
void tracecopystr(unsigned int src, unsigned int dest, unsigned int max,
	unsigned int lgn, unsigned int from) {

	spl_t					spl;

	spl = splhigh();
	printf("Copy in string called from %08X: src=%08X; dest=%08X; max=%08X; lgnadr=%08X\n", 
		from, src, dest, max, lgn);
	splx(spl);
	return;
}

unsigned int ExceptionTrace = 0;
extern void ExceptionTracePrint(struct savearea *sv, int type);
void ExceptionTracePrint(struct savearea *sv, int type) {

	spl_t					spl;

	spl = splhigh();
	
	if(type) {
		printf("   Trap from %08X, type=%08X, R0=%08X, R1=%08X, R3=%08X, LR=%08X, AST=%08X\n", 
			sv->save_srr0, sv->save_exception, sv->save_r0, sv->save_r1, sv->save_r3,
			sv->save_lr, need_ast[0]);
	}
	else {
		printf("Syscall from %08X, type=%08X, R0=%08X, R1=%08X, R3=%08X, LR=%08X, AST=%08X\n", 
			sv->save_srr0, sv->save_exception, sv->save_r0, sv->save_r1, sv->save_r3,
			sv->save_lr, need_ast[0]);
	}
	splx(spl);
	return;
}
#endif
