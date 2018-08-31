/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <libsa/types.h>

#include <kdp/kdp_core.h>
#include <kdp/kdp_internal.h>
#include <kdp/ml/i386/kdp_x86_common.h>
#include <mach-o/loader.h>
#include <mach/thread_status.h>
#include <i386/thread.h>

int	kdp_dump_trap(int type, x86_saved_state64_t *regs);

static const x86_state_hdr_t thread_flavor_array [] = { 
	{x86_THREAD_STATE64, x86_THREAD_STATE64_COUNT}
};

void
kern_collectth_state_size(uint64_t * tstate_count, uint64_t * ptstate_size)
{
	unsigned int i;
	uint64_t tstate_size = 0;

	for (i = 0; i < sizeof(thread_flavor_array)/sizeof(thread_flavor_array[0]); i++)
		tstate_size += sizeof(x86_state_hdr_t) +
		    (thread_flavor_array[i].count * sizeof(int));

	*tstate_count = 1;
	*ptstate_size = sizeof(struct thread_command) + tstate_size;
}

void
kern_collectth_state(thread_t thread, void *buffer, uint64_t size, void ** iter)
{
	size_t		hoffset;
	uint64_t 	tstate_size, tstate_count;
	unsigned int	i;
	struct thread_command	*tc;
	

	*iter = NULL;
	/*
	 *	Fill in thread command structure.
	 */
	hoffset = 0;
	
	if (hoffset + sizeof(struct thread_command) > size)
		return;

	kern_collectth_state_size(&tstate_count, &tstate_size);
	tc = (struct thread_command *) ((uintptr_t)buffer + hoffset);
	tc->cmd = LC_THREAD;
	tc->cmdsize = (uint32_t) tstate_size;
	hoffset += sizeof(struct thread_command);
	/*
	 * Follow with a struct thread_state_flavor and
	 * the appropriate thread state struct for each
	 * thread state flavor.
	 */
	for (i = 0; i < sizeof(thread_flavor_array)/sizeof(thread_flavor_array[0]); i++) {

		if (hoffset + sizeof(x86_state_hdr_t) > size)
			return;

		*(x86_state_hdr_t *)((uintptr_t)buffer + hoffset) =
		    thread_flavor_array[i];
		hoffset += sizeof(x86_state_hdr_t);


		if (hoffset + thread_flavor_array[i].count*sizeof(int) > size)
			return;

		/* Locate and obtain the non-volatile register context
		 * for this kernel thread. This should ideally be
		 * encapsulated in machine_thread_get_kern_state().
		 */
		if (thread_flavor_array[i].flavor == x86_THREAD_STATE64) {
			x86_thread_state64_t *tstate = (x86_thread_state64_t *) ((uintptr_t)buffer + hoffset);
			vm_offset_t kstack;
			x86_saved_state64_t *cpstate = current_cpu_datap()->cpu_fatal_trap_state;

			bzero(tstate, x86_THREAD_STATE64_COUNT * sizeof(int));
			if ((current_thread() == thread) && (cpstate != NULL)) {
				tstate->rax = cpstate->rax;
				tstate->rbx = cpstate->rbx;
				tstate->rcx = cpstate->rcx;
				tstate->rdx = cpstate->rdx;
				tstate->rdi = cpstate->rdi;
				tstate->rsi = cpstate->rsi;
				tstate->rbp = cpstate->rbp;
				tstate->r8 = cpstate->r8;
				tstate->r9 = cpstate->r9;
				tstate->r10 = cpstate->r10;
				tstate->r11 = cpstate->r11;
				tstate->r12 = cpstate->r12;
				tstate->r13 = cpstate->r13;
				tstate->r14 = cpstate->r14;
				tstate->r15 = cpstate->r15;
				tstate->rip = cpstate->isf.rip;
				tstate->rsp = cpstate->isf.rsp;
				tstate->rflags = cpstate->isf.rflags;
				tstate->cs = cpstate->isf.cs;
				tstate->fs = cpstate->fs;
				tstate->gs = cpstate->gs;
			} else if ((kstack = thread->kernel_stack) != 0){
				struct x86_kernel_state *iks = STACK_IKS(kstack);
				tstate->rbx = iks->k_rbx;
				tstate->rsp = iks->k_rsp;
				tstate->rbp = iks->k_rbp;
				tstate->r12 = iks->k_r12;
				tstate->r13 = iks->k_r13;
				tstate->r14 = iks->k_r14;
				tstate->r15 = iks->k_r15;
				tstate->rip = iks->k_rip;
			}
		} else {
			void *tstate = (void *)((uintptr_t)buffer + hoffset);

			bzero(tstate, thread_flavor_array[i].count*sizeof(int));
		}

		hoffset += thread_flavor_array[i].count*sizeof(int);
	}
}

/* Intended to be called from the kernel trap handler if an unrecoverable fault
 * occurs during a crashdump (which shouldn't happen since we validate mappings
 * and so on). This should be reworked to attempt some form of recovery.
 */
int
kdp_dump_trap(
	int type,
	__unused x86_saved_state64_t	*saved_state)
{
	printf ("An unexpected trap (type %d) occurred during the system dump, terminating.\n", type);
	kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0));
	abort_panic_transfer();
	kdp_flag &= ~KDP_PANIC_DUMP_ENABLED;
	kdp_flag &= ~PANIC_CORE_ON_NMI;
	kdp_flag &= ~PANIC_LOG_DUMP;

	kdp_reset();

	kdp_raise_exception(EXC_BAD_ACCESS, 0, 0, kdp.saved_state);
	return( 0 );
}
