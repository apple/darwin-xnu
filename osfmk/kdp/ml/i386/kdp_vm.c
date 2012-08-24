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

int	kdp_dump_trap(int type, x86_saved_state32_t *regs);

static const x86_state_hdr_t thread_flavor_array [] = { 
	{x86_THREAD_STATE32, x86_THREAD_STATE32_COUNT}
};

size_t
kern_collectth_state_size(void)
{
	unsigned int i;
	size_t tstate_size = 0;

	for (i = 0; i < sizeof(thread_flavor_array)/sizeof(thread_flavor_array[0]); i++)
		tstate_size += sizeof(x86_state_hdr_t) +
		    (thread_flavor_array[i].count * sizeof(int));

	return tstate_size;
}

void
kern_collectth_state(thread_t thread, void *buffer, size_t size)
{
	size_t			hoffset;
	unsigned int	i;
	struct thread_command	*tc;

	/*
	 *	Fill in thread command structure.
	 */
	hoffset = 0;
	
	if (hoffset + sizeof(struct thread_command) > size)
		return;

	tc = (struct thread_command *) ((uintptr_t)buffer + hoffset);
	tc->cmd = LC_THREAD;
	tc->cmdsize = sizeof(struct thread_command) + kern_collectth_state_size();
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
		 * encapsulated in machine_thread_get_kern_state()
		 * but that routine appears to have been co-opted
		 * by CHUD to obtain pre-interrupt state.
		 */
		if (thread_flavor_array[i].flavor == x86_THREAD_STATE32) {
			x86_thread_state32_t *tstate = (x86_thread_state32_t *) ((uintptr_t)buffer + hoffset);
			vm_offset_t kstack;

			bzero(tstate, x86_THREAD_STATE32_COUNT * sizeof(int));
			if ((kstack = thread->kernel_stack) != 0){
				struct x86_kernel_state *iks = STACK_IKS(kstack);
				tstate->ebx = iks->k_ebx;
				tstate->esp = iks->k_esp;
				tstate->ebp = iks->k_ebp;
				tstate->edi = iks->k_edi;
				tstate->esi = iks->k_esi;
				tstate->eip = iks->k_eip;
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
	__unused x86_saved_state32_t	*saved_state)
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
