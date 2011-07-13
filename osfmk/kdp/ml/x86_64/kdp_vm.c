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

#include <vm/vm_map.h>
#include <i386/pmap.h>

#include <kdp/kdp_core.h>
#include <kdp/kdp_internal.h>
#include <mach-o/loader.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h> 
#include <mach/vm_statistics.h>
#include <mach/thread_status.h>
#include <i386/thread.h>

#include <vm/vm_protos.h>
#include <vm/vm_kern.h>

int	kern_dump(void);
int	kdp_dump_trap(int type, x86_saved_state64_t *regs);

typedef struct {
	int	flavor;			/* the number for this flavor */
	mach_msg_type_number_t	count;	/* count of ints in this flavor */
} mythread_state_flavor_t;

static mythread_state_flavor_t thread_flavor_array [] = { 
	{x86_THREAD_STATE64, x86_THREAD_STATE64_COUNT}
};

static int kdp_mynum_flavors = 1;
static int MAX_TSTATE_FLAVORS = 1;

typedef struct {
	vm_offset_t header; 
	int  hoffset;
	mythread_state_flavor_t *flavors;
	int tstate_size;
} tir_t;

char command_buffer[512];

static void
kern_collectth_state(thread_t thread, tir_t *t)
{
	vm_offset_t	header;
	int  hoffset, i ;
	mythread_state_flavor_t *flavors;
	struct thread_command	*tc;
	/*
	 *	Fill in thread command structure.
	 */
	header = t->header;
	hoffset = t->hoffset;
	flavors = t->flavors;
	
	tc = (struct thread_command *) (header + hoffset);
	tc->cmd = LC_THREAD;
	tc->cmdsize = (uint32_t)sizeof(struct thread_command) + t->tstate_size;
	hoffset += (uint32_t)sizeof(struct thread_command);
	/*
	 * Follow with a struct thread_state_flavor and
	 * the appropriate thread state struct for each
	 * thread state flavor.
	 */
	for (i = 0; i < kdp_mynum_flavors; i++) {
		*(mythread_state_flavor_t *)(header+hoffset) =
		    flavors[i];
		hoffset += (uint32_t)sizeof(mythread_state_flavor_t);
		/* Locate and obtain the non-volatile register context
		 * for this kernel thread. This should ideally be
		 * encapsulated in machine_thread_get_kern_state()
		 * but that routine appears to have been co-opted
		 * by CHUD to obtain pre-interrupt state.
		 */
		if (flavors[i].flavor == x86_THREAD_STATE64) {
			x86_thread_state64_t *tstate = (x86_thread_state64_t *) (header + hoffset);
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
		}
		else if (machine_thread_get_kern_state(thread,
			flavors[i].flavor, (thread_state_t) (header+hoffset),
			&flavors[i].count) != KERN_SUCCESS)
			printf ("Failure in machine_thread_get_kern_state()\n");
		hoffset += (uint32_t)(flavors[i].count*sizeof(int));
	}

	t->hoffset = hoffset;
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

int
kern_dump(void)
{
	vm_map_t	map;
	unsigned int	thread_count, segment_count;
	unsigned int	command_size = 0, header_size = 0, tstate_size = 0;
	uint64_t	hoffset = 0, foffset = 0, nfoffset = 0;
	unsigned int	max_header_size = 0;
	vm_offset_t	header, txstart;
	vm_map_offset_t vmoffset;
	struct mach_header_64		*mh64;
	struct segment_command_64	*sc64;
	mach_vm_size_t	size = 0;
	vm_prot_t	prot = 0;
	vm_prot_t	maxprot = 0;
	mythread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
	vm_size_t	nflavors;
	vm_size_t	i;
	uint32_t	nesting_depth = 0;
	kern_return_t	kret = 0;
	struct vm_region_submap_info_64	vbr;
	mach_msg_type_number_t	vbrcount  = 0;
	tir_t tir1;

	int error = 0;
	int panic_error = 0;

	map = kernel_map;

	thread_count = 1;
	segment_count = get_vmmap_entries(map); 
  
	printf("Kernel map has %d entries\n", segment_count);

	nflavors = kdp_mynum_flavors;
	bcopy((char *)thread_flavor_array,(char *) flavors,sizeof(thread_flavor_array));

	for (i = 0; i < nflavors; i++)
		tstate_size += (uint32_t)(sizeof(mythread_state_flavor_t) +
		    (flavors[i].count * sizeof(int)));

	command_size = (uint32_t)((segment_count) *
	    sizeof(struct segment_command_64) +
	    thread_count * sizeof(struct thread_command) +
	    tstate_size * thread_count);

	header_size = command_size + (uint32_t)sizeof(struct mach_header_64);
	header = (vm_offset_t) command_buffer;
	
	/*
	 *	Set up Mach-O header for currently executing 32 bit kernel.
	 */
	printf ("Generated Mach-O header size was %d\n", header_size);

	mh64 = (struct mach_header_64 *) header;
	mh64->magic = MH_MAGIC_64;
	mh64->cputype = cpu_type();
	mh64->cpusubtype = cpu_subtype();
	mh64->filetype = MH_CORE;
	mh64->ncmds = segment_count + thread_count;
	mh64->sizeofcmds = command_size;
	mh64->flags = 0;
	mh64->reserved = 0;

	hoffset = sizeof(struct mach_header_64);	/* offset into header */
	foffset = (uint32_t)round_page(header_size);	/* offset into file */
	/* Padding */
	if ((foffset - header_size) < (4*sizeof(struct segment_command_64))) {
		foffset += (uint32_t)((4*sizeof(struct segment_command_64)) - (foffset-header_size)); 
	}

	max_header_size = (unsigned int)foffset;

	vmoffset = vm_map_min(map);

	/* Transmit the Mach-O MH_CORE header, and seek forward past the 
	 * area reserved for the segment and thread commands 
	 * to begin data transmission 
	 */
	if ((panic_error = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(nfoffset) , &nfoffset)) < 0) { 
		printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	} 

	if ((panic_error = kdp_send_crashdump_data (KDP_DATA, NULL, sizeof(struct mach_header_64), (caddr_t) mh64) < 0)) {
		printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	}
	if ((panic_error = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(foffset) , &foffset) < 0)) {
		printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	}
	printf ("Transmitting kernel state, please wait: ");

	while ((segment_count > 0) || (kret == KERN_SUCCESS)){

		while (1) {

			/*
			 *	Get region information for next region.
			 */

			vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;
			if((kret = mach_vm_region_recurse(map, 
				    &vmoffset, &size, &nesting_depth, 
				    (vm_region_recurse_info_t)&vbr,
				    &vbrcount)) != KERN_SUCCESS) {
				break;
			}

			if(vbr.is_submap) {
				nesting_depth++;
				continue;
			} else {
				break;
			}
		}

		if(kret != KERN_SUCCESS)
			break;

		prot = vbr.protection;
		maxprot = vbr.max_protection;

		/*
		 *	Fill in segment command structure.
		 */
    
		if (hoffset > max_header_size)
			break;
		sc64 = (struct segment_command_64 *) (header);
		sc64->cmd = LC_SEGMENT_64;
		sc64->cmdsize = sizeof(struct segment_command_64);
		sc64->segname[0] = 0;
		sc64->vmaddr = vmoffset;
		sc64->vmsize = size;
		sc64->fileoff = foffset;
		sc64->filesize = size;
		sc64->maxprot = maxprot;
		sc64->initprot = prot;
		sc64->nsects = 0;

		if ((panic_error = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(hoffset) , &hoffset)) < 0) { 
			printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
			error = panic_error;
			goto out;
		} 
    
		if ((panic_error = kdp_send_crashdump_data (KDP_DATA, NULL, sizeof(struct segment_command_64) , (caddr_t) sc64)) < 0) {
			printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
			error = panic_error;
			goto out;
		}

		/* Do not transmit memory tagged VM_MEMORY_IOKIT - instead,
		 * seek past that region on the server - this creates a
		 * hole in the file.
		 */

		if ((vbr.user_tag != VM_MEMORY_IOKIT)) {

			if ((panic_error = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(foffset) , &foffset)) < 0) {
				printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
				error = panic_error;
				goto out;
			}

			txstart = vmoffset;

			if ((panic_error = kdp_send_crashdump_data (KDP_DATA, NULL, (unsigned int)size, (caddr_t) txstart)) < 0)	{
				printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
				error = panic_error;
				goto out;
			}
		}

		hoffset += (unsigned int)sizeof(struct segment_command_64);
		foffset += (unsigned int)size;
		vmoffset += size;
		segment_count--;
	}
	tir1.header = header;
	tir1.hoffset = 0;
	tir1.flavors = flavors;
	tir1.tstate_size = tstate_size;

	/* Now send out the LC_THREAD load command, with the thread information
	 * for the current activation.
	 * Note that the corefile can contain LC_SEGMENT commands with file
	 * offsets that point past the edge of the corefile, in the event that
	 * the last N VM regions were all I/O mapped or otherwise
	 * non-transferable memory,  not followed by a normal VM region;
	 * i.e. there will be no hole that reaches to the end of the core file.
	 */
	kern_collectth_state (current_thread(), &tir1);

	if ((panic_error = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(hoffset) , &hoffset)) < 0) { 
		printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	}
  
	if ((panic_error = kdp_send_crashdump_data (KDP_DATA, NULL, tir1.hoffset , (caddr_t) header)) < 0) {
		printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	}
    
	/* last packet */
	if ((panic_error = kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0))) < 0)
	{
		printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		error = panic_error;
		goto out;
	}
out:
	return (error);
}
