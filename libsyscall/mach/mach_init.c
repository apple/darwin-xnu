/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach/mach.h>
#include <mach/boolean.h>
#include <mach/machine/ndr_def.h>
#include <mach/mach_traps.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/vm_param.h>
#include "externs.h"

mach_port_t	mach_task_self_ = MACH_PORT_NULL;
mach_port_t     mach_host_self_ = MACH_PORT_NULL;

__private_extern__ kern_return_t _host_mach_msg_trap_return_;

vm_size_t	vm_page_size;
vm_size_t	vm_page_mask;
int		vm_page_shift;

/*
 * Forward internal declarations for automatic mach_init during
 * fork() implementation.
 */
/* fork() calls through atfork_child_routine */
void (*_atfork_child_routine)(void);

static void mach_atfork_child_routine(void);
static boolean_t first = TRUE;
static void (*previous_atfork_child_routine)(void);
static boolean_t mach_init_inited = FALSE;
extern int mach_init(void);
extern void _pthread_set_self(void *);
extern void cthread_set_self(void *);
extern void __libc_init(void); /* Libc initialization routine */

kern_return_t
host_page_size(__unused host_t host, vm_size_t *out_page_size)
{
	*out_page_size = PAGE_SIZE;
	return KERN_SUCCESS;
}

static void mach_atfork_child_routine(void)
{
	/*
	 * If an (*_atfork_child_routine)() was registered when
	 * mach_init was first called, then call that routine
	 * prior to performing our re-initialization. This ensures
	 * that the post-fork handlers are called in exactly the
	 * same order as the crt0 (exec) handlers. Any library 
	 * that makes use of the _atfork_child_routine must follow
	 * the same technique.
	 */
	if (previous_atfork_child_routine) {
		(*previous_atfork_child_routine)();
	}
	mach_init_inited = FALSE;
	mach_init();
}

mach_port_t
mach_host_self(void)
{
        return(host_self_trap());
}

int mach_init_doit(int forkchild)
{
	host_t host;

	/*
	 *	Get the important ports into the cached values,
	 *	as required by "mach_init.h".
	 */
	 
	mach_task_self_ = task_self_trap();
	host = host_self_trap();


	if (!forkchild) {
		/*
		 * Set up the post-fork child handler in the libc stub
		 * to invoke this routine if this process forks. Save the
		 * previous value in order that we can call that handler
		 * prior to performing our postfork work.
		 */
            
		first = FALSE;
		previous_atfork_child_routine = _atfork_child_routine;
		_atfork_child_routine = mach_atfork_child_routine;
                _pthread_set_self(0);
                cthread_set_self(0);
	}

	/*
	 *	Initialize the single mig reply port
	 */

	mig_init(0);

	/*
	 *	Cache some other valuable system constants
	 */

	(void)host_page_size(host, &vm_page_size);
	vm_page_mask = vm_page_size - 1;
	if (vm_page_size == 0) {
		/* guard against unlikely craziness */
		vm_page_shift = 0;
	} else {
		/*
		 * Unfortunately there's no kernel interface to get the
		 * vm_page_shift, but it's easy enough to calculate.
		 */
		for (vm_page_shift = 0;
		     (vm_page_size & (1 << vm_page_shift)) == 0;
		     vm_page_shift++)
			continue;
	}

	mach_port_deallocate(mach_task_self_, host);

	mach_init_ports();

#if WE_REALLY_NEED_THIS_GDB_HACK
	/*
	 * Check to see if GDB wants us to stop
	 */
	{
	  task_user_data_data_t	user_data;
	  mach_msg_type_number_t	user_data_count = TASK_USER_DATA_COUNT;
	  
	user_data.user_data = 0;
	(void)task_info(mach_task_self_, TASK_USER_DATA,
		(task_info_t)&user_data, &user_data_count);
#define MACH_GDB_RUN_MAGIC_NUMBER 1
#ifdef	MACH_GDB_RUN_MAGIC_NUMBER	
	  /* This magic number is set in mach-aware gdb 
	   *  for RUN command to allow us to suspend user's
	   *  executable (linked with this libmach!) 
	   *  with the code below.
	* This hack should disappear when gdb improves.
	*/
	if ((int)user_data.user_data == MACH_GDB_RUN_MAGIC_NUMBER) {
	    kern_return_t ret;
	    user_data.user_data = 0;
	    
	    ret = task_suspend (mach_task_self_);
	    if (ret != KERN_SUCCESS) {
		while(1) (void)task_terminate(mach_task_self_);
	    }
	}
#undef MACH_GDB_RUN_MAGIC_NUMBER  
#endif /* MACH_GDB_RUN_MAGIC_NUMBER */
	}
#endif /* WE_REALLY_NEED_THIS_GDB_HACK */

	/*
         * Reserve page 0 so that the program doesn't get it as
	 * the result of a vm_allocate() or whatever.
	 */
	{
		vm_offset_t zero_page_start;

		zero_page_start = 0;
		(void)vm_map(mach_task_self_, &zero_page_start, vm_page_size,
			     0, FALSE, MEMORY_OBJECT_NULL, 0, TRUE,
			     VM_PROT_NONE, VM_PROT_NONE, VM_INHERIT_COPY);
		/* ignore result, we don't care if it failed */
	}

	return(0);
}




/* 
 * mach_init() is called explicitly in static executables (including dyld)
 * It is called implicitly by libSystem_initializer() in dynamic executables
 */
int mach_init(void)
{
	int ret;

	if (mach_init_inited)
		return(0);
	mach_init_inited = TRUE;
	ret = mach_init_doit(0);

	return ret;
}




/* called by _cthread_fork_child() */
int fork_mach_init(void)
{
	/* called only from child */
	return(mach_init_doit(1));
}

#undef	mach_task_self

mach_port_t
mach_task_self(void)
{
	return(task_self_trap());
}

mach_port_t
mach_thread_self(void)
{
	return(thread_self_trap());
}
