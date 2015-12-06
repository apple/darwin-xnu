/*
 * Copyright (c) 2000-2010 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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

/*
 * 	Default pager.
 * 		Threads management.
 *		Requests handling.
 */

#include "default_pager_internal.h"
#include <default_pager/default_pager_object_server.h>
#include <kern/host.h>
#include <mach/host_info.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>
#include <ipc/ipc_space.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_pageout.h>

char	my_name[] = "(default pager): ";

#if	DEFAULT_PAGER_DEBUG
int	debug_mask = 0;
#endif	/* DEFAULT_PAGER_DEBUG */

/*
 * Use 16 Kbyte stacks instead of the default 64K.
 * Use 4 Kbyte waiting stacks instead of the default 8K.
 */

vm_size_t	cthread_stack_size = 16 *1024;
extern vm_size_t cthread_wait_stack_size;

#ifndef MACH_KERNEL
unsigned long long	vm_page_mask;
int		vm_page_shift;
#endif

boolean_t	verbose;

/* task_t default_pager_self; */	/* Our task port. */
lck_mtx_t				dpt_lock;       /* lock for the dpt array struct */
default_pager_thread_t	**dpt_array;

memory_object_default_t default_pager_object; /* for memory_object_create. */

MACH_PORT_FACE default_pager_default_set; /* Port set for "default" thread. */
MACH_PORT_FACE default_pager_internal_set; /* Port set for internal objects. */
MACH_PORT_FACE default_pager_external_set; /* Port set for external objects. */

#define DEFAULT_PAGER_INTERNAL_COUNT	(4)


/* Memory created by default_pager_object_create should mostly be resident. */
#define DEFAULT_PAGER_EXTERNAL_COUNT	(2)

int	default_pager_internal_count = DEFAULT_PAGER_INTERNAL_COUNT;
/* Number of "internal" threads. */
int	default_pager_external_count = DEFAULT_PAGER_EXTERNAL_COUNT;
/* Number of "external" threads. */

/*
 * Forward declarations.
 */
boolean_t default_pager_notify_server(mach_msg_header_t *,
				      mach_msg_header_t *);
boolean_t default_pager_demux_object(mach_msg_header_t *,
				     mach_msg_header_t *);
boolean_t default_pager_demux_default(mach_msg_header_t *,
				      mach_msg_header_t *);
default_pager_thread_t *start_default_pager_thread(int, boolean_t);
void	default_pager(void);
void	default_pager_thread(void *);
void	default_pager_initialize(void);
boolean_t	dp_parse_argument(char *);	/* forward; */
unsigned int	d_to_i(char *);			/* forward; */

extern int vstruct_def_clshift;

struct global_stats global_stats;

/*
 * Initialize and Run the default pager
 */
void
default_pager(void)
{
	int			i, id;
	__unused static char here[] = "default_pager";
	default_pager_thread_t	dpt;
	kern_return_t kr;



	/*
	 * Give me space for the thread array and zero it.
	 */
	i = default_pager_internal_count + default_pager_external_count + 1;
	dpt_array = (default_pager_thread_t **)
	    kalloc(i * sizeof(default_pager_thread_t *));
	memset(dpt_array, 0, i * sizeof(default_pager_thread_t *));

	/* Setup my thread structure.  */
	id = 0;
	dpt.dpt_buffer = 0;
	dpt.dpt_internal = FALSE;
	dpt.dpt_initialized_p = TRUE;
	dpt_array[0] = &dpt;

	/*
	 * Now we create the threads that will actually
	 * manage objects.
	 */

	for (i = 0; i < default_pager_internal_count; i++) {
		dpt_array[id] = (default_pager_thread_t *)
				kalloc(sizeof (default_pager_thread_t));
		if (dpt_array[id] == NULL)
	 		Panic("alloc pager thread");
		kr = vm_allocate(kernel_map, &((dpt_array[id])->dpt_buffer),
				 vm_page_size << vstruct_def_clshift, VM_FLAGS_ANYWHERE | VM_MAKE_TAG(VM_KERN_MEMORY_OSFMK));
		if (kr != KERN_SUCCESS)
			Panic("alloc thread buffer");
		kr = vm_map_wire(kernel_map, (dpt_array[id])->dpt_buffer, 
			((dpt_array[id])->dpt_buffer)
					+(vm_page_size << vstruct_def_clshift), 
			VM_PROT_DEFAULT | VM_PROT_MEMORY_TAG_MAKE(VM_KERN_MEMORY_OSFMK),
			FALSE);
		if (kr != KERN_SUCCESS)
			Panic("wire thread buffer");
		(dpt_array[id])->dpt_internal = TRUE;
		(dpt_array[id])->dpt_initialized_p = TRUE;
		(dpt_array[id])->checked_out = FALSE;
		id++;
	}
	DPT_LOCK_INIT(dpt_lock);
}






/* simple utility: only works for 2^n */
int
local_log2(
	unsigned int n)
{
	register int	i = 0;

	if(n == 0) return 0;

	while ((n & 1) == 0) {
		i++;
		n >>= 1;
	}
	return i;
}




/* another simple utility, d_to_i(char*) supporting only decimal
 * and devoid of range checking; obscure name chosen deliberately
 * to avoid confusion with semantic-rich POSIX routines */
unsigned int
d_to_i(char * arg)
{
    unsigned int rval = 0;
    char ch;

    while ((ch = *arg++) && ch >= '0' && ch <= '9') {
	rval *= 10;
	rval += ch - '0';
    }
    return(rval);
}




/*
 * Check for non-disk-partition arguments of the form
 *	attribute=argument
 * returning TRUE if one if found
 */
boolean_t dp_parse_argument(char *av)
{
	char *rhs = av;
	__unused static char	here[] = "dp_parse_argument";

	/* Check for '-v' flag */

	if (av[0] == '-' && av[1] == 'v' && av[2] == 0) {
		verbose = TRUE ;
		return TRUE;
	}

	/*
	 * If we find a '=' followed by an argument in the string,
	 * check for known arguments
	 */
	while (*rhs && *rhs != '=')
		rhs++;
	if (*rhs && *++rhs) {
		/* clsize=N pages */
		if (strprefix(av,"cl")) {
			if (!bs_set_default_clsize(d_to_i(rhs)))
				dprintf(("Bad argument (%s) - ignored\n", av));
			return(TRUE);
		}
		/* else if strprefix(av,"another_argument")) {
			handle_another_argument(av);
			return(TRUE);
		} */
	}
	return(FALSE);
}

int
start_def_pager( __unused char *bs_device )
{
/*
	MACH_PORT_FACE		master_device_port;
*/
/*
	MACH_PORT_FACE		security_port;
*/
	__unused static char here[] = "main";




	/* setup read buffers, etc */
	default_pager_initialize();

#ifndef MACH_KERNEL	
	default_pager();
#endif

	if (DEFAULT_PAGER_IS_ACTIVE) {
		/* start the backing store monitor, it runs on a callout thread */
		default_pager_backing_store_monitor_callout = 
			thread_call_allocate(default_pager_backing_store_monitor, NULL);
		if (!default_pager_backing_store_monitor_callout)
			panic("can't start backing store monitor thread");
		thread_call_enter(default_pager_backing_store_monitor_callout);
	}

	return (0);
}

kern_return_t
default_pager_info(
	memory_object_default_t	pager,
	default_pager_info_t	*infop)
{
	uint64_t	pages_total, pages_free;

	if (pager != default_pager_object)
		return KERN_INVALID_ARGUMENT; 

	bs_global_info(&pages_total, &pages_free);

	infop->dpi_total_space = (vm_size_t) ptoa_64(pages_total);
	infop->dpi_free_space = (vm_size_t) ptoa_64(pages_free);
	infop->dpi_page_size = vm_page_size;

	return KERN_SUCCESS;
}


kern_return_t
default_pager_info_64(
	memory_object_default_t	pager,
	default_pager_info_64_t	*infop)
{
	uint64_t	pages_total, pages_free;

	if (pager != default_pager_object)
		return KERN_INVALID_ARGUMENT; 

	bs_global_info(&pages_total, &pages_free);

	infop->dpi_total_space = ptoa_64(pages_total);
	infop->dpi_free_space = ptoa_64(pages_free);
	infop->dpi_page_size = vm_page_size;
	infop->dpi_flags = 0;
	if (dp_encryption_inited && dp_encryption == TRUE) {
		infop->dpi_flags |= DPI_ENCRYPTED;
	}

	return KERN_SUCCESS;
}

lck_grp_t		default_pager_lck_grp;
lck_grp_attr_t	default_pager_lck_grp_attr;
lck_attr_t		default_pager_lck_attr;



void
default_pager_initialize(void)
{
	kern_return_t		kr;
	__unused static char	here[] = "default_pager_initialize";

	lck_grp_attr_setdefault(&default_pager_lck_grp_attr);
	lck_grp_init(&default_pager_lck_grp, "default_pager", &default_pager_lck_grp_attr);
	lck_attr_setdefault(&default_pager_lck_attr);	

	/*
	 * Vm variables.
	 */
#ifndef MACH_KERNEL
	vm_page_mask = vm_page_size - 1;
	assert((unsigned int) vm_page_size == vm_page_size);
	vm_page_shift = local_log2((unsigned int) vm_page_size);
#endif

	/*
	 * List of all vstructs.
	 */
	vstruct_zone = zinit(sizeof(struct vstruct),
			     10000 * sizeof(struct vstruct),
			     8192, "vstruct zone");
	zone_change(vstruct_zone, Z_CALLERACCT, FALSE);
	zone_change(vstruct_zone, Z_NOENCRYPT, TRUE);

	VSL_LOCK_INIT();
	queue_init(&vstruct_list.vsl_queue);
	vstruct_list.vsl_count = 0;

	VSTATS_LOCK_INIT(&global_stats.gs_lock);

	bs_initialize();

	/*
	 * Exported DMM port.
	 */
	default_pager_object = ipc_port_alloc_kernel();


	/*
	 * Export pager interfaces.
	 */
#ifdef	USER_PAGER
	if ((kr = netname_check_in(name_server_port, "UserPager",
				   default_pager_self,
				   default_pager_object))
	    != KERN_SUCCESS) {
		dprintf(("netname_check_in returned 0x%x\n", kr));
		exit(1);
	}
#else	/* USER_PAGER */
	{
		unsigned int clsize;
		memory_object_default_t dmm;

		dmm = default_pager_object;
		assert((unsigned int) vm_page_size == vm_page_size);
		clsize = ((unsigned int) vm_page_size << vstruct_def_clshift);
		kr = host_default_memory_manager(host_priv_self(), &dmm, clsize);
		if ((kr != KERN_SUCCESS) ||
		    (dmm != MEMORY_OBJECT_DEFAULT_NULL))
			Panic("default memory manager");

	}
#endif	/* USER_PAGER */


}

