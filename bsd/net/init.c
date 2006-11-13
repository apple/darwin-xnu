/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <kern/kalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/errno.h>
#include <net/init.h>
#include <libkern/libkern.h>
#include <string.h>

struct init_list_entry {
	struct init_list_entry	*next;
	net_init_func_ptr		func;
};

#define LIST_RAN ((struct init_list_entry*)0xffffffff)
static struct init_list_entry	*list_head = 0;

errno_t
net_init_add(
	net_init_func_ptr init_func)
{
	struct init_list_entry	*entry;
	
	if (init_func == 0) {
		return EINVAL;
	}
	
	/* Check if we've already started */
	if (list_head == LIST_RAN) {
		return EALREADY;
	}
	
	entry = kalloc(sizeof(*entry));
	if (entry == 0) {
		printf("net_init_add: no memory\n");
		return ENOMEM;
	}
	
	bzero(entry, sizeof(*entry));
	entry->func = init_func;
	
	do {
		entry->next = list_head;
		
		if (entry->next == LIST_RAN) {
			/* List already ran, cleanup and call the function */
			kfree(entry, sizeof(*entry));
			return EALREADY;
		}
	} while(!OSCompareAndSwap((UInt32)entry->next, (UInt32)entry,
							  (UInt32*)&list_head));
	
	return 0;
}

__private_extern__ void
net_init_run(void)
{
	struct init_list_entry	*backward_head = 0;
	struct init_list_entry	*forward_head = 0;
	struct init_list_entry	*current = 0;
	
	/*
	 * Grab the list, replacing the head with 0xffffffff to indicate
	 * that we've already run.
	 */
	do {
		backward_head = list_head;
	} while (!OSCompareAndSwap((UInt32)backward_head, (UInt32)LIST_RAN,
							   (UInt32*)&list_head));
	
	/* Reverse the order of the list */
	while (backward_head != 0) {
		current = backward_head;
		backward_head = current->next;
		current->next = forward_head;
		forward_head = current;
	}
	
	/* Call each function pointer registered */
	while (forward_head != 0) {
		current = forward_head;
		forward_head = current->next;
		current->func();
		kfree(current, sizeof(*current));
	}
}
