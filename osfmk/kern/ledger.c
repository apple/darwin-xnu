/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1995/01/06  19:47:19  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:19:28  dwm]
 *
 * Revision 1.1.3.4  1994/05/13  20:10:01  tmt
 * 	Changed three unsigned casts to natural_t.
 * 	[1994/05/12  22:12:28  tmt]
 * 
 * Revision 1.1.3.2  1993/11/30  18:26:24  jph
 * 	CR10228 -- Typo in unlock(), ledger_ledger should be child_ledger.
 * 	[1993/11/30  16:10:43  jph]
 * 
 * Revision 1.1.3.1  1993/11/24  21:22:14  jph
 * 	CR9801 brezak merge, ledgers, security and NMK15_COMPAT
 * 	[1993/11/23  22:41:07  jph]
 * 
 * Revision 1.1.1.4  1993/09/08  14:17:36  brezak
 * 	Include <mach/ledger_server.h> for protos.
 * 
 * Revision 1.1.1.3  1993/08/20  14:16:55  brezak
 * 	Created.
 * 
 * $EndLog$
 */

/*
 * 8/13/93
 * 
 * This is a half-hearted attempt at providing the parts of the
 * ledger facility to satisfy the ledger interfaces.
 *
 * This implementation basically leaves the (dysfunctional) ledgers
 * unfunctional and are mearly here to satisfy the Mach spec interface
 * reqirements.
 */

#include <mach/mach_types.h>
#include <mach/message.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <mach/port.h>
#include <kern/lock.h>
#include <kern/ipc_kobject.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <kern/host.h>
#include <kern/ledger.h>
#include <mach/ledger_server.h>

ledger_t	root_wired_ledger;
ledger_t	root_paged_ledger;


/* Utility routine to handle entries to a ledger */
kern_return_t
ledger_enter(
	     ledger_t		ledger,
	     ledger_item_t	amount)
{
	/* Need to lock the ledger */
	ledger_lock(ledger);
	
	if (amount > 0) {
		if (ledger->ledger_limit != LEDGER_ITEM_INFINITY &&
		    ledger->ledger_balance + amount > ledger->ledger_limit) {
			/* XXX this is where you do BAD things */
			printf("Ledger limit exceeded ! ledger=%x lim=%d balance=%d\n",
			       ledger, ledger->ledger_limit,
			       ledger->ledger_balance);
			ledger_unlock(ledger);
			return(KERN_RESOURCE_SHORTAGE);
		}
		if ((natural_t)(ledger->ledger_balance + amount) 
			< LEDGER_ITEM_INFINITY)
			ledger->ledger_balance += amount;
		else
			ledger->ledger_balance = LEDGER_ITEM_INFINITY;
	}
	else if (amount) {
		if (ledger->ledger_balance + amount > 0)
			ledger->ledger_balance += amount;
		else
			ledger->ledger_balance = 0;
	}
	ledger_unlock(ledger);
	return(KERN_SUCCESS);
}

/* Utility routine to create a new ledger */
static ledger_t
ledger_allocate(
		ledger_item_t	limit,
		ledger_t	ledger_ledger,
		ledger_t	ledger_parent)
{
	ledger_t	ledger;

	ledger = (ledger_t)kalloc(sizeof(ledger_data_t));
	if (ledger == LEDGER_NULL)
		return(LEDGER_NULL);

	ledger->ledger_self = ipc_port_alloc_kernel();
	if (ledger->ledger_self == IP_NULL)
		return(LEDGER_NULL);

	ledger_lock_init(ledger);
	ledger->ledger_limit = limit;
	ledger->ledger_balance = 0;
	ledger->ledger_service_port = MACH_PORT_NULL;
	ledger->ledger_ledger = ledger_ledger;
	ledger->ledger_parent = ledger_parent;
	ipc_kobject_set(ledger->ledger_self, (ipc_kobject_t)ledger,
			IKOT_LEDGER);

	return(ledger);
}

/* Utility routine to destroy a ledger */
static void
ledger_deallocate(
		  ledger_t	ledger)
{
	/* XXX can be many send rights (copies) of this */
	ipc_port_dealloc_kernel(ledger->ledger_self);

	/* XXX release send right on service port */
	kfree((vm_offset_t)ledger, sizeof(*ledger));
}


/*
 * Inititalize the ledger facility
 */
void ledger_init(void)
{
	/*
	 * Allocate the root ledgers; wired and paged.
	 */
	root_wired_ledger = ledger_allocate(LEDGER_ITEM_INFINITY,
					    LEDGER_NULL, LEDGER_NULL);
	if (root_wired_ledger == LEDGER_NULL)
		panic("can't allocate root (wired) ledger");
	ipc_port_make_send(root_wired_ledger->ledger_self);

	root_paged_ledger = ledger_allocate(LEDGER_ITEM_INFINITY,
					    LEDGER_NULL, LEDGER_NULL);
	if (root_paged_ledger == LEDGER_NULL)
		panic("can't allocate root (paged) ledger");
	ipc_port_make_send(root_paged_ledger->ledger_self);
}

/*
 *	Create a subordinate ledger
 */
kern_return_t ledger_create(
			    ledger_t parent_ledger,
			    ledger_t ledger_ledger,
			    ledger_t *new_ledger,
			    ledger_item_t transfer)
{
	if (parent_ledger == LEDGER_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (ledger_ledger == LEDGER_NULL)
		return(KERN_INVALID_LEDGER);

	/*
	 * Allocate a new ledger and change the ledger_ledger for
	 * its space.
	 */
	ledger_lock(ledger_ledger);
	if ((ledger_ledger->ledger_limit != LEDGER_ITEM_INFINITY) &&
	    (ledger_ledger->ledger_balance + sizeof(ledger_data_t) >
	     ledger_ledger->ledger_limit)) {
		ledger_unlock(ledger_ledger);
		return(KERN_RESOURCE_SHORTAGE);
	}

	*new_ledger = ledger_allocate(LEDGER_ITEM_INFINITY, ledger_ledger, parent_ledger);
	if (*new_ledger == LEDGER_NULL) {
		ledger_unlock(ledger_ledger);
		return(KERN_RESOURCE_SHORTAGE);
	}
	
	/*
	 * Now transfer the limit for the new ledger from the parent
	 */
	ledger_lock(parent_ledger);
	if (parent_ledger->ledger_limit != LEDGER_ITEM_INFINITY) {
		/* Would the existing balance exceed the new limit ? */
		if (parent_ledger->ledger_limit - transfer < parent_ledger->ledger_balance) {
			ledger_unlock(parent_ledger);
			ledger_unlock(ledger_ledger);
			return(KERN_RESOURCE_SHORTAGE);
		}
		if (parent_ledger->ledger_limit - transfer > 0)
			parent_ledger->ledger_limit -= transfer;
		else
			parent_ledger->ledger_limit = 0;
	}
	(*new_ledger)->ledger_limit = transfer;

	/* Charge the ledger against the ledger_ledger */
	ledger_ledger->ledger_balance += sizeof(ledger_data_t);
	ledger_unlock(parent_ledger);

	ledger_unlock(ledger_ledger);
	
	return(KERN_SUCCESS);
}

/*
 *	Destroy a ledger
 */
kern_return_t ledger_terminate(
			       ledger_t ledger)
{
	if (ledger == LEDGER_NULL)
		return(KERN_INVALID_ARGUMENT);
	
	/* You can't deallocate kernel ledgers */
	if (ledger == root_wired_ledger ||
	    ledger == root_paged_ledger)
		return(KERN_INVALID_LEDGER);

	/* Lock the ledger */
	ledger_lock(ledger);
	
	/* the parent ledger gets back the limit */
	ledger_lock(ledger->ledger_parent);
	if (ledger->ledger_parent->ledger_limit != LEDGER_ITEM_INFINITY) {
		assert((natural_t)(ledger->ledger_parent->ledger_limit +
				  ledger->ledger_limit) <
		       LEDGER_ITEM_INFINITY);
		ledger->ledger_parent->ledger_limit += ledger->ledger_limit;
	}
	ledger_unlock(ledger->ledger_parent);

	/*
	 * XXX The spec says that you have to destroy all objects that
	 * have been created with this ledger. Nice work eh? For now
	 * Transfer the balance to the parent and let it worry about
	 * it.
	 */
	/* XXX the parent ledger inherits the debt ?? */
	(void) ledger_enter(ledger->ledger_parent, ledger->ledger_balance);
	
	/* adjust the balance of the creation ledger */
	(void) ledger_enter(ledger->ledger_ledger, -sizeof(*ledger));

	/* delete the ledger */
	ledger_deallocate(ledger);

	return(KERN_SUCCESS);
}

/*
 *	Return the ledger limit and balance
 */
kern_return_t ledger_read(
			  ledger_t ledger,
			  ledger_item_t *balance,
			  ledger_item_t *limit)
{
	if (ledger == LEDGER_NULL)
		return(KERN_INVALID_ARGUMENT);
	
	ledger_lock(ledger);
	*balance = ledger->ledger_balance;
	*limit = ledger->ledger_limit;
	ledger_unlock(ledger);

	return(KERN_SUCCESS);
}

/*
 *	Transfer resources from a parent ledger to a child
 */
kern_return_t ledger_transfer(
			      ledger_t parent_ledger,
			      ledger_t child_ledger,
			      ledger_item_t transfer)
{
#define abs(v)	((v) > 0)?(v):-(v)
	
	ledger_t src, dest;
	ledger_item_t amount = abs(transfer);
	
	if (parent_ledger == LEDGER_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (child_ledger == LEDGER_NULL)
		return(KERN_INVALID_ARGUMENT);

	/* Must be different ledgers */
	if (parent_ledger == child_ledger)
		return(KERN_INVALID_ARGUMENT);

	if (transfer == 0)
		return(KERN_SUCCESS);
	
	ledger_lock(child_ledger);
	ledger_lock(parent_ledger);

	/* XXX Should be the parent you created it from ?? */
	if (parent_ledger != child_ledger->ledger_parent) {
		ledger_unlock(parent_ledger);
		ledger_unlock(child_ledger);
		return(KERN_INVALID_LEDGER);
	}

	if (transfer > 0) {
		dest = child_ledger;
		src = parent_ledger;
	}
	else {
		src = child_ledger;
		dest = parent_ledger;
	}

	if (src->ledger_limit != LEDGER_ITEM_INFINITY) {
		/* Would the existing balance exceed the new limit ? */
		if (src->ledger_limit - amount < src->ledger_balance) {
			ledger_unlock(parent_ledger);
			ledger_unlock(child_ledger);
			return(KERN_RESOURCE_SHORTAGE);
		}
		if (src->ledger_limit - amount > 0)
			src->ledger_limit -= amount;
		else
			src->ledger_limit = 0;
	}

	if (dest->ledger_limit != LEDGER_ITEM_INFINITY) {
		if ((natural_t)(dest->ledger_limit + amount) 
			< LEDGER_ITEM_INFINITY)
			dest->ledger_limit += amount;
		else
			dest->ledger_limit = (LEDGER_ITEM_INFINITY - 1);
	}

	ledger_unlock(parent_ledger);
	ledger_unlock(child_ledger);
	
	return(KERN_SUCCESS);
#undef abs
}

/*
 *	Routine:	convert_port_to_ledger
 *	Purpose:
 *		Convert from a port to a ledger.
 *		Doesn't consume the port ref; the ledger produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

ledger_t
convert_port_to_ledger(
		       ipc_port_t port)
{
	ledger_t ledger = LEDGER_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_LEDGER))
			ledger = (ledger_t) port->ip_kobject;
		ip_unlock(port);
	}

	return ledger;
}

/*
 *	Routine:	convert_ledger_to_port
 *	Purpose:
 *		Convert from a ledger to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_ledger_to_port(
		       ledger_t ledger)
{
	ipc_port_t port;

	port = ipc_port_make_send(ledger->ledger_self);

	return port;
}

/*
 * Copy a ledger
 */
ipc_port_t
ledger_copy(
	    ledger_t ledger)
{
	/* XXX reference counting */
	assert(ledger);
	return(ipc_port_copy_send(ledger->ledger_self));
}
