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
 */
/*
 *	File:	kern/ipc_kobject.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions for letting a port represent a kernel object.
 */

#include <mach_debug.h>
#include <mach_ipc_test.h>
#include <mach_machine_routines.h>
#include <norma_task.h>
#include <mach_rt.h>
#include <platforms.h>

#include <mach/mig.h>
#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/notify.h>

#include <kern/etap_macros.h>
#include <kern/ipc_mig.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>
#include <kern/mk_timer.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <kern/counters.h>


/*
 *	Routine:	ipc_kobject_notify
 *	Purpose:
 *		Deliver notifications to kobjects that care about them.
 */
boolean_t
ipc_kobject_notify(
        mach_msg_header_t *request_header,
        mach_msg_header_t *reply_header);

#include <mach/ndr.h>

typedef struct {
        mach_msg_id_t num;
        mig_routine_t routine;
	int size;
#if	MACH_COUNTERS
	mach_counter_t callcount;
#endif
} mig_hash_t;

#define MAX_MIG_ENTRIES 1024
#define MIG_HASH(x) (x)

#ifndef max
#define max(a,b)        (((a) > (b)) ? (a) : (b))
#endif /* max */

mig_hash_t mig_buckets[MAX_MIG_ENTRIES];
int mig_table_max_displ;
mach_msg_size_t mig_reply_size;


#include <mach/mach_port_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/host_security_server.h>
#include <mach/clock_server.h>
#include <mach/clock_priv_server.h>
#include <mach/ledger_server.h>
#include <mach/lock_set_server.h>
#include <default_pager/default_pager_object_server.h>
#include <mach/memory_object_server.h>
#include <mach/memory_object_control_server.h>
#include <mach/memory_object_default_server.h>
#include <mach/memory_object_name_server.h>
#include <mach/processor_server.h>
#include <mach/processor_set_server.h>
#include <mach/semaphore_server.h>
#include <mach/task_server.h>
#include <mach/vm_map_server.h>
#include <mach/thread_act_server.h>
#include <device/device_server.h>
#include <UserNotification/UNDReplyServer.h>

#if     MACH_MACHINE_ROUTINES
#include <machine/machine_routines.h>
#endif	/* MACH_MACHINE_ROUTINES */
#if	XK_PROXY
#include <uk_xkern/xk_uproxy_server.h>
#endif	/* XK_PROXY */


mig_subsystem_t mig_e[] = {
        (mig_subsystem_t)&mach_port_subsystem,
        (mig_subsystem_t)&mach_host_subsystem,
        (mig_subsystem_t)&host_priv_subsystem,
        (mig_subsystem_t)&host_security_subsystem,
        (mig_subsystem_t)&clock_subsystem,
        (mig_subsystem_t)&clock_priv_subsystem,
        (mig_subsystem_t)&processor_subsystem,
        (mig_subsystem_t)&processor_set_subsystem,
        (mig_subsystem_t)&is_iokit_subsystem,
        (mig_subsystem_t)&memory_object_name_subsystem,
	(mig_subsystem_t)&lock_set_subsystem,
	(mig_subsystem_t)&ledger_subsystem,
	(mig_subsystem_t)&semaphore_subsystem,
	(mig_subsystem_t)&task_subsystem,
	(mig_subsystem_t)&thread_act_subsystem,
	(mig_subsystem_t)&vm_map_subsystem,
	(mig_subsystem_t)&UNDReply_subsystem,

#if     XK_PROXY
        (mig_subsystem_t)&do_uproxy_xk_uproxy_subsystem,
#endif /* XK_PROXY */
#if     MACH_MACHINE_ROUTINES
        (mig_subsystem_t)&MACHINE_SUBSYSTEM,
#endif  /* MACH_MACHINE_ROUTINES */
#if     MCMSG && iPSC860
	(mig_subsystem_t)&mcmsg_info_subsystem,
#endif  /* MCMSG && iPSC860 */
};

void
mig_init(void)
{
    register unsigned int i, n = sizeof(mig_e)/sizeof(mig_subsystem_t);
    register unsigned int howmany;
    register mach_msg_id_t j, pos, nentry, range;
	
    for (i = 0; i < n; i++) {
	range = mig_e[i]->end - mig_e[i]->start;
	if (!mig_e[i]->start || range < 0)
	    panic("the msgh_ids in mig_e[] aren't valid!");
	mig_reply_size = max(mig_reply_size, mig_e[i]->maxsize);

	for  (j = 0; j < range; j++) {
	  if (mig_e[i]->routine[j].stub_routine) { 
	    /* Only put real entries in the table */
	    nentry = j + mig_e[i]->start;	
	    for (pos = MIG_HASH(nentry) % MAX_MIG_ENTRIES, howmany = 1;
		 mig_buckets[pos].num;
		 pos = ++pos % MAX_MIG_ENTRIES, howmany++) {
	         if (mig_buckets[pos].num == nentry) {
		        printf("message id = %d\n", nentry);
		 	panic("multiple entries with the same msgh_id");
	         }
		 if (howmany == MAX_MIG_ENTRIES)
		       panic("the mig dispatch table is too small");
	    }
		
	    mig_buckets[pos].num = nentry;
	    mig_buckets[pos].routine = mig_e[i]->routine[j].stub_routine;
	    if (mig_e[i]->routine[j].max_reply_msg)
		    mig_buckets[pos].size = mig_e[i]->routine[j].max_reply_msg;
	    else
		    mig_buckets[pos].size = mig_e[i]->maxsize;

	    mig_table_max_displ = max(howmany, mig_table_max_displ);
	  }
	}
    }
    printf("mig_table_max_displ = %d\n", mig_table_max_displ);
}


/*
 *	Routine:	ipc_kobject_server
 *	Purpose:
 *		Handle a message sent to the kernel.
 *		Generates a reply message.
 *		Version for Untyped IPC.
 *	Conditions:
 *		Nothing locked.
 */

ipc_kmsg_t
ipc_kobject_server(
	ipc_kmsg_t	request)
{
	mach_msg_size_t reply_size;
	ipc_kmsg_t reply;
	kern_return_t kr;
	mig_routine_t routine;
	ipc_port_t *destp;
	mach_msg_format_0_trailer_t *trailer;
	register mig_hash_t *ptr;
	unsigned int th;

	/* Only fetch current thread if ETAP is configured */
	ETAP_DATA_LOAD(th, current_thread());
        ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
                        EVENT_BEGIN,
			((thread_t) th),
                        &request->ikm_header.msgh_id,
                        sizeof(int));
	/*
         * Find out corresponding mig_hash entry if any
         */
	{
	    register int key = request->ikm_header.msgh_id;
	    register int i = MIG_HASH(key);
	    register int max_iter = mig_table_max_displ;
	
	    do
		ptr = &mig_buckets[i++ % MAX_MIG_ENTRIES];
	    while (key != ptr->num && ptr->num && --max_iter);

	    if (!ptr->routine || key != ptr->num) {
	        ptr = (mig_hash_t *)0;
		reply_size = mig_reply_size;
	    } else {
		reply_size = ptr->size;
#if	MACH_COUNTER
		ptr->callcount++;
#endif
	    }
	}

	/* round up for trailer size */
        reply_size += MAX_TRAILER_SIZE;
	reply = ipc_kmsg_alloc(reply_size);

	if (reply == IKM_NULL) {
		printf("ipc_kobject_server: dropping request\n");
		ipc_kmsg_destroy(request);
		return IKM_NULL;
	}

	/*
	 * Initialize reply message.
	 */
	{
#define	InP	((mach_msg_header_t *) &request->ikm_header)
#define	OutP	((mig_reply_error_t *) &reply->ikm_header)

	    OutP->NDR = NDR_record;
	    OutP->Head.msgh_size = sizeof(mig_reply_error_t);

	    OutP->Head.msgh_bits =
		MACH_MSGH_BITS(MACH_MSGH_BITS_LOCAL(InP->msgh_bits), 0);
	    OutP->Head.msgh_remote_port = InP->msgh_local_port;
	    OutP->Head.msgh_local_port  = MACH_PORT_NULL;
	    OutP->Head.msgh_id = InP->msgh_id + 100;

#undef	InP
#undef	OutP
	}

	/*
	 * Find the routine to call, and call it
	 * to perform the kernel function
	 */
	{
	    if (ptr) {	
		(*ptr->routine)(&request->ikm_header, &reply->ikm_header);
		kernel_task->messages_received++;
	    }
	    else {
		if (!ipc_kobject_notify(&request->ikm_header, &reply->ikm_header)){
#if	MACH_IPC_TEST
		    printf("ipc_kobject_server: bogus kernel message, id=%d\n",
			request->ikm_header.msgh_id);
#endif	/* MACH_IPC_TEST */
		    _MIG_MSGID_INVALID(request->ikm_header.msgh_id);

		    ((mig_reply_error_t *) &reply->ikm_header)->RetCode
			= MIG_BAD_ID;
		}
		else
		  kernel_task->messages_received++;
	    }
	    kernel_task->messages_sent++;
	}

	/*
	 *	Destroy destination. The following code differs from
	 *	ipc_object_destroy in that we release the send-once
	 *	right instead of generating a send-once notification
	 * 	(which would bring us here again, creating a loop).
	 *	It also differs in that we only expect send or
	 *	send-once rights, never receive rights.
	 *
	 *	We set msgh_remote_port to IP_NULL so that the kmsg
	 *	destroy routines don't try to destroy the port twice.
	 */
	destp = (ipc_port_t *) &request->ikm_header.msgh_remote_port;
	switch (MACH_MSGH_BITS_REMOTE(request->ikm_header.msgh_bits)) {
		case MACH_MSG_TYPE_PORT_SEND:
		    ipc_port_release_send(*destp);
		    break;
		
		case MACH_MSG_TYPE_PORT_SEND_ONCE:
		    ipc_port_release_sonce(*destp);
		    break;
		
		default:
		    panic("ipc_kobject_server: strange destination rights");
	}
	*destp = IP_NULL;

        if (!(reply->ikm_header.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
           ((mig_reply_error_t *) &reply->ikm_header)->RetCode != KERN_SUCCESS)
	 	kr = ((mig_reply_error_t *) &reply->ikm_header)->RetCode;
	else
		kr = KERN_SUCCESS;

	if ((kr == KERN_SUCCESS) || (kr == MIG_NO_REPLY)) {
		/*
		 *	The server function is responsible for the contents
		 *	of the message.  The reply port right is moved
		 *	to the reply message, and we have deallocated
		 *	the destination port right, so we just need
		 *	to free the kmsg.
		 */
		ipc_kmsg_free(request);

	} else {
		/*
		 *	The message contents of the request are intact.
		 *	Destroy everthing except the reply port right,
		 *	which is needed in the reply message.
		 */
		request->ikm_header.msgh_local_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(request);
	}

	if (kr == MIG_NO_REPLY) {
		/*
		 *	The server function will send a reply message
		 *	using the reply port right, which it has saved.
		 */

		ipc_kmsg_free(reply);

		ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
				EVENT_END,
				((thread_t) th),
				&request->ikm_header.msgh_id,
				sizeof(int));

		return IKM_NULL;
	} else if (!IP_VALID((ipc_port_t)reply->ikm_header.msgh_remote_port)) {
		/*
		 *	Can't queue the reply message if the destination
		 *	(the reply port) isn't valid.
		 */

		ipc_kmsg_destroy(reply);

		ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
				EVENT_END,
				((thread_t) th),
				&request->ikm_header.msgh_id,
				sizeof(int));

		return IKM_NULL;
	}

 	trailer = (mach_msg_format_0_trailer_t *)
		((vm_offset_t)&reply->ikm_header + (int)reply->ikm_header.msgh_size);                
 	trailer->msgh_sender = KERNEL_SECURITY_TOKEN;
 	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
 	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;

        ETAP_PROBE_DATA(ETAP_P_SYSCALL_MACH,
                        EVENT_END,
			((thread_t) th),
                        &request->ikm_header.msgh_id,
                        sizeof(int));

	return reply;
}

/*
 *	Routine:	ipc_kobject_set
 *	Purpose:
 *		Make a port represent a kernel object of the given type.
 *		The caller is responsible for handling refs for the
 *		kernel object, if necessary.
 *	Conditions:
 *		Nothing locked.  The port must be active if setting
 *		a kobject linkage.  Clearing a linkage is OK on an
 *		inactive port.
 */
void
ipc_kobject_set(
	ipc_port_t			port,
	ipc_kobject_t		kobject,
	ipc_kobject_type_t	type)
{
	ip_lock(port);
	ipc_kobject_set_atomically(port, kobject, type);
	ip_unlock(port);
}

void
ipc_kobject_set_atomically(
	ipc_port_t			port,
	ipc_kobject_t		kobject,
	ipc_kobject_type_t	type)
{
	assert(type == IKOT_NONE || ip_active(port));
#if	MACH_ASSERT
	port->ip_spares[2] = (port->ip_bits & IO_BITS_KOTYPE);
#endif	/* MACH_ASSERT */
	port->ip_bits = (port->ip_bits &~ IO_BITS_KOTYPE) | type;
	port->ip_kobject = kobject;
}

/*
 *	Routine:	ipc_kobject_destroy
 *	Purpose:
 *		Release any kernel object resources associated
 *		with the port, which is being destroyed.
 *
 *		This should only be needed when resources are
 *		associated with a user's port.  In the normal case,
 *		when the kernel is the receiver, the code calling
 *		ipc_port_dealloc_kernel should clean up the resources.
 *	Conditions:
 *		The port is not locked, but it is dead.
 */

void
ipc_kobject_destroy(
	ipc_port_t		port)
{
	switch (ip_kotype(port)) {

	case IKOT_TIMER:
		mk_timer_port_destroy(port);
		break;

	case IKOT_NAMED_ENTRY:
		mach_destroy_memory_entry(port);
		break;

	default:	/* XXX (bogon) */
		break;
	}
}


extern int vnode_pager_workaround;

boolean_t
ipc_kobject_notify(
	mach_msg_header_t *request_header,
	mach_msg_header_t *reply_header)
{
	ipc_port_t port = (ipc_port_t) request_header->msgh_remote_port;
	mig_subsystem_t		paging_subsystem_object;
	mach_port_seqno_t	seqno;

	((mig_reply_error_t *) reply_header)->RetCode = MIG_NO_REPLY;
	switch (request_header->msgh_id) {
		case MACH_NOTIFY_NO_SENDERS:
		   if(ip_kotype(port) == IKOT_NAMED_ENTRY) {
			ip_lock(port);

			/*
			 * Bring the sequence number and mscount in
			 * line with ipc_port_destroy assertion.
			 */
			port->ip_mscount = 0;
			port->ip_messages.imq_seqno = 0;
			ipc_port_destroy(port); /* releases lock */
			return TRUE;
		   }
		   if (ip_kotype(port) == IKOT_UPL) {
			   upl_no_senders(
				(ipc_port_t)request_header->msgh_remote_port, 
				(mach_port_mscount_t) 
				((mach_no_senders_notification_t *) 
				 request_header)->not_count);
			   (ipc_port_t)reply_header->msgh_remote_port
				   = MACH_PORT_NULL;
			   return TRUE;
		   }
				
	  	   break;

		case MACH_NOTIFY_PORT_DELETED:
		case MACH_NOTIFY_PORT_DESTROYED:
		case MACH_NOTIFY_SEND_ONCE:
		case MACH_NOTIFY_DEAD_NAME:
		break;

		default:
		return FALSE;
	}
	switch (ip_kotype(port)) {

#ifdef IOKIT
		case IKOT_IOKIT_OBJECT:
		case IKOT_IOKIT_CONNECT:
		case IKOT_IOKIT_SPARE:
		{
                extern boolean_t iokit_notify( mach_msg_header_t *msg);

                return iokit_notify(request_header);
		}
#endif
		default:
                return FALSE;
        }
}



#include <mach_kdb.h>
#if	MACH_COUNTERS && MACH_KDB

#include <ddb/db_output.h>
#include <ddb/db_sym.h>

#define printf  kdbprintf

extern void kobjserver_stats(void);
extern void bucket_stats_print(mig_hash_t *bucket);

extern void kobjserver_stats_clear(void);


void
kobjserver_stats_clear(void)
{
	int i;
	for (i = 0; i < MAX_MIG_ENTRIES; i++) {
		mig_buckets[i].callcount = 0;
	}
}

void
kobjserver_stats(void)
{
    register unsigned int i, n = sizeof(mig_e)/sizeof(mig_subsystem_t);
    register unsigned int howmany;
    register mach_msg_id_t j, pos, nentry, range;
	
    db_printf("Kobject server call counts:\n");
    for (i = 0; i < n; i++) {
	db_printf("  ");
	db_printsym((vm_offset_t)mig_e[i], DB_STGY_ANY);
	db_printf(":\n");
	range = mig_e[i]->end - mig_e[i]->start;
	if (!mig_e[i]->start || range < 0) continue;

	for  (j = 0; j < range; j++) {
	    nentry = j + mig_e[i]->start;	
	    for (pos = MIG_HASH(nentry) % MAX_MIG_ENTRIES, howmany = 1;
		 mig_buckets[pos].num;
		 pos = ++pos % MAX_MIG_ENTRIES, howmany++) {
		    if (mig_buckets[pos].num == nentry)
			bucket_stats_print(&mig_buckets[pos]);
	    }
	}
    }
}

void
bucket_stats_print(mig_hash_t *bucket)
{
	if (bucket->callcount) {
		db_printf("    ");
		db_printsym((vm_offset_t)bucket->routine, DB_STGY_ANY);
		db_printf(" (%d):\t%d\n", bucket->num, bucket->callcount);
	}
}


#endif	/* MACH_COUNTERS && MACH_KDB */
