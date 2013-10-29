/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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
 * Flow Control and Feedback Advisory
 *
 * Each mbuf that is being sent out through an interface is tagged with a
 * unique 32-bit ID which will help to identify all the packets that belong
 * to a particular flow at the interface layer.  Packets carrying such ID
 * would need to be marked with PKTF_FLOW_ID.  Normally, this ID is computed
 * by the module that generates the flow.  There are 3 kinds of flow sources
 * that are currently recognized:
 *
 *	a. INPCB (INET/INET6 Protocol Control Block).  When a socket is
 *	   connected, the flow hash for the socket is computed and stored in
 *	   the PCB.  Further transmissions on the socket will cause the hash
 *	   value to be carried within the mbuf as the flow ID.
 *
 *	b. Interface.  When an interface is attached, the flow hash for the
 *	   interface is computed and stored in the ifnet.  This value is
 *	   normally ignored for most network drivers, except for those that
 *	   reside atop another driver, e.g. a virtual interface performing
 *	   encapsulation/encryption on the original packet and sending the
 *	   newly-generated packet to another interface.  Such interface needs
 *	   to associate all generated packets with the interface flow hash
 *	   value as the flow ID.
 *
 *	c. PF (Packet Filter).  When a packet goes through PF and it is not
 *	   already associated with a flow ID, PF will compute a flow hash and
 *	   store it in the packet as flow ID.  When the packet is associated
 *	   with a PF state, the state record will have the flow ID stored
 *	   within, in order to avoid recalculating the flow hash.  Although PF
 *	   is capable of generating flow IDs, it does not participate in flow
 *	   advisory, and therefore packets whose IDs are computed by PF will
 *	   not have their PKTF_FLOW_ADV packet flag set.
 *
 * Activation of flow advisory mechanism is done by setting the PKTF_FLOW_ADV
 * packet flag; because a flow ID is required, the mechanism will not take
 * place unless PKTF_FLOW_ID is set as well.  The packet must also carry one
 * of the flow source types FLOWSRC_{INPCB,IFNET} in order to identify where
 * the flow advisory notification should be delivered to.  As noted above,
 * FLOWSRC_PF does not participate in this mechanism.
 *
 * The classq module configured on the interface is responsible for exerting
 * flow control to the upper layers.  This occurs when the number of packets
 * queued for a flow reaches a limit.  The module generating the flow will
 * cease transmission until further flow advisory notice, and the flow will
 * be inserted into the classq's flow control list.
 *
 * When packets are dequeued from the classq and the number of packets for
 * a flow goes below a limit, the classq will transfer its flow control list
 * to the global fadv_list.  This will then trigger the flow advisory thread
 * to run, which will cause the flow source modules to be notified that data
 * can now be generated for those previously flow-controlled flows.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mcache.h>
#include <sys/mbuf.h>
#include <sys/proc_internal.h>
#include <sys/socketvar.h>

#include <kern/assert.h>
#include <kern/thread.h>
#include <kern/locks.h>
#include <kern/zalloc.h>

#include <netinet/in_pcb.h>
#include <net/flowadv.h>

/* Lock group and attribute for fadv_lock */
static lck_grp_t	*fadv_lock_grp;
static lck_grp_attr_t	*fadv_lock_grp_attr;
decl_lck_mtx_data(static, fadv_lock);

/* protected by fadv_lock */
static STAILQ_HEAD(fadv_head, flowadv_fcentry) fadv_list;
static thread_t fadv_thread = THREAD_NULL;
static uint32_t fadv_active;

static unsigned int fadv_zone_size;		/* size of flowadv_fcentry */
static struct zone *fadv_zone;			/* zone for flowadv_fcentry */

#define	FADV_ZONE_MAX	32			/* maximum elements in zone */
#define	FADV_ZONE_NAME	"fadv_zone"		/* zone name */

static int flowadv_thread_cont(int);
static void flowadv_thread_func(void *, wait_result_t);

void
flowadv_init(void)
{
	STAILQ_INIT(&fadv_list);

	/* Setup lock group and attribute for fadv_lock */
	fadv_lock_grp_attr = lck_grp_attr_alloc_init();
	fadv_lock_grp = lck_grp_alloc_init("fadv_lock", fadv_lock_grp_attr);
	lck_mtx_init(&fadv_lock, fadv_lock_grp, NULL);

	fadv_zone_size = P2ROUNDUP(sizeof (struct flowadv_fcentry),
	    sizeof (u_int64_t));
	fadv_zone = zinit(fadv_zone_size,
	    FADV_ZONE_MAX * fadv_zone_size, 0, FADV_ZONE_NAME);
	if (fadv_zone == NULL) {
		panic("%s: failed allocating %s", __func__, FADV_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(fadv_zone, Z_EXPAND, TRUE);
	zone_change(fadv_zone, Z_CALLERACCT, FALSE);

	if (kernel_thread_start(flowadv_thread_func, NULL, &fadv_thread) !=
	    KERN_SUCCESS) {
		panic("%s: couldn't create flow event advisory thread",
		    __func__);
		/* NOTREACHED */
	}
	thread_deallocate(fadv_thread);
}

struct flowadv_fcentry *
flowadv_alloc_entry(int how)
{
	struct flowadv_fcentry *fce;

	fce = (how == M_WAITOK) ? zalloc(fadv_zone) : zalloc_noblock(fadv_zone);
	if (fce != NULL)
		bzero(fce, fadv_zone_size);

	return (fce);
}

void
flowadv_free_entry(struct flowadv_fcentry *fce)
{
	zfree(fadv_zone, fce);
}

void
flowadv_add(struct flowadv_fclist *fcl)
{
	if (STAILQ_EMPTY(fcl))
		return;

	lck_mtx_lock_spin(&fadv_lock);

	STAILQ_CONCAT(&fadv_list, fcl);
	VERIFY(!STAILQ_EMPTY(&fadv_list));

	if (!fadv_active && fadv_thread != THREAD_NULL)
		wakeup_one((caddr_t)&fadv_list);

	lck_mtx_unlock(&fadv_lock);
}

static int
flowadv_thread_cont(int err)
{
#pragma unused(err)
	for (;;) {
		lck_mtx_assert(&fadv_lock, LCK_MTX_ASSERT_OWNED);
		while (STAILQ_EMPTY(&fadv_list)) {
			VERIFY(!fadv_active);
			(void) msleep0(&fadv_list, &fadv_lock, (PSOCK | PSPIN),
			    "flowadv_cont", 0, flowadv_thread_cont);
			/* NOTREACHED */
		}

		fadv_active = 1;
		for (;;) {
			struct flowadv_fcentry *fce;

			VERIFY(!STAILQ_EMPTY(&fadv_list));
			fce = STAILQ_FIRST(&fadv_list);
			STAILQ_REMOVE(&fadv_list, fce,
			    flowadv_fcentry, fce_link);
			STAILQ_NEXT(fce, fce_link) = NULL;

			lck_mtx_unlock(&fadv_lock);
			switch (fce->fce_flowsrc) {
			case FLOWSRC_INPCB:
				inp_flowadv(fce->fce_flowid);
				break;

			case FLOWSRC_IFNET:
				ifnet_flowadv(fce->fce_flowid);
				break;

			case FLOWSRC_PF:
			default:
				break;
			}
			flowadv_free_entry(fce);
			lck_mtx_lock_spin(&fadv_lock);

			/* if there's no pending request, we're done */
			if (STAILQ_EMPTY(&fadv_list))
				break;
		}
		fadv_active = 0;
	}
}

static void
flowadv_thread_func(void *v, wait_result_t w)
{
#pragma unused(v, w)
	lck_mtx_lock(&fadv_lock);
	(void) msleep0(&fadv_list, &fadv_lock, (PSOCK | PSPIN),
	    "flowadv", 0, flowadv_thread_cont);
	/*
	 * msleep0() shouldn't have returned as PCATCH was not set;
	 * therefore assert in this case.
	 */
	lck_mtx_unlock(&fadv_lock);
	VERIFY(0);
}
