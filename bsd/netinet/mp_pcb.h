/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#ifndef _NETINET_MP_PCB_H_
#define	_NETINET_MP_PCB_H_

#ifdef BSD_KERNEL_PRIVATE
#include <sys/types.h>
#include <sys/queue.h>
#include <kern/locks.h>

/* Keep in sync with bsd/dev/dtrace/scripts/mptcp.d */
typedef enum mppcb_state {
	MPPCB_STATE_INUSE	= 1,
	MPPCB_STATE_DEAD	= 2,
} mppcb_state_t;

/*
 * Multipath Protocol Control Block
 */
struct mppcb {
	TAILQ_ENTRY(mppcb)	mpp_entry;	/* glue to all PCBs */
	decl_lck_mtx_data(, mpp_lock);		/* per PCB lock */
	struct mppcbinfo	*mpp_pcbinfo;	/* PCB info */
	void			*mpp_pcbe;	/* ptr to per-protocol ext */
	struct socket		*mpp_socket;	/* back pointer to socket */
	uint32_t		mpp_flags;	/* PCB flags */
	mppcb_state_t		mpp_state;	/* PCB state */
};

#define	sotomppcb(so)	((struct mppcb *)((so)->so_pcb))

/* valid values for mpp_flags */
#define	MPP_ATTACHED	0x1
#define MPP_DEFUNCT	0x2

/*
 * Multipath PCB Information
 */
struct mppcbinfo {
	TAILQ_ENTRY(mppcbinfo)	mppi_entry;	/* glue to all PCB info */
	TAILQ_HEAD(, mppcb)	mppi_pcbs;	/* list of PCBs */
	uint32_t		mppi_count;	/* # of PCBs in list */
	struct zone		*mppi_zone;	/* zone for this PCB */
	uint32_t		mppi_size;	/* size of PCB structure */
	lck_grp_t		*mppi_lock_grp;	/* lock grp */
	lck_attr_t		*mppi_lock_attr; /* lock attr */
	lck_grp_attr_t		*mppi_lock_grp_attr; /* lock grp attr */
	decl_lck_mtx_data(, mppi_lock);		/* global PCB lock */
	uint32_t (*mppi_gc)(struct mppcbinfo *); /* garbage collector func */
	uint32_t (*mppi_timer)(struct mppcbinfo *); /* timer func */
	/* Extended pcb create func */
	void *(*mppi_pcbe_create) (struct socket *mp_so, struct mppcb *mpp);
};

__BEGIN_DECLS
extern void mp_pcbinit(void);
extern void mp_pcbinfo_attach(struct mppcbinfo *);
extern int mp_pcbinfo_detach(struct mppcbinfo *);
extern int mp_pcballoc(struct socket *, struct mppcbinfo *);
extern void mp_pcbdetach(struct mppcb *);
extern void mp_pcbdispose(struct mppcb *);
extern void mp_gc_sched(void);
extern void mptcp_timer_sched(void);
__END_DECLS

#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_NETINET_MP_PCB_H_ */
