/*
 * Copyright (c) 1999-2008 Apple Inc. All rights reserved.
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
 *	Data Link Inteface Layer
 *	Author: Ted Walker
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/user.h>
#include <sys/random.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_var.h>
#include <net/dlil.h>
#include <net/if_arp.h>
#include <sys/kern_event.h>
#include <sys/kdebug.h>

#include <kern/assert.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <net/kpi_protocol.h>

#include <net/if_types.h>
#include <net/kpi_interfacefilter.h>

#include <libkern/OSAtomic.h>

#include <machine/machine_routines.h>

#include <mach/thread_act.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#if PF
#include <net/pfvar.h>
#endif /* PF */

#define DBG_LAYER_BEG			DLILDBG_CODE(DBG_DLIL_STATIC, 0)
#define DBG_LAYER_END			DLILDBG_CODE(DBG_DLIL_STATIC, 2)
#define DBG_FNC_DLIL_INPUT      DLILDBG_CODE(DBG_DLIL_STATIC, (1 << 8))
#define DBG_FNC_DLIL_OUTPUT     DLILDBG_CODE(DBG_DLIL_STATIC, (2 << 8))
#define DBG_FNC_DLIL_IFOUT      DLILDBG_CODE(DBG_DLIL_STATIC, (3 << 8))


#define MAX_FRAME_TYPE_SIZE 4 /* LONGWORDS */
#define MAX_LINKADDR	    4 /* LONGWORDS */
#define M_NKE M_IFADDR

#if 1
#define DLIL_PRINTF	printf
#else
#define DLIL_PRINTF	kprintf
#endif


enum {
	kProtoKPI_v1	= 1,
	kProtoKPI_v2	= 2
};

struct if_proto {
    SLIST_ENTRY(if_proto)	 next_hash;
    int						 refcount;
    int						 detaching;
    struct ifnet			 *ifp;
    struct domain			 *dl_domain;
    protocol_family_t		protocol_family;
    int						proto_kpi;
    union {
		struct {
			proto_media_input			input;
			proto_media_preout			pre_output;
			proto_media_event			event;
			proto_media_ioctl			ioctl;
			proto_media_detached		detached;
			proto_media_resolve_multi	resolve_multi;
			proto_media_send_arp		send_arp;
		} v1;
		struct {
			proto_media_input_v2		input;
			proto_media_preout			pre_output;
			proto_media_event			event;
			proto_media_ioctl			ioctl;
			proto_media_detached		detached;
			proto_media_resolve_multi	resolve_multi;
			proto_media_send_arp		send_arp;
		} v2;
	} kpi;
};

SLIST_HEAD(proto_hash_entry, if_proto);


struct dlil_ifnet {
    /* ifnet and drvr_ext are used by the stack and drivers
    drvr_ext extends the public ifnet and must follow dl_if */
    struct ifnet	dl_if;			/* public ifnet */
    
    /* dlil private fields */
    TAILQ_ENTRY(dlil_ifnet) dl_if_link;	/* dlil_ifnet are link together */
    								/* it is not the ifnet list */
    void		*if_uniqueid;	/* unique id identifying the interface */
    size_t		if_uniqueid_len;/* length of the unique id */
    char		if_namestorage[IFNAMSIZ]; /* interface name storage */
};

struct ifnet_filter {
	TAILQ_ENTRY(ifnet_filter)	filt_next;
    ifnet_t						filt_ifp;
    int							filt_detaching;
    
	const char					*filt_name;
	void						*filt_cookie;
    protocol_family_t			filt_protocol;
    iff_input_func				filt_input;
    iff_output_func				filt_output;
    iff_event_func				filt_event;
    iff_ioctl_func				filt_ioctl;
    iff_detached_func			filt_detached;
};

struct proto_input_entry;

static TAILQ_HEAD(, dlil_ifnet) dlil_ifnet_head;
static lck_grp_t *dlil_lock_group;
static lck_grp_t *ifnet_lock_group;
static lck_grp_t *ifnet_head_lock_group;
static lck_attr_t *ifnet_lock_attr;
static lck_rw_t *ifnet_head_mutex;
static lck_mtx_t *dlil_ifnet_mutex;
static lck_mtx_t *dlil_mutex;
static u_int32_t dlil_read_count = 0;
static u_int32_t dlil_detach_waiting = 0;
u_int32_t dlil_filter_count = 0;
extern u_int32_t	ipv4_ll_arp_aware;

static struct dlil_threading_info dlil_lo_thread;
__private_extern__  struct dlil_threading_info *dlil_lo_thread_ptr = &dlil_lo_thread;

static struct mbuf *dlil_lo_input_mbuf_head = NULL;
static struct mbuf *dlil_lo_input_mbuf_tail = NULL;

#if IFNET_INPUT_SANITY_CHK
static int dlil_lo_input_mbuf_count = 0;
int dlil_input_sanity_check = 0;	/* sanity checking of input packet lists received */
#endif
int dlil_multithreaded_input = 1;
static int cur_dlil_input_threads = 0; 

static int dlil_event_internal(struct ifnet *ifp, struct kev_msg *msg);
static int dlil_detach_filter_internal(interface_filter_t filter, int detached);
static void dlil_call_delayed_detach_thread(void);

static void	dlil_read_begin(void);
static __inline__ void	dlil_read_end(void);
static int	dlil_write_begin(void);
static void	dlil_write_end(void);

#if DEBUG
__private_extern__ int dlil_verbose = 1;
#else
__private_extern__ int dlil_verbose = 0;
#endif /* DEBUG */

unsigned int net_affinity = 1;
static kern_return_t dlil_affinity_set(struct thread *, u_int32_t);

extern void bpfdetach(struct ifnet*);
extern void proto_input_run(void); // new run_netisr

void dlil_input_packet_list(struct ifnet  *ifp, struct mbuf *m);
static void dlil_input_thread_func(struct dlil_threading_info *inpthread); 
__private_extern__ int dlil_create_input_thread(
		ifnet_t, struct dlil_threading_info *);
__private_extern__ void dlil_terminate_input_thread(
		struct dlil_threading_info *);

__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);

int dlil_expand_mcl;

extern u_int32_t	inject_buckets;

static const u_int32_t dlil_writer_waiting = 0x80000000;
static	lck_grp_attr_t	*dlil_grp_attributes = NULL;
static	lck_attr_t	*dlil_lck_attributes = NULL;
static	lck_grp_t	*dlil_input_lock_grp = NULL;

static inline void*
_cast_non_const(const void * ptr) {
	union {
		const void*		cval;
		void*			val;
	} ret;
	
	ret.cval = ptr;
	return (ret.val);
}

/* Should these be inline? */
static void
dlil_read_begin(void)
{
	u_int32_t new_value;
	u_int32_t old_value;
	struct uthread *uth = get_bsdthread_info(current_thread());
	
	if (uth->dlil_incremented_read == dlil_writer_waiting)
		panic("dlil_read_begin - thread is already a writer");
	
	do {
again:
		old_value = dlil_read_count;
		
		if ((old_value & dlil_writer_waiting) != 0 && uth->dlil_incremented_read == 0)
		{
			tsleep(&dlil_read_count, PRIBIO, "dlil_read_count", 1);
			goto again;
		}
		
		new_value = old_value + 1;
	} while (!OSCompareAndSwap((UInt32)old_value, (UInt32)new_value, (UInt32*)&dlil_read_count));
	
	uth->dlil_incremented_read++;
}

static void
dlil_read_end(void)
{
	struct uthread *uth = get_bsdthread_info(current_thread());
	
	OSDecrementAtomic(&dlil_read_count);
	uth->dlil_incremented_read--;
	if (dlil_read_count == dlil_writer_waiting)
		wakeup(_cast_non_const(&dlil_writer_waiting));
}

static int
dlil_write_begin(void)
{
	struct uthread *uth = get_bsdthread_info(current_thread());
	
	if (uth->dlil_incremented_read != 0) {
		return EDEADLK;
	}
	lck_mtx_lock(dlil_mutex);
	OSBitOrAtomic((UInt32)dlil_writer_waiting, &dlil_read_count);
again:
	if (dlil_read_count == dlil_writer_waiting) {
		uth->dlil_incremented_read = dlil_writer_waiting;
		return 0;
	}
	else {
		tsleep(_cast_non_const(&dlil_writer_waiting), PRIBIO, "dlil_writer_waiting", 1);
		goto again;
	}
}

static void
dlil_write_end(void)
{
	struct uthread *uth = get_bsdthread_info(current_thread());
	
	if (uth->dlil_incremented_read != dlil_writer_waiting)
		panic("dlil_write_end - thread is not a writer");
	OSBitAndAtomic((UInt32)~dlil_writer_waiting, &dlil_read_count);
	lck_mtx_unlock(dlil_mutex);
	uth->dlil_incremented_read = 0;
	wakeup(&dlil_read_count);
}

#define PROTO_HASH_SLOTS	0x5

/*
 * Internal functions.
 */

static int
proto_hash_value(u_int32_t protocol_family)
{
	/*
	 * dlil_proto_unplumb_all() depends on the mapping between
	 * the hash bucket index and the protocol family defined
	 * here; future changes must be applied there as well.
	 */
	switch(protocol_family) {
		case PF_INET:
			return 0;
		case PF_INET6:
			return 1;
		case PF_APPLETALK:
			return 2;
		case PF_VLAN:
			return 3;
		default:
			return 4;
	}
}

static struct if_proto*
find_attached_proto(struct ifnet *ifp, u_int32_t protocol_family)
{
	struct if_proto *proto = NULL;
	u_int32_t i = proto_hash_value(protocol_family);
	if (ifp->if_proto_hash) {
		proto = SLIST_FIRST(&ifp->if_proto_hash[i]);
	}
	
	while(proto && proto->protocol_family != protocol_family) {
		proto = SLIST_NEXT(proto, next_hash);
	}
	
	return proto;
}

static void
if_proto_ref(struct if_proto *proto)
{
	OSAddAtomic(1, &proto->refcount);
}

static void
if_proto_free(struct if_proto *proto)
{
	int oldval = OSAddAtomic(-1, &proto->refcount);
	
	if (oldval == 1) { /* This was the last reference */
		FREE(proto, M_IFADDR);
	}
}

__private_extern__ void
ifnet_lock_assert(
	__unused struct ifnet *ifp,
	__unused int what)
{
#if IFNET_RW_LOCK
	/*
	 * Not implemented for rw locks.
	 *
	 * Function exists so when/if we use mutex we can
	 * enable this check.
	 */
#else
	lck_mtx_assert(ifp->if_lock, what);
#endif
}

__private_extern__ void
ifnet_lock_shared(
	struct ifnet *ifp)
{
#if IFNET_RW_LOCK
	lck_rw_lock_shared(ifp->if_lock);
#else
	lck_mtx_assert(ifp->if_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(ifp->if_lock);
#endif
}

__private_extern__ void
ifnet_lock_exclusive(
	struct ifnet *ifp)
{
#if IFNET_RW_LOCK
	lck_rw_lock_exclusive(ifp->if_lock);
#else
	lck_mtx_assert(ifp->if_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(ifp->if_lock);
#endif
}

__private_extern__ void
ifnet_lock_done(
	struct ifnet *ifp)
{
#if IFNET_RW_LOCK
	lck_rw_done(ifp->if_lock);
#else
	lck_mtx_assert(ifp->if_lock, LCK_MTX_ASSERT_OWNED);
	lck_mtx_unlock(ifp->if_lock);
#endif
}

__private_extern__ void
ifnet_head_lock_shared(void)
{
	lck_rw_lock_shared(ifnet_head_mutex);
}

__private_extern__ void
ifnet_head_lock_exclusive(void)
{
	lck_rw_lock_exclusive(ifnet_head_mutex);
}

__private_extern__ void
ifnet_head_done(void)
{
	lck_rw_done(ifnet_head_mutex);
}

static int dlil_ifp_proto_count(struct ifnet * ifp) 
{
	int				count = 0;
	int				i;
	
	if (ifp->if_proto_hash != NULL) {	
		for (i = 0; i < PROTO_HASH_SLOTS; i++) {
			struct if_proto *proto;
			SLIST_FOREACH(proto, &ifp->if_proto_hash[i], next_hash) {
				count++;
			}
		}
	}
	
	return count;
}

__private_extern__ void
dlil_post_msg(struct ifnet *ifp, u_int32_t event_subclass, u_int32_t event_code, 
		   struct net_event_data *event_data, u_int32_t event_data_len) 
{
	struct net_event_data  	ev_data;
	struct kev_msg  		ev_msg;
	
	/* 
	 * a net event always starts with a net_event_data structure
	 * but the caller can generate a simple net event or
	 * provide a longer event structure to post
	 */
	
	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass   = event_subclass;
	ev_msg.event_code 	  = event_code;    
	
	if (event_data == 0) {
		event_data = &ev_data;
		event_data_len = sizeof(struct net_event_data);
	}
	
	strncpy(&event_data->if_name[0], ifp->if_name, IFNAMSIZ);
	event_data->if_family = ifp->if_family;
	event_data->if_unit   = (u_int32_t) ifp->if_unit;
	
	ev_msg.dv[0].data_length = event_data_len;
	ev_msg.dv[0].data_ptr    = event_data;	
	ev_msg.dv[1].data_length = 0;
	
	dlil_event_internal(ifp, &ev_msg);
}

__private_extern__ int
dlil_create_input_thread(
	ifnet_t ifp, struct dlil_threading_info *inputthread)
{
	int error;

	bzero(inputthread, sizeof(*inputthread));
	// loopback ifp may not be configured at dlil_init time.
	if (ifp == lo_ifp)
		strlcat(inputthread->input_name, "dlil_input_main_thread_mtx", 32);
	else
		snprintf(inputthread->input_name, 32, "dlil_input_%s%d_mtx", ifp->if_name, ifp->if_unit);	

	inputthread->lck_grp = lck_grp_alloc_init(inputthread->input_name, dlil_grp_attributes);
	inputthread->input_lck  = lck_mtx_alloc_init(inputthread->lck_grp, dlil_lck_attributes);

	error= kernel_thread_start((thread_continue_t)dlil_input_thread_func, inputthread, &inputthread->input_thread);
	if (error == 0) {
       		ml_thread_policy(inputthread->input_thread, MACHINE_GROUP,
				 (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_NETISR));
		/*
		 * Except for the loopback dlil input thread, we create
		 * an affinity set so that the matching workloop thread
		 * can be scheduled on the same processor set.
		 */
		if (net_affinity && inputthread != dlil_lo_thread_ptr) {
			struct thread *tp = inputthread->input_thread;
			u_int32_t tag;
			/*
			 * Randomize to reduce the probability
			 * of affinity tag namespace collision.
			 */
			read_random(&tag, sizeof (tag));
			if (dlil_affinity_set(tp, tag) == KERN_SUCCESS) {
				thread_reference(tp);
				inputthread->tag = tag;
				inputthread->net_affinity = TRUE;
			}
		}
	} else {
		panic("dlil_create_input_thread: couldn't create thread\n");
	}
	OSAddAtomic(1, &cur_dlil_input_threads);
#if DLIL_DEBUG
	printf("dlil_create_input_thread: threadinfo: %p input_thread=%p threads: cur=%d max=%d\n", 
		inputthread, inputthread->input_thread, dlil_multithreaded_input, cur_dlil_input_threads);
#endif
	return error;
}
__private_extern__ void
dlil_terminate_input_thread(
	struct dlil_threading_info *inputthread)
{
	OSAddAtomic(-1, &cur_dlil_input_threads);

	lck_mtx_unlock(inputthread->input_lck);
	lck_mtx_free(inputthread->input_lck, inputthread->lck_grp);
	lck_grp_free(inputthread->lck_grp);

	FREE(inputthread, M_NKE);

	/* For the extra reference count from kernel_thread_start() */
	thread_deallocate(current_thread());

	thread_terminate(current_thread());
}

static kern_return_t
dlil_affinity_set(struct thread *tp, u_int32_t tag)
{
	thread_affinity_policy_data_t policy;

	bzero(&policy, sizeof (policy));
	policy.affinity_tag = tag;
	return (thread_policy_set(tp, THREAD_AFFINITY_POLICY,
	    (thread_policy_t)&policy, THREAD_AFFINITY_POLICY_COUNT));
}

void
dlil_init(void)
{
	thread_t		thread = THREAD_NULL;

	PE_parse_boot_argn("net_affinity", &net_affinity, sizeof (net_affinity));
	
	TAILQ_INIT(&dlil_ifnet_head);
	TAILQ_INIT(&ifnet_head);
	
	/* Setup the lock groups we will use */
	dlil_grp_attributes = lck_grp_attr_alloc_init();

	dlil_lock_group = lck_grp_alloc_init("dlil internal locks", dlil_grp_attributes);
	ifnet_lock_group = lck_grp_alloc_init("ifnet locks", dlil_grp_attributes);
	ifnet_head_lock_group = lck_grp_alloc_init("ifnet head lock", dlil_grp_attributes);
	dlil_input_lock_grp = lck_grp_alloc_init("dlil input lock", dlil_grp_attributes);
	
	/* Setup the lock attributes we will use */
	dlil_lck_attributes = lck_attr_alloc_init();
	
	ifnet_lock_attr = lck_attr_alloc_init();
	
	
	ifnet_head_mutex = lck_rw_alloc_init(ifnet_head_lock_group, dlil_lck_attributes);
	dlil_ifnet_mutex = lck_mtx_alloc_init(dlil_lock_group, dlil_lck_attributes);
	dlil_mutex = lck_mtx_alloc_init(dlil_lock_group, dlil_lck_attributes);
	
	lck_attr_free(dlil_lck_attributes);
	dlil_lck_attributes = NULL;
	
	/*
	 * Create and start up the first dlil input thread once everything is initialized
	 */
	dlil_create_input_thread(0, dlil_lo_thread_ptr);

	(void) kernel_thread_start((thread_continue_t)dlil_call_delayed_detach_thread, NULL, &thread);
	thread_deallocate(thread);
#if PF
	/* Initialize the packet filter */
	pfinit();
#endif /* PF */
}

__private_extern__ int
dlil_attach_filter(
	struct ifnet			*ifp,
	const struct iff_filter	*if_filter,
	interface_filter_t		*filter_ref)
{
    int retval = 0;
    struct ifnet_filter	*filter;
    
	MALLOC(filter, struct ifnet_filter *, sizeof(*filter), M_NKE, M_WAITOK);
	if (filter == NULL)
		return ENOMEM;
	bzero(filter, sizeof(*filter));

    
	filter->filt_ifp = ifp;
	filter->filt_cookie = if_filter->iff_cookie;
	filter->filt_name = if_filter->iff_name;
	filter->filt_protocol = if_filter->iff_protocol;
	filter->filt_input = if_filter->iff_input;
	filter->filt_output = if_filter->iff_output;
	filter->filt_event = if_filter->iff_event;
	filter->filt_ioctl = if_filter->iff_ioctl;
	filter->filt_detached = if_filter->iff_detached;
	
	if ((retval = dlil_write_begin()) != 0) {
		/* Failed to acquire the write lock */
		FREE(filter, M_NKE);
		return retval;
	}
	TAILQ_INSERT_TAIL(&ifp->if_flt_head, filter, filt_next);
	dlil_write_end();
	*filter_ref = filter;

	/*
	 * Bump filter count and route_generation ID to let TCP
	 * know it shouldn't do TSO on this connection
	 */
	OSAddAtomic(1, &dlil_filter_count);
	if (use_routegenid)
		routegenid_update();

	return retval;
}

static int
dlil_detach_filter_internal(
	interface_filter_t	filter,
	int					detached)
{
	int retval = 0;
	
	if (detached == 0) {
		ifnet_t				ifp = NULL;
		interface_filter_t	entry = NULL;

		/* Take the write lock */
	 	retval = dlil_write_begin();
	 	if (retval != 0 && retval != EDEADLK)
	 		return retval;
	 	
	 	/*
	 	 * At this point either we have the write lock (retval == 0)
	 	 * or we couldn't get it (retval == EDEADLK) because someone
	 	 * else up the stack is holding the read lock. It is safe to
	 	 * read, either the read or write is held. Verify the filter
	 	 * parameter before proceeding.
	 	 */
		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			TAILQ_FOREACH(entry, &ifp->if_flt_head, filt_next) {
				if (entry == filter)
					break;
			}
			if (entry == filter)
				break;
		}
		ifnet_head_done();
		
		if (entry != filter) {
			/* filter parameter is not a valid filter ref */
			if (retval == 0) {
				dlil_write_end();
			}
			return EINVAL;
		}
		
		if (retval == EDEADLK) {
			/* Perform a delayed detach */
			filter->filt_detaching = 1;
			dlil_detach_waiting = 1;
			wakeup(&dlil_detach_waiting);
			return 0;
		}
		
		/* Remove the filter from the list */
		TAILQ_REMOVE(&ifp->if_flt_head, filter, filt_next);
		dlil_write_end();
	}
	
	/* Call the detached funciton if there is one */
	if (filter->filt_detached)
		filter->filt_detached(filter->filt_cookie, filter->filt_ifp);

	/* Free the filter */
	FREE(filter, M_NKE);
	
	/*
	 * Decrease filter count and route_generation ID to let TCP
	 * know it should reevalute doing TSO or not
	 */
	OSAddAtomic(-1, &dlil_filter_count);
	if (use_routegenid)
		routegenid_update();

	return retval;
}

__private_extern__ void
dlil_detach_filter(interface_filter_t filter)
{
	if (filter == NULL)
		return;
	dlil_detach_filter_internal(filter, 0);
}

static void
dlil_input_thread_func(
	struct dlil_threading_info *inputthread)
{
	while (1) {
		struct mbuf *m = NULL, *m_loop = NULL;
#if IFNET_INPUT_SANITY_CHK
		int		loop_cnt = 0, mbuf_cnt;
		int		count;
		struct mbuf *m1;
#endif /* IFNET_INPUT_SANITY_CHK */
		
		lck_mtx_lock(inputthread->input_lck);
		
		/* Wait until there is work to be done */
		while ((inputthread->input_waiting & ~DLIL_INPUT_RUNNING) == 0) {
			inputthread->input_waiting &= ~DLIL_INPUT_RUNNING;
			msleep(&inputthread->input_waiting, inputthread->input_lck, 0, inputthread->input_name, 0);
		}

	
		lck_mtx_assert(inputthread->input_lck, LCK_MTX_ASSERT_OWNED);

		m = inputthread->mbuf_head;
		inputthread->mbuf_head = NULL;
		inputthread->mbuf_tail = NULL;

		if (inputthread->input_waiting & DLIL_INPUT_TERMINATE) {
				if (m)
					mbuf_freem_list(m);
				/* this is the end */
				dlil_terminate_input_thread(inputthread);
				return;
		}

		inputthread->input_waiting |= DLIL_INPUT_RUNNING;
		inputthread->input_waiting &= ~DLIL_INPUT_WAITING;

		if (inputthread == dlil_lo_thread_ptr) {
			m_loop = dlil_lo_input_mbuf_head;
			dlil_lo_input_mbuf_head = NULL;
			dlil_lo_input_mbuf_tail = NULL;
		}

#if IFNET_INPUT_SANITY_CHK
		if (dlil_input_sanity_check != 0) {
			mbuf_cnt = inputthread->mbuf_count;
			inputthread->mbuf_count = 0;
			if (inputthread == dlil_lo_thread_ptr) {
				loop_cnt = dlil_lo_input_mbuf_count;
				dlil_lo_input_mbuf_count = 0;
			}
		
			lck_mtx_unlock(inputthread->input_lck);
		
			for (m1 = m, count = 0; m1; m1 = mbuf_nextpkt(m1)) {
				count++;
			}
			if (count != mbuf_cnt) {
				panic("dlil_input_func - thread=%p reg. loop queue has %d packets, should have %d\n",
					  inputthread, count, mbuf_cnt);
			}
	
			if (inputthread == dlil_lo_thread_ptr) {
				for (m1 = m_loop, count = 0; m1; m1 = mbuf_nextpkt(m1)) {
					count++;
				}
				if (count != loop_cnt) {
					panic("dlil_input_func - thread=%p loop queue has %d packets, should have %d\n",
					  inputthread, count, loop_cnt);
				}
			}
		} else 
#endif /* IFNET_INPUT_SANITY_CHK */
		{
			lck_mtx_unlock(inputthread->input_lck);
		}


		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation safeguards if 
		* we deal with long chains of packets.
		*/
		if (m_loop) {
			if (inputthread == dlil_lo_thread_ptr)
				dlil_input_packet_list(lo_ifp, m_loop);
#if IFNET_INPUT_SANITY_CHK
			else
				panic("dlil_input_func - thread=%p loop queue has %d packets, should have none!\n",
				  inputthread, loop_cnt);
#endif /* IFNET_INPUT_SANITY_CHK */
		}


		if (m)
			dlil_input_packet_list(0, m);


		lck_mtx_lock(inputthread->input_lck);

		if ((inputthread->input_waiting & (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER)) != 0)  {
			lck_mtx_unlock(inputthread->input_lck);
			proto_input_run();
		}	
		else	
			lck_mtx_unlock(inputthread->input_lck);
	}
}

errno_t
ifnet_input(
	ifnet_t									ifp,
	mbuf_t									m_head,
	const struct ifnet_stat_increment_param	*stats)
{
	struct thread *tp = current_thread();
	mbuf_t		m_tail;
	struct dlil_threading_info *inp;
#if IFNET_INPUT_SANITY_CHK
	u_int32_t	pkt_count = 0;
#endif /* IFNET_INPUT_SANITY_CHK */

	if (ifp == NULL || m_head == NULL) {
		if (m_head)
			mbuf_freem_list(m_head);
		return EINVAL;
	}

	m_tail = m_head;
	while (1) {
#if IFNET_INPUT_SANITY_CHK
		if (dlil_input_sanity_check != 0) {
			ifnet_t	rcvif;
		
			rcvif = mbuf_pkthdr_rcvif(m_tail);
			pkt_count++;
		
			if (rcvif == NULL ||
				(ifp->if_type != IFT_LOOP && rcvif != ifp) ||
				(mbuf_flags(m_head) & MBUF_PKTHDR) == 0) {
				panic("ifnet_input - invalid mbuf %p\n", m_tail);
			}
		}
#endif /* IFNET_INPUT_SANITY_CHK */
		if (mbuf_nextpkt(m_tail) == NULL)
			break;
		m_tail = mbuf_nextpkt(m_tail);
	}

	inp = ifp->if_input_thread;

	if (dlil_multithreaded_input == 0 || inp == NULL) 
		inp = dlil_lo_thread_ptr;

	/*
	 * If there is a matching dlil input thread associated with an
	 * affinity set, associate this workloop thread with the same set.
	 * We will only do this once.
	 */
	lck_mtx_lock(inp->input_lck);
	if (inp->net_affinity && inp->workloop_thread == NULL) {
		u_int32_t tag = inp->tag;
		inp->workloop_thread = tp;
		lck_mtx_unlock(inp->input_lck);

		/* Associated the current thread with the new affinity tag */
		(void) dlil_affinity_set(tp, tag);

		/*
		 * Take a reference on the workloop (current) thread; during
		 * detach, we will need to refer to it in order ot tear down
		 * its affinity.
		 */
		thread_reference(tp);
		lck_mtx_lock(inp->input_lck);
	}

        /* WARNING
	 * Because of loopbacked multicast we cannot stuff the ifp in
	 * the rcvif of the packet header: loopback has its own dlil
	 * input queue
	 */

	if (inp == dlil_lo_thread_ptr && ifp->if_type == IFT_LOOP) {
		if (dlil_lo_input_mbuf_head == NULL)
			dlil_lo_input_mbuf_head = m_head;
		else if (dlil_lo_input_mbuf_tail != NULL)
			dlil_lo_input_mbuf_tail->m_nextpkt = m_head;
		dlil_lo_input_mbuf_tail = m_tail;
#if IFNET_INPUT_SANITY_CHK
		if (dlil_input_sanity_check != 0) {
			dlil_lo_input_mbuf_count += pkt_count;
			inp->input_mbuf_cnt += pkt_count;
			inp->input_wake_cnt++;

			lck_mtx_assert(inp->input_lck, LCK_MTX_ASSERT_OWNED);
		}
#endif
	}
	else {
		if (inp->mbuf_head == NULL)
			inp->mbuf_head = m_head;
		else if (inp->mbuf_tail != NULL)
			inp->mbuf_tail->m_nextpkt = m_head;
		inp->mbuf_tail = m_tail;
#if IFNET_INPUT_SANITY_CHK
		if (dlil_input_sanity_check != 0) {
			inp->mbuf_count += pkt_count;
			inp->input_mbuf_cnt += pkt_count;
			inp->input_wake_cnt++;

			lck_mtx_assert(inp->input_lck, LCK_MTX_ASSERT_OWNED);
		}
#endif
	}


	inp->input_waiting |= DLIL_INPUT_WAITING;
	if ((inp->input_waiting & DLIL_INPUT_RUNNING) == 0) {
		wakeup((caddr_t)&inp->input_waiting);
	}
	if (stats) {
		ifp->if_data.ifi_ipackets += stats->packets_in;
		ifp->if_data.ifi_ibytes += stats->bytes_in;
		ifp->if_data.ifi_ierrors += stats->errors_in;
	
		ifp->if_data.ifi_opackets += stats->packets_out;
		ifp->if_data.ifi_obytes += stats->bytes_out;
		ifp->if_data.ifi_oerrors += stats->errors_out;
	
		ifp->if_data.ifi_collisions += stats->collisions;
		ifp->if_data.ifi_iqdrops += stats->dropped;
	}

	lck_mtx_unlock(inp->input_lck);
	
	return 0; 
}

static int
dlil_interface_filters_input(struct ifnet * ifp, struct mbuf * * m_p,
			     char * * frame_header_p,
			     protocol_family_t protocol_family)
{
	struct ifnet_filter * 		filter;

	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		int result;

		if (filter->filt_input 
		    && (filter->filt_protocol == 0
			|| filter->filt_protocol == protocol_family)) {
			result = (*filter->filt_input)(filter->filt_cookie,
						       ifp, protocol_family,
						       m_p, frame_header_p);
			if (result != 0) {
				return (result);
			}
		}
	}
	return (0);
}

static void
dlil_ifproto_input(struct if_proto * ifproto, mbuf_t m)
{
	int error;

	if (ifproto->proto_kpi == kProtoKPI_v1) {
		/* Version 1 protocols get one packet at a time */
		while (m != NULL) {
			char *	frame_header;
			mbuf_t	next_packet;
			
			next_packet = m->m_nextpkt;
			m->m_nextpkt = NULL;
			frame_header = m->m_pkthdr.header;
			m->m_pkthdr.header = NULL;
			error = (*ifproto->kpi.v1.input)(ifproto->ifp, 
							 ifproto->protocol_family,
							 m, frame_header);
			if (error != 0 && error != EJUSTRETURN)
				m_freem(m);
			m = next_packet;
		}
	}
	else if (ifproto->proto_kpi == kProtoKPI_v2) {
		/* Version 2 protocols support packet lists */
		error = (*ifproto->kpi.v2.input)(ifproto->ifp,
						 ifproto->protocol_family,
						 m);
		if (error != 0 && error != EJUSTRETURN)
			m_freem_list(m);
	}
	return;
}

__private_extern__ void
dlil_input_packet_list(struct ifnet * ifp_param, struct mbuf *m)
{
	int				error = 0;
	int				locked = 0;
	protocol_family_t		protocol_family;
	mbuf_t				next_packet;
	ifnet_t				ifp = ifp_param;
	char *				frame_header;
	struct if_proto	*		last_ifproto = NULL;
	mbuf_t				pkt_first = NULL;
	mbuf_t *			pkt_next = NULL;

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START,0,0,0,0,0);

	while (m != NULL) {
		struct if_proto *	ifproto = NULL;

		next_packet = m->m_nextpkt;
		m->m_nextpkt = NULL;
		if (ifp_param == NULL)
			ifp = m->m_pkthdr.rcvif;
		frame_header = m->m_pkthdr.header;
		m->m_pkthdr.header = NULL;

		if (locked == 0) {
			/* dlil lock protects the demux and interface filters */
			locked = 1;
			dlil_read_begin();
		}
		/* find which protocol family this packet is for */
		error = (*ifp->if_demux)(ifp, m, frame_header,
					 &protocol_family);
		if (error != 0) {
			if (error == EJUSTRETURN) {
				goto next;
			}
			protocol_family = 0;
		}
		
		/* DANGER!!! */
		if (m->m_flags & (M_BCAST|M_MCAST))
			ifp->if_imcasts++;

		/* run interface filters, exclude VLAN packets PR-3586856 */
		if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
			int	filter_result;

			filter_result = dlil_interface_filters_input(ifp, &m, 
							  &frame_header,
							  protocol_family);
			if (filter_result != 0) {
				if (filter_result != EJUSTRETURN) {
					m_freem(m);
				}
				goto next;
			}
		}
		if (error != 0 || ((m->m_flags & M_PROMISC) != 0) ) {
			m_freem(m);
			goto next;
		}
		
		/* Lookup the protocol attachment to this interface */
		if (protocol_family == 0) {
			ifproto = NULL;
		}
		else if (last_ifproto != NULL
			 && last_ifproto->ifp == ifp
			 && (last_ifproto->protocol_family
			     == protocol_family)) {
			ifproto = last_ifproto;
		}
		else {
			ifproto	= find_attached_proto(ifp, protocol_family);
		}
		if (ifproto == NULL) {
			/* no protocol for this packet, discard */
			m_freem(m);
			goto next;
		}
		if (ifproto != last_ifproto) {
			/* make sure ifproto can't go away during input */
			if_proto_ref(ifproto);
			if (last_ifproto != NULL) {
				/* pass up the list for the previous protocol */
				dlil_read_end();
				
				dlil_ifproto_input(last_ifproto, pkt_first);
				pkt_first = NULL;
				if_proto_free(last_ifproto);
				dlil_read_begin();
			}
			last_ifproto = ifproto;
		}
		/* extend the list */
		m->m_pkthdr.header = frame_header;
		if (pkt_first == NULL) {
			pkt_first = m;
		} else {
			*pkt_next = m;
		}
		pkt_next = &m->m_nextpkt;

	next:
		if (next_packet == NULL && last_ifproto != NULL) {
			/* pass up the last list of packets */
			dlil_read_end();

			dlil_ifproto_input(last_ifproto, pkt_first);
			if_proto_free(last_ifproto);
			locked = 0;
		}
		m = next_packet;

	}
	if (locked != 0) {
		dlil_read_end();
	}
	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
}

static int
dlil_event_internal(struct ifnet *ifp, struct kev_msg *event)
{
	struct ifnet_filter *filter;
	
	if (ifp_use(ifp, kIfNetUseCount_MustNotBeZero) == 0) {
		dlil_read_begin();
		
		/* Pass the event to the interface filters */
		TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
			if (filter->filt_event)
				filter->filt_event(filter->filt_cookie, ifp, filter->filt_protocol, event);
		}
		
		if (ifp->if_proto_hash) {
			int i;

			for (i = 0; i < PROTO_HASH_SLOTS; i++) {
				struct if_proto *proto;
				
				SLIST_FOREACH(proto, &ifp->if_proto_hash[i], next_hash) {
					proto_media_event eventp = proto->proto_kpi == kProtoKPI_v1
						 ? proto->kpi.v1.event : proto->kpi.v2.event;
					
					if (eventp)
						eventp(ifp, proto->protocol_family, event);
				}
			}
		}
		
		dlil_read_end();
		
		/* Pass the event to the interface */
		if (ifp->if_event)
			ifp->if_event(ifp, event);
		
		if (ifp_unuse(ifp))
			ifp_use_reached_zero(ifp);
	}
	
	return kev_post_msg(event);
}

errno_t
ifnet_event(
	ifnet_t					ifp,
	struct kern_event_msg	*event)
{
	struct kev_msg               kev_msg;
	int result = 0;

	if (ifp == NULL || event == NULL) return EINVAL;

	kev_msg.vendor_code    = event->vendor_code;
	kev_msg.kev_class      = event->kev_class;
	kev_msg.kev_subclass   = event->kev_subclass;
	kev_msg.event_code     = event->event_code;
	kev_msg.dv[0].data_ptr = &event->event_data[0];
	kev_msg.dv[0].data_length = event->total_size - KEV_MSG_HEADER_SIZE;
	kev_msg.dv[1].data_length = 0;
	
	result = dlil_event_internal(ifp, &kev_msg);

	return result;
}

#if CONFIG_MACF_NET
#include <netinet/ip6.h>
#include <netinet/ip.h>
static int dlil_get_socket_type(struct mbuf **mp, int family, int raw)
{
	struct mbuf *m;
	struct ip *ip;
	struct ip6_hdr *ip6;
	int type = SOCK_RAW;

	if (!raw) {
		switch (family) {
		case PF_INET:
			m = m_pullup(*mp, sizeof(struct ip));
			if (m == NULL)
				break;
			*mp = m;
			ip = mtod(m, struct ip *);
			if (ip->ip_p == IPPROTO_TCP)
				type = SOCK_STREAM;
			else if (ip->ip_p == IPPROTO_UDP)
				type = SOCK_DGRAM;
			break;
		case PF_INET6:
			m = m_pullup(*mp, sizeof(struct ip6_hdr));
			if (m == NULL)
				break;
			*mp = m;
			ip6 = mtod(m, struct ip6_hdr *);
			if (ip6->ip6_nxt == IPPROTO_TCP)
				type = SOCK_STREAM;
			else if (ip6->ip6_nxt == IPPROTO_UDP)
				type = SOCK_DGRAM;
			break;
		}
	}

	return (type);
}
#endif

#if 0
int
dlil_output_list(
	struct ifnet* ifp,
	u_long proto_family,
	struct mbuf		*packetlist,
	caddr_t		route,
	const struct sockaddr	*dest,
	int						raw)
{
	char			*frame_type = NULL;
	char			*dst_linkaddr = NULL;
	int				retval = 0;
	char			frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
	char			dst_linkaddr_buffer[MAX_LINKADDR * 4];
	struct ifnet_filter *filter;
	struct if_proto	*proto = 0;
	mbuf_t	m;
	mbuf_t	send_head = NULL;
	mbuf_t	*send_tail = &send_head;
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);
	
	dlil_read_begin();
	
	frame_type	   = frame_type_buffer;
	dst_linkaddr   = dst_linkaddr_buffer;
	
	if (raw == 0) {
		proto = find_attached_proto(ifp, proto_family);
		if (proto == NULL) {
			retval = ENXIO;
			goto cleanup;
		}
	}
	
preout_again:
	if (packetlist == NULL)
		goto cleanup;
	m = packetlist;
	packetlist = packetlist->m_nextpkt;
	m->m_nextpkt = NULL;
	
	if (raw == 0) {
		proto_media_preout preoutp = proto->proto_kpi == kProtoKPI_v1
			 ? proto->kpi.v1.pre_output : proto->kpi.v2.pre_output;
		retval = 0;
		if (preoutp)
			retval = preoutp(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
	
		if (retval) {
			if (retval == EJUSTRETURN) {
				goto preout_again;
			}
			
			m_freem(m);
			goto cleanup;
		}
	}

	do {
#if CONFIG_MACF_NET
		retval = mac_ifnet_check_transmit(ifp, m, proto_family,
		    dlil_get_socket_type(&m, proto_family, raw));
		if (retval) {
			m_freem(m);
			goto cleanup;
		}
#endif
	
		if (raw == 0 && ifp->if_framer) {
			retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr, frame_type); 
			if (retval) {
				if (retval != EJUSTRETURN) {
					m_freem(m);
				}
				goto next;
			}
		}
	
#if BRIDGE
		/* !!!LOCKING!!!
		 *
		 * Need to consider how to handle this.
		 * Also note that return should be a goto cleanup
		 */
		broken-locking
		if (do_bridge) {
			struct mbuf *m0 = m;
			struct ether_header *eh = mtod(m, struct ether_header *);
			
			if (m->m_pkthdr.rcvif)
				m->m_pkthdr.rcvif = NULL;
			ifp = bridge_dst_lookup(eh);
			bdg_forward(&m0, ifp);
			if (m0)
				m_freem(m0);
			
			return 0 - should be goto cleanup?
		}
#endif

		/* 
		 * Let interface filters (if any) do their thing ...
		 */
		/* Do not pass VLAN tagged packets to filters PR-3586856 */
		if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
			TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
				if ((filter->filt_protocol == 0 || (filter->filt_protocol == proto_family)) &&
					filter->filt_output) {
					retval = filter->filt_output(filter->filt_cookie, ifp, proto_family, &m);
					if (retval) {
						if (retval != EJUSTRETURN)
							m_freem(m);
						goto next;
					}
				}
			}
		}
		
		/*
		 * Finally, call the driver.
		 */
	
		if ((ifp->if_eflags & IFEF_SENDLIST) != 0) {
			*send_tail = m;
			send_tail = &m->m_nextpkt;
		}
		else {
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
			retval = ifp->if_output(ifp, m);
			if (retval && dlil_verbose) {
				printf("dlil_output: output error on %s%d retval = %d\n", 
					ifp->if_name, ifp->if_unit, retval);
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);

next:
		m = packetlist;
		if (m) {
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
		}
	} while (m);

	if (send_head) {
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
		retval = ifp->if_output(ifp, send_head);
		if (retval && dlil_verbose) {
			printf("dlil_output: output error on %s%d retval = %d\n",
				ifp->if_name, ifp->if_unit, retval);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
	}
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

cleanup:
	dlil_read_end();
	if (packetlist) /* if any packet left, clean up */
		mbuf_freem_list(packetlist);
	if (retval == EJUSTRETURN)
		retval = 0;
	return retval;
}
#endif

/*
 * dlil_output
 *
 * Caller should have a lock on the protocol domain if the protocol
 * doesn't support finer grained locking. In most cases, the lock
 * will be held from the socket layer and won't be released until
 * we return back to the socket layer.
 *
 * This does mean that we must take a protocol lock before we take
 * an interface lock if we're going to take both. This makes sense
 * because a protocol is likely to interact with an ifp while it
 * is under the protocol lock.
 */
__private_extern__ errno_t
dlil_output(
	ifnet_t					ifp,
	protocol_family_t		proto_family,
	mbuf_t					packetlist,
	void					*route,
	const struct sockaddr	*dest,
	int						raw)
{
	char			*frame_type = NULL;
	char			*dst_linkaddr = NULL;
	int				retval = 0;
	char			frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
	char			dst_linkaddr_buffer[MAX_LINKADDR * 4];
	struct ifnet_filter *filter;
	struct if_proto	*proto = 0;
	mbuf_t	m;
	mbuf_t	send_head = NULL;
	mbuf_t	*send_tail = &send_head;
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);
	
	dlil_read_begin();
	
	frame_type	   = frame_type_buffer;
	dst_linkaddr   = dst_linkaddr_buffer;
	
	if (raw == 0) {
		proto = find_attached_proto(ifp, proto_family);
		if (proto == NULL) {
			retval = ENXIO;
			goto cleanup;
		}
	}
	
preout_again:
	if (packetlist == NULL)
		goto cleanup;
	m = packetlist;
	packetlist = packetlist->m_nextpkt;
	m->m_nextpkt = NULL;
	
	if (raw == 0) {
		proto_media_preout preoutp = proto->proto_kpi == kProtoKPI_v1
			 ? proto->kpi.v1.pre_output : proto->kpi.v2.pre_output;
		retval = 0;
		if (preoutp)
			retval = preoutp(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
	
		if (retval) {
			if (retval == EJUSTRETURN) {
				goto preout_again;
			}
			
			m_freem(m);
			goto cleanup;
		}
	}

#if CONFIG_MACF_NET
	retval = mac_ifnet_check_transmit(ifp, m, proto_family,
	    dlil_get_socket_type(&m, proto_family, raw));
	if (retval) {
		m_freem(m);
		goto cleanup;
	}
#endif

	do {
		if (raw == 0 && ifp->if_framer) {
			int rcvif_set = 0;

			/*
			 * If this is a broadcast packet that needs to be
			 * looped back into the system, set the inbound ifp
			 * to that of the outbound ifp.  This will allow
			 * us to determine that it is a legitimate packet
			 * for the system.  Only set the ifp if it's not
			 * already set, just to be safe.
			 */
			if ((m->m_flags & (M_BCAST | M_LOOP)) &&
			    m->m_pkthdr.rcvif == NULL) {
				m->m_pkthdr.rcvif = ifp;
				rcvif_set = 1;
			}

			retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr, frame_type); 
			if (retval) {
				if (retval != EJUSTRETURN) {
					m_freem(m);
				}
				goto next;
			}

			/*
			 * Clear the ifp if it was set above, and to be
			 * safe, only if it is still the same as the
			 * outbound ifp we have in context.  If it was
			 * looped back, then a copy of it was sent to the
			 * loopback interface with the rcvif set, and we
			 * are clearing the one that will go down to the
			 * layer below.
			 */
			if (rcvif_set && m->m_pkthdr.rcvif == ifp)
				m->m_pkthdr.rcvif = NULL;
		}
	
#if BRIDGE
		/* !!!LOCKING!!!
		 *
		 * Need to consider how to handle this.
		 * Also note that return should be a goto cleanup
		 */
		broken-locking
		if (do_bridge) {
			struct mbuf *m0 = m;
			struct ether_header *eh = mtod(m, struct ether_header *);
			
			if (m->m_pkthdr.rcvif)
				m->m_pkthdr.rcvif = NULL;
			ifp = bridge_dst_lookup(eh);
			bdg_forward(&m0, ifp);
			if (m0)
				m_freem(m0);
			
			return 0 - should be goto cleanup?
		}
#endif

		/* 
		 * Let interface filters (if any) do their thing ...
		 */
		/* Do not pass VLAN tagged packets to filters PR-3586856 */
		if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
			TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
				if ((filter->filt_protocol == 0 || (filter->filt_protocol == proto_family)) &&
					filter->filt_output) {
					retval = filter->filt_output(filter->filt_cookie, ifp, proto_family, &m);
					if (retval) {
						if (retval != EJUSTRETURN)
							m_freem(m);
						goto next;
					}
				}
			}
		}

		/*
		 * If the underlying interface is not capable of handling a
		 * packet whose data portion spans across physically disjoint
		 * pages, we need to "normalize" the packet so that we pass
		 * down a chain of mbufs where each mbuf points to a span that
		 * resides in the system page boundary.  If the packet does
		 * not cross page(s), the following is a no-op.
		 */
		if (!(ifp->if_hwassist & IFNET_MULTIPAGES)) {
			if ((m = m_normalize(m)) == NULL)
				goto next;
		}

		/* 
		 * If this is a TSO packet, make sure the interface still advertise TSO capability
		 */

		if ((m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) && !(ifp->if_hwassist & IFNET_TSO_IPV4)) {
				retval = EMSGSIZE;
				m_freem(m);
				goto cleanup;
		}

		if ((m->m_pkthdr.csum_flags & CSUM_TSO_IPV6) && !(ifp->if_hwassist & IFNET_TSO_IPV6)) {
				retval = EMSGSIZE;
				m_freem(m);
				goto cleanup;
		}
		/*
		 * Finally, call the driver.
		 */
	
		if ((ifp->if_eflags & IFEF_SENDLIST) != 0) {
			*send_tail = m;
			send_tail = &m->m_nextpkt;
		}
		else {
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
			retval = ifp->if_output(ifp, m);
			if (retval && dlil_verbose) {
				printf("dlil_output: output error on %s%d retval = %d\n", 
					ifp->if_name, ifp->if_unit, retval);
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);

next:
		m = packetlist;
		if (m) {
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
		}
	} while (m);

	if (send_head) {
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
		retval = ifp->if_output(ifp, send_head);
		if (retval && dlil_verbose) {
			printf("dlil_output: output error on %s%d retval = %d\n", 
				ifp->if_name, ifp->if_unit, retval);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
	}
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

cleanup:
	dlil_read_end();
	if (packetlist) /* if any packet left, clean up */
		mbuf_freem_list(packetlist);
	if (retval == EJUSTRETURN)
		retval = 0;
	return retval;
}

errno_t
ifnet_ioctl(
	ifnet_t				ifp,
	protocol_family_t	proto_fam,
	u_long			ioctl_code,
	void				*ioctl_arg)
{
	struct ifnet_filter		*filter;
	int						retval = EOPNOTSUPP;
	int						result = 0;
	int						holding_read = 0;
	
	if (ifp == NULL || ioctl_code == 0)
		return EINVAL;
	
	/* Attempt to increment the use count. If it's zero, bail out, the ifp is invalid */
	result = ifp_use(ifp, kIfNetUseCount_MustNotBeZero);
	if (result != 0)
		return EOPNOTSUPP;
	
	dlil_read_begin();
	holding_read = 1;
	
	/* Run the interface filters first.
	 * We want to run all filters before calling the protocol,
	 * interface family, or interface.
	 */
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		if ((filter->filt_protocol == 0 || (filter->filt_protocol == proto_fam)) &&
			filter->filt_ioctl != NULL) {
			result = filter->filt_ioctl(filter->filt_cookie, ifp, proto_fam, ioctl_code, ioctl_arg);
			/* Only update retval if no one has handled the ioctl */
			if (retval == EOPNOTSUPP || result == EJUSTRETURN) {
				if (result == ENOTSUP)
					result = EOPNOTSUPP;
				retval = result;
				if (retval && retval != EOPNOTSUPP) {
					goto cleanup;
				}
			}
		}
	}
	
	/* Allow the protocol to handle the ioctl */
	if (proto_fam) {
		struct if_proto	*proto = find_attached_proto(ifp, proto_fam);
		
		if (proto != 0) {
			proto_media_ioctl ioctlp = proto->proto_kpi == kProtoKPI_v1
				 ? proto->kpi.v1.ioctl : proto->kpi.v2.ioctl;
			result = EOPNOTSUPP;
			if (ioctlp)
				result = ioctlp(ifp, proto_fam, ioctl_code, ioctl_arg);
			
			/* Only update retval if no one has handled the ioctl */
			if (retval == EOPNOTSUPP || result == EJUSTRETURN) {
				if (result == ENOTSUP)
					result = EOPNOTSUPP;
				retval = result;
				if (retval && retval != EOPNOTSUPP) {
					goto cleanup;
				}
			}
		}
	}
	
	/*
	 * Since we have incremented the use count on the ifp, we are guaranteed
	 * that the ifp will not go away (the function pointers may not be changed).
	 * We release the dlil read lock so the interface ioctl may trigger a
	 * protocol attach. This happens with vlan and may occur with other virtual
	 * interfaces.
	 */
	dlil_read_end();
	holding_read = 0;
	
	/* retval is either 0 or EOPNOTSUPP */
	
	/*
	 * Let the interface handle this ioctl.
	 * If it returns EOPNOTSUPP, ignore that, we may have
	 * already handled this in the protocol or family.
	 */
	if (ifp->if_ioctl) 
		result = (*ifp->if_ioctl)(ifp, ioctl_code, ioctl_arg);
	
	/* Only update retval if no one has handled the ioctl */
	if (retval == EOPNOTSUPP || result == EJUSTRETURN) {
		if (result == ENOTSUP)
			result = EOPNOTSUPP;
		retval = result;
		if (retval && retval != EOPNOTSUPP) {
			goto cleanup;
		}
	}
	
cleanup:
	if (holding_read)
		dlil_read_end();
	if (ifp_unuse(ifp))
		ifp_use_reached_zero(ifp);

	if (retval == EJUSTRETURN)
		retval = 0;
	return retval;
}

__private_extern__ errno_t
dlil_set_bpf_tap(
	ifnet_t			ifp,
	bpf_tap_mode	mode,
	bpf_packet_func	callback)
{
	errno_t	error = 0;
	
	dlil_read_begin();
	if (ifp->if_set_bpf_tap)
		error = ifp->if_set_bpf_tap(ifp, mode, callback);
	dlil_read_end();
	
	return error;
}

errno_t
dlil_resolve_multi(
	struct ifnet *ifp,
	const struct sockaddr *proto_addr,
	struct sockaddr *ll_addr,
	size_t ll_len)
{
	errno_t	result = EOPNOTSUPP;
	struct if_proto *proto;
	const struct sockaddr *verify;
	proto_media_resolve_multi resolvep;
	
	dlil_read_begin();
	
	bzero(ll_addr, ll_len);
	
	/* Call the protocol first */
	proto = find_attached_proto(ifp, proto_addr->sa_family);
	if (proto != NULL) {
		resolvep = proto->proto_kpi == kProtoKPI_v1
			 ? proto->kpi.v1.resolve_multi : proto->kpi.v2.resolve_multi;
		if (resolvep != NULL)
			result = resolvep(ifp, proto_addr,(struct sockaddr_dl*)ll_addr,
							  ll_len);
	}
	
	/* Let the interface verify the multicast address */
	if ((result == EOPNOTSUPP || result == 0) && ifp->if_check_multi) {
		if (result == 0)
			verify = ll_addr;
		else
			verify = proto_addr;
		result = ifp->if_check_multi(ifp, verify);
	}
	
	dlil_read_end();
	
	return result;
}

__private_extern__ errno_t
dlil_send_arp_internal(
	ifnet_t	ifp,
	u_short arpop,
	const struct sockaddr_dl* sender_hw,
	const struct sockaddr* sender_proto,
	const struct sockaddr_dl* target_hw,
	const struct sockaddr* target_proto)
{
	struct if_proto *proto;
	errno_t	result = 0;
	
	dlil_read_begin();
	
	proto = find_attached_proto(ifp, target_proto->sa_family);
	if (proto == NULL) {
		result = ENOTSUP;
	}
	else {
		proto_media_send_arp	arpp;
		arpp = proto->proto_kpi == kProtoKPI_v1
			 ? proto->kpi.v1.send_arp : proto->kpi.v2.send_arp;
		if (arpp == NULL)
			result = ENOTSUP;
		else
			result = arpp(ifp, arpop, sender_hw, sender_proto, target_hw,
						  target_proto);
	}
	
	dlil_read_end();
	
	return result;
}

static __inline__ int
_is_announcement(const struct sockaddr_in * sender_sin,
		     const struct sockaddr_in * target_sin)
{
	if (sender_sin == NULL) {
		return FALSE;
	}
	return (sender_sin->sin_addr.s_addr == target_sin->sin_addr.s_addr);
}

__private_extern__ errno_t
dlil_send_arp(
	ifnet_t	ifp,
	u_short arpop,
	const struct sockaddr_dl* sender_hw,
	const struct sockaddr* sender_proto,
	const struct sockaddr_dl* target_hw,
	const struct sockaddr* target_proto)
{
	errno_t	result = 0;
	const struct sockaddr_in * sender_sin;
	const struct sockaddr_in * target_sin;
	
	if (target_proto == NULL || (sender_proto &&
		sender_proto->sa_family != target_proto->sa_family))
		return EINVAL;
	
	/*
	 * If this is an ARP request and the target IP is IPv4LL,
	 * send the request on all interfaces.  The exception is
	 * an announcement, which must only appear on the specific
	 * interface.
	 */
	sender_sin = (const struct sockaddr_in *)sender_proto;
	target_sin = (const struct sockaddr_in *)target_proto;
	if (target_proto->sa_family == AF_INET
	    && IN_LINKLOCAL(ntohl(target_sin->sin_addr.s_addr))
	    && ipv4_ll_arp_aware != 0
	    && arpop == ARPOP_REQUEST
	    && !_is_announcement(target_sin, sender_sin)) {
		ifnet_t		*ifp_list;
		u_int32_t	count;
		u_int32_t	ifp_on;
		
		result = ENOTSUP;

		if (ifnet_list_get(IFNET_FAMILY_ANY, &ifp_list, &count) == 0) {
			for (ifp_on = 0; ifp_on < count; ifp_on++) {
				errno_t				new_result;
				ifaddr_t			source_hw = NULL;
				ifaddr_t			source_ip = NULL;
				struct sockaddr_in	source_ip_copy;
				
				/*
				 * Only arp on interfaces marked for IPv4LL ARPing. This may
				 * mean that we don't ARP on the interface the subnet route
				 * points to.
				 */
				if ((ifp_list[ifp_on]->if_eflags & IFEF_ARPLL) == 0) {
					continue;
				}

				/* Find the source IP address */
				ifnet_lock_shared(ifp_list[ifp_on]);
				source_hw = TAILQ_FIRST(&ifp_list[ifp_on]->if_addrhead);
				TAILQ_FOREACH(source_ip, &ifp_list[ifp_on]->if_addrhead,
							  ifa_link) {
					if (source_ip->ifa_addr &&
						source_ip->ifa_addr->sa_family == AF_INET) {
						break;
					}
				}
				
				/* No IP Source, don't arp */
				if (source_ip == NULL) {
					ifnet_lock_done(ifp_list[ifp_on]);
					continue;
				}
				
				/* Copy the source IP address */
				source_ip_copy = *(struct sockaddr_in*)source_ip->ifa_addr;
				ifaref(source_hw);
				ifnet_lock_done(ifp_list[ifp_on]);
				
				/* Send the ARP */
				new_result = dlil_send_arp_internal(ifp_list[ifp_on], arpop,
									(struct sockaddr_dl*)source_hw->ifa_addr,
									(struct sockaddr*)&source_ip_copy, NULL,
									target_proto);

				ifafree(source_hw);
				if (result == ENOTSUP) {
					result = new_result;
				}
			}
		}
		
		ifnet_list_free(ifp_list);
	}
	else {
		result = dlil_send_arp_internal(ifp, arpop, sender_hw, sender_proto,
										target_hw, target_proto);
	}
	
	return result;
}

__private_extern__ int
ifp_use(
	struct ifnet *ifp,
	int	handle_zero)
{
	int old_value;
	int retval = 0;
	
	do {
		old_value = ifp->if_usecnt;
		if (old_value == 0 && handle_zero == kIfNetUseCount_MustNotBeZero) {
			retval = ENXIO; // ifp is invalid
			break;
		}
	} while (!OSCompareAndSwap((UInt32)old_value, (UInt32)old_value + 1, (UInt32*)&ifp->if_usecnt));
 
	return retval;
}

/* ifp_unuse is broken into two pieces.
 *
 * ifp_use and ifp_unuse must be called between when the caller calls
 * dlil_write_begin and dlil_write_end. ifp_unuse needs to perform some
 * operations after dlil_write_end has been called. For this reason,
 * anyone calling ifp_unuse must call ifp_use_reached_zero if ifp_unuse
 * returns a non-zero value. The caller must call ifp_use_reached_zero
 * after the caller has called dlil_write_end.
 */
__private_extern__ void
ifp_use_reached_zero(
	struct ifnet *ifp)
{
	ifnet_detached_func	free_func;
	
	dlil_read_begin();
	
	if (ifp->if_usecnt != 0)
		panic("ifp_use_reached_zero: ifp->if_usecnt != 0");
	
	ifnet_head_lock_exclusive();
	ifnet_lock_exclusive(ifp);
	
	/* Remove ourselves from the list */
	TAILQ_REMOVE(&ifnet_head, ifp, if_link);
	ifnet_addrs[ifp->if_index - 1] = NULL;
	
	/* ifp should be removed from the interface list */
	while (ifp->if_multiaddrs.lh_first) {
		struct ifmultiaddr *ifma = ifp->if_multiaddrs.lh_first;
		
		/*
		 * When the interface is gone, we will no longer
		 * be listening on these multicasts. Various bits
		 * of the stack may be referencing these multicasts,
		 * release only our reference.
		 */
		LIST_REMOVE(ifma, ifma_link);
		ifma->ifma_ifp = NULL;
		ifma_release(ifma);
	}

	ifp->if_eflags &= ~IFEF_DETACHING; // clear the detaching flag
	ifnet_lock_done(ifp);
	ifnet_head_done();

	free_func = ifp->if_free;
	dlil_read_end();
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, NULL, 0);
	
	if (free_func)
		free_func(ifp);
}

__private_extern__ int
ifp_unuse(
	struct ifnet *ifp)
{
	int	oldval;
	oldval = OSDecrementAtomic(&ifp->if_usecnt);
	if (oldval == 0)
		panic("ifp_unuse: ifp(%s%d)->if_usecnt was zero\n", ifp->if_name, ifp->if_unit);
 	
	if (oldval > 1)
		return 0;
 	
	if ((ifp->if_eflags & IFEF_DETACHING) == 0)
		panic("ifp_unuse: use count reached zero but detching flag is not set!");
 	
 	return 1; /* caller must call ifp_use_reached_zero */
}

extern lck_mtx_t 	*domain_proto_mtx;

static errno_t
dlil_attach_protocol_internal(
	struct if_proto	*proto,
	const struct ifnet_demux_desc *demux_list,
	u_int32_t	demux_count)
{
	struct kev_dl_proto_data	ev_pr_data;
	struct ifnet *ifp = proto->ifp;
	int retval = 0;
	u_int32_t hash_value = proto_hash_value(proto->protocol_family);
    
    /* setup some of the common values */
	{
		struct domain *dp;
		lck_mtx_lock(domain_proto_mtx);
		dp = domains;
		while (dp && (protocol_family_t)dp->dom_family != proto->protocol_family)
			dp = dp->dom_next;
		proto->dl_domain = dp;
		lck_mtx_unlock(domain_proto_mtx);
	}
	
	/*
	 * Take the write lock to protect readers and exclude other writers.
	 */
	if ((retval = dlil_write_begin()) != 0) {
		printf("dlil_attach_protocol_internal - dlil_write_begin returned %d\n", retval);
		return retval;
	}
	
	/* Check that the interface isn't currently detaching */
	ifnet_lock_shared(ifp);
	if ((ifp->if_eflags & IFEF_DETACHING) != 0) {
		ifnet_lock_done(ifp);
		dlil_write_end();
		return ENXIO;
	}
	ifnet_lock_done(ifp);
	
	if (find_attached_proto(ifp, proto->protocol_family) != NULL) {
		dlil_write_end();
		return EEXIST;
	}
	
	/*
	 * Call family module add_proto routine so it can refine the
	 * demux descriptors as it wishes.
	 */
	retval = ifp->if_add_proto(ifp, proto->protocol_family, demux_list, demux_count);
	if (retval) {
		dlil_write_end();
		return retval;
	}
	
	/*
	 * We can't fail from this point on.
	 * Increment the number of uses (protocol attachments + interface attached).
	 */
	ifp_use(ifp, kIfNetUseCount_MustNotBeZero);
	
	/*
	 * Insert the protocol in the hash
	 */
	{
		struct if_proto*	prev_proto = SLIST_FIRST(&ifp->if_proto_hash[hash_value]);
		while (prev_proto && SLIST_NEXT(prev_proto, next_hash) != NULL)
			prev_proto = SLIST_NEXT(prev_proto, next_hash);
		if (prev_proto)
			SLIST_INSERT_AFTER(prev_proto, proto, next_hash);
		else
			SLIST_INSERT_HEAD(&ifp->if_proto_hash[hash_value], proto, next_hash);
	}

	/*
	 * Add to if_proto list for this interface
	 */
	if_proto_ref(proto);
	dlil_write_end();
	
	/* the reserved field carries the number of protocol still attached (subject to change) */
	ev_pr_data.proto_family = proto->protocol_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_ATTACHED, 
				  (struct net_event_data *)&ev_pr_data, 
				  sizeof(struct kev_dl_proto_data));
#if 0	
	DLIL_PRINTF("dlil. Attached protocol %d to %s%d - %d\n", proto->protocol_family,
			 ifp->if_name, ifp->if_unit, retval);
#endif
	return retval;
}

errno_t
ifnet_attach_protocol(ifnet_t ifp, protocol_family_t protocol,
	const struct ifnet_attach_proto_param *proto_details)
{
	int retval = 0;
	struct if_proto  *ifproto = NULL;
	
	if (ifp == NULL || protocol == 0 || proto_details == NULL)
		return EINVAL;
	
	ifproto = _MALLOC(sizeof(struct if_proto), M_IFADDR, M_WAITOK);
	if (ifproto == 0) {
		DLIL_PRINTF("ERROR - dlil failed if_proto allocation\n");
		retval = ENOMEM;
		goto end;
	}
	bzero(ifproto, sizeof(*ifproto));
	
	ifproto->ifp = ifp;
	ifproto->protocol_family = protocol;
	ifproto->proto_kpi = kProtoKPI_v1;
	ifproto->kpi.v1.input = proto_details->input;
	ifproto->kpi.v1.pre_output = proto_details->pre_output;
	ifproto->kpi.v1.event = proto_details->event;
	ifproto->kpi.v1.ioctl = proto_details->ioctl;
	ifproto->kpi.v1.detached = proto_details->detached;
	ifproto->kpi.v1.resolve_multi = proto_details->resolve;
	ifproto->kpi.v1.send_arp = proto_details->send_arp;
	
	retval = dlil_attach_protocol_internal(ifproto,
				proto_details->demux_list, proto_details->demux_count);
	
end:
	if (retval && ifproto)
		FREE(ifproto, M_IFADDR);
	return retval;
}

errno_t
ifnet_attach_protocol_v2(ifnet_t ifp, protocol_family_t protocol,
	const struct ifnet_attach_proto_param_v2 *proto_details)
{
	int retval = 0;
	struct if_proto  *ifproto = NULL;
	
	if (ifp == NULL || protocol == 0 || proto_details == NULL)
		return EINVAL;
	
	ifproto = _MALLOC(sizeof(struct if_proto), M_IFADDR, M_WAITOK);
	if (ifproto == 0) {
		DLIL_PRINTF("ERROR - dlil failed if_proto allocation\n");
		retval = ENOMEM;
		goto end;
	}
	bzero(ifproto, sizeof(*ifproto));
	
	ifproto->ifp = ifp;
	ifproto->protocol_family = protocol;
	ifproto->proto_kpi = kProtoKPI_v2;
	ifproto->kpi.v2.input = proto_details->input;
	ifproto->kpi.v2.pre_output = proto_details->pre_output;
	ifproto->kpi.v2.event = proto_details->event;
	ifproto->kpi.v2.ioctl = proto_details->ioctl;
	ifproto->kpi.v2.detached = proto_details->detached;
	ifproto->kpi.v2.resolve_multi = proto_details->resolve;
	ifproto->kpi.v2.send_arp = proto_details->send_arp;
	
	retval = dlil_attach_protocol_internal(ifproto,
				proto_details->demux_list, proto_details->demux_count);
	
end:
	if (retval && ifproto)
		FREE(ifproto, M_IFADDR);
	return retval;
}

extern void if_rtproto_del(struct ifnet *ifp, int protocol);

static int
dlil_detach_protocol_internal(
	struct if_proto *proto)
{
	struct ifnet *ifp = proto->ifp;
	u_int32_t proto_family = proto->protocol_family;
	struct kev_dl_proto_data	ev_pr_data;
	
	if (proto->proto_kpi == kProtoKPI_v1) {
		if (proto->kpi.v1.detached)
			proto->kpi.v1.detached(ifp, proto->protocol_family);
	}
	if (proto->proto_kpi == kProtoKPI_v2) {
		if (proto->kpi.v2.detached)
			proto->kpi.v2.detached(ifp, proto->protocol_family);
	}
	if_proto_free(proto);
    
	/*
	 * Cleanup routes that may still be in the routing table for that interface/protocol pair.
	 */
	
	if_rtproto_del(ifp, proto_family);
	
	/* the reserved field carries the number of protocol still attached (subject to change) */
	ev_pr_data.proto_family   = proto_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_DETACHED, 
				  (struct net_event_data *)&ev_pr_data, 
				  sizeof(struct kev_dl_proto_data));
	return 0;
}

errno_t
ifnet_detach_protocol(ifnet_t ifp, protocol_family_t proto_family)
{
	struct if_proto *proto = NULL;
	int	retval = 0;
	int use_reached_zero = 0;
	
	if (ifp == NULL || proto_family == 0) return EINVAL;

	if ((retval = dlil_write_begin()) != 0) {
		if (retval == EDEADLK) {
			retval = 0;
			dlil_read_begin();
			proto = find_attached_proto(ifp, proto_family);
			if (proto == 0) {
				retval = ENXIO;
			}
			else {
				proto->detaching = 1;
				dlil_detach_waiting = 1;
				wakeup(&dlil_detach_waiting);
			}
			dlil_read_end();
		}
		goto end;
	}
	
	proto = find_attached_proto(ifp, proto_family);
	
	if (proto == NULL) {
		retval = ENXIO;
		dlil_write_end();
		goto end;
	}
	
	/*
	 * Call family module del_proto
	 */
	
	if (ifp->if_del_proto)
		ifp->if_del_proto(ifp, proto->protocol_family);

	SLIST_REMOVE(&ifp->if_proto_hash[proto_hash_value(proto_family)], proto, if_proto, next_hash);
	
	/*
	 * We can do the rest of the work outside of the write lock.
	 */
	use_reached_zero = ifp_unuse(ifp);
	dlil_write_end();
	
	dlil_detach_protocol_internal(proto);

	/*
	 * Only handle the case where the interface will go away after
	 * we've sent the message. This way post message can send the
	 * message to the interface safely.
	 */
	
	if (use_reached_zero)
		ifp_use_reached_zero(ifp);
	
end:
    return retval;
}

/*
 * dlil_delayed_detach_thread is responsible for detaching
 * protocols, protocol filters, and interface filters after
 * an attempt was made to detach one of those items while
 * it was not safe to do so (i.e. called dlil_read_begin).
 *
 * This function will take the dlil write lock and walk
 * through each of the interfaces looking for items with
 * the detaching flag set. When an item is found, it is
 * detached from the interface and placed on a local list.
 * After all of the items have been collected, we drop the
 * write lock and performed the post detach. This is done
 * so we only have to take the write lock once.
 *
 * When detaching a protocol filter, if we find that we
 * have detached the very last protocol and we need to call
 * ifp_use_reached_zero, we have to break out of our work
 * to drop the write lock so we can call ifp_use_reached_zero.
 */
 
static void
dlil_delayed_detach_thread(__unused void* foo, __unused wait_result_t wait)
{
	thread_t self = current_thread();
	int asserted = 0;
	
	ml_thread_policy(self, MACHINE_GROUP,
					 (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_NETISR));

	
	while (1) {
		if (dlil_detach_waiting != 0 && dlil_write_begin() == 0) {
			struct ifnet *ifp;
			struct proto_hash_entry detached_protos;
			struct ifnet_filter_head detached_filters;
			struct if_proto	*proto;
			struct if_proto *next_proto;
			struct ifnet_filter *filt;
			struct ifnet_filter *next_filt;
			int reached_zero;
			
			reached_zero = 0;
			
			/* Clear the detach waiting flag */
			dlil_detach_waiting = 0;
			TAILQ_INIT(&detached_filters);
			SLIST_INIT(&detached_protos);
			
			ifnet_head_lock_shared();
			TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
				int i;
				
				// Look for protocols and protocol filters
				for (i = 0; i < PROTO_HASH_SLOTS && !reached_zero; i++) {
					struct if_proto **prev_nextptr = &SLIST_FIRST(&ifp->if_proto_hash[i]);
					for (proto = *prev_nextptr; proto; proto = *prev_nextptr) {
						
						// Detach this protocol
						if (proto->detaching) {
							if (ifp->if_del_proto)
								ifp->if_del_proto(ifp, proto->protocol_family);
							*prev_nextptr = SLIST_NEXT(proto, next_hash);
							SLIST_INSERT_HEAD(&detached_protos, proto, next_hash);
							reached_zero = ifp_unuse(ifp);
							if (reached_zero) {
								break;
							}
						}
						else {
							// Update prev_nextptr to point to our next ptr
							prev_nextptr = &SLIST_NEXT(proto, next_hash);
						}
					}
				}
				
				// look for interface filters that need to be detached
				for (filt = TAILQ_FIRST(&ifp->if_flt_head); filt; filt = next_filt) {
					next_filt = TAILQ_NEXT(filt, filt_next);
					if (filt->filt_detaching != 0) {
						// take this interface filter off the interface filter list
						TAILQ_REMOVE(&ifp->if_flt_head, filt, filt_next);
						
						// put this interface filter on the detached filters list
						TAILQ_INSERT_TAIL(&detached_filters, filt, filt_next);
					}
				}
				
				if (ifp->if_delayed_detach) {
					ifp->if_delayed_detach = 0;
					reached_zero = ifp_unuse(ifp);
				}
				
				if (reached_zero)
					break;
			}
			ifnet_head_done();
			dlil_write_end();
			
			for (filt = TAILQ_FIRST(&detached_filters); filt; filt = next_filt) {
				next_filt = TAILQ_NEXT(filt, filt_next);
				/*
				 * dlil_detach_filter_internal won't remove an item from
				 * the list if it is already detached (second parameter).
				 * The item will be freed though.
				 */
				dlil_detach_filter_internal(filt, 1);
			}
			
			for (proto = SLIST_FIRST(&detached_protos); proto; proto = next_proto) {
				next_proto = SLIST_NEXT(proto, next_hash);
				dlil_detach_protocol_internal(proto);
			}
			
			if (reached_zero) {
				ifp_use_reached_zero(ifp);
				dlil_detach_waiting = 1; // we may have missed something
			}
		}
		
		if (!asserted && dlil_detach_waiting == 0) {
			asserted = 1;
			assert_wait(&dlil_detach_waiting, THREAD_UNINT);
		}
		
		if (dlil_detach_waiting == 0) {
			asserted = 0;
			thread_block(dlil_delayed_detach_thread);
		}
	}
}

static void
dlil_call_delayed_detach_thread(void) {
	dlil_delayed_detach_thread(NULL, THREAD_RESTART);
}

extern int if_next_index(void);

errno_t
ifnet_attach(
	ifnet_t						ifp,
	const struct sockaddr_dl	*ll_addr)
{
	u_int32_t		    interface_family;
	struct ifnet *tmp_if;
	struct proto_hash_entry *new_proto_list = NULL;
	int locked = 0;
	
	if (ifp == NULL) return EINVAL;
	if (ll_addr && ifp->if_addrlen == 0) {
		ifp->if_addrlen = ll_addr->sdl_alen;
	}
	else if (ll_addr && ll_addr->sdl_alen != ifp->if_addrlen) {
		return EINVAL;
	}
	
	interface_family = ifp->if_family;
	
	ifnet_head_lock_shared();

	/* Verify we aren't already on the list */
	TAILQ_FOREACH(tmp_if, &ifnet_head, if_link) {
		if (tmp_if == ifp) {
			ifnet_head_done();
			return EEXIST;
		}
	}
	
	ifnet_head_done();
	
	if ((ifp->if_eflags & IFEF_REUSE) == 0 || ifp->if_lock == 0)
#if IFNET_RW_LOCK
		ifp->if_lock = lck_rw_alloc_init(ifnet_lock_group, ifnet_lock_attr);
#else
		ifp->if_lock = lck_mtx_alloc_init(ifnet_lock_group, ifnet_lock_attr);
#endif

	if (ifp->if_lock == 0) {
		return ENOMEM;
	}

	if (!(ifp->if_eflags & IFEF_REUSE) || ifp->if_fwd_route_lock == NULL) {
		if (ifp->if_fwd_route_lock == NULL)
			ifp->if_fwd_route_lock = lck_mtx_alloc_init(
			    ifnet_lock_group, ifnet_lock_attr);

		if (ifp->if_fwd_route_lock == NULL) {
#if IFNET_RW_LOCK
			lck_rw_free(ifp->if_lock, ifnet_lock_group);
#else
			lck_mtx_free(ifp->if_lock, ifnet_lock_group);
#endif
			ifp->if_lock = NULL;
			return (ENOMEM);
		}
	}

	/*
	 * Allow interfaces without protocol families to attach
	 * only if they have the necessary fields filled out.
	 */
	
	if (ifp->if_add_proto == 0 || ifp->if_del_proto == 0) {
		DLIL_PRINTF("dlil Attempt to attach interface without family module - %d\n", 
				interface_family);
		return ENODEV;
	}
	
	if ((ifp->if_eflags & IFEF_REUSE) == 0 || ifp->if_proto_hash == NULL) {
		MALLOC(new_proto_list, struct proto_hash_entry*, sizeof(struct proto_hash_entry) * PROTO_HASH_SLOTS,
			   M_NKE, M_WAITOK);

		if (new_proto_list == 0) {
			return ENOBUFS;
		}
	}

	dlil_write_begin();
	locked = 1;

	TAILQ_INIT(&ifp->if_flt_head);
	
		
	if (new_proto_list) {
		bzero(new_proto_list, (PROTO_HASH_SLOTS * sizeof(struct proto_hash_entry)));
		ifp->if_proto_hash = new_proto_list;
		new_proto_list = NULL;
	}
	
	/* old_if_attach */
	{
		char workbuf[64];
		int namelen, masklen, socksize, ifasize;
		struct ifaddr *ifa = NULL;
		
		if (ifp->if_snd.ifq_maxlen == 0)
			ifp->if_snd.ifq_maxlen = ifqmaxlen;
		TAILQ_INIT(&ifp->if_prefixhead);
		LIST_INIT(&ifp->if_multiaddrs);
		ifnet_touch_lastchange(ifp);
		
		/* usecount to track attachment to the ifnet list */
		ifp_use(ifp, kIfNetUseCount_MayBeZero);
		
		/* Lock the list of interfaces */
		ifnet_head_lock_exclusive();
		ifnet_lock_exclusive(ifp);
		
		if ((ifp->if_eflags & IFEF_REUSE) == 0 || ifp->if_index == 0) {
			int idx = if_next_index();
            
            if (idx == -1) {
                ifnet_lock_done(ifp);
                ifnet_head_done();
                ifp_unuse(ifp);
                dlil_write_end();
                
                return ENOBUFS;
            }
			ifp->if_index = idx;
		} else {
			ifa = TAILQ_FIRST(&ifp->if_addrhead);
		}
		namelen = snprintf(workbuf, sizeof(workbuf), "%s%d", ifp->if_name, ifp->if_unit);
#define _offsetof(t, m) ((uintptr_t)((caddr_t)&((t *)0)->m))
		masklen = _offsetof(struct sockaddr_dl, sdl_data[0]) + namelen;
		socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof(u_int32_t) - 1)))
		if ((u_int32_t)socksize < sizeof(struct sockaddr_dl))
			socksize = sizeof(struct sockaddr_dl);
		socksize = ROUNDUP(socksize);
		ifasize = sizeof(struct ifaddr) + 2 * socksize;
		
		/*
		 * Allocate a new ifa if we don't have one
		 * or the old one is too small.
		 */
		if (ifa == NULL || socksize > ifa->ifa_addr->sa_len) {
			if (ifa)
				if_detach_ifa(ifp, ifa);
			ifa = (struct ifaddr*)_MALLOC(ifasize, M_IFADDR, M_WAITOK);
		}
		
		if (ifa) {
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifa + 1);
			ifnet_addrs[ifp->if_index - 1] = ifa;
			bzero(ifa, ifasize);
			ifa->ifa_debug |= IFD_ALLOC;
			sdl->sdl_len = socksize;
			sdl->sdl_family = AF_LINK;
			bcopy(workbuf, sdl->sdl_data, namelen);
			sdl->sdl_nlen = namelen;
			sdl->sdl_index = ifp->if_index;
			sdl->sdl_type = ifp->if_type;
			if (ll_addr) {
				sdl->sdl_alen = ll_addr->sdl_alen;
				if (ll_addr->sdl_alen != ifp->if_addrlen)
					panic("ifnet_attach - ll_addr->sdl_alen != ifp->if_addrlen");
				bcopy(CONST_LLADDR(ll_addr), LLADDR(sdl), sdl->sdl_alen);
			}
			ifa->ifa_ifp = ifp;
			ifa->ifa_rtrequest = link_rtrequest;
			ifa->ifa_addr = (struct sockaddr*)sdl;
			sdl = (struct sockaddr_dl*)(socksize + (caddr_t)sdl);
			ifa->ifa_netmask = (struct sockaddr*)sdl;
			sdl->sdl_len = masklen;
			while (namelen != 0)
				sdl->sdl_data[--namelen] = 0xff;
		}

		TAILQ_INIT(&ifp->if_addrhead);
		ifa = ifnet_addrs[ifp->if_index - 1];
		
		if (ifa) {
			/*
			 * We don't use if_attach_ifa because we want
			 * this address to be first on the list.
			 */
			ifaref(ifa);
			ifa->ifa_debug |= IFD_ATTACHED;
			TAILQ_INSERT_HEAD(&ifp->if_addrhead, ifa, ifa_link);
		}
#if CONFIG_MACF_NET
		mac_ifnet_label_associate(ifp);
#endif
		
		TAILQ_INSERT_TAIL(&ifnet_head, ifp, if_link);
		ifindex2ifnet[ifp->if_index] = ifp;
	}

	/* 
	 * A specific dlil input thread is created per Ethernet/PDP interface.
	 * pseudo interfaces or other types of interfaces use the main ("loopback") thread.
	 * If the sysctl "net.link.generic.system.multi_threaded_input" is set to zero, all packets will
	 * be handled by the main loopback thread, reverting to 10.4.x behaviour.
	 * 
	 */

	if (ifp->if_type == IFT_ETHER || ifp->if_type == IFT_PDP) {
		int err;

		if (dlil_multithreaded_input > 0) {
			ifp->if_input_thread = _MALLOC(sizeof(struct dlil_threading_info), M_NKE, M_WAITOK);
			if (ifp->if_input_thread == NULL)
				panic("ifnet_attach ifp=%p couldn't alloc threading\n", ifp);
			if ((err = dlil_create_input_thread(ifp, ifp->if_input_thread)) != 0)
				panic("ifnet_attach ifp=%p couldn't get a thread. err=%d\n", ifp, err);
#ifdef DLIL_DEBUG
			printf("ifnet_attach: dlil thread for ifp=%p if_index=%d\n", ifp, ifp->if_index);
#endif
		}
	}
	ifnet_lock_done(ifp);
	ifnet_head_done();
#if PF
	/*
	 * Attach packet filter to this interface, if enaled.
	 */
	pf_ifnet_hook(ifp, 1);
#endif /* PF */
	dlil_write_end();

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, NULL, 0);

    return 0;
}

errno_t
ifnet_detach(
	ifnet_t	ifp)
{
	struct ifnet_filter *filter;
	struct ifnet_filter	*filter_next;
	int zeroed = 0;
	int retval = 0;
	struct ifnet_filter_head fhead;
	struct dlil_threading_info *inputthread;
	
	if (ifp == NULL) return EINVAL;
	
	ifnet_lock_exclusive(ifp);
	
	if ((ifp->if_eflags & IFEF_DETACHING) != 0) {
		/* Interface has already been detached */
		ifnet_lock_done(ifp);
		return ENXIO;
	}
	
	/*
	 * Indicate this interface is being detached.
	 * 
	 * This should prevent protocols from attaching
	 * from this point on. Interface will remain on
	 * the list until all of the protocols are detached.
	 */
	ifp->if_eflags |= IFEF_DETACHING;
	ifnet_lock_done(ifp);
	
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHING, NULL, 0);
	
	/* Let BPF know we're detaching */
	bpfdetach(ifp);
	
	if ((retval = dlil_write_begin()) != 0) {
		if (retval == EDEADLK) {
			retval = 0;
			
			/* We need to perform a delayed detach */
			ifp->if_delayed_detach = 1;
			dlil_detach_waiting = 1;
			wakeup(&dlil_detach_waiting);
		}
		return retval;
	}

#if PF
	/*
	 * Detach this interface from packet filter, if enabled.
	 */
	pf_ifnet_hook(ifp, 0);
#endif /* PF */

	/* Steal the list of interface filters */
	fhead = ifp->if_flt_head;
	TAILQ_INIT(&ifp->if_flt_head);

	/* unuse the interface */
	zeroed = ifp_unuse(ifp);

	/*
	 * If thread affinity was set for the workloop thread, we will need
	 * to tear down the affinity and release the extra reference count
	 * taken at attach time;
	 */
	if ((inputthread = ifp->if_input_thread) != NULL) {
		if (inputthread->net_affinity) {
			struct thread *tp;

			if (inputthread == dlil_lo_thread_ptr)
				panic("Thread affinity should not be enabled "
				    "on the loopback dlil input thread\n");

			lck_mtx_lock(inputthread->input_lck);
			tp = inputthread->workloop_thread;
			inputthread->workloop_thread = NULL;
			inputthread->tag = 0;
			inputthread->net_affinity = FALSE;
			lck_mtx_unlock(inputthread->input_lck);

			/* Tear down workloop thread affinity */
			if (tp != NULL) {
				(void) dlil_affinity_set(tp,
				    THREAD_AFFINITY_TAG_NULL);
				thread_deallocate(tp);
			}

			/* Tear down dlil input thread affinity */
			tp = inputthread->input_thread;
			(void) dlil_affinity_set(tp, THREAD_AFFINITY_TAG_NULL);
			thread_deallocate(tp);
		}

		/* cleanup ifp dlil input thread, if any */
		ifp->if_input_thread = NULL;

		if (inputthread != dlil_lo_thread_ptr) {
#ifdef DLIL_DEBUG
			printf("ifnet_detach: wakeup thread threadinfo: %p "
			    "input_thread=%p threads: cur=%d max=%d\n",
			    inputthread, inputthread->input_thread,
			    dlil_multithreaded_input, cur_dlil_input_threads);
#endif
			lck_mtx_lock(inputthread->input_lck);

			inputthread->input_waiting |= DLIL_INPUT_TERMINATE;
			if ((inputthread->input_waiting & DLIL_INPUT_RUNNING) == 0) {
				wakeup((caddr_t)&inputthread->input_waiting);
			}
			lck_mtx_unlock(inputthread->input_lck);
		}
	}
	/* last chance to clean up IPv4 forwarding cached route */
	lck_mtx_lock(ifp->if_fwd_route_lock);
	if (ifp->if_fwd_route.ro_rt != NULL) {
		rtfree(ifp->if_fwd_route.ro_rt);
		ifp->if_fwd_route.ro_rt = NULL;
	}
	lck_mtx_unlock(ifp->if_fwd_route_lock);
	dlil_write_end();
	
	for (filter = TAILQ_FIRST(&fhead); filter; filter = filter_next) {
		filter_next = TAILQ_NEXT(filter, filt_next);
		dlil_detach_filter_internal(filter, 1);
	}
	
	if (zeroed != 0) {
		ifp_use_reached_zero(ifp);
	}
	
	return retval;
}

static errno_t
dlil_recycle_ioctl(
	__unused ifnet_t ifnet_ptr,
	__unused u_long ioctl_code,
	__unused void *ioctl_arg)
{
    return EOPNOTSUPP;
}

static int
dlil_recycle_output(
	__unused struct ifnet *ifnet_ptr,
	struct mbuf *m)
{
    m_freem(m);
    return 0;
}

static void
dlil_recycle_free(
	__unused ifnet_t ifnet_ptr)
{
}

static errno_t
dlil_recycle_set_bpf_tap(
	__unused ifnet_t ifp,
	__unused bpf_tap_mode mode,
	__unused bpf_packet_func callback)
{
    /* XXX not sure what to do here */
    return 0;
}

__private_extern__
int dlil_if_acquire(
	u_int32_t family,
	const void *uniqueid,
	size_t uniqueid_len, 
	struct ifnet **ifp)
{
    struct ifnet	*ifp1 = NULL;
    struct dlil_ifnet	*dlifp1 = NULL;
    int	ret = 0;

    lck_mtx_lock(dlil_ifnet_mutex);
    TAILQ_FOREACH(dlifp1, &dlil_ifnet_head, dl_if_link) {
        
        ifp1 = (struct ifnet *)dlifp1;
            
		if (ifp1->if_family == family)  {
        
            /* same uniqueid and same len or no unique id specified */
            if ((uniqueid_len == dlifp1->if_uniqueid_len)
                && !bcmp(uniqueid, dlifp1->if_uniqueid, uniqueid_len)) {
                
				/* check for matching interface in use */
				if (ifp1->if_eflags & IFEF_INUSE) {
					if (uniqueid_len) {
						ret = EBUSY;
						goto end;
					}
				}
				else {
					if (!ifp1->if_lock)
						panic("ifp's lock is gone\n");
					ifnet_lock_exclusive(ifp1);
					ifp1->if_eflags |= (IFEF_INUSE | IFEF_REUSE);
					ifnet_lock_done(ifp1);
					*ifp = ifp1;
					goto end;
            	}
            }
        }
    }

    /* no interface found, allocate a new one */
    MALLOC(dlifp1, struct dlil_ifnet *, sizeof(*dlifp1), M_NKE, M_WAITOK);
    if (dlifp1 == 0) {
        ret = ENOMEM;
        goto end;
    }
    
    bzero(dlifp1, sizeof(*dlifp1));
    
    if (uniqueid_len) {
        MALLOC(dlifp1->if_uniqueid, void *, uniqueid_len, M_NKE, M_WAITOK);
        if (dlifp1->if_uniqueid == 0) {
            FREE(dlifp1, M_NKE);
            ret = ENOMEM;
           goto end;
        }
        bcopy(uniqueid, dlifp1->if_uniqueid, uniqueid_len);
        dlifp1->if_uniqueid_len = uniqueid_len;
    }

    ifp1 = (struct ifnet *)dlifp1;
    ifp1->if_eflags |= IFEF_INUSE;
    ifp1->if_name = dlifp1->if_namestorage;
#if CONFIG_MACF_NET
    mac_ifnet_label_init(ifp1);
#endif

    TAILQ_INSERT_TAIL(&dlil_ifnet_head, dlifp1, dl_if_link);
     
     *ifp = ifp1;

end:
	lck_mtx_unlock(dlil_ifnet_mutex);

    return ret;
}

__private_extern__ void
dlil_if_release(
	ifnet_t	ifp)
{
    struct dlil_ifnet	*dlifp = (struct dlil_ifnet *)ifp;
    
    /* Interface does not have a lock until it is attached - radar 3713951 */
    if (ifp->if_lock)
		ifnet_lock_exclusive(ifp);
    ifp->if_eflags &= ~IFEF_INUSE;
    ifp->if_ioctl = dlil_recycle_ioctl;
    ifp->if_output = dlil_recycle_output;
    ifp->if_free = dlil_recycle_free;
    ifp->if_set_bpf_tap = dlil_recycle_set_bpf_tap;

    strncpy(dlifp->if_namestorage, ifp->if_name, IFNAMSIZ);
    ifp->if_name = dlifp->if_namestorage;
#if CONFIG_MACF_NET
    /*
     * We can either recycle the MAC label here or in dlil_if_acquire().
     * It seems logical to do it here but this means that anything that
     * still has a handle on ifp will now see it as unlabeled.
     * Since the interface is "dead" that may be OK.  Revisit later.
     */
    mac_ifnet_label_recycle(ifp);
#endif
    if (ifp->if_lock)
		ifnet_lock_done(ifp);
    
}

__private_extern__ void
dlil_proto_unplumb_all(struct ifnet *ifp)
{
	/*
	 * if_proto_hash[0-3] are for PF_INET, PF_INET6, PF_APPLETALK
	 * and PF_VLAN, where each bucket contains exactly one entry;
	 * PF_VLAN does not need an explicit unplumb.
	 *
	 * if_proto_hash[4] is for other protocols; we expect anything
	 * in this bucket to respond to the DETACHING event (which would
	 * have happened by now) and do the unplumb then.
	 */
	(void) proto_unplumb(PF_INET, ifp);
#if INET6
	(void) proto_unplumb(PF_INET6, ifp);
#endif /* INET6 */
#if NETAT
	(void) proto_unplumb(PF_APPLETALK, ifp);
#endif /* NETAT */
}
