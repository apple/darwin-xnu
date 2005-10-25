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
 *	Copyright (c) 1999 Apple Computer, Inc. 
 *
 *	Data Link Inteface Layer
 *	Author: Ted Walker
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/user.h>
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

#include <net/if_types.h>
#include <net/kpi_interfacefilter.h>

#include <libkern/OSAtomic.h>

#include <machine/machine_routines.h>

#define DBG_LAYER_BEG		DLILDBG_CODE(DBG_DLIL_STATIC, 0)
#define DBG_LAYER_END		DLILDBG_CODE(DBG_DLIL_STATIC, 2)
#define DBG_FNC_DLIL_INPUT      DLILDBG_CODE(DBG_DLIL_STATIC, (1 << 8))
#define DBG_FNC_DLIL_OUTPUT     DLILDBG_CODE(DBG_DLIL_STATIC, (2 << 8))
#define DBG_FNC_DLIL_IFOUT      DLILDBG_CODE(DBG_DLIL_STATIC, (3 << 8))


#define MAX_DL_TAGS 		16
#define MAX_DLIL_FILTERS 	16
#define MAX_FRAME_TYPE_SIZE 4 /* LONGWORDS */
#define MAX_LINKADDR	    4 /* LONGWORDS */
#define M_NKE M_IFADDR

#define PFILT(x) ((struct dlil_filterq_entry *) (x))->variants.pr_filter
#define IFILT(x) ((struct dlil_filterq_entry *) (x))->variants.if_filter

#if 0
#define DLIL_PRINTF	printf
#else
#define DLIL_PRINTF	kprintf
#endif

enum {
	kProtoKPI_DLIL	= 0,
	kProtoKPI_v1	= 1
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
			dl_input_func			 dl_input;
			dl_pre_output_func		 dl_pre_output;
			dl_event_func			 dl_event;
			dl_offer_func			 dl_offer;
			dl_ioctl_func			 dl_ioctl;
			dl_detached_func		 dl_detached;
		} dlil;
		struct {
			proto_media_input			input;
			proto_media_preout			pre_output;
			proto_media_event			event;
			proto_media_ioctl			ioctl;
			proto_media_detached		detached;
			proto_media_resolve_multi	resolve_multi;
			proto_media_send_arp		send_arp;
		} v1;
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

struct if_family_str {
    TAILQ_ENTRY(if_family_str) if_fam_next;
    u_long	if_family;
    int		refcnt;
    int		flags;

#define DLIL_SHUTDOWN 1

    int (*add_if)(struct ifnet *ifp);
    int (*del_if)(struct ifnet *ifp);
    int (*init_if)(struct ifnet *ifp);
    int (*add_proto)(struct ifnet *ifp, u_long protocol_family, struct ddesc_head_str *demux_desc_head);
	ifnet_del_proto_func	del_proto;
    ifnet_ioctl_func		ifmod_ioctl;
    int (*shutdown)(void);
};

struct proto_family_str {
	TAILQ_ENTRY(proto_family_str) proto_fam_next;
	u_long	proto_family;
	u_long	if_family;
	int		usecnt;

	int (*attach_proto)(struct ifnet *ifp, u_long protocol_family);
	int (*detach_proto)(struct ifnet *ifp, u_long protocol_family);
};

enum {
	kIfNetUseCount_MayBeZero = 0,
	kIfNetUseCount_MustNotBeZero = 1
};

static TAILQ_HEAD(, dlil_ifnet) dlil_ifnet_head;
static TAILQ_HEAD(, if_family_str) if_family_head;
static TAILQ_HEAD(, proto_family_str) proto_family_head;
static lck_grp_t *dlil_lock_group;
static lck_grp_t *ifnet_lock_group;
static lck_grp_t *ifnet_head_lock_group;
static lck_attr_t *ifnet_lock_attr;
static lck_mtx_t *proto_family_mutex;
static lck_rw_t *ifnet_head_mutex;
static lck_mtx_t *dlil_ifnet_mutex;
static lck_mtx_t *dlil_mutex;
static unsigned long dlil_read_count = 0;
static unsigned long dlil_detach_waiting = 0;
extern u_int32_t	ipv4_ll_arp_aware;

int dlil_initialized = 0;
lck_spin_t *dlil_input_lock;
__private_extern__ thread_t	dlil_input_thread_ptr = 0;
int dlil_input_thread_wakeup = 0;
__private_extern__ int dlil_output_thread_wakeup = 0;
static struct mbuf *dlil_input_mbuf_head = NULL;
static struct mbuf *dlil_input_mbuf_tail = NULL;
#if NLOOP > 1
#error dlil_input() needs to be revised to support more than on loopback interface
#endif
static struct mbuf *dlil_input_loop_head = NULL;
static struct mbuf *dlil_input_loop_tail = NULL;

static void dlil_input_thread(void);
static int dlil_event_internal(struct ifnet *ifp, struct kev_msg *msg);
struct ifnet *ifbyfamily(u_long family, short unit);
static int dlil_detach_filter_internal(interface_filter_t filter, int detached);
static void dlil_call_delayed_detach_thread(void);

static void	dlil_read_begin(void);
static void	dlil_read_end(void);
static int	dlil_write_begin(void);
static void	dlil_write_end(void);

static int ifp_use(struct ifnet *ifp, int handle_zero);
static int ifp_unuse(struct ifnet *ifp);
static void ifp_use_reached_zero(struct ifnet *ifp);

extern void bpfdetach(struct ifnet*);
extern void proto_input_run(void); // new run_netisr


int dlil_input_packet(struct ifnet  *ifp, struct mbuf *m, char *frame_header);

__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);

int dlil_expand_mcl;

extern u_int32_t	inject_buckets;

static const u_int32_t dlil_writer_waiting = 0x80000000;

static __inline__ void*
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
	unsigned long new_value;
	unsigned long old_value;
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
	
	OSDecrementAtomic((UInt32*)&dlil_read_count);
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
	OSBitOrAtomic((UInt32)dlil_writer_waiting, (UInt32*)&dlil_read_count);
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
	OSBitAndAtomic((UInt32)~dlil_writer_waiting, (UInt32*)&dlil_read_count);
	lck_mtx_unlock(dlil_mutex);
	uth->dlil_incremented_read = 0;
	wakeup(&dlil_read_count);
}

#define PROTO_HASH_SLOTS	0x5

/*
 * Internal functions.
 */

static int
proto_hash_value(u_long protocol_family)
{
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

static 
struct if_family_str *find_family_module(u_long if_family)
{
    struct if_family_str  *mod = NULL;

    TAILQ_FOREACH(mod, &if_family_head, if_fam_next) {
	if (mod->if_family == (if_family & 0xffff)) 
	    break;
    }

    return mod;
}

static 
struct proto_family_str*
find_proto_module(u_long proto_family, u_long if_family)
{
	struct proto_family_str  *mod = NULL;

	TAILQ_FOREACH(mod, &proto_family_head, proto_fam_next) {
		if ((mod->proto_family == (proto_family & 0xffff)) 
			&& (mod->if_family == (if_family & 0xffff))) 
			break;
		}

	return mod;
}

static struct if_proto*
find_attached_proto(struct ifnet *ifp, u_long protocol_family)
{
	struct if_proto *proto = NULL;
	u_long i = proto_hash_value(protocol_family);
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
	OSAddAtomic(1, (UInt32*)&proto->refcount);
}

static void
if_proto_free(struct if_proto *proto)
{
	int oldval = OSAddAtomic(-1, (UInt32*)&proto->refcount);
	
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
ifnet_head_lock_shared()
{
	lck_rw_lock_shared(ifnet_head_mutex);
}

__private_extern__ void
ifnet_head_lock_exclusive()
{
	lck_rw_lock_exclusive(ifnet_head_mutex);
}

__private_extern__ void
ifnet_head_done()
{
	lck_rw_done(ifnet_head_mutex);
}

/*
 * Public functions.
 */
struct ifnet *ifbyfamily(u_long family, short unit)
{
	struct ifnet *ifp;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
		if ((family == ifp->if_family) && (ifp->if_unit == unit))
			break;
	ifnet_head_done();

	return ifp;
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
dlil_post_msg(struct ifnet *ifp, u_long event_subclass, u_long event_code, 
		   struct net_event_data *event_data, u_long event_data_len) 
{
	struct net_event_data  	ev_data;
	struct kev_msg  		ev_msg;
	
	/* 
	 * a net event always start with a net_event_data structure
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
	event_data->if_unit   = (unsigned long) ifp->if_unit;
	
	ev_msg.dv[0].data_length = event_data_len;
	ev_msg.dv[0].data_ptr    = event_data;	
	ev_msg.dv[1].data_length = 0;
	
	dlil_event_internal(ifp, &ev_msg);
}

void dlil_init(void);
void
dlil_init(void)
{
	lck_grp_attr_t	*grp_attributes = 0;
	lck_attr_t		*lck_attributes = 0;
	lck_grp_t		*input_lock_grp = 0;
	
	TAILQ_INIT(&dlil_ifnet_head);
	TAILQ_INIT(&if_family_head);
	TAILQ_INIT(&proto_family_head);
	TAILQ_INIT(&ifnet_head);
	
	/* Setup the lock groups we will use */
	grp_attributes = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(grp_attributes);

	dlil_lock_group = lck_grp_alloc_init("dlil internal locks", grp_attributes);
#if IFNET_RW_LOCK
	ifnet_lock_group = lck_grp_alloc_init("ifnet locks", grp_attributes);
#else
	ifnet_lock_group = lck_grp_alloc_init("ifnet locks", grp_attributes);
#endif
	ifnet_head_lock_group = lck_grp_alloc_init("ifnet head lock", grp_attributes);
	input_lock_grp = lck_grp_alloc_init("dlil input lock", grp_attributes);
	lck_grp_attr_free(grp_attributes);
	grp_attributes = 0;
	
	/* Setup the lock attributes we will use */
	lck_attributes = lck_attr_alloc_init();
	lck_attr_setdefault(lck_attributes);
	
	ifnet_lock_attr = lck_attr_alloc_init();
	lck_attr_setdefault(ifnet_lock_attr);
	
	dlil_input_lock = lck_spin_alloc_init(input_lock_grp, lck_attributes);
	input_lock_grp = 0;
	
	ifnet_head_mutex = lck_rw_alloc_init(ifnet_head_lock_group, lck_attributes);
	proto_family_mutex = lck_mtx_alloc_init(dlil_lock_group, lck_attributes);
	dlil_ifnet_mutex = lck_mtx_alloc_init(dlil_lock_group, lck_attributes);
	dlil_mutex = lck_mtx_alloc_init(dlil_lock_group, lck_attributes);
	
	lck_attr_free(lck_attributes);
	lck_attributes = 0;
	
	/*
	 * Start up the dlil input thread once everything is initialized
	 */
	(void) kernel_thread(kernel_task, dlil_input_thread);
	(void) kernel_thread(kernel_task, dlil_call_delayed_detach_thread);
}

int
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
	return retval;
}

static int
dlil_detach_filter_internal(interface_filter_t filter, int detached)
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
	
	return retval;
}

void
dlil_detach_filter(interface_filter_t filter)
{
	if (filter == NULL)
		return;
	dlil_detach_filter_internal(filter, 0);
}

static void
dlil_input_thread_continue(
	__unused void*			foo,
	__unused wait_result_t	wait)
{
	while (1) {
		struct mbuf *m, *m_loop;
		
		lck_spin_lock(dlil_input_lock);
		m = dlil_input_mbuf_head;
		dlil_input_mbuf_head = NULL;
		dlil_input_mbuf_tail = NULL;
		m_loop = dlil_input_loop_head;
		dlil_input_loop_head = NULL;
		dlil_input_loop_tail = NULL;
		lck_spin_unlock(dlil_input_lock);
		
		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation safeguards if 
		* we deal with long chains of packets.
		*/
		while (m) {
			struct mbuf *m0 = m->m_nextpkt;
			void *header = m->m_pkthdr.header;
			
			m->m_nextpkt = NULL;
			m->m_pkthdr.header = NULL;
			(void) dlil_input_packet(m->m_pkthdr.rcvif, m, header);
			m = m0;
		}
		m = m_loop;
		while (m) {
			struct mbuf *m0 = m->m_nextpkt;
			void *header = m->m_pkthdr.header;
			struct ifnet *ifp = &loif[0];
			
			m->m_nextpkt = NULL;
			m->m_pkthdr.header = NULL;
			(void) dlil_input_packet(ifp, m, header);
			m = m0;
		}
		
		proto_input_run();
		
		if (dlil_input_mbuf_head == NULL && 
			dlil_input_loop_head == NULL && inject_buckets == 0) {
			assert_wait(&dlil_input_thread_wakeup, THREAD_UNINT);
			(void) thread_block(dlil_input_thread_continue);
			/* NOTREACHED */
		}
	}
}

void dlil_input_thread(void)
{
	register thread_t self = current_thread();
	
	ml_thread_policy(self, MACHINE_GROUP,
					 (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_NETISR));
	
	dlil_initialized = 1;
	dlil_input_thread_ptr = current_thread();
	dlil_input_thread_continue(NULL, THREAD_RESTART);
}

int
dlil_input_with_stats(
	struct ifnet *ifp,
	struct mbuf *m_head,
	struct mbuf *m_tail,
	const struct ifnet_stat_increment_param *stats)
{
	/* WARNING
	 * Because of loopbacked multicast we cannot stuff the ifp in
	 * the rcvif of the packet header: loopback has its own dlil
	 * input queue
	 */
	
	lck_spin_lock(dlil_input_lock);
	if (ifp->if_type != IFT_LOOP) {
		if (dlil_input_mbuf_head == NULL)
			dlil_input_mbuf_head = m_head;
		else if (dlil_input_mbuf_tail != NULL)
			dlil_input_mbuf_tail->m_nextpkt = m_head;
		dlil_input_mbuf_tail = m_tail ? m_tail : m_head;
	} else {
		if (dlil_input_loop_head == NULL)
			dlil_input_loop_head = m_head;
		else if (dlil_input_loop_tail != NULL)
			dlil_input_loop_tail->m_nextpkt = m_head;
		dlil_input_loop_tail = m_tail ? m_tail : m_head;
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
	lck_spin_unlock(dlil_input_lock);
	
	wakeup((caddr_t)&dlil_input_thread_wakeup);
	
	return 0; 
}

int
dlil_input(struct ifnet  *ifp, struct mbuf *m_head, struct mbuf *m_tail)
{
	return dlil_input_with_stats(ifp, m_head, m_tail, NULL);
}

int
dlil_input_packet(struct ifnet  *ifp, struct mbuf *m,
	   char *frame_header)
{
    int				 retval;
    struct if_proto		 *ifproto = 0;
    protocol_family_t	protocol_family;
    struct ifnet_filter	*filter;


    KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START,0,0,0,0,0);

	/*
	 * Lock the interface while we run through
	 * the filters and the demux. This lock
	 * protects the filter list and the demux list.
	 */
	dlil_read_begin();

	/*
	 * Call family demux module. If the demux module finds a match
	 * for the frame it will fill-in the ifproto pointer.
	 */

	retval = ifp->if_demux(ifp, m, frame_header, &protocol_family);
	if (retval != 0)
		protocol_family = 0;
	if (retval == EJUSTRETURN) {
		dlil_read_end();
		return 0;
	}

	/* DANGER!!! */
	if (m->m_flags & (M_BCAST|M_MCAST))
		ifp->if_imcasts++;

	/*
	 * Run interface filters
	 */
	
	/* Do not pass VLAN tagged packets to filters PR-3586856 */
	if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
		TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
			int	filter_result;
			if (filter->filt_input && (filter->filt_protocol == 0 ||
				 filter->filt_protocol == protocol_family)) {
				filter_result = filter->filt_input(filter->filt_cookie, ifp, protocol_family, &m, &frame_header);
				
				if (filter_result) {
					dlil_read_end();
					if (filter_result == EJUSTRETURN) {
						filter_result = 0;
					}
					else {
						m_freem(m);
					}
					
					return filter_result;
				}
			}
		}
	}

	/* Demux is done, interface filters have been processed, unlock the mutex */
	if (retval || ((m->m_flags & M_PROMISC) != 0) ) {
		dlil_read_end();
		if (retval != EJUSTRETURN) {
			m_freem(m);
			return retval;
		}
		else
			return 0;
	}
	
	ifproto = find_attached_proto(ifp, protocol_family);
	
	if (ifproto == 0) {
		dlil_read_end();
		DLIL_PRINTF("ERROR - dlil_input - if_demux didn't return an if_proto pointer\n");
		m_freem(m);
		return 0;
	}
	
	/*
	 * Hand the packet off to the protocol.
	 */

	if (ifproto->dl_domain && (ifproto->dl_domain->dom_flags & DOM_REENTRANT) == 0) {
		lck_mtx_lock(ifproto->dl_domain->dom_mtx);
	}

	if (ifproto->proto_kpi == kProtoKPI_DLIL)
		retval = (*ifproto->kpi.dlil.dl_input)(m, frame_header, 
					  ifp, ifproto->protocol_family, 
					  TRUE);
	else
		retval = ifproto->kpi.v1.input(ifp, ifproto->protocol_family, m, frame_header);

	if (ifproto->dl_domain && (ifproto->dl_domain->dom_flags & DOM_REENTRANT) == 0) {
		lck_mtx_unlock(ifproto->dl_domain->dom_mtx);
	}

	dlil_read_end();

	if (retval == EJUSTRETURN)
		retval = 0;
	else 
		if (retval)
			m_freem(m);

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return retval;
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
					/* Pass the event to the protocol */
					if (proto->proto_kpi == kProtoKPI_DLIL) {
						if (proto->kpi.dlil.dl_event)
							proto->kpi.dlil.dl_event(ifp, event);
					}
					else {
						if (proto->kpi.v1.event)
							proto->kpi.v1.event(ifp, proto->protocol_family, event);
					}
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

int
dlil_event(struct ifnet *ifp, struct kern_event_msg *event)
{
    int result = 0;

	struct kev_msg               kev_msg;

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

int
dlil_output_list(
	struct ifnet* ifp,
	u_long proto_family,
	struct mbuf		*packetlist,
	caddr_t		route,
	const struct sockaddr	*dest,
	int			raw)
{
	char			*frame_type = 0;
	char			*dst_linkaddr = 0;
	int			error, retval = 0;
	char			frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
	char			dst_linkaddr_buffer[MAX_LINKADDR * 4];
	struct ifnet_filter *filter;
	struct if_proto	*proto = 0;
	struct mbuf *m;
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);
#if BRIDGE
	if ((raw != 0) || proto_family != PF_INET || do_brige) {
#else
	if ((raw != 0) || proto_family != PF_INET) {
#endif
		while (packetlist) {
			m = packetlist;
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
			error = dlil_output(ifp, proto_family, m, route, dest, raw);
			if (error) {
				if (packetlist)
					m_freem_list(packetlist);
				return (error);
			}
		}
		return (0);
	}
	
	dlil_read_begin();
	
	frame_type	   = frame_type_buffer;
	dst_linkaddr   = dst_linkaddr_buffer;
	m = packetlist;
	packetlist = packetlist->m_nextpkt;
	m->m_nextpkt = NULL;
	
	proto = find_attached_proto(ifp, proto_family);
	if (proto == NULL) {
		retval = ENXIO;
		goto cleanup;
	}

	retval = 0;
	if (proto->proto_kpi == kProtoKPI_DLIL) {
		if (proto->kpi.dlil.dl_pre_output)
		retval = proto->kpi.dlil.dl_pre_output(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
	}
	else {
		if (proto->kpi.v1.pre_output)
		retval = proto->kpi.v1.pre_output(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
	}

	if (retval) {
		if (retval != EJUSTRETURN)  {
			m_freem(m);
		}
		goto cleanup;
	}

	do {
		
	
		if (ifp->if_framer) {
			retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr, frame_type); 
			if (retval) {
				if (retval != EJUSTRETURN) {
					m_freem(m);
				}
				goto cleanup;
			}
		}
	
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
						if (retval == EJUSTRETURN)
							continue;
						else {
							m_freem(m);
						}
						goto cleanup;
					}
				}
			}
		}
		/*
		* Finally, call the driver.
		*/
	
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
		retval = ifp->if_output(ifp, m);
		if (retval) {
			printf("dlil_output_list: output error retval = %x\n", retval);
			goto cleanup;
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);

		m = packetlist;
		if (m) {
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
		}
	} while (m);

	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

cleanup:
	dlil_read_end();
	if (packetlist) /* if any packet left, clean up */
		m_freem_list(packetlist);
	if (retval == EJUSTRETURN)
		retval = 0;
	return retval;
}

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
int
dlil_output(
	struct ifnet* ifp,
	u_long proto_family,
	struct mbuf		*m,
	caddr_t		route,
	const struct sockaddr	*dest,
	int			raw)
{
	char			*frame_type = 0;
	char			*dst_linkaddr = 0;
	int				retval = 0;
	char			frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
	char			dst_linkaddr_buffer[MAX_LINKADDR * 4];
	struct ifnet_filter *filter;
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);
	
	dlil_read_begin();
	
	frame_type	   = frame_type_buffer;
	dst_linkaddr   = dst_linkaddr_buffer;
	
	if (raw == 0) {
		struct if_proto	*proto = 0;
		
		proto = find_attached_proto(ifp, proto_family);
		if (proto == NULL) {
			m_freem(m);
			retval = ENXIO;
			goto cleanup;
		}
		
		retval = 0;
		if (proto->proto_kpi == kProtoKPI_DLIL) {
			if (proto->kpi.dlil.dl_pre_output)
				retval = proto->kpi.dlil.dl_pre_output(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
		}
		else {
			if (proto->kpi.v1.pre_output)
				retval = proto->kpi.v1.pre_output(ifp, proto_family, &m, dest, route, frame_type, dst_linkaddr);
		}
		
		if (retval) {
			if (retval != EJUSTRETURN) {
				m_freem(m);
			}
			goto cleanup;
		}
	}
	
	/*
	 * Call framing module 
	 */
	if ((raw == 0) && (ifp->if_framer)) {
		retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr, frame_type); 
		if (retval) {
			if (retval != EJUSTRETURN) {
				m_freem(m);
			}
			goto cleanup;
		}
	}
	
#if BRIDGE
	/* !!!LOCKING!!!
	 *
	 * Need to consider how to handle this.
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
		
		return 0;
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
					goto cleanup;
				}
			}
		}
	}
	
	/*
	* Finally, call the driver.
	*/
	
	KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
	retval = ifp->if_output(ifp, m);
	KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
	
	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

cleanup:
	dlil_read_end();
	if (retval == EJUSTRETURN)
		retval = 0;
	return retval;
}

int
dlil_ioctl(u_long	proto_fam,
	   struct ifnet *ifp,
	   u_long	ioctl_code,
	   caddr_t	ioctl_arg)
{
	struct ifnet_filter		*filter;
	int						retval = EOPNOTSUPP;
	int						result = 0;
	struct if_family_str	*if_family;
	int						holding_read = 0;
	
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
			result = EOPNOTSUPP;
			if (proto->proto_kpi == kProtoKPI_DLIL) {
				if (proto->kpi.dlil.dl_ioctl)
					result = proto->kpi.dlil.dl_ioctl(proto_fam, ifp, ioctl_code, ioctl_arg);
			}
			else {
				if (proto->kpi.v1.ioctl)
					result = proto->kpi.v1.ioctl(ifp, proto_fam, ioctl_code, ioctl_arg);
			}
			
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
	 * Let the family handle this ioctl.
	 * If it returns something non-zero and not EOPNOTSUPP, we're done.
	 * If it returns zero, the ioctl was handled, so set retval to zero.
	 */
	if_family = find_family_module(ifp->if_family);
	if ((if_family) && (if_family->ifmod_ioctl)) {
		result = (*if_family->ifmod_ioctl)(ifp, ioctl_code, ioctl_arg);
		
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

__private_extern__ errno_t
dlil_resolve_multi(
	struct ifnet *ifp,
	const struct sockaddr *proto_addr,
	struct sockaddr *ll_addr,
	size_t ll_len)
{
	errno_t	result = EOPNOTSUPP;
	struct if_proto *proto;
	const struct sockaddr *verify;
	
	dlil_read_begin();
	
	bzero(ll_addr, ll_len);
	
	/* Call the protocol first */
	proto = find_attached_proto(ifp, proto_addr->sa_family);
	if (proto != NULL && proto->proto_kpi != kProtoKPI_DLIL &&
		proto->kpi.v1.resolve_multi != NULL) {
		result = proto->kpi.v1.resolve_multi(ifp, proto_addr,
										(struct sockaddr_dl*)ll_addr, ll_len);
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
	if (proto == NULL || proto->proto_kpi == kProtoKPI_DLIL ||
		proto->kpi.v1.send_arp == NULL) {
		result = ENOTSUP;
	}
	else {
		result = proto->kpi.v1.send_arp(ifp, arpop, sender_hw, sender_proto,
										target_hw, target_proto);
	}
	
	dlil_read_end();
	
	return result;
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
	
	if (target_proto == NULL || (sender_proto &&
		sender_proto->sa_family != target_proto->sa_family))
		return EINVAL;
	
	/*
	 * If this is an ARP request and the target IP is IPv4LL,
	 * send the request on all interfaces.
	 */
	if (IN_LINKLOCAL(((const struct sockaddr_in*)target_proto)->sin_addr.s_addr)
		 && ipv4_ll_arp_aware != 0 && target_proto->sa_family == AF_INET &&
		arpop == ARPOP_REQUEST) {
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
				
				source_hw = TAILQ_FIRST(&ifp_list[ifp_on]->if_addrhead);
				
				/* Find the source IP address */
				ifnet_lock_shared(ifp_list[ifp_on]);
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
				
				ifnet_lock_done(ifp_list[ifp_on]);
				
				/* Send the ARP */
				new_result = dlil_send_arp_internal(ifp_list[ifp_on], arpop,
									(struct sockaddr_dl*)source_hw->ifa_addr,
									(struct sockaddr*)&source_ip_copy, NULL,
									target_proto);
				
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

static int
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
static void
ifp_use_reached_zero(
	struct ifnet *ifp)
{
	struct if_family_str *if_family;
	ifnet_detached_func	free_func;
	
	dlil_read_begin();
	
	if (ifp->if_usecnt != 0)
		panic("ifp_use_reached_zero: ifp->if_usecnt != 0");
	
	/* Let BPF know we're detaching */
	bpfdetach(ifp);
	
	ifnet_head_lock_exclusive();
	ifnet_lock_exclusive(ifp);
	
	/* Remove ourselves from the list */
	TAILQ_REMOVE(&ifnet_head, ifp, if_link);
	ifnet_addrs[ifp->if_index - 1] = 0;
	
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
	ifnet_head_done();
	
	ifp->if_eflags &= ~IFEF_DETACHING; // clear the detaching flag
	ifnet_lock_done(ifp);

	if_family = find_family_module(ifp->if_family);
	if (if_family && if_family->del_if)
		if_family->del_if(ifp);
#if 0
	if (--if_family->if_usecnt == 0) {
		if (if_family->shutdown)
			(*if_family->shutdown)();
		
		TAILQ_REMOVE(&if_family_head, if_family, if_fam_next);
		FREE(if_family, M_IFADDR);
	}
#endif

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, 0, 0);
	free_func = ifp->if_free;
	dlil_read_end();
	
	if (free_func)
		free_func(ifp);
}

static int
ifp_unuse(
	struct ifnet *ifp)
{
	int	oldval;
	oldval = OSDecrementAtomic((UInt32*)&ifp->if_usecnt);
	if (oldval == 0)
		panic("ifp_unuse: ifp(%s%n)->if_usecnt was zero\n", ifp->if_name, ifp->if_unit);
 	
	if (oldval > 1)
		return 0;
 	
	if ((ifp->if_eflags & IFEF_DETACHING) == 0)
		panic("ifp_unuse: use count reached zero but detching flag is not set!");
 	
 	return 1; /* caller must call ifp_use_reached_zero */
}

void
ifp_reference(
	struct ifnet *ifp)
{
	int	oldval;
	oldval = OSIncrementAtomic(&ifp->if_refcnt);
}

void
ifp_release(
	struct ifnet *ifp)
{
	int	oldval;
	oldval = OSDecrementAtomic((UInt32*)&ifp->if_refcnt);
	if (oldval == 0)
		panic("dlil_if_reference - refcount decremented past zero!");
}

extern lck_mtx_t 	*domain_proto_mtx;

static int
dlil_attach_protocol_internal(
	struct if_proto	*proto,
	const struct ddesc_head_str *demux,
	const struct ifnet_demux_desc *demux_list,
	u_int32_t	demux_count)
{
	struct ddesc_head_str temp_head;
	struct kev_dl_proto_data	ev_pr_data;
	struct ifnet *ifp = proto->ifp;
	int retval = 0;
	u_long hash_value = proto_hash_value(proto->protocol_family);
	int	if_using_kpi = (ifp->if_eflags & IFEF_USEKPI) != 0;
	void* free_me = NULL;
    
    /* setup some of the common values */
	
	{
		lck_mtx_lock(domain_proto_mtx);
		struct domain *dp = domains;
		while (dp && (protocol_family_t)dp->dom_family != proto->protocol_family)
			dp = dp->dom_next;
		proto->dl_domain = dp;
		lck_mtx_unlock(domain_proto_mtx);
	}
	
	/*
	 * Convert the demux descriptors to a type the interface
	 * will understand. Checking e_flags should be safe, this
	 * flag won't change.
	 */
	if (if_using_kpi && demux) {
		/* Convert the demux linked list to a demux_list */
		struct dlil_demux_desc	*demux_entry;
		struct ifnet_demux_desc *temp_list = NULL;
		u_int32_t i = 0;
		
		TAILQ_FOREACH(demux_entry, demux, next) {
			i++;
		}
		
		temp_list = _MALLOC(sizeof(struct ifnet_demux_desc) * i, M_TEMP, M_WAITOK);
		free_me = temp_list;
		
		if (temp_list == NULL)
			return ENOMEM;
		
		i = 0;
		TAILQ_FOREACH(demux_entry, demux, next) {
			/* dlil_demux_desc types 1, 2, and 3 are obsolete and can not be translated */
			if (demux_entry->type == 1 ||
				demux_entry->type == 2 ||
				demux_entry->type == 3) {
				FREE(free_me, M_TEMP);
				return ENOTSUP;
			}
			
			temp_list[i].type = demux_entry->type;
			temp_list[i].data = demux_entry->native_type;
			temp_list[i].datalen = demux_entry->variants.native_type_length;
			i++;
		}
		demux_count = i;
		demux_list = temp_list;
	}
	else if (!if_using_kpi && demux_list != NULL) {
		struct dlil_demux_desc *demux_entry;
		u_int32_t i = 0;
		
		demux_entry = _MALLOC(sizeof(struct dlil_demux_desc) * demux_count, M_TEMP, M_WAITOK);
		free_me = demux_entry;
		if (demux_entry == NULL)
			return ENOMEM;
		
		TAILQ_INIT(&temp_head);
		
		for (i = 0; i < demux_count; i++) {
			demux_entry[i].type = demux_list[i].type;
			demux_entry[i].native_type = demux_list[i].data;
			demux_entry[i].variants.native_type_length = demux_list[i].datalen;
			TAILQ_INSERT_TAIL(&temp_head, &demux_entry[i], next);
		}
		demux = &temp_head;
	}
	
	/*
	 * Take the write lock to protect readers and exclude other writers.
	 */
	dlil_write_begin();
	
	/* Check that the interface isn't currently detaching */
	ifnet_lock_shared(ifp);
	if ((ifp->if_eflags & IFEF_DETACHING) != 0) {
		ifnet_lock_done(ifp);
		dlil_write_end();
		if (free_me)
			FREE(free_me, M_TEMP);
		return ENXIO;
	}
	ifnet_lock_done(ifp);
	
	if (find_attached_proto(ifp, proto->protocol_family) != NULL) {
		dlil_write_end();
		if (free_me)
			FREE(free_me, M_TEMP);
		return EEXIST;
	}
	
	/*
	 * Call family module add_proto routine so it can refine the
	 * demux descriptors as it wishes.
	 */
	if (if_using_kpi)
		retval = ifp->if_add_proto_u.kpi(ifp, proto->protocol_family, demux_list, demux_count);
	else {
		retval = ifp->if_add_proto_u.original(ifp, proto->protocol_family,
											  _cast_non_const(demux));
	}
	if (retval) {
		dlil_write_end();
		if (free_me)
			FREE(free_me, M_TEMP);
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
	if (proto->proto_kpi == kProtoKPI_DLIL && proto->kpi.dlil.dl_offer)
		ifp->offercnt++;
	dlil_write_end();
	
	/* the reserved field carries the number of protocol still attached (subject to change) */
	ev_pr_data.proto_family = proto->protocol_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_ATTACHED, 
				  (struct net_event_data *)&ev_pr_data, 
				  sizeof(struct kev_dl_proto_data));
	
	DLIL_PRINTF("Attached protocol %d to %s%d - %d\n", proto->protocol_family,
			 ifp->if_name, ifp->if_unit, retval);
	if (free_me)
		FREE(free_me, M_TEMP);
	return retval;
}

__private_extern__ int
dlil_attach_protocol_kpi(ifnet_t ifp, protocol_family_t protocol,
	const struct ifnet_attach_proto_param *proto_details)
{
	int retval = 0;
	struct if_proto  *ifproto = NULL;
	
	ifproto = _MALLOC(sizeof(struct if_proto), M_IFADDR, M_WAITOK);
	if (ifproto == 0) {
		DLIL_PRINTF("ERROR - DLIL failed if_proto allocation\n");
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
	
	retval = dlil_attach_protocol_internal(ifproto, NULL,
				proto_details->demux_list, proto_details->demux_count);
	
end:
	if (retval && ifproto)
		FREE(ifproto, M_IFADDR);
	return retval;
}

int
dlil_attach_protocol(struct dlil_proto_reg_str	 *proto)
{
	struct ifnet     *ifp = NULL;
	struct if_proto  *ifproto = NULL;
	int	retval = 0;

	/*
	 * Do everything we can before taking the write lock
	 */
	
	if ((proto->protocol_family == 0) || (proto->interface_family == 0))
		return EINVAL;

	/*
	 * Allocate and init a new if_proto structure
	 */
	ifproto = _MALLOC(sizeof(struct if_proto), M_IFADDR, M_WAITOK);
	if (!ifproto) {
		DLIL_PRINTF("ERROR - DLIL failed if_proto allocation\n");
		retval = ENOMEM;
		goto end;
	}
	

	/* ifbyfamily returns us an ifp with an incremented if_usecnt */
	ifp = ifbyfamily(proto->interface_family, proto->unit_number);
	if (!ifp) {
		DLIL_PRINTF("dlil_attach_protocol -- no such interface %d unit %d\n", 
				proto->interface_family, proto->unit_number);
		retval = ENXIO;
		goto end;
	}

    bzero(ifproto, sizeof(struct if_proto));
	
	ifproto->ifp			= ifp;
	ifproto->protocol_family = proto->protocol_family;
	ifproto->proto_kpi = kProtoKPI_DLIL;
	ifproto->kpi.dlil.dl_input		= proto->input;
	ifproto->kpi.dlil.dl_pre_output	= proto->pre_output;
	ifproto->kpi.dlil.dl_event		= proto->event;
	ifproto->kpi.dlil.dl_offer		= proto->offer;
	ifproto->kpi.dlil.dl_ioctl		= proto->ioctl;
	ifproto->kpi.dlil.dl_detached 	= proto->detached;
	
	retval = dlil_attach_protocol_internal(ifproto, &proto->demux_desc_head, NULL, 0);
	
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
	u_long proto_family = proto->protocol_family;
	struct kev_dl_proto_data	ev_pr_data;
	
	if (proto->proto_kpi == kProtoKPI_DLIL) {
		if (proto->kpi.dlil.dl_detached)
			proto->kpi.dlil.dl_detached(proto->protocol_family, ifp);
	}
	else {
		if (proto->kpi.v1.detached)
			proto->kpi.v1.detached(ifp, proto->protocol_family);
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

int
dlil_detach_protocol(struct ifnet *ifp, u_long proto_family)
{
	struct if_proto *proto = NULL;
	int	retval = 0;
	int use_reached_zero = 0;
	

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

	if (proto->proto_kpi == kProtoKPI_DLIL && proto->kpi.dlil.dl_offer)
		ifp->offercnt--;

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
							if (proto->proto_kpi == kProtoKPI_DLIL && proto->kpi.dlil.dl_offer)
								ifp->offercnt--;
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

__private_extern__ int
dlil_if_attach_with_address(
	struct ifnet		*ifp,
	const struct sockaddr_dl	*ll_addr)
{
	u_long		    interface_family = ifp->if_family;
	struct if_family_str    *if_family = NULL;
	int			    stat;
	struct ifnet *tmp_if;
	struct proto_hash_entry *new_proto_list = NULL;
	int locked = 0;
	
	
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

	// Only use family if this is not a KPI interface
	if ((ifp->if_eflags & IFEF_USEKPI) == 0) {
		if_family = find_family_module(interface_family);
	}

	/*
	 * Allow interfaces withouth protocol families to attach
	 * only if they have the necessary fields filled out.
	 */
	
	if ((if_family == 0) &&
		(ifp->if_add_proto == 0 || ifp->if_del_proto == 0)) {
		DLIL_PRINTF("Attempt to attach interface without family module - %d\n", 
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

	/*
	 * Call the family module to fill in the appropriate fields in the
	 * ifnet structure.
	 */
	
	if (if_family) {
		stat = if_family->add_if(ifp);
		if (stat) {
			DLIL_PRINTF("dlil_if_attach -- add_if failed with %d\n", stat);
			dlil_write_end();
			return stat;
		}
		ifp->if_add_proto_u.original = if_family->add_proto;
		ifp->if_del_proto = if_family->del_proto;
		if_family->refcnt++;
	}
	
	ifp->offercnt = 0;
	TAILQ_INIT(&ifp->if_flt_head);
	
		
	if (new_proto_list) {
		bzero(new_proto_list, (PROTO_HASH_SLOTS * sizeof(struct proto_hash_entry)));
		ifp->if_proto_hash = new_proto_list;
		new_proto_list = 0;
	}
	
	/* old_if_attach */
	{
		struct ifaddr *ifa = 0;
		
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
			char workbuf[64];
			int namelen, masklen, socksize, ifasize;
			
			ifp->if_index = if_next_index();
			
			namelen = snprintf(workbuf, sizeof(workbuf), "%s%d", ifp->if_name, ifp->if_unit);
#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
			masklen = _offsetof(struct sockaddr_dl, sdl_data[0]) + namelen;
			socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof(long) - 1)))
			if ((u_long)socksize < sizeof(struct sockaddr_dl))
				socksize = sizeof(struct sockaddr_dl);
			socksize = ROUNDUP(socksize);
			ifasize = sizeof(struct ifaddr) + 2 * socksize;
			ifa = (struct ifaddr*)_MALLOC(ifasize, M_IFADDR, M_WAITOK);
			if (ifa) {
				struct sockaddr_dl *sdl = (struct sockaddr_dl *)(ifa + 1);
				ifnet_addrs[ifp->if_index - 1] = ifa;
				bzero(ifa, ifasize);
				sdl->sdl_len = socksize;
				sdl->sdl_family = AF_LINK;
				bcopy(workbuf, sdl->sdl_data, namelen);
				sdl->sdl_nlen = namelen;
				sdl->sdl_index = ifp->if_index;
				sdl->sdl_type = ifp->if_type;
				if (ll_addr) {
					sdl->sdl_alen = ll_addr->sdl_alen;
					if (ll_addr->sdl_alen != ifp->if_addrlen)
						panic("dlil_if_attach - ll_addr->sdl_alen != ifp->if_addrlen");
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
		}
		else {
			/* preserve the first ifaddr */
			ifnet_addrs[ifp->if_index - 1] = TAILQ_FIRST(&ifp->if_addrhead);
		}
		

		TAILQ_INIT(&ifp->if_addrhead);
		ifa = ifnet_addrs[ifp->if_index - 1];
		
		if (ifa) {
			/*
			 * We don't use if_attach_ifa because we want
			 * this address to be first on the list.
			 */
			ifaref(ifa);
			ifa->ifa_debug |= IFA_ATTACHED;
			TAILQ_INSERT_HEAD(&ifp->if_addrhead, ifa, ifa_link);
		}
		
		TAILQ_INSERT_TAIL(&ifnet_head, ifp, if_link);
		ifindex2ifnet[ifp->if_index] = ifp;
		
		ifnet_head_done();
	}
    dlil_write_end();
		
	if (if_family && if_family->init_if) {
		stat = if_family->init_if(ifp);
		if (stat) {
			DLIL_PRINTF("dlil_if_attach -- init_if failed with %d\n", stat);
		}
	}
    
    dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, 0, 0);
	ifnet_lock_done(ifp);

    return 0;
}

int
dlil_if_attach(struct ifnet	*ifp)
{
	dlil_if_attach_with_address(ifp, NULL);
}


int
dlil_if_detach(struct ifnet *ifp)
{
	struct ifnet_filter *filter;
	struct ifnet_filter	*filter_next;
	int zeroed = 0;
	int retval = 0;
	struct ifnet_filter_head fhead;
	
	
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
	
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHING, 0, 0);
	
	if ((retval = dlil_write_begin()) != 0) {
		if (retval == EDEADLK) {
			retval = DLIL_WAIT_FOR_FREE;
			
			/* We need to perform a delayed detach */
			ifp->if_delayed_detach = 1;
			dlil_detach_waiting = 1;
			wakeup(&dlil_detach_waiting);
		}
		return retval;
	}
	
	/* Steal the list of interface filters */
	fhead = ifp->if_flt_head;
	TAILQ_INIT(&ifp->if_flt_head);
	
	/* unuse the interface */
	zeroed = ifp_unuse(ifp);
	
	dlil_write_end();
	
	for (filter = TAILQ_FIRST(&fhead); filter; filter = filter_next) {
		filter_next = TAILQ_NEXT(filter, filt_next);
		dlil_detach_filter_internal(filter, 1);
	}
	
	if (zeroed == 0) {
		retval = DLIL_WAIT_FOR_FREE;
	}
	else
	{
		ifp_use_reached_zero(ifp);
	}
	
	return retval;
}


int
dlil_reg_if_modules(u_long  interface_family, 
		    struct dlil_ifmod_reg_str  *ifmod)
{
    struct if_family_str *if_family;


    if (find_family_module(interface_family))  {
	DLIL_PRINTF("Attempt to register dlil family module more than once - %d\n", 
	       interface_family);
	return EEXIST;
    }

    if ((!ifmod->add_if) || (!ifmod->del_if) ||
	(!ifmod->add_proto) || (!ifmod->del_proto)) {
	DLIL_PRINTF("dlil_reg_if_modules passed at least one null pointer\n");
	return EINVAL;
    }
    
    /*
     * The following is a gross hack to keep from breaking
     * Vicomsoft's internet gateway on Jaguar. Vicomsoft
     * does not zero the reserved fields in dlil_ifmod_reg_str.
     * As a result, we have to zero any function that used to
     * be reserved fields at the time Vicomsoft built their
     * kext. Radar #2974305
     */
    if (ifmod->reserved[0] != 0 || ifmod->reserved[1] != 0 || ifmod->reserved[2]) {
    	if (interface_family == 123) {	/* Vicom */
			ifmod->init_if = 0;
		} else {
			return EINVAL;
		}
    }

    if_family = (struct if_family_str *) _MALLOC(sizeof(struct if_family_str), M_IFADDR, M_WAITOK);
    if (!if_family) {
	DLIL_PRINTF("dlil_reg_if_modules failed allocation\n");
	return ENOMEM;
    }
    
    bzero(if_family, sizeof(struct if_family_str));

    if_family->if_family	= interface_family & 0xffff;
    if_family->shutdown		= ifmod->shutdown;
    if_family->add_if		= ifmod->add_if;
    if_family->del_if		= ifmod->del_if;
    if_family->init_if		= ifmod->init_if;
    if_family->add_proto	= ifmod->add_proto;
    if_family->del_proto	= ifmod->del_proto;
    if_family->ifmod_ioctl	= ifmod->ifmod_ioctl;
    if_family->refcnt		= 1;
    if_family->flags		= 0;

    TAILQ_INSERT_TAIL(&if_family_head, if_family, if_fam_next);
    return 0;
}

int dlil_dereg_if_modules(u_long interface_family)
{
    struct if_family_str  *if_family;
    int ret = 0;


    if_family = find_family_module(interface_family);
    if (if_family == 0) {
	return ENXIO;
    }

    if (--if_family->refcnt == 0) {
	if (if_family->shutdown)
	    (*if_family->shutdown)();
	
	TAILQ_REMOVE(&if_family_head, if_family, if_fam_next);
	FREE(if_family, M_IFADDR);
    }	
    else {
	if_family->flags |= DLIL_SHUTDOWN;
        ret = DLIL_WAIT_FOR_FREE;
    }

    return ret;
}
					    
	    

int
dlil_reg_proto_module(
	u_long protocol_family,
	u_long  interface_family, 
	int (*attach)(struct ifnet *ifp, u_long protocol_family),
	int (*detach)(struct ifnet *ifp, u_long protocol_family))
{
	struct proto_family_str *proto_family;

	if (attach == NULL) return EINVAL;

	lck_mtx_lock(proto_family_mutex);
	
	TAILQ_FOREACH(proto_family, &proto_family_head, proto_fam_next) {
		if (proto_family->proto_family == protocol_family &&
			proto_family->if_family == interface_family) {
			lck_mtx_unlock(proto_family_mutex);
			return EEXIST;
		}
	}

	proto_family = (struct proto_family_str *) _MALLOC(sizeof(struct proto_family_str), M_IFADDR, M_WAITOK);
	if (!proto_family) {
		lck_mtx_unlock(proto_family_mutex);
		return ENOMEM;
	}

	bzero(proto_family, sizeof(struct proto_family_str));
	proto_family->proto_family	= protocol_family;
	proto_family->if_family		= interface_family & 0xffff;
	proto_family->attach_proto	= attach;
	proto_family->detach_proto	= detach;

	TAILQ_INSERT_TAIL(&proto_family_head, proto_family, proto_fam_next);
	lck_mtx_unlock(proto_family_mutex);
	return 0;
}

int dlil_dereg_proto_module(u_long protocol_family, u_long interface_family)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);

	proto_family = find_proto_module(protocol_family, interface_family);
	if (proto_family == 0) {
		lck_mtx_unlock(proto_family_mutex);
		return ENXIO;
	}

	TAILQ_REMOVE(&proto_family_head, proto_family, proto_fam_next);
	FREE(proto_family, M_IFADDR);
	
	lck_mtx_unlock(proto_family_mutex);
	return ret;
}

int dlil_plumb_protocol(u_long protocol_family, struct ifnet *ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);
	proto_family = find_proto_module(protocol_family, ifp->if_family);
	if (proto_family == 0) {
		lck_mtx_unlock(proto_family_mutex);
		return ENXIO;
	}

	ret = proto_family->attach_proto(ifp, protocol_family);

	lck_mtx_unlock(proto_family_mutex);
   	return ret;
}


int dlil_unplumb_protocol(u_long protocol_family, struct ifnet *ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);

	proto_family = find_proto_module(protocol_family, ifp->if_family);
	if (proto_family && proto_family->detach_proto)
		ret = proto_family->detach_proto(ifp, protocol_family);
	else
		ret = dlil_detach_protocol(ifp, protocol_family);
    
	lck_mtx_unlock(proto_family_mutex);
	return ret;
}

static errno_t
dlil_recycle_ioctl(
	__unused ifnet_t ifnet_ptr,
	__unused u_int32_t ioctl_code,
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

int dlil_if_acquire(
	u_long family,
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

    TAILQ_INSERT_TAIL(&dlil_ifnet_head, dlifp1, dl_if_link);
     
     *ifp = ifp1;

end:
	lck_mtx_unlock(dlil_ifnet_mutex);

    return ret;
}

void dlil_if_release(struct ifnet *ifp)
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
    if (ifp->if_lock)
		ifnet_lock_done(ifp);
    
}
