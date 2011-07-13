/*
 * Copyright (c) 1999-2011 Apple Inc. All rights reserved.
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
#include <sys/mcache.h>

#include <kern/assert.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <net/kpi_protocol.h>

#include <net/if_types.h>
#include <net/if_llreach.h>
#include <net/kpi_interfacefilter.h>

#if INET
#include <netinet/in_var.h>
#include <netinet/igmp_var.h>
#endif /* INET */

#if INET6
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#endif /* INET6 */

#if NETAT
#include <netat/at_var.h>
#endif /* NETAT */

#include <libkern/OSAtomic.h>

#include <machine/machine_routines.h>

#include <mach/thread_act.h>
#include <mach/sdt.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#if PF
#include <net/pfvar.h>
#endif /* PF */

#define DBG_LAYER_BEG		DLILDBG_CODE(DBG_DLIL_STATIC, 0)
#define DBG_LAYER_END		DLILDBG_CODE(DBG_DLIL_STATIC, 2)
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

#define	_CASSERT(x)	\
	switch (0) { case 0: case (x): ; }

#define	IF_DATA_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct if_data_internal, f) % sizeof (u_int64_t)))

#define	IFNET_IF_DATA_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct ifnet, if_data.f) % sizeof (u_int64_t)))

#define IFNET_IF_TC_REQUIRE_ALIGNED_64(f) \
	_CASSERT(!(offsetof(struct ifnet, if_tc.f) % sizeof (u_int64_t)))

enum {
	kProtoKPI_v1	= 1,
	kProtoKPI_v2	= 2
};

/*
 * List of if_proto structures in if_proto_hash[] is protected by
 * the ifnet lock.  The rest of the fields are initialized at protocol
 * attach time and never change, thus no lock required as long as
 * a reference to it is valid, via if_proto_ref().
 */
struct if_proto {
    SLIST_ENTRY(if_proto)	next_hash;
    u_int32_t			refcount;
    u_int32_t			detached;
    struct ifnet		*ifp;
    protocol_family_t		protocol_family;
    int				proto_kpi;
    union {
		struct {
			proto_media_input		input;
			proto_media_preout		pre_output;
			proto_media_event		event;
			proto_media_ioctl		ioctl;
			proto_media_detached		detached;
			proto_media_resolve_multi	resolve_multi;
			proto_media_send_arp		send_arp;
		} v1;
		struct {
			proto_media_input_v2		input;
			proto_media_preout		pre_output;
			proto_media_event		event;
			proto_media_ioctl		ioctl;
			proto_media_detached		detached;
			proto_media_resolve_multi	resolve_multi;
			proto_media_send_arp		send_arp;
		} v2;
	} kpi;
};

SLIST_HEAD(proto_hash_entry, if_proto);

#define	DLIL_SDLMAXLEN	64
#define	DLIL_SDLDATALEN	\
	(DLIL_SDLMAXLEN - offsetof(struct sockaddr_dl, sdl_data[0]))

struct dlil_ifnet {
	struct ifnet	dl_if;			/* public ifnet */
	/*
	 * dlil private fields, protected by dl_if_lock
	 */
	decl_lck_mtx_data(, dl_if_lock);
	TAILQ_ENTRY(dlil_ifnet) dl_if_link;	/* dlil_ifnet link */
	u_int32_t dl_if_flags;			/* flags (below) */
	u_int32_t dl_if_refcnt;			/* refcnt */
	void (*dl_if_trace)(struct dlil_ifnet *, int); /* ref trace callback */
	void	*dl_if_uniqueid;		/* unique interface id */
	size_t	dl_if_uniqueid_len;		/* length of the unique id */
	char	dl_if_namestorage[IFNAMSIZ];	/* interface name storage */
	struct {
		struct ifaddr	ifa;		/* lladdr ifa */
		u_int8_t	asdl[DLIL_SDLMAXLEN]; /* addr storage */
		u_int8_t	msdl[DLIL_SDLMAXLEN]; /* mask storage */
	} dl_if_lladdr;
	ctrace_t	dl_if_attach;		/* attach PC stacktrace */
	ctrace_t	dl_if_detach;		/* detach PC stacktrace */
};

/* Values for dl_if_flags (private to DLIL) */
#define	DLIF_INUSE	0x1	/* DLIL ifnet recycler, ifnet in use */
#define	DLIF_REUSE	0x2	/* DLIL ifnet recycles, ifnet is not new */
#define	DLIF_DEBUG	0x4	/* has debugging info */

#define	IF_REF_TRACE_HIST_SIZE	8	/* size of ref trace history */

/* For gdb */
__private_extern__ unsigned int if_ref_trace_hist_size = IF_REF_TRACE_HIST_SIZE;

struct dlil_ifnet_dbg {
	struct dlil_ifnet	dldbg_dlif;		/* dlil_ifnet */
	u_int16_t		dldbg_if_refhold_cnt;	/* # ifnet references */
	u_int16_t		dldbg_if_refrele_cnt;	/* # ifnet releases */
	/*
	 * Circular lists of ifnet_{reference,release} callers.
	 */
	ctrace_t		dldbg_if_refhold[IF_REF_TRACE_HIST_SIZE];
	ctrace_t		dldbg_if_refrele[IF_REF_TRACE_HIST_SIZE];
};

#define	DLIL_TO_IFP(s)	(&s->dl_if)
#define	IFP_TO_DLIL(s)	((struct dlil_ifnet *)s)

struct ifnet_filter {
	TAILQ_ENTRY(ifnet_filter)	filt_next;
	u_int32_t			filt_skip;
	ifnet_t				filt_ifp;
	const char			*filt_name;
	void				*filt_cookie;
	protocol_family_t		filt_protocol;
	iff_input_func			filt_input;
	iff_output_func			filt_output;
	iff_event_func			filt_event;
	iff_ioctl_func			filt_ioctl;
	iff_detached_func		filt_detached;
};

struct proto_input_entry;

static TAILQ_HEAD(, dlil_ifnet) dlil_ifnet_head;
static lck_grp_t *dlil_lock_group;
lck_grp_t *ifnet_lock_group;
static lck_grp_t *ifnet_head_lock_group;
lck_attr_t *ifnet_lock_attr;
decl_lck_rw_data(, ifnet_head_lock);
decl_lck_mtx_data(, dlil_ifnet_lock);
u_int32_t dlil_filter_count = 0;
extern u_int32_t	ipv4_ll_arp_aware;

#if DEBUG
static unsigned int ifnet_debug = 1;	/* debugging (enabled) */
#else
static unsigned int ifnet_debug;	/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int dlif_size;		/* size of dlil_ifnet to allocate */
static unsigned int dlif_bufsize;	/* size of dlif_size + headroom */
static struct zone *dlif_zone;		/* zone for dlil_ifnet */

#define	DLIF_ZONE_MAX		64		/* maximum elements in zone */
#define	DLIF_ZONE_NAME		"ifnet"		/* zone name */

static unsigned int dlif_filt_size;	/* size of ifnet_filter */
static struct zone *dlif_filt_zone;	/* zone for ifnet_filter */

#define	DLIF_FILT_ZONE_MAX	8		/* maximum elements in zone */
#define	DLIF_FILT_ZONE_NAME	"ifnet_filter"	/* zone name */

static unsigned int dlif_inp_size;	/* size of dlil_threading_info */
static struct zone *dlif_inp_zone;	/* zone for dlil_threading_info */

#define	DLIF_INP_ZONE_MAX	DLIF_ZONE_MAX	/* maximum elements in zone */
#define	DLIF_INP_ZONE_NAME	"ifnet_thread"	/* zone name */

static unsigned int dlif_phash_size;	/* size of ifnet proto hash table */
static struct zone *dlif_phash_zone;	/* zone for ifnet proto hash table */

#define	DLIF_PHASH_ZONE_MAX	DLIF_ZONE_MAX	/* maximum elements in zone */
#define	DLIF_PHASH_ZONE_NAME	"ifnet_proto_hash" /* zone name */

static unsigned int dlif_proto_size;	/* size of if_proto */
static struct zone *dlif_proto_zone;	/* zone for if_proto */

#define	DLIF_PROTO_ZONE_MAX	(DLIF_ZONE_MAX*2) /* maximum elements in zone */
#define	DLIF_PROTO_ZONE_NAME	"ifnet_proto"	/* zone name */

/*
 * Updating this variable should be done by first acquiring the global
 * radix node head (rnh_lock), in tandem with settting/clearing the
 * PR_AGGDRAIN for routedomain.
 */
u_int32_t ifnet_aggressive_drainers;
static u_int32_t net_rtref;

static struct dlil_threading_info dlil_lo_thread;
__private_extern__  struct dlil_threading_info *dlil_lo_thread_ptr = &dlil_lo_thread;

static struct mbuf *dlil_lo_input_mbuf_head = NULL;
static struct mbuf *dlil_lo_input_mbuf_tail = NULL;

static int dlil_event_internal(struct ifnet *ifp, struct kev_msg *msg);
static int dlil_detach_filter_internal(interface_filter_t filter, int detached);
static void dlil_if_trace(struct dlil_ifnet *, int);
static void if_proto_ref(struct if_proto *);
static void if_proto_free(struct if_proto *);
static struct if_proto *find_attached_proto(struct ifnet *, u_int32_t);
static int dlil_ifp_proto_count(struct ifnet *);
static void if_flt_monitor_busy(struct ifnet *);
static void if_flt_monitor_unbusy(struct ifnet *);
static void if_flt_monitor_enter(struct ifnet *);
static void if_flt_monitor_leave(struct ifnet *);
static int dlil_interface_filters_input(struct ifnet *, struct mbuf **,
    char **, protocol_family_t);
static int dlil_interface_filters_output(struct ifnet *, struct mbuf **,
    protocol_family_t);
static struct ifaddr *dlil_alloc_lladdr(struct ifnet *,
    const struct sockaddr_dl *);
static int ifnet_lookup(struct ifnet *);
static void if_purgeaddrs(struct ifnet *);

static errno_t ifproto_media_input_v1(struct ifnet *, protocol_family_t,
    struct mbuf *, char *);
static errno_t ifproto_media_input_v2(struct ifnet *, protocol_family_t,
    struct mbuf *);
static errno_t ifproto_media_preout(struct ifnet *, protocol_family_t,
    mbuf_t *, const struct sockaddr *, void *, char *, char *);
static void ifproto_media_event(struct ifnet *, protocol_family_t,
    const struct kev_msg *);
static errno_t ifproto_media_ioctl(struct ifnet *, protocol_family_t,
    unsigned long, void *);
static errno_t ifproto_media_resolve_multi(ifnet_t, const struct sockaddr *,
    struct sockaddr_dl *, size_t);
static errno_t ifproto_media_send_arp(struct ifnet *, u_short,
    const struct sockaddr_dl *, const struct sockaddr *,
    const struct sockaddr_dl *, const struct sockaddr *);

static errno_t ifp_if_output(struct ifnet *, struct mbuf *);
static errno_t ifp_if_demux(struct ifnet *, struct mbuf *, char *,
    protocol_family_t *);
static errno_t ifp_if_add_proto(struct ifnet *, protocol_family_t,
    const struct ifnet_demux_desc *, u_int32_t);
static errno_t ifp_if_del_proto(struct ifnet *, protocol_family_t);
static errno_t ifp_if_check_multi(struct ifnet *, const struct sockaddr *);
static errno_t ifp_if_framer(struct ifnet *, struct mbuf **,
    const struct sockaddr *, const char *, const char *);
static errno_t ifp_if_ioctl(struct ifnet *, unsigned long, void *);
static errno_t ifp_if_set_bpf_tap(struct ifnet *, bpf_tap_mode, bpf_packet_func);
static void ifp_if_free(struct ifnet *);
static void ifp_if_event(struct ifnet *, const struct kev_msg *);

static void dlil_input_thread_func(struct dlil_threading_info *inpthread);
static int dlil_create_input_thread(ifnet_t, struct dlil_threading_info *);

static void ifnet_delayed_thread_func(void);
static void ifnet_detach_final(struct ifnet *);
static void ifnet_detaching_enqueue(struct ifnet *);
static struct ifnet *ifnet_detaching_dequeue(void);

static void ifp_src_route_copyout(struct ifnet *, struct route *);
static void ifp_src_route_copyin(struct ifnet *, struct route *);
#if INET6
static void ifp_src_route6_copyout(struct ifnet *, struct route_in6 *);
static void ifp_src_route6_copyin(struct ifnet *, struct route_in6 *);
#endif /* INET6 */

/* The following are protected by dlil_ifnet_lock */
static TAILQ_HEAD(, ifnet) ifnet_detaching_head;
static u_int32_t ifnet_detaching_cnt;
static void *ifnet_delayed_run;	/* wait channel for detaching thread */

extern void bpfdetach(struct ifnet*);
extern void proto_input_run(void);

__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);

#if DEBUG
static int dlil_verbose = 1;
#else
static int dlil_verbose = 0;
#endif /* DEBUG */
static int dlil_multithreaded_input = 1;
static int cur_dlil_input_threads = 0;
#if IFNET_INPUT_SANITY_CHK
static int dlil_lo_input_mbuf_count = 0;
/* sanity checking of input packet lists received */
static int dlil_input_sanity_check = 0;
#endif

SYSCTL_DECL(_net_link_generic_system);

SYSCTL_INT(_net_link_generic_system, OID_AUTO, dlil_verbose, CTLFLAG_RW,
    &dlil_verbose, 0, "Log DLIL error messages");

SYSCTL_INT(_net_link_generic_system, OID_AUTO, multi_threaded_input, CTLFLAG_RW,
    &dlil_multithreaded_input , 0, "Uses multiple input thread for DLIL input");

#if IFNET_INPUT_SANITY_CHK
SYSCTL_INT(_net_link_generic_system, OID_AUTO, dlil_input_sanity_check,
    CTLFLAG_RW, &dlil_input_sanity_check , 0,
    "Turn on sanity checking in DLIL input");
#endif

unsigned int net_affinity = 1;
static kern_return_t dlil_affinity_set(struct thread *, u_int32_t);

extern u_int32_t	inject_buckets;

static	lck_grp_attr_t	*dlil_grp_attributes = NULL;
static	lck_attr_t	*dlil_lck_attributes = NULL;
static	lck_grp_t	*dlil_input_lock_grp = NULL;

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
			return (0);
		case PF_INET6:
			return (1);
		case PF_APPLETALK:
			return (2);
		case PF_VLAN:
			return (3);
		case PF_UNSPEC:
		default:
			return (4);
	}
}

/*
 * Caller must already be holding ifnet lock.
 */
static struct if_proto *
find_attached_proto(struct ifnet *ifp, u_int32_t protocol_family)
{
	struct if_proto *proto = NULL;
	u_int32_t i = proto_hash_value(protocol_family);

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	if (ifp->if_proto_hash != NULL)
		proto = SLIST_FIRST(&ifp->if_proto_hash[i]);

	while (proto != NULL && proto->protocol_family != protocol_family)
		proto = SLIST_NEXT(proto, next_hash);

	if (proto != NULL)
		if_proto_ref(proto);

	return (proto);
}

static void
if_proto_ref(struct if_proto *proto)
{
	atomic_add_32(&proto->refcount, 1);
}

extern void if_rtproto_del(struct ifnet *ifp, int protocol);

static void
if_proto_free(struct if_proto *proto)
{
	u_int32_t oldval;
	struct ifnet *ifp = proto->ifp;
	u_int32_t proto_family = proto->protocol_family;
	struct kev_dl_proto_data ev_pr_data;

	oldval = atomic_add_32_ov(&proto->refcount, -1);
	if (oldval > 1)
		return;

	/* No more reference on this, protocol must have been detached */
	VERIFY(proto->detached);

	if (proto->proto_kpi == kProtoKPI_v1) {
		if (proto->kpi.v1.detached)
			proto->kpi.v1.detached(ifp, proto->protocol_family);
	}
	if (proto->proto_kpi == kProtoKPI_v2) {
		if (proto->kpi.v2.detached)
			proto->kpi.v2.detached(ifp, proto->protocol_family);
	}

	/*
	 * Cleanup routes that may still be in the routing table for that
	 * interface/protocol pair.
	 */
	if_rtproto_del(ifp, proto_family);

	/*
	 * The reserved field carries the number of protocol still attached
	 * (subject to change)
	 */
	ifnet_lock_shared(ifp);
	ev_pr_data.proto_family = proto_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
	ifnet_lock_done(ifp);

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_DETACHED,
	    (struct net_event_data *)&ev_pr_data,
	    sizeof(struct kev_dl_proto_data));

	zfree(dlif_proto_zone, proto);
}

__private_extern__ void
ifnet_lock_assert(struct ifnet *ifp, ifnet_lock_assert_t what)
{
	unsigned int type = 0;
	int ass = 1;

	switch (what) {
	case IFNET_LCK_ASSERT_EXCLUSIVE:
		type = LCK_RW_ASSERT_EXCLUSIVE;
		break;

	case IFNET_LCK_ASSERT_SHARED:
		type = LCK_RW_ASSERT_SHARED;
		break;

	case IFNET_LCK_ASSERT_OWNED:
		type = LCK_RW_ASSERT_HELD;
		break;

	case IFNET_LCK_ASSERT_NOTOWNED:
		/* nothing to do here for RW lock; bypass assert */
		ass = 0;
		break;

	default:
		panic("bad ifnet assert type: %d", what);
		/* NOTREACHED */
	}
	if (ass)
		lck_rw_assert(&ifp->if_lock, type);
}

__private_extern__ void
ifnet_lock_shared(struct ifnet *ifp)
{
	lck_rw_lock_shared(&ifp->if_lock);
}

__private_extern__ void
ifnet_lock_exclusive(struct ifnet *ifp)
{
	lck_rw_lock_exclusive(&ifp->if_lock);
}

__private_extern__ void
ifnet_lock_done(struct ifnet *ifp)
{
	lck_rw_done(&ifp->if_lock);
}

__private_extern__ void
ifnet_head_lock_shared(void)
{
	lck_rw_lock_shared(&ifnet_head_lock);
}

__private_extern__ void
ifnet_head_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&ifnet_head_lock);
}

__private_extern__ void
ifnet_head_done(void)
{
	lck_rw_done(&ifnet_head_lock);
}

/*
 * Caller must already be holding ifnet lock.
 */
static int
dlil_ifp_proto_count(struct ifnet * ifp)
{
	int i, count = 0;

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	if (ifp->if_proto_hash == NULL)
		goto done;

	for (i = 0; i < PROTO_HASH_SLOTS; i++) {
		struct if_proto *proto;
		SLIST_FOREACH(proto, &ifp->if_proto_hash[i], next_hash) {
			count++;
		}
	}
done:
	return (count);
}

__private_extern__ void
dlil_post_msg(struct ifnet *ifp, u_int32_t event_subclass,
    u_int32_t event_code, struct net_event_data *event_data,
    u_int32_t event_data_len)
{
	struct net_event_data ev_data;
	struct kev_msg ev_msg;

	bzero(&ev_msg, sizeof (ev_msg));
	bzero(&ev_data, sizeof (ev_data));
	/*
	 * a net event always starts with a net_event_data structure
	 * but the caller can generate a simple net event or
	 * provide a longer event structure to post
	 */
	ev_msg.vendor_code	= KEV_VENDOR_APPLE;
	ev_msg.kev_class	= KEV_NETWORK_CLASS;
	ev_msg.kev_subclass	= event_subclass;
	ev_msg.event_code	= event_code;

	if (event_data == NULL) {
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

static int
dlil_create_input_thread(ifnet_t ifp, struct dlil_threading_info *inputthread)
{
	int error;

	bzero(inputthread, sizeof(*inputthread));
	/* loopback ifp may not be configured at dlil_init time. */
	if (ifp == lo_ifp) {
		(void) strlcat(inputthread->input_name,
		    "dlil_input_main_thread_mtx", DLIL_THREADNAME_LEN);
	} else {
		(void) snprintf(inputthread->input_name, DLIL_THREADNAME_LEN,
		    "dlil_input_%s%d_mtx", ifp->if_name, ifp->if_unit);
	}

	inputthread->lck_grp = lck_grp_alloc_init(inputthread->input_name,
	    dlil_grp_attributes);
	lck_mtx_init(&inputthread->input_lck, inputthread->lck_grp,
	    dlil_lck_attributes);

	error= kernel_thread_start((thread_continue_t)dlil_input_thread_func,
	    inputthread, &inputthread->input_thread);
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
		panic("%s: couldn't create thread", __func__);
		/* NOTREACHED */
	}
	OSAddAtomic(1, &cur_dlil_input_threads);
#if DLIL_DEBUG
	printf("%s: threadinfo: %p input_thread=%p threads: cur=%d max=%d\n",
	    __func__, inputthread, inputthread->input_thread,
	    dlil_multithreaded_input, cur_dlil_input_threads);
#endif
	return (error);
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
	thread_t thread = THREAD_NULL;

	/*
	 * The following fields must be 64-bit aligned for atomic operations.
	 */
	IF_DATA_REQUIRE_ALIGNED_64(ifi_ipackets);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_ierrors)
	IF_DATA_REQUIRE_ALIGNED_64(ifi_opackets);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_oerrors);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_collisions);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_ibytes);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_obytes);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_imcasts);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_omcasts);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_iqdrops);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_noproto);

	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_ipackets);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_ierrors)
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_opackets);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_oerrors);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_collisions);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_ibytes);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_obytes);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_imcasts);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_omcasts);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_iqdrops);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_noproto);

	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ibkpackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ibkbytes);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_obkpackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_obkbytes);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ivipackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ivibytes);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ovipackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ovibytes);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ivopackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ivobytes);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ovopackets);
	IFNET_IF_TC_REQUIRE_ALIGNED_64(ifi_ovobytes);

	/*
	 * These IF_HWASSIST_ flags must be equal to their IFNET_* counterparts.
	 */
	_CASSERT(IF_HWASSIST_CSUM_IP == IFNET_CSUM_IP);
	_CASSERT(IF_HWASSIST_CSUM_TCP == IFNET_CSUM_TCP);
	_CASSERT(IF_HWASSIST_CSUM_UDP == IFNET_CSUM_UDP);
	_CASSERT(IF_HWASSIST_CSUM_IP_FRAGS == IFNET_CSUM_FRAGMENT);
	_CASSERT(IF_HWASSIST_CSUM_FRAGMENT == IFNET_IP_FRAGMENT);
	_CASSERT(IF_HWASSIST_CSUM_TCP_SUM16 == IFNET_CSUM_SUM16);
	_CASSERT(IF_HWASSIST_VLAN_TAGGING == IFNET_VLAN_TAGGING);
	_CASSERT(IF_HWASSIST_VLAN_MTU == IFNET_VLAN_MTU);
	_CASSERT(IF_HWASSIST_TSO_V4 == IFNET_TSO_IPV4);
	_CASSERT(IF_HWASSIST_TSO_V6 == IFNET_TSO_IPV6);

	/*
	 * Make sure we have at least IF_LLREACH_MAXLEN in the llreach info.
	 */
	_CASSERT(IF_LLREACH_MAXLEN <= IF_LLREACHINFO_ADDRLEN);

	PE_parse_boot_argn("net_affinity", &net_affinity,
	    sizeof (net_affinity));

	PE_parse_boot_argn("net_rtref", &net_rtref, sizeof (net_rtref));

	PE_parse_boot_argn("ifnet_debug", &ifnet_debug, sizeof (ifnet_debug));

	dlif_size = (ifnet_debug == 0) ? sizeof (struct dlil_ifnet) :
	    sizeof (struct dlil_ifnet_dbg);
	/* Enforce 64-bit alignment for dlil_ifnet structure */
	dlif_bufsize = dlif_size + sizeof (void *) + sizeof (u_int64_t);
	dlif_bufsize = P2ROUNDUP(dlif_bufsize, sizeof (u_int64_t));
	dlif_zone = zinit(dlif_bufsize, DLIF_ZONE_MAX * dlif_bufsize,
	    0, DLIF_ZONE_NAME);
	if (dlif_zone == NULL) {
		panic("%s: failed allocating %s", __func__, DLIF_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_zone, Z_EXPAND, TRUE);
	zone_change(dlif_zone, Z_CALLERACCT, FALSE);

	dlif_filt_size = sizeof (struct ifnet_filter);
	dlif_filt_zone = zinit(dlif_filt_size,
	    DLIF_FILT_ZONE_MAX * dlif_filt_size, 0, DLIF_FILT_ZONE_NAME);
	if (dlif_filt_zone == NULL) {
		panic("%s: failed allocating %s", __func__,
		    DLIF_FILT_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_filt_zone, Z_EXPAND, TRUE);
	zone_change(dlif_filt_zone, Z_CALLERACCT, FALSE);

	dlif_inp_size = sizeof (struct dlil_threading_info);
	dlif_inp_zone = zinit(dlif_inp_size,
	    DLIF_INP_ZONE_MAX * dlif_inp_size, 0, DLIF_INP_ZONE_NAME);
	if (dlif_inp_zone == NULL) {
		panic("%s: failed allocating %s", __func__, DLIF_INP_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_inp_zone, Z_EXPAND, TRUE);
	zone_change(dlif_inp_zone, Z_CALLERACCT, FALSE);

	dlif_phash_size = sizeof (struct proto_hash_entry) * PROTO_HASH_SLOTS;
	dlif_phash_zone = zinit(dlif_phash_size,
	    DLIF_PHASH_ZONE_MAX * dlif_phash_size, 0, DLIF_PHASH_ZONE_NAME);
	if (dlif_phash_zone == NULL) {
		panic("%s: failed allocating %s", __func__,
		    DLIF_PHASH_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_phash_zone, Z_EXPAND, TRUE);
	zone_change(dlif_phash_zone, Z_CALLERACCT, FALSE);

	dlif_proto_size = sizeof (struct if_proto);
	dlif_proto_zone = zinit(dlif_proto_size,
	    DLIF_PROTO_ZONE_MAX * dlif_proto_size, 0, DLIF_PROTO_ZONE_NAME);
	if (dlif_proto_zone == NULL) {
		panic("%s: failed allocating %s", __func__,
		    DLIF_PROTO_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_proto_zone, Z_EXPAND, TRUE);
	zone_change(dlif_proto_zone, Z_CALLERACCT, FALSE);

	ifnet_llreach_init();

	TAILQ_INIT(&dlil_ifnet_head);
	TAILQ_INIT(&ifnet_head);
	TAILQ_INIT(&ifnet_detaching_head);

	/* Setup the lock groups we will use */
	dlil_grp_attributes = lck_grp_attr_alloc_init();

	dlil_lock_group = lck_grp_alloc_init("dlil internal locks",
	    dlil_grp_attributes);
	ifnet_lock_group = lck_grp_alloc_init("ifnet locks",
	    dlil_grp_attributes);
	ifnet_head_lock_group = lck_grp_alloc_init("ifnet head lock",
	    dlil_grp_attributes);
	dlil_input_lock_grp = lck_grp_alloc_init("dlil input lock",
	    dlil_grp_attributes);

	/* Setup the lock attributes we will use */
	dlil_lck_attributes = lck_attr_alloc_init();

	ifnet_lock_attr = lck_attr_alloc_init();

	lck_rw_init(&ifnet_head_lock, ifnet_head_lock_group,
	    dlil_lck_attributes);
	lck_mtx_init(&dlil_ifnet_lock, dlil_lock_group, dlil_lck_attributes);

	lck_attr_free(dlil_lck_attributes);
	dlil_lck_attributes = NULL;

	ifa_init();

	/*
	 * Create and start up the first dlil input thread once everything
	 * is initialized.
	 */
	dlil_create_input_thread(lo_ifp, dlil_lo_thread_ptr);

	if (kernel_thread_start((thread_continue_t)ifnet_delayed_thread_func,
	    NULL, &thread) != 0) {
		panic("%s: couldn't create detach thread", __func__);
		/* NOTREACHED */
	}
	thread_deallocate(thread);

#if PF
	/* Initialize the packet filter */
	pfinit();
#endif /* PF */
}

static void
if_flt_monitor_busy(struct ifnet *ifp)
{
	lck_mtx_assert(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	++ifp->if_flt_busy;
	VERIFY(ifp->if_flt_busy != 0);
}

static void
if_flt_monitor_unbusy(struct ifnet *ifp)
{
	if_flt_monitor_leave(ifp);
}

static void
if_flt_monitor_enter(struct ifnet *ifp)
{
	lck_mtx_assert(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	while (ifp->if_flt_busy) {
		++ifp->if_flt_waiters;
		(void) msleep(&ifp->if_flt_head, &ifp->if_flt_lock,
		    (PZERO - 1), "if_flt_monitor", NULL);
	}
	if_flt_monitor_busy(ifp);
}

static void
if_flt_monitor_leave(struct ifnet *ifp)
{
	lck_mtx_assert(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	VERIFY(ifp->if_flt_busy != 0);
	--ifp->if_flt_busy;

	if (ifp->if_flt_busy == 0 && ifp->if_flt_waiters > 0) {
		ifp->if_flt_waiters = 0;
		wakeup(&ifp->if_flt_head);
	}
}

__private_extern__ int
dlil_attach_filter(struct ifnet	*ifp, const struct iff_filter *if_filter,
    interface_filter_t *filter_ref)
{
	int retval = 0;
	struct ifnet_filter *filter = NULL;

	ifnet_head_lock_shared();
	/* Check that the interface is in the global list */
	if (!ifnet_lookup(ifp)) {
		retval = ENXIO;
		goto done;
	}

	filter = zalloc(dlif_filt_zone);
	if (filter == NULL) {
		retval = ENOMEM;
		goto done;
	}
	bzero(filter, dlif_filt_size);

	/* refcnt held above during lookup */
	filter->filt_ifp = ifp;
	filter->filt_cookie = if_filter->iff_cookie;
	filter->filt_name = if_filter->iff_name;
	filter->filt_protocol = if_filter->iff_protocol;
	filter->filt_input = if_filter->iff_input;
	filter->filt_output = if_filter->iff_output;
	filter->filt_event = if_filter->iff_event;
	filter->filt_ioctl = if_filter->iff_ioctl;
	filter->filt_detached = if_filter->iff_detached;

	lck_mtx_lock(&ifp->if_flt_lock);
	if_flt_monitor_enter(ifp);

	lck_mtx_assert(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);
	TAILQ_INSERT_TAIL(&ifp->if_flt_head, filter, filt_next);

	if_flt_monitor_leave(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	*filter_ref = filter;

	/*
	 * Bump filter count and route_generation ID to let TCP
	 * know it shouldn't do TSO on this connection
	 */
	OSAddAtomic(1, &dlil_filter_count);
	if (use_routegenid)
		routegenid_update();

	if (dlil_verbose) {
		printf("%s%d: %s filter attached\n", ifp->if_name,
		    ifp->if_unit, if_filter->iff_name);
	}
done:
	ifnet_head_done();
	if (retval != 0 && ifp != NULL) {
		DLIL_PRINTF("%s%d: failed to attach %s (err=%d)\n",
		    ifp->if_name, ifp->if_unit, if_filter->iff_name, retval);
	}
	if (retval != 0 && filter != NULL)
		zfree(dlif_filt_zone, filter);

	return (retval);
}

static int
dlil_detach_filter_internal(interface_filter_t	filter, int detached)
{
	int retval = 0;

	if (detached == 0) {
		ifnet_t ifp = NULL;

		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			interface_filter_t entry = NULL;

			lck_mtx_lock(&ifp->if_flt_lock);
			TAILQ_FOREACH(entry, &ifp->if_flt_head, filt_next) {
				if (entry != filter || entry->filt_skip)
					continue;
				/*
				 * We've found a match; since it's possible
				 * that the thread gets blocked in the monitor,
				 * we do the lock dance.  Interface should
				 * not be detached since we still have a use
				 * count held during filter attach.
				 */
				entry->filt_skip = 1;	/* skip input/output */
				lck_mtx_unlock(&ifp->if_flt_lock);
				ifnet_head_done();

				lck_mtx_lock(&ifp->if_flt_lock);
				if_flt_monitor_enter(ifp);
				lck_mtx_assert(&ifp->if_flt_lock,
				    LCK_MTX_ASSERT_OWNED);

				/* Remove the filter from the list */
				TAILQ_REMOVE(&ifp->if_flt_head, filter,
				    filt_next);

				if_flt_monitor_leave(ifp);
				lck_mtx_unlock(&ifp->if_flt_lock);
				if (dlil_verbose) {
					printf("%s%d: %s filter detached\n",
					    ifp->if_name, ifp->if_unit,
					    filter->filt_name);
				}
				goto destroy;
			}
			lck_mtx_unlock(&ifp->if_flt_lock);
		}
		ifnet_head_done();

		/* filter parameter is not a valid filter ref */
		retval = EINVAL;
		goto done;
	}

	if (dlil_verbose)
		printf("%s filter detached\n", filter->filt_name);

destroy:

	/* Call the detached function if there is one */
	if (filter->filt_detached)
		filter->filt_detached(filter->filt_cookie, filter->filt_ifp);

	/* Free the filter */
	zfree(dlif_filt_zone, filter);

	/*
	 * Decrease filter count and route_generation ID to let TCP
	 * know it should reevalute doing TSO or not
	 */
	OSAddAtomic(-1, &dlil_filter_count);
	if (use_routegenid)
		routegenid_update();

done:
	if (retval != 0) {
		DLIL_PRINTF("failed to detach %s filter (err=%d)\n",
		    filter->filt_name, retval);
	}
	return (retval);
}

__private_extern__ void
dlil_detach_filter(interface_filter_t filter)
{
	if (filter == NULL)
		return;
	dlil_detach_filter_internal(filter, 0);
}

static void
dlil_input_thread_func(struct dlil_threading_info *inputthread)
{
	while (1) {
		struct mbuf *m = NULL, *m_loop = NULL;
#if IFNET_INPUT_SANITY_CHK
		int		loop_cnt = 0, mbuf_cnt;
		int		count;
		struct mbuf *m1;
#endif /* IFNET_INPUT_SANITY_CHK */

		lck_mtx_lock_spin(&inputthread->input_lck);

		/* Wait until there is work to be done */
		while (!(inputthread->input_waiting & ~DLIL_INPUT_RUNNING)) {
			inputthread->input_waiting &= ~DLIL_INPUT_RUNNING;
			msleep(&inputthread->input_waiting,
			    &inputthread->input_lck, 0,
			    inputthread->input_name, 0);
		}

		lck_mtx_assert(&inputthread->input_lck, LCK_MTX_ASSERT_OWNED);

		m = inputthread->mbuf_head;
		inputthread->mbuf_head = NULL;
		inputthread->mbuf_tail = NULL;

		if (inputthread->input_waiting & DLIL_INPUT_TERMINATE) {
			lck_mtx_unlock(&inputthread->input_lck);

			if (m != NULL)
				mbuf_freem_list(m);

			OSAddAtomic(-1, &cur_dlil_input_threads);

			lck_mtx_destroy(&inputthread->input_lck,
			    inputthread->lck_grp);
			lck_grp_free(inputthread->lck_grp);

			zfree(dlif_inp_zone, inputthread);

			/* for the extra refcnt from kernel_thread_start() */
			thread_deallocate(current_thread());

			/* this is the end */
			thread_terminate(current_thread());
			/* NOTREACHED */
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

			lck_mtx_unlock(&inputthread->input_lck);

			for (m1 = m, count = 0; m1; m1 = mbuf_nextpkt(m1)) {
				count++;
			}
			if (count != mbuf_cnt) {
				panic("%s - thread=%p reg. loop queue "
				    "has %d packets, should have %d\n",
				    __func__, inputthread, count, mbuf_cnt);
				/* NOTREACHED */
			}

			if (inputthread == dlil_lo_thread_ptr) {
				for (m1 = m_loop, count = 0; m1;
				    m1 = mbuf_nextpkt(m1)) {
					count++;
				}
				if (count != loop_cnt) {
					panic("%s - thread=%p loop queue "
					    "has %d packets, should have %d\n",
					    __func__, inputthread, count,
					    loop_cnt);
					/* NOTREACHED */
				}
			}
		} else
#endif /* IFNET_INPUT_SANITY_CHK */
		{
			lck_mtx_unlock(&inputthread->input_lck);
		}


		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation
		* safeguards if we deal with long chains of packets.
		*/
		if (m_loop) {
			if (inputthread == dlil_lo_thread_ptr) {
				dlil_input_packet_list(lo_ifp, m_loop);
			}
#if IFNET_INPUT_SANITY_CHK
			else {
				panic("%s - thread=%p loop queue has %d "
				    "packets, should have none!\n", __func__,
				    inputthread, loop_cnt);
				/* NOTREACHED */
			}
#endif /* IFNET_INPUT_SANITY_CHK */
		}

		if (m != NULL)
			dlil_input_packet_list(0, m);

		lck_mtx_lock_spin(&inputthread->input_lck);

		if (inputthread->input_waiting &
		    (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER))  {
			lck_mtx_unlock(&inputthread->input_lck);
			proto_input_run();
		} else {
			lck_mtx_unlock(&inputthread->input_lck);
		}
	}
}

errno_t
ifnet_input(ifnet_t ifp, mbuf_t m_head,
    const struct ifnet_stat_increment_param *stats)
{
	struct thread *tp = current_thread();
	mbuf_t		m_tail;
	struct dlil_threading_info *inp;
#if IFNET_INPUT_SANITY_CHK
	u_int32_t	pkt_count = 0;
#endif /* IFNET_INPUT_SANITY_CHK */

	if (ifp == NULL || m_head == NULL) {
		if (m_head != NULL)
			mbuf_freem_list(m_head);
		return (EINVAL);
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
			    !(mbuf_flags(m_head) & MBUF_PKTHDR)) {
				panic("%s - invalid mbuf %p\n",
				    __func__, m_tail);
				/* NOTREACHED */
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
	lck_mtx_lock_spin(&inp->input_lck);
	if (inp->net_affinity && inp->workloop_thread == NULL) {
		u_int32_t tag = inp->tag;
		inp->workloop_thread = tp;
		lck_mtx_unlock(&inp->input_lck);

		/* Associated the current thread with the new affinity tag */
		(void) dlil_affinity_set(tp, tag);

		/*
		 * Take a reference on the workloop (current) thread; during
		 * detach, we will need to refer to it in order ot tear down
		 * its affinity.
		 */
		thread_reference(tp);
		lck_mtx_lock_spin(&inp->input_lck);
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

			lck_mtx_assert(&inp->input_lck, LCK_MTX_ASSERT_OWNED);
		}
#endif
	} else {
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

			lck_mtx_assert(&inp->input_lck, LCK_MTX_ASSERT_OWNED);
		}
#endif
	}

	inp->input_waiting |= DLIL_INPUT_WAITING;
	if ((inp->input_waiting & DLIL_INPUT_RUNNING) == 0) {
		wakeup((caddr_t)&inp->input_waiting);
	}
	lck_mtx_unlock(&inp->input_lck);

	if (stats) {
		atomic_add_64(&ifp->if_data.ifi_ipackets, stats->packets_in);
		atomic_add_64(&ifp->if_data.ifi_ibytes, stats->bytes_in);
		atomic_add_64(&ifp->if_data.ifi_ierrors, stats->errors_in);

		atomic_add_64(&ifp->if_data.ifi_opackets, stats->packets_out);
		atomic_add_64(&ifp->if_data.ifi_obytes, stats->bytes_out);
		atomic_add_64(&ifp->if_data.ifi_oerrors, stats->errors_out);

		atomic_add_64(&ifp->if_data.ifi_collisions, stats->collisions);
		atomic_add_64(&ifp->if_data.ifi_iqdrops, stats->dropped);
	}

	return (0);
}

static int
dlil_interface_filters_input(struct ifnet *ifp, struct mbuf **m_p,
    char **frame_header_p, protocol_family_t protocol_family)
{
	struct ifnet_filter *filter;

	/*
	 * Pass the inbound packet to the interface filters
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		int result;

		if (!filter->filt_skip && filter->filt_input != NULL &&
		    (filter->filt_protocol == 0 ||
		    filter->filt_protocol == protocol_family)) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			result = (*filter->filt_input)(filter->filt_cookie,
			    ifp, protocol_family, m_p, frame_header_p);

			lck_mtx_lock_spin(&ifp->if_flt_lock);
			if (result != 0) {
				/* we're done with the filter list */
				if_flt_monitor_unbusy(ifp);
				lck_mtx_unlock(&ifp->if_flt_lock);
				return (result);
			}
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	/*
	 * Strip away M_PROTO1 bit prior to sending packet up the stack as
	 * it is meant to be local to a subsystem -- if_bridge for M_PROTO1
	 */
	if (*m_p != NULL)
		(*m_p)->m_flags &= ~M_PROTO1;

	return (0);
}

static int
dlil_interface_filters_output(struct ifnet *ifp, struct mbuf **m_p,
    protocol_family_t protocol_family)
{
	struct ifnet_filter *filter;

	/*
	 * Pass the outbound packet to the interface filters
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		int result;

		if (!filter->filt_skip && filter->filt_output != NULL &&
		    (filter->filt_protocol == 0 ||
		    filter->filt_protocol == protocol_family)) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			result = filter->filt_output(filter->filt_cookie, ifp,
			    protocol_family, m_p);

			lck_mtx_lock_spin(&ifp->if_flt_lock);
			if (result != 0) {
				/* we're done with the filter list */
				if_flt_monitor_unbusy(ifp);
				lck_mtx_unlock(&ifp->if_flt_lock);
				return (result);
			}
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

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
			    ifproto->protocol_family, m, frame_header);
			if (error != 0 && error != EJUSTRETURN)
				m_freem(m);
			m = next_packet;
		}
	} else if (ifproto->proto_kpi == kProtoKPI_v2) {
		/* Version 2 protocols support packet lists */
		error = (*ifproto->kpi.v2.input)(ifproto->ifp,
		    ifproto->protocol_family, m);
		if (error != 0 && error != EJUSTRETURN)
			m_freem_list(m);
	}
	return;
}

__private_extern__ void
dlil_input_packet_list(struct ifnet * ifp_param, struct mbuf *m)
{
	int				error = 0;
	protocol_family_t		protocol_family;
	mbuf_t				next_packet;
	ifnet_t				ifp = ifp_param;
	char *				frame_header;
	struct if_proto	*		last_ifproto = NULL;
	mbuf_t				pkt_first = NULL;
	mbuf_t *			pkt_next = NULL;

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START,0,0,0,0,0);


	while (m != NULL) {
		struct if_proto *ifproto = NULL;
		int iorefcnt = 0;

		if (ifp_param == NULL)
			ifp = m->m_pkthdr.rcvif;

		/* Check if this mbuf looks valid */
		MBUF_INPUT_CHECK(m, ifp); 

		next_packet = m->m_nextpkt;
		m->m_nextpkt = NULL;
		frame_header = m->m_pkthdr.header;
		m->m_pkthdr.header = NULL;

		/* Get an IO reference count if the interface is not 
		 * loopback and it is attached.
		 */
		if (ifp != lo_ifp) {
			if (!ifnet_is_attached(ifp, 1)) {
				m_freem(m);
				goto next;
			}
			iorefcnt = 1;
		}

		switch (m->m_pkthdr.prio) {
			case MBUF_TC_BK:
				atomic_add_64(&ifp->if_tc.ifi_ibkpackets, 1);
				atomic_add_64(&ifp->if_tc.ifi_ibkbytes, m->m_pkthdr.len);
				break;
			case MBUF_TC_VI:
				atomic_add_64(&ifp->if_tc.ifi_ivipackets, 1);
				atomic_add_64(&ifp->if_tc.ifi_ivibytes, m->m_pkthdr.len);
				break;
			case MBUF_TC_VO:
				atomic_add_64(&ifp->if_tc.ifi_ivopackets, 1);
				atomic_add_64(&ifp->if_tc.ifi_ivobytes, m->m_pkthdr.len);
				break;
			default:
				break;
		}

		/* find which protocol family this packet is for */
		ifnet_lock_shared(ifp);
		error = (*ifp->if_demux)(ifp, m, frame_header,
		    &protocol_family);
		ifnet_lock_done(ifp);
		if (error != 0) {
			if (error == EJUSTRETURN)
				goto next;
			protocol_family = 0;
		}

		if (m->m_flags & (M_BCAST|M_MCAST))
			atomic_add_64(&ifp->if_imcasts, 1);

		/* run interface filters, exclude VLAN packets PR-3586856 */
		if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
			error = dlil_interface_filters_input(ifp, &m,
			    &frame_header, protocol_family);
			if (error != 0) {
				if (error != EJUSTRETURN)
					m_freem(m);
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
		} else if (last_ifproto != NULL && last_ifproto->ifp == ifp &&
		    (last_ifproto->protocol_family == protocol_family)) {
			VERIFY(ifproto == NULL);
			ifproto = last_ifproto;
			if_proto_ref(last_ifproto);
		} else {
			VERIFY(ifproto == NULL);
			ifnet_lock_shared(ifp);
			/* callee holds a proto refcnt upon success */
			ifproto	= find_attached_proto(ifp, protocol_family);
			ifnet_lock_done(ifp);
		}
		if (ifproto == NULL) {
			/* no protocol for this packet, discard */
			m_freem(m);
			goto next;
		}
		if (ifproto != last_ifproto) {
			if (last_ifproto != NULL) {
				/* pass up the list for the previous protocol */
				dlil_ifproto_input(last_ifproto, pkt_first);
				pkt_first = NULL;
				if_proto_free(last_ifproto);
			}
			last_ifproto = ifproto;
			if_proto_ref(ifproto);
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
			dlil_ifproto_input(last_ifproto, pkt_first);
			if_proto_free(last_ifproto);
			last_ifproto = NULL;
		}
		if (ifproto != NULL) {
			if_proto_free(ifproto);
			ifproto = NULL;
		}
		
		m = next_packet;

		/* update the driver's multicast filter, if needed */
		if (ifp->if_updatemcasts > 0 && if_mcasts_update(ifp) == 0)
			ifp->if_updatemcasts = 0;
		if (iorefcnt == 1)
			ifnet_decr_iorefcnt(ifp);
	}

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
}

errno_t
if_mcasts_update(struct ifnet *ifp)
{
	errno_t err;

	err = ifnet_ioctl(ifp, 0, SIOCADDMULTI, NULL);
	if (err == EAFNOSUPPORT)
		err = 0;
	printf("%s%d: %s %d suspended link-layer multicast membership(s) "
	    "(err=%d)\n", ifp->if_name, ifp->if_unit,
	    (err == 0 ? "successfully restored" : "failed to restore"),
	    ifp->if_updatemcasts, err);

	/* just return success */
	return (0);
}

static int
dlil_event_internal(struct ifnet *ifp, struct kev_msg *event)
{
	struct ifnet_filter *filter;

	/* Get an io ref count if the interface is attached */
	if (!ifnet_is_attached(ifp, 1))
		goto done;

	/*
	 * Pass the event to the interface filters
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		if (filter->filt_event != NULL) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			filter->filt_event(filter->filt_cookie, ifp,
			    filter->filt_protocol, event);

			lck_mtx_lock_spin(&ifp->if_flt_lock);
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	ifnet_lock_shared(ifp);
	if (ifp->if_proto_hash != NULL) {
		int i;

		for (i = 0; i < PROTO_HASH_SLOTS; i++) {
			struct if_proto *proto;

			SLIST_FOREACH(proto, &ifp->if_proto_hash[i],
			    next_hash) {
				proto_media_event eventp =
				    (proto->proto_kpi == kProtoKPI_v1 ?
				    proto->kpi.v1.event :
				    proto->kpi.v2.event);

				if (eventp != NULL) {
					if_proto_ref(proto);
					ifnet_lock_done(ifp);

					eventp(ifp, proto->protocol_family,
					    event);

					ifnet_lock_shared(ifp);
					if_proto_free(proto);
				}
			}
		}
	}
	ifnet_lock_done(ifp);

	/* Pass the event to the interface */
	if (ifp->if_event != NULL)
		ifp->if_event(ifp, event);

	/* Release the io ref count */
	ifnet_decr_iorefcnt(ifp);

done:
	return (kev_post_msg(event));
}

errno_t
ifnet_event(ifnet_t ifp, struct kern_event_msg *event)
{
	struct kev_msg               kev_msg;
	int result = 0;

	if (ifp == NULL || event == NULL)
		return (EINVAL);

	bzero(&kev_msg, sizeof (kev_msg));
	kev_msg.vendor_code    = event->vendor_code;
	kev_msg.kev_class      = event->kev_class;
	kev_msg.kev_subclass   = event->kev_subclass;
	kev_msg.event_code     = event->event_code;
	kev_msg.dv[0].data_ptr = &event->event_data[0];
	kev_msg.dv[0].data_length = event->total_size - KEV_MSG_HEADER_SIZE;
	kev_msg.dv[1].data_length = 0;

	result = dlil_event_internal(ifp, &kev_msg);

	return (result);
}

#if CONFIG_MACF_NET
#include <netinet/ip6.h>
#include <netinet/ip.h>
static int
dlil_get_socket_type(struct mbuf **mp, int family, int raw)
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

static void
if_inc_traffic_class_out(ifnet_t ifp, mbuf_t m)
{
	if (!(m->m_flags & M_PKTHDR))
		return;

	switch (m->m_pkthdr.prio) {
		case MBUF_TC_BK:
			atomic_add_64(&ifp->if_tc.ifi_obkpackets, 1);
			atomic_add_64(&ifp->if_tc.ifi_obkbytes, m->m_pkthdr.len);
			break;
		case MBUF_TC_VI:
			atomic_add_64(&ifp->if_tc.ifi_ovipackets, 1);
			atomic_add_64(&ifp->if_tc.ifi_ovibytes, m->m_pkthdr.len);
			break;
		case MBUF_TC_VO:
			atomic_add_64(&ifp->if_tc.ifi_ovopackets, 1);
			atomic_add_64(&ifp->if_tc.ifi_ovobytes, m->m_pkthdr.len);
			break;
		default:
			break;
	}
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
errno_t
dlil_output(ifnet_t ifp, protocol_family_t proto_family, mbuf_t packetlist,
    void *route, const struct sockaddr *dest, int raw)
{
	char *frame_type = NULL;
	char *dst_linkaddr = NULL;
	int retval = 0;
	char frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
	char dst_linkaddr_buffer[MAX_LINKADDR * 4];
	struct if_proto	*proto = NULL;
	mbuf_t	m;
	mbuf_t	send_head = NULL;
	mbuf_t	*send_tail = &send_head;
	int iorefcnt = 0;

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);

	/* Get an io refcnt if the interface is attached to prevent ifnet_detach
	 * from happening while this operation is in progress */
	if (!ifnet_is_attached(ifp, 1)) {
		retval = ENXIO;
		goto cleanup;
	}
	iorefcnt = 1;

	/* update the driver's multicast filter, if needed */
	if (ifp->if_updatemcasts > 0 && if_mcasts_update(ifp) == 0)
		ifp->if_updatemcasts = 0;

	frame_type = frame_type_buffer;
	dst_linkaddr = dst_linkaddr_buffer;

	if (raw == 0) {
		ifnet_lock_shared(ifp);
		/* callee holds a proto refcnt upon success */
		proto = find_attached_proto(ifp, proto_family);
		if (proto == NULL) {
			ifnet_lock_done(ifp);
			retval = ENXIO;
			goto cleanup;
		}
		ifnet_lock_done(ifp);
	}

preout_again:
	if (packetlist == NULL)
		goto cleanup;

	m = packetlist;
	packetlist = packetlist->m_nextpkt;
	m->m_nextpkt = NULL;

	if (raw == 0) {
		proto_media_preout preoutp = (proto->proto_kpi == kProtoKPI_v1 ?
		    proto->kpi.v1.pre_output : proto->kpi.v2.pre_output);
		retval = 0;
		if (preoutp != NULL) {
			retval = preoutp(ifp, proto_family, &m, dest, route,
			    frame_type, dst_linkaddr);

			if (retval != 0) {
				if (retval == EJUSTRETURN)
					goto preout_again;
				m_freem(m);
				goto cleanup;
			}
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
#if CONFIG_DTRACE
		if (proto_family == PF_INET) {
			struct ip *ip = mtod(m, struct ip*);
	                DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
				struct ip *, ip, struct ifnet *, ifp,
				struct ip *, ip, struct ip6_hdr *, NULL);

		} else if (proto_family == PF_INET6) {
			struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr*);
			DTRACE_IP6(send, struct mbuf*, m, struct inpcb *, NULL,
				struct ip6_hdr *, ip6, struct ifnet*, ifp,
				struct ip*, NULL, struct ip6_hdr *, ip6);
		}
#endif /* CONFIG_DTRACE */

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

			retval = ifp->if_framer(ifp, &m, dest, dst_linkaddr,
			    frame_type);
			if (retval) {
				if (retval != EJUSTRETURN)
					m_freem(m);
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

		/*
		 * Let interface filters (if any) do their thing ...
		 */
		/* Do not pass VLAN tagged packets to filters PR-3586856 */
		if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0) {
			retval = dlil_interface_filters_output(ifp,
			    &m, proto_family);
			if (retval != 0) {
				if (retval != EJUSTRETURN)
					m_freem(m);
				goto next;
			}
		}
		/*
		 * Strip away M_PROTO1 bit prior to sending packet to the driver
		 * as this field may be used by the driver
		 */
		m->m_flags &= ~M_PROTO1;

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
		 * If this is a TSO packet, make sure the interface still
		 * advertise TSO capability.
		 */

		if ((m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) &&
		    !(ifp->if_hwassist & IFNET_TSO_IPV4)) {
			retval = EMSGSIZE;
			m_freem(m);
			goto cleanup;
		}

		if ((m->m_pkthdr.csum_flags & CSUM_TSO_IPV6) &&
		    !(ifp->if_hwassist & IFNET_TSO_IPV6)) {
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
		} else {
			if_inc_traffic_class_out(ifp, m);
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START,
			    0,0,0,0,0);
			retval = ifp->if_output(ifp, m);
			if (retval && dlil_verbose) {
				printf("%s: output error on %s%d retval = %d\n",
				    __func__, ifp->if_name, ifp->if_unit,
				    retval);
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END,
			    0,0,0,0,0);
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
		if_inc_traffic_class_out(ifp, send_head);

		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
		retval = ifp->if_output(ifp, send_head);
		if (retval && dlil_verbose) {
			printf("%s: output error on %s%d retval = %d\n",
			    __func__, ifp->if_name, ifp->if_unit, retval);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);
	}

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

cleanup:
	if (proto != NULL)
		if_proto_free(proto);
	if (packetlist) /* if any packets are left, clean up */
		mbuf_freem_list(packetlist);
	if (retval == EJUSTRETURN)
		retval = 0;
	if (iorefcnt == 1)
		ifnet_decr_iorefcnt(ifp);

	return (retval);
}

errno_t
ifnet_ioctl(ifnet_t ifp, protocol_family_t proto_fam, u_long ioctl_code,
    void *ioctl_arg)
{
	struct ifnet_filter *filter;
	int retval = EOPNOTSUPP;
	int result = 0;

	if (ifp == NULL || ioctl_code == 0)
		return (EINVAL);

	/* Get an io ref count if the interface is attached */
	if (!ifnet_is_attached(ifp, 1))
		return (EOPNOTSUPP);

	/* Run the interface filters first.
	 * We want to run all filters before calling the protocol,
	 * interface family, or interface.
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		if (filter->filt_ioctl != NULL && (filter->filt_protocol == 0 ||
		    filter->filt_protocol == proto_fam)) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			result = filter->filt_ioctl(filter->filt_cookie, ifp,
			    proto_fam, ioctl_code, ioctl_arg);

			lck_mtx_lock_spin(&ifp->if_flt_lock);

			/* Only update retval if no one has handled the ioctl */
			if (retval == EOPNOTSUPP || result == EJUSTRETURN) {
				if (result == ENOTSUP)
					result = EOPNOTSUPP;
				retval = result;
				if (retval != 0 && retval != EOPNOTSUPP) {
					/* we're done with the filter list */
					if_flt_monitor_unbusy(ifp);
					lck_mtx_unlock(&ifp->if_flt_lock);
					goto cleanup;
				}
			}
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	/* Allow the protocol to handle the ioctl */
	if (proto_fam != 0) {
		struct if_proto	*proto;

		/* callee holds a proto refcnt upon success */
		ifnet_lock_shared(ifp);
		proto = find_attached_proto(ifp, proto_fam);
		ifnet_lock_done(ifp);
		if (proto != NULL) {
			proto_media_ioctl ioctlp =
			    (proto->proto_kpi == kProtoKPI_v1 ?
			    proto->kpi.v1.ioctl : proto->kpi.v2.ioctl);
			result = EOPNOTSUPP;
			if (ioctlp != NULL)
				result = ioctlp(ifp, proto_fam, ioctl_code,
				    ioctl_arg);
			if_proto_free(proto);

			/* Only update retval if no one has handled the ioctl */
			if (retval == EOPNOTSUPP || result == EJUSTRETURN) {
				if (result == ENOTSUP)
					result = EOPNOTSUPP;
				retval = result;
				if (retval && retval != EOPNOTSUPP)
					goto cleanup;
			}
		}
	}

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
	if (retval == EJUSTRETURN)
		retval = 0;

	ifnet_decr_iorefcnt(ifp);

	return (retval);
}

__private_extern__ errno_t
dlil_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func callback)
{
	errno_t	error = 0;


	if (ifp->if_set_bpf_tap) {
		/* Get an io reference on the interface if it is attached */
		if (!ifnet_is_attached(ifp, 1))
			return ENXIO;
		error = ifp->if_set_bpf_tap(ifp, mode, callback);
		ifnet_decr_iorefcnt(ifp);
	}
	return (error);
}

errno_t
dlil_resolve_multi(struct ifnet *ifp, const struct sockaddr *proto_addr,
    struct sockaddr *ll_addr, size_t ll_len)
{
	errno_t	result = EOPNOTSUPP;
	struct if_proto *proto;
	const struct sockaddr *verify;
	proto_media_resolve_multi resolvep;

	if (!ifnet_is_attached(ifp, 1))
		return result;

	bzero(ll_addr, ll_len);

	/* Call the protocol first; callee holds a proto refcnt upon success */
	ifnet_lock_shared(ifp);
	proto = find_attached_proto(ifp, proto_addr->sa_family);
	ifnet_lock_done(ifp);
	if (proto != NULL) {
		resolvep = (proto->proto_kpi == kProtoKPI_v1 ?
		    proto->kpi.v1.resolve_multi : proto->kpi.v2.resolve_multi);
		if (resolvep != NULL)
			result = resolvep(ifp, proto_addr,
			    (struct sockaddr_dl*)ll_addr, ll_len);
		if_proto_free(proto);
	}

	/* Let the interface verify the multicast address */
	if ((result == EOPNOTSUPP || result == 0) && ifp->if_check_multi) {
		if (result == 0)
			verify = ll_addr;
		else
			verify = proto_addr;
		result = ifp->if_check_multi(ifp, verify);
	}

	ifnet_decr_iorefcnt(ifp);
	return (result);
}

__private_extern__ errno_t
dlil_send_arp_internal(ifnet_t ifp, u_short arpop,
    const struct sockaddr_dl* sender_hw, const struct sockaddr* sender_proto,
    const struct sockaddr_dl* target_hw, const struct sockaddr* target_proto)
{
	struct if_proto *proto;
	errno_t	result = 0;

	/* callee holds a proto refcnt upon success */
	ifnet_lock_shared(ifp);
	proto = find_attached_proto(ifp, target_proto->sa_family);
	ifnet_lock_done(ifp);
	if (proto == NULL) {
		result = ENOTSUP;
	} else {
		proto_media_send_arp	arpp;
		arpp = (proto->proto_kpi == kProtoKPI_v1 ?
		    proto->kpi.v1.send_arp : proto->kpi.v2.send_arp);
		if (arpp == NULL)
			result = ENOTSUP;
		else
			result = arpp(ifp, arpop, sender_hw, sender_proto,
			    target_hw, target_proto);
		if_proto_free(proto);
	}

	return (result);
}

static __inline__ int
_is_announcement(const struct sockaddr_in * sender_sin,
    const struct sockaddr_in * target_sin)
{
	if (sender_sin == NULL) {
		return (FALSE);
	}
	return (sender_sin->sin_addr.s_addr == target_sin->sin_addr.s_addr);
}

__private_extern__ errno_t
dlil_send_arp(ifnet_t ifp, u_short arpop, const struct sockaddr_dl* sender_hw,
    const struct sockaddr* sender_proto, const struct sockaddr_dl* target_hw,
    const struct sockaddr* target_proto)
{
	errno_t	result = 0;
	const struct sockaddr_in * sender_sin;
	const struct sockaddr_in * target_sin;

	if (target_proto == NULL || (sender_proto != NULL &&
	    sender_proto->sa_family != target_proto->sa_family))
		return (EINVAL);

	/*
	 * If this is an ARP request and the target IP is IPv4LL,
	 * send the request on all interfaces.  The exception is
	 * an announcement, which must only appear on the specific
	 * interface.
	 */
	sender_sin = (const struct sockaddr_in *)sender_proto;
	target_sin = (const struct sockaddr_in *)target_proto;
	if (target_proto->sa_family == AF_INET &&
	    IN_LINKLOCAL(ntohl(target_sin->sin_addr.s_addr)) &&
	    ipv4_ll_arp_aware != 0 && arpop == ARPOP_REQUEST &&
	    !_is_announcement(target_sin, sender_sin)) {
		ifnet_t		*ifp_list;
		u_int32_t	count;
		u_int32_t	ifp_on;

		result = ENOTSUP;

		if (ifnet_list_get(IFNET_FAMILY_ANY, &ifp_list, &count) == 0) {
			for (ifp_on = 0; ifp_on < count; ifp_on++) {
				errno_t new_result;
				ifaddr_t source_hw = NULL;
				ifaddr_t source_ip = NULL;
				struct sockaddr_in source_ip_copy;
				struct ifnet *cur_ifp = ifp_list[ifp_on];

				/*
				 * Only arp on interfaces marked for IPv4LL
				 * ARPing.  This may mean that we don't ARP on
				 * the interface the subnet route points to.
				 */
				if (!(cur_ifp->if_eflags & IFEF_ARPLL))
					continue;

				/* Find the source IP address */
				ifnet_lock_shared(cur_ifp);
				source_hw = cur_ifp->if_lladdr;
				TAILQ_FOREACH(source_ip, &cur_ifp->if_addrhead,
				    ifa_link) {
					IFA_LOCK(source_ip);
					if (source_ip->ifa_addr != NULL &&
					    source_ip->ifa_addr->sa_family ==
					    AF_INET) {
						/* Copy the source IP address */
						source_ip_copy =
						    *(struct sockaddr_in *)
						    source_ip->ifa_addr;
						IFA_UNLOCK(source_ip);
						break;
					}
					IFA_UNLOCK(source_ip);
				}

				/* No IP Source, don't arp */
				if (source_ip == NULL) {
					ifnet_lock_done(cur_ifp);
					continue;
				}

				IFA_ADDREF(source_hw);
				ifnet_lock_done(cur_ifp);

				/* Send the ARP */
				new_result = dlil_send_arp_internal(cur_ifp,
				    arpop,
				    (struct sockaddr_dl *)source_hw->ifa_addr,
				    (struct sockaddr *)&source_ip_copy, NULL,
				    target_proto);

				IFA_REMREF(source_hw);
				if (result == ENOTSUP) {
					result = new_result;
				}
			}
			ifnet_list_free(ifp_list);
		}
	} else {
		result = dlil_send_arp_internal(ifp, arpop, sender_hw,
		    sender_proto, target_hw, target_proto);
	}

	return (result);
}

/*
 * Caller must hold ifnet head lock.
 */
static int
ifnet_lookup(struct ifnet *ifp)
{
	struct ifnet *_ifp;

	lck_rw_assert(&ifnet_head_lock, LCK_RW_ASSERT_HELD);
	TAILQ_FOREACH(_ifp, &ifnet_head, if_link) {
		if (_ifp == ifp)
			break;
	}
	return (_ifp != NULL);
}
/*
 * Caller has to pass a non-zero refio argument to get a
 * IO reference count. This will prevent ifnet_detach from
 * being called when there are outstanding io reference counts. 
 */
int
ifnet_is_attached(struct ifnet *ifp, int refio)
{
	int ret;

	lck_mtx_lock_spin(&ifp->if_ref_lock);
	if ((ret = ((ifp->if_refflags & (IFRF_ATTACHED | IFRF_DETACHING)) ==
	    IFRF_ATTACHED))) {
		if (refio > 0)
			ifp->if_refio++;
	}
	lck_mtx_unlock(&ifp->if_ref_lock);

	return (ret);
}

void
ifnet_decr_iorefcnt(struct ifnet *ifp)
{
	lck_mtx_lock_spin(&ifp->if_ref_lock);
	VERIFY(ifp->if_refio > 0);
	VERIFY((ifp->if_refflags & (IFRF_ATTACHED | IFRF_DETACHING)) != 0);
	ifp->if_refio--;

	/* if there are no more outstanding io references, wakeup the 
	 * ifnet_detach thread if detaching flag is set.
	 */
	if (ifp->if_refio == 0 && 
		(ifp->if_refflags & IFRF_DETACHING) != 0) {
		/* Convert the spinlock to a regular mutex if we have
		 * to wait for any reason while doing a wakeup.
		 */
		lck_mtx_convert_spin(&ifp->if_ref_lock);
		wakeup(&(ifp->if_refio));
	}
	lck_mtx_unlock(&ifp->if_ref_lock);
}

static void
dlil_if_trace(struct dlil_ifnet *dl_if, int refhold)
{
	struct dlil_ifnet_dbg *dl_if_dbg = (struct dlil_ifnet_dbg *)dl_if;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(dl_if->dl_if_flags & DLIF_DEBUG)) {
		panic("%s: dl_if %p has no debug structure", __func__, dl_if);
		/* NOTREACHED */
	}

	if (refhold) {
		cnt = &dl_if_dbg->dldbg_if_refhold_cnt;
		tr = dl_if_dbg->dldbg_if_refhold;
	} else {
		cnt = &dl_if_dbg->dldbg_if_refrele_cnt;
		tr = dl_if_dbg->dldbg_if_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IF_REF_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

errno_t
dlil_if_ref(struct ifnet *ifp)
{
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	if (dl_if == NULL)
		return (EINVAL);

	lck_mtx_lock_spin(&dl_if->dl_if_lock);
	++dl_if->dl_if_refcnt;
	if (dl_if->dl_if_refcnt == 0) {
		panic("%s: wraparound refcnt for ifp=%p", __func__, ifp);
		/* NOTREACHED */
	}
	if (dl_if->dl_if_trace != NULL)
		(*dl_if->dl_if_trace)(dl_if, TRUE);
	lck_mtx_unlock(&dl_if->dl_if_lock);

	return (0);
}

errno_t
dlil_if_free(struct ifnet *ifp)
{
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	if (dl_if == NULL)
		return (EINVAL);

	lck_mtx_lock_spin(&dl_if->dl_if_lock);
	if (dl_if->dl_if_refcnt == 0) {
		panic("%s: negative refcnt for ifp=%p", __func__, ifp);
		/* NOTREACHED */
	}
	--dl_if->dl_if_refcnt;
	if (dl_if->dl_if_trace != NULL)
		(*dl_if->dl_if_trace)(dl_if, FALSE);
	lck_mtx_unlock(&dl_if->dl_if_lock);

	return (0);
}

static errno_t
dlil_attach_protocol_internal(struct if_proto *proto,
    const struct ifnet_demux_desc *demux_list, u_int32_t demux_count)
{
	struct kev_dl_proto_data ev_pr_data;
	struct ifnet *ifp = proto->ifp;
	int retval = 0;
	u_int32_t hash_value = proto_hash_value(proto->protocol_family);
	struct if_proto *prev_proto;
	struct if_proto *_proto;

	/* callee holds a proto refcnt upon success */
	ifnet_lock_exclusive(ifp);
	_proto = find_attached_proto(ifp, proto->protocol_family);
	if (_proto != NULL) {
		ifnet_lock_done(ifp);
		if_proto_free(_proto);
		return (EEXIST);
	}

	/*
	 * Call family module add_proto routine so it can refine the
	 * demux descriptors as it wishes.
	 */
	retval = ifp->if_add_proto(ifp, proto->protocol_family, demux_list,
	    demux_count);
	if (retval) {
		ifnet_lock_done(ifp);
		return (retval);
	}

	/*
	 * Insert the protocol in the hash
	 */
	prev_proto = SLIST_FIRST(&ifp->if_proto_hash[hash_value]);
	while (prev_proto != NULL && SLIST_NEXT(prev_proto, next_hash) != NULL)
		prev_proto = SLIST_NEXT(prev_proto, next_hash);
	if (prev_proto)
		SLIST_INSERT_AFTER(prev_proto, proto, next_hash);
	else
		SLIST_INSERT_HEAD(&ifp->if_proto_hash[hash_value],
		    proto, next_hash);

	/* hold a proto refcnt for attach */
	if_proto_ref(proto);

	/*
	 * The reserved field carries the number of protocol still attached
	 * (subject to change)
	 */
	ev_pr_data.proto_family = proto->protocol_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
	ifnet_lock_done(ifp);

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_ATTACHED,
	    (struct net_event_data *)&ev_pr_data,
	    sizeof (struct kev_dl_proto_data));
	return (retval);
}

errno_t
ifnet_attach_protocol(ifnet_t ifp, protocol_family_t protocol,
    const struct ifnet_attach_proto_param *proto_details)
{
	int retval = 0;
	struct if_proto  *ifproto = NULL;

	ifnet_head_lock_shared();
	if (ifp == NULL || protocol == 0 || proto_details == NULL) {
		retval = EINVAL;
		goto end;
	}
	/* Check that the interface is in the global list */
	if (!ifnet_lookup(ifp)) {
		retval = ENXIO;
		goto end;
	}

	ifproto = zalloc(dlif_proto_zone);
	if (ifproto == NULL) {
		retval = ENOMEM;
		goto end;
	}
	bzero(ifproto, dlif_proto_size);

	/* refcnt held above during lookup */
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

	if (dlil_verbose) {
		printf("%s%d: attached v1 protocol %d\n", ifp->if_name,
		    ifp->if_unit, protocol);
	}

end:
	if (retval != 0 && retval != EEXIST && ifp != NULL) {
		DLIL_PRINTF("%s%d: failed to attach v1 protocol %d (err=%d)\n",
		    ifp->if_name, ifp->if_unit, protocol, retval);
	}
	ifnet_head_done();
	if (retval != 0  && ifproto != NULL)
		zfree(dlif_proto_zone, ifproto);
	return (retval);
}

errno_t
ifnet_attach_protocol_v2(ifnet_t ifp, protocol_family_t protocol,
    const struct ifnet_attach_proto_param_v2 *proto_details)
{
	int retval = 0;
	struct if_proto  *ifproto = NULL;

	ifnet_head_lock_shared();
	if (ifp == NULL || protocol == 0 || proto_details == NULL) {
		retval = EINVAL;
		goto end;
	}
	/* Check that the interface is in the global list */
	if (!ifnet_lookup(ifp)) {
		retval = ENXIO;
		goto end;
	}

	ifproto = zalloc(dlif_proto_zone);
	if (ifproto == NULL) {
		retval = ENOMEM;
		goto end;
	}
	bzero(ifproto, sizeof(*ifproto));

	/* refcnt held above during lookup */
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

	if (dlil_verbose) {
		printf("%s%d: attached v2 protocol %d\n", ifp->if_name,
		    ifp->if_unit, protocol);
	}

end:
	if (retval != 0 && retval != EEXIST && ifp != NULL) {
		DLIL_PRINTF("%s%d: failed to attach v2 protocol %d (err=%d)\n",
		    ifp->if_name, ifp->if_unit, protocol, retval);
	}
	ifnet_head_done();
	if (retval != 0 && ifproto != NULL)
		zfree(dlif_proto_zone, ifproto);
	return (retval);
}

errno_t
ifnet_detach_protocol(ifnet_t ifp, protocol_family_t proto_family)
{
	struct if_proto *proto = NULL;
	int	retval = 0;

	if (ifp == NULL || proto_family == 0) {
		retval = EINVAL;
		goto end;
	}

	ifnet_lock_exclusive(ifp);
	/* callee holds a proto refcnt upon success */
	proto = find_attached_proto(ifp, proto_family);
	if (proto == NULL) {
		retval = ENXIO;
		ifnet_lock_done(ifp);
		goto end;
	}

	/* call family module del_proto */
	if (ifp->if_del_proto)
		ifp->if_del_proto(ifp, proto->protocol_family);

	SLIST_REMOVE(&ifp->if_proto_hash[proto_hash_value(proto_family)],
	    proto, if_proto, next_hash);

	if (proto->proto_kpi == kProtoKPI_v1) {
		proto->kpi.v1.input = ifproto_media_input_v1;
		proto->kpi.v1.pre_output= ifproto_media_preout;
		proto->kpi.v1.event = ifproto_media_event;
		proto->kpi.v1.ioctl = ifproto_media_ioctl;
		proto->kpi.v1.resolve_multi = ifproto_media_resolve_multi;
		proto->kpi.v1.send_arp = ifproto_media_send_arp;
	} else {
		proto->kpi.v2.input = ifproto_media_input_v2;
		proto->kpi.v2.pre_output = ifproto_media_preout;
		proto->kpi.v2.event = ifproto_media_event;
		proto->kpi.v2.ioctl = ifproto_media_ioctl;
		proto->kpi.v2.resolve_multi = ifproto_media_resolve_multi;
		proto->kpi.v2.send_arp = ifproto_media_send_arp;
	}
	proto->detached = 1;
	ifnet_lock_done(ifp);

	if (dlil_verbose) {
		printf("%s%d: detached %s protocol %d\n", ifp->if_name,
		    ifp->if_unit, (proto->proto_kpi == kProtoKPI_v1) ?
		    "v1" : "v2", proto_family);
	}

	/* release proto refcnt held during protocol attach */
	if_proto_free(proto);

	/*
	 * Release proto refcnt held during lookup; the rest of
	 * protocol detach steps will happen when the last proto
	 * reference is released.
	 */
	if_proto_free(proto);

end:
	return (retval);
}


static errno_t
ifproto_media_input_v1(struct ifnet *ifp, protocol_family_t protocol,
    struct mbuf *packet, char *header)
{
#pragma unused(ifp, protocol, packet, header)
	return (ENXIO);
}

static errno_t
ifproto_media_input_v2(struct ifnet *ifp, protocol_family_t protocol,
    struct mbuf *packet)
{
#pragma unused(ifp, protocol, packet)
	return (ENXIO);

}

static errno_t
ifproto_media_preout(struct ifnet *ifp, protocol_family_t protocol,
    mbuf_t *packet, const struct sockaddr *dest, void *route, char *frame_type,
    char *link_layer_dest)
{
#pragma unused(ifp, protocol, packet, dest, route, frame_type, link_layer_dest)
	return (ENXIO);

}

static void
ifproto_media_event(struct ifnet *ifp, protocol_family_t protocol,
    const struct kev_msg *event)
{
#pragma unused(ifp, protocol, event)
}

static errno_t
ifproto_media_ioctl(struct ifnet *ifp, protocol_family_t protocol,
    unsigned long command, void *argument)
{
#pragma unused(ifp, protocol, command, argument)
	return (ENXIO);
}

static errno_t
ifproto_media_resolve_multi(ifnet_t ifp, const struct sockaddr *proto_addr,
    struct sockaddr_dl *out_ll, size_t ll_len)
{
#pragma unused(ifp, proto_addr, out_ll, ll_len)
	return (ENXIO);
}

static errno_t
ifproto_media_send_arp(struct ifnet *ifp, u_short arpop,
    const struct sockaddr_dl *sender_hw, const struct sockaddr *sender_proto,
    const struct sockaddr_dl *target_hw, const struct sockaddr *target_proto)
{
#pragma unused(ifp, arpop, sender_hw, sender_proto, target_hw, target_proto)
	return (ENXIO);
}

extern int if_next_index(void);

errno_t
ifnet_attach(ifnet_t ifp, const struct sockaddr_dl *ll_addr)
{
	struct ifnet *tmp_if;
	struct ifaddr *ifa;
	struct if_data_internal if_data_saved;
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	if (ifp == NULL)
		return (EINVAL);

	ifnet_head_lock_exclusive();
	/* Verify we aren't already on the list */
	TAILQ_FOREACH(tmp_if, &ifnet_head, if_link) {
		if (tmp_if == ifp) {
			ifnet_head_done();
			return (EEXIST);
		}
	}

	lck_mtx_lock_spin(&ifp->if_ref_lock);
	if (ifp->if_refflags & IFRF_ATTACHED) {
		panic("%s: flags mismatch (attached set) ifp=%p",
		    __func__, ifp);
		/* NOTREACHED */
	}
	lck_mtx_unlock(&ifp->if_ref_lock);

	ifnet_lock_exclusive(ifp);

	/* Sanity check */
	VERIFY(ifp->if_detaching_link.tqe_next == NULL);
	VERIFY(ifp->if_detaching_link.tqe_prev == NULL);

	if (ll_addr != NULL) {
		if (ifp->if_addrlen == 0) {
			ifp->if_addrlen = ll_addr->sdl_alen;
		} else if (ll_addr->sdl_alen != ifp->if_addrlen) {
			ifnet_lock_done(ifp);
			ifnet_head_done();
			return (EINVAL);
		}
	}

	/*
	 * Allow interfaces without protocol families to attach
	 * only if they have the necessary fields filled out.
	 */
	if (ifp->if_add_proto == NULL || ifp->if_del_proto == NULL) {
		DLIL_PRINTF("%s: Attempt to attach interface without "
		    "family module - %d\n", __func__, ifp->if_family);
		ifnet_lock_done(ifp);
		ifnet_head_done();
		return (ENODEV);
	}

	/* Allocate protocol hash table */
	VERIFY(ifp->if_proto_hash == NULL);
	ifp->if_proto_hash = zalloc(dlif_phash_zone);
	if (ifp->if_proto_hash == NULL) {
		ifnet_lock_done(ifp);
		ifnet_head_done();
		return (ENOBUFS);
	}
	bzero(ifp->if_proto_hash, dlif_phash_size);

	lck_mtx_lock_spin(&ifp->if_flt_lock);
	VERIFY(TAILQ_EMPTY(&ifp->if_flt_head));
	TAILQ_INIT(&ifp->if_flt_head);
	VERIFY(ifp->if_flt_busy == 0);
	VERIFY(ifp->if_flt_waiters == 0);
	lck_mtx_unlock(&ifp->if_flt_lock);

	VERIFY(TAILQ_EMPTY(&ifp->if_prefixhead));
	TAILQ_INIT(&ifp->if_prefixhead);

	if (!(dl_if->dl_if_flags & DLIF_REUSE)) {
		VERIFY(LIST_EMPTY(&ifp->if_multiaddrs));
		LIST_INIT(&ifp->if_multiaddrs);
	}

	VERIFY(ifp->if_allhostsinm == NULL);
	VERIFY(TAILQ_EMPTY(&ifp->if_addrhead));
	TAILQ_INIT(&ifp->if_addrhead);

	if (ifp->if_snd.ifq_maxlen == 0)
		ifp->if_snd.ifq_maxlen = ifqmaxlen;

	if (ifp->if_index == 0) {
		int idx = if_next_index();

		if (idx == -1) {
			ifp->if_index = 0;
			ifnet_lock_done(ifp);
			ifnet_head_done();
			return (ENOBUFS);
		}
		ifp->if_index = idx;
	}
	/* There should not be anything occupying this slot */
	VERIFY(ifindex2ifnet[ifp->if_index] == NULL);

	/* allocate (if needed) and initialize a link address */
	VERIFY(!(dl_if->dl_if_flags & DLIF_REUSE) || ifp->if_lladdr != NULL);
	ifa = dlil_alloc_lladdr(ifp, ll_addr);
	if (ifa == NULL) {
		ifnet_lock_done(ifp);
		ifnet_head_done();
		return (ENOBUFS);
	}

	VERIFY(ifnet_addrs[ifp->if_index - 1] == NULL);
	ifnet_addrs[ifp->if_index - 1] = ifa;

	/* make this address the first on the list */
	IFA_LOCK(ifa);
	/* hold a reference for ifnet_addrs[] */
	IFA_ADDREF_LOCKED(ifa);
	/* if_attach_link_ifa() holds a reference for ifa_link */
	if_attach_link_ifa(ifp, ifa);
	IFA_UNLOCK(ifa);

#if CONFIG_MACF_NET
	mac_ifnet_label_associate(ifp);
#endif

	TAILQ_INSERT_TAIL(&ifnet_head, ifp, if_link);
	ifindex2ifnet[ifp->if_index] = ifp;

	/* Hold a reference to the underlying dlil_ifnet */
	ifnet_reference(ifp);

	/*
	 * A specific dlil input thread is created per Ethernet/cellular
	 * interface.  pseudo interfaces or other types of interfaces use
	 * the main ("loopback") thread.
	 *
	 * If the sysctl "net.link.generic.system.multi_threaded_input" is set
	 * to zero, all packets will be handled by the main loopback thread,
	 * reverting to 10.4.x behaviour.
	 */
	if (dlil_multithreaded_input &&
	    (ifp->if_type == IFT_ETHER || ifp->if_type == IFT_CELLULAR)) {
		int err;

		ifp->if_input_thread = zalloc(dlif_inp_zone);
		if (ifp->if_input_thread == NULL) {
			panic("%s: ifp=%p couldn't alloc threading",
			    __func__, ifp);
			/* NOTREACHED */
		}
		bzero(ifp->if_input_thread, dlif_inp_size);
		err = dlil_create_input_thread(ifp, ifp->if_input_thread);
		if (err != 0) {
			panic("%s: ifp=%p couldn't get a thread. "
			    "err=%d", __func__, ifp, err);
			/* NOTREACHED */
		}
#ifdef DLIL_DEBUG
		printf("%s: dlil thread for ifp=%p if_index=%d\n",
		    __func__, ifp, ifp->if_index);
#endif
	}

	/* Clear stats (save and restore other fields that we care) */
	if_data_saved = ifp->if_data;
	bzero(&ifp->if_data, sizeof (ifp->if_data));
	ifp->if_data.ifi_type = if_data_saved.ifi_type;
	ifp->if_data.ifi_typelen = if_data_saved.ifi_typelen;
	ifp->if_data.ifi_physical = if_data_saved.ifi_physical;
	ifp->if_data.ifi_addrlen = if_data_saved.ifi_addrlen;
	ifp->if_data.ifi_hdrlen = if_data_saved.ifi_hdrlen;
	ifp->if_data.ifi_mtu = if_data_saved.ifi_mtu;
	ifp->if_data.ifi_baudrate = if_data_saved.ifi_baudrate;
	ifp->if_data.ifi_hwassist = if_data_saved.ifi_hwassist;
	ifp->if_data.ifi_tso_v4_mtu = if_data_saved.ifi_tso_v4_mtu;
	ifp->if_data.ifi_tso_v6_mtu = if_data_saved.ifi_tso_v6_mtu;
	ifnet_touch_lastchange(ifp);

	/* Record attach PC stacktrace */
	ctrace_record(&((struct dlil_ifnet *)ifp)->dl_if_attach);

	ifp->if_updatemcasts = 0;
	if (!LIST_EMPTY(&ifp->if_multiaddrs)) {
		struct ifmultiaddr *ifma;
		LIST_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			IFMA_LOCK(ifma);
			if (ifma->ifma_addr->sa_family == AF_LINK ||
			    ifma->ifma_addr->sa_family == AF_UNSPEC)
				ifp->if_updatemcasts++;
			IFMA_UNLOCK(ifma);
		}

		printf("%s%d: attached with %d suspended link-layer multicast "
		    "membership(s)\n", ifp->if_name, ifp->if_unit,
		    ifp->if_updatemcasts);
	}

	ifnet_lock_done(ifp);
	ifnet_head_done();

	lck_mtx_lock(&ifp->if_cached_route_lock);
	/* Enable forwarding cached route */
	ifp->if_fwd_cacheok = 1;
	/* Clean up any existing cached routes */
	if (ifp->if_fwd_route.ro_rt != NULL)
		rtfree(ifp->if_fwd_route.ro_rt);
	bzero(&ifp->if_fwd_route, sizeof (ifp->if_fwd_route));
	if (ifp->if_src_route.ro_rt != NULL)
		rtfree(ifp->if_src_route.ro_rt);
	bzero(&ifp->if_src_route, sizeof (ifp->if_src_route));
	if (ifp->if_src_route6.ro_rt != NULL)
		rtfree(ifp->if_src_route6.ro_rt);
	bzero(&ifp->if_src_route6, sizeof (ifp->if_src_route6));
	lck_mtx_unlock(&ifp->if_cached_route_lock);

	ifnet_llreach_ifattach(ifp, (dl_if->dl_if_flags & DLIF_REUSE));

	/*
	 * Allocate and attach IGMPv3/MLDv2 interface specific variables
	 * and trees; do this before the ifnet is marked as attached.
	 * The ifnet keeps the reference to the info structures even after
	 * the ifnet is detached, since the network-layer records still
	 * refer to the info structures even after that.  This also
	 * makes it possible for them to still function after the ifnet
	 * is recycled or reattached.
	 */
#if INET
	if (IGMP_IFINFO(ifp) == NULL) {
		IGMP_IFINFO(ifp) = igmp_domifattach(ifp, M_WAITOK);
		VERIFY(IGMP_IFINFO(ifp) != NULL);
	} else {
		VERIFY(IGMP_IFINFO(ifp)->igi_ifp == ifp);
		igmp_domifreattach(IGMP_IFINFO(ifp));
	}
#endif /* INET */
#if INET6
	if (MLD_IFINFO(ifp) == NULL) {
		MLD_IFINFO(ifp) = mld_domifattach(ifp, M_WAITOK);
		VERIFY(MLD_IFINFO(ifp) != NULL);
	} else {
		VERIFY(MLD_IFINFO(ifp)->mli_ifp == ifp);
		mld_domifreattach(MLD_IFINFO(ifp));
	}
#endif /* INET6 */

	/*
	 * Finally, mark this ifnet as attached.
	 */
	lck_mtx_lock(rnh_lock);
	ifnet_lock_exclusive(ifp);
	lck_mtx_lock_spin(&ifp->if_ref_lock);
	ifp->if_refflags = IFRF_ATTACHED;
	lck_mtx_unlock(&ifp->if_ref_lock);
	if (net_rtref) {
		/* boot-args override; enable idle notification */
		(void) ifnet_set_idle_flags_locked(ifp, IFRF_IDLE_NOTIFY,
		    IFRF_IDLE_NOTIFY);
	} else {
		/* apply previous request(s) to set the idle flags, if any */
		(void) ifnet_set_idle_flags_locked(ifp, ifp->if_idle_new_flags,
		    ifp->if_idle_new_flags_mask);

	}
	ifnet_lock_done(ifp);
	lck_mtx_unlock(rnh_lock);

#if PF
	/*
	 * Attach packet filter to this interface, if enabled.
	 */
	pf_ifnet_hook(ifp, 1);
#endif /* PF */

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, NULL, 0);

	if (dlil_verbose) {
		printf("%s%d: attached%s\n", ifp->if_name, ifp->if_unit,
		    (dl_if->dl_if_flags & DLIF_REUSE) ? " (recycled)" : "");
	}

	return (0);
}

/*
 * Prepare the storage for the first/permanent link address, which must
 * must have the same lifetime as the ifnet itself.  Although the link
 * address gets removed from if_addrhead and ifnet_addrs[] at detach time,
 * its location in memory must never change as it may still be referred
 * to by some parts of the system afterwards (unfortunate implementation
 * artifacts inherited from BSD.)
 *
 * Caller must hold ifnet lock as writer.
 */
static struct ifaddr *
dlil_alloc_lladdr(struct ifnet *ifp, const struct sockaddr_dl *ll_addr)
{
	struct ifaddr *ifa, *oifa;
	struct sockaddr_dl *asdl, *msdl;
	char workbuf[IFNAMSIZ*2];
	int namelen, masklen, socksize;
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	VERIFY(ll_addr == NULL || ll_addr->sdl_alen == ifp->if_addrlen);

	namelen = snprintf(workbuf, sizeof (workbuf), "%s%d",
	    ifp->if_name, ifp->if_unit);
	masklen = offsetof(struct sockaddr_dl, sdl_data[0]) + namelen;
	socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof (u_int32_t) - 1)))
	if ((u_int32_t)socksize < sizeof (struct sockaddr_dl))
		socksize = sizeof(struct sockaddr_dl);
	socksize = ROUNDUP(socksize);
#undef ROUNDUP

	ifa = ifp->if_lladdr;
	if (socksize > DLIL_SDLMAXLEN ||
	    (ifa != NULL && ifa != &dl_if->dl_if_lladdr.ifa)) {
		/*
		 * Rare, but in the event that the link address requires
		 * more storage space than DLIL_SDLMAXLEN, allocate the
		 * largest possible storages for address and mask, such
		 * that we can reuse the same space when if_addrlen grows.
		 * This same space will be used when if_addrlen shrinks.
		 */
		if (ifa == NULL || ifa == &dl_if->dl_if_lladdr.ifa) {
			int ifasize = sizeof (*ifa) + 2 * SOCK_MAXADDRLEN;
			ifa = _MALLOC(ifasize, M_IFADDR, M_WAITOK | M_ZERO);
			if (ifa == NULL)
				return (NULL);
			ifa_lock_init(ifa);
			/* Don't set IFD_ALLOC, as this is permanent */
			ifa->ifa_debug = IFD_LINK;
		}
		IFA_LOCK(ifa);
		/* address and mask sockaddr_dl locations */
		asdl = (struct sockaddr_dl *)(ifa + 1);
		bzero(asdl, SOCK_MAXADDRLEN);
		msdl = (struct sockaddr_dl *)((char *)asdl + SOCK_MAXADDRLEN);
		bzero(msdl, SOCK_MAXADDRLEN);
	} else {
		VERIFY(ifa == NULL || ifa == &dl_if->dl_if_lladdr.ifa);
		/*
		 * Use the storage areas for address and mask within the
		 * dlil_ifnet structure.  This is the most common case.
		 */
		if (ifa == NULL) {
			ifa = &dl_if->dl_if_lladdr.ifa;
			ifa_lock_init(ifa);
			/* Don't set IFD_ALLOC, as this is permanent */
			ifa->ifa_debug = IFD_LINK;
		}
		IFA_LOCK(ifa);
		/* address and mask sockaddr_dl locations */
		asdl = (struct sockaddr_dl *)&dl_if->dl_if_lladdr.asdl;
		bzero(asdl, sizeof (dl_if->dl_if_lladdr.asdl));
		msdl = (struct sockaddr_dl *)&dl_if->dl_if_lladdr.msdl;
		bzero(msdl, sizeof (dl_if->dl_if_lladdr.msdl));
	}

	/* hold a permanent reference for the ifnet itself */
	IFA_ADDREF_LOCKED(ifa);
	oifa = ifp->if_lladdr;
	ifp->if_lladdr = ifa;

	VERIFY(ifa->ifa_debug == IFD_LINK);
	ifa->ifa_ifp = ifp;
	ifa->ifa_rtrequest = link_rtrequest;
	ifa->ifa_addr = (struct sockaddr *)asdl;
	asdl->sdl_len = socksize;
	asdl->sdl_family = AF_LINK;
	bcopy(workbuf, asdl->sdl_data, namelen);
	asdl->sdl_nlen = namelen;
	asdl->sdl_index = ifp->if_index;
	asdl->sdl_type = ifp->if_type;
	if (ll_addr != NULL) {
		asdl->sdl_alen = ll_addr->sdl_alen;
		bcopy(CONST_LLADDR(ll_addr), LLADDR(asdl), asdl->sdl_alen);
	} else {
		asdl->sdl_alen = 0;
	}
	ifa->ifa_netmask = (struct sockaddr*)msdl;
	msdl->sdl_len = masklen;
	while (namelen != 0)
		msdl->sdl_data[--namelen] = 0xff;
	IFA_UNLOCK(ifa);

	if (oifa != NULL)
		IFA_REMREF(oifa);

	return (ifa);
}

static void
if_purgeaddrs(struct ifnet *ifp)
{
#if INET
	in_purgeaddrs(ifp);
#endif /* INET */
#if INET6
	in6_purgeaddrs(ifp);
#endif /* INET6 */
#if NETAT
	at_purgeaddrs(ifp);
#endif
}

errno_t
ifnet_detach(ifnet_t ifp)
{
	if (ifp == NULL)
		return (EINVAL);

	ifnet_head_lock_exclusive();
	lck_mtx_lock(rnh_lock);
	ifnet_lock_exclusive(ifp);

	/*
	 * Check to see if this interface has previously triggered
	 * aggressive protocol draining; if so, decrement the global
	 * refcnt and clear PR_AGGDRAIN on the route domain if
	 * there are no more of such an interface around.
	 */
	(void) ifnet_set_idle_flags_locked(ifp, 0, ~0);

	lck_mtx_lock_spin(&ifp->if_ref_lock);
	 if (!(ifp->if_refflags & IFRF_ATTACHED)) {
		lck_mtx_unlock(&ifp->if_ref_lock);
		ifnet_lock_done(ifp);
		lck_mtx_unlock(rnh_lock);
		ifnet_head_done();
		return (EINVAL);
	} else if (ifp->if_refflags & IFRF_DETACHING) {
		/* Interface has already been detached */
		lck_mtx_unlock(&ifp->if_ref_lock);
		ifnet_lock_done(ifp);
		lck_mtx_unlock(rnh_lock);
		ifnet_head_done();
		return (ENXIO);
	}
	/* Indicate this interface is being detached */
	ifp->if_refflags &= ~IFRF_ATTACHED;
	ifp->if_refflags |= IFRF_DETACHING;
	lck_mtx_unlock(&ifp->if_ref_lock);

	if (dlil_verbose)
		printf("%s%d: detaching\n", ifp->if_name, ifp->if_unit);

	/*
	 * Remove ifnet from the ifnet_head, ifindex2ifnet[]; it will
	 * no longer be visible during lookups from this point.
	 */
	VERIFY(ifindex2ifnet[ifp->if_index] == ifp);
	TAILQ_REMOVE(&ifnet_head, ifp, if_link);
	ifp->if_link.tqe_next = NULL;
	ifp->if_link.tqe_prev = NULL;
	ifindex2ifnet[ifp->if_index] = NULL;

	/* Record detach PC stacktrace */
	ctrace_record(&((struct dlil_ifnet *)ifp)->dl_if_detach);

	ifnet_lock_done(ifp);
	lck_mtx_unlock(rnh_lock);
	ifnet_head_done();

	/* Let BPF know we're detaching */
	bpfdetach(ifp);

	/* Mark the interface as DOWN */
	if_down(ifp);

	/* Disable forwarding cached route */
	lck_mtx_lock(&ifp->if_cached_route_lock);
	ifp->if_fwd_cacheok = 0;
	lck_mtx_unlock(&ifp->if_cached_route_lock);

	/*
	 * Drain any deferred IGMPv3/MLDv2 query responses, but keep the
	 * references to the info structures and leave them attached to
	 * this ifnet.
	 */
#if INET
	igmp_domifdetach(ifp);
#endif /* INET */
#if INET6
	mld_domifdetach(ifp);
#endif /* INET6 */

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHING, NULL, 0);

	/* Let worker thread take care of the rest, to avoid reentrancy */
	lck_mtx_lock(&dlil_ifnet_lock);
	ifnet_detaching_enqueue(ifp);
	lck_mtx_unlock(&dlil_ifnet_lock);

	return (0);
}

static void
ifnet_detaching_enqueue(struct ifnet *ifp)
{
	lck_mtx_assert(&dlil_ifnet_lock, LCK_MTX_ASSERT_OWNED);

	++ifnet_detaching_cnt;
	VERIFY(ifnet_detaching_cnt != 0);
	TAILQ_INSERT_TAIL(&ifnet_detaching_head, ifp, if_detaching_link);
	wakeup((caddr_t)&ifnet_delayed_run);
}

static struct ifnet *
ifnet_detaching_dequeue(void)
{
	struct ifnet *ifp;

	lck_mtx_assert(&dlil_ifnet_lock, LCK_MTX_ASSERT_OWNED);

	ifp = TAILQ_FIRST(&ifnet_detaching_head);
	VERIFY(ifnet_detaching_cnt != 0 || ifp == NULL);
	if (ifp != NULL) {
		VERIFY(ifnet_detaching_cnt != 0);
		--ifnet_detaching_cnt;
		TAILQ_REMOVE(&ifnet_detaching_head, ifp, if_detaching_link);
		ifp->if_detaching_link.tqe_next = NULL;
		ifp->if_detaching_link.tqe_prev = NULL;
	}
	return (ifp);
}

static void
ifnet_delayed_thread_func(void)
{
	struct ifnet *ifp;

	for (;;) {
		lck_mtx_lock(&dlil_ifnet_lock);
		while (ifnet_detaching_cnt == 0) {
			(void) msleep(&ifnet_delayed_run, &dlil_ifnet_lock,
			    (PZERO - 1), "ifnet_delayed_thread", NULL);
		}

		VERIFY(TAILQ_FIRST(&ifnet_detaching_head) != NULL);

		/* Take care of detaching ifnet */
		ifp = ifnet_detaching_dequeue();
		if (ifp != NULL) {
			lck_mtx_unlock(&dlil_ifnet_lock);
			ifnet_detach_final(ifp);
		} else {
			lck_mtx_unlock(&dlil_ifnet_lock);
		}
	}
}

static void
ifnet_detach_final(struct ifnet *ifp)
{
	struct ifnet_filter *filter, *filter_next;
	struct ifnet_filter_head fhead;
	struct dlil_threading_info *inputthread;
	struct ifaddr *ifa;
	ifnet_detached_func if_free;
	int i;

	lck_mtx_lock(&ifp->if_ref_lock);
	if (!(ifp->if_refflags & IFRF_DETACHING)) {
		panic("%s: flags mismatch (detaching not set) ifp=%p",
		    __func__, ifp);
		/* NOTREACHED */
	}

	/* Wait until the existing IO references get released
	 * before we proceed with ifnet_detach
	 */
	while (ifp->if_refio > 0) {
		printf("%s: Waiting for IO references on %s%d interface "
		    "to be released\n", __func__, ifp->if_name, ifp->if_unit);
		(void) msleep(&(ifp->if_refio), &ifp->if_ref_lock,
			(PZERO - 1), "ifnet_ioref_wait", NULL);
	}
	lck_mtx_unlock(&ifp->if_ref_lock);

	/* Detach interface filters */
	lck_mtx_lock(&ifp->if_flt_lock);
	if_flt_monitor_enter(ifp);

	lck_mtx_assert(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);
	fhead = ifp->if_flt_head;
	TAILQ_INIT(&ifp->if_flt_head);

	for (filter = TAILQ_FIRST(&fhead); filter; filter = filter_next) {
		filter_next = TAILQ_NEXT(filter, filt_next);
		lck_mtx_unlock(&ifp->if_flt_lock);

		dlil_detach_filter_internal(filter, 1);
		lck_mtx_lock(&ifp->if_flt_lock);
	}
	if_flt_monitor_leave(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	/* Tell upper layers to drop their network addresses */
	if_purgeaddrs(ifp);

	ifnet_lock_exclusive(ifp);

	/* Uplumb all protocols */
	for (i = 0; i < PROTO_HASH_SLOTS; i++) {
		struct if_proto *proto;

		proto = SLIST_FIRST(&ifp->if_proto_hash[i]);
		while (proto != NULL) {
			protocol_family_t family = proto->protocol_family;
			ifnet_lock_done(ifp);
			proto_unplumb(family, ifp);
			ifnet_lock_exclusive(ifp);
			proto = SLIST_FIRST(&ifp->if_proto_hash[i]);
		}
		/* There should not be any protocols left */
		VERIFY(SLIST_EMPTY(&ifp->if_proto_hash[i]));
	}
	zfree(dlif_phash_zone, ifp->if_proto_hash);
	ifp->if_proto_hash = NULL;

	/* Detach (permanent) link address from if_addrhead */
	ifa = TAILQ_FIRST(&ifp->if_addrhead);
	VERIFY(ifnet_addrs[ifp->if_index - 1] == ifa);
	IFA_LOCK(ifa);
	if_detach_link_ifa(ifp, ifa);
	IFA_UNLOCK(ifa);

	/* Remove (permanent) link address from ifnet_addrs[] */
	IFA_REMREF(ifa);
	ifnet_addrs[ifp->if_index - 1] = NULL;

	/* This interface should not be on {ifnet_head,detaching} */
	VERIFY(ifp->if_link.tqe_next == NULL);
	VERIFY(ifp->if_link.tqe_prev == NULL);
	VERIFY(ifp->if_detaching_link.tqe_next == NULL);
	VERIFY(ifp->if_detaching_link.tqe_prev == NULL);

	/* Prefix list should be empty by now */
	VERIFY(TAILQ_EMPTY(&ifp->if_prefixhead));

	/* The slot should have been emptied */
	VERIFY(ifindex2ifnet[ifp->if_index] == NULL);

	/* There should not be any addresses left */
	VERIFY(TAILQ_EMPTY(&ifp->if_addrhead));

	/*
	 * If thread affinity was set for the workloop thread, we will need
	 * to tear down the affinity and release the extra reference count
	 * taken at attach time;
	 */
	if ((inputthread = ifp->if_input_thread) != NULL) {
		if (inputthread->net_affinity) {
			struct thread *tp;

			if (inputthread == dlil_lo_thread_ptr) {
				panic("%s: Thread affinity should not be "
				    "enabled on the loopback dlil input "
				    "thread", __func__);
				/* NOTREACHED */
			}

			lck_mtx_lock_spin(&inputthread->input_lck);
			tp = inputthread->workloop_thread;
			inputthread->workloop_thread = NULL;
			inputthread->tag = 0;
			inputthread->net_affinity = FALSE;
			lck_mtx_unlock(&inputthread->input_lck);

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
			printf("%s: wakeup thread threadinfo: %p "
			    "input_thread=%p threads: cur=%d max=%d\n",
			    __func__, inputthread, inputthread->input_thread,
			    dlil_multithreaded_input, cur_dlil_input_threads);
#endif
			lck_mtx_lock_spin(&inputthread->input_lck);

			inputthread->input_waiting |= DLIL_INPUT_TERMINATE;
			if (!(inputthread->input_waiting & DLIL_INPUT_RUNNING))
				wakeup((caddr_t)&inputthread->input_waiting);

			lck_mtx_unlock(&inputthread->input_lck);
		}
	}

	/* The driver might unload, so point these to ourselves */
	if_free = ifp->if_free;
	ifp->if_output = ifp_if_output;
	ifp->if_ioctl = ifp_if_ioctl;
	ifp->if_set_bpf_tap = ifp_if_set_bpf_tap;
	ifp->if_free = ifp_if_free;
	ifp->if_demux = ifp_if_demux;
	ifp->if_event = ifp_if_event;
	ifp->if_framer = ifp_if_framer;
	ifp->if_add_proto = ifp_if_add_proto;
	ifp->if_del_proto = ifp_if_del_proto;
	ifp->if_check_multi = ifp_if_check_multi;

	ifnet_lock_done(ifp);

#if PF
	/*
	 * Detach this interface from packet filter, if enabled.
	 */
	pf_ifnet_hook(ifp, 0);
#endif /* PF */

	/* Filter list should be empty */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	VERIFY(TAILQ_EMPTY(&ifp->if_flt_head));
	VERIFY(ifp->if_flt_busy == 0);
	VERIFY(ifp->if_flt_waiters == 0);
	lck_mtx_unlock(&ifp->if_flt_lock);

	/* Last chance to cleanup any cached route */
	lck_mtx_lock(&ifp->if_cached_route_lock);
	VERIFY(!ifp->if_fwd_cacheok);
	if (ifp->if_fwd_route.ro_rt != NULL)
		rtfree(ifp->if_fwd_route.ro_rt);
	bzero(&ifp->if_fwd_route, sizeof (ifp->if_fwd_route));
	if (ifp->if_src_route.ro_rt != NULL)
		rtfree(ifp->if_src_route.ro_rt);
	bzero(&ifp->if_src_route, sizeof (ifp->if_src_route));
	if (ifp->if_src_route6.ro_rt != NULL)
		rtfree(ifp->if_src_route6.ro_rt);
	bzero(&ifp->if_src_route6, sizeof (ifp->if_src_route6));
	lck_mtx_unlock(&ifp->if_cached_route_lock);

	ifnet_llreach_ifdetach(ifp);

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, NULL, 0);

	if (if_free != NULL)
		if_free(ifp);

	/*
	 * Finally, mark this ifnet as detached.
	 */
	lck_mtx_lock_spin(&ifp->if_ref_lock);
	if (!(ifp->if_refflags & IFRF_DETACHING)) {
		panic("%s: flags mismatch (detaching not set) ifp=%p",
		    __func__, ifp);
		/* NOTREACHED */
	}
	ifp->if_refflags &= ~IFRF_DETACHING;
	lck_mtx_unlock(&ifp->if_ref_lock);

	if (dlil_verbose)
		printf("%s%d: detached\n", ifp->if_name, ifp->if_unit);

	/* Release reference held during ifnet attach */
	ifnet_release(ifp);
}

static errno_t
ifp_if_output(struct ifnet *ifp, struct mbuf *m)
{
#pragma unused(ifp)
	m_freem(m);
	return (0);
}

static errno_t
ifp_if_demux(struct ifnet *ifp, struct mbuf *m, char *fh, protocol_family_t *pf)
{
#pragma unused(ifp, fh, pf)
	m_freem(m);
	return (EJUSTRETURN);
}

static errno_t
ifp_if_add_proto(struct ifnet *ifp, protocol_family_t pf,
    const struct ifnet_demux_desc *da, u_int32_t dc)
{
#pragma unused(ifp, pf, da, dc)
	return (EINVAL);
}

static errno_t
ifp_if_del_proto(struct ifnet *ifp, protocol_family_t pf)
{
#pragma unused(ifp, pf)
	return (EINVAL);
}

static errno_t
ifp_if_check_multi(struct ifnet *ifp, const struct sockaddr *sa)
{
#pragma unused(ifp, sa)
	return (EOPNOTSUPP);
}

static errno_t
ifp_if_framer(struct ifnet *ifp, struct mbuf **m,
    const struct sockaddr *sa, const char *ll, const char *t)
{
#pragma unused(ifp, m, sa, ll, t)
	m_freem(*m);
	*m = NULL;
	return (EJUSTRETURN);
}

static errno_t
ifp_if_ioctl(struct ifnet *ifp, unsigned long cmd, void *arg)
{
#pragma unused(ifp, cmd, arg)
	return (EOPNOTSUPP);
}

static errno_t
ifp_if_set_bpf_tap(struct ifnet *ifp, bpf_tap_mode tm, bpf_packet_func f)
{
#pragma unused(ifp, tm, f)
	/* XXX not sure what to do here */
	return (0);
}

static void
ifp_if_free(struct ifnet *ifp)
{
#pragma unused(ifp)
}

static void
ifp_if_event(struct ifnet *ifp, const struct kev_msg *e)
{
#pragma unused(ifp, e)
}

__private_extern__
int dlil_if_acquire(u_int32_t family, const void *uniqueid,
    size_t uniqueid_len, struct ifnet **ifp)
{
	struct ifnet *ifp1 = NULL;
	struct dlil_ifnet *dlifp1 = NULL;
	void *buf, *base, **pbuf;
	int ret = 0;

	lck_mtx_lock(&dlil_ifnet_lock);
	TAILQ_FOREACH(dlifp1, &dlil_ifnet_head, dl_if_link) {
		ifp1 = (struct ifnet *)dlifp1;

		if (ifp1->if_family != family)
			continue;

		lck_mtx_lock(&dlifp1->dl_if_lock);
		/* same uniqueid and same len or no unique id specified */
		if ((uniqueid_len == dlifp1->dl_if_uniqueid_len) &&
		    !bcmp(uniqueid, dlifp1->dl_if_uniqueid, uniqueid_len)) {
			/* check for matching interface in use */
			if (dlifp1->dl_if_flags & DLIF_INUSE) {
				if (uniqueid_len) {
					ret = EBUSY;
					lck_mtx_unlock(&dlifp1->dl_if_lock);
					goto end;
				}
			} else {
				dlifp1->dl_if_flags |= (DLIF_INUSE|DLIF_REUSE);
				lck_mtx_unlock(&dlifp1->dl_if_lock);
				*ifp = ifp1;
				goto end;
			}
		}
		lck_mtx_unlock(&dlifp1->dl_if_lock);
	}

	/* no interface found, allocate a new one */
	buf = zalloc(dlif_zone);
	if (buf == NULL) {
		ret = ENOMEM;
		goto end;
	}
	bzero(buf, dlif_bufsize);

	/* Get the 64-bit aligned base address for this object */
	base = (void *)P2ROUNDUP((intptr_t)buf + sizeof (u_int64_t),
	    sizeof (u_int64_t));
	VERIFY(((intptr_t)base + dlif_size) <= ((intptr_t)buf + dlif_bufsize));

	/*
	 * Wind back a pointer size from the aligned base and
	 * save the original address so we can free it later.
	 */
	pbuf = (void **)((intptr_t)base - sizeof (void *));
	*pbuf = buf;
	dlifp1 = base;

	if (uniqueid_len) {
		MALLOC(dlifp1->dl_if_uniqueid, void *, uniqueid_len,
		    M_NKE, M_WAITOK);
		if (dlifp1->dl_if_uniqueid == NULL) {
			zfree(dlif_zone, dlifp1);
			ret = ENOMEM;
			goto end;
		}
		bcopy(uniqueid, dlifp1->dl_if_uniqueid, uniqueid_len);
		dlifp1->dl_if_uniqueid_len = uniqueid_len;
	}

	ifp1 = (struct ifnet *)dlifp1;
	dlifp1->dl_if_flags = DLIF_INUSE;
	if (ifnet_debug) {
		dlifp1->dl_if_flags |= DLIF_DEBUG;
		dlifp1->dl_if_trace = dlil_if_trace;
	}
	ifp1->if_name = dlifp1->dl_if_namestorage;
#if CONFIG_MACF_NET
	mac_ifnet_label_init(ifp1);
#endif

	lck_mtx_init(&dlifp1->dl_if_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_rw_init(&ifp1->if_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_ref_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_flt_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_cached_route_lock, ifnet_lock_group,
	    ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_addrconfig_lock, ifnet_lock_group,
	    ifnet_lock_attr);
	lck_rw_init(&ifp1->if_llreach_lock, ifnet_lock_group, ifnet_lock_attr);

	TAILQ_INSERT_TAIL(&dlil_ifnet_head, dlifp1, dl_if_link);

	*ifp = ifp1;

end:
	lck_mtx_unlock(&dlil_ifnet_lock);

	VERIFY(dlifp1 == NULL || (IS_P2ALIGNED(dlifp1, sizeof (u_int64_t)) &&
	    IS_P2ALIGNED(&ifp1->if_data, sizeof (u_int64_t))));

	return (ret);
}

__private_extern__ void
dlil_if_release(ifnet_t	ifp)
{
	struct dlil_ifnet *dlifp = (struct dlil_ifnet *)ifp;

	ifnet_lock_exclusive(ifp);
	lck_mtx_lock(&dlifp->dl_if_lock);
	dlifp->dl_if_flags &= ~DLIF_INUSE;
	strncpy(dlifp->dl_if_namestorage, ifp->if_name, IFNAMSIZ);
	ifp->if_name = dlifp->dl_if_namestorage;
	lck_mtx_unlock(&dlifp->dl_if_lock);
#if CONFIG_MACF_NET
	/*
	* We can either recycle the MAC label here or in dlil_if_acquire().
	* It seems logical to do it here but this means that anything that
	* still has a handle on ifp will now see it as unlabeled.
	* Since the interface is "dead" that may be OK.  Revisit later.
	*/
	mac_ifnet_label_recycle(ifp);
#endif
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

static void
ifp_src_route_copyout(struct ifnet *ifp, struct route *dst)
{
	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	route_copyout(dst, &ifp->if_src_route, sizeof (*dst));

	lck_mtx_unlock(&ifp->if_cached_route_lock);
}

static void
ifp_src_route_copyin(struct ifnet *ifp, struct route *src)
{
	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	if (ifp->if_fwd_cacheok) {
		route_copyin(src, &ifp->if_src_route, sizeof (*src));
	} else {
		rtfree(src->ro_rt);
		src->ro_rt = NULL;
	}
	lck_mtx_unlock(&ifp->if_cached_route_lock);
}

#if INET6
static void
ifp_src_route6_copyout(struct ifnet *ifp, struct route_in6 *dst)
{
	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	route_copyout((struct route *)dst, (struct route *)&ifp->if_src_route6,
	    sizeof (*dst));

	lck_mtx_unlock(&ifp->if_cached_route_lock);
}

static void
ifp_src_route6_copyin(struct ifnet *ifp, struct route_in6 *src)
{
	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	if (ifp->if_fwd_cacheok) {
		route_copyin((struct route *)src,
		    (struct route *)&ifp->if_src_route6, sizeof (*src));
	} else {
		rtfree(src->ro_rt);
		src->ro_rt = NULL;
	}
	lck_mtx_unlock(&ifp->if_cached_route_lock);
}
#endif /* INET6 */

struct rtentry *
ifnet_cached_rtlookup_inet(struct ifnet	*ifp, struct in_addr src_ip)
{
	struct route		src_rt;
	struct sockaddr_in	*dst = (struct sockaddr_in *)(&src_rt.ro_dst);

	ifp_src_route_copyout(ifp, &src_rt);

	if (src_rt.ro_rt == NULL || !(src_rt.ro_rt->rt_flags & RTF_UP) ||
	    src_ip.s_addr != dst->sin_addr.s_addr ||
	    src_rt.ro_rt->generation_id != route_generation) {
		if (src_rt.ro_rt != NULL) {
			rtfree(src_rt.ro_rt);
			src_rt.ro_rt = NULL;
		} else if (dst->sin_family != AF_INET) {
			bzero(&src_rt.ro_dst, sizeof (src_rt.ro_dst));
			dst->sin_len = sizeof (src_rt.ro_dst);
			dst->sin_family = AF_INET;
		}
		dst->sin_addr = src_ip;

		if (src_rt.ro_rt == NULL) {
			src_rt.ro_rt = rtalloc1_scoped((struct sockaddr *)dst,
			    0, 0, ifp->if_index);

			if (src_rt.ro_rt != NULL) {
				/* retain a ref, copyin consumes one */
				struct rtentry	*rte = src_rt.ro_rt;
				RT_ADDREF(rte);
				ifp_src_route_copyin(ifp, &src_rt);
				src_rt.ro_rt = rte;
			}
		}
	}

	return (src_rt.ro_rt);
}

#if INET6
struct rtentry*
ifnet_cached_rtlookup_inet6(struct ifnet *ifp, struct in6_addr *src_ip6)
{
	struct route_in6 src_rt;

	ifp_src_route6_copyout(ifp, &src_rt);

	if (src_rt.ro_rt == NULL || !(src_rt.ro_rt->rt_flags & RTF_UP) ||
	    !IN6_ARE_ADDR_EQUAL(src_ip6, &src_rt.ro_dst.sin6_addr) ||
	    src_rt.ro_rt->generation_id != route_generation) {
		if (src_rt.ro_rt != NULL) {
			rtfree(src_rt.ro_rt);
			src_rt.ro_rt = NULL;
		} else if (src_rt.ro_dst.sin6_family != AF_INET6) {
			bzero(&src_rt.ro_dst, sizeof (src_rt.ro_dst));
			src_rt.ro_dst.sin6_len = sizeof (src_rt.ro_dst);
			src_rt.ro_dst.sin6_family = AF_INET6;
		}
		src_rt.ro_dst.sin6_scope_id = in6_addr2scopeid(ifp, src_ip6);
		src_rt.ro_dst.sin6_addr = *src_ip6;

		if (src_rt.ro_rt == NULL) {
			src_rt.ro_rt = rtalloc1_scoped(
			    (struct sockaddr *)&src_rt.ro_dst, 0, 0,
			    ifp->if_index);

			if (src_rt.ro_rt != NULL) {
				/* retain a ref, copyin consumes one */
				struct rtentry	*rte = src_rt.ro_rt;
				RT_ADDREF(rte);
				ifp_src_route6_copyin(ifp, &src_rt);
				src_rt.ro_rt = rte;
			}
		}
	}

	return (src_rt.ro_rt);
}
#endif /* INET6 */
