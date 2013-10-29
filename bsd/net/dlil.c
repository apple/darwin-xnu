/*
 * Copyright (c) 1999-2013 Apple Inc. All rights reserved.
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
#include <stddef.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/user.h>
#include <sys/random.h>
#include <sys/socketvar.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_var.h>
#include <net/dlil.h>
#include <net/if_arp.h>
#include <net/iptap.h>
#include <net/pktap.h>
#include <sys/kern_event.h>
#include <sys/kdebug.h>
#include <sys/mcache.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/priv.h>

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
#include <net/classq/classq.h>
#include <net/classq/classq_sfb.h>
#include <net/flowhash.h>
#include <net/ntstat.h>

#if INET
#include <netinet/in_var.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_pcb.h>
#endif /* INET */

#if INET6
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/scope6_var.h>
#endif /* INET6 */

#include <libkern/OSAtomic.h>
#include <libkern/tree.h>

#include <dev/random/randomdev.h>
#include <machine/machine_routines.h>

#include <mach/thread_act.h>
#include <mach/sdt.h>

#if CONFIG_MACF
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <net/ethernet.h>
#include <net/firewire.h>
#endif

#if PF
#include <net/pfvar.h>
#endif /* PF */
#if PF_ALTQ
#include <net/altq/altq.h>
#endif /* PF_ALTQ */
#include <net/pktsched/pktsched.h>

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

#define	IF_DATA_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct if_data_internal, f) % sizeof (u_int64_t)))

#define	IFNET_IF_DATA_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct ifnet, if_data.f) % sizeof (u_int64_t)))

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
	 * DLIL private fields, protected by dl_if_lock
	 */
	decl_lck_mtx_data(, dl_if_lock);
	TAILQ_ENTRY(dlil_ifnet) dl_if_link;	/* dlil_ifnet link */
	u_int32_t dl_if_flags;			/* flags (below) */
	u_int32_t dl_if_refcnt;			/* refcnt */
	void (*dl_if_trace)(struct dlil_ifnet *, int); /* ref trace callback */
	void	*dl_if_uniqueid;		/* unique interface id */
	size_t	dl_if_uniqueid_len;		/* length of the unique id */
	char	dl_if_namestorage[IFNAMSIZ];	/* interface name storage */
	char	dl_if_xnamestorage[IFXNAMSIZ];	/* external name storage */
	struct {
		struct ifaddr	ifa;		/* lladdr ifa */
		u_int8_t	asdl[DLIL_SDLMAXLEN]; /* addr storage */
		u_int8_t	msdl[DLIL_SDLMAXLEN]; /* mask storage */
	} dl_if_lladdr;
	u_int8_t dl_if_descstorage[IF_DESCSIZE]; /* desc storage */
	struct dlil_threading_info dl_if_inpstorage; /* input thread storage */
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
	u_int32_t			filt_flags;
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
static lck_grp_t *ifnet_snd_lock_group;
static lck_grp_t *ifnet_rcv_lock_group;
lck_attr_t *ifnet_lock_attr;
decl_lck_rw_data(static, ifnet_head_lock);
decl_lck_mtx_data(static, dlil_ifnet_lock);
u_int32_t dlil_filter_disable_tso_count = 0;

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

static unsigned int dlif_phash_size;	/* size of ifnet proto hash table */
static struct zone *dlif_phash_zone;	/* zone for ifnet proto hash table */

#define	DLIF_PHASH_ZONE_MAX	DLIF_ZONE_MAX	/* maximum elements in zone */
#define	DLIF_PHASH_ZONE_NAME	"ifnet_proto_hash" /* zone name */

static unsigned int dlif_proto_size;	/* size of if_proto */
static struct zone *dlif_proto_zone;	/* zone for if_proto */

#define	DLIF_PROTO_ZONE_MAX	(DLIF_ZONE_MAX*2) /* maximum elements in zone */
#define	DLIF_PROTO_ZONE_NAME	"ifnet_proto"	/* zone name */

static unsigned int dlif_tcpstat_size;		/* size of tcpstat_local to allocate */
static unsigned int dlif_tcpstat_bufsize;	/* size of dlif_tcpstat_size + headroom */
static struct zone *dlif_tcpstat_zone;		/* zone for tcpstat_local */

#define	DLIF_TCPSTAT_ZONE_MAX	1		/* maximum elements in zone */
#define	DLIF_TCPSTAT_ZONE_NAME	"ifnet_tcpstat"	/* zone name */

static unsigned int dlif_udpstat_size;		/* size of udpstat_local to allocate */
static unsigned int dlif_udpstat_bufsize;	/* size of dlif_udpstat_size + headroom */
static struct zone *dlif_udpstat_zone;		/* zone for udpstat_local */

#define	DLIF_UDPSTAT_ZONE_MAX	1		/* maximum elements in zone */
#define	DLIF_UDPSTAT_ZONE_NAME	"ifnet_udpstat"	/* zone name */

/*
 * Updating this variable should be done by first acquiring the global
 * radix node head (rnh_lock), in tandem with settting/clearing the
 * PR_AGGDRAIN for routedomain.
 */
u_int32_t ifnet_aggressive_drainers;
static u_int32_t net_rtref;

static struct dlil_main_threading_info dlil_main_input_thread_info;
__private_extern__ struct dlil_threading_info *dlil_main_input_thread =
    (struct dlil_threading_info *)&dlil_main_input_thread_info;

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
static void ifp_if_start(struct ifnet *);
static void ifp_if_input_poll(struct ifnet *, u_int32_t, u_int32_t,
    struct mbuf **, struct mbuf **, u_int32_t *, u_int32_t *);
static errno_t ifp_if_ctl(struct ifnet *, ifnet_ctl_cmd_t, u_int32_t, void *);
static errno_t ifp_if_demux(struct ifnet *, struct mbuf *, char *,
    protocol_family_t *);
static errno_t ifp_if_add_proto(struct ifnet *, protocol_family_t,
    const struct ifnet_demux_desc *, u_int32_t);
static errno_t ifp_if_del_proto(struct ifnet *, protocol_family_t);
static errno_t ifp_if_check_multi(struct ifnet *, const struct sockaddr *);
static errno_t ifp_if_framer(struct ifnet *, struct mbuf **,
    const struct sockaddr *, const char *, const char *);
static errno_t ifp_if_framer_extended(struct ifnet *, struct mbuf **,
    const struct sockaddr *, const char *, const char *,
    u_int32_t *, u_int32_t *);
static errno_t ifp_if_set_bpf_tap(struct ifnet *, bpf_tap_mode, bpf_packet_func);
static void ifp_if_free(struct ifnet *);
static void ifp_if_event(struct ifnet *, const struct kev_msg *);
static __inline void ifp_inc_traffic_class_in(struct ifnet *, struct mbuf *);
static __inline void ifp_inc_traffic_class_out(struct ifnet *, struct mbuf *);

static void dlil_main_input_thread_func(void *, wait_result_t);
static void dlil_input_thread_func(void *, wait_result_t);
static void dlil_rxpoll_input_thread_func(void *, wait_result_t);
static int dlil_create_input_thread(ifnet_t, struct dlil_threading_info *);
static void dlil_terminate_input_thread(struct dlil_threading_info *);
static void dlil_input_stats_add(const struct ifnet_stat_increment_param *,
    struct dlil_threading_info *, boolean_t);
static void dlil_input_stats_sync(struct ifnet *, struct dlil_threading_info *);
static void dlil_input_packet_list_common(struct ifnet *, struct mbuf *,
    u_int32_t, ifnet_model_t, boolean_t);
static errno_t ifnet_input_common(struct ifnet *, struct mbuf *, struct mbuf *,
    const struct ifnet_stat_increment_param *, boolean_t, boolean_t);

#if DEBUG
static void dlil_verify_sum16(void);
#endif /* DEBUG */
static void dlil_output_cksum_dbg(struct ifnet *, struct mbuf *, uint32_t,
    protocol_family_t);
static void dlil_input_cksum_dbg(struct ifnet *, struct mbuf *, char *,
    protocol_family_t);

static void ifnet_detacher_thread_func(void *, wait_result_t);
static int ifnet_detacher_thread_cont(int);
static void ifnet_detach_final(struct ifnet *);
static void ifnet_detaching_enqueue(struct ifnet *);
static struct ifnet *ifnet_detaching_dequeue(void);

static void ifnet_start_thread_fn(void *, wait_result_t);
static void ifnet_poll_thread_fn(void *, wait_result_t);
static void ifnet_poll(struct ifnet *);

static void ifp_src_route_copyout(struct ifnet *, struct route *);
static void ifp_src_route_copyin(struct ifnet *, struct route *);
#if INET6
static void ifp_src_route6_copyout(struct ifnet *, struct route_in6 *);
static void ifp_src_route6_copyin(struct ifnet *, struct route_in6 *);
#endif /* INET6 */

static int sysctl_rxpoll SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_mode_holdtime SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_sample_holdtime SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_interval_time SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_wlowat SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_whiwat SYSCTL_HANDLER_ARGS;
static int sysctl_sndq_maxlen SYSCTL_HANDLER_ARGS;
static int sysctl_rcvq_maxlen SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_mode SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_partial_rxoff_forced SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_partial_rxoff_adj SYSCTL_HANDLER_ARGS;

/* The following are protected by dlil_ifnet_lock */
static TAILQ_HEAD(, ifnet) ifnet_detaching_head;
static u_int32_t ifnet_detaching_cnt;
static void *ifnet_delayed_run;	/* wait channel for detaching thread */

decl_lck_mtx_data(static, ifnet_fc_lock);

static uint32_t ifnet_flowhash_seed;

struct ifnet_flowhash_key {
	char		ifk_name[IFNAMSIZ];
	uint32_t	ifk_unit;
	uint32_t	ifk_flags;
	uint32_t	ifk_eflags;
	uint32_t	ifk_capabilities;
	uint32_t	ifk_capenable;
	uint32_t	ifk_output_sched_model;
	uint32_t	ifk_rand1;
	uint32_t	ifk_rand2;
};

/* Flow control entry per interface */
struct ifnet_fc_entry {
	RB_ENTRY(ifnet_fc_entry) ifce_entry;
	u_int32_t	ifce_flowhash;
	struct ifnet	*ifce_ifp;
};

static uint32_t ifnet_calc_flowhash(struct ifnet *);
static int ifce_cmp(const struct ifnet_fc_entry *,
    const struct ifnet_fc_entry *);
static int ifnet_fc_add(struct ifnet *);
static struct ifnet_fc_entry *ifnet_fc_get(u_int32_t);
static void ifnet_fc_entry_free(struct ifnet_fc_entry *);

/* protected by ifnet_fc_lock */
RB_HEAD(ifnet_fc_tree, ifnet_fc_entry) ifnet_fc_tree;
RB_PROTOTYPE(ifnet_fc_tree, ifnet_fc_entry, ifce_entry, ifce_cmp);
RB_GENERATE(ifnet_fc_tree, ifnet_fc_entry, ifce_entry, ifce_cmp);

static unsigned int ifnet_fc_zone_size;		/* sizeof ifnet_fc_entry */
static struct zone *ifnet_fc_zone;		/* ifnet_fc_entry zone */

#define	IFNET_FC_ZONE_NAME	"ifnet_fc_zone"
#define	IFNET_FC_ZONE_MAX	 32

extern void bpfdetach(struct ifnet*);
extern void proto_input_run(void);

extern uint32_t udp_count_opportunistic(unsigned int ifindex, 
	u_int32_t flags);
extern uint32_t tcp_count_opportunistic(unsigned int ifindex, 
	u_int32_t flags);

__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);

#if CONFIG_MACF
int dlil_lladdr_ckreq = 0;
#endif

#if DEBUG
int dlil_verbose = 1;
#else
int dlil_verbose = 0;
#endif /* DEBUG */
#if IFNET_INPUT_SANITY_CHK
/* sanity checking of input packet lists received */
static u_int32_t dlil_input_sanity_check = 0;
#endif /* IFNET_INPUT_SANITY_CHK */
/* rate limit debug messages */
struct timespec dlil_dbgrate = { 1, 0 };

SYSCTL_DECL(_net_link_generic_system);

#if CONFIG_MACF
SYSCTL_INT(_net_link_generic_system, OID_AUTO, dlil_lladdr_ckreq,
	CTLFLAG_RW | CTLFLAG_LOCKED, &dlil_lladdr_ckreq, 0,
	"Require MACF system info check to expose link-layer address");
#endif

SYSCTL_INT(_net_link_generic_system, OID_AUTO, dlil_verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED, &dlil_verbose, 0, "Log DLIL error messages");

#define	IF_SNDQ_MINLEN	32
u_int32_t if_sndq_maxlen = IFQ_MAXLEN;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, sndq_maxlen,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_sndq_maxlen, IFQ_MAXLEN,
    sysctl_sndq_maxlen, "I", "Default transmit queue max length");

#define	IF_RCVQ_MINLEN	32
#define IF_RCVQ_MAXLEN	256
u_int32_t if_rcvq_maxlen = IF_RCVQ_MAXLEN;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rcvq_maxlen,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rcvq_maxlen, IFQ_MAXLEN,
    sysctl_rcvq_maxlen, "I", "Default receive queue max length");

#define	IF_RXPOLL_DECAY		2	/* ilog2 of EWMA decay rate (4) */
static u_int32_t if_rxpoll_decay = IF_RXPOLL_DECAY;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_decay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_decay, IF_RXPOLL_DECAY,
    "ilog2 of EWMA decay rate of avg inbound packets");

#define	IF_RXPOLL_MODE_HOLDTIME_MIN	(10ULL * 1000 * 1000)   /* 10 ms */
#define	IF_RXPOLL_MODE_HOLDTIME		(1000ULL * 1000 * 1000)	/* 1 sec */
static u_int64_t if_rxpoll_mode_holdtime = IF_RXPOLL_MODE_HOLDTIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_freeze_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_mode_holdtime,
    IF_RXPOLL_MODE_HOLDTIME, sysctl_rxpoll_mode_holdtime,
    "Q", "input poll mode freeze time");

#define	IF_RXPOLL_SAMPLETIME_MIN	(1ULL * 1000 * 1000)	/* 1 ms */
#define	IF_RXPOLL_SAMPLETIME		(10ULL * 1000 * 1000)	/* 10 ms */
static u_int64_t if_rxpoll_sample_holdtime = IF_RXPOLL_SAMPLETIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_sample_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_sample_holdtime,
    IF_RXPOLL_SAMPLETIME, sysctl_rxpoll_sample_holdtime,
    "Q", "input poll sampling time");

#define	IF_RXPOLL_INTERVALTIME_MIN	(1ULL * 1000)		/* 1 us */
#define	IF_RXPOLL_INTERVALTIME		(1ULL * 1000 * 1000)	/* 1 ms */
static u_int64_t if_rxpoll_interval_time = IF_RXPOLL_INTERVALTIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_interval_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_interval_time,
    IF_RXPOLL_INTERVALTIME, sysctl_rxpoll_interval_time,
    "Q", "input poll interval (time)");

#define	IF_RXPOLL_INTERVAL_PKTS	0	/* 0 (disabled) */
static u_int32_t if_rxpoll_interval_pkts = IF_RXPOLL_INTERVAL_PKTS;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_interval_pkts,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_interval_pkts,
    IF_RXPOLL_INTERVAL_PKTS, "input poll interval (packets)");

#define	IF_RXPOLL_WLOWAT	10
static u_int32_t if_rxpoll_wlowat = IF_RXPOLL_WLOWAT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_wakeups_lowat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_wlowat,
    IF_RXPOLL_WLOWAT, sysctl_rxpoll_wlowat,
    "I", "input poll wakeup low watermark");

#define	IF_RXPOLL_WHIWAT	100
static u_int32_t if_rxpoll_whiwat = IF_RXPOLL_WHIWAT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_wakeups_hiwat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_whiwat,
    IF_RXPOLL_WHIWAT, sysctl_rxpoll_whiwat,
    "I", "input poll wakeup high watermark");

static u_int32_t if_rxpoll_max = 0;			/* 0 (automatic) */
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_max,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_max, 0,
    "max packets per poll call");

static u_int32_t if_rxpoll = 1;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll, 0,
    sysctl_rxpoll, "I", "enable opportunistic input polling");

u_int32_t if_bw_smoothing_val = 3;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, if_bw_smoothing_val,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_bw_smoothing_val, 0, "");

u_int32_t if_bw_measure_size = 10;
SYSCTL_INT(_net_link_generic_system, OID_AUTO, if_bw_measure_size,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_bw_measure_size, 0, "");

static u_int32_t cur_dlil_input_threads = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, dlil_input_threads,
    CTLFLAG_RD | CTLFLAG_LOCKED, &cur_dlil_input_threads , 0,
    "Current number of DLIL input threads");

#if IFNET_INPUT_SANITY_CHK
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, dlil_input_sanity_check,
    CTLFLAG_RW | CTLFLAG_LOCKED, &dlil_input_sanity_check , 0,
    "Turn on sanity checking in DLIL input");
#endif /* IFNET_INPUT_SANITY_CHK */

static u_int32_t if_flowadv = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, flow_advisory,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_flowadv, 1,
    "enable flow-advisory mechanism");

static uint64_t hwcksum_in_invalidated = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_in_invalidated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_in_invalidated, "inbound packets with invalidated hardware cksum");

uint32_t hwcksum_dbg = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_dbg,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg, 0,
    "enable hardware cksum debugging");

#define	HWCKSUM_DBG_PARTIAL_FORCED	0x1	/* forced partial checksum */
#define	HWCKSUM_DBG_PARTIAL_RXOFF_ADJ	0x2	/* adjust start offset */
#define	HWCKSUM_DBG_FINALIZE_FORCED	0x10	/* forced finalize */
#define	HWCKSUM_DBG_MASK \
	(HWCKSUM_DBG_PARTIAL_FORCED | HWCKSUM_DBG_PARTIAL_RXOFF_ADJ |	\
	HWCKSUM_DBG_FINALIZE_FORCED)

static uint32_t hwcksum_dbg_mode = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, hwcksum_dbg_mode,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg_mode,
    0, sysctl_hwcksum_dbg_mode, "I", "hardware cksum debugging mode");

static uint64_t hwcksum_dbg_partial_forced = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_forced, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_forced, "packets forced using partial cksum");

static uint64_t hwcksum_dbg_partial_forced_bytes = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_forced_bytes, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_forced_bytes, "bytes forced using partial cksum");

static uint32_t hwcksum_dbg_partial_rxoff_forced = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_rxoff_forced, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_rxoff_forced, 0,
    sysctl_hwcksum_dbg_partial_rxoff_forced, "I",
    "forced partial cksum rx offset");

static uint32_t hwcksum_dbg_partial_rxoff_adj = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, hwcksum_dbg_partial_rxoff_adj,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg_partial_rxoff_adj,
    0, sysctl_hwcksum_dbg_partial_rxoff_adj, "I",
    "adjusted partial cksum rx offset");

static uint64_t hwcksum_dbg_verified = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_verified, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_verified, "packets verified for having good checksum");

static uint64_t hwcksum_dbg_bad_cksum = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_bad_cksum, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_bad_cksum, "packets with bad hardware calculated checksum");

static uint64_t hwcksum_dbg_bad_rxoff = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_bad_rxoff, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_bad_rxoff, "packets with invalid rxoff");

static uint64_t hwcksum_dbg_adjusted = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_adjusted, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_adjusted, "packets with rxoff adjusted");

static uint64_t hwcksum_dbg_finalized_hdr = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_finalized_hdr, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_finalized_hdr, "finalized headers");

static uint64_t hwcksum_dbg_finalized_data = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_finalized_data, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_finalized_data, "finalized payloads");

uint32_t hwcksum_tx = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_tx,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_tx, 0,
    "enable transmit hardware checksum offload");

uint32_t hwcksum_rx = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_rx,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_rx, 0,
    "enable receive hardware checksum offload");

unsigned int net_rxpoll = 1;
unsigned int net_affinity = 1;
static kern_return_t dlil_affinity_set(struct thread *, u_int32_t);

extern u_int32_t	inject_buckets;

static	lck_grp_attr_t	*dlil_grp_attributes = NULL;
static	lck_attr_t	*dlil_lck_attributes = NULL;


#define	DLIL_INPUT_CHECK(m, ifp) {					\
	struct ifnet *_rcvif = mbuf_pkthdr_rcvif(m);			\
	if (_rcvif == NULL || (ifp != lo_ifp && _rcvif != ifp) ||	\
	    !(mbuf_flags(m) & MBUF_PKTHDR)) {				\
		panic_plain("%s: invalid mbuf %p\n", __func__, m);	\
		/* NOTREACHED */					\
	}								\
}

#define	DLIL_EWMA(old, new, decay) do {					\
	u_int32_t _avg;							\
	if ((_avg = (old)) > 0)						\
		_avg = (((_avg << (decay)) - _avg) + (new)) >> (decay);	\
	else								\
		_avg = (new);						\
	(old) = _avg;							\
} while (0)

#define	MBPS	(1ULL * 1000 * 1000)
#define	GBPS	(MBPS * 1000)

struct rxpoll_time_tbl {
	u_int64_t	speed;		/* downlink speed */
	u_int32_t	plowat;		/* packets low watermark */
	u_int32_t	phiwat;		/* packets high watermark */
	u_int32_t	blowat;		/* bytes low watermark */
	u_int32_t	bhiwat;		/* bytes high watermark */
};

static struct rxpoll_time_tbl rxpoll_tbl[] = {
	{  10 * MBPS,	2,	8,	(1 * 1024),	(6 * 1024)	},
	{ 100 * MBPS,	10,	40,	(4 * 1024),	(64 * 1024)	},
	{   1 * GBPS,	10,	40,	(4 * 1024),	(64 * 1024)	},
	{  10 * GBPS,	10,	40,	(4 * 1024),	(64 * 1024)	},
	{ 100 * GBPS,	10,	40,	(4 * 1024),	(64 * 1024)	},
	{ 0, 0, 0, 0, 0 }
};

int
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
		case PF_VLAN:
			return (2);
		case PF_UNSPEC:
		default:
			return (3);
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

#if INET6
__private_extern__ void
if_inet6data_lock_shared(struct ifnet *ifp)
{
	lck_rw_lock_shared(&ifp->if_inet6data_lock);
}

__private_extern__ void
if_inet6data_lock_exclusive(struct ifnet *ifp)
{
	lck_rw_lock_exclusive(&ifp->if_inet6data_lock);
}

__private_extern__ void
if_inet6data_lock_done(struct ifnet *ifp)
{
	lck_rw_done(&ifp->if_inet6data_lock);
}
#endif

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

__private_extern__ int
dlil_alloc_local_stats(struct ifnet *ifp)
{
	int ret = EINVAL;
	void *buf, *base, **pbuf;

	if (ifp == NULL)
		goto end;

	if (ifp->if_tcp_stat == NULL && ifp->if_udp_stat == NULL) {
		/* allocate tcpstat_local structure */
		buf = zalloc(dlif_tcpstat_zone);
		if (buf == NULL) {
			ret = ENOMEM;
			goto end;
		}
		bzero(buf, dlif_tcpstat_bufsize);

		/* Get the 64-bit aligned base address for this object */
		base = (void *)P2ROUNDUP((intptr_t)buf + sizeof (u_int64_t),
		    sizeof (u_int64_t));
		VERIFY(((intptr_t)base + dlif_tcpstat_size) <=
		    ((intptr_t)buf + dlif_tcpstat_bufsize));

		/*
		 * Wind back a pointer size from the aligned base and
		 * save the original address so we can free it later.
		 */
		pbuf = (void **)((intptr_t)base - sizeof (void *));
		*pbuf = buf;
		ifp->if_tcp_stat = base;

		/* allocate udpstat_local structure */
		buf = zalloc(dlif_udpstat_zone);
		if (buf == NULL) {
			ret = ENOMEM;
			goto end;
		}
		bzero(buf, dlif_udpstat_bufsize);

		/* Get the 64-bit aligned base address for this object */
		base = (void *)P2ROUNDUP((intptr_t)buf + sizeof (u_int64_t),
		    sizeof (u_int64_t));
		VERIFY(((intptr_t)base + dlif_udpstat_size) <=
		    ((intptr_t)buf + dlif_udpstat_bufsize));

		/*
		 * Wind back a pointer size from the aligned base and
		 * save the original address so we can free it later.
		 */
		pbuf = (void **)((intptr_t)base - sizeof (void *));
		*pbuf = buf;
		ifp->if_udp_stat = base;

		VERIFY(IS_P2ALIGNED(ifp->if_tcp_stat, sizeof (u_int64_t)) &&
		    IS_P2ALIGNED(ifp->if_udp_stat, sizeof (u_int64_t)));

		ret = 0;
	}

end:
	if (ret != 0) {
		if (ifp->if_tcp_stat != NULL) {
			pbuf = (void **)
			    ((intptr_t)ifp->if_tcp_stat - sizeof (void *));
			zfree(dlif_tcpstat_zone, *pbuf);
			ifp->if_tcp_stat = NULL;
		}
		if (ifp->if_udp_stat != NULL) {
			pbuf = (void **)
			    ((intptr_t)ifp->if_udp_stat - sizeof (void *));
			zfree(dlif_udpstat_zone, *pbuf);
			ifp->if_udp_stat = NULL;
		}
	}

	return (ret);
}

static int
dlil_create_input_thread(ifnet_t ifp, struct dlil_threading_info *inp)
{
	thread_continue_t func;
	u_int32_t limit;
	int error;

	/* NULL ifp indicates the main input thread, called at dlil_init time */
	if (ifp == NULL) {
		func = dlil_main_input_thread_func;
		VERIFY(inp == dlil_main_input_thread);
		(void) strlcat(inp->input_name,
		    "main_input", DLIL_THREADNAME_LEN);
	} else if (net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL)) {
		func = dlil_rxpoll_input_thread_func;
		VERIFY(inp != dlil_main_input_thread);
		(void) snprintf(inp->input_name, DLIL_THREADNAME_LEN,
		    "%s_input_poll", if_name(ifp));
	} else {
		func = dlil_input_thread_func;
		VERIFY(inp != dlil_main_input_thread);
		(void) snprintf(inp->input_name, DLIL_THREADNAME_LEN,
		    "%s_input", if_name(ifp));
	}
	VERIFY(inp->input_thr == THREAD_NULL);

	inp->lck_grp = lck_grp_alloc_init(inp->input_name, dlil_grp_attributes);
	lck_mtx_init(&inp->input_lck, inp->lck_grp, dlil_lck_attributes);

	inp->mode = IFNET_MODEL_INPUT_POLL_OFF;
	inp->ifp = ifp;		/* NULL for main input thread */

	net_timerclear(&inp->mode_holdtime);
	net_timerclear(&inp->mode_lasttime);
	net_timerclear(&inp->sample_holdtime);
	net_timerclear(&inp->sample_lasttime);
	net_timerclear(&inp->dbg_lasttime);

	/*
	 * For interfaces that support opportunistic polling, set the
	 * low and high watermarks for outstanding inbound packets/bytes.
	 * Also define freeze times for transitioning between modes
	 * and updating the average.
	 */
	if (ifp != NULL && net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL)) {
		limit = MAX(if_rcvq_maxlen, IF_RCVQ_MINLEN);
		(void) dlil_rxpoll_set_params(ifp, NULL, FALSE);
	} else {
		limit = (u_int32_t)-1;
	}

	_qinit(&inp->rcvq_pkts, Q_DROPTAIL, limit);
	if (inp == dlil_main_input_thread) {
		struct dlil_main_threading_info *inpm =
		    (struct dlil_main_threading_info *)inp;
		_qinit(&inpm->lo_rcvq_pkts, Q_DROPTAIL, limit);
	}

	error = kernel_thread_start(func, inp, &inp->input_thr);
	if (error == KERN_SUCCESS) {
		ml_thread_policy(inp->input_thr, MACHINE_GROUP,
		    (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_NETISR));
		/*
		 * We create an affinity set so that the matching workloop
		 * thread or the starter thread (for loopback) can be
		 * scheduled on the same processor set as the input thread.
		 */
		if (net_affinity) {
			struct thread *tp = inp->input_thr;
			u_int32_t tag;
			/*
			 * Randomize to reduce the probability
			 * of affinity tag namespace collision.
			 */
			read_random(&tag, sizeof (tag));
			if (dlil_affinity_set(tp, tag) == KERN_SUCCESS) {
				thread_reference(tp);
				inp->tag = tag;
				inp->net_affinity = TRUE;
			}
		}
	} else if (inp == dlil_main_input_thread) {
		panic_plain("%s: couldn't create main input thread", __func__);
		/* NOTREACHED */
	} else {
		panic_plain("%s: couldn't create %s input thread", __func__,
		    if_name(ifp));
		/* NOTREACHED */
	}
	OSAddAtomic(1, &cur_dlil_input_threads);

	return (error);
}

static void
dlil_terminate_input_thread(struct dlil_threading_info *inp)
{
	struct ifnet *ifp;

	VERIFY(current_thread() == inp->input_thr);
	VERIFY(inp != dlil_main_input_thread);

	OSAddAtomic(-1, &cur_dlil_input_threads);

	lck_mtx_destroy(&inp->input_lck, inp->lck_grp);
	lck_grp_free(inp->lck_grp);

	inp->input_waiting = 0;
	inp->wtot = 0;
	bzero(inp->input_name, sizeof (inp->input_name));
	ifp = inp->ifp;
	inp->ifp = NULL;
	VERIFY(qhead(&inp->rcvq_pkts) == NULL && qempty(&inp->rcvq_pkts));
	qlimit(&inp->rcvq_pkts) = 0;
	bzero(&inp->stats, sizeof (inp->stats));

	VERIFY(!inp->net_affinity);
	inp->input_thr = THREAD_NULL;
	VERIFY(inp->wloop_thr == THREAD_NULL);
	VERIFY(inp->poll_thr == THREAD_NULL);
	VERIFY(inp->tag == 0);

	inp->mode = IFNET_MODEL_INPUT_POLL_OFF;
	bzero(&inp->tstats, sizeof (inp->tstats));
	bzero(&inp->pstats, sizeof (inp->pstats));
	bzero(&inp->sstats, sizeof (inp->sstats));

	net_timerclear(&inp->mode_holdtime);
	net_timerclear(&inp->mode_lasttime);
	net_timerclear(&inp->sample_holdtime);
	net_timerclear(&inp->sample_lasttime);
	net_timerclear(&inp->dbg_lasttime);

#if IFNET_INPUT_SANITY_CHK
	inp->input_mbuf_cnt = 0;
#endif /* IFNET_INPUT_SANITY_CHK */

	if (dlil_verbose) {
		printf("%s: input thread terminated\n",
		    if_name(ifp));
	}

	/* for the extra refcnt from kernel_thread_start() */
	thread_deallocate(current_thread());

	/* this is the end */
	thread_terminate(current_thread());
	/* NOTREACHED */
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
	IF_DATA_REQUIRE_ALIGNED_64(ifi_alignerrs);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_dt_bytes);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_fpackets);
	IF_DATA_REQUIRE_ALIGNED_64(ifi_fbytes);

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
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_alignerrs);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_dt_bytes);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_fpackets);
	IFNET_IF_DATA_REQUIRE_ALIGNED_64(ifi_fbytes);

	/*
	 * These IF_HWASSIST_ flags must be equal to their IFNET_* counterparts.
	 */
	_CASSERT(IF_HWASSIST_CSUM_IP == IFNET_CSUM_IP);
	_CASSERT(IF_HWASSIST_CSUM_TCP == IFNET_CSUM_TCP);
	_CASSERT(IF_HWASSIST_CSUM_UDP == IFNET_CSUM_UDP);
	_CASSERT(IF_HWASSIST_CSUM_IP_FRAGS == IFNET_CSUM_FRAGMENT);
	_CASSERT(IF_HWASSIST_CSUM_FRAGMENT == IFNET_IP_FRAGMENT);
	_CASSERT(IF_HWASSIST_CSUM_TCPIPV6 == IFNET_CSUM_TCPIPV6);
	_CASSERT(IF_HWASSIST_CSUM_UDPIPV6 == IFNET_CSUM_UDPIPV6);
	_CASSERT(IF_HWASSIST_CSUM_FRAGMENT_IPV6 == IFNET_IPV6_FRAGMENT);
	_CASSERT(IF_HWASSIST_CSUM_PARTIAL == IFNET_CSUM_PARTIAL);
	_CASSERT(IF_HWASSIST_VLAN_TAGGING == IFNET_VLAN_TAGGING);
	_CASSERT(IF_HWASSIST_VLAN_MTU == IFNET_VLAN_MTU);
	_CASSERT(IF_HWASSIST_TSO_V4 == IFNET_TSO_IPV4);
	_CASSERT(IF_HWASSIST_TSO_V6 == IFNET_TSO_IPV6);

	/*
	 * ... as well as the mbuf checksum flags counterparts.
	 */
	_CASSERT(CSUM_IP == IF_HWASSIST_CSUM_IP);
	_CASSERT(CSUM_TCP == IF_HWASSIST_CSUM_TCP);
	_CASSERT(CSUM_UDP == IF_HWASSIST_CSUM_UDP);
	_CASSERT(CSUM_IP_FRAGS == IF_HWASSIST_CSUM_IP_FRAGS);
	_CASSERT(CSUM_FRAGMENT == IF_HWASSIST_CSUM_FRAGMENT);
	_CASSERT(CSUM_TCPIPV6 == IF_HWASSIST_CSUM_TCPIPV6);
	_CASSERT(CSUM_UDPIPV6 == IF_HWASSIST_CSUM_UDPIPV6);
	_CASSERT(CSUM_FRAGMENT_IPV6 == IF_HWASSIST_CSUM_FRAGMENT_IPV6);
	_CASSERT(CSUM_PARTIAL == IF_HWASSIST_CSUM_PARTIAL);
	_CASSERT(CSUM_VLAN_TAG_VALID == IF_HWASSIST_VLAN_TAGGING);

	/*
	 * Make sure we have at least IF_LLREACH_MAXLEN in the llreach info.
	 */
	_CASSERT(IF_LLREACH_MAXLEN <= IF_LLREACHINFO_ADDRLEN);
	_CASSERT(IFNET_LLREACHINFO_ADDRLEN == IF_LLREACHINFO_ADDRLEN);

	_CASSERT(IFRLOGF_DLIL == IFNET_LOGF_DLIL);
	_CASSERT(IFRLOGF_FAMILY == IFNET_LOGF_FAMILY);
	_CASSERT(IFRLOGF_DRIVER == IFNET_LOGF_DRIVER);
	_CASSERT(IFRLOGF_FIRMWARE == IFNET_LOGF_FIRMWARE);

	_CASSERT(IFRLOGCAT_CONNECTIVITY == IFNET_LOGCAT_CONNECTIVITY);
	_CASSERT(IFRLOGCAT_QUALITY == IFNET_LOGCAT_QUALITY);
	_CASSERT(IFRLOGCAT_PERFORMANCE == IFNET_LOGCAT_PERFORMANCE);

	_CASSERT(IFRTYPE_FAMILY_ANY == IFNET_FAMILY_ANY);
	_CASSERT(IFRTYPE_FAMILY_LOOPBACK == IFNET_FAMILY_LOOPBACK);
	_CASSERT(IFRTYPE_FAMILY_ETHERNET == IFNET_FAMILY_ETHERNET);
	_CASSERT(IFRTYPE_FAMILY_SLIP == IFNET_FAMILY_SLIP);
	_CASSERT(IFRTYPE_FAMILY_TUN == IFNET_FAMILY_TUN);
	_CASSERT(IFRTYPE_FAMILY_VLAN == IFNET_FAMILY_VLAN);
	_CASSERT(IFRTYPE_FAMILY_PPP == IFNET_FAMILY_PPP);
	_CASSERT(IFRTYPE_FAMILY_PVC == IFNET_FAMILY_PVC);
	_CASSERT(IFRTYPE_FAMILY_DISC == IFNET_FAMILY_DISC);
	_CASSERT(IFRTYPE_FAMILY_MDECAP == IFNET_FAMILY_MDECAP);
	_CASSERT(IFRTYPE_FAMILY_GIF == IFNET_FAMILY_GIF);
	_CASSERT(IFRTYPE_FAMILY_FAITH == IFNET_FAMILY_FAITH);
	_CASSERT(IFRTYPE_FAMILY_STF == IFNET_FAMILY_STF);
	_CASSERT(IFRTYPE_FAMILY_FIREWIRE == IFNET_FAMILY_FIREWIRE);
	_CASSERT(IFRTYPE_FAMILY_BOND == IFNET_FAMILY_BOND);
	_CASSERT(IFRTYPE_FAMILY_CELLULAR == IFNET_FAMILY_CELLULAR);

	_CASSERT(IFRTYPE_SUBFAMILY_ANY == IFNET_SUBFAMILY_ANY);
	_CASSERT(IFRTYPE_SUBFAMILY_USB == IFNET_SUBFAMILY_USB);
	_CASSERT(IFRTYPE_SUBFAMILY_BLUETOOTH == IFNET_SUBFAMILY_BLUETOOTH);
	_CASSERT(IFRTYPE_SUBFAMILY_WIFI == IFNET_SUBFAMILY_WIFI);
	_CASSERT(IFRTYPE_SUBFAMILY_THUNDERBOLT == IFNET_SUBFAMILY_THUNDERBOLT);

	_CASSERT(DLIL_MODIDLEN == IFNET_MODIDLEN);
	_CASSERT(DLIL_MODARGLEN == IFNET_MODARGLEN);

	PE_parse_boot_argn("net_affinity", &net_affinity,
	    sizeof (net_affinity));

	PE_parse_boot_argn("net_rxpoll", &net_rxpoll, sizeof (net_rxpoll));

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
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_zone, Z_EXPAND, TRUE);
	zone_change(dlif_zone, Z_CALLERACCT, FALSE);

	dlif_filt_size = sizeof (struct ifnet_filter);
	dlif_filt_zone = zinit(dlif_filt_size,
	    DLIF_FILT_ZONE_MAX * dlif_filt_size, 0, DLIF_FILT_ZONE_NAME);
	if (dlif_filt_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_FILT_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_filt_zone, Z_EXPAND, TRUE);
	zone_change(dlif_filt_zone, Z_CALLERACCT, FALSE);

	dlif_phash_size = sizeof (struct proto_hash_entry) * PROTO_HASH_SLOTS;
	dlif_phash_zone = zinit(dlif_phash_size,
	    DLIF_PHASH_ZONE_MAX * dlif_phash_size, 0, DLIF_PHASH_ZONE_NAME);
	if (dlif_phash_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_PHASH_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_phash_zone, Z_EXPAND, TRUE);
	zone_change(dlif_phash_zone, Z_CALLERACCT, FALSE);

	dlif_proto_size = sizeof (struct if_proto);
	dlif_proto_zone = zinit(dlif_proto_size,
	    DLIF_PROTO_ZONE_MAX * dlif_proto_size, 0, DLIF_PROTO_ZONE_NAME);
	if (dlif_proto_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_PROTO_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_proto_zone, Z_EXPAND, TRUE);
	zone_change(dlif_proto_zone, Z_CALLERACCT, FALSE);

	dlif_tcpstat_size = sizeof (struct tcpstat_local);
	/* Enforce 64-bit alignment for tcpstat_local structure */
	dlif_tcpstat_bufsize =
	    dlif_tcpstat_size + sizeof (void *) + sizeof (u_int64_t);
	dlif_tcpstat_bufsize =
	    P2ROUNDUP(dlif_tcpstat_bufsize, sizeof (u_int64_t));
	dlif_tcpstat_zone = zinit(dlif_tcpstat_bufsize,
	    DLIF_TCPSTAT_ZONE_MAX * dlif_tcpstat_bufsize, 0,
	    DLIF_TCPSTAT_ZONE_NAME);
	if (dlif_tcpstat_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_TCPSTAT_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_tcpstat_zone, Z_EXPAND, TRUE);
	zone_change(dlif_tcpstat_zone, Z_CALLERACCT, FALSE);

	dlif_udpstat_size = sizeof (struct udpstat_local);
	/* Enforce 64-bit alignment for udpstat_local structure */
	dlif_udpstat_bufsize =
	    dlif_udpstat_size + sizeof (void *) + sizeof (u_int64_t);
	dlif_udpstat_bufsize =
	    P2ROUNDUP(dlif_udpstat_bufsize, sizeof (u_int64_t));
	dlif_udpstat_zone = zinit(dlif_udpstat_bufsize,
	    DLIF_TCPSTAT_ZONE_MAX * dlif_udpstat_bufsize, 0,
	    DLIF_UDPSTAT_ZONE_NAME);
	if (dlif_udpstat_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    DLIF_UDPSTAT_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dlif_udpstat_zone, Z_EXPAND, TRUE);
	zone_change(dlif_udpstat_zone, Z_CALLERACCT, FALSE);

	ifnet_llreach_init();

	TAILQ_INIT(&dlil_ifnet_head);
	TAILQ_INIT(&ifnet_head);
	TAILQ_INIT(&ifnet_detaching_head);

	/* Setup the lock groups we will use */
	dlil_grp_attributes = lck_grp_attr_alloc_init();

	dlil_lock_group = lck_grp_alloc_init("DLIL internal locks",
	    dlil_grp_attributes);
	ifnet_lock_group = lck_grp_alloc_init("ifnet locks",
	    dlil_grp_attributes);
	ifnet_head_lock_group = lck_grp_alloc_init("ifnet head lock",
	    dlil_grp_attributes);
	ifnet_rcv_lock_group = lck_grp_alloc_init("ifnet rcv locks",
	    dlil_grp_attributes);
	ifnet_snd_lock_group = lck_grp_alloc_init("ifnet snd locks",
	    dlil_grp_attributes);

	/* Setup the lock attributes we will use */
	dlil_lck_attributes = lck_attr_alloc_init();

	ifnet_lock_attr = lck_attr_alloc_init();

	lck_rw_init(&ifnet_head_lock, ifnet_head_lock_group,
	    dlil_lck_attributes);
	lck_mtx_init(&dlil_ifnet_lock, dlil_lock_group, dlil_lck_attributes);

	/* Setup interface flow control related items */
	lck_mtx_init(&ifnet_fc_lock, dlil_lock_group, dlil_lck_attributes);

	ifnet_fc_zone_size = sizeof (struct ifnet_fc_entry);
	ifnet_fc_zone = zinit(ifnet_fc_zone_size,
	    IFNET_FC_ZONE_MAX * ifnet_fc_zone_size, 0, IFNET_FC_ZONE_NAME);
	if (ifnet_fc_zone == NULL) {
		panic_plain("%s: failed allocating %s", __func__,
		    IFNET_FC_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(ifnet_fc_zone, Z_EXPAND, TRUE);
	zone_change(ifnet_fc_zone, Z_CALLERACCT, FALSE);

	/* Initialize interface address subsystem */
	ifa_init();

#if PF
	/* Initialize the packet filter */
	pfinit();
#endif /* PF */

	/* Initialize queue algorithms */
	classq_init();

	/* Initialize packet schedulers */
	pktsched_init();

	/* Initialize flow advisory subsystem */
	flowadv_init();

	/* Initialize the pktap virtual interface */
	pktap_init();

#if DEBUG
	/* Run self-tests */
	dlil_verify_sum16();
#endif /* DEBUG */

	/*
	 * Create and start up the main DLIL input thread and the interface
	 * detacher threads once everything is initialized.
	 */
	dlil_create_input_thread(NULL, dlil_main_input_thread);

	if (kernel_thread_start(ifnet_detacher_thread_func,
	    NULL, &thread) != KERN_SUCCESS) {
		panic_plain("%s: couldn't create detacher thread", __func__);
		/* NOTREACHED */
	}
	thread_deallocate(thread);
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
    interface_filter_t *filter_ref, u_int32_t flags)
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
	filter->filt_flags = flags;
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
	if ((filter->filt_flags & DLIL_IFF_TSO) == 0) {
		OSAddAtomic(1, &dlil_filter_disable_tso_count);
		routegenid_update();
	}
	if (dlil_verbose) {
		printf("%s: %s filter attached\n", if_name(ifp),
		    if_filter->iff_name);
	}
done:
	ifnet_head_done();
	if (retval != 0 && ifp != NULL) {
		DLIL_PRINTF("%s: failed to attach %s (err=%d)\n",
		    if_name(ifp), if_filter->iff_name, retval);
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
					printf("%s: %s filter detached\n",
					    if_name(ifp), filter->filt_name);
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
	if ((filter->filt_flags & DLIL_IFF_TSO) == 0) {
		OSAddAtomic(-1, &dlil_filter_disable_tso_count);
		routegenid_update();
	}
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

/*
 * Main input thread:
 *
 *   a) handles all inbound packets for lo0
 *   b) handles all inbound packets for interfaces with no dedicated
 *	input thread (e.g. anything but Ethernet/PDP or those that support
 *	opportunistic polling.)
 *   c) protocol registrations
 *   d) packet injections
 */
static void
dlil_main_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct dlil_main_threading_info *inpm = v;
	struct dlil_threading_info *inp = v;

	VERIFY(inp == dlil_main_input_thread);
	VERIFY(inp->ifp == NULL);
	VERIFY(inp->mode == IFNET_MODEL_INPUT_POLL_OFF);

	while (1) {
		struct mbuf *m = NULL, *m_loop = NULL;
		u_int32_t m_cnt, m_cnt_loop;
		boolean_t proto_req;

		lck_mtx_lock_spin(&inp->input_lck);

		/* Wait until there is work to be done */
		while (!(inp->input_waiting & ~DLIL_INPUT_RUNNING)) {
			inp->input_waiting &= ~DLIL_INPUT_RUNNING;
			(void) msleep(&inp->input_waiting, &inp->input_lck,
			    (PZERO - 1) | PSPIN, inp->input_name, NULL);
		}

		inp->input_waiting |= DLIL_INPUT_RUNNING;
		inp->input_waiting &= ~DLIL_INPUT_WAITING;

		/* Main input thread cannot be terminated */
		VERIFY(!(inp->input_waiting & DLIL_INPUT_TERMINATE));

		proto_req = (inp->input_waiting &
		    (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER));

		/* Packets for non-dedicated interfaces other than lo0 */
		m_cnt = qlen(&inp->rcvq_pkts);
		m = _getq_all(&inp->rcvq_pkts);

		/* Packets exclusive to lo0 */
		m_cnt_loop = qlen(&inpm->lo_rcvq_pkts);
		m_loop = _getq_all(&inpm->lo_rcvq_pkts);

		inp->wtot = 0;

		lck_mtx_unlock(&inp->input_lck);

		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation
		* safeguards if we deal with long chains of packets.
		*/
		if (m_loop != NULL)
			dlil_input_packet_list_extended(lo_ifp, m_loop,
			    m_cnt_loop, inp->mode);

		if (m != NULL)
			dlil_input_packet_list_extended(NULL, m,
			    m_cnt, inp->mode);

		if (proto_req)
			proto_input_run();
	}

	/* NOTREACHED */
	VERIFY(0);	/* we should never get here */
}

/*
 * Input thread for interfaces with legacy input model.
 */
static void
dlil_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct dlil_threading_info *inp = v;
	struct ifnet *ifp = inp->ifp;

	VERIFY(inp != dlil_main_input_thread);
	VERIFY(ifp != NULL);
	VERIFY(!(ifp->if_eflags & IFEF_RXPOLL) || !net_rxpoll);
	VERIFY(inp->mode == IFNET_MODEL_INPUT_POLL_OFF);

	while (1) {
		struct mbuf *m = NULL;
		u_int32_t m_cnt;

		lck_mtx_lock_spin(&inp->input_lck);

		/* Wait until there is work to be done */
		while (!(inp->input_waiting & ~DLIL_INPUT_RUNNING)) {
			inp->input_waiting &= ~DLIL_INPUT_RUNNING;
			(void) msleep(&inp->input_waiting, &inp->input_lck,
			    (PZERO - 1) | PSPIN, inp->input_name, NULL);
		}

		inp->input_waiting |= DLIL_INPUT_RUNNING;
		inp->input_waiting &= ~DLIL_INPUT_WAITING;

		/*
		 * Protocol registration and injection must always use
		 * the main input thread; in theory the latter can utilize
		 * the corresponding input thread where the packet arrived
		 * on, but that requires our knowing the interface in advance
		 * (and the benefits might not worth the trouble.)
		 */
		VERIFY(!(inp->input_waiting &
		    (DLIL_PROTO_WAITING|DLIL_PROTO_REGISTER)));

		/* Packets for this interface */
		m_cnt = qlen(&inp->rcvq_pkts);
		m = _getq_all(&inp->rcvq_pkts);

		if (inp->input_waiting & DLIL_INPUT_TERMINATE) {
			lck_mtx_unlock(&inp->input_lck);

			/* Free up pending packets */
			if (m != NULL)
				mbuf_freem_list(m);

			dlil_terminate_input_thread(inp);
			/* NOTREACHED */
			return;
		}

		inp->wtot = 0;

		dlil_input_stats_sync(ifp, inp);

		lck_mtx_unlock(&inp->input_lck);

		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation
		* safeguards if we deal with long chains of packets.
		*/
		if (m != NULL)
			dlil_input_packet_list_extended(NULL, m,
			    m_cnt, inp->mode);
	}

	/* NOTREACHED */
	VERIFY(0);	/* we should never get here */
}

/*
 * Input thread for interfaces with opportunistic polling input model.
 */
static void
dlil_rxpoll_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct dlil_threading_info *inp = v;
	struct ifnet *ifp = inp->ifp;
	struct timespec ts;

	VERIFY(inp != dlil_main_input_thread);
	VERIFY(ifp != NULL && (ifp->if_eflags & IFEF_RXPOLL));

	while (1) {
		struct mbuf *m = NULL;
		u_int32_t m_cnt, m_size, poll_req = 0;
		ifnet_model_t mode;
		struct timespec now, delta;
		u_int64_t ival;

		lck_mtx_lock_spin(&inp->input_lck);

		if ((ival = inp->rxpoll_ival) < IF_RXPOLL_INTERVALTIME_MIN)
			ival = IF_RXPOLL_INTERVALTIME_MIN;

		/* Link parameters changed? */
		if (ifp->if_poll_update != 0) {
			ifp->if_poll_update = 0;
			(void) dlil_rxpoll_set_params(ifp, NULL, TRUE);
		}

		/* Current operating mode */
		mode = inp->mode;

		/* Wait until there is work to be done */
		while (!(inp->input_waiting & ~DLIL_INPUT_RUNNING)) {
			inp->input_waiting &= ~DLIL_INPUT_RUNNING;
			(void) msleep(&inp->input_waiting, &inp->input_lck,
			    (PZERO - 1) | PSPIN, inp->input_name, NULL);
		}

		inp->input_waiting |= DLIL_INPUT_RUNNING;
		inp->input_waiting &= ~DLIL_INPUT_WAITING;

		/*
		 * Protocol registration and injection must always use
		 * the main input thread; in theory the latter can utilize
		 * the corresponding input thread where the packet arrived
		 * on, but that requires our knowing the interface in advance
		 * (and the benefits might not worth the trouble.)
		 */
		VERIFY(!(inp->input_waiting &
		    (DLIL_PROTO_WAITING|DLIL_PROTO_REGISTER)));

		if (inp->input_waiting & DLIL_INPUT_TERMINATE) {
			/* Free up pending packets */
			_flushq(&inp->rcvq_pkts);
			lck_mtx_unlock(&inp->input_lck);

			dlil_terminate_input_thread(inp);
			/* NOTREACHED */
			return;
		}

		/* Total count of all packets */
		m_cnt = qlen(&inp->rcvq_pkts);

		/* Total bytes of all packets */
		m_size = qsize(&inp->rcvq_pkts);

		/* Packets for this interface */
		m = _getq_all(&inp->rcvq_pkts);
		VERIFY(m != NULL || m_cnt == 0);

		nanouptime(&now);
		if (!net_timerisset(&inp->sample_lasttime))
			*(&inp->sample_lasttime) = *(&now);

		net_timersub(&now, &inp->sample_lasttime, &delta);
		if (if_rxpoll && net_timerisset(&inp->sample_holdtime)) {
			u_int32_t ptot, btot;

			/* Accumulate statistics for current sampling */
			PKTCNTR_ADD(&inp->sstats, m_cnt, m_size);

			if (net_timercmp(&delta, &inp->sample_holdtime, <))
				goto skip;

			*(&inp->sample_lasttime) = *(&now);

			/* Calculate min/max of inbound bytes */
			btot = (u_int32_t)inp->sstats.bytes;
			if (inp->rxpoll_bmin == 0 || inp->rxpoll_bmin > btot)
				inp->rxpoll_bmin = btot;
			if (btot > inp->rxpoll_bmax)
				inp->rxpoll_bmax = btot;

			/* Calculate EWMA of inbound bytes */
			DLIL_EWMA(inp->rxpoll_bavg, btot, if_rxpoll_decay);

			/* Calculate min/max of inbound packets */
			ptot = (u_int32_t)inp->sstats.packets;
			if (inp->rxpoll_pmin == 0 || inp->rxpoll_pmin > ptot)
				inp->rxpoll_pmin = ptot;
			if (ptot > inp->rxpoll_pmax)
				inp->rxpoll_pmax = ptot;

			/* Calculate EWMA of inbound packets */
			DLIL_EWMA(inp->rxpoll_pavg, ptot, if_rxpoll_decay);

			/* Reset sampling statistics */
			PKTCNTR_CLEAR(&inp->sstats);

			/* Calculate EWMA of wakeup requests */
			DLIL_EWMA(inp->rxpoll_wavg, inp->wtot, if_rxpoll_decay);
			inp->wtot = 0;

			if (dlil_verbose) {
				if (!net_timerisset(&inp->dbg_lasttime))
					*(&inp->dbg_lasttime) = *(&now);
				net_timersub(&now, &inp->dbg_lasttime, &delta);
				if (net_timercmp(&delta, &dlil_dbgrate, >=)) {
					*(&inp->dbg_lasttime) = *(&now);
					printf("%s: [%s] pkts avg %d max %d "
					    "limits [%d/%d], wreq avg %d "
					    "limits [%d/%d], bytes avg %d "
					    "limits [%d/%d]\n", if_name(ifp),
					    (inp->mode ==
					    IFNET_MODEL_INPUT_POLL_ON) ?
					    "ON" : "OFF", inp->rxpoll_pavg,
					    inp->rxpoll_pmax,
					    inp->rxpoll_plowat,
					    inp->rxpoll_phiwat,
					    inp->rxpoll_wavg,
					    inp->rxpoll_wlowat,
					    inp->rxpoll_whiwat,
					    inp->rxpoll_bavg,
					    inp->rxpoll_blowat,
					    inp->rxpoll_bhiwat);
				}
			}

			/* Perform mode transition, if necessary */
			if (!net_timerisset(&inp->mode_lasttime))
				*(&inp->mode_lasttime) = *(&now);

			net_timersub(&now, &inp->mode_lasttime, &delta);
			if (net_timercmp(&delta, &inp->mode_holdtime, <))
				goto skip;

			if (inp->rxpoll_pavg <= inp->rxpoll_plowat &&
			    inp->rxpoll_bavg <= inp->rxpoll_blowat &&
			    inp->mode != IFNET_MODEL_INPUT_POLL_OFF) {
				mode = IFNET_MODEL_INPUT_POLL_OFF;
			} else if (inp->rxpoll_pavg >= inp->rxpoll_phiwat &&
			    (inp->rxpoll_bavg >= inp->rxpoll_bhiwat ||
			    inp->rxpoll_wavg >= inp->rxpoll_whiwat) &&
			    inp->mode != IFNET_MODEL_INPUT_POLL_ON) {
				mode = IFNET_MODEL_INPUT_POLL_ON;
			}

			if (mode != inp->mode) {
				inp->mode = mode;
				*(&inp->mode_lasttime) = *(&now);
				poll_req++;
			}
		}
skip:
		dlil_input_stats_sync(ifp, inp);

		lck_mtx_unlock(&inp->input_lck);

		/*
		 * If there's a mode change and interface is still attached,
		 * perform a downcall to the driver for the new mode.  Also
		 * hold an IO refcnt on the interface to prevent it from
		 * being detached (will be release below.)
		 */
		if (poll_req != 0 && ifnet_is_attached(ifp, 1)) {
			struct ifnet_model_params p = { mode, { 0 } };
			errno_t err;

			if (dlil_verbose) {
				printf("%s: polling is now %s, "
				    "pkts avg %d max %d limits [%d/%d], "
				    "wreq avg %d limits [%d/%d], "
				    "bytes avg %d limits [%d/%d]\n",
				    if_name(ifp),
				    (mode == IFNET_MODEL_INPUT_POLL_ON) ?
				    "ON" : "OFF", inp->rxpoll_pavg,
				    inp->rxpoll_pmax, inp->rxpoll_plowat,
				    inp->rxpoll_phiwat, inp->rxpoll_wavg,
				    inp->rxpoll_wlowat, inp->rxpoll_whiwat,
				    inp->rxpoll_bavg, inp->rxpoll_blowat,
				    inp->rxpoll_bhiwat);
			}

			if ((err = ((*ifp->if_input_ctl)(ifp,
			    IFNET_CTL_SET_INPUT_MODEL, sizeof (p), &p))) != 0) {
				printf("%s: error setting polling mode "
				    "to %s (%d)\n", if_name(ifp),
				    (mode == IFNET_MODEL_INPUT_POLL_ON) ?
				    "ON" : "OFF", err);
			}

			switch (mode) {
			case IFNET_MODEL_INPUT_POLL_OFF:
				ifnet_set_poll_cycle(ifp, NULL);
				inp->rxpoll_offreq++;
				if (err != 0)
					inp->rxpoll_offerr++;
				break;

			case IFNET_MODEL_INPUT_POLL_ON:
				net_nsectimer(&ival, &ts);
				ifnet_set_poll_cycle(ifp, &ts);
				ifnet_poll(ifp);
				inp->rxpoll_onreq++;
				if (err != 0)
					inp->rxpoll_onerr++;
				break;

			default:
				VERIFY(0);
				/* NOTREACHED */
			}

			/* Release the IO refcnt */
			ifnet_decr_iorefcnt(ifp);
		}

		/*
		* NOTE warning %%% attention !!!!
		* We should think about putting some thread starvation
		* safeguards if we deal with long chains of packets.
		*/
		if (m != NULL)
			dlil_input_packet_list_extended(NULL, m, m_cnt, mode);
	}

	/* NOTREACHED */
	VERIFY(0);	/* we should never get here */
}

/*
 * Must be called on an attached ifnet (caller is expected to check.)
 * Caller may pass NULL for poll parameters to indicate "auto-tuning."
 */
errno_t
dlil_rxpoll_set_params(struct ifnet *ifp, struct ifnet_poll_params *p,
    boolean_t locked)
{
	struct dlil_threading_info *inp;
	u_int64_t sample_holdtime, inbw;

	VERIFY(ifp != NULL);
	if (!(ifp->if_eflags & IFEF_RXPOLL) || (inp = ifp->if_inp) == NULL)
		return (ENXIO);

	if (p != NULL) {
		if ((p->packets_lowat == 0 && p->packets_hiwat != 0) ||
		    (p->packets_lowat != 0 && p->packets_hiwat == 0))
			return (EINVAL);
		if (p->packets_lowat != 0 &&	/* hiwat must be non-zero */
		    p->packets_lowat >= p->packets_hiwat)
			return (EINVAL);
		if ((p->bytes_lowat == 0 && p->bytes_hiwat != 0) ||
		    (p->bytes_lowat != 0 && p->bytes_hiwat == 0))
			return (EINVAL);
		if (p->bytes_lowat != 0 &&	/* hiwat must be non-zero */
		    p->bytes_lowat >= p->bytes_hiwat)
			return (EINVAL);
		if (p->interval_time != 0 &&
		    p->interval_time < IF_RXPOLL_INTERVALTIME_MIN)
			p->interval_time = IF_RXPOLL_INTERVALTIME_MIN;
	}

	if (!locked)
		lck_mtx_lock(&inp->input_lck);

	lck_mtx_assert(&inp->input_lck, LCK_MTX_ASSERT_OWNED);

	/*
	 * Normally, we'd reset the parameters to the auto-tuned values
	 * if the the input thread detects a change in link rate.  If the
	 * driver provides its own parameters right after a link rate
	 * changes, but before the input thread gets to run, we want to
	 * make sure to keep the driver's values.  Clearing if_poll_update
	 * will achieve that.
	 */
	if (p != NULL && !locked && ifp->if_poll_update != 0)
		ifp->if_poll_update = 0;

	if ((inbw = ifnet_input_linkrate(ifp)) == 0 && p == NULL) {
		sample_holdtime = 0;	/* polling is disabled */
		inp->rxpoll_wlowat = inp->rxpoll_plowat =
		    inp->rxpoll_blowat = 0;
		inp->rxpoll_whiwat = inp->rxpoll_phiwat =
		    inp->rxpoll_bhiwat = (u_int32_t)-1;
		inp->rxpoll_plim = 0;
		inp->rxpoll_ival = IF_RXPOLL_INTERVALTIME_MIN;
	} else {
		u_int32_t plowat, phiwat, blowat, bhiwat, plim;
		u_int64_t ival;
		unsigned int n, i;

		for (n = 0, i = 0; rxpoll_tbl[i].speed != 0; i++) {
			if (inbw < rxpoll_tbl[i].speed)
				break;
			n = i;
		}
		/* auto-tune if caller didn't specify a value */
		plowat = ((p == NULL || p->packets_lowat == 0) ?
		    rxpoll_tbl[n].plowat : p->packets_lowat);
		phiwat = ((p == NULL || p->packets_hiwat == 0) ?
		    rxpoll_tbl[n].phiwat : p->packets_hiwat);
		blowat = ((p == NULL || p->bytes_lowat == 0) ?
		    rxpoll_tbl[n].blowat : p->bytes_lowat);
		bhiwat = ((p == NULL || p->bytes_hiwat == 0) ?
		    rxpoll_tbl[n].bhiwat : p->bytes_hiwat);
		plim = ((p == NULL || p->packets_limit == 0) ?
		    if_rxpoll_max : p->packets_limit);
		ival = ((p == NULL || p->interval_time == 0) ?
		    if_rxpoll_interval_time : p->interval_time);

		VERIFY(plowat != 0 && phiwat != 0);
		VERIFY(blowat != 0 && bhiwat != 0);
		VERIFY(ival >= IF_RXPOLL_INTERVALTIME_MIN);

		sample_holdtime = if_rxpoll_sample_holdtime;
		inp->rxpoll_wlowat = if_rxpoll_wlowat;
		inp->rxpoll_whiwat = if_rxpoll_whiwat;
		inp->rxpoll_plowat = plowat;
		inp->rxpoll_phiwat = phiwat;
		inp->rxpoll_blowat = blowat;
		inp->rxpoll_bhiwat = bhiwat;
		inp->rxpoll_plim = plim;
		inp->rxpoll_ival = ival;
	}

	net_nsectimer(&if_rxpoll_mode_holdtime, &inp->mode_holdtime);
	net_nsectimer(&sample_holdtime, &inp->sample_holdtime);

	if (dlil_verbose) {
		printf("%s: speed %llu bps, sample per %llu nsec, "
		    "poll interval %llu nsec, pkts per poll %u, "
		    "pkt limits [%u/%u], wreq limits [%u/%u], "
		    "bytes limits [%u/%u]\n", if_name(ifp),
		    inbw, sample_holdtime, inp->rxpoll_ival, inp->rxpoll_plim,
		    inp->rxpoll_plowat, inp->rxpoll_phiwat, inp->rxpoll_wlowat,
		    inp->rxpoll_whiwat, inp->rxpoll_blowat, inp->rxpoll_bhiwat);
	}

	if (!locked)
		lck_mtx_unlock(&inp->input_lck);

	return (0);
}

/*
 * Must be called on an attached ifnet (caller is expected to check.)
 */
errno_t
dlil_rxpoll_get_params(struct ifnet *ifp, struct ifnet_poll_params *p)
{
	struct dlil_threading_info *inp;

	VERIFY(ifp != NULL && p != NULL);
	if (!(ifp->if_eflags & IFEF_RXPOLL) || (inp = ifp->if_inp) == NULL)
		return (ENXIO);

	bzero(p, sizeof (*p));

	lck_mtx_lock(&inp->input_lck);
	p->packets_limit = inp->rxpoll_plim;
	p->packets_lowat = inp->rxpoll_plowat;
	p->packets_hiwat = inp->rxpoll_phiwat;
	p->bytes_lowat = inp->rxpoll_blowat;
	p->bytes_hiwat = inp->rxpoll_bhiwat;
	p->interval_time = inp->rxpoll_ival;
	lck_mtx_unlock(&inp->input_lck);

	return (0);
}

errno_t
ifnet_input(struct ifnet *ifp, struct mbuf *m_head,
    const struct ifnet_stat_increment_param *s)
{
	return (ifnet_input_common(ifp, m_head, NULL, s, FALSE, FALSE));
}

errno_t
ifnet_input_extended(struct ifnet *ifp, struct mbuf *m_head,
    struct mbuf *m_tail, const struct ifnet_stat_increment_param *s)
{
	return (ifnet_input_common(ifp, m_head, m_tail, s, TRUE, FALSE));
}

static errno_t
ifnet_input_common(struct ifnet *ifp, struct mbuf *m_head, struct mbuf *m_tail,
    const struct ifnet_stat_increment_param *s, boolean_t ext, boolean_t poll)
{
	struct thread *tp = current_thread();
	struct mbuf *last;
	struct dlil_threading_info *inp;
	u_int32_t m_cnt = 0, m_size = 0;

	if ((m_head == NULL && !poll) || (s == NULL && ext)) {
		if (m_head != NULL)
			mbuf_freem_list(m_head);
		return (EINVAL);
	}

	VERIFY(m_head != NULL || (s == NULL && m_tail == NULL && !ext && poll));
	VERIFY(m_tail == NULL || ext);
	VERIFY(s != NULL || !ext);

	/*
	 * Drop the packet(s) if the parameters are invalid, or if the
	 * interface is no longer attached; else hold an IO refcnt to
	 * prevent it from being detached (will be released below.)
	 */
	if (ifp == NULL || (ifp != lo_ifp && !ifnet_is_attached(ifp, 1))) {
		if (m_head != NULL)
			mbuf_freem_list(m_head);
		return (EINVAL);
	}

	if (m_tail == NULL) {
		last = m_head;
		while (m_head != NULL) {
#if IFNET_INPUT_SANITY_CHK
			if (dlil_input_sanity_check != 0)
				DLIL_INPUT_CHECK(last, ifp);
#endif /* IFNET_INPUT_SANITY_CHK */
			m_cnt++;
			m_size += m_length(last);
			if (mbuf_nextpkt(last) == NULL)
				break;
			last = mbuf_nextpkt(last);
		}
		m_tail = last;
	} else {
#if IFNET_INPUT_SANITY_CHK
		if (dlil_input_sanity_check != 0) {
			last = m_head;
			while (1) {
				DLIL_INPUT_CHECK(last, ifp);
				m_cnt++;
				m_size += m_length(last);
				if (mbuf_nextpkt(last) == NULL)
					break;
				last = mbuf_nextpkt(last);
			}
		} else {
			m_cnt = s->packets_in;
			m_size = s->bytes_in;
			last = m_tail;
		}
#else
		m_cnt = s->packets_in;
		m_size = s->bytes_in;
		last = m_tail;
#endif /* IFNET_INPUT_SANITY_CHK */
	}

	if (last != m_tail) {
		panic_plain("%s: invalid input packet chain for %s, "
		    "tail mbuf %p instead of %p\n", __func__, if_name(ifp),
		    m_tail, last);
	}

	/*
	 * Assert packet count only for the extended variant, for backwards
	 * compatibility, since this came directly from the device driver.
	 * Relax this assertion for input bytes, as the driver may have
	 * included the link-layer headers in the computation; hence
	 * m_size is just an approximation.
	 */
	if (ext && s->packets_in != m_cnt) {
		panic_plain("%s: input packet count mismatch for %s, "
		    "%d instead of %d\n", __func__, if_name(ifp),
		    s->packets_in, m_cnt);
	}

	if ((inp = ifp->if_inp) == NULL)
		inp = dlil_main_input_thread;

	/*
	 * If there is a matching DLIL input thread associated with an
	 * affinity set, associate this thread with the same set.  We
	 * will only do this once.
	 */
	lck_mtx_lock_spin(&inp->input_lck);
	if (inp != dlil_main_input_thread && inp->net_affinity &&
	    ((!poll && inp->wloop_thr == THREAD_NULL) ||
	    (poll && inp->poll_thr == THREAD_NULL))) {
		u_int32_t tag = inp->tag;

		if (poll) {
			VERIFY(inp->poll_thr == THREAD_NULL);
			inp->poll_thr = tp;
		} else {
			VERIFY(inp->wloop_thr == THREAD_NULL);
			inp->wloop_thr = tp;
		}
		lck_mtx_unlock(&inp->input_lck);

		/* Associate the current thread with the new affinity tag */
		(void) dlil_affinity_set(tp, tag);

		/*
		 * Take a reference on the current thread; during detach,
		 * we will need to refer to it in order ot tear down its
		 * affinity.
		 */
		thread_reference(tp);
		lck_mtx_lock_spin(&inp->input_lck);
	}

	VERIFY(m_head != NULL || (m_tail == NULL && m_cnt == 0));

        /*
	 * Because of loopbacked multicast we cannot stuff the ifp in
	 * the rcvif of the packet header: loopback (lo0) packets use a
	 * dedicated list so that we can later associate them with lo_ifp
	 * on their way up the stack.  Packets for other interfaces without
	 * dedicated input threads go to the regular list.
	 */
	if (m_head != NULL) {
		if (inp == dlil_main_input_thread && ifp == lo_ifp) {
			struct dlil_main_threading_info *inpm =
			    (struct dlil_main_threading_info *)inp;
			_addq_multi(&inpm->lo_rcvq_pkts, m_head, m_tail,
			    m_cnt, m_size);
		} else {
			_addq_multi(&inp->rcvq_pkts, m_head, m_tail,
			    m_cnt, m_size);
		}
	}

#if IFNET_INPUT_SANITY_CHK
	if (dlil_input_sanity_check != 0) {
		u_int32_t count;
		struct mbuf *m0;

		for (m0 = m_head, count = 0; m0; m0 = mbuf_nextpkt(m0))
			count++;

		if (count != m_cnt) {
			panic_plain("%s: invalid packet count %d "
			    "(expected %d)\n", if_name(ifp),
			    count, m_cnt);
			/* NOTREACHED */
		}

		inp->input_mbuf_cnt += m_cnt;
	}
#endif /* IFNET_INPUT_SANITY_CHK */

	if (s != NULL) {
		dlil_input_stats_add(s, inp, poll);
		/*
		 * If we're using the main input thread, synchronize the
		 * stats now since we have the interface context.  All
		 * other cases involving dedicated input threads will
		 * have their stats synchronized there.
		 */
		if (inp == dlil_main_input_thread)
			dlil_input_stats_sync(ifp, inp);
	}

	inp->input_waiting |= DLIL_INPUT_WAITING;
	if (!(inp->input_waiting & DLIL_INPUT_RUNNING)) {
		inp->wtot++;
		wakeup_one((caddr_t)&inp->input_waiting);
	}
	lck_mtx_unlock(&inp->input_lck);

	if (ifp != lo_ifp) {
		/* Release the IO refcnt */
		ifnet_decr_iorefcnt(ifp);
	}

	return (0);
}

static void
ifnet_start_common(struct ifnet *ifp, int resetfc)
{
	if (!(ifp->if_eflags & IFEF_TXSTART))
		return;
	/*
	 * If the starter thread is inactive, signal it to do work,
	 * unless the interface is being flow controlled from below,
	 * e.g. a virtual interface being flow controlled by a real
	 * network interface beneath it.
	 */
	lck_mtx_lock_spin(&ifp->if_start_lock);
	if (resetfc) {
		ifp->if_start_flags &= ~IFSF_FLOW_CONTROLLED;
	} else if (ifp->if_start_flags & IFSF_FLOW_CONTROLLED) {
		lck_mtx_unlock(&ifp->if_start_lock);
		return;
	}
	ifp->if_start_req++;
	if (!ifp->if_start_active && ifp->if_start_thread != THREAD_NULL) {
		wakeup_one((caddr_t)&ifp->if_start_thread);
	}
	lck_mtx_unlock(&ifp->if_start_lock);
}

void
ifnet_start(struct ifnet *ifp)
{
	ifnet_start_common(ifp, 0);
}

static void
ifnet_start_thread_fn(void *v, wait_result_t w)
{
#pragma unused(w)
	struct ifnet *ifp = v;
	char ifname[IFNAMSIZ + 1];
	struct timespec *ts = NULL;
	struct ifclassq *ifq = &ifp->if_snd;

	/*
	 * Treat the dedicated starter thread for lo0 as equivalent to
	 * the driver workloop thread; if net_affinity is enabled for
	 * the main input thread, associate this starter thread to it
	 * by binding them with the same affinity tag.  This is done
	 * only once (as we only have one lo_ifp which never goes away.)
	 */
	if (ifp == lo_ifp) {
		struct dlil_threading_info *inp = dlil_main_input_thread;
		struct thread *tp = current_thread();

		lck_mtx_lock(&inp->input_lck);
		if (inp->net_affinity) {
			u_int32_t tag = inp->tag;

			VERIFY(inp->wloop_thr == THREAD_NULL);
			VERIFY(inp->poll_thr == THREAD_NULL);
			inp->wloop_thr = tp;
			lck_mtx_unlock(&inp->input_lck);

			/* Associate this thread with the affinity tag */
			(void) dlil_affinity_set(tp, tag);
		} else {
			lck_mtx_unlock(&inp->input_lck);
		}
	}

	snprintf(ifname, sizeof (ifname), "%s_starter",
	    if_name(ifp));

	lck_mtx_lock_spin(&ifp->if_start_lock);

	for (;;) {
		(void) msleep(&ifp->if_start_thread, &ifp->if_start_lock,
		    (PZERO - 1) | PSPIN, ifname, ts);

		/* interface is detached? */
		if (ifp->if_start_thread == THREAD_NULL) {
			ifnet_set_start_cycle(ifp, NULL);
			lck_mtx_unlock(&ifp->if_start_lock);
			ifnet_purge(ifp);

			if (dlil_verbose) {
				printf("%s: starter thread terminated\n",
				    if_name(ifp));
			}

			/* for the extra refcnt from kernel_thread_start() */
			thread_deallocate(current_thread());
			/* this is the end */
			thread_terminate(current_thread());
			/* NOTREACHED */
			return;
		}

		ifp->if_start_active = 1;
		for (;;) {
			u_int32_t req = ifp->if_start_req;

			lck_mtx_unlock(&ifp->if_start_lock);
			/* invoke the driver's start routine */
			((*ifp->if_start)(ifp));
			lck_mtx_lock_spin(&ifp->if_start_lock);

			/* if there's no pending request, we're done */
			if (req == ifp->if_start_req)
				break;
		}
		ifp->if_start_req = 0;
		ifp->if_start_active = 0;
		/*
		 * Wakeup N ns from now if rate-controlled by TBR, and if
		 * there are still packets in the send queue which haven't
		 * been dequeued so far; else sleep indefinitely (ts = NULL)
		 * until ifnet_start() is called again.
		 */
		ts = ((IFCQ_TBR_IS_ENABLED(ifq) && !IFCQ_IS_EMPTY(ifq)) ?
		    &ifp->if_start_cycle : NULL);

		if (ts != NULL && ts->tv_sec == 0 && ts->tv_nsec == 0)
			ts = NULL;
	}

	/* NOTREACHED */
	lck_mtx_unlock(&ifp->if_start_lock);
	VERIFY(0);	/* we should never get here */
}

void
ifnet_set_start_cycle(struct ifnet *ifp, struct timespec *ts)
{
	if (ts == NULL)
		bzero(&ifp->if_start_cycle, sizeof (ifp->if_start_cycle));
	else
		*(&ifp->if_start_cycle) = *ts;

	if (ts != NULL && ts->tv_nsec != 0 && dlil_verbose)
		printf("%s: restart interval set to %lu nsec\n",
		    if_name(ifp), ts->tv_nsec);
}

static void
ifnet_poll(struct ifnet *ifp)
{
	/*
	 * If the poller thread is inactive, signal it to do work.
	 */
	lck_mtx_lock_spin(&ifp->if_poll_lock);
	ifp->if_poll_req++;
	if (!ifp->if_poll_active && ifp->if_poll_thread != THREAD_NULL) {
		wakeup_one((caddr_t)&ifp->if_poll_thread);
	}
	lck_mtx_unlock(&ifp->if_poll_lock);
}

static void
ifnet_poll_thread_fn(void *v, wait_result_t w)
{
#pragma unused(w)
	struct dlil_threading_info *inp;
	struct ifnet *ifp = v;
	char ifname[IFNAMSIZ + 1];
	struct timespec *ts = NULL;
	struct ifnet_stat_increment_param s;

	snprintf(ifname, sizeof (ifname), "%s_poller",
	    if_name(ifp));
	bzero(&s, sizeof (s));

	lck_mtx_lock_spin(&ifp->if_poll_lock);

	inp = ifp->if_inp;
	VERIFY(inp != NULL);

	for (;;) {
		if (ifp->if_poll_thread != THREAD_NULL) {
			(void) msleep(&ifp->if_poll_thread, &ifp->if_poll_lock,
			    (PZERO - 1) | PSPIN, ifname, ts);
		}

		/* interface is detached (maybe while asleep)? */
		if (ifp->if_poll_thread == THREAD_NULL) {
			ifnet_set_poll_cycle(ifp, NULL);
			lck_mtx_unlock(&ifp->if_poll_lock);

			if (dlil_verbose) {
				printf("%s: poller thread terminated\n",
				    if_name(ifp));
			}

			/* for the extra refcnt from kernel_thread_start() */
			thread_deallocate(current_thread());
			/* this is the end */
			thread_terminate(current_thread());
			/* NOTREACHED */
			return;
		}

		ifp->if_poll_active = 1;
		for (;;) {
			struct mbuf *m_head, *m_tail;
			u_int32_t m_lim, m_cnt, m_totlen;
			u_int16_t req = ifp->if_poll_req;

			lck_mtx_unlock(&ifp->if_poll_lock);

			/*
			 * If no longer attached, there's nothing to do;
			 * else hold an IO refcnt to prevent the interface
			 * from being detached (will be released below.)
			 */
			if (!ifnet_is_attached(ifp, 1)) {
				lck_mtx_lock_spin(&ifp->if_poll_lock);
				break;
			}

			m_lim = (inp->rxpoll_plim != 0) ? inp->rxpoll_plim :
			    MAX((qlimit(&inp->rcvq_pkts)),
			    (inp->rxpoll_phiwat << 2));

			if (dlil_verbose > 1) {
				printf("%s: polling up to %d pkts, "
				    "pkts avg %d max %d, wreq avg %d, "
				    "bytes avg %d\n",
				    if_name(ifp), m_lim,
				    inp->rxpoll_pavg, inp->rxpoll_pmax,
				    inp->rxpoll_wavg, inp->rxpoll_bavg);
			}

			/* invoke the driver's input poll routine */
			((*ifp->if_input_poll)(ifp, 0, m_lim, &m_head, &m_tail,
			    &m_cnt, &m_totlen));

			if (m_head != NULL) {
				VERIFY(m_tail != NULL && m_cnt > 0);

				if (dlil_verbose > 1) {
					printf("%s: polled %d pkts, "
					    "pkts avg %d max %d, wreq avg %d, "
					    "bytes avg %d\n",
					    if_name(ifp), m_cnt,
					    inp->rxpoll_pavg, inp->rxpoll_pmax,
					    inp->rxpoll_wavg, inp->rxpoll_bavg);
				}

				/* stats are required for extended variant */
				s.packets_in = m_cnt;
				s.bytes_in = m_totlen;

				(void) ifnet_input_common(ifp, m_head, m_tail,
				    &s, TRUE, TRUE);
			} else {
				if (dlil_verbose > 1) {
					printf("%s: no packets, "
					    "pkts avg %d max %d, wreq avg %d, "
					    "bytes avg %d\n",
					    if_name(ifp), inp->rxpoll_pavg,
					    inp->rxpoll_pmax, inp->rxpoll_wavg,
					    inp->rxpoll_bavg);
				}

				(void) ifnet_input_common(ifp, NULL, NULL,
				    NULL, FALSE, TRUE);
			}

			/* Release the io ref count */
			ifnet_decr_iorefcnt(ifp);

			lck_mtx_lock_spin(&ifp->if_poll_lock);

			/* if there's no pending request, we're done */
			if (req == ifp->if_poll_req)
				break;
		}
		ifp->if_poll_req = 0;
		ifp->if_poll_active = 0;

		/*
		 * Wakeup N ns from now, else sleep indefinitely (ts = NULL)
		 * until ifnet_poll() is called again.
		 */
		ts = &ifp->if_poll_cycle;
		if (ts->tv_sec == 0 && ts->tv_nsec == 0)
			ts = NULL;
	}

	/* NOTREACHED */
	lck_mtx_unlock(&ifp->if_poll_lock);
	VERIFY(0);	/* we should never get here */
}

void
ifnet_set_poll_cycle(struct ifnet *ifp, struct timespec *ts)
{
	if (ts == NULL)
		bzero(&ifp->if_poll_cycle, sizeof (ifp->if_poll_cycle));
	else
		*(&ifp->if_poll_cycle) = *ts;

	if (ts != NULL && ts->tv_nsec != 0 && dlil_verbose)
		printf("%s: poll interval set to %lu nsec\n",
		    if_name(ifp), ts->tv_nsec);
}

void
ifnet_purge(struct ifnet *ifp)
{
	if (ifp != NULL && (ifp->if_eflags & IFEF_TXSTART))
		if_qflush(ifp, 0);
}

void
ifnet_update_sndq(struct ifclassq *ifq, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!(IFCQ_IS_READY(ifq)))
		return;

	if (IFCQ_TBR_IS_ENABLED(ifq)) {
		struct tb_profile tb = { ifq->ifcq_tbr.tbr_rate_raw,
		    ifq->ifcq_tbr.tbr_percent, 0 };
		(void) ifclassq_tbr_set(ifq, &tb, FALSE);
	}

	ifclassq_update(ifq, ev);
}

void
ifnet_update_rcv(struct ifnet *ifp, cqev_t ev)
{
	switch (ev) {
	case CLASSQ_EV_LINK_BANDWIDTH:
		if (net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL))
			ifp->if_poll_update++;
		break;

	default:
		break;
	}
}

errno_t
ifnet_set_output_sched_model(struct ifnet *ifp, u_int32_t model)
{
	struct ifclassq *ifq;
	u_int32_t omodel;
	errno_t err;

	if (ifp == NULL || (model != IFNET_SCHED_MODEL_DRIVER_MANAGED &&
	    model != IFNET_SCHED_MODEL_NORMAL))
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART))
		return (ENXIO);

	ifq = &ifp->if_snd;
	IFCQ_LOCK(ifq);
	omodel = ifp->if_output_sched_model;
	ifp->if_output_sched_model = model;
	if ((err = ifclassq_pktsched_setup(ifq)) != 0)
		ifp->if_output_sched_model = omodel;
	IFCQ_UNLOCK(ifq);

	return (err);
}

errno_t
ifnet_set_sndq_maxlen(struct ifnet *ifp, u_int32_t maxqlen)
{
	if (ifp == NULL)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART))
		return (ENXIO);

	ifclassq_set_maxlen(&ifp->if_snd, maxqlen);

	return (0);
}

errno_t
ifnet_get_sndq_maxlen(struct ifnet *ifp, u_int32_t *maxqlen)
{
	if (ifp == NULL || maxqlen == NULL)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART))
		return (ENXIO);

	*maxqlen = ifclassq_get_maxlen(&ifp->if_snd);

	return (0);
}

errno_t
ifnet_get_sndq_len(struct ifnet *ifp, u_int32_t *pkts)
{
	errno_t err;

	if (ifp == NULL || pkts == NULL)
		err = EINVAL;
	else if (!(ifp->if_eflags & IFEF_TXSTART))
		err = ENXIO;
	else
		err = ifclassq_get_len(&ifp->if_snd, MBUF_SC_UNSPEC,
		    pkts, NULL);

	return (err);
}

errno_t
ifnet_get_service_class_sndq_len(struct ifnet *ifp, mbuf_svc_class_t sc,
    u_int32_t *pkts, u_int32_t *bytes)
{
	errno_t err;

	if (ifp == NULL || !MBUF_VALID_SC(sc) ||
	    (pkts == NULL && bytes == NULL))
		err = EINVAL;
	else if (!(ifp->if_eflags & IFEF_TXSTART))
		err = ENXIO;
	else
		err = ifclassq_get_len(&ifp->if_snd, sc, pkts, bytes);

	return (err);
}

errno_t
ifnet_set_rcvq_maxlen(struct ifnet *ifp, u_int32_t maxqlen)
{
	struct dlil_threading_info *inp;

	if (ifp == NULL)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_RXPOLL) || ifp->if_inp == NULL)
		return (ENXIO);

	if (maxqlen == 0)
		maxqlen = if_rcvq_maxlen;
	else if (maxqlen < IF_RCVQ_MINLEN)
		maxqlen = IF_RCVQ_MINLEN;

	inp = ifp->if_inp;
	lck_mtx_lock(&inp->input_lck);
	qlimit(&inp->rcvq_pkts) = maxqlen;
	lck_mtx_unlock(&inp->input_lck);

	return (0);
}

errno_t
ifnet_get_rcvq_maxlen(struct ifnet *ifp, u_int32_t *maxqlen)
{
	struct dlil_threading_info *inp;

	if (ifp == NULL || maxqlen == NULL)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_RXPOLL) || ifp->if_inp == NULL)
		return (ENXIO);

	inp = ifp->if_inp;
	lck_mtx_lock(&inp->input_lck);
	*maxqlen = qlimit(&inp->rcvq_pkts);
	lck_mtx_unlock(&inp->input_lck);
	return (0);
}

errno_t
ifnet_enqueue(struct ifnet *ifp, struct mbuf *m)
{
	int error;

	if (ifp == NULL || m == NULL || !(m->m_flags & M_PKTHDR) ||
	    m->m_nextpkt != NULL) {
		if (m != NULL)
			m_freem_list(m);
		return (EINVAL);
	} else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    !(ifp->if_refflags & IFRF_ATTACHED)) {
		/* flag tested without lock for performance */
		m_freem(m);
		return (ENXIO);
	} else if (!(ifp->if_flags & IFF_UP)) {
		m_freem(m);
		return (ENETDOWN);
	}

	/* enqueue the packet */
	error = ifclassq_enqueue(&ifp->if_snd, m);

	/*
	 * Tell the driver to start dequeueing; do this even when the queue
	 * for the packet is suspended (EQSUSPENDED), as the driver could still
	 * be dequeueing from other unsuspended queues.
	 */
	if (error == 0 || error == EQFULL || error == EQSUSPENDED)
		ifnet_start(ifp);

	return (error);
}

errno_t
ifnet_dequeue(struct ifnet *ifp, struct mbuf **mp)
{
	if (ifp == NULL || mp == NULL)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    (ifp->if_output_sched_model != IFNET_SCHED_MODEL_NORMAL))
		return (ENXIO);

	return (ifclassq_dequeue(&ifp->if_snd, 1, mp, NULL, NULL, NULL));
}

errno_t
ifnet_dequeue_service_class(struct ifnet *ifp, mbuf_svc_class_t sc,
    struct mbuf **mp)
{
	if (ifp == NULL || mp == NULL || !MBUF_VALID_SC(sc))
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    (ifp->if_output_sched_model != IFNET_SCHED_MODEL_DRIVER_MANAGED))
		return (ENXIO);

	return (ifclassq_dequeue_sc(&ifp->if_snd, sc, 1, mp, NULL, NULL, NULL));
}

errno_t
ifnet_dequeue_multi(struct ifnet *ifp, u_int32_t limit, struct mbuf **head,
    struct mbuf **tail, u_int32_t *cnt, u_int32_t *len)
{
	if (ifp == NULL || head == NULL || limit < 1)
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    (ifp->if_output_sched_model != IFNET_SCHED_MODEL_NORMAL))
		return (ENXIO);

	return (ifclassq_dequeue(&ifp->if_snd, limit, head, tail, cnt, len));
}

errno_t
ifnet_dequeue_service_class_multi(struct ifnet *ifp, mbuf_svc_class_t sc,
    u_int32_t limit, struct mbuf **head, struct mbuf **tail, u_int32_t *cnt,
    u_int32_t *len)
{

	if (ifp == NULL || head == NULL || limit < 1 || !MBUF_VALID_SC(sc))
		return (EINVAL);
	else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    (ifp->if_output_sched_model != IFNET_SCHED_MODEL_DRIVER_MANAGED))
		return (ENXIO);

	return (ifclassq_dequeue_sc(&ifp->if_snd, sc, limit, head,
	    tail, cnt, len));
}

errno_t
ifnet_framer_stub(struct ifnet *ifp, struct mbuf **m,
    const struct sockaddr *dest, const char *dest_linkaddr,
    const char *frame_type, u_int32_t *pre, u_int32_t *post)
{
	if (pre != NULL)
		*pre = 0;
	if (post != NULL)
		*post = 0;

	return (ifp->if_framer_legacy(ifp, m, dest, dest_linkaddr, frame_type));
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
			frame_header = m->m_pkthdr.pkt_hdr;
			m->m_pkthdr.pkt_hdr = NULL;
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

static void
dlil_input_stats_add(const struct ifnet_stat_increment_param *s,
    struct dlil_threading_info *inp, boolean_t poll)
{
	struct ifnet_stat_increment_param *d = &inp->stats;

	if (s->packets_in != 0)
		d->packets_in += s->packets_in;
	if (s->bytes_in != 0)
		d->bytes_in += s->bytes_in;
	if (s->errors_in != 0)
		d->errors_in += s->errors_in;

	if (s->packets_out != 0)
		d->packets_out += s->packets_out;
	if (s->bytes_out != 0)
		d->bytes_out += s->bytes_out;
	if (s->errors_out != 0)
		d->errors_out += s->errors_out;

	if (s->collisions != 0)
		d->collisions += s->collisions;
	if (s->dropped != 0)
		d->dropped += s->dropped;

	if (poll)
		PKTCNTR_ADD(&inp->tstats, s->packets_in, s->bytes_in);
}

static void
dlil_input_stats_sync(struct ifnet *ifp, struct dlil_threading_info *inp)
{
	struct ifnet_stat_increment_param *s = &inp->stats;

	/*
	 * Use of atomic operations is unavoidable here because
	 * these stats may also be incremented elsewhere via KPIs.
	 */
	if (s->packets_in != 0) {
		atomic_add_64(&ifp->if_data.ifi_ipackets, s->packets_in);
		s->packets_in = 0;
	}
	if (s->bytes_in != 0) {
		atomic_add_64(&ifp->if_data.ifi_ibytes, s->bytes_in);
		s->bytes_in = 0;
	}
	if (s->errors_in != 0) {
		atomic_add_64(&ifp->if_data.ifi_ierrors, s->errors_in);
		s->errors_in = 0;
	}

	if (s->packets_out != 0) {
		atomic_add_64(&ifp->if_data.ifi_opackets, s->packets_out);
		s->packets_out = 0;
	}
	if (s->bytes_out != 0) {
		atomic_add_64(&ifp->if_data.ifi_obytes, s->bytes_out);
		s->bytes_out = 0;
	}
	if (s->errors_out != 0) {
		atomic_add_64(&ifp->if_data.ifi_oerrors, s->errors_out);
		s->errors_out = 0;
	}

	if (s->collisions != 0) {
		atomic_add_64(&ifp->if_data.ifi_collisions, s->collisions);
		s->collisions = 0;
	}
	if (s->dropped != 0) {
		atomic_add_64(&ifp->if_data.ifi_iqdrops, s->dropped);
		s->dropped = 0;
	}
	/*
	 * If we went over the threshold, notify NetworkStatistics.
	 */
	if (ifp->if_data_threshold &&
	    (ifp->if_ibytes + ifp->if_obytes) - ifp->if_dt_bytes >
	    ifp->if_data_threshold) {
		ifp->if_dt_bytes = ifp->if_ibytes + ifp->if_obytes;
		nstat_ifnet_threshold_reached(ifp->if_index);
	}
	/*
	 * No need for atomic operations as they are modified here
	 * only from within the DLIL input thread context.
	 */
	if (inp->tstats.packets != 0) {
		inp->pstats.ifi_poll_packets += inp->tstats.packets;
		inp->tstats.packets = 0;
	}
	if (inp->tstats.bytes != 0) {
		inp->pstats.ifi_poll_bytes += inp->tstats.bytes;
		inp->tstats.bytes = 0;
	}
}

__private_extern__ void
dlil_input_packet_list(struct ifnet *ifp, struct mbuf *m)
{
	return (dlil_input_packet_list_common(ifp, m, 0,
	    IFNET_MODEL_INPUT_POLL_OFF, FALSE));
}

__private_extern__ void
dlil_input_packet_list_extended(struct ifnet *ifp, struct mbuf *m,
    u_int32_t cnt, ifnet_model_t mode)
{
	return (dlil_input_packet_list_common(ifp, m, cnt, mode, TRUE));
}

static void
dlil_input_packet_list_common(struct ifnet *ifp_param, struct mbuf *m,
    u_int32_t cnt, ifnet_model_t mode, boolean_t ext)
{
	int				error = 0;
	protocol_family_t		protocol_family;
	mbuf_t				next_packet;
	ifnet_t				ifp = ifp_param;
	char *				frame_header;
	struct if_proto	*		last_ifproto = NULL;
	mbuf_t				pkt_first = NULL;
	mbuf_t *			pkt_next = NULL;
	u_int32_t			poll_thresh = 0, poll_ival = 0;

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START,0,0,0,0,0);

	if (ext && mode == IFNET_MODEL_INPUT_POLL_ON && cnt > 1 &&
	    (poll_ival = if_rxpoll_interval_pkts) > 0)
		poll_thresh = cnt;

	while (m != NULL) {
		struct if_proto *ifproto = NULL;
		int iorefcnt = 0;
		uint32_t pktf_mask;	/* pkt flags to preserve */

		if (ifp_param == NULL)
			ifp = m->m_pkthdr.rcvif;

		if ((ifp->if_eflags & IFEF_RXPOLL) && poll_thresh != 0 &&
		    poll_ival > 0 && (--poll_thresh % poll_ival) == 0)
			ifnet_poll(ifp);

		/* Check if this mbuf looks valid */
		MBUF_INPUT_CHECK(m, ifp);

		next_packet = m->m_nextpkt;
		m->m_nextpkt = NULL;
		frame_header = m->m_pkthdr.pkt_hdr;
		m->m_pkthdr.pkt_hdr = NULL;

		/*
		 * Get an IO reference count if the interface is not
		 * loopback (lo0) and it is attached; lo0 never goes
		 * away, so optimize for that.
		 */
		if (ifp != lo_ifp) {
			if (!ifnet_is_attached(ifp, 1)) {
				m_freem(m);
				goto next;
			}
			iorefcnt = 1;
			pktf_mask = 0;
		} else {
			/*
			 * If this arrived on lo0, preserve interface addr
			 * info to allow for connectivity between loopback
			 * and local interface addresses.
			 */
			pktf_mask = (PKTF_LOOP|PKTF_IFAINFO);
		}

		/* make sure packet comes in clean */
		m_classifier_init(m, pktf_mask);

		ifp_inc_traffic_class_in(ifp, m);

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

		if (hwcksum_dbg != 0 && !(ifp->if_flags & IFF_LOOPBACK) &&
		    !(m->m_pkthdr.pkt_flags & PKTF_LOOP))
			dlil_input_cksum_dbg(ifp, m, frame_header,
			    protocol_family);

		/*
		 * For partial checksum offload, we expect the driver to
		 * set the start offset indicating the start of the span
		 * that is covered by the hardware-computed checksum;
		 * adjust this start offset accordingly because the data
		 * pointer has been advanced beyond the link-layer header.
		 *
		 * Don't adjust if the interface is a bridge member, as
		 * the adjustment will occur from the context of the
		 * bridge interface during input.
		 */
		if (ifp->if_bridge == NULL && (m->m_pkthdr.csum_flags &
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			int adj;

			if (frame_header == NULL ||
			    frame_header < (char *)mbuf_datastart(m) ||
			    frame_header > (char *)m->m_data ||
			    (adj = (m->m_data - frame_header)) >
			    m->m_pkthdr.csum_rx_start) {
				m->m_pkthdr.csum_data = 0;
				m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;
				hwcksum_in_invalidated++;
			} else {
				m->m_pkthdr.csum_rx_start -= adj;
			}
		}

		pktap_input(ifp, protocol_family, m, frame_header);

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
		m->m_pkthdr.pkt_hdr = frame_header;
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
}

errno_t
if_mcasts_update(struct ifnet *ifp)
{
	errno_t err;

	err = ifnet_ioctl(ifp, 0, SIOCADDMULTI, NULL);
	if (err == EAFNOSUPPORT)
		err = 0;
	printf("%s: %s %d suspended link-layer multicast membership(s) "
	    "(err=%d)\n", if_name(ifp),
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

/*
 * This is mostly called from the context of the DLIL input thread;
 * because of that there is no need for atomic operations.
 */
static __inline void
ifp_inc_traffic_class_in(struct ifnet *ifp, struct mbuf *m)
{
	if (!(m->m_flags & M_PKTHDR))
		return;

	switch (m_get_traffic_class(m)) {
	case MBUF_TC_BE:
		ifp->if_tc.ifi_ibepackets++;
		ifp->if_tc.ifi_ibebytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_BK:
		ifp->if_tc.ifi_ibkpackets++;
		ifp->if_tc.ifi_ibkbytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_VI:
		ifp->if_tc.ifi_ivipackets++;
		ifp->if_tc.ifi_ivibytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_VO:
		ifp->if_tc.ifi_ivopackets++;
		ifp->if_tc.ifi_ivobytes += m->m_pkthdr.len;
		break;
	default:
		break;
	}

	if (mbuf_is_traffic_class_privileged(m)) {
		ifp->if_tc.ifi_ipvpackets++;
		ifp->if_tc.ifi_ipvbytes += m->m_pkthdr.len;
	}
}

/*
 * This is called from DLIL output, hence multiple threads could end
 * up modifying the statistics.  We trade off acccuracy for performance
 * by not using atomic operations here.
 */
static __inline void
ifp_inc_traffic_class_out(struct ifnet *ifp, struct mbuf *m)
{
	if (!(m->m_flags & M_PKTHDR))
		return;

	switch (m_get_traffic_class(m)) {
	case MBUF_TC_BE:
		ifp->if_tc.ifi_obepackets++;
		ifp->if_tc.ifi_obebytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_BK:
		ifp->if_tc.ifi_obkpackets++;
		ifp->if_tc.ifi_obkbytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_VI:
		ifp->if_tc.ifi_ovipackets++;
		ifp->if_tc.ifi_ovibytes += m->m_pkthdr.len;
		break;
	case MBUF_TC_VO:
		ifp->if_tc.ifi_ovopackets++;
		ifp->if_tc.ifi_ovobytes += m->m_pkthdr.len;
		break;
	default:
		break;
	}

	if (mbuf_is_traffic_class_privileged(m)) {
		ifp->if_tc.ifi_opvpackets++;
		ifp->if_tc.ifi_opvbytes += m->m_pkthdr.len;
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
 *
 * An advisory code will be returned if adv is not null. This
 * can be used to provide feedback about interface queues to the
 * application.
 */
errno_t
dlil_output(ifnet_t ifp, protocol_family_t proto_family, mbuf_t packetlist,
    void *route, const struct sockaddr *dest, int raw, struct flowadv *adv)
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
	u_int32_t pre = 0, post = 0;
	u_int32_t fpkts = 0, fbytes = 0;
	int32_t flen = 0;

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

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
	if (retval != 0) {
		m_freem(m);
		goto cleanup;
	}
#endif

	do {
#if CONFIG_DTRACE
		if (!raw && proto_family == PF_INET) {
			struct ip *ip = mtod(m, struct ip*);
	                DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
				struct ip *, ip, struct ifnet *, ifp,
				struct ip *, ip, struct ip6_hdr *, NULL);

		} else if (!raw && proto_family == PF_INET6) {
			struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr*);
			DTRACE_IP6(send, struct mbuf*, m, struct inpcb *, NULL,
				struct ip6_hdr *, ip6, struct ifnet*, ifp,
				struct ip*, NULL, struct ip6_hdr *, ip6);
		}
#endif /* CONFIG_DTRACE */

		if (raw == 0 && ifp->if_framer != NULL) {
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
			    frame_type, &pre, &post);
			if (retval != 0) {
				if (retval != EJUSTRETURN)
					m_freem(m);
				goto next;
			}

			/*
			 * For partial checksum offload, adjust the start
			 * and stuff offsets based on the prepended header.
			 */
			if ((m->m_pkthdr.csum_flags &
			    (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
			    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
				m->m_pkthdr.csum_tx_stuff += pre;
				m->m_pkthdr.csum_tx_start += pre;
			}

			if (hwcksum_dbg != 0 && !(ifp->if_flags & IFF_LOOPBACK))
				dlil_output_cksum_dbg(ifp, m, pre,
				    proto_family);

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
		 * Strip away M_PROTO1 bit prior to sending packet
		 * to the driver as this field may be used by the driver
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
		if (TSO_IPV4_NOTOK(ifp, m) || TSO_IPV6_NOTOK(ifp, m)) {
			retval = EMSGSIZE;
			m_freem(m);
			goto cleanup;
		}

		/*
		 * If the packet service class is not background,
		 * update the timestamp to indicate recent activity
		 * on a foreground socket.
		 */
		if (!(m->m_pkthdr.pkt_flags & PKTF_SO_BACKGROUND) &&
		    (m->m_pkthdr.pkt_flags & PKTF_FLOW_ID) &&
		    m->m_pkthdr.pkt_flowsrc == FLOWSRC_INPCB)
			ifp->if_fg_sendts = net_uptime();

		ifp_inc_traffic_class_out(ifp, m);
		pktap_output(ifp, proto_family, m, pre, post);

		/*
		 * Finally, call the driver.
		 */
		if (ifp->if_eflags & IFEF_SENDLIST) {
			if (m->m_pkthdr.pkt_flags & PKTF_FORWARDED) {
				flen += (m_pktlen(m) - (pre + post));
				m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;
			}
			*send_tail = m;
			send_tail = &m->m_nextpkt;
		} else {
			if (m->m_pkthdr.pkt_flags & PKTF_FORWARDED) {
				flen = (m_pktlen(m) - (pre + post));
				m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;
			} else {
				flen = 0;
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START,
			    0, 0, 0, 0, 0);
			retval = (*ifp->if_output)(ifp, m);
			if (retval == EQFULL || retval == EQSUSPENDED) {
				if (adv != NULL && adv->code == FADV_SUCCESS) {
					adv->code = (retval == EQFULL ?
					    FADV_FLOW_CONTROLLED :
					    FADV_SUSPENDED);
				}
				retval = 0;
			}
			if (retval == 0 && flen > 0) {
				fbytes += flen;
				fpkts++;
			}
			if (retval != 0 && dlil_verbose) {
				printf("%s: output error on %s retval = %d\n",
				    __func__, if_name(ifp),
				    retval);
			}
			KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END,
			    0, 0, 0, 0, 0);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0, 0, 0, 0, 0);

next:
		m = packetlist;
		if (m != NULL) {
			packetlist = packetlist->m_nextpkt;
			m->m_nextpkt = NULL;
		}
	} while (m != NULL);

	if (send_head != NULL) {
		VERIFY(ifp->if_eflags & IFEF_SENDLIST);
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START,
		    0, 0, 0, 0, 0);
		retval = (*ifp->if_output)(ifp, send_head);
		if (retval == EQFULL || retval == EQSUSPENDED) {
			if (adv != NULL) {
				adv->code = (retval == EQFULL ?
				    FADV_FLOW_CONTROLLED : FADV_SUSPENDED);
			}
			retval = 0;
		}
		if (retval == 0 && flen > 0) {
			fbytes += flen;
			fpkts++;
		}
		if (retval != 0 && dlil_verbose) {
			printf("%s: output error on %s retval = %d\n",
			    __func__, if_name(ifp), retval);
		}
		KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
	}

	KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);

cleanup:
	if (fbytes > 0)
		ifp->if_fbytes += fbytes;
	if (fpkts > 0)
		ifp->if_fpackets += fpkts;
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
			    (struct sockaddr_dl*)(void *)ll_addr, ll_len);
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
		if (arpp == NULL) {
			result = ENOTSUP;
		} else {
			switch (arpop) {
			case ARPOP_REQUEST:
				arpstat.txrequests++;
				if (target_hw != NULL)
					arpstat.txurequests++;
				break;
			case ARPOP_REPLY:
				arpstat.txreplies++;
				break;
			}
			result = arpp(ifp, arpop, sender_hw, sender_proto,
			    target_hw, target_proto);
		}
		if_proto_free(proto);
	}

	return (result);
}

struct net_thread_marks { };
static const struct net_thread_marks net_thread_marks_base = { };

__private_extern__ const net_thread_marks_t net_thread_marks_none =
    &net_thread_marks_base;

__private_extern__ net_thread_marks_t
net_thread_marks_push(u_int32_t push)
{
	static const char *const base = (const void*)&net_thread_marks_base;
	u_int32_t pop = 0;

	if (push != 0) {
		struct uthread *uth = get_bsdthread_info(current_thread());

		pop = push & ~uth->uu_network_marks;
		if (pop != 0)
			uth->uu_network_marks |= pop;
	}

	return ((net_thread_marks_t)&base[pop]);
}

__private_extern__ net_thread_marks_t
net_thread_unmarks_push(u_int32_t unpush)
{
	static const char *const base = (const void*)&net_thread_marks_base;
	u_int32_t unpop = 0;

	if (unpush != 0) {
		struct uthread *uth = get_bsdthread_info(current_thread());

		unpop = unpush & uth->uu_network_marks;
		if (unpop != 0)
			uth->uu_network_marks &= ~unpop;
	}

	return ((net_thread_marks_t)&base[unpop]);
}

__private_extern__ void
net_thread_marks_pop(net_thread_marks_t popx)
{
	static const char *const base = (const void*)&net_thread_marks_base;
	ptrdiff_t pop = (caddr_t)popx - (caddr_t)base;

	if (pop != 0) {
		static const ptrdiff_t ones = (ptrdiff_t)(u_int32_t)~0U;
		struct uthread *uth = get_bsdthread_info(current_thread());

		VERIFY((pop & ones) == pop);
		VERIFY((ptrdiff_t)(uth->uu_network_marks & pop) == pop);
		uth->uu_network_marks &= ~pop;
	}
}

__private_extern__ void
net_thread_unmarks_pop(net_thread_marks_t unpopx)
{
	static const char *const base = (const void*)&net_thread_marks_base;
	ptrdiff_t unpop = (caddr_t)unpopx - (caddr_t)base;

	if (unpop != 0) {
		static const ptrdiff_t ones = (ptrdiff_t)(u_int32_t)~0U;
		struct uthread *uth = get_bsdthread_info(current_thread());

		VERIFY((unpop & ones) == unpop);
		VERIFY((ptrdiff_t)(uth->uu_network_marks & unpop) == 0);
		uth->uu_network_marks |= unpop;
	}
}

__private_extern__ u_int32_t
net_thread_is_marked(u_int32_t check)
{
	if (check != 0) {
		struct uthread *uth = get_bsdthread_info(current_thread());
		return (uth->uu_network_marks & check);
	}
	else
		return (0);
}

__private_extern__ u_int32_t
net_thread_is_unmarked(u_int32_t check)
{
	if (check != 0) {
		struct uthread *uth = get_bsdthread_info(current_thread());
		return (~uth->uu_network_marks & check);
	}
	else
		return (0);
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
    const struct sockaddr* target_proto0, u_int32_t rtflags)
{
	errno_t	result = 0;
	const struct sockaddr_in * sender_sin;
	const struct sockaddr_in * target_sin;
	struct sockaddr_inarp target_proto_sinarp;
	struct sockaddr *target_proto = (void *)(uintptr_t)target_proto0;

	if (target_proto == NULL || (sender_proto != NULL &&
	    sender_proto->sa_family != target_proto->sa_family))
		return (EINVAL);

	/*
	 * If the target is a (default) router, provide that
	 * information to the send_arp callback routine.
	 */
	if (rtflags & RTF_ROUTER) {
		bcopy(target_proto, &target_proto_sinarp,
		    sizeof (struct sockaddr_in));
		target_proto_sinarp.sin_other |= SIN_ROUTER;
		target_proto = (struct sockaddr *)&target_proto_sinarp;
	}

	/*
	 * If this is an ARP request and the target IP is IPv4LL,
	 * send the request on all interfaces.  The exception is
	 * an announcement, which must only appear on the specific
	 * interface.
	 */
	sender_sin = (struct sockaddr_in *)(void *)(uintptr_t)sender_proto;
	target_sin = (struct sockaddr_in *)(void *)(uintptr_t)target_proto;
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
						    (void *)source_ip->ifa_addr;
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
				    arpop, (struct sockaddr_dl *)(void *)
				    source_hw->ifa_addr,
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
		printf("%s: attached v1 protocol %d\n", if_name(ifp),
		    protocol);
	}

end:
	if (retval != 0 && retval != EEXIST && ifp != NULL) {
		DLIL_PRINTF("%s: failed to attach v1 protocol %d (err=%d)\n",
		    if_name(ifp), protocol, retval);
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
		printf("%s: attached v2 protocol %d\n", if_name(ifp),
		    protocol);
	}

end:
	if (retval != 0 && retval != EEXIST && ifp != NULL) {
		DLIL_PRINTF("%s: failed to attach v2 protocol %d (err=%d)\n",
		    if_name(ifp), protocol, retval);
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
		printf("%s: detached %s protocol %d\n", if_name(ifp),
		    (proto->proto_kpi == kProtoKPI_v1) ?
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
	struct dlil_threading_info *dl_inp;
	u_int32_t sflags = 0;
	int err;

	if (ifp == NULL)
		return (EINVAL);

	/*
	 * Serialize ifnet attach using dlil_ifnet_lock, in order to
	 * prevent the interface from being configured while it is
	 * embryonic, as ifnet_head_lock is dropped and reacquired
	 * below prior to marking the ifnet with IFRF_ATTACHED.
	 */
	dlil_if_lock();
	ifnet_head_lock_exclusive();
	/* Verify we aren't already on the list */
	TAILQ_FOREACH(tmp_if, &ifnet_head, if_link) {
		if (tmp_if == ifp) {
			ifnet_head_done();
			dlil_if_unlock();
			return (EEXIST);
		}
	}

	lck_mtx_lock_spin(&ifp->if_ref_lock);
	if (ifp->if_refflags & IFRF_ATTACHED) {
		panic_plain("%s: flags mismatch (attached set) ifp=%p",
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
			dlil_if_unlock();
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
		dlil_if_unlock();
		return (ENODEV);
	}

	/* Allocate protocol hash table */
	VERIFY(ifp->if_proto_hash == NULL);
	ifp->if_proto_hash = zalloc(dlif_phash_zone);
	if (ifp->if_proto_hash == NULL) {
		ifnet_lock_done(ifp);
		ifnet_head_done();
		dlil_if_unlock();
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

	if (ifp->if_index == 0) {
		int idx = if_next_index();

		if (idx == -1) {
			ifp->if_index = 0;
			ifnet_lock_done(ifp);
			ifnet_head_done();
			dlil_if_unlock();
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
		dlil_if_unlock();
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

	VERIFY(ifp->if_output_sched_model == IFNET_SCHED_MODEL_NORMAL ||
	    ifp->if_output_sched_model == IFNET_SCHED_MODEL_DRIVER_MANAGED);

	/* By default, use SFB and enable flow advisory */
	sflags = PKTSCHEDF_QALG_SFB;
	if (if_flowadv)
		sflags |= PKTSCHEDF_QALG_FLOWCTL;

	/* Initialize transmit queue(s) */
	err = ifclassq_setup(ifp, sflags, (dl_if->dl_if_flags & DLIF_REUSE));
	if (err != 0) {
		panic_plain("%s: ifp=%p couldn't initialize transmit queue; "
		    "err=%d", __func__, ifp, err);
		/* NOTREACHED */
	}

	/* Sanity checks on the input thread storage */
	dl_inp = &dl_if->dl_if_inpstorage;
	bzero(&dl_inp->stats, sizeof (dl_inp->stats));
	VERIFY(dl_inp->input_waiting == 0);
	VERIFY(dl_inp->wtot == 0);
	VERIFY(dl_inp->ifp == NULL);
	VERIFY(qhead(&dl_inp->rcvq_pkts) == NULL && qempty(&dl_inp->rcvq_pkts));
	VERIFY(qlimit(&dl_inp->rcvq_pkts) == 0);
	VERIFY(!dl_inp->net_affinity);
	VERIFY(ifp->if_inp == NULL);
	VERIFY(dl_inp->input_thr == THREAD_NULL);
	VERIFY(dl_inp->wloop_thr == THREAD_NULL);
	VERIFY(dl_inp->poll_thr == THREAD_NULL);
	VERIFY(dl_inp->tag == 0);
	VERIFY(dl_inp->mode == IFNET_MODEL_INPUT_POLL_OFF);
	bzero(&dl_inp->tstats, sizeof (dl_inp->tstats));
	bzero(&dl_inp->pstats, sizeof (dl_inp->pstats));
	bzero(&dl_inp->sstats, sizeof (dl_inp->sstats));
#if IFNET_INPUT_SANITY_CHK
	VERIFY(dl_inp->input_mbuf_cnt == 0);
#endif /* IFNET_INPUT_SANITY_CHK */

	/*
	 * A specific DLIL input thread is created per Ethernet/cellular
	 * interface or for an interface which supports opportunistic
	 * input polling.  Pseudo interfaces or other types of interfaces
	 * use the main input thread instead.
	 */
	if ((net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL)) ||
	    ifp->if_type == IFT_ETHER || ifp->if_type == IFT_CELLULAR) {
		ifp->if_inp = dl_inp;
		err = dlil_create_input_thread(ifp, ifp->if_inp);
		if (err != 0) {
			panic_plain("%s: ifp=%p couldn't get an input thread; "
			    "err=%d", __func__, ifp, err);
			/* NOTREACHED */
		}
	}

	/*
	 * If the driver supports the new transmit model, calculate flow hash
	 * and create a workloop starter thread to invoke the if_start callback
	 * where the packets may be dequeued and transmitted.
	 */
	if (ifp->if_eflags & IFEF_TXSTART) {
		ifp->if_flowhash = ifnet_calc_flowhash(ifp);
		VERIFY(ifp->if_flowhash != 0);

		VERIFY(ifp->if_start != NULL);
		VERIFY(ifp->if_start_thread == THREAD_NULL);

		ifnet_set_start_cycle(ifp, NULL);
		ifp->if_start_active = 0;
		ifp->if_start_req = 0;
		ifp->if_start_flags = 0;
		if ((err = kernel_thread_start(ifnet_start_thread_fn, ifp,
		    &ifp->if_start_thread)) != KERN_SUCCESS) {
			panic_plain("%s: ifp=%p couldn't get a start thread; "
			    "err=%d", __func__, ifp, err);
			/* NOTREACHED */
		}
		ml_thread_policy(ifp->if_start_thread, MACHINE_GROUP,
		    (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_WORKLOOP));
	} else {
		ifp->if_flowhash = 0;
	}

	/*
	 * If the driver supports the new receive model, create a poller
	 * thread to invoke if_input_poll callback where the packets may
	 * be dequeued from the driver and processed for reception.
	 */
	if (ifp->if_eflags & IFEF_RXPOLL) {
		VERIFY(ifp->if_input_poll != NULL);
		VERIFY(ifp->if_input_ctl != NULL);
		VERIFY(ifp->if_poll_thread == THREAD_NULL);

		ifnet_set_poll_cycle(ifp, NULL);
		ifp->if_poll_update = 0;
		ifp->if_poll_active = 0;
		ifp->if_poll_req = 0;
		if ((err = kernel_thread_start(ifnet_poll_thread_fn, ifp,
		    &ifp->if_poll_thread)) != KERN_SUCCESS) {
			panic_plain("%s: ifp=%p couldn't get a poll thread; "
			    "err=%d", __func__, ifp, err);
			/* NOTREACHED */
		}
		ml_thread_policy(ifp->if_poll_thread, MACHINE_GROUP,
		    (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_WORKLOOP));
	}

	VERIFY(ifp->if_desc.ifd_maxlen == IF_DESCSIZE);
	VERIFY(ifp->if_desc.ifd_len == 0);
	VERIFY(ifp->if_desc.ifd_desc != NULL);

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

		printf("%s: attached with %d suspended link-layer multicast "
		    "membership(s)\n", if_name(ifp),
		    ifp->if_updatemcasts);
	}

	/* Clear logging parameters */
	bzero(&ifp->if_log, sizeof (ifp->if_log));
	ifp->if_fg_sendts = 0;

	VERIFY(ifp->if_delegated.ifp == NULL);
	VERIFY(ifp->if_delegated.type == 0);
	VERIFY(ifp->if_delegated.family == 0);
	VERIFY(ifp->if_delegated.subfamily == 0);

	ifnet_lock_done(ifp);
	ifnet_head_done();

	lck_mtx_lock(&ifp->if_cached_route_lock);
	/* Enable forwarding cached route */
	ifp->if_fwd_cacheok = 1;
	/* Clean up any existing cached routes */
	ROUTE_RELEASE(&ifp->if_fwd_route);
	bzero(&ifp->if_fwd_route, sizeof (ifp->if_fwd_route));
	ROUTE_RELEASE(&ifp->if_src_route);
	bzero(&ifp->if_src_route, sizeof (ifp->if_src_route));
	ROUTE_RELEASE(&ifp->if_src_route6);
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

	VERIFY(ifp->if_data_threshold == 0);

	/*
	 * Finally, mark this ifnet as attached.
	 */
	lck_mtx_lock(rnh_lock);
	ifnet_lock_exclusive(ifp);
	/* Initialize Link Quality Metric (loopback [lo0] is always good) */
	ifp->if_lqm = (ifp == lo_ifp) ? IFNET_LQM_THRESH_GOOD :
	    IFNET_LQM_THRESH_UNKNOWN;
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
	dlil_if_unlock();

#if PF
	/*
	 * Attach packet filter to this interface, if enabled.
	 */
	pf_ifnet_hook(ifp, 1);
#endif /* PF */

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, NULL, 0);

	if (dlil_verbose) {
		printf("%s: attached%s\n", if_name(ifp),
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

	namelen = snprintf(workbuf, sizeof (workbuf), "%s",
	    if_name(ifp));
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
		msdl = (struct sockaddr_dl *)(void *)
		    ((char *)asdl + SOCK_MAXADDRLEN);
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
		asdl = (struct sockaddr_dl *)(void *)&dl_if->dl_if_lladdr.asdl;
		bzero(asdl, sizeof (dl_if->dl_if_lladdr.asdl));
		msdl = (struct sockaddr_dl *)(void *)&dl_if->dl_if_lladdr.msdl;
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
}

errno_t
ifnet_detach(ifnet_t ifp)
{
	struct ifnet *delegated_ifp;

	if (ifp == NULL)
		return (EINVAL);

	lck_mtx_lock(rnh_lock);
	ifnet_head_lock_exclusive();
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
		ifnet_head_done();
		lck_mtx_unlock(rnh_lock);
		return (EINVAL);
	} else if (ifp->if_refflags & IFRF_DETACHING) {
		/* Interface has already been detached */
		lck_mtx_unlock(&ifp->if_ref_lock);
		ifnet_lock_done(ifp);
		ifnet_head_done();
		lck_mtx_unlock(rnh_lock);
		return (ENXIO);
	}
	/* Indicate this interface is being detached */
	ifp->if_refflags &= ~IFRF_ATTACHED;
	ifp->if_refflags |= IFRF_DETACHING;
	lck_mtx_unlock(&ifp->if_ref_lock);

	if (dlil_verbose)
		printf("%s: detaching\n", if_name(ifp));

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

	/* Clear logging parameters */
	bzero(&ifp->if_log, sizeof (ifp->if_log));

	/* Clear delegated interface info (reference released below) */
	delegated_ifp = ifp->if_delegated.ifp;
	bzero(&ifp->if_delegated, sizeof (ifp->if_delegated));

	ifnet_lock_done(ifp);
	ifnet_head_done();
	lck_mtx_unlock(rnh_lock);

	/* Release reference held on the delegated interface */
	if (delegated_ifp != NULL)
		ifnet_release(delegated_ifp);

	/* Reset Link Quality Metric (unless loopback [lo0]) */
	if (ifp != lo_ifp)
		if_lqm_update(ifp, IFNET_LQM_THRESH_OFF);

	/* Reset TCP local statistics */
	if (ifp->if_tcp_stat != NULL)
		bzero(ifp->if_tcp_stat, sizeof(*ifp->if_tcp_stat));

	/* Reset UDP local statistics */
	if (ifp->if_udp_stat != NULL)
		bzero(ifp->if_udp_stat, sizeof(*ifp->if_udp_stat));

	/* Let BPF know we're detaching */
	bpfdetach(ifp);

	/* Mark the interface as DOWN */
	if_down(ifp);

	/* Drain send queue */
	ifclassq_teardown(ifp);

	/* Disable forwarding cached route */
	lck_mtx_lock(&ifp->if_cached_route_lock);
	ifp->if_fwd_cacheok = 0;
	lck_mtx_unlock(&ifp->if_cached_route_lock);

	ifp->if_data_threshold = 0;
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
	dlil_if_lock();
	ifnet_detaching_enqueue(ifp);
	dlil_if_unlock();

	return (0);
}

static void
ifnet_detaching_enqueue(struct ifnet *ifp)
{
	dlil_if_lock_assert();

	++ifnet_detaching_cnt;
	VERIFY(ifnet_detaching_cnt != 0);
	TAILQ_INSERT_TAIL(&ifnet_detaching_head, ifp, if_detaching_link);
	wakeup((caddr_t)&ifnet_delayed_run);
}

static struct ifnet *
ifnet_detaching_dequeue(void)
{
	struct ifnet *ifp;

	dlil_if_lock_assert();

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

static int
ifnet_detacher_thread_cont(int err)
{
#pragma unused(err)
	struct ifnet *ifp;

	for (;;) {
		dlil_if_lock_assert();
		while (ifnet_detaching_cnt == 0) {
			(void) msleep0(&ifnet_delayed_run, &dlil_ifnet_lock,
			    (PZERO - 1), "ifnet_detacher_cont", 0,
			    ifnet_detacher_thread_cont);
			/* NOTREACHED */
		}

		VERIFY(TAILQ_FIRST(&ifnet_detaching_head) != NULL);

		/* Take care of detaching ifnet */
		ifp = ifnet_detaching_dequeue();
		if (ifp != NULL) {
			dlil_if_unlock();
			ifnet_detach_final(ifp);
			dlil_if_lock();
		}
	}
	/* NOTREACHED */
	return (0);
}

static void
ifnet_detacher_thread_func(void *v, wait_result_t w)
{
#pragma unused(v, w)
	dlil_if_lock();
	(void) msleep0(&ifnet_delayed_run, &dlil_ifnet_lock,
	    (PZERO - 1), "ifnet_detacher", 0, ifnet_detacher_thread_cont);
	/*
	 * msleep0() shouldn't have returned as PCATCH was not set;
	 * therefore assert in this case.
	 */
	dlil_if_unlock();
	VERIFY(0);
}

static void
ifnet_detach_final(struct ifnet *ifp)
{
	struct ifnet_filter *filter, *filter_next;
	struct ifnet_filter_head fhead;
	struct dlil_threading_info *inp;
	struct ifaddr *ifa;
	ifnet_detached_func if_free;
	int i;

	lck_mtx_lock(&ifp->if_ref_lock);
	if (!(ifp->if_refflags & IFRF_DETACHING)) {
		panic("%s: flags mismatch (detaching not set) ifp=%p",
		    __func__, ifp);
		/* NOTREACHED */
	}

	/*
	 * Wait until the existing IO references get released
	 * before we proceed with ifnet_detach.  This is not a
	 * common case, so block without using a continuation.
	 */
	while (ifp->if_refio > 0) {
		printf("%s: Waiting for IO references on %s interface "
		    "to be released\n", __func__, if_name(ifp));
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
	 * Signal the starter thread to terminate itself.
	 */
	if (ifp->if_start_thread != THREAD_NULL) {
		lck_mtx_lock_spin(&ifp->if_start_lock);
		ifp->if_start_flags = 0;
		ifp->if_start_thread = THREAD_NULL;
		wakeup_one((caddr_t)&ifp->if_start_thread);
		lck_mtx_unlock(&ifp->if_start_lock);
	}

	/*
	 * Signal the poller thread to terminate itself.
	 */
	if (ifp->if_poll_thread != THREAD_NULL) {
		lck_mtx_lock_spin(&ifp->if_poll_lock);
		ifp->if_poll_thread = THREAD_NULL;
		wakeup_one((caddr_t)&ifp->if_poll_thread);
		lck_mtx_unlock(&ifp->if_poll_lock);
	}

	/*
	 * If thread affinity was set for the workloop thread, we will need
	 * to tear down the affinity and release the extra reference count
	 * taken at attach time.  Does not apply to lo0 or other interfaces
	 * without dedicated input threads.
	 */
	if ((inp = ifp->if_inp) != NULL) {
		VERIFY(inp != dlil_main_input_thread);

		if (inp->net_affinity) {
			struct thread *tp, *wtp, *ptp;

			lck_mtx_lock_spin(&inp->input_lck);
			wtp = inp->wloop_thr;
			inp->wloop_thr = THREAD_NULL;
			ptp = inp->poll_thr;
			inp->poll_thr = THREAD_NULL;
			tp = inp->input_thr;	/* don't nullify now */
			inp->tag = 0;
			inp->net_affinity = FALSE;
			lck_mtx_unlock(&inp->input_lck);

			/* Tear down poll thread affinity */
			if (ptp != NULL) {
				VERIFY(ifp->if_eflags & IFEF_RXPOLL);
				(void) dlil_affinity_set(ptp,
				    THREAD_AFFINITY_TAG_NULL);
				thread_deallocate(ptp);
			}

			/* Tear down workloop thread affinity */
			if (wtp != NULL) {
				(void) dlil_affinity_set(wtp,
				    THREAD_AFFINITY_TAG_NULL);
				thread_deallocate(wtp);
			}

			/* Tear down DLIL input thread affinity */
			(void) dlil_affinity_set(tp, THREAD_AFFINITY_TAG_NULL);
			thread_deallocate(tp);
		}

		/* disassociate ifp DLIL input thread */
		ifp->if_inp = NULL;

		lck_mtx_lock_spin(&inp->input_lck);
		inp->input_waiting |= DLIL_INPUT_TERMINATE;
		if (!(inp->input_waiting & DLIL_INPUT_RUNNING)) {
			wakeup_one((caddr_t)&inp->input_waiting);
		}
		lck_mtx_unlock(&inp->input_lck);
	}

	/* The driver might unload, so point these to ourselves */
	if_free = ifp->if_free;
	ifp->if_output = ifp_if_output;
	ifp->if_pre_enqueue = ifp_if_output;
	ifp->if_start = ifp_if_start;
	ifp->if_output_ctl = ifp_if_ctl;
	ifp->if_input_poll = ifp_if_input_poll;
	ifp->if_input_ctl = ifp_if_ctl;
	ifp->if_ioctl = ifp_if_ioctl;
	ifp->if_set_bpf_tap = ifp_if_set_bpf_tap;
	ifp->if_free = ifp_if_free;
	ifp->if_demux = ifp_if_demux;
	ifp->if_event = ifp_if_event;
	ifp->if_framer_legacy = ifp_if_framer;
	ifp->if_framer = ifp_if_framer_extended;
	ifp->if_add_proto = ifp_if_add_proto;
	ifp->if_del_proto = ifp_if_del_proto;
	ifp->if_check_multi = ifp_if_check_multi;

	/* wipe out interface description */
	VERIFY(ifp->if_desc.ifd_maxlen == IF_DESCSIZE);
	ifp->if_desc.ifd_len = 0;
	VERIFY(ifp->if_desc.ifd_desc != NULL);
	bzero(ifp->if_desc.ifd_desc, IF_DESCSIZE);

	/* there shouldn't be any delegation by now */
	VERIFY(ifp->if_delegated.ifp == NULL);
	VERIFY(ifp->if_delegated.type == 0);
	VERIFY(ifp->if_delegated.family == 0);
	VERIFY(ifp->if_delegated.subfamily == 0);

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

	/* Last chance to drain send queue */
	if_qflush(ifp, 0);

	/* Last chance to cleanup any cached route */
	lck_mtx_lock(&ifp->if_cached_route_lock);
	VERIFY(!ifp->if_fwd_cacheok);
	ROUTE_RELEASE(&ifp->if_fwd_route);
	bzero(&ifp->if_fwd_route, sizeof (ifp->if_fwd_route));
	ROUTE_RELEASE(&ifp->if_src_route);
	bzero(&ifp->if_src_route, sizeof (ifp->if_src_route));
	ROUTE_RELEASE(&ifp->if_src_route6);
	bzero(&ifp->if_src_route6, sizeof (ifp->if_src_route6));
	lck_mtx_unlock(&ifp->if_cached_route_lock);

	VERIFY(ifp->if_data_threshold == 0);

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
		printf("%s: detached\n", if_name(ifp));

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

static void
ifp_if_start(struct ifnet *ifp)
{
	ifnet_purge(ifp);
}

static void
ifp_if_input_poll(struct ifnet *ifp, u_int32_t flags, u_int32_t max_cnt,
    struct mbuf **m_head, struct mbuf **m_tail, u_int32_t *cnt, u_int32_t *len)
{
#pragma unused(ifp, flags, max_cnt)
	if (m_head != NULL)
		*m_head = NULL;
	if (m_tail != NULL)
		*m_tail = NULL;
	if (cnt != NULL)
		*cnt = 0;
	if (len != NULL)
		*len = 0;
}

static errno_t
ifp_if_ctl(struct ifnet *ifp, ifnet_ctl_cmd_t cmd, u_int32_t arglen, void *arg)
{
#pragma unused(ifp, cmd, arglen, arg)
	return (EOPNOTSUPP);
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
	return (ifp_if_framer_extended(ifp, m, sa, ll, t, NULL, NULL));
}

static errno_t
ifp_if_framer_extended(struct ifnet *ifp, struct mbuf **m,
    const struct sockaddr *sa, const char *ll, const char *t,
    u_int32_t *pre, u_int32_t *post)
{
#pragma unused(ifp, sa, ll, t)
	m_freem(*m);
	*m = NULL;

	if (pre != NULL)
		*pre = 0;
	if (post != NULL)
		*post = 0;

	return (EJUSTRETURN);
}

errno_t
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

	dlil_if_lock();
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
	ifp1->if_xname = dlifp1->dl_if_xnamestorage;

	/* initialize interface description */
	ifp1->if_desc.ifd_maxlen = IF_DESCSIZE;
	ifp1->if_desc.ifd_len = 0;
	ifp1->if_desc.ifd_desc = dlifp1->dl_if_descstorage;

#if CONFIG_MACF_NET
	mac_ifnet_label_init(ifp1);
#endif

	if ((ret = dlil_alloc_local_stats(ifp1)) != 0) {
		DLIL_PRINTF("%s: failed to allocate if local stats, "
		    "error: %d\n", __func__, ret);
		/* This probably shouldn't be fatal */
		ret = 0;
	}

	lck_mtx_init(&dlifp1->dl_if_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_rw_init(&ifp1->if_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_ref_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_flt_lock, ifnet_lock_group, ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_addrconfig_lock, ifnet_lock_group,
	    ifnet_lock_attr);
	lck_rw_init(&ifp1->if_llreach_lock, ifnet_lock_group, ifnet_lock_attr);
#if INET6
	lck_rw_init(&ifp1->if_inet6data_lock, ifnet_lock_group, ifnet_lock_attr);
	ifp1->if_inet6data = NULL;
#endif

	/* for send data paths */
	lck_mtx_init(&ifp1->if_start_lock, ifnet_snd_lock_group,
	    ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_cached_route_lock, ifnet_snd_lock_group,
	    ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_snd.ifcq_lock, ifnet_snd_lock_group,
	    ifnet_lock_attr);

	/* for receive data paths */
	lck_mtx_init(&ifp1->if_poll_lock, ifnet_rcv_lock_group,
	    ifnet_lock_attr);

	TAILQ_INSERT_TAIL(&dlil_ifnet_head, dlifp1, dl_if_link);

	*ifp = ifp1;

end:
	dlil_if_unlock();

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
	/* Reset external name (name + unit) */
	ifp->if_xname = dlifp->dl_if_xnamestorage;
	snprintf(__DECONST(char *, ifp->if_xname), IFXNAMSIZ, 
	    "%s?", ifp->if_name);
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
dlil_if_lock(void)
{
	lck_mtx_lock(&dlil_ifnet_lock);
}

__private_extern__ void
dlil_if_unlock(void)
{
	lck_mtx_unlock(&dlil_ifnet_lock);
}

__private_extern__ void
dlil_if_lock_assert(void)
{
	lck_mtx_assert(&dlil_ifnet_lock, LCK_MTX_ASSERT_OWNED);
}

__private_extern__ void
dlil_proto_unplumb_all(struct ifnet *ifp)
{
	/*
	 * if_proto_hash[0-2] are for PF_INET, PF_INET6 and PF_VLAN, where
	 * each bucket contains exactly one entry; PF_VLAN does not need an
	 * explicit unplumb.
	 *
	 * if_proto_hash[3] is for other protocols; we expect anything
	 * in this bucket to respond to the DETACHING event (which would
	 * have happened by now) and do the unplumb then.
	 */
	(void) proto_unplumb(PF_INET, ifp);
#if INET6
	(void) proto_unplumb(PF_INET6, ifp);
#endif /* INET6 */
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
		ROUTE_RELEASE(src);
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
		ROUTE_RELEASE(src);
	}
	lck_mtx_unlock(&ifp->if_cached_route_lock);
}
#endif /* INET6 */

struct rtentry *
ifnet_cached_rtlookup_inet(struct ifnet	*ifp, struct in_addr src_ip)
{
	struct route		src_rt;
	struct sockaddr_in	*dst;

	dst = (struct sockaddr_in *)(void *)(&src_rt.ro_dst);

	ifp_src_route_copyout(ifp, &src_rt);

	if (ROUTE_UNUSABLE(&src_rt) || src_ip.s_addr != dst->sin_addr.s_addr) {
		ROUTE_RELEASE(&src_rt);
		if (dst->sin_family != AF_INET) {
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

	if (ROUTE_UNUSABLE(&src_rt) ||
	    !IN6_ARE_ADDR_EQUAL(src_ip6, &src_rt.ro_dst.sin6_addr)) {
		ROUTE_RELEASE(&src_rt);
		if (src_rt.ro_dst.sin6_family != AF_INET6) {
			bzero(&src_rt.ro_dst, sizeof (src_rt.ro_dst));
			src_rt.ro_dst.sin6_len = sizeof (src_rt.ro_dst);
			src_rt.ro_dst.sin6_family = AF_INET6;
		}
		src_rt.ro_dst.sin6_scope_id = in6_addr2scopeid(ifp, src_ip6);
		bcopy(src_ip6, &src_rt.ro_dst.sin6_addr,
		    sizeof (src_rt.ro_dst.sin6_addr));

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

void
if_lqm_update(struct ifnet *ifp, int lqm)
{
	struct kev_dl_link_quality_metric_data ev_lqm_data;

	VERIFY(lqm >= IFNET_LQM_MIN && lqm <= IFNET_LQM_MAX);

	/* Normalize to edge */
	if (lqm > IFNET_LQM_THRESH_UNKNOWN && lqm <= IFNET_LQM_THRESH_POOR)
		lqm = IFNET_LQM_THRESH_POOR;
	else if (lqm > IFNET_LQM_THRESH_POOR && lqm <= IFNET_LQM_THRESH_GOOD)
		lqm = IFNET_LQM_THRESH_GOOD;

	ifnet_lock_exclusive(ifp);
	if (lqm == ifp->if_lqm) {
		ifnet_lock_done(ifp);
		return;		/* nothing to update */
	}
	ifp->if_lqm = lqm;
	ifnet_lock_done(ifp);

	bzero(&ev_lqm_data, sizeof (ev_lqm_data));
	ev_lqm_data.link_quality_metric = lqm;

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_LINK_QUALITY_METRIC_CHANGED,
	    (struct net_event_data *)&ev_lqm_data, sizeof (ev_lqm_data));
}

/* for uuid.c */
int
uuid_get_ethernet(u_int8_t *node)
{
	struct ifnet *ifp;
	struct sockaddr_dl *sdl;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		ifnet_lock_shared(ifp);
		IFA_LOCK_SPIN(ifp->if_lladdr);
		sdl = (struct sockaddr_dl *)(void *)ifp->if_lladdr->ifa_addr;
		if (sdl->sdl_type == IFT_ETHER) {
			memcpy(node, LLADDR(sdl), ETHER_ADDR_LEN);
			IFA_UNLOCK(ifp->if_lladdr);
			ifnet_lock_done(ifp);
			ifnet_head_done();
			return (0);
		}
		IFA_UNLOCK(ifp->if_lladdr);
		ifnet_lock_done(ifp);
	}
	ifnet_head_done();

	return (-1);
}

static int
sysctl_rxpoll SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_rxpoll;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (net_rxpoll == 0)
		return (ENXIO);

	if_rxpoll = i;
	return (err);
}

static int
sysctl_rxpoll_mode_holdtime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_mode_holdtime;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (q < IF_RXPOLL_MODE_HOLDTIME_MIN)
		q = IF_RXPOLL_MODE_HOLDTIME_MIN;

	if_rxpoll_mode_holdtime = q;

	return (err);
}

static int
sysctl_rxpoll_sample_holdtime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_sample_holdtime;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (q < IF_RXPOLL_SAMPLETIME_MIN)
		q = IF_RXPOLL_SAMPLETIME_MIN;

	if_rxpoll_sample_holdtime = q;

	return (err);
}

static int
sysctl_rxpoll_interval_time SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_interval_time;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (q < IF_RXPOLL_INTERVALTIME_MIN)
		q = IF_RXPOLL_INTERVALTIME_MIN;

	if_rxpoll_interval_time = q;

	return (err);
}

static int
sysctl_rxpoll_wlowat SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_rxpoll_wlowat;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (i == 0 || i >= if_rxpoll_whiwat)
		return (EINVAL);

	if_rxpoll_wlowat = i;
	return (err);
}

static int
sysctl_rxpoll_whiwat SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_rxpoll_whiwat;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (i <= if_rxpoll_wlowat)
		return (EINVAL);

	if_rxpoll_whiwat = i;
	return (err);
}

static int
sysctl_sndq_maxlen SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_sndq_maxlen;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (i < IF_SNDQ_MINLEN)
		i = IF_SNDQ_MINLEN;

	if_sndq_maxlen = i;
	return (err);
}

static int
sysctl_rcvq_maxlen SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_rcvq_maxlen;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (i < IF_RCVQ_MINLEN)
		i = IF_RCVQ_MINLEN;

	if_rcvq_maxlen = i;
	return (err);
}

void
dlil_node_present(struct ifnet *ifp, struct sockaddr *sa,
    int32_t rssi, int lqm, int npm, u_int8_t srvinfo[48])
{
	struct kev_dl_node_presence kev;
	struct sockaddr_dl *sdl;
	struct sockaddr_in6 *sin6;

	VERIFY(ifp);
	VERIFY(sa);
	VERIFY(sa->sa_family == AF_LINK || sa->sa_family == AF_INET6);

	bzero(&kev, sizeof (kev));
	sin6 = &kev.sin6_node_address;
	sdl = &kev.sdl_node_address;
	nd6_alt_node_addr_decompose(ifp, sa, sdl, sin6);
	kev.rssi = rssi;
	kev.link_quality_metric = lqm;
	kev.node_proximity_metric = npm;
	bcopy(srvinfo, kev.node_service_info, sizeof (kev.node_service_info));

	nd6_alt_node_present(ifp, sin6, sdl, rssi, lqm, npm);
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_NODE_PRESENCE,
	    &kev.link_data, sizeof (kev));
}

void
dlil_node_absent(struct ifnet *ifp, struct sockaddr *sa)
{
	struct kev_dl_node_absence kev;
	struct sockaddr_in6 *sin6;
	struct sockaddr_dl *sdl;

	VERIFY(ifp);
	VERIFY(sa);
	VERIFY(sa->sa_family == AF_LINK || sa->sa_family == AF_INET6);

	bzero(&kev, sizeof (kev));
	sin6 = &kev.sin6_node_address;
	sdl = &kev.sdl_node_address;
	nd6_alt_node_addr_decompose(ifp, sa, sdl, sin6);

	nd6_alt_node_absent(ifp, sin6);
	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_NODE_ABSENCE,
	    &kev.link_data, sizeof (kev));
}

const void *
dlil_ifaddr_bytes(const struct sockaddr_dl *sdl, size_t *sizep,
	kauth_cred_t *credp)
{
	const u_int8_t *bytes;
	size_t size;

	bytes = CONST_LLADDR(sdl);
	size = sdl->sdl_alen;

#if CONFIG_MACF
	if (dlil_lladdr_ckreq) {
		switch (sdl->sdl_type) {
		case IFT_ETHER:
		case IFT_BRIDGE:
		case IFT_IEEE1394:
		case IFT_IEEE8023ADLAG:
		case IFT_L2VLAN:
			break;
		default:
			credp = NULL;
			break;
		};

		if (credp && mac_system_check_info(*credp, "net.link.addr")) {
			static const u_int8_t unspec[FIREWIRE_EUI64_LEN] = {
			    [0] = 2
			};

			switch (sdl->sdl_type) {
			case IFT_ETHER:
			case IFT_BRIDGE:
			case IFT_IEEE8023ADLAG:
			case IFT_L2VLAN:
				VERIFY(size == ETHER_ADDR_LEN);
				bytes = unspec;
				break;
			case IFT_IEEE1394:
				VERIFY(size == FIREWIRE_EUI64_LEN);
				bytes = unspec;
				break;
			default:
				VERIFY(FALSE);
				break;
			};
		}
	}
#else
#pragma unused(credp)
#endif

	if (sizep != NULL) *sizep = size;
	return (bytes);
}

void
dlil_report_issues(struct ifnet *ifp, u_int8_t modid[DLIL_MODIDLEN],
    u_int8_t info[DLIL_MODARGLEN])
{
	struct kev_dl_issues kev;
	struct timeval tv;

	VERIFY(ifp != NULL);
	VERIFY(modid != NULL);
	_CASSERT(sizeof (kev.modid) == DLIL_MODIDLEN);
	_CASSERT(sizeof (kev.info) == DLIL_MODARGLEN);

	bzero(&kev, sizeof (&kev));

	microtime(&tv);
	kev.timestamp = tv.tv_sec;
	bcopy(modid, &kev.modid, DLIL_MODIDLEN);
	if (info != NULL)
		bcopy(info, &kev.info, DLIL_MODARGLEN);

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_ISSUES,
	    &kev.link_data, sizeof (kev));
}

errno_t
ifnet_getset_opportunistic(ifnet_t ifp, u_long cmd, struct ifreq *ifr,
    struct proc *p)
{
	u_int32_t level = IFNET_THROTTLE_OFF;
	errno_t result = 0;

	VERIFY(cmd == SIOCSIFOPPORTUNISTIC || cmd == SIOCGIFOPPORTUNISTIC);

	if (cmd == SIOCSIFOPPORTUNISTIC) {
		/*
		 * XXX: Use priv_check_cred() instead of root check?
		 */
		if ((result = proc_suser(p)) != 0)
			return (result);

		if (ifr->ifr_opportunistic.ifo_flags ==
		    IFRIFOF_BLOCK_OPPORTUNISTIC)
			level = IFNET_THROTTLE_OPPORTUNISTIC;
		else if (ifr->ifr_opportunistic.ifo_flags == 0)
			level = IFNET_THROTTLE_OFF;
		else
			result = EINVAL;

		if (result == 0)
			result = ifnet_set_throttle(ifp, level);
	} else if ((result = ifnet_get_throttle(ifp, &level)) == 0) {
		ifr->ifr_opportunistic.ifo_flags = 0;
		if (level == IFNET_THROTTLE_OPPORTUNISTIC) {
			ifr->ifr_opportunistic.ifo_flags |=
			    IFRIFOF_BLOCK_OPPORTUNISTIC;
		}
	}

	/*
	 * Return the count of current opportunistic connections
	 * over the interface.
	 */
	if (result == 0) {
		uint32_t flags = 0;
		flags |= (cmd == SIOCSIFOPPORTUNISTIC) ?
			INPCB_OPPORTUNISTIC_SETCMD : 0;
		flags |= (level == IFNET_THROTTLE_OPPORTUNISTIC) ? 
			INPCB_OPPORTUNISTIC_THROTTLEON : 0;
		ifr->ifr_opportunistic.ifo_inuse =
		    udp_count_opportunistic(ifp->if_index, flags) +
		    tcp_count_opportunistic(ifp->if_index, flags);
	}

	if (result == EALREADY)
		result = 0;

	return (result);
}

int
ifnet_get_throttle(struct ifnet *ifp, u_int32_t *level)
{
	struct ifclassq *ifq;
	int err = 0;

	if (!(ifp->if_eflags & IFEF_TXSTART))
		return (ENXIO);

	*level = IFNET_THROTTLE_OFF;

	ifq = &ifp->if_snd;
	IFCQ_LOCK(ifq);
	/* Throttling works only for IFCQ, not ALTQ instances */
	if (IFCQ_IS_ENABLED(ifq))
		IFCQ_GET_THROTTLE(ifq, *level, err);
	IFCQ_UNLOCK(ifq);

	return (err);
}

int
ifnet_set_throttle(struct ifnet *ifp, u_int32_t level)
{
	struct ifclassq *ifq;
	int err = 0;

	if (!(ifp->if_eflags & IFEF_TXSTART))
		return (ENXIO);

	ifq = &ifp->if_snd;

	switch (level) {
	case IFNET_THROTTLE_OFF:
	case IFNET_THROTTLE_OPPORTUNISTIC:
#if PF_ALTQ
		/* Throttling works only for IFCQ, not ALTQ instances */
		if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq)))
			return (ENXIO);
#endif /* PF_ALTQ */
		break;
	default:
		return (EINVAL);
	}

	IFCQ_LOCK(ifq);
	if (IFCQ_IS_ENABLED(ifq))
		IFCQ_SET_THROTTLE(ifq, level, err);
	IFCQ_UNLOCK(ifq);

	if (err == 0) {
		printf("%s: throttling level set to %d\n", if_name(ifp),
		    level);
		if (level == IFNET_THROTTLE_OFF)
			ifnet_start(ifp);
	}

	return (err);
}

errno_t
ifnet_getset_log(ifnet_t ifp, u_long cmd, struct ifreq *ifr,
    struct proc *p)
{
#pragma unused(p)
	errno_t result = 0;
	uint32_t flags;
	int level, category, subcategory;

	VERIFY(cmd == SIOCSIFLOG || cmd == SIOCGIFLOG);

	if (cmd == SIOCSIFLOG) {
		if ((result = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (result);

		level = ifr->ifr_log.ifl_level;
		if (level < IFNET_LOG_MIN || level > IFNET_LOG_MAX)
			result = EINVAL;

		flags = ifr->ifr_log.ifl_flags;
		if ((flags &= IFNET_LOGF_MASK) == 0)
			result = EINVAL;

		category = ifr->ifr_log.ifl_category;
		subcategory = ifr->ifr_log.ifl_subcategory;

		if (result == 0)
			result = ifnet_set_log(ifp, level, flags,
			    category, subcategory);
	} else {
		result = ifnet_get_log(ifp, &level, &flags, &category,
		    &subcategory);
		if (result == 0) {
			ifr->ifr_log.ifl_level = level;
			ifr->ifr_log.ifl_flags = flags;
			ifr->ifr_log.ifl_category = category;
			ifr->ifr_log.ifl_subcategory = subcategory;
		}
	}

	return (result);
}

int
ifnet_set_log(struct ifnet *ifp, int32_t level, uint32_t flags,
    int32_t category, int32_t subcategory)
{
	int err = 0;

	VERIFY(level >= IFNET_LOG_MIN && level <= IFNET_LOG_MAX);
	VERIFY(flags & IFNET_LOGF_MASK);

	/*
	 * The logging level applies to all facilities; make sure to
	 * update them all with the most current level.
	 */
	flags |= ifp->if_log.flags;

	if (ifp->if_output_ctl != NULL) {
		struct ifnet_log_params l;

		bzero(&l, sizeof (l));
		l.level = level;
		l.flags = flags;
		l.flags &= ~IFNET_LOGF_DLIL;
		l.category = category;
		l.subcategory = subcategory;

		/* Send this request to lower layers */
		if (l.flags != 0) {
			err = ifp->if_output_ctl(ifp, IFNET_CTL_SET_LOG,
			    sizeof (l), &l);
		}
	} else if ((flags & ~IFNET_LOGF_DLIL) && ifp->if_output_ctl == NULL) {
		/*
		 * If targeted to the lower layers without an output
		 * control callback registered on the interface, just
		 * silently ignore facilities other than ours.
		 */
		flags &= IFNET_LOGF_DLIL;
		if (flags == 0 && (!ifp->if_log.flags & IFNET_LOGF_DLIL))
			level = 0;
	}

	if (err == 0) {
		if ((ifp->if_log.level = level) == IFNET_LOG_DEFAULT)
			ifp->if_log.flags = 0;
		else
			ifp->if_log.flags |= flags;

		log(LOG_INFO, "%s: logging level set to %d flags=%b "
		    "arg=%b, category=%d subcategory=%d\n", if_name(ifp),
		    ifp->if_log.level, ifp->if_log.flags,
		    IFNET_LOGF_BITS, flags, IFNET_LOGF_BITS,
		    category, subcategory);
	}

	return (err);
}

int
ifnet_get_log(struct ifnet *ifp, int32_t *level, uint32_t *flags,
    int32_t *category, int32_t *subcategory)
{
	if (level != NULL)
		*level = ifp->if_log.level;
	if (flags != NULL)
		*flags = ifp->if_log.flags;
	if (category != NULL)
		*category = ifp->if_log.category;
	if (subcategory != NULL)
		*subcategory = ifp->if_log.subcategory;

	return (0);
}

int
ifnet_notify_address(struct ifnet *ifp, int af)
{
	struct ifnet_notify_address_params na;

#if PF
	(void) pf_ifaddr_hook(ifp);
#endif /* PF */

	if (ifp->if_output_ctl == NULL)
		return (EOPNOTSUPP);

	bzero(&na, sizeof (na));
	na.address_family = af;

	return (ifp->if_output_ctl(ifp, IFNET_CTL_NOTIFY_ADDRESS,
	    sizeof (na), &na));
}

errno_t
ifnet_flowid(struct ifnet *ifp, uint32_t *flowid)
{
	if (ifp == NULL || flowid == NULL) {
		return (EINVAL);
	} else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    !(ifp->if_refflags & IFRF_ATTACHED)) {
		return (ENXIO);
	}

	*flowid = ifp->if_flowhash;

	return (0);
}

errno_t
ifnet_disable_output(struct ifnet *ifp)
{
	int err;

	if (ifp == NULL) {
		return (EINVAL);
	} else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    !(ifp->if_refflags & IFRF_ATTACHED)) {
		return (ENXIO);
	}

	if ((err = ifnet_fc_add(ifp)) == 0) {
		lck_mtx_lock_spin(&ifp->if_start_lock);
		ifp->if_start_flags |= IFSF_FLOW_CONTROLLED;
		lck_mtx_unlock(&ifp->if_start_lock);
	}
	return (err);
}

errno_t
ifnet_enable_output(struct ifnet *ifp)
{
	if (ifp == NULL) {
		return (EINVAL);
	} else if (!(ifp->if_eflags & IFEF_TXSTART) ||
	    !(ifp->if_refflags & IFRF_ATTACHED)) {
		return (ENXIO);
	}

	ifnet_start_common(ifp, 1);
	return (0);
}

void
ifnet_flowadv(uint32_t flowhash)
{
	struct ifnet_fc_entry *ifce;
	struct ifnet *ifp;

	ifce = ifnet_fc_get(flowhash);
	if (ifce == NULL)
		return;

	VERIFY(ifce->ifce_ifp != NULL);
	ifp = ifce->ifce_ifp;

	/* flow hash gets recalculated per attach, so check */
	if (ifnet_is_attached(ifp, 1)) {
		if (ifp->if_flowhash == flowhash)
			(void) ifnet_enable_output(ifp);
		ifnet_decr_iorefcnt(ifp);
	}
	ifnet_fc_entry_free(ifce);
}

/*
 * Function to compare ifnet_fc_entries in ifnet flow control tree
 */
static inline int
ifce_cmp(const struct ifnet_fc_entry *fc1, const struct ifnet_fc_entry *fc2)
{
	return (fc1->ifce_flowhash - fc2->ifce_flowhash);
}

static int
ifnet_fc_add(struct ifnet *ifp)
{
	struct ifnet_fc_entry keyfc, *ifce;
	uint32_t flowhash;

	VERIFY(ifp != NULL && (ifp->if_eflags & IFEF_TXSTART));
	VERIFY(ifp->if_flowhash != 0);
	flowhash = ifp->if_flowhash;

	bzero(&keyfc, sizeof (keyfc));
	keyfc.ifce_flowhash = flowhash;

	lck_mtx_lock_spin(&ifnet_fc_lock);
	ifce = RB_FIND(ifnet_fc_tree, &ifnet_fc_tree, &keyfc);
	if (ifce != NULL && ifce->ifce_ifp == ifp) {
		/* Entry is already in ifnet_fc_tree, return */
		lck_mtx_unlock(&ifnet_fc_lock);
		return (0);
	}

	if (ifce != NULL) {
		/*
		 * There is a different fc entry with the same flow hash
		 * but different ifp pointer.  There can be a collision
		 * on flow hash but the probability is low.  Let's just
		 * avoid adding a second one when there is a collision.
		 */
		lck_mtx_unlock(&ifnet_fc_lock);
		return (EAGAIN);
	}

	/* become regular mutex */
	lck_mtx_convert_spin(&ifnet_fc_lock);

	ifce = zalloc_noblock(ifnet_fc_zone);
	if (ifce == NULL) {
		/* memory allocation failed */
		lck_mtx_unlock(&ifnet_fc_lock);
		return (ENOMEM);
	}
	bzero(ifce, ifnet_fc_zone_size);

	ifce->ifce_flowhash = flowhash;
	ifce->ifce_ifp = ifp;

	RB_INSERT(ifnet_fc_tree, &ifnet_fc_tree, ifce);
	lck_mtx_unlock(&ifnet_fc_lock);
	return (0);
}

static struct ifnet_fc_entry *
ifnet_fc_get(uint32_t flowhash)
{
	struct ifnet_fc_entry keyfc, *ifce;
	struct ifnet *ifp;

	bzero(&keyfc, sizeof (keyfc));
	keyfc.ifce_flowhash = flowhash;

	lck_mtx_lock_spin(&ifnet_fc_lock);
	ifce = RB_FIND(ifnet_fc_tree, &ifnet_fc_tree, &keyfc);
	if (ifce == NULL) {
		/* Entry is not present in ifnet_fc_tree, return */
		lck_mtx_unlock(&ifnet_fc_lock);
		return (NULL);
	}

	RB_REMOVE(ifnet_fc_tree, &ifnet_fc_tree, ifce);

	VERIFY(ifce->ifce_ifp != NULL);
	ifp = ifce->ifce_ifp;

	/* become regular mutex */
	lck_mtx_convert_spin(&ifnet_fc_lock);

	if (!ifnet_is_attached(ifp, 0)) {
		/*
		 * This ifp is not attached or in the process of being
		 * detached; just don't process it.
		 */
		ifnet_fc_entry_free(ifce);
		ifce = NULL;
	}
	lck_mtx_unlock(&ifnet_fc_lock);

	return (ifce);
}

static void
ifnet_fc_entry_free(struct ifnet_fc_entry *ifce)
{
	zfree(ifnet_fc_zone, ifce);
}

static uint32_t
ifnet_calc_flowhash(struct ifnet *ifp)
{
	struct ifnet_flowhash_key fh __attribute__((aligned(8)));
	uint32_t flowhash = 0;

	if (ifnet_flowhash_seed == 0)
		ifnet_flowhash_seed = RandomULong();

	bzero(&fh, sizeof (fh));

	(void) snprintf(fh.ifk_name, sizeof (fh.ifk_name), "%s", ifp->if_name);
	fh.ifk_unit = ifp->if_unit;
	fh.ifk_flags = ifp->if_flags;
	fh.ifk_eflags = ifp->if_eflags;
	fh.ifk_capabilities = ifp->if_capabilities;
	fh.ifk_capenable = ifp->if_capenable;
	fh.ifk_output_sched_model = ifp->if_output_sched_model;
	fh.ifk_rand1 = RandomULong();
	fh.ifk_rand2 = RandomULong();

try_again:
	flowhash = net_flowhash(&fh, sizeof (fh), ifnet_flowhash_seed);
	if (flowhash == 0) {
		/* try to get a non-zero flowhash */
		ifnet_flowhash_seed = RandomULong();
		goto try_again;
	}

	return (flowhash);
}

static void
dlil_output_cksum_dbg(struct ifnet *ifp, struct mbuf *m, uint32_t hoff,
    protocol_family_t pf)
{
#pragma unused(ifp)
	uint32_t did_sw;

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_FINALIZE_FORCED) ||
	    (m->m_pkthdr.csum_flags & (CSUM_TSO_IPV4|CSUM_TSO_IPV6)))
		return;

	switch (pf) {
	case PF_INET:
		did_sw = in_finalize_cksum(m, hoff, m->m_pkthdr.csum_flags);
		if (did_sw & CSUM_DELAY_IP)
			hwcksum_dbg_finalized_hdr++;
		if (did_sw & CSUM_DELAY_DATA)
			hwcksum_dbg_finalized_data++;
		break;
#if INET6
	case PF_INET6:
		/*
		 * Checksum offload should not have been enabled when
		 * extension headers exist; that also means that we
		 * cannot force-finalize packets with extension headers.
		 * Indicate to the callee should it skip such case by
		 * setting optlen to -1.
		 */
		did_sw = in6_finalize_cksum(m, hoff, -1, -1,
		    m->m_pkthdr.csum_flags);
		if (did_sw & CSUM_DELAY_IPV6_DATA)
			hwcksum_dbg_finalized_data++;
		break;
#endif /* INET6 */
	default:
		return;
	}
}

static void
dlil_input_cksum_dbg(struct ifnet *ifp, struct mbuf *m, char *frame_header,
    protocol_family_t pf)
{
	uint16_t sum;
	uint32_t hlen;

	if (frame_header == NULL ||
	    frame_header < (char *)mbuf_datastart(m) ||
	    frame_header > (char *)m->m_data) {
		printf("%s: frame header pointer 0x%llx out of range "
		    "[0x%llx,0x%llx] for mbuf 0x%llx\n", if_name(ifp),
		    (uint64_t)VM_KERNEL_ADDRPERM(frame_header),
		    (uint64_t)VM_KERNEL_ADDRPERM(mbuf_datastart(m)),
		    (uint64_t)VM_KERNEL_ADDRPERM(m->m_data),
		    (uint64_t)VM_KERNEL_ADDRPERM(m));
		return;
	}
	hlen = (m->m_data - frame_header);

	switch (pf) {
	case PF_INET:
#if INET6
	case PF_INET6:
#endif /* INET6 */
		break;
	default:
		return;
	}

	/*
	 * Force partial checksum offload; useful to simulate cases
	 * where the hardware does not support partial checksum offload,
	 * in order to validate correctness throughout the layers above.
	 */
	if (hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED) {
		uint32_t foff = hwcksum_dbg_partial_rxoff_forced;

		if (foff > (uint32_t)m->m_pkthdr.len)
			return;

		m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;

		/* Compute 16-bit 1's complement sum from forced offset */
		sum = m_sum16(m, foff, (m->m_pkthdr.len - foff));

		m->m_pkthdr.csum_flags |= (CSUM_DATA_VALID | CSUM_PARTIAL);
		m->m_pkthdr.csum_rx_val = sum;
		m->m_pkthdr.csum_rx_start = (foff + hlen);

		hwcksum_dbg_partial_forced++;
		hwcksum_dbg_partial_forced_bytes += m->m_pkthdr.len;
	}

	/*
	 * Partial checksum offload verification (and adjustment);
	 * useful to validate and test cases where the hardware
	 * supports partial checksum offload.
	 */
	if ((m->m_pkthdr.csum_flags &
	    (CSUM_DATA_VALID | CSUM_PARTIAL | CSUM_PSEUDO_HDR)) ==
	    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
		uint32_t rxoff;

		/* Start offset must begin after frame header */
		rxoff = m->m_pkthdr.csum_rx_start;
		if (hlen > rxoff) {
			hwcksum_dbg_bad_rxoff++;
			if (dlil_verbose) {
				printf("%s: partial cksum start offset %d "
				    "is less than frame header length %d for "
				    "mbuf 0x%llx\n", if_name(ifp), rxoff, hlen,
				    (uint64_t)VM_KERNEL_ADDRPERM(m));
			}
			return;
		}
		rxoff -=hlen;

		if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED)) {
			/*
			 * Compute the expected 16-bit 1's complement sum;
			 * skip this if we've already computed it above
			 * when partial checksum offload is forced.
			 */
			sum = m_sum16(m, rxoff, (m->m_pkthdr.len - rxoff));

			/* Hardware or driver is buggy */
			if (sum != m->m_pkthdr.csum_rx_val) {
				hwcksum_dbg_bad_cksum++;
				if (dlil_verbose) {
					printf("%s: bad partial cksum value "
					    "0x%x (expected 0x%x) for mbuf "
					    "0x%llx [rx_start %d]\n",
					    if_name(ifp),
					    m->m_pkthdr.csum_rx_val, sum,
					    (uint64_t)VM_KERNEL_ADDRPERM(m),
					    m->m_pkthdr.csum_rx_start);
				}
				return;
			}
		}
		hwcksum_dbg_verified++;

		/*
		 * This code allows us to emulate various hardwares that
		 * perform 16-bit 1's complement sum beginning at various
		 * start offset values.
		 */
		if (hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_RXOFF_ADJ) {
			uint32_t aoff = hwcksum_dbg_partial_rxoff_adj;

			if (aoff == rxoff || aoff > (uint32_t)m->m_pkthdr.len)
				return;

			sum = m_adj_sum16(m, rxoff, aoff, sum);

			m->m_pkthdr.csum_rx_val = sum;
			m->m_pkthdr.csum_rx_start = (aoff + hlen);

			hwcksum_dbg_adjusted++;
		}
	}
}

static int
sysctl_hwcksum_dbg_mode SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = hwcksum_dbg_mode;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (hwcksum_dbg == 0)
		return (ENODEV);

	if ((i & ~HWCKSUM_DBG_MASK) != 0)
		return (EINVAL);

	hwcksum_dbg_mode = (i & HWCKSUM_DBG_MASK);

	return (err);
}

static int
sysctl_hwcksum_dbg_partial_rxoff_forced SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = hwcksum_dbg_partial_rxoff_forced;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED))
		return (ENODEV);

	hwcksum_dbg_partial_rxoff_forced = i;

	return (err);
}

static int
sysctl_hwcksum_dbg_partial_rxoff_adj SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = hwcksum_dbg_partial_rxoff_adj;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL)
		return (err);

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_RXOFF_ADJ))
		return (ENODEV);

	hwcksum_dbg_partial_rxoff_adj = i;

	return (err);
}

#if DEBUG
/* Blob for sum16 verification */
static uint8_t sumdata[] = {
	0x1f, 0x8b, 0x08, 0x08, 0x4c, 0xe5, 0x9a, 0x4f, 0x00, 0x03,
	0x5f, 0x00, 0x5d, 0x91, 0x41, 0x4e, 0xc4, 0x30, 0x0c, 0x45,
	0xf7, 0x9c, 0xc2, 0x07, 0x18, 0xf5, 0x0e, 0xb0, 0xe2, 0x00,
	0x48, 0x88, 0xa5, 0xdb, 0xba, 0x49, 0x34, 0x69, 0xdc, 0x71,
	0x92, 0xa9, 0xc2, 0x8a, 0x6b, 0x70, 0x3d, 0x4e, 0x82, 0x93,
	0xb4, 0x08, 0xd8, 0xc5, 0xb1, 0xfd, 0xff, 0xb3, 0xfd, 0x4c,
	0x42, 0x5f, 0x1f, 0x9f, 0x11, 0x12, 0x43, 0xb2, 0x04, 0x93,
	0xe0, 0x7b, 0x01, 0x0e, 0x14, 0x07, 0x78, 0xd1, 0x78, 0x75,
	0x71, 0x71, 0xe9, 0x08, 0x84, 0x46, 0xf2, 0xc7, 0x3b, 0x09,
	0xe7, 0xd1, 0xd3, 0x8a, 0x57, 0x92, 0x33, 0xcd, 0x39, 0xcc,
	0xb0, 0x91, 0x89, 0xe0, 0x42, 0x53, 0x8b, 0xb7, 0x8c, 0x42,
	0x60, 0xd9, 0x9f, 0x7a, 0x55, 0x19, 0x76, 0xcb, 0x10, 0x49,
	0x35, 0xac, 0x0b, 0x5a, 0x3c, 0xbb, 0x65, 0x51, 0x8c, 0x90,
	0x7c, 0x69, 0x45, 0x45, 0x81, 0xb4, 0x2b, 0x70, 0x82, 0x85,
	0x55, 0x91, 0x17, 0x90, 0xdc, 0x14, 0x1e, 0x35, 0x52, 0xdd,
	0x02, 0x16, 0xef, 0xb5, 0x40, 0x89, 0xe2, 0x46, 0x53, 0xad,
	0x93, 0x6e, 0x98, 0x30, 0xe5, 0x08, 0xb7, 0xcc, 0x03, 0xbc,
	0x71, 0x86, 0x09, 0x43, 0x0d, 0x52, 0xf5, 0xa2, 0xf5, 0xa2,
	0x56, 0x11, 0x8d, 0xa8, 0xf5, 0xee, 0x92, 0x3d, 0xfe, 0x8c,
	0x67, 0x71, 0x8b, 0x0e, 0x2d, 0x70, 0x77, 0xbe, 0xbe, 0xea,
	0xbf, 0x9a, 0x8d, 0x9c, 0x53, 0x53, 0xe5, 0xe0, 0x4b, 0x87,
	0x85, 0xd2, 0x45, 0x95, 0x30, 0xc1, 0xcc, 0xe0, 0x74, 0x54,
	0x13, 0x58, 0xe8, 0xe8, 0x79, 0xa2, 0x09, 0x73, 0xa4, 0x0e,
	0x39, 0x59, 0x0c, 0xe6, 0x9c, 0xb2, 0x4f, 0x06, 0x5b, 0x8e,
	0xcd, 0x17, 0x6c, 0x5e, 0x95, 0x4d, 0x70, 0xa2, 0x0a, 0xbf,
	0xa3, 0xcc, 0x03, 0xbc, 0x5a, 0xe7, 0x75, 0x06, 0x5e, 0x75,
	0xef, 0x58, 0x8e, 0x15, 0xd1, 0x0a, 0x18, 0xff, 0xdd, 0xe6,
	0x02, 0x3b, 0xb5, 0xb4, 0xa1, 0xe0, 0x72, 0xfc, 0xe3, 0xab,
	0x07, 0xe0, 0x4d, 0x65, 0xea, 0x92, 0xeb, 0xf2, 0x7b, 0x17,
	0x05, 0xce, 0xc6, 0xf6, 0x2b, 0xbb, 0x70, 0x3d, 0x00, 0x95,
	0xe0, 0x07, 0x52, 0x3b, 0x58, 0xfc, 0x7c, 0x69, 0x4d, 0xe9,
	0xf7, 0xa9, 0x66, 0x1e, 0x1e, 0xbe, 0x01, 0x69, 0x98, 0xfe,
	0xc8, 0x28, 0x02, 0x00, 0x00
};

/* Precomputed 16-bit 1's complement sums for various spans of the above data */
static struct {
	int		len;
	uint16_t	sum;
} sumtbl[] = {
	{	11,	0xcb6d	},
	{	20,	0x20dd	},
	{	27,	0xbabd	},
	{	32,	0xf3e8	},
	{	37,	0x197d	},
	{	43,	0x9eae	},
	{	64,	0x4678	},
	{	127,	0x9399	},
	{	256,	0xd147	},
	{	325,	0x0358	}
};
#define	SUMTBL_MAX	((int)sizeof (sumtbl) / (int)sizeof (sumtbl[0]))

static void
dlil_verify_sum16(void)
{
	struct mbuf *m;
	uint8_t *buf;
	int n;

	/* Make sure test data plus extra room for alignment fits in cluster */
	_CASSERT((sizeof (sumdata) + (sizeof (uint64_t) * 2)) <= MCLBYTES);

	m = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
	MH_ALIGN(m, sizeof (uint32_t));		/* 32-bit starting alignment */
	buf = mtod(m, uint8_t *);		/* base address */

	for (n = 0; n < SUMTBL_MAX; n++) {
		uint16_t len = sumtbl[n].len;
		int i;

		/* Verify for all possible alignments */
		for (i = 0; i < (int)sizeof (uint64_t); i++) {
			uint16_t sum;
			uint8_t *c;

			/* Copy over test data to mbuf */
			VERIFY(len <= sizeof (sumdata));
			c = buf + i;
			bcopy(sumdata, c, len);

			/* Zero-offset test (align by data pointer) */
			m->m_data = (caddr_t)c;
			m->m_len = len;
			sum = m_sum16(m, 0, len);

			/* Something is horribly broken; stop now */
			if (sum != sumtbl[n].sum) {
				panic("%s: broken m_sum16 for len=%d align=%d "
				    "sum=0x%04x [expected=0x%04x]\n", __func__,
				    len, i, sum, sumtbl[n].sum);
				/* NOTREACHED */
			}

			/* Alignment test by offset (fixed data pointer) */
			m->m_data = (caddr_t)buf;
			m->m_len = i + len;
			sum = m_sum16(m, i, len);

			/* Something is horribly broken; stop now */
			if (sum != sumtbl[n].sum) {
				panic("%s: broken m_sum16 for len=%d offset=%d "
				    "sum=0x%04x [expected=0x%04x]\n", __func__,
				    len, i, sum, sumtbl[n].sum);
				/* NOTREACHED */
			}
#if INET
			/* Simple sum16 contiguous buffer test by aligment */
			sum = b_sum16(c, len);

			/* Something is horribly broken; stop now */
			if (sum != sumtbl[n].sum) {
				panic("%s: broken b_sum16 for len=%d align=%d "
				    "sum=0x%04x [expected=0x%04x]\n", __func__,
				    len, i, sum, sumtbl[n].sum);
				/* NOTREACHED */
			}
#endif /* INET */
		}
	}
	m_freem(m);

	printf("DLIL: SUM16 self-tests PASSED\n");
}
#endif /* DEBUG */

#define	CASE_STRINGIFY(x) case x: return #x

__private_extern__ const char *
dlil_kev_dl_code_str(u_int32_t event_code)
{
	switch (event_code) {
	CASE_STRINGIFY(KEV_DL_SIFFLAGS);
	CASE_STRINGIFY(KEV_DL_SIFMETRICS);
	CASE_STRINGIFY(KEV_DL_SIFMTU);
	CASE_STRINGIFY(KEV_DL_SIFPHYS);
	CASE_STRINGIFY(KEV_DL_SIFMEDIA);
	CASE_STRINGIFY(KEV_DL_SIFGENERIC);
	CASE_STRINGIFY(KEV_DL_ADDMULTI);
	CASE_STRINGIFY(KEV_DL_DELMULTI);
	CASE_STRINGIFY(KEV_DL_IF_ATTACHED);
	CASE_STRINGIFY(KEV_DL_IF_DETACHING);
	CASE_STRINGIFY(KEV_DL_IF_DETACHED);
	CASE_STRINGIFY(KEV_DL_LINK_OFF);
	CASE_STRINGIFY(KEV_DL_LINK_ON);
	CASE_STRINGIFY(KEV_DL_PROTO_ATTACHED);
	CASE_STRINGIFY(KEV_DL_PROTO_DETACHED);
	CASE_STRINGIFY(KEV_DL_LINK_ADDRESS_CHANGED);
	CASE_STRINGIFY(KEV_DL_WAKEFLAGS_CHANGED);
	CASE_STRINGIFY(KEV_DL_IF_IDLE_ROUTE_REFCNT);
	CASE_STRINGIFY(KEV_DL_IFCAP_CHANGED);
	CASE_STRINGIFY(KEV_DL_LINK_QUALITY_METRIC_CHANGED);
	CASE_STRINGIFY(KEV_DL_NODE_PRESENCE);
	CASE_STRINGIFY(KEV_DL_NODE_ABSENCE);
	CASE_STRINGIFY(KEV_DL_MASTER_ELECTED);
	CASE_STRINGIFY(KEV_DL_ISSUES);
	CASE_STRINGIFY(KEV_DL_IFDELEGATE_CHANGED);
	default:
		break;
	}
	return ("");
}
