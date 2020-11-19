/*
 * Copyright (c) 2018-2019 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#if !TCPDEBUG
#define TCPSTATES
#endif /* TCPDEBUG */
#include <netinet/tcp_fsm.h>

#include <netinet/tcp_log.h>

SYSCTL_NODE(_net_inet_tcp, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "TCP logs");

static int tcp_log_level_info = 0;
SYSCTL_INT(_net_inet_tcp_log, OID_AUTO, level_info,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_level_info, 0, "");

#if (DEVELOPMENT || DEBUG)
#if defined(XNU_TARGET_OS_OSX)
/*
 * Log less on macOS as sockets are more prevalent than channels
 */
#define TCP_LOG_ENABLE_DEFAULT \
    (TLEF_CONNECTION | TLEF_DST_LOCAL | TLEF_DST_GW | \
    TLEF_DROP_NECP)
#else /* XNU_TARGET_OS_OSX */
#define TCP_LOG_ENABLE_DEFAULT \
    (TLEF_CONNECTION | TLEF_DST_LOCAL | TLEF_DST_GW | \
    TLEF_DROP_NECP | TLEF_DROP_PCB | TLEF_DROP_PKT | TLEF_THF_SYN)
#endif /* XNU_TARGET_OS_OSX */
#else /* (DEVELOPMENT || DEBUG) */
#define TCP_LOG_ENABLE_DEFAULT 0
#endif /* (DEVELOPMENT || DEBUG) */

uint32_t tcp_log_enable_flags = TCP_LOG_ENABLE_DEFAULT;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, enable,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_enable_flags, 0, "");

/*
 * The following is a help to describe the values of the flags
 */
#define X(name, value, description, ...) #description ":" #value " "
SYSCTL_STRING(_net_inet_tcp_log, OID_AUTO, enable_usage, CTLFLAG_RD | CTLFLAG_LOCKED,
    TCP_ENABLE_FLAG_LIST, 0, "");
#undef X

/*
 * Values for tcp_log_port when TLEF_RTT is enabled:
 *  0: log all TCP connections regardless of the port numbers
 *  1 to 65535: log TCP connections with this local or foreign port
 *  other: do not log (same effect as as tcp_log_rtt == 0)
 */
uint32_t tcp_log_port = 0;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rtt_port, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_log_port, 0, "");

/*
 * Values for tcp_log_thflags_if_family when TLEF_THF_XXX is enabled:
 *  0: all interfaces
 *  other: only for interfaces with the corresponding interface functional type
 */
#if (DEVELOPMENT || DEBUG)
#define TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT IFNET_FAMILY_IPSEC
#else /* (DEVELOPMENT || DEBUG) */
#define TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT 0
#endif /* (DEVELOPMENT || DEBUG) */

static uint32_t tcp_log_thflags_if_family = TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, thflags_if_family,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_thflags_if_family, 0, "");

#if (DEVELOPMENT || DEBUG)
#define TCP_LOG_PRIVACY_DEFAULT 0
#else
#define TCP_LOG_PRIVACY_DEFAULT 1
#endif /* (DEVELOPMENT || DEBUG) */

int tcp_log_privacy = TCP_LOG_PRIVACY_DEFAULT;
SYSCTL_INT(_net_inet_tcp_log, OID_AUTO, privacy,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_privacy, 0, "");

#define TCP_LOG_RATE_LIMIT 600
static unsigned int tcp_log_rate_limit = TCP_LOG_RATE_LIMIT;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rate_limit,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_rate_limit, 0, "");

/* 1 minute by default */
#define TCP_LOG_RATE_DURATION 60
static unsigned int tcp_log_rate_duration = TCP_LOG_RATE_DURATION;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rate_duration,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_rate_duration, 0, "");

static unsigned long tcp_log_rate_max = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_max,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_max, "");

static unsigned long tcp_log_rate_exceeded_total = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_exceeded_total,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_exceeded_total, "");

static unsigned long tcp_log_rate_current = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_current,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_current, "");

static bool tcp_log_rate_exceeded_logged = false;

static uint64_t tcp_log_current_period = 0;

#define ADDRESS_STR_LEN (MAX_IPv6_STR_LEN + 6)

#define TCP_LOG_COMMON_FMT \
	    "[%s:%u<->%s:%u] " \
	    "interface: %s " \
	    "(skipped: %lu)\n"

#define TCP_LOG_COMMON_ARGS \
	laddr_buf, ntohs(local_port), faddr_buf, ntohs(foreign_port), \
	    ifp != NULL ? if_name(ifp) : "", \
	    tcp_log_rate_exceeded_total

#define TCP_LOG_COMMON_PCB_FMT \
	TCP_LOG_COMMON_FMT \
	"t_state: %s " \
	"process: %s:%u "

#define TCP_LOG_COMMON_PCB_ARGS \
	TCP_LOG_COMMON_ARGS, \
	tcpstates[tp->t_state], \
	inp->inp_last_proc_name, so->last_pid

/*
 * Returns true when above the rate limit
 */
static bool
tcp_log_is_rate_limited(void)
{
	uint64_t current_net_period = net_uptime();

	/* When set to zero it means to reset to default */
	if (tcp_log_rate_duration == 0) {
		tcp_log_rate_duration = TCP_LOG_RATE_DURATION;
	}
	if (tcp_log_rate_limit == 0) {
		tcp_log_rate_duration = TCP_LOG_RATE_LIMIT;
	}

	if (current_net_period > tcp_log_current_period + tcp_log_rate_duration) {
		if (tcp_log_rate_current > tcp_log_rate_max) {
			tcp_log_rate_max = tcp_log_rate_current;
		}
		tcp_log_current_period = current_net_period;
		tcp_log_rate_current = 0;
		tcp_log_rate_exceeded_logged = false;
	}

	tcp_log_rate_current += 1;

	if (tcp_log_rate_current > (unsigned long) tcp_log_rate_limit) {
		tcp_log_rate_exceeded_total += 1;
		return true;
	}

	return false;
}

static void
tcp_log_inp_addresses(struct inpcb *inp, char *lbuf, socklen_t lbuflen, char *fbuf, socklen_t fbuflen)
{
	/*
	 * Ugly but %{private} does not work in the kernel version of os_log()
	 */
	if (tcp_log_privacy != 0) {
		if (inp->inp_vflag & INP_IPV6) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		}
	} else if (inp->inp_vflag & INP_IPV6) {
		inet_ntop(AF_INET6, (void *)&inp->in6p_laddr, lbuf, lbuflen);
		inet_ntop(AF_INET6, (void *)&inp->in6p_faddr, fbuf, fbuflen);
	} else {
		inet_ntop(AF_INET, (void *)&inp->inp_laddr.s_addr, lbuf, lbuflen);
		inet_ntop(AF_INET, (void *)&inp->inp_faddr.s_addr, fbuf, fbuflen);
	}
}

void
tcp_log_rtt_info(const char *func_name, int line_no, struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	os_log(OS_LOG_DEFAULT,
	    "tcp_rtt_info (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "rttcur: %u ms srtt: %u ms rttvar: %u ms rttmin: %u ms rxtcur: %u rxtshift: %u",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS,
	    tp->t_rttcur, tp->t_srtt >> TCP_RTT_SHIFT,
	    tp->t_rttvar >> TCP_RTTVAR_SHIFT,
	    tp->t_rttmin, tp->t_rxtcur, tp->t_rxtshift);
}

void
tcp_log_rt_rtt(const char *func_name, int line_no, struct tcpcb *tp,
    struct rtentry *rt)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	/*
	 * Log RTT values in milliseconds
	 */
	os_log(OS_LOG_DEFAULT,
	    "tcp_rt_rtt (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "rt_rmx: RTV_RTT: %d ms rtt: %u ms rttvar: %u ms",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS,
	    (rt->rt_rmx.rmx_locks & RTV_RTT),
	    rt->rt_rmx.rmx_rtt / (RTM_RTTUNIT / TCP_RETRANSHZ),
	    rt->rt_rmx.rmx_rttvar / (RTM_RTTUNIT / TCP_RETRANSHZ));
}

void
tcp_log_rtt_change(const char *func_name, int line_no, struct tcpcb *tp,
    int old_srtt, int old_rttvar)
{
	int srtt_diff;
	int rttvar_diff;

	srtt_diff = ABS(tp->t_srtt  - old_srtt) >> TCP_RTT_SHIFT;
	rttvar_diff =
	    ABS((tp->t_rttvar - old_rttvar) >> TCP_RTTVAR_SHIFT);
	if (srtt_diff >= 1000 || rttvar_diff >= 500) {
		struct inpcb *inp = tp->t_inpcb;
		struct socket *so = inp->inp_socket;
		struct ifnet *ifp;
		char laddr_buf[ADDRESS_STR_LEN];
		char faddr_buf[ADDRESS_STR_LEN];
		in_port_t local_port = inp->inp_lport;
		in_port_t foreign_port = inp->inp_fport;

		/* Do not log too much */
		if (tcp_log_is_rate_limited()) {
			return;
		}

		ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
		    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

		tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

		os_log(OS_LOG_DEFAULT,
		    "tcp_rtt_change (%s:%d) "
		    TCP_LOG_COMMON_PCB_FMT
		    "srtt: %u ms old_rtt: %u ms "
		    "rttvar: %u old_rttvar: %u ms ",
		    func_name, line_no,
		    TCP_LOG_COMMON_PCB_ARGS,
		    tp->t_srtt >> TCP_RTT_SHIFT,
		    old_srtt >> TCP_RTT_SHIFT,
		    tp->t_rttvar >> TCP_RTTVAR_SHIFT,
		    old_rttvar >> TCP_RTTVAR_SHIFT);
	}
}

void
tcp_log_keepalive(const char *func_name, int line_no, struct tcpcb *tp,
    int32_t idle_time)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	os_log(OS_LOG_DEFAULT,
	    "tcp_keepalive (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "snd_una: %u snd_max: %u "
	    "SO_KA: %d RSTALL: %d TFOPRB: %d idle_time: %u "
	    "KIDLE: %d KINTV: %d KCNT: %d",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS,
	    tp->snd_una, tp->snd_max,
	    tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE,
	    tp->t_flagsext & TF_DETECT_READSTALL,
	    tp->t_tfo_probe_state == TFO_PROBE_PROBING,
	    idle_time,
	    TCP_CONN_KEEPIDLE(tp), TCP_CONN_KEEPINTVL(tp),
	    TCP_CONN_KEEPCNT(tp));
}


void
tcp_log_connection(struct tcpcb *tp, const char *event, int error)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL || event == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_CONNECT_FMT \
	    "tcp %s: " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "rtt: %u.%u ms " \
	    "rttvar: %u.%u ms " \
	    "error: %d " \
	    "so_error: %d " \
	    "svc/tc: %u"

#define TCP_LOG_CONNECT_ARGS \
	    event, \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    tp->t_srtt >> TCP_RTT_SHIFT, tp->t_srtt - ((tp->t_srtt >> TCP_RTT_SHIFT) << TCP_RTT_SHIFT), \
	    tp->t_rttvar >> TCP_RTTVAR_SHIFT, tp->t_rttvar - ((tp->t_rttvar >> TCP_RTTVAR_SHIFT) << TCP_RTTVAR_SHIFT), \
	    error, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class

	if (so->so_head == NULL) {
		if (tcp_log_level_info == 0) {
			os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT,
			    TCP_LOG_CONNECT_ARGS);
		} else {
			os_log_info(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT,
			    TCP_LOG_CONNECT_ARGS);
		}
	} else {
#define TCP_LOG_CONN_Q_FMT \
	"so_qlimit: %d "\
	"so_qlen: %d "\
	"so_incqlen: %d "

#define TCP_LOG_CONN_Q_ARGS \
	so->so_head->so_qlimit, \
	so->so_head->so_qlen, \
	so->so_head->so_incqlen

		if (tcp_log_level_info == 0) {
			os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT "\n" TCP_LOG_CONN_Q_FMT,
			    TCP_LOG_CONNECT_ARGS, TCP_LOG_CONN_Q_ARGS);
		} else {
			os_log_info(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT "\n" TCP_LOG_CONN_Q_FMT,
			    TCP_LOG_CONNECT_ARGS, TCP_LOG_CONN_Q_ARGS);
		}
#undef TCP_LOG_CONN_Q_FMT
#undef TCP_LOG_CONN_Q_ARGS
	}
#undef TCP_LOG_CONNECT_FMT
#undef TCP_LOG_CONNECT_ARGS
}

void
tcp_log_listen(struct tcpcb *tp, int error)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_LISTEN_FMT \
	    "tcp listen: " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "so_qlimit: %d "\
	    "error: %d " \
	    "so_error: %d " \
	    "svc/tc: %u"

#define TCP_LOG_LISTEN_ARGS \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    so->so_qlimit, \
	    error, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class

	if (tcp_log_level_info == 0) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_LISTEN_FMT,
		    TCP_LOG_LISTEN_ARGS);
	} else {
		os_log_info(OS_LOG_DEFAULT, TCP_LOG_LISTEN_FMT,
		    TCP_LOG_LISTEN_ARGS);
	}
#undef TCP_LOG_LISTEN_FMT
#undef TCP_LOG_LISTEN_ARGS
}

void
tcp_log_connection_summary(struct tcpcb *tp)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	uint32_t conntime = 0;
	uint32_t duration = 0;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	/* Make sure the summary is logged once */
	if (tp->t_flagsext & TF_LOGGED_CONN_SUMMARY) {
		return;
	}
	tp->t_flagsext |= TF_LOGGED_CONN_SUMMARY;

	/*
	 * t_connect_time is the time when the connection started on
	 * the first SYN.
	 *
	 * t_starttime is when the three way handshake was completed.
	 */
	if (tp->t_connect_time > 0) {
		duration = tcp_now - tp->t_connect_time;

		if (tp->t_starttime > 0) {
			conntime = tp->t_starttime - tp->t_connect_time;
		}
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_CONNECTION_SUMMARY_FMT \
	    "tcp_connection_summary " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "Duration: %u.%u sec " \
	    "Conn_Time: %u.%u sec " \
	    "syn rxmit: %u\n" \
	    "bytes in/out: %llu/%llu " \
	    "pkts in/out: %llu/%llu " \
	    "rtt: %u.%u ms " \
	    "rttvar: %u.%u ms " \
	    "pkt rxmit: %u " \
	    "ooo pkts: %u dup bytes in: %u ACKs delayed: %u delayed ACKs sent: %u " \
	    "so_error: %d " \
	    "svc/tc: %u"

#define TCP_LOG_CONNECTION_SUMMARY_ARGS \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    duration / TCP_RETRANSHZ, duration % TCP_RETRANSHZ, \
	    conntime / TCP_RETRANSHZ, conntime % TCP_RETRANSHZ,  \
	    tp->t_stat.synrxtshift, \
	    inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	    inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	    tp->t_srtt >> TCP_RTT_SHIFT, tp->t_srtt - ((tp->t_srtt >> TCP_RTT_SHIFT) << TCP_RTT_SHIFT), \
	    tp->t_rttvar >> TCP_RTTVAR_SHIFT, tp->t_rttvar - ((tp->t_rttvar >> TCP_RTTVAR_SHIFT) << TCP_RTTVAR_SHIFT), \
	    tp->t_stat.rxmitpkts, \
	    tp->t_rcvoopack, tp->t_stat.rxduplicatebytes, tp->t_stat.acks_delayed, tp->t_stat.delayed_acks_sent, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class

	if (tcp_log_level_info == 0) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECTION_SUMMARY_FMT,
		    TCP_LOG_CONNECTION_SUMMARY_ARGS);
	} else {
		os_log_info(OS_LOG_DEFAULT, TCP_LOG_CONNECTION_SUMMARY_FMT,
		    TCP_LOG_CONNECTION_SUMMARY_ARGS);
	}
#undef TCP_LOG_CONNECTION_SUMMARY_FMT
#undef TCP_LOG_CONNECTION_SUMMARY_ARGS
}

static bool
tcp_log_pkt_addresses(void *hdr, struct tcphdr *th, bool outgoing,
    char *lbuf, socklen_t lbuflen, char *fbuf, socklen_t fbuflen)
{
	bool isipv6;
	uint8_t thflags;

	isipv6 = (((struct ip *)hdr)->ip_v == 6);
	thflags = th->th_flags;

	if (isipv6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)hdr;

		if (memcmp(&ip6->ip6_src, &in6addr_loopback, sizeof(struct in6_addr)) == 0 ||
		    memcmp(&ip6->ip6_dst, &in6addr_loopback, sizeof(struct in6_addr)) == 0) {
			if (!(tcp_log_enable_flags & TLEF_DST_LOOPBACK)) {
				return false;
			}
		}

		if (tcp_log_privacy != 0) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else if (outgoing) {
			inet_ntop(AF_INET6, &ip6->ip6_src, lbuf, lbuflen);
			inet_ntop(AF_INET6, &ip6->ip6_dst, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET6, &ip6->ip6_dst, lbuf, lbuflen);
			inet_ntop(AF_INET6, &ip6->ip6_src, fbuf, fbuflen);
		}
	} else {
		struct ip *ip = (struct ip *)hdr;

		if (ntohl(ip->ip_src.s_addr) == INADDR_LOOPBACK ||
		    ntohl(ip->ip_dst.s_addr) == INADDR_LOOPBACK) {
			if (!(tcp_log_enable_flags & TLEF_DST_LOOPBACK)) {
				return false;
			}
		}

		if (tcp_log_privacy != 0) {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		} else if (outgoing) {
			inet_ntop(AF_INET, (void *)&ip->ip_src.s_addr, lbuf, lbuflen);
			inet_ntop(AF_INET, (void *)&ip->ip_dst.s_addr, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET, (void *)&ip->ip_dst.s_addr, lbuf, lbuflen);
			inet_ntop(AF_INET, (void *)&ip->ip_src.s_addr, fbuf, fbuflen);
		}
	}
	return true;
}

/*
 * Note: currently only used in the input path
 */
void
tcp_log_drop_pcb(void *hdr, struct tcphdr *th, struct tcpcb *tp, bool outgoing, const char *reason)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	/* Use the packet addresses when in the data path */
	if (hdr != NULL && th != NULL) {
		if (outgoing) {
			local_port = th->th_sport;
			foreign_port = th->th_dport;
		} else {
			local_port = th->th_dport;
			foreign_port = th->th_sport;
		}
		(void) tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	} else {
		local_port = inp->inp_lport;
		foreign_port = inp->inp_fport;
		tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

#define TCP_LOG_DROP_PCB_FMT \
	    "tcp drop %s " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "t_state: %s " \
	    "so_error: %d " \
	    "reason: %s"

#define TCP_LOG_DROP_PCB_ARGS \
	    outgoing ? "outgoing" : "incoming", \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    tcpstates[tp->t_state], \
	    so->so_error, \
	    reason

	if (tcp_log_level_info == 0) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_DROP_PCB_FMT,
		    TCP_LOG_DROP_PCB_ARGS);
	} else {
		os_log_info(OS_LOG_DEFAULT, TCP_LOG_DROP_PCB_FMT,
		    TCP_LOG_DROP_PCB_ARGS);
	}
#undef TCP_LOG_DROP_PCB_FMT
#undef TCP_LOG_DROP_PCB_ARGS
}

#define TCP_LOG_TH_FLAGS_COMMON_FMT \
	"tcp control %s " \
	"%s" \
	"%s" \
	"%s" \
	"%s" \
	TCP_LOG_COMMON_FMT

#define TCP_LOG_TH_FLAGS_COMMON_ARGS \
	outgoing ? "outgoing" : "incoming", \
	thflags & TH_SYN ? "SYN " : "", \
	thflags & TH_FIN ? "FIN " : "", \
	thflags & TH_RST ? "RST " : "", \
	thflags & TH_ACK ? "ACK " : "", \
	TCP_LOG_COMMON_ARGS

void
tcp_log_th_flags(void *hdr, struct tcphdr *th, struct tcpcb *tp, bool outgoing, struct ifnet *ifp)
{
	struct socket *so = tp->t_inpcb != NULL ? tp->t_inpcb->inp_socket : NULL;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	uint8_t thflags;

	if (hdr == NULL || th == NULL) {
		return;
	}

	if (outgoing) {
		local_port = th->th_sport;
		foreign_port = th->th_dport;
	} else {
		local_port = th->th_dport;
		foreign_port = th->th_sport;
	}
	thflags = th->th_flags;

	if ((((thflags & TH_SYN) && (tcp_log_enable_flags & TLEF_THF_SYN)) ||
	    ((thflags & TH_FIN) && (tcp_log_enable_flags & TLEF_THF_FIN)) ||
	    ((thflags & TH_RST) && (tcp_log_enable_flags & TLEF_THF_RST))) == false) {
		return;
	}

	if (ifp != NULL && tcp_log_thflags_if_family != 0 && ifp->if_family != tcp_log_thflags_if_family) {
		return;
	}

	if (!tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf))) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	/*
	 * When no PCB or socket just log the packet
	 */
	if (tp == NULL || so == NULL) {
		if (tcp_log_level_info == 0) {
			os_log(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_COMMON_FMT " no pcb",
			    TCP_LOG_TH_FLAGS_COMMON_ARGS);
		} else {
			os_log_info(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_COMMON_FMT,
			    TCP_LOG_TH_FLAGS_COMMON_ARGS);
		}
	} else {
#define TCP_LOG_TH_FLAGS_PCB_FMT \
	        TCP_LOG_TH_FLAGS_COMMON_FMT \
	        "rtt: %u.%u ms " \
	        "rttvar: %u.%u ms " \
	        "syn rxmit: %u " \
	        "pkt rxmit: %u " \
	        "so_error: %d " \
	        "svc/tc: %u "

#define TCP_LOG_TH_FLAGS_PCB_ARGS \
	    TCP_LOG_TH_FLAGS_COMMON_ARGS, \
	    tp->t_srtt >> TCP_RTT_SHIFT, tp->t_srtt - ((tp->t_srtt >> TCP_RTT_SHIFT) << TCP_RTT_SHIFT), \
	    tp->t_rttvar >> TCP_RTTVAR_SHIFT, tp->t_rttvar - ((tp->t_rttvar >> TCP_RTTVAR_SHIFT) << TCP_RTTVAR_SHIFT), \
	    tp->t_stat.synrxtshift, \
	    tp->t_stat.rxmitpkts, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? \
	    so->so_netsvctype : so->so_traffic_class

		if (tcp_log_level_info == 0) {
			os_log(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_PCB_FMT,
			    TCP_LOG_TH_FLAGS_PCB_ARGS);
		} else {
			os_log_info(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_PCB_FMT,
			    TCP_LOG_TH_FLAGS_PCB_ARGS);
		}
#undef TCP_LOG_TH_FLAGS_PCB_FMT
#undef TCP_LOG_TH_FLAGS_PCB_ARGS
	}
}

void
tcp_log_drop_pkt(void *hdr, struct tcphdr *th, struct ifnet *ifp, const char *reason)
{
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	uint8_t thflags;
	bool outgoing = false;  /* This is only for incoming packets */

	if (hdr == NULL || th == NULL) {
		return;
	}

	local_port = th->th_dport;
	foreign_port = th->th_sport;
	thflags = th->th_flags;

	if ((((thflags & TH_SYN) && (tcp_log_enable_flags & TLEF_THF_SYN)) ||
	    ((thflags & TH_FIN) && (tcp_log_enable_flags & TLEF_THF_FIN)) ||
	    ((thflags & TH_RST) && (tcp_log_enable_flags & TLEF_THF_RST))) == false) {
		return;
	}

	if (ifp != NULL && tcp_log_thflags_if_family != 0 && ifp->if_family != tcp_log_thflags_if_family) {
		return;
	}

	if (!tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf))) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

#define TCP_LOG_DROP_PKT_FMT \
	    "tcp drop incoming control packet " \
	        TCP_LOG_TH_FLAGS_COMMON_FMT \
	    "reason: %s"

#define TCP_LOG_DROP_PKT_ARGS \
	    TCP_LOG_TH_FLAGS_COMMON_ARGS, \
	    reason != NULL ? reason : ""

	if (tcp_log_level_info == 0) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_DROP_PKT_FMT,
		    TCP_LOG_DROP_PKT_ARGS);
	} else {
		os_log_info(OS_LOG_DEFAULT, TCP_LOG_DROP_PKT_FMT,
		    TCP_LOG_DROP_PKT_ARGS);
	}
#undef TCP_LOG_DROP_PKT_FMT
#undef TCP_LOG_DROP_PKT_ARGS
}

void
tcp_log_message(const char *func_name, int line_no, struct tcpcb *tp, const char *format, ...)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	char message[256];

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define TCP_LOG_MESSAGE_FMT \
	"tcp (%s:%d) " \
	TCP_LOG_COMMON_PCB_FMT \
	"%s"

#define TCP_LOG_MESSAGE_ARGS \
	func_name, line_no, \
	TCP_LOG_COMMON_PCB_ARGS, \
	message

	if (tcp_log_level_info == 0) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_MESSAGE_FMT,
		    TCP_LOG_MESSAGE_ARGS);
	} else {
		os_log_info(OS_LOG_DEFAULT, TCP_LOG_MESSAGE_FMT,
		    TCP_LOG_MESSAGE_ARGS);
	}
#undef TCP_LOG_MESSAGE_FMT
#undef TCP_LOG_MESSAGE_ARGS
}

