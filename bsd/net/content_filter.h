/*
 * Copyright (c) 2013-2014 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#ifndef __CONTENT_FILTER_H__
#define	__CONTENT_FILTER_H__

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <netinet/in.h>
#include <stdint.h>

#ifdef BSD_KERNEL_PRIVATE
#include <sys/mbuf.h>
#include <sys/socketvar.h>
#endif /* BSD_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef PRIVATE

/*
 * Kernel control name for an instance of a Content Filter
 * Use CTLIOCGINFO to find out the corresponding kernel control id
 * to be set in the sc_id field of sockaddr_ctl for connect(2)
 * Note: the sc_unit is ephemeral
 */
#define	CONTENT_FILTER_CONTROL_NAME "com.apple.content-filter"

/*
 * CFIL_OPT_NECP_CONTROL_UNIT
 * To set or get the NECP filter control unit for the kernel control socket
 * The option level is SYSPROTO_CONTROL
 */
#define	CFIL_OPT_NECP_CONTROL_UNIT	1	/* uint32_t */

/*
 * How many filter may be active simultaneously
 */
#define	CFIL_MAX_FILTER_COUNT	2

/*
 * Types of messages
 *
 * Event messages flow from kernel to user space while action
 * messages flow in the reverse direction.
 * A message in entirely represented by a packet sent or received
 * on a Content Filter kernel control socket.
 */
#define	CFM_TYPE_EVENT 1	/* message from kernel */
#define	CFM_TYPE_ACTION 2	/* message to kernel */

/*
 * Operations associated with events from kernel
 */
#define	CFM_OP_SOCKET_ATTACHED 1	/* a socket has been attached */
#define	CFM_OP_SOCKET_CLOSED 2		/* a socket is being closed */
#define	CFM_OP_DATA_OUT 3		/* data being sent */
#define	CFM_OP_DATA_IN 4		/* data being received */
#define	CFM_OP_DISCONNECT_OUT 5		/* no more outgoing data */
#define	CFM_OP_DISCONNECT_IN 6		/* no more incoming data */

/*
 * Operations associated with action from filter to kernel
 */
#define	CFM_OP_DATA_UPDATE 16		/* update pass or peek offsets */
#define	CFM_OP_DROP 17			/* shutdown socket, no more data */

/*
 * Opaque socket identifier
 */
typedef uint64_t cfil_sock_id_t;

#define	CFIL_SOCK_ID_NONE UINT64_MAX

/*
 * Invariant timeval structure definition across architectures
 */
struct timeval64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

/*
 * struct cfil_msg_hdr
 *
 * Header common to all messages
 */
struct cfil_msg_hdr {
	uint32_t	cfm_len;	/* total length */
	uint32_t	cfm_version;
	uint32_t	cfm_type;
	uint32_t	cfm_op;
	cfil_sock_id_t	cfm_sock_id;
};

#define	CFM_VERSION_CURRENT 1

/*
 * struct cfil_msg_sock_attached
 *
 * Information about a new socket being attached to the content filter
 *
 * Action: No reply is expected as this does not block the creation of the
 * TCP/IP but timely action must be taken to avoid user noticeable delays.
 *
 * Valid Types: CFM_TYPE_EVENT
 *
 * Valid Op: CFM_OP_SOCKET_ATTACHED
 */
struct cfil_msg_sock_attached {
	struct cfil_msg_hdr	cfs_msghdr;
	int			cfs_sock_family;	/* e.g. PF_INET */
	int			cfs_sock_type;		/* e.g. SOCK_STREAM */
	int			cfs_sock_protocol;	/* e.g. IPPROTO_TCP */
	int			cfs_unused;		/* padding */
	pid_t			cfs_pid;
	pid_t			cfs_e_pid;
	uuid_t			cfs_uuid;
	uuid_t			cfs_e_uuid;
};

/*
 * struct cfil_msg_data_event
 *
 * Event for the content fiter to act on a span of data
 * A data span is described by a pair of offsets over the cumulative
 * number of bytes sent or received on the socket.
 *
 * Action: The event must be acted upon but the filter may buffer
 * data spans until it has enough content to make a decision.
 * The action must be timely to avoid user noticeable delays.
 *
 * Valid Type: CFM_TYPE_EVENT
 *
 * Valid Ops: CFM_OP_DATA_OUT, CFM_OP_DATA_IN
 */
struct cfil_msg_data_event {
	struct cfil_msg_hdr	cfd_msghdr;
	union sockaddr_in_4_6	cfc_src;
	union sockaddr_in_4_6	cfc_dst;
	uint64_t		cfd_start_offset;
	uint64_t		cfd_end_offset;
	/* Actual content data immediatly follows */
};

/*
 * struct cfil_msg_action
 *
 * Valid Type: CFM_TYPE_ACTION
 *
 * Valid Ops: CFM_OP_DATA_UPDATE, CFM_OP_DROP
 *
 * For CFM_OP_DATA_UPDATE:
 *
 * cfa_in_pass_offset and cfa_out_pass_offset indicates how much data is
 * allowed to pass. A zero value does not modify the corresponding pass offset.
 *
 * cfa_in_peek_offset and cfa_out_peek_offset lets the filter specify how much
 * data it needs to make a decision: the kernel will deliver data up to that
 * offset (if less than cfa_pass_offset it is ignored). Use CFM_MAX_OFFSET
 * if you don't value the corresponding peek offset to be updated.
 */
struct cfil_msg_action {
	struct cfil_msg_hdr	cfa_msghdr;
	uint64_t		cfa_in_pass_offset;
	uint64_t		cfa_in_peek_offset;
	uint64_t		cfa_out_pass_offset;
	uint64_t		cfa_out_peek_offset;
};

#define	CFM_MAX_OFFSET	UINT64_MAX

/*
 * Statistics retrieved via sysctl(3)
 */
struct cfil_filter_stat {
	uint32_t	cfs_len;
	uint32_t	cfs_filter_id;
	uint32_t	cfs_flags;
	uint32_t	cfs_sock_count;
	uint32_t	cfs_necp_control_unit;
};

struct cfil_entry_stat {
	uint32_t		ces_len;
	uint32_t		ces_filter_id;
	uint32_t		ces_flags;
	uint32_t		ces_necp_control_unit;
	struct timeval64	ces_last_event;
	struct timeval64	ces_last_action;
	struct cfe_buf_stat {
		uint64_t	cbs_pending_first;
		uint64_t	cbs_pending_last;
		uint64_t	cbs_ctl_first;
		uint64_t	cbs_ctl_last;
		uint64_t	cbs_pass_offset;
		uint64_t	cbs_peek_offset;
		uint64_t	cbs_peeked;
	} ces_snd, ces_rcv;
};

struct cfil_sock_stat {
	uint32_t	cfs_len;
	int		cfs_sock_family;
	int		cfs_sock_type;
	int		cfs_sock_protocol;
	cfil_sock_id_t	cfs_sock_id;
	uint64_t	cfs_flags;
	pid_t		cfs_pid;
	pid_t		cfs_e_pid;
	uuid_t		cfs_uuid;
	uuid_t		cfs_e_uuid;
	struct cfi_buf_stat {
		uint64_t	cbs_pending_first;
		uint64_t	cbs_pending_last;
		uint64_t	cbs_pass_offset;
		uint64_t	cbs_inject_q_len;
	} cfs_snd, cfs_rcv;
	struct cfil_entry_stat	ces_entries[CFIL_MAX_FILTER_COUNT];
};

/*
 * Global statistics
 */
struct cfil_stats {
	int32_t	cfs_ctl_connect_ok;
	int32_t	cfs_ctl_connect_fail;
	int32_t	cfs_ctl_disconnect_ok;
	int32_t	cfs_ctl_disconnect_fail;
	int32_t	cfs_ctl_send_ok;
	int32_t	cfs_ctl_send_bad;
	int32_t	cfs_ctl_rcvd_ok;
	int32_t	cfs_ctl_rcvd_bad;
	int32_t	cfs_ctl_rcvd_flow_lift;
	int32_t	cfs_ctl_action_data_update;
	int32_t	cfs_ctl_action_drop;
	int32_t	cfs_ctl_action_bad_op;
	int32_t	cfs_ctl_action_bad_len;

	int32_t	cfs_sock_id_not_found;

	int32_t	cfs_cfi_alloc_ok;
	int32_t	cfs_cfi_alloc_fail;

	int32_t	cfs_sock_userspace_only;
	int32_t	cfs_sock_attach_in_vain;
	int32_t	cfs_sock_attach_already;
	int32_t	cfs_sock_attach_no_mem;
	int32_t	cfs_sock_attach_failed;
	int32_t	cfs_sock_attached;
	int32_t	cfs_sock_detached;

	int32_t	cfs_attach_event_ok;
	int32_t	cfs_attach_event_flow_control;
	int32_t	cfs_attach_event_fail;

	int32_t	cfs_closed_event_ok;
	int32_t	cfs_closed_event_flow_control;
	int32_t	cfs_closed_event_fail;

	int32_t	cfs_data_event_ok;
	int32_t	cfs_data_event_flow_control;
	int32_t	cfs_data_event_fail;

	int32_t	cfs_disconnect_in_event_ok;
	int32_t	cfs_disconnect_out_event_ok;
	int32_t	cfs_disconnect_event_flow_control;
	int32_t	cfs_disconnect_event_fail;

	int32_t	cfs_ctl_q_not_started;

	int32_t cfs_close_wait;
	int32_t cfs_close_wait_timeout;

	int32_t cfs_flush_in_drop;
	int32_t cfs_flush_out_drop;
	int32_t cfs_flush_in_close;
	int32_t cfs_flush_out_close;
	int32_t cfs_flush_in_free;
	int32_t cfs_flush_out_free;

	int32_t	cfs_inject_q_nomem;
	int32_t	cfs_inject_q_nobufs;
	int32_t	cfs_inject_q_detached;
	int32_t	cfs_inject_q_in_fail;
	int32_t	cfs_inject_q_out_fail;

	int32_t	cfs_inject_q_in_retry;
	int32_t	cfs_inject_q_out_retry;

	int32_t cfs_data_in_control;
	int32_t cfs_data_in_oob;
	int32_t cfs_data_out_control;
	int32_t cfs_data_out_oob;

	int64_t	cfs_ctl_q_in_enqueued __attribute__((aligned(8)));
	int64_t	cfs_ctl_q_out_enqueued __attribute__((aligned(8)));
	int64_t	cfs_ctl_q_in_peeked __attribute__((aligned(8)));
	int64_t	cfs_ctl_q_out_peeked __attribute__((aligned(8)));

	int64_t	cfs_pending_q_in_enqueued __attribute__((aligned(8)));
	int64_t	cfs_pending_q_out_enqueued __attribute__((aligned(8)));

	int64_t	cfs_inject_q_in_enqueued __attribute__((aligned(8)));
	int64_t	cfs_inject_q_out_enqueued __attribute__((aligned(8)));
	int64_t	cfs_inject_q_in_passed __attribute__((aligned(8)));
	int64_t	cfs_inject_q_out_passed __attribute__((aligned(8)));

};
#endif /* PRIVATE */

#ifdef BSD_KERNEL_PRIVATE

#define	M_SKIPCFIL	M_PROTO5

extern int cfil_log_level;

#define	CFIL_LOG(level, fmt, ...) \
do { \
	if (cfil_log_level >= level) \
		printf("%s:%d " fmt "\n",\
			__FUNCTION__, __LINE__, ##__VA_ARGS__); \
} while (0)


extern void cfil_init(void);

extern errno_t cfil_sock_attach(struct socket *so);
extern errno_t cfil_sock_detach(struct socket *so);

extern int cfil_sock_data_out(struct socket *so, struct sockaddr  *to,
			struct mbuf *data, struct mbuf *control,
			uint32_t flags);
extern int cfil_sock_data_in(struct socket *so, struct sockaddr *from,
			struct mbuf *data, struct mbuf *control,
			uint32_t flags);

extern int cfil_sock_shutdown(struct socket *so, int *how);
extern void cfil_sock_is_closed(struct socket *so);
extern void cfil_sock_notify_shutdown(struct socket *so, int how);
extern void cfil_sock_close_wait(struct socket *so);

extern boolean_t cfil_sock_data_pending(struct sockbuf *sb);
extern int cfil_sock_data_space(struct sockbuf *sb);
extern void cfil_sock_buf_update(struct sockbuf *sb);

extern cfil_sock_id_t cfil_sock_id_from_socket(struct socket *so);

__END_DECLS

#endif /* BSD_KERNEL_PRIVATE */

#endif /* __CONTENT_FILTER_H__ */
