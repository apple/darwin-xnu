/*
 * Copyright (c) 2013-2014 Apple Computer, Inc.  All Rights Reserved.
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

#pragma D depends_on library darwin.d
#pragma D depends_on library socket.d
#pragma D depends_on module mach_kernel
#pragma D depends_on provider mptcp
#pragma D depends_on provider ip

/*
 * MPTCP Protocol Control Block.
 */
inline int MPTCPS_CLOSED                = 0;
#pragma D binding "1.0" MPTCPS_CLOSED
inline int MPTCPS_LISTEN                = 1;
#pragma D binding "1.0" MPTCPS_LISTEN
inline int MPTCPS_ESTABLISHED           = 2;
#pragma D binding "1.0" MPTCPS_ESTABLISHED
inline int MPTCPS_CLOSE_WAIT            = 3;
#pragma D binding "1.0" MPTCPS_CLOSE_WAIT
inline int MPTCPS_FIN_WAIT_1            = 4;
#pragma D binding "1.0" MPTCPS_FIN_WAIT_1
inline int MPTCPS_CLOSING               = 5;
#pragma D binding "1.0" MPTCPS_CLOSING
inline int MPTCPS_LAST_ACK              = 6;
#pragma D binding "1.0" MPTCPS_LAST_ACK
inline int MPTCPS_FIN_WAIT_2            = 7;
#pragma D binding "1.0" MPTCPS_FIN_WAIT_2
inline int MPTCPS_TIME_WAIT             = 8;
#pragma D binding "1.0" MPTCPS_TIME_WAIT
inline int MPTCPS_FASTCLOSE_WAIT        = 9;
#pragma D binding "1.0" MPTCPS_FASTCLOSE_WAIT
inline int MPTCPS_TERMINATE		= 10;
#pragma D binding "1.0" MPTCPS_TERMINATE

typedef uint64_t mptcp_key_t;
typedef uint32_t mptcp_token_t;

typedef struct mptsinfo {
	string		state;
	uint32_t	flags;
	uint32_t	vers;
	uint32_t	error;
	mptcp_key_t	localkey;
	mptcp_key_t	remotekey;
	mptcp_token_t	localtoken;
	mptcp_token_t	remotetoken;
	int		rxtshift;
	uint32_t	rxtstart;
	uint64_t	rtseq;
	uint32_t	timervals;
	uint32_t	timewait;
	uint64_t	snduna;
	uint64_t	sndnxt;
	uint64_t	sndmax;
	uint64_t	local_idsn;
	uint32_t	sndwnd;
	uint64_t	rcvnxt;
	uint64_t	rcvatmark;
	uint64_t	remote_idsn;
	uint32_t	rcvwnd;
	struct mptcb	*mptcb;
} mptsinfo_t;

#pragma D binding "1.0" translator
translator mptsinfo_t < struct mptcb *T > {
	state        = T->mpt_state == MPTCPS_CLOSED ? "state-closed" :
		       T->mpt_state == MPTCPS_LISTEN ? "state-listen" :
		       T->mpt_state == MPTCPS_ESTABLISHED ?
		           "state-established" :
		       T->mpt_state == MPTCPS_CLOSE_WAIT ? "state-close-wait" :
		       T->mpt_state == MPTCPS_FIN_WAIT_1 ? "state-fin-wait-1" :
		       T->mpt_state == MPTCPS_CLOSING ? "state-closing" :
		       T->mpt_state == MPTCPS_LAST_ACK ? "state-last-ack" :
		       T->mpt_state == MPTCPS_FIN_WAIT_2 ? "state-fin-wait-2" :
		       T->mpt_state == MPTCPS_TIME_WAIT ? "state-time-wait" :
		       T->mpt_state == MPTCPS_FASTCLOSE_WAIT ?
		           "state-fastclose-wait" :
		       T->mpt_state == MPTCPS_TERMINATE ?
		           "state-terminate" :
		       "<unknown>";
	flags        = T->mpt_flags;
	vers         = T->mpt_version;
	error        = T->mpt_softerror;
	localkey     = T->mpt_localkey ? *T->mpt_localkey : 0;
	remotekey    = T->mpt_remotekey;
	localtoken   = T->mpt_localtoken;
	remotetoken  = T->mpt_remotetoken;
	rxtshift     = T->mpt_rxtshift;
	rxtstart     = T->mpt_rxtstart;
	rtseq	     = T->mpt_rtseq;
	timervals    = T->mpt_timer_vals;
	timewait     = T->mpt_timewait;
	snduna       = T->mpt_snduna;
	sndnxt	     = T->mpt_sndnxt;
	sndmax	     = T->mpt_sndmax;
	local_idsn   = T->mpt_local_idsn;
	sndwnd	     = T->mpt_sndwnd;
	rcvnxt	     = T->mpt_rcvnxt;
	rcvatmark    = T->mpt_rcvatmark;
	remote_idsn  = T->mpt_remote_idsn;
	rcvwnd       = T->mpt_rcvwnd;
	mptcb	     = T;
};

/*
 * Multipath Control Block.
 */
inline int MPPCB_STATE_INUSE	= 1;
#pragma D binding "1.0" MPPCB_STATE_INUSE
inline int MPPCB_STATE_DEAD	= 2;
#pragma D binding "1.0" MPPCB_STATE_DEAD

typedef struct mppsinfo {
	string		state;
	uint32_t	flags;
	struct mppcb	*mppcb;
} mppsinfo_t;

#pragma D binding "1.0" translator
translator mppsinfo_t < struct mppcb *T> {
	state  = T ? 
	    T->mpp_state == MPPCB_STATE_INUSE ? "state-inuse" :
	    T->mpp_state == MPPCB_STATE_DEAD ? "state-dead" :
	    "<unknown>" : "<null>";
	flags  = T->mpp_flags;
	mppcb  = T;
};

/*
 * MPTCP Session.
 */
typedef struct mptsesinfo {
	uint16_t	numflows;
	uint16_t	nummpcapflows;
	connid_t	connid_last;
	uint8_t		flags;
	struct mptses	*mptses;
} mptsesinfo_t;

#pragma D binding "1.0" translator
translator mptsesinfo_t < struct mptses *T > {
	numflows      = T->mpte_numflows;
	nummpcapflows = T->mpte_nummpcapflows;
	connid_last   = T->mpte_connid_last;
	flags         = T->mpte_flags;
	mptses	      = T;
};

/*
 * MPTCP Subflow.
 */
inline int MPTSF_ATTACHED       = 0x00001;
#pragma D binding "1.0" MPTSF_ATTACHED
inline int MPTSF_CONNECTING     = 0x00002;
#pragma D binding "1.0" MPTSF_CONNECTING
inline int MPTSF_CONNECT_PENDING= 0x00004;
#pragma D binding "1.0" MPTSF_CONNECT_PENDING
inline int MPTSF_CONNECTED      = 0x00008;
#pragma D binding "1.0" MPTSF_CONNECTED
inline int MPTSF_DISCONNECTING  = 0x00010;
#pragma D binding "1.0" MPTSF_DISCONNECTING
inline int MPTSF_DISCONNECTED   = 0x00020;
#pragma D binding "1.0" MPTSF_DISCONNECTED
inline int MPTSF_MP_CAPABLE     = 0x00040;
#pragma D binding "1.0" MPTSF_MP_CAPABLE
inline int MPTSF_MP_READY       = 0x00080;
#pragma D binding "1.0" MPTSF_MP_READY
inline int MPTSF_MP_DEGRADED    = 0x00100;
#pragma D binding "1.0" MPTSF_MP_DEGRADED
inline int MPTSF_SUSPENDED      = 0x00200;
#pragma D binding "1.0" MPTSF_SUSPENDED
inline int MPTSF_BOUND_IF       = 0x00400;
#pragma D binding "1.0" MPTSF_BOUND_IF
inline int MPTSF_BOUND_IP       = 0x00800;
#pragma D binding "1.0" MPTSF_BOUND_IP
inline int MPTSF_BOUND_PORT     = 0x01000;
#pragma D binding "1.0" MPTSF_BOUND_PORT
inline int MPTSF_PREFERRED      = 0x02000;
#pragma D binding "1.0" MPTSF_PREFERRED
inline int MPTSF_SOPT_OLDVAL    = 0x04000;
#pragma D binding "1.0" MPTSF_SOPT_OLDVAL
inline int MPTSF_SOPT_INPROG    = 0x08000;
#pragma D binding "1.0" MPTSF_SOPT_INPROG
inline int MPTSF_DELETEOK       = 0x10000;
#pragma D binding "1.0" MPTSF_DELETEOK
inline int MPTSF_FAILINGOVER    = 0x20000;
#pragma D binding "1.0" MPTSF_FAILINGOVER
inline int MPTSF_ACTIVE         = 0x40000;
#pragma D binding "1.0" MPTSF_ACTIVE
inline int MPTSF_MPCAP_CTRSET   = 0x80000;
#pragma D binding "1.0" MPTSF_MPCAP_CTRSET
inline int MPTSF_FASTJ_SEND	= 0x100000;
#pragma D binding "1.0" MPTSF_FASTJ_SEND

typedef struct mptsubinfo {
	uint32_t	flags;
	uint32_t	evctl;
	uint32_t	family;
	connid_t	connid;
	uint32_t	rank;
	int32_t		error;
	uint64_t	sndnxt;
	struct mptsub	*mptsub;
} mptsubinfo_t;

#pragma D binding "1.0" translator
translator mptsubinfo_t < struct mptsub *T > {
	flags   = T->mpts_flags;
	evctl   = T->mpts_evctl;
	family  = T->mpts_family;
	connid  = T->mpts_connid;
	rank    = T->mpts_rank;
	error   = T->mpts_soerror;
	sndnxt  = T->mpts_sndnxt;
	mptsub  = T;
};
