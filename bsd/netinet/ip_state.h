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
 * Copyright (C) 1995-1997 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 *
 * @(#)ip_state.h	1.3 1/12/96 (C) 1995 Darren Reed
 */
#ifndef	__IP_STATE_H__
#define	__IP_STATE_H__

#define	IPSTATE_SIZE	257
#define	IPSTATE_MAX	2048	/* Maximum number of states held */

#define	PAIRS(s1,d1,s2,d2)	((((s1) == (s2)) && ((d1) == (d2))) ||\
				 (((s1) == (d2)) && ((d1) == (s2))))
#define	IPPAIR(s1,d1,s2,d2)	PAIRS((s1).s_addr, (d1).s_addr, \
				      (s2).s_addr, (d2).s_addr)


typedef struct udpstate {
	u_short	us_sport;
	u_short	us_dport;
} udpstate_t;

typedef struct icmpstate {
	u_short	ics_id;
	u_short	ics_seq;
	u_char	ics_type;
} icmpstate_t;

typedef	struct tcpstate {
	u_short	ts_sport;
	u_short	ts_dport;
	u_long	ts_seq;
	u_long	ts_ack;
	u_short	ts_swin;
	u_short	ts_dwin;
	u_char	ts_state[2];
} tcpstate_t;

typedef struct ipstate {
	struct	ipstate	*is_next;
	u_long	is_age;
	u_int	is_pass;
	U_QUAD_T	is_pkts;
	U_QUAD_T	is_bytes;
	void	*is_ifpin;
	void	*is_ifpout;
	struct	in_addr	is_src;
	struct	in_addr	is_dst;
	u_char	is_p;
	u_char	is_flags;
	u_32_t	is_opt;
	u_32_t	is_optmsk;
	u_short	is_sec;
	u_short	is_secmsk;
	u_short	is_auth;
	u_short	is_authmsk;
	union {
		icmpstate_t	is_ics;
		tcpstate_t	is_ts;
		udpstate_t	is_us;
	} is_ps;
} ipstate_t;

#define	is_icmp	is_ps.is_ics
#define	is_tcp	is_ps.is_ts
#define	is_udp	is_ps.is_us
#define	is_seq	is_tcp.ts_seq
#define	is_ack	is_tcp.ts_ack
#define	is_dwin	is_tcp.ts_dwin
#define	is_swin	is_tcp.ts_swin
#define	is_sport	is_tcp.ts_sport
#define	is_dport	is_tcp.ts_dport
#define	is_state	is_tcp.ts_state

#define	TH_OPENING	(TH_SYN|TH_ACK)


typedef	struct	ipslog	{
	U_QUAD_T	isl_pkts;
	U_QUAD_T	isl_bytes;
	struct	in_addr	isl_src;
	struct	in_addr	isl_dst;
	u_char	isl_p;
	u_char	isl_flags;
	u_short	isl_type;
	union {
		u_short	isl_filler[2];
		u_short	isl_ports[2];
		u_short	isl_icmp;
	} isl_ps;
} ipslog_t;

#define	isl_sport	isl_ps.isl_ports[0]
#define	isl_dport	isl_ps.isl_ports[1]
#define	isl_itype	isl_ps.isl_icmp

#define	ISL_NEW		0
#define	ISL_EXPIRE	0xffff
#define	ISL_FLUSH	0xfffe


typedef	struct	ips_stat {
	u_long	iss_hits;
	u_long	iss_miss;
	u_long	iss_max;
	u_long	iss_tcp;
	u_long	iss_udp;
	u_long	iss_icmp;
	u_long	iss_nomem;
	u_long	iss_expire;
	u_long	iss_fin;
	u_long	iss_active;
	u_long	iss_logged;
	u_long	iss_logfail;
	ipstate_t **iss_table;
} ips_stat_t;


extern	u_long	fr_tcpidletimeout;
extern	u_long	fr_tcpclosewait;
extern	u_long	fr_tcplastack;
extern	u_long	fr_tcptimeout;
extern	u_long	fr_tcpclosed;
extern	u_long	fr_udptimeout;
extern	u_long	fr_icmptimeout;
extern	int	fr_tcpstate __P((ipstate_t *, fr_info_t *, ip_t *, tcphdr_t *));
extern	int	fr_addstate __P((ip_t *, fr_info_t *, u_int));
extern	int	fr_checkstate __P((ip_t *, fr_info_t *));
extern	void	fr_timeoutstate __P((void));
extern	void	fr_tcp_age __P((u_long *, u_char *, ip_t *, fr_info_t *, int));
extern	void	fr_stateunload __P((void));
extern	void	ipstate_log __P((struct ipstate *, u_short));
#if defined(__NetBSD__) || defined(__OpenBSD__)
extern	int	fr_state_ioctl __P((caddr_t, u_long, int));
#else
extern	int	fr_state_ioctl __P((caddr_t, int, int));
#endif

#endif /* __IP_STATE_H__ */
