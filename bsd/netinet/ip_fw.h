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
 * Copyright (c) 1993 Daniel Boulet
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 */

#ifndef _IP_FW_H
#define _IP_FW_H

#include <sys/queue.h>

/*
 * This union structure identifies an interface, either explicitly
 * by name or implicitly by IP address. The flags IP_FW_F_IIFNAME
 * and IP_FW_F_OIFNAME say how to interpret this structure. An
 * interface unit number of -1 matches any unit number, while an
 * IP address of 0.0.0.0 indicates matches any interface.
 *
 * The receive and transmit interfaces are only compared against the
 * the packet if the corresponding bit (IP_FW_F_IIFACE or IP_FW_F_OIFACE)
 * is set. Note some packets lack a receive or transmit interface
 * (in which case the missing "interface" never matches).
 */

union ip_fw_if {
    struct in_addr fu_via_ip;	/* Specified by IP address */
    struct {			/* Specified by interface name */
#define FW_IFNLEN     10 /* need room ! was IFNAMSIZ */
	    char  name[FW_IFNLEN];
	    short unit;		/* -1 means match any unit */
    } fu_via_if;
};

/*
 * Format of an IP firewall descriptor
 *
 * fw_src, fw_dst, fw_smsk, fw_dmsk are always stored in network byte order.
 * fw_flg and fw_n*p are stored in host byte order (of course).
 * Port numbers are stored in HOST byte order.
 * Warning: setsockopt() will fail if sizeof(struct ip_fw) > MLEN (108)
 */

struct ip_fw {
    u_int64_t fw_pcnt,fw_bcnt;		/* Packet and byte counters */
    struct in_addr fw_src, fw_dst;	/* Source and destination IP addr */
    struct in_addr fw_smsk, fw_dmsk;	/* Mask for src and dest IP addr */
    u_short fw_number;			/* Rule number */
    u_int fw_flg;			/* Flags word */
#define IP_FW_MAX_PORTS	10		/* A reasonable maximum */
	union {
	u_short fw_pts[IP_FW_MAX_PORTS];	/* Array of port numbers to match */
#define IP_FW_ICMPTYPES_MAX	128
#define IP_FW_ICMPTYPES_DIM	(IP_FW_ICMPTYPES_MAX / (sizeof(unsigned) * 8))
	unsigned fw_icmptypes[IP_FW_ICMPTYPES_DIM]; /* ICMP types bitmap */
	} fw_uar;
    u_char fw_ipopt,fw_ipnopt;		/* IP options set/unset */
    u_char fw_tcpf,fw_tcpnf;		/* TCP flags set/unset */
    long timestamp;			/* timestamp (tv_sec) of last match */
    union ip_fw_if fw_in_if, fw_out_if;	/* Incoming and outgoing interfaces */
    union {
	u_short fu_divert_port;		/* Divert/tee port (options IPDIVERT) */
	u_short fu_pipe_nr;		/* pipe number (option DUMMYNET) */
	u_short fu_skipto_rule;		/* SKIPTO command rule number */
	u_short fu_reject_code;		/* REJECT response code */
	struct sockaddr_in fu_fwd_ip;
    } fw_un;
    u_char fw_prot;			/* IP protocol */
    u_char fw_nports;			/* N'of src ports and # of dst ports */
					/* in ports array (dst ports follow */
					/* src ports; max of 10 ports in all; */
					/* count of 0 means match all ports) */
    void *pipe_ptr;                    /* Pipe ptr in case of dummynet pipe */
    void *next_rule_ptr ;              /* next rule in case of match */
};

#define IP_FW_GETNSRCP(rule)		((rule)->fw_nports & 0x0f)
#define IP_FW_SETNSRCP(rule, n)		do {				\
					  (rule)->fw_nports &= ~0x0f;	\
					  (rule)->fw_nports |= (n);	\
					} while (0)
#define IP_FW_GETNDSTP(rule)		((rule)->fw_nports >> 4)
#define IP_FW_SETNDSTP(rule, n)		do {				\
					  (rule)->fw_nports &= ~0xf0;	\
					  (rule)->fw_nports |= (n) << 4;\
					} while (0)

#define fw_divert_port	fw_un.fu_divert_port
#define fw_skipto_rule	fw_un.fu_skipto_rule
#define fw_reject_code	fw_un.fu_reject_code
#define fw_pipe_nr	fw_un.fu_pipe_nr
#define fw_fwd_ip	fw_un.fu_fwd_ip

struct ip_fw_chain {
        LIST_ENTRY(ip_fw_chain) chain;
        struct ip_fw    *rule;
};

/*
 * Values for "flags" field .
 */
#define IP_FW_F_COMMAND 0x000000ff	/* Mask for type of chain entry:	*/
#define IP_FW_F_DENY	0x00000000	/* This is a deny rule			*/
#define IP_FW_F_REJECT	0x00000001	/* Deny and send a response packet	*/
#define IP_FW_F_ACCEPT	0x00000002	/* This is an accept rule		*/
#define IP_FW_F_COUNT	0x00000003	/* This is a count rule			*/
#define IP_FW_F_DIVERT	0x00000004	/* This is a divert rule		*/
#define IP_FW_F_TEE	0x00000005	/* This is a tee rule			*/
#define IP_FW_F_SKIPTO	0x00000006	/* This is a skipto rule		*/
#define IP_FW_F_FWD	0x00000007	/* This is a "change forwarding address" rule */
#define IP_FW_F_PIPE	0x00000008	/* This is a dummynet rule */

#define IP_FW_F_IN	0x00000100	/* Check inbound packets		*/
#define IP_FW_F_OUT	0x00000200	/* Check outbound packets		*/
#define IP_FW_F_IIFACE	0x00000400	/* Apply inbound interface test		*/
#define IP_FW_F_OIFACE	0x00000800	/* Apply outbound interface test	*/

#define IP_FW_F_PRN	0x00001000	/* Print if this rule matches		*/

#define IP_FW_F_SRNG	0x00002000	/* The first two src ports are a min	*
					 * and max range (stored in host byte	*
					 * order).				*/

#define IP_FW_F_DRNG	0x00004000	/* The first two dst ports are a min	*
					 * and max range (stored in host byte	*
					 * order).				*/

#define IP_FW_F_FRAG	0x00008000	/* Fragment				*/

#define IP_FW_F_IIFNAME	0x00010000	/* In interface by name/unit (not IP)	*/
#define IP_FW_F_OIFNAME	0x00020000	/* Out interface by name/unit (not IP)	*/

#define IP_FW_F_INVSRC	0x00040000	/* Invert sense of src check		*/
#define IP_FW_F_INVDST	0x00080000	/* Invert sense of dst check		*/

#define IP_FW_F_ICMPBIT 0x00100000	/* ICMP type bitmap is valid		*/

#define IP_FW_F_MASK	0x001FFFFF	/* All possible flag bits mask		*/

/*
 * For backwards compatibility with rules specifying "via iface" but
 * not restricted to only "in" or "out" packets, we define this combination
 * of bits to represent this configuration.
 */

#define IF_FW_F_VIAHACK	(IP_FW_F_IN|IP_FW_F_OUT|IP_FW_F_IIFACE|IP_FW_F_OIFACE)

/*
 * Definitions for REJECT response codes.
 * Values less than 256 correspond to ICMP unreachable codes.
 */
#define IP_FW_REJECT_RST	0x0100		/* TCP packets: send RST */

/*
 * Definitions for IP option names.
 */
#define IP_FW_IPOPT_LSRR	0x01
#define IP_FW_IPOPT_SSRR	0x02
#define IP_FW_IPOPT_RR		0x04
#define IP_FW_IPOPT_TS		0x08

/*
 * Definitions for TCP flags.
 */
#define IP_FW_TCPF_FIN		TH_FIN
#define IP_FW_TCPF_SYN		TH_SYN
#define IP_FW_TCPF_RST		TH_RST
#define IP_FW_TCPF_PSH		TH_PUSH
#define IP_FW_TCPF_ACK		TH_ACK
#define IP_FW_TCPF_URG		TH_URG
#define IP_FW_TCPF_ESTAB	0x40

/*
 * Main firewall chains definitions and global var's definitions.
 */
#ifdef KERNEL

/*
 * Function definitions.
 */
void ip_fw_init __P((void));

/* Firewall hooks */
struct ip;
struct sockopt;
typedef	int ip_fw_chk_t __P((struct ip **, int, struct ifnet *, u_int16_t *,
	     struct mbuf **, struct ip_fw_chain **, struct sockaddr_in **));
typedef	int ip_fw_ctl_t __P((struct sockopt *));
extern	ip_fw_chk_t *ip_fw_chk_ptr;
extern	ip_fw_ctl_t *ip_fw_ctl_ptr;

/* IP NAT hooks */
typedef	int ip_nat_t __P((struct ip **, struct mbuf **, struct ifnet *, int));
typedef	int ip_nat_ctl_t __P((struct sockopt *));
extern	ip_nat_t *ip_nat_ptr;
extern	ip_nat_ctl_t *ip_nat_ctl_ptr;
#define	IP_NAT_IN	0x00000001
#define	IP_NAT_OUT	0x00000002

#endif /* KERNEL */

#endif /* _IP_FW_H */
