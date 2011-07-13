/*
 * Copyright (c) 2004-2007 Apple Inc. All rights reserved.
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
/* IPFW2 Backward Compatibility */

/* Convert to and from IPFW2 structures. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#include <netinet/tcp.h>

#include "ip_fw2_compat.h"

#define FW2_DEBUG_VERBOSE 0

/*
 * _s_x is a structure that stores a string <-> token pairs, used in
 * various places in the parser. Entries are stored in arrays,
 * with an entry with s=NULL as terminator.
 * The search routines are match_token() and match_value().
 * Often, an element with x=0 contains an error string.
 *
 */
struct _s_x {
	char const *s;
	int x;
};

#define NO_VERSION_STR "IP_FW_VERSION_NONE"
#define VERSION_ZERO_STR "IP_FW_VERSION_0"
#define VERSION_ONE_STR "IP_FW_VERSION_1"
#define CURRENT_API_VERSION_STR "IP_FW_CURRENT_API_VERSION"

#if FW2_DEBUG_VERBOSE

static struct _s_x f_tcpflags[] = {
	{ "syn", TH_SYN },
	{ "fin", TH_FIN },
	{ "ack", TH_ACK },
	{ "psh", TH_PUSH },
	{ "rst", TH_RST },
	{ "urg", TH_URG },
	{ "tcp flag", 0 },
	{ NULL,	0 }
};

static struct _s_x f_tcpopts[] = {
	{ "mss",	IP_FW_TCPOPT_MSS },
	{ "maxseg",	IP_FW_TCPOPT_MSS },
	{ "window",	IP_FW_TCPOPT_WINDOW },
	{ "sack",	IP_FW_TCPOPT_SACK },
	{ "ts",		IP_FW_TCPOPT_TS },
	{ "timestamp",	IP_FW_TCPOPT_TS },
	{ "cc",		IP_FW_TCPOPT_CC },
	{ "tcp option",	0 },
	{ NULL,	0 }
};


/*
 * IP options span the range 0 to 255 so we need to remap them
 * (though in fact only the low 5 bits are significant).
 */
static struct _s_x f_ipopts[] = {
	{ "ssrr",	IP_FW_IPOPT_SSRR},
	{ "lsrr",	IP_FW_IPOPT_LSRR},
	{ "rr",		IP_FW_IPOPT_RR},
	{ "ts",		IP_FW_IPOPT_TS},
	{ "ip option",	0 },
	{ NULL,	0 }
};

static struct _s_x f_iptos[] = {
	{ "lowdelay",	IPTOS_LOWDELAY},
	{ "throughput",	IPTOS_THROUGHPUT},
	{ "reliability", IPTOS_RELIABILITY},
	{ "mincost",	IPTOS_MINCOST},
	{ "congestion",	IPTOS_CE},
	{ "ecntransport", IPTOS_ECT},
	{ "ip tos option", 0},
	{ NULL,	0 }
};

static struct _s_x limit_masks[] = {
	{"all",		DYN_SRC_ADDR|DYN_SRC_PORT|DYN_DST_ADDR|DYN_DST_PORT},
	{"src-addr",	DYN_SRC_ADDR},
	{"src-port",	DYN_SRC_PORT},
	{"dst-addr",	DYN_DST_ADDR},
	{"dst-port",	DYN_DST_PORT},
	{NULL,		0}
};

#endif /* !FW2_DEBUG_VERBOSE */

#if 0 /* version #1 */

static void
ipfw_print_fw_flags(u_int flags)
{
	/* print action */
	switch (flags & IP_FW_F_COMMAND_COMPAT) {
		case IP_FW_F_ACCEPT_COMPAT:
			printf("IP_FW_F_ACCEPT_COMPAT\n");
			break;
		case IP_FW_F_COUNT_COMPAT:
			printf("IP_FW_F_COUNT_COMPAT\n");
			break;
		case IP_FW_F_PIPE_COMPAT:
			printf("IP_FW_F_PIPE_COMPAT\n");
			break;
		case IP_FW_F_QUEUE_COMPAT:
			printf("IP_FW_F_QUEUE_COMPAT\n");
			break;
		case IP_FW_F_SKIPTO_COMPAT:
			printf("IP_FW_F_SKIPTO_COMPAT\n");
			break;
		case IP_FW_F_DIVERT_COMPAT:
			printf("IP_FW_F_DIVERT_COMPAT\n");
			break;
		case IP_FW_F_TEE_COMPAT:
			printf("IP_FW_F_TEE_COMPAT\n");
			break;
		case IP_FW_F_FWD_COMPAT:
			printf("IP_FW_F_FWD_COMPAT\n");
			break;
		case IP_FW_F_DENY_COMPAT:
			printf("IP_FW_F_DENY_COMPAT\n");
			break;
		case IP_FW_F_REJECT_COMPAT:
			printf("IP_FW_F_REJECT_COMPAT\n");
			break;
		case IP_FW_F_CHECK_S_COMPAT:
			printf("IP_FW_F_CHECK_S_COMPAT\n");
			break;
		default:
			printf("No action given\n");
			break;
	}

	/* print commands */
	if (flags & IP_FW_F_IN_COMPAT) {
		printf("IP_FW_F_IN_COMPAT\n");
	}
	if (flags & IP_FW_F_OUT_COMPAT) {
		printf("IP_FW_F_OUT_COMPAT\n");
	}
	if (flags & IP_FW_F_IIFACE_COMPAT) {
		printf("IP_FW_F_IIFACE_COMPAT\n");
	}
	if (flags & IP_FW_F_OIFACE_COMPAT) {
		printf("IP_FW_F_OIFACE_COMPAT\n");
	}
	if (flags & IP_FW_F_PRN_COMPAT) {
		printf("IP_FW_F_PRN_COMPAT\n");
	}
	if (flags & IP_FW_F_SRNG_COMPAT) {
		printf("IP_FW_F_SRNG_COMPAT\n");
	}
	if (flags & IP_FW_F_DRNG_COMPAT) {
		printf("IP_FW_F_DRNG_COMPAT\n");
	}
	if (flags & IP_FW_F_FRAG_COMPAT) {
		printf("IP_FW_F_FRAG_COMPAT\n");
	}
	if (flags & IP_FW_F_IIFNAME_COMPAT) {
		printf("IP_FW_F_IIFNAME_COMPAT\n");
	}
	if (flags & IP_FW_F_OIFNAME_COMPAT) {
		printf("IP_FW_F_OIFNAME_COMPAT\n");
	}
	if (flags & IP_FW_F_INVSRC_COMPAT) {
		printf("IP_FW_F_INVSRC_COMPAT\n");
	}
	if (flags & IP_FW_F_INVDST_COMPAT) {
		printf("IP_FW_F_INVDST_COMPAT\n");
	}
	if (flags & IP_FW_F_ICMPBIT_COMPAT) {
		printf("IP_FW_F_ICMPBIT_COMPAT\n");
	}
	if (flags & IP_FW_F_UID_COMPAT) {
		printf("IP_FW_F_UID_COMPAT\n");
	}
	if (flags & IP_FW_F_RND_MATCH_COMPAT) {
		printf("IP_FW_F_RND_MATCH_COMPAT\n");
	}
	if (flags & IP_FW_F_SMSK_COMPAT) {
		printf("IP_FW_F_SMSK_COMPAT\n");
	}
	if (flags & IP_FW_F_DMSK_COMPAT) {
		printf("IP_FW_F_DMSK_COMPAT\n");
	}
	if (flags & IP_FW_BRIDGED_COMPAT) {
		printf("IP_FW_BRIDGED_COMPAT\n");
	}
	if (flags & IP_FW_F_KEEP_S_COMPAT) {
		printf("IP_FW_F_KEEP_S_COMPAT\n");
	}
	if (flags & IP_FW_F_CHECK_S_COMPAT) {
		printf("IP_FW_F_CHECK_S_COMPAT\n");
	}
	if (flags & IP_FW_F_SME_COMPAT) {
		printf("IP_FW_F_SME_COMPAT\n");
	}
	if (flags & IP_FW_F_DME_COMPAT) {
		printf("IP_FW_F_DME_COMPAT\n");
	}
}

static void
print_fw_version(u_int32_t api_version)
{
	switch (api_version) {
		case IP_FW_VERSION_0:
			printf("Version: %s\n", VERSION_ZERO_STR);
			break;
		case IP_FW_VERSION_1:
			printf("Version: %s\n", VERSION_ONE_STR);
			break;
		case IP_FW_CURRENT_API_VERSION:
			printf("Version: %s\n", CURRENT_API_VERSION_STR);
			break;
		case IP_FW_VERSION_NONE:
			printf("Version: %s\n", NO_VERSION_STR);
			break;
		default:
			printf("Unrecognized version\n");
			break;
	}
}

static void
print_icmptypes(ipfw_insn_u32 *cmd)
{
	int i;
	char sep= ' ';

	printf(" icmptypes");
	for (i = 0; i < 32; i++) {
		if ( (cmd->d[0] & (1 << (i))) == 0)
			continue;
		printf("%c%d", sep, i);
		sep = ',';
	}
}

/*
 * print flags set/clear in the two bitmasks passed as parameters.
 * There is a specialized check for f_tcpflags.
 */
static void
print_flags(char const *name, ipfw_insn *cmd, struct _s_x *list)
{
	char const *comma = "";
	int i;
	uint8_t set = cmd->arg1 & 0xff;
	uint8_t clear = (cmd->arg1 >> 8) & 0xff;

	if (list == f_tcpflags && set == TH_SYN && clear == TH_ACK) {
		printf(" setup");
		return;
	}

	printf(" %s ", name);
	for (i=0; list[i].x != 0; i++) {
		if (set & list[i].x) {
			set &= ~list[i].x;
			printf("%s%s", comma, list[i].s);
			comma = ",";
		}
		if (clear & list[i].x) {
			clear &= ~list[i].x;
			printf("%s!%s", comma, list[i].s);
			comma = ",";
		}
	}
}

static int
contigmask(uint8_t *p, int len)
{
	int i, n;

	for (i=0; i<len ; i++)
		if ( (p[i/8] & (1 << (7 - (i%8)))) == 0) /* first bit unset */
			break;
	for (n=i+1; n < len; n++)
		if ( (p[n/8] & (1 << (7 - (n%8)))) != 0)
			return -1; /* mask not contiguous */
	return i;
}

/*
 * Print the ip address contained in a command.
 */
static void
print_ip(ipfw_insn_ip *cmd)
{
	int len = F_LEN((ipfw_insn *)cmd);
	uint32_t *a = ((ipfw_insn_u32 *)cmd)->d;
	char ipv4str[MAX_IPv4_STR_LEN];

	printf("%s ", cmd->o.len & F_NOT ? " not": "");

	if (cmd->o.opcode == O_IP_SRC_ME || cmd->o.opcode == O_IP_DST_ME) {
		printf("me");
		return;
	}

	/*
	 * len == 2 indicates a single IP, whereas lists of 1 or more
	 * addr/mask pairs have len = (2n+1). We convert len to n so we
	 * use that to count the number of entries.
	 */
    for (len = len / 2; len > 0; len--, a += 2) {
	int mb =	/* mask length */
	    (cmd->o.opcode == O_IP_SRC || cmd->o.opcode == O_IP_DST) ?
		32 : contigmask((uint8_t *)&(a[1]), 32);
	if (mb == 0) {	/* any */
		printf("any");
	} else {		/* numeric IP followed by some kind of mask */
		printf("%s", inet_ntop(AF_INET, &a[0], ipv4str, sizeof(ipv4str)));
		if (mb < 0)
			printf(":%s", inet_ntop(AF_INET, &a[1], ipv4str, sizeof(ipv4str)));
		else if (mb < 32)
			printf("/%d", mb);
	}
	if (len > 1)
		printf(",");
    }
}

/*
 * prints a MAC address/mask pair
 */
static void
print_mac(uint8_t *addr, uint8_t *mask)
{
	int l = contigmask(mask, 48);

	if (l == 0)
		printf(" any");
	else {
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
		    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		if (l == -1)
			printf("&%02x:%02x:%02x:%02x:%02x:%02x",
			    mask[0], mask[1], mask[2],
			    mask[3], mask[4], mask[5]);
		else if (l < 48)
			printf("/%d", l);
	}
}

#endif /* !version #1 */

#if FW2_DEBUG_VERBOSE
static void
ipfw_print_vers2_struct(struct ip_fw *vers2_rule)
{
	int			l;
	ipfw_insn		*cmd;
	ipfw_insn_log	*logptr = NULL;
	char			ipv4str[MAX_IPv4_STR_LEN];
	
	print_fw_version(vers2_rule->version);

	printf("act_ofs: %d\n", vers2_rule->act_ofs);
	printf("cmd_len: %d\n", vers2_rule->cmd_len);
	printf("rulenum: %d\n", vers2_rule->rulenum);
	printf("set: %d\n", vers2_rule->set);
	printf("pcnt: %llu\n", vers2_rule->pcnt);
	printf("bcnt: %llu\n", vers2_rule->bcnt);
	printf("timestamp: %d\n", vers2_rule->timestamp);
	
	/*
	 * first print actions
	 */
	for (l = vers2_rule->cmd_len - vers2_rule->act_ofs, cmd = ACTION_PTR(vers2_rule);
			l > 0 ; l -= F_LEN(cmd), cmd += F_LEN(cmd)) {
		switch(cmd->opcode) {
			case O_CHECK_STATE:
				printf("check-state");
				break;
	
			case O_ACCEPT:
				printf("allow");
				break;
	
			case O_COUNT:
				printf("count");
				break;
	
			case O_DENY:
				printf("deny");
				break;
	
			case O_REJECT:
				if (cmd->arg1 == ICMP_REJECT_RST)
					printf("reset");
				else if (cmd->arg1 == ICMP_UNREACH_HOST)
					printf("reject");
				else
					printf("unreach %u", cmd->arg1);
				break;
	
			case O_SKIPTO:
				printf("skipto %u", cmd->arg1);
				break;
	
			case O_PIPE:
				printf("pipe %u", cmd->arg1);
				break;
	
			case O_QUEUE:
				printf("queue %u", cmd->arg1);
				break;
	
			case O_DIVERT:
				printf("divert %u", cmd->arg1);
				break;
	
			case O_TEE:
				printf("tee %u", cmd->arg1);
				break;
	
			case O_FORWARD_IP:
			{
				ipfw_insn_sa *s = (ipfw_insn_sa *)cmd;
	
				printf("fwd %s",
					   inet_ntop(AF_INET, &s->sa.sin_addr, ipv4str,
					   			 sizeof(ipv4str)));
				if (s->sa.sin_port)
					printf(",%d", s->sa.sin_port);
				break;
			}
	
			case O_LOG: /* O_LOG is printed last */
				logptr = (ipfw_insn_log *)cmd;
				break;
	
			default:
				printf("** unrecognized action %d len %d",
					cmd->opcode, cmd->len);
		}
	}
	if (logptr) {
		if (logptr->max_log > 0)
			printf(" log logamount %d", logptr->max_log);
		else
			printf(" log");
	}

	/*
	 * then print the body.
	 */
	for (l = vers2_rule->act_ofs, cmd = vers2_rule->cmd ;
		l > 0 ; l -= F_LEN(cmd) , cmd += F_LEN(cmd)) {
		/* useful alias */
		ipfw_insn_u32 *cmd32 = (ipfw_insn_u32 *)cmd;

		switch(cmd->opcode) {
			case O_PROB:
				break;	/* done already */
	
			case O_PROBE_STATE:
				break; /* no need to print anything here */
	
			case O_MACADDR2: 
			{
				ipfw_insn_mac *m = (ipfw_insn_mac *)cmd;
	
				if (cmd->len & F_NOT)
					printf(" not");
				printf(" MAC");
				print_mac(m->addr, m->mask);
				print_mac(m->addr + 6, m->mask + 6);
				printf("\n");
				break;
			}
			case O_MAC_TYPE:
			{
				uint16_t *p = ((ipfw_insn_u16 *)cmd)->ports;
				int i;
	
				for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
					printf("0x%04x", p[0]);
					if (p[0] != p[1]) {
						printf("-");
						printf("0x%04x", p[1]);
					}
					printf(",");
				}
				break;
			}
			case O_IP_SRC:
			case O_IP_SRC_MASK:
			case O_IP_SRC_ME:
				print_ip((ipfw_insn_ip *)cmd);
				break;
	
			case O_IP_DST:
			case O_IP_DST_MASK:
			case O_IP_DST_ME:
				print_ip((ipfw_insn_ip *)cmd);
				break;
	
			case O_IP_DSTPORT:
			case O_IP_SRCPORT:
			{
				uint16_t *p = ((ipfw_insn_u16 *)cmd)->ports;
				int i;
	
				for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
					printf("0x%04x", p[0]);
					if (p[0] != p[1]) {
						printf("-");
						printf("0x%04x", p[1]);
					}
					printf(",");
				}
				break;
			}
			case O_PROTO: 
			{
				printf("O_PROTO");
				
				if (cmd->len & F_NOT)
					printf(" not");
	
				printf(" %u", cmd->arg1);
					
				break;
			}
	
			default: /*options ... */
			{
				if (cmd->len & F_NOT && cmd->opcode != O_IN)
					printf(" not");
				switch(cmd->opcode) {
					case O_FRAG:
						printf("O_FRAG");
						break;
		
					case O_IN:
						printf(cmd->len & F_NOT ? " out" : " O_IN");
						break;
		
					case O_LAYER2:
						printf(" O_LAYER2");
						break;
					case O_XMIT:
					case O_RECV:
					case O_VIA: 
					{
						char const *s;
						ipfw_insn_if *cmdif = (ipfw_insn_if *)cmd;
		
						if (cmd->opcode == O_XMIT)
							s = "O_XMIT";
						else if (cmd->opcode == O_RECV)
							s = "O_RECV";
						else /* if (cmd->opcode == O_VIA) */
							s = "O_VIA";
						if (cmdif->name[0] == '\0') {
							printf(" %s %s", s,
								   inet_ntop(AF_INET, &cmdif->p.ip, ipv4str,
								   			 sizeof(ipv4str)));
						}
						else if (cmdif->p.unit == -1)
							printf(" %s %s*", s, cmdif->name);
						else
							printf(" %s %s%d", s, cmdif->name,
								cmdif->p.unit);
					}
						break;
		
					case O_IPID:
						if (F_LEN(cmd) == 1)
							printf(" ipid %u", cmd->arg1 );
						else {
							uint16_t *p = ((ipfw_insn_u16 *)cmd)->ports;
							int i;
				
							for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
								printf("0x%04x", p[0]);
								if (p[0] != p[1]) {
									printf("-");
									printf("0x%04x", p[1]);
								}
								printf(",");
							}
						}
						
						break;
		
					case O_IPTTL:
						if (F_LEN(cmd) == 1)
							printf(" ipttl %u", cmd->arg1 );
						else {
							uint16_t *p = ((ipfw_insn_u16 *)cmd)->ports;
							int i;
				
							for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
								printf("0x%04x", p[0]);
								if (p[0] != p[1]) {
									printf("-");
									printf("0x%04x", p[1]);
								}
								printf(",");
							}
						}
						
						break;
		
					case O_IPVER:
						printf(" ipver %u", cmd->arg1 );
						break;
		
					case O_IPPRECEDENCE:
						printf(" ipprecedence %u", (cmd->arg1) >> 5 );
						break;
		
					case O_IPLEN:
						if (F_LEN(cmd) == 1)
							printf(" iplen %u", cmd->arg1 );
						else {
							uint16_t *p = ((ipfw_insn_u16 *)cmd)->ports;
							int i;
				
							for (i = F_LEN((ipfw_insn *)cmd) - 1; i > 0; i--, p += 2) {
								printf("0x%04x", p[0]);
								if (p[0] != p[1]) {
									printf("-");
									printf("0x%04x", p[1]);
								}
								printf(",");
							}
						}
						
						break;
		
					case O_IPOPT:
						print_flags("ipoptions", cmd, f_ipopts);
						break;
		
					case O_IPTOS:
						print_flags("iptos", cmd, f_iptos);
						break;
		
					case O_ICMPTYPE:
						print_icmptypes((ipfw_insn_u32 *)cmd);
						break;
		
					case O_ESTAB:
						printf(" established");
						break;
		
					case O_TCPFLAGS:
						print_flags("tcpflags", cmd, f_tcpflags);
						break;
		
					case O_TCPOPTS:
						print_flags("tcpoptions", cmd, f_tcpopts);
						break;
		
					case O_TCPWIN:
						printf(" tcpwin %d", ntohs(cmd->arg1));
						break;
		
					case O_TCPACK:
						printf(" tcpack %u", ntohl(cmd32->d[0]));
						break;
		
					case O_TCPSEQ:
						printf(" tcpseq %u", ntohl(cmd32->d[0]));
						break;
		
					case O_UID:
						printf(" uid %u", cmd32->d[0]);
						break;
		
					case O_GID:
						printf(" gid %u", cmd32->d[0]);
						break;
		
					case O_VERREVPATH:
						printf(" verrevpath");
						break;
		
					case O_IPSEC:
						printf(" ipsec");
						break;
		
					case O_NOP:
						break;
		
					case O_KEEP_STATE:
						printf(" keep-state");
						break;
		
					case O_LIMIT:
					{
						struct _s_x *p = limit_masks;
						ipfw_insn_limit *c = (ipfw_insn_limit *)cmd;
						uint8_t x = c->limit_mask;
						char const *comma = " ";
		
						printf(" limit");
						for (; p->x != 0 ; p++)
							if ((x & p->x) == p->x) {
								x &= ~p->x;
								printf("%s%s", comma, p->s);
								comma = ",";
							}
						printf(" %d", c->conn_limit);
						
						break;
					}
		
					default:
						printf(" [opcode %d len %d]",
							cmd->opcode, cmd->len);
				} /* switch */
			} /* default */
		} /* switch */
	} /* for */
}

#endif /* !FW2_DEBUG_VERBOSE */


/*
 * helper function, updates the pointer to cmd with the length
 * of the current command, and also cleans up the first word of
 * the new command in case it has been clobbered before.
 * from ipfw2.c
 */
static ipfw_insn *
next_cmd(ipfw_insn *cmd)
{
	cmd += F_LEN(cmd);
	bzero(cmd, sizeof(*cmd));
	return cmd;
}

/*
 * A function to fill simple commands of size 1.
 * Existing flags are preserved.
 * from ipfw2.c
 */
static void
fill_cmd(ipfw_insn *cmd, enum ipfw_opcodes opcode, uint16_t arg)
{
	cmd->opcode = opcode;
	cmd->len =  ((cmd->len) & (F_NOT | F_OR)) | 1;
	cmd->arg1 = arg;
}


static u_int32_t
fill_compat_tcpflags(u_int32_t flags) {
	u_int32_t	flags_compat = 0;
	
	if (flags & TH_FIN)
		flags_compat |= IP_FW_TCPF_FIN_COMPAT;
	if (flags & TH_SYN)
		flags_compat |= IP_FW_TCPF_SYN_COMPAT;
	if (flags & TH_RST)
		flags_compat |= IP_FW_TCPF_RST_COMPAT;
	if (flags & TH_PUSH)
		flags_compat |= IP_FW_TCPF_PSH_COMPAT;
	if (flags & TH_ACK)
		flags_compat |= IP_FW_TCPF_ACK_COMPAT;
	if (flags & TH_URG)
		flags_compat |= IP_FW_TCPF_URG_COMPAT;
		
	return flags_compat;
}


/* ********************************************
 * *********** Convert from Latest ************
 * ********************************************/

/*
 * Things we're actively ignoring:
 *	sets, sets of addresses, blocks (NOT, OR)
 */
static void
ipfw_map_from_cmds_32(struct ip_fw_32 *curr_rule, struct ip_fw_compat_32 *compat_rule)
{
	int 		l;
	ipfw_insn	*cmd;

	for (l = curr_rule->act_ofs, cmd = curr_rule->cmd ;
		l > 0 ; 
		l -= F_LEN(cmd) , cmd += F_LEN(cmd)) {
		/* useful alias */
		ipfw_insn_u32 *cmd32 = (ipfw_insn_u32 *)cmd;

		switch (cmd->opcode) {
			case O_PROTO:
				/* protocol */
				compat_rule->fw_prot = cmd->arg1;
				break;
			
			case O_IP_SRC_ME:
				compat_rule->fw_flg |= IP_FW_F_SME_COMPAT;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			
			case O_IP_SRC_MASK:
			{
				/* addr/mask */
				ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
				
				compat_rule->fw_src = ip->addr;
				compat_rule->fw_smsk = ip->mask;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			}
			
			case O_IP_SRC:
				/* one IP */
				/* source - 
				 * for now we only deal with one address
				 * per rule and ignore sets of addresses
				 */
				compat_rule->fw_src.s_addr = cmd32->d[0];
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			
			case O_IP_SRCPORT:
			{
				/* source ports */
				ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
				uint16_t		*p = ports->ports;
				int				i, j;
				
				/* copy list of ports */
				for (i = F_LEN(cmd) - 1, j = 0; i > 0; i--, j++, p += 2) {
					if (p[0] != p[1]) {
						/* this is a range */
						compat_rule->fw_flg |= IP_FW_F_SRNG_COMPAT;
						compat_rule->fw_uar_compat.fw_pts[j++] = p[0];
						compat_rule->fw_uar_compat.fw_pts[j] = p[1];
					} else {
						compat_rule->fw_uar_compat.fw_pts[j] = p[0];
					}
				}
				IP_FW_SETNSRCP_COMPAT(compat_rule, j);
				
				break;
			}

			case O_IP_DST_ME:
			/* destination */
				compat_rule->fw_flg |= IP_FW_F_DME_COMPAT;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;

			case O_IP_DST_MASK:
			{
				/* addr/mask */
				ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
				
				compat_rule->fw_dst = ip->addr;
				compat_rule->fw_dmsk = ip->mask;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;
			}
			case O_IP_DST:
				/* one IP */
				/* dest - 
				 * for now we only deal with one address
				 * per rule, and ignore sets of addresses
				 */
				compat_rule->fw_dst.s_addr = cmd32->d[0];
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;
				
			case O_IP_DSTPORT:
			{
				/* dest. ports */
				ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
				uint16_t		*p = ports->ports;
				int				i, 
								j = IP_FW_GETNSRCP_COMPAT(compat_rule);
				
				/* copy list of ports */
				for (i = F_LEN(cmd) - 1; i > 0; i--, j++, p += 2) {
					if (p[0] != p[1]) {
						/* this is a range */
						compat_rule->fw_flg |= IP_FW_F_DRNG_COMPAT;
						compat_rule->fw_uar_compat.fw_pts[j++] = p[0];
						compat_rule->fw_uar_compat.fw_pts[j] = p[1];
					} else {
						compat_rule->fw_uar_compat.fw_pts[j] = p[0];
					}
				}
				IP_FW_SETNDSTP_COMPAT(compat_rule, (j - IP_FW_GETNSRCP_COMPAT(compat_rule)));
				
				break;
			}
			
			case O_LOG:
			{
				ipfw_insn_log *c = (ipfw_insn_log *)cmd;
				
				compat_rule->fw_flg |= IP_FW_F_PRN_COMPAT;
				compat_rule->fw_logamount = c->max_log;
				break;
			}	
			case O_UID:
				compat_rule->fw_flg |= IP_FW_F_UID_COMPAT;
				compat_rule->fw_uid = cmd32->d[0];
				break;
			
			case O_IN:
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_OUT_COMPAT;
				} else {
					compat_rule->fw_flg |= IP_FW_F_IN_COMPAT;
				}
				break;
			
			case O_KEEP_STATE:
				compat_rule->fw_flg |= IP_FW_F_KEEP_S_COMPAT;
				break;

			case O_LAYER2:
				compat_rule->fw_flg |= IP_FW_BRIDGED_COMPAT;
				break;
			
			case O_XMIT:
			{
				ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					compat_rule->fw_flg |= IP_FW_F_OIFACE_COMPAT;
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->p.ip.s_addr != 0) {
					compat_rule->fw_flg |= IP_FW_F_OIFACE_COMPAT;
					ifu.fu_via_ip = ifcmd->p.ip;
				} else {
					compat_rule->fw_flg |= IP_FW_F_OIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				}
				compat_rule->fw_out_if = ifu;
				
				break;
			}
			
			case O_RECV:
			{
				ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					compat_rule->fw_flg |= IP_FW_F_IIFACE_COMPAT;
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->p.ip.s_addr != 0) {
					compat_rule->fw_flg |= IP_FW_F_IIFACE_COMPAT;
					ifu.fu_via_ip = ifcmd->p.ip;
				} else {
					compat_rule->fw_flg |= IP_FW_F_IIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				}
				compat_rule->fw_in_if = ifu;
				
				break;
			}
			
			case O_VIA:
			{
				ipfw_insn_if			*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->name[0] != '\0') {
					compat_rule->fw_flg |= IP_FW_F_IIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				} else {
					ifu.fu_via_ip = ifcmd->p.ip;
				}
				compat_rule->fw_flg |= IF_FW_F_VIAHACK_COMPAT;
				compat_rule->fw_out_if = compat_rule->fw_in_if = ifu;
				
				break;
			}

			case O_FRAG:
				compat_rule->fw_flg |= IP_FW_F_FRAG_COMPAT;
				break;
			
			case O_IPOPT:
				/* IP options */
				compat_rule->fw_ipopt = (cmd->arg1 & 0xff);
				compat_rule->fw_ipnopt = ((cmd->arg1 >> 8) & 0xff);
				break;
				
			case O_TCPFLAGS:
				/* check for "setup" */
				if ((cmd->arg1 & 0xff) == TH_SYN &&
					((cmd->arg1 >> 8) & 0xff) == TH_ACK) {
					compat_rule->fw_tcpf = IP_FW_TCPF_SYN_COMPAT;
					compat_rule->fw_tcpnf = IP_FW_TCPF_ACK_COMPAT;
				}
				else {
					compat_rule->fw_tcpf = fill_compat_tcpflags(cmd->arg1 & 0xff);
					compat_rule->fw_tcpnf = fill_compat_tcpflags((cmd->arg1 >> 8) & 0xff);
				}
				break;
				
			case O_TCPOPTS:
				/* TCP options */
				compat_rule->fw_tcpopt = (cmd->arg1 & 0xff);
				compat_rule->fw_tcpnopt = ((cmd->arg1 >> 8) & 0xff);
				break;
			
			case O_ESTAB:
				compat_rule->fw_ipflg |= IP_FW_IF_TCPEST_COMPAT;
				break;
			
			case O_ICMPTYPE:
			{
				/* ICMP */
				/* XXX: check this */
				int	i, type;
				
				compat_rule->fw_flg |= IP_FW_F_ICMPBIT_COMPAT;
				for (i = 0; i < sizeof(uint32_t) ; i++) {
					type = cmd32->d[0] & i;
					
					compat_rule->fw_uar_compat.fw_icmptypes[type / (sizeof(unsigned) * 8)] |= 
						1 << (type % (sizeof(unsigned) * 8));
				}
				break;
			}
			default:
				break;
		} /* switch */
	} /* for */
}

static void
ipfw_map_from_cmds_64(struct ip_fw_64 *curr_rule, struct ip_fw_compat_64 *compat_rule)
{
	int 		l;
	ipfw_insn	*cmd;
	for (l = curr_rule->act_ofs, cmd = curr_rule->cmd ;
		l > 0 ; 
		l -= F_LEN(cmd) , cmd += F_LEN(cmd)) {
		/* useful alias */
		ipfw_insn_u32 *cmd32 = (ipfw_insn_u32 *)cmd;

		switch (cmd->opcode) {
			case O_PROTO:
				/* protocol */
				compat_rule->fw_prot = cmd->arg1;
				break;
			
			case O_IP_SRC_ME:
				compat_rule->fw_flg |= IP_FW_F_SME_COMPAT;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			
			case O_IP_SRC_MASK:
			{
				/* addr/mask */
				ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
				
				compat_rule->fw_src = ip->addr;
				compat_rule->fw_smsk = ip->mask;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			}
			
			case O_IP_SRC:
				/* one IP */
				/* source - 
				 * for now we only deal with one address
				 * per rule and ignore sets of addresses
				 */
				compat_rule->fw_src.s_addr = cmd32->d[0];
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVSRC_COMPAT;
				}
				break;
			
			case O_IP_SRCPORT:
			{
				/* source ports */
				ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
				uint16_t		*p = ports->ports;
				int				i, j;
				
				/* copy list of ports */
				for (i = F_LEN(cmd) - 1, j = 0; i > 0; i--, j++, p += 2) {
					if (p[0] != p[1]) {
						/* this is a range */
						compat_rule->fw_flg |= IP_FW_F_SRNG_COMPAT;
						compat_rule->fw_uar_compat.fw_pts[j++] = p[0];
						compat_rule->fw_uar_compat.fw_pts[j] = p[1];
					} else {
						compat_rule->fw_uar_compat.fw_pts[j] = p[0];
					}
				}
				IP_FW_SETNSRCP_COMPAT(compat_rule, j);
				
				break;
			}

			case O_IP_DST_ME:
			/* destination */
				compat_rule->fw_flg |= IP_FW_F_DME_COMPAT;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;

			case O_IP_DST_MASK:
			{
				/* addr/mask */
				ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
				
				compat_rule->fw_dst = ip->addr;
				compat_rule->fw_dmsk = ip->mask;
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;
			}
			case O_IP_DST:
				/* one IP */
				/* dest - 
				 * for now we only deal with one address
				 * per rule, and ignore sets of addresses
				 */
				compat_rule->fw_dst.s_addr = cmd32->d[0];
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_INVDST_COMPAT;
				}
				break;
				
			case O_IP_DSTPORT:
			{
				/* dest. ports */
				ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
				uint16_t		*p = ports->ports;
				int				i, 
								j = IP_FW_GETNSRCP_COMPAT(compat_rule);
				
				/* copy list of ports */
				for (i = F_LEN(cmd) - 1; i > 0; i--, j++, p += 2) {
					if (p[0] != p[1]) {
						/* this is a range */
						compat_rule->fw_flg |= IP_FW_F_DRNG_COMPAT;
						compat_rule->fw_uar_compat.fw_pts[j++] = p[0];
						compat_rule->fw_uar_compat.fw_pts[j] = p[1];
					} else {
						compat_rule->fw_uar_compat.fw_pts[j] = p[0];
					}
				}
				IP_FW_SETNDSTP_COMPAT(compat_rule, (j - IP_FW_GETNSRCP_COMPAT(compat_rule)));
				
				break;
			}
			
			case O_LOG:
			{
				ipfw_insn_log *c = (ipfw_insn_log *)cmd;
				
				compat_rule->fw_flg |= IP_FW_F_PRN_COMPAT;
				compat_rule->fw_logamount = c->max_log;
				break;
			}	
			case O_UID:
				compat_rule->fw_flg |= IP_FW_F_UID_COMPAT;
				compat_rule->fw_uid = cmd32->d[0];
				break;
			
			case O_IN:
				if (cmd->len & F_NOT) {
					compat_rule->fw_flg |= IP_FW_F_OUT_COMPAT;
				} else {
					compat_rule->fw_flg |= IP_FW_F_IN_COMPAT;
				}
				break;
			
			case O_KEEP_STATE:
				compat_rule->fw_flg |= IP_FW_F_KEEP_S_COMPAT;
				break;

			case O_LAYER2:
				compat_rule->fw_flg |= IP_FW_BRIDGED_COMPAT;
				break;
			
			case O_XMIT:
			{
				ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					compat_rule->fw_flg |= IP_FW_F_OIFACE_COMPAT;
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->p.ip.s_addr != 0) {
					compat_rule->fw_flg |= IP_FW_F_OIFACE_COMPAT;
					ifu.fu_via_ip = ifcmd->p.ip;
				} else {
					compat_rule->fw_flg |= IP_FW_F_OIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				}
				compat_rule->fw_out_if = ifu;
				
				break;
			}
			
			case O_RECV:
			{
				ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					compat_rule->fw_flg |= IP_FW_F_IIFACE_COMPAT;
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->p.ip.s_addr != 0) {
					compat_rule->fw_flg |= IP_FW_F_IIFACE_COMPAT;
					ifu.fu_via_ip = ifcmd->p.ip;
				} else {
					compat_rule->fw_flg |= IP_FW_F_IIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				}
				compat_rule->fw_in_if = ifu;
				
				break;
			}
			
			case O_VIA:
			{
				ipfw_insn_if			*ifcmd = (ipfw_insn_if *)cmd;
				union ip_fw_if_compat	ifu;
				
				if ((ifcmd->o.len == 0) && (ifcmd->name[0] == '\0')) {
					/* any */
					ifu.fu_via_ip.s_addr = 0;
				}
				else if (ifcmd->name[0] != '\0') {
					compat_rule->fw_flg |= IP_FW_F_IIFNAME_COMPAT;
					strncpy(ifu.fu_via_if_compat.name, ifcmd->name, sizeof(ifu.fu_via_if_compat.name));
					ifu.fu_via_if_compat.unit = ifcmd->p.unit;
				} else {
					ifu.fu_via_ip = ifcmd->p.ip;
				}
				compat_rule->fw_flg |= IF_FW_F_VIAHACK_COMPAT;
				compat_rule->fw_out_if = compat_rule->fw_in_if = ifu;
				
				break;
			}

			case O_FRAG:
				compat_rule->fw_flg |= IP_FW_F_FRAG_COMPAT;
				break;
			
			case O_IPOPT:
				/* IP options */
				compat_rule->fw_ipopt = (cmd->arg1 & 0xff);
				compat_rule->fw_ipnopt = ((cmd->arg1 >> 8) & 0xff);
				break;
				
			case O_TCPFLAGS:
				/* check for "setup" */
				if ((cmd->arg1 & 0xff) == TH_SYN &&
					((cmd->arg1 >> 8) & 0xff) == TH_ACK) {
					compat_rule->fw_tcpf = IP_FW_TCPF_SYN_COMPAT;
					compat_rule->fw_tcpnf = IP_FW_TCPF_ACK_COMPAT;
				}
				else {
					compat_rule->fw_tcpf = fill_compat_tcpflags(cmd->arg1 & 0xff);
					compat_rule->fw_tcpnf = fill_compat_tcpflags((cmd->arg1 >> 8) & 0xff);
				}
				break;
				
			case O_TCPOPTS:
				/* TCP options */
				compat_rule->fw_tcpopt = (cmd->arg1 & 0xff);
				compat_rule->fw_tcpnopt = ((cmd->arg1 >> 8) & 0xff);
				break;
			
			case O_ESTAB:
				compat_rule->fw_ipflg |= IP_FW_IF_TCPEST_COMPAT;
				break;
			
			case O_ICMPTYPE:
			{
				/* ICMP */
				/* XXX: check this */
				int	i, type;
				
				compat_rule->fw_flg |= IP_FW_F_ICMPBIT_COMPAT;
				for (i = 0; i < sizeof(uint32_t) ; i++) {
					type = cmd32->d[0] & i;
					
					compat_rule->fw_uar_compat.fw_icmptypes[type / (sizeof(unsigned) * 8)] |= 
						1 << (type % (sizeof(unsigned) * 8));
				}
				break;
			}
			default:
				break;
		} /* switch */
	} /* for */
}

static void
ipfw_map_from_actions_32(struct ip_fw_32 *curr_rule, struct ip_fw_compat_32 *compat_rule)
{
	int l;
	ipfw_insn	*cmd;
	
	for (l = curr_rule->cmd_len - curr_rule->act_ofs, cmd = ACTION_PTR(curr_rule);
			l > 0 ; 
			l -= F_LEN(cmd), cmd += F_LEN(cmd)) {
		switch (cmd->opcode) {
			case O_ACCEPT:
				compat_rule->fw_flg |= IP_FW_F_ACCEPT_COMPAT;
				break;
			case O_COUNT:
				compat_rule->fw_flg |= IP_FW_F_COUNT_COMPAT;
				break;
			case O_PIPE:
				compat_rule->fw_flg |= IP_FW_F_PIPE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_QUEUE:
				compat_rule->fw_flg |= IP_FW_F_QUEUE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_SKIPTO:
				compat_rule->fw_flg |= IP_FW_F_SKIPTO_COMPAT;
				compat_rule->fw_skipto_rule_compat = cmd->arg1;
				break;
			case O_DIVERT:
				compat_rule->fw_flg |= IP_FW_F_DIVERT_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_TEE:
				compat_rule->fw_flg |= IP_FW_F_TEE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_FORWARD_IP:
			{
				ipfw_insn_sa	*p = (ipfw_insn_sa *)cmd;
				
				compat_rule->fw_flg |= IP_FW_F_FWD_COMPAT;
				compat_rule->fw_fwd_ip_compat.sin_len = p->sa.sin_len;
				compat_rule->fw_fwd_ip_compat.sin_family = p->sa.sin_family;
				compat_rule->fw_fwd_ip_compat.sin_port = p->sa.sin_port;
				compat_rule->fw_fwd_ip_compat.sin_addr = p->sa.sin_addr;

				break;
			}
			case O_DENY:
				compat_rule->fw_flg |= IP_FW_F_DENY_COMPAT;
				break;
			case O_REJECT:
				compat_rule->fw_flg |= IP_FW_F_REJECT_COMPAT;
				compat_rule->fw_reject_code_compat = cmd->arg1;
				break;
			case O_CHECK_STATE:
				compat_rule->fw_flg |= IP_FW_F_CHECK_S_COMPAT;
				break;
			default:
				break;
		}
	}
}

static void
ipfw_map_from_actions_64(struct ip_fw_64 *curr_rule, struct ip_fw_compat_64 *compat_rule)
{
	int l;
	ipfw_insn	*cmd;
	for (l = curr_rule->cmd_len - curr_rule->act_ofs, cmd = ACTION_PTR(curr_rule);
			l > 0 ; 
			l -= F_LEN(cmd), cmd += F_LEN(cmd)) {
		switch (cmd->opcode) {
			case O_ACCEPT:
				compat_rule->fw_flg |= IP_FW_F_ACCEPT_COMPAT;
				break;
			case O_COUNT:
				compat_rule->fw_flg |= IP_FW_F_COUNT_COMPAT;
				break;
			case O_PIPE:
				compat_rule->fw_flg |= IP_FW_F_PIPE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_QUEUE:
				compat_rule->fw_flg |= IP_FW_F_QUEUE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_SKIPTO:
				compat_rule->fw_flg |= IP_FW_F_SKIPTO_COMPAT;
				compat_rule->fw_skipto_rule_compat = cmd->arg1;
				break;
			case O_DIVERT:
				compat_rule->fw_flg |= IP_FW_F_DIVERT_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_TEE:
				compat_rule->fw_flg |= IP_FW_F_TEE_COMPAT;
				compat_rule->fw_divert_port_compat = cmd->arg1;
				break;
			case O_FORWARD_IP:
			{
				ipfw_insn_sa	*p = (ipfw_insn_sa *)cmd;
				
				compat_rule->fw_flg |= IP_FW_F_FWD_COMPAT;
				compat_rule->fw_fwd_ip_compat.sin_len = p->sa.sin_len;
				compat_rule->fw_fwd_ip_compat.sin_family = p->sa.sin_family;
				compat_rule->fw_fwd_ip_compat.sin_port = p->sa.sin_port;
				compat_rule->fw_fwd_ip_compat.sin_addr = p->sa.sin_addr;

				break;
			}
			case O_DENY:
				compat_rule->fw_flg |= IP_FW_F_DENY_COMPAT;
				break;
			case O_REJECT:
				compat_rule->fw_flg |= IP_FW_F_REJECT_COMPAT;
				compat_rule->fw_reject_code_compat = cmd->arg1;
				break;
			case O_CHECK_STATE:
				compat_rule->fw_flg |= IP_FW_F_CHECK_S_COMPAT;
				break;
			default:
				break;
		}
	}
}

static void
ipfw_version_latest_to_one_32(struct ip_fw_32 *curr_rule, struct ip_fw_compat_32 *rule_vers1)
{
	if (!rule_vers1)
		return;
		
	bzero(rule_vers1, sizeof(struct ip_fw_compat));
	
	rule_vers1->version = IP_FW_VERSION_1;
	rule_vers1->context = CAST_DOWN_EXPLICIT(user32_addr_t,curr_rule->context);
	rule_vers1->fw_number = curr_rule->rulenum;
	rule_vers1->fw_pcnt = curr_rule->pcnt;
	rule_vers1->fw_bcnt = curr_rule->bcnt;
	rule_vers1->timestamp = curr_rule->timestamp;
	
	/* convert actions */
	ipfw_map_from_actions_32(curr_rule, rule_vers1);

	/* convert commands */
	ipfw_map_from_cmds_32(curr_rule, rule_vers1);
	
#if FW2_DEBUG_VERBOSE
	ipfw_print_vers1_struct_32(rule_vers1);
#endif
}

static void
ipfw_version_latest_to_one_64(struct ip_fw_64 *curr_rule, struct ip_fw_compat_64 *rule_vers1)
{
	if (!rule_vers1)
		return;
		
	bzero(rule_vers1, sizeof(struct ip_fw_compat));
	
	rule_vers1->version = IP_FW_VERSION_1;
	rule_vers1->context = CAST_DOWN_EXPLICIT(__uint64_t, curr_rule->context);
	rule_vers1->fw_number = curr_rule->rulenum;
	rule_vers1->fw_pcnt = curr_rule->pcnt;
	rule_vers1->fw_bcnt = curr_rule->bcnt;
	rule_vers1->timestamp = curr_rule->timestamp;
	
	/* convert actions */
	ipfw_map_from_actions_64(curr_rule, rule_vers1);

	/* convert commands */
	ipfw_map_from_cmds_64(curr_rule, rule_vers1);
	
#if FW2_DEBUG_VERBOSE
	ipfw_print_vers1_struct_64(rule_vers1);
#endif
}

/* first convert to version one then to version zero */
static void
ipfw_version_latest_to_zero(struct ip_fw *curr_rule, struct ip_old_fw *rule_vers0, int is64user)
{
	
	if ( is64user ){
		struct ip_fw_compat_64	rule_vers1;
		ipfw_version_latest_to_one_64((struct ip_fw_64*)curr_rule, &rule_vers1);
		bzero(rule_vers0, sizeof(struct ip_old_fw));
		bcopy(&rule_vers1.fw_uar_compat, &rule_vers0->fw_uar, sizeof(rule_vers1.fw_uar_compat));
		bcopy(&rule_vers1.fw_in_if, &rule_vers0->fw_in_if, sizeof(rule_vers1.fw_in_if));
		bcopy(&rule_vers1.fw_out_if, &rule_vers0->fw_out_if, sizeof(rule_vers1.fw_out_if));
		bcopy(&rule_vers1.fw_un_compat, &rule_vers0->fw_un, sizeof(rule_vers1.fw_un_compat));
		rule_vers0->fw_pcnt       = rule_vers1.fw_pcnt;
		rule_vers0->fw_bcnt       = rule_vers1.fw_bcnt;
		rule_vers0->fw_src        = rule_vers1.fw_src;
		rule_vers0->fw_dst        = rule_vers1.fw_dst;
		rule_vers0->fw_smsk       = rule_vers1.fw_smsk;
		rule_vers0->fw_dmsk       = rule_vers1.fw_dmsk;
		rule_vers0->fw_number     = rule_vers1.fw_number;
		rule_vers0->fw_flg        = rule_vers1.fw_flg;
		rule_vers0->fw_ipopt      = rule_vers1.fw_ipopt;
		rule_vers0->fw_ipnopt     = rule_vers1.fw_ipnopt;
		rule_vers0->fw_tcpf       = rule_vers1.fw_tcpf;
		rule_vers0->fw_tcpnf      = rule_vers1.fw_tcpnf;
		rule_vers0->timestamp     = rule_vers1.timestamp;
		rule_vers0->fw_prot       = rule_vers1.fw_prot;
		rule_vers0->fw_nports     = rule_vers1.fw_nports;
		rule_vers0->pipe_ptr      = CAST_DOWN_EXPLICIT(void*, rule_vers1.pipe_ptr);
		rule_vers0->next_rule_ptr = CAST_DOWN_EXPLICIT(void*, rule_vers1.next_rule_ptr);

		if (rule_vers1.fw_ipflg & IP_FW_IF_TCPEST_COMPAT) rule_vers0->fw_tcpf |= IP_OLD_FW_TCPF_ESTAB;
	}
	else {
		struct ip_fw_compat_32	rule_vers1;
		ipfw_version_latest_to_one_32( (struct ip_fw_32*)curr_rule, &rule_vers1);
		bzero(rule_vers0, sizeof(struct ip_old_fw));
		bcopy(&rule_vers1.fw_uar_compat, &rule_vers0->fw_uar, sizeof(rule_vers1.fw_uar_compat));
		bcopy(&rule_vers1.fw_in_if, &rule_vers0->fw_in_if, sizeof(rule_vers1.fw_in_if));
		bcopy(&rule_vers1.fw_out_if, &rule_vers0->fw_out_if, sizeof(rule_vers1.fw_out_if));
		bcopy(&rule_vers1.fw_un_compat, &rule_vers0->fw_un, sizeof(rule_vers1.fw_un_compat));
		rule_vers0->fw_pcnt       = rule_vers1.fw_pcnt;
		rule_vers0->fw_bcnt       = rule_vers1.fw_bcnt;
		rule_vers0->fw_src        = rule_vers1.fw_src;
		rule_vers0->fw_dst        = rule_vers1.fw_dst;
		rule_vers0->fw_smsk       = rule_vers1.fw_smsk;
		rule_vers0->fw_dmsk       = rule_vers1.fw_dmsk;
		rule_vers0->fw_number     = rule_vers1.fw_number;
		rule_vers0->fw_flg        = rule_vers1.fw_flg;
		rule_vers0->fw_ipopt      = rule_vers1.fw_ipopt;
		rule_vers0->fw_ipnopt     = rule_vers1.fw_ipnopt;
		rule_vers0->fw_tcpf       = rule_vers1.fw_tcpf;
		rule_vers0->fw_tcpnf      = rule_vers1.fw_tcpnf;
		rule_vers0->timestamp     = rule_vers1.timestamp;
		rule_vers0->fw_prot       = rule_vers1.fw_prot;
		rule_vers0->fw_nports     = rule_vers1.fw_nports;
		rule_vers0->pipe_ptr      = CAST_DOWN_EXPLICIT(void*, rule_vers1.pipe_ptr);
		rule_vers0->next_rule_ptr = CAST_DOWN_EXPLICIT(void*, rule_vers1.next_rule_ptr);

		if (rule_vers1.fw_ipflg & IP_FW_IF_TCPEST_COMPAT) rule_vers0->fw_tcpf |= IP_OLD_FW_TCPF_ESTAB;
	}

}

void
ipfw_convert_from_latest(struct ip_fw *curr_rule, void *old_rule, u_int32_t api_version, int is64user)
{
	switch (api_version) {
		case IP_FW_VERSION_0:
		{
			struct ip_old_fw	*rule_vers0 = old_rule;
			
			ipfw_version_latest_to_zero(curr_rule, rule_vers0, is64user);
			break;
		}
		case IP_FW_VERSION_1:
		{			
			if ( is64user )
				ipfw_version_latest_to_one_64((struct ip_fw_64*)curr_rule, (struct ip_fw_compat_64 *)old_rule);
			else
				ipfw_version_latest_to_one_32((struct ip_fw_32*)curr_rule, (struct ip_fw_compat_32 *)old_rule);

			break;
		}
		case IP_FW_CURRENT_API_VERSION:
			/* ipfw2 for now, don't need to do anything */
			break;
		
		default:
			/* unknown version */
			break;
	}
}


/* ********************************************
 * *********** Convert to Latest **************
 * ********************************************/

/* from ip_fw.c */
static int
ipfw_check_vers1_struct_32(struct ip_fw_compat_32 *frwl)
{
	/* Check for invalid flag bits */
	if ((frwl->fw_flg & ~IP_FW_F_MASK_COMPAT) != 0) {
		/* 
		printf(("%s undefined flag bits set (flags=%x)\n",
		    err_prefix, frwl->fw_flg));
		*/
		return (EINVAL);
	}
	if (frwl->fw_flg == IP_FW_F_CHECK_S_COMPAT) {
		/* check-state */
		return 0 ;
	}
	/* Must apply to incoming or outgoing (or both) */
	if (!(frwl->fw_flg & (IP_FW_F_IN_COMPAT | IP_FW_F_OUT_COMPAT))) {
		/*
		printf(("%s neither in nor out\n", err_prefix));
		*/
		return (EINVAL);
	}
	/* Empty interface name is no good */
	if (((frwl->fw_flg & IP_FW_F_IIFNAME_COMPAT)
	      && !*frwl->fw_in_if.fu_via_if_compat.name)
	    || ((frwl->fw_flg & IP_FW_F_OIFNAME_COMPAT)
	      && !*frwl->fw_out_if.fu_via_if_compat.name)) {
		/*
		printf(("%s empty interface name\n", err_prefix));
		*/
		return (EINVAL);
	}
	/* Sanity check interface matching */
	if ((frwl->fw_flg & IF_FW_F_VIAHACK_COMPAT) == IF_FW_F_VIAHACK_COMPAT) {
		;		/* allow "via" backwards compatibility */
	} else if ((frwl->fw_flg & IP_FW_F_IN_COMPAT)
	    && (frwl->fw_flg & IP_FW_F_OIFACE_COMPAT)) {
		/*
		printf(("%s outgoing interface check on incoming\n",
		    err_prefix));
		*/
		return (EINVAL);
	}
	/* Sanity check port ranges */
	if ((frwl->fw_flg & IP_FW_F_SRNG_COMPAT) && IP_FW_GETNSRCP_COMPAT(frwl) < 2) {
		/*
		printf(("%s src range set but n_src_p=%d\n",
		    err_prefix, IP_FW_GETNSRCP_COMPAT(frwl)));
		*/
		return (EINVAL);
	}
	if ((frwl->fw_flg & IP_FW_F_DRNG_COMPAT) && IP_FW_GETNDSTP_COMPAT(frwl) < 2) {
		/*
		printf(("%s dst range set but n_dst_p=%d\n",
		    err_prefix, IP_FW_GETNDSTP_COMPAT(frwl)));
		*/
		return (EINVAL);
	}
	if (IP_FW_GETNSRCP_COMPAT(frwl) + IP_FW_GETNDSTP_COMPAT(frwl) > IP_FW_MAX_PORTS_COMPAT) {
		/*
		printf(("%s too many ports (%d+%d)\n",
		    err_prefix, IP_FW_GETNSRCP_COMPAT(frwl), IP_FW_GETNDSTP_COMPAT(frwl)));
		*/
		return (EINVAL);
	}
	/*
	 *	Protocols other than TCP/UDP don't use port range
	 */
	if ((frwl->fw_prot != IPPROTO_TCP) &&
	    (frwl->fw_prot != IPPROTO_UDP) &&
	    (IP_FW_GETNSRCP_COMPAT(frwl) || IP_FW_GETNDSTP_COMPAT(frwl))) {
		/*
		printf(("%s port(s) specified for non TCP/UDP rule\n",
		    err_prefix));
		*/
		return (EINVAL);
	}

	/*
	 *	Rather than modify the entry to make such entries work, 
	 *	we reject this rule and require user level utilities
	 *	to enforce whatever policy they deem appropriate.
	 */
	if ((frwl->fw_src.s_addr & (~frwl->fw_smsk.s_addr)) || 
		(frwl->fw_dst.s_addr & (~frwl->fw_dmsk.s_addr))) {
		/*
		printf(("%s rule never matches\n", err_prefix));
		*/
		return (EINVAL);
	}

	if ((frwl->fw_flg & IP_FW_F_FRAG_COMPAT) &&
		(frwl->fw_prot == IPPROTO_UDP || frwl->fw_prot == IPPROTO_TCP)) {
		if (frwl->fw_nports) {
		/*
			printf(("%s cannot mix 'frag' and ports\n", err_prefix));
		*/
			return (EINVAL);
		}
		if (frwl->fw_prot == IPPROTO_TCP &&
			frwl->fw_tcpf != frwl->fw_tcpnf) {
		/*
			printf(("%s cannot mix 'frag' and TCP flags\n", err_prefix));
		*/
			return (EINVAL);
		}
	}

	/* Check command specific stuff */
	switch (frwl->fw_flg & IP_FW_F_COMMAND_COMPAT)
	{
	case IP_FW_F_REJECT_COMPAT:
		if (frwl->fw_reject_code_compat >= 0x100
		    && !(frwl->fw_prot == IPPROTO_TCP
		      && frwl->fw_reject_code_compat == IP_FW_REJECT_RST_COMPAT)) {
		/*
			printf(("%s unknown reject code\n", err_prefix));
		*/
			return (EINVAL);
		}
		break;
	case IP_FW_F_DIVERT_COMPAT:		/* Diverting to port zero is invalid */
	case IP_FW_F_TEE_COMPAT:
	case IP_FW_F_PIPE_COMPAT:              /* piping through 0 is invalid */
	case IP_FW_F_QUEUE_COMPAT:             /* piping through 0 is invalid */
		if (frwl->fw_divert_port_compat == 0) {
		/*
			printf(("%s can't divert to port 0\n", err_prefix));
		*/
			return (EINVAL);
		}
		break;
	case IP_FW_F_DENY_COMPAT:
	case IP_FW_F_ACCEPT_COMPAT:
	case IP_FW_F_COUNT_COMPAT:
	case IP_FW_F_SKIPTO_COMPAT:
	case IP_FW_F_FWD_COMPAT:
	case IP_FW_F_UID_COMPAT:
		break;
	default:
		/*
		printf(("%s invalid command\n", err_prefix));
		*/
		return (EINVAL);
	}

	return 0;
}

static int
ipfw_check_vers1_struct_64(struct ip_fw_compat_64 *frwl)
{
	/* Check for invalid flag bits */
	if ((frwl->fw_flg & ~IP_FW_F_MASK_COMPAT) != 0) {
		/* 
		printf(("%s undefined flag bits set (flags=%x)\n",
		    err_prefix, frwl->fw_flg));
		*/
		 
		return (EINVAL);
	}
	if (frwl->fw_flg == IP_FW_F_CHECK_S_COMPAT) {
		/* check-state */
		return 0 ;
	}
	/* Must apply to incoming or outgoing (or both) */
	if (!(frwl->fw_flg & (IP_FW_F_IN_COMPAT | IP_FW_F_OUT_COMPAT))) {
		/*
		printf(("%s neither in nor out\n", err_prefix));
		*/
		
		return (EINVAL);
	}
	/* Empty interface name is no good */
	if (((frwl->fw_flg & IP_FW_F_IIFNAME_COMPAT)
	      && !*frwl->fw_in_if.fu_via_if_compat.name)
	    || ((frwl->fw_flg & IP_FW_F_OIFNAME_COMPAT)
	      && !*frwl->fw_out_if.fu_via_if_compat.name)) {
		/*
		printf(("%s empty interface name\n", err_prefix));
		*/
		
		return (EINVAL);
	}
	/* Sanity check interface matching */
	if ((frwl->fw_flg & IF_FW_F_VIAHACK_COMPAT) == IF_FW_F_VIAHACK_COMPAT) {
		;		/* allow "via" backwards compatibility */
	} else if ((frwl->fw_flg & IP_FW_F_IN_COMPAT)
	    && (frwl->fw_flg & IP_FW_F_OIFACE_COMPAT)) {
		/*
		printf(("%s outgoing interface check on incoming\n",
		    err_prefix));
		*/
		
		return (EINVAL);
	}
	/* Sanity check port ranges */
	if ((frwl->fw_flg & IP_FW_F_SRNG_COMPAT) && IP_FW_GETNSRCP_COMPAT(frwl) < 2) {
		/*
		printf(("%s src range set but n_src_p=%d\n",
		    err_prefix, IP_FW_GETNSRCP_COMPAT(frwl)));
		*/
		
		return (EINVAL);
	}
	if ((frwl->fw_flg & IP_FW_F_DRNG_COMPAT) && IP_FW_GETNDSTP_COMPAT(frwl) < 2) {
		/*
		printf(("%s dst range set but n_dst_p=%d\n",
		    err_prefix, IP_FW_GETNDSTP_COMPAT(frwl)));
		*/

		return (EINVAL);
	}
	if (IP_FW_GETNSRCP_COMPAT(frwl) + IP_FW_GETNDSTP_COMPAT(frwl) > IP_FW_MAX_PORTS_COMPAT) {
		/*
		printf(("%s too many ports (%d+%d)\n",
		    err_prefix, IP_FW_GETNSRCP_COMPAT(frwl), IP_FW_GETNDSTP_COMPAT(frwl)));
		*/
		
		return (EINVAL);
	}
	/*
	 *	Protocols other than TCP/UDP don't use port range
	 */
	if ((frwl->fw_prot != IPPROTO_TCP) &&
	    (frwl->fw_prot != IPPROTO_UDP) &&
	    (IP_FW_GETNSRCP_COMPAT(frwl) || IP_FW_GETNDSTP_COMPAT(frwl))) {
		/*
		printf(("%s port(s) specified for non TCP/UDP rule\n",
		    err_prefix));
		*/
		
		return (EINVAL);
	}

	/*
	 *	Rather than modify the entry to make such entries work, 
	 *	we reject this rule and require user level utilities
	 *	to enforce whatever policy they deem appropriate.
	 */
	if ((frwl->fw_src.s_addr & (~frwl->fw_smsk.s_addr)) || 
		(frwl->fw_dst.s_addr & (~frwl->fw_dmsk.s_addr))) {
		/*
		printf(("%s rule never matches\n", err_prefix));
		*/
		
		return (EINVAL);
	}

	if ((frwl->fw_flg & IP_FW_F_FRAG_COMPAT) &&
		(frwl->fw_prot == IPPROTO_UDP || frwl->fw_prot == IPPROTO_TCP)) {
		if (frwl->fw_nports) {
		/*
			printf(("%s cannot mix 'frag' and ports\n", err_prefix));
		*/
		
			return (EINVAL);
		}
		if (frwl->fw_prot == IPPROTO_TCP &&
			frwl->fw_tcpf != frwl->fw_tcpnf) {
		/*
			printf(("%s cannot mix 'frag' and TCP flags\n", err_prefix));
		*/
		
			return (EINVAL);
		}
	}

	/* Check command specific stuff */
	switch (frwl->fw_flg & IP_FW_F_COMMAND_COMPAT)
	{
	case IP_FW_F_REJECT_COMPAT:
		if (frwl->fw_reject_code_compat >= 0x100
		    && !(frwl->fw_prot == IPPROTO_TCP
		      && frwl->fw_reject_code_compat == IP_FW_REJECT_RST_COMPAT)) {
		/*
			printf(("%s unknown reject code\n", err_prefix));
		*/
		
			return (EINVAL);
		}
		break;
	case IP_FW_F_DIVERT_COMPAT:		/* Diverting to port zero is invalid */
	case IP_FW_F_TEE_COMPAT:
	case IP_FW_F_PIPE_COMPAT:              /* piping through 0 is invalid */
	case IP_FW_F_QUEUE_COMPAT:             /* piping through 0 is invalid */
		if (frwl->fw_divert_port_compat == 0) {
		/*
			printf(("%s can't divert to port 0\n", err_prefix));
		*/
		
			return (EINVAL);
		}
		break;
	case IP_FW_F_DENY_COMPAT:
	case IP_FW_F_ACCEPT_COMPAT:
	case IP_FW_F_COUNT_COMPAT:
	case IP_FW_F_SKIPTO_COMPAT:
	case IP_FW_F_FWD_COMPAT:
	case IP_FW_F_UID_COMPAT:
		break;
	default:
		/*
		printf(("%s invalid command\n", err_prefix));
		*/
		
		return (EINVAL);
	}

	return 0;
}

static void
ipfw_convert_to_cmds_32(struct ip_fw *curr_rule, struct ip_fw_compat_32 *compat_rule)
{
	int			k;	
	uint32_t	actbuf[255], cmdbuf[255];
	ipfw_insn	*action, *cmd, *src, *dst;
	ipfw_insn	*have_state = NULL;	/* track check-state or keep-state */
	
	if (!compat_rule || !curr_rule || !(curr_rule->cmd)) {
		return;
	}

	/* preemptively check the old ip_fw rule to
	 * make sure it's valid before starting to copy stuff
	 */
	if (ipfw_check_vers1_struct_32(compat_rule)) {
		/* bad rule */
		return;
	}
	
	bzero(actbuf, sizeof(actbuf));		/* actions go here */
	bzero(cmdbuf, sizeof(cmdbuf));

	/* fill in action */
	action = (ipfw_insn *)actbuf;
	{
	u_int	flag = compat_rule->fw_flg;
	
	action->len = 1;	/* default */
	
	if (flag & IP_FW_F_CHECK_S_COMPAT) {
		have_state = action;
		action->opcode = O_CHECK_STATE;
	} 
	else {
		switch (flag & IP_FW_F_COMMAND_COMPAT) {
			case IP_FW_F_ACCEPT_COMPAT:
				action->opcode = O_ACCEPT;
				break;
			case IP_FW_F_COUNT_COMPAT:
				action->opcode = O_COUNT;
				break;
			case IP_FW_F_PIPE_COMPAT:
				action->opcode = O_PIPE;
				action->len = F_INSN_SIZE(ipfw_insn_pipe);
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_QUEUE_COMPAT:
				action->opcode = O_QUEUE;
				action->len = F_INSN_SIZE(ipfw_insn_pipe);
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_SKIPTO_COMPAT:
				action->opcode = O_SKIPTO;
				action->arg1 = compat_rule->fw_skipto_rule_compat;
				break;
			case IP_FW_F_DIVERT_COMPAT:
				action->opcode = O_DIVERT;
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_TEE_COMPAT:
				action->opcode = O_TEE;
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_FWD_COMPAT:
			{
				ipfw_insn_sa *p = (ipfw_insn_sa *)action;
				
				action->opcode = O_FORWARD_IP;
				action->len = F_INSN_SIZE(ipfw_insn_sa);
				
				p->sa.sin_len = compat_rule->fw_fwd_ip_compat.sin_len;
				p->sa.sin_family = compat_rule->fw_fwd_ip_compat.sin_family;
				p->sa.sin_port = compat_rule->fw_fwd_ip_compat.sin_port;
				p->sa.sin_addr = compat_rule->fw_fwd_ip_compat.sin_addr;
				
				break;
			}
			case IP_FW_F_DENY_COMPAT:
				action->opcode = O_DENY;
				action->arg1 = 0;
				break;
			case IP_FW_F_REJECT_COMPAT:
				action->opcode = O_REJECT;
				action->arg1 = compat_rule->fw_reject_code_compat;
				break;
			default:
				action->opcode = O_NOP;
				break;
		}
	}
	
	/* action is mandatory */
	if (action->opcode == O_NOP) {
			return;
	}
	
	action = next_cmd(action);
	} /* end actions */
	
	cmd = (ipfw_insn *)cmdbuf;

	/* this is O_CHECK_STATE, we're done */
	if (have_state) {
			goto done;
	}

	{
	ipfw_insn		*prev = NULL;
	u_int			flag = compat_rule->fw_flg;
	
	/* logging */
	if (flag & IP_FW_F_PRN_COMPAT) {
		ipfw_insn_log *c = (ipfw_insn_log *)cmd;
		
		cmd->opcode = O_LOG;
		cmd->len |= F_INSN_SIZE(ipfw_insn_log);
		c->max_log = compat_rule->fw_logamount;

		prev = cmd;
		cmd = next_cmd(cmd);
	}

	/* protocol */
	if (compat_rule->fw_prot != 0) {
		fill_cmd(cmd, O_PROTO, compat_rule->fw_prot);
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* source */
	if (flag & IP_FW_F_SME_COMPAT) {
		cmd->opcode = O_IP_SRC_ME;
		cmd->len |= F_INSN_SIZE(ipfw_insn);
		if (flag & IP_FW_F_INVSRC_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (compat_rule->fw_smsk.s_addr != 0) {
			/* addr/mask */
			ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
			
			ip->addr = compat_rule->fw_src;
			ip->mask = compat_rule->fw_smsk;
			cmd->opcode = O_IP_SRC_MASK;
			cmd->len |= F_INSN_SIZE(ipfw_insn_ip); /* double check this */
		} else {
			/* one IP */
			ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
			if (compat_rule->fw_src.s_addr == 0) {
				/* any */
				cmd32->o.len &= ~F_LEN_MASK;	/* zero len */
			} else {
				cmd32->d[0] = compat_rule->fw_src.s_addr;
				cmd32->o.opcode = O_IP_SRC;
				cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			}
		}
		
		if (flag & IP_FW_F_INVSRC_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		if (F_LEN(cmd) != 0) { /* !any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* source ports */
	{
		ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
		uint16_t		*p = ports->ports;
		int				i, j = 0, 
						nports = IP_FW_GETNSRCP_COMPAT(compat_rule),
						have_range = 0;
		
		cmd->opcode = O_IP_SRCPORT;
		for (i = 0; i < nports; i++) {
			if (((flag & IP_FW_F_SRNG_COMPAT) ||
				(flag & IP_FW_F_SMSK_COMPAT)) && !have_range) {
				p[0] = compat_rule->fw_uar_compat.fw_pts[i++];
				p[1] = compat_rule->fw_uar_compat.fw_pts[i];
				have_range = 1;
			} else {
				p[0] = p[1] = compat_rule->fw_uar_compat.fw_pts[i];
			}
			p += 2;
			j++;
		}
		
		if (j > 0) {
			ports->o.len |= j+1; /* leave F_NOT and F_OR untouched */
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* destination */
	if (flag & IP_FW_F_DME_COMPAT) {
		cmd->opcode = O_IP_DST_ME;
		cmd->len |= F_INSN_SIZE(ipfw_insn);
		if (flag & IP_FW_F_INVDST_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (compat_rule->fw_dmsk.s_addr != 0) {
			/* addr/mask */
			ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
			
			ip->addr = compat_rule->fw_dst;
			ip->mask = compat_rule->fw_dmsk;
			cmd->opcode = O_IP_DST_MASK;
			cmd->len |= F_INSN_SIZE(ipfw_insn_ip); /* double check this */
		} else {
			/* one IP */
			ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
			if (compat_rule->fw_dst.s_addr == 0) {
				/* any */
				cmd32->o.len &= ~F_LEN_MASK;	/* zero len */
			} else {
				cmd32->d[0] = compat_rule->fw_dst.s_addr;
				cmd32->o.opcode = O_IP_DST;
				cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			}
		}
		
		if (flag & IP_FW_F_INVDST_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		if (F_LEN(cmd) != 0) { /* !any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* dest. ports */
	{
		ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
		uint16_t		*p = ports->ports;
		int				i = IP_FW_GETNSRCP_COMPAT(compat_rule), 
						j = 0, 
						nports = (IP_FW_GETNDSTP_COMPAT(compat_rule) + i),
						have_range = 0;
		
		cmd->opcode = O_IP_DSTPORT;
		for (; i < nports; i++, p += 2) {
			if (((flag & IP_FW_F_DRNG_COMPAT) ||
				(flag & IP_FW_F_DMSK_COMPAT)) && !have_range) {
				/* range */
				p[0] = compat_rule->fw_uar_compat.fw_pts[i++];
				p[1] = compat_rule->fw_uar_compat.fw_pts[i];
				have_range = 1;
			} else {
				p[0] = p[1] = compat_rule->fw_uar_compat.fw_pts[i];
			}
			j++;
		}
		
		if (j > 0) {
			ports->o.len |= j+1; /* leave F_NOT and F_OR untouched */
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (flag & IP_FW_F_UID_COMPAT) {
		ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
		cmd32->o.opcode = O_UID;
		cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		cmd32->d[0] = compat_rule->fw_uid;

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (flag & IP_FW_F_KEEP_S_COMPAT) {
		have_state = cmd;
		fill_cmd(cmd, O_KEEP_STATE, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	if (flag & IP_FW_BRIDGED_COMPAT) {
		fill_cmd(cmd, O_LAYER2, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if ((flag & IF_FW_F_VIAHACK_COMPAT) == IF_FW_F_VIAHACK_COMPAT) {
		/* via */
		ipfw_insn_if			*ifcmd = (ipfw_insn_if *)cmd;
		union ip_fw_if_compat	ifu = compat_rule->fw_in_if;
		
		cmd->opcode = O_VIA;
		ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
		
		if (ifu.fu_via_ip.s_addr == 0) {
			/* "any" */
			ifcmd->name[0] = '\0';
			ifcmd->o.len = 0;
		}
		else if (compat_rule->fw_flg & IP_FW_F_IIFNAME_COMPAT) {
			/* by name */
			strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
			ifcmd->p.unit = ifu.fu_via_if_compat.unit;
		} else {
			/* by addr */
			ifcmd->p.ip = ifu.fu_via_ip;
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (flag & IP_FW_F_IN_COMPAT) {
			fill_cmd(cmd, O_IN, 0);
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
		if (flag & IP_FW_F_OUT_COMPAT) {
			/* if the previous command was O_IN, and this
			 * is being set as well, it's equivalent to not
			 * having either command, so let's back up prev 
			 * to the cmd before it and move cmd to prev.
			 */
			if (prev->opcode == O_IN) {
				cmd = prev;
				bzero(cmd, sizeof(*cmd));
			} else {
				cmd->len ^= F_NOT; /* toggle F_NOT */
				fill_cmd(cmd, O_IN, 0);
		
				prev = cmd;
				cmd = next_cmd(cmd);
			}
		}
		if (flag & IP_FW_F_OIFACE_COMPAT) {
			/* xmit */
			ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
			union ip_fw_if_compat	ifu = compat_rule->fw_out_if;
			
			cmd->opcode = O_XMIT;
			ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
	
			if (ifu.fu_via_ip.s_addr == 0) {
				/* "any" */
				ifcmd->name[0] = '\0';
				ifcmd->o.len = 0;
			}
			else if (flag & IP_FW_F_OIFNAME_COMPAT) {
				/* by name */
				strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
				ifcmd->p.unit = ifu.fu_via_if_compat.unit;
			} else {
				/* by addr */
				ifcmd->p.ip = ifu.fu_via_ip;
			}
	
			prev = cmd;
			cmd = next_cmd(cmd);
		} 
		else if (flag & IP_FW_F_IIFACE_COMPAT) {
			/* recv */
			ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
			union ip_fw_if_compat	ifu = compat_rule->fw_in_if;
			
			cmd->opcode = O_RECV;
			ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
	
			if (ifu.fu_via_ip.s_addr == 0) {
				/* "any" */
				ifcmd->name[0] = '\0';
				ifcmd->o.len = 0;
			}
			else if (flag & IP_FW_F_IIFNAME_COMPAT) {
				/* by name */
				strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
				ifcmd->p.unit = ifu.fu_via_if_compat.unit;
			} else {
				/* by addr */
				ifcmd->p.ip = ifu.fu_via_ip;
			}
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	if (flag & IP_FW_F_FRAG_COMPAT) {
		fill_cmd(cmd, O_FRAG, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* IP options */
	if (compat_rule->fw_ipopt != 0 || compat_rule->fw_ipnopt != 0) {
		fill_cmd(cmd, O_IPOPT, (compat_rule->fw_ipopt & 0xff) |
								(compat_rule->fw_ipnopt & 0xff) << 8);
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (compat_rule->fw_prot == IPPROTO_TCP) {
		if (compat_rule->fw_ipflg & IP_FW_IF_TCPEST_COMPAT) {
			fill_cmd(cmd, O_ESTAB, 0);
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	
		/* TCP options and flags */
		if (compat_rule->fw_tcpf != 0 || compat_rule->fw_tcpnf != 0) {
			if ((compat_rule->fw_tcpf & IP_FW_TCPF_SYN_COMPAT) &&
				compat_rule->fw_tcpnf & IP_FW_TCPF_ACK_COMPAT) {
				fill_cmd(cmd, O_TCPFLAGS, (TH_SYN) | ( (TH_ACK) & 0xff) <<8);
				
				prev = cmd;
				cmd = next_cmd(cmd);
			}
			else {
				fill_cmd(cmd, O_TCPFLAGS, (compat_rule->fw_tcpf & 0xff) |
											(compat_rule->fw_tcpnf & 0xff) << 8);
				
				prev = cmd;
				cmd = next_cmd(cmd);
			}
		}
		if (compat_rule->fw_tcpopt != 0 || compat_rule->fw_tcpnopt != 0) {
			fill_cmd(cmd, O_TCPOPTS, (compat_rule->fw_tcpopt & 0xff) |
										(compat_rule->fw_tcpnopt & 0xff) << 8);
			
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* ICMP */
	/* XXX: check this */
	if (flag & IP_FW_F_ICMPBIT_COMPAT) {
		int	i;
		ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
		
		cmd32->o.opcode = O_ICMPTYPE;
		cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		
		for (i = 0; i < IP_FW_ICMPTYPES_DIM_COMPAT; i++) {
			cmd32->d[0] |= compat_rule->fw_uar_compat.fw_icmptypes[i];
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	} /* end commands */
	
done:
	/* finally, copy everything into the current 
	 * rule buffer in the right order.
	 */
	dst = curr_rule->cmd;
	
	/* first, do match probability */
	if (compat_rule->fw_flg & IP_FW_F_RND_MATCH_COMPAT) {
		dst->opcode = O_PROB;
		dst->len = 2;
		*((int32_t *)(dst+1)) = compat_rule->pipe_ptr;
		dst += dst->len;
	}
	
	/* generate O_PROBE_STATE if necessary */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		fill_cmd(dst, O_PROBE_STATE, 0);
		dst = next_cmd(dst);
	}
	
	/*
	 * copy all commands but O_LOG, O_KEEP_STATE
	 */
	for (src = (ipfw_insn *)cmdbuf; src != cmd; src += k) {
		k = F_LEN(src);

		switch (src->opcode) {
		case O_LOG:
		case O_KEEP_STATE:
			break;
		default:
			bcopy(src, dst, k * sizeof(uint32_t));
			dst += k;
		}
	}

	/*
	 * put back the have_state command as last opcode
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		k = F_LEN(have_state);
		bcopy(have_state, dst, k * sizeof(uint32_t));
		dst += k;
	}
	
	/*
	 * start action section
	 */
	curr_rule->act_ofs = dst - curr_rule->cmd;

	/*
	 * put back O_LOG if necessary
	 */
	src = (ipfw_insn *)cmdbuf;
	if (src->opcode == O_LOG) {
		k = F_LEN(src);
		bcopy(src, dst, k * sizeof(uint32_t));
		dst += k;
	}
	
	/*
	 * copy all other actions
	 */
	for (src = (ipfw_insn *)actbuf; src != action; src += k) {
		k = F_LEN(src);
		bcopy(src, dst, k * sizeof(uint32_t));
		dst += k;
	}

	curr_rule->cmd_len = (uint32_t *)dst - (uint32_t *)(curr_rule->cmd);
	
	return;
}

static void
ipfw_convert_to_cmds_64(struct ip_fw *curr_rule, struct ip_fw_compat_64 *compat_rule)
{
	int			k;	
	uint32_t	actbuf[255], cmdbuf[255];
	ipfw_insn	*action, *cmd, *src, *dst;
	ipfw_insn	*have_state = NULL;	/* track check-state or keep-state */
	
	if (!compat_rule || !curr_rule || !(curr_rule->cmd)) {
		return;
	}

	/* preemptively check the old ip_fw rule to
	 * make sure it's valid before starting to copy stuff
	 */
	if (ipfw_check_vers1_struct_64(compat_rule)) {
		/* bad rule */
		return;
	}
	
	bzero(actbuf, sizeof(actbuf));		/* actions go here */
	bzero(cmdbuf, sizeof(cmdbuf));
	/* fill in action */
	action = (ipfw_insn *)actbuf;
	{
	u_int	flag = compat_rule->fw_flg;
	
	action->len = 1;	/* default */
	
	if (flag & IP_FW_F_CHECK_S_COMPAT) {
		have_state = action;
		action->opcode = O_CHECK_STATE;
	} 
	else {
		switch (flag & IP_FW_F_COMMAND_COMPAT) {
			case IP_FW_F_ACCEPT_COMPAT:
				action->opcode = O_ACCEPT;
				break;
			case IP_FW_F_COUNT_COMPAT:
				action->opcode = O_COUNT;
				break;
			case IP_FW_F_PIPE_COMPAT:
				action->opcode = O_PIPE;
				action->len = F_INSN_SIZE(ipfw_insn_pipe);
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_QUEUE_COMPAT:
				action->opcode = O_QUEUE;
				action->len = F_INSN_SIZE(ipfw_insn_pipe);
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_SKIPTO_COMPAT:
				action->opcode = O_SKIPTO;
				action->arg1 = compat_rule->fw_skipto_rule_compat;
				break;
			case IP_FW_F_DIVERT_COMPAT:
				action->opcode = O_DIVERT;
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_TEE_COMPAT:
				action->opcode = O_TEE;
				action->arg1 = compat_rule->fw_divert_port_compat;
				break;
			case IP_FW_F_FWD_COMPAT:
			{
				ipfw_insn_sa *p = (ipfw_insn_sa *)action;
				
				action->opcode = O_FORWARD_IP;
				action->len = F_INSN_SIZE(ipfw_insn_sa);
				
				p->sa.sin_len = compat_rule->fw_fwd_ip_compat.sin_len;
				p->sa.sin_family = compat_rule->fw_fwd_ip_compat.sin_family;
				p->sa.sin_port = compat_rule->fw_fwd_ip_compat.sin_port;
				p->sa.sin_addr = compat_rule->fw_fwd_ip_compat.sin_addr;
				
				break;
			}
			case IP_FW_F_DENY_COMPAT:
				action->opcode = O_DENY;
				action->arg1 = 0;
				break;
			case IP_FW_F_REJECT_COMPAT:
				action->opcode = O_REJECT;
				action->arg1 = compat_rule->fw_reject_code_compat;
				break;
			default:
				action->opcode = O_NOP;
				break;
		}
	}
	
	/* action is mandatory */
	if (action->opcode == O_NOP) {
			return;
	}
	
	action = next_cmd(action);
	} /* end actions */
	
	cmd = (ipfw_insn *)cmdbuf;

	/* this is O_CHECK_STATE, we're done */
	if (have_state) {
			goto done;
	}

	{
	ipfw_insn		*prev = NULL;
	u_int			flag = compat_rule->fw_flg;
	
	/* logging */
	if (flag & IP_FW_F_PRN_COMPAT) {
		ipfw_insn_log *c = (ipfw_insn_log *)cmd;
		
		cmd->opcode = O_LOG;
		cmd->len |= F_INSN_SIZE(ipfw_insn_log);
		c->max_log = compat_rule->fw_logamount;

		prev = cmd;
		cmd = next_cmd(cmd);
	}

	/* protocol */
	if (compat_rule->fw_prot != 0) {
		fill_cmd(cmd, O_PROTO, compat_rule->fw_prot);
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* source */
	if (flag & IP_FW_F_SME_COMPAT) {
		cmd->opcode = O_IP_SRC_ME;
		cmd->len |= F_INSN_SIZE(ipfw_insn);
		if (flag & IP_FW_F_INVSRC_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (compat_rule->fw_smsk.s_addr != 0) {
			/* addr/mask */
			ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
			
			ip->addr = compat_rule->fw_src;
			ip->mask = compat_rule->fw_smsk;
			cmd->opcode = O_IP_SRC_MASK;
			cmd->len |= F_INSN_SIZE(ipfw_insn_ip); /* double check this */
		} else {
			/* one IP */
			ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
			if (compat_rule->fw_src.s_addr == 0) {
				/* any */
				cmd32->o.len &= ~F_LEN_MASK;	/* zero len */
			} else {
				cmd32->d[0] = compat_rule->fw_src.s_addr;
				cmd32->o.opcode = O_IP_SRC;
				cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			}
		}
		
		if (flag & IP_FW_F_INVSRC_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		if (F_LEN(cmd) != 0) { /* !any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* source ports */
	{
		ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
		uint16_t		*p = ports->ports;
		int				i, j = 0, 
						nports = IP_FW_GETNSRCP_COMPAT(compat_rule),
						have_range = 0;
		
		cmd->opcode = O_IP_SRCPORT;
		for (i = 0; i < nports; i++) {
			if (((flag & IP_FW_F_SRNG_COMPAT) ||
				(flag & IP_FW_F_SMSK_COMPAT)) && !have_range) {
				p[0] = compat_rule->fw_uar_compat.fw_pts[i++];
				p[1] = compat_rule->fw_uar_compat.fw_pts[i];
				have_range = 1;
			} else {
				p[0] = p[1] = compat_rule->fw_uar_compat.fw_pts[i];
			}
			p += 2;
			j++;
		}
		
		if (j > 0) {
			ports->o.len |= j+1; /* leave F_NOT and F_OR untouched */
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* destination */
	if (flag & IP_FW_F_DME_COMPAT) {
		cmd->opcode = O_IP_DST_ME;
		cmd->len |= F_INSN_SIZE(ipfw_insn);
		if (flag & IP_FW_F_INVDST_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (compat_rule->fw_dmsk.s_addr != 0) {
			/* addr/mask */
			ipfw_insn_ip	*ip = (ipfw_insn_ip *)cmd;
			
			ip->addr = compat_rule->fw_dst;
			ip->mask = compat_rule->fw_dmsk;
			cmd->opcode = O_IP_DST_MASK;
			cmd->len |= F_INSN_SIZE(ipfw_insn_ip); /* double check this */
		} else {
			/* one IP */
			ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
			if (compat_rule->fw_dst.s_addr == 0) {
				/* any */
				cmd32->o.len &= ~F_LEN_MASK;	/* zero len */
			} else {
				cmd32->d[0] = compat_rule->fw_dst.s_addr;
				cmd32->o.opcode = O_IP_DST;
				cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			}
		}
		
		if (flag & IP_FW_F_INVDST_COMPAT) {
			cmd->len ^= F_NOT; /* toggle F_NOT */			
		}

		if (F_LEN(cmd) != 0) { /* !any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* dest. ports */
	{
		ipfw_insn_u16	*ports = (ipfw_insn_u16 *)cmd;
		uint16_t		*p = ports->ports;
		int				i = IP_FW_GETNSRCP_COMPAT(compat_rule), 
						j = 0, 
						nports = (IP_FW_GETNDSTP_COMPAT(compat_rule) + i),
						have_range = 0;
		
		cmd->opcode = O_IP_DSTPORT;
		for (; i < nports; i++, p += 2) {
			if (((flag & IP_FW_F_DRNG_COMPAT) ||
				(flag & IP_FW_F_DMSK_COMPAT)) && !have_range) {
				/* range */
				p[0] = compat_rule->fw_uar_compat.fw_pts[i++];
				p[1] = compat_rule->fw_uar_compat.fw_pts[i];
				have_range = 1;
			} else {
				p[0] = p[1] = compat_rule->fw_uar_compat.fw_pts[i];
			}
			j++;
		}
		
		if (j > 0) {
			ports->o.len |= j+1; /* leave F_NOT and F_OR untouched */
		}
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (flag & IP_FW_F_UID_COMPAT) {
		ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
			
		cmd32->o.opcode = O_UID;
		cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		cmd32->d[0] = compat_rule->fw_uid;

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (flag & IP_FW_F_KEEP_S_COMPAT) {
		have_state = cmd;
		fill_cmd(cmd, O_KEEP_STATE, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	if (flag & IP_FW_BRIDGED_COMPAT) {
		fill_cmd(cmd, O_LAYER2, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if ((flag & IF_FW_F_VIAHACK_COMPAT) == IF_FW_F_VIAHACK_COMPAT) {
		/* via */
		ipfw_insn_if			*ifcmd = (ipfw_insn_if *)cmd;
		union ip_fw_if_compat	ifu = compat_rule->fw_in_if;
		
		cmd->opcode = O_VIA;
		ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
		
		if (ifu.fu_via_ip.s_addr == 0) {
			/* "any" */
			ifcmd->name[0] = '\0';
			ifcmd->o.len = 0;
		}
		else if (compat_rule->fw_flg & IP_FW_F_IIFNAME_COMPAT) {
			/* by name */
			strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
			ifcmd->p.unit = ifu.fu_via_if_compat.unit;
		} else {
			/* by addr */
			ifcmd->p.ip = ifu.fu_via_ip;
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	} else {
		if (flag & IP_FW_F_IN_COMPAT) {
			fill_cmd(cmd, O_IN, 0);
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
		if (flag & IP_FW_F_OUT_COMPAT) {
			/* if the previous command was O_IN, and this
			 * is being set as well, it's equivalent to not
			 * having either command, so let's back up prev 
			 * to the cmd before it and move cmd to prev.
			 */
			if (prev->opcode == O_IN) {
				cmd = prev;
				bzero(cmd, sizeof(*cmd));
			} else {
				cmd->len ^= F_NOT; /* toggle F_NOT */
				fill_cmd(cmd, O_IN, 0);
		
				prev = cmd;
				cmd = next_cmd(cmd);
			}
		}
		if (flag & IP_FW_F_OIFACE_COMPAT) {
			/* xmit */
			ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
			union ip_fw_if_compat	ifu = compat_rule->fw_out_if;
			
			cmd->opcode = O_XMIT;
			ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
	
			if (ifu.fu_via_ip.s_addr == 0) {
				/* "any" */
				ifcmd->name[0] = '\0';
				ifcmd->o.len = 0;
			}
			else if (flag & IP_FW_F_OIFNAME_COMPAT) {
				/* by name */
				strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
				ifcmd->p.unit = ifu.fu_via_if_compat.unit;
			} else {
				/* by addr */
				ifcmd->p.ip = ifu.fu_via_ip;
			}
	
			prev = cmd;
			cmd = next_cmd(cmd);
		} 
		else if (flag & IP_FW_F_IIFACE_COMPAT) {
			/* recv */
			ipfw_insn_if	*ifcmd = (ipfw_insn_if *)cmd;
			union ip_fw_if_compat	ifu = compat_rule->fw_in_if;
			
			cmd->opcode = O_RECV;
			ifcmd->o.len |= F_INSN_SIZE(ipfw_insn_if);
	
			if (ifu.fu_via_ip.s_addr == 0) {
				/* "any" */
				ifcmd->name[0] = '\0';
				ifcmd->o.len = 0;
			}
			else if (flag & IP_FW_F_IIFNAME_COMPAT) {
				/* by name */
				strncpy(ifcmd->name, ifu.fu_via_if_compat.name, sizeof(ifcmd->name));
				ifcmd->p.unit = ifu.fu_via_if_compat.unit;
			} else {
				/* by addr */
				ifcmd->p.ip = ifu.fu_via_ip;
			}
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	if (flag & IP_FW_F_FRAG_COMPAT) {
		fill_cmd(cmd, O_FRAG, 0);

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	/* IP options */
	if (compat_rule->fw_ipopt != 0 || compat_rule->fw_ipnopt != 0) {
		fill_cmd(cmd, O_IPOPT, (compat_rule->fw_ipopt & 0xff) |
								(compat_rule->fw_ipnopt & 0xff) << 8);
		
		prev = cmd;
		cmd = next_cmd(cmd);
	}
	
	if (compat_rule->fw_prot == IPPROTO_TCP) {
		if (compat_rule->fw_ipflg & IP_FW_IF_TCPEST_COMPAT) {
			fill_cmd(cmd, O_ESTAB, 0);
	
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	
		/* TCP options and flags */
		if (compat_rule->fw_tcpf != 0 || compat_rule->fw_tcpnf != 0) {
			if ((compat_rule->fw_tcpf & IP_FW_TCPF_SYN_COMPAT) &&
				compat_rule->fw_tcpnf & IP_FW_TCPF_ACK_COMPAT) {
				fill_cmd(cmd, O_TCPFLAGS, (TH_SYN) | ( (TH_ACK) & 0xff) <<8);
				
				prev = cmd;
				cmd = next_cmd(cmd);
			}
			else {
				fill_cmd(cmd, O_TCPFLAGS, (compat_rule->fw_tcpf & 0xff) |
											(compat_rule->fw_tcpnf & 0xff) << 8);
				
				prev = cmd;
				cmd = next_cmd(cmd);
			}
		}
		if (compat_rule->fw_tcpopt != 0 || compat_rule->fw_tcpnopt != 0) {
			fill_cmd(cmd, O_TCPOPTS, (compat_rule->fw_tcpopt & 0xff) |
										(compat_rule->fw_tcpnopt & 0xff) << 8);
			
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}
	
	/* ICMP */
	/* XXX: check this */
	if (flag & IP_FW_F_ICMPBIT_COMPAT) {
		int	i;
		ipfw_insn_u32	*cmd32 = (ipfw_insn_u32 *)cmd;	/* alias for cmd */
		cmd32->o.opcode = O_ICMPTYPE;
		cmd32->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		
		for (i = 0; i < IP_FW_ICMPTYPES_DIM_COMPAT; i++) {
			cmd32->d[0] |= compat_rule->fw_uar_compat.fw_icmptypes[i];
		}

		prev = cmd;
		cmd = next_cmd(cmd);
	}
	} /* end commands */
done:
	/* finally, copy everything into the current 
	 * rule buffer in the right order.
	 */
	dst = curr_rule->cmd;
	
	/* first, do match probability */
	if (compat_rule->fw_flg & IP_FW_F_RND_MATCH_COMPAT) {
		dst->opcode = O_PROB;
		dst->len = 2;
		*((int32_t *)(dst+1)) = compat_rule->pipe_ptr;
		dst += dst->len;
	}
	
	/* generate O_PROBE_STATE if necessary */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		fill_cmd(dst, O_PROBE_STATE, 0);
		dst = next_cmd(dst);
	}
	
	/*
	 * copy all commands but O_LOG, O_KEEP_STATE
	 */
	for (src = (ipfw_insn *)cmdbuf; src != cmd; src += k) {
		k = F_LEN(src);
		switch (src->opcode) {
		case O_LOG:
		case O_KEEP_STATE:
			break;
		default:
			bcopy(src, dst, k * sizeof(uint32_t));
			dst += k;
		}
	}

	/*
	 * put back the have_state command as last opcode
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		k = F_LEN(have_state);
		bcopy(have_state, dst, k * sizeof(uint32_t));
		dst += k;
	}
	
	/*
	 * start action section
	 */
	curr_rule->act_ofs = dst - curr_rule->cmd;

	/*
	 * put back O_LOG if necessary
	 */
	src = (ipfw_insn *)cmdbuf;
	if (src->opcode == O_LOG) {
		k = F_LEN(src);
		bcopy(src, dst, k * sizeof(uint32_t));
		dst += k;
	}
	
	/*
	 * copy all other actions
	 */
	for (src = (ipfw_insn *)actbuf; src != action; src += k) {
		k = F_LEN(src);
		bcopy(src, dst, k * sizeof(uint32_t));
		dst += k;
	}

	curr_rule->cmd_len = (uint32_t *)dst - (uint32_t *)(curr_rule->cmd);
	return;
}

static int
ipfw_version_one_to_version_two_32(struct sockopt *sopt, struct ip_fw *curr_rule, 
								struct ip_fw_compat_32 *rule_vers1)
{
	int	err = EINVAL;
	struct ip_fw_compat_32	*rule_ptr;
	struct ip_fw_compat_32	rule;
	
	if (rule_vers1) {
		rule_ptr = rule_vers1;
		err = 0;
	} else {
		/* do some basic size checking here, more extensive checking later */
		if (!sopt->sopt_val || sopt->sopt_valsize < sizeof(struct ip_fw_compat_32))
			return err;
	
		if ((err = sooptcopyin(sopt, &rule, sizeof(struct ip_fw_compat_32), 
							sizeof(struct ip_fw_compat_32)))) {
			return err;
		}
		
		rule_ptr = &rule;
	}

	/* deal with commands */
	ipfw_convert_to_cmds_32(curr_rule, rule_ptr);

	curr_rule->version = IP_FW_CURRENT_API_VERSION;
	curr_rule->context = CAST_DOWN_EXPLICIT(void*, rule_ptr->context);
	curr_rule->rulenum = rule_ptr->fw_number;
	curr_rule->pcnt = rule_ptr->fw_pcnt;
	curr_rule->bcnt = rule_ptr->fw_bcnt;
	curr_rule->timestamp = rule_ptr->timestamp;

	
#if FW2_DEBUG_VERBOSE
	ipfw_print_vers2_struct(curr_rule);
#endif
	
	return err;
}

static int
ipfw_version_one_to_version_two_64(struct sockopt *sopt, struct ip_fw *curr_rule, 
								struct ip_fw_compat_64 *rule_vers1)
{
	int	err = EINVAL;
	struct ip_fw_compat_64	*rule_ptr;
	struct ip_fw_compat_64	rule;
	
	if (rule_vers1) {
		rule_ptr = rule_vers1;
		err = 0;
	} else {
		/* do some basic size checking here, more extensive checking later */
		if (!sopt->sopt_val || sopt->sopt_valsize < sizeof(struct ip_fw_compat_64))
			return err;
	
		if ((err = sooptcopyin(sopt, &rule, sizeof(struct ip_fw_compat_64), 
							sizeof(struct ip_fw_compat_64)))) {
			return err;
		}
		rule_ptr = &rule;
	}

	/* deal with commands */
	ipfw_convert_to_cmds_64(curr_rule, rule_ptr);

	curr_rule->version = IP_FW_CURRENT_API_VERSION;
	curr_rule->context = CAST_DOWN_EXPLICIT( void *, rule_ptr->context);
	curr_rule->rulenum = rule_ptr->fw_number;
	curr_rule->pcnt = rule_ptr->fw_pcnt;
	curr_rule->bcnt = rule_ptr->fw_bcnt;
	curr_rule->timestamp = rule_ptr->timestamp;

	
#if FW2_DEBUG_VERBOSE
	ipfw_print_vers2_struct(curr_rule);
#endif
	
	return err;
}

/* This converts to whatever the latest version is. Currently the 
 * latest version of the firewall is ipfw2.
 */
static int
ipfw_version_one_to_latest_32(struct sockopt *sopt, struct ip_fw *curr_rule, struct ip_fw_compat_32 *rule_vers1)
{
	int err;
	
	/* if rule_vers1 is not null then this is coming from
	 * ipfw_version_zero_to_latest(), so pass that along;
	 * otherwise let ipfw_version_one_to_version_two()
	 * get the rule from sopt.
	 */
	err = ipfw_version_one_to_version_two_32(sopt, curr_rule, rule_vers1);
	
	return err;
}

static int
ipfw_version_one_to_latest_64(struct sockopt *sopt, struct ip_fw *curr_rule, struct ip_fw_compat_64 *rule_vers1)
{
	int err;
	
	/* if rule_vers1 is not null then this is coming from
	 * ipfw_version_zero_to_latest(), so pass that along;
	 * otherwise let ipfw_version_one_to_version_two()
	 * get the rule from sopt.
	 */
	err = ipfw_version_one_to_version_two_64(sopt, curr_rule, rule_vers1);
	
	return err;
}


#if 0

/* 
 * XXX - ipfw_version_zero_to_one
 * 
 * This function is only used in version #1 of ipfw, which is now deprecated.
 *
 */ 

static void
ipfw_version_zero_to_one(struct ip_old_fw *rule_vers0, struct ip_fw_compat *rule_vers1)
{
	bzero(rule_vers1, sizeof(struct ip_fw_compat));
	bcopy(&rule_vers0->fw_uar, &rule_vers1->fw_uar_compat, sizeof(rule_vers0->fw_uar));
	bcopy(&rule_vers0->fw_in_if, &rule_vers1->fw_in_if, sizeof(rule_vers0->fw_in_if));
	bcopy(&rule_vers0->fw_out_if, &rule_vers1->fw_out_if, sizeof(rule_vers0->fw_out_if));
	bcopy(&rule_vers0->fw_un, &rule_vers1->fw_un_compat, sizeof(rule_vers0->fw_un));

	rule_vers1->version       = 10;
	rule_vers1->fw_pcnt       = rule_vers0->fw_pcnt;
	rule_vers1->fw_bcnt       = rule_vers0->fw_bcnt;
	rule_vers1->fw_src        = rule_vers0->fw_src;
	rule_vers1->fw_dst        = rule_vers0->fw_dst;
	rule_vers1->fw_smsk       = rule_vers0->fw_smsk;
	rule_vers1->fw_dmsk       = rule_vers0->fw_dmsk;
	rule_vers1->fw_number     = rule_vers0->fw_number;
	rule_vers1->fw_flg        = rule_vers0->fw_flg;
	rule_vers1->fw_ipopt      = rule_vers0->fw_ipopt;
	rule_vers1->fw_ipnopt     = rule_vers0->fw_ipnopt;
	rule_vers1->fw_tcpf       = rule_vers0->fw_tcpf & ~IP_OLD_FW_TCPF_ESTAB;
	rule_vers1->fw_tcpnf      = rule_vers0->fw_tcpnf;
	rule_vers1->timestamp     = rule_vers0->timestamp;
	rule_vers1->fw_prot       = rule_vers0->fw_prot;
	rule_vers1->fw_nports     = rule_vers0->fw_nports;
	rule_vers1->pipe_ptr      = rule_vers0->pipe_ptr;
	rule_vers1->next_rule_ptr = rule_vers0->next_rule_ptr;
	rule_vers1->fw_ipflg      = (rule_vers0->fw_tcpf & IP_OLD_FW_TCPF_ESTAB) ? IP_FW_IF_TCPEST_COMPAT : 0;
}

#endif /* !ipfw_version_zero_to_one  */

/* rule is a u_int32_t buffer[255] into which the converted 
 * (if necessary) rules go.
 */
int
ipfw_convert_to_latest(struct sockopt *sopt, struct ip_fw *curr_rule, int api_version, int is64user)
{
	int	err = 0;
	
	/* the following functions copy the rules passed in and
	 * convert to latest structures based on version
	 */
	switch (api_version) {
		case IP_FW_VERSION_0:
			/* we're not supporting VERSION 0 */
			err = EOPNOTSUPP;
			break;
		
		case IP_FW_VERSION_1:
			/* this is the version supported in Panther */
			if ( is64user )
				err = ipfw_version_one_to_latest_64(sopt, curr_rule, NULL);
			else
				err = ipfw_version_one_to_latest_32(sopt, curr_rule, NULL);
			break;
		
		case IP_FW_CURRENT_API_VERSION:
			/* IPFW2 for now */
			/* do nothing here... */
			break;
		
		default:
			/* unrecognized/unsupported version */
			err = EINVAL;
			break;
	}
	
	return err;
}

int
ipfw_get_command_and_version(struct sockopt *sopt, int *command, u_int32_t *api_version)
{
	int cmd;
	int err = 0;
	u_int32_t	vers = IP_FW_VERSION_NONE;
	
	/* first deal with the oldest version */
	if (sopt->sopt_name == IP_OLD_FW_GET) { 
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_GET;
	}
	else if (sopt->sopt_name == IP_OLD_FW_FLUSH) {
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_FLUSH;
	}
	else if (sopt->sopt_name == IP_OLD_FW_ZERO) { 
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_ZERO;
	}
	else if (sopt->sopt_name == IP_OLD_FW_ADD) { 
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_ADD;
	}
	else if (sopt->sopt_name == IP_OLD_FW_DEL) { 
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_DEL;
	}
	else if (sopt->sopt_name == IP_OLD_FW_RESETLOG) { 
		vers = IP_FW_VERSION_0;
		cmd = IP_FW_RESETLOG;
	}
	else { 
		cmd = sopt->sopt_name;
	}
	
	if (vers == IP_FW_VERSION_NONE) {
		/* working off the fact that the offset
		 * is the same in both structs.
		 */
		struct ip_fw_64 rule;
                size_t  copyinsize;

                if (proc_is64bit(sopt->sopt_p))
                        copyinsize = sizeof(struct ip_fw_64);
                else
                        copyinsize = sizeof(struct ip_fw_32);
	
		if (!sopt->sopt_val || sopt->sopt_valsize < copyinsize)
			return EINVAL;
		if ((err = sooptcopyin(sopt, &rule, copyinsize, copyinsize))) {
			return err;
		}
		
		vers = rule.version;
	}

	if (command) {
		*command = cmd;
	}
	if (api_version) {
		*api_version = vers;
	}
	
	return err;
}

