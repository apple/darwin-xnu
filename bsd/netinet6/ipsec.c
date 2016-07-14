/*
 * Copyright (c) 2008-2015 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/ipsec.c,v 1.3.2.7 2001/07/19 06:37:23 kris Exp $	*/
/*	$KAME: ipsec.c,v 1.103 2001/05/24 07:14:18 sakane Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IPsec controller part.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <kern/locks.h>
#include <sys/kauth.h>
#include <libkern/OSAtomic.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_ipsec.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_ecn.h>
#if INET6
#include <netinet6/ip6_ecn.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/ip6.h>
#if INET6
#include <netinet6/ip6_var.h>
#endif
#include <netinet/in_pcb.h>
#if INET6
#include <netinet/icmp6.h>
#endif

#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#if IPSEC_ESP
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#endif
#include <netinet6/ipcomp.h>
#if INET6
#include <netinet6/ipcomp6.h>
#endif
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <netkey/key_debug.h>

#include <net/net_osdep.h>

#if IPSEC_DEBUG
int ipsec_debug = 1;
#else
int ipsec_debug = 0;
#endif

#include <sys/kdebug.h>
#define DBG_LAYER_BEG			NETDBG_CODE(DBG_NETIPSEC, 1)
#define DBG_LAYER_END			NETDBG_CODE(DBG_NETIPSEC, 3)
#define DBG_FNC_GETPOL_SOCK		NETDBG_CODE(DBG_NETIPSEC, (1 << 8))
#define DBG_FNC_GETPOL_ADDR		NETDBG_CODE(DBG_NETIPSEC, (2 << 8))
#define DBG_FNC_IPSEC_OUT		NETDBG_CODE(DBG_NETIPSEC, (3 << 8))

extern lck_mtx_t *sadb_mutex;

struct ipsecstat ipsecstat;
int ip4_ah_cleartos = 1;
int ip4_ah_offsetmask = 0;	/* maybe IP_DF? */
int ip4_ipsec_dfbit = 0;	/* DF bit on encap. 0: clear 1: set 2: copy */
int ip4_esp_trans_deflev = IPSEC_LEVEL_USE;
int ip4_esp_net_deflev = IPSEC_LEVEL_USE;
int ip4_ah_trans_deflev = IPSEC_LEVEL_USE;
int ip4_ah_net_deflev = IPSEC_LEVEL_USE;
struct secpolicy ip4_def_policy;
int ip4_ipsec_ecn = ECN_COMPATIBILITY;		/* ECN ignore(-1)/compatibility(0)/normal(1) */
int ip4_esp_randpad = -1;
int	esp_udp_encap_port = 0;
static int sysctl_def_policy SYSCTL_HANDLER_ARGS;
extern int natt_keepalive_interval;
extern u_int32_t natt_now;

struct ipsec_tag;

SYSCTL_DECL(_net_inet_ipsec);
#if INET6
SYSCTL_DECL(_net_inet6_ipsec6);
#endif
/* net.inet.ipsec */
SYSCTL_STRUCT(_net_inet_ipsec, IPSECCTL_STATS,
	stats, CTLFLAG_RD | CTLFLAG_LOCKED,	&ipsecstat,	ipsecstat, "");
SYSCTL_PROC(_net_inet_ipsec, IPSECCTL_DEF_POLICY, def_policy, CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip4_def_policy.policy,	0, &sysctl_def_policy, "I", "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_ESP_TRANSLEV, esp_trans_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip4_esp_trans_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_ESP_NETLEV, esp_net_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip4_esp_net_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_AH_TRANSLEV, ah_trans_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip4_ah_trans_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEF_AH_NETLEV, ah_net_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip4_ah_net_deflev,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_AH_CLEARTOS,
	ah_cleartos, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip4_ah_cleartos,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_AH_OFFSETMASK,
	ah_offsetmask, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip4_ah_offsetmask,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DFBIT,
	dfbit, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip4_ipsec_dfbit,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_ECN,
	ecn, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip4_ipsec_ecn,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_DEBUG,
	debug, CTLFLAG_RW | CTLFLAG_LOCKED,	&ipsec_debug,	0, "");
SYSCTL_INT(_net_inet_ipsec, IPSECCTL_ESP_RANDPAD,
	esp_randpad, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip4_esp_randpad,	0, "");

/* for performance, we bypass ipsec until a security policy is set */
int ipsec_bypass = 1;
SYSCTL_INT(_net_inet_ipsec, OID_AUTO, bypass, CTLFLAG_RD | CTLFLAG_LOCKED, &ipsec_bypass,0, "");

/*
 * NAT Traversal requires a UDP port for encapsulation,
 * esp_udp_encap_port controls which port is used. Racoon
 * must set this port to the port racoon is using locally
 * for nat traversal.
 */
SYSCTL_INT(_net_inet_ipsec, OID_AUTO, esp_port,
		   CTLFLAG_RW | CTLFLAG_LOCKED, &esp_udp_encap_port, 0, "");

#if INET6
struct ipsecstat ipsec6stat;
int ip6_esp_trans_deflev = IPSEC_LEVEL_USE;
int ip6_esp_net_deflev = IPSEC_LEVEL_USE;
int ip6_ah_trans_deflev = IPSEC_LEVEL_USE;
int ip6_ah_net_deflev = IPSEC_LEVEL_USE;
struct secpolicy ip6_def_policy;
int ip6_ipsec_ecn = ECN_COMPATIBILITY;		/* ECN ignore(-1)/compatibility(0)/normal(1) */
int ip6_esp_randpad = -1;

/* net.inet6.ipsec6 */
SYSCTL_STRUCT(_net_inet6_ipsec6, IPSECCTL_STATS,
	stats, CTLFLAG_RD | CTLFLAG_LOCKED, &ipsec6stat, ipsecstat, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_POLICY,
	def_policy, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip6_def_policy.policy,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_ESP_TRANSLEV, esp_trans_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_esp_trans_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_ESP_NETLEV, esp_net_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_esp_net_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_AH_TRANSLEV, ah_trans_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_ah_trans_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEF_AH_NETLEV, ah_net_deflev,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_ah_net_deflev,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_ECN,
	ecn, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip6_ipsec_ecn,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_DEBUG,
	debug, CTLFLAG_RW | CTLFLAG_LOCKED,	&ipsec_debug,	0, "");
SYSCTL_INT(_net_inet6_ipsec6, IPSECCTL_ESP_RANDPAD,
	esp_randpad, CTLFLAG_RW | CTLFLAG_LOCKED,	&ip6_esp_randpad,	0, "");
#endif /* INET6 */

static int ipsec_setspidx_interface(struct secpolicyindex *, u_int, struct mbuf *,
                         int, int, int);
static int ipsec_setspidx_mbuf(struct secpolicyindex *, u_int, u_int,
	struct mbuf *, int);
static int ipsec4_setspidx_inpcb(struct mbuf *, struct inpcb *pcb);
#if INET6
static int ipsec6_setspidx_in6pcb(struct mbuf *, struct in6pcb *pcb);
#endif
static int ipsec_setspidx(struct mbuf *, struct secpolicyindex *, int, int);
static void ipsec4_get_ulp(struct mbuf *m, struct secpolicyindex *, int);
static int ipsec4_setspidx_ipaddr(struct mbuf *, struct secpolicyindex *);
#if INET6
static void ipsec6_get_ulp(struct mbuf *m, struct secpolicyindex *, int);
static int ipsec6_setspidx_ipaddr(struct mbuf *, struct secpolicyindex *);
#endif
static struct inpcbpolicy *ipsec_newpcbpolicy(void);
static void ipsec_delpcbpolicy(struct inpcbpolicy *);
static struct secpolicy *ipsec_deepcopy_policy(struct secpolicy *src);
static int ipsec_set_policy(struct secpolicy **pcb_sp,
							int optname, caddr_t request, size_t len, int priv);
static void vshiftl(unsigned char *, int, int);
static int ipsec_in_reject(struct secpolicy *, struct mbuf *);
#if INET6
static int ipsec64_encapsulate(struct mbuf *, struct secasvar *);
static int ipsec6_update_routecache_and_output(struct ipsec_output_state *state, struct secasvar *sav);
static int ipsec46_encapsulate(struct ipsec_output_state *state, struct secasvar *sav);
#endif
static struct ipsec_tag *ipsec_addaux(struct mbuf *);
static struct ipsec_tag *ipsec_findaux(struct mbuf *);
static void ipsec_optaux(struct mbuf *, struct ipsec_tag *);
int ipsec_send_natt_keepalive(struct secasvar *sav);
bool ipsec_fill_offload_frame(ifnet_t ifp, struct secasvar *sav, struct ifnet_keepalive_offload_frame *frame, size_t frame_data_offset);

static int
sysctl_def_policy SYSCTL_HANDLER_ARGS
{
	int old_policy = ip4_def_policy.policy;
	int error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);

#pragma unused(arg1, arg2)

	if (ip4_def_policy.policy != IPSEC_POLICY_NONE &&
		ip4_def_policy.policy != IPSEC_POLICY_DISCARD) {
		ip4_def_policy.policy = old_policy;
		return EINVAL;
	}

	/* Turn off the bypass if the default security policy changes */
	if (ipsec_bypass != 0 && ip4_def_policy.policy != IPSEC_POLICY_NONE)
		ipsec_bypass = 0;

	return error;
}

/*
 * For OUTBOUND packet having a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occurred.
 *	others:	a pointer to SP
 *
 * NOTE: IPv6 mapped adddress concern is implemented here.
 */
struct secpolicy *
ipsec4_getpolicybysock(struct mbuf *m,
					   u_int dir,
					   struct socket *so,
					   int *error)
{
	struct inpcbpolicy *pcbsp = NULL;
	struct secpolicy *currsp = NULL;	/* policy on socket */
	struct secpolicy *kernsp = NULL;	/* policy on kernel */
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (m == NULL || so == NULL || error == NULL)
		panic("ipsec4_getpolicybysock: NULL pointer was passed.\n");
		
		if (so->so_pcb == NULL) {
			printf("ipsec4_getpolicybysock: so->so_pcb == NULL\n");
			return ipsec4_getpolicybyaddr(m, dir, 0, error);
		}
	
	switch (SOCK_DOM(so)) {
		case PF_INET:
			pcbsp = sotoinpcb(so)->inp_sp;
			break;
#if INET6
		case PF_INET6:
			pcbsp = sotoin6pcb(so)->in6p_sp;
			break;
#endif
	}
	
	if (!pcbsp){
		/* Socket has not specified an IPSEC policy */
		return ipsec4_getpolicybyaddr(m, dir, 0, error);
	}
	
	KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_START, 0,0,0,0,0);
	
	switch (SOCK_DOM(so)) {
		case PF_INET:
			/* set spidx in pcb */
			*error = ipsec4_setspidx_inpcb(m, sotoinpcb(so));
			break;
#if INET6
		case PF_INET6:
			/* set spidx in pcb */
			*error = ipsec6_setspidx_in6pcb(m, sotoin6pcb(so));
			break;
#endif
		default:
			panic("ipsec4_getpolicybysock: unsupported address family\n");
	}
	if (*error) {
		KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 1,*error,0,0,0);
		return NULL;
	}
	
	/* sanity check */
	if (pcbsp == NULL)
		panic("ipsec4_getpolicybysock: pcbsp is NULL.\n");
		
		switch (dir) {
			case IPSEC_DIR_INBOUND:
				currsp = pcbsp->sp_in;
				break;
			case IPSEC_DIR_OUTBOUND:
				currsp = pcbsp->sp_out;
				break;
			default:
				panic("ipsec4_getpolicybysock: illegal direction.\n");
		}
	
	/* sanity check */
	if (currsp == NULL)
		panic("ipsec4_getpolicybysock: currsp is NULL.\n");
		
	/* when privilieged socket */
		if (pcbsp->priv) {
			switch (currsp->policy) {
				case IPSEC_POLICY_BYPASS:
					lck_mtx_lock(sadb_mutex);
					currsp->refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 2,*error,0,0,0);
					return currsp;
					
				case IPSEC_POLICY_ENTRUST:
					/* look for a policy in SPD */
					kernsp = key_allocsp(&currsp->spidx, dir);
					
					/* SP found */
					if (kernsp != NULL) {
						KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
								 printf("DP ipsec4_getpolicybysock called "
										"to allocate SP:0x%llx\n",
										(uint64_t)VM_KERNEL_ADDRPERM(kernsp)));
						*error = 0;
						KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 3,*error,0,0,0);
						return kernsp;
					}
					
					/* no SP found */
					lck_mtx_lock(sadb_mutex);
					if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
						&& ip4_def_policy.policy != IPSEC_POLICY_NONE) {
						ipseclog((LOG_INFO,
								  "fixed system default policy: %d->%d\n",
								  ip4_def_policy.policy, IPSEC_POLICY_NONE));
						ip4_def_policy.policy = IPSEC_POLICY_NONE;
					}
					ip4_def_policy.refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 4,*error,0,0,0);
					return &ip4_def_policy;
					
				case IPSEC_POLICY_IPSEC:
					lck_mtx_lock(sadb_mutex);
					currsp->refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 5,*error,0,0,0);
					return currsp;
					
				default:
					ipseclog((LOG_ERR, "ipsec4_getpolicybysock: "
			      "Invalid policy for PCB %d\n", currsp->policy));
					*error = EINVAL;
					KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 6,*error,0,0,0);
					return NULL;
			}
			/* NOTREACHED */
		}
	
	/* when non-privilieged socket */
	/* look for a policy in SPD */
	kernsp = key_allocsp(&currsp->spidx, dir);
	
	/* SP found */
	if (kernsp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				 printf("DP ipsec4_getpolicybysock called "
		    "to allocate SP:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(kernsp)));
		*error = 0;
		KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 7,*error,0,0,0);
		return kernsp;
	}
	
	/* no SP found */
	switch (currsp->policy) {
		case IPSEC_POLICY_BYPASS:
			ipseclog((LOG_ERR, "ipsec4_getpolicybysock: "
					  "Illegal policy for non-priviliged defined %d\n",
					  currsp->policy));
			*error = EINVAL;
			KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 8,*error,0,0,0);
			return NULL;
			
		case IPSEC_POLICY_ENTRUST:
			lck_mtx_lock(sadb_mutex);
			if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
				&& ip4_def_policy.policy != IPSEC_POLICY_NONE) {
				ipseclog((LOG_INFO,
						  "fixed system default policy: %d->%d\n",
						  ip4_def_policy.policy, IPSEC_POLICY_NONE));
				ip4_def_policy.policy = IPSEC_POLICY_NONE;
			}
			ip4_def_policy.refcnt++;
			lck_mtx_unlock(sadb_mutex);
			*error = 0;
			KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 9,*error,0,0,0);
			return &ip4_def_policy;
			
		case IPSEC_POLICY_IPSEC:
			lck_mtx_lock(sadb_mutex);
			currsp->refcnt++;
			lck_mtx_unlock(sadb_mutex);
			*error = 0;
			KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 10,*error,0,0,0);
			return currsp;
			
		default:
			ipseclog((LOG_ERR, "ipsec4_getpolicybysock: "
					  "Invalid policy for PCB %d\n", currsp->policy));
			*error = EINVAL;
			KERNEL_DEBUG(DBG_FNC_GETPOL_SOCK | DBG_FUNC_END, 11,*error,0,0,0);
			return NULL;
	}
	/* NOTREACHED */
}

/*
 * For FORWADING packet or OUTBOUND without a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	positive: a pointer to the entry for security policy leaf matched.
 *	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occurred.
 */
struct secpolicy *
ipsec4_getpolicybyaddr(struct mbuf *m,
                       u_int dir,
                       int flag,
                       int *error)
{
	struct secpolicy *sp = NULL;
    
	if (ipsec_bypass != 0)
		return 0;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (m == NULL || error == NULL)
		panic("ipsec4_getpolicybyaddr: NULL pointer was passed.\n");
	{
		struct secpolicyindex spidx;

		KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_START, 0,0,0,0,0);
		bzero(&spidx, sizeof(spidx));

		/* make a index to look for a policy */
		*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET, m,
			(flag & IP_FORWARDING) ? 0 : 1);

		if (*error != 0) {
			KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 1,*error,0,0,0);
			return NULL;
		}

		sp = key_allocsp(&spidx, dir);
	}

	/* SP found */
	if (sp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP ipsec4_getpolicybyaddr called "
		    "to allocate SP:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
		*error = 0;
		KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 2,*error,0,0,0);
		return sp;
	}

	/* no SP found */
	lck_mtx_lock(sadb_mutex);
	if (ip4_def_policy.policy != IPSEC_POLICY_DISCARD
	 && ip4_def_policy.policy != IPSEC_POLICY_NONE) {
		ipseclog((LOG_INFO, "fixed system default policy:%d->%d\n",
			ip4_def_policy.policy,
			IPSEC_POLICY_NONE));
		ip4_def_policy.policy = IPSEC_POLICY_NONE;
	}
	ip4_def_policy.refcnt++;
	lck_mtx_unlock(sadb_mutex);
	*error = 0;
	KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 3,*error,0,0,0);
	return &ip4_def_policy;
}

/* Match with bound interface rather than src addr.
 * Unlike getpolicybyaddr, do not set the default policy.
 * Return 0 if should continue processing, or -1 if packet
 * should be dropped.
 */
int
ipsec4_getpolicybyinterface(struct mbuf *m,
                            u_int dir,
                            int *flags,
                            struct ip_out_args *ipoa,
                            struct secpolicy **sp)
{
	struct secpolicyindex spidx;
	int error = 0;

	if (ipsec_bypass != 0)
		return 0;
    
	/* Sanity check */
	if (m == NULL || ipoa == NULL || sp == NULL)
		panic("ipsec4_getpolicybyinterface: NULL pointer was passed.\n");
    
	if (ipoa->ipoa_boundif == IFSCOPE_NONE)
		return 0;
 
	KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_START, 0,0,0,0,0);
	bzero(&spidx, sizeof(spidx));
    
	/* make a index to look for a policy */
	error = ipsec_setspidx_interface(&spidx, dir, m, (*flags & IP_FORWARDING) ? 0 : 1,
					ipoa->ipoa_boundif, 4);
    
	if (error != 0) {
		KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 1,error,0,0,0);
		return 0;
	}
    
	*sp = key_allocsp(&spidx, dir);

	/* Return SP, whether NULL or not */
	if (*sp != NULL && (*sp)->policy == IPSEC_POLICY_IPSEC) {
		if ((*sp)->ipsec_if == NULL) {
			/* Invalid to capture on an interface without redirect */
			key_freesp(*sp, KEY_SADB_UNLOCKED);
			*sp = NULL;
			return -1;
		} else if ((*sp)->disabled) {
			/* Disabled policies go in the clear */
			key_freesp(*sp, KEY_SADB_UNLOCKED);
			*sp = NULL;
			*flags |= IP_NOIPSEC; /* Avoid later IPSec check */
		} else {
			/* If policy is enabled, redirect to ipsec interface */
			ipoa->ipoa_boundif = (*sp)->ipsec_if->if_index;
		}
	}
    
	KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 2,error,0,0,0);
    
	return 0;
}


#if INET6
/*
 * For OUTBOUND packet having a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * OUT:	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occurred.
 *	others:	a pointer to SP
 */
struct secpolicy *
ipsec6_getpolicybysock(struct mbuf *m,
					   u_int dir,
					   struct socket *so,
					   int *error)
{
	struct inpcbpolicy *pcbsp = NULL;
	struct secpolicy *currsp = NULL;	/* policy on socket */
	struct secpolicy *kernsp = NULL;	/* policy on kernel */
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (m == NULL || so == NULL || error == NULL)
		panic("ipsec6_getpolicybysock: NULL pointer was passed.\n");
		
#if DIAGNOSTIC
		if (SOCK_DOM(so) != PF_INET6)
			panic("ipsec6_getpolicybysock: socket domain != inet6\n");
#endif
			
			pcbsp = sotoin6pcb(so)->in6p_sp;
			
			if (!pcbsp){
				return ipsec6_getpolicybyaddr(m, dir, 0, error);
			}
	
	/* set spidx in pcb */
	ipsec6_setspidx_in6pcb(m, sotoin6pcb(so));
	
	/* sanity check */
	if (pcbsp == NULL)
		panic("ipsec6_getpolicybysock: pcbsp is NULL.\n");
		
		switch (dir) {
			case IPSEC_DIR_INBOUND:
				currsp = pcbsp->sp_in;
				break;
			case IPSEC_DIR_OUTBOUND:
				currsp = pcbsp->sp_out;
				break;
			default:
				panic("ipsec6_getpolicybysock: illegal direction.\n");
		}
	
	/* sanity check */
	if (currsp == NULL)
		panic("ipsec6_getpolicybysock: currsp is NULL.\n");
		
	/* when privilieged socket */
		if (pcbsp->priv) {
			switch (currsp->policy) {
				case IPSEC_POLICY_BYPASS:
					lck_mtx_lock(sadb_mutex);
					currsp->refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					return currsp;
					
				case IPSEC_POLICY_ENTRUST:
					/* look for a policy in SPD */
					kernsp = key_allocsp(&currsp->spidx, dir);
					
					/* SP found */
					if (kernsp != NULL) {
						KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
								 printf("DP ipsec6_getpolicybysock called "
										"to allocate SP:0x%llx\n",
										(uint64_t)VM_KERNEL_ADDRPERM(kernsp)));
						*error = 0;
						return kernsp;
					}
					
					/* no SP found */
					lck_mtx_lock(sadb_mutex);
					if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
						&& ip6_def_policy.policy != IPSEC_POLICY_NONE) {
						ipseclog((LOG_INFO,
								  "fixed system default policy: %d->%d\n",
								  ip6_def_policy.policy, IPSEC_POLICY_NONE));
						ip6_def_policy.policy = IPSEC_POLICY_NONE;
					}
					ip6_def_policy.refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					return &ip6_def_policy;
					
				case IPSEC_POLICY_IPSEC:
					lck_mtx_lock(sadb_mutex);
					currsp->refcnt++;
					lck_mtx_unlock(sadb_mutex);
					*error = 0;
					return currsp;
					
				default:
					ipseclog((LOG_ERR, "ipsec6_getpolicybysock: "
							  "Invalid policy for PCB %d\n", currsp->policy));
					*error = EINVAL;
					return NULL;
			}
			/* NOTREACHED */
		}
	
	/* when non-privilieged socket */
	/* look for a policy in SPD */
	kernsp = key_allocsp(&currsp->spidx, dir);
	
	/* SP found */
	if (kernsp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				 printf("DP ipsec6_getpolicybysock called "
		    "to allocate SP:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(kernsp)));
		*error = 0;
		return kernsp;
	}
	
	/* no SP found */
	switch (currsp->policy) {
		case IPSEC_POLICY_BYPASS:
			ipseclog((LOG_ERR, "ipsec6_getpolicybysock: "
					  "Illegal policy for non-priviliged defined %d\n",
					  currsp->policy));
			*error = EINVAL;
			return NULL;
			
		case IPSEC_POLICY_ENTRUST:
			lck_mtx_lock(sadb_mutex);
			if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
				&& ip6_def_policy.policy != IPSEC_POLICY_NONE) {
				ipseclog((LOG_INFO,
						  "fixed system default policy: %d->%d\n",
						  ip6_def_policy.policy, IPSEC_POLICY_NONE));
				ip6_def_policy.policy = IPSEC_POLICY_NONE;
			}
			ip6_def_policy.refcnt++;
			lck_mtx_unlock(sadb_mutex);
			*error = 0;
			return &ip6_def_policy;
			
		case IPSEC_POLICY_IPSEC:
			lck_mtx_lock(sadb_mutex);
			currsp->refcnt++;
			lck_mtx_unlock(sadb_mutex);
			*error = 0;
			return currsp;
			
		default:
			ipseclog((LOG_ERR,
					  "ipsec6_policybysock: Invalid policy for PCB %d\n",
					  currsp->policy));
			*error = EINVAL;
			return NULL;
	}
	/* NOTREACHED */
}

/*
 * For FORWADING packet or OUTBOUND without a socket. Searching SPD for packet,
 * and return a pointer to SP.
 * `flag' means that packet is to be forwarded whether or not.
 *	flag = 1: forwad
 * OUT:	positive: a pointer to the entry for security policy leaf matched.
 *	NULL:	no apropreate SP found, the following value is set to error.
 *		0	: bypass
 *		EACCES	: discard packet.
 *		ENOENT	: ipsec_acquire() in progress, maybe.
 *		others	: error occurred.
 */
#ifndef IP_FORWARDING
#define IP_FORWARDING 1
#endif

struct secpolicy *
ipsec6_getpolicybyaddr(struct mbuf *m,
                        u_int dir,
                        int flag,
                        int *error)
{
	struct secpolicy *sp = NULL;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (m == NULL || error == NULL)
		panic("ipsec6_getpolicybyaddr: NULL pointer was passed.\n");

    {
	struct secpolicyindex spidx;

	bzero(&spidx, sizeof(spidx));

	/* make a index to look for a policy */
	*error = ipsec_setspidx_mbuf(&spidx, dir, AF_INET6, m,
	    (flag & IP_FORWARDING) ? 0 : 1);

	if (*error != 0)
		return NULL;

	sp = key_allocsp(&spidx, dir);
    }

	/* SP found */
	if (sp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		    printf("DP ipsec6_getpolicybyaddr called "
		    "to allocate SP:0x%llx\n",
		    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
		*error = 0;
		return sp;
	}

	/* no SP found */
	lck_mtx_lock(sadb_mutex);
	if (ip6_def_policy.policy != IPSEC_POLICY_DISCARD
	 && ip6_def_policy.policy != IPSEC_POLICY_NONE) {
		ipseclog((LOG_INFO, "fixed system default policy: %d->%d\n",
		    ip6_def_policy.policy, IPSEC_POLICY_NONE));
		ip6_def_policy.policy = IPSEC_POLICY_NONE;
	}
	ip6_def_policy.refcnt++;
	lck_mtx_unlock(sadb_mutex);
	*error = 0;
	return &ip6_def_policy;
}

/* Match with bound interface rather than src addr.
 * Unlike getpolicybyaddr, do not set the default policy.
 * Return 0 if should continue processing, or -1 if packet
 * should be dropped.
 */
int
ipsec6_getpolicybyinterface(struct mbuf *m,
                            u_int dir,
                            int flag,
                            struct ip6_out_args *ip6oap,
                            int *noipsec,
                            struct secpolicy **sp)
{
	struct secpolicyindex spidx;
	int error = 0;
    
	if (ipsec_bypass != 0)
		return 0;
    
	/* Sanity check */
	if (m == NULL || sp == NULL || noipsec == NULL || ip6oap == NULL)
		panic("ipsec6_getpolicybyinterface: NULL pointer was passed.\n");
    
	*noipsec = 0;
    
	if (ip6oap->ip6oa_boundif == IFSCOPE_NONE)
		return 0;
    
	KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_START, 0,0,0,0,0);
	bzero(&spidx, sizeof(spidx));
    
	/* make a index to look for a policy */
	error = ipsec_setspidx_interface(&spidx, dir, m, (flag & IP_FORWARDING) ? 0 : 1,
					ip6oap->ip6oa_boundif, 6);
    
	if (error != 0) {
		KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 1,error,0,0,0);
		return 0;
	}
    
	*sp = key_allocsp(&spidx, dir);
    
	/* Return SP, whether NULL or not */
	if (*sp != NULL && (*sp)->policy == IPSEC_POLICY_IPSEC) {
		if ((*sp)->ipsec_if == NULL) {
			/* Invalid to capture on an interface without redirect */
			key_freesp(*sp, KEY_SADB_UNLOCKED);
			*sp = NULL;
			return -1;
		} else if ((*sp)->disabled) {
			/* Disabled policies go in the clear */
			key_freesp(*sp, KEY_SADB_UNLOCKED);
			*sp = NULL;
			*noipsec = 1; /* Avoid later IPSec check */
		} else {
			/* If policy is enabled, redirect to ipsec interface */
			ip6oap->ip6oa_boundif = (*sp)->ipsec_if->if_index;
		}
	}
    
	KERNEL_DEBUG(DBG_FNC_GETPOL_ADDR | DBG_FUNC_END, 2,*error,0,0,0);
    
	return 0;
}
#endif /* INET6 */

/*
 * set IP address into spidx from mbuf.
 * When Forwarding packet and ICMP echo reply, this function is used.
 *
 * IN:	get the followings from mbuf.
 *	protocol family, src, dst, next protocol
 * OUT:
 *	0:	success.
 *	other:	failure, and set errno.
 */
static int
ipsec_setspidx_mbuf(
	struct secpolicyindex *spidx,
	u_int dir,
	__unused u_int family,
	struct mbuf *m,
	int needport)
{
	int error;

	/* sanity check */
	if (spidx == NULL || m == NULL)
		panic("ipsec_setspidx_mbuf: NULL pointer was passed.\n");

	bzero(spidx, sizeof(*spidx));

	error = ipsec_setspidx(m, spidx, needport, 0);
	if (error)
		goto bad;
	spidx->dir = dir;

	return 0;

    bad:
	/* XXX initialize */
	bzero(spidx, sizeof(*spidx));
	return EINVAL;
}

static int
ipsec_setspidx_interface(
                    struct secpolicyindex *spidx,
                    u_int dir,
                    struct mbuf *m,
                    int needport,
                    int ifindex,
                    int ip_version)
{
	int error;
    
	/* sanity check */
	if (spidx == NULL || m == NULL)
		panic("ipsec_setspidx_interface: NULL pointer was passed.\n");
    
	bzero(spidx, sizeof(*spidx));
    
	error = ipsec_setspidx(m, spidx, needport, ip_version);
	if (error)
		goto bad;
	spidx->dir = dir;
    
	if (ifindex != 0) {
		ifnet_head_lock_shared();
		spidx->internal_if = ifindex2ifnet[ifindex];
		ifnet_head_done();
	} else {
		spidx->internal_if = NULL;
	}
    
	return 0;
    
bad:
	return EINVAL;
}

static int
ipsec4_setspidx_inpcb(m, pcb)
struct mbuf *m;
struct inpcb *pcb;
{
	struct secpolicyindex *spidx;
	int error;
	
	if (ipsec_bypass != 0)
		return 0;
	
	/* sanity check */
	if (pcb == NULL)
		panic("ipsec4_setspidx_inpcb: no PCB found.\n");
		if (pcb->inp_sp == NULL)
			panic("ipsec4_setspidx_inpcb: no inp_sp found.\n");
			if (pcb->inp_sp->sp_out == NULL || pcb->inp_sp->sp_in == NULL)
				panic("ipsec4_setspidx_inpcb: no sp_in/out found.\n");
				
				bzero(&pcb->inp_sp->sp_in->spidx, sizeof(*spidx));
				bzero(&pcb->inp_sp->sp_out->spidx, sizeof(*spidx));
				
				spidx = &pcb->inp_sp->sp_in->spidx;
				error = ipsec_setspidx(m, spidx, 1, 0);
				if (error)
					goto bad;
	spidx->dir = IPSEC_DIR_INBOUND;
	
	spidx = &pcb->inp_sp->sp_out->spidx;
	error = ipsec_setspidx(m, spidx, 1, 0);
	if (error)
		goto bad;
	spidx->dir = IPSEC_DIR_OUTBOUND;
	
	return 0;
	
bad:
	bzero(&pcb->inp_sp->sp_in->spidx, sizeof(*spidx));
	bzero(&pcb->inp_sp->sp_out->spidx, sizeof(*spidx));
	return error;
}

#if INET6
static int
ipsec6_setspidx_in6pcb(m, pcb)
struct mbuf *m;
struct in6pcb *pcb;
{
	struct secpolicyindex *spidx;
	int error;
	
	/* sanity check */
	if (pcb == NULL)
		panic("ipsec6_setspidx_in6pcb: no PCB found.\n");
		if (pcb->in6p_sp == NULL)
			panic("ipsec6_setspidx_in6pcb: no in6p_sp found.\n");
			if (pcb->in6p_sp->sp_out == NULL || pcb->in6p_sp->sp_in == NULL)
				panic("ipsec6_setspidx_in6pcb: no sp_in/out found.\n");
				
				bzero(&pcb->in6p_sp->sp_in->spidx, sizeof(*spidx));
				bzero(&pcb->in6p_sp->sp_out->spidx, sizeof(*spidx));
				
				spidx = &pcb->in6p_sp->sp_in->spidx;
				error = ipsec_setspidx(m, spidx, 1, 0);
				if (error)
					goto bad;
	spidx->dir = IPSEC_DIR_INBOUND;
	
	spidx = &pcb->in6p_sp->sp_out->spidx;
	error = ipsec_setspidx(m, spidx, 1, 0);
	if (error)
		goto bad;
	spidx->dir = IPSEC_DIR_OUTBOUND;
	
	return 0;
	
bad:
	bzero(&pcb->in6p_sp->sp_in->spidx, sizeof(*spidx));
	bzero(&pcb->in6p_sp->sp_out->spidx, sizeof(*spidx));
	return error;
}
#endif

/*
 * configure security policy index (src/dst/proto/sport/dport)
 * by looking at the content of mbuf.
 * the caller is responsible for error recovery (like clearing up spidx).
 */
static int
ipsec_setspidx(struct mbuf *m,
               struct secpolicyindex *spidx,
               int needport,
               int force_ip_version)
{
	struct ip *ip = NULL;
	struct ip ipbuf;
	u_int v;
	struct mbuf *n;
	int len;
	int error;
    
	if (m == NULL)
		panic("ipsec_setspidx: m == 0 passed.\n");
    
	/*
	 * validate m->m_pkthdr.len.  we see incorrect length if we
	 * mistakenly call this function with inconsistent mbuf chain
	 * (like 4.4BSD tcp/udp processing).  XXX should we panic here?
	 */
	len = 0;
	for (n = m; n; n = n->m_next)
		len += n->m_len;
	if (m->m_pkthdr.len != len) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec_setspidx: "
			       "total of m_len(%d) != pkthdr.len(%d), "
			       "ignored.\n",
				len, m->m_pkthdr.len));
		return EINVAL;
	}

	if (m->m_pkthdr.len < sizeof(struct ip)) {
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec_setspidx: "
			    "pkthdr.len(%d) < sizeof(struct ip), ignored.\n",
			    m->m_pkthdr.len));
		return EINVAL;
	}

	if (m->m_len >= sizeof(*ip))
		ip = mtod(m, struct ip *);
	else {
		m_copydata(m, 0, sizeof(ipbuf), (caddr_t)&ipbuf);
		ip = &ipbuf;
	}
    
	if (force_ip_version) {
		v = force_ip_version;
	} else {
#ifdef _IP_VHL
		v = _IP_VHL_V(ip->ip_vhl);
#else
		v = ip->ip_v;
#endif
	}
	switch (v) {
	case 4:
		error = ipsec4_setspidx_ipaddr(m, spidx);
		if (error)
			return error;
		ipsec4_get_ulp(m, spidx, needport);
		return 0;
#if INET6
	case 6:
		if (m->m_pkthdr.len < sizeof(struct ip6_hdr)) {
			KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
				printf("ipsec_setspidx: "
				    "pkthdr.len(%d) < sizeof(struct ip6_hdr), "
				    "ignored.\n", m->m_pkthdr.len));
			return EINVAL;
		}
		error = ipsec6_setspidx_ipaddr(m, spidx);
		if (error)
			return error;
		ipsec6_get_ulp(m, spidx, needport);
		return 0;
#endif
	default:
		KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			printf("ipsec_setspidx: "
			    "unknown IP version %u, ignored.\n", v));
		return EINVAL;
	}
}

static void
ipsec4_get_ulp(m, spidx, needport)
	struct mbuf *m;
	struct secpolicyindex *spidx;
	int needport;
{
	struct ip ip;
	struct ip6_ext ip6e;
	u_int8_t nxt;
	int off;
	struct tcphdr th;
	struct udphdr uh;

	/* sanity check */
	if (m == NULL)
		panic("ipsec4_get_ulp: NULL pointer was passed.\n");
	if (m->m_pkthdr.len < sizeof(ip))
		panic("ipsec4_get_ulp: too short\n");

	/* set default */
	spidx->ul_proto = IPSEC_ULPROTO_ANY;
	((struct sockaddr_in *)&spidx->src)->sin_port = IPSEC_PORT_ANY;
	((struct sockaddr_in *)&spidx->dst)->sin_port = IPSEC_PORT_ANY;

	m_copydata(m, 0, sizeof(ip), (caddr_t)&ip);
	/* ip_input() flips it into host endian XXX need more checking */
	if (ip.ip_off & (IP_MF | IP_OFFMASK))
		return;

	nxt = ip.ip_p;
#ifdef _IP_VHL
	off = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	off = ip.ip_hl << 2;
#endif
	while (off < m->m_pkthdr.len) {
		switch (nxt) {
		case IPPROTO_TCP:
			spidx->ul_proto = nxt;
			if (!needport)
				return;
			if (off + sizeof(struct tcphdr) > m->m_pkthdr.len)
				return;
			m_copydata(m, off, sizeof(th), (caddr_t)&th);
			((struct sockaddr_in *)&spidx->src)->sin_port =
			    th.th_sport;
			((struct sockaddr_in *)&spidx->dst)->sin_port =
			    th.th_dport;
			return;
		case IPPROTO_UDP:
			spidx->ul_proto = nxt;
			if (!needport)
				return;
			if (off + sizeof(struct udphdr) > m->m_pkthdr.len)
				return;
			m_copydata(m, off, sizeof(uh), (caddr_t)&uh);
			((struct sockaddr_in *)&spidx->src)->sin_port =
			    uh.uh_sport;
			((struct sockaddr_in *)&spidx->dst)->sin_port =
			    uh.uh_dport;
			return;
		case IPPROTO_AH:
			if (off + sizeof(ip6e) > m->m_pkthdr.len)
				return;
			m_copydata(m, off, sizeof(ip6e), (caddr_t)&ip6e);
			off += (ip6e.ip6e_len + 2) << 2;
			nxt = ip6e.ip6e_nxt;
			break;
		case IPPROTO_ICMP:
		default:
			/* XXX intermediate headers??? */
			spidx->ul_proto = nxt;
			return;
		}
	}
}

/* assumes that m is sane */
static int
ipsec4_setspidx_ipaddr(m, spidx)
	struct mbuf *m;
	struct secpolicyindex *spidx;
{
	struct ip *ip = NULL;
	struct ip ipbuf;
	struct sockaddr_in *sin;

	if (m->m_len >= sizeof(*ip))
		ip = mtod(m, struct ip *);
	else {
		m_copydata(m, 0, sizeof(ipbuf), (caddr_t)&ipbuf);
		ip = &ipbuf;
	}

	sin = (struct sockaddr_in *)&spidx->src;
	bzero(sin, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	bcopy(&ip->ip_src, &sin->sin_addr, sizeof(ip->ip_src));
	spidx->prefs = sizeof(struct in_addr) << 3;

	sin = (struct sockaddr_in *)&spidx->dst;
	bzero(sin, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	bcopy(&ip->ip_dst, &sin->sin_addr, sizeof(ip->ip_dst));
	spidx->prefd = sizeof(struct in_addr) << 3;
    
	return 0;
}

#if INET6
static void
ipsec6_get_ulp(struct mbuf *m,
			   struct secpolicyindex *spidx,
			   int needport)
{
	int off, nxt;
	struct tcphdr th;
	struct udphdr uh;

	/* sanity check */
	if (m == NULL)
		panic("ipsec6_get_ulp: NULL pointer was passed.\n");

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec6_get_ulp:\n"); kdebug_mbuf(m));

	/* set default */
	spidx->ul_proto = IPSEC_ULPROTO_ANY;
	((struct sockaddr_in6 *)&spidx->src)->sin6_port = IPSEC_PORT_ANY;
	((struct sockaddr_in6 *)&spidx->dst)->sin6_port = IPSEC_PORT_ANY;

	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off < 0 || m->m_pkthdr.len < off)
		return;

	switch (nxt) {
	case IPPROTO_TCP:
		spidx->ul_proto = nxt;
		if (!needport)
			break;
		if (off + sizeof(struct tcphdr) > m->m_pkthdr.len)
			break;
		m_copydata(m, off, sizeof(th), (caddr_t)&th);
		((struct sockaddr_in6 *)&spidx->src)->sin6_port = th.th_sport;
		((struct sockaddr_in6 *)&spidx->dst)->sin6_port = th.th_dport;
		break;
	case IPPROTO_UDP:
		spidx->ul_proto = nxt;
		if (!needport)
			break;
		if (off + sizeof(struct udphdr) > m->m_pkthdr.len)
			break;
		m_copydata(m, off, sizeof(uh), (caddr_t)&uh);
		((struct sockaddr_in6 *)&spidx->src)->sin6_port = uh.uh_sport;
		((struct sockaddr_in6 *)&spidx->dst)->sin6_port = uh.uh_dport;
		break;
	case IPPROTO_ICMPV6:
	default:
		/* XXX intermediate headers??? */
		spidx->ul_proto = nxt;
		break;
	}
}

/* assumes that m is sane */
static int
ipsec6_setspidx_ipaddr(struct mbuf *m,
					   struct secpolicyindex *spidx)
{
	struct ip6_hdr *ip6 = NULL;
	struct ip6_hdr ip6buf;
	struct sockaddr_in6 *sin6;

	if (m->m_len >= sizeof(*ip6))
		ip6 = mtod(m, struct ip6_hdr *);
	else {
		m_copydata(m, 0, sizeof(ip6buf), (caddr_t)&ip6buf);
		ip6 = &ip6buf;
	}

	sin6 = (struct sockaddr_in6 *)&spidx->src;
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&ip6->ip6_src, &sin6->sin6_addr, sizeof(ip6->ip6_src));
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
		sin6->sin6_addr.s6_addr16[1] = 0;
		sin6->sin6_scope_id = ntohs(ip6->ip6_src.s6_addr16[1]);
	}
	spidx->prefs = sizeof(struct in6_addr) << 3;

	sin6 = (struct sockaddr_in6 *)&spidx->dst;
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&ip6->ip6_dst, &sin6->sin6_addr, sizeof(ip6->ip6_dst));
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
		sin6->sin6_addr.s6_addr16[1] = 0;
		sin6->sin6_scope_id = ntohs(ip6->ip6_dst.s6_addr16[1]);
	}
	spidx->prefd = sizeof(struct in6_addr) << 3;

	return 0;
}
#endif

static struct inpcbpolicy *
ipsec_newpcbpolicy()
{
	struct inpcbpolicy *p;
	
	p = (struct inpcbpolicy *)_MALLOC(sizeof(*p), M_SECA, M_WAITOK);
	return p;
}

static void
ipsec_delpcbpolicy(struct inpcbpolicy *p)
{
	FREE(p, M_SECA);
}

/* initialize policy in PCB */
int
ipsec_init_policy(struct socket *so,
				  struct inpcbpolicy **pcb_sp)
{
	struct inpcbpolicy *new;
	
	/* sanity check. */
	if (so == NULL || pcb_sp == NULL)
		panic("ipsec_init_policy: NULL pointer was passed.\n");
		
		new = ipsec_newpcbpolicy();
		if (new == NULL) {
			ipseclog((LOG_DEBUG, "ipsec_init_policy: No more memory.\n"));
			return ENOBUFS;
		}
	bzero(new, sizeof(*new));
	
#ifdef __APPLE__
	if (kauth_cred_issuser(so->so_cred))
#else
		if (so->so_cred != 0 && !suser(so->so_cred->pc_ucred, NULL))
#endif
			new->priv = 1;
			else
				new->priv = 0;
				
				if ((new->sp_in = key_newsp()) == NULL) {
					ipsec_delpcbpolicy(new);
					return ENOBUFS;
				}
	new->sp_in->state = IPSEC_SPSTATE_ALIVE;
	new->sp_in->policy = IPSEC_POLICY_ENTRUST;
	
	if ((new->sp_out = key_newsp()) == NULL) {
		key_freesp(new->sp_in, KEY_SADB_UNLOCKED);
		ipsec_delpcbpolicy(new);
		return ENOBUFS;
	}
	new->sp_out->state = IPSEC_SPSTATE_ALIVE;
	new->sp_out->policy = IPSEC_POLICY_ENTRUST;
	
	*pcb_sp = new;
	
	return 0;
}

/* copy old ipsec policy into new */
int
ipsec_copy_policy(struct inpcbpolicy *old,
				  struct inpcbpolicy *new)
{
	struct secpolicy *sp;
	
	if (ipsec_bypass != 0)
		return 0;
	
	sp = ipsec_deepcopy_policy(old->sp_in);
	if (sp) {
		key_freesp(new->sp_in, KEY_SADB_UNLOCKED);
		new->sp_in = sp;
	} else
		return ENOBUFS;
	
	sp = ipsec_deepcopy_policy(old->sp_out);
	if (sp) {
		key_freesp(new->sp_out, KEY_SADB_UNLOCKED);
		new->sp_out = sp;
	} else
		return ENOBUFS;
	
	new->priv = old->priv;
	
	return 0;
}

/* deep-copy a policy in PCB */
static struct secpolicy *
ipsec_deepcopy_policy(struct secpolicy *src)
{
	struct ipsecrequest *newchain = NULL;
	struct ipsecrequest *p;
	struct ipsecrequest **q;
	struct ipsecrequest *r;
	struct secpolicy *dst;
	
	if (src == NULL)
		return NULL;
	dst = key_newsp();
	if (dst == NULL)
		return NULL;
	
	/*
	 * deep-copy IPsec request chain.  This is required since struct
	 * ipsecrequest is not reference counted.
	 */
	q = &newchain;
	for (p = src->req; p; p = p->next) {
		*q = (struct ipsecrequest *)_MALLOC(sizeof(struct ipsecrequest),
		    M_SECA, M_WAITOK | M_ZERO);
		if (*q == NULL)
			goto fail;
		(*q)->next = NULL;
		
		(*q)->saidx.proto = p->saidx.proto;
		(*q)->saidx.mode = p->saidx.mode;
		(*q)->level = p->level;
		(*q)->saidx.reqid = p->saidx.reqid;
		
		bcopy(&p->saidx.src, &(*q)->saidx.src, sizeof((*q)->saidx.src));
		bcopy(&p->saidx.dst, &(*q)->saidx.dst, sizeof((*q)->saidx.dst));
		
		(*q)->sp = dst;
		
		q = &((*q)->next);
	}
	
	dst->req = newchain;
	dst->state = src->state;
	dst->policy = src->policy;
	/* do not touch the refcnt fields */
	
	return dst;
	
fail:
	for (p = newchain; p; p = r) {
		r = p->next;
		FREE(p, M_SECA);
		p = NULL;
	}
	key_freesp(dst, KEY_SADB_UNLOCKED);
	return NULL;
}

/* set policy and ipsec request if present. */
static int
ipsec_set_policy(struct secpolicy **pcb_sp,
				 __unused int optname,
				 caddr_t request,
				 size_t len,
				 int priv)
{
	struct sadb_x_policy *xpl;
	struct secpolicy *newsp = NULL;
	int error;
	
	/* sanity check. */
	if (pcb_sp == NULL || *pcb_sp == NULL || request == NULL)
		return EINVAL;
	if (len < sizeof(*xpl))
		return EINVAL;
	xpl = (struct sadb_x_policy *)(void *)request;
	
	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			 printf("ipsec_set_policy: passed policy\n");
			 kdebug_sadb_x_policy((struct sadb_ext *)xpl));
	
	/* check policy type */
	/* ipsec_set_policy() accepts IPSEC, ENTRUST and BYPASS. */
	if (xpl->sadb_x_policy_type == IPSEC_POLICY_DISCARD
	 || xpl->sadb_x_policy_type == IPSEC_POLICY_NONE)
		return EINVAL;
	
	/* check privileged socket */
	if (priv == 0 && xpl->sadb_x_policy_type == IPSEC_POLICY_BYPASS)
		return EACCES;
	
	/* allocation new SP entry */
	if ((newsp = key_msg2sp(xpl, len, &error)) == NULL)
		return error;
	
	newsp->state = IPSEC_SPSTATE_ALIVE;
	
	/* clear old SP and set new SP */
	key_freesp(*pcb_sp, KEY_SADB_UNLOCKED);
	*pcb_sp = newsp;
	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
			 printf("ipsec_set_policy: new policy\n");
			 kdebug_secpolicy(newsp));
	
	return 0;
}

int
ipsec4_set_policy(struct inpcb *inp,
				  int optname,
				  caddr_t request,
				  size_t len,
				  int priv)
{
	struct sadb_x_policy *xpl;
	struct secpolicy **pcb_sp;
	int	error = 0;
	struct sadb_x_policy xpl_aligned_buf;
	u_int8_t             *xpl_unaligned;
	
	/* sanity check. */
	if (inp == NULL || request == NULL)
		return EINVAL;
	if (len < sizeof(*xpl))
		return EINVAL;
	xpl = (struct sadb_x_policy *)(void *)request;
	
	/* This is a new mbuf allocated by soopt_getm() */
	if (IPSEC_IS_P2ALIGNED(xpl)) {
		xpl_unaligned = NULL;
	} else {
		xpl_unaligned = (__typeof__(xpl_unaligned))xpl;
		memcpy(&xpl_aligned_buf, xpl, sizeof(xpl_aligned_buf));
		xpl = (__typeof__(xpl))&xpl_aligned_buf;
	}
	
	if (inp->inp_sp == NULL) {
		error = ipsec_init_policy(inp->inp_socket, &inp->inp_sp);
		if (error)
			return error;
	}
	
	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
		case IPSEC_DIR_INBOUND:
			pcb_sp = &inp->inp_sp->sp_in;
			break;
		case IPSEC_DIR_OUTBOUND:
			pcb_sp = &inp->inp_sp->sp_out;
			break;
		default:
			ipseclog((LOG_ERR, "ipsec4_set_policy: invalid direction=%u\n",
					  xpl->sadb_x_policy_dir));
			return EINVAL;
	}
	
	/* turn bypass off */
	if (ipsec_bypass != 0)
		ipsec_bypass = 0;
		
	return ipsec_set_policy(pcb_sp, optname, request, len, priv);
}

/* delete policy in PCB */
int
ipsec4_delete_pcbpolicy(struct inpcb *inp)
{
	
	/* sanity check. */
	if (inp == NULL)
		panic("ipsec4_delete_pcbpolicy: NULL pointer was passed.\n");
		
		if (inp->inp_sp == NULL)
			return 0;
	
	if (inp->inp_sp->sp_in != NULL) {
		key_freesp(inp->inp_sp->sp_in, KEY_SADB_UNLOCKED);
		inp->inp_sp->sp_in = NULL;
	}
	
	if (inp->inp_sp->sp_out != NULL) {
		key_freesp(inp->inp_sp->sp_out, KEY_SADB_UNLOCKED);
		inp->inp_sp->sp_out = NULL;
	}
	
	ipsec_delpcbpolicy(inp->inp_sp);
	inp->inp_sp = NULL;
	
	return 0;
}

#if INET6
int
ipsec6_set_policy(struct in6pcb *in6p,
				  int optname,
				  caddr_t request,
				  size_t len,
				  int priv)
{
	struct sadb_x_policy *xpl;
	struct secpolicy **pcb_sp;
	int error = 0;
	struct sadb_x_policy xpl_aligned_buf;
	u_int8_t *xpl_unaligned;
	
	/* sanity check. */
	if (in6p == NULL || request == NULL)
		return EINVAL;
	if (len < sizeof(*xpl))
		return EINVAL;
	xpl = (struct sadb_x_policy *)(void *)request;
	
	/* This is a new mbuf allocated by soopt_getm() */
	if (IPSEC_IS_P2ALIGNED(xpl)) {
		xpl_unaligned = NULL;
	} else {
		xpl_unaligned = (__typeof__(xpl_unaligned))xpl;
		memcpy(&xpl_aligned_buf, xpl, sizeof(xpl_aligned_buf));
		xpl = (__typeof__(xpl))&xpl_aligned_buf;
	}
	
	if (in6p->in6p_sp == NULL) {
		error = ipsec_init_policy(in6p->inp_socket, &in6p->in6p_sp);
		if (error)
			return error;
	}
	
	/* select direction */
	switch (xpl->sadb_x_policy_dir) {
		case IPSEC_DIR_INBOUND:
			pcb_sp = &in6p->in6p_sp->sp_in;
			break;
		case IPSEC_DIR_OUTBOUND:
			pcb_sp = &in6p->in6p_sp->sp_out;
			break;
		default:
			ipseclog((LOG_ERR, "ipsec6_set_policy: invalid direction=%u\n",
					  xpl->sadb_x_policy_dir));
			return EINVAL;
	}

	return ipsec_set_policy(pcb_sp, optname, request, len, priv);
}

int
ipsec6_delete_pcbpolicy(struct in6pcb *in6p)
{
	
	/* sanity check. */
	if (in6p == NULL)
		panic("ipsec6_delete_pcbpolicy: NULL pointer was passed.\n");
		
		if (in6p->in6p_sp == NULL)
			return 0;
	
	if (in6p->in6p_sp->sp_in != NULL) {
		key_freesp(in6p->in6p_sp->sp_in, KEY_SADB_UNLOCKED);
		in6p->in6p_sp->sp_in = NULL;
	}
	
	if (in6p->in6p_sp->sp_out != NULL) {
		key_freesp(in6p->in6p_sp->sp_out, KEY_SADB_UNLOCKED);
		in6p->in6p_sp->sp_out = NULL;
	}
	
	ipsec_delpcbpolicy(in6p->in6p_sp);
	in6p->in6p_sp = NULL;
	
	return 0;
}
#endif

/*
 * return current level.
 * Either IPSEC_LEVEL_USE or IPSEC_LEVEL_REQUIRE are always returned.
 */
u_int
ipsec_get_reqlevel(isr)
	struct ipsecrequest *isr;
{
	u_int level = 0;
	u_int esp_trans_deflev = 0, esp_net_deflev = 0, ah_trans_deflev = 0, ah_net_deflev = 0;

	/* sanity check */
	if (isr == NULL || isr->sp == NULL)
		panic("ipsec_get_reqlevel: NULL pointer is passed.\n");
	if (((struct sockaddr *)&isr->sp->spidx.src)->sa_family
			!= ((struct sockaddr *)&isr->sp->spidx.dst)->sa_family)
		panic("ipsec_get_reqlevel: family mismatched.\n");

/* XXX note that we have ipseclog() expanded here - code sync issue */
#define IPSEC_CHECK_DEFAULT(lev) \
	(((lev) != IPSEC_LEVEL_USE && (lev) != IPSEC_LEVEL_REQUIRE	      \
			&& (lev) != IPSEC_LEVEL_UNIQUE)			      \
		? (ipsec_debug						      \
			? log(LOG_INFO, "fixed system default level " #lev ":%d->%d\n",\
				(lev), IPSEC_LEVEL_REQUIRE)		      \
			: (void)0),									  \
			(lev) = IPSEC_LEVEL_REQUIRE,			      \
			(lev)						      \
		: (lev))

	/* set default level */
	switch (((struct sockaddr *)&isr->sp->spidx.src)->sa_family) {
#if INET
	case AF_INET:
		esp_trans_deflev = IPSEC_CHECK_DEFAULT(ip4_esp_trans_deflev);
		esp_net_deflev = IPSEC_CHECK_DEFAULT(ip4_esp_net_deflev);
		ah_trans_deflev = IPSEC_CHECK_DEFAULT(ip4_ah_trans_deflev);
		ah_net_deflev = IPSEC_CHECK_DEFAULT(ip4_ah_net_deflev);
		break;
#endif
#if INET6
	case AF_INET6:
		esp_trans_deflev = IPSEC_CHECK_DEFAULT(ip6_esp_trans_deflev);
		esp_net_deflev = IPSEC_CHECK_DEFAULT(ip6_esp_net_deflev);
		ah_trans_deflev = IPSEC_CHECK_DEFAULT(ip6_ah_trans_deflev);
		ah_net_deflev = IPSEC_CHECK_DEFAULT(ip6_ah_net_deflev);
		break;
#endif /* INET6 */
	default:
		panic("key_get_reqlevel: Unknown family. %d\n",
			((struct sockaddr *)&isr->sp->spidx.src)->sa_family);
	}

#undef IPSEC_CHECK_DEFAULT

	/* set level */
	switch (isr->level) {
	case IPSEC_LEVEL_DEFAULT:
		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
			if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
				level = esp_net_deflev;
			else
				level = esp_trans_deflev;
			break;
		case IPPROTO_AH:
			if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
				level = ah_net_deflev;
			else
				level = ah_trans_deflev;
			break;
		case IPPROTO_IPCOMP:
			/*
			 * we don't really care, as IPcomp document says that
			 * we shouldn't compress small packets
			 */
			level = IPSEC_LEVEL_USE;
			break;
		default:
			panic("ipsec_get_reqlevel: "
				"Illegal protocol defined %u\n",
				isr->saidx.proto);
		}
		break;

	case IPSEC_LEVEL_USE:
	case IPSEC_LEVEL_REQUIRE:
		level = isr->level;
		break;
	case IPSEC_LEVEL_UNIQUE:
		level = IPSEC_LEVEL_REQUIRE;
		break;

	default:
		panic("ipsec_get_reqlevel: Illegal IPsec level %u\n",
			isr->level);
	}

	return level;
}

/*
 * Check AH/ESP integrity.
 * OUT:
 *	0: valid
 *	1: invalid
 */
static int
ipsec_in_reject(sp, m)
	struct secpolicy *sp;
	struct mbuf *m;
{
	struct ipsecrequest *isr;
	u_int level;
	int need_auth, need_conf, need_icv;

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec_in_reject: using SP\n");
		kdebug_secpolicy(sp));

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_GENERATE:
		return 1;
	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		return 0;
	
	case IPSEC_POLICY_IPSEC:
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		panic("ipsec_hdrsiz: Invalid policy found. %d\n", sp->policy);
	}

	need_auth = 0;
	need_conf = 0;
	need_icv = 0;

	/* XXX should compare policy against ipsec header history */

	for (isr = sp->req; isr != NULL; isr = isr->next) {

		/* get current level */
		level = ipsec_get_reqlevel(isr);

		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
			if (level == IPSEC_LEVEL_REQUIRE) {
				need_conf++;

#if 0
		/* this won't work with multiple input threads - isr->sav would change 
		 * with every packet and is not necessarily related to the current packet 
		 * being processed.  If ESP processing is required - the esp code should
		 * make sure that the integrity check is present and correct.  I don't see
		 * why it would be necessary to check for the presence of the integrity
		 * check value here.  I think this is just wrong.
		 * isr->sav has been removed.
		 * %%%%%% this needs to be re-worked at some point but I think the code below can 
		 * be ignored for now.
		 */
				if (isr->sav != NULL
				 && isr->sav->flags == SADB_X_EXT_NONE
				 && isr->sav->alg_auth != SADB_AALG_NONE)
					need_icv++;
#endif
			}
			break;
		case IPPROTO_AH:
			if (level == IPSEC_LEVEL_REQUIRE) {
				need_auth++;
				need_icv++;
			}
			break;
		case IPPROTO_IPCOMP:
			/*
			 * we don't really care, as IPcomp document says that
			 * we shouldn't compress small packets, IPComp policy
			 * should always be treated as being in "use" level.
			 */
			break;
		}
	}

	KEYDEBUG(KEYDEBUG_IPSEC_DUMP,
		printf("ipsec_in_reject: auth:%d conf:%d icv:%d m_flags:%x\n",
			need_auth, need_conf, need_icv, m->m_flags));

	if ((need_conf && !(m->m_flags & M_DECRYPTED))
	 || (!need_auth && need_icv && !(m->m_flags & M_AUTHIPDGM))
	 || (need_auth && !(m->m_flags & M_AUTHIPHDR)))
		return 1;

	return 0;
}

/*
 * Check AH/ESP integrity.
 * This function is called from tcp_input(), udp_input(),
 * and {ah,esp}4_input for tunnel mode
 */
int
ipsec4_in_reject_so(m, so)
	struct mbuf *m;
	struct socket *so;
{
	struct secpolicy *sp = NULL;
	int error;
	int result;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec4_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (so == NULL)
		sp = ipsec4_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error);
	else
		sp = ipsec4_getpolicybyaddr(m, IPSEC_DIR_INBOUND, 0, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ?
				 * -> No, there may be error. */

	result = ipsec_in_reject(sp, m);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP ipsec4_in_reject_so call free SP:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
	key_freesp(sp, KEY_SADB_UNLOCKED);

	return result;
}

int
ipsec4_in_reject(m, inp)
	struct mbuf *m;
	struct inpcb *inp;
{
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	if (inp == NULL)
		return ipsec4_in_reject_so(m, NULL);
	if (inp->inp_socket)
		return ipsec4_in_reject_so(m, inp->inp_socket);
	else
		panic("ipsec4_in_reject: invalid inpcb/socket");

	/* NOTREACHED */
	return 0;
}

#if INET6
/*
 * Check AH/ESP integrity.
 * This function is called from tcp6_input(), udp6_input(),
 * and {ah,esp}6_input for tunnel mode
 */
int
ipsec6_in_reject_so(m, so)
	struct mbuf *m;
	struct socket *so;
{
	struct secpolicy *sp = NULL;
	int error;
	int result;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec6_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (so == NULL)
		sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_INBOUND, IP_FORWARDING, &error);
	else
		sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_INBOUND, 0, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ? */

	result = ipsec_in_reject(sp, m);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP ipsec6_in_reject_so call free SP:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
	key_freesp(sp, KEY_SADB_UNLOCKED);

	return result;
}

int
ipsec6_in_reject(m, in6p)
	struct mbuf *m;
	struct in6pcb *in6p;
{

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	if (in6p == NULL)
		return ipsec6_in_reject_so(m, NULL);
	if (in6p->in6p_socket)
		return ipsec6_in_reject_so(m, in6p->in6p_socket);
	else
		panic("ipsec6_in_reject: invalid in6p/socket");

	/* NOTREACHED */
	return 0;
}
#endif

/*
 * compute the byte size to be occupied by IPsec header.
 * in case it is tunneled, it includes the size of outer IP header.
 * NOTE: SP passed is free in this function.
 */
size_t
ipsec_hdrsiz(sp)
	struct secpolicy *sp;
{
	struct ipsecrequest *isr;
	size_t siz, clen;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec_hdrsiz: using SP\n");
		kdebug_secpolicy(sp));

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_GENERATE:
	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		return 0;
	
	case IPSEC_POLICY_IPSEC:
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		panic("ipsec_hdrsiz: Invalid policy found. %d\n", sp->policy);
	}

	siz = 0;

	for (isr = sp->req; isr != NULL; isr = isr->next) {

		clen = 0;

		switch (isr->saidx.proto) {
		case IPPROTO_ESP:
#if IPSEC_ESP
			clen = esp_hdrsiz(isr);
#else
			clen = 0;	/*XXX*/
#endif
			break;
		case IPPROTO_AH:
			clen = ah_hdrsiz(isr);
			break;
		case IPPROTO_IPCOMP:
			clen = sizeof(struct ipcomp);
			break;
		}

		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			switch (((struct sockaddr *)&isr->saidx.dst)->sa_family) {
			case AF_INET:
				clen += sizeof(struct ip);
				break;
#if INET6
			case AF_INET6:
				clen += sizeof(struct ip6_hdr);
				break;
#endif
			default:
				ipseclog((LOG_ERR, "ipsec_hdrsiz: "
				    "unknown AF %d in IPsec tunnel SA\n",
				    ((struct sockaddr *)&isr->saidx.dst)->sa_family));
				break;
			}
		}
		siz += clen;
	}

	return siz;
}

/* This function is called from ip_forward() and ipsec4_hdrsize_tcp(). */
size_t
ipsec4_hdrsiz(m, dir, inp)
	struct mbuf *m;
	u_int dir;
	struct inpcb *inp;
{
	struct secpolicy *sp = NULL;
	int error;
	size_t size;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX should be panic ? */
	if (inp != NULL && inp->inp_socket == NULL)
		panic("ipsec4_hdrsize: why is socket NULL but there is PCB.");

	/* get SP for this packet.
	 * When we are called from ip_forward(), we call
	 * ipsec4_getpolicybyaddr() with IP_FORWARDING flag.
	 */
	if (inp == NULL)
		sp = ipsec4_getpolicybyaddr(m, dir, IP_FORWARDING, &error);
	else
		sp = ipsec4_getpolicybyaddr(m, dir, 0, &error);

	if (sp == NULL)
		return 0;	/* XXX should be panic ? */

	size = ipsec_hdrsiz(sp);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP ipsec4_hdrsiz call free SP:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec4_hdrsiz: size:%lu.\n", (u_int32_t)size));
	key_freesp(sp, KEY_SADB_UNLOCKED);

	return size;
}

#if INET6
/* This function is called from ipsec6_hdrsize_tcp(),
 * and maybe from ip6_forward.()
 */
size_t
ipsec6_hdrsiz(m, dir, in6p)
	struct mbuf *m;
	u_int dir;
	struct in6pcb *in6p;
{
	struct secpolicy *sp = NULL;
	int error;
	size_t size;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (m == NULL)
		return 0;	/* XXX shoud be panic ? */
	if (in6p != NULL && in6p->in6p_socket == NULL)
		panic("ipsec6_hdrsize: why is socket NULL but there is PCB.");

	/* get SP for this packet */
	/* XXX Is it right to call with IP_FORWARDING. */
	if (in6p == NULL)
		sp = ipsec6_getpolicybyaddr(m, dir, IP_FORWARDING, &error);
	else
		sp = ipsec6_getpolicybyaddr(m, dir, 0, &error);

	if (sp == NULL)
		return 0;
	size = ipsec_hdrsiz(sp);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
	    printf("DP ipsec6_hdrsiz call free SP:0x%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(sp)));
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec6_hdrsiz: size:%lu.\n", (u_int32_t)size));
	key_freesp(sp, KEY_SADB_UNLOCKED);

	return size;
}
#endif /*INET6*/

#if INET
/*
 * encapsulate for ipsec tunnel.
 * ip->ip_src must be fixed later on.
 */
int
ipsec4_encapsulate(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip *oip;
	struct ip *ip;
	size_t hlen;
	size_t plen;

	/* can't tunnel between different AFs */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
		!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	 || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET) {
		m_freem(m);
		return EINVAL;
	}
#if 0
	/* XXX if the dst is myself, perform nothing. */
	if (key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst)) {
		m_freem(m);
		return EINVAL;
	}
#endif

	if (m->m_len < sizeof(*ip))
		panic("ipsec4_encapsulate: assumption failed (first mbuf length)");

	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	if (m->m_len != hlen)
		panic("ipsec4_encapsulate: assumption failed (first mbuf length)");

	/* generate header checksum */
	ip->ip_sum = 0;
#ifdef _IP_VHL
	ip->ip_sum = in_cksum(m, hlen);
#else
	ip->ip_sum = in_cksum(m, hlen);
#endif

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv4 header.
	 * NOTE: IPv4 options will never be copied.
	 */
	if (M_LEADINGSPACE(m->m_next) < hlen) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = hlen;
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += hlen;
		oip = mtod(n, struct ip *);
	} else {
		m->m_next->m_len += hlen;
		m->m_next->m_data -= hlen;
		m->m_pkthdr.len += hlen;
		oip = mtod(m->m_next, struct ip *);
	}
	ip = mtod(m, struct ip *);
	ovbcopy((caddr_t)ip, (caddr_t)oip, hlen);
	m->m_len = sizeof(struct ip);
	m->m_pkthdr.len -= (hlen - sizeof(struct ip));

	/* construct new IPv4 header. see RFC 2401 5.1.2.1 */
	/* ECN consideration. */
	ip_ecn_ingress(ip4_ipsec_ecn, &ip->ip_tos, &oip->ip_tos);
#ifdef _IP_VHL
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(struct ip) >> 2);
#else
	ip->ip_hl = sizeof(struct ip) >> 2;
#endif
	ip->ip_off &= htons(~IP_OFFMASK);
	ip->ip_off &= htons(~IP_MF);
	switch (ip4_ipsec_dfbit) {
	case 0:	/* clear DF bit */
		ip->ip_off &= htons(~IP_DF);
		break;
	case 1:	/* set DF bit */
		ip->ip_off |= htons(IP_DF);
		break;
	default:	/* copy DF bit */
		break;
	}
	ip->ip_p = IPPROTO_IPIP;
	if (plen + sizeof(struct ip) < IP_MAXPACKET)
		ip->ip_len = htons(plen + sizeof(struct ip));
	else {
		ipseclog((LOG_ERR, "IPv4 ipsec: size exceeds limit: "
			"leave ip_len as is (invalid packet)\n"));
	}
	ip->ip_id = ip_randomid();
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.src)->sin_addr,
		&ip->ip_src, sizeof(ip->ip_src));
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.dst)->sin_addr,
		&ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_ttl = IPDEFTTL;

	/* XXX Should ip_src be updated later ? */

	return 0;
}

/*
 * encapsulate for ipsec tunnel.
 * ip->ip_src must be fixed later on.
 */
int
ipsec4_encapsulate_utun_esp_keepalive(m_ptr, sav)
	struct mbuf **m_ptr;
	struct secasvar *sav;
{
	struct ip *ip;
	size_t plen;
	struct mbuf *m = *m_ptr;

	/* can't tunnel between different AFs */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
		!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	 || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET) {
		m_freem(m);
		*m_ptr = NULL;
		return EINVAL;
	}

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv4 header.
	 * NOTE: IPv4 options will never be copied.
	 */
	{
		struct mbuf *n;
		MGETHDR(n, M_DONTWAIT, MT_HEADER);     /* MAC-OK */
		if (!n) {
			m_freem(m);
			*m_ptr = NULL;
			return ENOBUFS;
		}
		if (m->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(n, m);
			m->m_flags &= ~M_PKTHDR;
		}
		MH_ALIGN(n, sizeof(*ip));
		n->m_len = sizeof(*ip);
		n->m_next = m;
		n->m_pkthdr.len = (plen + n->m_len);
		m_fixhdr(m);
		m = n;
		*m_ptr = m;
		plen = m->m_pkthdr.len;
	}
	ip = mtod(m, __typeof__(ip));

	/* construct new IPv4 header. see RFC 2401 5.1.2.1 */
	// ip_ecn_ingress(ip4_ipsec_ecn, &ip->ip_tos, &oip->ip_tos);
#ifdef _IP_VHL
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(*ip) >> 2);
#else
	ip->ip_hl = sizeof(*ip) >> 2;
#endif
	ip->ip_off &= htons(~IP_OFFMASK);
	ip->ip_off &= htons(~IP_MF);
	switch (ip4_ipsec_dfbit) {
	case 0:	/* clear DF bit */
		ip->ip_off &= htons(~IP_DF);
		break;
	case 1:	/* set DF bit */
		ip->ip_off |= htons(IP_DF);
		break;
	default:	/* copy DF bit */
		break;
	}
	ip->ip_p = IPPROTO_IPIP;
	if (plen < IP_MAXPACKET)
		ip->ip_len = htons(plen);
	else {
		ipseclog((LOG_ERR, "IPv4 ipsec: size exceeds limit: "
			"leave ip_len as is (invalid packet)\n"));
	}
	ip->ip_id = ip_randomid();
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.src)->sin_addr,
		&ip->ip_src, sizeof(ip->ip_src));
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.dst)->sin_addr,
		&ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_ttl = IPDEFTTL;

	/* XXX Should ip_src be updated later ? */

	return 0;
}
#endif /*INET*/

#if INET6
int
ipsec6_encapsulate(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip6_hdr *oip6;
	struct ip6_hdr *ip6;
	size_t plen;

	/* can't tunnel between different AFs */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
		!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	 || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET6) {
		m_freem(m);
		return EINVAL;
	}
#if 0
	/* XXX if the dst is myself, perform nothing. */
	if (key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst)) {
		m_freem(m);
		return EINVAL;
	}
#endif

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv6 header.
	 */
	if (m->m_len != sizeof(struct ip6_hdr))
		panic("ipsec6_encapsulate: assumption failed (first mbuf length)");
	if (M_LEADINGSPACE(m->m_next) < sizeof(struct ip6_hdr)) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = sizeof(struct ip6_hdr);
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip6 = mtod(n, struct ip6_hdr *);
	} else {
		m->m_next->m_len += sizeof(struct ip6_hdr);
		m->m_next->m_data -= sizeof(struct ip6_hdr);
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip6 = mtod(m->m_next, struct ip6_hdr *);
	}
	ip6 = mtod(m, struct ip6_hdr *);
	ovbcopy((caddr_t)ip6, (caddr_t)oip6, sizeof(struct ip6_hdr));

	/* Fake link-local scope-class addresses */
	if (IN6_IS_SCOPE_LINKLOCAL(&oip6->ip6_src))
		oip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_SCOPE_LINKLOCAL(&oip6->ip6_dst))
		oip6->ip6_dst.s6_addr16[1] = 0;

	/* construct new IPv6 header. see RFC 2401 5.1.2.2 */
	/* ECN consideration. */
	ip6_ecn_ingress(ip6_ipsec_ecn, &ip6->ip6_flow, &oip6->ip6_flow);
	if (plen < IPV6_MAXPACKET - sizeof(struct ip6_hdr))
		ip6->ip6_plen = htons(plen);
	else {
		/* ip6->ip6_plen will be updated in ip6_output() */
	}
	ip6->ip6_nxt = IPPROTO_IPV6;
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.src)->sin6_addr,
		&ip6->ip6_src, sizeof(ip6->ip6_src));
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr,
		&ip6->ip6_dst, sizeof(ip6->ip6_dst));
	ip6->ip6_hlim = IPV6_DEFHLIM;

	/* XXX Should ip6_src be updated later ? */

	return 0;
}

static int
ipsec64_encapsulate(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip6_hdr *ip6, *ip6i;
	struct ip *ip;
	size_t plen;
	u_int8_t hlim;

	/* tunneling over IPv4 */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
		!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	 || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET) {
		m_freem(m);
		return EINVAL;
	}
#if 0
	/* XXX if the dst is myself, perform nothing. */
	if (key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst)) {
		m_freem(m);
		return EINVAL;
	}
#endif

	plen = m->m_pkthdr.len;
	ip6 = mtod(m, struct ip6_hdr *);
	hlim = ip6->ip6_hlim; 
	/*
	 * grow the mbuf to accomodate the new IPv4 header.
	 */
	if (m->m_len != sizeof(struct ip6_hdr))
		panic("ipsec6_encapsulate: assumption failed (first mbuf length)");
	if (M_LEADINGSPACE(m->m_next) < sizeof(struct ip6_hdr)) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = sizeof(struct ip6_hdr);
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += sizeof(struct ip);
		ip6i = mtod(n, struct ip6_hdr *);
	} else {
		m->m_next->m_len += sizeof(struct ip6_hdr);
		m->m_next->m_data -= sizeof(struct ip6_hdr);
		m->m_pkthdr.len += sizeof(struct ip);
		ip6i = mtod(m->m_next, struct ip6_hdr *);
	}

	bcopy(ip6, ip6i, sizeof(struct ip6_hdr));
	ip = mtod(m, struct ip *);
	m->m_len = sizeof(struct ip);
	/* 
	 * Fill in some of the IPv4 fields - we don't need all of them
	 * because the rest will be filled in by ip_output
	 */
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_id = 0;
	ip->ip_sum = 0;
	ip->ip_tos = 0; 
	ip->ip_off = 0;
	ip->ip_ttl = hlim;
	ip->ip_p = IPPROTO_IPV6;

	/* construct new IPv4 header. see RFC 2401 5.1.2.1 */
	/* ECN consideration. */
	ip64_ecn_ingress(ip4_ipsec_ecn, &ip->ip_tos, &ip6->ip6_flow);

	if (plen + sizeof(struct ip) < IP_MAXPACKET)
		ip->ip_len = htons(plen + sizeof(struct ip));
	else {
		ip->ip_len = htons(plen);
		ipseclog((LOG_ERR, "IPv4 ipsec: size exceeds limit: "
			"leave ip_len as is (invalid packet)\n"));
	}
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.src)->sin_addr,
		&ip->ip_src, sizeof(ip->ip_src));
	bcopy(&((struct sockaddr_in *)&sav->sah->saidx.dst)->sin_addr,
		&ip->ip_dst, sizeof(ip->ip_dst));

	return 0;
}

int
ipsec6_encapsulate_utun_esp_keepalive(m_ptr, sav)
	struct mbuf **m_ptr;
	struct secasvar *sav;
{
	struct ip6_hdr *ip6;
	size_t plen;
	struct mbuf *m = *m_ptr;

	/* can't tunnel between different AFs */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
		!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	 || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET6) {
		m_freem(m);
		*m_ptr = NULL;
		return EINVAL;
	}

	plen = m->m_pkthdr.len;

	/*
	 * grow the mbuf to accomodate the new IPv6 header.
	 */
	{
		struct mbuf *n;
		MGETHDR(n, M_DONTWAIT, MT_HEADER);     /* MAC-OK */
		if (!n) {
			m_freem(m);
			*m_ptr = NULL;
			return ENOBUFS;
		}
		if (m->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(n, m);
			m->m_flags &= ~M_PKTHDR;
		}
		MH_ALIGN(n, sizeof(*ip6));
		n->m_len = sizeof(*ip6);
		n->m_next = m;
		n->m_pkthdr.len = (plen + n->m_len);
		m_fixhdr(m);
		m = n;
		*m_ptr = m;
		plen = m->m_pkthdr.len;
	}
	ip6 = mtod(m, __typeof__(ip6));

	/* construct new IPv6 header. see RFC 2401 5.1.2.2 */
	if (plen < IPV6_MAXPACKET)
		ip6->ip6_plen = htons(plen);
	else {
		/* ip6->ip6_plen will be updated in ip6_output() */
	}
	ip6->ip6_nxt = IPPROTO_IPV6;
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.src)->sin6_addr,
		&ip6->ip6_src, sizeof(ip6->ip6_src));
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr,
		&ip6->ip6_dst, sizeof(ip6->ip6_dst));
	ip6->ip6_hlim = IPV6_DEFHLIM;

	/* XXX Should ip6_src be updated later ? */

	return 0;
}

int
ipsec6_update_routecache_and_output(state, sav)
	struct ipsec_output_state *state;
	struct secasvar *sav;
{
	struct sockaddr_in6* dst6;
	struct route *ro6;
	struct ip6_hdr *ip6;
	errno_t error = 0;

	int plen;
	struct ip6_out_args ip6oa;
	struct route_in6 ro6_new;
	struct flowadv *adv = NULL;

	if (!state->m) {
		return EINVAL;
	}
	ip6 = mtod(state->m, struct ip6_hdr *);

	// grab sadb_mutex, before updating sah's route cache
	lck_mtx_lock(sadb_mutex);
	ro6 = &sav->sah->sa_route;
	dst6 = (struct sockaddr_in6 *)(void *)&ro6->ro_dst;
	if (ro6->ro_rt) {
	        RT_LOCK(ro6->ro_rt);
	}
	if (ROUTE_UNUSABLE(ro6) ||
	    !IN6_ARE_ADDR_EQUAL(&dst6->sin6_addr, &ip6->ip6_dst)) {
	        if (ro6->ro_rt != NULL)
		        RT_UNLOCK(ro6->ro_rt);
		ROUTE_RELEASE(ro6);
	}
	if (ro6->ro_rt == 0) {
		bzero(dst6, sizeof(*dst6));
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof(*dst6);
		dst6->sin6_addr = ip6->ip6_dst;
		rtalloc(ro6);
		if (ro6->ro_rt) {
		        RT_LOCK(ro6->ro_rt);
		}
	}
	if (ro6->ro_rt == 0) {
		ip6stat.ip6s_noroute++;
		IPSEC_STAT_INCREMENT(ipsec6stat.out_noroute);
		error = EHOSTUNREACH;
		// release sadb_mutex, after updating sah's route cache
		lck_mtx_unlock(sadb_mutex);
		return error;
	}

	/*
	 * adjust state->dst if tunnel endpoint is offlink
	 *
	 * XXX: caching rt_gateway value in the state is
	 * not really good, since it may point elsewhere
	 * when the gateway gets modified to a larger
	 * sockaddr via rt_setgate().  This is currently
	 * addressed by SA_SIZE roundup in that routine.
	 */
	if (ro6->ro_rt->rt_flags & RTF_GATEWAY)
	        dst6 = (struct sockaddr_in6 *)(void *)ro6->ro_rt->rt_gateway;
	RT_UNLOCK(ro6->ro_rt);
	ROUTE_RELEASE(&state->ro);
	route_copyout(&state->ro, ro6, sizeof(state->ro));
	state->dst = (struct sockaddr *)dst6;
	state->tunneled = 6;
	// release sadb_mutex, after updating sah's route cache                                                                                                                          
	lck_mtx_unlock(sadb_mutex);

	state->m = ipsec6_splithdr(state->m);
	if (!state->m) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_nomem);
		error = ENOMEM;
		return error;
	}

	ip6 = mtod(state->m, struct ip6_hdr *);
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
#if IPSEC_ESP
		error = esp6_output(state->m, &ip6->ip6_nxt, state->m->m_next, sav);
#else
		m_freem(state->m);
		error = EINVAL;
#endif
		break;
	case IPPROTO_AH:
		error = ah6_output(state->m, &ip6->ip6_nxt, state->m->m_next, sav);
		break;
	case IPPROTO_IPCOMP:
		/* XXX code should be here */
		/*FALLTHROUGH*/
	default:
		ipseclog((LOG_ERR, "%s: unknown ipsec protocol %d\n", __FUNCTION__, sav->sah->saidx.proto));
		m_freem(state->m);
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		error = EINVAL;
		break;
	}
	if (error) {
		// If error, packet already freed by above output routines
		state->m = NULL;
		return error;
	}

	plen = state->m->m_pkthdr.len - sizeof(struct ip6_hdr);
	if (plen > IPV6_MAXPACKET) {
		ipseclog((LOG_ERR, "%s: IPsec with IPv6 jumbogram is not supported\n", __FUNCTION__));
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		error = EINVAL;/*XXX*/
		return error;
	}
	ip6 = mtod(state->m, struct ip6_hdr *);
	ip6->ip6_plen = htons(plen);

	ipsec_set_pkthdr_for_interface(sav->sah->ipsec_if, state->m, AF_INET6);

	/* Increment statistics */
	ifnet_stat_increment_out(sav->sah->ipsec_if, 1, mbuf_pkthdr_len(state->m), 0);

	/* Send to ip6_output */
	bzero(&ro6_new, sizeof(ro6_new));
	bzero(&ip6oa, sizeof(ip6oa));
	ip6oa.ip6oa_flowadv.code = 0;
	ip6oa.ip6oa_flags = IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR;
	if (state->outgoing_if) {
		ip6oa.ip6oa_boundif = state->outgoing_if;
		ip6oa.ip6oa_flags |= IPOAF_BOUND_IF;
	}

	adv = &ip6oa.ip6oa_flowadv;
	(void) ip6_output(state->m, NULL, &ro6_new, IPV6_OUTARGS, NULL, NULL, &ip6oa);

	if (adv->code == FADV_FLOW_CONTROLLED || adv->code == FADV_SUSPENDED) {
		error = ENOBUFS;
		ifnet_disable_output(sav->sah->ipsec_if);
		return error;
	}

	return 0;
}

int
ipsec46_encapsulate(state, sav)
	struct secasvar *sav;
	struct ipsec_output_state *state;
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct ip *oip;
	struct ip *ip;
	size_t hlen;
	size_t plen;

	m = state->m;
	if (!m) {
		return EINVAL;
	}

	/* can't tunnel between different AFs */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
	    != ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family
	    || ((struct sockaddr *)&sav->sah->saidx.src)->sa_family != AF_INET6) {
		m_freem(m);
		return EINVAL;
	}
#if 0
	/* XXX if the dst is myself, perform nothing. */
	if (key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst)) {
	        m_freem(m);
		return EINVAL;
	}
#endif

	if (m->m_len < sizeof(*ip)) {
		panic("ipsec46_encapsulate: assumption failed (first mbuf length)");
		return EINVAL;
	}

	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	if (m->m_len != hlen) {
		panic("ipsec46_encapsulate: assumption failed (first mbuf length)");
		return EINVAL;
	}

	/* generate header checksum */
	ip->ip_sum = 0;
#ifdef _IP_VHL
	ip->ip_sum = in_cksum(m, hlen);
#else
	ip->ip_sum = in_cksum(m, hlen);
#endif

	plen = m->m_pkthdr.len; // save original IPv4 packet len, this will be ipv6 payload len

	/*
	 * First move the IPv4 header to the second mbuf in the chain
	 */
	if (M_LEADINGSPACE(m->m_next) < hlen) {
		struct mbuf *n;
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		n->m_len = hlen;
		n->m_next = m->m_next;
		m->m_next = n;
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip = mtod(n, struct ip *);
	} else {
		m->m_next->m_len += hlen;
		m->m_next->m_data -= hlen;
		m->m_pkthdr.len += sizeof(struct ip6_hdr);
		oip = mtod(m->m_next, struct ip *);
	}
	ip = mtod(m, struct ip *);
	ovbcopy((caddr_t)ip, (caddr_t)oip, hlen);

	/*
	 * Grow the first mbuf to accomodate the new IPv6 header.
	 */
	if (M_LEADINGSPACE(m) < sizeof(struct ip6_hdr) - hlen) {
		struct mbuf *n;
		MGETHDR(n, M_DONTWAIT, MT_HEADER);
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		M_COPY_PKTHDR(n, m);
		MH_ALIGN(n, sizeof(struct ip6_hdr));
		n->m_len = sizeof(struct ip6_hdr);
		n->m_next = m->m_next;
		m->m_next = NULL;
		m_freem(m);
		state->m = n;
		m = state->m;
	} else {	 
		m->m_len += (sizeof(struct ip6_hdr) - hlen);
		m->m_data -= (sizeof(struct ip6_hdr) - hlen);
	}
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;

	/* construct new IPv6 header. see RFC 2401 5.1.2.2 */
	/* ECN consideration. */
	ip46_ecn_ingress(ip6_ipsec_ecn, &ip6->ip6_flow, &ip->ip_tos);
	if (plen < IPV6_MAXPACKET - sizeof(struct ip6_hdr))
		ip6->ip6_plen = htons(plen);
	else {
		/* ip6->ip6_plen will be updated in ip6_output() */
	}

	ip6->ip6_nxt = IPPROTO_IPV4;
	ip6->ip6_hlim = IPV6_DEFHLIM;

	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.src)->sin6_addr,
	      &ip6->ip6_src, sizeof(ip6->ip6_src));
	bcopy(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr,
	      &ip6->ip6_dst, sizeof(ip6->ip6_dst));

	return 0;
}

#endif /*INET6*/

/*
 * Check the variable replay window.
 * ipsec_chkreplay() performs replay check before ICV verification.
 * ipsec_updatereplay() updates replay bitmap.  This must be called after
 * ICV verification (it also performs replay check, which is usually done
 * beforehand).
 * 0 (zero) is returned if packet disallowed, 1 if packet permitted.
 *
 * based on RFC 2401.
 */
int
ipsec_chkreplay(seq, sav)
	u_int32_t seq;
	struct secasvar *sav;
{
	const struct secreplay *replay;
	u_int32_t diff;
	int fr;
	u_int32_t wsizeb;	/* constant: bits of window size */
	int frlast;		/* constant: last frame */

	
	/* sanity check */
	if (sav == NULL)
		panic("ipsec_chkreplay: NULL pointer was passed.\n");

	lck_mtx_lock(sadb_mutex);
	replay = sav->replay;

	if (replay->wsize == 0) {
		lck_mtx_unlock(sadb_mutex);
		return 1;	/* no need to check replay. */
	}

	/* constant */
	frlast = replay->wsize - 1;
	wsizeb = replay->wsize << 3;

	/* sequence number of 0 is invalid */
	if (seq == 0) {
		lck_mtx_unlock(sadb_mutex);
		return 0;
	}

	/* first time is always okay */
	if (replay->count == 0) {
		lck_mtx_unlock(sadb_mutex);
		return 1;
	}

	if (seq > replay->lastseq) {
		/* larger sequences are okay */
		lck_mtx_unlock(sadb_mutex);
		return 1;
	} else {
		/* seq is equal or less than lastseq. */
		diff = replay->lastseq - seq;

		/* over range to check, i.e. too old or wrapped */
		if (diff >= wsizeb) {
			lck_mtx_unlock(sadb_mutex);
			return 0;
		}

		fr = frlast - diff / 8;

		/* this packet already seen ? */
		if ((replay->bitmap)[fr] & (1 << (diff % 8))) {
			lck_mtx_unlock(sadb_mutex);
			return 0;
		}

		/* out of order but good */
		lck_mtx_unlock(sadb_mutex);
		return 1;
	}
}

/*
 * check replay counter whether to update or not.
 * OUT:	0:	OK
 *	1:	NG
 */
int
ipsec_updatereplay(seq, sav)
	u_int32_t seq;
	struct secasvar *sav;
{
	struct secreplay *replay;
	u_int32_t diff;
	int fr;
	u_int32_t wsizeb;	/* constant: bits of window size */
	int frlast;		/* constant: last frame */
	
	/* sanity check */
	if (sav == NULL)
		panic("ipsec_chkreplay: NULL pointer was passed.\n");

	lck_mtx_lock(sadb_mutex);
	replay = sav->replay;

	if (replay->wsize == 0)
		goto ok;	/* no need to check replay. */

	/* constant */
	frlast = replay->wsize - 1;
	wsizeb = replay->wsize << 3;

	/* sequence number of 0 is invalid */
	if (seq == 0)
		return 1;

	/* first time */
	if (replay->count == 0) {
		replay->lastseq = seq;
		bzero(replay->bitmap, replay->wsize);
		(replay->bitmap)[frlast] = 1;
		goto ok;
	}

	if (seq > replay->lastseq) {
		/* seq is larger than lastseq. */
		diff = seq - replay->lastseq;

		/* new larger sequence number */
		if (diff < wsizeb) {
			/* In window */
			/* set bit for this packet */
			vshiftl((unsigned char *) replay->bitmap, diff, replay->wsize);
			(replay->bitmap)[frlast] |= 1;
		} else {
			/* this packet has a "way larger" */
			bzero(replay->bitmap, replay->wsize);
			(replay->bitmap)[frlast] = 1;
		}
		replay->lastseq = seq;

		/* larger is good */
	} else {
		/* seq is equal or less than lastseq. */
		diff = replay->lastseq - seq;

		/* over range to check, i.e. too old or wrapped */
		if (diff >= wsizeb) {
			lck_mtx_unlock(sadb_mutex);
			return 1;
		}

		fr = frlast - diff / 8;

		/* this packet already seen ? */
		if ((replay->bitmap)[fr] & (1 << (diff % 8))) {
			lck_mtx_unlock(sadb_mutex);
			return 1;
		}

		/* mark as seen */
		(replay->bitmap)[fr] |= (1 << (diff % 8));

		/* out of order but good */
	}

ok:
	if (replay->count == ~0) {

		/* set overflow flag */
		replay->overflow++;

		/* don't increment, no more packets accepted */
		if ((sav->flags & SADB_X_EXT_CYCSEQ) == 0) {
			lck_mtx_unlock(sadb_mutex);
			return 1;
		}

		ipseclog((LOG_WARNING, "replay counter made %d cycle. %s\n",
		    replay->overflow, ipsec_logsastr(sav)));
	}

	replay->count++;
	
	lck_mtx_unlock(sadb_mutex);
	return 0;
}

/*
 * shift variable length buffer to left.
 * IN:	bitmap: pointer to the buffer
 * 	nbit:	the number of to shift.
 *	wsize:	buffer size (bytes).
 */
static void
vshiftl(bitmap, nbit, wsize)
	unsigned char *bitmap;
	int nbit, wsize;
{
	int s, j, i;
	unsigned char over;

	for (j = 0; j < nbit; j += 8) {
		s = (nbit - j < 8) ? (nbit - j): 8;
		bitmap[0] <<= s;
		for (i = 1; i < wsize; i++) {
			over = (bitmap[i] >> (8 - s));
			bitmap[i] <<= s;
			bitmap[i-1] |= over;
		}
	}

	return;
}

const char *
ipsec4_logpacketstr(ip, spi)
	struct ip *ip;
	u_int32_t spi;
{
	static char buf[256] __attribute__((aligned(4)));
	char *p;
	u_int8_t *s, *d;

	s = (u_int8_t *)(&ip->ip_src);
	d = (u_int8_t *)(&ip->ip_dst);

	p = buf;
	snprintf(buf, sizeof(buf), "packet(SPI=%u ", (u_int32_t)ntohl(spi));
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), "src=%u.%u.%u.%u",
		s[0], s[1], s[2], s[3]);
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), " dst=%u.%u.%u.%u",
		d[0], d[1], d[2], d[3]);
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}

#if INET6
const char *
ipsec6_logpacketstr(ip6, spi)
	struct ip6_hdr *ip6;
	u_int32_t spi;
{
	static char buf[256] __attribute__((aligned(4)));
	char *p;

	p = buf;
	snprintf(buf, sizeof(buf), "packet(SPI=%u ", (u_int32_t)ntohl(spi));
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), "src=%s",
		ip6_sprintf(&ip6->ip6_src));
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), " dst=%s",
		ip6_sprintf(&ip6->ip6_dst));
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}
#endif /*INET6*/

const char *
ipsec_logsastr(sav)
	struct secasvar *sav;
{
	static char buf[256] __attribute__((aligned(4)));
	char *p;
	struct secasindex *saidx = &sav->sah->saidx;

	/* validity check */
	if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family
			!= ((struct sockaddr *)&sav->sah->saidx.dst)->sa_family)
		panic("ipsec_logsastr: family mismatched.\n");

	p = buf;
	snprintf(buf, sizeof(buf), "SA(SPI=%u ", (u_int32_t)ntohl(sav->spi));
	while (p && *p)
		p++;
	if (((struct sockaddr *)&saidx->src)->sa_family == AF_INET) {
		u_int8_t *s, *d;
		s = (u_int8_t *)&((struct sockaddr_in *)&saidx->src)->sin_addr;
		d = (u_int8_t *)&((struct sockaddr_in *)&saidx->dst)->sin_addr;
		snprintf(p, sizeof(buf) - (p - buf),
			"src=%d.%d.%d.%d dst=%d.%d.%d.%d",
			s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]);
	}
#if INET6
	else if (((struct sockaddr *)&saidx->src)->sa_family == AF_INET6) {
		snprintf(p, sizeof(buf) - (p - buf),
			"src=%s",
			ip6_sprintf(&((struct sockaddr_in6 *)&saidx->src)->sin6_addr));
		while (p && *p)
			p++;
		snprintf(p, sizeof(buf) - (p - buf),
			" dst=%s",
			ip6_sprintf(&((struct sockaddr_in6 *)&saidx->dst)->sin6_addr));
	}
#endif
	while (p && *p)
		p++;
	snprintf(p, sizeof(buf) - (p - buf), ")");

	return buf;
}

void
ipsec_dumpmbuf(m)
	struct mbuf *m;
{
	int totlen;
	int i;
	u_char *p;

	totlen = 0;
	printf("---\n");
	while (m) {
		p = mtod(m, u_char *);
		for (i = 0; i < m->m_len; i++) {
			printf("%02x ", p[i]);
			totlen++;
			if (totlen % 16 == 0)
				printf("\n");
		}
		m = m->m_next;
	}
	if (totlen % 16 != 0)
		printf("\n");
	printf("---\n");
}

#if INET
/*
 * IPsec output logic for IPv4.
 */
static int
ipsec4_output_internal(struct ipsec_output_state *state, struct secasvar *sav)
{
	struct ip *ip = NULL;
	int error = 0;
	struct sockaddr_in *dst4;
	struct route *ro4;

	/* validity check */
	if (sav == NULL || sav->sah == NULL) {
		error = EINVAL;
		goto bad;
	}

	/*
	 * If there is no valid SA, we give up to process any
	 * more.  In such a case, the SA's status is changed
	 * from DYING to DEAD after allocating.  If a packet
	 * send to the receiver by dead SA, the receiver can
	 * not decode a packet because SA has been dead.
	 */
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		IPSEC_STAT_INCREMENT(ipsecstat.out_nosa);
		error = EINVAL;
		goto bad;
	}
	
	state->outgoing_if = sav->sah->outgoing_if;

	/*
	 * There may be the case that SA status will be changed when
	 * we are refering to one. So calling splsoftnet().
	 */

	if (sav->sah->saidx.mode == IPSEC_MODE_TUNNEL) {
		/*
		 * build IPsec tunnel.
		 */
		state->m = ipsec4_splithdr(state->m);
		if (!state->m) {
			error = ENOMEM;
			goto bad;
		}

		if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family == AF_INET6) {
			error = ipsec46_encapsulate(state, sav);
			if (error) {
				// packet already freed by encapsulation error handling
				state->m = NULL;
				return error;
			}

			error = ipsec6_update_routecache_and_output(state, sav);
			return error;

		} else if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family == AF_INET) {
			error = ipsec4_encapsulate(state->m, sav);
			if (error) {
				state->m = NULL;
				goto bad;
			}
			ip = mtod(state->m, struct ip *);

			// grab sadb_mutex, before updating sah's route cache
			lck_mtx_lock(sadb_mutex);
			ro4= &sav->sah->sa_route;
			dst4 = (struct sockaddr_in *)(void *)&ro4->ro_dst;
			if (ro4->ro_rt != NULL) {
			        RT_LOCK(ro4->ro_rt);
			}
			if (ROUTE_UNUSABLE(ro4) ||
			    dst4->sin_addr.s_addr != ip->ip_dst.s_addr) {
			        if (ro4->ro_rt != NULL)
				        RT_UNLOCK(ro4->ro_rt);
				ROUTE_RELEASE(ro4);
			}
			if (ro4->ro_rt == 0) {
				dst4->sin_family = AF_INET;
				dst4->sin_len = sizeof(*dst4);
				dst4->sin_addr = ip->ip_dst;
				rtalloc(ro4);
				if (ro4->ro_rt == 0) {
					OSAddAtomic(1, &ipstat.ips_noroute);
					error = EHOSTUNREACH;
					// release sadb_mutex, after updating sah's route cache
					lck_mtx_unlock(sadb_mutex);
					goto bad;
				}
				RT_LOCK(ro4->ro_rt);
			}

			/*
			 * adjust state->dst if tunnel endpoint is offlink
			 *
			 * XXX: caching rt_gateway value in the state is
			 * not really good, since it may point elsewhere
			 * when the gateway gets modified to a larger
			 * sockaddr via rt_setgate().  This is currently
			 * addressed by SA_SIZE roundup in that routine.
			 */
			if (ro4->ro_rt->rt_flags & RTF_GATEWAY)
			        dst4 = (struct sockaddr_in *)(void *)ro4->ro_rt->rt_gateway;
			RT_UNLOCK(ro4->ro_rt);
			ROUTE_RELEASE(&state->ro);
			route_copyout(&state->ro, ro4, sizeof(state->ro));
			state->dst = (struct sockaddr *)dst4;
			state->tunneled = 4;
			// release sadb_mutex, after updating sah's route cache                                                                                                    
			lck_mtx_unlock(sadb_mutex);
		} else {
			ipseclog((LOG_ERR, "%s: family mismatched between inner and outer spi=%u\n",
				  __FUNCTION__, (u_int32_t)ntohl(sav->spi)));
			error = EAFNOSUPPORT;
			goto bad;
		}
	}

	state->m = ipsec4_splithdr(state->m);
	if (!state->m) {
		error = ENOMEM;
		goto bad;
	}
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
#if IPSEC_ESP
		if ((error = esp4_output(state->m, sav)) != 0) {
			state->m = NULL;
			goto bad;
		}
		break;
#else
		m_freem(state->m);
		state->m = NULL;
		error = EINVAL;
		goto bad;
#endif
	case IPPROTO_AH:
		if ((error = ah4_output(state->m, sav)) != 0) {
			state->m = NULL;
			goto bad;
		}
		break;
	case IPPROTO_IPCOMP:
		if ((error = ipcomp4_output(state->m, sav)) != 0) {
			state->m = NULL;
			goto bad;
		}
		break;
	default:
		ipseclog((LOG_ERR,
			"ipsec4_output: unknown ipsec protocol %d\n",
			sav->sah->saidx.proto));
		m_freem(state->m);
		state->m = NULL;
		error = EINVAL;
		goto bad;
	}

	if (state->m == 0) {
		error = ENOMEM;
		goto bad;
	}

	return 0;

bad:
	return error;
}

int
ipsec4_interface_output(struct ipsec_output_state *state, ifnet_t interface)
{
	int error = 0;
	struct secasvar *sav = NULL;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (!state)
		panic("state == NULL in ipsec4_output");
	if (!state->m)
		panic("state->m == NULL in ipsec4_output");
	if (!state->dst)
		panic("state->dst == NULL in ipsec4_output");
	
	sav = key_alloc_outbound_sav_for_interface(interface, AF_INET);
	if (sav == NULL) {
		goto bad;
	}
	
	if ((error = ipsec4_output_internal(state, sav)) != 0) {
		goto bad;
	}
	
	KERNEL_DEBUG(DBG_FNC_IPSEC_OUT | DBG_FUNC_END, 0,0,0,0,0);
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	return 0;
	
bad:
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	m_freem(state->m);
	state->m = NULL;
	KERNEL_DEBUG(DBG_FNC_IPSEC_OUT | DBG_FUNC_END, error,0,0,0,0);
	return error;
}

int
ipsec4_output(struct ipsec_output_state *state, struct secpolicy *sp, __unused int flags)
{
	struct ip *ip = NULL;
	struct ipsecrequest *isr = NULL;
	struct secasindex saidx;
	struct secasvar *sav = NULL;
	int error = 0;
	struct sockaddr_in *sin;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (!state)
		panic("state == NULL in ipsec4_output");
	if (!state->m)
		panic("state->m == NULL in ipsec4_output");
	if (!state->dst)
		panic("state->dst == NULL in ipsec4_output");
	
	KERNEL_DEBUG(DBG_FNC_IPSEC_OUT | DBG_FUNC_START, 0,0,0,0,0);
	
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
			 printf("ipsec4_output: applied SP\n");
			 kdebug_secpolicy(sp));
	
	for (isr = sp->req; isr != NULL; isr = isr->next) {
		/* make SA index for search proper SA */
		ip = mtod(state->m, struct ip *);
		bcopy(&isr->saidx, &saidx, sizeof(saidx));
		saidx.mode = isr->saidx.mode;
		saidx.reqid = isr->saidx.reqid;
		sin = (struct sockaddr_in *)&saidx.src;
		if (sin->sin_len == 0) {
			sin->sin_len = sizeof(*sin);
			sin->sin_family = AF_INET;
			sin->sin_port = IPSEC_PORT_ANY;
			bcopy(&ip->ip_src, &sin->sin_addr,
				  sizeof(sin->sin_addr));
		}
		sin = (struct sockaddr_in *)&saidx.dst;
		if (sin->sin_len == 0) {
			sin->sin_len = sizeof(*sin);
			sin->sin_family = AF_INET;
			sin->sin_port = IPSEC_PORT_ANY;
			/*
			 * Get port from packet if upper layer is UDP and nat traversal
			 * is enabled and transport mode.
			 */
			
			if ((esp_udp_encap_port & 0xFFFF) != 0 &&
				isr->saidx.mode == IPSEC_MODE_TRANSPORT) {
				
				if (ip->ip_p == IPPROTO_UDP) {
					struct udphdr  *udp;
					size_t hlen;
#ifdef _IP_VHL
					hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
					hlen = ip->ip_hl << 2;
#endif
					if (state->m->m_len < hlen + sizeof(struct udphdr)) {
						state->m = m_pullup(state->m, hlen + sizeof(struct udphdr));
						if (!state->m) {
							ipseclog((LOG_DEBUG, "IPv4 output: can't pullup UDP header\n"));
							IPSEC_STAT_INCREMENT(ipsecstat.in_inval);
							goto bad;
						}
						ip = mtod(state->m, struct ip *);
					}
					udp = (struct udphdr *)(void *)(((u_int8_t *)ip) + hlen);
					sin->sin_port = udp->uh_dport;
				}
			}
			
			bcopy(&ip->ip_dst, &sin->sin_addr,
				  sizeof(sin->sin_addr));
		}
		
		if ((error = key_checkrequest(isr, &saidx, &sav)) != 0) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			IPSEC_STAT_INCREMENT(ipsecstat.out_nosa);
			goto bad;
		}
		
		/* validity check */
		if (sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
				case IPSEC_LEVEL_USE:
					continue;
				case IPSEC_LEVEL_REQUIRE:
					/* must be not reached here. */
					panic("ipsec4_output: no SA found, but required.");
			}
		}
		
		if ((error = ipsec4_output_internal(state, sav)) != 0) {
			goto bad;
		}
	}
	
	KERNEL_DEBUG(DBG_FNC_IPSEC_OUT | DBG_FUNC_END, 0,0,0,0,0);
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	return 0;
	
bad:
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	m_freem(state->m);
	state->m = NULL;
	KERNEL_DEBUG(DBG_FNC_IPSEC_OUT | DBG_FUNC_END, error,0,0,0,0);
	return error;
}

#endif

#if INET6
/*
 * IPsec output logic for IPv6, transport mode.
 */
static int
ipsec6_output_trans_internal(
	struct ipsec_output_state *state,
	struct secasvar *sav,
	u_char *nexthdrp,
	struct mbuf *mprev)
{
	struct ip6_hdr *ip6;
	int error = 0;
	int plen;
	
	/* validity check */
	if (sav == NULL || sav->sah == NULL) {
		error = EINVAL;
		goto bad;
	}
	
	/*
	 * If there is no valid SA, we give up to process.
	 * see same place at ipsec4_output().
	 */
	if (sav->state != SADB_SASTATE_MATURE
	 && sav->state != SADB_SASTATE_DYING) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_nosa);
		error = EINVAL;
		goto bad;
	}
	
	state->outgoing_if = sav->sah->outgoing_if;

	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
#if IPSEC_ESP
		error = esp6_output(state->m, nexthdrp, mprev->m_next, sav);
#else
		m_freem(state->m);
		error = EINVAL;
#endif
		break;
	case IPPROTO_AH:
		error = ah6_output(state->m, nexthdrp, mprev->m_next, sav);
		break;
	case IPPROTO_IPCOMP:
		error = ipcomp6_output(state->m, nexthdrp, mprev->m_next, sav);
		break;
	default:
		ipseclog((LOG_ERR, "ipsec6_output_trans: "
			"unknown ipsec protocol %d\n", sav->sah->saidx.proto));
		m_freem(state->m);
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		error = EINVAL;
		break;
	}
	if (error) {
		state->m = NULL;
		goto bad;
	}
	plen = state->m->m_pkthdr.len - sizeof(struct ip6_hdr);
	if (plen > IPV6_MAXPACKET) {
		ipseclog((LOG_ERR, "ipsec6_output_trans: "
			"IPsec with IPv6 jumbogram is not supported\n"));
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		error = EINVAL;	/*XXX*/
		goto bad;
	}
	ip6 = mtod(state->m, struct ip6_hdr *);
	ip6->ip6_plen = htons(plen);

	return 0;
bad:
	return error;
}

int
ipsec6_output_trans(
					struct ipsec_output_state *state,
					u_char *nexthdrp,
					struct mbuf *mprev,
					struct secpolicy *sp,
					__unused int flags,
					int *tun)
{
	struct ip6_hdr *ip6;
	struct ipsecrequest *isr = NULL;
	struct secasindex saidx;
	int error = 0;
	struct sockaddr_in6 *sin6;
	struct secasvar *sav = NULL;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (!state)
		panic("state == NULL in ipsec6_output_trans");
	if (!state->m)
		panic("state->m == NULL in ipsec6_output_trans");
	if (!nexthdrp)
		panic("nexthdrp == NULL in ipsec6_output_trans");
	if (!mprev)
		panic("mprev == NULL in ipsec6_output_trans");
	if (!sp)
		panic("sp == NULL in ipsec6_output_trans");
	if (!tun)
		panic("tun == NULL in ipsec6_output_trans");
	
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
			 printf("ipsec6_output_trans: applyed SP\n");
			 kdebug_secpolicy(sp));
	
	*tun = 0;
	for (isr = sp->req; isr; isr = isr->next) {
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/* the rest will be handled by ipsec6_output_tunnel() */
			break;
		}
		
		/* make SA index for search proper SA */
		ip6 = mtod(state->m, struct ip6_hdr *);
		bcopy(&isr->saidx, &saidx, sizeof(saidx));
		saidx.mode = isr->saidx.mode;
		saidx.reqid = isr->saidx.reqid;
		sin6 = (struct sockaddr_in6 *)&saidx.src;
		if (sin6->sin6_len == 0) {
			sin6->sin6_len = sizeof(*sin6);
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = IPSEC_PORT_ANY;
			bcopy(&ip6->ip6_src, &sin6->sin6_addr,
				  sizeof(ip6->ip6_src));
			if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
				/* fix scope id for comparing SPD */
				sin6->sin6_addr.s6_addr16[1] = 0;
				sin6->sin6_scope_id = ntohs(ip6->ip6_src.s6_addr16[1]);
			}
		}
		sin6 = (struct sockaddr_in6 *)&saidx.dst;
		if (sin6->sin6_len == 0) {
			sin6->sin6_len = sizeof(*sin6);
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = IPSEC_PORT_ANY;
			bcopy(&ip6->ip6_dst, &sin6->sin6_addr,
				  sizeof(ip6->ip6_dst));
			if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
				/* fix scope id for comparing SPD */
				sin6->sin6_addr.s6_addr16[1] = 0;
				sin6->sin6_scope_id = ntohs(ip6->ip6_dst.s6_addr16[1]);
			}
		}
		
		if (key_checkrequest(isr, &saidx, &sav) == ENOENT) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			IPSEC_STAT_INCREMENT(ipsec6stat.out_nosa);
			error = ENOENT;
			
			/*
			 * Notify the fact that the packet is discarded
			 * to ourselves. I believe this is better than
			 * just silently discarding. (jinmei@kame.net)
			 * XXX: should we restrict the error to TCP packets?
			 * XXX: should we directly notify sockets via
			 *      pfctlinputs?
			 */
			icmp6_error(state->m, ICMP6_DST_UNREACH,
						ICMP6_DST_UNREACH_ADMIN, 0);
			state->m = NULL; /* icmp6_error freed the mbuf */
			goto bad;
		}
		
		/* validity check */
		if (sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
				case IPSEC_LEVEL_USE:
					continue;
				case IPSEC_LEVEL_REQUIRE:
					/* must be not reached here. */
					panic("ipsec6_output_trans: no SA found, but required.");
			}
		}
		
		if ((error = ipsec6_output_trans_internal(state, sav, nexthdrp, mprev)) != 0) {
			goto bad;
		}
	}
	
	/* if we have more to go, we need a tunnel mode processing */
	if (isr != NULL)
		*tun = 1;
	
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	return 0;
	
bad:
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	m_freem(state->m);
	state->m = NULL;
	return error;
}

/*
 * IPsec output logic for IPv6, tunnel mode.
 */
static int
ipsec6_output_tunnel_internal(struct ipsec_output_state *state, struct secasvar *sav, int *must_be_last)
{
	struct ip6_hdr *ip6;
	int error = 0;
	int plen;
	struct sockaddr_in6* dst6;
	struct route *ro6;
	
	/* validity check */
	if (sav == NULL || sav->sah == NULL || sav->sah->saidx.mode != IPSEC_MODE_TUNNEL) {
		error = EINVAL;
		goto bad;
	}
		
	/*
	 * If there is no valid SA, we give up to process.
	 * see same place at ipsec4_output().
	 */
	if (sav->state != SADB_SASTATE_MATURE
		&& sav->state != SADB_SASTATE_DYING) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_nosa);
		error = EINVAL;
		goto bad;
	}
	
	state->outgoing_if = sav->sah->outgoing_if;
	
	if (sav->sah->saidx.mode == IPSEC_MODE_TUNNEL) {
		/*
		 * build IPsec tunnel.
		 */
		state->m = ipsec6_splithdr(state->m);
		if (!state->m) {
			IPSEC_STAT_INCREMENT(ipsec6stat.out_nomem);
			error = ENOMEM;
			goto bad;
		}
		
		if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family == AF_INET6) {
			error = ipsec6_encapsulate(state->m, sav);
			if (error) {
				state->m = 0;
				goto bad;
			}
			ip6 = mtod(state->m, struct ip6_hdr *);
		} else if (((struct sockaddr *)&sav->sah->saidx.src)->sa_family == AF_INET) {
			
			struct ip *ip;
			struct sockaddr_in* dst4;
			struct route *ro4 = NULL;
			struct route  ro4_copy;
			struct ip_out_args ipoa = { IFSCOPE_NONE, { 0 },
				IPOAF_SELECT_SRCIF, 0 };
			
			if (must_be_last)
				*must_be_last = 1;

			state->tunneled = 4; /* must not process any further in ip6_output */
			error = ipsec64_encapsulate(state->m, sav);
			if (error) {
				state->m = 0;
				goto bad;
			}
			/* Now we have an IPv4 packet */
			ip = mtod(state->m, struct ip *);
			
			// grab sadb_mutex, to update sah's route cache and get a local copy of it
			lck_mtx_lock(sadb_mutex);
			ro4 = &sav->sah->sa_route;
			dst4 = (struct sockaddr_in *)(void *)&ro4->ro_dst;
			if (ro4->ro_rt) {
				RT_LOCK(ro4->ro_rt);
			}
			if (ROUTE_UNUSABLE(ro4) ||
				dst4->sin_addr.s_addr != ip->ip_dst.s_addr) {
				if (ro4->ro_rt != NULL)
					RT_UNLOCK(ro4->ro_rt);
				ROUTE_RELEASE(ro4);
			}
			if (ro4->ro_rt == NULL) {
				dst4->sin_family = AF_INET;
				dst4->sin_len = sizeof(*dst4);
				dst4->sin_addr = ip->ip_dst;
			} else {
				RT_UNLOCK(ro4->ro_rt);
			}
			route_copyout(&ro4_copy, ro4, sizeof(ro4_copy));
			// release sadb_mutex, after updating sah's route cache and getting a local copy
			lck_mtx_unlock(sadb_mutex);
			state->m = ipsec4_splithdr(state->m);
			if (!state->m) {
				error = ENOMEM;
				ROUTE_RELEASE(&ro4_copy);
				goto bad;
			}
			switch (sav->sah->saidx.proto) {
				case IPPROTO_ESP:
#if IPSEC_ESP
					if ((error = esp4_output(state->m, sav)) != 0) {
						state->m = NULL;
						ROUTE_RELEASE(&ro4_copy);
						goto bad;
					}
					break;
					
#else
					m_freem(state->m);
					state->m = NULL;
					error = EINVAL;
					ROUTE_RELEASE(&ro4_copy);
					goto bad;
#endif
				case IPPROTO_AH:
					if ((error = ah4_output(state->m, sav)) != 0) {
						state->m = NULL;
						ROUTE_RELEASE(&ro4_copy);
						goto bad;
					}
					break;
				case IPPROTO_IPCOMP:
					if ((error = ipcomp4_output(state->m, sav)) != 0) {
						state->m = NULL;
						ROUTE_RELEASE(&ro4_copy);
						goto bad;
					}
					break;
				default:
					ipseclog((LOG_ERR,
							  "ipsec4_output: unknown ipsec protocol %d\n",
							  sav->sah->saidx.proto));
					m_freem(state->m);
					state->m = NULL;
					error = EINVAL;
					ROUTE_RELEASE(&ro4_copy);
					goto bad;
			}
			
			if (state->m == 0) {
				error = ENOMEM;
				ROUTE_RELEASE(&ro4_copy);
				goto bad;
			}
			ipsec_set_pkthdr_for_interface(sav->sah->ipsec_if, state->m, AF_INET);
			ip = mtod(state->m, struct ip *);
			ip->ip_len = ntohs(ip->ip_len);  /* flip len field before calling ip_output */
			error = ip_output(state->m, NULL, &ro4_copy, IP_OUTARGS, NULL, &ipoa);
			state->m = NULL;
			// grab sadb_mutex, to synchronize the sah's route cache with the local copy
			lck_mtx_lock(sadb_mutex);
			route_copyin(&ro4_copy, ro4, sizeof(ro4_copy));
			lck_mtx_unlock(sadb_mutex);
			if (error != 0)
				goto bad;
			goto done;
		} else {
			ipseclog((LOG_ERR, "ipsec6_output_tunnel: "
					  "unsupported inner family, spi=%u\n",
					  (u_int32_t)ntohl(sav->spi)));
			IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
			error = EAFNOSUPPORT;
			goto bad;
		}
		
		// grab sadb_mutex, before updating sah's route cache
		lck_mtx_lock(sadb_mutex);
		ro6 = &sav->sah->sa_route;
		dst6 = (struct sockaddr_in6 *)(void *)&ro6->ro_dst;
		if (ro6->ro_rt) {
			RT_LOCK(ro6->ro_rt);
		}
		if (ROUTE_UNUSABLE(ro6) ||
			!IN6_ARE_ADDR_EQUAL(&dst6->sin6_addr, &ip6->ip6_dst)) {
			if (ro6->ro_rt != NULL)
				RT_UNLOCK(ro6->ro_rt);
			ROUTE_RELEASE(ro6);
		}
		if (ro6->ro_rt == 0) {
			bzero(dst6, sizeof(*dst6));
			dst6->sin6_family = AF_INET6;
			dst6->sin6_len = sizeof(*dst6);
			dst6->sin6_addr = ip6->ip6_dst;
			rtalloc(ro6);
			if (ro6->ro_rt) {
				RT_LOCK(ro6->ro_rt);
			}
		}
		if (ro6->ro_rt == 0) {
			ip6stat.ip6s_noroute++;
			IPSEC_STAT_INCREMENT(ipsec6stat.out_noroute);
			error = EHOSTUNREACH;
			// release sadb_mutex, after updating sah's route cache
			lck_mtx_unlock(sadb_mutex);
			goto bad;
		}
		
		/*
		 * adjust state->dst if tunnel endpoint is offlink
		 *
		 * XXX: caching rt_gateway value in the state is
		 * not really good, since it may point elsewhere
		 * when the gateway gets modified to a larger
		 * sockaddr via rt_setgate().  This is currently
		 * addressed by SA_SIZE roundup in that routine.
		 */
		if (ro6->ro_rt->rt_flags & RTF_GATEWAY)
			dst6 = (struct sockaddr_in6 *)(void *)ro6->ro_rt->rt_gateway;
		RT_UNLOCK(ro6->ro_rt);
		ROUTE_RELEASE(&state->ro);
		route_copyout(&state->ro, ro6, sizeof(state->ro));
		state->dst = (struct sockaddr *)dst6;
		state->tunneled = 6;
		// release sadb_mutex, after updating sah's route cache
		lck_mtx_unlock(sadb_mutex);
	}
	
	state->m = ipsec6_splithdr(state->m);
	if (!state->m) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_nomem);
		error = ENOMEM;
		goto bad;
	}
	ip6 = mtod(state->m, struct ip6_hdr *);
	switch (sav->sah->saidx.proto) {
		case IPPROTO_ESP:
#if IPSEC_ESP
			error = esp6_output(state->m, &ip6->ip6_nxt, state->m->m_next, sav);
#else
			m_freem(state->m);
			error = EINVAL;
#endif
			break;
		case IPPROTO_AH:
			error = ah6_output(state->m, &ip6->ip6_nxt, state->m->m_next, sav);
			break;
		case IPPROTO_IPCOMP:
			/* XXX code should be here */
			/*FALLTHROUGH*/
		default:
			ipseclog((LOG_ERR, "ipsec6_output_tunnel: "
					  "unknown ipsec protocol %d\n", sav->sah->saidx.proto));
			m_freem(state->m);
			IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
			error = EINVAL;
			break;
	}
	if (error) {
		state->m = NULL;
		goto bad;
	}
	plen = state->m->m_pkthdr.len - sizeof(struct ip6_hdr);
	if (plen > IPV6_MAXPACKET) {
		ipseclog((LOG_ERR, "ipsec6_output_tunnel: "
				  "IPsec with IPv6 jumbogram is not supported\n"));
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		error = EINVAL;	/*XXX*/
		goto bad;
	}
	ip6 = mtod(state->m, struct ip6_hdr *);
	ip6->ip6_plen = htons(plen);
done:
	return 0;
	
bad:
	return error;
}

int
ipsec6_output_tunnel(
	struct ipsec_output_state *state,
	struct secpolicy *sp,
	__unused int flags)
{
	struct ip6_hdr *ip6;
	struct ipsecrequest *isr = NULL;
	struct secasindex saidx;
	struct secasvar *sav = NULL;
	int error = 0;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (!state)
		panic("state == NULL in ipsec6_output_tunnel");
	if (!state->m)
		panic("state->m == NULL in ipsec6_output_tunnel");
	if (!sp)
		panic("sp == NULL in ipsec6_output_tunnel");

	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("ipsec6_output_tunnel: applyed SP\n");
		kdebug_secpolicy(sp));

	/*
	 * transport mode ipsec (before the 1st tunnel mode) is already
	 * processed by ipsec6_output_trans().
	 */
	for (isr = sp->req; isr; isr = isr->next) {
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL)
			break;
	}

	for (/* already initialized */; isr; isr = isr->next) {
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/* When tunnel mode, SA peers must be specified. */
			bcopy(&isr->saidx, &saidx, sizeof(saidx));
		} else {
			/* make SA index to look for a proper SA */
			struct sockaddr_in6 *sin6;

			bzero(&saidx, sizeof(saidx));
			saidx.proto = isr->saidx.proto;
			saidx.mode = isr->saidx.mode;
			saidx.reqid = isr->saidx.reqid;

			ip6 = mtod(state->m, struct ip6_hdr *);
			sin6 = (struct sockaddr_in6 *)&saidx.src;
			if (sin6->sin6_len == 0) {
				sin6->sin6_len = sizeof(*sin6);
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = IPSEC_PORT_ANY;
				bcopy(&ip6->ip6_src, &sin6->sin6_addr,
				    sizeof(ip6->ip6_src));
				if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
					/* fix scope id for comparing SPD */
					sin6->sin6_addr.s6_addr16[1] = 0;
					sin6->sin6_scope_id = ntohs(ip6->ip6_src.s6_addr16[1]);
				}
			}
			sin6 = (struct sockaddr_in6 *)&saidx.dst;
			if (sin6->sin6_len == 0) {
				sin6->sin6_len = sizeof(*sin6);
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = IPSEC_PORT_ANY;
				bcopy(&ip6->ip6_dst, &sin6->sin6_addr,
				    sizeof(ip6->ip6_dst));
				if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
					/* fix scope id for comparing SPD */
					sin6->sin6_addr.s6_addr16[1] = 0;
					sin6->sin6_scope_id = ntohs(ip6->ip6_dst.s6_addr16[1]);
				}
			}
		}

		if (key_checkrequest(isr, &saidx, &sav) == ENOENT) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
			IPSEC_STAT_INCREMENT(ipsec6stat.out_nosa);
			error = ENOENT;
			goto bad;
		}

		/* validity check */
		if (sav == NULL) {
			switch (ipsec_get_reqlevel(isr)) {
			case IPSEC_LEVEL_USE:
				continue;
			case IPSEC_LEVEL_REQUIRE:
				/* must be not reached here. */
				panic("ipsec6_output_tunnel: no SA found, but required.");
			}
		}

		/*
		 * If there is no valid SA, we give up to process.
		 * see same place at ipsec4_output().
		 */
		if (sav->state != SADB_SASTATE_MATURE
		 && sav->state != SADB_SASTATE_DYING) {
			IPSEC_STAT_INCREMENT(ipsec6stat.out_nosa);
			error = EINVAL;
			goto bad;
		}
		
		int must_be_last = 0;
		
		if ((error = ipsec6_output_tunnel_internal(state, sav, &must_be_last)) != 0) {
			goto bad;
		}
		
		if (must_be_last && isr->next) {
			ipseclog((LOG_ERR, "ipsec6_output_tunnel: "
					  "IPv4 must be outer layer, spi=%u\n",
					  (u_int32_t)ntohl(sav->spi)));
			error = EINVAL;
			goto bad;
		}
	}

	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	return 0;

bad:
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	if (state->m)
		m_freem(state->m);
	state->m = NULL;
	return error;
}

int
ipsec6_interface_output(struct ipsec_output_state *state, ifnet_t interface, u_char *nexthdrp, struct mbuf *mprev)
{
	int error = 0;
	struct secasvar *sav = NULL;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (!state)
		panic("state == NULL in ipsec6_output");
	if (!state->m)
		panic("state->m == NULL in ipsec6_output");
	if (!nexthdrp)
		panic("nexthdrp == NULL in ipsec6_output");
	if (!mprev)
		panic("mprev == NULL in ipsec6_output");
	
	sav = key_alloc_outbound_sav_for_interface(interface, AF_INET6);
	if (sav == NULL) {
		goto bad;
	}
	
	if (sav->sah && sav->sah->saidx.mode == IPSEC_MODE_TUNNEL) {
		if ((error = ipsec6_output_tunnel_internal(state, sav, NULL)) != 0) {
			goto bad;
		}
	}
	else {
		if ((error = ipsec6_output_trans_internal(state, sav, nexthdrp, mprev)) != 0) {
			goto bad;
		}
	}
	
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	return 0;
	
bad:
	if (sav)
		key_freesav(sav, KEY_SADB_UNLOCKED);
	m_freem(state->m);
	state->m = NULL;
	return error;
}
#endif /*INET6*/

#if INET
/*
 * Chop IP header and option off from the payload.
 */
struct mbuf *
ipsec4_splithdr(m)
	struct mbuf *m;
{
	struct mbuf *mh;
	struct ip *ip;
	int hlen;

	if (m->m_len < sizeof(struct ip))
		panic("ipsec4_splithdr: first mbuf too short, m_len %d, pkt_len %d, m_flag %x", m->m_len, m->m_pkthdr.len, m->m_flags);
	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif
	if (m->m_len > hlen) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (!mh) {
			m_freem(m);
			return NULL;
		}
		M_COPY_PKTHDR(mh, m);
		MH_ALIGN(mh, hlen);
		m->m_flags &= ~M_PKTHDR;
		m_mchtype(m, MT_DATA);
		m->m_len -= hlen;
		m->m_data += hlen;
		mh->m_next = m;
		m = mh;
		m->m_len = hlen;
		bcopy((caddr_t)ip, mtod(m, caddr_t), hlen);
	} else if (m->m_len < hlen) {
		m = m_pullup(m, hlen);
		if (!m)
			return NULL;
	}
	return m;
}
#endif

#if INET6
struct mbuf *
ipsec6_splithdr(m)
	struct mbuf *m;
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;
	int hlen;

	if (m->m_len < sizeof(struct ip6_hdr))
		panic("ipsec6_splithdr: first mbuf too short");
	ip6 = mtod(m, struct ip6_hdr *);
	hlen = sizeof(struct ip6_hdr);
	if (m->m_len > hlen) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (!mh) {
			m_freem(m);
			return NULL;
		}
		M_COPY_PKTHDR(mh, m);
		MH_ALIGN(mh, hlen);
		m->m_flags &= ~M_PKTHDR;
		m_mchtype(m, MT_DATA);
		m->m_len -= hlen;
		m->m_data += hlen;
		mh->m_next = m;
		m = mh;
		m->m_len = hlen;
		bcopy((caddr_t)ip6, mtod(m, caddr_t), hlen);
	} else if (m->m_len < hlen) {
		m = m_pullup(m, hlen);
		if (!m)
			return NULL;
	}
	return m;
}
#endif

/* validate inbound IPsec tunnel packet. */
int
ipsec4_tunnel_validate(m, off, nxt0, sav, ifamily)
	struct mbuf *m;		/* no pullup permitted, m->m_len >= ip */
	int off;
	u_int nxt0;
	struct secasvar *sav;
	sa_family_t *ifamily;
{
	u_int8_t nxt = nxt0 & 0xff;
	struct sockaddr_in *sin;
	struct sockaddr_in osrc, odst, i4src, i4dst;
	struct sockaddr_in6 i6src, i6dst;
	int hlen;
	struct secpolicy *sp;
	struct ip *oip;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

#if DIAGNOSTIC
	if (m->m_len < sizeof(struct ip))
		panic("too short mbuf on ipsec4_tunnel_validate");
#endif
	if (nxt != IPPROTO_IPV4 && nxt != IPPROTO_IPV6)
		return 0;
	if (m->m_pkthdr.len < off + sizeof(struct ip))
		return 0;
	/* do not decapsulate if the SA is for transport mode only */
	if (sav->sah->saidx.mode == IPSEC_MODE_TRANSPORT)
		return 0;

	oip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = _IP_VHL_HL(oip->ip_vhl) << 2;
#else
	hlen = oip->ip_hl << 2;
#endif
	if (hlen != sizeof(struct ip))
		return 0;

	sin = (struct sockaddr_in *)&sav->sah->saidx.dst;
	if (sin->sin_family != AF_INET)
		return 0;
	if (bcmp(&oip->ip_dst, &sin->sin_addr, sizeof(oip->ip_dst)) != 0)
		return 0;

	if (sav->utun_in_fn ||
		sav->sah->ipsec_if != NULL) {
		// the ipsec/utun interface SAs don't have a policies.
		if (nxt == IPPROTO_IPV4) {
			*ifamily = AF_INET;
		} else if (nxt == IPPROTO_IPV6) {
			*ifamily = AF_INET6;
		} else {
			return 0;
		}
		return 1;
	}

	/* XXX slow */
	bzero(&osrc, sizeof(osrc));
	bzero(&odst, sizeof(odst));
	osrc.sin_family = odst.sin_family = AF_INET;
	osrc.sin_len = odst.sin_len = sizeof(struct sockaddr_in);
	osrc.sin_addr = oip->ip_src;
	odst.sin_addr = oip->ip_dst;
	/*
	 * RFC2401 5.2.1 (b): (assume that we are using tunnel mode)
	 * - if the inner destination is multicast address, there can be
	 *   multiple permissible inner source address.  implementation
	 *   may want to skip verification of inner source address against
	 *   SPD selector.
	 * - if the inner protocol is ICMP, the packet may be an error report
	 *   from routers on the other side of the VPN cloud (R in the
	 *   following diagram).  in this case, we cannot verify inner source
	 *   address against SPD selector.
	 *	me -- gw === gw -- R -- you
	 *
	 * we consider the first bullet to be users responsibility on SPD entry
	 * configuration (if you need to encrypt multicast traffic, set
	 * the source range of SPD selector to 0.0.0.0/0, or have explicit
	 * address ranges for possible senders).
	 * the second bullet is not taken care of (yet).
	 *
	 * therefore, we do not do anything special about inner source.
	 */
	if (nxt == IPPROTO_IPV4) {
		bzero(&i4src, sizeof(struct sockaddr_in));
		bzero(&i4dst, sizeof(struct sockaddr_in));
		i4src.sin_family = i4dst.sin_family = *ifamily = AF_INET;
		i4src.sin_len = i4dst.sin_len = sizeof(struct sockaddr_in);
		m_copydata(m, off + offsetof(struct ip, ip_src), sizeof(i4src.sin_addr),
			   (caddr_t)&i4src.sin_addr);
		m_copydata(m, off + offsetof(struct ip, ip_dst), sizeof(i4dst.sin_addr),
			   (caddr_t)&i4dst.sin_addr);
		sp = key_gettunnel((struct sockaddr *)&osrc, (struct sockaddr *)&odst,
				   (struct sockaddr *)&i4src, (struct sockaddr *)&i4dst);
	} else if (nxt == IPPROTO_IPV6) {
		bzero(&i6src, sizeof(struct sockaddr_in6));
		bzero(&i6dst, sizeof(struct sockaddr_in6));
		i6src.sin6_family = i6dst.sin6_family = *ifamily = AF_INET6;
		i6src.sin6_len = i6dst.sin6_len = sizeof(struct sockaddr_in6);
		m_copydata(m, off + offsetof(struct ip6_hdr, ip6_src), sizeof(i6src.sin6_addr),
			   (caddr_t)&i6src.sin6_addr);
		m_copydata(m, off + offsetof(struct ip6_hdr, ip6_dst), sizeof(i6dst.sin6_addr),
			   (caddr_t)&i6dst.sin6_addr);
		sp = key_gettunnel((struct sockaddr *)&osrc, (struct sockaddr *)&odst,
				   (struct sockaddr *)&i6src, (struct sockaddr *)&i6dst);
	} else 
		return 0;	/* unsupported family */

	if (!sp) 
		return 0;

	key_freesp(sp, KEY_SADB_UNLOCKED);

	return 1;
}

#if INET6
/* validate inbound IPsec tunnel packet. */
int
ipsec6_tunnel_validate(m, off, nxt0, sav, ifamily)
	struct mbuf *m;		/* no pullup permitted, m->m_len >= ip */
	int off;
	u_int nxt0;
	struct secasvar *sav;
	sa_family_t *ifamily;
{
	u_int8_t nxt = nxt0 & 0xff;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in i4src, i4dst;
	struct sockaddr_in6 osrc, odst, i6src, i6dst;
	struct secpolicy *sp;
	struct ip6_hdr *oip6;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
#if DIAGNOSTIC
	if (m->m_len < sizeof(struct ip6_hdr))
		panic("too short mbuf on ipsec6_tunnel_validate");
#endif
	if (nxt != IPPROTO_IPV4 && nxt != IPPROTO_IPV6)
		return 0;

	if (m->m_pkthdr.len < off + sizeof(struct ip6_hdr))
		return 0;
	/* do not decapsulate if the SA is for transport mode only */
	if (sav->sah->saidx.mode == IPSEC_MODE_TRANSPORT)
		return 0;

	oip6 = mtod(m, struct ip6_hdr *);
	/* AF_INET should be supported, but at this moment we don't. */
	sin6 = (struct sockaddr_in6 *)&sav->sah->saidx.dst;
	if (sin6->sin6_family != AF_INET6)
		return 0;
	if (!IN6_ARE_ADDR_EQUAL(&oip6->ip6_dst, &sin6->sin6_addr))
		return 0;

	if (sav->utun_in_fn ||
		sav->sah->ipsec_if != NULL) {
		// the ipsec/utun interface SAs don't have a policies.
		if (nxt == IPPROTO_IPV4) {
			*ifamily = AF_INET;
		} else if (nxt == IPPROTO_IPV6) {
			*ifamily = AF_INET6;
		} else {
			return 0;
		}
		return 1;
	}
	
	/* XXX slow */
	bzero(&osrc, sizeof(osrc));
	bzero(&odst, sizeof(odst));
	osrc.sin6_family = odst.sin6_family = AF_INET6;
	osrc.sin6_len = odst.sin6_len = sizeof(struct sockaddr_in6);
	osrc.sin6_addr = oip6->ip6_src;
	odst.sin6_addr = oip6->ip6_dst;

	/*
	 * regarding to inner source address validation, see a long comment
	 * in ipsec4_tunnel_validate.
	 */

	if (nxt == IPPROTO_IPV4) {
		bzero(&i4src, sizeof(struct sockaddr_in));
		bzero(&i4dst, sizeof(struct sockaddr_in));
		i4src.sin_family = i4dst.sin_family = *ifamily = AF_INET;
		i4src.sin_len = i4dst.sin_len = sizeof(struct sockaddr_in);
		m_copydata(m, off + offsetof(struct ip, ip_src), sizeof(i4src.sin_addr),
				   (caddr_t)&i4src.sin_addr);
		m_copydata(m, off + offsetof(struct ip, ip_dst), sizeof(i4dst.sin_addr),
				   (caddr_t)&i4dst.sin_addr);
		sp = key_gettunnel((struct sockaddr *)&osrc, (struct sockaddr *)&odst,
						   (struct sockaddr *)&i4src, (struct sockaddr *)&i4dst);
	} else if (nxt == IPPROTO_IPV6) {
		bzero(&i6src, sizeof(struct sockaddr_in6));
		bzero(&i6dst, sizeof(struct sockaddr_in6));
		i6src.sin6_family = i6dst.sin6_family = *ifamily = AF_INET6;
		i6src.sin6_len = i6dst.sin6_len = sizeof(struct sockaddr_in6);
		m_copydata(m, off + offsetof(struct ip6_hdr, ip6_src), sizeof(i6src.sin6_addr),
				   (caddr_t)&i6src.sin6_addr);
		m_copydata(m, off + offsetof(struct ip6_hdr, ip6_dst), sizeof(i6dst.sin6_addr),
				   (caddr_t)&i6dst.sin6_addr);
		sp = key_gettunnel((struct sockaddr *)&osrc, (struct sockaddr *)&odst,
						   (struct sockaddr *)&i6src, (struct sockaddr *)&i6dst);
	} else
		return 0;	/* unsupported family */
	/*
	 * when there is no suitable inbound policy for the packet of the ipsec
	 * tunnel mode, the kernel never decapsulate the tunneled packet
	 * as the ipsec tunnel mode even when the system wide policy is "none".
	 * then the kernel leaves the generic tunnel module to process this
	 * packet.  if there is no rule of the generic tunnel, the packet
	 * is rejected and the statistics will be counted up.
	 */
	if (!sp)
		return 0;
	key_freesp(sp, KEY_SADB_UNLOCKED);

	return 1;
}
#endif

/*
 * Make a mbuf chain for encryption.
 * If the original mbuf chain contains a mbuf with a cluster,
 * allocate a new cluster and copy the data to the new cluster.
 * XXX: this hack is inefficient, but is necessary to handle cases
 * of TCP retransmission...
 */
struct mbuf *
ipsec_copypkt(m)
	struct mbuf *m;
{
	struct mbuf *n, **mpp, *mnew;

	for (n = m, mpp = &m; n; n = n->m_next) {
		if (n->m_flags & M_EXT) {
			/*
			 * Make a copy only if there are more than one references
			 * to the cluster.
			 * XXX: is this approach effective?
			 */
			if (
				n->m_ext.ext_free ||
				m_mclhasreference(n)
			    )
			{
				int remain, copied;
				struct mbuf *mm;

				if (n->m_flags & M_PKTHDR) {
					MGETHDR(mnew, M_DONTWAIT, MT_HEADER); /* MAC-OK */
					if (mnew == NULL)
						goto fail;
					M_COPY_PKTHDR(mnew, n);
				}
				else {
					MGET(mnew, M_DONTWAIT, MT_DATA);
					if (mnew == NULL)
						goto fail;
				}
				mnew->m_len = 0;
				mm = mnew;

				/*
				 * Copy data. If we don't have enough space to
				 * store the whole data, allocate a cluster
				 * or additional mbufs.
				 * XXX: we don't use m_copyback(), since the
				 * function does not use clusters and thus is
				 * inefficient.
				 */
				remain = n->m_len;
				copied = 0;
				while (1) {
					int len;
					struct mbuf *mn;

					if (remain <= (mm->m_flags & M_PKTHDR ? MHLEN : MLEN))
						len = remain;
					else { /* allocate a cluster */
						MCLGET(mm, M_DONTWAIT);
						if (!(mm->m_flags & M_EXT)) {
							m_free(mm);
							goto fail;
						}
						len = remain < MCLBYTES ?
							remain : MCLBYTES;
					}

					bcopy(n->m_data + copied, mm->m_data,
					      len);

					copied += len;
					remain -= len;
					mm->m_len = len;

					if (remain <= 0) /* completed? */
						break;

					/* need another mbuf */
					MGETHDR(mn, M_DONTWAIT, MT_HEADER);	/* XXXMAC: tags copied next time in loop? */
					if (mn == NULL)
						goto fail;
					mn->m_pkthdr.rcvif = NULL;
					mm->m_next = mn;
					mm = mn;
				}

				/* adjust chain */
				mm->m_next = m_free(n);
				n = mm;
				*mpp = mnew;
				mpp = &n->m_next;

				continue;
			}
		}
		*mpp = n;
		mpp = &n->m_next;
	}

	return(m);
  fail:
	m_freem(m);
	return(NULL);
}

/*
 * Tags are allocated as mbufs for now, since our minimum size is MLEN, we
 * should make use of up to that much space.
 */
#define	IPSEC_TAG_HEADER \

struct ipsec_tag {
	struct socket			*socket;
	u_int32_t				history_count;
	struct ipsec_history	history[];
};

#define	IPSEC_TAG_SIZE		(MLEN - sizeof(struct m_tag))
#define	IPSEC_TAG_HDR_SIZE	(offsetof(struct ipsec_tag, history[0]))
#define IPSEC_HISTORY_MAX	((IPSEC_TAG_SIZE - IPSEC_TAG_HDR_SIZE) / \
							 sizeof(struct ipsec_history))

static struct ipsec_tag *
ipsec_addaux(
	struct mbuf *m)
{
	struct m_tag		*tag;
	
	/* Check if the tag already exists */
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPSEC, NULL);
	
	if (tag == NULL) {
		struct ipsec_tag	*itag;
		
		/* Allocate a tag */
		tag = m_tag_create(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPSEC,
						  IPSEC_TAG_SIZE, M_DONTWAIT, m);
		
		if (tag) {
			itag = (struct ipsec_tag*)(tag + 1);
			itag->socket = 0;
			itag->history_count = 0;
			
			m_tag_prepend(m, tag);
		}
	}
	
	return tag ? (struct ipsec_tag*)(tag + 1) : NULL;
}

static struct ipsec_tag *
ipsec_findaux(
	struct mbuf *m)
{
	struct m_tag	*tag;
	
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPSEC, NULL);
	
	return tag ? (struct ipsec_tag*)(tag + 1) : NULL;
}

void
ipsec_delaux(
	struct mbuf *m)
{
	struct m_tag	*tag;
	
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPSEC, NULL);
	
	if (tag) {
		m_tag_delete(m, tag);
	}
}

/* if the aux buffer is unnecessary, nuke it. */
static void
ipsec_optaux(
	struct mbuf			*m,
	struct ipsec_tag	*itag)
{
	if (itag && itag->socket == NULL && itag->history_count == 0) {
		m_tag_delete(m, ((struct m_tag*)itag) - 1);
	}
}

int
ipsec_setsocket(struct mbuf *m, struct socket *so)
{
	struct ipsec_tag	*tag;
	
	/* if so == NULL, don't insist on getting the aux mbuf */
	if (so) {
		tag = ipsec_addaux(m);
		if (!tag)
			return ENOBUFS;
	} else
		tag = ipsec_findaux(m);
	if (tag) {
		tag->socket = so;
		ipsec_optaux(m, tag);
	}
	return 0;
}

struct socket *
ipsec_getsocket(struct mbuf *m)
{
	struct ipsec_tag	*itag;
	
	itag = ipsec_findaux(m);
	if (itag)
		return itag->socket;
	else
		return NULL;
}

int
ipsec_addhist(
	struct mbuf *m,
	int proto,
	u_int32_t spi)
{
	struct ipsec_tag		*itag;
	struct ipsec_history	*p;
	itag = ipsec_addaux(m);
	if (!itag)
		return ENOBUFS;
	if (itag->history_count == IPSEC_HISTORY_MAX)
		return ENOSPC;	/* XXX */
	
	p = &itag->history[itag->history_count];
	itag->history_count++;
	
	bzero(p, sizeof(*p));
	p->ih_proto = proto;
	p->ih_spi = spi;
	
	return 0;
}

struct ipsec_history *
ipsec_gethist(
	struct mbuf *m,
	int *lenp)
{
	struct ipsec_tag	*itag;
	
	itag = ipsec_findaux(m);
	if (!itag)
		return NULL;
	if (itag->history_count == 0)
		return NULL;
	if (lenp)
		*lenp = (int)(itag->history_count * sizeof(struct ipsec_history));
	return itag->history;
}

void
ipsec_clearhist(
	struct mbuf *m)
{
	struct ipsec_tag	*itag;
	
	itag = ipsec_findaux(m);
	if (itag) {
		itag->history_count = 0;
	}
	ipsec_optaux(m, itag);
}

__private_extern__ int
ipsec_send_natt_keepalive(
	struct secasvar *sav)
{
	struct mbuf	       *m;
	struct ip          *ip;
	int                 error;
	struct ip_out_args  ipoa =
	    { IFSCOPE_NONE, { 0 }, IPOAF_SELECT_SRCIF, 0 };
	struct route        ro;
	int keepalive_interval = natt_keepalive_interval;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

	if ((esp_udp_encap_port & 0xFFFF) == 0 || sav->remote_ike_port == 0) return FALSE;

	if (sav->natt_interval != 0) {
		keepalive_interval = (int)sav->natt_interval;
	}
	
	// natt timestamp may have changed... reverify
	if ((natt_now - sav->natt_last_activity) < keepalive_interval) return FALSE;

	if (sav->flags & SADB_X_EXT_ESP_KEEPALIVE) return FALSE; // don't send these from the kernel

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL) return FALSE;

	ip = (__typeof__(ip))m_mtod(m);

	// this sends one type of NATT keepalives (Type 1, ESP keepalives, aren't sent by kernel)
	if ((sav->flags & SADB_X_EXT_ESP_KEEPALIVE) == 0) {
		struct udphdr      *uh;
		
		/*
		 * Type 2: a UDP packet complete with IP header.
		 * We must do this because UDP output requires
		 * an inpcb which we don't have. UDP packet
		 * contains one byte payload. The byte is set
		 * to 0xFF.
		 */
		uh = (__typeof__(uh))(void *)((char *)m_mtod(m) + sizeof(*ip));
		m->m_len = sizeof(struct udpiphdr) + 1;
		bzero(m_mtod(m), m->m_len);
		m->m_pkthdr.len = m->m_len;

		ip->ip_len = m->m_len;
		ip->ip_ttl = ip_defttl;
		ip->ip_p = IPPROTO_UDP;
		if (sav->sah->dir != IPSEC_DIR_INBOUND) {
			ip->ip_src = ((struct sockaddr_in*)&sav->sah->saidx.src)->sin_addr;
			ip->ip_dst = ((struct sockaddr_in*)&sav->sah->saidx.dst)->sin_addr;
		} else {
			ip->ip_src = ((struct sockaddr_in*)&sav->sah->saidx.dst)->sin_addr;
			ip->ip_dst = ((struct sockaddr_in*)&sav->sah->saidx.src)->sin_addr;
		}
		uh->uh_sport = htons((u_short)esp_udp_encap_port);
		uh->uh_dport = htons(sav->remote_ike_port);
		uh->uh_ulen = htons(1 + sizeof(*uh));
		uh->uh_sum = 0;
		*(u_int8_t*)((char*)m_mtod(m) + sizeof(*ip) + sizeof(*uh)) = 0xFF;
	}

	// grab sadb_mutex, to get a local copy of sah's route cache
	lck_mtx_lock(sadb_mutex);
	if (ROUTE_UNUSABLE(&sav->sah->sa_route) ||
	    rt_key(sav->sah->sa_route.ro_rt)->sa_family != AF_INET)
		ROUTE_RELEASE(&sav->sah->sa_route);

	route_copyout(&ro, &sav->sah->sa_route, sizeof(ro));
	lck_mtx_unlock(sadb_mutex);
	
	necp_mark_packet_as_keepalive(m, TRUE);

	error = ip_output(m, NULL, &ro, IP_OUTARGS | IP_NOIPSEC, NULL, &ipoa);

	// grab sadb_mutex, to synchronize the sah's route cache with the local copy
	lck_mtx_lock(sadb_mutex);
	route_copyin(&ro, &sav->sah->sa_route, sizeof(ro));
	lck_mtx_unlock(sadb_mutex);
	if (error == 0) {
		sav->natt_last_activity = natt_now;
		return TRUE;
	}
	return FALSE;
}

__private_extern__ bool
ipsec_fill_offload_frame(ifnet_t ifp,
						 struct secasvar *sav,
						 struct ifnet_keepalive_offload_frame *frame,
						 size_t frame_data_offset)
{
	u_int8_t *data = NULL;
	struct ip *ip = NULL;
	struct udphdr *uh = NULL;

	if (sav == NULL || sav->sah == NULL || frame == NULL ||
		(ifp != NULL && ifp->if_index != sav->sah->outgoing_if) ||
		sav->sah->saidx.dst.ss_family != AF_INET ||
		!(sav->flags & SADB_X_EXT_NATT) ||
		!(sav->flags & SADB_X_EXT_NATT_KEEPALIVE) ||
		!(sav->flags & SADB_X_EXT_NATT_KEEPALIVE_OFFLOAD) ||
		sav->flags & SADB_X_EXT_ESP_KEEPALIVE ||
		(esp_udp_encap_port & 0xFFFF) == 0 ||
		sav->remote_ike_port == 0 ||
		(natt_keepalive_interval == 0 && sav->natt_interval == 0 && sav->natt_offload_interval == 0)) {
		/* SA is not eligible for keepalive offload on this interface */
		return (FALSE);
	}

	if (frame_data_offset + sizeof(struct udpiphdr) + 1 >
	    IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
		/* Not enough room in this data frame */
		return (FALSE);
	}
	
	data = frame->data;
	ip = (__typeof__(ip))(void *)(data + frame_data_offset);
	uh = (__typeof__(uh))(void *)(data + frame_data_offset + sizeof(*ip));

	frame->length = frame_data_offset + sizeof(struct udpiphdr) + 1;
	frame->type = IFNET_KEEPALIVE_OFFLOAD_FRAME_IPSEC;
	frame->ether_type = IFNET_KEEPALIVE_OFFLOAD_FRAME_ETHERTYPE_IPV4;

	bzero(data, IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE);

	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_off &= htons(~IP_OFFMASK);
	ip->ip_off &= htons(~IP_MF);
	switch (ip4_ipsec_dfbit) {
		case 0:	/* clear DF bit */
			ip->ip_off &= htons(~IP_DF);
			break;
		case 1:	/* set DF bit */
			ip->ip_off |= htons(IP_DF);
			break;
		default:	/* copy DF bit */
			break;
	}
	ip->ip_len = htons(sizeof(struct udpiphdr) + 1);
	ip->ip_id = ip_randomid();
	ip->ip_ttl = ip_defttl;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0;
	if (sav->sah->dir != IPSEC_DIR_INBOUND) {
		ip->ip_src = ((struct sockaddr_in*)&sav->sah->saidx.src)->sin_addr;
		ip->ip_dst = ((struct sockaddr_in*)&sav->sah->saidx.dst)->sin_addr;
	} else {
		ip->ip_src = ((struct sockaddr_in*)&sav->sah->saidx.dst)->sin_addr;
		ip->ip_dst = ((struct sockaddr_in*)&sav->sah->saidx.src)->sin_addr;
	}
	ip->ip_sum = in_cksum_hdr_opt(ip);
	uh->uh_sport = htons((u_short)esp_udp_encap_port);
	uh->uh_dport = htons(sav->remote_ike_port);
	uh->uh_ulen = htons(1 + sizeof(*uh));
	uh->uh_sum = 0;
	*(u_int8_t*)(data + frame_data_offset + sizeof(*ip) + sizeof(*uh)) = 0xFF;

	if (sav->natt_offload_interval != 0) {
		frame->interval = sav->natt_offload_interval;
	} else if (sav->natt_interval != 0) {
		frame->interval = sav->natt_interval;
	} else {
		frame->interval = natt_keepalive_interval;
	}
	return (TRUE);
}
