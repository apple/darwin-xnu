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
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _NET_IF_VLAN_VAR_H_
#define	_NET_IF_VLAN_VAR_H_	1
#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#ifdef KERNEL
struct	ifvlan {
	struct	arpcom ifv_ac;	/* make this an interface */
	struct	ifnet *ifv_p;	/* parent inteface of this vlan */
	struct	ifv_linkmib {
		int	ifvm_parent;
		u_int16_t ifvm_proto; /* encapsulation ethertype */
		u_int16_t ifvm_tag; /* tag to apply on packets leaving if */
	}	ifv_mib;
};
#define	ifv_if	ifv_ac.ac_if
#define	ifv_tag	ifv_mib.ifvm_tag
#endif /* KERNEL */

struct	ether_vlan_header {
	u_char	evl_dhost[ETHER_ADDR_LEN];
	u_char	evl_shost[ETHER_ADDR_LEN];
	u_int16_t evl_encap_proto;
	u_int16_t evl_tag;
	u_int16_t evl_proto;
};

#define	EVL_VLANOFTAG(tag) ((tag) & 4095)
#define	EVL_PRIOFTAG(tag) (((tag) >> 13) & 7)
#define	EVL_ENCAPLEN	4	/* length in octets of encapsulation */

/* When these sorts of interfaces get their own identifier... */
#define	IFT_8021_VLAN	IFT_PROPVIRTUAL

/* sysctl(3) tags, for compatibility purposes */
#define	VLANCTL_PROTO	1
#define	VLANCTL_MAX	2

/*
 * Configuration structure for SIOCSETVLAN and SIOCGETVLAN ioctls.
 */
struct	vlanreq {
	char	vlr_parent[IFNAMSIZ];
	u_short	vlr_tag;
};
#define	SIOCSETVLAN	SIOCSIFGENERIC
#define	SIOCGETVLAN	SIOCGIFGENERIC

#ifdef KERNEL
/* shared with if_ethersubr.c: */
extern	u_int vlan_proto;
extern	int vlan_input(struct ether_header *eh, struct mbuf *m);
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* _NET_IF_VLAN_VAR_H_ */
