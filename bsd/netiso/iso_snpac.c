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
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)iso_snpac.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */

#include <sys/param.h>
#include <sys/systm.h>

#if ISO
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_snpac.h>
#include <netiso/clnp.h>
#include <netiso/clnp_stat.h>
#include <netiso/esis.h>
#include <netiso/argo_debug.h>

int 				iso_systype = SNPA_ES;	/* default to be an ES */
extern short	esis_holding_time, esis_config_time, esis_esconfig_time;
extern struct	timeval time;
extern void esis_config();
extern int hz;
static void snpac_fixdstandmask();

struct sockaddr_iso blank_siso = {sizeof(blank_siso), AF_ISO};
extern u_long iso_hashchar();
static struct sockaddr_iso
	dst	= {sizeof(dst), AF_ISO},
	gte	= {sizeof(dst), AF_ISO},
	src	= {sizeof(dst), AF_ISO},
	msk	= {sizeof(dst), AF_ISO},
	zmk = {0};
#define zsi blank_siso
#define zero_isoa	zsi.siso_addr
#define zap_isoaddr(a, b) {Bzero(&a.siso_addr, sizeof(*r)); r = b; \
	   Bcopy(r, &a.siso_addr, 1 + (r)->isoa_len);}
#define S(x) ((struct sockaddr *)&(x))

static struct sockaddr_dl blank_dl = {sizeof(blank_dl), AF_LINK};
static struct sockaddr_dl gte_dl;
#define zap_linkaddr(a, b, c, i) \
	(*a = blank_dl, bcopy(b, a->sdl_data, a->sdl_alen = c), a->sdl_index = i)

/*
 *	We only keep track of a single IS at a time.
 */
struct rtentry	*known_is;

/*
 *	Addresses taken from NBS agreements, December 1987.
 *
 *	These addresses assume on-the-wire transmission of least significant
 *	bit first. This is the method used by 802.3. When these
 *	addresses are passed to the token ring driver, (802.5), they
 *	must be bit-swaped because 802.5 transmission order is MSb first.
 *
 *	Furthermore, according to IBM Austin, these addresses are not
 *	true token ring multicast addresses. More work is necessary
 *	to get multicast to work right on token ring.
 *
 *	Currently, the token ring driver does not handle multicast, so
 *	these addresses are converted into the broadcast address in
 *	lan_output() That means that if these multicast addresses change
 *	the token ring driver must be altered.
 */
char all_es_snpa[] = { 0x09, 0x00, 0x2b, 0x00, 0x00, 0x04 };
char all_is_snpa[] = { 0x09, 0x00, 0x2b, 0x00, 0x00, 0x05 };
char all_l1is_snpa[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x14};
char all_l2is_snpa[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x15};

union sockunion {
	struct sockaddr_iso siso;
	struct sockaddr_dl	sdl;
	struct sockaddr		sa;
};

/*
 * FUNCTION:		llc_rtrequest
 *
 * PURPOSE:			Manage routing table entries specific to LLC for ISO.
 *
 * NOTES:			This does a lot of obscure magic;
 */
llc_rtrequest(req, rt, sa)
int req;
register struct rtentry *rt;
struct sockaddr *sa;
{
	register union sockunion *gate = (union sockunion *)rt->rt_gateway;
	register struct llinfo_llc *lc = (struct llinfo_llc *)rt->rt_llinfo, *lc2;
	struct rtentry *rt2;
	struct ifnet *ifp = rt->rt_ifp;
	int addrlen = ifp->if_addrlen;
#define LLC_SIZE 3 /* XXXXXX do this right later */

	IFDEBUG (D_SNPA)
		printf("llc_rtrequest(%d, %x, %x)\n", req, rt, sa);
	ENDDEBUG
	if (rt->rt_flags & RTF_GATEWAY)
		return;
	else switch (req) {
	case RTM_ADD:
		/*
		 * Case 1: This route may come from a route to iface with mask
		 * or from a default route.
		 */
		if (rt->rt_flags & RTF_CLONING) {
			iso_setmcasts(ifp, req);
			rt_setgate(rt, rt_key(rt), &blank_dl);
			return;
		}
		if (lc != 0)
			return; /* happens on a route change */
		/* FALLTHROUGH */
	case RTM_RESOLVE:
		/*
		 * Case 2:  This route may come from cloning, or a manual route
		 * add with a LL address.
		 */
		if (gate->sdl.sdl_family != AF_LINK) {
			log(LOG_DEBUG, "llc_rtrequest: got non-link non-gateway route\n");
			break;
		}
		R_Malloc(lc, struct llinfo_llc *, sizeof (*lc));
		rt->rt_llinfo = (caddr_t)lc;
		if (lc == 0) {
			log(LOG_DEBUG, "llc_rtrequest: malloc failed\n");
			break;
		}
		Bzero(lc, sizeof(*lc));
		lc->lc_rt = rt;
		rt->rt_flags |= RTF_LLINFO;
		insque(lc, &llinfo_llc);
		if (gate->sdl.sdl_alen == sizeof(struct esis_req) + addrlen) {
			gate->sdl.sdl_alen -= sizeof(struct esis_req);
			bcopy(addrlen + LLADDR(&gate->sdl),
				  (caddr_t)&lc->lc_er, sizeof(lc->lc_er));
		} else if (gate->sdl.sdl_alen == addrlen)
			lc->lc_flags = (SNPA_ES | SNPA_VALID | SNPA_PERM);
		break;
	case RTM_DELETE:
		if (rt->rt_flags & RTF_CLONING)
			iso_setmcasts(ifp, req);
		if (lc == 0)
			return;
		remque(lc);
		Free(lc);
		rt->rt_llinfo = 0;
		rt->rt_flags &= ~RTF_LLINFO;
		break;
	}
	if (rt->rt_rmx.rmx_mtu == 0) {
			rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu - LLC_SIZE;
	}
}
/*
 * FUNCTION:		iso_setmcasts
 *
 * PURPOSE:			Enable/Disable ESIS/ISIS multicast reception on interfaces.
 *
 * NOTES:			This also does a lot of obscure magic;
 */
iso_setmcasts(ifp, req)
	struct	ifnet *ifp;
	int		req;
{
	static char *addrlist[] =
		{ all_es_snpa, all_is_snpa, all_l1is_snpa, all_l2is_snpa, 0};
	struct ifreq ifr;
	register caddr_t *cpp;
	int		doreset = 0;

	bzero((caddr_t)&ifr, sizeof(ifr));
	for (cpp = (caddr_t *)addrlist; *cpp; cpp++) {
		bcopy(*cpp, (caddr_t)ifr.ifr_addr.sa_data, 6);
		if (req == RTM_ADD)
			if (ether_addmulti(&ifr, (struct arpcom *)ifp) == ENETRESET)
				doreset++;
		else
			if (ether_delmulti(&ifr, (struct arpcom *)ifp) == ENETRESET)
				doreset++;
	}
	if (doreset) {
		if (ifp->if_reset)
			(*ifp->if_reset)(ifp->if_unit);
		else
			printf("iso_setmcasts: %s%d needs reseting to receive iso mcasts\n",
					ifp->if_name, ifp->if_unit);
	}
}
/*
 * FUNCTION:		iso_snparesolve
 *
 * PURPOSE:			Resolve an iso address into snpa address
 *
 * RETURNS:			0 if addr is resolved
 *					errno if addr is unknown
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			Now that we have folded the snpa cache into the routing
 *					table, we know there is no snpa address known for this
 *					destination.  If we know of a default IS, then the address
 *					of the IS is returned.  If no IS is known, then return the
 *					multi-cast address for "all ES" for this interface.
 *
 *					NB: the last case described above constitutes the
 *					query configuration function 9542, sec 6.5
 *					A mechanism is needed to prevent this function from
 *					being invoked if the system is an IS.
 */
iso_snparesolve(ifp, dest, snpa, snpa_len)
struct	ifnet *ifp;			/* outgoing interface */
struct	sockaddr_iso *dest;	/* destination */
caddr_t	snpa;				/* RESULT: snpa to be used */
int		*snpa_len;			/* RESULT: length of snpa */
{
	struct	llinfo_llc *sc;	/* ptr to snpa table entry */
	caddr_t	found_snpa;
	int 	addrlen;

	/*
	 *	This hack allows us to send esis packets that have the destination snpa
	 *	addresss embedded in the destination nsap address 
	 */
	if (dest->siso_data[0] == AFI_SNA) {
		/*
		 *	This is a subnetwork address. Return it immediately
		 */
		IFDEBUG(D_SNPA)
			printf("iso_snparesolve: return SN address\n");
		ENDDEBUG
		addrlen = dest->siso_nlen - 1;	/* subtract size of AFI */
		found_snpa = (caddr_t) dest->siso_data + 1;
	/* 
	 * If we are an IS, we can't do much with the packet;
	 *	Check if we know about an IS.
	 */
	} else if (iso_systype != SNPA_IS && known_is != 0 &&
				(sc = (struct llinfo_llc *)known_is->rt_llinfo) &&
				 (sc->lc_flags & SNPA_VALID)) {
		register struct sockaddr_dl *sdl =
			(struct sockaddr_dl *)(known_is->rt_gateway);
		found_snpa = LLADDR(sdl);
		addrlen = sdl->sdl_alen;
	} else if (ifp->if_flags & IFF_BROADCAST) {
		/* 
		 *	no IS, no match. Return "all es" multicast address for this
		 *	interface, as per Query Configuration Function (9542 sec 6.5)
		 *
		 *	Note: there is a potential problem here. If the destination
		 *	is on the subnet and it does not respond with a ESH, but
		 *	does send back a TP CC, a connection could be established
		 *	where we always transmit the CLNP packet to "all es"
		 */
		addrlen = ifp->if_addrlen;
		found_snpa = (caddr_t)all_es_snpa;
	} else
		return (ENETUNREACH);
	bcopy(found_snpa, snpa, *snpa_len = addrlen);
	return (0);
}


/*
 * FUNCTION:		snpac_free
 *
 * PURPOSE:			free an entry in the iso address map table
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			If there is a route entry associated with cache
 *					entry, then delete that as well
 */
snpac_free(lc)
register struct llinfo_llc *lc;		/* entry to free */
{
	register struct rtentry *rt = lc->lc_rt;
	register struct iso_addr *r;

	if (known_is == rt)
		known_is = 0;
	if (rt && (rt->rt_flags & RTF_UP) &&
		(rt->rt_flags & (RTF_DYNAMIC | RTF_MODIFIED))) {
			RTFREE(rt);
			rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway, rt_mask(rt),
						rt->rt_flags, (struct rtentry **)0);
		RTFREE(rt);
	}
}

/*
 * FUNCTION:		snpac_add
 *
 * PURPOSE:			Add an entry to the snpa cache
 *
 * RETURNS:			
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			If entry already exists, then update holding time.
 */
snpac_add(ifp, nsap, snpa, type, ht, nsellength)
struct ifnet		*ifp;		/* interface info is related to */
struct iso_addr		*nsap;		/* nsap to add */
caddr_t				snpa;		/* translation */
char				type;		/* SNPA_IS or SNPA_ES */
u_short				ht;			/* holding time (in seconds) */
int					nsellength;	/* nsaps may differ only in trailing bytes */
{
	register struct	llinfo_llc *lc;
	register struct rtentry *rt;
	struct	rtentry *mrt = 0;
	register struct	iso_addr *r; /* for zap_isoaddr macro */
	int		snpalen = min(ifp->if_addrlen, MAX_SNPALEN);
	int		new_entry = 0, index = ifp->if_index, iftype = ifp->if_type;

	IFDEBUG(D_SNPA)
		printf("snpac_add(%x, %x, %x, %x, %x, %x)\n",
			ifp, nsap, snpa, type, ht, nsellength);
	ENDDEBUG
	zap_isoaddr(dst, nsap);
	rt = rtalloc1(S(dst), 0);
	IFDEBUG(D_SNPA)
		printf("snpac_add: rtalloc1 returns %x\n", rt);
	ENDDEBUG
	if (rt == 0) {
		struct sockaddr *netmask;
		int flags;
		add:
		if (nsellength) {
			netmask = S(msk); flags = RTF_UP;
			snpac_fixdstandmask(nsellength);
		} else {
			netmask = 0; flags = RTF_UP | RTF_HOST;
		}
		new_entry = 1;
		zap_linkaddr((&gte_dl), snpa, snpalen, index);
		gte_dl.sdl_type = iftype;
		if (rtrequest(RTM_ADD, S(dst), S(gte_dl), netmask, flags, &mrt) ||
			mrt == 0)
			return (0);
		rt = mrt;
		rt->rt_refcnt--;
	} else {
		register struct sockaddr_dl *sdl = (struct sockaddr_dl *)rt->rt_gateway;
		rt->rt_refcnt--;
		if ((rt->rt_flags & RTF_LLINFO) == 0)
			goto add;
		if (nsellength && (rt->rt_flags & RTF_HOST)) {
			if (rt->rt_refcnt == 0) {
				rtrequest(RTM_DELETE, S(dst), (struct sockaddr *)0,
					(struct sockaddr *)0, 0, (struct rtentry *)0);
				rt = 0;
				goto add;
			} else {
				static struct iso_addr nsap2; register char *cp;
				nsap2 = *nsap;
				cp = nsap2.isoa_genaddr + nsap->isoa_len - nsellength;
				while (cp < (char *)(1 + &nsap2))
					*cp++ = 0;
				(void) snpac_add(ifp, &nsap2, snpa, type, ht, nsellength);
			}
		}
		if (sdl->sdl_family != AF_LINK || sdl->sdl_alen == 0) {
			int old_sdl_len = sdl->sdl_len;
			if (old_sdl_len < sizeof(*sdl)) {
				log(LOG_DEBUG, "snpac_add: cant make room for lladdr\n");
				return (0);
			}
			zap_linkaddr(sdl, snpa, snpalen, index);
			sdl->sdl_len = old_sdl_len;
			sdl->sdl_type = iftype;
			new_entry = 1;
		}
	}
	if ((lc = (struct llinfo_llc *)rt->rt_llinfo) == 0)
		panic("snpac_rtrequest");
	rt->rt_rmx.rmx_expire = ht + time.tv_sec;
	lc->lc_flags = SNPA_VALID | type;
	if ((type & SNPA_IS) && !(iso_systype & SNPA_IS))
		snpac_logdefis(rt);
	return (new_entry);
}

static void
snpac_fixdstandmask(nsellength)
{
	register char *cp = msk.siso_data, *cplim;

	cplim = cp + (dst.siso_nlen -= nsellength);
	msk.siso_len = cplim - (char *)&msk;
	msk.siso_nlen = 0;
	while (cp < cplim)
		*cp++ = -1;
	while (cp < (char *)msk.siso_pad)
		*cp++ = 0;
	for (cp = dst.siso_data + dst.siso_nlen; cp < (char *)dst.siso_pad; )
		*cp++ = 0;
}

/*
 * FUNCTION:		snpac_ioctl
 *
 * PURPOSE:			Set/Get the system type and esis parameters
 *
 * RETURNS:			0 on success, or unix error code
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
snpac_ioctl (so, cmd, data)
struct socket *so;
int		cmd;	/* ioctl to process */
caddr_t	data;	/* data for the cmd */
{
	register struct systype_req *rq = (struct systype_req *)data;

	IFDEBUG(D_IOCTL)
		if (cmd == SIOCSSTYPE)
			printf("snpac_ioctl: cmd set, type x%x, ht %d, ct %d\n",
				rq->sr_type, rq->sr_holdt, rq->sr_configt);
		else
			printf("snpac_ioctl: cmd get\n");
	ENDDEBUG

	if (cmd == SIOCSSTYPE) {
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
		if ((rq->sr_type & (SNPA_ES|SNPA_IS)) == (SNPA_ES|SNPA_IS))
			return(EINVAL);
		if (rq->sr_type & SNPA_ES) {
			iso_systype = SNPA_ES;
		} else if (rq->sr_type & SNPA_IS) {
			iso_systype = SNPA_IS;
		} else {
			return(EINVAL);
		}
		esis_holding_time = rq->sr_holdt;
		esis_config_time = rq->sr_configt;
		if (esis_esconfig_time != rq->sr_esconfigt) {
			untimeout(esis_config, (caddr_t)0);
			esis_esconfig_time = rq->sr_esconfigt;
			esis_config();
		}
	} else if (cmd == SIOCGSTYPE) {
		rq->sr_type = iso_systype;
		rq->sr_holdt = esis_holding_time;
		rq->sr_configt = esis_config_time;
		rq->sr_esconfigt = esis_esconfig_time;
	} else {
		return (EINVAL);
	}
	return (0);
}

/*
 * FUNCTION:		snpac_logdefis
 *
 * PURPOSE:			Mark the IS passed as the default IS
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
snpac_logdefis(sc)
register struct rtentry *sc;
{
	register struct iso_addr *r;
	register struct sockaddr_dl *sdl = (struct sockaddr_dl *)sc->rt_gateway;
	register struct rtentry *rt;

	if (known_is == sc || !(sc->rt_flags & RTF_HOST))
		return;
	if (known_is) {
		RTFREE(known_is);
	}
	known_is = sc;
	RTHOLD(sc);
	rt = rtalloc1((struct sockaddr *)&zsi, 0);
	if (rt == 0)
		rtrequest(RTM_ADD, S(zsi), rt_key(sc), S(zmk),
						RTF_DYNAMIC|RTF_GATEWAY, 0);
	else {
		if ((rt->rt_flags & RTF_DYNAMIC) && 
		    (rt->rt_flags & RTF_GATEWAY) && rt_mask(rt)->sa_len == 0)
			rt_setgate(rt, rt_key(rt), rt_key(sc));
	}
}

/*
 * FUNCTION:		snpac_age
 *
 * PURPOSE:			Time out snpac entries
 *
 * RETURNS:			
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			When encountering an entry for the first time, snpac_age
 *					may delete up to SNPAC_AGE too many seconds. Ie.
 *					if the entry is added a moment before snpac_age is
 *					called, the entry will immediately have SNPAC_AGE
 *					seconds taken off the holding time, even though
 *					it has only been held a brief moment.
 *
 *					The proper way to do this is set an expiry timeval
 *					equal to current time + holding time. Then snpac_age
 *					would time out entries where expiry date is older
 *					than the current time.
 */
void
snpac_age()
{
	register struct	llinfo_llc *lc, *nlc;
	register struct	rtentry *rt;

	timeout(snpac_age, (caddr_t)0, SNPAC_AGE * hz);

	for (lc = llinfo_llc.lc_next; lc != & llinfo_llc; lc = nlc) {
		nlc = lc->lc_next;
		if (lc->lc_flags & SNPA_VALID) {
			rt = lc->lc_rt;
			if (rt->rt_rmx.rmx_expire && rt->rt_rmx.rmx_expire < time.tv_sec)
				snpac_free(lc);
		}
	}
}

/*
 * FUNCTION:		snpac_ownmulti
 *
 * PURPOSE:			Determine if the snpa address is a multicast address
 *					of the same type as the system.
 *
 * RETURNS:			true or false
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			Used by interface drivers when not in eavesdrop mode 
 *					as interm kludge until
 *					real multicast addresses can be configured
 */
snpac_ownmulti(snpa, len)
caddr_t	snpa;
u_int	len;
{
	return (((iso_systype & SNPA_ES) &&
			 (!bcmp(snpa, (caddr_t)all_es_snpa, len))) ||
			((iso_systype & SNPA_IS) &&
			 (!bcmp(snpa, (caddr_t)all_is_snpa, len))));
}

/*
 * FUNCTION:		snpac_flushifp
 *
 * PURPOSE:			Flush entries associated with specific ifp
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			
 */
snpac_flushifp(ifp)
struct ifnet	*ifp;
{
	register struct llinfo_llc	*lc;

	for (lc = llinfo_llc.lc_next; lc != & llinfo_llc; lc = lc->lc_next) {
		if (lc->lc_rt->rt_ifp == ifp && (lc->lc_flags & SNPA_VALID))
			snpac_free(lc);
	}
}

/*
 * FUNCTION:		snpac_rtrequest
 *
 * PURPOSE:			Make a routing request
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			In the future, this should make a request of a user
 *					level routing daemon.
 */
snpac_rtrequest(req, host, gateway, netmask, flags, ret_nrt)
int				req;
struct iso_addr	*host;
struct iso_addr	*gateway;
struct iso_addr	*netmask;
short			flags;
struct rtentry	**ret_nrt;
{
	register struct iso_addr *r;

	IFDEBUG(D_SNPA)
		printf("snpac_rtrequest: ");
		if (req == RTM_ADD)
			printf("add");
		else if (req == RTM_DELETE)
			printf("delete");
		else 
			printf("unknown command");
		printf(" dst: %s\n", clnp_iso_addrp(host));
		printf("\tgateway: %s\n", clnp_iso_addrp(gateway));
	ENDDEBUG


	zap_isoaddr(dst, host);
	zap_isoaddr(gte, gateway);
	if (netmask) {
		zap_isoaddr(msk, netmask);
		msk.siso_nlen = 0;
		msk.siso_len = msk.siso_pad - (u_char *)&msk;
	}

	rtrequest(req, S(dst), S(gte), (netmask ? S(msk) : (struct sockaddr *)0),
		flags, ret_nrt);
}

/*
 * FUNCTION:		snpac_addrt
 *
 * PURPOSE:			Associate a routing entry with an snpac entry
 *
 * RETURNS:			nothing
 *
 * SIDE EFFECTS:	
 *
 * NOTES:			If a cache entry exists for gateway, then
 *					make a routing entry (host, gateway) and associate
 *					with gateway.
 *
 *					If a route already exists and is different, first delete
 *					it.
 *
 *					This could be made more efficient by checking 
 *					the existing route before adding a new one.
 */
snpac_addrt(ifp, host, gateway, netmask)
struct ifnet *ifp;
struct iso_addr	*host, *gateway, *netmask;
{
	register struct iso_addr *r;

	zap_isoaddr(dst, host);
	zap_isoaddr(gte, gateway);
	if (netmask) {
		zap_isoaddr(msk, netmask);
		msk.siso_nlen = 0;
		msk.siso_len = msk.siso_pad - (u_char *)&msk;
		rtredirect(S(dst), S(gte), S(msk), RTF_DONE, S(gte), 0);
	} else
		rtredirect(S(dst), S(gte), (struct sockaddr *)0,
							RTF_DONE | RTF_HOST, S(gte), 0);
}
#endif	/* ISO */
