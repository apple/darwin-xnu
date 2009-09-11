/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

/*	$apfw: if_pflog.c,v 1.4 2008/08/27 00:01:32 jhw Exp $		*/
/*	$OpenBSD: if_pflog.c,v 1.22 2006/12/15 09:31:20 otto Exp $	*/
/*
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr) and 
 * Niels Provos (provos@physnet.uni-hamburg.de).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece, 
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Copyright (C) 1995, 1996, 1997, 1998 by John Ioannidis, Angelos D. Keromytis
 * and Niels Provos.
 * Copyright (c) 2001, Angelos D. Keromytis, Niels Provos.
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software. 
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/proc_internal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#if INET6
#if !INET
#include <netinet/in.h>
#endif
#include <netinet6/nd6.h>
#endif /* INET6 */

#include <net/pfvar.h>
#include <net/if_pflog.h>

#define	PFLOGNAME	"pflog"
#define PFLOGMTU	(32768 + MHLEN + MLEN)

#ifdef PFLOGDEBUG
#define DPRINTF(x)    do { if (pflogdebug) printf x ; } while (0)
#else
#define DPRINTF(x)
#endif

static int pflog_create_dev(void);
static errno_t pflogoutput(struct ifnet *, struct mbuf *);
static errno_t pflogioctl(struct ifnet *, unsigned long, void *);
static errno_t pflogdemux(struct ifnet *, struct mbuf *, char *,
    protocol_family_t *);
static errno_t pflogaddproto(struct ifnet *, protocol_family_t,
    const struct ifnet_demux_desc *, u_int32_t);
static errno_t pflogdelproto(struct ifnet *, protocol_family_t);

static LIST_HEAD(, pflog_softc)	pflogif_list;

struct ifnet *pflogifs[PFLOGIFS_MAX];	/* for fast access */
static int npflog;
static lck_attr_t *pflog_lock_attr;
static lck_grp_t *pflog_lock_grp;
static lck_grp_attr_t *pflog_lock_grp_attr;
static lck_mtx_t *pflog_lock;

void
pfloginit(void)
{
	int i;

	if (pflog_lock != NULL)
		return;

	pflog_lock_grp_attr = lck_grp_attr_alloc_init();
	pflog_lock_grp = lck_grp_alloc_init("pflog", pflog_lock_grp_attr);
	pflog_lock_attr = lck_attr_alloc_init();
	pflog_lock = lck_mtx_alloc_init(pflog_lock_grp, pflog_lock_attr);
	if (pflog_lock == NULL) {
		panic("%s: unable to allocate lock", __func__);
		/* NOTREACHED */
	}
	LIST_INIT(&pflogif_list);
	for (i = 0; i < PFLOGIFS_MAX; i++)
		pflogifs[i] = NULL;

	pflog_create_dev();
}

static int
pflog_create_dev(void)
{
	struct pflog_softc *pflogif;
	struct ifnet_init_params pf_init;
	int error = 0;

	lck_mtx_lock(pflog_lock);
	if (npflog >= PFLOGIFS_MAX) {
		error = EINVAL;
		goto done;
	}

	if ((pflogif = _MALLOC(sizeof (*pflogif),
	    M_DEVBUF, M_WAITOK|M_ZERO)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	bzero(&pf_init, sizeof (pf_init));
	pf_init.name = PFLOGNAME;
	pf_init.unit = npflog;
	pf_init.type = IFT_PFLOG;
	pf_init.family = IFNET_FAMILY_LOOPBACK;
	pf_init.output = pflogoutput;
	pf_init.demux = pflogdemux;
	pf_init.add_proto = pflogaddproto;
	pf_init.del_proto = pflogdelproto;
	pf_init.softc = pflogif;
	pf_init.ioctl = pflogioctl;

	bzero(pflogif, sizeof (*pflogif));
	pflogif->sc_unit = npflog;

	error = ifnet_allocate(&pf_init, &pflogif->sc_if);
	if (error != 0) {
		printf("%s: ifnet_allocate failed - %d\n", __func__, error);
		_FREE(pflogif, M_DEVBUF);
		goto done;
	}

	ifnet_set_mtu(pflogif->sc_if, PFLOGMTU);
	ifnet_set_flags(pflogif->sc_if, IFF_UP, IFF_UP);

	error = ifnet_attach(pflogif->sc_if, NULL);
	if (error != 0) {
		printf("%s: ifnet_attach failed - %d\n", __func__, error);
		ifnet_release(pflogif->sc_if);
		_FREE(pflogif, M_DEVBUF);
		goto done;
	}

#if NBPFILTER > 0
	bpfattach(pflogif->sc_if, DLT_PFLOG, PFLOG_HDRLEN);
#endif

	LIST_INSERT_HEAD(&pflogif_list, pflogif, sc_list);
	pflogifs[npflog] = pflogif->sc_if;
	++npflog;
done:
	lck_mtx_unlock(pflog_lock);

	return (error);
}

#if 0
int
pflog_destroy_dev(struct ifnet *ifp)
{
	struct pflog_softc	*pflogif = ifp->if_softc;

	lck_mtx_lock(pflog_lock);
	pflogifs[pflogif->sc_unit] = NULL;
	LIST_REMOVE(pflogif, sc_list);
	lck_mtx_unlock(pflog_lock);

#if NBPFILTER > 0
	bpfdetach(ifp);
#endif
	if_detach(ifp);
	_FREE(pflogif, M_DEVBUF);
	return (0);
}
#endif

static errno_t
pflogoutput(struct ifnet *ifp, struct mbuf *m)
{
	printf("%s: freeing data for %s%d\n", __func__, ifp->if_name,
	    ifp->if_unit);
	m_freem(m);
	return (ENOTSUP);
}

static errno_t
pflogioctl(struct ifnet *ifp, unsigned long cmd, void *data)
{
#pragma unused(data)
	switch (cmd) {
	case SIOCSIFADDR:
	case SIOCAIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFFLAGS:
		if (ifnet_flags(ifp) & IFF_UP)
			ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
		else
			ifnet_set_flags(ifp, 0, IFF_RUNNING);
		break;
	default:
		return (ENOTTY);
	}

	return (0);
}

static errno_t
pflogdemux(struct ifnet *ifp, struct mbuf *m, char *h, protocol_family_t *ppf)
{
#pragma unused(h, ppf)
	printf("%s: freeing data for %s%d\n", __func__, ifp->if_name,
	    ifp->if_unit);
	m_freem(m);
	return (EJUSTRETURN);
}

static errno_t
pflogaddproto(struct ifnet *ifp, protocol_family_t pf,
    const struct ifnet_demux_desc *d, u_int32_t cnt)
{
#pragma unused(ifp, pf, d, cnt)
	return (0);
}

static errno_t
pflogdelproto(struct ifnet *ifp, protocol_family_t pf)
{
#pragma unused(ifp, pf)
	return (0);
}

int
pflog_packet(struct pfi_kif *kif, struct mbuf *m, sa_family_t af, u_int8_t dir,
    u_int8_t reason, struct pf_rule *rm, struct pf_rule *am,
    struct pf_ruleset *ruleset, struct pf_pdesc *pd)
{
#if NBPFILTER > 0
	struct ifnet *ifn;
	struct pfloghdr hdr;

	if (kif == NULL || m == NULL || rm == NULL || pd == NULL)
		return (-1);

	if (rm->logif >= PFLOGIFS_MAX ||
	    (ifn = pflogifs[rm->logif]) == NULL || !ifn->if_bpf) {
		return (0);
	}

	bzero(&hdr, sizeof (hdr));
	hdr.length = PFLOG_REAL_HDRLEN;
	hdr.af = af;
	hdr.action = rm->action;
	hdr.reason = reason;
	memcpy(hdr.ifname, kif->pfik_name, sizeof (hdr.ifname));

	if (am == NULL) {
		hdr.rulenr = htonl(rm->nr);
		hdr.subrulenr = -1;
	} else {
		hdr.rulenr = htonl(am->nr);
		hdr.subrulenr = htonl(rm->nr);
		if (ruleset != NULL && ruleset->anchor != NULL)
			strlcpy(hdr.ruleset, ruleset->anchor->name,
			    sizeof (hdr.ruleset));
	}
	if (rm->log & PF_LOG_SOCKET_LOOKUP && !pd->lookup.done)
		pd->lookup.done = pf_socket_lookup(dir, pd);
	if (pd->lookup.done > 0) {
		hdr.uid = pd->lookup.uid;
		hdr.pid = pd->lookup.pid;
	} else {
		hdr.uid = UID_MAX;
		hdr.pid = NO_PID;
	}
	hdr.rule_uid = rm->cuid;
	hdr.rule_pid = rm->cpid;
	hdr.dir = dir;

#if INET
	if (af == AF_INET && dir == PF_OUT) {
		struct ip *ip;

		ip = mtod(m, struct ip *);
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, ip->ip_hl << 2);
	}
#endif /* INET */

	ifn->if_opackets++;
	ifn->if_obytes += m->m_pkthdr.len;

	switch (dir) {
	case PF_IN:
		bpf_tap_in(ifn, DLT_PFLOG, m, &hdr, PFLOG_HDRLEN);
		break;

	case PF_OUT:
		bpf_tap_out(ifn, DLT_PFLOG, m, &hdr, PFLOG_HDRLEN);
		break;

	default:
		break;
	}
#endif /* NBPFILTER > 0 */
	return (0);
}
