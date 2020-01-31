/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
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
 *	@(#)bpf.c	8.2 (Berkeley) 3/28/94
 *
 * $FreeBSD: src/sys/net/bpf.c,v 1.59.2.5 2001/01/05 04:49:09 jdp Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include "bpf.h"

#ifndef __GNUC__
#define inline
#else
#define inline __inline
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <sys/ttycom.h>
#include <sys/filedesc.h>
#include <sys/uio_internal.h>
#include <sys/file_internal.h>
#include <sys/event.h>

#include <sys/poll.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/if_ether.h>
#include <netinet/isakmp.h>
#include <netinet6/esp.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <net/firewire.h>

#include <miscfs/devfs/devfs.h>
#include <net/dlil.h>
#include <net/pktap.h>

#include <kern/locks.h>
#include <kern/thread_call.h>
#include <libkern/section_keywords.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#include <os/log.h>

extern int tvtohz(struct timeval *);

#define BPF_BUFSIZE 4096
#define UIOMOVE(cp, len, code, uio) uiomove(cp, len, uio)

#define PRINET  26                      /* interruptible */

#define ISAKMP_HDR_SIZE (sizeof(struct isakmp) + sizeof(struct isakmp_gen))
#define ESP_HDR_SIZE sizeof(struct newesp)

typedef void (*pktcopyfunc_t)(const void *, void *, size_t);

/*
 * The default read buffer size is patchable.
 */
static unsigned int bpf_bufsize = BPF_BUFSIZE;
SYSCTL_INT(_debug, OID_AUTO, bpf_bufsize, CTLFLAG_RW | CTLFLAG_LOCKED,
    &bpf_bufsize, 0, "");
__private_extern__ unsigned int bpf_maxbufsize = BPF_MAXBUFSIZE;
SYSCTL_INT(_debug, OID_AUTO, bpf_maxbufsize, CTLFLAG_RW | CTLFLAG_LOCKED,
    &bpf_maxbufsize, 0, "");
static unsigned int bpf_maxdevices = 256;
SYSCTL_UINT(_debug, OID_AUTO, bpf_maxdevices, CTLFLAG_RW | CTLFLAG_LOCKED,
    &bpf_maxdevices, 0, "");
/*
 * bpf_wantpktap controls the defaul visibility of DLT_PKTAP
 * For OS X is off by default so process need to use the ioctl BPF_WANT_PKTAP
 * explicitly to be able to use DLT_PKTAP.
 */
#if CONFIG_EMBEDDED
static unsigned int bpf_wantpktap = 1;
#else
static unsigned int bpf_wantpktap = 0;
#endif
SYSCTL_UINT(_debug, OID_AUTO, bpf_wantpktap, CTLFLAG_RW | CTLFLAG_LOCKED,
    &bpf_wantpktap, 0, "");

static int bpf_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, bpf_debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &bpf_debug, 0, "");

/*
 *  bpf_iflist is the list of interfaces; each corresponds to an ifnet
 *  bpf_dtab holds pointer to the descriptors, indexed by minor device #
 */
static struct bpf_if    *bpf_iflist;
#ifdef __APPLE__
/*
 * BSD now stores the bpf_d in the dev_t which is a struct
 * on their system. Our dev_t is an int, so we still store
 * the bpf_d in a separate table indexed by minor device #.
 *
 * The value stored in bpf_dtab[n] represent three states:
 *  NULL: device not opened
 *  BPF_DEV_RESERVED: device opening or closing
 *  other: device <n> opened with pointer to storage
 */
#define BPF_DEV_RESERVED ((struct bpf_d *)(uintptr_t)1)
static struct bpf_d     **bpf_dtab = NULL;
static unsigned int bpf_dtab_size = 0;
static unsigned int     nbpfilter = 0;

decl_lck_mtx_data(static, bpf_mlock_data);
static lck_mtx_t                *bpf_mlock = &bpf_mlock_data;
static lck_grp_t                *bpf_mlock_grp;
static lck_grp_attr_t   *bpf_mlock_grp_attr;
static lck_attr_t               *bpf_mlock_attr;

#endif /* __APPLE__ */

static int      bpf_allocbufs(struct bpf_d *);
static errno_t  bpf_attachd(struct bpf_d *d, struct bpf_if *bp);
static int      bpf_detachd(struct bpf_d *d, int);
static void     bpf_freed(struct bpf_d *);
static int      bpf_movein(struct uio *, int,
    struct mbuf **, struct sockaddr *, int *);
static int      bpf_setif(struct bpf_d *, ifnet_t ifp, bool, bool);
static void     bpf_timed_out(void *, void *);
static void     bpf_wakeup(struct bpf_d *);
static u_int    get_pkt_trunc_len(u_char *, u_int);
static void     catchpacket(struct bpf_d *, struct bpf_packet *, u_int, int);
static void     reset_d(struct bpf_d *);
static int      bpf_setf(struct bpf_d *, u_int, user_addr_t, u_long);
static int      bpf_getdltlist(struct bpf_d *, caddr_t, struct proc *);
static int      bpf_setdlt(struct bpf_d *, u_int);
static int      bpf_set_traffic_class(struct bpf_d *, int);
static void     bpf_set_packet_service_class(struct mbuf *, int);

static void     bpf_acquire_d(struct bpf_d *);
static void     bpf_release_d(struct bpf_d *);

static  int bpf_devsw_installed;

void bpf_init(void *unused);
static int bpf_tap_callback(struct ifnet *ifp, struct mbuf *m);

/*
 * Darwin differs from BSD here, the following are static
 * on BSD and not static on Darwin.
 */
d_open_t            bpfopen;
d_close_t           bpfclose;
d_read_t            bpfread;
d_write_t           bpfwrite;
ioctl_fcn_t         bpfioctl;
select_fcn_t        bpfselect;

/* Darwin's cdevsw struct differs slightly from BSDs */
#define CDEV_MAJOR 23
static struct cdevsw bpf_cdevsw = {
	/* open */ bpfopen,
	/* close */ bpfclose,
	/* read */ bpfread,
	/* write */ bpfwrite,
	/* ioctl */ bpfioctl,
	/* stop */ eno_stop,
	/* reset */ eno_reset,
	/* tty */ NULL,
	/* select */ bpfselect,
	/* mmap */ eno_mmap,
	/* strategy */ eno_strat,
	/* getc */ eno_getc,
	/* putc */ eno_putc,
	/* type */ 0
};

#define SOCKADDR_HDR_LEN           offsetof(struct sockaddr, sa_data)

static int
bpf_movein(struct uio *uio, int linktype, struct mbuf **mp,
    struct sockaddr *sockp, int *datlen)
{
	struct mbuf *m;
	int error;
	int len;
	uint8_t sa_family;
	int hlen;

	switch (linktype) {
#if SLIP
	case DLT_SLIP:
		sa_family = AF_INET;
		hlen = 0;
		break;
#endif /* SLIP */

	case DLT_EN10MB:
		sa_family = AF_UNSPEC;
		/* XXX Would MAXLINKHDR be better? */
		hlen = sizeof(struct ether_header);
		break;

#if FDDI
	case DLT_FDDI:
#if defined(__FreeBSD__) || defined(__bsdi__)
		sa_family = AF_IMPLINK;
		hlen = 0;
#else
		sa_family = AF_UNSPEC;
		/* XXX 4(FORMAC)+6(dst)+6(src)+3(LLC)+5(SNAP) */
		hlen = 24;
#endif
		break;
#endif /* FDDI */

	case DLT_RAW:
	case DLT_NULL:
		sa_family = AF_UNSPEC;
		hlen = 0;
		break;

#ifdef __FreeBSD__
	case DLT_ATM_RFC1483:
		/*
		 * en atm driver requires 4-byte atm pseudo header.
		 * though it isn't standard, vpi:vci needs to be
		 * specified anyway.
		 */
		sa_family = AF_UNSPEC;
		hlen = 12;      /* XXX 4(ATM_PH) + 3(LLC) + 5(SNAP) */
		break;
#endif

	case DLT_PPP:
		sa_family = AF_UNSPEC;
		hlen = 4;       /* This should match PPP_HDRLEN */
		break;

	case DLT_APPLE_IP_OVER_IEEE1394:
		sa_family = AF_UNSPEC;
		hlen = sizeof(struct firewire_header);
		break;

	case DLT_IEEE802_11:            /* IEEE 802.11 wireless */
		sa_family = AF_IEEE80211;
		hlen = 0;
		break;

	case DLT_IEEE802_11_RADIO:
		sa_family = AF_IEEE80211;
		hlen = 0;
		break;

	default:
		return EIO;
	}

	// LP64todo - fix this!
	len = uio_resid(uio);
	*datlen = len - hlen;
	if ((unsigned)len > MCLBYTES) {
		return EIO;
	}

	if (sockp) {
		/*
		 * Build a sockaddr based on the data link layer type.
		 * We do this at this level because the ethernet header
		 * is copied directly into the data field of the sockaddr.
		 * In the case of SLIP, there is no header and the packet
		 * is forwarded as is.
		 * Also, we are careful to leave room at the front of the mbuf
		 * for the link level header.
		 */
		if ((hlen + SOCKADDR_HDR_LEN) > sockp->sa_len) {
			return EIO;
		}
		sockp->sa_family = sa_family;
	} else {
		/*
		 * We're directly sending the packet data supplied by
		 * the user; we don't need to make room for the link
		 * header, and don't need the header length value any
		 * more, so set it to 0.
		 */
		hlen = 0;
	}

	MGETHDR(m, M_WAIT, MT_DATA);
	if (m == 0) {
		return ENOBUFS;
	}
	if ((unsigned)len > MHLEN) {
		MCLGET(m, M_WAIT);
		if ((m->m_flags & M_EXT) == 0) {
			error = ENOBUFS;
			goto bad;
		}
	}
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = NULL;
	*mp = m;

	/*
	 * Make room for link header.
	 */
	if (hlen != 0) {
		m->m_pkthdr.len -= hlen;
		m->m_len -= hlen;
		m->m_data += hlen; /* XXX */
		error = UIOMOVE((caddr_t)sockp->sa_data, hlen, UIO_WRITE, uio);
		if (error) {
			goto bad;
		}
	}
	error = UIOMOVE(mtod(m, caddr_t), len - hlen, UIO_WRITE, uio);
	if (error) {
		goto bad;
	}

	/* Check for multicast destination */
	switch (linktype) {
	case DLT_EN10MB: {
		struct ether_header *eh;

		eh = mtod(m, struct ether_header *);
		if (ETHER_IS_MULTICAST(eh->ether_dhost)) {
			if (_ether_cmp(etherbroadcastaddr,
			    eh->ether_dhost) == 0) {
				m->m_flags |= M_BCAST;
			} else {
				m->m_flags |= M_MCAST;
			}
		}
		break;
	}
	}

	return 0;
bad:
	m_freem(m);
	return error;
}

#ifdef __APPLE__

/*
 * The dynamic addition of a new device node must block all processes that
 * are opening the last device so that no process will get an unexpected
 * ENOENT
 */
static void
bpf_make_dev_t(int maj)
{
	static int              bpf_growing = 0;
	unsigned int    cur_size = nbpfilter, i;

	if (nbpfilter >= bpf_maxdevices) {
		return;
	}

	while (bpf_growing) {
		/* Wait until new device has been created */
		(void) tsleep((caddr_t)&bpf_growing, PZERO, "bpf_growing", 0);
	}
	if (nbpfilter > cur_size) {
		/* other thread grew it already */
		return;
	}
	bpf_growing = 1;

	/* need to grow bpf_dtab first */
	if (nbpfilter == bpf_dtab_size) {
		int new_dtab_size;
		struct bpf_d **new_dtab = NULL;
		struct bpf_d **old_dtab = NULL;

		new_dtab_size = bpf_dtab_size + NBPFILTER;
		new_dtab = (struct bpf_d **)_MALLOC(
			sizeof(struct bpf_d *) * new_dtab_size, M_DEVBUF, M_WAIT);
		if (new_dtab == 0) {
			printf("bpf_make_dev_t: malloc bpf_dtab failed\n");
			goto done;
		}
		if (bpf_dtab) {
			bcopy(bpf_dtab, new_dtab,
			    sizeof(struct bpf_d *) * bpf_dtab_size);
		}
		bzero(new_dtab + bpf_dtab_size,
		    sizeof(struct bpf_d *) * NBPFILTER);
		old_dtab = bpf_dtab;
		bpf_dtab = new_dtab;
		bpf_dtab_size = new_dtab_size;
		if (old_dtab != NULL) {
			_FREE(old_dtab, M_DEVBUF);
		}
	}
	i = nbpfilter++;
	(void) devfs_make_node(makedev(maj, i),
	    DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0600,
	    "bpf%d", i);
done:
	bpf_growing = 0;
	wakeup((caddr_t)&bpf_growing);
}

#endif

/*
 * Attach file to the bpf interface, i.e. make d listen on bp.
 */
static errno_t
bpf_attachd(struct bpf_d *d, struct bpf_if *bp)
{
	int first = bp->bif_dlist == NULL;
	int     error = 0;

	/*
	 * Point d at bp, and add d to the interface's list of listeners.
	 * Finally, point the driver's bpf cookie at the interface so
	 * it will divert packets to bpf.
	 */
	d->bd_bif = bp;
	d->bd_next = bp->bif_dlist;
	bp->bif_dlist = d;

	/*
	 * Take a reference on the device even if an error is returned
	 * because we keep the device in the interface's list of listeners
	 */
	bpf_acquire_d(d);

	if (first) {
		/* Find the default bpf entry for this ifp */
		if (bp->bif_ifp->if_bpf == NULL) {
			struct bpf_if   *tmp, *primary = NULL;

			for (tmp = bpf_iflist; tmp; tmp = tmp->bif_next) {
				if (tmp->bif_ifp == bp->bif_ifp) {
					primary = tmp;
					break;
				}
			}
			bp->bif_ifp->if_bpf = primary;
		}
		/* Only call dlil_set_bpf_tap for primary dlt */
		if (bp->bif_ifp->if_bpf == bp) {
			dlil_set_bpf_tap(bp->bif_ifp, BPF_TAP_INPUT_OUTPUT,
			    bpf_tap_callback);
		}

		if (bp->bif_tap != NULL) {
			error = bp->bif_tap(bp->bif_ifp, bp->bif_dlt,
			    BPF_TAP_INPUT_OUTPUT);
		}
	}

	/*
	 * Reset the detach flags in case we previously detached an interface
	 */
	d->bd_flags &= ~(BPF_DETACHING | BPF_DETACHED);

	if (bp->bif_dlt == DLT_PKTAP) {
		d->bd_flags |= BPF_FINALIZE_PKTAP;
	} else {
		d->bd_flags &= ~BPF_FINALIZE_PKTAP;
	}
	return error;
}

/*
 * Detach a file from its interface.
 *
 * Return 1 if was closed by some thread, 0 otherwise
 */
static int
bpf_detachd(struct bpf_d *d, int closing)
{
	struct bpf_d **p;
	struct bpf_if *bp;
	struct ifnet  *ifp;

	int bpf_closed = d->bd_flags & BPF_CLOSING;
	/*
	 * Some other thread already detached
	 */
	if ((d->bd_flags & (BPF_DETACHED | BPF_DETACHING)) != 0) {
		goto done;
	}
	/*
	 * This thread is doing the detach
	 */
	d->bd_flags |= BPF_DETACHING;

	ifp = d->bd_bif->bif_ifp;
	bp = d->bd_bif;

	if (bpf_debug != 0) {
		printf("%s: %llx %s%s\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(d),
		    if_name(ifp), closing ? " closing" : "");
	}

	/* Remove d from the interface's descriptor list. */
	p = &bp->bif_dlist;
	while (*p != d) {
		p = &(*p)->bd_next;
		if (*p == 0) {
			panic("bpf_detachd: descriptor not in list");
		}
	}
	*p = (*p)->bd_next;
	if (bp->bif_dlist == 0) {
		/*
		 * Let the driver know that there are no more listeners.
		 */
		/* Only call dlil_set_bpf_tap for primary dlt */
		if (bp->bif_ifp->if_bpf == bp) {
			dlil_set_bpf_tap(ifp, BPF_TAP_DISABLE, NULL);
		}
		if (bp->bif_tap) {
			bp->bif_tap(ifp, bp->bif_dlt, BPF_TAP_DISABLE);
		}

		for (bp = bpf_iflist; bp; bp = bp->bif_next) {
			if (bp->bif_ifp == ifp && bp->bif_dlist != 0) {
				break;
			}
		}
		if (bp == NULL) {
			ifp->if_bpf = NULL;
		}
	}
	d->bd_bif = NULL;
	/*
	 * Check if this descriptor had requested promiscuous mode.
	 * If so, turn it off.
	 */
	if (d->bd_promisc) {
		d->bd_promisc = 0;
		lck_mtx_unlock(bpf_mlock);
		if (ifnet_set_promiscuous(ifp, 0)) {
			/*
			 * Something is really wrong if we were able to put
			 * the driver into promiscuous mode, but can't
			 * take it out.
			 * Most likely the network interface is gone.
			 */
			printf("%s: ifnet_set_promiscuous failed\n", __func__);
		}
		lck_mtx_lock(bpf_mlock);
	}

	/*
	 * Wake up other thread that are waiting for this thread to finish
	 * detaching
	 */
	d->bd_flags &= ~BPF_DETACHING;
	d->bd_flags |= BPF_DETACHED;

	/* Refresh the local variable as d could have been modified */
	bpf_closed = d->bd_flags & BPF_CLOSING;
	/*
	 * Note that We've kept the reference because we may have dropped
	 * the lock when turning off promiscuous mode
	 */
	bpf_release_d(d);

done:
	/*
	 * When closing makes sure no other thread refer to the bpf_d
	 */
	if (bpf_debug != 0) {
		printf("%s: %llx done\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(d));
	}
	/*
	 * Let the caller know the bpf_d is closed
	 */
	if (bpf_closed) {
		return 1;
	} else {
		return 0;
	}
}

/*
 * Start asynchronous timer, if necessary.
 * Must be called with bpf_mlock held.
 */
static void
bpf_start_timer(struct bpf_d *d)
{
	uint64_t deadline;
	struct timeval tv;

	if (d->bd_rtout > 0 && d->bd_state == BPF_IDLE) {
		tv.tv_sec = d->bd_rtout / hz;
		tv.tv_usec = (d->bd_rtout % hz) * tick;

		clock_interval_to_deadline(
			(uint64_t)tv.tv_sec * USEC_PER_SEC + tv.tv_usec,
			NSEC_PER_USEC, &deadline);
		/*
		 * The state is BPF_IDLE, so the timer hasn't
		 * been started yet, and hasn't gone off yet;
		 * there is no thread call scheduled, so this
		 * won't change the schedule.
		 *
		 * XXX - what if, by the time it gets entered,
		 * the deadline has already passed?
		 */
		thread_call_enter_delayed(d->bd_thread_call, deadline);
		d->bd_state = BPF_WAITING;
	}
}

/*
 * Cancel asynchronous timer.
 * Must be called with bpf_mlock held.
 */
static boolean_t
bpf_stop_timer(struct bpf_d *d)
{
	/*
	 * If the timer has already gone off, this does nothing.
	 * Our caller is expected to set d->bd_state to BPF_IDLE,
	 * with the bpf_mlock, after we are called. bpf_timed_out()
	 * also grabs bpf_mlock, so, if the timer has gone off and
	 * bpf_timed_out() hasn't finished, it's waiting for the
	 * lock; when this thread releases the lock, it will
	 * find the state is BPF_IDLE, and just release the
	 * lock and return.
	 */
	return thread_call_cancel(d->bd_thread_call);
}

void
bpf_acquire_d(struct bpf_d *d)
{
	void *lr_saved =  __builtin_return_address(0);

	LCK_MTX_ASSERT(bpf_mlock, LCK_MTX_ASSERT_OWNED);

	d->bd_refcnt += 1;

	d->bd_ref_lr[d->bd_next_ref_lr] = lr_saved;
	d->bd_next_ref_lr = (d->bd_next_ref_lr + 1) % BPF_REF_HIST;
}

void
bpf_release_d(struct bpf_d *d)
{
	void *lr_saved =  __builtin_return_address(0);

	LCK_MTX_ASSERT(bpf_mlock, LCK_MTX_ASSERT_OWNED);

	if (d->bd_refcnt <= 0) {
		panic("%s: %p refcnt <= 0", __func__, d);
	}

	d->bd_refcnt -= 1;

	d->bd_unref_lr[d->bd_next_unref_lr] = lr_saved;
	d->bd_next_unref_lr = (d->bd_next_unref_lr + 1) % BPF_REF_HIST;

	if (d->bd_refcnt == 0) {
		/* Assert the device is detached */
		if ((d->bd_flags & BPF_DETACHED) == 0) {
			panic("%s: %p BPF_DETACHED not set", __func__, d);
		}

		_FREE(d, M_DEVBUF);
	}
}

/*
 * Open ethernet device.  Returns ENXIO for illegal minor device number,
 * EBUSY if file is open by another process.
 */
/* ARGSUSED */
int
bpfopen(dev_t dev, int flags, __unused int fmt,
    struct proc *p)
{
	struct bpf_d *d;

	lck_mtx_lock(bpf_mlock);
	if ((unsigned int) minor(dev) >= nbpfilter) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}
	/*
	 * New device nodes are created on demand when opening the last one.
	 * The programming model is for processes to loop on the minor starting
	 * at 0 as long as EBUSY is returned. The loop stops when either the
	 * open succeeds or an error other that EBUSY is returned. That means
	 * that bpf_make_dev_t() must block all processes that are opening the
	 * last  node. If not all processes are blocked, they could unexpectedly
	 * get ENOENT and abort their opening loop.
	 */
	if ((unsigned int) minor(dev) == (nbpfilter - 1)) {
		bpf_make_dev_t(major(dev));
	}

	/*
	 * Each minor can be opened by only one process.  If the requested
	 * minor is in use, return EBUSY.
	 *
	 * Important: bpfopen() and bpfclose() have to check and set the status
	 * of a device in the same lockin context otherwise the device may be
	 * leaked because the vnode use count will be unpextectly greater than 1
	 * when close() is called.
	 */
	if (bpf_dtab[minor(dev)] == NULL) {
		/* Reserve while opening */
		bpf_dtab[minor(dev)] = BPF_DEV_RESERVED;
	} else {
		lck_mtx_unlock(bpf_mlock);
		return EBUSY;
	}
	d = (struct bpf_d *)_MALLOC(sizeof(struct bpf_d), M_DEVBUF,
	    M_WAIT | M_ZERO);
	if (d == NULL) {
		/* this really is a catastrophic failure */
		printf("bpfopen: malloc bpf_d failed\n");
		bpf_dtab[minor(dev)] = NULL;
		lck_mtx_unlock(bpf_mlock);
		return ENOMEM;
	}

	/* Mark "in use" and do most initialization. */
	bpf_acquire_d(d);
	d->bd_bufsize = bpf_bufsize;
	d->bd_sig = SIGIO;
	d->bd_seesent = 1;
	d->bd_oflags = flags;
	d->bd_state = BPF_IDLE;
	d->bd_traffic_class = SO_TC_BE;
	d->bd_flags |= BPF_DETACHED;
	if (bpf_wantpktap) {
		d->bd_flags |= BPF_WANT_PKTAP;
	} else {
		d->bd_flags &= ~BPF_WANT_PKTAP;
	}
	d->bd_thread_call = thread_call_allocate(bpf_timed_out, d);
	if (d->bd_thread_call == NULL) {
		printf("bpfopen: malloc thread call failed\n");
		bpf_dtab[minor(dev)] = NULL;
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);

		return ENOMEM;
	}
	d->bd_opened_by = p;
	uuid_generate(d->bd_uuid);

#if CONFIG_MACF_NET
	mac_bpfdesc_label_init(d);
	mac_bpfdesc_label_associate(kauth_cred_get(), d);
#endif
	bpf_dtab[minor(dev)] = d; /* Mark opened */
	lck_mtx_unlock(bpf_mlock);

	return 0;
}

/*
 * Close the descriptor by detaching it from its interface,
 * deallocating its buffers, and marking it free.
 */
/* ARGSUSED */
int
bpfclose(dev_t dev, __unused int flags, __unused int fmt,
    __unused struct proc *p)
{
	struct bpf_d *d;

	/* Take BPF lock to ensure no other thread is using the device */
	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == NULL || d == BPF_DEV_RESERVED) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	/*
	 * Other threads may call bpd_detachd() if we drop the bpf_mlock
	 */
	d->bd_flags |= BPF_CLOSING;

	if (bpf_debug != 0) {
		printf("%s: %llx\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(d));
	}

	bpf_dtab[minor(dev)] = BPF_DEV_RESERVED; /* Reserve while closing */

	/*
	 * Deal with any in-progress timeouts.
	 */
	switch (d->bd_state) {
	case BPF_IDLE:
		/*
		 * Not waiting for a timeout, and no timeout happened.
		 */
		break;

	case BPF_WAITING:
		/*
		 * Waiting for a timeout.
		 * Cancel any timer that has yet to go off,
		 * and mark the state as "closing".
		 * Then drop the lock to allow any timers that
		 * *have* gone off to run to completion, and wait
		 * for them to finish.
		 */
		if (!bpf_stop_timer(d)) {
			/*
			 * There was no pending call, so the call must
			 * have been in progress. Wait for the call to
			 * complete; we have to drop the lock while
			 * waiting. to let the in-progrss call complete
			 */
			d->bd_state = BPF_DRAINING;
			while (d->bd_state == BPF_DRAINING) {
				msleep((caddr_t)d, bpf_mlock, PRINET,
				    "bpfdraining", NULL);
			}
		}
		d->bd_state = BPF_IDLE;
		break;

	case BPF_TIMED_OUT:
		/*
		 * Timer went off, and the timeout routine finished.
		 */
		d->bd_state = BPF_IDLE;
		break;

	case BPF_DRAINING:
		/*
		 * Another thread is blocked on a close waiting for
		 * a timeout to finish.
		 * This "shouldn't happen", as the first thread to enter
		 * bpfclose() will set bpf_dtab[minor(dev)] to 1, and
		 * all subsequent threads should see that and fail with
		 * ENXIO.
		 */
		panic("Two threads blocked in a BPF close");
		break;
	}

	if (d->bd_bif) {
		bpf_detachd(d, 1);
	}
	selthreadclear(&d->bd_sel);
#if CONFIG_MACF_NET
	mac_bpfdesc_label_destroy(d);
#endif
	thread_call_free(d->bd_thread_call);

	while (d->bd_hbuf_read != 0) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	bpf_freed(d);

	/* Mark free in same context as bpfopen comes to check */
	bpf_dtab[minor(dev)] = NULL;                    /* Mark closed */

	bpf_release_d(d);

	lck_mtx_unlock(bpf_mlock);

	return 0;
}

#define BPF_SLEEP bpf_sleep

static int
bpf_sleep(struct bpf_d *d, int pri, const char *wmesg, int timo)
{
	u_int64_t abstime = 0;

	if (timo != 0) {
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	}

	return msleep1((caddr_t)d, bpf_mlock, pri, wmesg, abstime);
}

static void
bpf_finalize_pktap(struct bpf_hdr *hp, struct pktap_header *pktaphdr)
{
	if (pktaphdr->pth_flags & PTH_FLAG_V2_HDR) {
		struct pktap_v2_hdr *pktap_v2_hdr;

		pktap_v2_hdr = (struct pktap_v2_hdr *)pktaphdr;

		if (pktap_v2_hdr->pth_flags & PTH_FLAG_DELAY_PKTAP) {
			pktap_v2_finalize_proc_info(pktap_v2_hdr);
		}
	} else {
		if (pktaphdr->pth_flags & PTH_FLAG_DELAY_PKTAP) {
			pktap_finalize_proc_info(pktaphdr);
		}

		if (pktaphdr->pth_flags & PTH_FLAG_TSTAMP) {
			hp->bh_tstamp.tv_sec = pktaphdr->pth_tstamp.tv_sec;
			hp->bh_tstamp.tv_usec = pktaphdr->pth_tstamp.tv_usec;
		}
	}
}

/*
 * Rotate the packet buffers in descriptor d.  Move the store buffer
 * into the hold slot, and the free buffer into the store slot.
 * Zero the length of the new store buffer.
 */
#define ROTATE_BUFFERS(d) \
	if (d->bd_hbuf_read != 0) \
	        panic("rotating bpf buffers during read"); \
	(d)->bd_hbuf = (d)->bd_sbuf; \
	(d)->bd_hlen = (d)->bd_slen; \
	(d)->bd_hcnt = (d)->bd_scnt; \
	(d)->bd_sbuf = (d)->bd_fbuf; \
	(d)->bd_slen = 0; \
	(d)->bd_scnt = 0; \
	(d)->bd_fbuf = NULL;
/*
 *  bpfread - read next chunk of packets from buffers
 */
int
bpfread(dev_t dev, struct uio *uio, int ioflag)
{
	struct bpf_d *d;
	caddr_t hbuf;
	int timed_out, hbuf_len;
	int error;
	int flags;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == NULL || d == BPF_DEV_RESERVED ||
	    (d->bd_flags & BPF_CLOSING) != 0) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	bpf_acquire_d(d);

	/*
	 * Restrict application to use a buffer the same size as
	 * as kernel buffers.
	 */
	if (uio_resid(uio) != d->bd_bufsize) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return EINVAL;
	}

	if (d->bd_state == BPF_WAITING) {
		bpf_stop_timer(d);
	}

	timed_out = (d->bd_state == BPF_TIMED_OUT);
	d->bd_state = BPF_IDLE;

	while (d->bd_hbuf_read != 0) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	if ((d->bd_flags & BPF_CLOSING) != 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}
	/*
	 * If the hold buffer is empty, then do a timed sleep, which
	 * ends when the timeout expires or when enough packets
	 * have arrived to fill the store buffer.
	 */
	while (d->bd_hbuf == 0) {
		if ((d->bd_immediate || timed_out || (ioflag & IO_NDELAY)) &&
		    d->bd_slen != 0) {
			/*
			 * We're in immediate mode, or are reading
			 * in non-blocking mode, or a timer was
			 * started before the read (e.g., by select()
			 * or poll()) and has expired and a packet(s)
			 * either arrived since the previous
			 * read or arrived while we were asleep.
			 * Rotate the buffers and return what's here.
			 */
			ROTATE_BUFFERS(d);
			break;
		}

		/*
		 * No data is available, check to see if the bpf device
		 * is still pointed at a real interface.  If not, return
		 * ENXIO so that the userland process knows to rebind
		 * it before using it again.
		 */
		if (d->bd_bif == NULL) {
			bpf_release_d(d);
			lck_mtx_unlock(bpf_mlock);
			return ENXIO;
		}
		if (ioflag & IO_NDELAY) {
			bpf_release_d(d);
			lck_mtx_unlock(bpf_mlock);
			return EWOULDBLOCK;
		}
		error = BPF_SLEEP(d, PRINET | PCATCH, "bpf", d->bd_rtout);
		/*
		 * Make sure device is still opened
		 */
		if ((d->bd_flags & BPF_CLOSING) != 0) {
			bpf_release_d(d);
			lck_mtx_unlock(bpf_mlock);
			return ENXIO;
		}

		while (d->bd_hbuf_read != 0) {
			msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading",
			    NULL);
		}

		if ((d->bd_flags & BPF_CLOSING) != 0) {
			bpf_release_d(d);
			lck_mtx_unlock(bpf_mlock);
			return ENXIO;
		}

		if (error == EINTR || error == ERESTART) {
			if (d->bd_hbuf != NULL) {
				/*
				 * Because we msleep, the hold buffer might
				 * be filled when we wake up.  Avoid rotating
				 * in this case.
				 */
				break;
			}
			if (d->bd_slen != 0) {
				/*
				 * Sometimes we may be interrupted often and
				 * the sleep above will not timeout.
				 * Regardless, we should rotate the buffers
				 * if there's any new data pending and
				 * return it.
				 */
				ROTATE_BUFFERS(d);
				break;
			}
			bpf_release_d(d);
			lck_mtx_unlock(bpf_mlock);
			if (error == ERESTART) {
				printf("%s: %llx ERESTART to EINTR\n",
				    __func__, (uint64_t)VM_KERNEL_ADDRPERM(d));
				error = EINTR;
			}
			return error;
		}
		if (error == EWOULDBLOCK) {
			/*
			 * On a timeout, return what's in the buffer,
			 * which may be nothing.  If there is something
			 * in the store buffer, we can rotate the buffers.
			 */
			if (d->bd_hbuf) {
				/*
				 * We filled up the buffer in between
				 * getting the timeout and arriving
				 * here, so we don't need to rotate.
				 */
				break;
			}

			if (d->bd_slen == 0) {
				bpf_release_d(d);
				lck_mtx_unlock(bpf_mlock);
				return 0;
			}
			ROTATE_BUFFERS(d);
			break;
		}
	}
	/*
	 * At this point, we know we have something in the hold slot.
	 */

	/*
	 * Set the hold buffer read. So we do not
	 * rotate the buffers until the hold buffer
	 * read is complete. Also to avoid issues resulting
	 * from page faults during disk sleep (<rdar://problem/13436396>).
	 */
	d->bd_hbuf_read = 1;
	hbuf = d->bd_hbuf;
	hbuf_len = d->bd_hlen;
	flags = d->bd_flags;
	lck_mtx_unlock(bpf_mlock);

#ifdef __APPLE__
	/*
	 * Before we move data to userland, we fill out the extended
	 * header fields.
	 */
	if (flags & BPF_EXTENDED_HDR) {
		char *p;

		p = hbuf;
		while (p < hbuf + hbuf_len) {
			struct bpf_hdr_ext *ehp;
			uint32_t flowid;
			struct so_procinfo soprocinfo;
			int found = 0;

			ehp = (struct bpf_hdr_ext *)(void *)p;
			if ((flowid = ehp->bh_flowid) != 0) {
				if (ehp->bh_proto == IPPROTO_TCP) {
					found = inp_findinpcb_procinfo(&tcbinfo,
					    flowid, &soprocinfo);
				} else if (ehp->bh_proto == IPPROTO_UDP) {
					found = inp_findinpcb_procinfo(&udbinfo,
					    flowid, &soprocinfo);
				}
				if (found == 1) {
					ehp->bh_pid = soprocinfo.spi_pid;
					proc_name(ehp->bh_pid, ehp->bh_comm,
					    MAXCOMLEN);
				}
				ehp->bh_flowid = 0;
			}

			if (flags & BPF_FINALIZE_PKTAP) {
				struct pktap_header *pktaphdr;

				pktaphdr = (struct pktap_header *)(void *)
				    (p + BPF_WORDALIGN(ehp->bh_hdrlen));

				bpf_finalize_pktap((struct bpf_hdr *) ehp,
				    pktaphdr);
			}
			p += BPF_WORDALIGN(ehp->bh_hdrlen + ehp->bh_caplen);
		}
	} else if (flags & BPF_FINALIZE_PKTAP) {
		char *p;

		p = hbuf;
		while (p < hbuf + hbuf_len) {
			struct bpf_hdr *hp;
			struct pktap_header *pktaphdr;

			hp = (struct bpf_hdr *)(void *)p;
			pktaphdr = (struct pktap_header *)(void *)
			    (p + BPF_WORDALIGN(hp->bh_hdrlen));

			bpf_finalize_pktap(hp, pktaphdr);

			p += BPF_WORDALIGN(hp->bh_hdrlen + hp->bh_caplen);
		}
	}
#endif

	/*
	 * Move data from hold buffer into user space.
	 * We know the entire buffer is transferred since
	 * we checked above that the read buffer is bpf_bufsize bytes.
	 */
	error = UIOMOVE(hbuf, hbuf_len, UIO_READ, uio);

	lck_mtx_lock(bpf_mlock);
	/*
	 * Make sure device is still opened
	 */
	if ((d->bd_flags & BPF_CLOSING) != 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	d->bd_hbuf_read = 0;
	d->bd_fbuf = d->bd_hbuf;
	d->bd_hbuf = NULL;
	d->bd_hlen = 0;
	d->bd_hcnt = 0;
	wakeup((caddr_t)d);

	bpf_release_d(d);
	lck_mtx_unlock(bpf_mlock);
	return error;
}

/*
 * If there are processes sleeping on this descriptor, wake them up.
 */
static void
bpf_wakeup(struct bpf_d *d)
{
	if (d->bd_state == BPF_WAITING) {
		bpf_stop_timer(d);
		d->bd_state = BPF_IDLE;
	}
	wakeup((caddr_t)d);
	if (d->bd_async && d->bd_sig && d->bd_sigio) {
		pgsigio(d->bd_sigio, d->bd_sig);
	}

	selwakeup(&d->bd_sel);
	if ((d->bd_flags & BPF_KNOTE)) {
		KNOTE(&d->bd_sel.si_note, 1);
	}
}

static void
bpf_timed_out(void *arg, __unused void *dummy)
{
	struct bpf_d *d = (struct bpf_d *)arg;

	lck_mtx_lock(bpf_mlock);
	if (d->bd_state == BPF_WAITING) {
		/*
		 * There's a select or kqueue waiting for this; if there's
		 * now stuff to read, wake it up.
		 */
		d->bd_state = BPF_TIMED_OUT;
		if (d->bd_slen != 0) {
			bpf_wakeup(d);
		}
	} else if (d->bd_state == BPF_DRAINING) {
		/*
		 * A close is waiting for this to finish.
		 * Mark it as finished, and wake the close up.
		 */
		d->bd_state = BPF_IDLE;
		bpf_wakeup(d);
	}
	lck_mtx_unlock(bpf_mlock);
}

/* keep in sync with bpf_movein above: */
#define MAX_DATALINK_HDR_LEN    (sizeof(struct firewire_header))

int
bpfwrite(dev_t dev, struct uio *uio, __unused int ioflag)
{
	struct bpf_d *d;
	struct ifnet *ifp;
	struct mbuf *m = NULL;
	int error;
	char              dst_buf[SOCKADDR_HDR_LEN + MAX_DATALINK_HDR_LEN];
	int datlen = 0;
	int bif_dlt;
	int bd_hdrcmplt;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == NULL || d == BPF_DEV_RESERVED ||
	    (d->bd_flags & BPF_CLOSING) != 0) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	bpf_acquire_d(d);

	if (d->bd_bif == 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	ifp = d->bd_bif->bif_ifp;

	if ((ifp->if_flags & IFF_UP) == 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENETDOWN;
	}
	if (uio_resid(uio) == 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return 0;
	}
	((struct sockaddr *)dst_buf)->sa_len = sizeof(dst_buf);

	/*
	 * fix for PR-6849527
	 * geting variables onto stack before dropping lock for bpf_movein()
	 */
	bif_dlt = (int)d->bd_bif->bif_dlt;
	bd_hdrcmplt  = d->bd_hdrcmplt;

	/* bpf_movein allocating mbufs; drop lock */
	lck_mtx_unlock(bpf_mlock);

	error = bpf_movein(uio, bif_dlt, &m,
	    bd_hdrcmplt ? NULL : (struct sockaddr *)dst_buf,
	    &datlen);

	/* take the lock again */
	lck_mtx_lock(bpf_mlock);
	if (error) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return error;
	}

	/* verify the device is still open */
	if ((d->bd_flags & BPF_CLOSING) != 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		m_freem(m);
		return ENXIO;
	}

	if (d->bd_bif == NULL) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		m_free(m);
		return ENXIO;
	}

	if ((unsigned)datlen > ifp->if_mtu) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		m_freem(m);
		return EMSGSIZE;
	}

#if CONFIG_MACF_NET
	mac_mbuf_label_associate_bpfdesc(d, m);
#endif

	bpf_set_packet_service_class(m, d->bd_traffic_class);

	lck_mtx_unlock(bpf_mlock);

	/*
	 * The driver frees the mbuf.
	 */
	if (d->bd_hdrcmplt) {
		if (d->bd_bif->bif_send) {
			error = d->bd_bif->bif_send(ifp, d->bd_bif->bif_dlt, m);
		} else {
			error = dlil_output(ifp, 0, m, NULL, NULL, 1, NULL);
		}
	} else {
		error = dlil_output(ifp, PF_INET, m, NULL,
		    (struct sockaddr *)dst_buf, 0, NULL);
	}

	lck_mtx_lock(bpf_mlock);
	bpf_release_d(d);
	lck_mtx_unlock(bpf_mlock);

	return error;
}

/*
 * Reset a descriptor by flushing its packet buffer and clearing the
 * receive and drop counts.
 */
static void
reset_d(struct bpf_d *d)
{
	if (d->bd_hbuf_read != 0) {
		panic("resetting buffers during read");
	}

	if (d->bd_hbuf) {
		/* Free the hold buffer. */
		d->bd_fbuf = d->bd_hbuf;
		d->bd_hbuf = NULL;
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	d->bd_scnt = 0;
	d->bd_hcnt = 0;
	d->bd_rcount = 0;
	d->bd_dcount = 0;
}

static struct bpf_d *
bpf_get_device_from_uuid(uuid_t uuid)
{
	unsigned int i;

	for (i = 0; i < nbpfilter; i++) {
		struct bpf_d *d = bpf_dtab[i];

		if (d == NULL || d == BPF_DEV_RESERVED ||
		    (d->bd_flags & BPF_CLOSING) != 0) {
			continue;
		}
		if (uuid_compare(uuid, d->bd_uuid) == 0) {
			return d;
		}
	}

	return NULL;
}

/*
 * The BIOCSETUP command "atomically" attach to the interface and
 * copy the buffer from another interface. This minimizes the risk
 * of missing packet because this is done while holding
 * the BPF global lock
 */
static int
bpf_setup(struct bpf_d *d_to, uuid_t uuid_from, ifnet_t ifp)
{
	struct bpf_d *d_from;
	int error = 0;

	LCK_MTX_ASSERT(bpf_mlock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Sanity checks
	 */
	d_from = bpf_get_device_from_uuid(uuid_from);
	if (d_from == NULL) {
		error = ENOENT;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: uuids not found error %d",
		    __func__, error);
		return error;
	}
	if (d_from->bd_opened_by != d_to->bd_opened_by) {
		error = EACCES;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: processes not matching error %d",
		    __func__, error);
		return error;
	}

	/*
	 * Prevent any read while copying
	 */
	while (d_to->bd_hbuf_read != 0) {
		msleep((caddr_t)d_to, bpf_mlock, PRINET, __func__, NULL);
	}
	d_to->bd_hbuf_read = 1;

	while (d_from->bd_hbuf_read != 0) {
		msleep((caddr_t)d_from, bpf_mlock, PRINET, __func__, NULL);
	}
	d_from->bd_hbuf_read = 1;

	/*
	 * Verify the devices have not been closed
	 */
	if (d_to->bd_flags & BPF_CLOSING) {
		error = ENXIO;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: d_to is closing error %d",
		    __func__, error);
		goto done;
	}
	if (d_from->bd_flags & BPF_CLOSING) {
		error = ENXIO;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: d_from is closing error %d",
		    __func__, error);
		goto done;
	}

	/*
	 * For now require the same buffer size
	 */
	if (d_from->bd_bufsize != d_to->bd_bufsize) {
		error = EINVAL;
		os_log_info(OS_LOG_DEFAULT,
		    "%s: bufsizes not matching error %d",
		    __func__, error);
		goto done;
	}

	/*
	 * Attach to the interface
	 */
	error = bpf_setif(d_to, ifp, false, true);
	if (error != 0) {
		os_log_info(OS_LOG_DEFAULT,
		    "%s: bpf_setif() failed error %d",
		    __func__, error);
		goto done;
	}

	/*
	 * Make sure the buffers are setup as expected by bpf_setif()
	 */
	ASSERT(d_to->bd_hbuf == NULL);
	ASSERT(d_to->bd_sbuf != NULL);
	ASSERT(d_to->bd_fbuf != NULL);

	/*
	 * Copy the buffers and update the pointers and counts
	 */
	memcpy(d_to->bd_sbuf, d_from->bd_sbuf, d_from->bd_slen);
	d_to->bd_slen = d_from->bd_slen;
	d_to->bd_scnt = d_from->bd_scnt;

	if (d_from->bd_hbuf != NULL) {
		d_to->bd_hbuf = d_to->bd_fbuf;
		d_to->bd_fbuf = NULL;
		memcpy(d_to->bd_hbuf, d_from->bd_hbuf, d_from->bd_hlen);
	}
	d_to->bd_hlen = d_from->bd_hlen;
	d_to->bd_hcnt = d_from->bd_hcnt;

	if (bpf_debug > 0) {
		os_log_info(OS_LOG_DEFAULT,
		    "%s: done slen %u scnt %u hlen %u hcnt %u",
		    __func__, d_to->bd_slen, d_to->bd_scnt,
		    d_to->bd_hlen, d_to->bd_hcnt);
	}
done:
	d_from->bd_hbuf_read = 0;
	wakeup((caddr_t)d_from);

	d_to->bd_hbuf_read = 0;
	wakeup((caddr_t)d_to);

	return error;
}

/*
 *  FIONREAD		Check for read packet available.
 *  SIOCGIFADDR		Get interface address - convenient hook to driver.
 *  BIOCGBLEN		Get buffer len [for read()].
 *  BIOCSETF		Set ethernet read filter.
 *  BIOCFLUSH		Flush read packet buffer.
 *  BIOCPROMISC		Put interface into promiscuous mode.
 *  BIOCGDLT		Get link layer type.
 *  BIOCGETIF		Get interface name.
 *  BIOCSETIF		Set interface.
 *  BIOCSRTIMEOUT	Set read timeout.
 *  BIOCGRTIMEOUT	Get read timeout.
 *  BIOCGSTATS		Get packet stats.
 *  BIOCIMMEDIATE	Set immediate mode.
 *  BIOCVERSION		Get filter language version.
 *  BIOCGHDRCMPLT	Get "header already complete" flag
 *  BIOCSHDRCMPLT	Set "header already complete" flag
 *  BIOCGSEESENT	Get "see packets sent" flag
 *  BIOCSSEESENT	Set "see packets sent" flag
 *  BIOCSETTC		Set traffic class.
 *  BIOCGETTC		Get traffic class.
 *  BIOCSEXTHDR		Set "extended header" flag
 *  BIOCSHEADDROP	Drop head of the buffer if user is not reading
 *  BIOCGHEADDROP	Get "head-drop" flag
 */
/* ARGSUSED */
int
bpfioctl(dev_t dev, u_long cmd, caddr_t addr, __unused int flags,
    struct proc *p)
{
	struct bpf_d *d;
	int error = 0;
	u_int int_arg;
	struct ifreq ifr;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == NULL || d == BPF_DEV_RESERVED ||
	    (d->bd_flags & BPF_CLOSING) != 0) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	bpf_acquire_d(d);

	if (d->bd_state == BPF_WAITING) {
		bpf_stop_timer(d);
	}
	d->bd_state = BPF_IDLE;

	switch (cmd) {
	default:
		error = EINVAL;
		break;

	/*
	 * Check for read packet available.
	 */
	case FIONREAD:                  /* int */
	{
		int n;

		n = d->bd_slen;
		if (d->bd_hbuf && d->bd_hbuf_read == 0) {
			n += d->bd_hlen;
		}

		bcopy(&n, addr, sizeof(n));
		break;
	}

	case SIOCGIFADDR:               /* struct ifreq */
	{
		struct ifnet *ifp;

		if (d->bd_bif == 0) {
			error = EINVAL;
		} else {
			ifp = d->bd_bif->bif_ifp;
			error = ifnet_ioctl(ifp, 0, cmd, addr);
		}
		break;
	}

	/*
	 * Get buffer len [for read()].
	 */
	case BIOCGBLEN:                 /* u_int */
		bcopy(&d->bd_bufsize, addr, sizeof(u_int));
		break;

	/*
	 * Set buffer length.
	 */
	case BIOCSBLEN: {               /* u_int */
		u_int size;
		unsigned int maxbufsize = bpf_maxbufsize;

		/*
		 * Allow larger buffer in head drop mode to with the
		 * assumption the reading process may be low priority but
		 * is interested in the most recent traffic
		 */
		if (d->bd_headdrop != 0) {
			maxbufsize = 2 * bpf_maxbufsize;
		}

		if (d->bd_bif != 0 || (d->bd_flags & BPF_DETACHING)) {
			/*
			 * Interface already attached, unable to change buffers
			 */
			error = EINVAL;
			break;
		}
		bcopy(addr, &size, sizeof(size));

		if (size > maxbufsize) {
			d->bd_bufsize = maxbufsize;

			os_log_info(OS_LOG_DEFAULT,
			    "%s bufsize capped to %u from %u",
			    __func__, d->bd_bufsize, size);
		} else if (size < BPF_MINBUFSIZE) {
			d->bd_bufsize = BPF_MINBUFSIZE;

			os_log_info(OS_LOG_DEFAULT,
			    "%s bufsize bumped to %u from %u",
			    __func__, d->bd_bufsize, size);
		} else {
			d->bd_bufsize = size;
		}

		/* It's a read/write ioctl */
		bcopy(&d->bd_bufsize, addr, sizeof(u_int));
		break;
	}
	/*
	 * Set link layer read filter.
	 */
	case BIOCSETF32:
	case BIOCSETFNR32: {            /* struct bpf_program32 */
		struct bpf_program32 prg32;

		bcopy(addr, &prg32, sizeof(prg32));
		error = bpf_setf(d, prg32.bf_len,
		    CAST_USER_ADDR_T(prg32.bf_insns), cmd);
		break;
	}

	case BIOCSETF64:
	case BIOCSETFNR64: {            /* struct bpf_program64 */
		struct bpf_program64 prg64;

		bcopy(addr, &prg64, sizeof(prg64));
		error = bpf_setf(d, prg64.bf_len, prg64.bf_insns, cmd);
		break;
	}

	/*
	 * Flush read packet buffer.
	 */
	case BIOCFLUSH:
		while (d->bd_hbuf_read != 0) {
			msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading",
			    NULL);
		}
		if ((d->bd_flags & BPF_CLOSING) != 0) {
			error = ENXIO;
			break;
		}
		reset_d(d);
		break;

	/*
	 * Put interface into promiscuous mode.
	 */
	case BIOCPROMISC:
		if (d->bd_bif == 0) {
			/*
			 * No interface attached yet.
			 */
			error = EINVAL;
			break;
		}
		if (d->bd_promisc == 0) {
			lck_mtx_unlock(bpf_mlock);
			error = ifnet_set_promiscuous(d->bd_bif->bif_ifp, 1);
			lck_mtx_lock(bpf_mlock);
			if (error == 0) {
				d->bd_promisc = 1;
			}
		}
		break;

	/*
	 * Get device parameters.
	 */
	case BIOCGDLT:                  /* u_int */
		if (d->bd_bif == 0) {
			error = EINVAL;
		} else {
			bcopy(&d->bd_bif->bif_dlt, addr, sizeof(u_int));
		}
		break;

	/*
	 * Get a list of supported data link types.
	 */
	case BIOCGDLTLIST:              /* struct bpf_dltlist */
		if (d->bd_bif == NULL) {
			error = EINVAL;
		} else {
			error = bpf_getdltlist(d, addr, p);
		}
		break;

	/*
	 * Set data link type.
	 */
	case BIOCSDLT:                  /* u_int */
		if (d->bd_bif == NULL) {
			error = EINVAL;
		} else {
			u_int dlt;

			bcopy(addr, &dlt, sizeof(dlt));

			if (dlt == DLT_PKTAP &&
			    !(d->bd_flags & BPF_WANT_PKTAP)) {
				dlt = DLT_RAW;
			}
			error = bpf_setdlt(d, dlt);
		}
		break;

	/*
	 * Get interface name.
	 */
	case BIOCGETIF:                 /* struct ifreq */
		if (d->bd_bif == 0) {
			error = EINVAL;
		} else {
			struct ifnet *const ifp = d->bd_bif->bif_ifp;

			snprintf(((struct ifreq *)(void *)addr)->ifr_name,
			    sizeof(ifr.ifr_name), "%s", if_name(ifp));
		}
		break;

	/*
	 * Set interface.
	 */
	case BIOCSETIF: {               /* struct ifreq */
		ifnet_t ifp;

		bcopy(addr, &ifr, sizeof(ifr));
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
		ifp = ifunit(ifr.ifr_name);
		if (ifp == NULL) {
			error = ENXIO;
		} else {
			error = bpf_setif(d, ifp, true, false);
		}
		break;
	}

	/*
	 * Set read timeout.
	 */
	case BIOCSRTIMEOUT32: {         /* struct user32_timeval */
		struct user32_timeval _tv;
		struct timeval tv;

		bcopy(addr, &_tv, sizeof(_tv));
		tv.tv_sec  = _tv.tv_sec;
		tv.tv_usec = _tv.tv_usec;

		/*
		 * Subtract 1 tick from tvtohz() since this isn't
		 * a one-shot timer.
		 */
		if ((error = itimerfix(&tv)) == 0) {
			d->bd_rtout = tvtohz(&tv) - 1;
		}
		break;
	}

	case BIOCSRTIMEOUT64: {         /* struct user64_timeval */
		struct user64_timeval _tv;
		struct timeval tv;

		bcopy(addr, &_tv, sizeof(_tv));
		tv.tv_sec  = _tv.tv_sec;
		tv.tv_usec = _tv.tv_usec;

		/*
		 * Subtract 1 tick from tvtohz() since this isn't
		 * a one-shot timer.
		 */
		if ((error = itimerfix(&tv)) == 0) {
			d->bd_rtout = tvtohz(&tv) - 1;
		}
		break;
	}

	/*
	 * Get read timeout.
	 */
	case BIOCGRTIMEOUT32: {         /* struct user32_timeval */
		struct user32_timeval tv;

		bzero(&tv, sizeof(tv));
		tv.tv_sec = d->bd_rtout / hz;
		tv.tv_usec = (d->bd_rtout % hz) * tick;
		bcopy(&tv, addr, sizeof(tv));
		break;
	}

	case BIOCGRTIMEOUT64: {         /* struct user64_timeval */
		struct user64_timeval tv;

		bzero(&tv, sizeof(tv));
		tv.tv_sec = d->bd_rtout / hz;
		tv.tv_usec = (d->bd_rtout % hz) * tick;
		bcopy(&tv, addr, sizeof(tv));
		break;
	}

	/*
	 * Get packet stats.
	 */
	case BIOCGSTATS: {              /* struct bpf_stat */
		struct bpf_stat bs;

		bzero(&bs, sizeof(bs));
		bs.bs_recv = d->bd_rcount;
		bs.bs_drop = d->bd_dcount;
		bcopy(&bs, addr, sizeof(bs));
		break;
	}

	/*
	 * Set immediate mode.
	 */
	case BIOCIMMEDIATE:             /* u_int */
		d->bd_immediate = *(u_int *)(void *)addr;
		break;

	case BIOCVERSION: {             /* struct bpf_version */
		struct bpf_version bv;

		bzero(&bv, sizeof(bv));
		bv.bv_major = BPF_MAJOR_VERSION;
		bv.bv_minor = BPF_MINOR_VERSION;
		bcopy(&bv, addr, sizeof(bv));
		break;
	}

	/*
	 * Get "header already complete" flag
	 */
	case BIOCGHDRCMPLT:             /* u_int */
		bcopy(&d->bd_hdrcmplt, addr, sizeof(u_int));
		break;

	/*
	 * Set "header already complete" flag
	 */
	case BIOCSHDRCMPLT:             /* u_int */
		bcopy(addr, &int_arg, sizeof(int_arg));
		d->bd_hdrcmplt = int_arg ? 1 : 0;
		break;

	/*
	 * Get "see sent packets" flag
	 */
	case BIOCGSEESENT:              /* u_int */
		bcopy(&d->bd_seesent, addr, sizeof(u_int));
		break;

	/*
	 * Set "see sent packets" flag
	 */
	case BIOCSSEESENT:              /* u_int */
		bcopy(addr, &d->bd_seesent, sizeof(u_int));
		break;

	/*
	 * Set traffic service class
	 */
	case BIOCSETTC: {               /* int */
		int tc;

		bcopy(addr, &tc, sizeof(int));
		error = bpf_set_traffic_class(d, tc);
		break;
	}

	/*
	 * Get traffic service class
	 */
	case BIOCGETTC:                 /* int */
		bcopy(&d->bd_traffic_class, addr, sizeof(int));
		break;

	case FIONBIO:           /* Non-blocking I/O; int */
		break;

	case FIOASYNC:          /* Send signal on receive packets; int */
		bcopy(addr, &d->bd_async, sizeof(int));
		break;
#ifndef __APPLE__
	case FIOSETOWN:
		error = fsetown(*(int *)addr, &d->bd_sigio);
		break;

	case FIOGETOWN:
		*(int *)addr = fgetown(d->bd_sigio);
		break;

	/* This is deprecated, FIOSETOWN should be used instead. */
	case TIOCSPGRP:
		error = fsetown(-(*(int *)addr), &d->bd_sigio);
		break;

	/* This is deprecated, FIOGETOWN should be used instead. */
	case TIOCGPGRP:
		*(int *)addr = -fgetown(d->bd_sigio);
		break;
#endif
	case BIOCSRSIG: {       /* Set receive signal; u_int */
		u_int sig;

		bcopy(addr, &sig, sizeof(u_int));

		if (sig >= NSIG) {
			error = EINVAL;
		} else {
			d->bd_sig = sig;
		}
		break;
	}
	case BIOCGRSIG:                 /* u_int */
		bcopy(&d->bd_sig, addr, sizeof(u_int));
		break;
#ifdef __APPLE__
	case BIOCSEXTHDR:               /* u_int */
		bcopy(addr, &int_arg, sizeof(int_arg));
		if (int_arg) {
			d->bd_flags |= BPF_EXTENDED_HDR;
		} else {
			d->bd_flags &= ~BPF_EXTENDED_HDR;
		}
		break;

	case BIOCGIFATTACHCOUNT: {              /* struct ifreq */
		ifnet_t ifp;
		struct bpf_if *bp;

		bcopy(addr, &ifr, sizeof(ifr));
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
		ifp = ifunit(ifr.ifr_name);
		if (ifp == NULL) {
			error = ENXIO;
			break;
		}
		ifr.ifr_intval = 0;
		for (bp = bpf_iflist; bp != 0; bp = bp->bif_next) {
			struct bpf_d *bpf_d;

			if (bp->bif_ifp == NULL || bp->bif_ifp != ifp) {
				continue;
			}
			for (bpf_d = bp->bif_dlist; bpf_d;
			    bpf_d = bpf_d->bd_next) {
				ifr.ifr_intval += 1;
			}
		}
		bcopy(&ifr, addr, sizeof(ifr));
		break;
	}
	case BIOCGWANTPKTAP:                    /* u_int */
		int_arg = d->bd_flags & BPF_WANT_PKTAP ? 1 : 0;
		bcopy(&int_arg, addr, sizeof(int_arg));
		break;

	case BIOCSWANTPKTAP:                    /* u_int */
		bcopy(addr, &int_arg, sizeof(int_arg));
		if (int_arg) {
			d->bd_flags |= BPF_WANT_PKTAP;
		} else {
			d->bd_flags &= ~BPF_WANT_PKTAP;
		}
		break;
#endif

	case BIOCSHEADDROP:
		bcopy(addr, &int_arg, sizeof(int_arg));
		d->bd_headdrop = int_arg ? 1 : 0;
		break;

	case BIOCGHEADDROP:
		bcopy(&d->bd_headdrop, addr, sizeof(int));
		break;

	case BIOCSTRUNCATE:
		bcopy(addr, &int_arg, sizeof(int_arg));
		if (int_arg) {
			d->bd_flags |=  BPF_TRUNCATE;
		} else {
			d->bd_flags &= ~BPF_TRUNCATE;
		}
		break;

	case BIOCGETUUID:
		bcopy(&d->bd_uuid, addr, sizeof(uuid_t));
		break;

	case BIOCSETUP: {
		struct bpf_setup_args bsa;
		ifnet_t ifp;

		bcopy(addr, &bsa, sizeof(struct bpf_setup_args));
		bsa.bsa_ifname[IFNAMSIZ - 1] = 0;
		ifp = ifunit(bsa.bsa_ifname);
		if (ifp == NULL) {
			error = ENXIO;
			os_log_info(OS_LOG_DEFAULT,
			    "%s: ifnet not found for %s error %d",
			    __func__, bsa.bsa_ifname, error);
			break;
		}

		error = bpf_setup(d, bsa.bsa_uuid, ifp);
		break;
	}
	case BIOCSPKTHDRV2:
		bcopy(addr, &int_arg, sizeof(int_arg));
		if (int_arg != 0) {
			d->bd_flags |= BPF_PKTHDRV2;
		} else {
			d->bd_flags &= ~BPF_PKTHDRV2;
		}
		break;

	case BIOCGPKTHDRV2:
		int_arg = d->bd_flags & BPF_PKTHDRV2 ? 1 : 0;
		bcopy(&int_arg, addr, sizeof(int));
		break;
	}

	bpf_release_d(d);
	lck_mtx_unlock(bpf_mlock);

	return error;
}

/*
 * Set d's packet filter program to fp.  If this file already has a filter,
 * free it and replace it.  Returns EINVAL for bogus requests.
 */
static int
bpf_setf(struct bpf_d *d, u_int bf_len, user_addr_t bf_insns,
    u_long cmd)
{
	struct bpf_insn *fcode, *old;
	u_int flen, size;

	while (d->bd_hbuf_read != 0) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	if ((d->bd_flags & BPF_CLOSING) != 0) {
		return ENXIO;
	}

	old = d->bd_filter;
	if (bf_insns == USER_ADDR_NULL) {
		if (bf_len != 0) {
			return EINVAL;
		}
		d->bd_filter = NULL;
		reset_d(d);
		if (old != 0) {
			FREE(old, M_DEVBUF);
		}
		return 0;
	}
	flen = bf_len;
	if (flen > BPF_MAXINSNS) {
		return EINVAL;
	}

	size = flen * sizeof(struct bpf_insn);
	fcode = (struct bpf_insn *) _MALLOC(size, M_DEVBUF, M_WAIT);
#ifdef __APPLE__
	if (fcode == NULL) {
		return ENOBUFS;
	}
#endif
	if (copyin(bf_insns, (caddr_t)fcode, size) == 0 &&
	    bpf_validate(fcode, (int)flen)) {
		d->bd_filter = fcode;

		if (cmd == BIOCSETF32 || cmd == BIOCSETF64) {
			reset_d(d);
		}

		if (old != 0) {
			FREE(old, M_DEVBUF);
		}

		return 0;
	}
	FREE(fcode, M_DEVBUF);
	return EINVAL;
}

/*
 * Detach a file from its current interface (if attached at all) and attach
 * to the interface indicated by the name stored in ifr.
 * Return an errno or 0.
 */
static int
bpf_setif(struct bpf_d *d, ifnet_t theywant, bool do_reset, bool has_hbuf_read)
{
	struct bpf_if *bp;
	int error;

	while (d->bd_hbuf_read != 0 && !has_hbuf_read) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	if ((d->bd_flags & BPF_CLOSING) != 0) {
		return ENXIO;
	}

	/*
	 * Look through attached interfaces for the named one.
	 */
	for (bp = bpf_iflist; bp != 0; bp = bp->bif_next) {
		struct ifnet *ifp = bp->bif_ifp;

		if (ifp == 0 || ifp != theywant) {
			continue;
		}
		/*
		 * Do not use DLT_PKTAP, unless requested explicitly
		 */
		if (bp->bif_dlt == DLT_PKTAP && !(d->bd_flags & BPF_WANT_PKTAP)) {
			continue;
		}
		/*
		 * Skip the coprocessor interface
		 */
		if (!intcoproc_unrestricted && IFNET_IS_INTCOPROC(ifp)) {
			continue;
		}
		/*
		 * We found the requested interface.
		 * Allocate the packet buffers.
		 */
		error = bpf_allocbufs(d);
		if (error != 0) {
			return error;
		}
		/*
		 * Detach if attached to something else.
		 */
		if (bp != d->bd_bif) {
			if (d->bd_bif != NULL) {
				if (bpf_detachd(d, 0) != 0) {
					return ENXIO;
				}
			}
			if (bpf_attachd(d, bp) != 0) {
				return ENXIO;
			}
		}
		if (do_reset) {
			reset_d(d);
		}
		return 0;
	}
	/* Not found. */
	return ENXIO;
}

/*
 * Get a list of available data link type of the interface.
 */
static int
bpf_getdltlist(struct bpf_d *d, caddr_t addr, struct proc *p)
{
	u_int           n;
	int             error;
	struct ifnet    *ifp;
	struct bpf_if   *bp;
	user_addr_t     dlist;
	struct bpf_dltlist bfl;

	bcopy(addr, &bfl, sizeof(bfl));
	if (proc_is64bit(p)) {
		dlist = (user_addr_t)bfl.bfl_u.bflu_pad;
	} else {
		dlist = CAST_USER_ADDR_T(bfl.bfl_u.bflu_list);
	}

	ifp = d->bd_bif->bif_ifp;
	n = 0;
	error = 0;

	for (bp = bpf_iflist; bp; bp = bp->bif_next) {
		if (bp->bif_ifp != ifp) {
			continue;
		}
		/*
		 * Do not use DLT_PKTAP, unless requested explicitly
		 */
		if (bp->bif_dlt == DLT_PKTAP && !(d->bd_flags & BPF_WANT_PKTAP)) {
			continue;
		}
		if (dlist != USER_ADDR_NULL) {
			if (n >= bfl.bfl_len) {
				return ENOMEM;
			}
			error = copyout(&bp->bif_dlt, dlist,
			    sizeof(bp->bif_dlt));
			if (error != 0) {
				break;
			}
			dlist += sizeof(bp->bif_dlt);
		}
		n++;
	}
	bfl.bfl_len = n;
	bcopy(&bfl, addr, sizeof(bfl));

	return error;
}

/*
 * Set the data link type of a BPF instance.
 */
static int
bpf_setdlt(struct bpf_d *d, uint32_t dlt)
{
	int error, opromisc;
	struct ifnet *ifp;
	struct bpf_if *bp;

	if (d->bd_bif->bif_dlt == dlt) {
		return 0;
	}

	while (d->bd_hbuf_read != 0) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	if ((d->bd_flags & BPF_CLOSING) != 0) {
		return ENXIO;
	}

	ifp = d->bd_bif->bif_ifp;
	for (bp = bpf_iflist; bp; bp = bp->bif_next) {
		if (bp->bif_ifp == ifp && bp->bif_dlt == dlt) {
			/*
			 * Do not use DLT_PKTAP, unless requested explicitly
			 */
			if (bp->bif_dlt == DLT_PKTAP &&
			    !(d->bd_flags & BPF_WANT_PKTAP)) {
				continue;
			}
			break;
		}
	}
	if (bp != NULL) {
		opromisc = d->bd_promisc;
		if (bpf_detachd(d, 0) != 0) {
			return ENXIO;
		}
		error = bpf_attachd(d, bp);
		if (error) {
			printf("bpf_setdlt: bpf_attachd %s%d failed (%d)\n",
			    ifnet_name(bp->bif_ifp), ifnet_unit(bp->bif_ifp),
			    error);
			return error;
		}
		reset_d(d);
		if (opromisc) {
			lck_mtx_unlock(bpf_mlock);
			error = ifnet_set_promiscuous(bp->bif_ifp, 1);
			lck_mtx_lock(bpf_mlock);
			if (error) {
				printf("%s: ifpromisc %s%d failed (%d)\n",
				    __func__, ifnet_name(bp->bif_ifp),
				    ifnet_unit(bp->bif_ifp), error);
			} else {
				d->bd_promisc = 1;
			}
		}
	}
	return bp == NULL ? EINVAL : 0;
}

static int
bpf_set_traffic_class(struct bpf_d *d, int tc)
{
	int error = 0;

	if (!SO_VALID_TC(tc)) {
		error = EINVAL;
	} else {
		d->bd_traffic_class = tc;
	}

	return error;
}

static void
bpf_set_packet_service_class(struct mbuf *m, int tc)
{
	if (!(m->m_flags & M_PKTHDR)) {
		return;
	}

	VERIFY(SO_VALID_TC(tc));
	(void) m_set_service_class(m, so_tc2msc(tc));
}

/*
 * Support for select()
 *
 * Return true iff the specific operation will not block indefinitely.
 * Otherwise, return false but make a note that a selwakeup() must be done.
 */
int
bpfselect(dev_t dev, int which, void * wql, struct proc *p)
{
	struct bpf_d *d;
	int ret = 0;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == NULL || d == BPF_DEV_RESERVED ||
	    (d->bd_flags & BPF_CLOSING) != 0) {
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	bpf_acquire_d(d);

	if (d->bd_bif == NULL) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	while (d->bd_hbuf_read != 0) {
		msleep((caddr_t)d, bpf_mlock, PRINET, "bpf_reading", NULL);
	}

	if ((d->bd_flags & BPF_CLOSING) != 0) {
		bpf_release_d(d);
		lck_mtx_unlock(bpf_mlock);
		return ENXIO;
	}

	switch (which) {
	case FREAD:
		if (d->bd_hlen != 0 ||
		    ((d->bd_immediate ||
		    d->bd_state == BPF_TIMED_OUT) && d->bd_slen != 0)) {
			ret = 1;         /* read has data to return */
		} else {
			/*
			 * Read has no data to return.
			 * Make the select wait, and start a timer if
			 * necessary.
			 */
			selrecord(p, &d->bd_sel, wql);
			bpf_start_timer(d);
		}
		break;

	case FWRITE:
		/* can't determine whether a write would block */
		ret = 1;
		break;
	}

	bpf_release_d(d);
	lck_mtx_unlock(bpf_mlock);

	return ret;
}

/*
 * Support for kevent() system call.  Register EVFILT_READ filters and
 * reject all others.
 */
int bpfkqfilter(dev_t dev, struct knote *kn);
static void filt_bpfdetach(struct knote *);
static int filt_bpfread(struct knote *, long);
static int filt_bpftouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_bpfprocess(struct knote *kn, struct filt_process_s *data,
    struct kevent_internal_s *kev);

SECURITY_READ_ONLY_EARLY(struct filterops) bpfread_filtops = {
	.f_isfd = 1,
	.f_detach = filt_bpfdetach,
	.f_event = filt_bpfread,
	.f_touch = filt_bpftouch,
	.f_process = filt_bpfprocess,
};

static int
filt_bpfread_common(struct knote *kn, struct bpf_d *d)
{
	int ready = 0;

	if (d->bd_immediate) {
		/*
		 * If there's data in the hold buffer, it's the
		 * amount of data a read will return.
		 *
		 * If there's no data in the hold buffer, but
		 * there's data in the store buffer, a read will
		 * immediately rotate the store buffer to the
		 * hold buffer, the amount of data in the store
		 * buffer is the amount of data a read will
		 * return.
		 *
		 * If there's no data in either buffer, we're not
		 * ready to read.
		 */
		kn->kn_data = (d->bd_hlen == 0 || d->bd_hbuf_read != 0 ?
		    d->bd_slen : d->bd_hlen);
		int64_t lowwat = 1;
		if (kn->kn_sfflags & NOTE_LOWAT) {
			if (kn->kn_sdata > d->bd_bufsize) {
				lowwat = d->bd_bufsize;
			} else if (kn->kn_sdata > lowwat) {
				lowwat = kn->kn_sdata;
			}
		}
		ready = (kn->kn_data >= lowwat);
	} else {
		/*
		 * If there's data in the hold buffer, it's the
		 * amount of data a read will return.
		 *
		 * If there's no data in the hold buffer, but
		 * there's data in the store buffer, if the
		 * timer has expired a read will immediately
		 * rotate the store buffer to the hold buffer,
		 * so the amount of data in the store buffer is
		 * the amount of data a read will return.
		 *
		 * If there's no data in either buffer, or there's
		 * no data in the hold buffer and the timer hasn't
		 * expired, we're not ready to read.
		 */
		kn->kn_data = ((d->bd_hlen == 0 || d->bd_hbuf_read != 0) &&
		    d->bd_state == BPF_TIMED_OUT ? d->bd_slen : d->bd_hlen);
		ready = (kn->kn_data > 0);
	}
	if (!ready) {
		bpf_start_timer(d);
	}

	return ready;
}

int
bpfkqfilter(dev_t dev, struct knote *kn)
{
	struct bpf_d *d;
	int res;

	/*
	 * Is this device a bpf?
	 */
	if (major(dev) != CDEV_MAJOR ||
	    kn->kn_filter != EVFILT_READ) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return 0;
	}

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];

	if (d == NULL || d == BPF_DEV_RESERVED ||
	    (d->bd_flags & BPF_CLOSING) != 0 ||
	    d->bd_bif == NULL) {
		lck_mtx_unlock(bpf_mlock);
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENXIO;
		return 0;
	}

	kn->kn_hook = d;
	kn->kn_filtid = EVFILTID_BPFREAD;
	KNOTE_ATTACH(&d->bd_sel.si_note, kn);
	d->bd_flags |= BPF_KNOTE;

	/* capture the current state */
	res = filt_bpfread_common(kn, d);

	lck_mtx_unlock(bpf_mlock);

	return res;
}

static void
filt_bpfdetach(struct knote *kn)
{
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;

	lck_mtx_lock(bpf_mlock);
	if (d->bd_flags & BPF_KNOTE) {
		KNOTE_DETACH(&d->bd_sel.si_note, kn);
		d->bd_flags &= ~BPF_KNOTE;
	}
	lck_mtx_unlock(bpf_mlock);
}

static int
filt_bpfread(struct knote *kn, long hint)
{
#pragma unused(hint)
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;

	return filt_bpfread_common(kn, d);
}

static int
filt_bpftouch(struct knote *kn, struct kevent_internal_s *kev)
{
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;
	int res;

	lck_mtx_lock(bpf_mlock);

	/* save off the lowat threshold and flag */
	kn->kn_sdata = kev->data;
	kn->kn_sfflags = kev->fflags;

	/* output data will be re-generated here */
	res = filt_bpfread_common(kn, d);

	lck_mtx_unlock(bpf_mlock);

	return res;
}

static int
filt_bpfprocess(struct knote *kn, struct filt_process_s *data,
    struct kevent_internal_s *kev)
{
#pragma unused(data)
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;
	int res;

	lck_mtx_lock(bpf_mlock);
	res = filt_bpfread_common(kn, d);
	if (res) {
		*kev = kn->kn_kevent;
	}
	lck_mtx_unlock(bpf_mlock);

	return res;
}

/*
 * Copy data from an mbuf chain into a buffer.	This code is derived
 * from m_copydata in kern/uipc_mbuf.c.
 */
static void
bpf_mcopy(struct mbuf * m, void *dst_arg, size_t len)
{
	u_int count;
	u_char *dst;

	dst = dst_arg;
	while (len > 0) {
		if (m == 0) {
			panic("bpf_mcopy");
		}
		count = min(m->m_len, len);
		bcopy(mbuf_data(m), dst, count);
		m = m->m_next;
		dst += count;
		len -= count;
	}
}

static inline void
bpf_tap_imp(
	ifnet_t         ifp,
	u_int32_t       dlt,
	struct bpf_packet *bpf_pkt,
	int             outbound)
{
	struct bpf_d    *d;
	u_int slen;
	struct bpf_if *bp;

	/*
	 * It's possible that we get here after the bpf descriptor has been
	 * detached from the interface; in such a case we simply return.
	 * Lock ordering is important since we can be called asynchronously
	 * (from IOKit) to process an inbound packet; when that happens
	 * we would have been holding its "gateLock" and will be acquiring
	 * "bpf_mlock" upon entering this routine.  Due to that, we release
	 * "bpf_mlock" prior to calling ifnet_set_promiscuous (which will
	 * acquire "gateLock" in the IOKit), in order to avoid a deadlock
	 * when a ifnet_set_promiscuous request simultaneously collides with
	 * an inbound packet being passed into the tap callback.
	 */
	lck_mtx_lock(bpf_mlock);
	if (ifp->if_bpf == NULL) {
		lck_mtx_unlock(bpf_mlock);
		return;
	}
	for (bp = ifp->if_bpf; bp != NULL; bp = bp->bif_next) {
		if (bp->bif_ifp != ifp) {
			/* wrong interface */
			bp = NULL;
			break;
		}
		if (dlt == 0 || bp->bif_dlt == dlt) {
			/* tapping default DLT or DLT matches */
			break;
		}
	}
	if (bp == NULL) {
		goto done;
	}
	for (d = bp->bif_dlist; d; d = d->bd_next) {
		struct bpf_packet *bpf_pkt_saved = bpf_pkt;
		struct bpf_packet bpf_pkt_tmp;
		struct pktap_header_buffer bpfp_header_tmp;

		if (outbound && !d->bd_seesent) {
			continue;
		}

		++d->bd_rcount;
		slen = bpf_filter(d->bd_filter, (u_char *)bpf_pkt,
		    bpf_pkt->bpfp_total_length, 0);
		if (bp->bif_ifp->if_type == IFT_PKTAP &&
		    bp->bif_dlt == DLT_PKTAP) {
			/*
			 * Need to copy the bpf_pkt because the conversion
			 * to v2 pktap header modifies the content of the
			 * bpfp_header
			 */
			if ((d->bd_flags & BPF_PKTHDRV2) &&
			    bpf_pkt->bpfp_header_length <= sizeof(bpfp_header_tmp)) {
				bpf_pkt_tmp = *bpf_pkt;

				bpf_pkt = &bpf_pkt_tmp;

				memcpy(&bpfp_header_tmp, bpf_pkt->bpfp_header,
				    bpf_pkt->bpfp_header_length);

				bpf_pkt->bpfp_header = &bpfp_header_tmp;

				convert_to_pktap_header_to_v2(bpf_pkt,
				    !!(d->bd_flags & BPF_TRUNCATE));
			}

			if (d->bd_flags & BPF_TRUNCATE) {
				slen = min(slen,
				    get_pkt_trunc_len((u_char *)bpf_pkt,
				    bpf_pkt->bpfp_total_length));
			}
		}
		if (slen != 0) {
#if CONFIG_MACF_NET
			if (mac_bpfdesc_check_receive(d, bp->bif_ifp) != 0) {
				continue;
			}
#endif
			catchpacket(d, bpf_pkt, slen, outbound);
		}
		bpf_pkt = bpf_pkt_saved;
	}

done:
	lck_mtx_unlock(bpf_mlock);
}

static inline void
bpf_tap_mbuf(
	ifnet_t         ifp,
	u_int32_t       dlt,
	mbuf_t          m,
	void*           hdr,
	size_t          hlen,
	int             outbound)
{
	struct bpf_packet bpf_pkt;
	struct mbuf *m0;

	if (ifp->if_bpf == NULL) {
		/* quickly check without taking lock */
		return;
	}
	bpf_pkt.bpfp_type = BPF_PACKET_TYPE_MBUF;
	bpf_pkt.bpfp_mbuf = m;
	bpf_pkt.bpfp_total_length = 0;
	for (m0 = m; m0 != NULL; m0 = m0->m_next) {
		bpf_pkt.bpfp_total_length += m0->m_len;
	}
	bpf_pkt.bpfp_header = hdr;
	if (hdr != NULL) {
		bpf_pkt.bpfp_total_length += hlen;
		bpf_pkt.bpfp_header_length = hlen;
	} else {
		bpf_pkt.bpfp_header_length = 0;
	}
	bpf_tap_imp(ifp, dlt, &bpf_pkt, outbound);
}

void
bpf_tap_out(
	ifnet_t         ifp,
	u_int32_t       dlt,
	mbuf_t          m,
	void*           hdr,
	size_t          hlen)
{
	bpf_tap_mbuf(ifp, dlt, m, hdr, hlen, 1);
}

void
bpf_tap_in(
	ifnet_t         ifp,
	u_int32_t       dlt,
	mbuf_t          m,
	void*           hdr,
	size_t          hlen)
{
	bpf_tap_mbuf(ifp, dlt, m, hdr, hlen, 0);
}

/* Callback registered with Ethernet driver. */
static int
bpf_tap_callback(struct ifnet *ifp, struct mbuf *m)
{
	bpf_tap_mbuf(ifp, 0, m, NULL, 0, mbuf_pkthdr_rcvif(m) == NULL);

	return 0;
}


static errno_t
bpf_copydata(struct bpf_packet *pkt, size_t off, size_t len, void* out_data)
{
	errno_t err = 0;
	if (pkt->bpfp_type == BPF_PACKET_TYPE_MBUF) {
		err = mbuf_copydata(pkt->bpfp_mbuf, off, len, out_data);
	} else {
		err = EINVAL;
	}

	return err;
}

static void
copy_bpf_packet(struct bpf_packet * pkt, void * dst, size_t len)
{
	/* copy the optional header */
	if (pkt->bpfp_header_length != 0) {
		size_t  count = min(len, pkt->bpfp_header_length);
		bcopy(pkt->bpfp_header, dst, count);
		len -= count;
		dst += count;
	}
	if (len == 0) {
		/* nothing past the header */
		return;
	}
	/* copy the packet */
	switch (pkt->bpfp_type) {
	case BPF_PACKET_TYPE_MBUF:
		bpf_mcopy(pkt->bpfp_mbuf, dst, len);
		break;
	default:
		break;
	}
}

static uint16_t
get_esp_trunc_len(__unused struct bpf_packet *pkt, __unused uint16_t off,
    const uint16_t remaining_caplen)
{
	/*
	 * For some reason tcpdump expects to have one byte beyond the ESP header
	 */
	uint16_t trunc_len = ESP_HDR_SIZE + 1;

	if (trunc_len > remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_isakmp_trunc_len(__unused struct bpf_packet *pkt, __unused uint16_t off,
    const uint16_t remaining_caplen)
{
	/*
	 * Include the payload generic header
	 */
	uint16_t trunc_len = ISAKMP_HDR_SIZE;

	if (trunc_len > remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_isakmp_natt_trunc_len(struct bpf_packet *pkt, uint16_t off,
    const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t trunc_len = 0;
	char payload[remaining_caplen];

	err = bpf_copydata(pkt, off, remaining_caplen, payload);
	if (err != 0) {
		return remaining_caplen;
	}
	/*
	 * They are three cases:
	 * - IKE: payload start with 4 bytes header set to zero before ISAKMP header
	 * - keep alive: 1 byte payload
	 * - otherwise it's ESP
	 */
	if (remaining_caplen >= 4 &&
	    payload[0] == 0 && payload[1] == 0 &&
	    payload[2] == 0 && payload[3] == 0) {
		trunc_len = 4 + get_isakmp_trunc_len(pkt, off + 4, remaining_caplen - 4);
	} else if (remaining_caplen == 1) {
		trunc_len = 1;
	} else {
		trunc_len = get_esp_trunc_len(pkt, off, remaining_caplen);
	}

	if (trunc_len > remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_udp_trunc_len(struct bpf_packet *pkt, uint16_t off, const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t trunc_len = sizeof(struct udphdr); /* By default no UDP payload */

	if (trunc_len >= remaining_caplen) {
		return remaining_caplen;
	}

	struct udphdr udphdr;
	err = bpf_copydata(pkt, off, sizeof(struct udphdr), &udphdr);
	if (err != 0) {
		return remaining_caplen;
	}

	u_short sport, dport;

	sport = EXTRACT_SHORT(&udphdr.uh_sport);
	dport = EXTRACT_SHORT(&udphdr.uh_dport);

	if (dport == PORT_DNS || sport == PORT_DNS) {
		/*
		 * Full UDP payload for DNS
		 */
		trunc_len = remaining_caplen;
	} else if ((sport == PORT_BOOTPS && dport == PORT_BOOTPC) ||
	    (sport == PORT_BOOTPC && dport == PORT_BOOTPS)) {
		/*
		 * Full UDP payload for BOOTP and DHCP
		 */
		trunc_len = remaining_caplen;
	} else if (dport == PORT_ISAKMP && sport == PORT_ISAKMP) {
		/*
		 * Return the ISAKMP header
		 */
		trunc_len += get_isakmp_trunc_len(pkt, off + sizeof(struct udphdr),
		    remaining_caplen - sizeof(struct udphdr));
	} else if (dport == PORT_ISAKMP_NATT && sport == PORT_ISAKMP_NATT) {
		trunc_len += get_isakmp_natt_trunc_len(pkt, off + sizeof(struct udphdr),
		    remaining_caplen - sizeof(struct udphdr));
	}
	if (trunc_len >= remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_tcp_trunc_len(struct bpf_packet *pkt, uint16_t off, const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t trunc_len = sizeof(struct tcphdr); /* By default no TCP payload */
	if (trunc_len >= remaining_caplen) {
		return remaining_caplen;
	}

	struct tcphdr tcphdr;
	err = bpf_copydata(pkt, off, sizeof(struct tcphdr), &tcphdr);
	if (err != 0) {
		return remaining_caplen;
	}

	u_short sport, dport;
	sport = EXTRACT_SHORT(&tcphdr.th_sport);
	dport = EXTRACT_SHORT(&tcphdr.th_dport);

	if (dport == PORT_DNS || sport == PORT_DNS) {
		/*
		 * Full TCP payload  for DNS
		 */
		trunc_len = remaining_caplen;
	} else {
		trunc_len = tcphdr.th_off << 2;
	}
	if (trunc_len >= remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_proto_trunc_len(uint8_t proto, struct bpf_packet *pkt, uint16_t off, const uint16_t remaining_caplen)
{
	uint16_t trunc_len;

	switch (proto) {
	case IPPROTO_ICMP: {
		/*
		 * Full IMCP payload
		 */
		trunc_len = remaining_caplen;
		break;
	}
	case IPPROTO_ICMPV6: {
		/*
		 * Full IMCPV6 payload
		 */
		trunc_len = remaining_caplen;
		break;
	}
	case IPPROTO_IGMP: {
		/*
		 * Full IGMP payload
		 */
		trunc_len = remaining_caplen;
		break;
	}
	case IPPROTO_UDP: {
		trunc_len = get_udp_trunc_len(pkt, off, remaining_caplen);
		break;
	}
	case IPPROTO_TCP: {
		trunc_len = get_tcp_trunc_len(pkt, off, remaining_caplen);
		break;
	}
	case IPPROTO_ESP: {
		trunc_len = get_esp_trunc_len(pkt, off, remaining_caplen);
		break;
	}
	default: {
		/*
		 * By default we only include the IP header
		 */
		trunc_len = 0;
		break;
	}
	}
	if (trunc_len >= remaining_caplen) {
		return remaining_caplen;
	}

	return trunc_len;
}

static uint16_t
get_ip_trunc_len(struct bpf_packet *pkt, uint16_t off, const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t iplen = sizeof(struct ip);
	if (iplen >= remaining_caplen) {
		return remaining_caplen;
	}

	struct ip iphdr;
	err =  bpf_copydata(pkt, off, sizeof(struct ip), &iphdr);
	if (err != 0) {
		return remaining_caplen;
	}

	uint8_t proto = 0;

	iplen = iphdr.ip_hl << 2;
	if (iplen >= remaining_caplen) {
		return remaining_caplen;
	}

	proto = iphdr.ip_p;
	iplen += get_proto_trunc_len(proto, pkt, off + iplen, remaining_caplen - iplen);

	if (iplen >= remaining_caplen) {
		return remaining_caplen;
	}

	return iplen;
}

static uint16_t
get_ip6_trunc_len(struct bpf_packet *pkt, uint16_t off, const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t iplen = sizeof(struct ip6_hdr);
	if (iplen >= remaining_caplen) {
		return remaining_caplen;
	}

	struct ip6_hdr ip6hdr;
	err = bpf_copydata(pkt, off, sizeof(struct ip6_hdr), &ip6hdr);
	if (err != 0) {
		return remaining_caplen;
	}

	uint8_t proto = 0;

	/*
	 * TBD: process the extension headers
	 */
	proto = ip6hdr.ip6_nxt;
	iplen += get_proto_trunc_len(proto, pkt, off + iplen, remaining_caplen - iplen);

	if (iplen >= remaining_caplen) {
		return remaining_caplen;
	}

	return iplen;
}

static uint16_t
get_ether_trunc_len(struct bpf_packet *pkt, int off, const uint16_t remaining_caplen)
{
	int err = 0;
	uint16_t ethlen = sizeof(struct ether_header);
	if (ethlen >= remaining_caplen) {
		return remaining_caplen;
	}

	struct ether_header eh;
	u_short type;
	err = bpf_copydata(pkt, off, sizeof(struct ether_header), &eh);
	if (err != 0) {
		return remaining_caplen;
	}

	type = EXTRACT_SHORT(&eh.ether_type);
	/* Include full ARP */
	if (type == ETHERTYPE_ARP) {
		ethlen = remaining_caplen;
	} else if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6) {
		ethlen = min(BPF_MIN_PKT_SIZE, remaining_caplen);
	} else {
		if (type == ETHERTYPE_IP) {
			ethlen += get_ip_trunc_len(pkt, sizeof(struct ether_header),
			    remaining_caplen);
		} else if (type == ETHERTYPE_IPV6) {
			ethlen += get_ip6_trunc_len(pkt, sizeof(struct ether_header),
			    remaining_caplen);
		}
	}
	return ethlen;
}

static uint32_t
get_pkt_trunc_len(u_char *p, u_int len)
{
	struct bpf_packet *pkt = (struct bpf_packet *)(void *) p;
	struct pktap_header *pktap = (struct pktap_header *) (pkt->bpfp_header);
	uint32_t out_pkt_len = 0, tlen = 0;
	/*
	 * pktap->pth_frame_pre_length is L2 header length and accounts
	 * for both pre and pre_adjust.
	 * pktap->pth_length is sizeof(pktap_header) (excl the pre/pre_adjust)
	 * pkt->bpfp_header_length is (pktap->pth_length + pre_adjust)
	 * pre is the offset to the L3 header after the bpfp_header, or length
	 * of L2 header after bpfp_header, if present.
	 */
	uint32_t pre = pktap->pth_frame_pre_length -
	    (pkt->bpfp_header_length - pktap->pth_length);

	/* Length of the input packet starting from  L3 header */
	uint32_t in_pkt_len = len - pkt->bpfp_header_length - pre;
	if (pktap->pth_protocol_family == AF_INET ||
	    pktap->pth_protocol_family == AF_INET6) {
		/* Contains L2 header */
		if (pre > 0) {
			if (pre < sizeof(struct ether_header)) {
				goto too_short;
			}

			out_pkt_len = get_ether_trunc_len(pkt, 0, in_pkt_len);
		} else if (pre == 0) {
			if (pktap->pth_protocol_family == AF_INET) {
				out_pkt_len = get_ip_trunc_len(pkt, pre, in_pkt_len);
			} else if (pktap->pth_protocol_family == AF_INET6) {
				out_pkt_len = get_ip6_trunc_len(pkt, pre, in_pkt_len);
			}
		} else {
			/* Ideally pre should be >= 0. This is an exception */
			out_pkt_len = min(BPF_MIN_PKT_SIZE, in_pkt_len);
		}
	} else {
		if (pktap->pth_iftype == IFT_ETHER) {
			if (in_pkt_len < sizeof(struct ether_header)) {
				goto too_short;
			}
			/* At most include the Ethernet header and 16 bytes */
			out_pkt_len = MIN(sizeof(struct ether_header) + 16,
			    in_pkt_len);
		} else {
			/*
			 * For unknown protocols include at most 16 bytes
			 */
			out_pkt_len = MIN(16, in_pkt_len);
		}
	}
done:
	tlen = pkt->bpfp_header_length + out_pkt_len + pre;
	return tlen;
too_short:
	out_pkt_len = in_pkt_len;
	goto done;
}

/*
 * Move the packet data from interface memory (pkt) into the
 * store buffer.  Return 1 if it's time to wakeup a listener (buffer full),
 * otherwise 0.
 */
static void
catchpacket(struct bpf_d *d, struct bpf_packet * pkt,
    u_int snaplen, int outbound)
{
	struct bpf_hdr *hp;
	struct bpf_hdr_ext *ehp;
	int totlen, curlen;
	int hdrlen, caplen;
	int do_wakeup = 0;
	u_char *payload;
	struct timeval tv;

	hdrlen = (d->bd_flags & BPF_EXTENDED_HDR) ? d->bd_bif->bif_exthdrlen :
	    d->bd_bif->bif_hdrlen;
	/*
	 * Figure out how many bytes to move.  If the packet is
	 * greater or equal to the snapshot length, transfer that
	 * much.  Otherwise, transfer the whole packet (unless
	 * we hit the buffer size limit).
	 */
	totlen = hdrlen + min(snaplen, pkt->bpfp_total_length);
	if (totlen > d->bd_bufsize) {
		totlen = d->bd_bufsize;
	}

	if (hdrlen > totlen) {
		return;
	}

	/*
	 * Round up the end of the previous packet to the next longword.
	 */
	curlen = BPF_WORDALIGN(d->bd_slen);
	if (curlen + totlen > d->bd_bufsize) {
		/*
		 * This packet will overflow the storage buffer.
		 * Rotate the buffers if we can, then wakeup any
		 * pending reads.
		 *
		 * We cannot rotate buffers if a read is in progress
		 * so drop the packet
		 */
		if (d->bd_hbuf_read != 0) {
			++d->bd_dcount;
			return;
		}

		if (d->bd_fbuf == NULL) {
			if (d->bd_headdrop == 0) {
				/*
				 * We haven't completed the previous read yet,
				 * so drop the packet.
				 */
				++d->bd_dcount;
				return;
			}
			/*
			 * Drop the hold buffer as it contains older packets
			 */
			d->bd_dcount += d->bd_hcnt;
			d->bd_fbuf = d->bd_hbuf;
			ROTATE_BUFFERS(d);
		} else {
			ROTATE_BUFFERS(d);
		}
		do_wakeup = 1;
		curlen = 0;
	} else if (d->bd_immediate || d->bd_state == BPF_TIMED_OUT) {
		/*
		 * Immediate mode is set, or the read timeout has
		 * already expired during a select call. A packet
		 * arrived, so the reader should be woken up.
		 */
		do_wakeup = 1;
	}

	/*
	 * Append the bpf header.
	 */
	microtime(&tv);
	if (d->bd_flags & BPF_EXTENDED_HDR) {
		struct mbuf *m;

		m = (pkt->bpfp_type == BPF_PACKET_TYPE_MBUF)
		    ? pkt->bpfp_mbuf : NULL;
		ehp = (struct bpf_hdr_ext *)(void *)(d->bd_sbuf + curlen);
		memset(ehp, 0, sizeof(*ehp));
		ehp->bh_tstamp.tv_sec = tv.tv_sec;
		ehp->bh_tstamp.tv_usec = tv.tv_usec;

		ehp->bh_datalen = pkt->bpfp_total_length;
		ehp->bh_hdrlen = hdrlen;
		caplen = ehp->bh_caplen = totlen - hdrlen;
		if (m == NULL) {
			if (outbound) {
				ehp->bh_flags |= BPF_HDR_EXT_FLAGS_DIR_OUT;
			} else {
				ehp->bh_flags |= BPF_HDR_EXT_FLAGS_DIR_IN;
			}
		} else if (outbound) {
			ehp->bh_flags |= BPF_HDR_EXT_FLAGS_DIR_OUT;

			/* only do lookups on non-raw INPCB */
			if ((m->m_pkthdr.pkt_flags & (PKTF_FLOW_ID |
			    PKTF_FLOW_LOCALSRC | PKTF_FLOW_RAWSOCK)) ==
			    (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC) &&
			    m->m_pkthdr.pkt_flowsrc == FLOWSRC_INPCB) {
				ehp->bh_flowid = m->m_pkthdr.pkt_flowid;
				ehp->bh_proto = m->m_pkthdr.pkt_proto;
			}
			ehp->bh_svc = so_svc2tc(m->m_pkthdr.pkt_svc);
			if (m->m_pkthdr.pkt_flags & PKTF_TCP_REXMT) {
				ehp->bh_pktflags |= BPF_PKTFLAGS_TCP_REXMT;
			}
			if (m->m_pkthdr.pkt_flags & PKTF_START_SEQ) {
				ehp->bh_pktflags |= BPF_PKTFLAGS_START_SEQ;
			}
			if (m->m_pkthdr.pkt_flags & PKTF_LAST_PKT) {
				ehp->bh_pktflags |= BPF_PKTFLAGS_LAST_PKT;
			}
			if (m->m_pkthdr.pkt_flags & PKTF_VALID_UNSENT_DATA) {
				ehp->bh_unsent_bytes =
				    m->m_pkthdr.bufstatus_if;
				ehp->bh_unsent_snd =
				    m->m_pkthdr.bufstatus_sndbuf;
			}
		} else {
			ehp->bh_flags |= BPF_HDR_EXT_FLAGS_DIR_IN;
		}
		payload = (u_char *)ehp + hdrlen;
	} else {
		hp = (struct bpf_hdr *)(void *)(d->bd_sbuf + curlen);
		hp->bh_tstamp.tv_sec = tv.tv_sec;
		hp->bh_tstamp.tv_usec = tv.tv_usec;
		hp->bh_datalen = pkt->bpfp_total_length;
		hp->bh_hdrlen = hdrlen;
		caplen = hp->bh_caplen = totlen - hdrlen;
		payload = (u_char *)hp + hdrlen;
	}
	/*
	 * Copy the packet data into the store buffer and update its length.
	 */
	copy_bpf_packet(pkt, payload, caplen);
	d->bd_slen = curlen + totlen;
	d->bd_scnt += 1;

	if (do_wakeup) {
		bpf_wakeup(d);
	}
}

/*
 * Initialize all nonzero fields of a descriptor.
 */
static int
bpf_allocbufs(struct bpf_d *d)
{
	if (d->bd_sbuf != NULL) {
		FREE(d->bd_sbuf, M_DEVBUF);
		d->bd_sbuf = NULL;
	}
	if (d->bd_hbuf != NULL) {
		FREE(d->bd_hbuf, M_DEVBUF);
		d->bd_hbuf = NULL;
	}
	if (d->bd_fbuf != NULL) {
		FREE(d->bd_fbuf, M_DEVBUF);
		d->bd_fbuf = NULL;
	}

	d->bd_fbuf = (caddr_t) _MALLOC(d->bd_bufsize, M_DEVBUF, M_WAIT);
	if (d->bd_fbuf == NULL) {
		return ENOBUFS;
	}

	d->bd_sbuf = (caddr_t) _MALLOC(d->bd_bufsize, M_DEVBUF, M_WAIT);
	if (d->bd_sbuf == NULL) {
		FREE(d->bd_fbuf, M_DEVBUF);
		d->bd_fbuf = NULL;
		return ENOBUFS;
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	d->bd_scnt = 0;
	d->bd_hcnt = 0;
	return 0;
}

/*
 * Free buffers currently in use by a descriptor.
 * Called on close.
 */
static void
bpf_freed(struct bpf_d *d)
{
	/*
	 * We don't need to lock out interrupts since this descriptor has
	 * been detached from its interface and it yet hasn't been marked
	 * free.
	 */
	if (d->bd_hbuf_read != 0) {
		panic("bpf buffer freed during read");
	}

	if (d->bd_sbuf != 0) {
		FREE(d->bd_sbuf, M_DEVBUF);
		if (d->bd_hbuf != 0) {
			FREE(d->bd_hbuf, M_DEVBUF);
		}
		if (d->bd_fbuf != 0) {
			FREE(d->bd_fbuf, M_DEVBUF);
		}
	}
	if (d->bd_filter) {
		FREE(d->bd_filter, M_DEVBUF);
	}
}

/*
 * Attach an interface to bpf.	driverp is a pointer to a (struct bpf_if *)
 * in the driver's softc; dlt is the link layer type; hdrlen is the fixed
 * size of the link header (variable length headers not yet supported).
 */
void
bpfattach(struct ifnet *ifp, u_int dlt, u_int hdrlen)
{
	bpf_attach(ifp, dlt, hdrlen, NULL, NULL);
}

errno_t
bpf_attach(
	ifnet_t                 ifp,
	u_int32_t               dlt,
	u_int32_t               hdrlen,
	bpf_send_func   send,
	bpf_tap_func    tap)
{
	struct bpf_if *bp;
	struct bpf_if *bp_new;
	struct bpf_if *bp_before_first = NULL;
	struct bpf_if *bp_first = NULL;
	struct bpf_if *bp_last = NULL;
	boolean_t found;

	bp_new = (struct bpf_if *) _MALLOC(sizeof(*bp_new), M_DEVBUF,
	    M_WAIT | M_ZERO);
	if (bp_new == 0) {
		panic("bpfattach");
	}

	lck_mtx_lock(bpf_mlock);

	/*
	 * Check if this interface/dlt is already attached. Remember the
	 * first and last attachment for this interface, as well as the
	 * element before the first attachment.
	 */
	found = FALSE;
	for (bp = bpf_iflist; bp != NULL; bp = bp->bif_next) {
		if (bp->bif_ifp != ifp) {
			if (bp_first != NULL) {
				/* no more elements for this interface */
				break;
			}
			bp_before_first = bp;
		} else {
			if (bp->bif_dlt == dlt) {
				found = TRUE;
				break;
			}
			if (bp_first == NULL) {
				bp_first = bp;
			}
			bp_last = bp;
		}
	}
	if (found) {
		lck_mtx_unlock(bpf_mlock);
		printf("bpfattach - %s with dlt %d is already attached\n",
		    if_name(ifp), dlt);
		FREE(bp_new, M_DEVBUF);
		return EEXIST;
	}

	bp_new->bif_ifp = ifp;
	bp_new->bif_dlt = dlt;
	bp_new->bif_send = send;
	bp_new->bif_tap = tap;

	if (bp_first == NULL) {
		/* No other entries for this ifp */
		bp_new->bif_next = bpf_iflist;
		bpf_iflist = bp_new;
	} else {
		if (ifnet_type(ifp) == IFT_ETHER && dlt == DLT_EN10MB) {
			/* Make this the first entry for this interface */
			if (bp_before_first != NULL) {
				/*  point the previous to us */
				bp_before_first->bif_next = bp_new;
			} else {
				/* we're the new head */
				bpf_iflist = bp_new;
			}
			bp_new->bif_next = bp_first;
		} else {
			/* Add this after the last entry for this interface */
			bp_new->bif_next = bp_last->bif_next;
			bp_last->bif_next = bp_new;
		}
	}

	/*
	 * Compute the length of the bpf header.  This is not necessarily
	 * equal to SIZEOF_BPF_HDR because we want to insert spacing such
	 * that the network layer header begins on a longword boundary (for
	 * performance reasons and to alleviate alignment restrictions).
	 */
	bp_new->bif_hdrlen = BPF_WORDALIGN(hdrlen + SIZEOF_BPF_HDR) - hdrlen;
	bp_new->bif_exthdrlen = BPF_WORDALIGN(hdrlen +
	    sizeof(struct bpf_hdr_ext)) - hdrlen;

	/* Take a reference on the interface */
	ifnet_reference(ifp);

	lck_mtx_unlock(bpf_mlock);

#ifndef __APPLE__
	if (bootverbose) {
		printf("bpf: %s attached\n", if_name(ifp));
	}
#endif

	return 0;
}

/*
 * Detach bpf from an interface.  This involves detaching each descriptor
 * associated with the interface, and leaving bd_bif NULL.  Notify each
 * descriptor as it's detached so that any sleepers wake up and get
 * ENXIO.
 */
void
bpfdetach(struct ifnet *ifp)
{
	struct bpf_if   *bp, *bp_prev, *bp_next;
	struct bpf_d    *d;

	if (bpf_debug != 0) {
		printf("%s: %s\n", __func__, if_name(ifp));
	}

	lck_mtx_lock(bpf_mlock);

	/*
	 * Build the list of devices attached to that interface
	 * that we need to free while keeping the lock to maintain
	 * the integrity of the interface list
	 */
	bp_prev = NULL;
	for (bp = bpf_iflist; bp != NULL; bp = bp_next) {
		bp_next = bp->bif_next;

		if (ifp != bp->bif_ifp) {
			bp_prev = bp;
			continue;
		}
		/* Unlink from the interface list */
		if (bp_prev) {
			bp_prev->bif_next = bp->bif_next;
		} else {
			bpf_iflist = bp->bif_next;
		}

		/* Detach the devices attached to the interface */
		while ((d = bp->bif_dlist) != NULL) {
			/*
			 * Take an extra reference to prevent the device
			 * from being freed when bpf_detachd() releases
			 * the reference for the interface list
			 */
			bpf_acquire_d(d);
			bpf_detachd(d, 0);
			bpf_wakeup(d);
			bpf_release_d(d);
		}
		ifnet_release(ifp);
	}

	lck_mtx_unlock(bpf_mlock);
}

void
bpf_init(__unused void *unused)
{
#ifdef __APPLE__
	int     i;
	int     maj;

	if (bpf_devsw_installed == 0) {
		bpf_devsw_installed = 1;
		bpf_mlock_grp_attr = lck_grp_attr_alloc_init();
		bpf_mlock_grp = lck_grp_alloc_init("bpf", bpf_mlock_grp_attr);
		bpf_mlock_attr = lck_attr_alloc_init();
		lck_mtx_init(bpf_mlock, bpf_mlock_grp, bpf_mlock_attr);
		maj = cdevsw_add(CDEV_MAJOR, &bpf_cdevsw);
		if (maj == -1) {
			if (bpf_mlock_attr) {
				lck_attr_free(bpf_mlock_attr);
			}
			if (bpf_mlock_grp) {
				lck_grp_free(bpf_mlock_grp);
			}
			if (bpf_mlock_grp_attr) {
				lck_grp_attr_free(bpf_mlock_grp_attr);
			}

			bpf_mlock = NULL;
			bpf_mlock_attr = NULL;
			bpf_mlock_grp = NULL;
			bpf_mlock_grp_attr = NULL;
			bpf_devsw_installed = 0;
			printf("bpf_init: failed to allocate a major number\n");
			return;
		}

		for (i = 0; i < NBPFILTER; i++) {
			bpf_make_dev_t(maj);
		}
	}
#else
	cdevsw_add(&bpf_cdevsw);
#endif
}

#ifndef __APPLE__
SYSINIT(bpfdev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE + CDEV_MAJOR, bpf_drvinit, NULL)
#endif

#if CONFIG_MACF_NET
struct label *
mac_bpfdesc_label_get(struct bpf_d *d)
{
	return d->bd_label;
}

void
mac_bpfdesc_label_set(struct bpf_d *d, struct label *label)
{
	d->bd_label = label;
}
#endif
