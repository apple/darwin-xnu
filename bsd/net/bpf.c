/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 *      @(#)bpf.c	8.2 (Berkeley) 3/28/94
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

#if defined(sparc) && BSD < 199103
#include <sys/stream.h>
#endif
#include <sys/poll.h>

#include <sys/socket.h>
#include <sys/vnode.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <net/firewire.h>

#include <miscfs/devfs/devfs.h>
#include <net/dlil.h>

#include <kern/locks.h>
#include <kern/thread_call.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

extern int tvtohz(struct timeval *);

/*
 * Older BSDs don't have kernel malloc.
 */
#if BSD < 199103
extern bcopy();
static caddr_t bpf_alloc();
#include <net/bpf_compat.h>
#define BPF_BUFSIZE (MCLBYTES-8)
#define UIOMOVE(cp, len, code, uio) uiomove(cp, len, code, uio)
#else
#define BPF_BUFSIZE 4096
#define UIOMOVE(cp, len, code, uio) uiomove(cp, len, uio)
#endif


#define PRINET  26			/* interruptible */

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
 *  bpf_iflist is the list of interfaces; each corresponds to an ifnet
 *  bpf_dtab holds pointer to the descriptors, indexed by minor device #
 */
static struct bpf_if	*bpf_iflist;
#ifdef __APPLE__
/*
 * BSD now stores the bpf_d in the dev_t which is a struct
 * on their system. Our dev_t is an int, so we still store
 * the bpf_d in a separate table indexed by minor device #.
 *
 * The value stored in bpf_dtab[n] represent three states:
 *  0: device not opened
 *  1: device opening or closing
 *  other: device <n> opened with pointer to storage
 */
static struct bpf_d	**bpf_dtab = NULL;
static unsigned int bpf_dtab_size = 0;
static unsigned int	nbpfilter = 0;

static lck_mtx_t		*bpf_mlock;
static lck_grp_t		*bpf_mlock_grp;
static lck_grp_attr_t	*bpf_mlock_grp_attr;
static lck_attr_t		*bpf_mlock_attr;

/*
 * Mark a descriptor free by making it point to itself.
 * This is probably cheaper than marking with a constant since
 * the address should be in a register anyway.
 */
#endif /* __APPLE__ */

static int	bpf_allocbufs(struct bpf_d *);
static errno_t	bpf_attachd(struct bpf_d *d, struct bpf_if *bp);
static void	bpf_detachd(struct bpf_d *d);
static void	bpf_freed(struct bpf_d *);
static void	bpf_mcopy(const void *, void *, size_t);
static int	bpf_movein(struct uio *, int,
		    struct mbuf **, struct sockaddr *, int *);
static int	bpf_setif(struct bpf_d *, ifnet_t ifp, u_int32_t dlt);
static void bpf_timed_out(void *, void *);
static void bpf_wakeup(struct bpf_d *);
static void	catchpacket(struct bpf_d *, u_char *, u_int,
		    u_int, void (*)(const void *, void *, size_t));
static void	reset_d(struct bpf_d *);
static int bpf_setf(struct bpf_d *, u_int bf_len, user_addr_t bf_insns);
static int	bpf_getdltlist(struct bpf_d *, struct bpf_dltlist *,
    struct proc *);
static int	bpf_setdlt(struct bpf_d *, u_int);

/*static  void *bpf_devfs_token[MAXBPFILTER];*/

static  int bpf_devsw_installed;

void bpf_init(void *unused);
static int bpf_tap_callback(struct ifnet *ifp, struct mbuf *m);

/*
 * Darwin differs from BSD here, the following are static
 * on BSD and not static on Darwin.
 */
	d_open_t	    bpfopen;
	d_close_t	    bpfclose;
	d_read_t	    bpfread;
	d_write_t	    bpfwrite;
    ioctl_fcn_t	    bpfioctl;
    select_fcn_t	bpfselect;


/* Darwin's cdevsw struct differs slightly from BSDs */
#define CDEV_MAJOR 23
static struct cdevsw bpf_cdevsw = {
	/* open */	    bpfopen,
	/* close */	    bpfclose,
	/* read */	    bpfread,
	/* write */	    bpfwrite,
	/* ioctl */	    bpfioctl,
	/* stop */		eno_stop,
	/* reset */		eno_reset,
	/* tty */		NULL,
	/* select */	bpfselect,
	/* mmap */		eno_mmap,
	/* strategy*/	eno_strat,
	/* getc */		eno_getc,
	/* putc */		eno_putc,
	/* type */		0
};

#define SOCKADDR_HDR_LEN	   offsetof(struct sockaddr, sa_data)

static int
bpf_movein(struct uio *uio, int linktype, struct mbuf **mp, struct sockaddr *sockp, int *datlen)
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
		hlen = 12; 	/* XXX 4(ATM_PH) + 3(LLC) + 5(SNAP) */
		break;
	#endif

	case DLT_PPP:
		sa_family = AF_UNSPEC;
		hlen = 4;	/* This should match PPP_HDRLEN */
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
		return (EIO);
	}

	// LP64todo - fix this!
	len = uio_resid(uio);
	*datlen = len - hlen;
	if ((unsigned)len > MCLBYTES)
		return (EIO);

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
			return (EIO);
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
	if (m == 0)
		return (ENOBUFS);
	if ((unsigned)len > MHLEN) {
#if BSD >= 199103
		MCLGET(m, M_WAIT);
		if ((m->m_flags & M_EXT) == 0) {
#else
		MCLGET(m);
		if (m->m_len != MCLBYTES) {
#endif
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
#if BSD >= 199103
		m->m_data += hlen; /* XXX */
#else
		m->m_off += hlen;
#endif
		error = UIOMOVE((caddr_t)sockp->sa_data, hlen, UIO_WRITE, uio);
		if (error)
			goto bad;
	}
	error = UIOMOVE(mtod(m, caddr_t), len - hlen, UIO_WRITE, uio);
	if (error)
		goto bad;
	
	/* Check for multicast destination */
	switch (linktype) {
		case DLT_EN10MB: {
			struct ether_header *eh = mtod(m, struct ether_header *);
			
			if (ETHER_IS_MULTICAST(eh->ether_dhost)) {
				if (_ether_cmp(etherbroadcastaddr, eh->ether_dhost) == 0)
					m->m_flags |= M_BCAST;
				else
					m->m_flags |= M_MCAST;
			}
			break;
		}
	}
	
	return 0;
 bad:
	m_freem(m);
	return (error);
}

#ifdef __APPLE__

/*
 * The dynamic addition of a new device node must block all processes that are opening 
 * the last device so that no process will get an unexpected ENOENT 
 */
static void
bpf_make_dev_t(int maj)
{
	static int		bpf_growing = 0;
	unsigned int	cur_size = nbpfilter, i;

	if (nbpfilter >= bpf_maxdevices)
		return;

	while (bpf_growing) {
		/* Wait until new device has been created */
		(void)tsleep((caddr_t)&bpf_growing, PZERO, "bpf_growing", 0);
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
		new_dtab = (struct bpf_d **)_MALLOC(sizeof(struct bpf_d *) * new_dtab_size, M_DEVBUF, M_WAIT);
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
		if (old_dtab != NULL)
			_FREE(old_dtab, M_DEVBUF);
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
	int	error = 0;
	
	/*
	 * Point d at bp, and add d to the interface's list of listeners.
	 * Finally, point the driver's bpf cookie at the interface so
	 * it will divert packets to bpf.
	 */
	d->bd_bif = bp;
	d->bd_next = bp->bif_dlist;
	bp->bif_dlist = d;
	
	if (first) {
		/* Find the default bpf entry for this ifp */
		if (bp->bif_ifp->if_bpf == NULL) {
			struct bpf_if	*primary;
			
			for (primary = bpf_iflist; primary && primary->bif_ifp != bp->bif_ifp;
				 primary = primary->bif_next)
				;
		
			bp->bif_ifp->if_bpf = primary;
		}
		
		/* Only call dlil_set_bpf_tap for primary dlt */
		if (bp->bif_ifp->if_bpf == bp)
			dlil_set_bpf_tap(bp->bif_ifp, BPF_TAP_INPUT_OUTPUT, bpf_tap_callback);
		
		if (bp->bif_tap)
			error = bp->bif_tap(bp->bif_ifp, bp->bif_dlt, BPF_TAP_INPUT_OUTPUT);
	}

	return error;
}

/*
 * Detach a file from its interface.
 */
static void
bpf_detachd(struct bpf_d *d)
{
	struct bpf_d **p;
	struct bpf_if *bp;
	struct ifnet  *ifp;

	ifp = d->bd_bif->bif_ifp;
	bp = d->bd_bif;
	
	/* Remove d from the interface's descriptor list. */
	p = &bp->bif_dlist;
	while (*p != d) {
		p = &(*p)->bd_next;
		if (*p == 0)
			panic("bpf_detachd: descriptor not in list");
	}
	*p = (*p)->bd_next;
	if (bp->bif_dlist == 0) {
		/*
		 * Let the driver know that there are no more listeners.
		 */
		/* Only call dlil_set_bpf_tap for primary dlt */
		if (bp->bif_ifp->if_bpf == bp)
			dlil_set_bpf_tap(ifp, BPF_TAP_DISABLE, NULL);
		if (bp->bif_tap)
			bp->bif_tap(ifp, bp->bif_dlt, BPF_TAP_DISABLE);
		
		for (bp = bpf_iflist; bp; bp = bp->bif_next)
			if (bp->bif_ifp == ifp && bp->bif_dlist != 0)
				break;
		if (bp == NULL)
			ifp->if_bpf = NULL;
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
			printf("bpf: ifnet_set_promiscuous failed");
		}
		lck_mtx_lock(bpf_mlock);
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

		clock_interval_to_deadline((uint64_t)tv.tv_sec * USEC_PER_SEC + tv.tv_usec,
				NSEC_PER_USEC,
				&deadline);
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
	return (thread_call_cancel(d->bd_thread_call));
}



/*
 * Open ethernet device.  Returns ENXIO for illegal minor device number,
 * EBUSY if file is open by another process.
 */
/* ARGSUSED */
int
bpfopen(dev_t dev, int flags, __unused int fmt,
	__unused struct proc *p)
{
	struct bpf_d *d;

	lck_mtx_lock(bpf_mlock);
	if ((unsigned int) minor(dev) >= nbpfilter) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}
	/* 
	 * New device nodes are created on demand when opening the last one. 
	 * The programming model is for processes to loop on the minor starting at 0 
	 * as long as EBUSY is returned. The loop stops when either the open succeeds or 
	 * an error other that EBUSY is returned. That means that bpf_make_dev_t() must 
	 * block all processes that are opening the last  node. If not all 
	 * processes are blocked, they could unexpectedly get ENOENT and abort their 
	 * opening loop.
	 */
	if ((unsigned int) minor(dev) == (nbpfilter - 1))
		bpf_make_dev_t(major(dev));

	/*
	 * Each minor can be opened by only one process.  If the requested 
	 * minor is in use, return EBUSY.
	 *
	 * Important: bpfopen() and bpfclose() have to check and set the status of a device
	 * in the same lockin context otherwise the device may be leaked because the vnode use count 
	 * will be unpextectly greater than 1 when close() is called.
	 */
	if (bpf_dtab[minor(dev)] == 0) {
		bpf_dtab[minor(dev)] = (void *)1;	/* Mark opening */
	} else {
		lck_mtx_unlock(bpf_mlock);
		return (EBUSY);
	}
	d = (struct bpf_d *)_MALLOC(sizeof(struct bpf_d), M_DEVBUF, M_WAIT);
	if (d == NULL) {
		/* this really is a catastrophic failure */
		printf("bpfopen: malloc bpf_d failed\n");
		bpf_dtab[minor(dev)] = NULL;
		lck_mtx_unlock(bpf_mlock);
		return ENOMEM;
	}
	bzero(d, sizeof(struct bpf_d));
	
	/*
	 * It is not necessary to take the BPF lock here because no other 
	 * thread can access the device until it is marked opened...
	 */
	
	/* Mark "in use" and do most initialization. */
	d->bd_bufsize = bpf_bufsize;
	d->bd_sig = SIGIO;
	d->bd_seesent = 1;
	d->bd_oflags = flags;
	d->bd_state = BPF_IDLE;
    d->bd_thread_call = thread_call_allocate(bpf_timed_out, d);

	if (d->bd_thread_call == NULL) {
		printf("bpfopen: malloc thread call failed\n");
		bpf_dtab[minor(dev)] = NULL;
		lck_mtx_unlock(bpf_mlock);
		_FREE(d, M_DEVBUF);
		return ENOMEM;
	}
#if CONFIG_MACF_NET
	mac_bpfdesc_label_init(d);
	mac_bpfdesc_label_associate(kauth_cred_get(), d);
#endif
	bpf_dtab[minor(dev)] = d; 				/* Mark opened */
	lck_mtx_unlock(bpf_mlock);

	return (0);
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
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}	
	bpf_dtab[minor(dev)] = (void *)1;		/* Mark closing */

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
				while (d->bd_state == BPF_DRAINING)
					msleep((caddr_t)d, bpf_mlock, PRINET,
							"bpfdraining", NULL);
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

	if (d->bd_bif)
		bpf_detachd(d);
	selthreadclear(&d->bd_sel);
#if CONFIG_MACF_NET
	mac_bpfdesc_label_destroy(d);
#endif
	thread_call_free(d->bd_thread_call);
	bpf_freed(d);

	/* Mark free in same context as bpfopen comes to check */
	bpf_dtab[minor(dev)] = NULL;			/* Mark closed */
	lck_mtx_unlock(bpf_mlock);
	
	_FREE(d, M_DEVBUF);
	
	return (0);
}


#define BPF_SLEEP bpf_sleep

static int
bpf_sleep(struct bpf_d *d, int pri, const char *wmesg, int timo)
{
	u_int64_t abstime = 0;

	if(timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	
	return msleep1((caddr_t)d, bpf_mlock, pri, wmesg, abstime);
}

/*
 * Rotate the packet buffers in descriptor d.  Move the store buffer
 * into the hold slot, and the free buffer into the store slot.
 * Zero the length of the new store buffer.
 */
#define ROTATE_BUFFERS(d) \
	(d)->bd_hbuf = (d)->bd_sbuf; \
	(d)->bd_hlen = (d)->bd_slen; \
	(d)->bd_sbuf = (d)->bd_fbuf; \
	(d)->bd_slen = 0; \
	(d)->bd_fbuf = NULL;
/*
 *  bpfread - read next chunk of packets from buffers
 */
int
bpfread(dev_t dev, struct uio *uio, int ioflag)
{
	struct bpf_d *d;
	int timed_out;
	int error;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	/*
	 * Restrict application to use a buffer the same size as
	 * as kernel buffers.
	 */
	if (uio_resid(uio) != d->bd_bufsize) {
		lck_mtx_unlock(bpf_mlock);
		return (EINVAL);
	}
	
 	if (d->bd_state == BPF_WAITING)
		bpf_stop_timer(d);
	
	timed_out = (d->bd_state == BPF_TIMED_OUT);
	d->bd_state = BPF_IDLE;

	/*
	 * If the hold buffer is empty, then do a timed sleep, which
	 * ends when the timeout expires or when enough packets
	 * have arrived to fill the store buffer.
	 */
	while (d->bd_hbuf == 0) {
		if ((d->bd_immediate || timed_out || (ioflag & IO_NDELAY)) 
			&& d->bd_slen != 0) {
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
			lck_mtx_unlock(bpf_mlock);
			return (ENXIO);
		}
		if (ioflag & IO_NDELAY) {
			lck_mtx_unlock(bpf_mlock);
			return (EWOULDBLOCK);
		}
		error = BPF_SLEEP(d, PRINET|PCATCH, "bpf",
				  d->bd_rtout);
		/*
		 * Make sure device is still opened
		 */
		d = bpf_dtab[minor(dev)];
		if (d == 0 || d == (void *)1) {
			lck_mtx_unlock(bpf_mlock);
			return (ENXIO);
		}
		if (error == EINTR || error == ERESTART) {
			lck_mtx_unlock(bpf_mlock);
			return (error);
		}
		if (error == EWOULDBLOCK) {
			/*
			 * On a timeout, return what's in the buffer,
			 * which may be nothing.  If there is something
			 * in the store buffer, we can rotate the buffers.
			 */
			if (d->bd_hbuf)
				/*
				 * We filled up the buffer in between
				 * getting the timeout and arriving
				 * here, so we don't need to rotate.
				 */
				break;

			if (d->bd_slen == 0) {
				lck_mtx_unlock(bpf_mlock);
				return (0);
			}
			ROTATE_BUFFERS(d);
			break;
		}
	}
	/*
	 * At this point, we know we have something in the hold slot.
	 */

	/*
	 * Move data from hold buffer into user space.
	 * We know the entire buffer is transferred since
	 * we checked above that the read buffer is bpf_bufsize bytes.
	 */
	error = UIOMOVE(d->bd_hbuf, d->bd_hlen, UIO_READ, uio);

	d->bd_fbuf = d->bd_hbuf;
	d->bd_hbuf = NULL;
	d->bd_hlen = 0;
	lck_mtx_unlock(bpf_mlock);
	return (error);
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
	if (d->bd_async && d->bd_sig && d->bd_sigio)
		pgsigio(d->bd_sigio, d->bd_sig);

#if BSD >= 199103
	selwakeup(&d->bd_sel);
	KNOTE(&d->bd_sel.si_note, 1);
#ifndef __APPLE__
	/* XXX */
	d->bd_sel.si_pid = 0;
#endif
#else
	if (d->bd_selproc) {
		selwakeup(d->bd_selproc, (int)d->bd_selcoll);
		d->bd_selcoll = 0;
		d->bd_selproc = 0;
	}
#endif
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
		if (d->bd_slen != 0)
			bpf_wakeup(d);
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
#define MAX_DATALINK_HDR_LEN	(sizeof(struct firewire_header))

int
bpfwrite(dev_t dev, struct uio *uio, __unused int ioflag)
{
	struct bpf_d *d;
	struct ifnet *ifp;
	struct mbuf *m = NULL;
	int error;
	char 		  dst_buf[SOCKADDR_HDR_LEN + MAX_DATALINK_HDR_LEN];
	int datlen = 0;
    int bif_dlt;
    int bd_hdrcmplt;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}
	if (d->bd_bif == 0) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	ifp = d->bd_bif->bif_ifp;

	if ((ifp->if_flags & IFF_UP) == 0) {
		lck_mtx_unlock(bpf_mlock);
		return (ENETDOWN);
	}
	if (uio_resid(uio) == 0) {
		lck_mtx_unlock(bpf_mlock);
		return (0);
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
	
    if (error) {
		return (error);
	}

	/* taking the lock again and verifying whether device is open */
    lck_mtx_lock(bpf_mlock);
	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		m_freem(m);
		return (ENXIO);
	}

	if (d->bd_bif == NULL) {
		lck_mtx_unlock(bpf_mlock);
		m_free(m);
		return (ENXIO);
	}

	if ((unsigned)datlen > ifp->if_mtu) {
		lck_mtx_unlock(bpf_mlock);
		m_freem(m);
		return (EMSGSIZE);
	}


#if CONFIG_MACF_NET
	mac_mbuf_label_associate_bpfdesc(d, m);
#endif
	lck_mtx_unlock(bpf_mlock);

	if (d->bd_hdrcmplt) {
		if (d->bd_bif->bif_send)
			error = d->bd_bif->bif_send(ifp, d->bd_bif->bif_dlt, m);
		else
			error = dlil_output(ifp, 0, m, NULL, NULL, 1);
	}
	else {
		error = dlil_output(ifp, PF_INET, m, NULL, (struct sockaddr *)dst_buf, 0);
	}

	/*
	 * The driver frees the mbuf.
	 */
	return (error);
}

/*
 * Reset a descriptor by flushing its packet buffer and clearing the
 * receive and drop counts.
 */
static void
reset_d(struct bpf_d *d)
{
	if (d->bd_hbuf) {
		/* Free the hold buffer. */
		d->bd_fbuf = d->bd_hbuf;
		d->bd_hbuf = NULL;
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	d->bd_rcount = 0;
	d->bd_dcount = 0;
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
 */
/* ARGSUSED */
int
bpfioctl(dev_t dev, u_long cmd, caddr_t addr, __unused int flags,
    struct proc *p)
{
	struct bpf_d *d;
	int error = 0;

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	if (d->bd_state == BPF_WAITING)
		bpf_stop_timer(d);
	d->bd_state = BPF_IDLE;

	switch (cmd) {

	default:
		error = EINVAL;
		break;

	/*
	 * Check for read packet available.
	 */
	case FIONREAD:
		{
			int n;

			n = d->bd_slen;
			if (d->bd_hbuf)
				n += d->bd_hlen;

			*(int *)addr = n;
			break;
		}

	case SIOCGIFADDR:
		{
			struct ifnet *ifp;

			if (d->bd_bif == 0)
				error = EINVAL;
			else {
				ifp = d->bd_bif->bif_ifp;
				error = ifnet_ioctl(ifp, 0, cmd, addr);
			}
			break;
		}

	/*
	 * Get buffer len [for read()].
	 */
	case BIOCGBLEN:
		*(u_int *)addr = d->bd_bufsize;
		break;

	/*
	 * Set buffer length.
	 */
	case BIOCSBLEN:
#if BSD < 199103
		error = EINVAL;
#else
		if (d->bd_bif != 0)
			error = EINVAL;
		else {
			u_int size = *(u_int *)addr;

			if (size > bpf_maxbufsize)
				*(u_int *)addr = size = bpf_maxbufsize;
			else if (size < BPF_MINBUFSIZE)
				*(u_int *)addr = size = BPF_MINBUFSIZE;
			d->bd_bufsize = size;
		}
#endif
		break;

	/*
	 * Set link layer read filter.
	 */
	case BIOCSETF32: {
		struct bpf_program32 *prg32 = (struct bpf_program32 *)addr;
		error = bpf_setf(d, prg32->bf_len,
		    CAST_USER_ADDR_T(prg32->bf_insns));
		break;
	}

	case BIOCSETF64: {
		struct bpf_program64 *prg64 = (struct bpf_program64 *)addr;
		error = bpf_setf(d, prg64->bf_len, prg64->bf_insns);
		break;
	}

	/*
	 * Flush read packet buffer.
	 */
	case BIOCFLUSH:
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
			if (error == 0)
				d->bd_promisc = 1;
		}
		break;

	/*
	 * Get device parameters.
	 */
	case BIOCGDLT:
		if (d->bd_bif == 0)
			error = EINVAL;
		else
			*(u_int *)addr = d->bd_bif->bif_dlt;
		break;

	/*
	 * Get a list of supported data link types.
	 */
	case BIOCGDLTLIST:
		if (d->bd_bif == NULL) {
			error = EINVAL;
		} else {
			error = bpf_getdltlist(d,
			    (struct bpf_dltlist *)addr, p);
		}
		break;

	/*
	 * Set data link type.
	 */
	case BIOCSDLT:
			if (d->bd_bif == NULL)
					error = EINVAL;
			else
					error = bpf_setdlt(d, *(u_int *)addr);
			break;

	/*
	 * Get interface name.
	 */
	case BIOCGETIF:
		if (d->bd_bif == 0)
			error = EINVAL;
		else {
			struct ifnet *const ifp = d->bd_bif->bif_ifp;
			struct ifreq *const ifr = (struct ifreq *)addr;

			snprintf(ifr->ifr_name, sizeof(ifr->ifr_name),
			    "%s%d", ifp->if_name, ifp->if_unit);
		}
		break;

	/*
	 * Set interface.
	 */
	case BIOCSETIF: {
		ifnet_t	ifp;
		ifp = ifunit(((struct ifreq *)addr)->ifr_name);
		if (ifp == NULL)
			error = ENXIO;
		else
			error = bpf_setif(d, ifp, 0);
		break;
	}

	/*
	 * Set read timeout.
	 */
        case BIOCSRTIMEOUT32:
                {
			struct user32_timeval *_tv = (struct user32_timeval *)addr;
			struct timeval tv;

			tv.tv_sec  = _tv->tv_sec;
			tv.tv_usec = _tv->tv_usec;

                        /*
			 * Subtract 1 tick from tvtohz() since this isn't
			 * a one-shot timer.
			 */
			if ((error = itimerfix(&tv)) == 0)
				d->bd_rtout = tvtohz(&tv) - 1;
			break;
                }

        case BIOCSRTIMEOUT64:
                {
			struct user64_timeval *_tv = (struct user64_timeval *)addr;
			struct timeval tv;
                        
			tv.tv_sec  = _tv->tv_sec;
			tv.tv_usec = _tv->tv_usec;
                        
			/*
			 * Subtract 1 tick from tvtohz() since this isn't
			 * a one-shot timer.
			 */
			if ((error = itimerfix(&tv)) == 0)
				d->bd_rtout = tvtohz(&tv) - 1;
			break;
                }
	
        /*
	 * Get read timeout.
	 */
	case BIOCGRTIMEOUT32:
		{
			struct user32_timeval *tv = (struct user32_timeval *)addr;

			tv->tv_sec = d->bd_rtout / hz;
			tv->tv_usec = (d->bd_rtout % hz) * tick;
			break;
                }

	case BIOCGRTIMEOUT64:
		{
			struct user64_timeval *tv = (struct user64_timeval *)addr;

			tv->tv_sec = d->bd_rtout / hz;
			tv->tv_usec = (d->bd_rtout % hz) * tick;
			break;
                }

	/*
	 * Get packet stats.
	 */
	case BIOCGSTATS:
		{
			struct bpf_stat *bs = (struct bpf_stat *)addr;

			bs->bs_recv = d->bd_rcount;
			bs->bs_drop = d->bd_dcount;
			break;
		}

	/*
	 * Set immediate mode.
	 */
	case BIOCIMMEDIATE:
		d->bd_immediate = *(u_int *)addr;
		break;

	case BIOCVERSION:
		{
			struct bpf_version *bv = (struct bpf_version *)addr;

			bv->bv_major = BPF_MAJOR_VERSION;
			bv->bv_minor = BPF_MINOR_VERSION;
			break;
		}

	/*
	 * Get "header already complete" flag
	 */
	case BIOCGHDRCMPLT:
		*(u_int *)addr = d->bd_hdrcmplt;
		break;

	/*
	 * Set "header already complete" flag
	 */
	case BIOCSHDRCMPLT:
		d->bd_hdrcmplt = *(u_int *)addr ? 1 : 0;
		break;

	/*
	 * Get "see sent packets" flag
	 */
	case BIOCGSEESENT:
		*(u_int *)addr = d->bd_seesent;
		break;

	/*
	 * Set "see sent packets" flag
	 */
	case BIOCSSEESENT:
		d->bd_seesent = *(u_int *)addr;
		break;

	case FIONBIO:		/* Non-blocking I/O */
		break;

	case FIOASYNC:		/* Send signal on receive packets */
		d->bd_async = *(int *)addr;
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
	case BIOCSRSIG:		/* Set receive signal */
		{
		 	u_int sig;

			sig = *(u_int *)addr;

			if (sig >= NSIG)
				error = EINVAL;
			else
				d->bd_sig = sig;
			break;
		}
	case BIOCGRSIG:
		*(u_int *)addr = d->bd_sig;
		break;
	}
	
	lck_mtx_unlock(bpf_mlock);

	return (error);
}

/*
 * Set d's packet filter program to fp.  If this file already has a filter,
 * free it and replace it.  Returns EINVAL for bogus requests.
 */
static int
bpf_setf(struct bpf_d *d, u_int bf_len, user_addr_t bf_insns)
{
	struct bpf_insn *fcode, *old;
	u_int flen, size;

	old = d->bd_filter;
	if (bf_insns == USER_ADDR_NULL) {
		if (bf_len != 0)
			return (EINVAL);
		d->bd_filter = NULL;
		reset_d(d);
		if (old != 0)
			FREE((caddr_t)old, M_DEVBUF);
		return (0);
	}
	flen = bf_len;
	if (flen > BPF_MAXINSNS)
		return (EINVAL);

	size = flen * sizeof(struct bpf_insn);
	fcode = (struct bpf_insn *) _MALLOC(size, M_DEVBUF, M_WAIT);
#ifdef __APPLE__
	if (fcode == NULL)
		return (ENOBUFS);
#endif
	if (copyin(bf_insns, (caddr_t)fcode, size) == 0 &&
	    bpf_validate(fcode, (int)flen)) {
		d->bd_filter = fcode;
		reset_d(d);
		if (old != 0)
			FREE((caddr_t)old, M_DEVBUF);

		return (0);
	}
	FREE((caddr_t)fcode, M_DEVBUF);
	return (EINVAL);
}

/*
 * Detach a file from its current interface (if attached at all) and attach
 * to the interface indicated by the name stored in ifr.
 * Return an errno or 0.
 */
static int
bpf_setif(struct bpf_d *d, ifnet_t theywant, u_int32_t dlt)
{
	struct bpf_if *bp;
	int error;
	
	/*
	 * Look through attached interfaces for the named one.
	 */
	for (bp = bpf_iflist; bp != 0; bp = bp->bif_next) {
		struct ifnet *ifp = bp->bif_ifp;

		if (ifp == 0 || ifp != theywant || (dlt != 0 && dlt != bp->bif_dlt))
			continue;
		/*
		 * We found the requested interface.
		 * Allocate the packet buffers if we need to.
		 * If we're already attached to requested interface,
		 * just flush the buffer.
		 */
		if (d->bd_sbuf == 0) {
			error = bpf_allocbufs(d);
			if (error != 0)
				return (error);
		}
		if (bp != d->bd_bif) {
			if (d->bd_bif)
				/*
				 * Detach if attached to something else.
				 */
				bpf_detachd(d);

			if (bpf_attachd(d, bp) != 0) {
				return ENXIO;
			}
		}
		reset_d(d);
		return (0);
	}
	/* Not found. */
	return (ENXIO);
}



/*
 * Get a list of available data link type of the interface.
 */
static int
bpf_getdltlist(struct bpf_d *d, struct bpf_dltlist *bfl, struct proc *p)
{
	u_int		n;
	int		error;
	struct ifnet	*ifp;
	struct bpf_if	*bp;
	user_addr_t	dlist;

	if (proc_is64bit(p)) {
		dlist = (user_addr_t)bfl->bfl_u.bflu_pad;
	} else {
		dlist = CAST_USER_ADDR_T(bfl->bfl_u.bflu_list);
	}

	ifp = d->bd_bif->bif_ifp;
	n = 0;
	error = 0;
	for (bp = bpf_iflist; bp; bp = bp->bif_next) {
		if (bp->bif_ifp != ifp)
			continue;
		if (dlist != USER_ADDR_NULL) {
			if (n >= bfl->bfl_len) {
				return (ENOMEM);
			}
			error = copyout(&bp->bif_dlt, dlist,
			    sizeof (bp->bif_dlt));
			dlist += sizeof (bp->bif_dlt);
		}
		n++;
	}
	bfl->bfl_len = n;
	return (error);
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
	
	if (d->bd_bif->bif_dlt == dlt)
		return (0);
	ifp = d->bd_bif->bif_ifp;
	for (bp = bpf_iflist; bp; bp = bp->bif_next) {
		if (bp->bif_ifp == ifp && bp->bif_dlt == dlt)
			break;
	}
	if (bp != NULL) {
		opromisc = d->bd_promisc;
		bpf_detachd(d);
		error = bpf_attachd(d, bp);
		if (error) {
			printf("bpf_setdlt: bpf_attachd %s%d failed (%d)\n",
				ifnet_name(bp->bif_ifp), ifnet_unit(bp->bif_ifp), error);
			return error;
		}
		reset_d(d);
		if (opromisc) {
			lck_mtx_unlock(bpf_mlock);
			error = ifnet_set_promiscuous(bp->bif_ifp, 1);
			lck_mtx_lock(bpf_mlock);
			if (error)
				printf("bpf_setdlt: ifpromisc %s%d failed (%d)\n",
					   ifnet_name(bp->bif_ifp), ifnet_unit(bp->bif_ifp), error);
			else
				d->bd_promisc = 1;
		}
	}
	return (bp == NULL ? EINVAL : 0);
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
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	if (d->bd_bif == NULL) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	switch (which) {
		case FREAD:
			if (d->bd_hlen != 0 ||
					((d->bd_immediate || d->bd_state == BPF_TIMED_OUT) &&
					 d->bd_slen != 0))
				ret = 1; /* read has data to return */
			else {
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
			ret = 1; /* can't determine whether a write would block */
			break;
	}

	lck_mtx_unlock(bpf_mlock);
	return (ret);
}


/*
 * Support for kevent() system call.  Register EVFILT_READ filters and
 * reject all others.
 */
int bpfkqfilter(dev_t dev, struct knote *kn);
static void filt_bpfdetach(struct knote *);
static int filt_bpfread(struct knote *, long);

static struct filterops bpfread_filtops = {
	.f_isfd = 1, 
	.f_detach = filt_bpfdetach,
	.f_event = filt_bpfread,
};

int
bpfkqfilter(dev_t dev, struct knote *kn)
{
	struct bpf_d *d;

	/*
	 * Is this device a bpf?
	 */
	if (major(dev) != CDEV_MAJOR) {
		return (EINVAL);
	}

	if (kn->kn_filter != EVFILT_READ) {
		return (EINVAL);
	}

	lck_mtx_lock(bpf_mlock);

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	if (d->bd_bif == NULL) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	kn->kn_hook = d;
	kn->kn_fop = &bpfread_filtops;
	KNOTE_ATTACH(&d->bd_sel.si_note, kn);
	lck_mtx_unlock(bpf_mlock);
	return 0;
}

static void
filt_bpfdetach(struct knote *kn)
{
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;

	lck_mtx_lock(bpf_mlock);
	KNOTE_DETACH(&d->bd_sel.si_note, kn);
	lck_mtx_unlock(bpf_mlock);
}

static int
filt_bpfread(struct knote *kn, long hint)
{
	struct bpf_d *d = (struct bpf_d *)kn->kn_hook;
	int ready = 0;

	if (hint == 0)
		lck_mtx_lock(bpf_mlock);

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
		kn->kn_data = (d->bd_hlen == 0 ? d->bd_slen : d->bd_hlen);
		int64_t lowwat = 1;
		if (kn->kn_sfflags & NOTE_LOWAT)
		{
			if (kn->kn_sdata > d->bd_bufsize)
				lowwat = d->bd_bufsize;
			else if (kn->kn_sdata > lowwat)
				lowwat = kn->kn_sdata;
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
		kn->kn_data = (d->bd_hlen == 0 && d->bd_state == BPF_TIMED_OUT ? 
				d->bd_slen : d->bd_hlen);
		ready = (kn->kn_data > 0);
	}
	if (!ready)
		bpf_start_timer(d);

	if (hint == 0)
		lck_mtx_unlock(bpf_mlock);
	return (ready);
}

static inline void*
_cast_non_const(const void * ptr) {
	union {
		const void*		cval;
		void*			val;
	} ret;
	
	ret.cval = ptr;
	return (ret.val);
}

/*
 * Copy data from an mbuf chain into a buffer.  This code is derived
 * from m_copydata in sys/uipc_mbuf.c.
 */
static void
bpf_mcopy(const void *src_arg, void *dst_arg, size_t len)
{
	struct mbuf *m = _cast_non_const(src_arg);
	u_int count;
	u_char *dst;

	dst = dst_arg;
	while (len > 0) {
		if (m == 0)
			panic("bpf_mcopy");
		count = min(m->m_len, len);
		bcopy(mbuf_data(m), dst, count);
		m = m->m_next;
		dst += count;
		len -= count;
	}
}

static inline void
bpf_tap_imp(
	ifnet_t		ifp,
	u_int32_t	dlt,
	mbuf_t		m,
	void*		hdr,
	size_t		hlen,
	int			outbound)
{
	struct bpf_if *bp;

	/*
	 * It's possible that we get here after the bpf descriptor has been
	 * detached from the interface; in such a case we simply return.
	 * Lock ordering is important since we can be called asynchronously
	 * (from the IOKit) to process an inbound packet; when that happens
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
	bp = ifp->if_bpf;
	for (bp = ifp->if_bpf; bp && bp->bif_ifp == ifp &&
		 (dlt != 0 && bp->bif_dlt != dlt); bp = bp->bif_next)
		;
	if (bp && bp->bif_ifp == ifp && bp->bif_dlist != NULL) {
		struct bpf_d	*d;
		struct m_hdr	hack_hdr;
		u_int	pktlen = 0;
		u_int	slen = 0;
		struct mbuf *m0;
		
		if (hdr) {
			/*
			 * This is gross. We mock up an mbuf that points to the
			 * header buffer. This means we don't have to copy the
			 * header. A number of interfaces prepended headers just
			 * for bpf by allocating an mbuf on the stack. We want to
			 * give developers an easy way to prepend a header for bpf.
			 * Since a developer allocating an mbuf on the stack is bad,
			 * we do even worse here, allocating only a header to point
			 * to a buffer the developer supplied. This makes assumptions
			 * that bpf_filter and catchpacket will not look at anything
			 * in the mbuf other than the header. This was true at the
			 * time this code was written.
			 */
			hack_hdr.mh_next = m;
			hack_hdr.mh_nextpkt = NULL;
			hack_hdr.mh_len = hlen;
			hack_hdr.mh_data = hdr;
			hack_hdr.mh_type = m->m_type;
			hack_hdr.mh_flags = 0;
			
			m = (mbuf_t)&hack_hdr;
		}

		for (m0 = m; m0 != 0; m0 = m0->m_next)
			pktlen += m0->m_len;
		
		for (d = bp->bif_dlist; d; d = d->bd_next) {
			if (outbound && !d->bd_seesent)
				continue;
			++d->bd_rcount;
			slen = bpf_filter(d->bd_filter, (u_char *)m, pktlen, 0);
			if (slen != 0) {
#if CONFIG_MACF_NET
				if (mac_bpfdesc_check_receive(d, bp->bif_ifp) != 0)
					continue;
#endif
				catchpacket(d, (u_char *)m, pktlen, slen, bpf_mcopy);
			}
		}
	}
	lck_mtx_unlock(bpf_mlock);
}

void
bpf_tap_out(
	ifnet_t		ifp,
	u_int32_t	dlt,
	mbuf_t		m,
	void*		hdr,
	size_t		hlen)
{
	bpf_tap_imp(ifp, dlt, m, hdr, hlen, 1);
}

void
bpf_tap_in(
	ifnet_t		ifp,
	u_int32_t	dlt,
	mbuf_t		m,
	void*		hdr,
	size_t		hlen)
{
	bpf_tap_imp(ifp, dlt, m, hdr, hlen, 0);
}

/* Callback registered with Ethernet driver. */
static int bpf_tap_callback(struct ifnet *ifp, struct mbuf *m)
{
	bpf_tap_imp(ifp, 0, m, NULL, 0, mbuf_pkthdr_rcvif(m) == NULL);
	
	return 0;
}

/*
 * Move the packet data from interface memory (pkt) into the
 * store buffer.  Return 1 if it's time to wakeup a listener (buffer full),
 * otherwise 0.  "copy" is the routine called to do the actual data
 * transfer.  bcopy is passed in to copy contiguous chunks, while
 * bpf_mcopy is passed in to copy mbuf chains.  In the latter case,
 * pkt is really an mbuf.
 */
static void
catchpacket(struct bpf_d *d, u_char *pkt, u_int pktlen, u_int snaplen, 
	void (*cpfn)(const void *, void *, size_t))
{
	struct bpf_hdr *hp;
	int totlen, curlen;
	int hdrlen = d->bd_bif->bif_hdrlen;
	int do_wakeup = 0;
	/*
	 * Figure out how many bytes to move.  If the packet is
	 * greater or equal to the snapshot length, transfer that
	 * much.  Otherwise, transfer the whole packet (unless
	 * we hit the buffer size limit).
	 */
	totlen = hdrlen + min(snaplen, pktlen);
	if (totlen > d->bd_bufsize)
		totlen = d->bd_bufsize;

	/*
	 * Round up the end of the previous packet to the next longword.
	 */
	curlen = BPF_WORDALIGN(d->bd_slen);
	if (curlen + totlen > d->bd_bufsize) {
		/*
		 * This packet will overflow the storage buffer.
		 * Rotate the buffers if we can, then wakeup any
		 * pending reads.
		 */
		if (d->bd_fbuf == NULL) {
			/*
			 * We haven't completed the previous read yet,
			 * so drop the packet.
			 */
			++d->bd_dcount;
			return;
		}
		ROTATE_BUFFERS(d);
		do_wakeup = 1;
		curlen = 0;
	}
	else if (d->bd_immediate || d->bd_state == BPF_TIMED_OUT)
		/*
		 * Immediate mode is set, or the read timeout has 
		 * already expired during a select call. A packet 
		 * arrived, so the reader should be woken up.
		 */
		do_wakeup = 1;

	/*
	 * Append the bpf header.
	 */
	hp = (struct bpf_hdr *)(d->bd_sbuf + curlen);
	struct timeval tv;
	microtime(&tv);
	hp->bh_tstamp.tv_sec = tv.tv_sec;
	hp->bh_tstamp.tv_usec = tv.tv_usec;
	hp->bh_datalen = pktlen;
	hp->bh_hdrlen = hdrlen;
	/*
	 * Copy the packet data into the store buffer and update its length.
	 */
	(*cpfn)(pkt, (u_char *)hp + hdrlen, (hp->bh_caplen = totlen - hdrlen));
	d->bd_slen = curlen + totlen;

	if (do_wakeup)
		bpf_wakeup(d);
}

/*
 * Initialize all nonzero fields of a descriptor.
 */
static int
bpf_allocbufs(struct bpf_d *d)
{
	d->bd_fbuf = (caddr_t) _MALLOC(d->bd_bufsize, M_DEVBUF, M_WAIT);
	if (d->bd_fbuf == 0)
		return (ENOBUFS);

	d->bd_sbuf = (caddr_t) _MALLOC(d->bd_bufsize, M_DEVBUF, M_WAIT);
	if (d->bd_sbuf == 0) {
		FREE(d->bd_fbuf, M_DEVBUF);
		return (ENOBUFS);
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	return (0);
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
	if (d->bd_sbuf != 0) {
		FREE(d->bd_sbuf, M_DEVBUF);
		if (d->bd_hbuf != 0)
			FREE(d->bd_hbuf, M_DEVBUF);
		if (d->bd_fbuf != 0)
			FREE(d->bd_fbuf, M_DEVBUF);
	}
	if (d->bd_filter)
		FREE((caddr_t)d->bd_filter, M_DEVBUF);
}

/*
 * Attach an interface to bpf.  driverp is a pointer to a (struct bpf_if *)
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
	ifnet_t			ifp,
	u_int32_t		dlt,
	u_int32_t		hdrlen,
	bpf_send_func	send,
	bpf_tap_func	tap)
{
	struct bpf_if *bp_new;
	struct bpf_if *bp_temp;
	struct bpf_if *bp_first = NULL;
	
	bp_new = (struct bpf_if *) _MALLOC(sizeof(*bp_new), M_DEVBUF, M_WAIT);
	if (bp_new == 0)
		panic("bpfattach");

	lck_mtx_lock(bpf_mlock);

	/*
	 * Check if this interface/dlt is already attached, record first
	 * attachment for this interface.
	 */
	for (bp_temp = bpf_iflist; bp_temp && (bp_temp->bif_ifp != ifp ||
		 bp_temp->bif_dlt != dlt); bp_temp = bp_temp->bif_next) {
		 if (bp_temp->bif_ifp == ifp && bp_first == NULL)
		 	bp_first = bp_temp;
	}
	
	if (bp_temp != NULL) {
		printf("bpfattach - %s%d with dlt %d is already attached\n",
			ifp->if_name, ifp->if_unit, dlt);
		FREE(bp_new, M_DEVBUF);
		lck_mtx_unlock(bpf_mlock);
		return EEXIST;
	}
	
	bzero(bp_new, sizeof(*bp_new));
	bp_new->bif_ifp = ifp;
	bp_new->bif_dlt = dlt;
	bp_new->bif_send = send;
	bp_new->bif_tap = tap;
	
	if (bp_first == NULL) {
		/* No other entries for this ifp */
		bp_new->bif_next = bpf_iflist;
		bpf_iflist = bp_new;
	}
	else {
		/* Add this after the first entry for this interface */
		bp_new->bif_next = bp_first->bif_next;
		bp_first->bif_next = bp_new;
	}
	
	/*
	 * Compute the length of the bpf header.  This is not necessarily
	 * equal to SIZEOF_BPF_HDR because we want to insert spacing such
	 * that the network layer header begins on a longword boundary (for
	 * performance reasons and to alleviate alignment restrictions).
	 */
	bp_new->bif_hdrlen = BPF_WORDALIGN(hdrlen + SIZEOF_BPF_HDR) - hdrlen;
	
	/* Take a reference on the interface */
	ifnet_reference(ifp);

	lck_mtx_unlock(bpf_mlock);

#ifndef __APPLE__
	if (bootverbose)
		printf("bpf: %s%d attached\n", ifp->if_name, ifp->if_unit);
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
	struct bpf_if	*bp, *bp_prev, *bp_next;
	struct bpf_if	*bp_free = NULL;
	struct bpf_d	*d;

	
	lck_mtx_lock(bpf_mlock);

	/* Locate BPF interface information */
	bp_prev = NULL;
	for (bp = bpf_iflist; bp != NULL; bp = bp_next) {
		bp_next = bp->bif_next;
		if (ifp != bp->bif_ifp) {
			bp_prev = bp;
			continue;
		}
		
		while ((d = bp->bif_dlist) != NULL) {
			bpf_detachd(d);
			bpf_wakeup(d);
		}
	
		if (bp_prev) {
			bp_prev->bif_next = bp->bif_next;
		} else {
			bpf_iflist = bp->bif_next;
		}
		
		bp->bif_next = bp_free;
		bp_free = bp;
		
		ifnet_release(ifp);
	}

	lck_mtx_unlock(bpf_mlock);

	FREE(bp, M_DEVBUF);

}

void
bpf_init(__unused void *unused)
{
#ifdef __APPLE__
	int 	i;
	int	maj;

	if (bpf_devsw_installed == 0) {
		bpf_devsw_installed = 1;

        bpf_mlock_grp_attr = lck_grp_attr_alloc_init();

        bpf_mlock_grp = lck_grp_alloc_init("bpf", bpf_mlock_grp_attr);

        bpf_mlock_attr = lck_attr_alloc_init();

        bpf_mlock = lck_mtx_alloc_init(bpf_mlock_grp, bpf_mlock_attr);

		if (bpf_mlock == 0) {
			printf("bpf_init: failed to allocate bpf_mlock\n");
			bpf_devsw_installed = 0;
			return;
		}
		
		maj = cdevsw_add(CDEV_MAJOR, &bpf_cdevsw);
		if (maj == -1) {
			if (bpf_mlock)
				lck_mtx_free(bpf_mlock, bpf_mlock_grp);
			if (bpf_mlock_attr)
				lck_attr_free(bpf_mlock_attr);
			if (bpf_mlock_grp)
				lck_grp_free(bpf_mlock_grp);
			if (bpf_mlock_grp_attr)
				lck_grp_attr_free(bpf_mlock_grp_attr);
			
			bpf_mlock = NULL;
			bpf_mlock_attr = NULL;
			bpf_mlock_grp = NULL;
			bpf_mlock_grp_attr = NULL;
			bpf_devsw_installed = 0;
			printf("bpf_init: failed to allocate a major number!\n");
			return;
		}

		for (i = 0 ; i < NBPFILTER; i++)
			bpf_make_dev_t(maj);
	}
#else
	cdevsw_add(&bpf_cdevsw);
#endif
}

#ifndef __APPLE__
SYSINIT(bpfdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,bpf_drvinit,NULL)
#endif

#if CONFIG_MACF_NET
struct label *
mac_bpfdesc_label_get(struct bpf_d *d)
{

	return (d->bd_label);
}

void
mac_bpfdesc_label_set(struct bpf_d *d, struct label *label)
{

	d->bd_label = label;
}
#endif
