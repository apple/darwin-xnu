/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <machine/spl.h>
#include <miscfs/devfs/devfs.h>
#include <net/dlil.h>

#include <kern/locks.h>

extern int tvtohz(struct timeval *);

#if NBPFILTER > 0

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
SYSCTL_INT(_debug, OID_AUTO, bpf_bufsize, CTLFLAG_RW, 
	&bpf_bufsize, 0, "");
static unsigned int bpf_maxbufsize = BPF_MAXBUFSIZE;
SYSCTL_INT(_debug, OID_AUTO, bpf_maxbufsize, CTLFLAG_RW, 
	&bpf_maxbufsize, 0, "");
static unsigned int bpf_maxdevices = 256;
SYSCTL_UINT(_debug, OID_AUTO, bpf_maxdevices, CTLFLAG_RW, 
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
static void	bpf_attachd(struct bpf_d *d, struct bpf_if *bp);
static void	bpf_detachd(struct bpf_d *d);
static void	bpf_freed(struct bpf_d *);
static void	bpf_mcopy(const void *, void *, size_t);
static int	bpf_movein(struct uio *, int,
		    struct mbuf **, struct sockaddr *, int *);
static int	bpf_setif(struct bpf_d *, struct ifreq *);
static void bpf_wakeup(struct bpf_d *);
static void	catchpacket(struct bpf_d *, u_char *, u_int,
		    u_int, void (*)(const void *, void *, size_t));
static void	reset_d(struct bpf_d *);
static int bpf_setf(struct bpf_d *, struct user_bpf_program *);

/*static  void *bpf_devfs_token[MAXBPFILTER];*/

static  int bpf_devsw_installed;

void bpf_init(void *unused);
int bpf_tap_callback(struct ifnet *ifp, struct mbuf *m);

/*
 * Darwin differs from BSD here, the following are static
 * on BSD and not static on Darwin.
 */
	d_open_t	bpfopen;
	d_close_t	bpfclose;
	d_read_t	bpfread;
	d_write_t	bpfwrite;
	 ioctl_fcn_t	bpfioctl;
	select_fcn_t	bpfpoll;


/* Darwin's cdevsw struct differs slightly from BSDs */
#define CDEV_MAJOR 23
static struct cdevsw bpf_cdevsw = {
	/* open */	bpfopen,
	/* close */	bpfclose,
	/* read */	bpfread,
	/* write */	bpfwrite,
	/* ioctl */	bpfioctl,
	/* stop */		eno_stop,
	/* reset */		eno_reset,
	/* tty */		NULL,
	/* select */	bpfpoll,
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
	int hlen;

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
		switch (linktype) {
	
		case DLT_SLIP:
			sockp->sa_family = AF_INET;
			hlen = 0;
			break;
	
		case DLT_EN10MB:
			sockp->sa_family = AF_UNSPEC;
			/* XXX Would MAXLINKHDR be better? */
			hlen = sizeof(struct ether_header);
			break;
	
		case DLT_FDDI:
	#if defined(__FreeBSD__) || defined(__bsdi__)
			sockp->sa_family = AF_IMPLINK;
			hlen = 0;
	#else
			sockp->sa_family = AF_UNSPEC;
			/* XXX 4(FORMAC)+6(dst)+6(src)+3(LLC)+5(SNAP) */
			hlen = 24;
	#endif
			break;
	
		case DLT_RAW:
		case DLT_NULL:
			sockp->sa_family = AF_UNSPEC;
			hlen = 0;
			break;
	
	#ifdef __FreeBSD__
		case DLT_ATM_RFC1483:
			/*
			 * en atm driver requires 4-byte atm pseudo header.
			 * though it isn't standard, vpi:vci needs to be
			 * specified anyway.
			 */
			sockp->sa_family = AF_UNSPEC;
			hlen = 12; 	/* XXX 4(ATM_PH) + 3(LLC) + 5(SNAP) */
			break;
	#endif
		case DLT_PPP:
			sockp->sa_family = AF_UNSPEC;
			hlen = 4;	/* This should match PPP_HDRLEN */
			break;
	
		case DLT_APPLE_IP_OVER_IEEE1394:
			sockp->sa_family = AF_UNSPEC;
			hlen = sizeof(struct firewire_header);
			break;
	
		default:
			return (EIO);
		}
		if ((hlen + SOCKADDR_HDR_LEN) > sockp->sa_len) {
			return (EIO);
		}
	}
	else {
		hlen = 0;
	}
	
	// LP64todo - fix this!
	len = uio_resid(uio);
	*datlen = len - hlen;
	if ((unsigned)len > MCLBYTES)
		return (EIO);

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
	if (!error)
		return (0);
 bad:
	m_freem(m);
	return (error);
}

#ifdef __APPLE__
/* Callback registered with Ethernet driver. */
int bpf_tap_callback(struct ifnet *ifp, struct mbuf *m)
{
    /*
     * Do nothing if the BPF tap has been turned off.
     * This is to protect from a potential race where this
     * call blocks on the lock. And in the meantime
     * BPF is turned off, which will clear if_bpf.
     */
    if (ifp->if_bpf)
        bpf_mtap(ifp, m);
    return 0;
}

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
 * Must be called at splimp.
 */
static void
bpf_attachd(struct bpf_d *d, struct bpf_if *bp)
{
	/*
	 * Point d at bp, and add d to the interface's list of listeners.
	 * Finally, point the driver's bpf cookie at the interface so
	 * it will divert packets to bpf.
	 */
	d->bd_bif = bp;
	d->bd_next = bp->bif_dlist;
	bp->bif_dlist = d;

	bp->bif_ifp->if_bpf = bp;

#ifdef __APPLE__
	dlil_set_bpf_tap(bp->bif_ifp, BPF_TAP_INPUT_OUTPUT, bpf_tap_callback);
#endif
}

/*
 * Detach a file from its interface.
 */
static void
bpf_detachd(struct bpf_d *d)
{
	struct bpf_d **p;
	struct bpf_if *bp;
#ifdef __APPLE__
	struct ifnet  *ifp;

	ifp = d->bd_bif->bif_ifp;

#endif

	bp = d->bd_bif;
	/*
	 * Check if this descriptor had requested promiscuous mode.
	 * If so, turn it off.
	 */
	if (d->bd_promisc) {
		d->bd_promisc = 0;
		if (ifnet_set_promiscuous(bp->bif_ifp, 0))
			/*
			 * Something is really wrong if we were able to put
			 * the driver into promiscuous mode, but can't
			 * take it out.
			 * Most likely the network interface is gone.
			 */
			printf("bpf: ifnet_set_promiscuous failed");
	}
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
		if (ifp->if_set_bpf_tap)
			(*ifp->if_set_bpf_tap)(ifp, BPF_TAP_DISABLE, 0);
		d->bd_bif->bif_ifp->if_bpf = 0;
	}
	d->bd_bif = 0;
}


/*
 * Open ethernet device.  Returns ENXIO for illegal minor device number,
 * EBUSY if file is open by another process.
 */
/* ARGSUSED */
	int
bpfopen(dev_t dev, __unused int flags, __unused int fmt, __unused struct proc *p)
{
	register struct bpf_d *d;

	if ((unsigned int) minor(dev) >= nbpfilter)
		return (ENXIO);
		
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
	if (bpf_dtab[minor(dev)] == 0)
		bpf_dtab[minor(dev)] = (void *)1;	/* Mark opening */
	else
		return (EBUSY);

	d = (struct bpf_d *)_MALLOC(sizeof(struct bpf_d), M_DEVBUF, M_WAIT);
	if (d == NULL) {
		/* this really is a catastrophic failure */
		printf("bpfopen: malloc bpf_d failed\n");
		bpf_dtab[minor(dev)] = 0;
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
	bpf_dtab[minor(dev)] = d; 				/* Mark opened */

	return (0);
}

/*
 * Close the descriptor by detaching it from its interface,
 * deallocating its buffers, and marking it free.
 */
/* ARGSUSED */
	int
bpfclose(dev_t dev, __unused int flags, __unused int fmt, __unused struct proc *p)
{
	register struct bpf_d *d;

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1)
		return (ENXIO);
	
	bpf_dtab[minor(dev)] = (void *)1;		/* Mark closing */

	/* Take BPF lock to ensure no other thread is using the device */
	lck_mtx_lock(bpf_mlock);

	if (d->bd_bif)
		bpf_detachd(d);
	selthreadclear(&d->bd_sel);
	bpf_freed(d);

	lck_mtx_unlock(bpf_mlock);
	
	/* Mark free in same context as bpfopen comes to check */
	bpf_dtab[minor(dev)] = 0;				/* Mark closed */
	_FREE(d, M_DEVBUF);
	
	return (0);
}


#define BPF_SLEEP bpf_sleep

static int
bpf_sleep(struct bpf_d *d, int pri, const char *wmesg, int timo)
{
	register int st;

	lck_mtx_unlock(bpf_mlock);
	
	st = tsleep((caddr_t)d, pri, wmesg, timo);
	
	lck_mtx_lock(bpf_mlock);
	
	return st;
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
	(d)->bd_fbuf = 0;
/*
 *  bpfread - read next chunk of packets from buffers
 */
	int
bpfread(dev_t dev, struct uio *uio, int ioflag)
{
	register struct bpf_d *d;
	int error;
	int s;

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1)
		return (ENXIO);

	lck_mtx_lock(bpf_mlock);


	/*
	 * Restrict application to use a buffer the same size as
	 * as kernel buffers.
	 */
	// LP64todo - fix this
	if (uio->uio_resid != d->bd_bufsize) {
		lck_mtx_unlock(bpf_mlock);
		return (EINVAL);
	}

	s = splimp();
	/*
	 * If the hold buffer is empty, then do a timed sleep, which
	 * ends when the timeout expires or when enough packets
	 * have arrived to fill the store buffer.
	 */
	while (d->bd_hbuf == 0) {
		if (d->bd_immediate && d->bd_slen != 0) {
			/*
			 * A packet(s) either arrived since the previous
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
			splx(s);
			lck_mtx_unlock(bpf_mlock);
			return (ENXIO);
		}
		
		if (ioflag & IO_NDELAY)
			error = EWOULDBLOCK;
		else
			error = BPF_SLEEP(d, PRINET|PCATCH, "bpf",
					  d->bd_rtout);
		if (error == EINTR || error == ERESTART) {
			splx(s);
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
				splx(s);
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
	splx(s);

	/*
	 * Move data from hold buffer into user space.
	 * We know the entire buffer is transferred since
	 * we checked above that the read buffer is bpf_bufsize bytes.
	 */
	error = UIOMOVE(d->bd_hbuf, d->bd_hlen, UIO_READ, uio);

	s = splimp();
	d->bd_fbuf = d->bd_hbuf;
	d->bd_hbuf = 0;
	d->bd_hlen = 0;
	splx(s);
	lck_mtx_unlock(bpf_mlock);
	return (error);
}


/*
 * If there are processes sleeping on this descriptor, wake them up.
 */
static void
bpf_wakeup(struct bpf_d *d)
{
	wakeup((caddr_t)d);
	if (d->bd_async && d->bd_sig && d->bd_sigio)
		pgsigio(d->bd_sigio, d->bd_sig, 0);

#if BSD >= 199103
	selwakeup(&d->bd_sel);
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

/* keep in sync with bpf_movein above: */
#define MAX_DATALINK_HDR_LEN	(sizeof(struct firewire_header))

	int
bpfwrite(dev_t dev, struct uio *uio, __unused int ioflag)
{
	register struct bpf_d *d;
	struct ifnet *ifp;
	struct mbuf *m;
	int error;
	char 		  dst_buf[SOCKADDR_HDR_LEN + MAX_DATALINK_HDR_LEN];
	int datlen;

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1)
		return (ENXIO);
	
	lck_mtx_lock(bpf_mlock);
	
	if (d->bd_bif == 0) {
		lck_mtx_unlock(bpf_mlock);
	     return (ENXIO);
	}

	ifp = d->bd_bif->bif_ifp;

	if (uio->uio_resid == 0) {
		lck_mtx_unlock(bpf_mlock);
	     return (0);
	}
	((struct sockaddr *)dst_buf)->sa_len = sizeof(dst_buf);
	error = bpf_movein(uio, (int)d->bd_bif->bif_dlt, &m, 
			   d->bd_hdrcmplt ? 0 : (struct sockaddr *)dst_buf, &datlen);
	if (error) {
		lck_mtx_unlock(bpf_mlock);
	     return (error);
	}

	if ((unsigned)datlen > ifp->if_mtu) {
		lck_mtx_unlock(bpf_mlock);
	     return (EMSGSIZE);
	}

	lck_mtx_unlock(bpf_mlock);

	if (d->bd_hdrcmplt) {
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
 * receive and drop counts.  Should be called at splimp.
 */
static void
reset_d(struct bpf_d *d)
{
	if (d->bd_hbuf) {
		/* Free the hold buffer. */
		d->bd_fbuf = d->bd_hbuf;
		d->bd_hbuf = 0;
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
bpfioctl(dev_t dev, u_long cmd, caddr_t addr, __unused int flags, struct proc *p)
{
	register struct bpf_d *d;
	int s, error = 0;

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1)
		return (ENXIO);

	lck_mtx_lock(bpf_mlock);

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

			s = splimp();
			n = d->bd_slen;
			if (d->bd_hbuf)
				n += d->bd_hlen;
			splx(s);

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
				error = dlil_ioctl(0, ifp, cmd, addr);
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
			register u_int size = *(u_int *)addr;

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
	case BIOCSETF:
		if (proc_is64bit(p)) {
			error = bpf_setf(d, (struct user_bpf_program *)addr);
		}
		else {
			struct bpf_program *	tmpp;
			struct user_bpf_program	tmp;

			tmpp = (struct bpf_program *)addr;
			tmp.bf_len = tmpp->bf_len;
			tmp.bf_insns = CAST_USER_ADDR_T(tmpp->bf_insns);
			error = bpf_setf(d, &tmp);
		}
		break;

	/*
	 * Flush read packet buffer.
	 */
	case BIOCFLUSH:
		s = splimp();
		reset_d(d);
		splx(s);
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
		s = splimp();
		if (d->bd_promisc == 0) {
			error = ifnet_set_promiscuous(d->bd_bif->bif_ifp, 1);
			if (error == 0)
				d->bd_promisc = 1;
		}
		splx(s);
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
	case BIOCSETIF:
		error = bpf_setif(d, (struct ifreq *)addr);
		break;

	/*
	 * Set read timeout.
	 */
	case BIOCSRTIMEOUT:
		{
			struct timeval *tv = (struct timeval *)addr;

			/*
			 * Subtract 1 tick from tvtohz() since this isn't
			 * a one-shot timer.
			 */
			if ((error = itimerfix(tv)) == 0)
				d->bd_rtout = tvtohz(tv) - 1;
			break;
		}

	/*
	 * Get read timeout.
	 */
	case BIOCGRTIMEOUT:
		{
			struct timeval *tv = (struct timeval *)addr;

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
bpf_setf(struct bpf_d *d, struct user_bpf_program *fp)
{
	struct bpf_insn *fcode, *old;
	u_int flen, size;
	int s;

	old = d->bd_filter;
	if (fp->bf_insns == USER_ADDR_NULL) {
		if (fp->bf_len != 0)
			return (EINVAL);
		s = splimp();
		d->bd_filter = 0;
		reset_d(d);
		splx(s);
		if (old != 0)
			FREE((caddr_t)old, M_DEVBUF);
		return (0);
	}
	flen = fp->bf_len;
	if (flen > BPF_MAXINSNS)
		return (EINVAL);

	size = flen * sizeof(struct bpf_insn);
	fcode = (struct bpf_insn *) _MALLOC(size, M_DEVBUF, M_WAIT);
#ifdef __APPLE__
	if (fcode == NULL)
		return (ENOBUFS);
#endif
	if (copyin(fp->bf_insns, (caddr_t)fcode, size) == 0 &&
	    bpf_validate(fcode, (int)flen)) {
		s = splimp();
		d->bd_filter = fcode;
		reset_d(d);
		splx(s);
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
bpf_setif(struct bpf_d *d, struct ifreq *ifr)
{
	struct bpf_if *bp;
	int s, error;
	struct ifnet *theywant;

	theywant = ifunit(ifr->ifr_name);
	if (theywant == 0)
		return ENXIO;

	/*
	 * Look through attached interfaces for the named one.
	 */
	for (bp = bpf_iflist; bp != 0; bp = bp->bif_next) {
		struct ifnet *ifp = bp->bif_ifp;

		if (ifp == 0 || ifp != theywant)
			continue;
		/*
		 * We found the requested interface.
		 * If it's not up, return an error.
		 * Allocate the packet buffers if we need to.
		 * If we're already attached to requested interface,
		 * just flush the buffer.
		 */
		if ((ifp->if_flags & IFF_UP) == 0)
			return (ENETDOWN);

		if (d->bd_sbuf == 0) {
			error = bpf_allocbufs(d);
			if (error != 0)
				return (error);
		}
		s = splimp();
		if (bp != d->bd_bif) {
			if (d->bd_bif)
				/*
				 * Detach if attached to something else.
				 */
				bpf_detachd(d);

			bpf_attachd(d, bp);
		}
		reset_d(d);
		splx(s);
		return (0);
	}
	/* Not found. */
	return (ENXIO);
}

/*
 * Support for select() and poll() system calls
 *
 * Return true iff the specific operation will not block indefinitely.
 * Otherwise, return false but make a note that a selwakeup() must be done.
 */
int
bpfpoll(dev_t dev, int events, void * wql, struct proc *p)
{
	register struct bpf_d *d;
	register int s;
	int revents = 0;

	d = bpf_dtab[minor(dev)];
	if (d == 0 || d == (void *)1)
		return (ENXIO);

	lck_mtx_lock(bpf_mlock);

	/*
	 * An imitation of the FIONREAD ioctl code.
	 */
	if (d->bd_bif == NULL) {
		lck_mtx_unlock(bpf_mlock);
		return (ENXIO);
	}

	s = splimp();
	if (events & (POLLIN | POLLRDNORM)) {
		if (d->bd_hlen != 0 || (d->bd_immediate && d->bd_slen != 0))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(p, &d->bd_sel, wql);
	}
	splx(s);

	lck_mtx_unlock(bpf_mlock);
	return (revents);
}

/*
 * Incoming linkage from device drivers.  Process the packet pkt, of length
 * pktlen, which is stored in a contiguous buffer.  The packet is parsed
 * by each process' filter, and if accepted, stashed into the corresponding
 * buffer.
 */
void
bpf_tap(struct ifnet *ifp, u_char *pkt, u_int pktlen)
{
	struct bpf_if *bp;
	register struct bpf_d *d;
	register u_int slen;
	/*
	 * Note that the ipl does not have to be raised at this point.
	 * The only problem that could arise here is that if two different
	 * interfaces shared any data.  This is not the case.
	 */
	lck_mtx_lock(bpf_mlock);
	
	bp = ifp->if_bpf;
#ifdef __APPLE__
	if (bp) {
#endif
		for (d = bp->bif_dlist; d != 0; d = d->bd_next) {
			++d->bd_rcount;
			slen = bpf_filter(d->bd_filter, pkt, pktlen, pktlen);
			if (slen != 0)
				catchpacket(d, pkt, pktlen, slen, bcopy);
		}
#ifdef __APPLE__
    }
	lck_mtx_unlock(bpf_mlock);
#endif
}

/*
 * Copy data from an mbuf chain into a buffer.  This code is derived
 * from m_copydata in sys/uipc_mbuf.c.
 */
static void
bpf_mcopy(const void *src_arg, void *dst_arg, size_t len)
{
	const struct mbuf *m;
	u_int count;
	u_char *dst;

	m = src_arg;
	dst = dst_arg;
	while (len > 0) {
		if (m == 0)
			panic("bpf_mcopy");
		count = min(m->m_len, len);
		bcopy(mtod(m, const void *), dst, count);
		m = m->m_next;
		dst += count;
		len -= count;
	}
}

/*
 * Incoming linkage from device drivers, when packet is in an mbuf chain.
 */
void
bpf_mtap(struct ifnet *ifp, struct mbuf *m)
{
	struct bpf_if *bp;
	struct bpf_d *d;
	u_int pktlen, slen;
	struct mbuf *m0;

	lck_mtx_lock(bpf_mlock);
	
	bp = ifp->if_bpf;
	if (bp) {
	pktlen = 0;
	for (m0 = m; m0 != 0; m0 = m0->m_next)
		pktlen += m0->m_len;
	
		for (d = bp->bif_dlist; d != 0; d = d->bd_next) {
			if (!d->bd_seesent && (m->m_pkthdr.rcvif == NULL))
				continue;
			++d->bd_rcount;
			slen = bpf_filter(d->bd_filter, (u_char *)m, pktlen, 0);
			if (slen != 0)
				catchpacket(d, (u_char *)m, pktlen, slen, bpf_mcopy);
		}
	}
	
	lck_mtx_unlock(bpf_mlock);
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
	register struct bpf_hdr *hp;
	register int totlen, curlen;
	register int hdrlen = d->bd_bif->bif_hdrlen;
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
		if (d->bd_fbuf == 0) {
			/*
			 * We haven't completed the previous read yet,
			 * so drop the packet.
			 */
			++d->bd_dcount;
			return;
		}
		ROTATE_BUFFERS(d);
		bpf_wakeup(d);
		curlen = 0;
	}
	else if (d->bd_immediate)
		/*
		 * Immediate mode is set.  A packet arrived so any
		 * reads should be woken up.
		 */
		bpf_wakeup(d);

	/*
	 * Append the bpf header.
	 */
	hp = (struct bpf_hdr *)(d->bd_sbuf + curlen);
#if BSD >= 199103
	microtime(&hp->bh_tstamp);
#elif defined(sun)
	uniqtime(&hp->bh_tstamp);
#else
	hp->bh_tstamp = time;
#endif
	hp->bh_datalen = pktlen;
	hp->bh_hdrlen = hdrlen;
	/*
	 * Copy the packet data into the store buffer and update its length.
	 */
	(*cpfn)(pkt, (u_char *)hp + hdrlen, (hp->bh_caplen = totlen - hdrlen));
	d->bd_slen = curlen + totlen;
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
	struct bpf_if *bp;
	bp = (struct bpf_if *) _MALLOC(sizeof(*bp), M_DEVBUF, M_WAIT);
	if (bp == 0)
		panic("bpfattach");

	lck_mtx_lock(bpf_mlock);

	bp->bif_dlist = 0;
	bp->bif_ifp = ifp;
	bp->bif_dlt = dlt;

	bp->bif_next = bpf_iflist;
	bpf_iflist = bp;

	bp->bif_ifp->if_bpf = 0;

	/*
	 * Compute the length of the bpf header.  This is not necessarily
	 * equal to SIZEOF_BPF_HDR because we want to insert spacing such
	 * that the network layer header begins on a longword boundary (for
	 * performance reasons and to alleviate alignment restrictions).
	 */
	bp->bif_hdrlen = BPF_WORDALIGN(hdrlen + SIZEOF_BPF_HDR) - hdrlen;
	
	/* Take a reference on the interface */
	ifp_reference(ifp);

	lck_mtx_unlock(bpf_mlock);

#ifndef __APPLE__
	if (bootverbose)
		printf("bpf: %s%d attached\n", ifp->if_name, ifp->if_unit);
#endif
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
	struct bpf_if	*bp, *bp_prev;
	struct bpf_d	*d;
	int	s;

	s = splimp();
	
	lck_mtx_lock(bpf_mlock);

	/* Locate BPF interface information */
	bp_prev = NULL;
	for (bp = bpf_iflist; bp != NULL; bp = bp->bif_next) {
		if (ifp == bp->bif_ifp)
			break;
		bp_prev = bp;
	}

#ifdef __APPLE__
	/* Check for no BPF interface information */
	if (bp == NULL) {
		return;
	}
#endif

	/* Interface wasn't attached */
	if (bp->bif_ifp == NULL) {
		splx(s);
#ifndef __APPLE__
		printf("bpfdetach: %s%d was not attached\n", ifp->if_name,
		    ifp->if_unit);
#endif
		return;
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
	
	ifp_release(ifp);
	
	lck_mtx_unlock(bpf_mlock);

	FREE(bp, M_DEVBUF);

	splx(s);
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
        lck_grp_attr_setdefault(bpf_mlock_grp_attr);

        bpf_mlock_grp = lck_grp_alloc_init("bpf", bpf_mlock_grp_attr);

        bpf_mlock_attr = lck_attr_alloc_init();
        lck_attr_setdefault(bpf_mlock_attr);

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
			
			bpf_mlock = 0;
			bpf_mlock_attr = 0;
			bpf_mlock_grp = 0;
			bpf_mlock_grp_attr = 0;
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

#else /* !BPF */
#ifndef __APPLE__
/*
 * NOP stubs to allow bpf-using drivers to load and function.
 *
 * A 'better' implementation would allow the core bpf functionality
 * to be loaded at runtime.
 */

void
bpf_tap(ifp, pkt, pktlen)
	struct ifnet *ifp;
	register u_char *pkt;
	register u_int pktlen;
{
}

void
bpf_mtap(ifp, m)
	struct ifnet *ifp;
	struct mbuf *m;
{
}

void
bpfattach(ifp, dlt, hdrlen)
	struct ifnet *ifp;
	u_int dlt, hdrlen;
{
}

void
bpfdetach(ifp)
	struct ifnet *ifp;
{
}

u_int
bpf_filter(pc, p, wirelen, buflen)
	register const struct bpf_insn *pc;
	register u_char *p;
	u_int wirelen;
	register u_int buflen;
{
	return -1;	/* "no filter" behaviour */
}
#endif /* !defined(__APPLE__) */
#endif /* NBPFILTER > 0 */
