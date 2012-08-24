/*
 * Copyright (c) 1998-2012 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)uipc_socket.c	8.3 (Berkeley) 4/15/94
 * $FreeBSD: src/sys/kern/uipc_socket.c,v 1.68.2.16 2001/06/14 20:46:06 ume Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/poll.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/ev.h>
#include <sys/kdebug.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/priv.h>
#include <net/route.h>
#include <net/ntstat.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <machine/limits.h>
#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>
#include <kern/assert.h>
#include <kern/task.h>
#include <sys/kpi_mbuf.h>
#include <sys/mcache.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_framework.h>
#endif /* MAC */


int			so_cache_hw = 0;
int			so_cache_timeouts = 0;
int			so_cache_max_freed = 0;
int			cached_sock_count = 0;
__private_extern__ int	max_cached_sock_count = MAX_CACHED_SOCKETS;
struct socket		*socket_cache_head = 0;
struct socket		*socket_cache_tail = 0;
u_int32_t			so_cache_time = 0;
int			so_cache_init_done = 0;
struct zone		*so_cache_zone;

static lck_grp_t		*so_cache_mtx_grp;
static lck_attr_t		*so_cache_mtx_attr;
static lck_grp_attr_t	*so_cache_mtx_grp_attr;
lck_mtx_t				*so_cache_mtx;

#include <machine/limits.h>

static void	filt_sordetach(struct knote *kn);
static int	filt_soread(struct knote *kn, long hint);
static void	filt_sowdetach(struct knote *kn);
static int	filt_sowrite(struct knote *kn, long hint);
static void	filt_sockdetach(struct knote *kn);
static int	filt_sockev(struct knote *kn, long hint);

static int
sooptcopyin_timeval(struct sockopt *sopt, struct timeval * tv_p);

static int
sooptcopyout_timeval(struct sockopt *sopt, const struct timeval * tv_p);

static struct filterops soread_filtops = {
        .f_isfd = 1,
        .f_detach = filt_sordetach,
        .f_event = filt_soread,
};
static struct filterops sowrite_filtops = {
        .f_isfd = 1,
        .f_detach = filt_sowdetach,
        .f_event = filt_sowrite,
};
static struct filterops sock_filtops = {
	.f_isfd = 1,
	.f_detach = filt_sockdetach,
	.f_event = filt_sockev,
};

#define	EVEN_MORE_LOCKING_DEBUG 0
int socket_debug = 0;
int socket_zone = M_SOCKET;
so_gen_t	so_gencnt;	/* generation count for sockets */

MALLOC_DEFINE(M_SONAME, "soname", "socket name");
MALLOC_DEFINE(M_PCB, "pcb", "protocol control block");

#define	DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETSOCK, 0)
#define	DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETSOCK, 2)
#define	DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETSOCK, 1)
#define	DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETSOCK, 3)
#define	DBG_FNC_SOSEND		NETDBG_CODE(DBG_NETSOCK, (4 << 8) | 1)
#define	DBG_FNC_SORECEIVE	NETDBG_CODE(DBG_NETSOCK, (8 << 8))
#define	DBG_FNC_SOSHUTDOWN	NETDBG_CODE(DBG_NETSOCK, (9 << 8))

#define	MAX_SOOPTGETM_SIZE	(128 * MCLBYTES)


SYSCTL_DECL(_kern_ipc);

int somaxconn = SOMAXCONN;
SYSCTL_INT(_kern_ipc, KIPC_SOMAXCONN, somaxconn, CTLFLAG_RW | CTLFLAG_LOCKED, &somaxconn, 0, "");

/* Should we get a maximum also ??? */
static int sosendmaxchain = 65536;
static int sosendminchain = 16384;
static int sorecvmincopy  = 16384;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendminchain, CTLFLAG_RW | CTLFLAG_LOCKED, &sosendminchain,
    0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, sorecvmincopy, CTLFLAG_RW | CTLFLAG_LOCKED, &sorecvmincopy,
    0, "");

/*
 * Set to enable jumbo clusters (if available) for large writes when
 * the socket is marked with SOF_MULTIPAGES; see below.
 */
int sosendjcl = 1;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendjcl, CTLFLAG_RW | CTLFLAG_LOCKED, &sosendjcl, 0, "");

/*
 * Set this to ignore SOF_MULTIPAGES and use jumbo clusters for large
 * writes on the socket for all protocols on any network interfaces,
 * depending upon sosendjcl above.  Be extra careful when setting this
 * to 1, because sending down packets that cross physical pages down to
 * broken drivers (those that falsely assume that the physical pages
 * are contiguous) might lead to system panics or silent data corruption.
 * When set to 0, the system will respect SOF_MULTIPAGES, which is set
 * only for TCP sockets whose outgoing interface is IFNET_MULTIPAGES
 * capable.  Set this to 1 only for testing/debugging purposes.
 */
int sosendjcl_ignore_capab = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendjcl_ignore_capab, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sosendjcl_ignore_capab, 0, "");

int sodefunctlog = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sodefunctlog, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sodefunctlog, 0, "");

int sothrottlelog = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sothrottlelog, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sothrottlelog, 0, "");

/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */

/* sys_generic.c */
extern void postevent(struct socket *, struct sockbuf *, int);
extern void evsofree(struct socket *);
extern int tcp_notsent_lowat_check(struct socket *so);

/* TODO: these should be in header file */
extern int get_inpcb_str_size(void);
extern int get_tcp_str_size(void);
extern struct domain *pffinddomain(int);
extern struct protosw *pffindprotonotype(int, int);
extern int soclose_locked(struct socket *);
extern int soo_kqfilter(struct fileproc *, struct knote *, struct proc *);

#ifdef __APPLE__

vm_size_t	so_cache_zone_element_size;

static int sodelayed_copy(struct socket *, struct uio *, struct mbuf **, int *);
static void cached_sock_alloc(struct socket **, int);
static void cached_sock_free(struct socket *);
static void so_cache_timer(void *);

void soclose_wait_locked(struct socket *so);
int so_isdstlocal(struct socket *so);

/*
 * SOTCDB_NO_DSCP is set by default, to prevent the networking stack from
 * setting the DSCP code on the packet based on the service class; see
 * <rdar://problem/11277343> for details.
 */
__private_extern__ u_int32_t sotcdb = SOTCDB_NO_DSCP;
SYSCTL_INT(_kern_ipc, OID_AUTO, sotcdb, CTLFLAG_RW | CTLFLAG_LOCKED,
    &sotcdb, 0, "");

void
socketinit(void)
{
	vm_size_t str_size;

	if (so_cache_init_done) {
		printf("socketinit: already called...\n");
		return;
	}

	PE_parse_boot_argn("socket_debug", &socket_debug, sizeof (socket_debug));

	/*
	 * allocate lock group attribute and group for socket cache mutex
	 */
	so_cache_mtx_grp_attr = lck_grp_attr_alloc_init();

	so_cache_mtx_grp = lck_grp_alloc_init("so_cache",
	    so_cache_mtx_grp_attr);

	/*
	 * allocate the lock attribute for socket cache mutex
	 */
	so_cache_mtx_attr = lck_attr_alloc_init();

	so_cache_init_done = 1;

	/* cached sockets mutex */
	so_cache_mtx = lck_mtx_alloc_init(so_cache_mtx_grp, so_cache_mtx_attr);

	if (so_cache_mtx == NULL)
		return; /* we're hosed... */

	str_size = (vm_size_t)(sizeof (struct socket) + 4 +
	    get_inpcb_str_size() + 4 + get_tcp_str_size());

	so_cache_zone = zinit(str_size, 120000*str_size, 8192, "socache zone");
	zone_change(so_cache_zone, Z_CALLERACCT, FALSE);
	zone_change(so_cache_zone, Z_NOENCRYPT, TRUE);
#if TEMPDEBUG
	printf("cached_sock_alloc -- so_cache_zone size is %x\n", str_size);
#endif
	timeout(so_cache_timer, NULL, (SO_CACHE_FLUSH_INTERVAL * hz));

	so_cache_zone_element_size = str_size;

	sflt_init();

	_CASSERT(_SO_TC_MAX == SO_TC_STATS_MAX);

	socket_tclass_init();

	socket_flowadv_init();
}

static void
cached_sock_alloc(struct socket **so, int waitok)
{
	caddr_t	temp;
	register uintptr_t offset;

	lck_mtx_lock(so_cache_mtx);

	if (cached_sock_count) {
		cached_sock_count--;
		*so = socket_cache_head;
		if (*so == 0)
			panic("cached_sock_alloc: cached sock is null");

		socket_cache_head = socket_cache_head->cache_next;
		if (socket_cache_head)
			socket_cache_head->cache_prev = 0;
		else
			socket_cache_tail = 0;

		lck_mtx_unlock(so_cache_mtx);

		temp = (*so)->so_saved_pcb;
		bzero((caddr_t)*so, sizeof (struct socket));
#if TEMPDEBUG
		kprintf("cached_sock_alloc - retreiving cached sock %p - "
		    "count == %d\n", *so, cached_sock_count);
#endif
		(*so)->so_saved_pcb = temp;
		(*so)->cached_in_sock_layer = 1;
	} else {
#if TEMPDEBUG
		kprintf("Allocating cached sock %p from memory\n", *so);
#endif

		lck_mtx_unlock(so_cache_mtx);

		if (waitok)
			*so = (struct socket *)zalloc(so_cache_zone);
		else
			*so = (struct socket *)zalloc_noblock(so_cache_zone);

		if (*so == 0)
			return;

		bzero((caddr_t)*so, sizeof (struct socket));

		/*
		 * Define offsets for extra structures into our single block of
		 * memory. Align extra structures on longword boundaries.
		 */

		offset = (uintptr_t) *so;
		offset += sizeof (struct socket);

		offset = ALIGN(offset);

		(*so)->so_saved_pcb = (caddr_t)offset;
		offset += get_inpcb_str_size();

		offset = ALIGN(offset);

		((struct inpcb *)(void *)(*so)->so_saved_pcb)->inp_saved_ppcb =
		    (caddr_t)offset;
#if TEMPDEBUG
		kprintf("Allocating cached socket - %p, pcb=%p tcpcb=%p\n",
		    *so, (*so)->so_saved_pcb,
		    ((struct inpcb *)(*so)->so_saved_pcb)->inp_saved_ppcb);
#endif
	}

	(*so)->cached_in_sock_layer = 1;
}

static void
cached_sock_free(struct socket *so)
{

	lck_mtx_lock(so_cache_mtx);

	if (++cached_sock_count > max_cached_sock_count) {
		--cached_sock_count;
		lck_mtx_unlock(so_cache_mtx);
#if TEMPDEBUG
		kprintf("Freeing overflowed cached socket %p\n", so);
#endif
		zfree(so_cache_zone, so);
	} else {
#if TEMPDEBUG
		kprintf("Freeing socket %p into cache\n", so);
#endif
		if (so_cache_hw < cached_sock_count)
			so_cache_hw = cached_sock_count;

		so->cache_next = socket_cache_head;
		so->cache_prev = 0;
		if (socket_cache_head)
			socket_cache_head->cache_prev = so;
		else
			socket_cache_tail = so;

		so->cache_timestamp = so_cache_time;
		socket_cache_head = so;
		lck_mtx_unlock(so_cache_mtx);
	}

#if TEMPDEBUG
	kprintf("Freed cached sock %p into cache - count is %d\n",
	    so, cached_sock_count);
#endif
}

static void
so_update_last_owner_locked(
	struct socket	*so,
	proc_t			self)
{
	if (so->last_pid != 0)
	{
		if (self == NULL)
			self = current_proc();
		
		if (self)
		{
			so->last_upid = proc_uniqueid(self);
			so->last_pid = proc_pid(self);
		}
	}
}

static void
so_cache_timer(__unused void *dummy)
{
	register struct socket	*p;
	register int		n_freed = 0;

	lck_mtx_lock(so_cache_mtx);

	++so_cache_time;

	while ((p = socket_cache_tail)) {
		if ((so_cache_time - p->cache_timestamp) < SO_CACHE_TIME_LIMIT)
			break;

		so_cache_timeouts++;

		if ((socket_cache_tail = p->cache_prev))
			p->cache_prev->cache_next = 0;
		if (--cached_sock_count == 0)
			socket_cache_head = 0;

		zfree(so_cache_zone, p);

		if (++n_freed >= SO_CACHE_MAX_FREE_BATCH) {
			so_cache_max_freed++;
			break;
		}
	}
	lck_mtx_unlock(so_cache_mtx);

	timeout(so_cache_timer, NULL, (SO_CACHE_FLUSH_INTERVAL * hz));
}
#endif /* __APPLE__ */

/*
 * Get a socket structure from our zone, and initialize it.
 * We don't implement `waitok' yet (see comments in uipc_domain.c).
 * Note that it would probably be better to allocate socket
 * and PCB at the same time, but I'm not convinced that all
 * the protocols can be easily modified to do this.
 */
struct socket *
soalloc(int waitok, int dom, int type)
{
	struct socket *so;

	if ((dom == PF_INET) && (type == SOCK_STREAM)) {
		cached_sock_alloc(&so, waitok);
	} else {
		MALLOC_ZONE(so, struct socket *, sizeof (*so), socket_zone,
		    M_WAITOK);
		if (so != NULL)
			bzero(so, sizeof (*so));
	}
	/* XXX race condition for reentrant kernel */
//###LD Atomic add for so_gencnt
	if (so != NULL) {
		so->so_gencnt = ++so_gencnt;
		so->so_zone = socket_zone;
#if CONFIG_MACF_SOCKET
	     /* Convert waitok to  M_WAITOK/M_NOWAIT for MAC Framework. */
	     if (mac_socket_label_init(so, !waitok) != 0) {
			sodealloc(so);
			return (NULL);
		}
#endif /* MAC_SOCKET */
	}

	return (so);
}

/*
 * Returns:	0			Success
 *		EAFNOSUPPORT
 *		EPROTOTYPE
 *		EPROTONOSUPPORT
 *		ENOBUFS
 *	<pru_attach>:ENOBUFS[AF_UNIX]
 *	<pru_attach>:ENOBUFS[TCP]
 *	<pru_attach>:ENOMEM[TCP]
 *	<pru_attach>:EISCONN[TCP]
 *	<pru_attach>:???		[other protocol families, IPSEC]
 */
int
socreate(int dom, struct socket **aso, int type, int proto)
{
	struct proc *p = current_proc();
	register struct protosw *prp;
	register struct socket *so;
	register int error = 0;

#if TCPDEBUG
	extern int tcpconsdebug;
#endif
	if (proto)
		prp = pffindproto(dom, proto, type);
	else
		prp = pffindtype(dom, type);

	if (prp == 0 || prp->pr_usrreqs->pru_attach == 0) {
		if (pffinddomain(dom) == NULL) {
			return (EAFNOSUPPORT);
		}
		if (proto != 0) {
			if (pffindprotonotype(dom, proto) != NULL) {
				return (EPROTOTYPE);
			}
		}
		return (EPROTONOSUPPORT);
	}
	if (prp->pr_type != type)
		return (EPROTOTYPE);
	so = soalloc(1, dom, type);
	if (so == 0)
		return (ENOBUFS);

	TAILQ_INIT(&so->so_incomp);
	TAILQ_INIT(&so->so_comp);
	so->so_type = type;
	so->last_upid = proc_uniqueid(p);
	so->last_pid = proc_pid(p);

	so->so_cred = kauth_cred_proc_ref(p);
	if (!suser(kauth_cred_get(), NULL))
		so->so_state = SS_PRIV;

	so->so_proto = prp;
#ifdef __APPLE__
	so->so_rcv.sb_flags |= SB_RECV;	/* XXX */
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
#endif
	so->next_lock_lr = 0;
	so->next_unlock_lr = 0;

#if CONFIG_MACF_SOCKET
	mac_socket_label_associate(kauth_cred_get(), so);
#endif /* MAC_SOCKET */

//### Attachement will create the per pcb lock if necessary and increase refcount
	/*
	 * for creation, make sure it's done before
	 * socket is inserted in lists
	 */
	so->so_usecount++;

	error = (*prp->pr_usrreqs->pru_attach)(so, proto, p);
	if (error) {
		/*
		 * Warning:
		 * If so_pcb is not zero, the socket will be leaked,
		 * so protocol attachment handler must be coded carefuly
		 */
		so->so_state |= SS_NOFDREF;
		so->so_usecount--;
		sofreelastref(so, 1);	/* will deallocate the socket */
		return (error);
	}
#ifdef __APPLE__
	prp->pr_domain->dom_refs++;
	TAILQ_INIT(&so->so_evlist);

	/* Attach socket filters for this protocol */
	sflt_initsock(so);
#if TCPDEBUG
	if (tcpconsdebug == 2)
		so->so_options |= SO_DEBUG;
#endif
#endif
	so_set_default_traffic_class(so);
	/*
	 * If this is a background thread/task, mark the socket as such.
	 */
	if (proc_get_self_isbackground() != 0) {
		socket_set_traffic_mgt_flags(so, TRAFFIC_MGT_SO_BACKGROUND);
		so->so_background_thread = current_thread();
	}

	switch (dom) {
	/*
	 * Don't mark Unix domain or system sockets as eligible for defunct by default.
	*/
	case PF_LOCAL:
	case PF_SYSTEM:
		so->so_flags |= SOF_NODEFUNCT;
		break;
	default:
		break;
	}

	*aso = so;
	return (0);
}

/*
 * Returns:	0			Success
 *	<pru_bind>:EINVAL		Invalid argument [COMMON_START]
 *	<pru_bind>:EAFNOSUPPORT		Address family not supported
 *	<pru_bind>:EADDRNOTAVAIL	Address not available.
 *	<pru_bind>:EINVAL		Invalid argument
 *	<pru_bind>:EAFNOSUPPORT		Address family not supported [notdef]
 *	<pru_bind>:EACCES		Permission denied
 *	<pru_bind>:EADDRINUSE		Address in use
 *	<pru_bind>:EAGAIN		Resource unavailable, try again
 *	<pru_bind>:EPERM		Operation not permitted
 *	<pru_bind>:???
 *	<sf_bind>:???
 *
 * Notes:	It's not possible to fully enumerate the return codes above,
 *		since socket filter authors and protocol family authors may
 *		not choose to limit their error returns to those listed, even
 *		though this may result in some software operating incorrectly.
 *
 *		The error codes which are enumerated above are those known to
 *		be returned by the tcp_usr_bind function supplied.
 */
int
sobind(struct socket *so, struct sockaddr *nam)
{
	struct proc *p = current_proc();
	int error = 0;

	socket_lock(so, 1);
	VERIFY(so->so_usecount > 1);	
	so_update_last_owner_locked(so, p);

	/*
	 * If this is a bind request on a socket that has been marked
	 * as inactive, reject it now before we go any further.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		error = EINVAL;
		SODEFUNCTLOG(("%s[%d]: defunct so %p [%d,%d] (%d)\n",
		    __func__, proc_pid(p), so, INP_SOCKAF(so), INP_SOCKTYPE(so),
		    error));
		goto out;
	}

	/* Socket filter */
	error = sflt_bind(so, nam);

	if (error == 0)
		error = (*so->so_proto->pr_usrreqs->pru_bind)(so, nam, p);
out:
	socket_unlock(so, 1);

	if (error == EJUSTRETURN)
		error = 0;

	return (error);
}

void
sodealloc(struct socket *so)
{
	kauth_cred_unref(&so->so_cred);

	/* Remove any filters */
	sflt_termsock(so);

	so->so_gencnt = ++so_gencnt;

#if CONFIG_MACF_SOCKET
	mac_socket_label_destroy(so);
#endif /* MAC_SOCKET */
	if (so->cached_in_sock_layer == 1) {
		cached_sock_free(so);
	} else {
		if (so->cached_in_sock_layer == -1)
			panic("sodealloc: double dealloc: so=%p\n", so);
		so->cached_in_sock_layer = -1;
		FREE_ZONE(so, sizeof (*so), so->so_zone);
	}
}

/*
 * Returns:	0			Success
 *		EINVAL
 *		EOPNOTSUPP
 *	<pru_listen>:EINVAL[AF_UNIX]
 *	<pru_listen>:EINVAL[TCP]
 *	<pru_listen>:EADDRNOTAVAIL[TCP]	Address not available.
 *	<pru_listen>:EINVAL[TCP]	Invalid argument
 *	<pru_listen>:EAFNOSUPPORT[TCP]	Address family not supported [notdef]
 *	<pru_listen>:EACCES[TCP]	Permission denied
 *	<pru_listen>:EADDRINUSE[TCP]	Address in use
 *	<pru_listen>:EAGAIN[TCP]	Resource unavailable, try again
 *	<pru_listen>:EPERM[TCP]		Operation not permitted
 *	<sf_listen>:???
 *
 * Notes:	Other <pru_listen> returns depend on the protocol family; all
 *		<sf_listen> returns depend on what the filter author causes
 *		their filter to return.
 */
int
solisten(struct socket *so, int backlog)
{
	struct proc *p = current_proc();
	int error = 0;

	socket_lock(so, 1);
	
	if (so->so_proto == NULL) {
		error = EINVAL;
		goto out;
	}
	if ((so->so_proto->pr_flags & PR_CONNREQUIRED) == 0) {
		error = EOPNOTSUPP;
		goto out;
	}

	/*
	 * If the listen request is made on a socket that is not fully
	 * disconnected, or on a socket that has been marked as inactive,
	 * reject the request now.
	 */
	if ((so->so_state &
	    (SS_ISCONNECTED|SS_ISCONNECTING|SS_ISDISCONNECTING)) ||
	    (so->so_flags & SOF_DEFUNCT)) {
		error = EINVAL;
		if (so->so_flags & SOF_DEFUNCT) {
			SODEFUNCTLOG(("%s[%d]: defunct so %p [%d,%d] (%d)\n",
			    __func__, proc_pid(p), so, INP_SOCKAF(so),
			    INP_SOCKTYPE(so), error));
		}
		goto out;
	}

	if ((so->so_restrictions & SO_RESTRICT_DENYIN) != 0) {
		error = EPERM;
		goto out;
	}

	error = sflt_listen(so);

	if (error == 0) {
		error = (*so->so_proto->pr_usrreqs->pru_listen)(so, p);
	}

	if (error) {
		if (error == EJUSTRETURN)
			error = 0;
		goto out;
	}

	if (TAILQ_EMPTY(&so->so_comp))
		so->so_options |= SO_ACCEPTCONN;
	/*
	 * POSIX: The implementation may have an upper limit on the length of
	 * the listen queue-either global or per accepting socket. If backlog
	 * exceeds this limit, the length of the listen queue is set to the
	 * limit.
	 *
	 * If listen() is called with a backlog argument value that is less
	 * than 0, the function behaves as if it had been called with a backlog
	 * argument value of 0.
	 *
	 * A backlog argument of 0 may allow the socket to accept connections,
	 * in which case the length of the listen queue may be set to an
	 * implementation-defined minimum value.
	 */
	if (backlog <= 0 || backlog > somaxconn)
		backlog = somaxconn;

	so->so_qlimit = backlog;
out:
	socket_unlock(so, 1);
	return (error);
}

void
sofreelastref(struct socket *so, int dealloc)
{
	struct socket *head = so->so_head;

	/* Assume socket is locked */

	if ((!(so->so_flags & SOF_PCBCLEARING)) ||
	    ((so->so_state & SS_NOFDREF) == 0)) {
#ifdef __APPLE__
		selthreadclear(&so->so_snd.sb_sel);
		selthreadclear(&so->so_rcv.sb_sel);
		so->so_rcv.sb_flags &= ~SB_UPCALL;
		so->so_snd.sb_flags &= ~SB_UPCALL;
#endif
		return;
	}
	if (head != NULL) {
		socket_lock(head, 1);
		if (so->so_state & SS_INCOMP) {
			TAILQ_REMOVE(&head->so_incomp, so, so_list);
			head->so_incqlen--;
		} else if (so->so_state & SS_COMP) {
			/*
			 * We must not decommission a socket that's
			 * on the accept(2) queue.  If we do, then
			 * accept(2) may hang after select(2) indicated
			 * that the listening socket was ready.
			 */
#ifdef __APPLE__
			selthreadclear(&so->so_snd.sb_sel);
			selthreadclear(&so->so_rcv.sb_sel);
			so->so_rcv.sb_flags &= ~SB_UPCALL;
			so->so_snd.sb_flags &= ~SB_UPCALL;
#endif
			socket_unlock(head, 1);
			return;
		} else {
			panic("sofree: not queued");
		}
		head->so_qlen--;
		so->so_state &= ~SS_INCOMP;
		so->so_head = NULL;
		socket_unlock(head, 1);
	}
#ifdef __APPLE__
	selthreadclear(&so->so_snd.sb_sel);
	sbrelease(&so->so_snd);
#endif
	sorflush(so);

	/* 3932268: disable upcall */
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	so->so_snd.sb_flags &= ~SB_UPCALL;

	if (dealloc)
		sodealloc(so);
}

void
soclose_wait_locked(struct socket *so)
{
	lck_mtx_t *mutex_held;

	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	/*
	 * Double check here and return if there's no outstanding upcall;
	 * otherwise proceed further only if SOF_UPCALLCLOSEWAIT is set.
	 */
	if (!so->so_upcallusecount || !(so->so_flags & SOF_UPCALLCLOSEWAIT))
		return;
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	so->so_snd.sb_flags &= ~SB_UPCALL;
	so->so_flags |= SOF_CLOSEWAIT;
	(void) msleep((caddr_t)&so->so_upcall, mutex_held, (PZERO - 1),
	    "soclose_wait_locked", NULL);
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	so->so_flags &= ~SOF_CLOSEWAIT;
}

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
int
soclose_locked(struct socket *so)
{
	int error = 0;
	lck_mtx_t *mutex_held;
	struct timespec ts;

	if (so->so_usecount == 0) {
		panic("soclose: so=%p refcount=0\n", so);
	}

	sflt_notify(so, sock_evt_closing, NULL);

	if ((so->so_options & SO_ACCEPTCONN)) {
		struct socket *sp, *sonext;
		int socklock = 0;

		/*
		 * We do not want new connection to be added
		 * to the connection queues
		 */
		so->so_options &= ~SO_ACCEPTCONN;

		for (sp = TAILQ_FIRST(&so->so_incomp); sp != NULL; sp = sonext) {
			sonext = TAILQ_NEXT(sp, so_list);

			/* Radar 5350314
			 * skip sockets thrown away by tcpdropdropblreq
			 * they will get cleanup by the garbage collection.
			 * otherwise, remove the incomp socket from the queue
			 * and let soabort trigger the appropriate cleanup.
			 */
			if (sp->so_flags & SOF_OVERFLOW) 
				continue;

			if (so->so_proto->pr_getlock != NULL) {
				/* lock ordering for consistency with the rest of the stack,
				 * we lock the socket first and then grabb the head.
				 */
				socket_unlock(so, 0);
				socket_lock(sp, 1);
				socket_lock(so, 0);
				socklock = 1; 
			}

			TAILQ_REMOVE(&so->so_incomp, sp, so_list);
			so->so_incqlen--;

			if (sp->so_state & SS_INCOMP) {
				sp->so_state &= ~SS_INCOMP;
				sp->so_head = NULL;

				(void) soabort(sp);
			}

			if (socklock) 
				socket_unlock(sp, 1);
		}

		while ((sp = TAILQ_FIRST(&so->so_comp)) != NULL) {
			/* Dequeue from so_comp since sofree() won't do it */
			TAILQ_REMOVE(&so->so_comp, sp, so_list);
			so->so_qlen--;

			if (so->so_proto->pr_getlock != NULL) {
				socket_unlock(so, 0);
				socket_lock(sp, 1);
			}

			if (sp->so_state & SS_COMP) {
				sp->so_state &= ~SS_COMP;
				sp->so_head = NULL;

				(void) soabort(sp);
			}

			if (so->so_proto->pr_getlock != NULL) {
				socket_unlock(sp, 1);
				socket_lock(so, 0);
			}
		}
	}
	if (so->so_pcb == 0) {
		/* 3915887: mark the socket as ready for dealloc */
		so->so_flags |= SOF_PCBCLEARING;
		goto discard;
	}
	if (so->so_state & SS_ISCONNECTED) {
		if ((so->so_state & SS_ISDISCONNECTING) == 0) {
			error = sodisconnectlocked(so);
			if (error)
				goto drop;
		}
		if (so->so_options & SO_LINGER) {
			if ((so->so_state & SS_ISDISCONNECTING) &&
			    (so->so_state & SS_NBIO))
				goto drop;
			if (so->so_proto->pr_getlock != NULL)
				mutex_held = (*so->so_proto->pr_getlock)(so, 0);
			else
				mutex_held = so->so_proto->pr_domain->dom_mtx;
			while (so->so_state & SS_ISCONNECTED) {
				ts.tv_sec = (so->so_linger/100);
				ts.tv_nsec = (so->so_linger % 100) *
				    NSEC_PER_USEC * 1000 * 10;
				error = msleep((caddr_t)&so->so_timeo,
				    mutex_held, PSOCK | PCATCH, "soclose", &ts);
				if (error) {
					/*
					 * It's OK when the time fires,
					 * don't report an error
					 */
					if (error == EWOULDBLOCK)
						error = 0;
					break;
				}
			}
		}
	}
drop:
	if (so->so_usecount == 0)
		panic("soclose: usecount is zero so=%p\n", so);
	if (so->so_pcb && !(so->so_flags & SOF_PCBCLEARING)) {
		/*
		 * Let NetworkStatistics know this PCB is going away
		 * before we detach it.
		 */
		if (nstat_collect &&
		    (so->so_proto->pr_domain->dom_family == AF_INET ||
		    so->so_proto->pr_domain->dom_family == AF_INET6))
			nstat_pcb_detach(so->so_pcb);

		int error2 = (*so->so_proto->pr_usrreqs->pru_detach)(so);
		if (error == 0)
			error = error2;
	}
	if (so->so_usecount <= 0)
		panic("soclose: usecount is zero so=%p\n", so);
discard:
	if (so->so_pcb && so->so_state & SS_NOFDREF)
		panic("soclose: NOFDREF");
	so->so_state |= SS_NOFDREF;
	
	if ((so->so_flags & SOF_KNOTE) != 0)
		KNOTE(&so->so_klist, SO_FILT_HINT_LOCKED);
#ifdef __APPLE__
	so->so_proto->pr_domain->dom_refs--;
	evsofree(so);
#endif
	so->so_usecount--;
	sofree(so);
	return (error);
}

int
soclose(struct socket *so)
{
	int error = 0;
	socket_lock(so, 1);

	if (so->so_upcallusecount)
		soclose_wait_locked(so);

	if (so->so_retaincnt == 0) {
		error = soclose_locked(so);
	} else {
		/*
		 * if the FD is going away, but socket is
		 * retained in kernel remove its reference
		 */
		so->so_usecount--;
		if (so->so_usecount < 2)
			panic("soclose: retaincnt non null and so=%p "
			    "usecount=%d\n", so, so->so_usecount);
	}
	socket_unlock(so, 1);
	return (error);
}

/*
 * Must be called at splnet...
 */
/* Should already be locked */
int
soabort(struct socket *so)
{
	int error;

#ifdef MORE_LOCKING_DEBUG
	lck_mtx_t *mutex_held;

	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif

	if ((so->so_flags & SOF_ABORTED) == 0) {
		so->so_flags |= SOF_ABORTED;
		error = (*so->so_proto->pr_usrreqs->pru_abort)(so);
		if (error) {
			sofree(so);
			return (error);
		}
	}
	return (0);
}

int
soacceptlock(struct socket *so, struct sockaddr **nam, int dolock)
{
	int error;

	if (dolock)
		socket_lock(so, 1);

	if ((so->so_state & SS_NOFDREF) == 0)
		panic("soaccept: !NOFDREF");
	so->so_state &= ~SS_NOFDREF;
	error = (*so->so_proto->pr_usrreqs->pru_accept)(so, nam);

	if (dolock)
		socket_unlock(so, 1);
	return (error);
}

int
soaccept(struct socket *so, struct sockaddr **nam)
{
	return (soacceptlock(so, nam, 1));
}

int
soacceptfilter(struct socket *so)
{
	struct sockaddr *local = NULL, *remote = NULL;
	int error = 0;
	struct socket *head = so->so_head;

	/*
	 * Hold the lock even if this socket
	 * has not been made visible to the filter(s).
	 * For sockets with global locks, this protect against the 
	 * head or peer going away
	 */
	socket_lock(so, 1);
	if (sogetaddr_locked(so, &remote, 1) != 0 ||
	    sogetaddr_locked(so, &local, 0) != 0) {
		so->so_state &= ~(SS_NOFDREF | SS_COMP);
		so->so_head = NULL;
		socket_unlock(so, 1);
		soclose(so);
		/* Out of resources; try it again next time */
		error = ECONNABORTED;
		goto done;
	}

	error = sflt_accept(head, so, local, remote);

	/*
	 * If we get EJUSTRETURN from one of the filters, mark this socket
	 * as inactive and return it anyway.  This newly accepted socket
	 * will be disconnected later before we hand it off to the caller.
	 */
	if (error == EJUSTRETURN) {
		error = 0;
		(void) sosetdefunct(current_proc(), so,
		    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL, FALSE);
	}

	if (error != 0) {
		/*
		 * This may seem like a duplication to the above error
		 * handling part when we return ECONNABORTED, except
		 * the following is done while holding the lock since
		 * the socket has been exposed to the filter(s) earlier.
		 */
		so->so_state &= ~(SS_NOFDREF | SS_COMP);
		so->so_head = NULL;
		socket_unlock(so, 1);
		soclose(so);
		/* Propagate socket filter's error code to the caller */
	} else {
		socket_unlock(so, 1);
	}
done:
	/* Callee checks for NULL pointer */
	sock_freeaddr(remote);
	sock_freeaddr(local);
	return (error);
}

/*
 * Returns:	0			Success
 *		EOPNOTSUPP		Operation not supported on socket
 *		EISCONN			Socket is connected
 *	<pru_connect>:EADDRNOTAVAIL	Address not available.
 *	<pru_connect>:EINVAL		Invalid argument
 *	<pru_connect>:EAFNOSUPPORT	Address family not supported [notdef]
 *	<pru_connect>:EACCES		Permission denied
 *	<pru_connect>:EADDRINUSE	Address in use
 *	<pru_connect>:EAGAIN		Resource unavailable, try again
 *	<pru_connect>:EPERM		Operation not permitted
 *	<sf_connect_out>:???		[anything a filter writer might set]
 */
int
soconnectlock(struct socket *so, struct sockaddr *nam, int dolock)
{
	int error;
	struct proc *p = current_proc();

	if (dolock)
		socket_lock(so, 1);
	
	/*
	 * If this is a listening socket or if this is a previously-accepted
	 * socket that has been marked as inactive, reject the connect request.
	 */
	if ((so->so_options & SO_ACCEPTCONN) || (so->so_flags & SOF_DEFUNCT)) {
		error = EOPNOTSUPP;
		if (so->so_flags & SOF_DEFUNCT) {
			SODEFUNCTLOG(("%s[%d]: defunct so %p [%d,%d] (%d)\n",
			    __func__, proc_pid(p), so, INP_SOCKAF(so),
			    INP_SOCKTYPE(so), error));
		}
		if (dolock)
			socket_unlock(so, 1);
		return (error);
	}

	if ((so->so_restrictions & SO_RESTRICT_DENYOUT) != 0) {
		if (dolock)
			socket_unlock(so, 1);
		return (EPERM);
	}

	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.
	 * This allows user to disconnect by connecting to, e.g.,
	 * a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnectlocked(so)))) {
		error = EISCONN;
	} else {
		/*
		 * Run connect filter before calling protocol:
		 *  - non-blocking connect returns before completion;
		 */
		error = sflt_connectout(so, nam);

		if (error) {
			if (error == EJUSTRETURN)
				error = 0;
		} else {
			error = (*so->so_proto->pr_usrreqs->pru_connect)(so, nam, p);
		}
	}
	if (dolock)
		socket_unlock(so, 1);
	return (error);
}

int
soconnect(struct socket *so, struct sockaddr *nam)
{
	return (soconnectlock(so, nam, 1));
}

/*
 * Returns:	0			Success
 *	<pru_connect2>:EINVAL[AF_UNIX]
 *	<pru_connect2>:EPROTOTYPE[AF_UNIX]
 *	<pru_connect2>:???		[other protocol families]
 *
 * Notes:	<pru_connect2> is not supported by [TCP].
 */
int
soconnect2(struct socket *so1, struct socket *so2)
{
	int error;

	socket_lock(so1, 1);
	if (so2->so_proto->pr_lock)
		socket_lock(so2, 1);

	error = (*so1->so_proto->pr_usrreqs->pru_connect2)(so1, so2);

	socket_unlock(so1, 1);
	if (so2->so_proto->pr_lock)
		socket_unlock(so2, 1);
	return (error);
}

int
sodisconnectlocked(struct socket *so)
{
	int error;

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		error = ENOTCONN;
		goto bad;
	}
	if (so->so_state & SS_ISDISCONNECTING) {
		error = EALREADY;
		goto bad;
	}

	error = (*so->so_proto->pr_usrreqs->pru_disconnect)(so);

	if (error == 0) {
		sflt_notify(so, sock_evt_disconnected, NULL);
	}
bad:
	return (error);
}

/* Locking version */
int
sodisconnect(struct socket *so)
{
	int error;

	socket_lock(so, 1);
	error = sodisconnectlocked(so);
	socket_unlock(so, 1);
	return (error);
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_DONTWAIT : M_WAIT)

/*
 * sosendcheck will lock the socket buffer if it isn't locked and
 * verify that there is space for the data being inserted.
 *
 * Returns:	0			Success
 *		EPIPE
 *	sblock:EWOULDBLOCK
 *	sblock:EINTR
 *	sbwait:EBADF
 *	sbwait:EINTR
 *	[so_error]:???
 */
static int
sosendcheck(struct socket *so, struct sockaddr *addr, int32_t resid, int32_t clen,
    int32_t atomic, int flags, int *sblocked)
{
	int 	error = 0;
	int32_t space;
	int	assumelock = 0;

restart:
	if (*sblocked == 0) {
		if ((so->so_snd.sb_flags & SB_LOCK) != 0 &&
		    so->so_send_filt_thread != 0 &&
		    so->so_send_filt_thread == current_thread()) {
			/*
			 * We're being called recursively from a filter,
			 * allow this to continue. Radar 4150520.
			 * Don't set sblocked because we don't want
			 * to perform an unlock later.
			 */
			assumelock = 1;
		} else {
			error = sblock(&so->so_snd, SBLOCKWAIT(flags));
			if (error) {
				if (so->so_flags & SOF_DEFUNCT)
					goto defunct;
				return (error);
			}
			*sblocked = 1;
		}
	}

	/*
	 * If a send attempt is made on a socket that has been marked
	 * as inactive (disconnected), reject the request.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
defunct:
		error = EPIPE;
		SODEFUNCTLOG(("%s[%d]: defunct so %p [%d,%d] (%d)\n", __func__,
		    proc_selfpid(), so, INP_SOCKAF(so), INP_SOCKTYPE(so),
		    error));
		return (error);
	}

	if (so->so_state & SS_CANTSENDMORE)
		return (EPIPE);

	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		return (error);
	}

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		if ((so->so_proto->pr_flags & PR_CONNREQUIRED) != 0) {
			if ((so->so_state & SS_ISCONFIRMING) == 0 &&
			    !(resid == 0 && clen != 0))
				return (ENOTCONN);
		} else if (addr == 0 && !(flags&MSG_HOLD)) {
			return ((so->so_proto->pr_flags & PR_CONNREQUIRED) ?
			    ENOTCONN : EDESTADDRREQ);
		}
	}
	space = sbspace(&so->so_snd);
	if (flags & MSG_OOB)
		space += 1024;
	if ((atomic && resid > so->so_snd.sb_hiwat) ||
	    clen > so->so_snd.sb_hiwat)
		return (EMSGSIZE);
	if ((space < resid + clen &&
	    (atomic || space < (int32_t)so->so_snd.sb_lowat || space < clen)) ||
	    (so->so_type == SOCK_STREAM && so_wait_for_if_feedback(so))) {
		if ((so->so_state & SS_NBIO) || (flags & MSG_NBIO) ||
		    assumelock) {
			return (EWOULDBLOCK);
		}
		sbunlock(&so->so_snd, 1);
		*sblocked = 0;
		error = sbwait(&so->so_snd);
		if (error) {
			if (so->so_flags & SOF_DEFUNCT)
				goto defunct;
			return (error);
		}
		goto restart;
	}

	return (0);
}

/*
 * Send on a socket.
 * If send must go all at once and message is larger than
 * send buffering, then hard error.
 * Lock against other senders.
 * If must go all at once and not enough room now, then
 * inform user that this would block and do nothing.
 * Otherwise, if nonblocking, send as much as possible.
 * The data to be sent is described by "uio" if nonzero,
 * otherwise by the mbuf chain "top" (which must be null
 * if uio is not).  Data provided in mbuf chain must be small
 * enough to send all at once.
 *
 * Returns nonzero on error, timeout or signal; callers
 * must check for short counts if EINTR/ERESTART are returned.
 * Data and control buffers are freed on return.
 * Experiment:
 * MSG_HOLD: go thru most of sosend(), but just enqueue the mbuf
 * MSG_SEND: go thru as for MSG_HOLD on current fragment, then
 *  point at the mbuf chain being constructed and go from there.
 *
 * Returns:	0			Success
 *		EOPNOTSUPP
 *		EINVAL
 *		ENOBUFS
 *	uiomove:EFAULT
 *	sosendcheck:EPIPE
 *	sosendcheck:EWOULDBLOCK
 *	sosendcheck:EINTR
 *	sosendcheck:EBADF
 *	sosendcheck:EINTR
 *	sosendcheck:???			[value from so_error]
 *	<pru_send>:ECONNRESET[TCP]
 *	<pru_send>:EINVAL[TCP]
 *	<pru_send>:ENOBUFS[TCP]
 *	<pru_send>:EADDRINUSE[TCP]
 *	<pru_send>:EADDRNOTAVAIL[TCP]
 *	<pru_send>:EAFNOSUPPORT[TCP]
 *	<pru_send>:EACCES[TCP]
 *	<pru_send>:EAGAIN[TCP]
 *	<pru_send>:EPERM[TCP]
 *	<pru_send>:EMSGSIZE[TCP]
 *	<pru_send>:EHOSTUNREACH[TCP]
 *	<pru_send>:ENETUNREACH[TCP]
 *	<pru_send>:ENETDOWN[TCP]
 *	<pru_send>:ENOMEM[TCP]
 *	<pru_send>:ENOBUFS[TCP]
 *	<pru_send>:???[TCP]		[ignorable: mostly IPSEC/firewall/DLIL]
 *	<pru_send>:EINVAL[AF_UNIX]
 *	<pru_send>:EOPNOTSUPP[AF_UNIX]
 *	<pru_send>:EPIPE[AF_UNIX]
 *	<pru_send>:ENOTCONN[AF_UNIX]
 *	<pru_send>:EISCONN[AF_UNIX]
 *	<pru_send>:???[AF_UNIX]		[whatever a filter author chooses]
 *	<sf_data_out>:???		[whatever a filter author chooses]
 *
 * Notes:	Other <pru_send> returns depend on the protocol family; all
 *		<sf_data_out> returns depend on what the filter author causes
 *		their filter to return.
 */
int
sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags)
{
	struct mbuf **mp;
	register struct mbuf *m, *freelist = NULL;
	register int32_t space, len, resid;
	int clen = 0, error, dontroute, mlen, sendflags;
	int atomic = sosendallatonce(so) || top;
	int sblocked = 0;
	struct proc *p = current_proc();

	if (uio) {
		// LP64todo - fix this!
		resid = uio_resid(uio);
	} else {
		resid = top->m_pkthdr.len;
	}
	KERNEL_DEBUG((DBG_FNC_SOSEND | DBG_FUNC_START), so, resid,
	    so->so_snd.sb_cc, so->so_snd.sb_lowat, so->so_snd.sb_hiwat);

	socket_lock(so, 1);
	so_update_last_owner_locked(so, p);
	
	if (so->so_type != SOCK_STREAM && (flags & MSG_OOB) != 0) {
		error = EOPNOTSUPP;
		socket_unlock(so, 1);
		goto out;
	}

	/*
	 * In theory resid should be unsigned.
	 * However, space must be signed, as it might be less than 0
	 * if we over-committed, and we must use a signed comparison
	 * of space and resid.  On the other hand, a negative resid
	 * causes us to loop sending 0-length segments to the protocol.
	 *
	 * Also check to make sure that MSG_EOR isn't used on SOCK_STREAM
	 * type sockets since that's an error.
	 */
	if (resid < 0 || (so->so_type == SOCK_STREAM && (flags & MSG_EOR))) {
		error = EINVAL;
		socket_unlock(so, 1);
		goto out;
	}

	dontroute =
	    (flags & MSG_DONTROUTE) && (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgsnd);
	if (control)
		clen = control->m_len;

	do {
		error = sosendcheck(so, addr, resid, clen, atomic, flags,
		    &sblocked);
		if (error) {
			goto release;
		}
		mp = &top;
		space = sbspace(&so->so_snd) - clen + ((flags & MSG_OOB) ?
		    1024 : 0);

		do {
			if (uio == NULL) {
				/*
				 * Data is prepackaged in "top".
				 */
				resid = 0;
				if (flags & MSG_EOR)
					top->m_flags |= M_EOR;
			} else {
				int chainlength;
				int bytes_to_copy;
				boolean_t jumbocl;

				bytes_to_copy = imin(resid, space);

				if (sosendminchain > 0) {
					chainlength = 0;
				} else {
					chainlength = sosendmaxchain;
				}

				/*
				 * Attempt to use larger than system page-size
				 * clusters for large writes only if there is
				 * a jumbo cluster pool and if the socket is
				 * marked accordingly.
				 */
				jumbocl = sosendjcl && njcl > 0 &&
				    ((so->so_flags & SOF_MULTIPAGES) ||
				    sosendjcl_ignore_capab);

				socket_unlock(so, 0);

				do {
					int num_needed;
					int hdrs_needed = (top == 0) ? 1 : 0;

					/*
					 * try to maintain a local cache of mbuf
					 * clusters needed to complete this
					 * write the list is further limited to
					 * the number that are currently needed
					 * to fill the socket this mechanism
					 * allows a large number of mbufs/
					 * clusters to be grabbed under a single
					 * mbuf lock... if we can't get any
					 * clusters, than fall back to trying
					 * for mbufs if we fail early (or
					 * miscalcluate the number needed) make
					 * sure to release any clusters we
					 * haven't yet consumed.
					 */
					if (freelist == NULL &&
					    bytes_to_copy > MBIGCLBYTES &&
					    jumbocl) {
						num_needed =
						    bytes_to_copy / M16KCLBYTES;

						if ((bytes_to_copy -
						    (num_needed * M16KCLBYTES))
						    >= MINCLSIZE)
							num_needed++;

						freelist =
						    m_getpackets_internal(
						    (unsigned int *)&num_needed,
						    hdrs_needed, M_WAIT, 0,
						    M16KCLBYTES);
						/*
						 * Fall back to 4K cluster size
						 * if allocation failed
						 */
					}

					if (freelist == NULL &&
					    bytes_to_copy > MCLBYTES) {
						num_needed =
						    bytes_to_copy / MBIGCLBYTES;

						if ((bytes_to_copy -
						    (num_needed * MBIGCLBYTES)) >=
						    MINCLSIZE)
							num_needed++;

						freelist =
						    m_getpackets_internal(
						    (unsigned int *)&num_needed,
						    hdrs_needed, M_WAIT, 0,
						    MBIGCLBYTES);
						/*
						 * Fall back to cluster size
						 * if allocation failed
						 */
					}

					if (freelist == NULL &&
					    bytes_to_copy > MINCLSIZE) {
						num_needed =
						    bytes_to_copy / MCLBYTES;

						if ((bytes_to_copy -
						    (num_needed * MCLBYTES)) >=
						    MINCLSIZE)
							num_needed++;

						freelist =
						    m_getpackets_internal(
						    (unsigned int *)&num_needed,
						    hdrs_needed, M_WAIT, 0,
						    MCLBYTES);
						/*
						 * Fall back to a single mbuf
						 * if allocation failed
						 */
					}

					if (freelist == NULL) {
						if (top == 0)
							MGETHDR(freelist,
							    M_WAIT, MT_DATA);
						else
							MGET(freelist,
							    M_WAIT, MT_DATA);

						if (freelist == NULL) {
							error = ENOBUFS;
							socket_lock(so, 0);
							goto release;
						}
						/*
						 * For datagram protocols,
						 * leave room for protocol
						 * headers in first mbuf.
						 */
						if (atomic && top == 0 &&
						    bytes_to_copy < MHLEN) {
							MH_ALIGN(freelist,
							    bytes_to_copy);
						}
					}
					m = freelist;
					freelist = m->m_next;
					m->m_next = NULL;

					if ((m->m_flags & M_EXT))
						mlen = m->m_ext.ext_size;
					else if ((m->m_flags & M_PKTHDR))
						mlen =
						    MHLEN - m_leadingspace(m);
					else
						mlen = MLEN;
					len = imin(mlen, bytes_to_copy);

					chainlength += len;

					space -= len;

					error = uiomove(mtod(m, caddr_t),
					    len, uio);

					resid = uio_resid(uio);

					m->m_len = len;
					*mp = m;
					top->m_pkthdr.len += len;
					if (error)
						break;
					mp = &m->m_next;
					if (resid <= 0) {
						if (flags & MSG_EOR)
							top->m_flags |= M_EOR;
						break;
					}
					bytes_to_copy = min(resid, space);

				} while (space > 0 &&
				    (chainlength < sosendmaxchain || atomic ||
				    resid < MINCLSIZE));

				socket_lock(so, 0);

				if (error)
					goto release;
			}

			if (flags & (MSG_HOLD|MSG_SEND)) {
				/* Enqueue for later, go away if HOLD */
				register struct mbuf *mb1;
				if (so->so_temp && (flags & MSG_FLUSH)) {
					m_freem(so->so_temp);
					so->so_temp = NULL;
				}
				if (so->so_temp)
					so->so_tail->m_next = top;
				else
					so->so_temp = top;
				mb1 = top;
				while (mb1->m_next)
					mb1 = mb1->m_next;
				so->so_tail = mb1;
				if (flags & MSG_HOLD) {
					top = NULL;
					goto release;
				}
				top = so->so_temp;
			}
			if (dontroute)
				so->so_options |= SO_DONTROUTE;

			/* Compute flags here, for pru_send and NKEs */
			sendflags = (flags & MSG_OOB) ? PRUS_OOB :
			    /*
			     * If the user set MSG_EOF, the protocol
			     * understands this flag and nothing left to
			     * send then use PRU_SEND_EOF instead of PRU_SEND.
			     */
			    ((flags & MSG_EOF) &&
			     (so->so_proto->pr_flags & PR_IMPLOPCL) &&
			     (resid <= 0)) ?
				PRUS_EOF :
			    /* If there is more to send set PRUS_MORETOCOME */
			    (resid > 0 && space > 0) ? PRUS_MORETOCOME : 0;

			/*
			 * Socket filter processing
			 */
			error = sflt_data_out(so, addr, &top, &control,
						(sendflags & MSG_OOB) ? sock_data_filt_flag_oob : 0);
			if (error) {
				if (error == EJUSTRETURN) {
					error = 0;
					clen = 0;
					control = 0;
					top = 0;
				}

				goto release;
			}
			/*
			 * End Socket filter processing
			 */

			error = (*so->so_proto->pr_usrreqs->pru_send)
				(so, sendflags, top, addr, control, p);
#ifdef __APPLE__
			if (flags & MSG_SEND)
				so->so_temp = NULL;
#endif
			if (dontroute)
				so->so_options &= ~SO_DONTROUTE;

			clen = 0;
			control = 0;
			top = 0;
			mp = &top;
			if (error)
				goto release;
		} while (resid && space > 0);
	} while (resid);

release:
	if (sblocked)
		sbunlock(&so->so_snd, 0);	/* will unlock socket */
	else
		socket_unlock(so, 1);
out:
	if (top)
		m_freem(top);
	if (control)
		m_freem(control);
	if (freelist)
		m_freem_list(freelist);

	KERNEL_DEBUG(DBG_FNC_SOSEND | DBG_FUNC_END, so, resid, so->so_snd.sb_cc,
	    space, error);

	return (error);
}

/*
 * Implement receive operations on a socket.
 * We depend on the way that records are added to the sockbuf
 * by sbappend*.  In particular, each record (mbufs linked through m_next)
 * must begin with an address if the protocol so specifies,
 * followed by an optional mbuf or mbufs containing ancillary data,
 * and then zero or more mbufs of data.
 * In order to avoid blocking network interrupts for the entire time here,
 * we splx() while doing the actual copy to user space.
 * Although the sockbuf is locked, new data may still be appended,
 * and thus we must maintain consistency of the sockbuf during that time.
 *
 * The caller may receive the data as a single mbuf chain by supplying
 * an mbuf **mp0 for use in returning the chain.  The uio is then used
 * only for the count in uio_resid.
 *
 * Returns:	0			Success
 *		ENOBUFS
 *		ENOTCONN
 *		EWOULDBLOCK
 *	uiomove:EFAULT
 *	sblock:EWOULDBLOCK
 *	sblock:EINTR
 *	sbwait:EBADF
 *	sbwait:EINTR
 *	sodelayed_copy:EFAULT
 *	<pru_rcvoob>:EINVAL[TCP]
 *	<pru_rcvoob>:EWOULDBLOCK[TCP]
 *	<pru_rcvoob>:???
 *	<pr_domain->dom_externalize>:EMSGSIZE[AF_UNIX]
 *	<pr_domain->dom_externalize>:ENOBUFS[AF_UNIX]
 *	<pr_domain->dom_externalize>:???
 *
 * Notes:	Additional return values from calls through <pru_rcvoob> and
 *		<pr_domain->dom_externalize> depend on protocols other than
 *		TCP or AF_UNIX, which are documented above.
 */
int
soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	register struct mbuf *m, **mp, *ml = NULL;
	register int flags, len, error, offset;
	struct protosw *pr = so->so_proto;
	struct mbuf *nextrecord;
	int moff, type = 0;
	int orig_resid = uio_resid(uio);
	struct mbuf *free_list;
	int delayed_copy_len;
	int can_delay;
	int need_event;
	struct proc *p = current_proc();

	// LP64todo - fix this!
	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_START, so, uio_resid(uio),
	    so->so_rcv.sb_cc, so->so_rcv.sb_lowat, so->so_rcv.sb_hiwat);

	socket_lock(so, 1);
	so_update_last_owner_locked(so, p);

#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount == 1)
		panic("soreceive: so=%x no other reference on socket\n", so);
#endif
	mp = mp0;
	if (psa)
		*psa = 0;
	if (controlp)
		*controlp = 0;
	if (flagsp)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;

	/*
	 * If a recv attempt is made on a previously-accepted socket
	 * that has been marked as inactive (disconnected), reject
	 * the request.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		struct sockbuf *sb = &so->so_rcv;

		error = ENOTCONN;
		SODEFUNCTLOG(("%s[%d]: defunct so %p [%d,%d] (%d)\n", __func__,
		    proc_pid(p), so, INP_SOCKAF(so), INP_SOCKTYPE(so), error));
		/*
		 * This socket should have been disconnected and flushed
		 * prior to being returned from sodefunct(); there should
		 * be no data on its receive list, so panic otherwise.
		 */
		if (so->so_state & SS_DEFUNCT)
			sb_empty_assert(sb, __func__);
		socket_unlock(so, 1);
		return (error);
	}

	/*
	 * When SO_WANTOOBFLAG is set we try to get out-of-band data
	 * regardless of the flags argument. Here is the case were
	 * out-of-band data is not inline.
	 */
	if ((flags & MSG_OOB) ||
	    ((so->so_options & SO_WANTOOBFLAG) != 0 &&
	    (so->so_options & SO_OOBINLINE) == 0 &&
	    (so->so_oobmark || (so->so_state & SS_RCVATMARK)))) {
		m = m_get(M_WAIT, MT_DATA);
		if (m == NULL) {
			socket_unlock(so, 1);
			KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END,
			    ENOBUFS, 0, 0, 0, 0);
			return (ENOBUFS);
		}
		error = (*pr->pr_usrreqs->pru_rcvoob)(so, m, flags & MSG_PEEK);
		if (error)
			goto bad;
		socket_unlock(so, 0);
		do {
			error = uiomove(mtod(m, caddr_t),
			    imin(uio_resid(uio), m->m_len), uio);
			m = m_free(m);
		} while (uio_resid(uio) && error == 0 && m);
		socket_lock(so, 0);
bad:
		if (m)
			m_freem(m);
#ifdef __APPLE__
		if ((so->so_options & SO_WANTOOBFLAG) != 0) {
			if (error == EWOULDBLOCK || error == EINVAL) {
				/*
				 * Let's try to get normal data:
				 * EWOULDBLOCK: out-of-band data not
				 * receive yet. EINVAL: out-of-band data
				 * already read.
				 */
				error = 0;
				goto nooob;
			} else if (error == 0 && flagsp) {
				*flagsp |= MSG_OOB;
			}
		}
		socket_unlock(so, 1);
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
		    0, 0, 0, 0);
#endif
		return (error);
	}
nooob:
	if (mp)
		*mp = (struct mbuf *)0;
	if (so->so_state & SS_ISCONFIRMING && uio_resid(uio))
		(*pr->pr_usrreqs->pru_rcvd)(so, 0);


	free_list = (struct mbuf *)0;
	delayed_copy_len = 0;
restart:
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1)
		printf("soreceive: sblock so=%p ref=%d on socket\n",
		    so, so->so_usecount);
#endif
	/*
	 * See if the socket has been closed (SS_NOFDREF|SS_CANTRCVMORE)
	 * and if so just return to the caller.  This could happen when
	 * soreceive() is called by a socket upcall function during the
	 * time the socket is freed.  The socket buffer would have been
	 * locked across the upcall, therefore we cannot put this thread
	 * to sleep (else we will deadlock) or return EWOULDBLOCK (else
	 * we may livelock), because the lock on the socket buffer will
	 * only be released when the upcall routine returns to its caller.
	 * Because the socket has been officially closed, there can be
	 * no further read on it.
	 */
	if ((so->so_state & (SS_NOFDREF | SS_CANTRCVMORE)) ==
	    (SS_NOFDREF | SS_CANTRCVMORE)) {
		socket_unlock(so, 1);
		return (0);
	}

	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error) {
		socket_unlock(so, 1);
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
		    0, 0, 0, 0);
		return (error);
	}

	m = so->so_rcv.sb_mb;
	/*
	 * If we have less data than requested, block awaiting more
	 * (subject to any timeout) if:
	 *   1. the current count is less than the low water mark, or
	 *   2. MSG_WAITALL is set, and it is possible to do the entire
	 *	receive operation at once if we block (resid <= hiwat).
	 *   3. MSG_DONTWAIT is not set
	 * If MSG_WAITALL is set but resid is larger than the receive buffer,
	 * we have to do the receive in sections, and thus risk returning
	 * a short count if a timeout or signal occurs after we start.
	 */
	if (m == 0 || (((flags & MSG_DONTWAIT) == 0 &&
	    so->so_rcv.sb_cc < uio_resid(uio)) &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && uio_resid(uio) <= so->so_rcv.sb_hiwat)) &&
	    m->m_nextpkt == 0 && (pr->pr_flags & PR_ATOMIC) == 0)) {
		/*
		 * Panic if we notice inconsistencies in the socket's
		 * receive list; both sb_mb and sb_cc should correctly
		 * reflect the contents of the list, otherwise we may
		 * end up with false positives during select() or poll()
		 * which could put the application in a bad state.
		 */
		SB_MB_CHECK(&so->so_rcv);

		if (so->so_error) {
			if (m)
				goto dontblock;
			error = so->so_error;
			if ((flags & MSG_PEEK) == 0)
				so->so_error = 0;
			goto release;
		}
		if (so->so_state & SS_CANTRCVMORE) {
			if (m)
				goto dontblock;
			else
				goto release;
		}
		for (; m; m = m->m_next)
			if (m->m_type == MT_OOBDATA || (m->m_flags & M_EOR)) {
				m = so->so_rcv.sb_mb;
				goto dontblock;
			}
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
		    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
			error = ENOTCONN;
			goto release;
		}
		if (uio_resid(uio) == 0)
			goto release;
		if ((so->so_state & SS_NBIO) ||
		    (flags & (MSG_DONTWAIT|MSG_NBIO))) {
			error = EWOULDBLOCK;
			goto release;
		}
		SBLASTRECORDCHK(&so->so_rcv, "soreceive sbwait 1");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive sbwait 1");
		sbunlock(&so->so_rcv, 1);
#if EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
			printf("Waiting for socket data\n");
#endif

		error = sbwait(&so->so_rcv);
#if EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
			printf("SORECEIVE - sbwait returned %d\n", error);
#endif
		if (so->so_usecount < 1)
			panic("soreceive: after 2nd sblock so=%p ref=%d on "
			    "socket\n", so, so->so_usecount);
		if (error) {
			socket_unlock(so, 1);
			KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
			    0, 0, 0, 0);
			return (error);
		}
		goto restart;
	}
dontblock:
	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgrcv);
	SBLASTRECORDCHK(&so->so_rcv, "soreceive 1");
	SBLASTMBUFCHK(&so->so_rcv, "soreceive 1");
	nextrecord = m->m_nextpkt;
	if ((pr->pr_flags & PR_ADDR) && m->m_type == MT_SONAME) {
		KASSERT(m->m_type == MT_SONAME, ("receive 1a"));
#if CONFIG_MACF_SOCKET_SUBSET
		/*
		 * Call the MAC framework for policy checking if we're in
		 * the user process context and the socket isn't connected.
		 */
		if (p != kernproc && !(so->so_state & SS_ISCONNECTED)) {
			struct mbuf *m0 = m;
			/*
			 * Dequeue this record (temporarily) from the receive
			 * list since we're about to drop the socket's lock
			 * where a new record may arrive and be appended to
			 * the list.  Upon MAC policy failure, the record
			 * will be freed.  Otherwise, we'll add it back to
			 * the head of the list.  We cannot rely on SB_LOCK
			 * because append operation uses the socket's lock.
			 */
			do {
				m->m_nextpkt = NULL;
				sbfree(&so->so_rcv, m);
				m = m->m_next;
			} while (m != NULL);
			m = m0;
			so->so_rcv.sb_mb = nextrecord;
			SB_EMPTY_FIXUP(&so->so_rcv);
			SBLASTRECORDCHK(&so->so_rcv, "soreceive 1a");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive 1a");
			socket_unlock(so, 0);
			if (mac_socket_check_received(proc_ucred(p), so,
			    mtod(m, struct sockaddr *)) != 0) {
				/*
				 * MAC policy failure; free this record and
				 * process the next record (or block until
				 * one is available).  We have adjusted sb_cc
				 * and sb_mbcnt above so there is no need to
				 * call sbfree() again.
				 */
				do {
					m = m_free(m);
				} while (m != NULL);
				/*
				 * Clear SB_LOCK but don't unlock the socket.
				 * Process the next record or wait for one.
				 */
				socket_lock(so, 0);
				sbunlock(&so->so_rcv, 1);
				goto restart;
			}
			socket_lock(so, 0);
			/*
			 * If the socket has been defunct'd, drop it.
			 */
			if (so->so_flags & SOF_DEFUNCT) {
				m_freem(m);
				error = ENOTCONN;
				goto release;
			}
			/*
			 * Re-adjust the socket receive list and re-enqueue
			 * the record in front of any packets which may have
			 * been appended while we dropped the lock.
			 */
			for (m = m0; m->m_next != NULL; m = m->m_next)
				sballoc(&so->so_rcv, m);
			sballoc(&so->so_rcv, m);
			if (so->so_rcv.sb_mb == NULL) {
				so->so_rcv.sb_lastrecord = m0;
				so->so_rcv.sb_mbtail = m;
			}
			m = m0;
			nextrecord = m->m_nextpkt = so->so_rcv.sb_mb;
			so->so_rcv.sb_mb = m;
			SBLASTRECORDCHK(&so->so_rcv, "soreceive 1b");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive 1b");
		}
#endif /* CONFIG_MACF_SOCKET_SUBSET */
		orig_resid = 0;
		if (psa) {
			*psa = dup_sockaddr(mtod(m, struct sockaddr *),
			    mp0 == 0);
			if ((*psa == 0) && (flags & MSG_NEEDSA)) {
				error = EWOULDBLOCK;
				goto release;
			}
		}
		if (flags & MSG_PEEK) {
			m = m->m_next;
		} else {
			sbfree(&so->so_rcv, m);
			if (m->m_next == 0 && so->so_rcv.sb_cc != 0)
				panic("soreceive: about to create invalid "
				    "socketbuf");
			MFREE(m, so->so_rcv.sb_mb);
			m = so->so_rcv.sb_mb;
			if (m != NULL) {
				m->m_nextpkt = nextrecord;
			} else {
				so->so_rcv.sb_mb = nextrecord;
				SB_EMPTY_FIXUP(&so->so_rcv);
			}
		}
	}

	/*
	 * Process one or more MT_CONTROL mbufs present before any data mbufs
	 * in the first mbuf chain on the socket buffer.  If MSG_PEEK, we
	 * just copy the data; if !MSG_PEEK, we call into the protocol to
	 * perform externalization.
	 */
	if (m != NULL && m->m_type == MT_CONTROL) {
		struct mbuf *cm = NULL, *cmn;
		struct mbuf **cme = &cm;
		struct sockbuf *sb_rcv = &so->so_rcv;
		struct mbuf **msgpcm = NULL;

		/*
		 * Externalizing the control messages would require us to
		 * drop the socket's lock below.  Once we re-acquire the
		 * lock, the mbuf chain might change.  In order to preserve
		 * consistency, we unlink all control messages from the
		 * first mbuf chain in one shot and link them separately
		 * onto a different chain.
		 */
		do {
			if (flags & MSG_PEEK) {
				if (controlp != NULL) {
					if (*controlp == NULL) {
						msgpcm = controlp;
					}
					*controlp = m_copy(m, 0, m->m_len);

					/* If we failed to allocate an mbuf,
					 * release any previously allocated
					 * mbufs for control data. Return 
					 * an error. Keep the mbufs in the
					 * socket as this is using 
					 * MSG_PEEK flag.
					 */
					if (*controlp == NULL) {
						m_freem(*msgpcm);
						error = ENOBUFS;
						goto release;
					}
					controlp = &(*controlp)->m_next;
				}
				m = m->m_next;
			} else {
				m->m_nextpkt = NULL;
				sbfree(sb_rcv, m);
				sb_rcv->sb_mb = m->m_next;
				m->m_next = NULL;
				*cme = m;
				cme = &(*cme)->m_next;
				m = sb_rcv->sb_mb;
			}
		} while (m != NULL && m->m_type == MT_CONTROL);

		if (!(flags & MSG_PEEK)) {
			if (sb_rcv->sb_mb != NULL) {
				sb_rcv->sb_mb->m_nextpkt = nextrecord;
			} else {
				sb_rcv->sb_mb = nextrecord;
				SB_EMPTY_FIXUP(sb_rcv);
			}
			if (nextrecord == NULL)
				sb_rcv->sb_lastrecord = m;
		}

		SBLASTRECORDCHK(&so->so_rcv, "soreceive ctl");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive ctl");

		while (cm != NULL) {
			int cmsg_type;

			cmn = cm->m_next;
			cm->m_next = NULL;
			cmsg_type = mtod(cm, struct cmsghdr *)->cmsg_type;

			/*
			 * Call the protocol to externalize SCM_RIGHTS message
			 * and return the modified message to the caller upon
			 * success.  Otherwise, all other control messages are
			 * returned unmodified to the caller.  Note that we
			 * only get into this loop if MSG_PEEK is not set.
			 */
			if (pr->pr_domain->dom_externalize != NULL &&
			    cmsg_type == SCM_RIGHTS) {
				/*
				 * Release socket lock: see 3903171.  This
				 * would also allow more records to be appended
				 * to the socket buffer.  We still have SB_LOCK
				 * set on it, so we can be sure that the head
				 * of the mbuf chain won't change.
				 */
				socket_unlock(so, 0);
				error = (*pr->pr_domain->dom_externalize)(cm);
				socket_lock(so, 0);
			} else {
				error = 0;
			}

			if (controlp != NULL && error == 0) {
				*controlp = cm;
				controlp = &(*controlp)->m_next;
				orig_resid = 0;
			} else {
				(void) m_free(cm);
			}
			cm = cmn;
		}
		/* 
		 * Update the value of nextrecord in case we received new
		 * records when the socket was unlocked above for 
		 * externalizing SCM_RIGHTS.
		 */
		if (m != NULL)
			nextrecord = sb_rcv->sb_mb->m_nextpkt;
		else
			nextrecord = sb_rcv->sb_mb;
		orig_resid = 0;
	}

	if (m != NULL) {
		if (!(flags & MSG_PEEK)) {
			/*
			 * We get here because m points to an mbuf following
			 * any MT_SONAME or MT_CONTROL mbufs which have been
			 * processed above.  In any case, m should be pointing
			 * to the head of the mbuf chain, and the nextrecord
			 * should be either NULL or equal to m->m_nextpkt.
			 * See comments above about SB_LOCK.
			 */
			if (m != so->so_rcv.sb_mb || m->m_nextpkt != nextrecord)
				panic("soreceive: post-control !sync so=%p "
				    "m=%p nextrecord=%p\n", so, m, nextrecord);

			if (nextrecord == NULL)
				so->so_rcv.sb_lastrecord = m;
		}
		type = m->m_type;
		if (type == MT_OOBDATA)
			flags |= MSG_OOB;
	} else {
		if (!(flags & MSG_PEEK)) {
			SB_EMPTY_FIXUP(&so->so_rcv);
		}
	}
	SBLASTRECORDCHK(&so->so_rcv, "soreceive 2");
	SBLASTMBUFCHK(&so->so_rcv, "soreceive 2");

	moff = 0;
	offset = 0;

	if (!(flags & MSG_PEEK) && uio_resid(uio) > sorecvmincopy)
		can_delay = 1;
	else
		can_delay = 0;

	need_event = 0;

	while (m && (uio_resid(uio) - delayed_copy_len) > 0 && error == 0) {
		if (m->m_type == MT_OOBDATA) {
			if (type != MT_OOBDATA)
				break;
		} else if (type == MT_OOBDATA) {
			break;
		}
		/*
		 * Make sure to allways set MSG_OOB event when getting
		 * out of band data inline.
		 */
		if ((so->so_options & SO_WANTOOBFLAG) != 0 &&
		    (so->so_options & SO_OOBINLINE) != 0 &&
		    (so->so_state & SS_RCVATMARK) != 0) {
			flags |= MSG_OOB;
		}
		so->so_state &= ~SS_RCVATMARK;
		len = uio_resid(uio) - delayed_copy_len;
		if (so->so_oobmark && len > so->so_oobmark - offset)
			len = so->so_oobmark - offset;
		if (len > m->m_len - moff)
			len = m->m_len - moff;
		/*
		 * If mp is set, just pass back the mbufs.
		 * Otherwise copy them out via the uio, then free.
		 * Sockbuf must be consistent here (points to current mbuf,
		 * it points to next record) when we drop priority;
		 * we must note any additions to the sockbuf when we
		 * block interrupts again.
		 */
		if (mp == 0) {
			SBLASTRECORDCHK(&so->so_rcv, "soreceive uiomove");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive uiomove");
			if (can_delay && len == m->m_len) {
				/*
				 * only delay the copy if we're consuming the
				 * mbuf and we're NOT in MSG_PEEK mode
				 * and we have enough data to make it worthwile
				 * to drop and retake the lock... can_delay
				 * reflects the state of the 2 latter
				 * constraints moff should always be zero
				 * in these cases
				 */
				delayed_copy_len += len;
			} else {
				if (delayed_copy_len) {
					error = sodelayed_copy(so, uio,
					    &free_list, &delayed_copy_len);

					if (error) {
						goto release;
					}
					/*
					 * can only get here if MSG_PEEK is not
					 * set therefore, m should point at the
					 * head of the rcv queue; if it doesn't,
					 * it means something drastically
					 * changed while we were out from behind
					 * the lock in sodelayed_copy. perhaps
					 * a RST on the stream. in any event,
					 * the stream has been interrupted. it's
					 * probably best just to return whatever
					 * data we've moved and let the caller
					 * sort it out...
					 */
					if (m != so->so_rcv.sb_mb) {
						break;
					}
				}
				socket_unlock(so, 0);
				error = uiomove(mtod(m, caddr_t) + moff,
				    (int)len, uio);
				socket_lock(so, 0);

				if (error)
					goto release;
			}
		} else {
			uio_setresid(uio, (uio_resid(uio) - len));
		}
		if (len == m->m_len - moff) {
			if (m->m_flags & M_EOR)
				flags |= MSG_EOR;
			if (flags & MSG_PEEK) {
				m = m->m_next;
				moff = 0;
			} else {
				nextrecord = m->m_nextpkt;
				sbfree(&so->so_rcv, m);
				m->m_nextpkt = NULL;

				if (mp) {
					*mp = m;
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = (struct mbuf *)0;
				} else {
					if (free_list == NULL)
						free_list = m;
					else
						ml->m_next = m;
					ml = m;
					so->so_rcv.sb_mb = m = m->m_next;
					ml->m_next = 0;
				}
				if (m != NULL) {
					m->m_nextpkt = nextrecord;
					if (nextrecord == NULL)
						so->so_rcv.sb_lastrecord = m;
				} else {
					so->so_rcv.sb_mb = nextrecord;
					SB_EMPTY_FIXUP(&so->so_rcv);
				}
				SBLASTRECORDCHK(&so->so_rcv, "soreceive 3");
				SBLASTMBUFCHK(&so->so_rcv, "soreceive 3");
			}
		} else {
			if (flags & MSG_PEEK) {
				moff += len;
			} else {
				if (mp != NULL) {
					int copy_flag;

					if (flags & MSG_DONTWAIT)
						copy_flag = M_DONTWAIT;
					else
						copy_flag = M_WAIT;
					*mp = m_copym(m, 0, len, copy_flag);
					if (*mp == NULL) {
						/*
					 	 * Failed to allocate an mbuf.
					 	 * Adjust uio_resid back, it was
					 	 * adjusted down by len bytes which
					 	 * we didn't copy over
					  	 */
						uio_setresid(uio, (uio_resid(uio) + len));
						break;
					}
				}
				m->m_data += len;
				m->m_len -= len;
				so->so_rcv.sb_cc -= len;
			}
		}
		if (so->so_oobmark) {
			if ((flags & MSG_PEEK) == 0) {
				so->so_oobmark -= len;
				if (so->so_oobmark == 0) {
					so->so_state |= SS_RCVATMARK;
					/*
					 * delay posting the actual event until
					 * after any delayed copy processing
					 * has finished
					 */
					need_event = 1;
					break;
				}
			} else {
				offset += len;
				if (offset == so->so_oobmark)
					break;
			}
		}
		if (flags & MSG_EOR)
			break;
		/*
		 * If the MSG_WAITALL or MSG_WAITSTREAM flag is set
		 * (for non-atomic socket), we must not quit until
		 * "uio->uio_resid == 0" or an error termination.
		 * If a signal/timeout occurs, return with a short
		 * count but without error.  Keep sockbuf locked
		 * against other readers.
		 */
		while (flags & (MSG_WAITALL|MSG_WAITSTREAM) && m == 0 &&
		    (uio_resid(uio) - delayed_copy_len) > 0 &&
		    !sosendallatonce(so) && !nextrecord) {
			if (so->so_error || so->so_state & SS_CANTRCVMORE)
				goto release;

			/*
			 * Depending on the protocol (e.g. TCP), the following
			 * might cause the socket lock to be dropped and later
			 * be reacquired, and more data could have arrived and
			 * have been appended to the receive socket buffer by
			 * the time it returns.  Therefore, we only sleep in
			 * sbwait() below if and only if the socket buffer is
			 * empty, in order to avoid a false sleep.
			 */
			if (pr->pr_flags & PR_WANTRCVD && so->so_pcb &&
			    (((struct inpcb *)so->so_pcb)->inp_state !=
			    INPCB_STATE_DEAD))
				(*pr->pr_usrreqs->pru_rcvd)(so, flags);

			SBLASTRECORDCHK(&so->so_rcv, "soreceive sbwait 2");
			SBLASTMBUFCHK(&so->so_rcv, "soreceive sbwait 2");

			if (so->so_rcv.sb_mb == NULL && sbwait(&so->so_rcv)) {
				error = 0;
				goto release;
			}
			/*
			 * have to wait until after we get back from the sbwait
			 * to do the copy because we will drop the lock if we
			 * have enough data that has been delayed... by dropping
			 * the lock we open up a window allowing the netisr
			 * thread to process the incoming packets and to change
			 * the state of this socket... we're issuing the sbwait
			 * because the socket is empty and we're expecting the
			 * netisr thread to wake us up when more packets arrive;
			 * if we allow that processing to happen and then sbwait
			 * we could stall forever with packets sitting in the
			 * socket if no further packets arrive from the remote
			 * side.
			 *
			 * we want to copy before we've collected all the data
			 * to satisfy this request to allow the copy to overlap
			 * the incoming packet processing on an MP system
			 */
			if (delayed_copy_len > sorecvmincopy &&
			    (delayed_copy_len > (so->so_rcv.sb_hiwat / 2))) {
				error = sodelayed_copy(so, uio,
				    &free_list, &delayed_copy_len);

				if (error)
					goto release;
			}
			m = so->so_rcv.sb_mb;
			if (m) {
				nextrecord = m->m_nextpkt;
			}
			SB_MB_CHECK(&so->so_rcv);
		}
	}
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1)
		panic("soreceive: after big while so=%p ref=%d on socket\n",
		    so, so->so_usecount);
#endif

	if (m && pr->pr_flags & PR_ATOMIC) {
#ifdef __APPLE__
		if (so->so_options & SO_DONTTRUNC) {
			flags |= MSG_RCVMORE;
		} else {
#endif
			flags |= MSG_TRUNC;
			if ((flags & MSG_PEEK) == 0)
				(void) sbdroprecord(&so->so_rcv);
#ifdef __APPLE__
		}
#endif
	}

	/*
	 * pru_rcvd below (for TCP) may cause more data to be received
	 * if the socket lock is dropped prior to sending the ACK; some
	 * legacy OpenTransport applications don't handle this well
	 * (if it receives less data than requested while MSG_HAVEMORE
	 * is set), and so we set the flag now based on what we know
	 * prior to calling pru_rcvd.
	 */
	if ((so->so_options & SO_WANTMORE) && so->so_rcv.sb_cc > 0)
		flags |= MSG_HAVEMORE;

	if ((flags & MSG_PEEK) == 0) {
		if (m == 0) {
			so->so_rcv.sb_mb = nextrecord;
			/*
			 * First part is an inline SB_EMPTY_FIXUP().  Second
			 * part makes sure sb_lastrecord is up-to-date if
			 * there is still data in the socket buffer.
			 */
			if (so->so_rcv.sb_mb == NULL) {
				so->so_rcv.sb_mbtail = NULL;
				so->so_rcv.sb_lastrecord = NULL;
			} else if (nextrecord->m_nextpkt == NULL) {
				so->so_rcv.sb_lastrecord = nextrecord;
			}
			SB_MB_CHECK(&so->so_rcv);
		}
		SBLASTRECORDCHK(&so->so_rcv, "soreceive 4");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive 4");
		if (pr->pr_flags & PR_WANTRCVD && so->so_pcb)
			(*pr->pr_usrreqs->pru_rcvd)(so, flags);
	}
#ifdef __APPLE__
	if (delayed_copy_len) {
		error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);

		if (error)
			goto release;
	}
	if (free_list) {
		m_freem_list((struct mbuf *)free_list);
		free_list = (struct mbuf *)0;
	}
	if (need_event)
		postevent(so, 0, EV_OOB);
#endif
	if (orig_resid == uio_resid(uio) && orig_resid &&
	    (flags & MSG_EOR) == 0 && (so->so_state & SS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv, 1);
		goto restart;
	}

	if (flagsp)
		*flagsp |= flags;
release:
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1)
		panic("soreceive: release so=%p ref=%d on socket\n",
		    so, so->so_usecount);
#endif
	if (delayed_copy_len) {
		error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);
	}
	if (free_list) {
		m_freem_list((struct mbuf *)free_list);
	}
	sbunlock(&so->so_rcv, 0);	/* will unlock socket */

	// LP64todo - fix this!
	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, so, uio_resid(uio),
	    so->so_rcv.sb_cc, 0, error);

	return (error);
}

/*
 * Returns:	0			Success
 *	uiomove:EFAULT
 */
static int
sodelayed_copy(struct socket *so, struct uio *uio, struct mbuf **free_list,
    int *resid)
{
	int error = 0;
	struct mbuf *m;

	m = *free_list;

	socket_unlock(so, 0);

	while (m && error == 0) {

		error = uiomove(mtod(m, caddr_t), (int)m->m_len, uio);

		m = m->m_next;
	}
	m_freem_list(*free_list);

	*free_list = (struct mbuf *)NULL;
	*resid = 0;

	socket_lock(so, 0);

	return (error);
}


/*
 * Returns:	0			Success
 *		EINVAL
 *		ENOTCONN
 *	<pru_shutdown>:EINVAL
 *	<pru_shutdown>:EADDRNOTAVAIL[TCP]
 *	<pru_shutdown>:ENOBUFS[TCP]
 *	<pru_shutdown>:EMSGSIZE[TCP]
 *	<pru_shutdown>:EHOSTUNREACH[TCP]
 *	<pru_shutdown>:ENETUNREACH[TCP]
 *	<pru_shutdown>:ENETDOWN[TCP]
 *	<pru_shutdown>:ENOMEM[TCP]
 *	<pru_shutdown>:EACCES[TCP]
 *	<pru_shutdown>:EMSGSIZE[TCP]
 *	<pru_shutdown>:ENOBUFS[TCP]
 *	<pru_shutdown>:???[TCP]		[ignorable: mostly IPSEC/firewall/DLIL]
 *	<pru_shutdown>:???		[other protocol families]
 */
int
soshutdown(struct socket *so, int how)
{
	int error;

	switch (how) {
	case SHUT_RD:
	case SHUT_WR:
	case SHUT_RDWR:
		socket_lock(so, 1);
		if ((so->so_state &
		    (SS_ISCONNECTED|SS_ISCONNECTING|SS_ISDISCONNECTING)) == 0) {
			error = ENOTCONN;
		} else {
			error = soshutdownlock(so, how);
		}
		socket_unlock(so, 1);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

int
soshutdownlock(struct socket *so, int how)
{
	struct protosw *pr = so->so_proto;
	int error = 0;

	sflt_notify(so, sock_evt_shutdown, &how);

	if (how != SHUT_WR) {
		if ((so->so_state & SS_CANTRCVMORE) != 0) {
			/* read already shut down */
			error = ENOTCONN;
			goto done;
		}
		sorflush(so);
		postevent(so, 0, EV_RCLOSED);
	}
	if (how != SHUT_RD) {
		if ((so->so_state & SS_CANTSENDMORE) != 0) {
			/* write already shut down */
			error = ENOTCONN;
			goto done;
		}
		error = (*pr->pr_usrreqs->pru_shutdown)(so);
		postevent(so, 0, EV_WCLOSED);
	}
done:
	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, 0, 0, 0, 0, 0);
	return (error);
}

void
sorflush(struct socket *so)
{
	register struct sockbuf *sb = &so->so_rcv;
	register struct protosw *pr = so->so_proto;
	struct sockbuf asb;

#ifdef MORE_LOCKING_DEBUG
	lck_mtx_t *mutex_held;

	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif

	sflt_notify(so, sock_evt_flush_read, NULL);

	sb->sb_flags |= SB_NOINTR;
	(void) sblock(sb, M_WAIT);
	socantrcvmore(so);
	sbunlock(sb, 1);
#ifdef __APPLE__
	selthreadclear(&sb->sb_sel);
#endif
	asb = *sb;
	bzero((caddr_t)sb, sizeof (*sb));
	sb->sb_so = so;	/* reestablish link to socket */
	if (asb.sb_flags & SB_KNOTE) {
		sb->sb_sel.si_note = asb.sb_sel.si_note;
		sb->sb_flags = SB_KNOTE;
	}
	if (asb.sb_flags & SB_DROP)
		sb->sb_flags |= SB_DROP;
	if (asb.sb_flags & SB_UNIX)
		sb->sb_flags |= SB_UNIX;
	if ((pr->pr_flags & PR_RIGHTS) && pr->pr_domain->dom_dispose) {
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);
	}
	sbrelease(&asb);
}

/*
 * Perhaps this routine, and sooptcopyout(), below, ought to come in
 * an additional variant to handle the case where the option value needs
 * to be some kind of integer, but not a specific size.
 * In addition to their use here, these functions are also called by the
 * protocol-level pr_ctloutput() routines.
 *
 * Returns:	0			Success
 *		EINVAL
 *	copyin:EFAULT
 */
int
sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen)
{
	size_t	valsize;

	/*
	 * If the user gives us more than we wanted, we ignore it,
	 * but if we don't get the minimum length the caller
	 * wants, we return EINVAL.  On success, sopt->sopt_valsize
	 * is set to however much we actually retrieved.
	 */
	if ((valsize = sopt->sopt_valsize) < minlen)
		return (EINVAL);
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;

	if (sopt->sopt_p != kernproc)
		return (copyin(sopt->sopt_val, buf, valsize));

	bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), buf, valsize);
	return (0);
}

/*
 * sooptcopyin_timeval
 *   Copy in a timeval value into tv_p, and take into account whether the
 *   the calling process is 64-bit or 32-bit.  Moved the sanity checking
 *   code here so that we can verify the 64-bit tv_sec value before we lose
 *   the top 32-bits assigning tv64.tv_sec to tv_p->tv_sec.
 */
static int
sooptcopyin_timeval(struct sockopt *sopt, struct timeval * tv_p)
{
	int			error;

	if (proc_is64bit(sopt->sopt_p)) {
		struct user64_timeval	tv64;

		if (sopt->sopt_valsize < sizeof(tv64)) {
			return (EINVAL);
		}
		sopt->sopt_valsize = sizeof(tv64);
		if (sopt->sopt_p != kernproc) {
			error = copyin(sopt->sopt_val, &tv64, sizeof(tv64));
			if (error != 0)
				return (error);
		} else {
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), &tv64,
				sizeof(tv64));
		}
		if (tv64.tv_sec < 0 || tv64.tv_sec > LONG_MAX 
		    || tv64.tv_usec < 0 || tv64.tv_usec >= 1000000) {
			return (EDOM);
		}
		tv_p->tv_sec = tv64.tv_sec;
		tv_p->tv_usec = tv64.tv_usec;
	} else {
		struct user32_timeval	tv32;

		if (sopt->sopt_valsize < sizeof(tv32)) {
			return (EINVAL);
		}
		sopt->sopt_valsize = sizeof(tv32);
		if (sopt->sopt_p != kernproc) {
			error = copyin(sopt->sopt_val, &tv32, sizeof(tv32));
			if (error != 0) {
				return (error);
			}
		} else {
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), &tv32,
			      sizeof(tv32));
		}
#ifndef __LP64__ // K64todo "comparison is always false due to limited range of data type"
		if (tv32.tv_sec < 0 || tv32.tv_sec > LONG_MAX 
		    || tv32.tv_usec < 0 || tv32.tv_usec >= 1000000) {
			return (EDOM);
		}
#endif
		tv_p->tv_sec = tv32.tv_sec;
		tv_p->tv_usec = tv32.tv_usec;
	}
	return (0);
}

/*
 * Returns:	0			Success
 *		EINVAL
 *		ENOPROTOOPT
 *		ENOBUFS
 *		EDOM
 *	sooptcopyin:EINVAL
 *	sooptcopyin:EFAULT
 *	sooptcopyin_timeval:EINVAL
 *	sooptcopyin_timeval:EFAULT
 *	sooptcopyin_timeval:EDOM
 *	<pr_ctloutput>:EOPNOTSUPP[AF_UNIX]
 *	<pr_ctloutput>:???w
 *	sflt_attach_private:???		[whatever a filter author chooses]
 *	<sf_setoption>:???		[whatever a filter author chooses]
 *
 * Notes:	Other <pru_listen> returns depend on the protocol family; all
 *		<sf_listen> returns depend on what the filter author causes
 *		their filter to return.
 */
int
sosetopt(struct socket *so, struct sockopt *sopt)
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
#if CONFIG_MACF_SOCKET
	struct mac extmac;
#endif /* MAC_SOCKET */

	socket_lock(so, 1);
	
	if ((so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE))
	    == (SS_CANTRCVMORE | SS_CANTSENDMORE) && 
	    (so->so_flags & SOF_NPX_SETOPTSHUT) == 0) {
		/* the socket has been shutdown, no more sockopt's */
		error = EINVAL;
		goto bad;
	}

	if (sopt->sopt_dir != SOPT_SET) {
		sopt->sopt_dir = SOPT_SET;
	}

	error = sflt_setsockopt(so, sopt);
	if (error) {
		if (error == EJUSTRETURN)
			error = 0;
		goto bad;
	}

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
			socket_unlock(so, 1);
			return (error);
		}
		error = ENOPROTOOPT;
	} else {
		switch (sopt->sopt_name) {
		case SO_LINGER:
		case SO_LINGER_SEC:
			error = sooptcopyin(sopt, &l, sizeof (l), sizeof (l));
			if (error)
				goto bad;

			so->so_linger = (sopt->sopt_name == SO_LINGER) ?
			    l.l_linger : l.l_linger * hz;
			if (l.l_onoff)
				so->so_options |= SO_LINGER;
			else
				so->so_options &= ~SO_LINGER;
			break;

		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_USELOOPBACK:
		case SO_BROADCAST:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_OOBINLINE:
		case SO_TIMESTAMP:
		case SO_TIMESTAMP_MONOTONIC:
#ifdef __APPLE__
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
#endif
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_options |= sopt->sopt_name;
			else
				so->so_options &= ~sopt->sopt_name;
			break;

		case SO_SNDBUF:
		case SO_RCVBUF:
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;

			/*
			 * Values < 1 make no sense for any of these
			 * options, so disallow them.
			 */
			if (optval < 1) {
				error = EINVAL;
				goto bad;
			}

			switch (sopt->sopt_name) {
			case SO_SNDBUF:
			case SO_RCVBUF:
			{
				struct sockbuf *sb = (sopt->sopt_name == SO_SNDBUF) ?
					&so->so_snd : &so->so_rcv;
				if (sbreserve(sb, (u_int32_t) optval) == 0) {
					error = ENOBUFS;
					goto bad;
				}
				sb->sb_flags |= SB_USRSIZE;
				sb->sb_flags &= ~SB_AUTOSIZE;
				sb->sb_idealsize = (u_int32_t)optval;
				break;
			}

			/*
			 * Make sure the low-water is never greater than
			 * the high-water.
			 */
			case SO_SNDLOWAT:
				so->so_snd.sb_lowat =
				    (optval > so->so_snd.sb_hiwat) ?
				    so->so_snd.sb_hiwat : optval;
				break;
			case SO_RCVLOWAT:
				so->so_rcv.sb_lowat =
				    (optval > so->so_rcv.sb_hiwat) ?
				    so->so_rcv.sb_hiwat : optval;
				break;
			}
			break;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			error = sooptcopyin_timeval(sopt, &tv);
			if (error)
				goto bad;

			switch (sopt->sopt_name) {
			case SO_SNDTIMEO:
				so->so_snd.sb_timeo = tv;
				break;
			case SO_RCVTIMEO:
				so->so_rcv.sb_timeo = tv;
				break;
			}
			break;

		case SO_NKE:
		{
			struct so_nke nke;

			error = sooptcopyin(sopt, &nke, sizeof (nke),
			    sizeof (nke));
			if (error)
				goto bad;

			error = sflt_attach_internal(so, nke.nke_handle);
			break;
		}

		case SO_NOSIGPIPE:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_NOSIGPIPE;
			else
				so->so_flags &= ~SOF_NOSIGPIPE;

			break;

		case SO_NOADDRERR:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_NOADDRAVAIL;
			else
				so->so_flags &= ~SOF_NOADDRAVAIL;

			break;

		case SO_REUSESHAREUID:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_REUSESHAREUID;
			else
				so->so_flags &= ~SOF_REUSESHAREUID;
			break;
#ifdef __APPLE_API_PRIVATE
		case SO_NOTIFYCONFLICT:
			if (kauth_cred_issuser(kauth_cred_get()) == 0) {
				error = EPERM;
				goto bad;
			}
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_NOTIFYCONFLICT;
			else
				so->so_flags &= ~SOF_NOTIFYCONFLICT;
			break;
#endif
		case SO_RESTRICTIONS:
			if (kauth_cred_issuser(kauth_cred_get()) == 0) {
				error = EPERM;
				goto bad;
			}
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			so->so_restrictions = (optval & (SO_RESTRICT_DENYIN |
			    SO_RESTRICT_DENYOUT | SO_RESTRICT_DENYSET));
			break;

		case SO_LABEL:
#if CONFIG_MACF_SOCKET
			if ((error = sooptcopyin(sopt, &extmac, sizeof (extmac),
			    sizeof (extmac))) != 0)
				goto bad;

			error = mac_setsockopt_label(proc_ucred(sopt->sopt_p),
			    so, &extmac);
#else
			error = EOPNOTSUPP;
#endif /* MAC_SOCKET */
			break;

#ifdef __APPLE_API_PRIVATE
		case SO_UPCALLCLOSEWAIT:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_UPCALLCLOSEWAIT;
			else
				so->so_flags &= ~SOF_UPCALLCLOSEWAIT;
			break;
#endif

		case SO_RANDOMPORT:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error)
				goto bad;
			if (optval)
				so->so_flags |= SOF_BINDRANDOMPORT;
			else
				so->so_flags &= ~SOF_BINDRANDOMPORT;
			break;

		case SO_NP_EXTENSIONS: {
			struct so_np_extensions sonpx;

			error = sooptcopyin(sopt, &sonpx, sizeof(sonpx), sizeof(sonpx));
			if (error)
				goto bad;
			if (sonpx.npx_mask & ~SONPX_MASK_VALID) {
				error = EINVAL;
				goto bad;
			}
			/*
			 * Only one bit defined for now
			 */
			if ((sonpx.npx_mask & SONPX_SETOPTSHUT)) {
				if ((sonpx.npx_flags & SONPX_SETOPTSHUT))
					so->so_flags |= SOF_NPX_SETOPTSHUT;
				else
					so->so_flags &= ~SOF_NPX_SETOPTSHUT;
			}
			break;
		}

		case SO_TRAFFIC_CLASS: {
			error = sooptcopyin(sopt, &optval, sizeof (optval),
				sizeof (optval));
			if (error)
				goto bad;
			error = so_set_traffic_class(so, optval);
			if (error)
				goto bad;
			break;
		}

		case SO_RECV_TRAFFIC_CLASS: {
			error = sooptcopyin(sopt, &optval, sizeof (optval),
				sizeof (optval));
			if (error)
				goto bad;
			if (optval == 0)
				so->so_flags &= ~SOF_RECV_TRAFFIC_CLASS;
			else
				so->so_flags |= SOF_RECV_TRAFFIC_CLASS;
			break;
		}

		case SO_TRAFFIC_CLASS_DBG: {
			struct so_tcdbg so_tcdbg;

			error = sooptcopyin(sopt, &so_tcdbg,
			    sizeof (struct so_tcdbg), sizeof (struct so_tcdbg));
			if (error)
				goto bad;
			error = so_set_tcdbg(so, &so_tcdbg);
			if (error)
				goto bad;
			break;
		}

		case SO_PRIVILEGED_TRAFFIC_CLASS:
			error = priv_check_cred(kauth_cred_get(),
			    PRIV_NET_PRIVILEGED_TRAFFIC_CLASS, 0);
			if (error)
				goto bad;
			error = sooptcopyin(sopt, &optval, sizeof (optval),
				sizeof (optval));
			if (error)
				goto bad;
			if (optval == 0)
				so->so_flags &= ~SOF_PRIVILEGED_TRAFFIC_CLASS;
			else
				so->so_flags |= SOF_PRIVILEGED_TRAFFIC_CLASS;
			break;

		case SO_DEFUNCTOK:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0 || (so->so_flags & SOF_DEFUNCT)) {
				if (error == 0)
					error = EBADF;
				goto bad;
			}
			/*
			 * Any process can set SO_DEFUNCTOK (clear
			 * SOF_NODEFUNCT), but only root can clear
			 * SO_DEFUNCTOK (set SOF_NODEFUNCT).
			 */
			if (optval == 0 &&
			    kauth_cred_issuser(kauth_cred_get()) == 0) {
				error = EPERM;
				goto bad;
			}
			if (optval)
				so->so_flags &= ~SOF_NODEFUNCT;
			else
				so->so_flags |= SOF_NODEFUNCT;

			SODEFUNCTLOG(("%s[%d]: so %p [%d,%d] is now marked as "
			    "%seligible for defunct\n", __func__,
			    proc_selfpid(), so, INP_SOCKAF(so),
			    INP_SOCKTYPE(so),
			    (so->so_flags & SOF_NODEFUNCT) ? "not " : ""));
			break;

		case SO_ISDEFUNCT:
			/* This option is not settable */
			error = EINVAL;
			break;

		case SO_OPPORTUNISTIC:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error == 0)
				error = so_set_opportunistic(so, optval);
			break;

		case SO_FLUSH:
			/* This option is handled by lower layer(s) */
			error = 0;
			break;

		case SO_RECV_ANYIF:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error == 0)
				error = so_set_recv_anyif(so, optval);
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto && so->so_proto->pr_ctloutput) {
			(void) ((*so->so_proto->pr_ctloutput)(so, sopt));
		}
	}
bad:
	socket_unlock(so, 1);
	return (error);
}

/* Helper routines for getsockopt */
int
sooptcopyout(struct sockopt *sopt, void *buf, size_t len)
{
	int	error;
	size_t	valsize;

	error = 0;

	/*
	 * Documented get behavior is that we always return a value,
	 * possibly truncated to fit in the user's buffer.
	 * Traditional behavior is that we always tell the user
	 * precisely how much we copied, rather than something useful
	 * like the total amount we had available for her.
	 * Note that this interface is not idempotent; the entire answer must
	 * generated ahead of time.
	 */
	valsize = min(len, sopt->sopt_valsize);
	sopt->sopt_valsize = valsize;
	if (sopt->sopt_val != USER_ADDR_NULL) {
		if (sopt->sopt_p != kernproc)
			error = copyout(buf, sopt->sopt_val, valsize);
		else
			bcopy(buf, CAST_DOWN(caddr_t, sopt->sopt_val), valsize);
	}
	return (error);
}

static int
sooptcopyout_timeval(struct sockopt *sopt, const struct timeval * tv_p)
{
	int			error;
	size_t			len;
	struct user64_timeval	tv64;
	struct user32_timeval	tv32;
	const void *		val;
	size_t			valsize;

	error = 0;
	if (proc_is64bit(sopt->sopt_p)) {
		len = sizeof(tv64);
		tv64.tv_sec = tv_p->tv_sec;
		tv64.tv_usec = tv_p->tv_usec;
		val = &tv64;
	} else {
		len = sizeof(tv32);
		tv32.tv_sec = tv_p->tv_sec;
		tv32.tv_usec = tv_p->tv_usec;
		val = &tv32;
	}
	valsize = min(len, sopt->sopt_valsize);
	sopt->sopt_valsize = valsize;
	if (sopt->sopt_val != USER_ADDR_NULL) {
		if (sopt->sopt_p != kernproc)
			error = copyout(val, sopt->sopt_val, valsize);
		else
			bcopy(val, CAST_DOWN(caddr_t, sopt->sopt_val), valsize);
	}
	return (error);
}

/*
 * Return:	0			Success
 *		ENOPROTOOPT
 *	<pr_ctloutput>:EOPNOTSUPP[AF_UNIX]
 *	<pr_ctloutput>:???
 *	<sf_getoption>:???
 */
int
sogetopt(struct socket *so, struct sockopt *sopt)
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
#if CONFIG_MACF_SOCKET
	struct mac extmac;
#endif /* MAC_SOCKET */

	if (sopt->sopt_dir != SOPT_GET) {
		sopt->sopt_dir = SOPT_GET;
	}

	socket_lock(so, 1);

	error = sflt_getsockopt(so, sopt);
	if (error) {
		if (error == EJUSTRETURN)
			error = 0;
		socket_unlock(so, 1);
		return (error);
	}
	
	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
			socket_unlock(so, 1);
			return (error);
		} else {
			socket_unlock(so, 1);
			return (ENOPROTOOPT);
		}
	} else {
		switch (sopt->sopt_name) {
		case SO_LINGER:
		case SO_LINGER_SEC:
			l.l_onoff = so->so_options & SO_LINGER;
			l.l_linger = (sopt->sopt_name == SO_LINGER) ?
			    so->so_linger : so->so_linger / hz;
			error = sooptcopyout(sopt, &l, sizeof (l));
			break;

		case SO_USELOOPBACK:
		case SO_DONTROUTE:
		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_BROADCAST:
		case SO_OOBINLINE:
		case SO_TIMESTAMP:
		case SO_TIMESTAMP_MONOTONIC:
#ifdef __APPLE__
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
#endif
			optval = so->so_options & sopt->sopt_name;
integer:
			error = sooptcopyout(sopt, &optval, sizeof (optval));
			break;

		case SO_TYPE:
			optval = so->so_type;
			goto integer;

#ifdef __APPLE__
		case SO_NREAD:
			if (so->so_proto->pr_flags & PR_ATOMIC) {
				int pkt_total;
				struct mbuf *m1;

				pkt_total = 0;
				m1 = so->so_rcv.sb_mb;
				while (m1) {
					if (m1->m_type == MT_DATA || m1->m_type == MT_HEADER ||
						m1->m_type == MT_OOBDATA)
						pkt_total += m1->m_len;
					m1 = m1->m_next;
				}
				optval = pkt_total;
			} else {
				optval = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
			}
			goto integer;
		
		case SO_NWRITE:
			optval = so->so_snd.sb_cc;
			goto integer;
#endif
		case SO_ERROR:
			optval = so->so_error;
			so->so_error = 0;
			goto integer;

		case SO_SNDBUF:
			optval = so->so_snd.sb_hiwat;
			goto integer;

		case SO_RCVBUF:
			optval = so->so_rcv.sb_hiwat;
			goto integer;

		case SO_SNDLOWAT:
			optval = so->so_snd.sb_lowat;
			goto integer;

		case SO_RCVLOWAT:
			optval = so->so_rcv.sb_lowat;
			goto integer;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			tv = (sopt->sopt_name == SO_SNDTIMEO ?
			    so->so_snd.sb_timeo : so->so_rcv.sb_timeo);

			error = sooptcopyout_timeval(sopt, &tv);
			break;

		case SO_NOSIGPIPE:
			optval = (so->so_flags & SOF_NOSIGPIPE);
			goto integer;

		case SO_NOADDRERR:
			optval = (so->so_flags & SOF_NOADDRAVAIL);
			goto integer;

		case SO_REUSESHAREUID:
			optval = (so->so_flags & SOF_REUSESHAREUID);
			goto integer;

#ifdef __APPLE_API_PRIVATE
		case SO_NOTIFYCONFLICT:
			optval = (so->so_flags & SOF_NOTIFYCONFLICT);
			goto integer;
#endif
		case SO_RESTRICTIONS:
			optval = so->so_restrictions & (SO_RESTRICT_DENYIN |
			    SO_RESTRICT_DENYOUT | SO_RESTRICT_DENYSET);
			goto integer;

		case SO_LABEL:
#if CONFIG_MACF_SOCKET
			if ((error = sooptcopyin(sopt, &extmac, sizeof (extmac),
			    sizeof (extmac))) != 0 ||
			    (error = mac_socket_label_get(proc_ucred(
			    sopt->sopt_p), so, &extmac)) != 0)
				break;

			error = sooptcopyout(sopt, &extmac, sizeof (extmac));
#else
			error = EOPNOTSUPP;
#endif /* MAC_SOCKET */
			break;

		case SO_PEERLABEL:
#if CONFIG_MACF_SOCKET
			if ((error = sooptcopyin(sopt, &extmac, sizeof (extmac),
			    sizeof (extmac))) != 0 ||
			    (error = mac_socketpeer_label_get(proc_ucred(
			    sopt->sopt_p), so, &extmac)) != 0)
				break;

			error = sooptcopyout(sopt, &extmac, sizeof (extmac));
#else
			error = EOPNOTSUPP;
#endif /* MAC_SOCKET */
			break;

#ifdef __APPLE_API_PRIVATE
		case SO_UPCALLCLOSEWAIT:
			optval = (so->so_flags & SOF_UPCALLCLOSEWAIT);
			goto integer;
#endif
		case SO_RANDOMPORT:
			optval = (so->so_flags & SOF_BINDRANDOMPORT);
			goto integer;

		case SO_NP_EXTENSIONS: {
			struct so_np_extensions sonpx;

			sonpx.npx_flags = (so->so_flags & SOF_NPX_SETOPTSHUT) ? SONPX_SETOPTSHUT : 0;
			sonpx.npx_mask = SONPX_MASK_VALID;

			error = sooptcopyout(sopt, &sonpx, sizeof(struct so_np_extensions));
			break;	
		}

		case SO_TRAFFIC_CLASS:
			optval = so->so_traffic_class;
			goto integer;

		case SO_RECV_TRAFFIC_CLASS:
			optval = (so->so_flags & SOF_RECV_TRAFFIC_CLASS);
			goto integer;

		case SO_TRAFFIC_CLASS_STATS:
			error = sooptcopyout(sopt, &so->so_tc_stats, sizeof(so->so_tc_stats));
			break;

		case SO_TRAFFIC_CLASS_DBG: 
			error = sogetopt_tcdbg(so, sopt);
			break;

		case SO_PRIVILEGED_TRAFFIC_CLASS:
			optval = (so->so_flags & SOF_PRIVILEGED_TRAFFIC_CLASS);
			goto integer;

		case SO_DEFUNCTOK:
			optval = !(so->so_flags & SOF_NODEFUNCT);
			goto integer;

		case SO_ISDEFUNCT:
			optval = (so->so_flags & SOF_DEFUNCT);
			goto integer;

		case SO_OPPORTUNISTIC:
			optval = so_get_opportunistic(so);
			goto integer;

		case SO_FLUSH:
			/* This option is not gettable */
			error = EINVAL;
			break;

		case SO_RECV_ANYIF:
			optval = so_get_recv_anyif(so);
			goto integer;

		default:
			error = ENOPROTOOPT;
			break;
		}
		socket_unlock(so, 1);
		return (error);
	}
}
/* The size limits on our soopt_getm is different from that on FreeBSD.
 * We limit the size of options to MCLBYTES. This will have to change
 * if we need to define options that need more space than MCLBYTES.
 */
int
soopt_getm(struct sockopt *sopt, struct mbuf **mp)
{
	struct mbuf *m, *m_prev;
	int sopt_size = sopt->sopt_valsize;
	int how;

	if (sopt_size <= 0 || sopt_size > MCLBYTES)
		return (EMSGSIZE);

	how = sopt->sopt_p != kernproc ? M_WAIT : M_DONTWAIT;
	MGET(m, how, MT_DATA);
	if (m == 0)
		return (ENOBUFS);
	if (sopt_size > MLEN) {
		MCLGET(m, how);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
		m->m_len = min(MCLBYTES, sopt_size);
	} else {
		m->m_len = min(MLEN, sopt_size);
	}
	sopt_size -= m->m_len;
	*mp = m;
	m_prev = m;

	while (sopt_size > 0) {
		MGET(m, how, MT_DATA);
		if (m == 0) {
			m_freem(*mp);
			return (ENOBUFS);
		}
		if (sopt_size > MLEN) {
			MCLGET(m, how);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(*mp);
				m_freem(m);
				return (ENOBUFS);
			}
			m->m_len = min(MCLBYTES, sopt_size);
		} else {
			m->m_len = min(MLEN, sopt_size);
		}
		sopt_size -= m->m_len;
		m_prev->m_next = m;
		m_prev = m;
	}
	return (0);
}

/* copyin sopt data into mbuf chain */
int
soopt_mcopyin(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;

	if (sopt->sopt_val == USER_ADDR_NULL)
		return (0);
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != kernproc) {
			int error;

			error = copyin(sopt->sopt_val, mtod(m, char *),
			    m->m_len);
			if (error != 0) {
				m_freem(m0);
				return (error);
			}
		} else {
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val),
			    mtod(m, char *), m->m_len);
		}
		sopt->sopt_valsize -= m->m_len;
		sopt->sopt_val += m->m_len;
		m = m->m_next;
	}
	if (m != NULL) /* should be allocated enoughly at ip6_sooptmcopyin() */
		panic("soopt_mcopyin");
	return (0);
}

/* copyout mbuf chain data into soopt */
int
soopt_mcopyout(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;
	size_t valsize = 0;

	if (sopt->sopt_val == USER_ADDR_NULL)
		return (0);
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != kernproc) {
			int error;

			error = copyout(mtod(m, char *), sopt->sopt_val,
			    m->m_len);
			if (error != 0) {
				m_freem(m0);
				return (error);
			}
		} else {
			bcopy(mtod(m, char *),
			    CAST_DOWN(caddr_t, sopt->sopt_val), m->m_len);
		}
		sopt->sopt_valsize -= m->m_len;
		sopt->sopt_val += m->m_len;
		valsize += m->m_len;
		m = m->m_next;
	}
	if (m != NULL) {
		/* enough soopt buffer should be given from user-land */
		m_freem(m0);
		return (EINVAL);
	}
	sopt->sopt_valsize = valsize;
	return (0);
}

void
sohasoutofband(struct socket *so)
{

	if (so->so_pgid < 0)
		gsignal(-so->so_pgid, SIGURG);
	else if (so->so_pgid > 0)
		proc_signal(so->so_pgid, SIGURG);
	selwakeup(&so->so_rcv.sb_sel);
}

int
sopoll(struct socket *so, int events, __unused kauth_cred_t cred, void * wql)
{
	struct proc *p = current_proc();
	int revents = 0;

	socket_lock(so, 1);

	if (events & (POLLIN | POLLRDNORM))
		if (soreadable(so))
			revents |= events & (POLLIN | POLLRDNORM);

	if (events & (POLLOUT | POLLWRNORM))
		if (sowriteable(so))
			revents |= events & (POLLOUT | POLLWRNORM);

	if (events & (POLLPRI | POLLRDBAND))
		if (so->so_oobmark || (so->so_state & SS_RCVATMARK))
			revents |= events & (POLLPRI | POLLRDBAND);

	if (revents == 0) {
		if (events & (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)) {
			/*
			 * Darwin sets the flag first,
			 * BSD calls selrecord first
			 */
			so->so_rcv.sb_flags |= SB_SEL;
			selrecord(p, &so->so_rcv.sb_sel, wql);
		}

		if (events & (POLLOUT | POLLWRNORM)) {
			/*
			 * Darwin sets the flag first,
			 * BSD calls selrecord first
			 */
			so->so_snd.sb_flags |= SB_SEL;
			selrecord(p, &so->so_snd.sb_sel, wql);
		}
	}

	socket_unlock(so, 1);
	return (revents);
}

int
soo_kqfilter(__unused struct fileproc *fp, struct knote *kn,
    __unused struct proc *p)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	struct klist *skl;

	socket_lock(so, 1);

#if CONFIG_MACF_SOCKET
	if (mac_socket_check_kqfilter(proc_ucred(p), kn, so) != 0) {
		socket_unlock(so, 1);
		return (1);
	}
#endif /* MAC_SOCKET */

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &soread_filtops;
		skl = &so->so_rcv.sb_sel.si_note;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &sowrite_filtops;
		skl = &so->so_snd.sb_sel.si_note;
		break;
	case EVFILT_SOCK:
		kn->kn_fop = &sock_filtops;
		skl = &so->so_klist;
		break;
	default:
		socket_unlock(so, 1);
		return (1);
	}

	if (KNOTE_ATTACH(skl, kn)) {
		switch(kn->kn_filter) {
		case EVFILT_READ:
			so->so_rcv.sb_flags |= SB_KNOTE;
			break;
		case EVFILT_WRITE:
			so->so_snd.sb_flags |= SB_KNOTE;
			break;
		case EVFILT_SOCK:
			so->so_flags |= SOF_KNOTE;
			break;
		default:
			socket_unlock(so, 1);
			return (1);
		}
	}
	socket_unlock(so, 1);
	return (0);
}

static void
filt_sordetach(struct knote *kn)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;

	socket_lock(so, 1);
	if (so->so_rcv.sb_flags & SB_KNOTE)
		if (KNOTE_DETACH(&so->so_rcv.sb_sel.si_note, kn))
			so->so_rcv.sb_flags &= ~SB_KNOTE;
	socket_unlock(so, 1);
}

/*ARGSUSED*/
static int
filt_soread(struct knote *kn, long hint)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_lock(so, 1);

	if (so->so_options & SO_ACCEPTCONN) {
		int isempty;

		/* Radar 6615193 handle the listen case dynamically
		 * for kqueue read filter. This allows to call listen() after registering
		 * the kqueue EVFILT_READ.
		 */

		kn->kn_data = so->so_qlen;
		isempty = ! TAILQ_EMPTY(&so->so_comp);

		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);

		return (isempty);
	}

	/* socket isn't a listener */

	kn->kn_data = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;

	if (so->so_oobmark) {
		if (kn->kn_flags & EV_OOBAND) {
			kn->kn_data -= so->so_oobmark;
			if ((hint & SO_FILT_HINT_LOCKED) == 0)
				socket_unlock(so, 1);
			return (1);
		}
		kn->kn_data = so->so_oobmark;
		kn->kn_flags |= EV_OOBAND;
	} else {
		if (so->so_state & SS_CANTRCVMORE) {
			kn->kn_flags |= EV_EOF;
			kn->kn_fflags = so->so_error;
			if ((hint & SO_FILT_HINT_LOCKED) == 0)
				socket_unlock(so, 1);
			return (1);
		}
	}

	if (so->so_state & SS_RCVATMARK) {
		if (kn->kn_flags & EV_OOBAND) {
			if ((hint & SO_FILT_HINT_LOCKED) == 0)
				socket_unlock(so, 1);
			return (1);
		}
		kn->kn_flags |= EV_OOBAND;
	} else if (kn->kn_flags & EV_OOBAND) {
		kn->kn_data = 0;
		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);
		return (0);
	}

	if (so->so_error) {	/* temporary udp error */
		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);
		return (1);
	}

	int64_t	lowwat = so->so_rcv.sb_lowat;
	if (kn->kn_sfflags & NOTE_LOWAT)
	{
		if (kn->kn_sdata > so->so_rcv.sb_hiwat)
			lowwat = so->so_rcv.sb_hiwat;
		else if (kn->kn_sdata > lowwat)
			lowwat = kn->kn_sdata;
	}
	
	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);
	
	return ((kn->kn_flags & EV_OOBAND) || kn->kn_data >= lowwat);
}

static void
filt_sowdetach(struct knote *kn)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	socket_lock(so, 1);

	if (so->so_snd.sb_flags & SB_KNOTE)
		if (KNOTE_DETACH(&so->so_snd.sb_sel.si_note, kn))
			so->so_snd.sb_flags &= ~SB_KNOTE;
	socket_unlock(so, 1);
}

int
so_wait_for_if_feedback(struct socket *so)
{
	if ((so->so_proto->pr_domain->dom_family == AF_INET ||
	    so->so_proto->pr_domain->dom_family == AF_INET6) &&
	    (so->so_state & SS_ISCONNECTED)) {
		struct inpcb *inp = sotoinpcb(so);
		if (INP_WAIT_FOR_IF_FEEDBACK(inp))
			return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
filt_sowrite(struct knote *kn, long hint)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	int ret = 0;

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_lock(so, 1);

	kn->kn_data = sbspace(&so->so_snd);
	if (so->so_state & SS_CANTSENDMORE) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		ret = 1;
		goto out;
	}
	if (so->so_error) {	/* temporary udp error */
		ret = 1;
		goto out;
	}
	if (((so->so_state & SS_ISCONNECTED) == 0) &&
	    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
		ret = 0;
		goto out;
	}
	int64_t	lowwat = so->so_snd.sb_lowat;
	if (kn->kn_sfflags & NOTE_LOWAT)
	{
		if (kn->kn_sdata > so->so_snd.sb_hiwat)
			lowwat = so->so_snd.sb_hiwat;
		else if (kn->kn_sdata > lowwat)
			lowwat = kn->kn_sdata;
	}
	if (kn->kn_data >= lowwat) {
		if ((so->so_flags & SOF_NOTSENT_LOWAT) != 0) {
			ret = tcp_notsent_lowat_check(so);
		} else {
			ret = 1;
		}
	}
	if (so_wait_for_if_feedback(so))
		ret = 0;
out:
	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);
	return(ret);
}

static void
filt_sockdetach(struct knote *kn)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	socket_lock(so, 1);
	
	if ((so->so_flags & SOF_KNOTE) != 0)
		if (KNOTE_DETACH(&so->so_klist, kn))
			so->so_flags &= ~SOF_KNOTE;
	socket_unlock(so, 1);
}

static int
filt_sockev(struct knote *kn, long hint)
{
	int ret = 0, locked = 0;
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;

	if ((hint & SO_FILT_HINT_LOCKED) == 0) {
		socket_lock(so, 1);
		locked = 1;
	}

	switch (hint & SO_FILT_HINT_EV) {
	case SO_FILT_HINT_CONNRESET:
		if (kn->kn_sfflags & NOTE_CONNRESET)
			kn->kn_fflags |= NOTE_CONNRESET;
		break;
	case SO_FILT_HINT_TIMEOUT:
		if (kn->kn_sfflags & NOTE_TIMEOUT)
			kn->kn_fflags |= NOTE_TIMEOUT;
		break;
	case SO_FILT_HINT_NOSRCADDR:
		if (kn->kn_sfflags & NOTE_NOSRCADDR)
			kn->kn_fflags |= NOTE_NOSRCADDR;
		break;
	case SO_FILT_HINT_IFDENIED:
		if ((kn->kn_sfflags & NOTE_IFDENIED))
			kn->kn_fflags |= NOTE_IFDENIED;
		break;
	case SO_FILT_HINT_KEEPALIVE:
		if (kn->kn_sfflags & NOTE_KEEPALIVE)
			kn->kn_fflags |= NOTE_KEEPALIVE;
	}

	if ((kn->kn_sfflags & NOTE_READCLOSED) &&
		(so->so_state & SS_CANTRCVMORE))
		kn->kn_fflags |= NOTE_READCLOSED;

	if ((kn->kn_sfflags & NOTE_WRITECLOSED) &&
		(so->so_state & SS_CANTSENDMORE))
		kn->kn_fflags |= NOTE_WRITECLOSED;

	if ((kn->kn_sfflags & NOTE_SUSPEND) &&
	    ((hint & SO_FILT_HINT_SUSPEND) ||
	    (so->so_flags & SOF_SUSPENDED))) {
		kn->kn_fflags &=
			~(NOTE_SUSPEND | NOTE_RESUME);
		kn->kn_fflags |= NOTE_SUSPEND;
	}

	if ((kn->kn_sfflags & NOTE_RESUME) &&
	    ((hint & SO_FILT_HINT_RESUME) ||
	    (so->so_flags & SOF_SUSPENDED) == 0)) {
		kn->kn_fflags &=
			~(NOTE_SUSPEND | NOTE_RESUME);
		kn->kn_fflags |= NOTE_RESUME;
	}

	if (so->so_error != 0) {
		ret = 1;
		kn->kn_data = so->so_error;
		kn->kn_flags |= EV_EOF;
	} else {
		get_sockev_state(so, (u_int32_t *)&(kn->kn_data));
	}

	if (kn->kn_fflags != 0)
		ret = 1;

	if (locked)
		socket_unlock(so, 1);

	return(ret);
}

void
get_sockev_state(struct socket *so, u_int32_t *statep) {
	u_int32_t state = *(statep);

	if (so->so_state & SS_ISCONNECTED)	
		state |= SOCKEV_CONNECTED;
	else 
		state &= ~(SOCKEV_CONNECTED);
	state |= ((so->so_state & SS_ISDISCONNECTED) ?
		SOCKEV_DISCONNECTED : 0);
	*(statep) = state;
	return;
}

#define SO_LOCK_HISTORY_STR_LEN (2 * SO_LCKDBG_MAX * (2 + (2 * sizeof(void *)) + 1) + 1)

__private_extern__ const char * solockhistory_nr(struct socket *so)
{
        size_t n = 0;
        int i;
        static char lock_history_str[SO_LOCK_HISTORY_STR_LEN];

	bzero(lock_history_str, sizeof(lock_history_str));
        for (i = SO_LCKDBG_MAX - 1; i >= 0; i--) {
                n += snprintf(lock_history_str + n, SO_LOCK_HISTORY_STR_LEN - n, "%lx:%lx ",
                        (uintptr_t) so->lock_lr[(so->next_lock_lr + i) % SO_LCKDBG_MAX],
                        (uintptr_t) so->unlock_lr[(so->next_unlock_lr + i) % SO_LCKDBG_MAX]);
	}
        return lock_history_str;
}

int
socket_lock(struct socket *so, int refcount)
{
	int error = 0;
	void *lr_saved;

	lr_saved = __builtin_return_address(0);

	if (so->so_proto->pr_lock) {
		error = (*so->so_proto->pr_lock)(so, refcount, lr_saved);
	} else {
#ifdef MORE_LOCKING_DEBUG
		lck_mtx_assert(so->so_proto->pr_domain->dom_mtx,
		    LCK_MTX_ASSERT_NOTOWNED);
#endif
		lck_mtx_lock(so->so_proto->pr_domain->dom_mtx);
		if (refcount)
			so->so_usecount++;
		so->lock_lr[so->next_lock_lr] = lr_saved;
		so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
	}

	return (error);
}

int
socket_unlock(struct socket *so, int refcount)
{
	int error = 0;
	void *lr_saved;
	lck_mtx_t *mutex_held;

	lr_saved = __builtin_return_address(0);

	if (so->so_proto == NULL)
		panic("socket_unlock null so_proto so=%p\n", so);

	if (so && so->so_proto->pr_unlock) {
		error = (*so->so_proto->pr_unlock)(so, refcount, lr_saved);
	} else {
		mutex_held = so->so_proto->pr_domain->dom_mtx;
#ifdef MORE_LOCKING_DEBUG
		lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;

		if (refcount) {
			if (so->so_usecount <= 0)
				panic("socket_unlock: bad refcount=%d so=%p (%d, %d, %d) lrh=%s",
				    so->so_usecount, so, so->so_proto->pr_domain->dom_family,
				    so->so_type, so->so_proto->pr_protocol, 
				    solockhistory_nr(so));
			
			so->so_usecount--;
			if (so->so_usecount == 0) {
				sofreelastref(so, 1);
			}
		}
		lck_mtx_unlock(mutex_held);
	}

	return (error);
}

/* Called with socket locked, will unlock socket */
void
sofree(struct socket *so)
{

	lck_mtx_t *mutex_held;
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);

	sofreelastref(so, 0);
}

void
soreference(struct socket *so)
{
	socket_lock(so, 1);	/* locks & take one reference on socket */
	socket_unlock(so, 0);	/* unlock only */
}

void
sodereference(struct socket *so)
{
	socket_lock(so, 0);
	socket_unlock(so, 1);
}

/*
 * Set or clear SOF_MULTIPAGES on the socket to enable or disable the
 * possibility of using jumbo clusters.  Caller must ensure to hold
 * the socket lock.
 */
void
somultipages(struct socket *so, boolean_t set)
{
	if (set)
		so->so_flags |= SOF_MULTIPAGES;
	else
		so->so_flags &= ~SOF_MULTIPAGES;
}

int
so_isdstlocal(struct socket *so) {

	struct inpcb *inp = (struct inpcb *)so->so_pcb;

	if (so->so_proto->pr_domain->dom_family == AF_INET) {
		return inaddr_local(inp->inp_faddr);
	} else if (so->so_proto->pr_domain->dom_family == AF_INET6) {
		return in6addr_local(&inp->in6p_faddr);
	} 
	return 0;
}

int
sosetdefunct(struct proc *p, struct socket *so, int level, boolean_t noforce)
{
	int err = 0, defunct;

	defunct = (so->so_flags & SOF_DEFUNCT);
	if (defunct) {
		if (!(so->so_snd.sb_flags & so->so_rcv.sb_flags & SB_DROP))
			panic("%s: SB_DROP not set", __func__);
		goto done;
	}

	if (so->so_flags & SOF_NODEFUNCT) {
		if (noforce) {
			err = EOPNOTSUPP;
			SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so %p "
			    "[%d,%d] is not eligible for defunct (%d)\n",
			    __func__, proc_selfpid(), proc_pid(p), level, so,
			    INP_SOCKAF(so), INP_SOCKTYPE(so), err));
			return (err);
		}
		so->so_flags &= ~SOF_NODEFUNCT;
		SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so %p [%d,%d] "
		    "defunct by force\n", __func__, proc_selfpid(), proc_pid(p),
		    level, so, INP_SOCKAF(so), INP_SOCKTYPE(so)));
	}

	so->so_flags |= SOF_DEFUNCT;
	/* Prevent further data from being appended to the socket buffers */
	so->so_snd.sb_flags |= SB_DROP;
	so->so_rcv.sb_flags |= SB_DROP;

done:
	SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so %p [%d,%d] %s "
	    "defunct\n", __func__, proc_selfpid(), proc_pid(p), level, so,
	    INP_SOCKAF(so), INP_SOCKTYPE(so),
	    defunct ? "is already" : "marked as"));

	return (err);
}

int
sodefunct(struct proc *p, struct socket *so, int level)
{
	struct sockbuf *rcv, *snd;

	if (!(so->so_flags & SOF_DEFUNCT))
		panic("%s improperly called", __func__);

	if (so->so_state & SS_DEFUNCT)
		goto done;

	rcv = &so->so_rcv;
	snd = &so->so_snd;

	SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so %p [%d,%d] is now "
	    "defunct [rcv_si 0x%x, snd_si 0x%x, rcv_fl 0x%x, snd_fl 0x%x]\n",
	    __func__, proc_selfpid(), proc_pid(p), level, so,
	    INP_SOCKAF(so), INP_SOCKTYPE(so),
	    (uint32_t)rcv->sb_sel.si_flags, (uint32_t)snd->sb_sel.si_flags,
	    (uint16_t)rcv->sb_flags, (uint16_t)snd->sb_flags));

	/*
	 * Unwedge threads blocked on sbwait() and sb_lock().
	 */
	sbwakeup(rcv);
	sbwakeup(snd);

	if (rcv->sb_flags & SB_LOCK)
		sbunlock(rcv, 1);
	if (snd->sb_flags & SB_LOCK)
		sbunlock(snd, 1);

	/*
	 * Flush the buffers and disconnect.  We explicitly call shutdown
	 * on both data directions to ensure that SS_CANT{RCV,SEND}MORE
	 * states are set for the socket.  This would also flush out data
	 * hanging off the receive list of this socket.
	 */
	(void) soshutdownlock(so, SHUT_RD);
	(void) soshutdownlock(so, SHUT_WR);
	(void) sodisconnectlocked(so);

	/*
	 * Explicitly handle connectionless-protocol disconnection
	 * and release any remaining data in the socket buffers.
	 */
	if (!(so->so_flags & SS_ISDISCONNECTED))
		(void) soisdisconnected(so);

	if (so->so_error == 0)
		so->so_error = EBADF;

	if (rcv->sb_cc != 0)
		sbrelease(rcv);
	if (snd->sb_cc != 0)
		sbrelease(snd);

	so->so_state |= SS_DEFUNCT;

done:
	return (0);
}

__private_extern__ int
so_set_recv_anyif(struct socket *so, int optval)
{
	int ret = 0;

#if INET6
	if (INP_SOCKAF(so) == AF_INET || INP_SOCKAF(so) == AF_INET6) {
#else
	if (INP_SOCKAF(so) == AF_INET) {
#endif /* !INET6 */
		if (optval)
			sotoinpcb(so)->inp_flags |= INP_RECV_ANYIF;
		else
			sotoinpcb(so)->inp_flags &= ~INP_RECV_ANYIF;
	} else {
		ret = EPROTONOSUPPORT;
	}

	return (ret);
}

__private_extern__ int
so_get_recv_anyif(struct socket *so)
{
	int ret = 0;

#if INET6
	if (INP_SOCKAF(so) == AF_INET || INP_SOCKAF(so) == AF_INET6) {
#else
	if (INP_SOCKAF(so) == AF_INET) {
#endif /* !INET6 */
		ret = (sotoinpcb(so)->inp_flags & INP_RECV_ANYIF) ? 1 : 0;
	}

	return (ret);
}
